"""核心业务逻辑：可信核验、离线补传、复核、撤销与确定性状态归并。

三类写入方
----------
- 赛事方：场次（正常/延期/取消）、票券（出票/退款）；
- 景区：设备登记、在线核验、离线签名留存与补传；
- 结算：复核结论、人工撤销、清算批次（见 ``clearing.py``）。

一切状态变化都先追加进哈希链台账，再更新物化表；物化表可由
``rebuild_state`` 清空后重放台账完整重建。

防重复补贴的三道闸
------------------
1. 指纹去重：离线记录指纹 = 签名负载规范串的哈希，重复补传只记审计；
2. 业务键去重：(票号, 景区, 原始业务键) 唯一，重签/换设备不能二次出权益；
3. 确定性归并：同一票的全部记录按 (发生时间, 指纹) 排序竞争限兑名额，
   结果只取决于记录内容而与到达顺序无关——晚到的早记录会把已出权益
   确定性地冲回，而不会叠加成两份补贴。
"""

from __future__ import annotations

import contextlib
import json
from typing import Any, Callable

from crypto import (SIGN_ALGO, canonical, new_device_secret,
                    offline_fingerprint, sha256_hex, verify_signature)
from domain import (ADJUST_REVERSAL, ADJUST_SUBSIDY, ADJUST_VOID,
                    EV_ADJUST, EV_BATCH, EV_CONFIG, EV_DEDUP, EV_DEVICE,
                    EV_MATCH, EV_REDEEM, EV_REVIEW, EV_TICKET,
                    R_PENDING, R_REVIEW, R_REVOKED, R_SETTLED, R_VALID,
                    REV_CANCEL, REV_MANUAL, REV_POSTPONE, REV_QUOTA, REV_REFUND,
                    REV_REVIEW_REJECT, REV_SEASON, REV_WINDOW, Domain, now_ts,
                    parse_iso, period_key, ts_to_date)
from store import Store

# 复核原因（除核销结果外的异常口径）
RV_UNKNOWN_TICKET = "票号不存在"
RV_HOLDER_MISMATCH = "持票人不符"
RV_PAPER = "纸质票根防伪复核"
RV_LATE_UPLOAD = "超过补传时限"
RV_CLOCK_AHEAD = "签名时间超前"
RV_DEVICE_FORK = "同序号签名不一致"
RV_STUB_EXPIRED = "存根逾期未补传"

# 撤销原因中“黏性”与“可恢复”的分界：
# 超出名额是软撤销，当更早的记录被撤销后名额可恢复；其余均为刚性结论。
STICKY_REASONS = {REV_REFUND, REV_POSTPONE, REV_CANCEL, REV_MANUAL,
                  REV_REVIEW_REJECT, REV_WINDOW, REV_SEASON}

CHANNEL_ONLINE = "online"
CHANNEL_OFFLINE = "offline"

MATCH_NORMAL = "正常"
MATCH_POSTPONED = "延期"
MATCH_CANCELED = "取消"
TICKET_NORMAL = "正常"
TICKET_REFUNDED = "退款"


class BusinessError(Exception):
    """可预期的业务拒绝（伪造、签名错误、参数非法等）。"""

    def __init__(self, message: str, status: int = 400, extra: dict | None = None):
        super().__init__(message)
        self.status = status
        self.extra = extra or {}


def online_fingerprint(ticket_no: str, holder: str, scenic: str,
                       business_key: str, occurred_at: float) -> str:
    return sha256_hex(canonical({
        "channel": CHANNEL_ONLINE,
        "ticket_no": ticket_no,
        "holder": holder,
        "scenic": scenic,
        "business_key": business_key,
        "occurred_at": round(float(occurred_at), 3),
    }))


class Core:
    def __init__(self, store: Store, domain: Domain,
                 clock: Callable[[], float] = now_ts):
        self.s = store
        self.d = domain
        self._clock = clock

    def now(self) -> float:
        return self._clock()

    @contextlib.contextmanager
    def txn(self):
        with self.s.lock:
            self.s.conn.execute("BEGIN IMMEDIATE")
            try:
                yield
                self.s.conn.execute("COMMIT")
            except Exception:
                self.s.conn.execute("ROLLBACK")
                raise

    # ------------------------------------------------------------------ #
    # 基础登记
    # ------------------------------------------------------------------ #
    def configure_scenic(self, scenic: str, period: str):
        if scenic not in self.d.scenic_group:
            raise BusinessError(f"景区 {scenic} 不在口径分组中", 404)
        if period not in self.d.periods:
            raise BusinessError(f"未知结算周期 {period}")
        at = self.now()
        with self.txn():
            existed = self.s.conn.execute(
                "SELECT period FROM scenics WHERE scenic=?", (scenic,)
            ).fetchone()
            if existed and existed["period"] == period:
                return {"scenic": scenic, "period": period, "changed": False}
            if existed:
                raise BusinessError(
                    f"景区 {scenic} 已按 {existed['period']} 开账，周期不可中途变更；"
                    "请在新周期生效前调整", 409)
            body = {"scenic": scenic, "group": self.d.group_name_of(scenic),
                    "period": period}
            ev = self.s.append_event(self.s.new_event_id(), EV_CONFIG, body, at)
            self.s.conn.execute(
                "INSERT INTO scenics(scenic,group_name,period) VALUES(?,?,?)",
                (scenic, body["group"], period))
            return {"scenic": scenic, "period": period, "changed": True,
                    "event_id": ev["event_id"]}

    def register_device(self, device_id: str, scenic: str,
                        secret: str | None = None) -> dict:
        if scenic not in self.d.scenic_group:
            raise BusinessError(f"景区 {scenic} 不在口径分组中", 404)
        at = self.now()
        secret = secret or new_device_secret()
        with self.txn():
            row = self.s.conn.execute(
                "SELECT device_id FROM devices WHERE device_id=?", (device_id,)
            ).fetchone()
            if row:
                raise BusinessError(f"设备 {device_id} 已登记", 409)
            body = {"device_id": device_id, "scenic": scenic,
                    "secret": secret, "revoked": False}
            ev = self.s.append_event(self.s.new_event_id(), EV_DEVICE, body, at)
            self.s.conn.execute(
                "INSERT INTO devices(device_id,scenic,secret,revoked,registered_at)"
                " VALUES(?,?,?,0,?)", (device_id, scenic, secret, at))
            return {"device_id": device_id, "scenic": scenic,
                    "secret": secret, "event_id": ev["event_id"]}

    def revoke_device(self, device_id: str, reason: str) -> dict:
        at = self.now()
        with self.txn():
            row = self.s.conn.execute(
                "SELECT * FROM devices WHERE device_id=?", (device_id,)
            ).fetchone()
            if not row:
                raise BusinessError(f"设备 {device_id} 不存在", 404)
            if row["revoked"]:
                return {"device_id": device_id, "revoked": True, "changed": False}
            body = {"device_id": device_id, "scenic": row["scenic"],
                    "secret": row["secret"], "revoked": True, "reason": reason}
            ev = self.s.append_event(self.s.new_event_id(), EV_DEVICE, body, at)
            self.s.conn.execute(
                "UPDATE devices SET revoked=1 WHERE device_id=?", (device_id,))
            return {"device_id": device_id, "revoked": True,
                    "event_id": ev["event_id"]}

    # ------------------------------------------------------------------ #
    # 赛事：场次与票券
    # ------------------------------------------------------------------ #
    def create_match(self, match_id: str, season_code: str, opponent: str,
                     kickoff: str | float) -> dict:
        if season_code not in self.d.season_by_code:
            raise BusinessError(f"未知赛季 {season_code}")
        kickoff_at = kickoff if isinstance(kickoff, (int, float)) else parse_iso(kickoff)
        at = self.now()
        with self.txn():
            if self.s.conn.execute("SELECT 1 FROM matches WHERE match_id=?",
                                   (match_id,)).fetchone():
                raise BusinessError(f"场次 {match_id} 已存在", 409)
            body = {"match_id": match_id, "season_code": season_code,
                    "opponent": opponent, "kickoff_at": kickoff_at,
                    "status": MATCH_NORMAL}
            ev = self.s.append_event(self.s.new_event_id(), EV_MATCH, body, at)
            self.s.conn.execute(
                "INSERT INTO matches(match_id,season_code,opponent,kickoff_at,"
                "status,updated_at) VALUES(?,?,?,?,?,?)",
                (match_id, season_code, opponent, kickoff_at, MATCH_NORMAL, at))
            return {"match_id": match_id, "event_id": ev["event_id"]}

    def _set_match_status(self, match_id: str, status: str,
                          new_kickoff_at: float | None, reason_extra: dict | None):
        at = self.now()
        with self.txn():
            m = self.s.conn.execute(
                "SELECT * FROM matches WHERE match_id=?", (match_id,)
            ).fetchone()
            if not m:
                raise BusinessError(f"场次 {match_id} 不存在", 404)
            body = {"match_id": match_id, "season_code": m["season_code"],
                    "opponent": m["opponent"], "kickoff_at": m["kickoff_at"],
                    "status": status, "new_kickoff_at": new_kickoff_at}
            if reason_extra:
                body.update(reason_extra)
            ev = self.s.append_event(self.s.new_event_id(), EV_MATCH, body, at)
            self.s.conn.execute(
                "UPDATE matches SET status=?, new_kickoff_at=?, updated_at=? "
                "WHERE match_id=?",
                (status, new_kickoff_at, at, match_id))

            # 场次延期：票券权益窗口整体平移到新比赛日，窗口外已兑记录由归并冲回
            if status == MATCH_POSTPONED and new_kickoff_at is not None:
                tickets = self.s.conn.execute(
                    "SELECT * FROM tickets WHERE match_id=? AND status=?",
                    (match_id, TICKET_NORMAL)).fetchall()
                for t in tickets:
                    days = self.d.rule_for(t["ticket_type"])["有效天数"]
                    vf, vu = new_kickoff_at, new_kickoff_at + days * 86400
                    tb = dict(t)
                    tb.update({"status": TICKET_NORMAL, "valid_from": vf,
                               "valid_until": vu, "refunded_at": None})
                    tev_body = {**{k: t[k] for k in t.keys()},
                                "valid_from": vf, "valid_until": vu,
                                "change": "延期改期"}
                    self.s.append_event(self.s.new_event_id(), EV_TICKET, tev_body, at)
                    self.s.conn.execute(
                        "UPDATE tickets SET valid_from=?, valid_until=?, "
                        "updated_at=? WHERE ticket_no=?",
                        (vf, vu, at, t["ticket_no"]))
                affected = [t["ticket_no"] for t in tickets]
            else:
                affected = [r["ticket_no"] for r in self.s.conn.execute(
                    "SELECT DISTINCT ticket_no FROM tickets WHERE match_id=?",
                    (match_id,)).fetchall()]

            for no in affected:
                self._reconcile(no, at)
            return {"match_id": match_id, "status": status,
                    "affected_tickets": affected, "event_id": ev["event_id"]}

    def postpone_match(self, match_id: str, new_kickoff: str | float) -> dict:
        with self.txn():
            m = self.s.conn.execute(
                "SELECT status FROM matches WHERE match_id=?", (match_id,)
            ).fetchone()
            if not m:
                raise BusinessError(f"场次 {match_id} 不存在", 404)
            if m["status"] == MATCH_CANCELED:
                raise BusinessError("比赛已取消，不能再延期", 409)
        nk = new_kickoff if isinstance(new_kickoff, (int, float)) else parse_iso(new_kickoff)
        return self._set_match_status(match_id, MATCH_POSTPONED, nk, None)

    def cancel_match(self, match_id: str) -> dict:
        return self._set_match_status(match_id, MATCH_CANCELED, None, None)

    def issue_ticket(self, ticket_no: str, season_code: str, match_id: str,
                     ticket_type: str, holder: str,
                     kickoff_at: float | None = None) -> dict:
        if ticket_type not in self.d.ticket_types:
            raise BusinessError(f"票种 {ticket_type} 不在口径中")
        at = self.now()
        with self.txn():
            if self.s.conn.execute("SELECT 1 FROM tickets WHERE ticket_no=?",
                                   (ticket_no,)).fetchone():
                raise BusinessError(f"票 {ticket_no} 已存在", 409)
            m = self.s.conn.execute(
                "SELECT * FROM matches WHERE match_id=?", (match_id,)
            ).fetchone()
            if not m:
                raise BusinessError(f"场次 {match_id} 不存在", 404)
            if m["season_code"] != season_code:
                raise BusinessError("赛季与场次不一致")
            base = kickoff_at or (m["new_kickoff_at"] or m["kickoff_at"])
            days = self.d.rule_for(ticket_type)["有效天数"]
            vf, vu = base, base + days * 86400
            body = {"ticket_no": ticket_no, "season_code": season_code,
                    "match_id": match_id, "ticket_type": ticket_type,
                    "holder": holder, "issued_at": at,
                    "valid_from": vf, "valid_until": vu,
                    "status": TICKET_NORMAL, "refunded_at": None,
                    "change": "出票"}
            ev = self.s.append_event(self.s.new_event_id(), EV_TICKET, body, at)
            self.s.conn.execute(
                "INSERT INTO tickets(ticket_no,season_code,match_id,ticket_type,"
                "holder,issued_at,valid_from,valid_until,status,refunded_at,updated_at)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (ticket_no, season_code, match_id, ticket_type, holder, at,
                 vf, vu, TICKET_NORMAL, None, at))
            # 票券建档后重算（早前“票号不存在”的记录仍留在复核队列，
            # 由结算人员确认后放行；退款/取消等状态变化也借此即时归并）
            self._reconcile(ticket_no, at)
            return {"ticket_no": ticket_no, "event_id": ev["event_id"],
                    "valid_from": vf, "valid_until": vu}

    def refund_ticket(self, ticket_no: str) -> dict:
        at = self.now()
        with self.txn():
            t = self.s.conn.execute(
                "SELECT * FROM tickets WHERE ticket_no=?", (ticket_no,)
            ).fetchone()
            if not t:
                raise BusinessError(f"票 {ticket_no} 不存在", 404)
            if t["status"] == TICKET_REFUNDED:
                return {"ticket_no": ticket_no, "changed": False}
            body = {**{k: t[k] for k in t.keys()},
                    "status": TICKET_REFUNDED, "refunded_at": at, "change": "退款"}
            ev = self.s.append_event(self.s.new_event_id(), EV_TICKET, body, at)
            self.s.conn.execute(
                "UPDATE tickets SET status=?, refunded_at=?, updated_at=? "
                "WHERE ticket_no=?", (TICKET_REFUNDED, at, at, ticket_no))
            self._reconcile(ticket_no, at)
            return {"ticket_no": ticket_no, "refunded": True,
                    "event_id": ev["event_id"]}

    # ------------------------------------------------------------------ #
    # 核验：通用判定与入库
    # ------------------------------------------------------------------ #
    def _scenic_required(self, scenic: str):
        if scenic not in self.d.scenic_group:
            raise BusinessError(f"景区 {scenic} 不在口径分组中", 404)
        row = self.s.conn.execute(
            "SELECT period FROM scenics WHERE scenic=?", (scenic,)
        ).fetchone()
        if not row:
            raise BusinessError(f"景区 {scenic} 尚未开账配置", 409)
        return row["period"]

    def _evaluate(self, ticket, scenic: str, occurred_at: float,
                  holder: str) -> tuple[str, str | None]:
        """对一条新记录做静态判定。返回 (目标状态, 复核/撤销原因)。"""
        if ticket is None:
            return R_REVIEW, RV_UNKNOWN_TICKET
        if ticket["holder"] != holder:
            return R_REVIEW, RV_HOLDER_MISMATCH
        season = self.d.season_by_code.get(ticket["season_code"])
        if season and not (season.start <= ts_to_date(occurred_at) <= season.end):
            return R_REVOKED, REV_SEASON
        if ticket["status"] == TICKET_REFUNDED:
            return R_REVOKED, REV_REFUND
        m = self.s.conn.execute(
            "SELECT status FROM matches WHERE match_id=?", (ticket["match_id"],)
        ).fetchone()
        if m and m["status"] == MATCH_CANCELED:
            return R_REVOKED, REV_CANCEL
        if not (ticket["valid_from"] <= occurred_at <= ticket["valid_until"]):
            reason = REV_POSTPONE if (m and m["status"] == MATCH_POSTPONED) else REV_WINDOW
            return R_REVOKED, reason
        # 纸质票根易伪造：一律先复核，人工确认后才计补贴
        if ticket["ticket_type"] == "纸质票根":
            return R_REVIEW, RV_PAPER
        return R_VALID, None

    def _admit(self, *, channel: str, fingerprint: str, device_id: str | None,
               device_seq: int | None, ticket_no: str, holder: str,
               scenic: str, occurred_at: float, business_key: str,
               server_ts: float) -> dict:
        """登记一条核验记录并触发归并。调用方须在事务内。"""
        self._scenic_required(scenic)
        group = self.d.group_name_of(scenic)
        amount = self.d.subsidy_for(scenic)

        # —— 第一道闸：指纹完全相同 => 同一记录重发/重传 ——
        existing = self.s.conn.execute(
            "SELECT * FROM redemptions WHERE fingerprint=?", (fingerprint,)
        ).fetchone()
        if existing:
            return self._register_duplicate(existing, fingerprint, server_ts,
                                            note="指纹重复")

        # —— 第二道闸：同设备序号 / 同业务键 ——
        if device_id is not None:
            seq_row = self.s.conn.execute(
                "SELECT fingerprint FROM redemptions WHERE device_id=? AND device_seq=?",
                (device_id, device_seq)).fetchone()
            if seq_row and seq_row["fingerprint"] != fingerprint:
                # 同设备同序号出现不同签名（可能是伪造/重放攻击）：
                # 不吞掉也不出权益，直接挂复核并指向规范记录
                review_id = self._open_review(
                    fingerprint, ticket_no, scenic, RV_DEVICE_FORK,
                    occurred_at, server_ts,
                    extra={"device_id": device_id, "device_seq": device_seq,
                           "canonical_fingerprint": seq_row["fingerprint"]})
                canonical_row = self.s.conn.execute(
                    "SELECT * FROM redemptions WHERE fingerprint=?",
                    (seq_row["fingerprint"],)).fetchone()
                return self._row_result(canonical_row, extra={
                    "review_id": review_id,
                    "state": R_REVIEW,
                    "note": "设备同序号签名冲突，异常记录已转复核"})

        bk_row = self.s.conn.execute(
            "SELECT * FROM redemptions WHERE ticket_no=? AND scenic=? AND business_key=?",
            (ticket_no, scenic, business_key)).fetchone()
        if bk_row and bk_row["fingerprint"] != fingerprint:
            # 换签重发同一入园事实：只记审计，绝不产生第二份权益
            self._note_alias_duplicate(bk_row["fingerprint"], fingerprint,
                                       server_ts)
            return self._row_result(bk_row, duplicate=True,
                                    note="业务键重复，已归并到首条记录")

        ticket = self.s.conn.execute(
            "SELECT * FROM tickets WHERE ticket_no=?", (ticket_no,)
        ).fetchone()
        state, reason = self._evaluate(ticket, scenic, occurred_at, holder)

        ev_body = {"kind": "在线核验" if channel == CHANNEL_ONLINE else "补传",
                   "fingerprint": fingerprint, "channel": channel,
                   "device_id": device_id, "device_seq": device_seq,
                   "ticket_no": ticket_no, "holder": holder, "scenic": scenic,
                   "group": group, "amount_cents": amount,
                   "occurred_at": occurred_at, "business_key": business_key,
                   "state": state, "reason": reason}
        ev = self.s.append_event(self.s.new_event_id(), EV_REDEEM, ev_body, server_ts)
        self.s.conn.execute(
            "INSERT INTO redemptions(fingerprint,event_id,channel,device_id,"
            "device_seq,ticket_no,holder,scenic,group_name,amount_cents,"
            "occurred_at,server_ts,business_key,state,revoke_reason) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (fingerprint, ev["event_id"], channel, device_id, device_seq,
             ticket_no, holder, scenic, group, amount, occurred_at, server_ts,
             business_key, state, reason))

        review_id = None
        if state == R_REVIEW:
            review_id = self._open_review(fingerprint, ticket_no, scenic, reason,
                                          occurred_at, server_ts)

        result = self._row_result(
            self.s.conn.execute("SELECT * FROM redemptions WHERE fingerprint=?",
                                (fingerprint,)).fetchone())
        if state == R_VALID and ticket is not None:
            self._reconcile(ticket_no, server_ts)
            result = self._row_result(
                self.s.conn.execute("SELECT * FROM redemptions WHERE fingerprint=?",
                                    (fingerprint,)).fetchone())
        result["review_id"] = review_id
        return result

    def verify_online(self, ticket_no: str, holder: str, scenic: str,
                      business_key: str | None = None,
                      device_id: str | None = None,
                      occurred_at: float | None = None) -> dict:
        self._scenic_required(scenic)
        at = self.now()
        occurred_at = occurred_at if occurred_at is not None else at
        if device_id is not None:
            dev = self.s.conn.execute(
                "SELECT revoked FROM devices WHERE device_id=?", (device_id,)
            ).fetchone()
            if not dev:
                raise BusinessError(f"设备 {device_id} 未登记", 404)
            if dev["revoked"]:
                raise BusinessError(f"设备 {device_id} 已冻结", 403)
        business_key = business_key or f"ONL-{sha256_hex(str(at) + ticket_no + scenic)[:16]}"
        fp = online_fingerprint(ticket_no, holder, scenic, business_key, occurred_at)
        with self.txn():
            return self._admit(channel=CHANNEL_ONLINE, fingerprint=fp,
                               device_id=device_id, device_seq=None,
                               ticket_no=ticket_no, holder=holder, scenic=scenic,
                               occurred_at=occurred_at,
                               business_key=business_key, server_ts=at)

    # ------------------------------------------------------------------ #
    # 离线：签名信封 -> 存根(待补传) -> 补传判定
    # ------------------------------------------------------------------ #
    def _verify_envelope(self, record: dict[str, Any],
                         server_ts: float) -> tuple[dict, str]:
        """验设备、验签名、验时钟，返回 (规范负载, 设备密钥行)。"""
        needed = {"device_id", "seq", "ticket_no", "holder", "scenic",
                  "signed_at", "business_key", "sig"}
        missing = needed - record.keys()
        if missing:
            raise BusinessError(f"离线记录缺少字段: {sorted(missing)}", 422)
        dev = self.s.conn.execute(
            "SELECT * FROM devices WHERE device_id=?", (record["device_id"],)
        ).fetchone()
        if not dev:
            raise BusinessError(f"设备 {record['device_id']} 未登记", 404)
        if dev["revoked"]:
            raise BusinessError(f"设备 {record['device_id']} 已冻结", 403)
        payload = {
            "alg": record.get("alg", SIGN_ALGO),
            "device_id": record["device_id"],
            "seq": int(record["seq"]),
            "ticket_no": record["ticket_no"],
            "holder": record["holder"],
            "scenic": record["scenic"],
            "signed_at": round(float(record["signed_at"]), 3),
            "business_key": record["business_key"],
            "prev_sig": record.get("prev_sig"),
        }
        if payload["alg"] != SIGN_ALGO:
            raise BusinessError(f"不支持的签名算法 {payload['alg']}", 400)
        if not verify_signature(dev["secret"], payload, record["sig"]):
            raise BusinessError("签名无效：记录可能被篡改或密钥不符", 401)
        if payload["scenic"] != dev["scenic"]:
            raise BusinessError("设备与记录景区不一致", 401)
        return payload, dev

    def _clock_anomaly(self, payload: dict, server_ts: float) -> str | None:
        tol = self.d.offline["时钟容差秒"]
        limit = self.d.offline["补传时限天"] * 86400
        if payload["signed_at"] > server_ts + tol:
            return RV_CLOCK_AHEAD
        if server_ts - payload["signed_at"] > limit:
            return RV_LATE_UPLOAD
        return None

    def retain_offline(self, record: dict[str, Any],
                       server_ts: float | None = None) -> dict:
        """第一步：签名信封留存登记，状态=待补传（时钟异常直接挂复核）。"""
        at = server_ts if server_ts is not None else self.now()
        with self.txn():
            return self._retain_locked(record, at)

    def _retain_locked(self, record: dict[str, Any], at: float) -> dict:
        """留存的事务内实现，供一步到位流程复用（避免嵌套事务）。"""
        self._scenic_required(record["scenic"])
        payload, _dev = self._verify_envelope(record, at)
        fp = offline_fingerprint(payload)
        existing = self.s.conn.execute(
            "SELECT * FROM redemptions WHERE fingerprint=?", (fp,)
        ).fetchone()
        if existing:
            return self._register_duplicate(existing, fp, at,
                                            note="存根重复送达")
        # 同设备序号出现不同签名（伪造/重放）：不吞掉，挂复核并指向规范记录
        seq_row = self.s.conn.execute(
            "SELECT * FROM redemptions WHERE device_id=? AND device_seq=?",
            (payload["device_id"], payload["seq"])).fetchone()
        if seq_row and seq_row["fingerprint"] != fp:
            self._open_review(fp, payload["ticket_no"], payload["scenic"],
                              RV_DEVICE_FORK, payload["signed_at"], at,
                              extra={"device_id": payload["device_id"],
                                     "device_seq": payload["seq"],
                                     "canonical_fingerprint": seq_row["fingerprint"]})
            return self._row_result(seq_row, extra={
                "state": R_REVIEW,
                "note": "设备同序号签名冲突，异常记录已转复核"})
        # 同业务键的存根已存在（可能来自其他渠道）：归并，不重复建账
        bk = self.s.conn.execute(
            "SELECT * FROM redemptions WHERE ticket_no=? AND scenic=? "
            "AND business_key=?",
            (payload["ticket_no"], payload["scenic"],
             payload["business_key"])).fetchone()
        if bk:
            self._note_alias_duplicate(bk["fingerprint"], fp, at)
            return self._row_result(bk, duplicate=True,
                                    note="业务键重复，已归并到首条记录")

        anomaly = self._clock_anomaly(payload, at)
        state = R_REVIEW if anomaly else R_PENDING
        amount = self.d.subsidy_for(payload["scenic"])
        body = {"kind": "签名留存", "fingerprint": fp,
                "channel": CHANNEL_OFFLINE,
                "device_id": payload["device_id"],
                "device_seq": payload["seq"],
                "ticket_no": payload["ticket_no"],
                "holder": payload["holder"], "scenic": payload["scenic"],
                "group": self.d.group_name_of(payload["scenic"]),
                "amount_cents": amount,
                "occurred_at": payload["signed_at"],
                "business_key": payload["business_key"],
                "state": state, "reason": anomaly,
                "prev_sig": payload["prev_sig"]}
        ev = self.s.append_event(self.s.new_event_id(), EV_REDEEM, body, at)
        self.s.conn.execute(
            "INSERT INTO redemptions(fingerprint,event_id,channel,device_id,"
            "device_seq,ticket_no,holder,scenic,group_name,amount_cents,"
            "occurred_at,server_ts,business_key,state,revoke_reason) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (fp, ev["event_id"], CHANNEL_OFFLINE, payload["device_id"],
             payload["seq"], payload["ticket_no"], payload["holder"],
             payload["scenic"], body["group"], amount,
             payload["signed_at"], at, payload["business_key"],
             state, anomaly))
        review_id = None
        if anomaly:
            review_id = self._open_review(fp, payload["ticket_no"],
                                          payload["scenic"], anomaly,
                                          payload["signed_at"], at,
                                          extra={"signed_at": payload["signed_at"]})
        res = self._row_result(self.s.conn.execute(
            "SELECT * FROM redemptions WHERE fingerprint=?", (fp,)).fetchone())
        res["review_id"] = review_id
        return res

    def complete_offline(self, record: dict[str, Any],
                         server_ts: float | None = None) -> dict:
        """第二步：补传判定。记录必须已通过签名留存；重复补传幂等。"""
        at = server_ts if server_ts is not None else self.now()
        with self.txn():
            payload, _dev = self._verify_envelope(record, at)
            fp = offline_fingerprint(payload)
            row = self.s.conn.execute(
                "SELECT * FROM redemptions WHERE fingerprint=?", (fp,)
            ).fetchone()
            if not row:
                # 允许一步到位：没做过留存则先补登记（同样做时钟检查）
                retained = self._retain_locked(record, at)
                if retained["state"] != R_PENDING:
                    return retained
                row = self.s.conn.execute(
                    "SELECT * FROM redemptions WHERE fingerprint=?", (fp,)
                ).fetchone()
            if row["state"] != R_PENDING:
                # 已补传/已撤销/复核中：补传幂等，返回现状并记一次重放
                return self._register_duplicate(row, fp, at,
                                                note="补传重复送达")

            ticket = self.s.conn.execute(
                "SELECT * FROM tickets WHERE ticket_no=?", (row["ticket_no"],)
            ).fetchone()
            state, reason = self._evaluate(ticket, row["scenic"],
                                           row["occurred_at"], row["holder"])
            self.s.append_event(self.s.new_event_id(), EV_REDEEM,
                                {"kind": "补传判定", "fingerprint": fp,
                                 "channel": CHANNEL_OFFLINE,
                                 "ticket_no": row["ticket_no"],
                                 "scenic": row["scenic"],
                                 "occurred_at": row["occurred_at"],
                                 "state": state, "reason": reason}, at)
            self.s.conn.execute(
                "UPDATE redemptions SET state=?, revoke_reason=? WHERE fingerprint=?",
                (state, reason, fp))
            review_id = None
            if state == R_REVIEW:
                review_id = self._open_review(fp, row["ticket_no"],
                                              row["scenic"], reason,
                                              row["occurred_at"], at)
            if state == R_VALID and ticket is not None:
                self._reconcile(row["ticket_no"], at)
            return self._row_result(self.s.conn.execute(
                "SELECT * FROM redemptions WHERE fingerprint=?", (fp,)).fetchone(),
                extra={"review_id": review_id})

    def submit_offline(self, record: dict[str, Any],
                       server_ts: float | None = None) -> dict:
        """一步到位：留存 + 补传（网络尚可的网点直接调用）。"""
        at = server_ts if server_ts is not None else self.now()
        with self.txn():
            retained = self._retain_locked(record, at)
            if retained["state"] != R_PENDING:
                return retained
            payload, _dev = self._verify_envelope(record, at)
            fp = offline_fingerprint(payload)
            row = self.s.conn.execute(
                "SELECT * FROM redemptions WHERE fingerprint=?", (fp,)
            ).fetchone()
            ticket = self.s.conn.execute(
                "SELECT * FROM tickets WHERE ticket_no=?", (row["ticket_no"],)
            ).fetchone()
            state, reason = self._evaluate(ticket, row["scenic"],
                                           row["occurred_at"], row["holder"])
            self.s.append_event(self.s.new_event_id(), EV_REDEEM,
                                {"kind": "补传判定", "fingerprint": fp,
                                 "channel": CHANNEL_OFFLINE,
                                 "ticket_no": row["ticket_no"],
                                 "scenic": row["scenic"],
                                 "occurred_at": row["occurred_at"],
                                 "state": state, "reason": reason}, at)
            self.s.conn.execute(
                "UPDATE redemptions SET state=?, revoke_reason=? WHERE fingerprint=?",
                (state, reason, fp))
            if state == R_REVIEW:
                self._open_review(fp, row["ticket_no"], row["scenic"], reason,
                                  row["occurred_at"], at)
            if state == R_VALID and ticket is not None:
                self._reconcile(row["ticket_no"], at)
            return self._row_result(self.s.conn.execute(
                "SELECT * FROM redemptions WHERE fingerprint=?", (fp,)).fetchone())

    def sweep_stubs(self, server_ts: float | None = None) -> dict:
        """把超过补传时限仍停留在“待补传”的存根转入复核。"""
        at = server_ts if server_ts is not None else self.now()
        limit = self.d.offline["补传时限天"] * 86400
        with self.txn():
            rows = self.s.conn.execute(
                "SELECT * FROM redemptions WHERE state=? AND ?-occurred_at>?",
                (R_PENDING, at, limit)).fetchall()
            swept = []
            for r in rows:
                rid = self._open_review(r["fingerprint"], r["ticket_no"],
                                        r["scenic"], RV_STUB_EXPIRED,
                                        r["occurred_at"], at)
                self.s.append_event(self.s.new_event_id(), EV_REDEEM,
                                    {"kind": "存根逾期",
                                     "fingerprint": r["fingerprint"],
                                     "state": R_REVIEW,
                                     "reason": RV_STUB_EXPIRED}, at)
                self.s.conn.execute(
                    "UPDATE redemptions SET state=?, revoke_reason=? "
                    "WHERE fingerprint=?", (R_REVIEW, RV_STUB_EXPIRED,
                                            r["fingerprint"]))
                swept.append({"fingerprint": r["fingerprint"],
                              "review_id": rid})
            return {"swept": swept, "count": len(swept)}

    # ------------------------------------------------------------------ #
    # 复核
    # ------------------------------------------------------------------ #
    def _open_review(self, fingerprint: str, ticket_no: str | None,
                     scenic: str | None, reason: str, occurred_at: float,
                     at: float, extra: dict | None = None) -> str:
        """调用方须在事务内。先建复核单，再把单号写入台账事件。"""
        cur = self.s.conn.execute(
            "INSERT INTO reviews(fingerprint,ticket_no,scenic,reason,"
            "occurred_at,created_at,state) VALUES(?,?,?,?,?,?,?)",
            (fingerprint, ticket_no, scenic, reason, occurred_at, at, "待复核"))
        review_id = cur.lastrowid
        body = {"kind": "建立", "review_id": review_id,
                "fingerprint": fingerprint,
                "ticket_no": ticket_no, "scenic": scenic, "reason": reason,
                "occurred_at": occurred_at}
        if extra:
            body.update(extra)
        self.s.append_event(self.s.new_event_id(), EV_REVIEW, body, at)
        self.s.conn.execute(
            "UPDATE reviews SET decision_event_id=NULL WHERE id=?", (review_id,))
        return str(review_id)

    def list_reviews(self, state: str = "待复核") -> list[dict]:
        sql = "SELECT * FROM reviews"
        args: tuple = ()
        if state:
            sql += " WHERE state=?"
            args = (state,)
        sql += " ORDER BY id"
        return [dict(r) for r in self.s.conn.execute(sql, args).fetchall()]

    def decide_review(self, review_id: int, approve: bool,
                      decided_by: str) -> dict:
        at = self.now()
        with self.txn():
            rv = self.s.conn.execute(
                "SELECT * FROM reviews WHERE id=?", (review_id,)
            ).fetchone()
            if not rv:
                raise BusinessError(f"复核单 {review_id} 不存在", 404)
            if rv["state"] != "待复核":
                raise BusinessError(f"复核单 {review_id} 已结论：{rv['state']}", 409)
            decision = "已通过" if approve else "已拒绝"
            row = self.s.conn.execute(
                "SELECT * FROM redemptions WHERE fingerprint=?",
                (rv["fingerprint"],)).fetchone()
            body = {"kind": "结论", "review_id": review_id,
                    "fingerprint": rv["fingerprint"],
                    "ticket_no": rv["ticket_no"], "scenic": rv["scenic"],
                    "reason": rv["reason"], "decision": decision,
                    "decided_by": decided_by}
            ev = self.s.append_event(self.s.new_event_id(), EV_REVIEW, body, at)
            self.s.conn.execute(
                "UPDATE reviews SET state=?, decided_at=?, decided_by=?, "
                "decision_event_id=? WHERE id=?",
                (decision, at, decided_by, ev["event_id"], review_id))
            if not row:
                return {"review_id": review_id, "decision": decision,
                        "redemption": None}
            if approve:
                # 人工确认票根真实：背书后加入候选池参与名额竞争
                ticket = self.s.conn.execute(
                    "SELECT 1 FROM tickets WHERE ticket_no=?",
                    (row["ticket_no"],)).fetchone()
                if ticket:
                    self._reconcile(row["ticket_no"], at)
                elif row["state"] == R_REVIEW:
                    # 票券尚未建档（离线早到）：人工背书直接置有效，待票券建档后再归并
                    self.s.conn.execute(
                        "UPDATE redemptions SET state=?, revoke_reason=NULL, "
                        "manual_override=1 WHERE fingerprint=?",
                        (R_VALID, rv["fingerprint"]))
                    self._promise_or_settle(self.s.conn.execute(
                        "SELECT * FROM redemptions WHERE fingerprint=?",
                        (rv["fingerprint"],)).fetchone(), at)
            else:
                self.s.conn.execute(
                    "UPDATE redemptions SET state=?, revoke_reason=? "
                    "WHERE fingerprint=?",
                    (R_REVOKED, REV_REVIEW_REJECT, rv["fingerprint"]))
                self._revoke_settled_if_needed(
                    self.s.conn.execute(
                        "SELECT * FROM redemptions WHERE fingerprint=?",
                        (rv["fingerprint"],)).fetchone(),
                    REV_REVIEW_REJECT, at)
                t = self.s.conn.execute(
                    "SELECT 1 FROM tickets WHERE ticket_no=?",
                    (row["ticket_no"],)).fetchone()
                if t:
                    self._reconcile(row["ticket_no"], at)
            return {"review_id": review_id, "decision": decision,
                    "redemption": self._row_result(self.s.conn.execute(
                        "SELECT * FROM redemptions WHERE fingerprint=?",
                        (rv["fingerprint"],)).fetchone())}

    def manual_revoke(self, fingerprint: str, decided_by: str,
                      reason: str = REV_MANUAL, note: str | None = None) -> dict:
        if reason not in (REV_MANUAL, REV_CANCEL, REV_REFUND, REV_POSTPONE):
            raise BusinessError(f"不支持的人工撤销原因 {reason}")
        at = self.now()
        with self.txn():
            row = self.s.conn.execute(
                "SELECT * FROM redemptions WHERE fingerprint=?", (fingerprint,)
            ).fetchone()
            if not row:
                raise BusinessError("核销记录不存在", 404)
            if row["state"] == R_REVOKED and row["revoke_reason"] == reason:
                return self._row_result(row, note="已处于该撤销状态")
            self.s.append_event(self.s.new_event_id(), EV_ADJUST,
                                {"kind": ADJUST_VOID, "fingerprint": fingerprint,
                                 "ticket_no": row["ticket_no"],
                                 "scenic": row["scenic"],
                                 "amount_cents": -row["amount_cents"],
                                 "reason": reason, "by": decided_by,
                                 "note": note, "from": row["state"],
                                 "to": R_REVOKED}, at)
            self.s.conn.execute(
                "UPDATE redemptions SET state=?, revoke_reason=? WHERE fingerprint=?",
                (R_REVOKED, reason, fingerprint))
            self._revoke_settled_if_needed(
                self.s.conn.execute("SELECT * FROM redemptions WHERE fingerprint=?",
                                    (fingerprint,)).fetchone(),
                reason, at)
            ticket = self.s.conn.execute(
                "SELECT 1 FROM tickets WHERE ticket_no=?",
                (row["ticket_no"],)).fetchone()
            if ticket:
                self._reconcile(row["ticket_no"], at)
            return self._row_result(self.s.conn.execute(
                "SELECT * FROM redemptions WHERE fingerprint=?",
                (fingerprint,)).fetchone())

    # ------------------------------------------------------------------ #
    # 确定性归并（与到达顺序无关的核心）
    # ------------------------------------------------------------------ #
    def _reconcile(self, ticket_no: str, at: float):
        """对一张票的全部记录重算有效集合，差异以调整事件落账。

        有效集合 = 通过刚性校验（含人工复核 override）的记录，
        按 (occurred_at, fingerprint) 排序取限兑名额内的前 N 条；
        已清算记录被刚性撤销时生成负向冲正，落入后续批次。
        """
        t = self.s.conn.execute(
            "SELECT * FROM tickets WHERE ticket_no=?", (ticket_no,)
        ).fetchone()
        if t is None:
            return
        m = self.s.conn.execute(
            "SELECT * FROM matches WHERE match_id=?", (t["match_id"],)
        ).fetchone()
        quota = self.d.rule_for(t["ticket_type"])["限兑次数"]

        rows = self.s.conn.execute(
            "SELECT * FROM redemptions WHERE ticket_no=? ORDER BY occurred_at, fingerprint",
            (ticket_no,)).fetchall()

        # 1) 逐条计算刚性判定
        desired: dict[str, tuple[str, str | None]] = {}
        for r in rows:
            if r["state"] == R_PENDING:
                desired[r["fingerprint"]] = (R_PENDING, r["revoke_reason"])
                continue
            # 票券/场次生命周期的刚性结论优先（退款、取消、窗口、赛季）
            hard = self._hard_reason(t, m, r)
            if hard:
                desired[r["fingerprint"]] = (R_REVOKED, hard)
                continue
            # 已有人工刚性结论（人工撤销/复核拒绝）：黏性，不再复活
            if r["revoke_reason"] in STICKY_REASONS:
                desired[r["fingerprint"]] = (R_REVOKED, r["revoke_reason"])
                continue
            # 待复核且仍有未结复核单：冻结，不占名额也不出补贴
            open_review = self.s.conn.execute(
                "SELECT 1 FROM reviews WHERE fingerprint=? AND state='待复核'",
                (r["fingerprint"],)).fetchone()
            if r["state"] == R_REVIEW and open_review:
                desired[r["fingerprint"]] = (R_REVIEW, r["revoke_reason"])
                continue
            # 复核通过（纸质票根防伪/时钟异常等）：人工背书后进入候选池
            desired[r["fingerprint"]] = ("候选", None)

        # 2) 候选记录按发生时间竞争名额
        candidates = [(r["occurred_at"], r["fingerprint"]) for r in rows
                      if desired[r["fingerprint"]][0] == "候选"]
        winners = {fp for _, fp in candidates[:quota]}
        for r in rows:
            fp = r["fingerprint"]
            if desired[fp][0] == "候选":
                if fp in winners:
                    desired[fp] = (R_SETTLED if r["state"] == R_SETTLED else R_VALID, None)
                else:
                    desired[fp] = (R_REVOKED, REV_QUOTA)

        # 3) 差异落账
        for r in rows:
            want_state, want_reason = desired[r["fingerprint"]]
            if want_state == R_PENDING or want_state == R_REVIEW:
                continue
            cur = r["state"]
            if cur == want_state and r["revoke_reason"] == want_reason:
                if want_state == R_VALID:
                    self._promise_or_settle(r, at)
                continue
            self._apply_transition(r, want_state, want_reason, at)

    def _hard_reason(self, t, m, r) -> str | None:
        """依据票券/场次当前生命周期计算刚性撤销原因（无则 None）。"""
        season = self.d.season_by_code.get(t["season_code"])
        if season and not (season.start <= ts_to_date(r["occurred_at"]) <= season.end):
            return REV_SEASON
        if t["status"] == TICKET_REFUNDED:
            return REV_REFUND
        if m and m["status"] == MATCH_CANCELED:
            return REV_CANCEL
        if not (t["valid_from"] <= r["occurred_at"] <= t["valid_until"]):
            if m and m["status"] == MATCH_POSTPONED:
                return REV_POSTPONE
            return REV_WINDOW
        return None

    def _apply_transition(self, r, want_state: str, want_reason: str | None,
                          at: float):
        fp = r["fingerprint"]
        cur = r["state"]
        if want_state == R_REVOKED:
            self.s.append_event(self.s.new_event_id(), EV_ADJUST,
                                {"kind": ADJUST_VOID, "fingerprint": fp,
                                 "ticket_no": r["ticket_no"],
                                 "scenic": r["scenic"],
                                 "amount_cents": -r["amount_cents"],
                                 "reason": want_reason,
                                 "from": cur, "to": R_REVOKED}, at)
            self.s.conn.execute(
                "UPDATE redemptions SET state=?, revoke_reason=? WHERE fingerprint=?",
                (R_REVOKED, want_reason, fp))
            refreshed = self.s.conn.execute(
                "SELECT * FROM redemptions WHERE fingerprint=?", (fp,)).fetchone()
            self._revoke_settled_if_needed(refreshed, want_reason, at)
        elif want_state == R_VALID:
            # 软撤销恢复（名额因刚性记录撤销而腾出）
            self.s.append_event(self.s.new_event_id(), EV_ADJUST,
                                {"kind": "恢复", "fingerprint": fp,
                                 "ticket_no": r["ticket_no"],
                                 "scenic": r["scenic"],
                                 "amount_cents": r["amount_cents"],
                                 "reason": "名额恢复",
                                 "from": cur, "to": R_VALID}, at)
            self.s.conn.execute(
                "UPDATE redemptions SET state=?, revoke_reason=NULL "
                "WHERE fingerprint=?", (R_VALID, fp))
            self._promise_or_settle(
                self.s.conn.execute("SELECT * FROM redemptions WHERE fingerprint=?",
                                    (fp,)).fetchone(), at)

    def _revoke_settled_if_needed(self, r, reason: str, at: float):
        """撤销的账务处理：已清算 -> 负向冲正；已挂往期追补但未出账 -> 作废追补。

        两种追回都只发生一次，且按当时状态选择方向，避免“补贴已撤销、
        追补仍出账”的重复/错误补贴。
        """
        if r is None or r["state"] != R_REVOKED:
            return
        # 1) 已在某批次出账：负向冲正（一条记录最多一笔）
        if r["settled_batch_id"]:
            exists = self.s.conn.execute(
                "SELECT 1 FROM adjustments WHERE ref_fingerprint=? AND kind=?",
                (r["fingerprint"], ADJUST_REVERSAL)).fetchone()
            if not exists:
                amount = -r["amount_cents"]
                body = {"kind": ADJUST_REVERSAL,
                        "ref_fingerprint": r["fingerprint"],
                        "ref_batch_id": r["settled_batch_id"],
                        "ticket_no": r["ticket_no"], "scenic": r["scenic"],
                        "group": r["group_name"], "amount_cents": amount,
                        "occurred_at": at, "reason": reason}
                ev = self.s.append_event(self.s.new_event_id(), EV_ADJUST,
                                         body, at)
                self.s.conn.execute(
                    "INSERT INTO adjustments(event_id,ref_fingerprint,"
                    "ref_batch_id,kind,amount_cents,scenic,group_name,"
                    "ticket_no,occurred_at,reason,state) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (ev["event_id"], r["fingerprint"],
                     r["settled_batch_id"], ADJUST_REVERSAL, amount,
                     r["scenic"], r["group_name"], r["ticket_no"], at,
                     reason, "待结"))
            return
        # 2) 未出账但已挂往期追补（待结）：把追补作废，不再进入任何批次
        if r["carryover"]:
            pending = self.s.conn.execute(
                "SELECT event_id FROM adjustments WHERE ref_fingerprint=? "
                "AND kind=? AND state='待结'",
                (r["fingerprint"], ADJUST_SUBSIDY)).fetchone()
            if pending:
                self.s.append_event(self.s.new_event_id(), EV_ADJUST,
                                    {"kind": "追补作废",
                                     "ref_adjust_event": pending["event_id"],
                                     "ref_fingerprint": r["fingerprint"],
                                     "scenic": r["scenic"],
                                     "reason": reason}, at)
                self.s.conn.execute(
                    "UPDATE adjustments SET state='已作废' WHERE event_id=?",
                    (pending["event_id"],))

    def _promise_or_settle(self, r, at: float):
        """记录变为有效时，若所属周期批次已定稿，生成往期追补。

        已存在待结追补或追补已出账时不重复生成；若此前的待结追补被
        “追补作废”取消（记录曾短暂撤销），允许重新挂账。
        """
        if r is None or r["state"] != R_VALID:
            return
        existing = self.s.conn.execute(
            "SELECT state FROM adjustments WHERE ref_fingerprint=? AND kind=?",
            (r["fingerprint"], ADJUST_SUBSIDY)).fetchall()
        if any(x["state"] in ("待结", "已结") for x in existing):
            return
        period = self.s.conn.execute(
            "SELECT period FROM scenics WHERE scenic=?", (r["scenic"],)
        ).fetchone()
        if not period:
            return
        key = period_key(period["period"], ts_to_date(r["occurred_at"]))
        batch = self.s.conn.execute(
            "SELECT 1 FROM batches WHERE scenic=? AND period=? AND period_key=?",
            (r["scenic"], period["period"], key)).fetchone()
        if not batch:
            self.s.conn.execute(
                "UPDATE redemptions SET carryover=0 WHERE fingerprint=?",
                (r["fingerprint"],))
            return
        body = {"kind": ADJUST_SUBSIDY, "ref_fingerprint": r["fingerprint"],
                "ticket_no": r["ticket_no"], "scenic": r["scenic"],
                "group": r["group_name"], "amount_cents": r["amount_cents"],
                "occurred_at": at, "reason": "往期补结",
                "origin_period_key": key}
        ev = self.s.append_event(self.s.new_event_id(), EV_ADJUST, body, at)
        self.s.conn.execute(
            "INSERT INTO adjustments(event_id,ref_fingerprint,kind,amount_cents,"
            "scenic,group_name,ticket_no,occurred_at,reason,state) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (ev["event_id"], r["fingerprint"], ADJUST_SUBSIDY,
             r["amount_cents"], r["scenic"], r["group_name"], r["ticket_no"],
             at, "往期补结", "待结"))
        self.s.conn.execute(
            "UPDATE redemptions SET carryover=1 WHERE fingerprint=?",
            (r["fingerprint"],))

    # ------------------------------------------------------------------ #
    # 重放审计与查询
    # ------------------------------------------------------------------ #
    def _register_duplicate(self, existing_row, fp: str, at: float,
                            note: str) -> dict:
        row = self.s.conn.execute(
            "SELECT * FROM replay_audit WHERE fingerprint=?", (fp,)
        ).fetchone()
        if row:
            self.s.conn.execute(
                "UPDATE replay_audit SET dup_count=dup_count+1, last_seen=?, note=?"
                " WHERE fingerprint=?", (at, note, fp))
        else:
            self.s.conn.execute(
                "INSERT INTO replay_audit(fingerprint,channel,first_event_id,"
                "first_seen,last_seen,dup_count,note) VALUES(?,?,?,?,?,1,?)",
                (fp, existing_row["channel"], existing_row["event_id"],
                 existing_row["server_ts"], at, note))
        self.s.append_event(self.s.new_event_id(), EV_DEDUP,
                            {"fingerprint": fp,
                             "ticket_no": existing_row["ticket_no"],
                             "scenic": existing_row["scenic"],
                             "business_key": existing_row["business_key"],
                             "note": note}, at)
        return self._row_result(existing_row, duplicate=True, note=note)

    def _note_alias_duplicate(self, canonical_fp: str, alias_fp: str, at: float):
        self.s.append_event(self.s.new_event_id(), EV_DEDUP,
                            {"fingerprint": alias_fp, "canonical_fingerprint": canonical_fp,
                             "note": "异签名同业务键"}, at)
        self.s.conn.execute(
            "INSERT INTO replay_audit(fingerprint,channel,first_event_id,"
            "first_seen,last_seen,dup_count,note) VALUES(?,?,?,?,?,1,?)",
            (alias_fp, CHANNEL_OFFLINE, "-", at, at,
             f"异签名同业务键，归并至 {canonical_fp}"))

    @staticmethod
    def _row_result(row, duplicate: bool = False, note: str | None = None,
                    extra: dict | None = None) -> dict:
        if row is None:
            raise BusinessError("核销记录不存在", 404)
        d = {
            "fingerprint": row["fingerprint"], "state": row["state"],
            "channel": row["channel"], "ticket_no": row["ticket_no"],
            "holder": row["holder"], "scenic": row["scenic"],
            "group": row["group_name"], "amount_cents": row["amount_cents"],
            "occurred_at": row["occurred_at"],
            "business_key": row["business_key"],
            "revoke_reason": row["revoke_reason"],
            "settled_batch_id": row["settled_batch_id"],
            "duplicate": duplicate,
        }
        if note:
            d["note"] = note
        if extra:
            d.update(extra)
        return d

    def get_redemption(self, fingerprint: str) -> dict:
        row = self.s.conn.execute(
            "SELECT * FROM redemptions WHERE fingerprint=?", (fingerprint,)
        ).fetchone()
        return self._row_result(row)

    def ticket_trail(self, ticket_no: str) -> dict:
        t = self.s.conn.execute(
            "SELECT * FROM tickets WHERE ticket_no=?", (ticket_no,)
        ).fetchone()
        reds = [dict(r) for r in self.s.conn.execute(
            "SELECT * FROM redemptions WHERE ticket_no=? "
            "ORDER BY occurred_at, fingerprint", (ticket_no,)).fetchall()]
        # 台账轨迹：事件体顶层带该票号，或批次明细中引用了该票
        events = []
        for e in self.s.iter_events(0):
            b = e["body"]
            hit = b.get("ticket_no") == ticket_no
            if not hit and e["type"] == EV_BATCH:
                hit = any(i.get("ticket_no") == ticket_no for i in b.get("items", []))
            if hit:
                events.append({"seq": e["seq"], "ts": e["ts"],
                               "type": e["type"], "body": b})
        return {"ticket": dict(t) if t else None,
                "redemptions": reds, "events": events}

    def list_replay_audit(self) -> list[dict]:
        return [dict(r) for r in self.s.conn.execute(
            "SELECT * FROM replay_audit ORDER BY last_seen").fetchall()]

    def list_stubs(self, device_id: str | None = None) -> list[dict]:
        sql = "SELECT * FROM redemptions WHERE state=?"
        args: list = [R_PENDING]
        if device_id:
            sql += " AND device_id=?"
            args.append(device_id)
        return [dict(r) for r in self.s.conn.execute(
                sql + " ORDER BY occurred_at", args).fetchall()]

    # ------------------------------------------------------------------ #
    # 台账重放：物化状态整体重建
    # ------------------------------------------------------------------ #
    def rebuild_state(self) -> dict:
        with self.txn():
            self.s.wipe_state()
            counts: dict[str, int] = {}
            for e in self.s.iter_events(0):
                self._reduce(e)
                counts[e["type"]] = counts.get(e["type"], 0) + 1
            ok, broken = self.s.verify_chain()
            return {"replayed_events": counts, "chain_ok": ok,
                    "broken_at": broken,
                    "chain_tip": self.s.chain_tip()}

    def _reduce(self, e: dict):
        """按台账事件重建一行物化状态。与写入路径保持同一事件口径。"""
        c = self.s.conn
        b = e["body"]
        kind = b.get("kind")
        if e["type"] == EV_CONFIG:
            c.execute("INSERT OR REPLACE INTO scenics(scenic,group_name,period)"
                      " VALUES(?,?,?)", (b["scenic"], b["group"], b["period"]))
        elif e["type"] == EV_DEVICE:
            c.execute("INSERT OR REPLACE INTO devices(device_id,scenic,secret,"
                      "revoked,registered_at) VALUES(?,?,?,?,?)",
                      (b["device_id"], b["scenic"], b["secret"],
                       1 if b["revoked"] else 0, e["ts"]))
        elif e["type"] == EV_MATCH:
            c.execute("INSERT OR REPLACE INTO matches(match_id,season_code,"
                      "opponent,kickoff_at,status,new_kickoff_at,updated_at)"
                      " VALUES(?,?,?,?,?,?,?)",
                      (b["match_id"], b["season_code"], b["opponent"],
                       b["kickoff_at"], b["status"], b.get("new_kickoff_at"),
                       e["ts"]))
        elif e["type"] == EV_TICKET:
            c.execute("INSERT OR REPLACE INTO tickets(ticket_no,season_code,"
                      "match_id,ticket_type,holder,issued_at,valid_from,"
                      "valid_until,status,refunded_at,updated_at) "
                      "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                      (b["ticket_no"], b["season_code"], b["match_id"],
                       b["ticket_type"], b["holder"], b["issued_at"],
                       b["valid_from"], b["valid_until"], b["status"],
                       b.get("refunded_at"), e["ts"]))
        elif e["type"] == EV_REDEEM:
            if kind in ("在线核验", "签名留存", "补传"):
                c.execute("INSERT OR IGNORE INTO redemptions(fingerprint,event_id,"
                          "channel,device_id,device_seq,ticket_no,holder,scenic,"
                          "group_name,amount_cents,occurred_at,server_ts,"
                          "business_key,state,revoke_reason) "
                          "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                          (b["fingerprint"], e["event_id"], b["channel"],
                           b.get("device_id"), b.get("device_seq"),
                           b["ticket_no"], b["holder"], b["scenic"], b["group"],
                           b["amount_cents"], b["occurred_at"], e["ts"],
                           b["business_key"], b["state"], b.get("reason")))
            elif kind == "补传判定":
                c.execute("UPDATE redemptions SET state=?, revoke_reason=? "
                          "WHERE fingerprint=?",
                          (b["state"], b.get("reason"), b["fingerprint"]))
            elif kind == "存根逾期":
                c.execute("UPDATE redemptions SET state=?, revoke_reason=? "
                          "WHERE fingerprint=?",
                          (b["state"], b["reason"], b["fingerprint"]))
        elif e["type"] == EV_DEDUP:
            fp = b["fingerprint"]
            row = c.execute("SELECT 1 FROM replay_audit WHERE fingerprint=?",
                            (fp,)).fetchone()
            if row:
                c.execute("UPDATE replay_audit SET dup_count=dup_count+1,"
                          "last_seen=? WHERE fingerprint=?", (e["ts"], fp))
            else:
                red = c.execute("SELECT * FROM redemptions WHERE fingerprint=?",
                                (fp,)).fetchone()
                c.execute("INSERT OR IGNORE INTO replay_audit(fingerprint,channel,"
                          "first_event_id,first_seen,last_seen,dup_count,note) "
                          "VALUES(?,?,?,?,?,1,?)",
                          (fp, red["channel"] if red else "offline",
                           red["event_id"] if red else "-",
                           red["server_ts"] if red else e["ts"], e["ts"],
                           b.get("note", "重复送达")))
        elif e["type"] == EV_REVIEW:
            if kind == "建立":
                c.execute(
                    "INSERT INTO reviews(id,fingerprint,ticket_no,scenic,reason,"
                    "occurred_at,created_at,state) VALUES(?,?,?,?,?,?,?,?)",
                    (b["review_id"], b["fingerprint"], b.get("ticket_no"),
                     b.get("scenic"), b["reason"], b["occurred_at"], e["ts"],
                     "待复核"))
            else:
                c.execute("UPDATE reviews SET state=?, decided_at=?, decided_by=?,"
                          "decision_event_id=? WHERE id=?",
                          (b["decision"], e["ts"], b["decided_by"],
                           e["event_id"], b["review_id"]))
                if b["decision"] == "已通过":
                    # 置为有效作为中间态：若票已建档，后续“恢复/撤销”事件
                    # 会给出名额竞争后的最终态；票未建档时这就是最终态。
                    c.execute("UPDATE redemptions SET state=?, revoke_reason=NULL,"
                              "manual_override=1 WHERE fingerprint=?",
                              (R_VALID, b["fingerprint"]))
                else:
                    c.execute("UPDATE redemptions SET state=?, revoke_reason=? "
                              "WHERE fingerprint=?",
                              (R_REVOKED, REV_REVIEW_REJECT, b["fingerprint"]))
        elif e["type"] == EV_ADJUST:
            if kind in (ADJUST_VOID, "恢复"):
                c.execute("UPDATE redemptions SET state=?, revoke_reason=? "
                          "WHERE fingerprint=?",
                          (b["to"], b.get("reason"), b["fingerprint"]))
                if kind == "恢复":
                    c.execute("UPDATE redemptions SET revoke_reason=NULL "
                              "WHERE fingerprint=?", (b["fingerprint"],))
            elif kind in (ADJUST_REVERSAL, ADJUST_SUBSIDY):
                c.execute("INSERT OR IGNORE INTO adjustments(event_id,"
                          "ref_fingerprint,ref_batch_id,kind,amount_cents,scenic,"
                          "group_name,ticket_no,occurred_at,reason,state) "
                          "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                          (e["event_id"], b["ref_fingerprint"],
                           b.get("ref_batch_id"), kind, b["amount_cents"],
                           b["scenic"], b["group"], b["ticket_no"],
                           b["occurred_at"], b["reason"], "待结"))
                if kind == ADJUST_SUBSIDY:
                    c.execute("UPDATE redemptions SET carryover=1 WHERE fingerprint=?",
                              (b["ref_fingerprint"],))
            elif kind == "追补作废":
                c.execute("UPDATE adjustments SET state='已作废' WHERE event_id=?",
                          (b["ref_adjust_event"],))
        elif e["type"] == EV_BATCH:
            self._reduce_batch(b, e["ts"])

    def _reduce_batch(self, b: dict, ts: float):
        c = self.s.conn
        c.execute("INSERT OR REPLACE INTO batches(batch_id,scenic,period,"
                  "period_key,seq_no,status,opened_at,finalized_at,event_count,"
                  "total_cents,content_hash,body_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                  (b["batch_id"], b["scenic"], b["period"], b["period_key"],
                   b["seq_no"], "已定稿", b["opened_at"], b["finalized_at"],
                   b["event_count"], b["total_cents"], b["content_hash"],
                   json.dumps(b, ensure_ascii=False, sort_keys=True)))
        for item in b["items"]:
            if item["kind"] == "核销":
                c.execute("UPDATE redemptions SET state=?, settled_batch_id=? "
                          "WHERE fingerprint=?",
                          (R_SETTLED, b["batch_id"], item["ref"]))
            elif item["kind"] == ADJUST_SUBSIDY:
                c.execute("UPDATE redemptions SET state=?, settled_batch_id=? "
                          "WHERE fingerprint=?",
                          (R_SETTLED, b["batch_id"], item["ref_fp"]))
            if item["kind"] in (ADJUST_REVERSAL, ADJUST_SUBSIDY):
                c.execute("UPDATE adjustments SET state='已结' WHERE event_id=?",
                          (item["ref"],))

    # ------------------------------------------------------------------ #
    # 收敛指纹：用于“乱序到达等价性”证明
    # ------------------------------------------------------------------ #
    def state_fingerprint(self) -> str:
        """对当前全部业务状态取规范哈希。

        刻意排除 event_id、服务器到达时间等随机/时序字段：同一批记录
        无论以何种顺序到达（或重放台账重建），业务结果都应得到相同指纹。
        """
        c = self.s.conn
        reds = sorted(
            ({"fp": r["fingerprint"], "state": r["state"],
              "reason": r["revoke_reason"], "amount": r["amount_cents"],
              "carryover": r["carryover"], "batch": r["settled_batch_id"]}
             for r in c.execute("SELECT * FROM redemptions")),
            key=lambda x: x["fp"])
        adjs = sorted(
            ({"fp": r["ref_fingerprint"], "kind": r["kind"],
              "amount": r["amount_cents"], "state": r["state"],
              "reason": r["reason"]}
             for r in c.execute("SELECT * FROM adjustments")),
            key=lambda x: (x["fp"] or "", x["kind"], x["reason"]))
        batches = sorted(
            ({"id": r["batch_id"], "hash": r["content_hash"],
              "total": r["total_cents"]}
             for r in c.execute("SELECT * FROM batches")),
            key=lambda x: x["id"])
        return sha256_hex(canonical(
            {"redemptions": reds, "adjustments": adjs, "batches": batches}))
