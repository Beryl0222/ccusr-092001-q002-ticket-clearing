"""按景区与结算周期生成可复算的清算批次。

批次规则
--------
1. 每个 (景区, 周期, 周期键) 只有一个批次，定稿幂等，batch_id 由三元组
   确定性派生；并发定稿由 ``batches`` 表唯一约束兜底。
2. 批次明细两类：
   - 核销：发生时间落在周期自然边界内、状态为“有效”且未结算的记录；
   - 调整：待结的追补（往期补结）与冲正（清算后退款/取消/撤销追回），
     统一随该景区下一个定稿批次出账，避免跨期遗留无归属的调整。
3. 明细按 (类型, 引用) 排序后规范哈希得到 content_hash；金额单位为分，
   冲正为负，批次总额可由明细独立重算。
4. 定稿本身是台账事件（EV_BATCH），哈希链覆盖；删除任何核销/调整事件
   后用 ``rebuild_state`` 重放，批次明细与 content_hash 仍逐笔一致。
"""

from __future__ import annotations

import json

from crypto import canonical, sha256_hex
from domain import (ADJUST_REVERSAL, ADJUST_SUBSIDY, EV_BATCH,
                    PERIOD_WEEKLY, R_VALID, period_bounds, period_key,
                    ts_to_date)

BATCH_VERSION = "v1"


def batch_id(scenic: str, period: str, key: str) -> str:
    return "B-" + sha256_hex(f"{BATCH_VERSION}|{scenic}|{period}|{key}")[:16]


class Clearing:
    def __init__(self, core):
        self.core = core
        self.s = core.s
        self.d = core.d

    # ------------------------------------------------------------------ #
    # 纯计算：给定景区+周期键，批次应包含哪些明细
    # ------------------------------------------------------------------ #
    def compute_items(self, scenic: str, period: str, key: str) -> list[dict]:
        start, end = period_bounds(period, key)
        c = self.s.conn

        def in_bounds(ts: float) -> bool:
            return start <= ts_to_date(ts) <= end

        items: list[dict] = []
        for r in c.execute(
                "SELECT * FROM redemptions WHERE scenic=? AND state=? "
                "AND settled_batch_id IS NULL ORDER BY occurred_at, fingerprint",
                (scenic, R_VALID)).fetchall():
            if in_bounds(r["occurred_at"]):
                items.append({
                    "kind": "核销", "ref": r["fingerprint"],
                    "ref_fp": r["fingerprint"], "ticket_no": r["ticket_no"],
                    "occurred_at": round(r["occurred_at"], 3),
                    "amount_cents": r["amount_cents"],
                })
        # 待结调整（追补/冲正）随本景区下一批次出账
        for a in c.execute(
                "SELECT * FROM adjustments WHERE scenic=? AND state='待结' "
                "ORDER BY occurred_at,event_id", (scenic,)).fetchall():
            items.append({
                "kind": a["kind"], "ref": a["event_id"],
                "ref_fp": a["ref_fingerprint"],
                "ticket_no": a["ticket_no"],
                "occurred_at": round(a["occurred_at"], 3),
                "amount_cents": a["amount_cents"],
                "reason": a["reason"],
            })
        items.sort(key=lambda x: (x["kind"], x["ref"]))
        return items

    @staticmethod
    def hash_items(items: list[dict]) -> str:
        return sha256_hex(canonical({"version": BATCH_VERSION, "items": items}))

    # ------------------------------------------------------------------ #
    # 定稿
    # ------------------------------------------------------------------ #
    def finalize(self, scenic: str, period: str, key: str,
                 operator: str = "settlement") -> dict:
        if scenic not in self.d.scenic_group:
            raise ValueError(f"景区 {scenic} 不在口径分组中")
        if period not in self.d.periods:
            raise ValueError(f"未知结算周期 {period}")
        # 校验周期键格式合法
        period_bounds(period, key)
        at = self.core.now()
        bid = batch_id(scenic, period, key)

        with self.core.txn():
            existed = self.s.conn.execute(
                "SELECT * FROM batches WHERE batch_id=?", (bid,)).fetchone()
            if existed:
                return self._batch_view(existed, idempotent=True)

            items = self.compute_items(scenic, period, key)
            content_hash = self.hash_items(items)
            total = sum(i["amount_cents"] for i in items)
            body = {
                "batch_id": bid, "version": BATCH_VERSION,
                "scenic": scenic, "period": period, "period_key": key,
                "seq_no": 1, "currency": "分",
                "opened_at": at, "finalized_at": at, "operator": operator,
                "event_count": len(items), "total_cents": total,
                "content_hash": content_hash, "items": items,
            }
            ev = self.s.append_event(self.s.new_event_id(), EV_BATCH, body, at)
            self.s.conn.execute(
                "INSERT INTO batches(batch_id,scenic,period,period_key,seq_no,"
                "status,opened_at,finalized_at,event_count,total_cents,"
                "content_hash,body_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (bid, scenic, period, key, 1, "已定稿", at, at, len(items),
                 total, content_hash,
                 json.dumps(body, ensure_ascii=False, sort_keys=True)))
            for i in items:
                if i["kind"] == "核销":
                    self.s.conn.execute(
                        "UPDATE redemptions SET state='已清算', settled_batch_id=? "
                        "WHERE fingerprint=?", (bid, i["ref_fp"]))
                elif i["kind"] == ADJUST_SUBSIDY:
                    self.s.conn.execute(
                        "UPDATE redemptions SET state='已清算', settled_batch_id=? "
                        "WHERE fingerprint=?", (bid, i["ref_fp"]))
                    self.s.conn.execute(
                        "UPDATE adjustments SET state='已结' WHERE event_id=?",
                        (i["ref"],))
                elif i["kind"] == ADJUST_REVERSAL:
                    self.s.conn.execute(
                        "UPDATE adjustments SET state='已结' WHERE event_id=?",
                        (i["ref"],))
            row = self.s.conn.execute(
                "SELECT * FROM batches WHERE batch_id=?", (bid,)).fetchone()
            view = self._batch_view(row)
            view["event_id"] = ev["event_id"]
            return view

    def finalize_current(self, scenic: str, at: float | None = None) -> dict:
        """便捷定稿：按景区配置的周期取参考时间所在周期键。"""
        at = at if at is not None else self.core.now()
        row = self.s.conn.execute(
            "SELECT period FROM scenics WHERE scenic=?", (scenic,)
        ).fetchone()
        if not row:
            raise ValueError(f"景区 {scenic} 尚未开账配置")
        key = period_key(row["period"], ts_to_date(at))
        return self.finalize(scenic, row["period"], key)

    # ------------------------------------------------------------------ #
    # 查询与复核
    # ------------------------------------------------------------------ #
    def _batch_view(self, row, idempotent: bool = False) -> dict:
        body = json.loads(row["body_json"])
        view = {
            "batch_id": row["batch_id"], "scenic": row["scenic"],
            "period": row["period"], "period_key": row["period_key"],
            "status": row["status"], "finalized_at": row["finalized_at"],
            "event_count": row["event_count"], "total_cents": row["total_cents"],
            "content_hash": row["content_hash"], "items": body["items"],
        }
        if idempotent:
            view["idempotent"] = True
        return view

    def get_batch(self, batch_id_: str) -> dict:
        row = self.s.conn.execute(
            "SELECT * FROM batches WHERE batch_id=?", (batch_id_,)
        ).fetchone()
        if not row:
            raise KeyError(batch_id_)
        return self._batch_view(row)

    def list_batches(self, scenic: str | None = None) -> list[dict]:
        sql = "SELECT * FROM batches"
        args: tuple = ()
        if scenic:
            sql += " WHERE scenic=?"
            args = (scenic,)
        sql += " ORDER BY finalized_at, batch_id"
        return [self._batch_view(r) for r in
                self.s.conn.execute(sql, args).fetchall()]

    def verify_batches(self) -> dict:
        """独立复算：逐笔重算每批金额与 content_hash，并核对归属一致。

        任何对台账/明细的事后篡改都会在这里暴露为金额或哈希不一致。
        """
        results = []
        ok_all = True
        for r in self.s.conn.execute(
                "SELECT * FROM batches ORDER BY batch_id").fetchall():
            stored = self._batch_view(r)
            items = stored["items"]
            recomputed_hash = self.hash_items(items)
            recomputed_total = sum(i["amount_cents"] for i in items)
            problems = []
            if recomputed_hash != stored["content_hash"]:
                problems.append("content_hash不一致")
            if recomputed_total != stored["total_cents"]:
                problems.append("总额不可复算")
            if len(items) != stored["event_count"]:
                problems.append("明细笔数不一致")
            # 每一笔明细都应能在核销/调整表中找到、归属本批且金额一致
            for i in items:
                if i["kind"] in ("核销", ADJUST_SUBSIDY):
                    red = self.s.conn.execute(
                        "SELECT settled_batch_id,amount_cents FROM redemptions "
                        "WHERE fingerprint=?", (i["ref_fp"],)).fetchone()
                    if not red or red["settled_batch_id"] != stored["batch_id"]:
                        problems.append(f"明细 {i['ref_fp']} 归属不一致")
                        break
                    if red["amount_cents"] != i["amount_cents"]:
                        problems.append(f"明细 {i['ref_fp']} 金额被改动")
                        break
                if i["kind"] in (ADJUST_REVERSAL, ADJUST_SUBSIDY):
                    adj = self.s.conn.execute(
                        "SELECT state,amount_cents FROM adjustments WHERE event_id=?",
                        (i["ref"],)).fetchone()
                    if not adj or adj["state"] != "已结":
                        problems.append(f"调整 {i['ref']} 状态不一致")
                        break
                    if adj["amount_cents"] != i["amount_cents"]:
                        problems.append(f"调整 {i['ref']} 金额被改动")
                        break
            if problems:
                ok_all = False
            results.append({"batch_id": stored["batch_id"],
                            "scenic": stored["scenic"],
                            "period_key": stored["period_key"],
                            "total_cents": stored["total_cents"],
                            "ok": not problems, "problems": problems})
        return {"ok": ok_all and self.s.verify_chain()[0],
                "batches": results,
                "chain_ok": self.s.verify_chain()[0]}

    def scenic_summary(self, scenic: str) -> dict:
        """景区对账视图：各状态笔数、待结金额、已定稿批次总额。"""
        c = self.s.conn
        by_state = {r["state"]: r["n"] for r in c.execute(
            "SELECT state, COUNT(*) n FROM redemptions WHERE scenic=? GROUP BY state",
            (scenic,)).fetchall()}
        pending_adj = c.execute(
            "SELECT COALESCE(SUM(amount_cents),0) s FROM adjustments "
            "WHERE scenic=? AND state='待结'", (scenic,)).fetchone()["s"]
        settled = c.execute(
            "SELECT COALESCE(SUM(total_cents),0) s, COUNT(*) n FROM batches "
            "WHERE scenic=?", (scenic,)).fetchone()
        return {"scenic": scenic,
                "group": self.d.group_name_of(scenic),
                "redemption_states": by_state,
                "pending_adjustment_cents": pending_adj,
                "settled_total_cents": settled["s"],
                "batch_count": settled["n"]}
