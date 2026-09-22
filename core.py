"""票根惠游权益清算 —— 领域内核。

设计要点
========
1. 可信核验：票根由赛事方以 HMAC-SHA256 签名（防伪造）；核销时校验
   赛季、持票人、票种×景区分组权益范围、场次状态、每景区 1 次、
   每票累计 3 个景区上限。
2. 离线两阶段：弱网景区先在本地对原始记录签名留存（状态"待补传"），
   网络恢复后以"设备签名清单"闭合补传。清单与记录签名使记录不可抵赖、
   不可篡改；重复补传以 (设备, 原始业务键) 唯一约束去重，同一批记录
   无论以何种顺序、重放多少次到达，判定结果完全一致（顺序无关）。
3. 时钟偏差：记录事件时间与服务器时间偏差超过 domain.json 中
   "时钟容忍秒"的进入待复核，不产生补贴。
4. 不重复补贴：有效核销唯一键 (票号, 景区)；票务退款、场次取消、
   场次延期、人工撤销对已生效权益一律生成"调整单"冲抵；已封账周期
   不可改写，调整滚入当前开放周期。
5. 不可篡改轨迹：核销、判定、退款、取消、延期、撤销、复核、封账
   全部写入哈希链事件账本（prev_hash + 载荷哈希），任何篡改都会断链。
6. 可复算清算：按景区与周结/月结周期投影有效核销与调整单，封账批次
   保存输入事件指纹与快照哈希；必须按周期顺序封账，可随时重放复算。
7. 异常不吞掉：票种不符、签名可疑、超窗口、超上限、时钟异常等全部
   进入待复核队列，由复核员裁决，裁决过程同样留痕。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable

# ---------------------------------------------------------------------------
# 常量与领域口径（与 domain.json 保持一致）
# ---------------------------------------------------------------------------

TZ = timezone(timedelta(hours=8))  # Asia/Shanghai
RESULT_VALID = "有效"
RESULT_PENDING_UPLOAD = "待补传"
RESULT_PENDING_REVIEW = "待复核"
RESULT_REVOKED = "已撤销"
RESULT_SETTLED = "已清算"

# 调整单类型
ADJ_REFUND = "票务退款"
ADJ_MATCH_CANCEL = "场次取消"
ADJ_MATCH_POSTPONE = "场次延期"
ADJ_MANUAL_REVOKE = "人工撤销"
ADJ_REVIEW_REJECT = "复核驳回"
ADJ_REVIEW_APPROVE = "复核通过"

# 离线记录判定
DECISION_VALID = "有效"
DECISION_REVIEW = "待复核"
DECISION_DUPLICATE = "重复"
DECISION_REVOKED = "已撤销"
DECISION_REFUNDED = "已退款"
DECISION_REVOKE_DONE = "撤销完成"

REVIEW_OPEN = "待处理"
REVIEW_APPROVED = "通过"
REVIEW_REJECTED = "驳回"


class DomainError(Exception):
    """可向调用方展示的业务错误（携带错误码）。"""

    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


def now_iso() -> str:
    return datetime.now(TZ).replace(microsecond=0).isoformat()


def parse_ts(value: str) -> datetime:
    """解析 ISO8601；无时区信息时按 +08:00 处理（弱网设备常见）。"""
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=TZ)
    return dt.astimezone(TZ)


def fmt_ts(dt: datetime) -> str:
    return dt.astimezone(TZ).replace(microsecond=0).isoformat()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(payload: dict | list) -> str:
    """确定性 JSON 序列化：键排序、无空白、不转义非 ASCII。"""
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


# ---------------------------------------------------------------------------
# 领域配置加载
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ScenicSpot:
    code: str
    name: str
    group: str


@dataclass(frozen=True)
class DomainConfig:
    raw: dict
    spots: dict[str, ScenicSpot]
    group_ticket_types: dict[str, set[str]]
    group_cadence: dict[str, str]
    subsidy: dict[str, int]

    @classmethod
    def load(cls, path: str) -> "DomainConfig":
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)
        spots: dict[str, ScenicSpot] = {}
        group_types: dict[str, set[str]] = {}
        group_cadence: dict[str, str] = {}
        for grp in raw["景区分组"]:
            g = grp["分组编号"]
            group_types[g] = set(grp["适用票种"])
            group_cadence[g] = grp["结算周期"]
            for sp in grp["景区"]:
                spots[sp["景区编号"]] = ScenicSpot(sp["景区编号"], sp["景区名称"], g)
        return cls(raw, spots, group_types, group_cadence,
                   dict(raw["补贴标准_元_人次"]))

    def check(self) -> list[str]:
        """基础配置自检，返回问题列表（空列表表示通过）。"""
        problems: list[str] = []
        required = ["项目", "票种", "景区分组", "核销结果", "结算周期",
                    "补贴标准_元_人次", "权益上限", "核销参数", "赛季"]
        for key in required:
            if key not in self.raw:
                problems.append(f"缺少配置项: {key}")
        if problems:
            return problems
        codes = set()
        total = 0
        for grp in self.raw["景区分组"]:
            for sp in grp["景区"]:
                total += 1
                if sp["景区编号"] in codes:
                    problems.append(f"景区编号重复: {sp['景区编号']}")
                codes.add(sp["景区编号"])
                if not set(grp["适用票种"]) <= set(self.raw["票种"]):
                    problems.append(f"分组 {grp['分组编号']} 适用票种越界")
                if grp.get("结算周期") not in ("周结", "月结"):
                    problems.append(f"分组 {grp['分组编号']} 结算周期口径缺失")
        if total != 42:
            problems.append(f"景区数量应为 42 家，实际 {total} 家")
        for t in self.raw["票种"]:
            if t not in self.raw["补贴标准_元_人次"]:
                problems.append(f"票种 {t} 缺少补贴标准")
        for r in ("有效", "待补传", "待复核", "已撤销", "已清算"):
            if r not in self.raw["核销结果"]:
                problems.append(f"核销结果缺少约定取值: {r}")
        for p in ("周结", "月结"):
            if p not in self.raw["结算周期"]:
                problems.append(f"结算周期缺少约定取值: {p}")
        return problems

    # 方便的访问器 ----------------------------------------------------------
    @property
    def season(self) -> dict:
        return self.raw["赛季"]

    @property
    def per_spot_limit(self) -> int:
        return self.raw["权益上限"]["每景区次数"]

    @property
    def total_spots_limit(self) -> int:
        return self.raw["权益上限"]["每票累计景区数"]

    @property
    def clock_skew_seconds(self) -> int:
        return self.raw["核销参数"]["时钟容忍秒"]

    @property
    def manifest_close_hours(self) -> int:
        return self.raw["核销参数"]["离线清单闭合时限小时"]

    @property
    def upload_grace_hours(self) -> int:
        return self.raw["核销参数"]["离线补传宽限小时"]

    def cadence_of(self, spot_code: str) -> str:
        return self.group_cadence[self.spots[spot_code].group]


# ---------------------------------------------------------------------------
# HMAC 签名
# ---------------------------------------------------------------------------

def sign_payload(secret: str, payload: dict) -> str:
    return hmac.new(secret.encode(), canonical_json(payload).encode(),
                    hashlib.sha256).hexdigest()


def verify_signature(secret: str, payload: dict, signature: str) -> bool:
    return hmac.compare_digest(sign_payload(secret, payload), signature or "")


# ---------------------------------------------------------------------------
# 存储层（SQLite + 写串行化）
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tickets (
    code TEXT PRIMARY KEY,
    payload TEXT NOT NULL,
    signature TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT '正常',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS matches (
    code TEXT PRIMARY KEY,
    kickoff_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT '正常',
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS redemptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_code TEXT NOT NULL,
    holder TEXT NOT NULL,
    ticket_type TEXT NOT NULL,
    spot_code TEXT NOT NULL,
    match_code TEXT NOT NULL,
    channel TEXT NOT NULL,                 -- online | offline
    device_id TEXT,
    site TEXT,
    event_at TEXT NOT NULL,                -- 核销发生时间（设备时钟）
    server_at TEXT NOT NULL,               -- 服务器受理时间
    received_at TEXT NOT NULL,
    result TEXT NOT NULL,
    review_id INTEGER,
    settlement_batch_id INTEGER,
    redeem_sig TEXT,
    raw_record TEXT,
    manifest_id TEXT
);
CREATE TABLE IF NOT EXISTS valid_redemption_keys (
    ticket_code TEXT NOT NULL,
    spot_code TEXT NOT NULL,
    redemption_id INTEGER NOT NULL,
    batch_id INTEGER,
    PRIMARY KEY (ticket_code, spot_code)
);
CREATE TABLE IF NOT EXISTS offline_records (
    device_id TEXT NOT NULL,
    record_id TEXT NOT NULL,
    ticket_code TEXT NOT NULL,
    holder TEXT NOT NULL,
    ticket_type TEXT NOT NULL,
    spot_code TEXT NOT NULL,
    match_code TEXT NOT NULL,
    site TEXT,
    event_at TEXT NOT NULL,
    record_sig TEXT NOT NULL,
    raw TEXT NOT NULL,
    manifest_id TEXT,
    received_at TEXT,
    redemption_id INTEGER,
    decision TEXT,
    decided_at TEXT,
    PRIMARY KEY (device_id, record_id)
);
CREATE TABLE IF NOT EXISTS manifests (
    manifest_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    opened_at TEXT NOT NULL,
    closed_at TEXT,
    keys_sig TEXT,
    received_at TEXT
);
CREATE TABLE IF NOT EXISTS adjustments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_code TEXT NOT NULL,
    spot_code TEXT NOT NULL,
    redemption_id INTEGER,
    kind TEXT NOT NULL,
    amount INTEGER NOT NULL,               -- 分；冲抵为负
    reason TEXT NOT NULL,
    event_at TEXT NOT NULL,
    settlement_batch_id INTEGER,
    related_batch_id INTEGER
);
CREATE TABLE IF NOT EXISTS review_cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    redemption_id INTEGER,
    ticket_code TEXT NOT NULL,
    spot_code TEXT NOT NULL,
    channel TEXT NOT NULL,
    reasons TEXT NOT NULL,                 -- JSON 数组
    evidence TEXT NOT NULL,                -- JSON
    status TEXT NOT NULL DEFAULT '待处理',
    decided_by TEXT,
    decided_at TEXT,
    adjustment_id INTEGER,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settlement_batches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    period_kind TEXT NOT NULL,
    period_start TEXT NOT NULL,
    period_end TEXT NOT NULL,
    spot_code TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT '开放',
    count INTEGER NOT NULL DEFAULT 0,
    gross INTEGER NOT NULL DEFAULT 0,
    adjustments INTEGER NOT NULL DEFAULT 0,
    net INTEGER NOT NULL DEFAULT 0,
    input_fingerprint TEXT,
    snapshot_hash TEXT,
    sealed_at TEXT,
    seq INTEGER NOT NULL DEFAULT 0,
    UNIQUE (period_kind, period_start, spot_code)
);
CREATE TABLE IF NOT EXISTS event_log (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    payload TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL UNIQUE
);
"""


class Store:
    """SQLite 封装。所有写操作经同一把锁串行化，保证判定顺序确定。"""

    def __init__(self, path: str | None = None,
                 clock: Callable[[], datetime] | None = None):
        self.conn = sqlite3.connect(path or ":memory:", check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = OFF")
        self.conn.execute("PRAGMA journal_mode = WAL") if path else None
        self.conn.executescript(SCHEMA)
        self.conn.commit()
        self.lock = threading.RLock()
        self.clock = clock or (lambda: datetime.now(TZ))
        if self.conn.execute("SELECT COUNT(*) c FROM event_log").fetchone()["c"] == 0:
            self._init_genesis()

    def _init_genesis(self) -> None:
        zero = "0" * 64
        body = canonical_json({"note": "账本建立"})
        h = sha256_hex(f"{zero}|genesis|{body}".encode())
        at = self.clock().astimezone(TZ).replace(microsecond=0).isoformat()
        self.conn.execute(
            "INSERT INTO event_log (at, actor, action, payload, prev_hash, hash) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (at, "system", "genesis", body, zero, h),
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    # 哈希链事件日志 --------------------------------------------------------
    def append_event(self, actor: str, action: str, payload: dict) -> dict:
        at = self.clock().astimezone(TZ).replace(microsecond=0).isoformat()
        row = self.conn.execute(
            "SELECT hash FROM event_log ORDER BY seq DESC LIMIT 1").fetchone()
        prev_hash = row["hash"] if row else "0" * 64
        body = canonical_json(payload)
        h = sha256_hex(f"{prev_hash}|{action}|{body}".encode())
        cur = self.conn.execute(
            "INSERT INTO event_log (at, actor, action, payload, prev_hash, hash) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (at, actor, action, body, prev_hash, h),
        )
        return {"seq": cur.lastrowid, "at": at, "actor": actor,
                "action": action, "payload": payload, "prev_hash": prev_hash,
                "hash": h}

    def verify_chain(self) -> dict:
        rows = self.conn.execute("SELECT * FROM event_log ORDER BY seq").fetchall()
        prev = "0" * 64
        for row in rows:
            expect = sha256_hex(
                f"{prev}|{row['action']}|{row['payload']}".encode())
            if row["prev_hash"] != prev or not hmac.compare_digest(expect, row["hash"]):
                return {"ok": False, "broken_at_seq": row["seq"],
                        "expected": expect, "actual": row["hash"]}
            prev = row["hash"]
        return {"ok": True, "events": len(rows), "tail": prev}

    # 通用便捷方法 ----------------------------------------------------------
    def get_meta(self, key: str, default=None):
        row = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return json.loads(row["value"]) if row else default

    def set_meta(self, key: str, value) -> None:
        self.conn.execute(
            "INSERT INTO meta(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, json.dumps(value, ensure_ascii=False)))

    def insert(self, sql: str, params: tuple = ()) -> int:
        cur = self.conn.execute(sql, params)
        return cur.lastrowid

    def query(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        return self.conn.execute(sql, params).fetchall()

    def query_one(self, sql: str, params: tuple = ()) -> sqlite3.Row | None:
        return self.conn.execute(sql, params).fetchone()

    def commit(self) -> None:
        self.conn.commit()


# ---------------------------------------------------------------------------
# 周期工具
# ---------------------------------------------------------------------------

def period_bounds(kind: str, ts: datetime) -> tuple[datetime, datetime]:
    """返回 ts 所属结算周期的 [起, 止)。"""
    ts = ts.astimezone(TZ)
    if kind == "周结":
        start = (ts - timedelta(days=ts.weekday())).replace(
            hour=0, minute=0, second=0, microsecond=0)
        return start, start + timedelta(days=7)
    if kind == "月结":
        start = ts.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        if start.month == 12:
            nxt = start.replace(year=start.year + 1, month=1)
        else:
            nxt = start.replace(month=start.month + 1)
        return start, nxt
    raise DomainError("BAD_PERIOD", f"未知结算周期: {kind}")


def shift_period(kind: str, start: datetime, n: int) -> datetime:
    if kind == "周结":
        return start + timedelta(weeks=n)
    year, month = start.year, start.month + n
    year += (month - 1) // 12
    month = (month - 1) % 12 + 1
    return start.replace(year=year, month=month)


# ---------------------------------------------------------------------------
# 核心服务
# ---------------------------------------------------------------------------

class ClearingService:
    def __init__(self, config: DomainConfig, store: Store,
                 issuer_secret: str | None = None,
                 device_secrets: dict[str, str] | None = None,
                 clock: Callable[[], datetime] | None = None):
        self.cfg = config
        self.store = store
        self.issuer_secret = issuer_secret or os.environ.get(
            "ISSUER_SECRET", "demo-issuer-secret")
        # 演示环境设备密钥表；生产应由设备注册流程下发
        self.device_secrets = device_secrets or {}
        # 可注入时钟（测试按周期封账时使用），默认取东八区当前时间
        self._clock = clock or (lambda: datetime.now(TZ))

    def _now(self) -> datetime:
        return self._clock().astimezone(TZ)

    def _ts(self) -> str:
        return fmt_ts(self._now())

    # 票根签发（赛事方） ----------------------------------------------------
    def issue_ticket(self, ticket_code: str, ticket_type: str, holder: str,
                     match_code: str, face_value: int, issued_at: str | None = None,
                     actor: str = "赛事方") -> dict:
        if ticket_type not in self.cfg.raw["票种"]:
            raise DomainError("BAD_TICKET_TYPE", f"未知票种: {ticket_type}")
        payload = {
            "ticket_code": ticket_code,
            "ticket_type": ticket_type,
            "holder": holder,
            "match_code": match_code,
            "face_value": face_value,
            "season": self.cfg.season["赛季编号"],
            "issued_at": issued_at or self._ts(),
        }
        sig = sign_payload(self.issuer_secret, payload)
        with self.store.lock:
            if self.store.query_one("SELECT 1 FROM tickets WHERE code=?", (ticket_code,)):
                raise DomainError("TICKET_EXISTS", f"票号已存在: {ticket_code}", 409)
            self.store.insert(
                "INSERT INTO tickets(code,payload,signature,status,created_at) "
                "VALUES(?,?,?,?,?)",
                (ticket_code, canonical_json(payload), sig, "正常", self._ts()))
            ev = self.store.append_event(actor, "ticket.issued",
                                         {"ticket_code": ticket_code, **payload})
            self.store.commit()
        return {"ticket": payload, "signature": sig, "event_seq": ev["seq"]}

    def register_device(self, device_id: str, secret: str, spot_code: str,
                        site: str) -> dict:
        if spot_code not in self.cfg.spots:
            raise DomainError("BAD_SPOT", f"未知景区: {spot_code}", 404)
        self.device_secrets[device_id] = secret
        with self.store.lock:
            self.store.set_meta(f"device:{device_id}",
                                {"spot_code": spot_code, "site": site,
                                 "secret": secret})
            ev = self.store.append_event("系统", "device.registered",
                                         {"device_id": device_id,
                                          "spot_code": spot_code, "site": site})
            self.store.commit()
        return {"device_id": device_id, "spot_code": spot_code, "site": site,
                "event_seq": ev["seq"]}

    def _device_secret(self, device_id: str) -> str | None:
        """设备密钥：内存表优先，其次读注册时落库的密钥。"""
        if device_id in self.device_secrets:
            return self.device_secrets[device_id]
        meta = self.store.get_meta(f"device:{device_id}")
        if meta and meta.get("secret"):
            self.device_secrets[device_id] = meta["secret"]
            return meta["secret"]
        return None

    def register_match(self, match_code: str, kickoff_at: str) -> dict:
        ts = fmt_ts(parse_ts(kickoff_at))
        with self.store.lock:
            self.store.insert(
                "INSERT OR REPLACE INTO matches(code,kickoff_at,status,updated_at) "
                "VALUES(?,?,?,?)", (match_code, ts, "正常", self._ts()))
            ev = self.store.append_event("赛事方", "match.registered",
                                         {"match_code": match_code, "kickoff_at": ts})
            self.store.commit()
        return {"match_code": match_code, "kickoff_at": ts, "event_seq": ev["seq"]}

    # 票根读取与校验 --------------------------------------------------------
    def _load_ticket(self, ticket_code: str, signature: str | None = None) -> dict:
        row = self.store.query_one("SELECT * FROM tickets WHERE code=?", (ticket_code,))
        if not row:
            raise DomainError("TICKET_NOT_FOUND", f"票号不存在: {ticket_code}", 404)
        payload = json.loads(row["payload"])
        if signature is not None and not verify_signature(
                self.issuer_secret, payload, signature):
            raise DomainError("BAD_TICKET_SIGNATURE", "票根签名校验失败：疑似伪造", 403)
        payload["_status"] = row["status"]
        payload["_stored_sig"] = row["signature"]
        return payload

    def _load_match(self, match_code: str) -> dict | None:
        row = self.store.query_one("SELECT * FROM matches WHERE code=?", (match_code,))
        return dict(row) if row else None

    def _benefit_window(self, kickoff: datetime) -> tuple[datetime, datetime]:
        w = self.cfg.season["权益生效窗口"]
        return (kickoff - timedelta(hours=w["开赛前小时"]),
                kickoff + timedelta(hours=w["赛后小时"]))

    def _eligibility_checks(self, ticket: dict, spot: ScenicSpot,
                            event_dt: datetime, ticket_type: str,
                            holder: str) -> list[str]:
        """返回异常原因列表；空列表表示权益核验通过。"""
        reasons: list[str] = []
        season = self.cfg.season
        if ticket.get("season") != season["赛季编号"]:
            reasons.append("非当前赛季票根")
        season_start = parse_ts(season["开始日期"] + "T00:00:00")
        season_end = parse_ts(season["结束日期"] + "T23:59:59")
        if not (season_start <= event_dt <= season_end):
            reasons.append("核销时间不在赛季范围内")
        if ticket["ticket_type"] != ticket_type:
            reasons.append("票种与申报不符")
        if ticket["holder"] != holder:
            reasons.append("持票人与票根登记不一致")
        allowed = self.cfg.group_ticket_types[spot.group]
        if ticket["ticket_type"] not in allowed:
            reasons.append(f"票种不在景区分组{spot.group}适用范围")
        match = self._load_match(ticket["match_code"])
        if match:
            if match["status"] == "已取消":
                reasons.append("所属场次已取消")
            else:
                kickoff = parse_ts(match["kickoff_at"])
                lo, hi = self._benefit_window(kickoff)
                if not (lo <= event_dt <= hi):
                    reasons.append("场次已延期且新时间超出权益窗口"
                                   if match["status"] == "已延期"
                                   else "不在场次权益生效窗口（赛前72h/赛后168h）")
        if ticket["_status"] == "已退款":
            reasons.append("票根已退款")
        # 权益上限：每景区 1 次、每票累计 3 个不同景区（仅统计现存有效核销）
        if self.store.query_one(
                "SELECT 1 FROM valid_redemption_keys WHERE ticket_code=? AND spot_code=?",
                (ticket["code"] if "code" in ticket else ticket["ticket_code"],
                 spot.code)):
            reasons.append("同一景区已核销（每景区限1次）")
        used = self.store.query_one(
            "SELECT COUNT(DISTINCT spot_code) c FROM valid_redemption_keys "
            "WHERE ticket_code=?", (ticket["ticket_code"],))
        if used and used["c"] >= self.cfg.total_spots_limit:
            reasons.append(f"已达每票累计{self.cfg.total_spots_limit}个景区上限")
        return reasons

    # 在线核销（景区） ------------------------------------------------------
    def redeem_online(self, ticket_code: str, signature: str, spot_code: str,
                      holder: str, ticket_type: str, event_at: str | None = None,
                      actor: str = "景区") -> dict:
        spot = self.cfg.spots.get(spot_code)
        if not spot:
            raise DomainError("BAD_SPOT", f"未知景区: {spot_code}", 404)
        event_dt = parse_ts(event_at) if event_at else self._now()
        server_dt = self._now()
        with self.store.lock:
            ticket = self._load_ticket(ticket_code, signature)
            skew = abs((event_dt - server_dt).total_seconds())
            reasons = self._eligibility_checks(ticket, spot, event_dt,
                                               ticket_type, holder)
            if skew > self.cfg.clock_skew_seconds:
                reasons.append(f"设备时钟偏差{int(skew)}秒超过容忍"
                               f"{self.cfg.clock_skew_seconds}秒")
            result = RESULT_VALID if not reasons else RESULT_PENDING_REVIEW
            rid = self.store.insert(
                "INSERT INTO redemptions(ticket_code,holder,ticket_type,spot_code,"
                "match_code,channel,event_at,server_at,received_at,result) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (ticket_code, holder, ticket_type, spot_code,
                 ticket["match_code"], "online", fmt_ts(event_dt), fmt_ts(server_dt),
                 self._ts(), result))
            ev_payload = {"redemption_id": rid, "ticket_code": ticket_code,
                          "spot_code": spot_code, "event_at": fmt_ts(event_dt),
                          "channel": "online", "result": result}
            if result == RESULT_VALID:
                self.store.insert(
                    "INSERT INTO valid_redemption_keys(ticket_code,spot_code,"
                    "redemption_id) VALUES(?,?,?)", (ticket_code, spot_code, rid))
            else:
                review_id = self._open_review(rid, ticket_code, spot_code,
                                              "online", reasons,
                                              {"event_at": fmt_ts(event_dt),
                                               "server_at": fmt_ts(server_dt),
                                               "skew_seconds": int(skew)})
                self.store.conn.execute(
                    "UPDATE redemptions SET review_id=? WHERE id=?", (review_id, rid))
                ev_payload["review_id"] = review_id
                ev_payload["reasons"] = reasons
            ev = self.store.append_event(actor, "redemption.online", ev_payload)
            self.store.commit()
        return {"redemption_id": rid, "result": result,
                "spot": {"code": spot.code, "name": spot.name},
                "review_reasons": reasons, "event_seq": ev["seq"]}

    def _open_review(self, redemption_id: int | None, ticket_code: str,
                     spot_code: str, channel: str, reasons: list[str],
                     evidence: dict) -> int:
        rid = self.store.insert(
            "INSERT INTO review_cases(redemption_id,ticket_code,spot_code,channel,"
            "reasons,evidence,status,created_at) VALUES(?,?,?,?,?,?,?,?)",
            (redemption_id, ticket_code, spot_code, channel,
             canonical_json(reasons), canonical_json(evidence), REVIEW_OPEN, self._ts()))
        return rid

    # 离线第一阶段：设备签名记录（本地留存，可预生成） ----------------------
    @staticmethod
    def build_offline_record(device_secret: str, device_id: str, record_id: str,
                             ticket_code: str, holder: str, ticket_type: str,
                             spot_code: str, match_code: str, site: str,
                             event_at: str) -> tuple[dict, str]:
        body = {
            "device_id": device_id, "record_id": record_id,
            "ticket_code": ticket_code, "holder": holder,
            "ticket_type": ticket_type, "spot_code": spot_code,
            "match_code": match_code, "site": site, "event_at": event_at,
        }
        return body, sign_payload(device_secret, body)

    def open_manifest(self, device_id: str, opened_at: str | None = None) -> dict:
        manifest_id = f"MF-{uuid.uuid4().hex[:16]}"
        with self.store.lock:
            self.store.insert(
                "INSERT INTO manifests(manifest_id,device_id,opened_at) VALUES(?,?,?)",
                (manifest_id, device_id, opened_at or self._ts()))
            self.store.commit()
        return {"manifest_id": manifest_id, "device_id": device_id,
                "opened_at": opened_at or self._ts()}

    def close_manifest(self, device_id: str, record_ids: list[str],
                       closed_at: str | None = None) -> dict:
        """设备网络恢复后闭合清单：对清单内全部原始业务键签名。"""
        secret = self._device_secret(device_id)
        if secret is None:
            raise DomainError("DEVICE_UNKNOWN", f"设备未注册: {device_id}", 404)
        keys = sorted(record_ids)
        keys_sig = sign_payload(secret, {"device_id": device_id, "record_ids": keys})
        manifest_id = f"MF-{uuid.uuid4().hex[:16]}"
        with self.store.lock:
            self.store.insert(
                "INSERT INTO manifests(manifest_id,device_id,opened_at,closed_at,"
                "keys_sig,received_at) VALUES(?,?,?,?,?,?)",
                (manifest_id, device_id, self._ts(), closed_at or self._ts(),
                 keys_sig, self._ts()))
            self.store.commit()
        return {"manifest_id": manifest_id, "device_id": device_id,
                "record_ids": keys, "keys_sig": keys_sig}

    # 离线第二阶段：补传（顺序无关、重放安全） ------------------------------
    def upload_offline(self, records: list[dict], manifest: dict,
                       actor: str = "景区") -> dict:
        """批量补传设备签名记录。

        - 同一 (设备, 原始业务键) 已补传过：判定为"重复"，不产生任何权益；
        - 清单签名/记录签名校验失败：整批拒绝（防混入伪造记录）；
        - 本方法对 records 顺序不敏感，可任意重放，结果幂等。
        """
        if not records:
            raise DomainError("EMPTY_BATCH", "补传记录为空")
        device_id = manifest.get("device_id")
        secret = self._device_secret(device_id)
        if secret is None:
            raise DomainError("DEVICE_UNKNOWN", f"设备未注册: {device_id}", 404)
        declared_keys = sorted(manifest.get("record_ids", []))
        if not declared_keys:
            raise DomainError("BAD_MANIFEST", "清单缺少原始业务键列表")
        expect_keys_sig = sign_payload(
            secret, {"device_id": device_id, "record_ids": declared_keys})
        if not verify_signature(secret,
                                {"device_id": device_id,
                                 "record_ids": declared_keys},
                                manifest.get("keys_sig", "")):
            raise DomainError("BAD_MANIFEST_SIGNATURE",
                              "清单签名校验失败：记录集合来源不可信", 403)
        # 逐条验签并与清单核对
        norm: list[dict] = []
        for rec in records:
            body = {k: rec.get(k) for k in (
                "device_id", "record_id", "ticket_code", "holder", "ticket_type",
                "spot_code", "match_code", "site", "event_at")}
            if body["device_id"] != device_id:
                raise DomainError("DEVICE_MISMATCH",
                                  f"记录设备不一致: {body['record_id']}", 403)
            if not verify_signature(secret, body, rec.get("record_sig", "")):
                raise DomainError("BAD_RECORD_SIGNATURE",
                                  f"记录签名校验失败: {body['record_id']}", 403)
            if body["record_id"] not in declared_keys:
                raise DomainError("NOT_IN_MANIFEST",
                                  f"记录不在签名清单内: {body['record_id']}", 403)
            norm.append(body)
        got_keys = sorted(r["record_id"] for r in norm)
        if not set(got_keys) <= set(declared_keys):
            raise DomainError("NOT_IN_MANIFEST",
                              "存在签名清单之外的记录，整批拒绝", 400)
        manifest_id = manifest.get("manifest_id") or f"MF-{uuid.uuid4().hex[:16]}"

        decisions: list[dict] = []
        server_dt = self._now()
        with self.store.lock:
            # 顺序无关：同键 INSERT OR IGNORE，只有真正首次插入的行参与判定
            first_seen: list[dict] = []
            for body in norm:
                existed = self.store.query_one(
                    "SELECT 1 FROM offline_records WHERE device_id=? AND record_id=?",
                    (device_id, body["record_id"]))
                if existed:
                    decisions.append({"record_id": body["record_id"],
                                      "decision": DECISION_DUPLICATE,
                                      "result": RESULT_PENDING_UPLOAD,
                                      "note": "重复补传，已忽略"})
                    continue
                self.store.insert(
                    "INSERT INTO offline_records(device_id,record_id,ticket_code,"
                    "holder,ticket_type,spot_code,match_code,site,event_at,"
                    "record_sig,raw,manifest_id,received_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (device_id, body["record_id"], body["ticket_code"], body["holder"],
                     body["ticket_type"], body["spot_code"], body["match_code"],
                     body["site"], body["event_at"],
                     sign_payload(secret, body), canonical_json(body),
                     manifest_id, self._ts()))
                first_seen.append(body)

            # 对首次见到的记录做确定性判定（按业务键排序，保证与到达顺序无关）
            for body in sorted(first_seen, key=lambda b: (b["ticket_code"],
                                                          b["spot_code"],
                                                          b["event_at"],
                                                          b["record_id"])):
                outcome = self._decide_offline(body, secret, manifest_id, server_dt,
                                               actor)
                decisions.append(outcome)

            self.store.append_event(actor, "offline.uploaded", {
                "device_id": device_id,
                "manifest_id": manifest_id,
                "records_total": len(norm),
                "first_seen": len(first_seen),
                "duplicates": len(norm) - len(first_seen),
                "decisions": sorted(
                    d["decision"] for d in decisions),
            })
            self.store.commit()
        # 输出按 record_id 排序，调用方看到的结果同样与到达顺序无关
        decisions.sort(key=lambda d: d["record_id"])
        summary: dict[str, int] = {}
        for d in decisions:
            summary[d["decision"]] = summary.get(d["decision"], 0) + 1
        return {"manifest_id": manifest_id, "device_id": device_id,
                "received": len(norm), "summary": summary, "decisions": decisions}

    def _decide_offline(self, body: dict, device_secret: str,
                        manifest_id: str, server_dt: datetime, actor: str) -> dict:
        spot = self.cfg.spots.get(body["spot_code"])
        event_dt = parse_ts(body["event_at"])
        record_id = body["record_id"]
        base = {"record_id": record_id, "ticket_code": body["ticket_code"],
                "spot_code": body["spot_code"], "event_at": body["event_at"]}

        # 设备只能为其注册绑定的景区上报，防止跨网点借设备套补
        device_meta = self.store.get_meta(f"device:{body['device_id']}")
        bound_spot = device_meta["spot_code"] if device_meta else None

        ticket_row = self.store.query_one(
            "SELECT * FROM tickets WHERE code=?", (body["ticket_code"],))
        reasons: list[str] = []
        hard_revoked = False
        ticket = None
        if not ticket_row:
            reasons.append("票号不存在")
        else:
            ticket = json.loads(ticket_row["payload"])
            # 先对原始载荷验签，再附加内部状态字段
            if not verify_signature(self.issuer_secret, ticket,
                                    ticket_row["signature"]):
                reasons.append("票根库存签名异常")
            ticket["_status"] = ticket_row["status"]
            if ticket["_status"] == "已退款":
                reasons.append("票根已退款")
                hard_revoked = True
            if ticket["match_code"] != body["match_code"]:
                reasons.append("记录场次与票根所属场次不一致")
        if bound_spot is None:
            reasons.append("设备未绑定景区")
        elif bound_spot != body["spot_code"]:
            reasons.append(f"设备绑定景区{bound_spot}，与记录景区不一致")
        if spot is None:
            reasons.append("未知景区")
        else:
            season = self.cfg.season
            season_start = parse_ts(season["开始日期"] + "T00:00:00")
            season_end = parse_ts(season["结束日期"] + "T23:59:59")
            if not (season_start <= event_dt <= season_end):
                reasons.append("核销时间不在赛季范围内")
            if ticket:
                if ticket["ticket_type"] != body["ticket_type"]:
                    reasons.append("票种与申报不符")
                if ticket["holder"] != body["holder"]:
                    reasons.append("持票人与票根登记不一致")
                if ticket["ticket_type"] not in self.cfg.group_ticket_types[spot.group]:
                    reasons.append(f"票种不在景区分组{spot.group}适用范围")
                match = self._load_match(ticket["match_code"])
                if match:
                    if match["status"] == "已取消":
                        reasons.append("所属场次已取消")
                        hard_revoked = True
                    else:
                        kickoff = parse_ts(match["kickoff_at"])
                        lo, hi = self._benefit_window(kickoff)
                        if not (lo <= event_dt <= hi):
                            reasons.append("场次已延期且新时间超出权益窗口"
                                           if match["status"] == "已延期"
                                           else "不在场次权益生效窗口")
        # 该票在本景区已被撤销（退款/取消/延期/人工/复核驳回）：不得重新取得权益
        revoked = self.store.query_one(
            "SELECT 1 FROM redemptions WHERE ticket_code=? AND spot_code=? "
            "AND result=?", (body["ticket_code"], body["spot_code"],
                             RESULT_REVOKED))
        if revoked:
            hard_revoked = True

        # 时钟偏差：事件时间不得晚于服务器时间+容忍；过早则超过闭合/宽限
        skew = (event_dt - server_dt).total_seconds()
        if skew > self.cfg.clock_skew_seconds:
            reasons.append(f"设备时钟超前{int(skew)}秒，超过容忍"
                           f"{self.cfg.clock_skew_seconds}秒")
        if server_dt - event_dt > timedelta(hours=self.cfg.upload_grace_hours):
            reasons.append(f"超出补传宽限{self.cfg.upload_grace_hours}小时")
        # 清单闭合时限：事件到补传受理超过闭合时限 → 复核（防止事后批量伪造）
        if server_dt - event_dt > timedelta(hours=self.cfg.manifest_close_hours):
            reasons.append(f"超过清单闭合时限"
                           f"{self.cfg.manifest_close_hours}小时")

        # 唯一权益键冲突 → 重复（不论线上线下、不论哪台设备先占）
        dup = self.store.query_one(
            "SELECT 1 FROM valid_redemption_keys WHERE ticket_code=? AND spot_code=?",
            (body["ticket_code"], body["spot_code"]))

        result: str
        decision: str
        redemption_id: int | None = None
        review_id: int | None = None

        if hard_revoked:
            # 已退款/场次取消/此前已撤销：确定性置为已撤销，不进补贴、不入复核
            result, decision = RESULT_REVOKED, DECISION_REVOKED
        elif reasons:
            result, decision = RESULT_PENDING_REVIEW, DECISION_REVIEW
        elif dup:
            result, decision = RESULT_VALID, DECISION_DUPLICATE
        else:
            result, decision = RESULT_VALID, DECISION_VALID

        rid = self.store.insert(
            "INSERT INTO redemptions(ticket_code,holder,ticket_type,spot_code,"
            "match_code,channel,device_id,site,event_at,server_at,received_at,"
            "result,redeem_sig,raw_record,manifest_id) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (body["ticket_code"], body["holder"], body["ticket_type"],
             body["spot_code"], body["match_code"], "offline", device_id_of(body),
             body["site"], body["event_at"], fmt_ts(server_dt), self._ts(),
             result, body.get("record_sig"), canonical_json(body), manifest_id))
        redemption_id = rid

        if decision == DECISION_VALID:
            self.store.insert(
                "INSERT INTO valid_redemption_keys(ticket_code,spot_code,"
                "redemption_id) VALUES(?,?,?)",
                (body["ticket_code"], body["spot_code"], rid))
        if decision == DECISION_REVIEW:
            review_id = self._open_review(rid, body["ticket_code"],
                                          body["spot_code"], "offline", reasons,
                                          {"record": body,
                                           "manifest_id": manifest_id,
                                           "server_at": fmt_ts(server_dt)})
            self.store.conn.execute(
                "UPDATE redemptions SET review_id=? WHERE id=?", (review_id, rid))
        self.store.conn.execute(
            "UPDATE offline_records SET redemption_id=?, decision=?, decided_at=? "
            "WHERE device_id=? AND record_id=?",
            (rid, decision, self._ts(), body["device_id"], record_id))
        self.store.append_event(actor, "offline.decided",
                                {**base, "redemption_id": rid, "decision": decision,
                                 "result": result,
                                 "reasons": reasons, "review_id": review_id})
        out = {**base, "redemption_id": redemption_id, "decision": decision,
               "result": result}
        if reasons:
            out["review_id"] = review_id
            out["review_reasons"] = reasons
        return out

    # 赛事方：退款 / 场次取消 / 场次延期 -------------------------------
    def refund_ticket(self, ticket_code: str, reason: str = "观众退票",
                      actor: str = "赛事方") -> dict:
        with self.store.lock:
            row = self.store.query_one("SELECT * FROM tickets WHERE code=?",
                                       (ticket_code,))
            if not row:
                raise DomainError("TICKET_NOT_FOUND", f"票号不存在: {ticket_code}", 404)
            if row["status"] == "已退款":
                raise DomainError("ALREADY_REFUNDED", "票根已退款，请勿重复操作", 409)
            self.store.conn.execute(
                "UPDATE tickets SET status='已退款' WHERE code=?", (ticket_code,))
            created = self._claw_back(ticket_code, ADJ_REFUND, reason, actor,
                                      match_scope=None)
            ev = self.store.append_event(actor, "ticket.refunded",
                                         {"ticket_code": ticket_code, "reason": reason,
                                          "adjustments": created})
            self.store.commit()
        return {"ticket_code": ticket_code, "status": "已退款",
                "adjustments": created, "event_seq": ev["seq"]}

    def cancel_match(self, match_code: str, reason: str = "赛事取消",
                     actor: str = "赛事方") -> dict:
        with self.store.lock:
            m = self.store.query_one("SELECT * FROM matches WHERE code=?",
                                     (match_code,))
            if not m:
                raise DomainError("MATCH_NOT_FOUND", f"场次不存在: {match_code}", 404)
            self.store.conn.execute(
                "UPDATE matches SET status='已取消', updated_at=? WHERE code=?",
                (self._ts(), match_code))
            created = self._claw_back(None, ADJ_MATCH_CANCEL, reason, actor,
                                      match_scope=match_code)
            ev = self.store.append_event(actor, "match.cancelled",
                                         {"match_code": match_code,
                                          "reason": reason, "adjustments": created})
            self.store.commit()
        return {"match_code": match_code, "status": "已取消",
                "adjustments": created, "event_seq": ev["seq"]}

    def postpone_match(self, match_code: str, new_kickoff_at: str,
                       actor: str = "赛事方") -> dict:
        """场次延期：未核销者按新开赛时间重算窗口；已在旧窗口核销、按新窗口
        不再合格者，冲抵其权益（防止凭延期票重复/套取补贴）。"""
        new_ts = fmt_ts(parse_ts(new_kickoff_at))
        with self.store.lock:
            m = self.store.query_one("SELECT * FROM matches WHERE code=?",
                                     (match_code,))
            if not m:
                raise DomainError("MATCH_NOT_FOUND", f"场次不存在: {match_code}", 404)
            self.store.conn.execute(
                "UPDATE matches SET status='已延期', kickoff_at=?, updated_at=? "
                "WHERE code=?", (new_ts, self._ts(), match_code))
            lo, hi = self._benefit_window(parse_ts(new_ts))
            # 已生效但落在新窗口之外的核销 → 冲抵
            rows = self.store.query(
                "SELECT vr.redemption_id rid, r.ticket_code tc, r.spot_code sc, "
                "r.event_at ea, r.ticket_type tt FROM valid_redemption_keys vr "
                "JOIN redemptions r ON r.id=vr.redemption_id "
                "WHERE r.match_code=?", (match_code,))
            created = []
            for r in rows:
                if not (lo <= parse_ts(r["ea"]) <= hi):
                    created.extend(self._claw_back(
                        r["tc"], ADJ_MATCH_POSTPONE,
                        f"场次延期至{new_ts}，原核销时间超出新权益窗口",
                        actor, spot_scope=r["sc"]))
            ev = self.store.append_event(actor, "match.postponed",
                                         {"match_code": match_code,
                                          "new_kickoff_at": new_ts,
                                          "adjustments": created})
            self.store.commit()
        return {"match_code": match_code, "status": "已延期",
                "new_kickoff_at": new_ts, "adjustments": created,
                "event_seq": ev["seq"]}

    def _claw_back(self, ticket_code: str | None, kind: str, reason: str,
                   actor: str, match_scope: str | None = None,
                   spot_scope: str | None = None) -> list[dict]:
        """对现存有效核销生成冲抵调整单并移出有效键集合。

        幂等：同一 (核销, 调整类型) 只生成一次调整单，重复退款/取消/补传
        不会造成重复冲抵或负补贴。
        """
        sql = ("SELECT vr.redemption_id rid, vr.ticket_code tc, vr.spot_code sc, "
               "r.ticket_type tt, r.event_at ea FROM valid_redemption_keys vr "
               "JOIN redemptions r ON r.id=vr.redemption_id WHERE 1=1")
        params: list = []
        if ticket_code:
            sql += " AND vr.ticket_code=?"
            params.append(ticket_code)
        if match_scope:
            sql += " AND r.match_code=?"
            params.append(match_scope)
        if spot_scope:
            sql += " AND vr.spot_code=?"
            params.append(spot_scope)
        created: list[dict] = []
        for row in self.store.query(sql, tuple(params)):
            dup_adj = self.store.query_one(
                "SELECT 1 FROM adjustments WHERE redemption_id=? AND kind=?",
                (row["rid"], kind))
            if dup_adj:
                continue
            amount = -self.cfg.subsidy[row["tt"]] * 100  # 元 → 分
            # 若被冲抵的核销已随某批次封账，调整单只关联不改账，计入当前开放周期
            sealed_in = self.store.query_one(
                "SELECT settlement_batch_id b FROM redemptions WHERE id=?",
                (row["rid"],))
            related_batch = sealed_in["b"] if sealed_in else None
            aid = self.store.insert(
                "INSERT INTO adjustments(ticket_code,spot_code,redemption_id,"
                "kind,amount,reason,event_at,related_batch_id) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (row["tc"], row["sc"], row["rid"], kind, amount, reason,
                 self._ts(), related_batch))
            self.store.conn.execute(
                "DELETE FROM valid_redemption_keys WHERE redemption_id=?",
                (row["rid"],))
            self.store.conn.execute(
                "UPDATE redemptions SET result=? WHERE id=?",
                (RESULT_REVOKED, row["rid"]))
            self.store.append_event(actor, "adjustment.created",
                                    {"adjustment_id": aid, "ticket_code": row["tc"],
                                     "spot_code": row["sc"], "kind": kind,
                                     "amount": amount, "redemption_id": row["rid"],
                                     "reason": reason})
            created.append({"adjustment_id": aid, "ticket_code": row["tc"],
                            "spot_code": row["sc"], "amount_fen": amount,
                            "redemption_id": row["rid"], "kind": kind})
        return created

    # 人工撤销（结算/稽核人员） ---------------------------------------------
    def manual_revoke(self, redemption_id: int, reason: str,
                      actor: str = "结算人员") -> dict:
        with self.store.lock:
            r = self.store.query_one("SELECT * FROM redemptions WHERE id=?",
                                     (redemption_id,))
            if not r:
                raise DomainError("REDEMPTION_NOT_FOUND",
                                  f"核销记录不存在: {redemption_id}", 404)
            if r["result"] == RESULT_REVOKED:
                raise DomainError("ALREADY_REVOKED", "该核销已撤销，请勿重复操作", 409)
            # 已清算批次中的核销：只能在当前开放周期以调整单冲抵，批次不改写
            related_batch = r["settlement_batch_id"]
            created = self._claw_back(r["ticket_code"], ADJ_MANUAL_REVOKE, reason,
                                      actor, spot_scope=r["spot_code"])
            note = "冲抵已封账批次，调整计入当前开放周期" if related_batch else None
            ev = self.store.append_event(actor, "redemption.manual_revoked",
                                         {"redemption_id": redemption_id,
                                          "ticket_code": r["ticket_code"],
                                          "spot_code": r["spot_code"],
                                          "related_batch_id": related_batch,
                                          "reason": reason, "note": note})
            self.store.commit()
        return {"redemption_id": redemption_id, "adjustments": created,
                "related_batch_id": related_batch, "note": note,
                "event_seq": ev["seq"]}

    # 复核队列裁决 ----------------------------------------------------------
    def list_reviews(self, status: str = REVIEW_OPEN) -> list[dict]:
        rows = self.store.query(
            "SELECT * FROM review_cases WHERE status=? ORDER BY id", (status,))
        return [dict(r) | {"reasons": json.loads(r["reasons"]),
                           "evidence": json.loads(r["evidence"])} for r in rows]

    def resolve_review(self, review_id: int, approve: bool, actor: str,
                       reason: str = "") -> dict:
        with self.store.lock:
            case = self.store.query_one("SELECT * FROM review_cases WHERE id=?",
                                        (review_id,))
            if not case:
                raise DomainError("REVIEW_NOT_FOUND", f"复核单不存在: {review_id}", 404)
            if case["status"] != REVIEW_OPEN:
                raise DomainError("REVIEW_CLOSED",
                                  f"复核单已裁决: {case['status']}", 409)
            r = self.store.query_one("SELECT * FROM redemptions WHERE id=?",
                                     (case["redemption_id"],))
            adjustment_id = None
            if approve:
                # 票仍有效且权益键未被占用时才转为有效；否则继续留痕不补贴
                occupied = self.store.query_one(
                    "SELECT 1 FROM valid_redemption_keys WHERE ticket_code=? "
                    "AND spot_code=?", (case["ticket_code"], case["spot_code"]))
                ticket = self.store.query_one(
                    "SELECT status FROM tickets WHERE code=?",
                    (case["ticket_code"],))
                if not occupied and ticket and ticket["status"] == "正常":
                    self.store.conn.execute(
                        "UPDATE redemptions SET result=? WHERE id=?",
                        (RESULT_VALID, case["redemption_id"]))
                    self.store.insert(
                        "INSERT INTO valid_redemption_keys(ticket_code,spot_code,"
                        "redemption_id) VALUES(?,?,?)",
                        (case["ticket_code"], case["spot_code"],
                         case["redemption_id"]))
                    decision = "approved_valid"
                else:
                    self.store.conn.execute(
                        "UPDATE redemptions SET result=? WHERE id=?",
                        (RESULT_REVOKED, case["redemption_id"]))
                    decision = "approved_unbindable"
            else:
                if r:
                    self.store.conn.execute(
                        "UPDATE redemptions SET result=? WHERE id=?",
                        (RESULT_REVOKED, case["redemption_id"]))
                # 若该笔曾因复核挂起而后被错误计入（正常不会），驳回生成负调整
                existing = self.store.query_one(
                    "SELECT 1 FROM valid_redemption_keys WHERE redemption_id=?",
                    (case["redemption_id"],))
                decision = "rejected"
                if existing:
                    tt = r["ticket_type"] if r else "纸质票根"
                    aid = self.store.insert(
                        "INSERT INTO adjustments(ticket_code,spot_code,"
                        "redemption_id,kind,amount,reason,event_at) "
                        "VALUES(?,?,?,?,?,?,?)",
                        (case["ticket_code"], case["spot_code"],
                         case["redemption_id"], ADJ_REVIEW_REJECT,
                         -self.cfg.subsidy[tt] * 100, reason or "复核驳回", self._ts()))
                    adjustment_id = aid
            self.store.conn.execute(
                "UPDATE review_cases SET status=?,decided_by=?,decided_at=?,"
                "adjustment_id=? WHERE id=?",
                (REVIEW_APPROVED if approve else REVIEW_REJECTED, actor, self._ts(),
                 adjustment_id, review_id))
            ev = self.store.append_event(actor, "review.resolved",
                                         {"review_id": review_id,
                                          "approved": approve, "decision": decision,
                                          "reason": reason,
                                          "adjustment_id": adjustment_id})
            self.store.commit()
        return {"review_id": review_id, "approved": approve, "decision": decision,
                "adjustment_id": adjustment_id, "event_seq": ev["seq"]}

    # 清算批次 --------------------------------------------------------------
    def _ensure_batch(self, kind: str, start: datetime, spot_code: str) -> int:
        end = shift_period(kind, start, 1)
        row = self.store.query_one(
            "SELECT id FROM settlement_batches WHERE period_kind=? AND period_start=? "
            "AND spot_code=?", (kind, fmt_ts(start), spot_code))
        if row:
            return row["id"]
        return self.store.insert(
            "INSERT INTO settlement_batches(period_kind,period_start,period_end,"
            "spot_code,status) VALUES(?,?,?,?,'开放')",
            (kind, fmt_ts(start), fmt_ts(end), spot_code))

    def _project(self, kind: str, start: datetime, spot_code: str) -> dict:
        """投影某景区某周期的可结算事项。

        封账采用"上界归集"：归入本景区所有 event_at < 本周期结束 且尚未绑定
        批次的事项。配合"必须按周期顺序封账"，更早周期的事项要么已被前置
        批次取走，要么作为迟来事项滚入本批次；结果只取决于事件时间与调整单
        内容，与调用时机/顺序无关。
        """
        end = shift_period(kind, start, 1)
        e = fmt_ts(end)
        valid_rows = self.store.query(
            "SELECT r.id rid, r.ticket_type tt, r.event_at ea, r.ticket_code tc "
            "FROM valid_redemption_keys vr JOIN redemptions r ON r.id=vr.redemption_id "
            "WHERE vr.spot_code=? AND r.event_at<? AND vr.batch_id IS NULL",
            (spot_code, e))
        adj_rows = self.store.query(
            "SELECT a.id aid, a.amount amt, a.kind kind, a.event_at ea, "
            "a.related_batch_id rb FROM adjustments a "
            "WHERE a.spot_code=? AND a.event_at<? AND a.settlement_batch_id IS NULL",
            (spot_code, e))
        items = [("R", r["rid"], self.cfg.subsidy[r["tt"]] * 100, r["ea"],
                  r["tc"]) for r in valid_rows]
        items += [("A", r["aid"], r["amt"], r["ea"], r["kind"]) for r in adj_rows]
        items.sort(key=lambda x: (x[3], x[0], x[1]))
        gross = sum(v for t, _, v, _, _ in items if t == "R")
        adj_sum = sum(v for t, _, v, _, _ in items if t == "A")
        fingerprint = sha256_hex(canonical_json(
            [{"t": t, "id": i, "v": v, "at": at, "ref": ref}
             for t, i, v, at, ref in items]).encode())
        return {"items": items, "count": sum(1 for t, *_ in items if t == "R"),
                "gross": gross, "adjustments_sum": adj_sum,
                "net": gross + adj_sum, "input_fingerprint": fingerprint,
                "period_start": fmt_ts(start), "period_end": e}

    def seal_batch(self, kind: str, period_start: str, spot_code: str,
                   actor: str = "结算人员") -> dict:
        if spot_code not in self.cfg.spots:
            raise DomainError("BAD_SPOT", f"未知景区: {spot_code}", 404)
        if kind != self.cfg.cadence_of(spot_code):
            raise DomainError(
                "CADENCE_MISMATCH",
                f"景区{spot_code}按分组口径执行{self.cfg.cadence_of(spot_code)}，"
                f"不能按{kind}封账", 400)
        start = parse_ts(period_start)
        start = start.replace(minute=0, hour=0, second=0, microsecond=0)
        if kind == "月结":
            start = start.replace(day=1)
        elif kind == "周结":
            start = (start - timedelta(days=start.weekday())).replace(hour=0)
        end = shift_period(kind, start, 1)
        if self._now() < end:
            raise DomainError("PERIOD_OPEN", "该周期尚未结束，不能封账", 409)
        with self.store.lock:
            # 顺序封账：同一周期口径同景区不允许有更早的未封账批次
            bid = self._ensure_batch(kind, start, spot_code)
            batch = self.store.query_one(
                "SELECT * FROM settlement_batches WHERE id=?", (bid,))
            if batch["status"] == "已封账":
                raise DomainError("ALREADY_SEALED", "该批次已封账，不可改写", 409)
            prev_open = self.store.query_one(
                "SELECT id FROM settlement_batches WHERE period_kind=? AND spot_code=? "
                "AND period_start<? AND status!='已封账' ORDER BY period_start",
                (kind, spot_code, fmt_ts(start)))
            if prev_open:
                raise DomainError("OUT_OF_ORDER_SEAL",
                                  "存在更早的未封账周期，必须按周期顺序封账", 409)
            proj = self._project(kind, start, spot_code)
            seq_row = self.store.query_one(
                "SELECT COALESCE(MAX(seq),0)+1 n FROM settlement_batches "
                "WHERE spot_code=?", (spot_code,))
            seq = seq_row["n"]
            snapshot = {
                "batch_id": bid, "period_kind": kind, "spot_code": spot_code,
                "period_start": proj["period_start"], "period_end": proj["period_end"],
                "seq": seq,
                "items": [{"t": t, "id": i, "value_fen": v, "at": at, "ref": ref}
                          for t, i, v, at, ref in proj["items"]],
                "gross_fen": proj["gross"], "adjustments_fen": proj["adjustments_sum"],
                "net_fen": proj["net"], "input_fingerprint": proj["input_fingerprint"],
            }
            snapshot_hash = sha256_hex(canonical_json(snapshot).encode())
            self.store.conn.execute(
                "UPDATE settlement_batches SET status='已封账',count=?,gross=?,"
                "adjustments=?,net=?,input_fingerprint=?,snapshot_hash=?,sealed_at=?,"
                "seq=? WHERE id=?",
                (proj["count"], proj["gross"], proj["adjustments_sum"], proj["net"],
                 proj["input_fingerprint"], snapshot_hash, self._ts(), seq, bid))
            # 绑定事项到批次
            for t, i, v, at, ref in proj["items"]:
                if t == "R":
                    self.store.conn.execute(
                        "UPDATE valid_redemption_keys SET batch_id=? WHERE redemption_id=?",
                        (bid, i))
                    self.store.conn.execute(
                        "UPDATE redemptions SET result=?, settlement_batch_id=? WHERE id=?",
                        (RESULT_SETTLED, bid, i))
                else:
                    self.store.conn.execute(
                        "UPDATE adjustments SET settlement_batch_id=? WHERE id=?",
                        (bid, i))
            ev = self.store.append_event(actor, "batch.sealed",
                                         {"batch_id": bid, "period_kind": kind,
                                          "spot_code": spot_code,
                                          "period_start": proj["period_start"],
                                          "period_end": proj["period_end"],
                                          "count": proj["count"],
                                          "gross_fen": proj["gross"],
                                          "adjustments_fen": proj["adjustments_sum"],
                                          "net_fen": proj["net"], "seq": seq,
                                          "input_fingerprint": proj["input_fingerprint"],
                                          "snapshot_hash": snapshot_hash})
            self.store.commit()
        return {"batch_id": snapshot["batch_id"],
                "period_kind": snapshot["period_kind"],
                "spot_code": snapshot["spot_code"],
                "period_start": snapshot["period_start"],
                "period_end": snapshot["period_end"], "seq": snapshot["seq"],
                "count": proj["count"], "gross_fen": snapshot["gross_fen"],
                "adjustments_fen": snapshot["adjustments_fen"],
                "net_fen": snapshot["net_fen"],
                "input_fingerprint": snapshot["input_fingerprint"],
                "snapshot_hash": snapshot_hash,
                "sealed_at": self._ts(), "event_seq": ev["seq"]}

    def recompute_batch(self, batch_id: int) -> dict:
        """以批次封账时保存的输入指纹与快照哈希复算，证明批次可复算、未被篡改。"""
        with self.store.lock:
            b = self.store.query_one("SELECT * FROM settlement_batches WHERE id=?",
                                     (batch_id,))
            if not b:
                raise DomainError("BATCH_NOT_FOUND", f"批次不存在: {batch_id}", 404)
            chain = self.store.verify_chain()
            if not chain["ok"]:
                return {"batch_id": batch_id, "recomputable": False,
                        "reason": "哈希链断裂", "chain": chain}
            rows = self.store.query(
                "SELECT r.id rid, r.ticket_type tt, r.event_at ea, r.ticket_code tc "
                "FROM redemptions r WHERE r.settlement_batch_id=?", (batch_id,))
            items = [("R", r["rid"], self.cfg.subsidy[r["tt"]] * 100, r["ea"],
                      r["tc"]) for r in rows]
            arows = self.store.query(
                "SELECT id aid, amount amt, kind, event_at ea FROM adjustments "
                "WHERE settlement_batch_id=?", (batch_id,))
            items += [("A", r["aid"], r["amt"], r["ea"], r["kind"]) for r in arows]
            items.sort(key=lambda x: (x[3], x[0], x[1]))
            fp = sha256_hex(canonical_json(
                [{"t": t, "id": i, "v": v, "at": at, "ref": ref}
                 for t, i, v, at, ref in items]).encode())
            gross = sum(v for t, _, v, _, _ in items if t == "R")
            adj_sum = sum(v for t, _, v, _, _ in items if t == "A")
            match = (fp == b["input_fingerprint"]
                     and gross == b["gross"] and adj_sum == b["adjustments"]
                     and gross + adj_sum == b["net"])
            return {"batch_id": batch_id, "recomputable": bool(match),
                    "stored": {"count": b["count"], "gross_fen": b["gross"],
                               "adjustments_fen": b["adjustments"],
                               "net_fen": b["net"],
                               "input_fingerprint": b["input_fingerprint"],
                               "snapshot_hash": b["snapshot_hash"]},
                    "recomputed": {"count": sum(1 for t, *_ in items if t == "R"),
                                   "gross_fen": gross,
                                   "adjustments_fen": adj_sum,
                                   "net_fen": gross + adj_sum,
                                   "input_fingerprint": fp},
                    "chain_tail": chain["tail"]}

    def list_batches(self, spot_code: str | None = None) -> list[dict]:
        sql = ("SELECT * FROM settlement_batches "
               + ("WHERE spot_code=? " if spot_code else "")
               + "ORDER BY period_kind, period_start, spot_code")
        rows = self.store.query(sql, (spot_code,) if spot_code else ())
        return [dict(r) for r in rows]

    # 顺序无关性自证明 ------------------------------------------------------
    def prove_order_independence(self, fixture: dict) -> dict:
        """用一份自包含签名夹具，在全新内存库上以多种顺序（含乱序与重复补传）
        重放同一批离线记录，比对各景区有效权益集合与清算指纹是否完全一致。"""
        import itertools
        results = {}
        orders = {
            "原序": fixture["records"],
            "逆序": list(reversed(fixture["records"])),
            "洗牌": [fixture["records"][i] for i in fixture["shuffle"]],
        }
        # 重复补传：先传一半，再全量
        orders["重复补传"] = fixture["records"][:1] + fixture["records"]
        for name, recs in orders.items():
            svc = _build_proof_service(self.cfg, fixture)
            for t in fixture["tickets"]:
                svc.issue_ticket(**t)
            for m in fixture["matches"]:
                svc.register_match(**m)
            svc.upload_offline(recs, fixture["manifest"])
            snapshot = svc._rights_snapshot()
            results[name] = snapshot
        digests = {name: sha256_hex(canonical_json(snap).encode())
                   for name, snap in results.items()}
        unique = set(digests.values())
        return {
            "conclusion": "同一批离线记录无论以何种顺序/重放到达，只产生一次有效权益"
            if len(unique) == 1 else "顺序敏感，实现存在缺陷",
            "identical": len(unique) == 1,
            "digests": digests,
            "snapshot": results["原序"],
            "orders_verified": list(orders.keys()),
        }

    def _rights_snapshot(self) -> dict:
        # 只取业务身份（票号, 景区），与哪条记录先占用、自增行号无关
        rows = self.store.query(
            "SELECT DISTINCT ticket_code tc, spot_code sc "
            "FROM valid_redemption_keys ORDER BY tc, sc")
        valid = [[r["tc"], r["sc"]] for r in rows]
        reviews = self.store.query(
            "SELECT ticket_code tc, spot_code sc FROM review_cases "
            "WHERE status=? ORDER BY id", (REVIEW_OPEN,))
        return {"valid_rights": valid,
                "pending_review": [[r["tc"], r["sc"]] for r in reviews],
                "total_valid": len(valid)}


def device_id_of(body: dict) -> str:
    return body["device_id"]


def _build_proof_service(cfg: DomainConfig, fixture: dict) -> ClearingService:
    """为顺序无关性证明构建隔离的内存服务实例（同 issuer 密钥以验签）。"""
    fixed = parse_ts(fixture["server_now"])
    store = Store(":memory:", clock=lambda: fixed)
    svc = ClearingService(cfg, store, issuer_secret=fixture["issuer_secret"],
                          device_secrets={fixture["device_id"]:
                                         fixture["device_secret"]},
                          clock=lambda: fixed)
    svc.register_device(fixture["device_id"], fixture["device_secret"],
                        fixture["device_spot"], fixture.get("site", "证明网点"))
    return svc


def build_order_independence_fixture(cfg: DomainConfig,
                                     at: datetime | None = None) -> dict:
    """构造一份自包含签名夹具：含正常、同票同景区重复、票种越界待复核三类记录，
    可在隔离内存库中重放，供接口与测试复用。"""
    at = (at or datetime(2026, 5, 13, 10, 0, tzinfo=TZ))
    at_s = fmt_ts(at)
    issuer_secret, device_secret = "proof-issuer-secret", "proof-device-secret"
    device_id, spot0 = "DEV-PROOF", "S001"
    match_code = "M2026-PROOF"
    tickets = [
        {"ticket_code": "P-T001", "ticket_type": "纸质票根", "holder": "张三",
         "match_code": match_code, "face_value": 80, "issued_at": at_s},
        {"ticket_code": "P-T002", "ticket_type": "纸质票根", "holder": "李四",
         "match_code": match_code, "face_value": 80, "issued_at": at_s},
        {"ticket_code": "P-T003", "ticket_type": "纸质票根", "holder": "王五",
         "match_code": match_code, "face_value": 80, "issued_at": at_s},
        {"ticket_code": "P-T004", "ticket_type": "团体票", "holder": "赵六团",
         "match_code": match_code, "face_value": 200, "issued_at": at_s},
        {"ticket_code": "P-T005", "ticket_type": "团体票", "holder": "孙七团",
         "match_code": match_code, "face_value": 200, "issued_at": at_s},
    ]
    raw_specs = [
        ("R1", "P-T001", "张三", "纸质票根"),
        ("R2", "P-T002", "李四", "纸质票根"),
        ("R3", "P-T003", "王五", "纸质票根"),
        ("R4", "P-T002", "李四", "纸质票根"),   # 与 R2 同票同景区 → 重复
        ("R5", "P-T004", "赵六团", "团体票"),
        ("R6", "P-T005", "孙七团", "纸质票根"),  # 申报票种与票根不符 → 待复核
    ]
    records: list[dict] = []
    for rid, tc, holder, ttype in raw_specs:
        body, sig = ClearingService.build_offline_record(
            device_secret, device_id, rid, tc, holder, ttype, spot0,
            match_code, "证明网点闸机", at_s)
        body["record_sig"] = sig
        records.append(body)
    keys = sorted(r["record_id"] for r in records)
    manifest = {
        "manifest_id": "MF-PROOF-0001",
        "device_id": device_id,
        "record_ids": keys,
        "keys_sig": sign_payload(device_secret,
                                 {"device_id": device_id, "record_ids": keys}),
    }
    shuffle = [3, 0, 5, 1, 4, 2]  # 任意确定性乱序索引
    return {
        "issuer_secret": issuer_secret,
        "device_secret": device_secret,
        "device_id": device_id,
        "device_spot": spot0,
        "site": "证明网点闸机",
        "server_now": at_s,
        "tickets": tickets,
        "matches": [{"match_code": match_code, "kickoff_at": at_s}],
        "records": records,
        "manifest": manifest,
        "shuffle": shuffle,
    }
