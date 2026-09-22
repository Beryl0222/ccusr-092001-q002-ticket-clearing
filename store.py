"""SQLite 存储：追加式哈希链台账 + 可重建的物化状态。

设计要点
--------
1. ``events`` 是唯一真相来源：核销、调整、复核、批次定稿等一切状态变化
   都以追加事件落账，事件间用 sha256 哈希链串联，删除/改写/插入任何一条
   都会让链尾指纹变化（``verify_chain``）。
2. 其余表都是台账的物化视图，可由 ``core.rebuild_state`` 清空重放得到，
   清算的可复算性建立在这一点上。
3. 所有写操作在同一把锁内以 BEGIN IMMEDIATE 提交，配合
   ``redemptions`` 上的 (device_id, device_seq) 与 (ticket_no, scenic,
   business_key) 唯一约束，从数据库层兜底并发重复补贴。
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from pathlib import Path
from typing import Any

from crypto import chain_hash

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scenics (
    scenic TEXT PRIMARY KEY,
    group_name TEXT NOT NULL,
    period TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT UNIQUE NOT NULL,
    ts REAL NOT NULL,
    type TEXT NOT NULL,
    body TEXT NOT NULL,
    prev_hash TEXT,
    hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS replay_audit (
    fingerprint TEXT PRIMARY KEY,
    channel TEXT NOT NULL,
    first_event_id TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    dup_count INTEGER NOT NULL DEFAULT 0,
    note TEXT
);
CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    scenic TEXT NOT NULL,
    secret TEXT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    registered_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS matches (
    match_id TEXT PRIMARY KEY,
    season_code TEXT NOT NULL,
    opponent TEXT,
    kickoff_at REAL NOT NULL,
    status TEXT NOT NULL DEFAULT '正常',
    new_kickoff_at REAL,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS tickets (
    ticket_no TEXT PRIMARY KEY,
    season_code TEXT NOT NULL,
    match_id TEXT NOT NULL,
    ticket_type TEXT NOT NULL,
    holder TEXT NOT NULL,
    issued_at REAL NOT NULL,
    valid_from REAL NOT NULL,
    valid_until REAL NOT NULL,
    status TEXT NOT NULL DEFAULT '正常',
    refunded_at REAL,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS redemptions (
    fingerprint TEXT PRIMARY KEY,
    event_id TEXT NOT NULL,
    channel TEXT NOT NULL,
    device_id TEXT,
    device_seq INTEGER,
    ticket_no TEXT NOT NULL,
    holder TEXT NOT NULL,
    scenic TEXT NOT NULL,
    group_name TEXT NOT NULL,
    amount_cents INTEGER NOT NULL,
    occurred_at REAL NOT NULL,
    server_ts REAL NOT NULL,
    business_key TEXT NOT NULL,
    state TEXT NOT NULL,
    revoke_reason TEXT,
    settled_batch_id TEXT,
    manual_override INTEGER NOT NULL DEFAULT 0,
    carryover INTEGER NOT NULL DEFAULT 0,
    UNIQUE(device_id, device_seq),
    UNIQUE(ticket_no, scenic, business_key)
);
CREATE INDEX IF NOT EXISTS idx_red_ticket ON redemptions(ticket_no);
CREATE INDEX IF NOT EXISTS idx_red_scenic_state ON redemptions(scenic, state);
CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL,
    ticket_no TEXT,
    scenic TEXT,
    reason TEXT NOT NULL,
    occurred_at REAL NOT NULL,
    created_at REAL NOT NULL,
    state TEXT NOT NULL DEFAULT '待复核',
    decided_at REAL,
    decided_by TEXT,
    decision_event_id TEXT
);
CREATE TABLE IF NOT EXISTS adjustments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL,
    ref_fingerprint TEXT,
    ref_batch_id TEXT,
    kind TEXT NOT NULL,
    amount_cents INTEGER NOT NULL,
    scenic TEXT NOT NULL,
    group_name TEXT NOT NULL,
    ticket_no TEXT,
    occurred_at REAL NOT NULL,
    reason TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT '待结',
    settled_batch_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_adj_scenic_state ON adjustments(scenic, state);
CREATE TABLE IF NOT EXISTS batches (
    batch_id TEXT PRIMARY KEY,
    scenic TEXT NOT NULL,
    period TEXT NOT NULL,
    period_key TEXT NOT NULL,
    seq_no INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT '已定稿',
    opened_at REAL NOT NULL,
    finalized_at REAL NOT NULL,
    event_count INTEGER NOT NULL,
    total_cents INTEGER NOT NULL,
    content_hash TEXT NOT NULL,
    body_json TEXT NOT NULL,
    UNIQUE(scenic, period, period_key)
);
"""

STATE_TABLES = ("replay_audit", "scenics", "devices", "matches", "tickets",
                "redemptions", "reviews", "adjustments", "batches")


class Store:
    def __init__(self, path: str | Path = ":memory:"):
        self.path = str(path)
        self.conn = sqlite3.connect(
            self.path, check_same_thread=False, isolation_level=None
        )
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.lock = threading.RLock()
        self._init()

    def _init(self):
        with self.lock:
            self.conn.executescript(SCHEMA)
            genesis = self.get_meta("genesis_hash")
            if genesis is None:
                gh = chain_hash(None, {"genesis": "ticket-benefit-clearing", "version": 1})
                self.set_meta("genesis_hash", gh)

    # ---- meta ----
    def get_meta(self, key: str) -> str | None:
        row = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else None

    def set_meta(self, key: str, value: str):
        self.conn.execute(
            "INSERT INTO meta(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )

    def chain_tip(self) -> str:
        row = self.conn.execute(
            "SELECT hash FROM events ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return row["hash"] if row else self.get_meta("genesis_hash")

    # ---- 追加事件 ----
    def append_event(self, event_id: str, etype: str, body: dict[str, Any],
                     ts: float) -> dict:
        """在哈希链尾部追加事件。调用方须持有锁/事务。"""
        prev = self.chain_tip()
        h = chain_hash(prev, body)
        cur = self.conn.execute(
            "INSERT INTO events(event_id,ts,type,body,prev_hash,hash) "
            "VALUES(?,?,?,?,?,?)",
            (event_id, ts, etype, json.dumps(body, ensure_ascii=False, sort_keys=True),
             prev, h),
        )
        return {"seq": cur.lastrowid, "event_id": event_id, "hash": h, "prev_hash": prev}

    @staticmethod
    def new_event_id() -> str:
        return uuid.uuid4().hex

    def iter_events(self, after_seq: int = 0):
        rows = self.conn.execute(
            "SELECT seq,event_id,ts,type,body,prev_hash,hash FROM events "
            "WHERE seq>? ORDER BY seq", (after_seq,)
        )
        for r in rows:
            d = dict(r)
            d["body"] = json.loads(r["body"])
            yield d

    def verify_chain(self) -> tuple[bool, int | None]:
        """自 genesis 起重算整条哈希链，返回 (是否完整, 断裂位置)。"""
        prev = self.get_meta("genesis_hash")
        for e in self.iter_events(0):
            if e["prev_hash"] != prev:
                return False, e["seq"]
            if chain_hash(prev, e["body"]) != e["hash"]:
                return False, e["seq"]
            prev = e["hash"]
        if self.chain_tip() != prev:
            return False, None
        return True, None

    def wipe_state(self):
        """清空物化状态（不动台账），供重放重建。"""
        for t in STATE_TABLES:
            self.conn.execute(f"DELETE FROM {t}")

    def close(self):
        self.conn.close()
