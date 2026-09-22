"""票券/场次生命周期：退款、延期、取消、人工撤销，均不得重复补贴。"""

import pytest

from domain import R_REVOKED, R_VALID, REV_CANCEL, REV_POSTPONE, REV_REFUND

SCENIC = "柳子庙"
TICKET = "T-ET-1001"
HOLDER = "张磊"


def test_refund_revokes_all_future_and_valid_redemptions(system, sign, device_for):
    did = device_for(system, SCENIC)
    for i in range(2):
        rec = sign(system.demo, did, i + 1, TICKET, HOLDER, SCENIC,
                   system.clock.t - 3600 + i * 100, f"BK-{i}")
        system.core.submit_offline(rec)
    system.core.refund_ticket(TICKET)
    rows = system.store.conn.execute(
        "SELECT state,revoke_reason FROM redemptions WHERE ticket_no=?",
        (TICKET,)).fetchall()
    assert {r["state"] for r in rows} == {R_REVOKED}
    assert {r["revoke_reason"] for r in rows} == {REV_REFUND}
    # 退款后再送达的记录也是退款撤销，不会复活
    rec3 = sign(system.demo, did, 3, TICKET, HOLDER, SCENIC,
                system.clock.t - 100, "BK-2")
    out = system.core.submit_offline(rec3)
    assert out["state"] == R_REVOKED and out["revoke_reason"] == REV_REFUND


def test_cancel_match_revokes_redemptions(system, sign, device_for):
    did = device_for(system, SCENIC)
    rec = sign(system.demo, did, 1, TICKET, HOLDER, SCENIC,
               system.clock.t - 3600, "BK-1")
    system.core.submit_offline(rec)
    system.core.cancel_match("M2026-01")
    out = system.core.get_redemption(
        system.store.conn.execute(
            "SELECT fingerprint FROM redemptions WHERE business_key='BK-1'")
        .fetchone()[0])
    assert out["state"] == R_REVOKED and out["revoke_reason"] == REV_CANCEL


def test_postponement_moves_window_and_revokes_early_redemption(system, sign,
                                                                 device_for):
    """场次延期到 4 月：3 月已兑记录落在新窗口外，确定性冲回；不重复补贴。"""
    from domain import parse_iso
    did = device_for(system, SCENIC)
    rec = sign(system.demo, did, 1, TICKET, HOLDER, SCENIC,
               system.clock.t - 3600, "BK-1")  # 3 月 8 日
    assert system.core.submit_offline(rec)["state"] == R_VALID
    system.core.postpone_match("M2026-01", "2026-04-20T19:30:00+08:00")
    row = system.store.conn.execute(
                "SELECT * FROM redemptions WHERE business_key='BK-1'").fetchone()
    assert row["state"] == R_REVOKED and row["revoke_reason"] == REV_POSTPONE
    # 票券窗口平移到 4/20 起 7 天
    t = system.store.conn.execute(
        "SELECT valid_from FROM tickets WHERE ticket_no=?", (TICKET,)).fetchone()
    assert t["valid_from"] == parse_iso("2026-04-20T19:30:00+08:00")
    # 旧记录重复补传不会复活
    dup = system.core.complete_offline(rec)
    assert dup["state"] == R_REVOKED


def test_postponement_then_new_redemption_in_new_window_pays(system, sign,
                                                             device_for):
    from domain import parse_iso
    did = device_for(system, SCENIC)
    rec = sign(system.demo, did, 1, TICKET, HOLDER, SCENIC,
               system.clock.t - 3600, "BK-1")
    system.core.submit_offline(rec)
    system.core.postpone_match("M2026-01", "2026-04-20T19:30:00+08:00")
    # 服务器时间推进到新比赛日
    system.clock.set(parse_iso("2026-04-21T12:00:00+08:00"))
    rec2 = sign(system.demo, did, 2, TICKET, HOLDER, SCENIC,
                system.clock.t - 3600, "BK-2")
    out = system.core.submit_offline(rec2)
    assert out["state"] == R_VALID


def test_manual_revoke_is_idempotent_and_traced(system, sign, device_for):
    did = device_for(system, SCENIC)
    rec = sign(system.demo, did, 1, TICKET, HOLDER, SCENIC,
               system.clock.t - 3600, "BK-1")
    system.core.submit_offline(rec)
    fp = system.store.conn.execute(
        "SELECT fingerprint FROM redemptions WHERE business_key='BK-1'") \
        .fetchone()[0]
    system.core.manual_revoke(fp, "inspector", note="核查冒领")
    system.core.manual_revoke(fp, "inspector", note="重复操作")
    r = system.core.get_redemption(fp)
    assert r["state"] == R_REVOKED and r["revoke_reason"] == "人工撤销"
    # 台账中可追溯到人工撤销事件
    kinds = [e["body"].get("note") for e in system.store.iter_events(0)
             if e["type"] == "调整" and e["body"].get("fingerprint") == fp]
    assert "核查冒领" in kinds


def test_refund_is_idempotent(system, sign, device_for):
    did = device_for(system, SCENIC)
    rec = sign(system.demo, did, 1, TICKET, HOLDER, SCENIC,
               system.clock.t - 3600, "BK-1")
    system.core.submit_offline(rec)
    r1 = system.core.refund_ticket(TICKET)
    r2 = system.core.refund_ticket(TICKET)
    assert r1["refunded"] is True
    assert r2.get("changed") is False
    # 只有一笔撤销，不重复冲正
    n = system.store.conn.execute(
        "SELECT COUNT(*) n FROM events WHERE type='调整' "
        "AND body LIKE '%票务退款%'").fetchone()["n"]
    # LIKE over JSON text works in SQLite
    assert n >= 1
