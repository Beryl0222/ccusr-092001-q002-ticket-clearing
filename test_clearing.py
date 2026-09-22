"""可复算清算批次：周期归属、幂等定稿、往期追补/冲正、篡改检测、重放重建。"""

import json

import pytest

from domain import parse_iso

MONTH_SCENIC = "柳子庙"      # 月结 3000
WEEK_SCENIC = "勾蓝瑶寨"     # 周结 4000
TICKET = "T-ET-1001"
HOLDER = "张磊"


def redeem_at(system, sign, device_for, scenic, when_iso, bk, seq,
              ticket=TICKET, holder=HOLDER):
    """把服务器时间与签名时间一起固定到 when（+60 秒），再提交一条离线记录。"""
    t = parse_iso(when_iso)
    system.clock.set(t + 60)
    did = device_for(system, scenic)
    rec = sign(system.demo, did, seq, ticket, holder, scenic, t, bk)
    return system.core.submit_offline(rec)


def test_monthly_batch_collects_only_in_period(system, sign, device_for):
    redeem_at(system, sign, device_for, MONTH_SCENIC,
              "2026-03-08T10:00:00+08:00", "BK-1", 1)
    redeem_at(system, sign, device_for, MONTH_SCENIC,
              "2026-03-09T10:00:00+08:00", "BK-2", 2)
    # 4 月记录须用 4 月场次的票（T-ET-1004，4/11 场次，持票人赵敏）
    redeem_at(system, sign, device_for, MONTH_SCENIC,
              "2026-04-12T10:00:00+08:00", "BK-3", 3,
              ticket="T-ET-1004", holder="赵敏")
    b3 = system.clearing.finalize(MONTH_SCENIC, "月结", "2026-03")
    assert b3["event_count"] == 2
    assert b3["total_cents"] == 6000
    b4 = system.clearing.finalize(MONTH_SCENIC, "月结", "2026-04")
    assert b4["event_count"] == 1 and b4["total_cents"] == 3000
    assert system.clearing.verify_batches()["ok"] is True


def test_weekly_boundary_splits_batches(system, sign, device_for):
    # 3/8 周日属 W10；3/9 周一属 W11
    redeem_at(system, sign, device_for, WEEK_SCENIC,
              "2026-03-08T15:00:00+08:00", "BK-1", 1)
    redeem_at(system, sign, device_for, WEEK_SCENIC,
              "2026-03-09T15:00:00+08:00", "BK-2", 2)
    b1 = system.clearing.finalize(WEEK_SCENIC, "周结", "2026-W10")
    b2 = system.clearing.finalize(WEEK_SCENIC, "周结", "2026-W11")
    assert b1["total_cents"] == 4000 and b2["total_cents"] == 4000
    assert b1["batch_id"] != b2["batch_id"]


def test_finalize_is_idempotent(system, sign, device_for):
    redeem_at(system, sign, device_for, MONTH_SCENIC,
              "2026-03-08T10:00:00+08:00", "BK-1", 1)
    b1 = system.clearing.finalize(MONTH_SCENIC, "月结", "2026-03")
    b2 = system.clearing.finalize(MONTH_SCENIC, "月结", "2026-03")
    assert b1["batch_id"] == b2["batch_id"]
    assert b1["content_hash"] == b2["content_hash"]
    assert b2.get("idempotent") is True
    # 定稿后再到达的同周期有效记录不会改动已定稿批次（落入下期追补）
    redeem_at(system, sign, device_for, MONTH_SCENIC,
              "2026-03-10T10:00:00+08:00", "BK-2", 2)
    b_again = system.clearing.finalize(MONTH_SCENIC, "月结", "2026-03")
    assert b_again["content_hash"] == b1["content_hash"]
    b4 = system.clearing.finalize(MONTH_SCENIC, "月结", "2026-04")
    assert any(i["kind"] == "追补" and i["amount_cents"] == 3000
               for i in b4["items"])


def test_refund_after_settlement_creates_one_reversal(system, sign, device_for):
    """清算后退款：原批不改，负向冲正只在下期出现一次，不发生重复补贴。"""
    redeem_at(system, sign, device_for, MONTH_SCENIC,
              "2026-03-08T10:00:00+08:00", "BK-1", 1)
    redeem_at(system, sign, device_for, MONTH_SCENIC,
              "2026-03-09T10:00:00+08:00", "BK-2", 2)
    b3 = system.clearing.finalize(MONTH_SCENIC, "月结", "2026-03")
    assert b3["total_cents"] == 6000

    system.clock.set(parse_iso("2026-04-05T10:00:00+08:00"))
    system.core.refund_ticket(TICKET)
    # 重复退款不会产生第二笔冲正
    system.core.refund_ticket(TICKET)
    n_rev = system.store.conn.execute(
        "SELECT COUNT(*) n FROM adjustments WHERE kind='冲正'").fetchone()["n"]
    assert n_rev == 2  # 恰好两笔，每张已兑记录一笔

    b4 = system.clearing.finalize(MONTH_SCENIC, "月结", "2026-04")
    assert b4["total_cents"] == -6000
    reversals = [i for i in b4["items"] if i["kind"] == "冲正"]
    assert len(reversals) == 2 and all(i["amount_cents"] == -3000
                                       for i in reversals)
    # 两批净额 = 0，且三月批次指纹不变
    assert b3["total_cents"] + b4["total_cents"] == 0
    assert system.clearing.get_batch(b3["batch_id"])["content_hash"] == \
        b3["content_hash"]
    # 冲正已结，再定稿五月不会再次追回
    b5 = system.clearing.finalize(MONTH_SCENIC, "月结", "2026-05")
    assert b5["event_count"] == 0


def test_paper_approved_after_period_closed_is_caught_up(system, sign,
                                                         device_for):
    """纸质票根在批次定稿后才复核通过：往期追补进入下期，不重开历史批。"""
    redeem_at(system, sign, device_for, MONTH_SCENIC,
              "2026-03-08T10:00:00+08:00", "BK-P1", 1,
              ticket="T-PA-2001", holder="王芳")
    b3 = system.clearing.finalize(MONTH_SCENIC, "月结", "2026-03")
    assert b3["event_count"] == 0  # 待复核，不计入

    system.clock.set(parse_iso("2026-04-06T10:00:00+08:00"))
    rid = int(system.core.list_reviews()[0]["id"])
    dec = system.core.decide_review(rid, True, "auditor")
    assert dec["redemption"]["state"] == "有效"
    b4 = system.clearing.finalize(MONTH_SCENIC, "月结", "2026-04")
    catches = [i for i in b4["items"] if i["kind"] == "追补"]
    assert len(catches) == 1 and catches[0]["amount_cents"] == 3000
    # 三月批次仍为空批，历史不可变
    assert system.clearing.get_batch(b3["batch_id"])["total_cents"] == 0


def test_batch_hash_deterministic_across_instances(system, sign, device_for):
    """同样的业务动作在两个实例上产生相同 batch_id 与 content_hash。"""
    from app import System
    from seed import seed_demo
    t = parse_iso("2026-03-08T10:00:00+08:00")
    did = system.demo["device_by_scenic"][MONTH_SCENIC]
    system.clock.set(t + 60)
    rec = sign(system.demo, did, 1, TICKET, HOLDER, MONTH_SCENIC, t, "BK-1")
    system.core.submit_offline(rec)
    b1 = system.clearing.finalize(MONTH_SCENIC, "月结", "2026-03")

    secrets = {d: i["secret"] for d, i in system.demo["devices"].items()}

    class FixedClock:
        def __call__(self):
            return t + 60

    other = System(":memory:", clock=FixedClock())
    other.demo = seed_demo(other, device_secrets=secrets)
    rec2 = sign(other.demo, did, 1, TICKET, HOLDER, MONTH_SCENIC, t, "BK-1")
    other.core.submit_offline(rec2)
    b2 = other.clearing.finalize(MONTH_SCENIC, "月结", "2026-03")
    assert b2["batch_id"] == b1["batch_id"]
    assert b2["content_hash"] == b1["content_hash"]
    assert b2["total_cents"] == b1["total_cents"]
    other.close()


def test_tamper_with_materialized_row_is_detected(system, sign, device_for):
    redeem_at(system, sign, device_for, MONTH_SCENIC,
              "2026-03-08T10:00:00+08:00", "BK-1", 1)
    system.clearing.finalize(MONTH_SCENIC, "月结", "2026-03")
    # 绕过台账直接改物化表金额（伪造补贴）
    fp = system.store.conn.execute(
        "SELECT fingerprint FROM redemptions WHERE business_key='BK-1'") \
        .fetchone()[0]
    system.store.conn.execute(
        "UPDATE redemptions SET amount_cents=99999 WHERE fingerprint=?", (fp,))
    res = system.clearing.verify_batches()
    assert res["ok"] is False
    assert any("金额被改动" in p for b in res["batches"] for p in b["problems"])


def test_tamper_with_ledger_breaks_hash_chain(system, sign, device_for):
    redeem_at(system, sign, device_for, MONTH_SCENIC,
              "2026-03-08T10:00:00+08:00", "BK-1", 1)
    tip_before = system.store.chain_tip()
    # 直接改写一条历史台账事件
    row = system.store.conn.execute(
        "SELECT seq,body FROM events WHERE type='核销' LIMIT 1").fetchone()
    body = json.loads(row["body"])
    body["amount_cents"] = 99999
    system.store.conn.execute("UPDATE events SET body=? WHERE seq=?",
                              (json.dumps(body, ensure_ascii=False,
                                          sort_keys=True), row["seq"]))
    ok, broken = system.store.verify_chain()
    assert ok is False and broken is not None
    assert system.clearing.verify_batches()["ok"] is False
    assert tip_before != system.store.chain_tip() or broken is not None


def test_rebuild_state_reproduces_batches(system, sign, device_for):
    """清空物化状态、重放台账后，每批哈希与总额逐笔一致。"""
    redeem_at(system, sign, device_for, MONTH_SCENIC,
              "2026-03-08T10:00:00+08:00", "BK-1", 1)
    redeem_at(system, sign, device_for, MONTH_SCENIC,
              "2026-03-09T10:00:00+08:00", "BK-2", 2)
    b3 = system.clearing.finalize(MONTH_SCENIC, "月结", "2026-03")
    system.clock.set(parse_iso("2026-04-05T10:00:00+08:00"))
    system.core.refund_ticket(TICKET)
    b4 = system.clearing.finalize(MONTH_SCENIC, "月结", "2026-04")

    fp_before = system.core.state_fingerprint()
    res = system.core.rebuild_state()
    assert res["chain_ok"] is True
    verify = system.clearing.verify_batches()
    assert verify["ok"] is True
    # 重放后批次内容哈希不变
    assert system.clearing.get_batch(b3["batch_id"])["content_hash"] == \
        b3["content_hash"]
    assert system.clearing.get_batch(b4["batch_id"])["total_cents"] == -6000
    assert system.core.state_fingerprint() == fp_before


def test_pending_catchup_voided_when_record_revoked_before_next_batch(
        system, sign, device_for):
    """往期追补还未出账，该记录即被名额挤出/退款：追补作废，下期无该项。"""
    # 3/10 先占满 3 个名额并定稿 3 月
    for i, (day, bk) in enumerate([("08", "BK-2"), ("09", "BK-3"),
                                   ("10", "BK-4")], start=2):
        redeem_at(system, sign, device_for, MONTH_SCENIC,
                  f"2026-03-{day}T10:00:00+08:00", bk, i)
    system.clearing.finalize(MONTH_SCENIC, "月结", "2026-03")
    # 3/12 早记录晚到：成为有效并挂 4 月追补，同时把 BK-4 挤成冲正
    did = device_for(system, MONTH_SCENIC)
    early = parse_iso("2026-03-07T20:00:00+08:00")
    system.clock.set(parse_iso("2026-03-12T12:00:00+08:00"))
    rec = sign(system.demo, did, 1, TICKET, HOLDER, MONTH_SCENIC, early, "BK-1")
    system.core.submit_offline(rec)
    pending = system.store.conn.execute(
        "SELECT COUNT(*) n FROM adjustments WHERE kind='追补' AND state='待结'"
    ).fetchone()["n"]
    assert pending == 1
    # 4 月定稿前退款：BK-1 的待结追补必须作废，只留 BK-2/BK-3/BK-4 的冲正
    system.clock.set(parse_iso("2026-04-01T10:00:00+08:00"))
    system.core.refund_ticket(TICKET)
    voided = system.store.conn.execute(
        "SELECT COUNT(*) n FROM adjustments WHERE kind='追补' AND state='已作废'"
    ).fetchone()["n"]
    assert voided == 1
    b4 = system.clearing.finalize(MONTH_SCENIC, "月结", "2026-04")
    assert not any(i["kind"] == "追补" for i in b4["items"])
    # 三笔已清算记录各一笔 -3000 冲正
    assert b4["total_cents"] == -9000
    assert system.clearing.verify_batches()["ok"] is True
    # 重放后同样成立
    fp = system.core.state_fingerprint()
    assert system.core.rebuild_state()["chain_ok"] is True
    assert system.core.state_fingerprint() == fp


def test_scenic_isolation(system, sign, device_for):
    redeem_at(system, sign, device_for, MONTH_SCENIC,
              "2026-03-08T10:00:00+08:00", "BK-1", 1)
    redeem_at(system, sign, device_for, WEEK_SCENIC,
              "2026-03-08T10:00:00+08:00", "BK-1", 1)
    b = system.clearing.finalize(MONTH_SCENIC, "月结", "2026-03")
    assert b["event_count"] == 1 and b["total_cents"] == 3000


def test_late_earlier_record_displaces_settled_winner_without_double_pay(
        system, sign, device_for):
    """批次定稿后，更早的记录在补传时限内晚到：确定性赢家集合重排，
    被挤出的已清算名额产生负向冲正，晚到记录以追补出账，净补贴不增加。"""
    # 3/10 当天补传 3 条（3/8、3/9、3/10 入园），占满 3 个名额
    redeem_at(system, sign, device_for, MONTH_SCENIC,
              "2026-03-08T10:00:00+08:00", "BK-2", 2)
    redeem_at(system, sign, device_for, MONTH_SCENIC,
              "2026-03-09T10:00:00+08:00", "BK-3", 3)
    redeem_at(system, sign, device_for, MONTH_SCENIC,
              "2026-03-10T10:00:00+08:00", "BK-4", 4)
    b3 = system.clearing.finalize(MONTH_SCENIC, "月结", "2026-03")
    assert b3["total_cents"] == 9000

    # 3/12 补传一条 3/7 20:00 的更早记录（补传时限 7 天内）
    did = device_for(system, MONTH_SCENIC)
    early = parse_iso("2026-03-07T20:00:00+08:00")
    system.clock.set(parse_iso("2026-03-12T12:00:00+08:00"))
    rec = sign(system.demo, did, 1, TICKET, HOLDER, MONTH_SCENIC, early, "BK-1")
    system.core.submit_offline(rec)
    displaced = system.store.conn.execute(
        "SELECT state,settled_batch_id,revoke_reason FROM redemptions "
        "WHERE business_key='BK-4'").fetchone()
    assert displaced["state"] == "已撤销"
    assert displaced["settled_batch_id"] == b3["batch_id"]
    assert displaced["revoke_reason"] == "超出权益次数"

    # 4 月批次：+3000 追补（晚到的 BK-1）、-3000 冲正（被挤出的 BK-4）
    system.clock.set(parse_iso("2026-04-02T10:00:00+08:00"))
    b4 = system.clearing.finalize(MONTH_SCENIC, "月结", "2026-04")
    kinds = {i["kind"]: i["amount_cents"] for i in b4["items"]}
    assert kinds.get("追补") == 3000
    assert kinds.get("冲正") == -3000
    assert b4["total_cents"] == 0
    # 两批净额仍为 9000：三个名额，没有第四份补贴
    assert b3["total_cents"] + b4["total_cents"] == 9000
    assert system.clearing.verify_batches()["ok"] is True
    # 清空物化状态重放台账后，业务指纹与复算结论完全一致
    fp = system.core.state_fingerprint()
    rebuilt = system.core.rebuild_state()
    assert rebuilt["chain_ok"] is True
    assert system.core.state_fingerprint() == fp
    assert system.clearing.verify_batches()["ok"] is True
