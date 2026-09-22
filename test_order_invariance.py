"""核心证明：同一批离线记录无论以何种顺序、重复多少次、
是否拆成留存/补传两步到达，最终只产生一次有效权益，且业务状态完全一致。
"""

import itertools
import random

import pytest

from core import BusinessError
from domain import R_PENDING, R_REVIEW, R_REVOKED, R_SETTLED, R_VALID
from domain import parse_iso

# 固定在比赛日次日（与 conftest 时钟一致），保证记录落在权益窗口内
BASE_T = parse_iso("2026-03-08T12:00:00+08:00")

SCENIC = "柳子庙"          # 月结，补贴 3000 分
SCENIC2 = "勾蓝瑶寨"       # 周结，补贴 4000 分
TICKET = "T-ET-1001"      # 实名电子票，限兑 3 次
HOLDER = "张磊"


def _records(sign, demo, did, times):
    """造一组业务键不同的离线记录。"""
    out = []
    prev = None
    for i, t in enumerate(times, start=1):
        bk = f"BK-{i:03d}"
        p = sign(demo, did, i, TICKET, HOLDER, SCENIC, t, bk, prev)
        out.append(p)
        prev = p["sig"]
    return out


def _replay(system, sign, demo, plan):
    """按 plan 描述的操作序列驱动系统，返回最终状态指纹与有效数。"""
    did = demo["device_by_scenic"][SCENIC]
    # 6 条记录，发生时间相隔 1 小时，限兑 3 次
    times = [BASE_T - 3600 * (6 - i) for i in range(1, 7)]
    records = _records(sign, demo, did, times)

    for op in plan:
        kind, idx = op
        rec = records[idx]
        if kind == "submit":
            system.core.submit_offline(rec)
        elif kind == "retain":
            system.core.retain_offline(rec)
        elif kind == "complete":
            system.core.complete_offline(rec)
    return system.core.state_fingerprint()


PLANS = [
    # 1) 全部一步到位，正序
    [("submit", i) for i in range(6)],
    # 2) 全部一步到位，逆序
    [("submit", i) for i in range(5, -1, -1)],
    # 3) 随机交错顺序
    [("submit", i) for i in (2, 5, 0, 4, 1, 3)],
    # 4) 先全部留存，再正序补传
    [("retain", i) for i in range(6)] + [("complete", i) for i in range(6)],
    # 5) 先全部留存，再逆序补传
    [("retain", i) for i in range(6)] + [("complete", i) for i in range(5, -1, -1)],
    # 6) 留存与补传交错：部分一步到位、部分两步，每条记录恰好判定一次
    [("retain", 0), ("complete", 0),
     ("retain", 1), ("retain", 2), ("complete", 2), ("complete", 1),
     ("submit", 3), ("retain", 4), ("retain", 5),
     ("complete", 4), ("complete", 5)],
]


@pytest.mark.parametrize("plan_a,plan_b",
                         [(p, PLANS[0]) for p in PLANS[1:]],
                         ids=["reverse", "shuffle", "retain-then-complete-asc",
                              "retain-then-complete-desc", "interleaved"])
def test_arrival_order_does_not_change_final_state(system, sign, plan_a, plan_b):
    """任意到达序列的最终业务状态指纹与正序一致。"""
    from app import System
    from seed import seed_demo
    fp_b = _replay(system, sign, system.demo, plan_b)

    # 第二个实例复用同一批设备密钥，离线签名/指纹才能字节一致
    same_secrets = {did: info["secret"]
                    for did, info in system.demo["devices"].items()}
    other = System(":memory:", clock=system.clock)
    other.demo = seed_demo(other, device_secrets=same_secrets)
    fp_a = _replay(other, sign, other.demo, plan_a)
    other.close()
    assert fp_a == fp_b


def test_exactly_quota_winners_regardless_of_order(system, sign):
    """6 条抢 3 个名额：任何顺序下恰好 3 条有效，且都是发生最早的 3 条。"""
    demo = system.demo
    did = demo["device_by_scenic"][SCENIC]
    base = system.clock.t
    times = [base - 600 * i for i in range(6)]
    # 升序造记录：BK-001 发生最早，BK-006 最晚
    records = _records(sign, demo, did, sorted(times))
    order = list(range(6))
    random.Random(42).shuffle(order)
    for i in order:
        system.core.submit_offline(records[i])

    rows = system.store.conn.execute(
        "SELECT business_key,state FROM redemptions WHERE ticket_no=? ",
        (TICKET,)).fetchall()
    valid = [r["business_key"] for r in rows if r["state"] == R_VALID]
    revoked_quota = [r for r in rows if r["state"] == R_REVOKED]
    assert sorted(valid) == ["BK-001", "BK-002", "BK-003"]
    assert len(revoked_quota) == 3
    assert all(r["state"] == R_REVOKED for r in revoked_quota)


def test_duplicate_resubmits_add_no_benefit(system, sign):
    """同一条离线记录重复补传 N 次，只建一条权益，重放全部进审计。"""
    demo = system.demo
    did = demo["device_by_scenic"][SCENIC]
    rec = sign(demo, did, 1, TICKET, HOLDER, SCENIC, system.clock.t - 60, "BK-1")
    first = system.core.retain_offline(rec)
    assert first["state"] == R_PENDING
    for _ in range(5):
        again = system.core.complete_offline(rec)
        assert again["duplicate"] is True or again["state"] in (
            R_VALID, R_REVIEW, R_SETTLED)
    # 第一次补传生效
    system.core.complete_offline(rec)
    rows = system.store.conn.execute(
        "SELECT COUNT(*) n FROM redemptions WHERE ticket_no=? AND scenic=?",
        (TICKET, SCENIC)).fetchone()
    assert rows["n"] == 1
    from crypto import offline_fingerprint
    fp = offline_fingerprint({k: v for k, v in rec.items() if k != "sig"})
    audit = system.store.conn.execute(
        "SELECT dup_count FROM replay_audit WHERE fingerprint=?",
        (fp,)).fetchone()
    # 重放次数 >= 5（首条留存后每次补传重复都计数）
    assert audit is not None and audit["dup_count"] >= 5


def test_split_retain_complete_equivalent_to_submit(system, sign):
    """先留存后补传 与 一步到位，在同一记录上结果一致且只出一次权益。"""
    demo = system.demo
    did = demo["device_by_scenic"][SCENIC]
    rec = sign(demo, did, 1, TICKET, HOLDER, SCENIC, system.clock.t - 60, "BK-1")
    r1 = system.core.retain_offline(rec)
    r2 = system.core.complete_offline(rec)
    assert r1["fingerprint"] == r2["fingerprint"]
    assert r2["state"] == R_VALID

    from app import System
    from seed import seed_demo
    same_secrets = {did: info["secret"]
                    for did, info in system.demo["devices"].items()}
    other = System(":memory:", clock=system.clock)
    other.demo = seed_demo(other, device_secrets=same_secrets)
    rec2 = sign(other.demo, did, 1, TICKET, HOLDER, SCENIC,
                system.clock.t - 60, "BK-1")
    one = other.core.submit_offline(rec2)
    assert one["state"] == R_VALID
    assert system.core.state_fingerprint() == other.core.state_fingerprint()
    other.close()


def test_same_business_key_resigned_cannot_double_redeem(system, sign):
    """攻击者换签名/换序号重发同一业务键：归并到首条，不出第二份权益。"""
    demo = system.demo
    did = demo["device_by_scenic"][SCENIC]
    t = system.clock.t - 60
    r1 = sign(demo, did, 1, TICKET, HOLDER, SCENIC, t, "ENTRY-X")
    system.core.submit_offline(r1)
    # 同业务键，不同序号、稍改时间 -> 不同指纹，但业务键相同
    r2 = sign(demo, did, 99, TICKET, HOLDER, SCENIC, t + 1, "ENTRY-X")
    out = system.core.submit_offline(r2)
    assert out["duplicate"] is True
    n = system.store.conn.execute(
        "SELECT COUNT(*) n FROM redemptions WHERE ticket_no=? AND scenic=? "
        "AND business_key='ENTRY-X'", (TICKET, SCENIC)).fetchone()["n"]
    assert n == 1


def test_quota_soft_revoke_recovers_after_refund_like_release(system, sign):
    """被名额挤掉的记录，在更早的赢家被刚性撤销后自动恢复，且不产生双份。"""
    demo = system.demo
    did = demo["device_by_scenic"][SCENIC]
    base = system.clock.t
    recs = [sign(demo, did, i, TICKET, HOLDER, SCENIC, base - 1000 * (4 - i),
                 f"BK-{i}") for i in range(1, 5)]
    for r in recs:
        system.core.submit_offline(r)
    states = {r["business_key"]: r["state"] for r in system.store.conn.execute(
        "SELECT business_key,state FROM redemptions WHERE ticket_no=?",
        (TICKET,)).fetchall()}
    assert states["BK-4"] == R_REVOKED  # 超名额
    # 人工撤销最早一条 -> BK-4 应恢复为有效
    fp1 = system.store.conn.execute(
        "SELECT fingerprint FROM redemptions WHERE business_key='BK-1'").fetchone()[0]
    system.core.manual_revoke(fp1, "audit")
    states = {r["business_key"]: r["state"] for r in system.store.conn.execute(
        "SELECT business_key,state FROM redemptions WHERE ticket_no=?",
        (TICKET,)).fetchall()}
    assert states["BK-1"] == R_REVOKED
    assert states["BK-4"] == R_VALID
    assert sum(1 for v in states.values() if v == R_VALID) == 3
