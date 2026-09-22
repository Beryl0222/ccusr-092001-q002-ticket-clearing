"""并发竞争：多线程同时提交相同/不同记录，数据库约束与确定性归并兜底。"""

import threading

from crypto import offline_payload, sign_payload
from domain import R_REVOKED, R_VALID

SCENIC = "柳子庙"
TICKET = "T-ET-1001"
HOLDER = "张磊"


def test_concurrent_identical_offline_submit(system, device_for):
    """同一条离线记录 20 个线程同时提交：只建一条权益。"""
    did = device_for(system, SCENIC)
    secret = system.demo["devices"][did]["secret"]
    t = system.clock.t - 60
    payload = offline_payload(device_id=did, seq=1, ticket_no=TICKET,
                              holder=HOLDER, scenic=SCENIC, signed_at=t,
                              business_key="BK-C1", prev_sig=None)
    payload["sig"] = sign_payload(secret, payload)

    errors = []
    barrier = threading.Barrier(20)

    def worker():
        barrier.wait()
        try:
            system.core.submit_offline(dict(payload))
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()

    rows = system.store.conn.execute(
        "SELECT state,COUNT(*) n FROM redemptions WHERE business_key='BK-C1' "
        "GROUP BY state").fetchall()
    assert len(rows) == 1
    assert rows[0]["n"] == 1
    n_audit = system.store.conn.execute(
        "SELECT COALESCE(SUM(dup_count),0) d FROM replay_audit "
        "WHERE note LIKE '%指纹%' OR note LIKE '%重复%' OR note LIKE '%归并%'"
    ).fetchone()["d"]
    assert n_audit >= 19


def test_concurrent_distinct_records_respect_quota(system, device_for):
    """20 条不同业务键的记录并发提交：有效数严格不超过限兑 3 次。"""
    did = device_for(system, SCENIC)
    secret = system.demo["devices"][did]["secret"]
    base = system.clock.t

    def make(seq):
        payload = offline_payload(
            device_id=did, seq=seq, ticket_no=TICKET, holder=HOLDER,
            scenic=SCENIC, signed_at=base - 600 * (20 - seq),
            business_key=f"BK-D{seq:02d}", prev_sig=None)
        payload["sig"] = sign_payload(secret, payload)
        return payload

    records = [make(i) for i in range(1, 21)]
    barrier = threading.Barrier(20)

    def worker(rec):
        barrier.wait()
        system.core.submit_offline(dict(rec))

    threads = [threading.Thread(target=worker, args=(r,)) for r in records]
    for th in threads:
        th.start()
    for th in threads:
        th.join()

    valid = system.store.conn.execute(
        "SELECT COUNT(*) n FROM redemptions WHERE ticket_no=? AND state=?",
        (TICKET, R_VALID)).fetchone()["n"]
    revoked = system.store.conn.execute(
        "SELECT COUNT(*) n FROM redemptions WHERE ticket_no=? AND state=? "
        "AND revoke_reason='超出权益次数'",
        (TICKET, R_REVOKED)).fetchone()["n"]
    assert valid == 3
    assert valid + revoked == 20
