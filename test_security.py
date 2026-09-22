"""安全：伪造票根、签名篡改、时钟偏差、持票人、赛季/窗口、设备分叉。"""

import pytest

from core import (BusinessError, RV_CLOCK_AHEAD, RV_DEVICE_FORK,
                  RV_HOLDER_MISMATCH, RV_LATE_UPLOAD, RV_PAPER,
                  RV_UNKNOWN_TICKET)
from domain import R_PENDING, R_REVIEW, R_REVOKED, R_VALID

SCENIC = "柳子庙"
TICKET = "T-ET-1001"
HOLDER = "张磊"


def test_bad_signature_rejected(system, sign, device_for):
    did = device_for(system, SCENIC)
    rec = sign(system.demo, did, 1, TICKET, HOLDER, SCENIC,
               system.clock.t - 60, "BK-1")
    rec["sig"] = "0" * 64
    with pytest.raises(BusinessError) as e:
        system.core.retain_offline(rec)
    assert e.value.status == 401


def test_tampered_payload_rejected(system, sign, device_for):
    did = device_for(system, SCENIC)
    rec = sign(system.demo, did, 1, TICKET, HOLDER, SCENIC,
               system.clock.t - 60, "BK-1")
    rec["scenic"] = "朝阳岩"  # 改掉负载但签名不变
    with pytest.raises(BusinessError):
        system.core.retain_offline(rec)


def test_wrong_device_secret_rejected(system, sign, device_for):
    did = device_for(system, SCENIC)
    rec = sign(system.demo, did, 1, TICKET, HOLDER, SCENIC,
               system.clock.t - 60, "BK-1")
    # 用另一台设备的密钥重签 -> 与登记密钥不符
    other_did = device_for(system, "朝阳岩")
    other_secret = system.demo["devices"][other_did]["secret"]
    from crypto import sign_payload
    rec["sig"] = sign_payload(other_secret,
                              {k: v for k, v in rec.items() if k != "sig"})
    with pytest.raises(BusinessError) as e:
        system.core.retain_offline(rec)
    assert e.value.status == 401


def test_clock_skew_ahead_goes_to_review_not_silently_accepted(system, sign,
                                                               device_for):
    did = device_for(system, SCENIC)
    tol = system.domain.offline["时钟容差秒"]
    rec = sign(system.demo, did, 1, TICKET, HOLDER, SCENIC,
               system.clock.t + tol + 60, "BK-1")  # 超前 6 分钟
    out = system.core.retain_offline(rec)
    assert out["state"] == R_REVIEW
    assert out["revoke_reason"] == RV_CLOCK_AHEAD
    # 异常进复核队列，而不是被吞掉或直接出补贴
    reviews = system.core.list_reviews()
    assert len(reviews) == 1 and reviews[0]["reason"] == RV_CLOCK_AHEAD


def test_late_upload_beyond_limit_rejected_to_review(system, sign, device_for):
    did = device_for(system, SCENIC)
    limit = system.domain.offline["补传时限天"] * 86400
    rec = sign(system.demo, did, 1, TICKET, HOLDER, SCENIC,
               system.clock.t - limit - 1, "BK-1")
    out = system.core.retain_offline(rec)
    assert out["state"] == R_REVIEW
    assert out["revoke_reason"] == RV_LATE_UPLOAD


def test_sweep_expired_stubs_to_review(system, sign, device_for):
    did = device_for(system, SCENIC)
    limit = system.domain.offline["补传时限天"] * 86400
    # 留存时在容差内：先成为待补传
    rec = sign(system.demo, did, 1, TICKET, HOLDER, SCENIC,
               system.clock.t - 60, "BK-1")
    assert system.core.retain_offline(rec)["state"] == R_PENDING
    # 超过补传时限仍未补传
    system.clock.advance(limit + 10)
    res = system.core.sweep_stubs()
    assert res["count"] == 1
    assert system.core.get_redemption(
        res["swept"][0]["fingerprint"])["state"] == R_REVIEW


def test_unknown_ticket_enters_review(system, sign, device_for):
    did = device_for(system, SCENIC)
    rec = sign(system.demo, did, 1, "T-NOPE", "无名氏", SCENIC,
               system.clock.t - 60, "BK-1")
    out = system.core.submit_offline(rec)
    assert out["state"] == R_REVIEW
    assert out["revoke_reason"] == RV_UNKNOWN_TICKET


def test_holder_mismatch_enters_review(system, sign, device_for):
    did = device_for(system, SCENIC)
    rec = sign(system.demo, did, 1, TICKET, "冒名者", SCENIC,
               system.clock.t - 60, "BK-1")
    out = system.core.submit_offline(rec)
    assert out["state"] == R_REVIEW
    assert out["revoke_reason"] == RV_HOLDER_MISMATCH


def test_paper_ticket_always_reviewed_before_benefit(system, sign, device_for):
    """纸质票根易伪造：即使票真、人对、窗口内，也必须人工复核后才计补贴。"""
    scenic = "阳明山"
    did = device_for(system, scenic)
    rec = sign(system.demo, did, 1, "T-PA-2001", "王芳", scenic,
               system.clock.t - 3600, "BK-P1")
    out = system.core.submit_offline(rec)
    assert out["state"] == R_REVIEW
    assert out["revoke_reason"] == RV_PAPER
    # 复核拒绝：不出补贴且结论可追溯
    rid = int(system.core.list_reviews()[0]["id"])
    dec = system.core.decide_review(rid, False, "auditor-1")
    assert dec["redemption"]["state"] == R_REVOKED


def test_paper_ticket_approved_after_review_pays_once(system, sign, device_for):
    scenic = "阳明山"
    did = device_for(system, scenic)
    rec = sign(system.demo, did, 1, "T-PA-2001", "王芳", scenic,
               system.clock.t - 3600, "BK-P1")
    system.core.submit_offline(rec)
    rid = int(system.core.list_reviews()[0]["id"])
    dec = system.core.decide_review(rid, True, "auditor-1")
    assert dec["redemption"]["state"] == R_VALID
    assert dec["redemption"]["amount_cents"] == 5000


def test_out_of_season_revoked(system):
    from domain import parse_iso
    # 在线核验允许指定入园时间：2025 年的记录不属于 2026 赛季
    out = system.core.verify_online(
        TICKET, HOLDER, SCENIC, business_key="S1",
        occurred_at=parse_iso("2025-12-30T12:00:00+08:00"))
    assert out["state"] == R_REVOKED
    assert out["revoke_reason"] == "非赛期"


def test_out_of_window_revoked(system):
    out = system.core.verify_online(
        TICKET, HOLDER, SCENIC, business_key="W1",
        occurred_at=system.clock.t + 20 * 86400)
    assert out["state"] == R_REVOKED
    assert out["revoke_reason"] == "不在权益窗口"


def test_device_seq_fork_enters_review(system, sign, device_for):
    did = device_for(system, SCENIC)
    r1 = sign(system.demo, did, 7, TICKET, HOLDER, SCENIC,
              system.clock.t - 120, "BK-1")
    system.core.submit_offline(r1)
    # 同设备同序号 7，但业务键/时间不同 -> 分叉
    r2 = sign(system.demo, did, 7, TICKET, HOLDER, SCENIC,
              system.clock.t - 60, "BK-FORGE")
    out = system.core.submit_offline(r2)
    assert out["state"] == R_REVIEW
    reasons = [r["reason"] for r in system.core.list_reviews()]
    assert RV_DEVICE_FORK in reasons


def test_revoked_device_cannot_submit(system, sign, device_for):
    did = device_for(system, SCENIC)
    system.core.revoke_device(did, "密钥泄露")
    rec = sign(system.demo, did, 1, TICKET, HOLDER, SCENIC,
               system.clock.t - 60, "BK-1")
    with pytest.raises(BusinessError) as e:
        system.core.submit_offline(rec)
    assert e.value.status == 403
