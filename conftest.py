"""测试公共夹具：可控时钟 + 已播种的内存系统 + 离线签名助手。"""

import pytest

from app import System
from crypto import offline_payload, sign_payload
from domain import parse_iso
from seed import seed_demo

# 固定在 2026 赛季比赛日次日（周六）12:00（+08:00）
T0 = parse_iso("2026-03-08T12:00:00+08:00")


class Clock:
    def __init__(self, t: float):
        self.t = t

    def __call__(self) -> float:
        return self.t

    def set(self, t: float):
        self.t = t

    def advance(self, seconds: float):
        self.t += seconds
        return self.t


@pytest.fixture
def clock():
    return Clock(T0)


@pytest.fixture
def system(clock):
    s = System(":memory:", clock=clock)
    s.demo = seed_demo(s)
    s.clock = clock
    yield s
    s.close()


@pytest.fixture
def sign():
    """返回签名助手：sign(demo, device_id, seq, ticket, holder, scenic, at, bk)。"""
    def _sign(demo, device_id, seq, ticket_no, holder, scenic, signed_at,
              business_key, prev_sig=None):
        secret = demo["devices"][device_id]["secret"]
        payload = offline_payload(
            device_id=device_id, seq=seq, ticket_no=ticket_no, holder=holder,
            scenic=scenic, signed_at=signed_at, business_key=business_key,
            prev_sig=prev_sig)
        payload["sig"] = sign_payload(secret, payload)
        return payload
    return _sign


@pytest.fixture
def device_for():
    """按景区名取演示设备 ID（seed 中 DEV-001..042，顺序同 domain.json）。"""
    def _device(system_, scenic):
        for item in system_.demo["scenics"]:
            if item["scenic"] == scenic:
                return item["device_id"]
        raise KeyError(scenic)
    return _device
