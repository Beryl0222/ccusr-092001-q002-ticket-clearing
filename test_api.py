"""HTTP 接口层测试：角色边界、在线/离线接口、复核、封账与证明接口。"""

import json
import os
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from api import create_handler
from core import ClearingService, DomainConfig, Store, TZ
from datetime import datetime


class TestClock:
    def __init__(self, dt):
        self.dt = dt

    def __call__(self):
        return self.dt


class ApiTestBase(unittest.TestCase):
    def setUp(self):
        cfg = DomainConfig.load(os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "domain.json"))
        self.clock = TestClock(datetime(2026, 5, 16, 12, 0, tzinfo=TZ))
        self.store = Store(":memory:", clock=self.clock)
        self.svc = ClearingService(cfg, self.store,
                                   issuer_secret="http-issuer",
                                   clock=self.clock)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0),
                                          create_handler(self.svc))
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def call(self, method, path, body=None, role=None, actor="tester"):
        data = (json.dumps(body, ensure_ascii=False).encode()
                if body is not None else None)
        headers = {"Content-Type": "application/json", "X-Actor": actor}
        if role:
            headers["X-Role"] = role
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}", data=data, method=method,
            headers=headers)
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())


class HttpRoleTest(ApiTestBase):
    def test_健康检查与领域口径(self):
        s, b = self.call("GET", "/health")
        self.assertEqual(s, 200)
        self.assertEqual(b["service"], "ticket-benefit-clearing")
        s, b = self.call("GET", "/domain")
        self.assertEqual(len(b["景区"]), 42)

    def test_缺少角色与角色越权被拒(self):
        s, b = self.call("POST", "/issuer/matches",
                         {"match_code": "M1", "kickoff_at": "2026-05-15T19:30:00+08:00"})
        self.assertEqual(s, 403)
        self.assertEqual(b["error"], "ROLE_REQUIRED")
        s, b = self.call("POST", "/issuer/matches",
                         {"match_code": "M1", "kickoff_at": "2026-05-15T19:30:00+08:00"},
                         role="scenic")
        self.assertEqual(b["error"], "ROLE_FORBIDDEN")

    def test_全链路接口(self):
        # 赛事方：场次 + 票根
        s, m = self.call("POST", "/issuer/matches",
                         {"match_code": "M1",
                          "kickoff_at": "2026-05-15T19:30:00+08:00"},
                         role="issuer")
        self.assertEqual(s, 201)
        s, t = self.call("POST", "/issuer/tickets",
                         {"ticket_code": "T1", "ticket_type": "纸质票根",
                          "holder": "张三", "match_code": "M1",
                          "face_value": 80}, role="issuer")
        self.assertEqual(s, 201)
        # 景区：设备注册
        s, d = self.call("POST", "/devices",
                         {"device_id": "D1", "secret": "k1",
                          "spot_code": "S001", "site": "gate"},
                         role="scenic")
        self.assertEqual(s, 201)
        # 在线核销（事件时间与服务时钟一致）
        s, r = self.call("POST", "/scenic/redeem",
                         {"ticket_code": "T1", "signature": t["signature"],
                          "spot_code": "S001", "holder": "张三",
                          "ticket_type": "纸质票根",
                          "event_at": "2026-05-16T12:00:00+08:00"},
                         role="scenic")
        self.assertEqual(r["result"], "有效")
        # 复核队列初始为空
        s, rv = self.call("GET", "/reviews", role="reviewer")
        self.assertEqual(rv["cases"], [])
        # 结算员封账（推进时钟到周期结束后）
        self.clock.dt = datetime(2026, 5, 18, 10, 0, tzinfo=TZ)
        s, b = self.call("POST", "/settlement/seal",
                         {"period_kind": "周结",
                          "period_start": "2026-05-11T00:00:00+08:00",
                          "spot_code": "S001"}, role="cashier")
        self.assertEqual(s, 200)
        self.assertEqual(b["net_fen"], 3000)
        s, rc = self.call(
            "GET", f"/settlement/batches/{b['batch_id']}/recompute",
            role="cashier")
        self.assertTrue(rc["recomputable"])
        # 账本可验证
        s, lv = self.call("GET", "/ledger/verify", role="cashier")
        self.assertTrue(lv["ok"])

    def test_离线补传与顺序无关性证明接口(self):
        s, p = self.call("GET", "/proof/order-independence")
        self.assertEqual(s, 200)
        self.assertTrue(p["identical"])
        self.assertEqual(set(p["digests"]), {"原序", "逆序", "洗牌", "重复补传"})
        self.assertEqual(len(set(p["digests"].values())), 1)
        self.assertEqual(p["snapshot"]["total_valid"], 4)


if __name__ == "__main__":
    unittest.main()
