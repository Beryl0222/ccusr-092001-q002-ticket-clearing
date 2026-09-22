"""HTTP 接口端到端：鉴权、在线/离线、复核、定稿、对账。"""

import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from urllib.parse import quote

import pytest

from crypto import offline_payload, sign_payload
from domain import parse_iso
from seed import seed_demo
from service import make_handler


@pytest.fixture
def server(system):
    handler = make_handler(system)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    system.base_url = f"http://127.0.0.1:{port}"
    yield system
    httpd.shutdown()
    httpd.server_close()


def call(system, method, path, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        system.base_url + path, data=data, method=method,
        headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_health_and_domain(server):
    code, h = call(server, "GET", "/health")
    assert code == 200 and h["service"] == "ticket-benefit-clearing"
    code, d = call(server, "GET", "/domain")
    assert code == 200 and sum(len(g["景区"]) for g in d["景区分组"]) == 42


def test_role_isolation(server):
    # 无凭证
    code, _ = call(server, "GET", "/settlement/reviews")
    assert code == 401
    # 赛事方令牌不能访问结算接口
    code, _ = call(server, "GET", "/settlement/reviews",
                   headers={"Authorization": "Bearer event-token"})
    assert code == 401
    # 结算令牌可以
    code, d = call(server, "GET", "/settlement/reviews",
                   headers={"Authorization": "Bearer settlement-token"})
    assert code == 200 and d["reviews"] == []
    # 结算令牌不能创建场次
    code, _ = call(server, "POST", "/event/matches",
                   {"match_id": "X", "season_code": "2026",
                    "opponent": "y", "kickoff": "2026-06-01T19:00:00+08:00"},
                   {"Authorization": "Bearer settlement-token"})
    assert code == 401


def test_event_then_online_verify_flow(server):
    headers = {"Authorization": "Bearer event-token"}
    code, _ = call(server, "POST", "/event/matches",
                   {"match_id": "MT-99", "season_code": "2026",
                    "opponent": "测试队",
                    "kickoff": "2026-03-07T19:30:00+08:00"}, headers)
    assert code == 201
    code, t = call(server, "POST", "/event/tickets",
                   {"ticket_no": "T-T99", "season_code": "2026",
                    "match_id": "MT-99", "ticket_type": "实名电子票",
                    "holder": "测试人"}, headers)
    assert code == 201

    # 无设备头 -> 401
    code, _ = call(server, "POST", "/scenic/verify",
                   {"ticket_no": "T-T99", "holder": "测试人", "scenic": "柳子庙"})
    assert code == 401

    device = next(i for i in server.demo["scenics"] if i["scenic"] == "柳子庙")
    dev_headers = {"X-Device-Id": device["device_id"],
                   "X-Device-Secret": server.demo["devices"][device["device_id"]]["secret"]}
    server.clock.set(parse_iso("2026-03-08T12:00:00+08:00"))
    code, v = call(server, "POST", "/scenic/verify",
                   {"ticket_no": "T-T99", "holder": "测试人",
                    "scenic": "柳子庙", "business_key": "H-1"}, dev_headers)
    assert code == 200 and v["state"] == "有效"
    # 同业务键重复 -> 幂等，不双补
    code, v2 = call(server, "POST", "/scenic/verify",
                    {"ticket_no": "T-T99", "holder": "测试人",
                     "scenic": "柳子庙", "business_key": "H-1"}, dev_headers)
    assert v2["fingerprint"] == v["fingerprint"]


def _offline_record(demo, scenic, seq, ticket, holder, when, bk):
    device = next(i for i in demo["scenics"] if i["scenic"] == scenic)
    did = device["device_id"]
    secret = demo["devices"][did]["secret"]
    payload = offline_payload(device_id=did, seq=seq, ticket_no=ticket,
                              holder=holder, scenic=scenic, signed_at=when,
                              business_key=bk, prev_sig=None)
    payload["sig"] = sign_payload(secret, payload)
    return did, payload


def test_offline_retain_complete_review_finalize_flow(server):
    server.clock.set(parse_iso("2026-03-08T12:00:00+08:00"))
    when = parse_iso("2026-03-08T11:00:00+08:00")

    # 电子票：留存 -> 补传生效
    did, rec = _offline_record(server.demo, "柳子庙", 1,
                               "T-ET-1001", "张磊", when, "O-1")
    dh = {"X-Device-Id": did, "X-Device-Secret": server.demo["devices"][did]["secret"]}
    code, r = call(server, "POST", "/scenic/offline/retain", rec, dh)
    assert code == 200 and r["state"] == "待补传"
    code, r = call(server, "POST", "/scenic/offline/complete", rec, dh)
    assert code == 200 and r["state"] == "有效"
    # 重复补传
    code, r = call(server, "POST", "/scenic/offline/complete", rec, dh)
    assert code == 200 and r.get("duplicate") is True

    # 纸质票根：一步到位 -> 待复核
    _, recp = _offline_record(server.demo, "阳明山", 1,
                              "T-PA-2001", "王芳", when, "O-P1")
    dpa = next(i for i in server.demo["scenics"] if i["scenic"] == "阳明山")
    dph = {"X-Device-Id": dpa["device_id"],
           "X-Device-Secret": server.demo["devices"][dpa["device_id"]]["secret"]}
    code, rp = call(server, "POST", "/scenic/offline/submit", recp, dph)
    assert code == 200 and rp["state"] == "待复核"

    sh = {"Authorization": "Bearer settlement-token"}
    code, d = call(server, "GET", "/settlement/reviews", headers=sh)
    rid = next(x["id"] for x in d["reviews"]
               if x["fingerprint"] == rp["fingerprint"])
    code, dec = call(server, "POST", f"/settlement/reviews/{rid}/decision",
                     {"approve": True, "decided_by": "tester"}, sh)
    assert code == 200 and dec["redemption"]["state"] == "有效"

    # 定稿：柳子庙月结 3 月只有电子票一笔
    code, b = call(server, "POST", "/settlement/finalize",
                   {"scenic": "柳子庙", "period": "月结",
                    "period_key": "2026-03"}, sh)
    assert code == 200 and b["total_cents"] == 3000
    # 幂等
    code, b2 = call(server, "POST", "/settlement/finalize",
                    {"scenic": "柳子庙", "period": "月结",
                     "period_key": "2026-03"}, sh)
    assert b2["batch_id"] == b["batch_id"] and b2.get("idempotent") is True

    # 独立复算通过
    code, v = call(server, "GET", "/settlement/verify", headers=sh)
    assert code == 200 and v["ok"] is True


def test_refund_then_next_batch_reversal_over_http(server):
    sh = {"Authorization": "Bearer settlement-token"}
    eh = {"Authorization": "Bearer event-token"}
    server.clock.set(parse_iso("2026-03-08T12:00:00+08:00"))
    did, rec = _offline_record(server.demo, "柳子庙", 1,
                               "T-ET-1002", "李娜",
                               parse_iso("2026-03-08T10:00:00+08:00"), "R-1")
    dh = {"X-Device-Id": did,
          "X-Device-Secret": server.demo["devices"][did]["secret"]}
    call(server, "POST", "/scenic/offline/submit", rec, dh)
    code, b3 = call(server, "POST", "/settlement/finalize",
                    {"scenic": "柳子庙", "period": "月结",
                     "period_key": "2026-03"}, sh)
    assert b3["total_cents"] == 3000

    # 4 月退款
    server.clock.set(parse_iso("2026-04-05T12:00:00+08:00"))
    code, _ = call(server, "POST", "/event/tickets/T-ET-1002/refund", {}, eh)
    assert code == 200
    code, b4 = call(server, "POST", "/settlement/finalize",
                    {"scenic": "柳子庙", "period": "月结",
                     "period_key": "2026-04"}, sh)
    assert b4["total_cents"] == -3000
    code, summ = call(server, "GET",
                      f"/scenics/{quote('柳子庙')}/summary", headers=sh)
    assert code == 200 and summ["settled_total_cents"] == 0


def test_chain_tip_and_state_fingerprint_endpoints(server):
    sh = {"Authorization": "Bearer settlement-token"}
    code, d = call(server, "GET", "/audit/state-fingerprint", headers=sh)
    assert code == 200 and d["chain_ok"] is True and len(d["chain_tip"]) == 64
