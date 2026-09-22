"""票根惠游权益清算 HTTP 服务。

角色与鉴权（演示用静态令牌，生产环境应替换为网关签发的短期凭证）：
- 赛事方：``Authorization: Bearer event-token``
- 结算人员：``Authorization: Bearer settlement-token``
- 景区设备：``X-Device-Id`` + ``X-Device-Secret``（登记时发放的 HMAC 密钥）

接口一览见模块底部 ``ROUTES``，或启动后访问 ``GET /``。
"""

from __future__ import annotations

import argparse
import json
import os
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

from app import System
from core import BusinessError
from domain import REV_MANUAL

SERVICE_ID = "ticket-benefit-clearing"

EVENT_TOKEN = os.environ.get("EVENT_TOKEN", "event-token")
SETTLEMENT_TOKEN = os.environ.get("SETTLEMENT_TOKEN", "settlement-token")


def health():
    """返回稳定的服务身份。"""
    return {"status": "ok", "service": SERVICE_ID}


# ---------------------------------------------------------------------- #
# 处理器
# ---------------------------------------------------------------------- #
def make_handler(system: System):
    core = system.core
    cl = system.clearing

    class Handler(BaseHTTPRequestHandler):
        server_version = "TicketBenefit/1.0"

        # -- 基础工具 --
        def _send(self, code: int, obj):
            body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _body(self) -> dict:
            n = int(self.headers.get("Content-Length") or 0)
            if not n:
                return {}
            raw = self.rfile.read(n)
            try:
                data = json.loads(raw.decode("utf-8"))
            except json.JSONDecodeError as e:
                raise BusinessError(f"请求体不是合法 JSON: {e}", 400)
            if not isinstance(data, dict):
                raise BusinessError("请求体必须是 JSON 对象", 400)
            return data

        def _qs(self) -> dict:
            q = parse_qs(urlparse(self.path).query)
            return {k: v[-1] for k, v in q.items()}

        def _role(self) -> str | None:
            tok = self.headers.get("Authorization", "").removeprefix("Bearer ").strip()
            if tok == EVENT_TOKEN:
                return "event"
            if tok == SETTLEMENT_TOKEN:
                return "settlement"
            return None

        def _require(self, *roles: str):
            role = self._role()
            if role not in roles:
                raise BusinessError("需要身份: " + "/".join(roles), 401)
            return role

        def _device(self) -> tuple[str, str]:
            did = self.headers.get("X-Device-Id")
            sec = self.headers.get("X-Device-Secret")
            if not did or not sec:
                raise BusinessError("需要设备头 X-Device-Id / X-Device-Secret", 401)
            row = system.store.conn.execute(
                "SELECT secret, revoked FROM devices WHERE device_id=?", (did,)
            ).fetchone()
            if not row:
                raise BusinessError(f"设备 {did} 未登记", 404)
            if row["revoked"]:
                raise BusinessError(f"设备 {did} 已冻结", 403)
            if row["secret"] != sec:
                raise BusinessError("设备密钥错误", 401)
            return did, sec

        # -- 路由 --
        def do_GET(self):
            self._dispatch("GET")

        def do_POST(self):
            self._dispatch("POST")

        def _dispatch(self, method: str):
            path = urlparse(self.path).path.rstrip("/") or "/"
            try:
                if method == "GET" and path == "/health":
                    return self._send(200, health())
                if method == "GET" and path == "/":
                    return self._send(200, {"service": SERVICE_ID,
                                            "routes": ROUTES})
                if method == "GET" and path == "/domain":
                    d = system.domain
                    return self._send(200, {
                        "票种": list(d.ticket_types),
                        "核销结果": list(d.results),
                        "结算周期": list(d.periods),
                        "景区分组": [{"组": g.name, "补贴单价分": g.subsidy_cents,
                                  "景区": list(g.scenics)} for g in d.groups],
                        "权益规则": d.rules, "离线": d.offline,
                        "赛季": [{"代码": s.code, "开始": str(s.start),
                                  "结束": str(s.end)} for s in d.seasons]})

                # 赛事方
                if method == "POST" and path == "/event/matches":
                    self._require("event")
                    b = self._body()
                    return self._send(201, core.create_match(
                        b["match_id"], b["season_code"], b["opponent"],
                        b["kickoff"]))
                if method == "POST" and path.startswith("/event/matches/") and \
                        path.endswith("/postpone"):
                    self._require("event")
                    mid = unquote(path.split("/")[3])
                    return self._send(200, core.postpone_match(
                        mid, self._body()["new_kickoff"]))
                if method == "POST" and path.startswith("/event/matches/") and \
                        path.endswith("/cancel"):
                    self._require("event")
                    mid = unquote(path.split("/")[3])
                    return self._send(200, core.cancel_match(mid))
                if method == "POST" and path == "/event/tickets":
                    self._require("event")
                    b = self._body()
                    return self._send(201, core.issue_ticket(
                        b["ticket_no"], b["season_code"], b["match_id"],
                        b["ticket_type"], b["holder"]))
                if method == "POST" and path.startswith("/event/tickets/") and \
                        path.endswith("/refund"):
                    self._require("event")
                    no = unquote(path.split("/")[3])
                    return self._send(200, core.refund_ticket(no))

                # 景区
                if method == "POST" and path == "/scenic/verify":
                    did, _ = self._device()
                    b = self._body()
                    return self._send(200, core.verify_online(
                        b["ticket_no"], b["holder"], b["scenic"],
                        b.get("business_key"), device_id=did,
                        occurred_at=b.get("occurred_at")))
                if method == "POST" and path == "/scenic/offline/retain":
                    self._device()
                    return self._send(200, core.retain_offline(self._body()))
                if method == "POST" and path == "/scenic/offline/complete":
                    self._device()
                    return self._send(200, core.complete_offline(self._body()))
                if method == "POST" and path == "/scenic/offline/submit":
                    self._device()
                    return self._send(200, core.submit_offline(self._body()))
                if method == "GET" and path == "/scenic/offline/stubs":
                    did, _ = self._device()
                    return self._send(200, {"stubs": core.list_stubs(did)})

                # 结算/平台
                if method == "POST" and path == "/admin/scenics":
                    self._require("settlement")
                    b = self._body()
                    return self._send(201, core.configure_scenic(
                        b["scenic"], b["period"]))
                if method == "POST" and path == "/admin/devices":
                    self._require("settlement")
                    b = self._body()
                    return self._send(201, core.register_device(
                        b["device_id"], b["scenic"], b.get("secret")))
                if method == "POST" and path.startswith("/admin/devices/") and \
                        path.endswith("/revoke"):
                    self._require("settlement")
                    did = unquote(path.split("/")[3])
                    return self._send(200, core.revoke_device(
                        did, self._body().get("reason", "管理冻结")))
                if method == "POST" and path == "/admin/sweep":
                    self._require("settlement")
                    return self._send(200, core.sweep_stubs())
                if method == "GET" and path == "/settlement/reviews":
                    self._require("settlement")
                    return self._send(200, {
                        "reviews": core.list_reviews(self._qs().get("state", "待复核"))})
                if method == "POST" and path.startswith("/settlement/reviews/") and \
                        path.endswith("/decision"):
                    self._require("settlement")
                    rid = int(path.split("/")[3])
                    b = self._body()
                    return self._send(200, core.decide_review(
                        rid, bool(b["approve"]),
                        b.get("decided_by", "settlement")))
                if method == "POST" and path == "/settlement/revoke":
                    self._require("settlement")
                    b = self._body()
                    return self._send(200, core.manual_revoke(
                        b["fingerprint"], b.get("decided_by", "settlement"),
                        b.get("reason", REV_MANUAL), b.get("note")))
                if method == "POST" and path == "/settlement/finalize":
                    self._require("settlement")
                    b = self._body()
                    return self._send(200, cl.finalize(
                        b["scenic"], b["period"], b["period_key"],
                        b.get("operator", "settlement")))
                if method == "POST" and path == "/settlement/finalize-current":
                    self._require("settlement")
                    b = self._body()
                    return self._send(200, cl.finalize_current(
                        b["scenic"], b.get("at")))
                if method == "GET" and path == "/settlement/batches":
                    self._require("settlement")
                    q = self._qs()
                    return self._send(200, {
                        "batches": cl.list_batches(q.get("scenic"))})
                if method == "GET" and path.startswith("/settlement/batches/"):
                    self._require("settlement")
                    bid = unquote(path.split("/")[3])
                    try:
                        return self._send(200, cl.get_batch(bid))
                    except KeyError:
                        raise BusinessError(f"批次 {bid} 不存在", 404)
                if method == "GET" and path == "/settlement/verify":
                    self._require("settlement")
                    return self._send(200, cl.verify_batches())
                if method == "GET" and path.startswith("/scenics/") and \
                        path.endswith("/summary"):
                    self._require("settlement")
                    scenic = unquote(path.split("/")[2])
                    return self._send(200, cl.scenic_summary(scenic))
                if method == "GET" and path.startswith("/tickets/") and \
                        path.endswith("/trail"):
                    self._require("settlement", "event")
                    no = unquote(path.split("/")[2])
                    return self._send(200, core.ticket_trail(no))
                if method == "GET" and path == "/audit/replays":
                    self._require("settlement")
                    return self._send(200, {"records": core.list_replay_audit()})
                if method == "GET" and path == "/audit/state-fingerprint":
                    self._require("settlement")
                    ok, broken = system.store.verify_chain()
                    return self._send(200, {
                        "state_fingerprint": core.state_fingerprint(),
                        "chain_tip": system.store.chain_tip(),
                        "chain_ok": ok, "broken_at": broken})
                if method == "POST" and path == "/admin/rebuild":
                    self._require("settlement")
                    return self._send(200, core.rebuild_state())

                self._send(404, {"error": f"无此路由: {method} {path}"})
            except BusinessError as e:
                self._send(e.status, {"error": str(e), **e.extra})
            except KeyError as e:
                self._send(400, {"error": f"缺少字段: {e}"})
            except ValueError as e:
                self._send(400, {"error": str(e)})
            except Exception:  # noqa: BLE001
                traceback.print_exc()
                self._send(500, {"error": "服务器内部错误"})

        def log_message(self, *_args):
            return

    return Handler


ROUTES = {
    "公共": ["GET /health", "GET /domain"],
    "赛事方(Event)": [
        "POST /event/matches",
        "POST /event/matches/{match_id}/postpone",
        "POST /event/matches/{match_id}/cancel",
        "POST /event/tickets",
        "POST /event/tickets/{ticket_no}/refund",
        "GET  /tickets/{ticket_no}/trail",
    ],
    "景区(Device)": [
        "POST /scenic/verify            在线核验",
        "POST /scenic/offline/retain    离线签名留存(待补传)",
        "POST /scenic/offline/complete  补传判定(幂等)",
        "POST /scenic/offline/submit    留存+补传一步到位",
        "GET  /scenic/offline/stubs     本设备待补传存根",
    ],
    "结算(Settlement)": [
        "POST /admin/scenics, POST /admin/devices, POST /admin/devices/{id}/revoke",
        "POST /admin/sweep              逾期存根转复核",
        "GET  /settlement/reviews",
        "POST /settlement/reviews/{id}/decision",
        "POST /settlement/revoke        人工撤销",
        "POST /settlement/finalize      按景区+周期定稿(幂等)",
        "POST /settlement/finalize-current",
        "GET  /settlement/batches[?scenic=], GET /settlement/batches/{id}",
        "GET  /settlement/verify        批次与哈希链独立复算",
        "GET  /scenics/{scenic}/summary",
        "GET  /audit/replays, GET /audit/state-fingerprint",
        "POST /admin/rebuild            清空物化状态并重放台账",
    ],
}


def serve(system: System, port: int):
    handler = make_handler(system)
    httpd = ThreadingHTTPServer(("0.0.0.0", port), handler)
    print(f"{SERVICE_ID} 监听 :{port}")
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()


def main():
    parser = argparse.ArgumentParser(description="票根权益清算")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--db", default=os.environ.get("TBC_DB", ":memory:"))
    parser.add_argument("--seed", action="store_true", help="启动时写入演示数据")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    if args.check:
        system = System(":memory:")
        d = system.domain
        ok, _ = system.store.verify_chain()
        print(f"基础检查通过：{len(d.list_scenics())} 家景区、"
              f"{len(d.groups)} 个分组、{len(d.ticket_types)} 种票、"
              f"哈希链 {'完整' if ok else '异常'}")
        system.close()
        return

    system = System(args.db)
    if args.seed:
        from seed import seed_demo
        seeded = seed_demo(system)
        print(f"演示数据就绪：{len(seeded['scenics'])} 家景区，"
              f"{len(seeded['tickets'])} 张票，{len(seeded['matches'])} 个场次")
    serve(system, args.port)


if __name__ == "__main__":
    main()
