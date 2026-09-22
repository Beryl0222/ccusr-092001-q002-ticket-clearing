"""票根惠游权益清算 —— HTTP 接口层。

角色
----
- 赛事方 /issuer/* ：票根签发、场次登记、退票、取消、延期
- 景区   /scenic/* 、/devices：在线可信核验、设备注册、离线补传
- 复核员 /reviews/*：异常票根复核队列裁决（异常只入队，不吞掉）
- 结算员 /settlement/*、/ledger/*：封账、复算、人工撤销、哈希链校验
- 证明   /proof/order-independence：自包含签名夹具，接口级证明同一批离线
         记录无论何种顺序（含重复补传）到达，只产生一次有效权益

演示环境用 X-Actor 头标识操作人，不做真实鉴权；生产应在网关层替换为
角色令牌/双向证书。
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

from core import DomainError, ClearingService, build_order_independence_fixture

# 角色令牌（ASCII，经 X-Role 请求头携带）到中文名称的映射
ROLE_NAMES = {"issuer": "赛事方", "scenic": "景区",
              "reviewer": "复核员", "cashier": "结算员"}
ROLE_ROUTES = {
    "/issuer/": "issuer",
    "/scenic/": "scenic",
    "/devices": "scenic",
    "/reviews": "reviewer",
    "/settlement/": "cashier",
    "/ledger/": "cashier",
}


def create_handler(svc: ClearingService):
    cfg = svc.cfg

    class Handler(BaseHTTPRequestHandler):
        server_version = "TicketBenefitClearing/1.0"

        # -- 基础工具 ------------------------------------------------------
        def _send(self, obj, status: int = 200) -> None:
            body = json.dumps(obj, ensure_ascii=False).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _body(self) -> dict:
            length = int(self.headers.get("Content-Length") or 0)
            if not length:
                return {}
            try:
                data = json.loads(self.rfile.read(length).decode())
            except json.JSONDecodeError as exc:
                raise DomainError("BAD_JSON", f"请求体不是合法 JSON: {exc}")
            if not isinstance(data, dict):
                raise DomainError("BAD_BODY", "请求体必须是 JSON 对象")
            return data

        def _actor(self) -> str:
            return self.headers.get("X-Actor") or "anonymous"

        def _role(self) -> str | None:
            return self.headers.get("X-Role")

        def log_message(self, *_args):
            return

        # -- 路由 ----------------------------------------------------------
        def do_GET(self):
            self._dispatch("GET")

        def do_POST(self):
            self._dispatch("POST")

        def _dispatch(self, method: str) -> None:
            parsed = urlparse(self.path)
            path = parsed.path
            qs = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            try:
                body = self._body() if method == "POST" else {}
                # 角色边界：写/读业务路由必须携带与路由匹配的 X-Role
                required = ROLE_ROUTES.get(next(
                    (p for p in ROLE_ROUTES if path.startswith(p)), ""))
                if required is not None:
                    got = self._role()
                    if not got:
                        raise DomainError("ROLE_REQUIRED",
                                          f"该接口需要 X-Role: {required}", 403)
                    if got != required:
                        raise DomainError("ROLE_FORBIDDEN",
                                          f"该接口仅限{required}，当前角色{got}", 403)
                # 所有数据库访问经写锁串行，消除多线程竞争
                actor = self._actor()
                if required is not None:
                    actor = f"{ROLE_NAMES[required]}/{actor}"
                with svc.store.lock:
                    self._route(method, path, qs, body, actor)
            except DomainError as exc:
                self._send({"error": exc.code, "message": exc.message}, exc.status)
            except (KeyError, TypeError) as exc:
                self._send({"error": "BAD_REQUEST", "message": f"参数错误: {exc}"}, 400)
            except Exception as exc:  # noqa: BLE001
                self._send({"error": "INTERNAL", "message": str(exc)}, 500)

        def _route(self, method, path, qs, body, actor):
            # -- 通用 -------------------------------------------------------
            if method == "GET" and path == "/health":
                return self._send({"status": "ok", "service": "ticket-benefit-clearing"})
            if method == "GET" and path == "/domain":
                return self._send({
                    "赛季": cfg.season,
                    "票种": cfg.raw["票种"],
                    "补贴标准_元_人次": cfg.subsidy,
                    "权益上限": cfg.raw["权益上限"],
                    "结算周期": cfg.raw["结算周期"],
                    "核销参数": cfg.raw["核销参数"],
                    "景区分组": [
                        {"分组编号": g["分组编号"], "分组名称": g["分组名称"],
                         "结算周期": g["结算周期"], "适用票种": g["适用票种"],
                         "景区数量": len(g["景区"])}
                        for g in cfg.raw["景区分组"]],
                    "景区": [{"编号": s.code, "名称": s.name, "分组": s.group,
                             "结算周期": cfg.cadence_of(s.code)}
                            for s in sorted(cfg.spots.values(), key=lambda x: x.code)],
                })

            # -- 赛事方 -----------------------------------------------------
            if method == "POST" and path == "/issuer/tickets":
                return self._send(svc.issue_ticket(
                    ticket_code=body["ticket_code"], ticket_type=body["ticket_type"],
                    holder=body["holder"], match_code=body["match_code"],
                    face_value=int(body.get("face_value", 0)),
                    issued_at=body.get("issued_at"), actor=actor), 201)
            if method == "POST" and path == "/issuer/matches":
                return self._send(svc.register_match(
                    body["match_code"], body["kickoff_at"]), 201)
            if method == "POST" and path.startswith("/issuer/tickets/") \
                    and path.endswith("/refund"):
                code = path.split("/")[3]
                return self._send(svc.refund_ticket(
                    code, body.get("reason", "观众退票"), actor))
            if method == "POST" and path.startswith("/issuer/matches/") \
                    and path.endswith("/cancel"):
                code = path.split("/")[3]
                return self._send(svc.cancel_match(
                    code, body.get("reason", "赛事取消"), actor))
            if method == "POST" and path.startswith("/issuer/matches/") \
                    and path.endswith("/postpone"):
                code = path.split("/")[3]
                return self._send(svc.postpone_match(
                    code, body["new_kickoff_at"], actor))

            # -- 景区 -------------------------------------------------------
            if method == "POST" and path == "/devices":
                return self._send(svc.register_device(
                    body["device_id"], body["secret"], body["spot_code"],
                    body.get("site", "")), 201)
            if method == "POST" and path == "/scenic/redeem":
                return self._send(svc.redeem_online(
                    ticket_code=body["ticket_code"], signature=body["signature"],
                    spot_code=body["spot_code"], holder=body["holder"],
                    ticket_type=body["ticket_type"], event_at=body.get("event_at"),
                    actor=actor), 201)
            if method == "POST" and path == "/scenic/offline/manifest":
                return self._send(svc.close_manifest(
                    body["device_id"], body["record_ids"],
                    body.get("closed_at")), 201)
            if method == "POST" and path == "/scenic/offline/upload":
                return self._send(svc.upload_offline(
                    body["records"], body["manifest"], actor), 201)
            if method == "GET" and path == "/scenic/rights":
                rows = svc.store.query(
                    "SELECT r.ticket_code tc, r.spot_code sc, r.result res, "
                    "r.event_at ea, r.channel ch, r.id rid FROM redemptions r "
                    "WHERE r.ticket_code=? ORDER BY r.id", (qs["ticket"],))
                return self._send({"ticket_code": qs["ticket"],
                                   "records": [dict(r) for r in rows]})

            # -- 复核员 -----------------------------------------------------
            if method == "GET" and path == "/reviews":
                return self._send({"cases": svc.list_reviews(
                    qs.get("status", "待处理"))})
            if method == "POST" and path.startswith("/reviews/") \
                    and path.endswith("/resolve"):
                rid = int(path.split("/")[2])
                return self._send(svc.resolve_review(
                    rid, bool(body["approved"]), actor,
                    body.get("reason", "")))

            # -- 结算员 -----------------------------------------------------
            if method == "POST" and path == "/settlement/seal":
                return self._send(svc.seal_batch(
                    body["period_kind"], body["period_start"],
                    body["spot_code"], actor))
            if method == "GET" and path == "/settlement/batches":
                return self._send({"batches": svc.list_batches(qs.get("spot"))})
            if method == "GET" and path.startswith("/settlement/batches/") \
                    and path.endswith("/recompute"):
                bid = int(path.split("/")[3])
                return self._send(svc.recompute_batch(bid))
            if method == "POST" and path == "/settlement/revocations":
                return self._send(svc.manual_revoke(
                    int(body["redemption_id"]), body["reason"], actor))
            if method == "GET" and path == "/ledger/verify":
                return self._send(svc.store.verify_chain())
            if method == "GET" and path == "/ledger/events":
                limit = int(qs.get("limit", "100"))
                rows = svc.store.query(
                    "SELECT seq,at,actor,action,payload,prev_hash,hash "
                    "FROM event_log ORDER BY seq DESC LIMIT ?", (limit,))
                out = []
                for r in rows:
                    d = dict(r)
                    d["payload"] = json.loads(d["payload"])
                    out.append(d)
                return self._send({"events": list(reversed(out))})

            # -- 顺序无关性证明 ---------------------------------------------
            if method == "GET" and path == "/proof/order-independence":
                fixture = build_order_independence_fixture(cfg)
                proof = svc.prove_order_independence(fixture)
                return self._send({"fixture": {
                    "manifest": fixture["manifest"],
                    "records": fixture["records"],
                    "shuffle": fixture["shuffle"],
                    "orders": ["原序", "逆序", "洗牌", "重复补传"],
                }, **proof})

            self._send({"error": "NOT_FOUND", "message": f"无此路由: {path}"}, 404)

    return Handler
