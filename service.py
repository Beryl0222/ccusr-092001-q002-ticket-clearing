"""票根惠游权益清算服务入口。

- python3 service.py --check            校验 domain.json 基础口径
- python3 service.py                    启动 HTTP 服务（默认 8000）
环境变量：
  DB_PATH         SQLite 数据文件（默认 clearing.db；:memory: 仅调试）
  ISSUER_SECRET   赛事方票根 HMAC 密钥（生产务必通过环境注入）
"""

import argparse
import json
import os
import sys
from http.server import ThreadingHTTPServer

from api import create_handler
from core import DomainConfig, ClearingService, Store

SERVICE_ID = "ticket-benefit-clearing"

DOMAIN_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "domain.json")


def health():
    """返回稳定的服务身份。"""
    return {"status": "ok", "service": SERVICE_ID}


def build_service(db_path: str | None = None) -> ClearingService:
    cfg = DomainConfig.load(DOMAIN_PATH)
    problems = cfg.check()
    if problems:
        raise SystemExit("领域配置校验失败：\n- " + "\n- ".join(problems))
    store = Store(db_path or os.environ.get("DB_PATH", "clearing.db"))
    return ClearingService(cfg, store,
                           issuer_secret=os.environ.get("ISSUER_SECRET"))


def main() -> int:
    parser = argparse.ArgumentParser(description="票根权益清算")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--check", action="store_true",
                        help="校验 domain.json 后退出")
    args = parser.parse_args()

    cfg = DomainConfig.load(DOMAIN_PATH)
    problems = cfg.check()
    if args.check:
        if problems:
            print("基础检查失败：")
            for p in problems:
                print(" -", p)
            return 1
        print("基础检查通过")
        print(json.dumps({
            "景区数": len(cfg.spots),
            "分组": {g: {"结算周期": cfg.group_cadence[g],
                         "适用票种": sorted(cfg.group_ticket_types[g])}
                    for g in sorted(cfg.group_cadence)},
            "票种补贴_元": cfg.subsidy,
        }, ensure_ascii=False, indent=2))
        return 0

    svc = build_service()
    server = ThreadingHTTPServer(("0.0.0.0", args.port), create_handler(svc))
    print(f"{SERVICE_ID} 监听 :{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        svc.store.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
