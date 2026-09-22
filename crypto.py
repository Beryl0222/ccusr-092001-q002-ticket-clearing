"""签名与哈希工具。

弱网景区在本地先对核验记录签名留存，恢复网络后再补传。
- 设备密钥在发放时登记（seed/管理接口注册），平台侧按 device_id 查密钥验签；
- 签名负载为字段的规范序列化（不含签名本身、不含到达时间），
  因此同一条离线记录无论何时、分几次、以什么顺序补传，验签结果都一致；
- 每条设备记录带单调递增 seq，设备侧维护本地哈希链，平台可检测跳号/分叉；
- 台账自身用 prev_hash 串成哈希链，任何篡改都会破坏链尾指纹。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any

SIGN_ALGO = "HMAC-SHA256"


def new_device_secret() -> str:
    return os.urandom(32).hex()


def canonical(payload: dict[str, Any]) -> bytes:
    """规范序列化：键排序、无空白、ASCII 转义，保证跨端字节一致。"""
    return json.dumps(payload, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":")).encode("utf-8")


def sign_payload(secret: str, payload: dict[str, Any]) -> str:
    return hmac.new(secret.encode("utf-8"), canonical(payload), hashlib.sha256).hexdigest()


def verify_signature(secret: str, payload: dict[str, Any], signature: str) -> bool:
    return hmac.compare_digest(sign_payload(secret, payload), signature or "")


def sha256_hex(b: bytes | str) -> str:
    if isinstance(b, str):
        b = b.encode("utf-8")
    return hashlib.sha256(b).hexdigest()


def offline_payload(*, device_id: str, seq: int, ticket_no: str,
                    holder: str, scenic: str, signed_at: float,
                    business_key: str, prev_sig: str | None) -> dict[str, Any]:
    """构造待签名负载。business_key 是网点侧原始业务键（一次入园一条）。"""
    return {
        "alg": SIGN_ALGO,
        "device_id": device_id,
        "seq": seq,
        "ticket_no": ticket_no,
        "holder": holder,
        "scenic": scenic,
        "signed_at": round(float(signed_at), 3),
        "business_key": business_key,
        "prev_sig": prev_sig,
    }


def chain_hash(prev_hash: str | None, body: dict[str, Any]) -> str:
    """台账哈希链：sha256(prev_hash || canonical(body))。"""
    return sha256_hex((prev_hash or "") + canonical(body).decode("ascii"))


def offline_fingerprint(record_payload: dict[str, Any]) -> str:
    """离线记录内容指纹：对签名负载（去掉 sig 本身）取规范哈希。

    与到达时间、到达渠道、是否重复无关，因此同一条记录的任何重复送达
    都得到同一指纹。
    """
    payload = {k: v for k, v in record_payload.items() if k != "sig"}
    return sha256_hex(canonical(payload))
