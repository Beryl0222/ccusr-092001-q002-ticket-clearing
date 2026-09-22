"""演示种子：把 domain.json 中的 42 家景区全部开账，登记核销设备，
并建立若干场次与票券，供接口联调与离线流程演示。

用法::

    from app import System
    from seed import seed_demo
    sys = System("data.db")
    demo = seed_demo(sys)

``demo["devices"]`` 内含每台设备的签名密钥（真实环境中密钥只发放给网点，
平台侧仅留存用于验签的同一密钥副本）。
"""

from __future__ import annotations

from domain import PERIOD_MONTHLY, PERIOD_WEEKLY, parse_iso

# 各分组按既有业务约定选用结算周期
GROUP_PERIOD = {
    "山水名胜": PERIOD_WEEKLY,
    "人文古迹": PERIOD_MONTHLY,
    "瑶寨民俗": PERIOD_WEEKLY,
    "生态度假": PERIOD_MONTHLY,
    "城市休闲": PERIOD_WEEKLY,
}

MATCHES = [
    ("M2026-01", "衡阳湘涛", "2026-03-07T19:30:00+08:00"),
    ("M2026-02", "株洲狼腾", "2026-03-21T19:30:00+08:00"),
    ("M2026-03", "郴州盛和", "2026-04-11T19:30:00+08:00"),
    ("M2026-04", "长沙涛羽", "2026-05-02T19:30:00+08:00"),
]

TICKETS = [
    # 票号, 场次, 票种, 持票人
    ("T-ET-1001", "M2026-01", "实名电子票", "张磊"),
    ("T-ET-1002", "M2026-01", "实名电子票", "李娜"),
    ("T-PA-2001", "M2026-01", "纸质票根", "王芳"),
    ("T-GR-3001", "M2026-01", "团体票", "永州一中研学团"),
    ("T-ET-1003", "M2026-02", "实名电子票", "陈杰"),
    ("T-PA-2002", "M2026-02", "纸质票根", "刘洋"),
    ("T-ET-1004", "M2026-03", "实名电子票", "赵敏"),
    ("T-ET-1005", "M2026-04", "实名电子票", "孙强"),
]


def seed_demo(system, device_secrets: dict | None = None) -> dict:
    """写入演示数据。

    ``device_secrets`` 形如 ``{device_id: secret}``；传入时复用指定密钥，
    便于在两个独立实例间产生字节一致的离线签名（等价性证明测试需要）。
    返回的 ``devices`` 中含实际使用的密钥。
    """
    core = system.core
    scenics = system.domain.list_scenics()

    configured, devices = [], {}
    for idx, scenic in enumerate(scenics, start=1):
        group = system.domain.group_name_of(scenic)
        period = GROUP_PERIOD[group]
        core.configure_scenic(scenic, period)
        # 设备 ID 使用 ASCII，避免中文进入 HTTP 头的编码问题
        device_id = f"DEV-{idx:03d}"
        secret = (device_secrets or {}).get(device_id)
        info = core.register_device(device_id, scenic, secret)
        devices[device_id] = {"scenic": scenic, "secret": info["secret"]}
        configured.append({"scenic": scenic, "group": group,
                           "period": period, "device_id": device_id})

    for match_id, opponent, kickoff in MATCHES:
        core.create_match(match_id, "2026", opponent, parse_iso(kickoff))

    tickets = []
    for no, match_id, ttype, holder in TICKETS:
        info = core.issue_ticket(no, "2026", match_id, ttype, holder)
        tickets.append({"ticket_no": no, "match_id": match_id,
                        "ticket_type": ttype, "holder": holder,
                        "valid_until": info["valid_until"]})

    return {"scenics": configured, "devices": devices,
            "device_by_scenic": {item["scenic"]: item["device_id"]
                                 for item in configured},
            "matches": [m[0] for m in MATCHES], "tickets": tickets}
