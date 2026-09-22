"""领域口径加载与校验。

`domain.json` 是赛事方、景区、结算三方共用的唯一口径来源：
票种、核销结果、结算周期、景区分组与补贴单价、权益规则、离线参数。
本模块只负责读取与校验，不做任何业务判断。
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

DOMAIN_PATH = Path(__file__).with_name("domain.json")

# 核销结果（与 domain.json 保持一致，代码内引用常量避免拼写漂移）
R_VALID = "有效"        # 核验通过，权益生效
R_PENDING = "待补传"    # 离线已签名留存，尚未补传到平台
R_REVIEW = "待复核"     # 异常票根，进入人工复核（不得直接吞掉）
R_REVOKED = "已撤销"    # 权益被撤销（退款/延期冲突/人工撤销/复核拒绝）
R_SETTLED = "已清算"    # 已计入定稿批次

PERIOD_WEEKLY = "周结"
PERIOD_MONTHLY = "月结"

# 台账事件类型（追加式，永不更新删除）
EV_CONFIG = "配置"        # 景区结算周期等基础配置
EV_DEVICE = "设备"        # 核销设备登记/冻结
EV_MATCH = "场次"         # 比赛创建/延期/取消
EV_TICKET = "票券"        # 出票/改期/退款
EV_REDEEM = "核销"        # 一次核验/补传产生的权益事件
EV_DEDUP = "重复送达"     # 同一记录再次到达（重放审计）
EV_ADJUST = "调整"        # 对既有事件的调整（追补/冲正/撤销）
EV_REVIEW = "复核"        # 复核单的建立与结论
EV_BATCH = "批次"         # 清算批次定稿

ADJUST_SUBSIDY = "追补"
ADJUST_REVERSAL = "冲正"
ADJUST_VOID = "撤销"

REV_REFUND = "票务退款"
REV_POSTPONE = "场次延期"
REV_CANCEL = "比赛取消"
REV_MANUAL = "人工撤销"
REV_REVIEW_REJECT = "复核拒绝"
REV_QUOTA = "超出权益次数"
REV_WINDOW = "不在权益窗口"
REV_SEASON = "非赛期"
REV_REASONS = (REV_REFUND, REV_POSTPONE, REV_CANCEL, REV_MANUAL,
               REV_REVIEW_REJECT, REV_QUOTA, REV_WINDOW, REV_SEASON)


@dataclass(frozen=True)
class Season:
    code: str
    name: str
    start: date
    end: date


@dataclass(frozen=True)
class ScenicGroup:
    name: str
    subsidy_cents: int
    scenics: tuple[str, ...]


class DomainError(ValueError):
    """口径配置错误。"""


class Domain:
    def __init__(self, data: dict):
        self.raw = data
        self.ticket_types: tuple[str, ...] = tuple(data["票种"])
        self.results: tuple[str, ...] = tuple(data["核销结果"])
        self.periods: tuple[str, ...] = tuple(data["结算周期"])
        self.groups: tuple[ScenicGroup, ...] = tuple(
            ScenicGroup(g["组"], int(g["补贴单价分"]), tuple(g["景区"])) for g in data["景区分组"]
        )
        self.rules: dict = data["权益规则"]
        self.offline: dict = data["离线"]
        self.clearing: dict = data["清算"]
        self.seasons: tuple[Season, ...] = tuple(
            Season(s["代码"], s["名称"], date.fromisoformat(s["开始"]), date.fromisoformat(s["结束"]))
            for s in data["赛季"]
        )
        self._validate()

        self.scenic_group: dict[str, ScenicGroup] = {}
        for g in self.groups:
            for s in g.scenics:
                if s in self.scenic_group:
                    raise DomainError(f"景区 {s} 出现在多个分组中")
                self.scenic_group[s] = g
        self.season_by_code = {s.code: s for s in self.seasons}

    def _validate(self):
        required = {"项目", "票种", "核销结果", "结算周期", "景区分组",
                    "赛季", "权益规则", "离线", "清算"}
        missing = required - self.raw.keys()
        if missing:
            raise DomainError(f"domain.json 缺少字段: {sorted(missing)}")
        for r in (R_VALID, R_PENDING, R_REVIEW, R_REVOKED, R_SETTLED):
            if r not in self.results:
                raise DomainError(f"核销结果缺少约定值: {r}")
        for p in (PERIOD_WEEKLY, PERIOD_MONTHLY):
            if p not in self.periods:
                raise DomainError(f"结算周期缺少约定值: {p}")
        if not self.groups:
            raise DomainError("至少需要一个景区分组")
        for g in self.groups:
            if g.subsidy_cents <= 0:
                raise DomainError(f"分组 {g.name} 补贴单价必须为正")
        for t in self.ticket_types:
            rule = self.rules.get(t)
            if not rule or rule["限兑次数"] < 1 or rule["有效天数"] < 1:
                raise DomainError(f"票种 {t} 缺少有效权益规则")
        if self.offline["时钟容差秒"] < 0 or self.offline["补传时限天"] < 1:
            raise DomainError("离线参数非法")
        for s in self.seasons:
            if s.end < s.start:
                raise DomainError(f"赛季 {s.code} 结束早于开始")

    # ---- 查询 ----
    def subsidy_for(self, scenic: str) -> int:
        return self.scenic_group[scenic].subsidy_cents

    def group_name_of(self, scenic: str) -> str:
        return self.scenic_group[scenic].name

    def rule_for(self, ticket_type: str) -> dict:
        return self.rules[ticket_type]

    def season_for_date(self, d: date) -> Season | None:
        for s in self.seasons:
            if s.start <= d <= s.end:
                return s
        return None

    def list_scenics(self) -> list[str]:
        return [s for g in self.groups for s in g.scenics]


# ---- 时间工具（统一 UTC 感知时间戳）----

def now_ts() -> float:
    return datetime.now(timezone.utc).timestamp()


def ts_to_dt(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, timezone.utc)


def ts_to_date(ts: float) -> date:
    return ts_to_dt(ts).date()


def parse_iso(s: str) -> float:
    """解析 ISO8601 字符串为 UTC 时间戳；裸日期按 00:00 UTC。"""
    if len(s) == 10:
        return datetime.fromisoformat(s).replace(tzinfo=timezone.utc).timestamp()
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def period_key(period: str, d: date) -> str:
    """结算周期键。

    周结：ISO 周，键形如 ``2026-W12``；月结：``2026-03``。
    周/月边界由日历唯一确定，便于按景区复算。
    """
    if period == PERIOD_WEEKLY:
        iso = d.isocalendar()
        return f"{iso[0]:04d}-W{iso[1]:02d}"
    if period == PERIOD_MONTHLY:
        return f"{d.year:04d}-{d.month:02d}"
    raise DomainError(f"未知结算周期: {period}")


def period_bounds(period: str, key: str) -> tuple[date, date]:
    """周期键对应的自然边界 [start, end]。"""
    if period == PERIOD_MONTHLY:
        y, m = map(int, key.split("-"))
        start = date(y, m, 1)
        end = date(y + (m // 12), 1 if m == 12 else m + 1, 1) - timedelta(days=1)
        return start, end
    if period == PERIOD_WEEKLY:
        y, w = key.split("-W")
        jan4 = date(int(y), 1, 4)
        start = jan4 - timedelta(days=jan4.isoweekday() - 1) + timedelta(weeks=int(w) - 1)
        end = start + timedelta(days=6)
        return start, end
    raise DomainError(f"未知结算周期: {period}")


def load(path: str | Path = DOMAIN_PATH) -> Domain:
    with open(path, encoding="utf-8") as f:
        return Domain(json.load(f))
