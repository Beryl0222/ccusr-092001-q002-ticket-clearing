"""领域口径与周期工具。"""

from datetime import date

import pytest

from domain import (DomainError, load, period_bounds, period_key,
                    PERIOD_MONTHLY, PERIOD_WEEKLY)


def test_domain_loads_42_scenics_in_5_groups():
    d = load()
    scenics = d.list_scenics()
    assert len(scenics) == 42
    assert len(set(scenics)) == 42
    assert len(d.groups) == 5
    # 每个景区名唯一归属一个分组
    assert len(d.scenic_group) == 42
    assert d.subsidy_for("柳子庙") == 3000
    assert d.group_name_of("阳明山") == "山水名胜"


def test_ticket_rules_present_for_all_types():
    d = load()
    for t in d.ticket_types:
        rule = d.rule_for(t)
        assert rule["限兑次数"] >= 1
        assert rule["有效天数"] >= 1


def test_period_key_and_bounds_monthly():
    key = period_key(PERIOD_MONTHLY, date(2026, 3, 31))
    assert key == "2026-03"
    start, end = period_bounds(PERIOD_MONTHLY, key)
    assert (start, end) == (date(2026, 3, 1), date(2026, 3, 31))


def test_period_key_and_bounds_weekly():
    # 2026-03-08 是周日，属 ISO 第 10 周（周一 3/2 起）
    key = period_key(PERIOD_WEEKLY, date(2026, 3, 8))
    assert key == "2026-W10"
    start, end = period_bounds(PERIOD_WEEKLY, key)
    assert (start, end) == (date(2026, 3, 2), date(2026, 3, 8))


def test_weekly_key_year_boundary():
    # 2027-01-01 周五，属 2026-W53
    key = period_key(PERIOD_WEEKLY, date(2027, 1, 1))
    assert key == "2026-W53"
    start, end = period_bounds(PERIOD_WEEKLY, key)
    assert start == date(2026, 12, 28)
    assert end == date(2027, 1, 3)


def test_season_lookup():
    d = load()
    assert d.season_for_date(date(2026, 6, 1)).code == "2026"
    assert d.season_for_date(date(2025, 12, 31)) is None


def test_bad_domain_rejected(tmp_path):
    import json
    p = tmp_path / "d.json"
    good = json.loads(open("domain.json", encoding="utf-8").read())
    bad = {**good, "票种": ["未知票种"]}
    # 票种在规则表中缺失 -> 校验失败
    p.write_text(json.dumps(bad), encoding="utf-8")
    with pytest.raises(DomainError):
        load(p)
