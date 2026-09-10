# -*- coding: utf-8 -*-
"""时间与时区处理。内部统一存 UTC ISO-8601，并保留采集时区。"""
from __future__ import annotations

from datetime import datetime, timezone
from zoneinfo import ZoneInfo, available_timezones

try:  # Python 3.9+ 大多数发行版自带 tzdata；缺失时给出明确提示
    ZoneInfo("Asia/Shanghai")
    _TZ_OK = True
except Exception:  # pragma: no cover
    _TZ_OK = False

VALID_TIMEZONES = set(available_timezones())


class TimeError(ValueError):
    pass


def validate_timezone(tz: str) -> str:
    if tz not in VALID_TIMEZONES:
        raise TimeError(
            f"无效时区 {tz!r}，应为 IANA 名称，例如 Asia/Shanghai、UTC。"
            + ("" if _TZ_OK else " 系统缺少 tzdata，请 pip install tzdata。")
        )
    return tz


def parse_dt(value: str | datetime, field: str = "时间") -> datetime:
    """解析 ISO-8601 时间，要求带时区偏移，返回 aware datetime。"""
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError as exc:
            raise TimeError(f"{field} 不是合法 ISO-8601 时间：{value!r}") from exc
    if dt.tzinfo is None:
        raise TimeError(f"{field} 必须带时区偏移，例如 2026-09-01T09:30:00+08:00")
    return dt


def to_utc_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def local_iso(dt: datetime, tz_name: str) -> str:
    return dt.astimezone(ZoneInfo(tz_name)).isoformat()


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
