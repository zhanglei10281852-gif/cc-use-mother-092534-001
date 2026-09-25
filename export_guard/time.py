"""时间来源。

领域规则统一使用带时区的 ISO 8601 时间。测试可以注入固定时钟，
生产使用系统时钟；所有时间在落库前归一化为 UTC 存储，展示时保留时区语义。
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Protocol


class Clock(Protocol):
    def now(self) -> datetime:
        """返回当前带时区时间。"""


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(timezone.utc)


class FixedClock:
    """从固定起点按固定秒数推进的时钟，供测试与确定性复盘使用。"""

    def __init__(self, start: datetime, step_seconds: float = 0.0) -> None:
        if start.tzinfo is None:
            raise ValueError("固定时钟必须使用带时区的时间")
        self._current = start.astimezone(timezone.utc)
        self._step = timedelta(seconds=step_seconds)

    def now(self) -> datetime:
        result = self._current
        self._current = self._current + self._step
        return result

    def advance(self, duration: timedelta) -> None:
        """显式推进时钟（测试用）。"""
        self._current = self._current + duration


def normalize(value: datetime) -> datetime:
    """把任意带时区时间归一化为 UTC；拒绝朴素时间。"""
    if value.tzinfo is None:
        raise ValueError("时间必须显式携带时区")
    return value.astimezone(timezone.utc)


def parse_iso(value: str) -> datetime:
    """解析落库的 ISO 字符串并归一化为 UTC。"""
    parsed = datetime.fromisoformat(value)
    return normalize(parsed)


__all__ = ["Clock", "SystemClock", "FixedClock", "normalize"]
