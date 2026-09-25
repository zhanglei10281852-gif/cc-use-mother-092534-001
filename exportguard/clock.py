"""时间来源。

统一从这里取"现在"，测试时可以注入固定时钟；所有时间都带时区，
与合同 ``time_policy = ISO 8601 with timezone`` 保持一致。
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, Protocol


class Clock(Protocol):
    def now(self) -> datetime: ...


class SystemClock:
    """生产环境使用的 UTC 时钟。"""

    def now(self) -> datetime:
        return datetime.now(timezone.utc)


ClockFactory = Callable[[], datetime]


class FixedClock:
    """测试用：先固定一个起点，也可以通过 ``advance`` 推进时间。"""

    def __init__(self, start: datetime | None = None) -> None:
        if start is None:
            start = datetime(2026, 9, 25, 1, 0, 0, tzinfo=timezone.utc)
        if start.tzinfo is None:
            raise ValueError("固定时钟的起点必须带时区")
        self._now = start

    def now(self) -> datetime:
        return self._now

    def set(self, value: datetime) -> None:
        if value.tzinfo is None:
            raise ValueError("时间必须带时区")
        self._now = value

    def advance(self, seconds: float) -> datetime:
        from datetime import timedelta

        self._now = self._now + timedelta(seconds=seconds)
        return self._now
