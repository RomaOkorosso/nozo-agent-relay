"""Injectable clock. All persisted times are epoch milliseconds (UTC)."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Protocol, runtime_checkable


@runtime_checkable
class Clock(Protocol):
    def now_ms(self) -> int:
        """Current UTC time as epoch milliseconds."""
        ...


class SystemClock:
    def now_ms(self) -> int:
        return time.time_ns() // 1_000_000


class FakeClock:
    """Deterministic clock for tests."""

    def __init__(self, start_ms: int = 1_800_000_000_000) -> None:
        self._now = start_ms

    def now_ms(self) -> int:
        return self._now

    def advance(self, *, seconds: float = 0, ms: int = 0) -> int:
        self._now += int(seconds * 1000) + ms
        return self._now

    def set(self, ms: int) -> None:
        self._now = ms


def ms_to_rfc3339(ms: int) -> str:
    dt = datetime.fromtimestamp(ms / 1000, tz=UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"
