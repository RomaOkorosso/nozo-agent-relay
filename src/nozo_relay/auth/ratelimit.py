"""Small in-memory login throttle (single Uvicorn worker by design)."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field

from nozo_relay.clock import Clock


@dataclass
class _Bucket:
    failures: list[int] = field(default_factory=list)
    locked_until: int = 0


class LoginRateLimiter:
    def __init__(self, clock: Clock, *, max_failures: int, window_s: int, lockout_s: int) -> None:
        self._clock = clock
        self._max = max_failures
        self._window_ms = window_s * 1000
        self._lockout_ms = lockout_s * 1000
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def retry_after_seconds(self, key: str) -> int:
        """0 if the attempt may proceed, else seconds to wait."""
        now = self._clock.now_ms()
        with self._lock:
            b = self._buckets.get(key)
            if b and b.locked_until > now:
                return max(1, (b.locked_until - now + 999) // 1000)
        return 0

    def record_failure(self, key: str) -> None:
        now = self._clock.now_ms()
        with self._lock:
            b = self._buckets.setdefault(key, _Bucket())
            b.failures = [t for t in b.failures if now - t < self._window_ms]
            b.failures.append(now)
            if len(b.failures) >= self._max:
                b.locked_until = now + self._lockout_ms
                b.failures.clear()
            if len(self._buckets) > 10_000:  # bound memory
                self._buckets = {k: v for k, v in self._buckets.items() if v.locked_until > now}

    def record_success(self, key: str) -> None:
        with self._lock:
            self._buckets.pop(key, None)
