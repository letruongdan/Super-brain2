"""System wall and high-resolution monotonic clock adapters."""

import time
from datetime import UTC, datetime


class SystemMonotonicClock:
    """High-resolution monotonic clock backed by ``time.perf_counter_ns``."""

    def monotonic_ns(self) -> int:
        return time.perf_counter_ns()


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)

    def monotonic_ns(self) -> int:
        return time.perf_counter_ns()
