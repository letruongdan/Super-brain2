"""Clock ports (wall UTC and high-resolution monotonic nanoseconds)."""

from datetime import datetime
from typing import Protocol


class Clock(Protocol):
    def now(self) -> datetime:
        """Current time as a timezone-aware UTC datetime."""
        ...


class MonotonicClock(Protocol):
    def monotonic_ns(self) -> int:
        """Current high-resolution monotonic timestamp in nanoseconds."""
        ...
