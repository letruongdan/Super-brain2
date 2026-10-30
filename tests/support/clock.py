"""Deterministic clock for tests."""

from datetime import datetime, timedelta


def _require_aware(value: datetime) -> datetime:
    assert value.tzinfo is not None and value.utcoffset() is not None, "FakeClock requires timezone-aware datetimes"
    return value


class FakeClock:
    def __init__(self, start: datetime) -> None:
        self._now = _require_aware(start)

    def now(self) -> datetime:
        return self._now

    def advance(self, delta: timedelta) -> None:
        self._now = _require_aware(self._now + delta)

    def set(self, value: datetime) -> None:
        self._now = _require_aware(value)
