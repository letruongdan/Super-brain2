"""Thread-safe, strictly increasing UUIDv7 generation."""

import secrets
import threading
import time
import uuid
from collections.abc import Callable

_COUNTER_MAX = 0xFFF


class IdGenerator:
    def __init__(self, now_ms: Callable[[], int], random_bits: Callable[[int], int]) -> None:
        self._now_ms = now_ms
        self._random_bits = random_bits
        self._lock = threading.Lock()
        self._last_ms = -1
        self._counter = 0

    def next(self) -> str:
        with self._lock:
            now = self._now_ms()
            if now > self._last_ms:
                self._last_ms = now
                self._counter = self._random_bits(12)
            else:
                # Same millisecond or clock rollback: keep the last timestamp, bump the counter.
                self._counter += 1
                if self._counter > _COUNTER_MAX:
                    self._last_ms += 1
                    self._counter = 0
            ms, counter = self._last_ms, self._counter
            rand_b = self._random_bits(62)
        value = (ms & 0xFFFFFFFFFFFF) << 80 | 0x7 << 76 | counter << 64 | 0b10 << 62 | rand_b
        return str(uuid.UUID(int=value))


_default = IdGenerator(lambda: time.time_ns() // 1_000_000, secrets.randbits)


def new_id() -> str:
    return _default.next()


def id_timestamp_ms(value: str) -> int:
    return uuid.UUID(value).int >> 80
