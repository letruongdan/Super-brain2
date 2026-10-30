"""Single-writer lease over ``writer.lock`` (spec 5.5).

The lock payload holds two 256-byte slots (file offsets 1 and 257, payload offsets 0 and 256). A slot is the
JSON ``{"seq":n,"writer_epoch":e,"trust_generation_hwm":t}`` padded with spaces to 252 bytes, then the CRC32 of
those 252 bytes, big-endian. Every write overwrites the older slot, so a torn write leaves the other one intact;
the valid slot with the highest ``seq`` is current. Both slots absent (all zero) is a fresh file. No valid slot in
a file that is not fresh is ``INTEGRITY_FAILURE``: guessing would restart the epoch and trust high-water at 0.
"""

import json
import zlib
from dataclasses import dataclass
from types import TracebackType

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.faults import crashpoint, pausepoint
from superbrain.ports.os import LockHandle, OsAdapters
from superbrain.storage.layout import DataRoot

SLOT_SIZE = 256
_BODY_SIZE = SLOT_SIZE - 4
_SLOT_OFFSETS = (0, SLOT_SIZE)
_TORN_AT = 128
_FIELDS = ("seq", "writer_epoch", "trust_generation_hwm")


@dataclass(frozen=True)
class LockState:
    writer_epoch: int
    trust_generation_hwm: int


@dataclass(frozen=True)
class _Slot:
    seq: int
    writer_epoch: int
    trust_generation_hwm: int

    def encode(self) -> bytes:
        fields = {"seq": self.seq, "writer_epoch": self.writer_epoch, "trust_generation_hwm": self.trust_generation_hwm}
        body = json.dumps(fields, separators=(",", ":")).encode("ascii")
        if len(body) > _BODY_SIZE:
            raise BrainError(ErrorCode.INVALID_INPUT, "writer lock state does not fit in a slot")
        body = body.ljust(_BODY_SIZE, b" ")
        return body + zlib.crc32(body).to_bytes(4, "big")


_FRESH = _Slot(seq=0, writer_epoch=0, trust_generation_hwm=0)


def _decode(raw: bytes) -> _Slot | None:
    """The slot in ``raw``, or ``None`` if it is torn or corrupt. ``raw`` is a full, non-zero slot."""
    body, crc = raw[:_BODY_SIZE], raw[_BODY_SIZE:]
    if zlib.crc32(body).to_bytes(4, "big") != crc:
        return None
    try:
        value = json.loads(body.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict) or sorted(value) != sorted(_FIELDS):
        return None
    numbers = [value[name] for name in _FIELDS]
    if not all(type(n) is int and n >= 0 for n in numbers):
        return None
    return _Slot(*numbers)


def _read_slots(payload: bytes) -> tuple[_Slot, int]:
    """The current slot and the index of the slot the next write goes to."""
    payload = payload.ljust(2 * SLOT_SIZE, b"\0")
    raws = [payload[offset : offset + SLOT_SIZE] for offset in _SLOT_OFFSETS]
    absent = [raw == bytes(SLOT_SIZE) for raw in raws]
    if all(absent):
        return _FRESH, 0
    slots = [None if gone else _decode(raw) for raw, gone in zip(raws, absent, strict=True)]
    valid = [(slot, index) for index, slot in enumerate(slots) if slot is not None]
    if not valid:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "writer.lock has no valid state slot")
    if len(valid) == 2 and valid[0][0].seq == valid[1][0].seq and valid[0][0] != valid[1][0]:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "writer.lock slots disagree at the same sequence number")
    current, index = max(valid, key=lambda pair: pair[0].seq)
    return current, 1 - index


class WriterLease:
    """The held writer lock for one data root. Obtain it with ``acquire_writer``."""

    def __init__(self, root: DataRoot, handle: LockHandle, current: _Slot, target: int) -> None:
        self.root = root
        self._handle: LockHandle | None = handle
        self._current = current
        self._target = target
        self._handles: set[str] = set()

    @property
    def epoch(self) -> int:
        return self._current.writer_epoch

    @property
    def held(self) -> bool:
        return self._handle is not None

    def state(self) -> LockState:
        return LockState(self._current.writer_epoch, self._current.trust_generation_hwm)

    def raise_trust_hwm(self, value: int) -> None:
        """Persist ``value`` as the trust-generation high-water mark if it is higher; it never goes down."""
        if value > self._current.trust_generation_hwm:
            self._write(self._current.writer_epoch, value)
        else:
            self._live_handle()

    def bump_epoch(self) -> int:
        self._write(self._current.writer_epoch + 1, self._current.trust_generation_hwm)
        return self._current.writer_epoch

    def release(self) -> None:
        handle, self._handle = self._handle, None
        if handle is not None:
            handle.release()

    def register_handle(self, name: str) -> None:
        if name in self._handles:
            raise AssertionError(f"handle {name!r} is already open under this lease")
        self._handles.add(name)

    def unregister_handle(self, name: str) -> None:
        if name not in self._handles:
            raise AssertionError(f"handle {name!r} is not open under this lease")
        self._handles.remove(name)

    def open_handles(self) -> frozenset[str]:
        return frozenset(self._handles)

    def __enter__(self) -> "WriterLease":
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        self.release()

    def _live_handle(self) -> LockHandle:
        if self._handle is None:
            raise AssertionError("writer lease already released")
        return self._handle

    def _write(self, writer_epoch: int, trust_generation_hwm: int) -> None:
        handle = self._live_handle()
        slot = _Slot(self._current.seq + 1, writer_epoch, trust_generation_hwm)
        raw = slot.encode()
        offset = _SLOT_OFFSETS[self._target]
        handle.write_payload(offset, raw[:_TORN_AT])
        pausepoint("writer.mid_slot_write")
        crashpoint("writer.mid_slot_write")
        handle.write_payload(offset + _TORN_AT, raw[_TORN_AT:])
        self._current = slot
        self._target = 1 - self._target


def acquire_writer(root: DataRoot, os_: OsAdapters) -> WriterLease:
    """Take the writer lock, then durably record a new ``writer_epoch`` before returning the lease."""
    handle = os_.locks.acquire(root.lock_path)
    try:
        current, target = _read_slots(handle.read_payload())
        lease = WriterLease(root, handle, current, target)
        lease.bump_epoch()
    except BaseException:
        handle.release()
        raise
    return lease
