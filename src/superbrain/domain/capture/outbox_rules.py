"""Pure capture watermark, separated ACK eviction, and bounded batch partitioning rules."""

from __future__ import annotations

from collections.abc import Sequence

from superbrain.core._kernel_base import require_positive_int
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.capture import (
    MAX_CAPTURE_BATCH_EVENTS,
    OUTBOX_RECORD_EVENT,
    OUTBOX_RECORD_GAP,
    CaptureBatchAck,
    OutboxEntry,
    compute_contiguous_event_acked_through,
)

DEFAULT_MAX_WIRE_BATCH_BYTES = 4 * 1024 * 1024


__all__ = [
    "DEFAULT_MAX_WIRE_BATCH_BYTES",
    "compute_contiguous_event_acked_through",
    "partition_pending_for_batch",
    "should_evict_outbox_entry",
]


def should_evict_outbox_entry(record_kind: str, sequence: int, ack: CaptureBatchAck) -> bool:
    """Check whether an outbox entry of ``record_kind`` at ``sequence`` may be evicted by ``ack``.

    Events and producer capture gaps are evicted separately; a gap ACK never evicts an Event.
    """
    if record_kind not in (OUTBOX_RECORD_EVENT, OUTBOX_RECORD_GAP):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if not isinstance(ack, CaptureBatchAck):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    return ack.allows_eviction(record_kind, sequence)


def partition_pending_for_batch(
    entries: Sequence[OutboxEntry],
    *,
    max_events: int = MAX_CAPTURE_BATCH_EVENTS,
    max_wire_bytes: int = DEFAULT_MAX_WIRE_BATCH_BYTES,
) -> tuple[tuple[OutboxEntry, ...], ...]:
    """Split pending outbox entries into ordered batches bounded by count and payload bytes."""
    require_positive_int(max_events)
    if max_events > MAX_CAPTURE_BATCH_EVENTS:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    require_positive_int(max_wire_bytes)

    batches: list[tuple[OutboxEntry, ...]] = []
    current: list[OutboxEntry] = []
    current_bytes = 0
    for entry in entries:
        if not isinstance(entry, OutboxEntry):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if current and (len(current) >= max_events or current_bytes + entry.byte_size > max_wire_bytes):
            batches.append(tuple(current))
            current = [entry]
            current_bytes = entry.byte_size
        else:
            current.append(entry)
            current_bytes += entry.byte_size
    if current:
        batches.append(tuple(current))
    return tuple(batches)
