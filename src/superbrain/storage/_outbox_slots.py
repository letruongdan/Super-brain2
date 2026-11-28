"""Hook slot allocation and previous-binary (v3) cursor normalization helpers for ``_outbox_seq``."""

from __future__ import annotations

from typing import TYPE_CHECKING

from superbrain.core.canonical import canonical_json
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id

if TYPE_CHECKING:
    from superbrain.storage._outbox_bindings import HookBindingRecord
    from superbrain.storage._outbox_seq import StreamSeqCursor


def serialize_v3_normalized(cursor: StreamSeqCursor, binding_count: int, max_bytes: int) -> bytes:
    """v3 cursor bytes exactly as the previous binary's own recovery writes them: no pending binding, merged
    ``acked_ranges``. Writing this changes nothing the previous binary could not have written itself."""
    contig = cursor.contiguous_acked_through
    ranges = sorted({*(((1, contig),) if contig > 0 else ()), *cursor.acked_ranges, *cursor.legacy_acked_ranges})
    payload = canonical_json({
        "schema_version": 3, "next_seq": cursor.next_seq, "binding_count": binding_count,
        "acked_ranges": [[lo, hi] for lo, hi in ranges], "pending_binding": None,
    })
    if len(payload) > max_bytes:
        raise BrainError(ErrorCode.STORAGE_FULL, "stream cursor exceeds size bound")
    return payload


def allocate_event_id(dedup_key: str | None) -> str:
    """Derive a collision-free opaque ``event_id`` (deterministic when ``dedup_key`` is given)."""
    if dedup_key is not None and dedup_key.startswith("sha256:"):
        return f"ev-{dedup_key.removeprefix('sha256:')[:24]}"
    return f"ev-{new_id()}"


def resolve_hook_envelope_slot(
    cursor: StreamSeqCursor, *, cached: HookBindingRecord | None = None, max_frame_seq: int,
    explicit_sequence: int | None, explicit_event_id: str | None, dedup_key: str | None, fallback_recorded_at: str,
) -> tuple[int, str, str]:
    """Choose deterministic retry slot from ``cached`` binding or allocate next monotonic stream sequence."""
    if cached is not None:
        if (explicit_sequence is not None and explicit_sequence != cached.sequence) or (
            explicit_event_id is not None and explicit_event_id != cached.event_id
        ):
            raise BrainError(ErrorCode.IDEMPOTENCY_CONFLICT, "idempotency conflict")
        return cached.sequence, cached.event_id, cached.recorded_at
    seq = explicit_sequence if explicit_sequence is not None else max(cursor.next_seq, max_frame_seq + 1)
    ev_id = explicit_event_id if explicit_event_id is not None else allocate_event_id(dedup_key)
    return seq, ev_id, fallback_recorded_at
