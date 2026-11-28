"""Cursor helpers for hook enqueue and slot ownership, built on the stream cursor in ``_outbox_seq``."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.capture import (
    OUTBOX_RECORD_EVENT,
    CaptureEventRecord,
    OutboxDirRenamer,
    OutboxPermissionsPort,
)
from superbrain.storage import _outbox_io as _io
from superbrain.storage import _outbox_seq as _seq
from superbrain.storage._outbox_bindings import (
    _BINDINGS_DIR,
    HookBindingRecord,
    backfill_binding_digest_if_missing,
    count_all_bindings,
    lookup_binding,
    prepare_binding_upsert,
    read_binding_bucket,
    write_prepared_binding_bucket,
)
from superbrain.storage._outbox_io import verify_stream_dir_safe
from superbrain.storage._outbox_seq import StreamSeqCursor, read_stream_cursor

# Upkeep after a frame is published may stop on these; the next recovery repairs it, so the enqueue still succeeds.
DEFERRABLE_AFTER_PUBLISH = (ErrorCode.DEADLINE_EXCEEDED, ErrorCode.STORAGE_FULL)


def slot_owner(stream_dir: Path, sequence: int, perms: OutboxPermissionsPort) -> HookBindingRecord | None:
    """The binding that reserved ``sequence`` in this stream (pending, legacy or sharded), if any."""
    if not verify_stream_dir_safe(stream_dir, perms):
        return None
    if _seq.cursor_exists(stream_dir):
        cur = read_stream_cursor(stream_dir, perms)
        held: list[HookBindingRecord] = list(cur.legacy_recent)
        if cur.pending_binding is not None:
            held.append(cur.pending_binding)
        for item in held:
            if item.sequence == sequence:
                return item
    bdir = stream_dir / _BINDINGS_DIR
    if not os.path.isdir(bdir):
        return None
    for name in sorted(os.listdir(bdir)):
        if name.endswith(".json"):
            for rec in read_binding_bucket(stream_dir, name, perms).values():
                if rec.sequence == sequence:
                    return rec
    return None


def slot_holds_event(stream_dir: Path, sequence: int, perms: OutboxPermissionsPort) -> bool:
    """True when ``sequence`` already has a published event frame or an acknowledged event in this stream."""
    if not verify_stream_dir_safe(stream_dir, perms):
        return False
    suffix = f"_{OUTBOX_RECORD_EVENT}_{sequence:020d}{_io._FRAME_SUFFIX}"
    with os.scandir(stream_dir) as it:
        if any(entry.name.endswith(suffix) for entry in it):
            return True
    return _seq.cursor_exists(stream_dir) and read_stream_cursor(stream_dir, perms).is_event_acked(sequence)


def read_hook_cursor_readonly(stream_dir: Path, perms: OutboxPermissionsPort) -> StreamSeqCursor:
    """Read stream cursor without mutating disk (returns fresh cursor when stream absent)."""
    return read_stream_cursor(stream_dir, perms) if verify_stream_dir_safe(stream_dir, perms) else StreamSeqCursor(1)


def compute_projected_hook_recovery(
    stream_dir: Path, cursor: StreamSeqCursor, perms: OutboxPermissionsPort
) -> tuple[StreamSeqCursor, int]:
    """Compute post-recovery cursor preview and exact deduplicated binding count read-only."""
    want_v4 = cursor.schema_v4 or _seq._is_outbox_v4_fenced(stream_dir)
    if not _seq._needs_cursor_recovery(cursor):
        cur = cursor.with_binding_state(pending_binding=cursor.pending_binding, schema_v4=True) if want_v4 else cursor
        return cur, cursor.binding_count
    preview, _ = _seq._preview_recovered_cursor(cursor, force_v4=want_v4)
    pending_keys = {it.key for it in cursor.legacy_recent}
    if cursor.pending_binding is not None:
        pending_keys.add(cursor.pending_binding.key)
    has_bdir = os.path.lexists(stream_dir / _BINDINGS_DIR)
    base_count = count_all_bindings(stream_dir, perms) if has_bdir else 0
    added = sum(1 for k in pending_keys if not has_bdir or lookup_binding(stream_dir, k, perms) is None)
    projected = base_count + added
    return preview.with_binding_state(binding_count=projected, pending_binding=None), projected


def preflight_hook_cursor_size(
    stream_dir: Path, preview: StreamSeqCursor, *, sequence: int,
    prepared: tuple[HookBindingRecord, str, bytes | None, bool] | None,
) -> None:
    """Validate serialized hook cursor byte limit before any durable mutation."""
    new_count = preview.binding_count + (1 if (prepared is not None and prepared[3]) else 0)
    pending_b = prepared[0] if (prepared is not None and prepared[2] is not None) else None
    bound_c = preview.with_binding_state(
        next_seq=max(preview.next_seq, sequence + 1), binding_count=new_count,
        pending_binding=pending_b, schema_v4=preview.schema_v4 or _seq._is_outbox_v4_fenced(stream_dir),
    )
    _seq._serialize_cursor_bytes(bound_c)
    _seq._serialize_cursor_bytes(bound_c.with_binding_state(pending_binding=None))


def settle_published_hook_frame(
    stream_dir: Path, raw_cur: StreamSeqCursor, *, matched: bool, dedup_key: str | None,
    cached: HookBindingRecord | None, record: CaptureEventRecord, payload_digest: str, perms: OutboxPermissionsPort,
    renamer: OutboxDirRenamer | None, check_deadline: Callable[[], None] | None,
) -> None:
    """Upkeep for an event whose frame is already published (or acknowledged). A deadline or capacity stop here is
    left to the next recovery, never reported as a failure the hook would record as a lost event."""
    try:
        cursor = _seq.recover_stream_cursor(stream_dir, raw_cur, perms, renamer=renamer, check_deadline=check_deadline)
        if matched:
            reconcile_matched_hook_frame_cursor(stream_dir, cursor, dedup_key=dedup_key, cached=cached, record=record,
                payload_digest=payload_digest, perms=perms, renamer=renamer, check_deadline=check_deadline)
        else:
            backfill_binding_digest_if_missing(stream_dir, cached, payload_digest, perms,
                renamer=renamer, check_deadline=check_deadline)
    except BrainError as err:
        if err.code not in DEFERRABLE_AFTER_PUBLISH:
            raise


def reconcile_matched_hook_frame_cursor(
    stream_dir: Path, cursor: StreamSeqCursor, *, dedup_key: str | None,
    cached: HookBindingRecord | None, record: CaptureEventRecord, payload_digest: str,
    perms: OutboxPermissionsPort, renamer: OutboxDirRenamer | None, check_deadline: Callable[[], None] | None,
) -> None:
    """Ensure sharded binding and cursor ``next_seq`` reflect a pre-existing matched frame."""
    if dedup_key is not None and cached is None:
        b_exist = HookBindingRecord(dedup_key, record.sequence, record.event_id, record.recorded_at, payload_digest)
        bucket_name, payload, added = prepare_binding_upsert(stream_dir, b_exist, perms)
        next_seq = max(cursor.next_seq, record.sequence + 1)
        new_count = cursor.binding_count + (1 if added else 0)
        if payload is not None:
            bound_c = cursor.with_binding_state(next_seq=next_seq, binding_count=new_count, pending_binding=b_exist)
            _seq.write_stream_cursor(stream_dir, bound_c, perms)
            write_prepared_binding_bucket(
                stream_dir, bucket_name, payload, perms, renamer=renamer, check_deadline=check_deadline
            )
        cleared_c = cursor.with_binding_state(next_seq=next_seq, binding_count=new_count, pending_binding=None)
        if payload is not None or cleared_c != cursor:
            _seq.write_stream_cursor(stream_dir, cleared_c, perms)
        return
    if cached is not None and cached.payload_digest is None:
        backfill_binding_digest_if_missing(
            stream_dir, cached, payload_digest, perms, renamer=renamer, check_deadline=check_deadline
        )
    if cursor.next_seq <= record.sequence:
        _seq.write_stream_cursor(stream_dir, cursor.bump_next_seq(record.sequence), perms)
