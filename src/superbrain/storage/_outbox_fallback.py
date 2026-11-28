"""Fallback gaps that keep the notification's slot: one spool lock decides the slot, reserves it with a durable
binding stamped with the gap identity, and publishes the gap (audit 2026-11-28 group A)."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.capture import OUTBOX_RECORD_GAP, ProducerCaptureGap, default_outbox_dir_renamer
from superbrain.storage import _outbox_io as _io
from superbrain.storage import _outbox_seq as _seq
from superbrain.storage._outbox_bindings import (
    HookBindingRecord,
    prepare_binding_upsert,
    write_prepared_binding_bucket,
)
from superbrain.storage._outbox_hookseq import (
    DEFERRABLE_AFTER_PUBLISH,
    compute_projected_hook_recovery,
    read_hook_cursor_readonly,
    slot_holds_event,
    slot_owner,
)
from superbrain.storage._outbox_slots import allocate_event_id

if TYPE_CHECKING:
    from superbrain.storage.outbox import OutboxSpool


def fallback_gap_id(producer_stream: str, sequence: int) -> str:
    """Gap id derived from the slot, so every fallback for one slot names the same gap."""
    slot = (producer_stream + "\n" + str(sequence)).encode()
    return "gap-" + digest_bytes(slot)[7:39]


def enqueue_fallback_gap(
    spool: OutboxSpool, *, producer_stream: str, sequence: int | None, dedup_key: str | None, reason: str,
    recorded_at: str, duration_ms: int, deadline_ns: int | None, event_id: str | None = None,
) -> str | None:
    """See ``OutboxSpool.enqueue_fallback_gap``."""
    if not spool.root.exists():
        first = sequence if sequence is not None else 1
        probe = ProducerCaptureGap(gap_id=fallback_gap_id(producer_stream, first), producer_stream=producer_stream,
                                   sequence=first, reason=reason, recorded_at=recorded_at, estimated_count=1,
                                   duration_ms=duration_ms)
        _digest, frame = _io.prepare_outbox_frame_bytes(record_kind=OUTBOX_RECORD_GAP, producer_stream=producer_stream,
            sequence=first, entry_id=probe.gap_id, payload_dict=probe.to_dict())
        if len(frame) > spool._max_bytes:
            raise BrainError(ErrorCode.STORAGE_FULL, "storage full")  # refused before the spool is created
    dl_check: Callable[[], None] | None = (
        (lambda: spool._check_deadline(deadline_ns)) if deadline_ns is not None else None)
    with spool._locked(create_root=True, sweep=False, deadline_ns=deadline_ns):
        perms = spool._resolve_permissions()
        key = _io.stream_dir_key(producer_stream)
        sdir = spool.root / _io._STREAMS_DIR / key
        raw_cur = read_hook_cursor_readonly(sdir, perms)
        cached = (_seq.lookup_stream_binding_with_bucket(sdir, raw_cur, dedup_key, perms)[0]
                  if dedup_key is not None else None)
        if cached is not None:
            if (sequence is not None and sequence != cached.sequence) or (
                event_id is not None and event_id != cached.event_id
            ):
                raise BrainError(ErrorCode.IDEMPOTENCY_CONFLICT, "idempotency conflict")
            seq = cached.sequence
        elif sequence is not None:
            seq = sequence
            if slot_owner(sdir, seq, perms) is not None:
                raise BrainError(ErrorCode.IDEMPOTENCY_CONFLICT, "slot reserved by another notification")
        else:
            max_seq = spool._scan_outbox_with_stream(deadline_ns=deadline_ns, match_stream_key=key, sweep=False,
                                                     collect_stream_frames=True)[3]
            seq = max(compute_projected_hook_recovery(sdir, raw_cur, perms)[0].next_seq, max_seq + 1)
        if slot_holds_event(sdir, seq, perms):
            return None
        adopted = None if cached is not None and cached.gap is not None else _pending_gap_stamp(spool, sdir, seq)
        stamp = (cached.gap if cached is not None and cached.gap is not None else adopted if adopted is not None else
                 (fallback_gap_id(producer_stream, seq), reason, cached.recorded_at if cached else recorded_at,
                  duration_ms))
        reserved = False
        if dedup_key is not None and (cached is None or cached.gap is None):
            # the producer's own event_id when it gave one, as the hook path binds it (resolve_hook_envelope_slot)
            new_id = event_id if event_id is not None else allocate_event_id(dedup_key)
            binding = HookBindingRecord(dedup_key, seq, cached.event_id if cached else new_id,
                                        cached.recorded_at if cached else recorded_at,
                                        cached.payload_digest if cached else None, stamp)
            reserved = _reserve_slot(spool, sdir, binding, new_key=cached is None, check=dl_check)
        if adopted is not None:
            gap_id = adopted[0]  # that gap is already pending for the slot: keep it, publish nothing new
        else:
            gap = ProducerCaptureGap(gap_id=stamp[0], producer_stream=producer_stream, sequence=seq, reason=stamp[1],
                                     recorded_at=stamp[2], estimated_count=1, duration_ms=stamp[3])
            gap_id = spool.enqueue_gap(gap, deadline_ns=deadline_ns)
        if reserved:
            try:
                now = _seq.read_stream_cursor(sdir, perms)
                if now.pending_binding is not None:
                    _seq.write_stream_cursor(sdir, now.with_binding_state(pending_binding=None), perms)
            except BrainError as err:  # the gap is published; the next recovery clears a stale pending binding
                if err.code not in DEFERRABLE_AFTER_PUBLISH:
                    raise
        return gap_id


def _pending_gap_stamp(spool: OutboxSpool, sdir: Path, seq: int) -> tuple[str, str, str, int] | None:
    """Identity of a gap frame already pending at ``seq`` (an earlier binary's random id), or ``None``."""
    if not sdir.is_dir():
        return None
    suffix = f"_{OUTBOX_RECORD_GAP}_{seq:020d}{_io._FRAME_SUFFIX}"
    with os.scandir(sdir) as it:
        path = next((Path(e.path) for e in it if e.name.endswith(suffix)), None)
    if path is None:
        return None
    gap = ProducerCaptureGap.from_dict(json.loads(spool._decode_frame_file(path).payload_json))
    return gap.gap_id, gap.reason, gap.recorded_at, gap.duration_ms if gap.duration_ms is not None else 0


def _reserve_slot(
    spool: OutboxSpool, sdir: Path, binding: HookBindingRecord, *, new_key: bool, check: Callable[[], None] | None,
) -> bool:
    """Durably bind ``binding.key`` to its slot with the gap stamp before the gap is published. Returns ``False``
    when the binding window cannot take one more key: the gap is then written without a reservation."""
    perms = spool._resolve_permissions()
    renamer = default_outbox_dir_renamer()
    raw_cur = read_hook_cursor_readonly(sdir, perms)
    if new_key and compute_projected_hook_recovery(sdir, raw_cur, perms)[1] >= spool._max_binding_keys:
        return False
    streams_dir = spool.root / _io._STREAMS_DIR
    _io.ensure_dir_tree_atomic(streams_dir, perms, renamer, check_deadline=check)
    _io.ensure_dir_tree_atomic(sdir, perms, renamer, check_deadline=check)
    if not (streams_dir / _io._V4_FENCE_FILE).exists():
        _seq._publish_v4_fence(sdir, perms, renamer=renamer, check_deadline=check)
    # gap-stamped rows: fence 5 goes first so every earlier binary (incl. v4 4e33772) refuses before reading them
    _io.raise_fence_for_gap_stamps(streams_dir, perms, check_deadline=check)
    cursor = _seq.recover_stream_cursor(sdir, read_hook_cursor_readonly(sdir, perms), perms, renamer=renamer,
                                        check_deadline=check)
    try:
        bucket, payload, added = prepare_binding_upsert(sdir, binding, perms)
    except BrainError as err:
        if err.code is ErrorCode.STORAGE_FULL:
            return False
        raise
    bound = cursor.with_binding_state(next_seq=max(cursor.next_seq, binding.sequence + 1),
                                      binding_count=cursor.binding_count + (1 if added else 0),
                                      pending_binding=binding if payload is not None else None)
    if bound != cursor:
        _seq.write_stream_cursor(sdir, bound, perms)
    if payload is not None:
        write_prepared_binding_bucket(sdir, bucket, payload, perms, renamer=renamer, check_deadline=check)
    return True
