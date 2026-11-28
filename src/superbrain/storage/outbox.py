"""Crash-safe bounded file-backed local outbox spool (no sqlite3, no socket, no module-level faults import)."""

from __future__ import annotations

import os
import stat
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

from superbrain.core._kernel_base import require_positive_int
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.ports.capture import (
    DEFAULT_OUTBOX_MAX_BYTES,
    MAX_CAPTURE_BATCH_EVENTS,
    OUTBOX_RECORD_EVENT,
    OUTBOX_RECORD_GAP,
    CaptureBatchAck,
    CaptureEventRecord,
    OutboxEntry,
    OutboxFileLockPort,
    OutboxPermissionsPort,
    ProducerCaptureGap,
    default_outbox_dir_renamer,
    default_outbox_file_lock,
    default_outbox_permissions,
)
from superbrain.storage import _outbox_fallback as _fallback
from superbrain.storage import _outbox_io as _io
from superbrain.storage import _outbox_scan as _scan
from superbrain.storage._outbox_bindings import (
    DEFAULT_MAX_STREAM_BINDING_KEYS,
    bucket_name_for_key,
    prepare_hook_binding_upsert,
    project_recovered_buckets,
    write_prepared_binding_bucket,
)
from superbrain.storage._outbox_hookseq import (
    DEFERRABLE_AFTER_PUBLISH,
    compute_projected_hook_recovery,
    preflight_hook_cursor_size,
    read_hook_cursor_readonly,
    settle_published_hook_frame,
    slot_owner,
)
from superbrain.storage._outbox_seq import (
    StreamSeqCursor,
    commit_bumped_cursor,
    lookup_stream_binding_with_bucket,
    persist_cursor_ack,
    prepare_cursor_for_direct_enqueue,
    recover_stream_cursor,
    resolve_hook_envelope_slot,
    sync_stream_metadata,
    verify_stream_cursor_integrity,
)
from superbrain.storage._outbox_seq import (
    write_stream_cursor as write_stream_cursor,
)


class OutboxSpool:
    """Owner-only, fsynced, bounded local capture outbox supporting crash recovery and separated EV/gap ACK."""

    def __init__(
        self,
        path: Path,
        *,
        max_bytes: int = DEFAULT_OUTBOX_MAX_BYTES,
        max_binding_keys: int = DEFAULT_MAX_STREAM_BINDING_KEYS,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
        permissions: OutboxPermissionsPort | None = None,
        file_lock: OutboxFileLockPort | None = None,
    ) -> None:
        _io.check_safe_path_syntax(path)
        require_positive_int(max_bytes)
        require_positive_int(max_binding_keys)
        _io.reject_links_upward(path)
        self._root = path if path.is_absolute() else path.absolute()
        self._max_bytes = max_bytes
        self._max_binding_keys = max_binding_keys
        self._monotonic_ns = monotonic_ns
        self._permissions = permissions
        self._file_lock = file_lock
        self._resolve_permissions()
        self._resolve_file_lock()
        self._thread_lock = _io.thread_lock_for(self._root)
        self._lock_depth = 0  # >0 while this thread already holds the spool lock (nested operation)
        self._verify_existing_root_readonly()

    @property
    def root(self) -> Path:
        return self._root

    def _resolve_permissions(self) -> OutboxPermissionsPort:
        perms = self._permissions if self._permissions is not None else default_outbox_permissions()
        if perms is None:
            raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "outbox permission adapter is not configured")
        return perms

    def _resolve_file_lock(self) -> OutboxFileLockPort:
        adapter = self._file_lock if self._file_lock is not None else default_outbox_file_lock()
        if adapter is None:
            raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "outbox file lock adapter is not configured")
        return adapter

    def _check_deadline(self, deadline_ns: int | None) -> None:
        if deadline_ns is not None and int(self._monotonic_ns()) >= deadline_ns:
            raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")

    def _verify_existing_root_readonly(self) -> None:
        if not os.path.lexists(self._root):
            return
        _io.reject_links_upward(self._root)
        if _io.is_link_path(self._root):
            raise BrainError(ErrorCode.UNSAFE_PATH, "outbox root is a link")
        if not stat.S_ISDIR(os.lstat(self._root).st_mode):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "outbox root is not a directory")
        _io.verify_owner_only(self._root, self._resolve_permissions())

    @contextmanager
    def _locked(self, *, create_root: bool, sweep: bool = True, deadline_ns: int | None = None) -> Iterator[None]:
        perms = self._resolve_permissions()
        adapter = self._resolve_file_lock()
        renamer = default_outbox_dir_renamer()
        dl_check = (lambda: self._check_deadline(deadline_ns)) if deadline_ns is not None else None
        wait_s = -1.0 if deadline_ns is None else max(0.0, (deadline_ns - int(self._monotonic_ns())) / 1e9)
        if not self._thread_lock.acquire(timeout=wait_s):
            raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")
        if self._lock_depth:
            try:
                yield from self._nested_lock(deadline_ns, dl_check)
            finally:
                self._thread_lock.release()
            return
        try:
            self._check_deadline(deadline_ns)
            if not os.path.lexists(self._root):
                if not create_root:
                    yield
                    return
                _io.ensure_dir_tree_atomic(self._root, perms, renamer, check_deadline=dl_check)
            else:
                _io.reject_links_upward(self._root)
                _io.ensure_dir_tree_atomic(self._root, perms, renamer, check_deadline=dl_check)
            lock_path = self._root / _io._LOCK_FILE
            _io.ensure_secure_regular_file_atomic(lock_path, perms, check_deadline=dl_check)
            fd = os.open(lock_path, os.O_RDWR | _io._O_BINARY | _io._O_NOFOLLOW)
            locked = False
            dl_tok = _io.push_deadline_check(dl_check)
            rem_tok = _io.push_deadline_remaining(
                (lambda: deadline_ns - int(self._monotonic_ns())) if deadline_ns is not None else None)
            try:
                locked = self._acquire_file_lock(fd, adapter=adapter, deadline_ns=deadline_ns)
                if sweep:
                    self._scan_outbox(deadline_ns=deadline_ns)
                self._lock_depth = 1
                try:
                    yield
                finally:
                    self._lock_depth = 0
            finally:
                _io.reset_deadline_remaining(rem_tok)
                _io.reset_deadline_check(dl_tok)
                try:
                    if locked:
                        adapter.unlock_fd(fd)
                finally:
                    os.close(fd)
        finally:
            self._thread_lock.release()

    def _nested_lock(self, deadline_ns: int | None, dl_check: Callable[[], None] | None) -> Iterator[None]:
        """Inner operation of a thread that already holds the spool lock: same lock, its own deadline."""
        self._check_deadline(deadline_ns)
        dl_tok = _io.push_deadline_check(dl_check)
        rem_tok = _io.push_deadline_remaining(
            (lambda: deadline_ns - int(self._monotonic_ns())) if deadline_ns is not None else None)
        self._lock_depth += 1
        try:
            yield
        finally:
            self._lock_depth -= 1
            _io.reset_deadline_remaining(rem_tok)
            _io.reset_deadline_check(dl_tok)

    def _acquire_file_lock(self, fd: int, *, adapter: OutboxFileLockPort, deadline_ns: int | None) -> bool:
        while True:
            self._check_deadline(deadline_ns)
            try:
                if adapter.try_lock_fd(fd):
                    return True
            except OSError as err:
                raise _io.raise_storage_error(err, "cannot lock outbox") from err
            _io.wait_within_budget(0.002)

    def _scan_outbox_with_stream(
        self,
        *,
        deadline_ns: int | None = None,
        match_stream_key: str | None = None,
        match_suffix: str | None = None,
        sweep: bool = True,
        collect_stream_frames: bool = False,
    ) -> _scan.ScanResult:
        """Single-pass scandir: reject links, sweep staging when asked, sum bytes, optionally collect one stream."""
        return _scan.scan_outbox(
            self._root, perms=self._resolve_permissions(), check=lambda: self._check_deadline(deadline_ns),
            match_stream_key=match_stream_key, match_suffix=match_suffix, sweep=sweep,
            collect_stream_frames=collect_stream_frames,
        )

    def _scan_outbox(
        self,
        *,
        deadline_ns: int | None = None,
        match_stream_key: str | None = None,
        match_suffix: str | None = None,
        sweep: bool = True,
    ) -> tuple[int, int, Path | None]:
        """Single-pass scandir: reject links, sweep .part files, sum frame bytes, and locate target frame."""
        total, order, matched, _sseq, _frames, _ok = self._scan_outbox_with_stream(
            deadline_ns=deadline_ns, match_stream_key=match_stream_key, match_suffix=match_suffix, sweep=sweep
        )
        return total, order, matched

    def _collect_regular_frames(self, directory: Path) -> list[Path]:
        return _scan.collect_regular_frames(directory, self._resolve_permissions())

    def _iter_frame_paths(
        self, *, producer_stream: str | None = None, verify_cursor: bool = True
    ) -> list[Path]:
        perms = self._resolve_permissions()
        streams_root = self._root / _io._STREAMS_DIR
        if not os.path.lexists(streams_root):
            return []
        _io.verify_streams_fence_if_present(streams_root, perms)
        if producer_stream is not None:
            sdir = streams_root / _io.stream_dir_key(producer_stream)
            if not os.path.lexists(sdir):
                return []
            if verify_cursor:
                verify_stream_cursor_integrity(sdir, perms)
            paths = self._collect_regular_frames(sdir)
        else:
            paths = []
            with os.scandir(streams_root) as it:
                for sd_entry in it:
                    if _io.entry_is_link(sd_entry):
                        raise BrainError(ErrorCode.UNSAFE_PATH, "stream directory is a link")
                    if sd_entry.name == _io._V4_FENCE_FILE:
                        _io.verify_v4_fence_file(Path(sd_entry.path), perms)
                        continue
                    if _io.is_v4_fence_part_name(sd_entry.name):
                        continue
                    if stat.S_ISDIR(sd_entry.stat(follow_symlinks=False).st_mode):
                        sdir_path = Path(sd_entry.path)
                        if verify_cursor:
                            verify_stream_cursor_integrity(sdir_path, perms)
                        paths.extend(self._collect_regular_frames(sdir_path))
        paths.sort(key=_io.parse_frame_order)
        return paths

    def _decode_frame_file(self, path: Path) -> OutboxEntry:
        if _io.is_link_path(path):
            raise BrainError(ErrorCode.UNSAFE_PATH, "frame file is a link")
        if not stat.S_ISREG(os.lstat(path).st_mode):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt outbox frame type")
        _io.verify_owner_only(path, self._resolve_permissions())
        raw = _io.read_all_binary(path)
        entry, nl_idx = _io.parse_verified_outbox_frame(raw)
        if nl_idx < len(raw) - 1:
            self._atomic_publish_frame(path, path.with_name(f"{path.name}{_io._PART_SUFFIX}"), raw[: nl_idx + 1])
        return entry

    def _atomic_publish_frame(
        self,
        final_path: Path,
        part_path: Path,
        frame_bytes: bytes,
        *,
        crashpoint_name: str | None = None,
        deadline_ns: int | None = None,
    ) -> None:
        dl_check = (lambda: self._check_deadline(deadline_ns)) if deadline_ns is not None else None
        _io.publish_outbox_frame_atomic(
            final_path, part_path, frame_bytes, self._resolve_permissions(),
            crashpoint_name=crashpoint_name, check_deadline=dl_check,
        )

    def _enqueue_record(
        self,
        *,
        record_kind: str,
        producer_stream: str,
        sequence: int,
        entry_id: str,
        payload_dict: dict[str, JsonValue],
        deadline_ns: int | None,
    ) -> str:
        self._check_deadline(deadline_ns)
        payload_digest, frame_bytes = _io.prepare_outbox_frame_bytes(
            record_kind=record_kind, producer_stream=producer_stream, sequence=sequence,
            entry_id=entry_id, payload_dict=payload_dict,
        )
        stream_key = _io.stream_dir_key(producer_stream)
        target_suffix = f"_{record_kind}_{sequence:020d}{_io._FRAME_SUFFIX}"
        dl_check = (lambda: self._check_deadline(deadline_ns)) if deadline_ns is not None else None
        perms = self._resolve_permissions()
        renamer = default_outbox_dir_renamer()
        if not os.path.lexists(self._root) and len(frame_bytes) > self._max_bytes:
            raise BrainError(ErrorCode.STORAGE_FULL, "storage full")  # refused before the spool is created
        with self._locked(create_root=True, sweep=False, deadline_ns=deadline_ns):
            used, highest_order, matched_path = self._scan_outbox(
                deadline_ns=deadline_ns, match_stream_key=stream_key, match_suffix=target_suffix, sweep=False
            )
            streams_root = self._root / _io._STREAMS_DIR
            sdir = streams_root / stream_key
            if os.path.lexists(streams_root) and os.path.lexists(sdir):
                verify_stream_cursor_integrity(sdir, perms)
                sync_stream_metadata(sdir)
            if matched_path is not None:
                existing_entry = self._decode_frame_file(matched_path)
                if existing_entry.entry_id == entry_id and existing_entry.payload_digest == payload_digest:
                    return existing_entry.entry_id
                raise BrainError(ErrorCode.IDEMPOTENCY_CONFLICT, "idempotency conflict")
            if record_kind == OUTBOX_RECORD_EVENT:
                owner = slot_owner(sdir, sequence, perms)
                if owner is not None and owner.event_id != entry_id:
                    raise BrainError(ErrorCode.IDEMPOTENCY_CONFLICT, "slot reserved by another notification")
            if used + len(frame_bytes) > self._max_bytes:
                raise BrainError(ErrorCode.STORAGE_FULL, "storage full")
            _io.ensure_dir_tree_atomic(streams_root, perms, renamer, check_deadline=dl_check)
            preflight_cur = prepare_cursor_for_direct_enqueue(
                sdir, sequence, perms, renamer=renamer, check_deadline=dl_check
            )
            _io.ensure_dir_tree_atomic(sdir, perms, renamer, check_deadline=dl_check)
            base = f"{highest_order + 1:016d}_{record_kind}_{sequence:020d}"
            self._atomic_publish_frame(
                sdir / f"{base}{_io._FRAME_SUFFIX}", sdir / f"{base}{_io._PART_SUFFIX}", frame_bytes,
                crashpoint_name="capture.outbox.after_write_before_fsync", deadline_ns=deadline_ns,
            )
            try:
                commit_bumped_cursor(sdir, preflight_cur, sequence, perms)
            except BrainError as err:  # frame is published; the next recovery repairs a stopped cursor bump
                if err.code not in DEFERRABLE_AFTER_PUBLISH:
                    raise
            return entry_id

    def enqueue_event(self, record: CaptureEventRecord, *, deadline_ns: int | None = None) -> str:
        """Persist a sanitized ``CaptureEventRecord`` durably; idempotent on matching key, conflict on mismatch."""
        if not isinstance(record, CaptureEventRecord):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        return self._enqueue_record(record_kind=OUTBOX_RECORD_EVENT, producer_stream=record.producer_stream,
            sequence=record.sequence, entry_id=record.event_id, payload_dict=record.to_dict(),
            deadline_ns=deadline_ns)

    def enqueue_hook_event(
        self,
        *,
        producer_stream: str,
        build_event: Callable[[int, str, str], CaptureEventRecord],
        explicit_sequence: int | None = None,
        explicit_event_id: str | None = None,
        dedup_key: str | None = None,
        fallback_recorded_at: str,
        deadline_ns: int | None = None,
    ) -> CaptureEventRecord:
        """Allocate/reuse durable sharded hook binding, sanitize via ``build_event``, and enqueue atomically."""
        stream_key = _io.stream_dir_key(producer_stream)
        perms = self._resolve_permissions()
        renamer = default_outbox_dir_renamer()
        dl_check = (lambda: self._check_deadline(deadline_ns)) if deadline_ns is not None else None
        if not os.path.lexists(self._root):
            self._refuse_oversized_first_hook(build_event, explicit_sequence, explicit_event_id, dedup_key,
                                              fallback_recorded_at)
        with self._locked(create_root=True, sweep=False, deadline_ns=deadline_ns):
            _io.verify_streams_fence_if_present(self._root / _io._STREAMS_DIR, perms)
            sdir = self._root / _io._STREAMS_DIR / stream_key
            raw_cur = read_hook_cursor_readonly(sdir, perms)
            used, highest_order, _mp, max_frame_seq, stream_frames, sdir_ok = self._scan_outbox_with_stream(
                deadline_ns=deadline_ns, match_stream_key=stream_key, sweep=False, collect_stream_frames=True
            )
            if sdir_ok:
                sync_stream_metadata(sdir)  # before any replay, settle or fresh path acts on what was read
            cached, _bname, bucket_entries = (
                lookup_stream_binding_with_bucket(sdir, raw_cur, dedup_key, perms)
                if dedup_key is not None else (None, None, None)
            )
            if cached is None and explicit_sequence is not None:
                owner = slot_owner(sdir, explicit_sequence, perms)
                if owner is not None and owner.key != dedup_key:
                    raise BrainError(ErrorCode.IDEMPOTENCY_CONFLICT, "slot reserved by another notification")
            preview_cur, projected_bcount = compute_projected_hook_recovery(sdir, raw_cur, perms)
            if dedup_key is not None and cached is None and projected_bcount >= self._max_binding_keys:
                raise BrainError(ErrorCode.STORAGE_FULL, "hook dedup binding window full")
            seq, ev_id, rec_at = resolve_hook_envelope_slot(
                preview_cur, cached=cached, max_frame_seq=max_frame_seq, explicit_sequence=explicit_sequence,
                explicit_event_id=explicit_event_id, dedup_key=dedup_key, fallback_recorded_at=fallback_recorded_at,
            )
            record = build_event(seq, ev_id, rec_at)
            payload_digest, frame_bytes = _io.prepare_outbox_frame_bytes(record_kind=OUTBOX_RECORD_EVENT,
                producer_stream=record.producer_stream, sequence=record.sequence,
                entry_id=record.event_id, payload_dict=record.to_dict())
            if cached is not None and cached.payload_digest is not None and cached.payload_digest != payload_digest:
                raise BrainError(ErrorCode.IDEMPOTENCY_CONFLICT, "idempotency conflict")
            target_suffix = f"_{OUTBOX_RECORD_EVENT}_{record.sequence:020d}{_io._FRAME_SUFFIX}"
            matched_path = next((p for fname, p in stream_frames.items() if fname.endswith(target_suffix)), None)
            if matched_path is not None:
                existing = self._decode_frame_file(matched_path)
                if existing.entry_id != record.event_id or existing.payload_digest != payload_digest:
                    raise BrainError(ErrorCode.IDEMPOTENCY_CONFLICT, "idempotency conflict")
            if matched_path is not None or (cached is not None and preview_cur.is_event_acked(record.sequence)):
                settle_published_hook_frame(sdir, raw_cur, matched=matched_path is not None, dedup_key=dedup_key,
                    cached=cached, record=record, payload_digest=payload_digest, perms=perms, renamer=renamer,
                    check_deadline=dl_check)
                return record
            if used + len(frame_bytes) > self._max_bytes:
                raise BrainError(ErrorCode.STORAGE_FULL, "storage full")
            pending = (*raw_cur.legacy_recent, *((raw_cur.pending_binding,) if raw_cur.pending_binding else ()))
            projected = project_recovered_buckets(sdir, pending, perms)
            target = projected.get(bucket_name_for_key(dedup_key)) if dedup_key is not None else None
            prepared = prepare_hook_binding_upsert(
                sdir, dedup_key=dedup_key, record=record, payload_digest=payload_digest,
                perms=perms, preloaded_entries=target if target is not None else bucket_entries,
            )
            preflight_hook_cursor_size(sdir, preview_cur, sequence=record.sequence, prepared=prepared)
            if not sdir_ok:
                _io.ensure_dir_tree_atomic(self._root / _io._STREAMS_DIR, perms, renamer, check_deadline=dl_check)
                _io.ensure_dir_tree_atomic(sdir, perms, renamer, check_deadline=dl_check)
            cursor = recover_stream_cursor(sdir, raw_cur, perms, renamer=renamer, check_deadline=dl_check)
            new_count = cursor.binding_count + (1 if (prepared is not None and prepared[3]) else 0)
            pending_b = prepared[0] if (prepared is not None and prepared[2] is not None) else None
            bound_c = cursor.with_binding_state(
                next_seq=max(cursor.next_seq, record.sequence + 1), binding_count=new_count, pending_binding=pending_b
            )
            if bound_c != cursor:
                write_stream_cursor(sdir, bound_c, perms)
                cursor = bound_c
            if prepared is not None and prepared[2] is not None:
                write_prepared_binding_bucket(
                    sdir, prepared[1], prepared[2], perms, renamer=renamer, check_deadline=dl_check
                )
            base = f"{highest_order + 1:016d}_{OUTBOX_RECORD_EVENT}_{record.sequence:020d}"
            self._atomic_publish_frame(
                sdir / f"{base}{_io._FRAME_SUFFIX}", sdir / f"{base}{_io._PART_SUFFIX}", frame_bytes,
                crashpoint_name="capture.outbox.after_write_before_fsync", deadline_ns=deadline_ns,
            )
            pub_c = cursor.with_binding_state(pending_binding=None)
            if pub_c != cursor:
                try:
                    write_stream_cursor(sdir, pub_c, perms)
                except BrainError as err:  # frame is published; the next recovery clears a stale pending_binding
                    if err.code not in DEFERRABLE_AFTER_PUBLISH:
                        raise
            return record

    def enqueue_gap(self, gap: ProducerCaptureGap, *, deadline_ns: int | None = None) -> str:
        """Persist a ``ProducerCaptureGap`` durably under separated ``record_kind=capture_gap``."""
        if not isinstance(gap, ProducerCaptureGap):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        return self._enqueue_record(record_kind=OUTBOX_RECORD_GAP, producer_stream=gap.producer_stream,
            sequence=gap.sequence, entry_id=gap.gap_id, payload_dict=gap.to_dict(), deadline_ns=deadline_ns)

    def enqueue_fallback_gap(
        self, *, producer_stream: str, sequence: int | None, dedup_key: str | None, reason: str, recorded_at: str,
        duration_ms: int, deadline_ns: int | None = None,
    ) -> str | None:
        """Write the gap standing in for an event that may not have been published, under one spool lock. Its slot is
        ``sequence`` when known, else the binding of ``dedup_key``, else the next free slot. With a ``dedup_key`` the
        slot is reserved by a binding stamped with the gap identity before the gap is published, so a retry, a late
        event and a repeat after the gap ACK all land on that slot with that gap. Returns ``None`` without writing
        when the slot already holds a published or acknowledged event."""
        return _fallback.enqueue_fallback_gap(
            self, producer_stream=producer_stream, sequence=sequence, dedup_key=dedup_key, reason=reason,
            recorded_at=recorded_at, duration_ms=duration_ms, deadline_ns=deadline_ns,
        )

    def _refuse_oversized_first_hook(
        self, build_event: Callable[[int, str, str], CaptureEventRecord], explicit_sequence: int | None,
        explicit_event_id: str | None, dedup_key: str | None, fallback_recorded_at: str,
    ) -> None:
        # A spool that does not exist yet holds nothing: the first slot is fixed, so the frame size is exact.
        seq, ev_id, rec_at = resolve_hook_envelope_slot(
            StreamSeqCursor(1), cached=None, max_frame_seq=0, explicit_sequence=explicit_sequence,
            explicit_event_id=explicit_event_id, dedup_key=dedup_key, fallback_recorded_at=fallback_recorded_at,
        )
        record = build_event(seq, ev_id, rec_at)
        _digest, frame = _io.prepare_outbox_frame_bytes(record_kind=OUTBOX_RECORD_EVENT,
            producer_stream=record.producer_stream, sequence=record.sequence, entry_id=record.event_id,
            payload_dict=record.to_dict())
        if len(frame) > self._max_bytes:
            raise BrainError(ErrorCode.STORAGE_FULL, "storage full")  # refused before the spool is created

    def read_pending(
        self, limit: int = MAX_CAPTURE_BATCH_EVENTS, *, producer_stream: str | None = None
    ) -> list[OutboxEntry]:
        """Return up to ``limit`` pending entries in insertion order."""
        require_positive_int(limit)
        if limit > MAX_CAPTURE_BATCH_EVENTS:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        with self._locked(create_root=False):
            if not os.path.lexists(self._root):
                return []
            out: list[OutboxEntry] = []
            for path in self._iter_frame_paths(producer_stream=producer_stream):
                out.append(self._decode_frame_file(path))
                if len(out) >= limit:
                    break
            return out

    def apply_ack(self, ack: CaptureBatchAck, *, deadline_ns: int | None = None) -> int:
        """Evict only entries proven committed by ``ack`` for its ``producer_stream``; returns evicted count."""
        if not isinstance(ack, CaptureBatchAck):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if ack.policy_disabled:
            return 0
        dl_check = (lambda: self._check_deadline(deadline_ns)) if deadline_ns is not None else None
        with self._locked(create_root=False, deadline_ns=deadline_ns):
            if not os.path.lexists(self._root):
                return 0
            perms = self._resolve_permissions()
            sdir = self._root / _io._STREAMS_DIR / _io.stream_dir_key(ack.producer_stream)
            persist_cursor_ack(
                sdir, ack, perms, renamer=default_outbox_dir_renamer(), check_deadline=dl_check
            )
            evicted = 0
            for path in self._iter_frame_paths(producer_stream=ack.producer_stream, verify_cursor=False):
                self._check_deadline(deadline_ns)
                parsed = _io.parse_frame_filename_identity(path.name)
                if parsed is not None and not ack.allows_eviction(parsed[0], parsed[1]):
                    continue
                entry = self._decode_frame_file(path)
                if ack.allows_eviction(entry.record_kind, entry.sequence):
                    self._check_deadline(deadline_ns)
                    path.unlink(missing_ok=True)
                    evicted += 1
            if evicted and sdir.exists():
                _io.sync_dir(sdir)
            return evicted

    def total_bytes(self) -> int:
        """Current durable on-disk frame bytes held in the outbox."""
        with self._locked(create_root=False, sweep=False):
            if not os.path.lexists(self._root):
                return 0
            total, _order, _matched = self._scan_outbox()
            return total
