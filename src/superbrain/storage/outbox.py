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
from superbrain.storage._outbox_acks import _ACKS_DIR, _verify_acks_dir_node, verify_acks_dir
from superbrain.storage._outbox_bindings import (
    _BINDINGS_DIR,
    DEFAULT_MAX_STREAM_BINDING_KEYS,
    _verify_bindings_dir_node,
    verify_bindings_dir,
    write_prepared_binding_bucket,
)
from superbrain.storage._outbox_io import (
    _FRAME_SUFFIX,
    _LOCK_FILE,
    _O_BINARY,
    _O_NOFOLLOW,
    _PART_SUFFIX,
    _STREAMS_DIR,
    check_safe_path_syntax,
    ensure_dir_tree_atomic,
    ensure_secure_regular_file_atomic,
    entry_is_link,
    is_link_path,
    maybe_crashpoint,
    parse_frame_filename_identity,
    parse_frame_order,
    parse_verified_outbox_frame,
    raise_storage_error,
    read_all_binary,
    reject_links_upward,
    replace_file_resilient,
    stream_dir_key,
    sync_dir,
    thread_lock_for,
    verify_owner_only,
    write_all_fd,
)
from superbrain.storage._outbox_seq import (
    advance_cursor_next_seq,
    backfill_binding_digest_if_missing,
    load_or_recover_hook_cursor,
    lookup_stream_binding_with_bucket,
    persist_cursor_ack,
    prepare_hook_binding_upsert,
    prepare_outbox_frame_bytes,
    reconcile_matched_hook_frame_cursor,
    resolve_hook_envelope_slot,
)
from superbrain.storage._outbox_seq import write_stream_cursor as write_stream_cursor

_DEADLINE_CHECK_STRIDE = 64


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
        check_safe_path_syntax(path)
        require_positive_int(max_bytes)
        require_positive_int(max_binding_keys)
        reject_links_upward(path)
        self._root = path if path.is_absolute() else path.absolute()
        self._max_bytes = max_bytes
        self._max_binding_keys = max_binding_keys
        self._monotonic_ns = monotonic_ns
        self._permissions = permissions
        self._file_lock = file_lock
        self._resolve_permissions()
        self._resolve_file_lock()
        self._thread_lock = thread_lock_for(self._root)
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
        reject_links_upward(self._root)
        if is_link_path(self._root):
            raise BrainError(ErrorCode.UNSAFE_PATH, "outbox root is a link")
        if not stat.S_ISDIR(os.lstat(self._root).st_mode):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "outbox root is not a directory")
        verify_owner_only(self._root, self._resolve_permissions())

    @contextmanager
    def _locked(self, *, create_root: bool, sweep: bool = True, deadline_ns: int | None = None) -> Iterator[None]:
        perms = self._resolve_permissions()
        adapter = self._resolve_file_lock()
        renamer = default_outbox_dir_renamer()
        dl_check = (lambda: self._check_deadline(deadline_ns)) if deadline_ns is not None else None
        with self._thread_lock:
            self._check_deadline(deadline_ns)
            if not os.path.lexists(self._root):
                if not create_root:
                    yield
                    return
                ensure_dir_tree_atomic(self._root, perms, renamer, check_deadline=dl_check)
            else:
                reject_links_upward(self._root)
                ensure_dir_tree_atomic(self._root, perms, renamer, check_deadline=dl_check)
            lock_path = self._root / _LOCK_FILE
            ensure_secure_regular_file_atomic(lock_path, perms, check_deadline=dl_check)
            fd = os.open(lock_path, os.O_RDWR | _O_BINARY | _O_NOFOLLOW)
            locked = False
            try:
                locked = self._acquire_file_lock(fd, adapter=adapter, deadline_ns=deadline_ns)
                if sweep:
                    self._scan_outbox(deadline_ns=deadline_ns)
                yield
            finally:
                try:
                    if locked:
                        adapter.unlock_fd(fd)
                finally:
                    os.close(fd)

    def _acquire_file_lock(self, fd: int, *, adapter: OutboxFileLockPort, deadline_ns: int | None) -> bool:
        while True:
            self._check_deadline(deadline_ns)
            try:
                if adapter.try_lock_fd(fd):
                    return True
            except OSError as err:
                raise raise_storage_error(err, "cannot lock outbox") from err
            time.sleep(0.002)

    def _scan_stream_dir(
        self,
        sdir: Path,
        *,
        perms: OutboxPermissionsPort,
        deadline_ns: int | None,
        match_suffix: str | None,
        counter: list[int],
        sweep: bool = True,
        frames_out: dict[str, Path] | None = None,
    ) -> tuple[int, int, Path | None, int]:
        verify_owner_only(sdir, perms)
        self._check_deadline(deadline_ns)
        total_bytes = 0
        highest_order = 0
        max_frame_seq = 0
        matched_path: Path | None = None
        with os.scandir(sdir) as sit:
            for fe in sit:
                counter[0] += 1
                if (counter[0] & (_DEADLINE_CHECK_STRIDE - 1)) == 0:
                    self._check_deadline(deadline_ns)
                if entry_is_link(fe):
                    raise BrainError(ErrorCode.UNSAFE_PATH, "frame file is a link")
                name = fe.name
                if name == _BINDINGS_DIR:
                    verify_bindings_dir(sdir, perms) if sweep else _verify_bindings_dir_node(sdir, perms)
                    continue
                if name == _ACKS_DIR:
                    verify_acks_dir(sdir, perms) if sweep else _verify_acks_dir_node(sdir, perms)
                    continue
                if name.endswith(_PART_SUFFIX):
                    Path(fe.path).unlink(missing_ok=True)
                    continue
                if name.endswith(_FRAME_SUFFIX):
                    st = fe.stat(follow_symlinks=False)
                    if not stat.S_ISREG(st.st_mode):
                        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "frame entry is not a regular file")
                    total_bytes += st.st_size
                    order = parse_frame_order(Path(fe.path))[0]
                    if order > highest_order:
                        highest_order = order
                    if frames_out is not None:
                        frames_out[name] = Path(fe.path)
                        ident = parse_frame_filename_identity(name)
                        if ident is not None and ident[1] > max_frame_seq:
                            max_frame_seq = ident[1]
                    if match_suffix is not None and name.endswith(match_suffix):
                        matched_path = Path(fe.path)
        return total_bytes, highest_order, matched_path, max_frame_seq

    def _scan_outbox_with_stream(
        self,
        *,
        deadline_ns: int | None = None,
        match_stream_key: str | None = None,
        match_suffix: str | None = None,
        sweep: bool = True,
        collect_stream_frames: bool = False,
    ) -> tuple[int, int, Path | None, int, dict[str, Path], bool]:
        """Single-pass scandir: reject links, sweep .part files, sum bytes, optionally collect one stream."""
        stream_frames: dict[str, Path] = {}
        if not os.path.lexists(self._root):
            return 0, 0, None, 0, stream_frames, False
        perms = self._resolve_permissions()
        total_bytes, highest_order, max_stream_seq = 0, 0, 0
        matched_path: Path | None = None
        stream_verified = False
        counter = [0]
        streams_dir: Path | None = None

        with os.scandir(self._root) as root_it:
            for re_entry in root_it:
                counter[0] += 1
                if (counter[0] & (_DEADLINE_CHECK_STRIDE - 1)) == 0:
                    self._check_deadline(deadline_ns)
                if entry_is_link(re_entry):
                    raise BrainError(ErrorCode.UNSAFE_PATH, "symlink detected in outbox")
                rname = re_entry.name
                if rname.endswith(_PART_SUFFIX):
                    Path(re_entry.path).unlink(missing_ok=True)
                elif rname == _STREAMS_DIR:
                    st_r = re_entry.stat(follow_symlinks=False)
                    if not stat.S_ISDIR(st_r.st_mode):
                        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "streams entry is not a directory")
                    streams_dir = Path(re_entry.path)

        if streams_dir is None:
            return 0, 0, None, 0, stream_frames, False
        verify_owner_only(streams_dir, perms)
        self._check_deadline(deadline_ns)

        with os.scandir(streams_dir) as st_it:
            for sd_entry in st_it:
                self._check_deadline(deadline_ns)
                if entry_is_link(sd_entry):
                    raise BrainError(ErrorCode.UNSAFE_PATH, "stream directory is a link")
                if sd_entry.name.startswith(".") and ".init-" in sd_entry.name:
                    continue
                if not stat.S_ISDIR(sd_entry.stat(follow_symlinks=False).st_mode):
                    raise BrainError(ErrorCode.INTEGRITY_FAILURE, "stream entry is not a directory")
                sd_path = Path(sd_entry.path)
                is_target = match_stream_key is not None and sd_entry.name == match_stream_key
                want_suffix = match_suffix if is_target else None
                want_frames = stream_frames if (collect_stream_frames and is_target) else None
                if is_target:
                    stream_verified = True
                sb, so, mp, s_max_seq = self._scan_stream_dir(
                    sd_path, perms=perms, deadline_ns=deadline_ns, match_suffix=want_suffix,
                    counter=counter, sweep=sweep, frames_out=want_frames,
                )
                total_bytes += sb
                if so > highest_order:
                    highest_order = so
                if s_max_seq > max_stream_seq:
                    max_stream_seq = s_max_seq
                if mp is not None:
                    matched_path = mp
        self._check_deadline(deadline_ns)
        return total_bytes, highest_order, matched_path, max_stream_seq, stream_frames, stream_verified

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
        perms = self._resolve_permissions()
        if is_link_path(directory):
            raise BrainError(ErrorCode.UNSAFE_PATH, "stream directory is a link")
        if not stat.S_ISDIR(os.lstat(directory).st_mode):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "stream path is not a directory")
        verify_owner_only(directory, perms)
        found: list[Path] = []
        with os.scandir(directory) as it:
            for entry in it:
                if entry_is_link(entry):
                    raise BrainError(ErrorCode.UNSAFE_PATH, "frame file is a link")
                if entry.name.endswith(_FRAME_SUFFIX):
                    if not stat.S_ISREG(entry.stat(follow_symlinks=False).st_mode):
                        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "frame entry is not a regular file")
                    found.append(Path(entry.path))
        return found

    def _iter_frame_paths(self, *, producer_stream: str | None = None) -> list[Path]:
        streams_root = self._root / _STREAMS_DIR
        if not os.path.lexists(streams_root):
            return []
        if is_link_path(streams_root):
            raise BrainError(ErrorCode.UNSAFE_PATH, "streams directory is a link")
        verify_owner_only(streams_root, self._resolve_permissions())
        if producer_stream is not None:
            sdir = streams_root / stream_dir_key(producer_stream)
            paths = self._collect_regular_frames(sdir) if os.path.lexists(sdir) else []
        else:
            paths = []
            with os.scandir(streams_root) as it:
                for sd_entry in it:
                    if entry_is_link(sd_entry):
                        raise BrainError(ErrorCode.UNSAFE_PATH, "stream directory is a link")
                    if stat.S_ISDIR(sd_entry.stat(follow_symlinks=False).st_mode):
                        paths.extend(self._collect_regular_frames(Path(sd_entry.path)))
        paths.sort(key=parse_frame_order)
        return paths

    def _decode_frame_file(self, path: Path) -> OutboxEntry:
        if is_link_path(path):
            raise BrainError(ErrorCode.UNSAFE_PATH, "frame file is a link")
        if not stat.S_ISREG(os.lstat(path).st_mode):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt outbox frame type")
        verify_owner_only(path, self._resolve_permissions())
        raw = read_all_binary(path)
        entry, nl_idx = parse_verified_outbox_frame(raw)
        if nl_idx < len(raw) - 1:
            self._atomic_publish_frame(path, path.with_name(f"{path.name}{_PART_SUFFIX}"), raw[: nl_idx + 1])
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
        perms = self._resolve_permissions()
        self._check_deadline(deadline_ns)
        part_path.unlink(missing_ok=True)
        fd = -1
        committed = False
        try:
            fd = os.open(part_path, os.O_RDWR | os.O_CREAT | os.O_EXCL | _O_BINARY | _O_NOFOLLOW, 0o600)
            write_all_fd(fd, frame_bytes)
            perms.secure_file(part_path)
            self._check_deadline(deadline_ns)
            if crashpoint_name is not None:
                maybe_crashpoint(crashpoint_name)
            os.fsync(fd)
            os.close(fd)
            fd = -1
            replace_file_resilient(part_path, final_path)
            sync_dir(final_path.parent)
            committed = True
        except BrainError:
            raise
        except OSError as err:
            raise raise_storage_error(err, "cannot write outbox frame") from err
        finally:
            if fd != -1:
                try:
                    os.close(fd)
                except OSError:
                    pass
            if not committed:
                part_path.unlink(missing_ok=True)

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
        payload_digest, frame_bytes = prepare_outbox_frame_bytes(
            record_kind=record_kind, producer_stream=producer_stream, sequence=sequence,
            entry_id=entry_id, payload_dict=payload_dict,
        )
        stream_key = stream_dir_key(producer_stream)
        target_suffix = f"_{record_kind}_{sequence:020d}{_FRAME_SUFFIX}"
        dl_check = (lambda: self._check_deadline(deadline_ns)) if deadline_ns is not None else None
        perms = self._resolve_permissions()
        renamer = default_outbox_dir_renamer()
        with self._locked(create_root=True, sweep=False, deadline_ns=deadline_ns):
            used, highest_order, matched_path = self._scan_outbox(
                deadline_ns=deadline_ns, match_stream_key=stream_key, match_suffix=target_suffix, sweep=False
            )
            if matched_path is not None:
                existing_entry = self._decode_frame_file(matched_path)
                if existing_entry.entry_id == entry_id and existing_entry.payload_digest == payload_digest:
                    return existing_entry.entry_id
                raise BrainError(ErrorCode.IDEMPOTENCY_CONFLICT, "idempotency conflict")
            if used + len(frame_bytes) > self._max_bytes:
                raise BrainError(ErrorCode.STORAGE_FULL, "storage full")
            streams_root = self._root / _STREAMS_DIR
            ensure_dir_tree_atomic(streams_root, perms, renamer, check_deadline=dl_check)
            sdir = streams_root / stream_key
            ensure_dir_tree_atomic(sdir, perms, renamer, check_deadline=dl_check)
            base = f"{highest_order + 1:016d}_{record_kind}_{sequence:020d}"
            self._atomic_publish_frame(
                sdir / f"{base}{_FRAME_SUFFIX}", sdir / f"{base}{_PART_SUFFIX}", frame_bytes,
                crashpoint_name="capture.outbox.after_write_before_fsync", deadline_ns=deadline_ns,
            )
            advance_cursor_next_seq(sdir, sequence, perms, renamer=renamer)
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
        stream_key = stream_dir_key(producer_stream)
        perms = self._resolve_permissions()
        renamer = default_outbox_dir_renamer()
        dl_check = (lambda: self._check_deadline(deadline_ns)) if deadline_ns is not None else None
        with self._locked(create_root=True, sweep=False, deadline_ns=deadline_ns):
            sdir = self._root / _STREAMS_DIR / stream_key
            cursor = load_or_recover_hook_cursor(sdir, perms, renamer=renamer, check_deadline=dl_check)
            used, highest_order, _mp, max_frame_seq, stream_frames, sdir_ok = self._scan_outbox_with_stream(
                deadline_ns=deadline_ns, match_stream_key=stream_key, sweep=False, collect_stream_frames=True
            )
            cached, _bname, bucket_entries = (
                lookup_stream_binding_with_bucket(sdir, cursor, dedup_key, perms)
                if dedup_key is not None
                else (None, None, None)
            )
            if dedup_key is not None and cached is None and cursor.binding_count >= self._max_binding_keys:
                raise BrainError(ErrorCode.STORAGE_FULL, "hook dedup binding window full")
            seq, ev_id, rec_at = resolve_hook_envelope_slot(
                cursor, cached=cached, max_frame_seq=max_frame_seq, explicit_sequence=explicit_sequence,
                explicit_event_id=explicit_event_id, dedup_key=dedup_key, fallback_recorded_at=fallback_recorded_at,
            )
            record = build_event(seq, ev_id, rec_at)
            payload_digest, frame_bytes = prepare_outbox_frame_bytes(record_kind=OUTBOX_RECORD_EVENT,
                producer_stream=record.producer_stream, sequence=record.sequence,
                entry_id=record.event_id, payload_dict=record.to_dict())
            if cached is not None and cached.payload_digest is not None and cached.payload_digest != payload_digest:
                raise BrainError(ErrorCode.IDEMPOTENCY_CONFLICT, "idempotency conflict")
            target_suffix = f"_{OUTBOX_RECORD_EVENT}_{record.sequence:020d}{_FRAME_SUFFIX}"
            matched_path = next((p for fname, p in stream_frames.items() if fname.endswith(target_suffix)), None)
            if matched_path is not None:
                existing = self._decode_frame_file(matched_path)
                if existing.entry_id != record.event_id or existing.payload_digest != payload_digest:
                    raise BrainError(ErrorCode.IDEMPOTENCY_CONFLICT, "idempotency conflict")
                reconcile_matched_hook_frame_cursor(sdir, cursor, dedup_key=dedup_key, cached=cached, record=record,
                    payload_digest=payload_digest, perms=perms, renamer=renamer, check_deadline=dl_check)
                return record
            if cached is not None and cursor.is_event_acked(record.sequence):
                backfill_binding_digest_if_missing(sdir, cached, payload_digest, perms,
                    renamer=renamer, check_deadline=dl_check)
                return record
            if used + len(frame_bytes) > self._max_bytes:
                raise BrainError(ErrorCode.STORAGE_FULL, "storage full")
            prepared = prepare_hook_binding_upsert(
                sdir, dedup_key=dedup_key, record=record, payload_digest=payload_digest,
                perms=perms, preloaded_entries=bucket_entries,
            )
            if not sdir_ok:
                ensure_dir_tree_atomic(self._root / _STREAMS_DIR, perms, renamer, check_deadline=dl_check)
                ensure_dir_tree_atomic(sdir, perms, renamer, check_deadline=dl_check)
            new_count = cursor.binding_count + (1 if (prepared is not None and prepared[3]) else 0)
            pending_b = prepared[0] if (prepared is not None and prepared[2] is not None) else None
            next_seq = max(cursor.next_seq, record.sequence + 1)
            bound_c = cursor.with_binding_state(next_seq=next_seq, binding_count=new_count, pending_binding=pending_b)
            if bound_c != cursor:
                write_stream_cursor(sdir, bound_c, perms)
                cursor = bound_c
            if prepared is not None and prepared[2] is not None:
                write_prepared_binding_bucket(
                    sdir, prepared[1], prepared[2], perms, renamer=renamer, check_deadline=dl_check
                )
            base = f"{highest_order + 1:016d}_{OUTBOX_RECORD_EVENT}_{record.sequence:020d}"
            self._atomic_publish_frame(
                sdir / f"{base}{_FRAME_SUFFIX}", sdir / f"{base}{_PART_SUFFIX}", frame_bytes,
                crashpoint_name="capture.outbox.after_write_before_fsync", deadline_ns=deadline_ns,
            )
            pub_c = cursor.with_binding_state(pending_binding=None)
            if pub_c != cursor:
                write_stream_cursor(sdir, pub_c, perms)
            return record

    def enqueue_gap(self, gap: ProducerCaptureGap, *, deadline_ns: int | None = None) -> str:
        """Persist a ``ProducerCaptureGap`` durably under separated ``record_kind=capture_gap``."""
        if not isinstance(gap, ProducerCaptureGap):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        return self._enqueue_record(record_kind=OUTBOX_RECORD_GAP, producer_stream=gap.producer_stream,
            sequence=gap.sequence, entry_id=gap.gap_id, payload_dict=gap.to_dict(), deadline_ns=deadline_ns)

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

    def apply_ack(self, ack: CaptureBatchAck) -> int:
        """Evict only entries proven committed by ``ack`` for its ``producer_stream``; returns evicted count."""
        if not isinstance(ack, CaptureBatchAck):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if ack.policy_disabled:
            return 0
        with self._locked(create_root=False):
            if not os.path.lexists(self._root):
                return 0
            perms = self._resolve_permissions()
            sdir = self._root / _STREAMS_DIR / stream_dir_key(ack.producer_stream)
            persist_cursor_ack(sdir, ack, perms, renamer=default_outbox_dir_renamer())
            evicted = 0
            for path in self._iter_frame_paths(producer_stream=ack.producer_stream):
                parsed = parse_frame_filename_identity(path.name)
                if parsed is not None and not ack.allows_eviction(parsed[0], parsed[1]):
                    continue
                entry = self._decode_frame_file(path)
                if ack.allows_eviction(entry.record_kind, entry.sequence):
                    path.unlink(missing_ok=True)
                    evicted += 1
            if evicted and sdir.exists():
                sync_dir(sdir)
            return evicted

    def total_bytes(self) -> int:
        """Current durable on-disk frame bytes held in the outbox."""
        with self._locked(create_root=False, sweep=False):
            if not os.path.lexists(self._root):
                return 0
            total, _order, _matched = self._scan_outbox()
            return total
