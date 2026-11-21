"""Crash-safe bounded file-backed local outbox spool (no sqlite3, no socket, no module-level faults import)."""

from __future__ import annotations

import json
import os
import stat
import time
import zlib
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

from superbrain.core._kernel_base import require_positive_int, require_sha256_digest
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.ports.capture import (
    DEFAULT_OUTBOX_MAX_BYTES,
    MAX_CAPTURE_BATCH_EVENTS,
    MAX_CAPTURE_ENTRY_BYTES,
    OUTBOX_RECORD_EVENT,
    OUTBOX_RECORD_GAP,
    CaptureBatchAck,
    CaptureEventRecord,
    OutboxEntry,
    OutboxFileLockPort,
    OutboxPermissionsPort,
    ProducerCaptureGap,
    default_outbox_file_lock,
    default_outbox_permissions,
)
from superbrain.storage._outbox_io import (
    _FRAME_SUFFIX,
    _LOCK_FILE,
    _O_BINARY,
    _O_NOFOLLOW,
    _PART_SUFFIX,
    _STREAMS_DIR,
    check_safe_path_syntax,
    is_link_path,
    maybe_crashpoint,
    parse_frame_order,
    raise_storage_error,
    read_all_binary,
    reject_links_upward,
    stream_dir_key,
    sync_dir,
    thread_lock_for,
    write_all_fd,
)


class OutboxSpool:
    """Owner-only, fsynced, bounded local capture outbox supporting crash recovery and separated EV/gap ACK."""

    def __init__(
        self,
        path: Path,
        *,
        max_bytes: int = DEFAULT_OUTBOX_MAX_BYTES,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
        permissions: OutboxPermissionsPort | None = None,
        file_lock: OutboxFileLockPort | None = None,
    ) -> None:
        check_safe_path_syntax(path)
        require_positive_int(max_bytes)
        reject_links_upward(path)
        self._root = path if path.is_absolute() else path.absolute()
        self._max_bytes = max_bytes
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

    def _verify_owner_only(self, target: Path, perms: OutboxPermissionsPort | None = None) -> None:
        guard = perms if perms is not None else self._resolve_permissions()
        obj_check = getattr(guard, "object_problems", None)
        probs = obj_check(target) if callable(obj_check) else guard.problems(target)
        if probs:
            raise BrainError(ErrorCode.INSECURE_PERMISSIONS, f"insecure permissions on {target}")

    def _verify_existing_root_readonly(self) -> None:
        if not os.path.lexists(self._root):
            return
        reject_links_upward(self._root)
        if is_link_path(self._root):
            raise BrainError(ErrorCode.UNSAFE_PATH, "outbox root is a link")
        if not stat.S_ISDIR(os.lstat(self._root).st_mode):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "outbox root is not a directory")
        self._verify_owner_only(self._root)
        for dirpath, dirnames, filenames in os.walk(self._root, followlinks=False):
            dp = Path(dirpath)
            if is_link_path(dp):
                raise BrainError(ErrorCode.UNSAFE_PATH, "symlink detected in outbox")
            for name in (*dirnames, *filenames):
                if is_link_path(dp / name):
                    raise BrainError(ErrorCode.UNSAFE_PATH, "symlink detected in outbox")

    def _ensure_dir_tree(self, directory: Path) -> None:
        perms = self._resolve_permissions()
        missing: list[Path] = []
        cur = directory
        while not os.path.lexists(cur):
            missing.append(cur)
            parent = cur.parent
            if parent == cur:
                raise BrainError(ErrorCode.IO_ERROR, f"no existing ancestor directory for {directory}")
            cur = parent
        reject_links_upward(cur)
        for item in reversed(missing) if missing else (directory,):
            created = False
            if missing:
                try:
                    item.mkdir(mode=0o700)
                    created = True
                except FileExistsError:
                    pass
                except OSError as err:
                    raise raise_storage_error(err, f"cannot create outbox directory {item}") from err
            else:
                reject_links_upward(item)
            if is_link_path(item):
                raise BrainError(ErrorCode.UNSAFE_PATH, "outbox directory must not be a link")
            try:
                st = os.lstat(item)
            except OSError as err:
                raise BrainError(ErrorCode.IO_ERROR, f"cannot inspect outbox directory {item}: {err}") from err
            if not stat.S_ISDIR(st.st_mode):
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"outbox path {item} is not a directory")
            if created:
                perms.secure_directory(item)
                sync_dir(item.parent)
            else:
                self._verify_owner_only(item, perms)

    def _sweep_links_and_parts(self) -> None:
        if not os.path.lexists(self._root):
            return
        to_unlink: list[Path] = []
        for dirpath, dirnames, filenames in os.walk(self._root, followlinks=False):
            dp = Path(dirpath)
            if is_link_path(dp):
                raise BrainError(ErrorCode.UNSAFE_PATH, "symlink detected in outbox")
            for dname in dirnames:
                if is_link_path(dp / dname):
                    raise BrainError(ErrorCode.UNSAFE_PATH, "symlink detected in outbox")
            for fname in filenames:
                fpath = dp / fname
                if is_link_path(fpath):
                    raise BrainError(ErrorCode.UNSAFE_PATH, "symlink detected in outbox")
                if fname.endswith(_PART_SUFFIX):
                    to_unlink.append(fpath)
        for p in to_unlink:
            p.unlink(missing_ok=True)

    @contextmanager
    def _locked(self, *, create_root: bool, deadline_ns: int | None = None) -> Iterator[None]:
        perms = self._resolve_permissions()
        adapter = self._resolve_file_lock()
        with self._thread_lock:
            if not os.path.lexists(self._root):
                if not create_root:
                    yield
                    return
                self._ensure_dir_tree(self._root)
            else:
                reject_links_upward(self._root)
                self._ensure_dir_tree(self._root)
            fd = self._open_lock_file(self._root / _LOCK_FILE, perms=perms)
            locked = False
            try:
                locked = self._acquire_file_lock(fd, adapter=adapter, deadline_ns=deadline_ns)
                self._sweep_links_and_parts()
                yield
            finally:
                try:
                    if locked:
                        adapter.unlock_fd(fd)
                finally:
                    os.close(fd)

    def _open_lock_file(self, lock_path: Path, *, perms: OutboxPermissionsPort) -> int:
        if is_link_path(lock_path):
            raise BrainError(ErrorCode.UNSAFE_PATH, "outbox lock file is a link")
        if os.path.lexists(lock_path):
            if not stat.S_ISREG(os.lstat(lock_path).st_mode):
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, "outbox lock file is not a regular file")
            self._verify_owner_only(lock_path, perms)
            return os.open(lock_path, os.O_RDWR | _O_BINARY | _O_NOFOLLOW)
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_RDWR | _O_BINARY | _O_NOFOLLOW, 0o600)
        except FileExistsError as err:
            if is_link_path(lock_path):
                raise BrainError(ErrorCode.UNSAFE_PATH, "outbox lock file is a link") from err
            self._verify_owner_only(lock_path, perms)
            return os.open(lock_path, os.O_RDWR | _O_BINARY | _O_NOFOLLOW)
        try:
            perms.secure_file(lock_path)
            self._verify_owner_only(lock_path, perms)
        except BaseException:
            os.close(fd)
            raise
        return fd

    def _acquire_file_lock(self, fd: int, *, adapter: OutboxFileLockPort, deadline_ns: int | None) -> bool:
        while True:
            if deadline_ns is not None and int(self._monotonic_ns()) >= deadline_ns:
                raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")
            try:
                if adapter.try_lock_fd(fd):
                    return True
            except OSError as err:
                raise raise_storage_error(err, "cannot lock outbox") from err
            time.sleep(0.002)

    def _collect_regular_frames(self, directory: Path) -> list[Path]:
        perms = self._resolve_permissions()
        if is_link_path(directory):
            raise BrainError(ErrorCode.UNSAFE_PATH, "stream directory is a link")
        if not stat.S_ISDIR(os.lstat(directory).st_mode):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "stream path is not a directory")
        self._verify_owner_only(directory, perms)
        found: list[Path] = []
        for p in directory.iterdir():
            if is_link_path(p):
                raise BrainError(ErrorCode.UNSAFE_PATH, "frame file is a link")
            if p.name.endswith(_FRAME_SUFFIX):
                if not stat.S_ISREG(os.lstat(p).st_mode):
                    raise BrainError(ErrorCode.INTEGRITY_FAILURE, "frame entry is not a regular file")
                found.append(p)
        return found

    def _iter_frame_paths(self, *, producer_stream: str | None = None) -> list[Path]:
        streams_root = self._root / _STREAMS_DIR
        if not os.path.lexists(streams_root):
            return []
        if is_link_path(streams_root):
            raise BrainError(ErrorCode.UNSAFE_PATH, "streams directory is a link")
        self._verify_owner_only(streams_root)
        if producer_stream is not None:
            sdir = streams_root / stream_dir_key(producer_stream)
            paths = self._collect_regular_frames(sdir) if os.path.lexists(sdir) else []
        else:
            paths = []
            for sdir in streams_root.iterdir():
                if is_link_path(sdir):
                    raise BrainError(ErrorCode.UNSAFE_PATH, "stream directory is a link")
                if stat.S_ISDIR(os.lstat(sdir).st_mode):
                    paths.extend(self._collect_regular_frames(sdir))
        paths.sort(key=parse_frame_order)
        return paths

    def _decode_frame_file(self, path: Path) -> OutboxEntry:
        if is_link_path(path):
            raise BrainError(ErrorCode.UNSAFE_PATH, "frame file is a link")
        if not stat.S_ISREG(os.lstat(path).st_mode):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt outbox frame type")
        self._verify_owner_only(path)
        raw = read_all_binary(path)
        nl_idx = raw.rfind(b"\n")
        if nl_idx == -1:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt outbox frame missing delimiter")
        committed_slice = raw[:nl_idx]
        has_tail = nl_idx < len(raw) - 1
        if committed_slice.find(b"\n") != -1:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt outbox frame framing")
        try:
            obj = json.loads(committed_slice.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as err:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt outbox frame") from err
        if not isinstance(obj, dict):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt outbox frame")
        record_kind, producer_stream = obj.get("record_kind"), obj.get("producer_stream")
        sequence, entry_id = obj.get("sequence"), obj.get("entry_id")
        payload_json, payload_digest = obj.get("payload_json"), obj.get("payload_digest")
        byte_size, frame_crc = obj.get("byte_size"), obj.get("frame_crc32")
        if (
            not isinstance(record_kind, str) or not isinstance(producer_stream, str)
            or type(sequence) is not int or not isinstance(entry_id, str)
            or not isinstance(payload_json, str) or not isinstance(payload_digest, str)
            or type(byte_size) is not int or not isinstance(frame_crc, str)
        ):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt outbox frame schema")
        require_sha256_digest(payload_digest)
        encoded_payload = payload_json.encode("utf-8")
        if len(encoded_payload) != byte_size or digest_bytes(encoded_payload) != payload_digest:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt outbox payload digest")
        core_canonical = canonical_json(
            {
                "byte_size": byte_size, "entry_id": entry_id, "payload_digest": payload_digest,
                "payload_json": payload_json, "producer_stream": producer_stream,
                "record_kind": record_kind, "sequence": sequence,
            }
        )
        if frame_crc != f"{zlib.crc32(core_canonical) & 0xFFFFFFFF:08x}":
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt outbox frame crc32")
        if has_tail:
            self._atomic_publish_frame(path, path.with_name(f"{path.name}{_PART_SUFFIX}"), raw[: nl_idx + 1])
        return OutboxEntry(
            record_kind=record_kind, producer_stream=producer_stream, sequence=sequence,
            entry_id=entry_id, payload_json=payload_json, payload_digest=payload_digest, byte_size=byte_size,
        )

    def _atomic_publish_frame(
        self,
        final_path: Path,
        part_path: Path,
        frame_bytes: bytes,
        *,
        crashpoint_name: str | None = None,
    ) -> None:
        perms = self._resolve_permissions()
        part_path.unlink(missing_ok=True)
        fd = -1
        committed = False
        try:
            fd = os.open(part_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_BINARY | _O_NOFOLLOW, 0o600)
            write_all_fd(fd, frame_bytes)
            os.close(fd)
            fd = -1
            perms.secure_file(part_path)
            if crashpoint_name is not None:
                maybe_crashpoint(crashpoint_name)
            fd = os.open(part_path, os.O_RDWR | _O_BINARY | _O_NOFOLLOW)
            os.fsync(fd)
            os.close(fd)
            fd = -1
            os.replace(part_path, final_path)
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

    def _find_existing_entry(
        self, producer_stream: str, record_kind: str, sequence: int
    ) -> tuple[Path, OutboxEntry] | None:
        for path in self._iter_frame_paths(producer_stream=producer_stream):
            entry = self._decode_frame_file(path)
            if entry.record_kind == record_kind and entry.sequence == sequence:
                return (path, entry)
        return None

    def _next_order_index(self) -> int:
        highest = 0
        for path in self._iter_frame_paths():
            order, _ = parse_frame_order(path)
            if order > highest:
                highest = order
        return highest + 1

    def _total_bytes_unlocked(self) -> int:
        total = 0
        for path in self._iter_frame_paths():
            self._decode_frame_file(path)
            total += path.stat().st_size
        return total

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
        payload_bytes = canonical_json(payload_dict)
        if len(payload_bytes) > MAX_CAPTURE_ENTRY_BYTES:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        payload_json = payload_bytes.decode("utf-8")
        payload_digest = digest_bytes(payload_bytes)
        byte_size = len(payload_bytes)
        core_fields: dict[str, JsonValue] = {
            "byte_size": byte_size, "entry_id": entry_id, "payload_digest": payload_digest,
            "payload_json": payload_json, "producer_stream": producer_stream,
            "record_kind": record_kind, "sequence": sequence,
        }
        core_fields["frame_crc32"] = f"{zlib.crc32(canonical_json(core_fields)) & 0xFFFFFFFF:08x}"
        frame_bytes = canonical_json(core_fields) + b"\n"

        with self._locked(create_root=True, deadline_ns=deadline_ns):
            if deadline_ns is not None and int(self._monotonic_ns()) >= deadline_ns:
                raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")
            existing = self._find_existing_entry(producer_stream, record_kind, sequence)
            if existing is not None:
                _epath, existing_entry = existing
                if existing_entry.entry_id == entry_id and existing_entry.payload_digest == payload_digest:
                    return existing_entry.entry_id
                raise BrainError(ErrorCode.IDEMPOTENCY_CONFLICT, "idempotency conflict")
            if self._total_bytes_unlocked() + len(frame_bytes) > self._max_bytes:
                raise BrainError(ErrorCode.STORAGE_FULL, "storage full")
            streams_root = self._root / _STREAMS_DIR
            self._ensure_dir_tree(streams_root)
            sdir = streams_root / stream_dir_key(producer_stream)
            self._ensure_dir_tree(sdir)
            base = f"{self._next_order_index():016d}_{record_kind}_{sequence:020d}"
            self._atomic_publish_frame(
                sdir / f"{base}{_FRAME_SUFFIX}",
                sdir / f"{base}{_PART_SUFFIX}",
                frame_bytes,
                crashpoint_name="capture.outbox.after_write_before_fsync",
            )
            return entry_id

    def enqueue_event(self, record: CaptureEventRecord, *, deadline_ns: int | None = None) -> str:
        """Persist a sanitized ``CaptureEventRecord`` durably; idempotent on matching key, conflict on mismatch."""
        if not isinstance(record, CaptureEventRecord):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        return self._enqueue_record(
            record_kind=OUTBOX_RECORD_EVENT, producer_stream=record.producer_stream,
            sequence=record.sequence, entry_id=record.event_id,
            payload_dict=record.to_dict(), deadline_ns=deadline_ns,
        )

    def enqueue_gap(self, gap: ProducerCaptureGap, *, deadline_ns: int | None = None) -> str:
        """Persist a ``ProducerCaptureGap`` durably under separated ``record_kind=capture_gap``."""
        if not isinstance(gap, ProducerCaptureGap):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        return self._enqueue_record(
            record_kind=OUTBOX_RECORD_GAP, producer_stream=gap.producer_stream,
            sequence=gap.sequence, entry_id=gap.gap_id,
            payload_dict=gap.to_dict(), deadline_ns=deadline_ns,
        )

    def read_pending(
        self,
        limit: int = MAX_CAPTURE_BATCH_EVENTS,
        *,
        producer_stream: str | None = None,
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
            evicted = 0
            for path in self._iter_frame_paths(producer_stream=ack.producer_stream):
                entry = self._decode_frame_file(path)
                if ack.allows_eviction(entry.record_kind, entry.sequence):
                    path.unlink(missing_ok=True)
                    evicted += 1
            if evicted:
                sdir = self._root / _STREAMS_DIR / stream_dir_key(ack.producer_stream)
                if sdir.exists():
                    sync_dir(sdir)
            return evicted

    def total_bytes(self) -> int:
        """Current durable on-disk frame bytes held in the outbox."""
        with self._locked(create_root=False):
            if not os.path.lexists(self._root):
                return 0
            return self._total_bytes_unlocked()
