"""Crash-safe bounded file-backed local outbox spool (no sqlite3, no socket, no module-level faults import)."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import stat
import sys
import threading
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
    OUTBOX_RECORD_EVENT,
    OUTBOX_RECORD_GAP,
    CaptureBatchAck,
    CaptureEventRecord,
    OutboxEntry,
    OutboxPermissionsPort,
    ProducerCaptureGap,
)

_REPARSE_POINT = 0x400
_PART_SUFFIX = ".part"
_FRAME_SUFFIX = ".frame"
_STREAMS_DIR = "streams"
_LOCK_FILE = ".spool.lock"
_PROCESS_LOCKS_GUARD = threading.Lock()
_PROCESS_LOCKS: dict[str, threading.RLock] = {}
_ENOSPC_WINERROR = 112


def _thread_lock_for(path: Path) -> threading.RLock:
    key = os.path.normcase(os.path.abspath(os.fspath(path)))
    with _PROCESS_LOCKS_GUARD:
        lock = _PROCESS_LOCKS.get(key)
        if lock is None:
            lock = threading.RLock()
            _PROCESS_LOCKS[key] = lock
        return lock


def _is_link_path(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        st = os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return False
    except OSError as err:
        raise BrainError(ErrorCode.UNSAFE_PATH, f"cannot inspect outbox path: {err}") from err
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & _REPARSE_POINT)


def _check_safe_path_syntax(path: Path) -> None:
    if not isinstance(path, Path):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    raw = os.fspath(path)
    if not raw or "\x00" in raw or ".." in path.parts:
        raise BrainError(ErrorCode.UNSAFE_PATH, "unsafe outbox path")
    if sys.platform == "win32":
        if raw.startswith(("\\\\", "//")):
            raise BrainError(ErrorCode.UNSAFE_PATH, "unsafe outbox path")
        drive_colon = 1 if len(raw) >= 2 and raw[0].isalpha() and raw[1] == ":" else -1
        if any(i != drive_colon for i, ch in enumerate(raw) if ch == ":"):
            raise BrainError(ErrorCode.UNSAFE_PATH, "unsafe outbox path")


def _reject_links_upward(path: Path) -> None:
    cur = path if path.is_absolute() else path.absolute()
    seen: set[Path] = set()
    while cur not in seen:
        seen.add(cur)
        if _is_link_path(cur):
            raise BrainError(ErrorCode.UNSAFE_PATH, "outbox path must not contain a symlink or reparse point")
        parent = cur.parent
        if parent == cur:
            break
        cur = parent


def _raise_storage_error(err: OSError, message: str) -> BrainError:
    winerr = getattr(err, "winerror", None)
    if err.errno in (errno.ENOSPC, errno.EDQUOT) or winerr == _ENOSPC_WINERROR:
        return BrainError(ErrorCode.STORAGE_FULL, "storage full")
    return BrainError(ErrorCode.IO_ERROR, f"{message}: {err}")


def _maybe_crashpoint(name: str) -> None:
    if os.environ.get("SUPERBRAIN_CRASHPOINT") or os.environ.get("SUPERBRAIN_PAUSEPOINT"):
        from superbrain.core.faults import crashpoint

        crashpoint(name)


def _stream_dir_key(producer_stream: str) -> str:
    return hashlib.sha256(producer_stream.encode("utf-8")).hexdigest()[:24]


def _parse_frame_order(path: Path) -> tuple[int, str]:
    stem = path.stem
    head, _, _rest = stem.partition("_")
    try:
        return (int(head), path.name)
    except ValueError:
        return (0, path.name)


class OutboxSpool:
    """Owner-only, fsynced, bounded local capture outbox supporting crash recovery and separated EV/gap ACK."""

    def __init__(
        self,
        path: Path,
        *,
        max_bytes: int = DEFAULT_OUTBOX_MAX_BYTES,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
        permissions: OutboxPermissionsPort | None = None,
    ) -> None:
        _check_safe_path_syntax(path)
        require_positive_int(max_bytes)
        _reject_links_upward(path)
        self._root = path if path.is_absolute() else path.absolute()
        self._max_bytes = max_bytes
        self._monotonic_ns = monotonic_ns
        self._permissions = permissions
        self._thread_lock = _thread_lock_for(self._root)
        self._ensure_layout_verified()

    @property
    def root(self) -> Path:
        return self._root

    def _secure_dir(self, directory: Path) -> None:
        if self._permissions is not None:
            self._permissions.secure_directory(directory)
        elif sys.platform != "win32":
            try:
                os.chmod(directory, 0o700)
            except OSError as err:
                raise BrainError(ErrorCode.INSECURE_PERMISSIONS, f"cannot secure directory {directory}: {err}") from err

    def _secure_file(self, file_path: Path) -> None:
        if self._permissions is not None:
            self._permissions.secure_file(file_path)
        elif sys.platform != "win32":
            try:
                os.chmod(file_path, 0o600)
            except OSError as err:
                raise BrainError(ErrorCode.INSECURE_PERMISSIONS, f"cannot secure file {file_path}: {err}") from err

    def _ensure_dir(self, directory: Path) -> None:
        _reject_links_upward(directory)
        created = False
        if not os.path.lexists(directory):
            try:
                directory.mkdir(parents=True, exist_ok=True)
                created = True
            except OSError as err:
                raise _raise_storage_error(err, f"cannot create outbox directory {directory}") from err
        if _is_link_path(directory):
            raise BrainError(ErrorCode.UNSAFE_PATH, "outbox directory must not be a link")
        try:
            st = os.lstat(directory)
        except OSError as err:
            raise BrainError(ErrorCode.IO_ERROR, f"cannot inspect outbox directory {directory}: {err}") from err
        if not stat.S_ISDIR(st.st_mode):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"outbox path {directory} is not a directory")
        self._secure_dir(directory)
        if created:
            self._sync_dir(directory.parent)

    @staticmethod
    def _sync_dir(directory: Path) -> None:
        if sys.platform == "win32":
            return
        try:
            fd = os.open(directory, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(fd)
        except OSError:
            pass
        finally:
            os.close(fd)

    def _ensure_layout_verified(self) -> None:
        if not os.path.lexists(self._root):
            return
        _reject_links_upward(self._root)
        if _is_link_path(self._root):
            raise BrainError(ErrorCode.UNSAFE_PATH, "outbox root is a link")
        st = os.lstat(self._root)
        if not stat.S_ISDIR(st.st_mode):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "outbox root is not a directory")
        self._secure_dir(self._root)
        self._sweep_links_and_parts()

    def _sweep_links_and_parts(self) -> None:
        if not os.path.lexists(self._root):
            return
        to_unlink: list[Path] = []
        for dirpath, dirnames, filenames in os.walk(self._root, followlinks=False):
            dp = Path(dirpath)
            if _is_link_path(dp):
                raise BrainError(ErrorCode.UNSAFE_PATH, "symlink detected in outbox")
            for dname in dirnames:
                dpath = dp / dname
                if _is_link_path(dpath):
                    raise BrainError(ErrorCode.UNSAFE_PATH, "symlink detected in outbox")
            for fname in filenames:
                fpath = dp / fname
                if _is_link_path(fpath):
                    raise BrainError(ErrorCode.UNSAFE_PATH, "symlink detected in outbox")
                if fname.endswith(_PART_SUFFIX):
                    to_unlink.append(fpath)
        for p in to_unlink:
            p.unlink(missing_ok=True)

    @contextmanager
    def _locked(self, *, create_root: bool, deadline_ns: int | None = None) -> Iterator[None]:
        with self._thread_lock:
            if not os.path.lexists(self._root):
                if not create_root:
                    yield
                    return
                self._ensure_dir(self._root)
            else:
                _reject_links_upward(self._root)
            lock_path = self._root / _LOCK_FILE
            if _is_link_path(lock_path):
                raise BrainError(ErrorCode.UNSAFE_PATH, "outbox lock file is a link")
            fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
            locked = False
            try:
                self._secure_file(lock_path)
                locked = self._acquire_file_lock(fd, deadline_ns=deadline_ns)
                self._sweep_links_and_parts()
                yield
            finally:
                try:
                    if locked:
                        self._release_file_lock(fd)
                finally:
                    os.close(fd)

    def _acquire_file_lock(self, fd: int, *, deadline_ns: int | None) -> bool:
        while True:
            if deadline_ns is not None and int(self._monotonic_ns()) >= deadline_ns:
                raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")
            try:
                if sys.platform == "win32":
                    import msvcrt

                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return True
            except OSError as err:
                if err.errno in (errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK, errno.EDEADLK):
                    time.sleep(0.002)
                    continue
                raise _raise_storage_error(err, "cannot lock outbox") from err

    @staticmethod
    def _release_file_lock(fd: int) -> None:
        try:
            if sys.platform == "win32":
                import msvcrt

                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass

    def _iter_frame_paths(self, *, producer_stream: str | None = None) -> list[Path]:
        streams_root = self._root / _STREAMS_DIR
        if not os.path.lexists(streams_root):
            return []
        if _is_link_path(streams_root):
            raise BrainError(ErrorCode.UNSAFE_PATH, "streams directory is a link")
        if producer_stream is not None:
            sdir = streams_root / _stream_dir_key(producer_stream)
            if not os.path.lexists(sdir):
                return []
            if _is_link_path(sdir):
                raise BrainError(ErrorCode.UNSAFE_PATH, "stream directory is a link")
            paths = [p for p in sdir.iterdir() if p.is_file() and p.name.endswith(_FRAME_SUFFIX)]
        else:
            paths = []
            for sdir in streams_root.iterdir():
                if _is_link_path(sdir):
                    raise BrainError(ErrorCode.UNSAFE_PATH, "stream directory is a link")
                if sdir.is_dir():
                    for p in sdir.iterdir():
                        if _is_link_path(p):
                            raise BrainError(ErrorCode.UNSAFE_PATH, "frame file is a link")
                        if p.is_file() and p.name.endswith(_FRAME_SUFFIX):
                            paths.append(p)
        paths.sort(key=_parse_frame_order)
        return paths

    def _decode_frame_file(self, path: Path) -> OutboxEntry | None:
        if _is_link_path(path):
            raise BrainError(ErrorCode.UNSAFE_PATH, "frame file is a link")
        try:
            raw = path.read_bytes()
        except OSError as err:
            raise BrainError(ErrorCode.IO_ERROR, f"cannot read frame {path}: {err}") from err
        nl_idx = raw.rfind(b"\n")
        if nl_idx == -1:
            # Whole file lacks a newline delimiter -> treat only as torn incomplete tail at EOF?
            # If the file starts like a complete JSON frame without newline or is pure junk, drop torn tail.
            path.unlink(missing_ok=True)
            return None
        committed_slice = raw[:nl_idx]
        has_tail = nl_idx < len(raw) - 1
        # Expect single canonical JSON line ending at last valid newline before EOF tail (or multiple?).
        first_nl = committed_slice.find(b"\n")
        if first_nl != -1:
            # Multiple newline-terminated lines inside a single-frame file -> corrupted framing.
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt outbox frame framing")
        try:
            obj = json.loads(committed_slice.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as err:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt outbox frame") from err
        if not isinstance(obj, dict):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt outbox frame")
        record_kind = obj.get("record_kind")
        producer_stream = obj.get("producer_stream")
        sequence = obj.get("sequence")
        entry_id = obj.get("entry_id")
        payload_json = obj.get("payload_json")
        payload_digest = obj.get("payload_digest")
        byte_size = obj.get("byte_size")
        frame_crc = obj.get("frame_crc32")
        if (
            not isinstance(record_kind, str)
            or not isinstance(producer_stream, str)
            or type(sequence) is not int
            or not isinstance(entry_id, str)
            or not isinstance(payload_json, str)
            or not isinstance(payload_digest, str)
            or type(byte_size) is not int
            or not isinstance(frame_crc, str)
        ):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt outbox frame schema")
        require_sha256_digest(payload_digest)
        encoded_payload = payload_json.encode("utf-8")
        if len(encoded_payload) != byte_size or digest_bytes(encoded_payload) != payload_digest:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt outbox payload digest")
        core_canonical = canonical_json(
            {
                "byte_size": byte_size,
                "entry_id": entry_id,
                "payload_digest": payload_digest,
                "payload_json": payload_json,
                "producer_stream": producer_stream,
                "record_kind": record_kind,
                "sequence": sequence,
            }
        )
        expected_crc = f"{zlib.crc32(core_canonical) & 0xFFFFFFFF:08x}"
        if frame_crc != expected_crc:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt outbox frame crc32")
        if has_tail:
            # Truncate away torn incomplete EOF bytes while keeping the durable committed frame.
            self._rewrite_clean_bytes(path, raw[: nl_idx + 1])
        return OutboxEntry(
            record_kind=record_kind,
            producer_stream=producer_stream,
            sequence=sequence,
            entry_id=entry_id,
            payload_json=payload_json,
            payload_digest=payload_digest,
            byte_size=byte_size,
        )

    def _rewrite_clean_bytes(self, path: Path, data: bytes) -> None:
        fd = os.open(path, os.O_WRONLY | os.O_TRUNC)
        try:
            os.write(fd, data)
            os.fsync(fd)
        except OSError as err:
            raise _raise_storage_error(err, "cannot repair outbox EOF tail") from err
        finally:
            os.close(fd)

    def _find_existing_entry(
        self, producer_stream: str, record_kind: str, sequence: int
    ) -> tuple[Path, OutboxEntry] | None:
        for path in self._iter_frame_paths(producer_stream=producer_stream):
            entry = self._decode_frame_file(path)
            if entry is not None and entry.record_kind == record_kind and entry.sequence == sequence:
                return (path, entry)
        return None

    def _next_order_index(self) -> int:
        highest = 0
        for path in self._iter_frame_paths():
            order, _ = _parse_frame_order(path)
            if order > highest:
                highest = order
        return highest + 1

    def _total_bytes_unlocked(self) -> int:
        total = 0
        for path in self._iter_frame_paths():
            entry = self._decode_frame_file(path)
            if entry is not None:
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
        payload_json = payload_bytes.decode("utf-8")
        payload_digest = digest_bytes(payload_bytes)
        byte_size = len(payload_bytes)
        core_fields: dict[str, JsonValue] = {
            "byte_size": byte_size,
            "entry_id": entry_id,
            "payload_digest": payload_digest,
            "payload_json": payload_json,
            "producer_stream": producer_stream,
            "record_kind": record_kind,
            "sequence": sequence,
        }
        crc_hex = f"{zlib.crc32(canonical_json(core_fields)) & 0xFFFFFFFF:08x}"
        core_fields["frame_crc32"] = crc_hex
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

            used = self._total_bytes_unlocked()
            if used + len(frame_bytes) > self._max_bytes:
                raise BrainError(ErrorCode.STORAGE_FULL, "storage full")

            streams_root = self._root / _STREAMS_DIR
            self._ensure_dir(streams_root)
            sdir = streams_root / _stream_dir_key(producer_stream)
            self._ensure_dir(sdir)

            order_idx = self._next_order_index()
            base = f"{order_idx:016d}_{record_kind}_{sequence:020d}"
            part_path = sdir / f"{base}{_PART_SUFFIX}"
            final_path = sdir / f"{base}{_FRAME_SUFFIX}"
            part_path.unlink(missing_ok=True)
            fd = os.open(part_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            committed = False
            try:
                view = memoryview(frame_bytes)
                written = 0
                while written < len(frame_bytes):
                    n = os.write(fd, view[written:])
                    if n <= 0:
                        raise BrainError(ErrorCode.IO_ERROR, "short write on outbox frame")
                    written += n
                os.close(fd)
                fd = -1
                self._secure_file(part_path)
                _maybe_crashpoint("capture.outbox.after_write_before_fsync")
                fd = os.open(part_path, os.O_RDWR)
                os.fsync(fd)
                os.close(fd)
                fd = -1
                os.replace(part_path, final_path)
                self._sync_dir(sdir)
                committed = True
            except BrainError:
                raise
            except OSError as err:
                raise _raise_storage_error(err, "cannot write outbox frame") from err
            finally:
                if fd != -1:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                if not committed:
                    part_path.unlink(missing_ok=True)
            return entry_id

    def enqueue_event(self, record: CaptureEventRecord, *, deadline_ns: int | None = None) -> str:
        """Persist a sanitized ``CaptureEventRecord`` durably; idempotent on matching key, conflict on mismatch."""
        if not isinstance(record, CaptureEventRecord):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        return self._enqueue_record(
            record_kind=OUTBOX_RECORD_EVENT,
            producer_stream=record.producer_stream,
            sequence=record.sequence,
            entry_id=record.event_id,
            payload_dict=record.to_dict(),
            deadline_ns=deadline_ns,
        )

    def enqueue_gap(self, gap: ProducerCaptureGap, *, deadline_ns: int | None = None) -> str:
        """Persist a ``ProducerCaptureGap`` durably under separated ``record_kind=capture_gap``."""
        if not isinstance(gap, ProducerCaptureGap):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        return self._enqueue_record(
            record_kind=OUTBOX_RECORD_GAP,
            producer_stream=gap.producer_stream,
            sequence=gap.sequence,
            entry_id=gap.gap_id,
            payload_dict=gap.to_dict(),
            deadline_ns=deadline_ns,
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
                entry = self._decode_frame_file(path)
                if entry is not None:
                    out.append(entry)
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
                if entry is not None and ack.allows_eviction(entry.record_kind, entry.sequence):
                    path.unlink(missing_ok=True)
                    evicted += 1
            if evicted:
                sdir = self._root / _STREAMS_DIR / _stream_dir_key(ack.producer_stream)
                if sdir.exists():
                    self._sync_dir(sdir)
            return evicted

    def total_bytes(self) -> int:
        """Current durable on-disk frame bytes held in the outbox."""
        with self._locked(create_root=False):
            if not os.path.lexists(self._root):
                return 0
            return self._total_bytes_unlocked()
