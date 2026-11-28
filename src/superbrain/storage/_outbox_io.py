"""Low-level binary, safe-path, fsync, atomic-cold-create, and fast scandir helpers for ``storage.outbox``."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import shutil
import stat
import threading
import uuid
import zlib
from collections.abc import Callable
from pathlib import Path

from superbrain.core._kernel_base import require_sha256_digest
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.ports.capture import (
    MAX_CAPTURE_ENTRY_BYTES,
    OutboxDirRenamer,
    OutboxEntry,
    OutboxPermissionsPort,
)
from superbrain.storage._outbox_durable import (
    _ACTIVE_DEADLINE_CHECK as _ACTIVE_DEADLINE_CHECK,
)
from superbrain.storage._outbox_durable import active_deadline_check as active_deadline_check
from superbrain.storage._outbox_durable import push_deadline_check as push_deadline_check
from superbrain.storage._outbox_durable import push_deadline_remaining as push_deadline_remaining
from superbrain.storage._outbox_durable import raise_storage_error as raise_storage_error
from superbrain.storage._outbox_durable import replace_file_resilient as replace_file_resilient
from superbrain.storage._outbox_durable import reset_deadline_check as reset_deadline_check
from superbrain.storage._outbox_durable import reset_deadline_remaining as reset_deadline_remaining
from superbrain.storage._outbox_durable import staging_cleanup_allowed as staging_cleanup_allowed
from superbrain.storage._outbox_durable import sync_dir as sync_dir
from superbrain.storage._outbox_durable import sync_existing_dirs as sync_existing_dirs
from superbrain.storage._outbox_durable import unlink_before_deadline as unlink_before_deadline
from superbrain.storage._outbox_durable import wait_within_budget as wait_within_budget

_REPARSE_POINT = 0x400
_PART_SUFFIX = ".part"
_FRAME_SUFFIX = ".frame"
_STREAMS_DIR = "streams"
_V4_FENCE_FILE = ".v4_fence"
_LOCK_FILE = ".spool.lock"
# Creation stages made by the spool carry this marker; a sweep removes only these (``.init-`` is any other writer's).
_SPOOL_STAGE_MARKER = ".sbstage-"
FOREIGN_STAGE_MARKER = ".init-"
_PROCESS_LOCKS_GUARD = threading.Lock()
_PROCESS_LOCKS: dict[str, threading.RLock] = {}
_O_BINARY = getattr(os, "O_BINARY", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_ORIG_PATH_IS_SYMLINK = Path.is_symlink


def thread_lock_for(path: Path) -> threading.RLock:
    key = os.path.normcase(os.path.abspath(os.fspath(path)))
    with _PROCESS_LOCKS_GUARD:
        lock = _PROCESS_LOCKS.get(key)
        if lock is None:
            lock = threading.RLock()
            _PROCESS_LOCKS[key] = lock
        return lock


def is_link_path(path: Path) -> bool:
    try:
        if Path.is_symlink is not _ORIG_PATH_IS_SYMLINK and path.is_symlink():
            return True
        st = os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return False
    except OSError as err:
        raise BrainError(ErrorCode.UNSAFE_PATH, f"cannot inspect outbox path: {err}") from err
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & _REPARSE_POINT)


def entry_is_link(entry: os.DirEntry[str]) -> bool:
    try:
        if entry.is_symlink():
            return True
        st = entry.stat(follow_symlinks=False)
    except (FileNotFoundError, NotADirectoryError):
        return False
    except OSError as err:
        raise BrainError(ErrorCode.UNSAFE_PATH, f"cannot inspect outbox path: {err}") from err
    if getattr(st, "st_file_attributes", 0) & _REPARSE_POINT:
        return True
    if Path.is_symlink is not _ORIG_PATH_IS_SYMLINK:
        return Path(entry.path).is_symlink()
    return False


def check_safe_path_syntax(path: Path) -> None:
    if not isinstance(path, Path):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    raw = os.fspath(path)
    if not raw or "\x00" in raw or ".." in path.parts:
        raise BrainError(ErrorCode.UNSAFE_PATH, "unsafe outbox path")
    if raw.startswith(("\\\\", "//")):
        raise BrainError(ErrorCode.UNSAFE_PATH, "unsafe outbox path")
    drive_colon = 1 if len(raw) >= 2 and raw[0].isalpha() and raw[1] == ":" else -1
    if any(i != drive_colon for i, ch in enumerate(raw) if ch == ":"):
        raise BrainError(ErrorCode.UNSAFE_PATH, "unsafe outbox path")


def reject_links_upward(path: Path) -> None:
    cur = path if path.is_absolute() else path.absolute()
    seen: set[Path] = set()
    while cur not in seen:
        seen.add(cur)
        if is_link_path(cur):
            raise BrainError(ErrorCode.UNSAFE_PATH, "outbox path must not contain a symlink or reparse point")
        parent = cur.parent
        if parent == cur:
            break
        cur = parent


def maybe_crashpoint(name: str) -> None:
    if os.environ.get("SUPERBRAIN_CRASHPOINT") or os.environ.get("SUPERBRAIN_PAUSEPOINT"):
        from superbrain.core.faults import crashpoint

        crashpoint(name)


def stream_dir_key(producer_stream: str) -> str:
    return hashlib.sha256(producer_stream.encode("utf-8")).hexdigest()[:24]


def parse_frame_order(path: Path) -> tuple[int, str]:
    head, _, _rest = path.stem.partition("_")
    try:
        return (int(head), path.name)
    except ValueError:
        return (0, path.name)


def parse_frame_filename_identity(name: str) -> tuple[str, int] | None:
    if not name.endswith(_FRAME_SUFFIX):
        return None
    stem = name[: -len(_FRAME_SUFFIX)]
    parts = stem.split("_")
    if len(parts) < 3:
        return None
    seq_part = parts[-1]
    kind_part = "_".join(parts[1:-1])
    try:
        seq = int(seq_part)
    except ValueError:
        return None
    if seq <= 0 or not kind_part:
        return None
    return (kind_part, seq)








def write_all_fd(fd: int, data: bytes) -> None:
    view = memoryview(data)
    written = 0
    while written < len(data):
        n = os.write(fd, view[written:])
        if n <= 0:
            raise BrainError(ErrorCode.IO_ERROR, "short write on outbox frame")
        written += n


def read_all_binary(path: Path) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | _O_BINARY | _O_NOFOLLOW)
    except OSError as err:
        raise raise_storage_error(err, f"cannot open frame {path}") from err
    chunks: list[bytes] = []
    try:
        while True:
            chunk = os.read(fd, 65_536)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    except OSError as err:
        raise raise_storage_error(err, f"cannot read frame {path}") from err
    finally:
        os.close(fd)


def verify_owner_only(target: Path, perms: OutboxPermissionsPort) -> None:
    obj_check = getattr(perms, "object_problems", None)
    probs = obj_check(target) if callable(obj_check) else perms.problems(target)
    if probs:
        raise BrainError(ErrorCode.INSECURE_PERMISSIONS, f"insecure permissions on {target}")


def _fallback_rename_dir(src: Path, dst: Path) -> None:
    if os.path.lexists(dst):
        raise FileExistsError(errno.EEXIST, "target directory exists", str(dst))
    os.rename(src, dst)


def atomic_create_dir(
    target: Path,
    perms: OutboxPermissionsPort,
    rename_dir_fn: OutboxDirRenamer | None,
    *,
    check_deadline: Callable[[], None] | None = None,
    stage_marker: str = _SPOOL_STAGE_MARKER,
) -> bool:
    """Create ``target`` via hardened staging dir + non-replacing rename; return ``True`` if created."""
    created = False
    if not os.path.lexists(target):
        stage = target.parent / f".{target.name}{stage_marker}{os.getpid()}-{threading.get_ident()}-{uuid.uuid4().hex}"
        try:
            stage.mkdir(mode=0o700)
            perms.secure_directory(stage)
            if check_deadline is not None:
                check_deadline()
            renamer = rename_dir_fn if rename_dir_fn is not None else _fallback_rename_dir
            try:
                renamer(stage, target)
                created = True
            except FileExistsError:
                pass
        except OSError as err:
            raise raise_storage_error(err, f"cannot create directory {target}") from err
        finally:
            if stage.exists() and staging_cleanup_allowed(check_deadline):
                shutil.rmtree(stage, ignore_errors=True)
    if is_link_path(target):
        raise BrainError(ErrorCode.UNSAFE_PATH, "directory must not be a link")
    try:
        st = os.lstat(target)
    except OSError as err:
        raise BrainError(ErrorCode.IO_ERROR, f"cannot inspect directory {target}: {err}") from err
    if not stat.S_ISDIR(st.st_mode):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"path {target} is not a directory")
    if not created:
        verify_owner_only(target, perms)
    if check_deadline is not None:
        check_deadline()
    return created


def ensure_dir_tree_atomic(
    directory: Path,
    perms: OutboxPermissionsPort,
    rename_dir_fn: OutboxDirRenamer | None,
    *,
    check_deadline: Callable[[], None] | None = None,
    verify_existing: bool = True,
    stage_marker: str = _SPOOL_STAGE_MARKER,
) -> None:
    missing: list[Path] = []
    cur = directory
    while not os.path.lexists(cur):
        missing.append(cur)
        parent = cur.parent
        if parent == cur:
            raise BrainError(ErrorCode.IO_ERROR, f"no existing ancestor directory for {directory}")
        cur = parent
    reject_links_upward(cur)
    if not missing:
        if verify_existing:
            atomic_create_dir(directory, perms, rename_dir_fn, check_deadline=check_deadline, stage_marker=stage_marker)
            return
        if is_link_path(directory) or not stat.S_ISDIR(os.lstat(directory).st_mode):
            raise BrainError(ErrorCode.UNSAFE_PATH, "log parent directory is not a valid directory")
        return
    for item in reversed(missing):
        atomic_create_dir(item, perms, rename_dir_fn, check_deadline=check_deadline, stage_marker=stage_marker)


def ensure_secure_regular_file_atomic(
    target: Path,
    perms: OutboxPermissionsPort,
    *,
    check_deadline: Callable[[], None] | None = None,
    stage_marker: str = _SPOOL_STAGE_MARKER,
) -> None:
    """Create missing ``target`` with owner-only ACLs prior to publishing, or verify existing owner-only file. A
    stage removed by a concurrent sweep is accepted when ``target`` exists by then."""
    if is_link_path(target):
        raise BrainError(ErrorCode.UNSAFE_PATH, f"file is a link: {target}")
    if not os.path.lexists(target):
        stage = target.with_name(
            f".{target.name}{stage_marker}{os.getpid()}-{threading.get_ident()}-{uuid.uuid4().hex}")
        fd_s = -1
        try:
            fd_s = os.open(stage, os.O_CREAT | os.O_EXCL | os.O_RDWR | _O_BINARY | _O_NOFOLLOW, 0o600)
            os.close(fd_s)
            fd_s = -1
            perms.secure_file(stage)
            if check_deadline is not None:
                check_deadline()
            try:
                os.link(stage, target)
            except FileExistsError:
                pass
        except FileNotFoundError as err:
            if not os.path.lexists(target):
                raise raise_storage_error(err, f"cannot create file {target}") from err
        except OSError as err:
            raise raise_storage_error(err, f"cannot create file {target}") from err
        finally:
            if fd_s != -1:
                try:
                    os.close(fd_s)
                except OSError:
                    pass
            if staging_cleanup_allowed(check_deadline):
                stage.unlink(missing_ok=True)
    if is_link_path(target):
        raise BrainError(ErrorCode.UNSAFE_PATH, f"file is a link: {target}")
    try:
        st = os.lstat(target)
    except OSError as err:
        raise BrainError(ErrorCode.IO_ERROR, f"cannot inspect file {target}: {err}") from err
    if not stat.S_ISREG(st.st_mode):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"path {target} is not a regular file")
    verify_owner_only(target, perms)
    if check_deadline is not None:
        check_deadline()


def parse_verified_outbox_frame(raw: bytes) -> tuple[OutboxEntry, int]:
    """Decode and CRC32/digest-verify committed outbox frame bytes; return ``(entry, nl_idx)``."""
    nl_idx = raw.rfind(b"\n")
    if nl_idx == -1:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt outbox frame missing delimiter")
    committed_slice = raw[:nl_idx]
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
    entry = OutboxEntry(
        record_kind=record_kind, producer_stream=producer_stream, sequence=sequence,
        entry_id=entry_id, payload_json=payload_json, payload_digest=payload_digest, byte_size=byte_size,
    )
    return entry, nl_idx


def verify_v4_fence_file(path: Path, perms: OutboxPermissionsPort) -> None:
    """Validate ``streams/.v4_fence`` is a link-free regular owner-only file at supported version <= 4."""
    if is_link_path(path):
        raise BrainError(ErrorCode.UNSAFE_PATH, "streams version fence is a link")
    if not stat.S_ISREG(os.lstat(path).st_mode):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "streams version fence is not a regular file")
    verify_owner_only(path, perms)
    fd = os.open(path, os.O_RDONLY | _O_BINARY | _O_NOFOLLOW)
    try:
        raw = os.read(fd, 257)
    finally:
        os.close(fd)
    if len(raw) > 256:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt streams version fence")
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as err:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt streams version fence") from err
    if (
        not isinstance(obj, dict)
        or set(obj.keys()) != {"schema_version"}
        or type(obj.get("schema_version")) is not int
        or obj["schema_version"] != 4
    ):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "unsupported streams version fence")


def is_v4_fence_part_name(name: str) -> bool:
    """Return ``True`` for an interrupted staging file of ``streams/.v4_fence``."""
    return name.startswith(f"{_V4_FENCE_FILE}-") and name.endswith(_PART_SUFFIX)


def verify_streams_fence_if_present(streams_dir: Path, perms: OutboxPermissionsPort, *, sweep: bool = False) -> None:
    """Reject links or unsupported future version fences on ``streams``; remove fence staging only on a sweep."""
    if not os.path.lexists(streams_dir):
        return
    if is_link_path(streams_dir):
        raise BrainError(ErrorCode.UNSAFE_PATH, "streams directory is a link")
    if not stat.S_ISDIR(os.lstat(streams_dir).st_mode):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "streams entry is not a directory")
    verify_owner_only(streams_dir, perms)
    with os.scandir(streams_dir) as it:
        for entry in it:
            if entry.name == _V4_FENCE_FILE:
                verify_v4_fence_file(Path(entry.path), perms)
            elif is_v4_fence_part_name(entry.name):
                if entry_is_link(entry):
                    raise BrainError(ErrorCode.UNSAFE_PATH, "streams version fence staging file is a link")
                if sweep:
                    unlink_before_deadline(Path(entry.path))


def ensure_v4_fence(
    streams_dir: Path,
    perms: OutboxPermissionsPort,
    *,
    renamer: OutboxDirRenamer | None,
    check_deadline: Callable[[], None] | None = None,
) -> None:
    """Create owner-only ``streams/.v4_fence`` before writing v4 state so legacy writers fail closed."""
    ensure_dir_tree_atomic(streams_dir, perms, renamer, check_deadline=check_deadline)
    fence = streams_dir / _V4_FENCE_FILE
    if os.path.lexists(fence):
        verify_v4_fence_file(fence, perms)
        return
    tmp = streams_dir / f".v4_fence-{uuid.uuid4().hex}{_PART_SUFFIX}"
    fd = -1
    committed = False
    try:
        fd = os.open(tmp, os.O_RDWR | os.O_CREAT | os.O_EXCL | _O_BINARY | _O_NOFOLLOW, 0o600)
        write_all_fd(fd, canonical_json({"schema_version": 4}))
        perms.secure_file(tmp)
        dl = check_deadline or _ACTIVE_DEADLINE_CHECK.get()
        if dl is not None:
            dl()
        os.fsync(fd)
        os.close(fd)
        fd = -1
        if dl is not None:
            dl()
        replace_file_resilient(tmp, fence)
        sync_dir(streams_dir)
        committed = True
    except BrainError:
        raise
    except OSError as err:
        raise raise_storage_error(err, "cannot write streams version fence") from err
    finally:
        if fd != -1:
            try:
                os.close(fd)
            except OSError:
                pass
        if not committed and staging_cleanup_allowed(check_deadline):
            tmp.unlink(missing_ok=True)


def prepare_outbox_frame_bytes(
    *,
    record_kind: str,
    producer_stream: str,
    sequence: int,
    entry_id: str,
    payload_dict: dict[str, JsonValue],
) -> tuple[str, bytes]:
    """Serialize, bound-check, and CRC32-wrap an outbox frame."""
    payload_bytes = canonical_json(payload_dict)
    if len(payload_bytes) > MAX_CAPTURE_ENTRY_BYTES:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    payload_json = payload_bytes.decode("utf-8")
    payload_digest = digest_bytes(payload_bytes)
    core_fields: dict[str, JsonValue] = {
        "byte_size": len(payload_bytes), "entry_id": entry_id, "payload_digest": payload_digest,
        "payload_json": payload_json, "producer_stream": producer_stream,
        "record_kind": record_kind, "sequence": sequence,
    }
    core_fields["frame_crc32"] = f"{zlib.crc32(canonical_json(core_fields)) & 0xFFFFFFFF:08x}"
    return payload_digest, canonical_json(core_fields) + b"\n"


def verify_stream_dir_safe(stream_dir: Path, perms: OutboxPermissionsPort) -> bool:
    """Verify ``stream_dir`` (and ``streams`` parent if present) are safe non-link dirs; return exists."""
    parent = stream_dir.parent
    if os.path.lexists(parent):
        if is_link_path(parent):
            raise BrainError(ErrorCode.UNSAFE_PATH, "streams directory is a link")
        if not stat.S_ISDIR(os.lstat(parent).st_mode):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "streams entry is not a directory")
        if parent.name == _STREAMS_DIR:
            verify_owner_only(parent, perms)
    if not os.path.lexists(stream_dir):
        return False
    if is_link_path(stream_dir):
        raise BrainError(ErrorCode.UNSAFE_PATH, "stream directory is a link")
    if not stat.S_ISDIR(os.lstat(stream_dir).st_mode):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "stream entry is not a directory")
    verify_owner_only(stream_dir, perms)
    return True


def publish_outbox_frame_atomic(
    final_path: Path,
    part_path: Path,
    frame_bytes: bytes,
    perms: OutboxPermissionsPort,
    *,
    crashpoint_name: str | None = None,
    check_deadline: Callable[[], None] | None = None,
) -> None:
    """Write ``part_path``, fsync, check crashpoint/deadline, replace ``final_path``, and sync dir."""
    unlink_before_deadline(part_path, check_deadline)
    fd = -1
    committed = False
    try:
        fd = os.open(part_path, os.O_RDWR | os.O_CREAT | os.O_EXCL | _O_BINARY | _O_NOFOLLOW, 0o600)
        write_all_fd(fd, frame_bytes)
        perms.secure_file(part_path)
        dl = check_deadline or _ACTIVE_DEADLINE_CHECK.get()
        if dl is not None:
            dl()
        if crashpoint_name is not None:
            maybe_crashpoint(crashpoint_name)
        os.fsync(fd)
        os.close(fd)
        fd = -1
        if dl is not None:
            dl()
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
        if not committed and staging_cleanup_allowed(check_deadline):
            part_path.unlink(missing_ok=True)
