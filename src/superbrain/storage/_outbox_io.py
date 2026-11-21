"""Low-level binary, safe-path, fsync, atomic-cold-create, and fast scandir helpers for ``storage.outbox``."""

from __future__ import annotations

import errno
import hashlib
import os
import shutil
import stat
import threading
import uuid
from collections.abc import Callable
from pathlib import Path

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.capture import OutboxDirRenamer, OutboxPermissionsPort

_REPARSE_POINT = 0x400
_PART_SUFFIX = ".part"
_FRAME_SUFFIX = ".frame"
_STREAMS_DIR = "streams"
_LOCK_FILE = ".spool.lock"
_PROCESS_LOCKS_GUARD = threading.Lock()
_PROCESS_LOCKS: dict[str, threading.RLock] = {}
_ENOSPC_WINERROR = 112
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
        if path.is_symlink():
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


def raise_storage_error(err: OSError, message: str) -> BrainError:
    winerr = getattr(err, "winerror", None)
    if err.errno in (errno.ENOSPC, errno.EDQUOT) or winerr == _ENOSPC_WINERROR:
        return BrainError(ErrorCode.STORAGE_FULL, "storage full")
    if getattr(errno, "ELOOP", None) is not None and err.errno == errno.ELOOP:
        return BrainError(ErrorCode.UNSAFE_PATH, f"symlink detected in outbox: {err}")
    return BrainError(ErrorCode.IO_ERROR, f"{message}: {err}")


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


def sync_dir(directory: Path) -> None:
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
) -> bool:
    """Create ``target`` via hardened staging dir + non-replacing rename; return ``True`` if created."""
    created = False
    if not os.path.lexists(target):
        stage = target.parent / f".{target.name}.init-{os.getpid()}-{threading.get_ident()}-{uuid.uuid4().hex}"
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
            if stage.exists():
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
            atomic_create_dir(directory, perms, rename_dir_fn, check_deadline=check_deadline)
            return
        if is_link_path(directory) or not stat.S_ISDIR(os.lstat(directory).st_mode):
            raise BrainError(ErrorCode.UNSAFE_PATH, "log parent directory is not a valid directory")
        return
    for item in reversed(missing):
        atomic_create_dir(item, perms, rename_dir_fn, check_deadline=check_deadline)


def ensure_secure_regular_file_atomic(
    target: Path,
    perms: OutboxPermissionsPort,
    *,
    check_deadline: Callable[[], None] | None = None,
) -> None:
    """Create missing ``target`` with owner-only ACLs prior to publishing, or verify existing owner-only file."""
    if is_link_path(target):
        raise BrainError(ErrorCode.UNSAFE_PATH, f"file is a link: {target}")
    if not os.path.lexists(target):
        stage = target.with_name(f".{target.name}.init-{os.getpid()}-{threading.get_ident()}-{uuid.uuid4().hex}")
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
        except OSError as err:
            raise raise_storage_error(err, f"cannot create file {target}") from err
        finally:
            if fd_s != -1:
                try:
                    os.close(fd_s)
                except OSError:
                    pass
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
