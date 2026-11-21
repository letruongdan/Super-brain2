"""Low-level binary/safe-path/fsync/atomic-write helpers for ``storage.outbox``."""

from __future__ import annotations

import errno
import hashlib
import os
import stat
import threading
from pathlib import Path

from superbrain.core.errors import BrainError, ErrorCode

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
