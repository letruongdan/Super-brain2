"""Inter-process writer lock (spec 5.5).

The lock calls are extracted from the old ``ensemble_brain/storage/ownership.py`` (blob d28475c): Windows locks
byte 0 with ``msvcrt.locking(fd, LK_NBLCK, 1)``, POSIX locks the whole file with ``flock(LOCK_EX | LOCK_NB)``.
The payload lives after byte 0, so a Windows holder can still write it. The lock file is never deleted, because
removing it would let two processes lock two different inodes.
"""

import errno
import os
import stat
import sys
from pathlib import Path

from superbrain.adapters.os.durable import full_fsync, map_os_error
from superbrain.adapters.os.paths import OsPathSafety
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.capture import register_outbox_file_lock

_LOCK_REGION = 1  # byte 0; the payload starts right after it
_REPARSE_POINT = 0x400

if sys.platform == "win32":
    import ctypes
    import msvcrt
    from ctypes import wintypes

    # msvcrt reports a lock held elsewhere as EACCES (or EDEADLOCK, 36).
    _HELD_ERRNOS = frozenset({errno.EACCES, errno.EDEADLK})
    _KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    _GENERIC_READ = 0x80000000
    _FILE_SHARE_ALL = 0x1 | 0x2 | 0x4
    _OPEN_EXISTING = 3
    _FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    _LOCKFILE_FAIL_IMMEDIATELY = 0x00000001
    _ERR_FILE_NOT_FOUND = 2
    _ERR_PATH_NOT_FOUND = 3
    _ERR_ACCESS_DENIED = 5
    _ERR_LOCK_VIOLATION = 33

    class _Overlapped(ctypes.Structure):
        _fields_ = [
            ("Internal", ctypes.c_void_p),
            ("InternalHigh", ctypes.c_void_p),
            ("Offset", wintypes.DWORD),
            ("OffsetHigh", wintypes.DWORD),
            ("hEvent", wintypes.HANDLE),
        ]

    _CREATE_FILE_W = _KERNEL32.CreateFileW
    _CREATE_FILE_W.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _CREATE_FILE_W.restype = wintypes.HANDLE
    _LOCK_FILE_EX = _KERNEL32.LockFileEx
    _LOCK_FILE_EX.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(_Overlapped),
    ]
    _LOCK_FILE_EX.restype = wintypes.BOOL
    _UNLOCK_FILE_EX = _KERNEL32.UnlockFileEx
    _UNLOCK_FILE_EX.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(_Overlapped),
    ]
    _UNLOCK_FILE_EX.restype = wintypes.BOOL
    _CLOSE_HANDLE = _KERNEL32.CloseHandle
    _CLOSE_HANDLE.argtypes = [wintypes.HANDLE]
    _CLOSE_HANDLE.restype = wintypes.BOOL

    def _lock(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)  # msvcrt.locking starts at the current position
        msvcrt.locking(fd, msvcrt.LK_NBLCK, _LOCK_REGION)

    def _unlock(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, _LOCK_REGION)

    def _probe_held_os(path: Path) -> bool:
        handle = _CREATE_FILE_W(
            os.fspath(path),
            _GENERIC_READ,
            _FILE_SHARE_ALL,
            None,
            _OPEN_EXISTING,
            _FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        if handle == _INVALID_HANDLE_VALUE or not handle:
            err_code = ctypes.get_last_error()
            if err_code in (_ERR_FILE_NOT_FOUND, _ERR_PATH_NOT_FOUND):
                return False
            if err_code == _ERR_ACCESS_DENIED:
                raise BrainError(ErrorCode.INSECURE_PERMISSIONS, f"permission denied inspecting lock file {path}")
            raise BrainError(ErrorCode.IO_ERROR, f"cannot open lock file {path} for probe (winerror {err_code})")
        try:
            ov = _Overlapped()
            ok = _LOCK_FILE_EX(handle, _LOCKFILE_FAIL_IMMEDIATELY, 0, _LOCK_REGION, 0, ctypes.byref(ov))
            if ok:
                _UNLOCK_FILE_EX(handle, 0, _LOCK_REGION, 0, ctypes.byref(ov))
                return False
            err_code = ctypes.get_last_error()
            if err_code == _ERR_LOCK_VIOLATION:
                return True
            if err_code == _ERR_ACCESS_DENIED:
                raise BrainError(ErrorCode.INSECURE_PERMISSIONS, f"permission denied probing lock file {path}")
            raise BrainError(ErrorCode.IO_ERROR, f"cannot probe lock file {path} (winerror {err_code})")
        finally:
            _CLOSE_HANDLE(handle)

else:
    import fcntl

    _HELD_ERRNOS = frozenset({errno.EWOULDBLOCK, errno.EAGAIN})

    def _lock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _unlock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)

    def _probe_held_os(path: Path) -> bool:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path, flags)
        except FileNotFoundError:
            return False
        except PermissionError as err:
            raise BrainError(ErrorCode.INSECURE_PERMISSIONS, f"permission denied probing lock file {path}") from err
        except OSError as err:
            if err.errno == errno.ELOOP:
                raise BrainError(ErrorCode.UNSAFE_PATH, f"lock path {path} must not be a symlink") from err
            raise map_os_error(err, f"opening lock file {path} for probe") from err
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except OSError as err:
                if err.errno in _HELD_ERRNOS:
                    return True
                if err.errno in (errno.EACCES, errno.EPERM):
                    raise BrainError(
                        ErrorCode.INSECURE_PERMISSIONS, f"permission denied probing lock file {path}"
                    ) from err
                raise map_os_error(err, f"probing lock file {path}") from err
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
            return False
        finally:
            os.close(fd)


class _OsLockHandle:
    def __init__(self, fd: int) -> None:
        self._fd: int | None = fd

    def _live_fd(self) -> int:
        if self._fd is None:
            raise AssertionError("lock handle already released")
        return self._fd

    def read_payload(self) -> bytes:
        fd = self._live_fd()
        chunks: list[bytes] = []
        try:
            os.lseek(fd, _LOCK_REGION, os.SEEK_SET)
            while chunk := os.read(fd, 4096):
                chunks.append(chunk)
        except OSError as err:
            raise map_os_error(err, "reading the lock payload") from err
        return b"".join(chunks)

    def write_payload(self, offset: int, data: bytes) -> None:
        if offset < 0:
            raise AssertionError(f"negative payload offset {offset}")
        fd = self._live_fd()
        try:
            os.lseek(fd, _LOCK_REGION + offset, os.SEEK_SET)
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view) :]
            full_fsync(fd)
        except OSError as err:
            raise map_os_error(err, "writing the lock payload") from err

    def release(self) -> None:
        fd, self._fd = self._fd, None
        if fd is None:
            return
        try:
            _unlock(fd)
        except OSError as err:
            raise map_os_error(err, "unlocking the writer lock") from err
        finally:
            os.close(fd)


class OsLockFactory:
    def acquire(self, path: Path) -> _OsLockHandle:
        flags = os.O_RDWR | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path, flags)
        except OSError as err:
            raise map_os_error(err, f"opening the lock file {path}") from err
        try:
            _lock(fd)
        except OSError as err:
            os.close(fd)
            if err.errno in _HELD_ERRNOS:
                raise BrainError(ErrorCode.WRITER_HELD, "another process holds the writer lock") from err
            raise map_os_error(err, "locking the writer lock") from err
        return _OsLockHandle(fd)

    def probe_held(self, path: Path) -> bool:
        OsPathSafety().reject_unsafe_path(os.fspath(path))
        OsPathSafety().reject_links(path)
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            return False
        except PermissionError as err:
            raise BrainError(ErrorCode.INSECURE_PERMISSIONS, f"cannot stat lock file {path}: {err}") from err
        except OSError as err:
            raise map_os_error(err, f"inspecting lock file {path}") from err
        if stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & _REPARSE_POINT):
            raise BrainError(ErrorCode.UNSAFE_PATH, f"lock path {path} must not be a symlink or reparse point")
        return _probe_held_os(path)

class _OsOutboxFileLock:
    def try_lock_fd(self, fd: int) -> bool:
        try:
            _lock(fd)
            return True
        except OSError as err:
            if err.errno in _HELD_ERRNOS:
                return False
            raise map_os_error(err, "locking the outbox") from err

    def unlock_fd(self, fd: int) -> None:
        try:
            _unlock(fd)
        except OSError:
            pass


OUTBOX_FILE_LOCK = _OsOutboxFileLock()
register_outbox_file_lock(OUTBOX_FILE_LOCK)
