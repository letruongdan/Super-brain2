"""Inter-process writer lock (spec 5.5).

The lock calls are extracted from the old ``ensemble_brain/storage/ownership.py`` (blob d28475c): Windows locks
byte 0 with ``msvcrt.locking(fd, LK_NBLCK, 1)``, POSIX locks the whole file with ``flock(LOCK_EX | LOCK_NB)``.
The payload lives after byte 0, so a Windows holder can still write it. The lock file is never deleted, because
removing it would let two processes lock two different inodes.
"""

import errno
import os
import sys
from pathlib import Path

from superbrain.adapters.os.durable import _full_fsync, map_os_error
from superbrain.core.errors import BrainError, ErrorCode

_LOCK_REGION = 1  # byte 0; the payload starts right after it

if sys.platform == "win32":
    import msvcrt

    # msvcrt reports a lock held elsewhere as EACCES (or EDEADLOCK, 36).
    _HELD_ERRNOS = frozenset({errno.EACCES, errno.EDEADLK})

    def _lock(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)  # msvcrt.locking starts at the current position
        msvcrt.locking(fd, msvcrt.LK_NBLCK, _LOCK_REGION)

    def _unlock(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, _LOCK_REGION)

else:
    import fcntl

    _HELD_ERRNOS = frozenset({errno.EWOULDBLOCK, errno.EAGAIN})

    def _lock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _unlock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)


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
            _full_fsync(fd)
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
