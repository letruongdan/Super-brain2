"""The one mapping from OS and SQLite failures to ``BrainError``, shared by every storage module.

Disk full (``ENOSPC``, ``EDQUOT``, Windows ``ERROR_DISK_FULL`` or SQLite ``SQLITE_FULL``) is ``STORAGE_FULL``. Where
the caller asks for the distinction, a busy database (``SQLITE_BUSY``/``SQLITE_LOCKED``) is ``STORE_BUSY`` and a
Windows sharing violation ``FILESYSTEM_BUSY``. Everything else is ``IO_ERROR``. The caller raises the result
``from`` the original error, so the cause stays chained. (``adapters.os.durable`` keeps its own copy for the
adapters, because ``storage`` never imports ``adapters``.)
"""

import errno
import sqlite3

from superbrain.core.errors import BrainError, ErrorCode

_FULL_ERRNOS = frozenset({errno.ENOSPC, errno.EDQUOT})
_ERROR_DISK_FULL = 112
SHARING_WINERRORS = frozenset({32, 5})
"""``ERROR_SHARING_VIOLATION`` and ``ERROR_ACCESS_DENIED``: another process (antivirus, indexer) holds the file."""
_BUSY_CODES = frozenset({sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED})


def _winerror(err: OSError) -> int | None:
    value = getattr(err, "winerror", None)
    return value if isinstance(value, int) else None


def _sqlite_code(exc: sqlite3.Error) -> int | None:
    """The primary result code of ``exc`` (the low byte of an extended code), if SQLite reported one."""
    value = getattr(exc, "sqlite_errorcode", None)
    return value & 0xFF if isinstance(value, int) else None


def is_busy(exc: sqlite3.Error) -> bool:
    """``exc`` reports another connection holding the database (``SQLITE_BUSY``/``SQLITE_LOCKED``)."""
    return _sqlite_code(exc) in _BUSY_CODES


def os_error(what: str, err: OSError, *, sharing_busy: bool = False) -> BrainError:
    """``STORAGE_FULL`` for a full disk or quota, ``FILESYSTEM_BUSY`` for a Windows sharing violation when
    ``sharing_busy``, else ``IO_ERROR``."""
    if err.errno in _FULL_ERRNOS or _winerror(err) == _ERROR_DISK_FULL:
        return BrainError(ErrorCode.STORAGE_FULL, f"no space left: {what}: {err}")
    if sharing_busy and _winerror(err) in SHARING_WINERRORS:
        return BrainError(ErrorCode.FILESYSTEM_BUSY, f"{what}: held by another process (antivirus or indexer?)")
    return BrainError(ErrorCode.IO_ERROR, f"{what}: {err}")


def sqlite_error(what: str, exc: sqlite3.Error, *, busy: bool = False) -> BrainError:
    """``STORAGE_FULL`` for ``SQLITE_FULL``, ``STORE_BUSY`` for a busy or locked database when ``busy``, else
    ``IO_ERROR``."""
    if _sqlite_code(exc) == sqlite3.SQLITE_FULL:
        return BrainError(ErrorCode.STORAGE_FULL, f"no space left: {what}: {exc}")
    if busy and is_busy(exc):
        return BrainError(ErrorCode.STORE_BUSY, f"{what}: the database is busy: {exc}")
    return BrainError(ErrorCode.IO_ERROR, f"{what}: {exc}")
