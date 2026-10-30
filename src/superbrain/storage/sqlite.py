"""SQLite connection factory shared by the main store, the policy store and backup verification."""

import sqlite3
import sys
from pathlib import Path

from superbrain.core.errors import BrainError, ErrorCode

_BUSY_TIMEOUT_MS = 5000


def connect(path: Path, *, readonly: bool = False, platform: str = sys.platform) -> sqlite3.Connection:
    """Open ``path`` with the store's durability pragmas.

    ``readonly`` opens ``file:<path>?mode=ro`` and leaves ``journal_mode`` untouched (changing it needs a write).
    ``platform`` selects the macOS ``fullfsync`` pragmas; it is a parameter so tests can exercise it anywhere.
    Every ``sqlite3.Error`` is mapped to ``BrainError(IO_ERROR)``; the connection is closed on failure.
    """
    try:
        if readonly:
            db = sqlite3.connect(f"{path.absolute().as_uri()}?mode=ro", uri=True, isolation_level=None)
        else:
            db = sqlite3.connect(path, isolation_level=None)
    except sqlite3.Error as exc:
        raise BrainError(ErrorCode.IO_ERROR, f"cannot open database {path}: {exc}") from exc
    try:
        db.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
        if not readonly:
            mode = db.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            if str(mode).lower() != "wal":
                raise BrainError(ErrorCode.IO_ERROR, f"{path}: journal_mode is {mode!r}, WAL did not take effect")
        db.execute("PRAGMA synchronous=FULL")
        if not readonly and db.execute("PRAGMA synchronous").fetchone()[0] != 2:
            raise BrainError(ErrorCode.IO_ERROR, f"{path}: synchronous=FULL did not take effect")
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA secure_delete=ON")
        if platform == "darwin":
            db.execute("PRAGMA fullfsync=ON")
            db.execute("PRAGMA checkpoint_fullfsync=ON")
    except BrainError:
        db.close()
        raise
    except sqlite3.Error as exc:
        db.close()
        raise BrainError(ErrorCode.IO_ERROR, f"cannot configure database {path}: {exc}") from exc
    return db
