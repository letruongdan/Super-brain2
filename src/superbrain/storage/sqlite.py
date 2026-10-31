"""SQLite connection factory and database-file helpers shared by the main store, the policy store and backup
verification."""

import os
import sqlite3
import sys
from pathlib import Path

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.storage.errors import os_error, sqlite_error

_BUSY_TIMEOUT_MS = 5000
CREATING = ".creating-"
"""A new database is built at ``<name>.creating-<id>`` and published to ``<name>`` only once complete."""


def db_files(path: Path) -> tuple[Path, Path, Path]:
    """``path`` and its ``-wal`` and ``-shm`` companions, whether or not they exist."""
    return (path, path.with_name(path.name + "-wal"), path.with_name(path.name + "-shm"))


def remove_unfinished_creates(path: Path) -> None:
    """Delete ``<path>.creating-*`` leftovers (with their ``-wal``/``-shm``) of a failed or interrupted create."""
    prefix = path.name + CREATING
    try:
        for name in sorted(os.listdir(path.parent)):
            if name.startswith(prefix):
                os.unlink(path.parent / name)
    except OSError as exc:
        raise os_error(f"cannot remove an unfinished create of {path.name}", exc) from exc


def open_readonly(path: Path) -> sqlite3.Connection:
    """Read-only open that never creates or changes any file.

    Even ``mode=ro`` creates ``-wal``/``-shm`` when they are missing (observed on Windows), which would change a
    database we promised only to look at. So ``mode=ro`` is used only when both ``-wal`` and ``-shm`` exist, which
    means a live writer or one that died before checkpointing; the reader then sees the committed WAL frames (a
    read-only connection never checkpoints or deletes the WAL). Otherwise the file is opened ``immutable=1``: no locks,
    nothing written, any stale or empty ``-wal`` ignored. ``immutable`` is safe only when no writer is active: every
    reader here runs under the writer lease or on a closed or copied database.

    Limitation: stores are always in WAL mode. A rollback-journal database with a hot journal would not be recovered
    by this read (``immutable`` ignores the journal), so such a file is not supported.
    """
    uri = path.absolute().as_uri()
    live = path.with_name(path.name + "-wal").exists() and path.with_name(path.name + "-shm").exists()
    return sqlite3.connect(f"{uri}?{'mode=ro' if live else 'immutable=1'}", uri=True, isolation_level=None)


def open_immutable(path: Path) -> sqlite3.Connection:
    """Open the closed, self-contained database file ``path`` with ``immutable=1``: no lock, no file created or
    changed, and any ``-wal``/``-shm`` ignored. For backup snapshots, which never have companions."""
    return sqlite3.connect(f"{path.absolute().as_uri()}?immutable=1", uri=True, isolation_level=None)


def connect(path: Path, *, readonly: bool = False, platform: str = sys.platform) -> sqlite3.Connection:
    """Open ``path`` with the store's durability pragmas.

    ``readonly`` opens ``file:<path>?mode=ro`` and leaves ``journal_mode`` untouched (changing it needs a write).
    ``platform`` selects the macOS ``fullfsync`` pragmas; it is a parameter so tests can exercise it anywhere.
    Every ``sqlite3.Error`` is mapped by ``sqlite_error``; the connection is closed on failure.
    """
    try:
        if readonly:
            db = sqlite3.connect(f"{path.absolute().as_uri()}?mode=ro", uri=True, isolation_level=None)
        else:
            db = sqlite3.connect(path, isolation_level=None)
    except sqlite3.Error as exc:
        raise sqlite_error(f"cannot open database {path}", exc) from exc
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
        raise sqlite_error(f"cannot configure database {path}", exc) from exc
    return db
