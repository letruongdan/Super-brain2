"""SQLite connection factory and database-file helpers shared by the main store, the policy store and backup
verification."""

import os
import shutil
import sqlite3
import stat
import sys
from pathlib import Path

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.storage.errors import os_error, sqlite_error

_BUSY_TIMEOUT_MS = 5000
CREATING = ".creating-"
"""A new database is built at ``<name>.creating-<id>`` and published to ``<name>`` only once complete."""
READING = ".reading-"
"""``open_readonly`` recovers a WAL in a private ``<name>.reading-<id>/`` directory, removed before it returns."""
_REPARSE_POINT = 0x400  # FILE_ATTRIBUTE_REPARSE_POINT; st_file_attributes exists on Windows only
WAL_HEADER_SIZE = 32
"""A ``-wal`` no longer than its header holds no frame, so nothing committed."""


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


def remove_unfinished_reads(path: Path) -> None:
    """Under the writer lease: delete ``<path>.reading-*`` directories that a reader killed mid-way left behind.

    Every ``open_readonly`` of a live database runs under the lease, so none is in use. Only real directories are
    removed; a link, junction or other reparse point with that name is never followed or touched (``rmtree`` does
    not descend into links). A missing parent directory means there is nothing to remove.
    """
    prefix = path.name + READING
    try:
        names = sorted(n for n in os.listdir(path.parent) if n.startswith(prefix))
    except FileNotFoundError:
        return
    except OSError as exc:
        raise os_error(f"cannot list {path.parent}", exc) from exc
    for name in names:
        leftover = path.parent / name
        try:
            st = os.lstat(leftover)
            if stat.S_ISDIR(st.st_mode) and not getattr(st, "st_file_attributes", 0) & _REPARSE_POINT:
                shutil.rmtree(leftover)
        except OSError as exc:
            raise os_error(f"cannot remove the unfinished read copy {name}", exc) from exc


def _wal_size(wal: Path) -> int:
    try:
        return os.stat(wal).st_size
    except FileNotFoundError:
        return 0
    except OSError as exc:
        raise os_error(f"cannot inspect {wal.name}", exc) from exc


def _recovered_copy(path: Path, *, scratch_dir: Path | None = None) -> sqlite3.Connection:
    """An in-memory copy of what SQLite itself recovers from ``path`` plus its ``-wal`` (no ``-shm``).

    Both files are copied into a new private directory next to ``path`` (or inside ``scratch_dir`` when supplied so
    ``path.parent`` stays untouched), the copy is opened writable so SQLite recovers the WAL into it, then it is
    backed up into a ``:memory:`` connection and the directory is removed. ``path`` and its ``-wal`` are only read.
    SQLite decides which WAL frames are committed: a WAL with no valid header or checksum adds nothing.
    """
    parent = scratch_dir if scratch_dir is not None else path.parent
    work = parent / f"{path.name}{READING}{new_id()}"
    try:
        work.mkdir(mode=0o700)
    except OSError as exc:
        raise os_error(f"cannot create a private copy of {path.name}", exc) from exc
    try:
        copy = work / path.name
        try:
            shutil.copyfile(path, copy)
            shutil.copyfile(db_files(path)[1], db_files(copy)[1])
        except OSError as exc:
            raise os_error(f"cannot copy {path.name} to recover its WAL", exc) from exc
        source = sqlite3.connect(copy, isolation_level=None)
        try:
            memory = sqlite3.connect(":memory:", isolation_level=None)
            try:
                source.backup(memory)
            except BaseException:
                memory.close()
                raise
        finally:
            source.close()
    except BaseException as err:
        try:
            shutil.rmtree(work)
        except OSError as cleanup:
            err.add_note(f"the private copy {work} could not be removed: {cleanup}")
        raise
    try:
        shutil.rmtree(work)
    except OSError as exc:
        memory.close()
        raise os_error(f"cannot remove the private copy {work}", exc) from exc
    return memory


def open_readonly(path: Path, *, scratch_dir: Path | None = None) -> sqlite3.Connection:
    """A read-only view of the committed state of the closed (or leased) database ``path``.

    Even ``mode=ro`` creates ``-wal``/``-shm`` when they are missing (observed on Windows), and updates reader marks
    in an existing ``-shm``. When ``scratch_dir`` is provided (for pre-admission under a held writer lease with no
    live writer), any ``-wal`` holding frames is recovered in ``scratch_dir`` outside the data root so ``path``,
    ``-wal`` and ``-shm`` remain byte-for-byte untouched; otherwise:

    * ``-wal`` and ``-shm`` both exist (a live writer, or one that died before checkpointing): ``mode=ro``, which
      sees the committed WAL frames and never checkpoints or deletes the WAL.
    * a ``-wal`` that may hold frames (longer than its header) but no ``-shm``: the ``-shm`` is only a rebuildable
      index, so its absence says nothing about the WAL; the WAL is committed state. ``_recovered_copy`` returns what
      SQLite recovers from a private copy, in memory. ``path``, its ``-wal`` and the absent ``-shm`` stay as they were.
    * otherwise (no WAL, or an empty or header-only one, which holds no frame): ``immutable=1``, no locks, nothing
      written.

    ``immutable`` is safe only when no writer is active: every reader here runs under the writer lease or on a
    closed or copied database. ``sqlite3.Error`` propagates; a failure to copy is a ``BrainError`` (``os_error``).

    Limitation: stores are always in WAL mode. A rollback-journal database with a hot journal would not be recovered
    by this read (``immutable`` ignores the journal), so such a file is not supported.
    """
    uri = path.absolute().as_uri()
    _, wal, shm = db_files(path)
    if scratch_dir is not None:
        if _wal_size(wal) > WAL_HEADER_SIZE:
            return _recovered_copy(path, scratch_dir=scratch_dir)
        return sqlite3.connect(f"{uri}?immutable=1", uri=True, isolation_level=None)
    if os.path.exists(wal) and os.path.exists(shm):
        return sqlite3.connect(f"{uri}?mode=ro", uri=True, isolation_level=None)
    if _wal_size(wal) > WAL_HEADER_SIZE:
        return _recovered_copy(path)
    return sqlite3.connect(f"{uri}?immutable=1", uri=True, isolation_level=None)


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
