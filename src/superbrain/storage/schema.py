"""Schema versioning shared by the main store and the policy store (spec 5.8).

Writing requires ``schema_version`` to equal the code's version exactly: newer is ``UNSUPPORTED_VERSION`` (whatever
``min_reader_version`` says), older is ``MIGRATION_REQUIRED``. Reading needs only ``min_reader_version <= code``.
A migration never runs automatically.
"""

import sqlite3
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from superbrain.core.errors import BrainError, ErrorCode

_META_KEYS = ("schema_version", "min_reader_version", "store_id")


@dataclass(frozen=True)
class SchemaInfo:
    schema_version: int
    min_reader_version: int
    store_id: str


@dataclass(frozen=True)
class Migration:
    to_version: int
    min_reader_version: int
    apply: Callable[[sqlite3.Connection], None]
    """Runs inside ``initialize``'s transaction. It must not call ``executescript``: that issues an implicit COMMIT
    and would break the single transaction."""


def _store_v1(db: sqlite3.Connection) -> None:
    """Main store v1 DDL: ``ledger`` and ``applied_intents``; ``meta`` is written by ``initialize``.

    ``ledger.meta`` and ``ledger.refs`` hold canonical JSON bytes. Projection tables are not part of the schema:
    each handler creates its own ``p_<name>_*`` tables when the store is created or opened.
    """
    db.execute(
        "CREATE TABLE ledger ("
        "sequence INTEGER PRIMARY KEY AUTOINCREMENT, "
        "entry_id TEXT UNIQUE NOT NULL, "
        "kind TEXT NOT NULL, "
        "schema_version INTEGER NOT NULL, "
        "handler_version INTEGER NOT NULL, "
        "writer_epoch INTEGER NOT NULL, "
        "actor TEXT NOT NULL, "
        "owner_id TEXT, "
        "recorded_at TEXT NOT NULL, "
        "meta BLOB NOT NULL, "
        "refs BLOB NOT NULL)"
    )
    db.execute("CREATE TABLE applied_intents (intent_id TEXT PRIMARY KEY, applied_sequence INTEGER NOT NULL)")


def _policy_v1(db: sqlite3.Connection) -> None:
    """Policy store v1 DDL. Task 11 fills this in; ``meta`` is written by ``initialize``."""


STORE_MIGRATIONS: tuple[Migration, ...] = (Migration(to_version=1, min_reader_version=1, apply=_store_v1),)
POLICY_MIGRATIONS: tuple[Migration, ...] = (Migration(to_version=1, min_reader_version=1, apply=_policy_v1),)


def code_version(migrations: Sequence[Migration]) -> int:
    """The newest schema version the code knows; ``migrations`` must be 1, 2, ... with no gaps."""
    assert migrations, "at least one migration is required"
    assert [m.to_version for m in migrations] == list(range(1, len(migrations) + 1)), "migrations must be 1..N"
    return migrations[-1].to_version


def _open_readonly(path: Path) -> sqlite3.Connection:
    """Read-only open that never creates or changes any file.

    Even ``mode=ro`` creates ``-wal``/``-shm`` when they are missing (observed on Windows), which would change a
    database we promised only to look at. So ``mode=ro`` is used only when both ``-wal`` and ``-shm`` exist, which
    means a live writer; the reader then sees the live WAL. Otherwise the file is opened ``immutable=1``: no locks,
    nothing written, any stale or empty ``-wal`` ignored. ``immutable`` is safe only when no writer is active: every
    reader here runs under the writer lease or on a closed or copied database.

    Limitation: stores are always in WAL mode. A rollback-journal database with a hot journal would not be recovered
    by this read (``immutable`` ignores the journal), so such a file is not supported.
    """
    uri = path.absolute().as_uri()
    live = path.with_name(path.name + "-wal").exists() and path.with_name(path.name + "-shm").exists()
    return sqlite3.connect(f"{uri}?{'mode=ro' if live else 'immutable=1'}", uri=True, isolation_level=None)


def _version(path: Path, name: str, value: object) -> int:
    if not isinstance(value, str) or not (value.isascii() and value.isdigit()):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"{path}: meta {name} is not a plain decimal integer")
    return int(value)


def read_schema_info(path: Path) -> SchemaInfo | None:
    """The ``meta`` of the database at ``path`` without writing anything; ``None`` if the file does not exist.

    Opens through ``_open_readonly``, so no file is created or modified.
    """
    if not path.exists():
        return None
    db: sqlite3.Connection | None = None
    try:
        db = _open_readonly(path)
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta'").fetchone() is None:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"{path}: not a store database (no meta)")
        columns = {row[1] for row in db.execute("PRAGMA table_info(meta)")}
        if not {"key", "value"} <= columns:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"{path}: meta has the wrong shape")
        rows = dict(db.execute("SELECT key, value FROM meta").fetchall())
        if any(k not in rows for k in _META_KEYS):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"{path}: meta is missing required keys")
        store_id = rows["store_id"]
        if not isinstance(store_id, str):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"{path}: meta store_id is not text")
        schema_version = _version(path, "schema_version", rows["schema_version"])
        min_reader = _version(path, "min_reader_version", rows["min_reader_version"])
        if schema_version < 1 or min_reader > schema_version:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"{path}: meta versions are inconsistent")
        return SchemaInfo(schema_version, min_reader, store_id)
    except BrainError:
        raise
    except sqlite3.OperationalError as exc:
        raise BrainError(ErrorCode.IO_ERROR, f"cannot read {path}: {exc}") from exc
    except sqlite3.DatabaseError as exc:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"{path}: not a valid database: {exc}") from exc
    except (sqlite3.Error, OSError) as exc:
        raise BrainError(ErrorCode.IO_ERROR, f"cannot read {path}: {exc}") from exc
    finally:
        if db is not None:
            db.close()


def ensure_writable(info: SchemaInfo, migrations: Sequence[Migration]) -> None:
    code = code_version(migrations)
    if info.schema_version > code:
        raise BrainError(ErrorCode.UNSUPPORTED_VERSION, f"schema {info.schema_version} is newer than code {code}")
    if info.schema_version < code:
        raise BrainError(ErrorCode.MIGRATION_REQUIRED, f"schema {info.schema_version} needs migration to {code}")


def ensure_readable(info: SchemaInfo, migrations: Sequence[Migration]) -> None:
    code = code_version(migrations)
    if info.min_reader_version > code:
        raise BrainError(
            ErrorCode.UNSUPPORTED_VERSION, f"reader version {info.min_reader_version} is newer than code {code}"
        )


def initialize(db: sqlite3.Connection, migrations: Sequence[Migration], *, store_id: str) -> None:
    """Create a brand-new database: every migration plus ``meta``, in one transaction."""
    code_version(migrations)
    last = migrations[-1]
    try:
        db.execute("BEGIN IMMEDIATE")
        try:
            existing = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta'").fetchone()
            assert existing is None, "initialize is only for a new database"
            for migration in migrations:
                migration.apply(db)
            db.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            db.executemany(
                "INSERT INTO meta (key, value) VALUES (?, ?)",
                [
                    ("schema_version", str(last.to_version)),
                    ("min_reader_version", str(last.min_reader_version)),
                    ("store_id", store_id),
                ],
            )
            db.execute("COMMIT")
        except BaseException:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise
    except sqlite3.Error as exc:
        raise BrainError(ErrorCode.IO_ERROR, f"cannot initialize database: {exc}") from exc
