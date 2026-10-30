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


def _store_v1(db: sqlite3.Connection) -> None:
    """Main store v1 DDL (ledger, applied_intents). Task 8 fills this in; ``meta`` is written by ``initialize``."""


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
    """Read-only open that never creates or changes ``-wal``/``-shm``.

    Even ``mode=ro`` creates ``-wal``/``-shm`` when it opens a WAL database that has none (observed on Windows), which
    would change the bytes of a database we promised only to look at. So: if a ``-wal`` file exists, open ``mode=ro``
    (it sees the live WAL); if not, there is nothing to replay and the file is opened with ``immutable=1``, which
    takes no locks and writes nothing. ``immutable`` is safe only when no writer is active: every reader here runs
    under the writer lease or on a closed or copied database.
    """
    uri = path.absolute().as_uri()
    mode = "mode=ro" if path.with_name(path.name + "-wal").exists() else "immutable=1"
    return sqlite3.connect(f"{uri}?{mode}", uri=True, isolation_level=None)


def read_schema_info(path: Path) -> SchemaInfo | None:
    """The ``meta`` of the database at ``path`` without writing anything; ``None`` if the file does not exist."""
    if not path.exists():
        return None
    db: sqlite3.Connection | None = None
    try:
        db = _open_readonly(path)
        rows = dict(db.execute("SELECT key, value FROM meta").fetchall())
        if any(k not in rows for k in _META_KEYS):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"{path}: meta is missing required keys")
        return SchemaInfo(int(rows["schema_version"]), int(rows["min_reader_version"]), str(rows["store_id"]))
    except BrainError:
        raise
    except sqlite3.OperationalError as exc:
        if "no such table" in str(exc):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"{path}: not a store database (no meta)") from exc
        raise BrainError(ErrorCode.IO_ERROR, f"cannot read {path}: {exc}") from exc
    except sqlite3.DatabaseError as exc:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"{path}: not a valid database: {exc}") from exc
    except ValueError as exc:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"{path}: malformed meta values") from exc
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
