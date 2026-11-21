"""Migration of the main store and the policy store (spec 5.8).

A migration never runs by itself: a newer binary that meets an older store gets ``MIGRATION_REQUIRED`` and the
operator runs it, under the writer lease, with both the store and the policy store closed (the store holds a
reference to the policy store). It takes a verified maintenance backup first, builds the migrated copy in a stage
and swaps it in with ``stage_and_swap``. A failure before the swap leaves the original untouched.
"""

import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.os import OsAdapters, PlatformTraits
from superbrain.storage._policy_accounting import sync_legacy_accounting_from_store
from superbrain.storage._restore_epoch import read_restore_epoch, write_restore_epoch
from superbrain.storage.backup import (
    BackupKind,
    copy_blobs,
    copy_database,
    create_maintenance_backup,
    new_directory,
    verify_backup,
)
from superbrain.storage.cas import blob_digests
from superbrain.storage.errors import os_error, sqlite_error
from superbrain.storage.layout import DataRoot
from superbrain.storage.schema import (
    POLICY_MIGRATIONS,
    STORE_MIGRATIONS,
    Migration,
    code_version,
    read_schema_info,
)
from superbrain.storage.sqlite import apply_durability_pragmas, db_files
from superbrain.storage.swap import stage_and_swap
from superbrain.storage.writer import WriterLease

__all__ = ["MigrationReport", "migrate_database", "migrate_staged_file"]


@dataclass(frozen=True)
class MigrationReport:
    target: str
    from_version: int
    to_version: int
    backup: Path
    """The verified maintenance backup taken before the migration."""
    replaced_dir: Path
    """Where the pre-migration ``store/`` or ``policy/`` directory was kept."""


def _apply(db: sqlite3.Connection, pending: Sequence[Migration]) -> None:
    for migration in pending:
        db.execute("BEGIN IMMEDIATE")
        try:
            try:
                migration.apply(db)
            except sqlite3.Error as exc:
                raise BrainError(
                    ErrorCode.INTEGRITY_FAILURE, f"migration v{migration.to_version} failed: {exc}"
                ) from exc
            db.execute("UPDATE meta SET value = ? WHERE key = 'schema_version'", (str(migration.to_version),))
            db.execute(
                "UPDATE meta SET value = ? WHERE key = 'min_reader_version'", (str(migration.min_reader_version),)
            )
            db.execute("COMMIT")
        except BaseException as err:
            if db.in_transaction:
                try:
                    db.execute("ROLLBACK")
                except sqlite3.Error as rollback:
                    err.add_note(f"rolling back migration v{migration.to_version} also failed: {rollback}")
            raise


def _configure(db: sqlite3.Connection, traits_or_platform: PlatformTraits | str) -> None:
    """The durability settings every database connection of this package uses (see ``sqlite.connect``)."""
    if isinstance(traits_or_platform, str):
        apply_durability_pragmas(db, platform=traits_or_platform, foreign_keys=True)
    else:
        apply_durability_pragmas(db, traits_or_platform, foreign_keys=True)


def _integrity_report(db: sqlite3.Connection) -> str:
    return "\n".join(str(row[0]) for row in db.execute("PRAGMA integrity_check"))


def migrate_staged_file(
    path: Path,
    pending: Sequence[Migration],
    os_: OsAdapters,
    platform: str | None = None,
    *,
    flush: bool = True,
) -> None:
    """Recover the WAL of the staged copy ``path``, apply ``pending`` and leave one self-contained file, made durable
    with ``os_.publisher.flush_file`` when ``flush`` is true."""
    db = sqlite3.connect(path, isolation_level=None)
    try:
        _configure(db, platform if platform is not None else os_.traits)
        mode = db.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
        if str(mode).lower() != "delete":
            raise BrainError(ErrorCode.IO_ERROR, f"{path.name}: journal_mode is {mode!r}, DELETE did not take effect")
        _apply(db, pending)
        result = _integrity_report(db)
        if result != "ok":
            raise BrainError(
                ErrorCode.INTEGRITY_FAILURE, f"the migrated {path.name} failed its integrity check: {result}"
            )
    finally:
        db.close()
    leftovers = [p.name for p in (*db_files(path)[1:], path.with_name(path.name + "-journal")) if p.exists()]
    if leftovers:
        raise BrainError(ErrorCode.IO_ERROR, f"the migrated {path.name} kept companions {leftovers}")
    if flush:
        os_.publisher.flush_file(path)


def migrate_database(
    root: DataRoot,
    lease: WriterLease,
    os_: OsAdapters,
    *,
    target: Literal["store", "policy"],
    migrations: Sequence[Migration] | None = None,
    now: datetime,
) -> MigrationReport:
    """Migrate the closed ``target`` database to ``code_version(migrations)``.

    Both the store and the policy store must be closed (``STORE_BUSY``). A database already at the code's version
    is ``INVALID_INPUT``, a newer one ``UNSUPPORTED_VERSION``. A verified ``create_maintenance_backup`` comes first
    (verified against the old schema), then ``brain.db`` or ``policy.db`` (and ``cas/``) is copied into a stage,
    migrated one transaction per migration, integrity-checked and swapped in. Any failure before the swap
    leaves the original directory byte-for-byte unchanged; an error from a migration's ``apply`` propagates.
    """
    if target not in ("store", "policy"):
        raise BrainError(ErrorCode.INVALID_INPUT, f"unknown migration target {target!r}")
    busy = sorted({"store", "policy"} & lease.open_handles())
    if busy:
        raise BrainError(ErrorCode.STORE_BUSY, f"close {' and '.join(busy)} before migrating the {target} database")
    if migrations is None:
        migrations = STORE_MIGRATIONS if target == "store" else POLICY_MIGRATIONS
    latest = code_version(migrations)
    source = root.store_db if target == "store" else root.policy_db
    info = read_schema_info(source)
    if info is None:
        raise BrainError(ErrorCode.NOT_FOUND, f"no {target} database at {source}")
    if info.schema_version > latest:
        raise BrainError(ErrorCode.UNSUPPORTED_VERSION, f"schema {info.schema_version} is newer than code {latest}")
    if info.schema_version == latest:
        raise BrainError(ErrorCode.INVALID_INPUT, f"nothing to migrate: the {target} database is at version {latest}")
    kind: BackupKind = "store_full" if target == "store" else "policy"
    try:
        backup = create_maintenance_backup(root, lease, os_, target=target, now=now)
    except OSError as err:
        raise os_error(f"cannot back up the {target} database before migrating it", err) from err
    verify_backup(
        backup,
        expected_kind=kind,
        expected_store_id=info.store_id,
        migrations=migrations[: info.schema_version],
        os_=os_,
    )
    pending = [m for m in migrations if m.to_version > info.schema_version]
    name = source.name
    existing_epoch = (
        read_restore_epoch(root, schema_version=info.schema_version, os_=os_) if target == "store" else 0
    )

    def build(stage: Path) -> None:
        copy_database(source, stage / name, "into the migration stage")
        try:
            migrate_staged_file(stage / name, pending, os_)
        except sqlite3.Error as exc:
            raise sqlite_error(f"cannot migrate the {target} database", exc) from exc
        if target == "store":
            copy_blobs(root.cas_dir, stage / "cas", sorted(blob_digests(root.cas_dir, os_)), os_)
            new_directory(stage / "staging", os_)
            if latest >= 5:
                write_restore_epoch(stage, existing_epoch, os_)
        elif info.schema_version < 4 <= latest:
            sync_legacy_accounting_from_store(stage / name, root, now=now)
            os_.publisher.flush_file(stage / name)

    replaced = stage_and_swap(root, lease, os_, target=target, purpose="migrating", build=build, now=now)
    return MigrationReport(
        target=target, from_version=info.schema_version, to_version=latest, backup=backup, replaced_dir=replaced
    )
