"""Restore of the main store and of the policy store from a verified backup (spec 5.7).

Both verify the backup and check the open handles before anything is staged, then publish the copy with
``stage_and_swap``: the current directory is kept as ``*.replaced-*`` and nothing is deleted.

A restored store is never opened here. The next ``open_runtime`` opens the published copy, and ``Store.open``
reconciles every intent of the live policy store against the snapshot's own ``applied_intents``, so tombstones and
quarantines recorded after the backup are applied again (I1-03).

A restored policy store gets a trust generation above every earlier one, ``max(hwm, backup's, live's) + 1``,
written into the staged copy before it is published; then the lock's high-water mark is raised. A crash between the
two is reconciled by ``PolicyStore.open``, which raises the mark to a generation above it. Until then the live
policy store is ahead of the mark, which is why its own generation is part of the maximum.
"""

import os
import sqlite3
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.faults import crashpoint
from superbrain.ports.os import OsAdapters
from superbrain.storage.backup import BackupManifest, copy_blobs, new_directory, verify_backup, write_new_file
from superbrain.storage.errors import sqlite_error
from superbrain.storage.layout import DataRoot
from superbrain.storage.migrate import migrate_staged_file
from superbrain.storage.policy_store import STORE_PUBLISHED, PolicyStore
from superbrain.storage.schema import POLICY_MIGRATIONS, STORE_MIGRATIONS, Migration, SchemaInfo, _meta, code_version
from superbrain.storage.sqlite import db_files, open_immutable, open_readonly
from superbrain.storage.swap import stage_and_swap
from superbrain.storage.writer import WriterLease


@dataclass(frozen=True)
class RestoreReport:
    restored_from: Path
    replaced_dir: Path
    """Where the previous ``store/`` or ``policy/`` was kept."""
    new_epoch: int
    trust_generation: int | None
    """The restored policy store's new trust generation; ``None`` for a store restore."""


def _check_lease(root: DataRoot, lease: WriterLease) -> None:
    if not lease.held or lease.root != root:
        raise AssertionError("a restore needs a held writer lease for this data root")


def _copy_snapshot(backup: Path, name: str, manifest: BackupManifest, dest: Path, os_: OsAdapters) -> None:
    """Copy the backup's snapshot ``name`` to the new file ``dest``, durable and owner-only, checking that its
    bytes are still the verified ones."""
    try:
        data = (backup / name).read_bytes()
    except OSError as err:
        raise BrainError(ErrorCode.IO_ERROR, f"cannot read the snapshot of {backup.name}: {err}") from err
    if digest_bytes(data) != manifest.db_digest:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"the snapshot of {backup.name} changed after verification")
    write_new_file(dest, data, os_)


def _check_store_restore_fences(root: DataRoot, backup: Path, policy: PolicyStore, *, target: int) -> None:
    """Refuse store restore when ``migrations`` is older than the open policy store, backup history or live store."""
    if target < 3 and policy.schema_version > target:
        raise BrainError(
            ErrorCode.UNSUPPORTED_VERSION,
            f"the open policy store has schema {policy.schema_version}, which exceeds store code version {target}",
        )
    if target < 3:
        snapshot = backup / "brain.db"
        try:
            snap_db = open_immutable(snapshot)
            try:
                snap_row = snap_db.execute(
                    "SELECT MAX(handler_version) FROM ledger WHERE kind = 'policy.workspace_register'"
                ).fetchone()
            finally:
                snap_db.close()
        except sqlite3.Error as exc:
            raise BrainError(
                ErrorCode.INTEGRITY_FAILURE, f"cannot read the backup snapshot {snapshot}: {exc}"
            ) from exc
        snap_hv = snap_row[0] if snap_row is not None else None
        if snap_hv is not None:
            if type(snap_hv) is not int or snap_hv < 1:
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, "the backup snapshot has a corrupt handler_version")
            if snap_hv >= 2:
                raise BrainError(
                    ErrorCode.UNSUPPORTED_VERSION,
                    f"the backup {backup.name} records policy.workspace_register v{snap_hv}, "
                    "requiring store schema >= 3",
                )
    path = root.store_db
    if not os.path.lexists(path):
        return
    live_row: tuple[object, ...] | None = None
    try:
        db = open_readonly(path)
        try:
            store_info: SchemaInfo = _meta(db, path)
            if target < 3:
                live_row = db.execute(
                    "SELECT MAX(handler_version) FROM ledger WHERE kind = 'policy.workspace_register'"
                ).fetchone()
        finally:
            db.close()
    except BrainError as err:
        if target < 3 or err.code is not ErrorCode.INTEGRITY_FAILURE:
            raise
        return
    except sqlite3.OperationalError as exc:
        raise sqlite_error("cannot read the live data store before restoring it", exc) from exc
    except sqlite3.DatabaseError as exc:
        if target < 3:
            raise BrainError(
                ErrorCode.INTEGRITY_FAILURE, f"cannot read the live data store before restoring it: {exc}"
            ) from exc
        return
    except sqlite3.Error as exc:
        raise sqlite_error("cannot read the live data store before restoring it", exc) from exc
    if store_info.store_id != policy.store_id:
        raise BrainError(
            ErrorCode.INTEGRITY_FAILURE,
            f"the live data store belongs to store {store_info.store_id!r}, expected {policy.store_id!r}",
        )
    if store_info.schema_version > target or store_info.min_reader_version > target:
        raise BrainError(
            ErrorCode.UNSUPPORTED_VERSION,
            f"the live data store has schema {store_info.schema_version} "
            f"(min_reader {store_info.min_reader_version}), which exceeds code version {target}",
        )
    if target < 3:
        max_hv = live_row[0] if live_row is not None else None
        if max_hv is not None:
            if type(max_hv) is not int or max_hv < 1:
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, "the live data store has a corrupt handler_version")
            if max_hv >= 2:
                raise BrainError(
                    ErrorCode.UNSUPPORTED_VERSION,
                    f"the live data store records policy.workspace_register v{max_hv}, "
                    "requiring store schema >= 3",
                )


def restore_store(
    root: DataRoot,
    lease: WriterLease,
    os_: OsAdapters,
    backup: Path,
    policy: PolicyStore,
    now: datetime,
    *,
    migrations: Sequence[Migration] = STORE_MIGRATIONS,
) -> RestoreReport:
    """Replace ``store/`` with the ``store`` or ``store_full`` backup at ``backup``.

    The backup must verify against ``policy.store_id`` (``INTEGRITY_FAILURE`` otherwise), be logically verified and
    no newer than ``migrations`` (``UNSUPPORTED_VERSION``). An open ``store`` handle is ``STORE_BUSY``, and a live
    store or open policy store whose schema/history exceeds ``migrations`` is ``UNSUPPORTED_VERSION``; all checked
    before anything is staged. An older backup snapshot is migrated in the stage to ``code_version(migrations)``
    (same-version snapshots are copied byte-for-byte untouched). The stage receives ``brain.db``, every listed blob
    under ``cas/`` and an empty ``staging/``; reconciliation happens when the next ``open_runtime`` opens the store.
    """
    _check_lease(root, lease)
    target = code_version(migrations)
    kinds = frozenset({"store", "store_full"})
    manifest = verify_backup(
        backup, expected_kind=kinds, expected_store_id=policy.store_id, migrations=migrations, os_=os_
    )
    if not manifest.logical_verified:
        raise BrainError(
            ErrorCode.UNSUPPORTED_VERSION,
            f"the backup {backup.name} has schema {manifest.schema_version}, which this version cannot verify",
        )
    if manifest.schema_version > target:
        raise BrainError(
            ErrorCode.UNSUPPORTED_VERSION,
            f"the backup {backup.name} has schema {manifest.schema_version}, which exceeds code version {target}",
        )
    if "store" in lease.open_handles():
        raise BrainError(ErrorCode.STORE_BUSY, "the store is open; close it before restoring it")
    _check_store_restore_fences(root, backup, policy, target=target)
    pending = [m for m in migrations if m.to_version > manifest.schema_version]

    def build(stage: Path) -> None:
        staged = stage / "brain.db"
        _copy_snapshot(backup, "brain.db", manifest, staged, os_)
        if pending:
            try:
                migrate_staged_file(staged, pending, os_, flush=True)
            except sqlite3.Error as exc:
                raise sqlite_error("cannot migrate the staged data store", exc) from exc
        copy_blobs(backup / "cas", stage / "cas", manifest.blobs, os_)
        new_directory(stage / "staging", os_)

    replaced = stage_and_swap(root, lease, os_, target="store", purpose="restoring", build=build, now=now)
    return RestoreReport(restored_from=backup, replaced_dir=replaced, new_epoch=lease.epoch, trust_generation=None)


def _write_generation(path: Path, generation: int, os_: OsAdapters, *, published: bool) -> None:
    """Set the trust generation of the closed policy database ``path`` and, if ``published``, its
    ``meta.store_published`` marker (C02); then make the file durable (``os_.publisher.flush_file``). A marker the
    copy already has is kept either way: a restore never clears it."""
    try:
        db = sqlite3.connect(path, isolation_level=None)
    except sqlite3.Error as exc:
        raise sqlite_error("cannot open the staged policy store", exc) from exc
    try:
        try:
            db.execute("PRAGMA synchronous=FULL")
            if sys.platform == "darwin":
                db.execute("PRAGMA fullfsync=ON")
            rows = db.execute("UPDATE trust SET generation = ? WHERE id = 1", (generation,)).rowcount
            if published:
                db.execute(
                    "INSERT INTO meta (key, value) VALUES (?, '1') ON CONFLICT (key) DO UPDATE SET value = '1'",
                    (STORE_PUBLISHED,),
                )
        except sqlite3.Error as exc:
            raise sqlite_error("cannot write the staged trust generation", exc) from exc
        if rows != 1:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "the staged policy store has no trust row")
    finally:
        db.close()
    companions = (*db_files(path)[1:], path.with_name(f"{path.name}-journal"))
    leftovers = [p.name for p in companions if p.exists()]
    if leftovers:
        raise BrainError(ErrorCode.IO_ERROR, f"the staged policy store kept {leftovers} after closing")
    os_.publisher.flush_file(path)


def _live_policy(root: DataRoot, *, store_id: str, target: int) -> tuple[int, bool]:
    """The trust generation of the closed live ``policy.db`` and whether it holds store history: the
    ``meta.store_published`` marker or ANY intent (C02, ruling S5). Read without creating or changing any file;
    ``(0, False)`` if there is none. A ``policy.db`` that cannot be read or belongs to another store is
    ``INTEGRITY_FAILURE``; one whose schema or reader version exceeds ``target`` is ``UNSUPPORTED_VERSION``."""
    path = root.policy_db
    if not os.path.lexists(path):
        return 0, False
    try:
        db = open_readonly(path)
        try:
            info = _meta(db, path)
            if info.store_id != store_id:
                raise BrainError(
                    ErrorCode.INTEGRITY_FAILURE,
                    f"the live policy store belongs to store {info.store_id!r}, expected {store_id!r}",
                )
            if info.schema_version > target or info.min_reader_version > target:
                raise BrainError(
                    ErrorCode.UNSUPPORTED_VERSION,
                    f"the live policy store has schema {info.schema_version} "
                    f"(min_reader {info.min_reader_version}), which exceeds code version {target}",
                )
            rows = db.execute("SELECT id, generation FROM trust").fetchall()
            marked = "SELECT 1 FROM meta WHERE key = ? AND value = '1'"
            published = db.execute(marked, (STORE_PUBLISHED,)).fetchone() is not None
            published = published or db.execute("SELECT 1 FROM intents LIMIT 1").fetchone() is not None
        finally:
            db.close()
    except sqlite3.Error as exc:
        raise BrainError(
            ErrorCode.INTEGRITY_FAILURE, f"cannot read the trust generation of the live policy store: {exc}"
        ) from exc
    if (
        len(rows) != 1
        or type(rows[0][0]) is not int
        or rows[0][0] != 1
        or type(rows[0][1]) is not int
        or rows[0][1] < 1
    ):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "the live policy store has no valid trust generation")
    return rows[0][1], published


def _check_live_store_fence(root: DataRoot, *, store_id: str, target: int) -> None:
    """Refuse policy restore below v3 when the live ``store.db`` already requires the v3 policy fence."""
    if target >= 3 or not os.path.lexists(root.store_db):
        return
    path = root.store_db
    try:
        db = open_readonly(path)
        try:
            store_info = _meta(db, path)
            if store_info.store_id != store_id:
                raise BrainError(
                    ErrorCode.INTEGRITY_FAILURE,
                    f"the live data store belongs to store {store_info.store_id!r}, expected {store_id!r}",
                )
            if store_info.schema_version >= 3 or store_info.min_reader_version >= 3:
                raise BrainError(
                    ErrorCode.UNSUPPORTED_VERSION,
                    f"the live data store has schema {store_info.schema_version} "
                    f"(min_reader {store_info.min_reader_version}), requiring policy schema >= 3",
                )
            row = db.execute(
                "SELECT MAX(handler_version) FROM ledger WHERE kind = 'policy.workspace_register'"
            ).fetchone()
        finally:
            db.close()
    except sqlite3.Error as exc:
        raise BrainError(
            ErrorCode.INTEGRITY_FAILURE, f"cannot read the live data store before restoring policy: {exc}"
        ) from exc
    max_hv = row[0] if row is not None else None
    if max_hv is not None:
        if type(max_hv) is not int or max_hv < 1:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "the live data store has a corrupt handler_version")
        if max_hv >= 2:
            raise BrainError(
                ErrorCode.UNSUPPORTED_VERSION,
                f"the live data store records policy.workspace_register v{max_hv}, requiring policy schema >= 3",
            )


def restore_policy(
    root: DataRoot,
    lease: WriterLease,
    os_: OsAdapters,
    backup: Path,
    *,
    store_id: str,
    now: datetime,
    migrations: Sequence[Migration] = POLICY_MIGRATIONS,
) -> RestoreReport:
    """Replace ``policy/`` with the ``policy`` backup at ``backup``, under a trust generation above every earlier one.

    An open ``store`` or ``policy`` handle is ``STORE_BUSY``, then the backup must verify against ``store_id`` and
    the live ``policy.db``, if any, must be readable (``INTEGRITY_FAILURE``) and no newer than ``migrations``
    (``UNSUPPORTED_VERSION``); all before anything is staged. An older backup snapshot is migrated in the stage to
    ``code_version(migrations)`` before setting ``trust.generation`` above the lock's mark, the backup's and the live
    store's. The staged copy also keeps ``meta.store_published`` (C02): it is set if the backup, the live policy
    store or a published ``brain.db`` shows the store was published, and never invented on a root whose store never
    was. Afterwards the caller opens a new runtime, so the store binds to the restored policy store and reconciles.
    """
    _check_lease(root, lease)
    target = code_version(migrations)
    busy = sorted({"store", "policy"} & lease.open_handles())
    if busy:
        raise BrainError(ErrorCode.STORE_BUSY, f"close {' and '.join(busy)} before restoring the policy store")
    manifest = verify_backup(backup, expected_kind="policy", expected_store_id=store_id, migrations=migrations, os_=os_)
    if manifest.schema_version > target:
        raise BrainError(
            ErrorCode.UNSUPPORTED_VERSION,
            f"the backup {backup.name} has schema {manifest.schema_version}, which exceeds code version {target}",
        )
    if manifest.trust_generation is None:  # verify_backup requires it for a policy backup
        raise AssertionError("a verified policy backup has a trust generation")
    live_generation, live_history = _live_policy(root, store_id=store_id, target=target)
    _check_live_store_fence(root, store_id=store_id, target=target)
    generation = max(lease.state().trust_generation_hwm, manifest.trust_generation, live_generation) + 1
    # C02: never roll a store-history signal back. The backup's own marker is copied with it; the live policy's marker
    # or intents, or a published brain.db, set it in the stage, so it is atomic with the swap.
    published = live_history or os.path.lexists(root.store_db)
    pending = [m for m in migrations if m.to_version > manifest.schema_version]

    def build(stage: Path) -> None:
        staged = stage / "policy.db"
        _copy_snapshot(backup, "policy.db", manifest, staged, os_)
        if pending:
            try:
                migrate_staged_file(staged, pending, os_, flush=False)
            except sqlite3.Error as exc:
                raise sqlite_error("cannot migrate the staged policy store", exc) from exc
        _write_generation(staged, generation, os_, published=published)
        crashpoint("restoring.policy.after_generation_persist")

    replaced = stage_and_swap(root, lease, os_, target="policy", purpose="restoring", build=build, now=now)
    crashpoint("restoring.policy.before_hwm_update")
    lease.raise_trust_hwm(generation)
    return RestoreReport(
        restored_from=backup, replaced_dir=replaced, new_epoch=lease.epoch, trust_generation=generation
    )
