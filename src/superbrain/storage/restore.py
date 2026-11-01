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
from superbrain.storage.cas import check_container
from superbrain.storage.errors import sqlite_error
from superbrain.storage.layout import DataRoot
from superbrain.storage.policy_store import STORE_PUBLISHED, PolicyStore
from superbrain.storage.schema import POLICY_MIGRATIONS, STORE_MIGRATIONS, Migration
from superbrain.storage.sqlite import open_readonly
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

    The backup must verify against ``policy.store_id`` (``INTEGRITY_FAILURE`` otherwise) and be logically verified:
    a ``store_full`` whose schema ``migrations`` cannot read is ``UNSUPPORTED_VERSION``. An open ``store`` handle is
    ``STORE_BUSY``. All three are checked before anything is staged. The stage receives ``brain.db``, every listed
    blob under ``cas/`` and an empty ``staging/``; it is not opened, and reconciliation happens when the next
    ``open_runtime`` opens the published store.
    """
    _check_lease(root, lease)
    kinds = frozenset({"store", "store_full"})
    _check_backup_directories(backup, os_)
    manifest = verify_backup(backup, expected_kind=kinds, expected_store_id=policy.store_id, migrations=migrations)
    if not manifest.logical_verified:
        raise BrainError(
            ErrorCode.UNSUPPORTED_VERSION,
            f"the backup {backup.name} has schema {manifest.schema_version}, which this version cannot verify",
        )
    if "store" in lease.open_handles():
        raise BrainError(ErrorCode.STORE_BUSY, "the store is open; close it before restoring it")

    def build(stage: Path) -> None:
        _copy_snapshot(backup, "brain.db", manifest, stage / "brain.db", os_)
        copy_blobs(backup / "cas", stage / "cas", manifest.blobs, os_)
        new_directory(stage / "staging", os_)

    replaced = stage_and_swap(root, lease, os_, target="store", purpose="restoring", build=build, now=now)
    return RestoreReport(restored_from=backup, replaced_dir=replaced, new_epoch=lease.epoch, trust_generation=None)


def _check_backup_directories(backup: Path, os_: OsAdapters) -> None:
    """The backup directory and its ``cas/`` container (if any) pass ``check_container`` before anything in the
    backup is read or copied (spec 5.9: backups are owner-only; C04). Shards and blobs are checked by ``copy_blobs``."""
    check_container(backup, os_)
    if os.path.lexists(backup / "cas"):
        check_container(backup / "cas", os_)


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
    companions = (path.with_name(f"{path.name}-journal"), path.with_name(f"{path.name}-wal"))
    leftovers = [p.name for p in companions if p.exists()]
    if leftovers:
        raise BrainError(ErrorCode.IO_ERROR, f"the staged policy store kept {leftovers} after closing")
    os_.publisher.flush_file(path)


def _live_policy(root: DataRoot) -> tuple[int, bool]:
    """The trust generation and ``meta.store_published`` marker of the closed live ``policy.db``, read without
    creating or changing any file; ``(0, False)`` if there is none. A ``policy.db`` that cannot be read is
    ``INTEGRITY_FAILURE``: guessing could reuse a generation or drop the marker."""
    path = root.policy_db
    if not os.path.lexists(path):
        return 0, False
    try:
        db = open_readonly(path)
        try:
            rows = db.execute("SELECT generation FROM trust WHERE id = 1").fetchall()
            marked = "SELECT 1 FROM meta WHERE key = ? AND value = '1'"
            published = db.execute(marked, (STORE_PUBLISHED,)).fetchone() is not None
        finally:
            db.close()
    except sqlite3.Error as exc:
        raise BrainError(
            ErrorCode.INTEGRITY_FAILURE, f"cannot read the trust generation of the live policy store: {exc}"
        ) from exc
    if len(rows) != 1 or type(rows[0][0]) is not int or rows[0][0] < 1:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "the live policy store has no valid trust generation")
    return rows[0][0], published


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
    the live ``policy.db``, if any, must be readable (``INTEGRITY_FAILURE``); all before anything is staged. The new
    generation is above the lock's mark, the backup's and the live store's: after a crash before the mark was
    raised, the live store is ahead of it. The staged copy also keeps ``meta.store_published`` (C02): it is set if the
    backup, the live policy store or a published ``brain.db`` shows the store was published, and never invented on a
    root whose store never was. Afterwards the caller opens a new runtime, so the store binds to the restored policy
    store and reconciles against it.
    """
    _check_lease(root, lease)
    busy = sorted({"store", "policy"} & lease.open_handles())
    if busy:
        raise BrainError(ErrorCode.STORE_BUSY, f"close {' and '.join(busy)} before restoring the policy store")
    _check_backup_directories(backup, os_)
    manifest = verify_backup(backup, expected_kind="policy", expected_store_id=store_id, migrations=migrations)
    if manifest.trust_generation is None:  # verify_backup requires it for a policy backup
        raise AssertionError("a verified policy backup has a trust generation")
    live_generation, live_published = _live_policy(root)
    generation = max(lease.state().trust_generation_hwm, manifest.trust_generation, live_generation) + 1
    # C02: never roll the published-store marker back. The backup's own marker is copied with it; the live policy's,
    # or a published brain.db, sets it in the stage, so it is atomic with the swap.
    published = live_published or os.path.lexists(root.store_db)

    def build(stage: Path) -> None:
        staged = stage / "policy.db"
        _copy_snapshot(backup, "policy.db", manifest, staged, os_)
        _write_generation(staged, generation, os_, published=published)
        crashpoint("restoring.policy.after_generation_persist")

    replaced = stage_and_swap(root, lease, os_, target="policy", purpose="restoring", build=build, now=now)
    crashpoint("restoring.policy.before_hwm_update")
    lease.raise_trust_hwm(generation)
    return RestoreReport(
        restored_from=backup, replaced_dir=replaced, new_epoch=lease.epoch, trust_generation=generation
    )
