"""Every storage file flush goes through ``os_.publisher.flush_file``: the snapshots, the restored policy store's
trust generation and the migrated database."""

from datetime import UTC, datetime
from pathlib import Path

from superbrain.adapters.os import os_adapters
from superbrain.storage.backup import create_maintenance_backup, create_policy_backup, create_store_backup
from superbrain.storage.migrate import migrate_database
from superbrain.storage.restore import restore_policy
from superbrain.storage.runtime import open_runtime
from superbrain.storage.schema import STORE_MIGRATIONS, Migration
from tests.storage.conftest import maintenance_lease
from tests.storage.test_layout import SyncSpy, with_sync_spy

NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
STORE_V2 = (*STORE_MIGRATIONS, Migration(to_version=2, min_reader_version=1, apply=lambda db: None))


def rel(root: Path, paths: list[Path]) -> list[str]:
    return [p.relative_to(root).as_posix() for p in paths]


def test_backups_flush_their_snapshot_through_the_publisher(trusted_tmp: Path) -> None:
    spy = SyncSpy(os_adapters().publisher)
    rt = open_runtime(trusted_tmp, with_sync_spy(spy))
    try:
        store_backup = create_store_backup(rt.store, rt.os_, NOW)
        policy_backup = create_policy_backup(rt.policy, rt.os_, NOW)
    finally:
        rt.close()
    with maintenance_lease(trusted_tmp, with_sync_spy(spy)) as (root, lease):
        full_backup = create_maintenance_backup(root, lease, with_sync_spy(spy), target="store", now=NOW)
    assert spy.flushed == [store_backup / "brain.db", policy_backup / "policy.db", full_backup / "brain.db"]


def test_policy_restore_flushes_the_staged_policy_store_through_the_publisher(trusted_tmp: Path) -> None:
    rt = open_runtime(trusted_tmp, os_adapters())
    try:
        backup = create_policy_backup(rt.policy, rt.os_, NOW)
        store_id = rt.store.store_id
    finally:
        rt.close()
    spy = SyncSpy(os_adapters().publisher)
    with maintenance_lease(trusted_tmp) as (root, lease):
        restore_policy(root, lease, with_sync_spy(spy), backup, store_id=store_id, now=NOW)
    assert rel(trusted_tmp, spy.flushed) == ["policy.restoring/policy.db"]


def test_migration_flushes_the_migrated_database_through_the_publisher(trusted_tmp: Path) -> None:
    open_runtime(trusted_tmp, os_adapters()).close()
    spy = SyncSpy(os_adapters().publisher)
    with maintenance_lease(trusted_tmp) as (root, lease):
        report = migrate_database(root, lease, with_sync_spy(spy), target="store", migrations=STORE_V2, now=NOW)
    assert rel(trusted_tmp, spy.flushed) == [
        rel(trusted_tmp, [report.backup / "brain.db"])[0],
        "store.migrating/brain.db",
    ]
