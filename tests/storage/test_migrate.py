"""Store and policy migration (spec 5.8): explicit, under the lease, backed up first, swapped in whole."""

import errno
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.storage import backup as backup_module
from superbrain.storage.backup import verify_backup
from superbrain.storage.cas import RetentionClass
from superbrain.storage.layout import DataRoot
from superbrain.storage.migrate import migrate_database
from superbrain.storage.runtime import open_runtime
from superbrain.storage.schema import POLICY_MIGRATIONS, STORE_MIGRATIONS, Migration, read_schema_info
from tests.storage.conftest import Env, maintenance_lease
from tests.support.crash import run_until_crash
from tests.support.fs import digest_tree

NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
EVENT_ID = "0192f3a4-5b6c-7d8e-9f01-000000000e01"


def add_table(db: sqlite3.Connection) -> None:
    db.execute("CREATE TABLE added_in_v2(a)")


def raise_runtime_error(db: sqlite3.Connection) -> None:
    raise RuntimeError("migration blew up")


V2 = Migration(to_version=2, min_reader_version=1, apply=add_table)
P2 = Migration(to_version=2, min_reader_version=1, apply=add_table)
STORE_V2 = (*STORE_MIGRATIONS, V2)
POLICY_V2 = (*POLICY_MIGRATIONS, P2)


def store_id_of(data_root: Path) -> str:
    info = read_schema_info(data_root / "store" / "brain.db")
    assert info is not None
    return info.store_id


def test_new_binary_meets_old_store_then_migrates(trusted_tmp: Path) -> None:
    rt = open_runtime(trusted_tmp, os_adapters())
    digest = rt.store.store_content(b"blob one", "event", EVENT_ID, RetentionClass.EVENT_PAYLOAD, None)
    rt.close()
    with pytest.raises(BrainError) as e:
        open_runtime(trusted_tmp, os_adapters(), store_migrations=STORE_V2)
    assert e.value.code == ErrorCode.MIGRATION_REQUIRED
    with maintenance_lease(trusted_tmp) as (root, lease):
        report = migrate_database(root, lease, os_adapters(), target="store", migrations=STORE_V2, now=NOW)
    assert (report.target, report.from_version, report.to_version) == ("store", 1, 2)
    verify_backup(
        report.backup,
        expected_kind="store_full",
        expected_store_id=store_id_of(trusted_tmp),
        migrations=STORE_MIGRATIONS,
    )
    assert (report.replaced_dir / "brain.db").is_file()
    rt = open_runtime(trusted_tmp, os_adapters(), store_migrations=STORE_V2)
    try:
        info = read_schema_info(rt.root.store_db)
        assert info is not None and info.schema_version == 2
        assert rt.store.cas.read(digest) == b"blob one"
    finally:
        rt.close()


def test_new_binary_meets_old_policy_then_migrates(trusted_tmp: Path) -> None:
    open_runtime(trusted_tmp, os_adapters()).close()
    with pytest.raises(BrainError) as e:
        open_runtime(trusted_tmp, os_adapters(), policy_migrations=POLICY_V2)
    assert e.value.code == ErrorCode.MIGRATION_REQUIRED
    with maintenance_lease(trusted_tmp) as (root, lease):
        report = migrate_database(root, lease, os_adapters(), target="policy", migrations=POLICY_V2, now=NOW)
    verify_backup(
        report.backup,
        expected_kind="policy",
        expected_store_id=store_id_of(trusted_tmp),
        migrations=POLICY_MIGRATIONS,
    )
    rt = open_runtime(trusted_tmp, os_adapters(), policy_migrations=POLICY_V2)
    try:
        info = read_schema_info(rt.root.policy_db)
        assert info is not None and info.schema_version == 2
    finally:
        rt.close()


def test_failed_policy_backup_leaves_policy_untouched(trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    open_runtime(trusted_tmp, os_adapters()).close()
    policy_dir = DataRoot.at(trusted_tmp).policy_dir
    before = digest_tree(policy_dir)
    calls: list[Path] = []

    def full(source: sqlite3.Connection, dest: Path) -> None:
        calls.append(dest)
        raise OSError(errno.ENOSPC, "full")

    monkeypatch.setattr(backup_module, "_snapshot_db", full)
    with maintenance_lease(trusted_tmp) as (root, lease), pytest.raises(BrainError) as e:
        migrate_database(root, lease, os_adapters(), target="policy", migrations=POLICY_V2, now=NOW)
    assert e.value.code == ErrorCode.STORAGE_FULL
    assert len(calls) == 1 and digest_tree(policy_dir) == before


def test_migration_with_open_store_is_refused(env: Env) -> None:
    with pytest.raises(BrainError) as e:
        migrate_database(env.root, env.lease, env.os_, target="store", migrations=STORE_V2, now=NOW)
    assert e.value.code == ErrorCode.STORE_BUSY


def test_migration_with_only_the_policy_open_is_refused(env: Env) -> None:
    env.store.close()
    with pytest.raises(BrainError) as e:
        migrate_database(env.root, env.lease, env.os_, target="store", migrations=STORE_V2, now=NOW)
    assert e.value.code == ErrorCode.STORE_BUSY


def test_nothing_to_migrate_and_newer_schema(trusted_tmp: Path) -> None:
    open_runtime(trusted_tmp, os_adapters()).close()
    with maintenance_lease(trusted_tmp) as (root, lease):
        with pytest.raises(BrainError) as e:
            migrate_database(root, lease, os_adapters(), target="store", migrations=STORE_MIGRATIONS, now=NOW)
        assert e.value.code == ErrorCode.INVALID_INPUT
        migrate_database(root, lease, os_adapters(), target="store", migrations=STORE_V2, now=NOW)
    with maintenance_lease(trusted_tmp) as (root, lease), pytest.raises(BrainError) as e:
        migrate_database(root, lease, os_adapters(), target="store", migrations=STORE_MIGRATIONS, now=NOW)
    assert e.value.code == ErrorCode.UNSUPPORTED_VERSION


@pytest.mark.parametrize("target", ["store", "policy"])
def test_failed_migration_leaves_target_untouched(trusted_tmp: Path, target: Literal["store", "policy"]) -> None:
    bad = Migration(to_version=2, min_reader_version=1, apply=raise_runtime_error)
    open_runtime(trusted_tmp, os_adapters()).close()
    layout = DataRoot.at(trusted_tmp)
    directory = layout.store_dir if target == "store" else layout.policy_dir
    base = STORE_MIGRATIONS if target == "store" else POLICY_MIGRATIONS
    before = digest_tree(directory)
    with maintenance_lease(trusted_tmp) as (root, lease), pytest.raises(RuntimeError):
        migrate_database(root, lease, os_adapters(), target=target, migrations=(*base, bad), now=NOW)
    assert digest_tree(directory) == before
    assert [p.name for p in trusted_tmp.iterdir() if f"{target}.migrating.abandoned-" in p.name]


@pytest.mark.parametrize(
    ("point", "expected_version"), [("migrating.store.after_stage", 1), ("migrating.store.between_renames", 2)]
)
def test_interrupted_migration_recovers(trusted_tmp: Path, point: str, expected_version: int) -> None:
    open_runtime(trusted_tmp, os_adapters()).close()
    run_until_crash("migrate_store_to_v2", point, trusted_tmp)
    with maintenance_lease(trusted_tmp) as (root, _lease):
        info = read_schema_info(root.store_db)
        assert info is not None and info.schema_version == expected_version
