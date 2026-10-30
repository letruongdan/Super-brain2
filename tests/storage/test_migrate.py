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
from superbrain.storage import migrate as migrate_module
from superbrain.storage.backup import verify_backup
from superbrain.storage.cas import RetentionClass
from superbrain.storage.layout import DataRoot
from superbrain.storage.migrate import _configure, migrate_database
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


def add_table_v3(db: sqlite3.Connection) -> None:
    db.execute("CREATE TABLE added_in_v3(a)")


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


def meta_of(path: Path) -> tuple[str, str]:
    db = sqlite3.connect(path)
    try:
        rows = dict(db.execute("SELECT key, value FROM meta").fetchall())
    finally:
        db.close()
    return rows["schema_version"], rows["min_reader_version"]


def test_failed_backup_verification_stops_before_staging(trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    open_runtime(trusted_tmp, os_adapters()).close()
    store_dir = DataRoot.at(trusted_tmp).store_dir
    before = digest_tree(store_dir)
    boom = BrainError(ErrorCode.INTEGRITY_FAILURE, "injected verification failure")

    def fail(*args: object, **kwargs: object) -> None:
        raise boom

    monkeypatch.setattr(migrate_module, "verify_backup", fail)
    with maintenance_lease(trusted_tmp) as (root, lease), pytest.raises(BrainError) as e:
        migrate_database(root, lease, os_adapters(), target="store", migrations=STORE_V2, now=NOW)
    assert e.value is boom
    assert not [p for p in trusted_tmp.iterdir() if ".migrating" in p.name]
    assert digest_tree(store_dir) == before


def test_backup_is_verified_against_the_old_schema(trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    open_runtime(trusted_tmp, os_adapters()).close()
    seen: list[tuple[Migration, ...]] = []
    original = verify_backup

    def spy(path: Path, **kwargs: object) -> object:
        seen.append(tuple(kwargs["migrations"]))  # type: ignore[arg-type]
        return original(path, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(migrate_module, "verify_backup", spy)
    with maintenance_lease(trusted_tmp) as (root, lease):
        migrate_database(root, lease, os_adapters(), target="store", migrations=STORE_V2, now=NOW)
    assert seen == [STORE_MIGRATIONS]


def test_migrating_across_versions_sets_min_reader_version(trusted_tmp: Path) -> None:
    v2 = Migration(to_version=2, min_reader_version=1, apply=add_table)
    v3 = Migration(to_version=3, min_reader_version=2, apply=add_table_v3)
    all_three = (*STORE_MIGRATIONS, v2, v3)
    open_runtime(trusted_tmp, os_adapters()).close()
    with maintenance_lease(trusted_tmp) as (root, lease):
        report = migrate_database(root, lease, os_adapters(), target="store", migrations=all_three, now=NOW)
    assert (report.from_version, report.to_version) == (1, 3)
    assert meta_of(DataRoot.at(trusted_tmp).store_db) == ("3", "2")
    with pytest.raises(BrainError) as e:
        open_runtime(trusted_tmp, os_adapters(), store_migrations=STORE_MIGRATIONS)
    assert e.value.code == ErrorCode.UNSUPPORTED_VERSION
    open_runtime(trusted_tmp, os_adapters(), store_migrations=all_three).close()


def test_migration_connection_has_the_global_pragmas(tmp_path: Path) -> None:
    for platform, expected in (("darwin", 1), ("linux", 0)):
        db = sqlite3.connect(tmp_path / f"{platform}.db")
        _configure(db, platform)
        assert db.execute("PRAGMA secure_delete").fetchone()[0] == 1
        assert db.execute("PRAGMA synchronous").fetchone()[0] == 2
        assert db.execute("PRAGMA fullfsync").fetchone()[0] == expected
        assert db.execute("PRAGMA checkpoint_fullfsync").fetchone()[0] == expected
        db.close()


def test_default_migrations_follow_the_target(trusted_tmp: Path) -> None:
    open_runtime(trusted_tmp, os_adapters()).close()
    with maintenance_lease(trusted_tmp) as (root, lease), pytest.raises(BrainError) as e:
        migrate_database(root, lease, os_adapters(), target="policy", now=NOW)
    assert e.value.code == ErrorCode.INVALID_INPUT and "nothing to migrate" in e.value.message


def test_sqlite_error_in_a_migration_is_an_integrity_failure(trusted_tmp: Path) -> None:
    def bad_sql(db: sqlite3.Connection) -> None:
        db.execute("CREATE TABLE ledger(a)")  # already exists in v1

    bad = Migration(to_version=2, min_reader_version=1, apply=bad_sql)
    open_runtime(trusted_tmp, os_adapters()).close()
    before = digest_tree(DataRoot.at(trusted_tmp).store_dir)
    with maintenance_lease(trusted_tmp) as (root, lease), pytest.raises(BrainError) as e:
        migrate_database(root, lease, os_adapters(), target="store", migrations=(*STORE_MIGRATIONS, bad), now=NOW)
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE and e.value.message.startswith("migration v2 failed")
    assert isinstance(e.value.__cause__, sqlite3.Error)
    assert digest_tree(DataRoot.at(trusted_tmp).store_dir) == before


def test_failed_rollback_does_not_mask_the_original_error(tmp_path: Path) -> None:
    path = tmp_path / "x.db"
    db = sqlite3.connect(path, isolation_level=None)
    db.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    db.close()

    class FlakyDb:
        """Wraps a connection; ROLLBACK fails."""

        def __init__(self) -> None:
            self.db = sqlite3.connect(path, isolation_level=None)

        @property
        def in_transaction(self) -> bool:
            return True

        def execute(self, sql: str, *params: object) -> sqlite3.Cursor:
            if sql == "ROLLBACK":
                raise sqlite3.OperationalError("rollback broke")
            return self.db.execute(sql, *params)  # type: ignore[arg-type]

    flaky = FlakyDb()
    with pytest.raises(RuntimeError) as e:
        migrate_module._apply(flaky, [Migration(to_version=2, min_reader_version=1, apply=raise_runtime_error)])  # type: ignore[arg-type]
    assert any("rollback broke" in n for n in e.value.__notes__)
    flaky.db.close()


def test_failed_integrity_check_is_caught(trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    open_runtime(trusted_tmp, os_adapters()).close()
    before = digest_tree(DataRoot.at(trusted_tmp).store_dir)
    monkeypatch.setattr(migrate_module, "_integrity_report", lambda db: "not ok")
    with maintenance_lease(trusted_tmp) as (root, lease), pytest.raises(BrainError) as e:
        migrate_database(root, lease, os_adapters(), target="store", migrations=STORE_V2, now=NOW)
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE
    assert digest_tree(DataRoot.at(trusted_tmp).store_dir) == before


def test_replaced_dir_is_byte_identical_to_the_old_store(trusted_tmp: Path) -> None:
    rt = open_runtime(trusted_tmp, os_adapters())
    rt.store.store_content(b"blob one", "event", EVENT_ID, RetentionClass.EVENT_PAYLOAD, None)
    rt.close()
    before = digest_tree(DataRoot.at(trusted_tmp).store_dir)
    with maintenance_lease(trusted_tmp) as (root, lease):
        report = migrate_database(root, lease, os_adapters(), target="store", migrations=STORE_V2, now=NOW)
    assert digest_tree(report.replaced_dir) == before
