from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import NoReturn

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.ports.policy import IntentKind
from superbrain.storage.backup import create_maintenance_backup, create_policy_backup, create_store_backup
from superbrain.storage.kinds import KindRegistry
from superbrain.storage.layout import DataRoot
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.runtime import open_runtime
from superbrain.storage.schema import STORE_MIGRATIONS, Migration
from superbrain.storage.store import Store
from tests.storage.conftest import DEMO_KINDS, CounterProjection, counter, maintenance_lease
from tests.support.crash import run_child
from tests.support.fs import digest_tree
from tests.support.inc2_fixture import open_cloned_runtime

STORE_V2 = (*STORE_MIGRATIONS, Migration(to_version=2, min_reader_version=1, apply=lambda db: None))


def raising(err: BaseException) -> Callable[..., NoReturn]:
    def fn(*_args: object, **_kwargs: object) -> NoReturn:
        raise err

    return fn


def writer_is_free(data_root: Path) -> bool:
    result = run_child("acquire_writer", data_root)
    return result.returncode == 0 and result.error_code is None


# --- trust generation ------------------------------------------------------------------------------------------


def test_policy_generation_below_lock_hwm_is_raised_above_it(trusted_tmp: Path) -> None:
    rt = open_cloned_runtime(trusted_tmp, os_adapters(), role="runtime-test")
    assert rt.policy.trust_generation() == 1
    rt.lease.raise_trust_hwm(10)
    rt.close()
    rt = open_runtime(trusted_tmp, os_adapters())
    assert rt.policy.trust_generation() == 11 and rt.lease.state().trust_generation_hwm == 11
    rt.close()


# --- binding and order -----------------------------------------------------------------------------------------


def test_open_runtime_on_fresh_root_binds_store_to_policy(trusted_tmp: Path) -> None:
    rt = open_runtime(trusted_tmp / "r", os_adapters())
    assert rt.store.store_id == rt.policy.store_id
    assert rt.lease.open_handles() == frozenset({"store", "policy"})
    assert rt.root.store_db.exists() and rt.root.policy_db.exists()
    rt.close()
    rt = open_runtime(trusted_tmp / "r", os_adapters())
    assert rt.store.store_id == rt.policy.store_id
    rt.close()


def test_missing_policy_store_next_to_an_existing_store_is_refused_before_creating(trusted_tmp: Path) -> None:
    open_runtime(trusted_tmp / "r", os_adapters()).close()
    with maintenance_lease(trusted_tmp / "r") as (root, _lease):
        for path in (root.policy_db, *(root.policy_dir / f"policy.db{s}" for s in ("-wal", "-shm"))):
            path.unlink(missing_ok=True)
        store_before = digest_tree(root.store_dir)
    with pytest.raises(BrainError) as e:
        open_runtime(trusted_tmp / "r", os_adapters())
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE
    assert e.value.message == "policy store missing for an existing data store; restore a policy backup"
    assert list(root.policy_dir.iterdir()) == []  # no policy.db, no creating-* leftover
    assert digest_tree(root.store_dir) == store_before
    assert writer_is_free(trusted_tmp / "r")


def test_runtime_forwards_handlers_and_kinds(trusted_tmp: Path) -> None:
    rt = open_cloned_runtime(
        trusted_tmp / "r",
        os_adapters(),
        role="runtime-test",
        handlers=[CounterProjection()],
        kinds=KindRegistry(DEMO_KINDS),
    )
    with rt.store.transaction() as t:
        t.append("demo.count", actor="user:cli", owner_id="dan", meta={"n": 1})
    assert counter(rt.store) == 1
    rt.close()


def test_runtime_forwards_store_migrations(trusted_tmp: Path) -> None:
    open_runtime(trusted_tmp / "r", os_adapters(), store_migrations=STORE_V2).close()
    with pytest.raises(BrainError) as e:
        open_runtime(trusted_tmp / "r", os_adapters())
    assert e.value.code == ErrorCode.UNSUPPORTED_VERSION and writer_is_free(trusted_tmp / "r")
    open_runtime(trusted_tmp / "r", os_adapters(), store_migrations=STORE_V2).close()


# --- failure and close -----------------------------------------------------------------------------------------


def test_failed_open_releases_lease(trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Store, "open", raising(BrainError(ErrorCode.INTEGRITY_FAILURE, "x")))
    open_runtime(trusted_tmp, os_adapters()).close()  # the first run creates, so Store.open is not called
    with pytest.raises(BrainError):
        open_runtime(trusted_tmp, os_adapters())
    assert run_child("acquire_writer", trusted_tmp).error_code is None


def test_failed_store_create_closes_the_policy_store(trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    opened: list[PolicyStore] = []
    real_create = PolicyStore.create

    def create(*args: object, **kwargs: object) -> PolicyStore:
        policy = real_create(*args, **kwargs)  # type: ignore[arg-type]
        opened.append(policy)
        return policy

    monkeypatch.setattr(PolicyStore, "create", create)
    monkeypatch.setattr(Store, "create", raising(BrainError(ErrorCode.IO_ERROR, "injected")))
    with pytest.raises(BrainError, match="injected"):
        open_runtime(trusted_tmp / "r", os_adapters())
    assert len(opened) == 1 and opened[0].closed and writer_is_free(trusted_tmp / "r")
    monkeypatch.undo()
    rt = open_runtime(trusted_tmp / "r", os_adapters())  # the policy store from the failed run is reused
    assert rt.store.store_id == rt.policy.store_id
    rt.close()


def test_failed_policy_open_releases_lease(trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    open_runtime(trusted_tmp / "r", os_adapters()).close()
    monkeypatch.setattr(PolicyStore, "open", raising(BrainError(ErrorCode.MIGRATION_REQUIRED, "injected")))
    with pytest.raises(BrainError) as e:
        open_runtime(trusted_tmp / "r", os_adapters())
    assert e.value.code == ErrorCode.MIGRATION_REQUIRED and writer_is_free(trusted_tmp / "r")


def test_close_is_ordered_and_idempotent(trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rt = open_runtime(trusted_tmp / "r", os_adapters())
    order: list[str] = []

    def spy(name: str, real: Callable[[], None]) -> Callable[[], None]:
        def close() -> None:
            order.append(name)
            real()

        return close

    monkeypatch.setattr(rt.store, "close", spy("store", rt.store.close))
    monkeypatch.setattr(rt.policy, "close", spy("policy", rt.policy.close))
    rt.close()
    assert order == ["store", "policy"] and rt.store.closed and rt.policy.closed and not rt.lease.held
    rt.close()
    assert order == ["store", "policy"] and writer_is_free(trusted_tmp / "r")


def test_runtime_holds_the_writer_lock(trusted_tmp: Path) -> None:
    rt = open_cloned_runtime(trusted_tmp / "r", os_adapters(), role="runtime-test")
    try:
        assert run_child("acquire_writer", trusted_tmp / "r").error_code == ErrorCode.WRITER_HELD.value
    finally:
        rt.close()
    assert writer_is_free(trusted_tmp / "r")


def test_maintenance_lease_opens_no_database(trusted_tmp: Path) -> None:
    with maintenance_lease(trusted_tmp / "r") as (root, lease):
        assert lease.held and lease.open_handles() == frozenset()
        assert all(directory.is_dir() for directory in root.subdirectories())
        assert not root.policy_db.exists() and not root.store_db.exists()
        assert run_child("acquire_writer", trusted_tmp / "r").error_code == ErrorCode.WRITER_HELD.value
    assert not lease.held and writer_is_free(trusted_tmp / "r")


@pytest.mark.parametrize("failing", ["store", "policy"])
def test_failed_close_keeps_the_writer_lock(trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, failing: str) -> None:
    rt = open_cloned_runtime(trusted_tmp / "r", os_adapters(), role="runtime-test")
    handle = rt.store if failing == "store" else rt.policy
    monkeypatch.setattr(handle, "close", raising(BrainError(ErrorCode.IO_ERROR, "injected")))
    with pytest.raises(BrainError, match="injected"):
        rt.close()
    # A handle may still be open: another process must not become the writer.
    assert rt.lease.held and run_child("acquire_writer", trusted_tmp / "r").error_code == ErrorCode.WRITER_HELD.value
    assert rt.store.closed == (failing == "policy") and rt.policy.closed == (failing == "store")
    monkeypatch.undo()
    rt.close()
    assert rt.store.closed and rt.policy.closed and not rt.lease.held and writer_is_free(trusted_tmp / "r")
    rt.close()


def test_failed_open_releases_the_lease_even_when_closing_the_policy_store_breaks(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    open_runtime(trusted_tmp / "r", os_adapters()).close()
    real_close = PolicyStore.close

    def close(self: PolicyStore) -> None:
        real_close(self)
        raise RuntimeError("close bug")

    monkeypatch.setattr(Store, "open", raising(BrainError(ErrorCode.INTEGRITY_FAILURE, "original")))
    monkeypatch.setattr(PolicyStore, "close", close)
    with pytest.raises(RuntimeError, match="close bug") as e:
        open_runtime(trusted_tmp / "r", os_adapters())
    original = e.value.__context__
    assert isinstance(original, BrainError) and original.message == "original"
    assert writer_is_free(trusted_tmp / "r")


def test_missing_policy_store_is_refused_before_any_subdirectory_is_created(trusted_tmp: Path) -> None:
    open_runtime(trusted_tmp / "r", os_adapters()).close()
    with maintenance_lease(trusted_tmp / "r") as (root, _lease):
        for path in (root.policy_db, *(root.policy_dir / f"policy.db{s}" for s in ("-wal", "-shm"))):
            path.unlink(missing_ok=True)
        for directory in (root.outbox_dir, root.logs_dir):
            directory.rmdir()
    with pytest.raises(BrainError) as e:
        open_runtime(trusted_tmp / "r", os_adapters())
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE
    assert not root.outbox_dir.exists() and not root.logs_dir.exists()


# --- single writer across modules ------------------------------------------------------------------------------


def test_releasing_the_lease_under_open_stores_is_refused(trusted_tmp: Path) -> None:
    rt = open_cloned_runtime(trusted_tmp / "r", os_adapters(), role="runtime-test", kinds=KindRegistry(DEMO_KINDS))
    try:
        with pytest.raises(AssertionError, match="open handles"):
            rt.lease.release()
        assert rt.lease.held
        assert run_child("acquire_writer", trusted_tmp / "r").error_code == ErrorCode.WRITER_HELD.value
        with rt.store.transaction() as t:
            t.append("demo.count", actor="user:cli", owner_id="dan", meta={"n": 1})
    finally:
        rt.close()
    assert not rt.lease.held and writer_is_free(trusted_tmp / "r")


def test_stores_refuse_work_once_their_lease_was_released(trusted_tmp: Path) -> None:
    rt = open_cloned_runtime(trusted_tmp / "r", os_adapters(), role="runtime-test", kinds=KindRegistry(DEMO_KINDS))
    for name in ("store", "policy"):
        rt.lease.unregister_handle(name)  # the only way around the release guard: forge a closed bookkeeping
    rt.lease.release()
    try:
        with pytest.raises(AssertionError, match="lease"):
            rt.store.transaction()
        with pytest.raises(AssertionError, match="lease"):
            rt.store.entries()
        with pytest.raises(AssertionError, match="lease"):
            rt.policy.intents()
        with pytest.raises(AssertionError, match="lease"):
            rt.policy.trust_generation()
    finally:
        rt.store._db.close()
        rt.policy._db.close()
    assert writer_is_free(trusted_tmp / "r")


# --- missing data store next to history (M9) -------------------------------------------------------------------

E1 = "0192f3a4-5b6c-7d8e-9f01-000000000001"
NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)


def lose_the_data_store(data_root: Path) -> DataRoot:
    """Delete ``brain.db`` (and its ``-wal``/``-shm``) plus two subdirectories, so a re-creation would show."""
    with maintenance_lease(data_root) as (root, _lease):
        for path in (root.store_db, *(root.store_dir / f"brain.db{s}" for s in ("-wal", "-shm"))):
            path.unlink(missing_ok=True)
        for directory in (root.outbox_dir, root.logs_dir):
            directory.rmdir()
    return root


def assert_refused_before_creating(data_root: Path, root: DataRoot) -> None:
    before = digest_tree(root.policy_dir)
    with pytest.raises(BrainError) as e:
        open_runtime(data_root, os_adapters())
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE
    assert "data store missing for a policy store with history; restore a store backup" in e.value.message
    assert not root.store_db.exists() and not root.outbox_dir.exists() and not root.logs_dir.exists()
    assert digest_tree(root.policy_dir) == before and writer_is_free(data_root)


def test_missing_data_store_next_to_policy_intents_is_refused(trusted_tmp: Path) -> None:
    rt = open_cloned_runtime(trusted_tmp / "r", os_adapters(), role="runtime-test")
    try:
        rt.policy.record_intent(IntentKind.TOMBSTONE, {"holder_kind": "event", "holder_id": E1})
    finally:
        rt.close()
    assert_refused_before_creating(trusted_tmp / "r", lose_the_data_store(trusted_tmp / "r"))


@pytest.mark.parametrize("kind", ["store", "store_full"])
def test_missing_data_store_next_to_a_complete_store_backup_is_refused(trusted_tmp: Path, kind: str) -> None:
    rt = open_cloned_runtime(trusted_tmp / "r", os_adapters(), role="runtime-test")
    try:
        if kind == "store":
            create_store_backup(rt.store, rt.os_, NOW)
    finally:
        rt.close()
    if kind == "store_full":
        with maintenance_lease(trusted_tmp / "r") as (root, lease):
            create_maintenance_backup(root, lease, os_adapters(), target="store", now=NOW)
    assert_refused_before_creating(trusted_tmp / "r", lose_the_data_store(trusted_tmp / "r"))


def test_missing_data_store_without_history_is_created(trusted_tmp: Path) -> None:
    """A store that was never published has no history: a policy backup and an incomplete store backup do not count.

    Round 2 (controller ruling of 2026-10-31 on C02): once a store was published, losing ``brain.db`` is refused even
    without other evidence (``test_remediation_c02_lost_main_db.py``). So the policy store here is created on its own
    and ``brain.db`` was never published; before the ruling this test published a store and then deleted it.
    """
    with maintenance_lease(trusted_tmp / "r") as (root, lease):
        policy = PolicyStore.create(root, lease, os_adapters(), store_id=new_id())
        try:
            create_policy_backup(policy, os_adapters(), NOW)  # a policy backup is not store history
            store_id = policy.store_id
        finally:
            policy.close()
    assert not root.store_db.exists()
    (root.backups_dir / f"store-20261030T120000Z-{E1}").mkdir()  # incomplete: no manifest
    rt = open_runtime(trusted_tmp / "r", os_adapters())
    try:
        assert rt.store.store_id == store_id and list(rt.store.entries()) == []
    finally:
        rt.close()
