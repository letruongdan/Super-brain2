from collections.abc import Callable
from pathlib import Path
from typing import NoReturn

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.storage.kinds import KindRegistry
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.runtime import open_runtime
from superbrain.storage.schema import STORE_MIGRATIONS, Migration
from superbrain.storage.store import Store
from tests.storage.conftest import DEMO_KINDS, CounterProjection, counter, maintenance_lease
from tests.support.crash import run_child
from tests.support.fs import digest_tree

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
    rt = open_runtime(trusted_tmp, os_adapters())
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
    rt = open_runtime(trusted_tmp / "r", os_adapters(), handlers=[CounterProjection()], kinds=KindRegistry(DEMO_KINDS))
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
    rt = open_runtime(trusted_tmp / "r", os_adapters())
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
