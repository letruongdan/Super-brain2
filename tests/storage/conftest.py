"""Storage fixtures: a FakeClock-backed ``os_``, a ``StaticPolicy`` double, a demo projection, store factories,
the ``env`` runtime fixture and ``maintenance_lease``."""

import contextlib
import os
import shutil
import sqlite3
import threading
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.ports.os import OsAdapters
from superbrain.ports.policy import Intent, PolicyView
from superbrain.storage.kinds import CORE_KINDS, EntryKind, FieldType, KindRegistry
from superbrain.storage.layout import DataRoot, prepare_data_root, secure_subdirectories
from superbrain.storage.ledger import LedgerEntry, ProjectionHandler
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.runtime import Runtime
from superbrain.storage.schema import POLICY_MIGRATIONS, STORE_MIGRATIONS
from superbrain.storage.store import Store
from superbrain.storage.swap import recover_interrupted_swaps
from superbrain.storage.writer import WriterLease, acquire_writer
from tests.support.clock import FakeClock
from tests.support.crash import run_child
from tests.support.inc2_fixture import (
    ensure_template_base,
    kind_registry_signature,
    open_cloned_runtime,
    uses_real_adapters,
)

STORE_ID = "store-test-0001"
CLOCK_START = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
DEMO_KINDS: tuple[EntryKind, ...] = (*CORE_KINDS, EntryKind("demo.count", 1, {"n": FieldType.INT}, {}))


@dataclass
class StaticPolicy:
    """``PolicySource`` test double with fixed answers."""

    store_id: str = STORE_ID
    quarantined: list[str] = field(default_factory=list)
    tombstoned: list[tuple[str, str]] = field(default_factory=list)
    queued_intents: list[Intent] = field(default_factory=list)

    def is_quarantined(self, digest: str) -> bool:
        return digest in self.quarantined

    def is_tombstoned(self, holder_kind: str, holder_id: str) -> bool:
        return (holder_kind, holder_id) in self.tombstoned

    def intents(self) -> Sequence[Intent]:
        return tuple(self.queued_intents)


class CounterProjection:
    """Counts ``demo.count`` entries: applying one entry twice would show up as a double count."""

    name = "counter"
    handler_version = 1
    kinds = frozenset({"demo.count"})

    def create_tables(self, db: sqlite3.Connection, prefix: str) -> None:
        db.execute(f"CREATE TABLE {prefix}state (k INTEGER PRIMARY KEY CHECK (k = 1), entries INTEGER NOT NULL)")
        db.execute(f"INSERT INTO {prefix}state (k, entries) VALUES (1, 0)")

    def apply(self, db: sqlite3.Connection, prefix: str, entry: LedgerEntry, policy: PolicyView) -> None:
        db.execute(f"UPDATE {prefix}state SET entries = entries + 1 WHERE k = 1")


def counter(store: Store) -> int:
    with store.transaction() as t:
        row = t.db.execute("SELECT entries FROM p_counter_state WHERE k = 1").fetchone()
    assert row is not None
    return int(row[0])


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock(CLOCK_START)


@pytest.fixture
def os_(clock: FakeClock) -> OsAdapters:
    return os_adapters(clock=clock)


class _Opened:
    """Stores and leases opened by a test, closed and released at teardown."""

    def __init__(self) -> None:
        self.stores: list[Store] = []
        self.leases: list[WriterLease] = []

    def close_all(self) -> None:
        for store in self.stores:
            if not store.closed:
                store.close()
        for lease in self.leases:
            lease.release()


@pytest.fixture
def _opened() -> Iterator[_Opened]:
    opened = _Opened()
    yield opened
    opened.close_all()


_STORE_DB_LOCK = threading.Lock()
_STORE_DB_CACHE: dict[tuple[object, ...], Path] = {}
_STORE_DB_COUNTER = 0


def _cached_store_db_template(policy_obj: StaticPolicy, kinds_obj: KindRegistry) -> Path | None:
    """Return a closed pristine ``brain.db`` template path for ``(policy_obj.store_id, kinds_obj)``."""
    global _STORE_DB_COUNTER
    key: tuple[object, ...] = (policy_obj.store_id, kind_registry_signature(kinds_obj))
    with _STORE_DB_LOCK:
        tpl_db = _STORE_DB_CACHE.get(key)
        if tpl_db is not None and tpl_db.is_file():
            return tpl_db
        if len(_STORE_DB_CACHE) >= 16:
            return None
        base = ensure_template_base()
        _STORE_DB_COUNTER += 1
        seed_os = os_adapters(clock=FakeClock(CLOCK_START))
        tpl_root = prepare_data_root(base / f"store-tpl-{_STORE_DB_COUNTER}", seed_os)
        tpl_lease = acquire_writer(tpl_root, seed_os)
        try:
            secure_subdirectories(tpl_root, tpl_lease, seed_os)
            tpl_store = Store.create(
                tpl_root,
                tpl_lease,
                seed_os,
                StaticPolicy(store_id=policy_obj.store_id),
                (),
                kinds_obj,
            )
            tpl_store.close()
        finally:
            tpl_lease.release()
        tpl_db = tpl_root.store_db
        _STORE_DB_CACHE[key] = tpl_db
        return tpl_db


StoreFactory = Callable[..., Store]


@pytest.fixture
def store_factory(trusted_tmp: Path, os_: OsAdapters, _opened: _Opened) -> StoreFactory:
    """``store_factory(handlers=(), policy=None, kinds=None)``: a new store in a fresh data root."""
    count = 0

    def make(
        handlers: Sequence[ProjectionHandler] = (),
        policy: StaticPolicy | None = None,
        kinds: KindRegistry | None = None,
    ) -> Store:
        nonlocal count
        count += 1
        root = prepare_data_root(trusted_tmp / f"root{count}", os_)
        lease = acquire_writer(root, os_)
        _opened.leases.append(lease)
        secure_subdirectories(root, lease, os_)
        policy_obj = policy or StaticPolicy()
        kinds_obj = kinds or KindRegistry(DEMO_KINDS)
        tpl_db: Path | None = None
        if (
            not handlers
            and type(policy_obj) is StaticPolicy
            and type(kinds_obj) is KindRegistry
            and uses_real_adapters(os_)
            and not os.path.lexists(root.store_db)
        ):
            tpl_db = _cached_store_db_template(policy_obj, kinds_obj)
        if tpl_db is not None:
            shutil.copyfile(tpl_db, root.store_db)
            os_.permissions.secure_file(root.store_db)
            store = Store.open(root, lease, os_, policy_obj, (), kinds_obj)
        else:
            store = Store.create(root, lease, os_, policy_obj, handlers, kinds_obj)
        _opened.stores.append(store)
        return store

    return make


def seed_store(data_root: Path) -> None:
    """Create a store at ``data_root`` in a child process (the writer lock is per process)."""
    result = run_child("create_store", data_root, STORE_ID)
    assert result.returncode == 0, f"create_store failed:\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"


@pytest.fixture
def reopen(os_: OsAdapters, _opened: _Opened) -> Callable[..., Store]:
    """``reopen(data_root, handlers=(), policy=None)``: open the existing store in this process."""

    def open_(data_root: Path, handlers: Sequence[ProjectionHandler] = (), policy: StaticPolicy | None = None) -> Store:
        root = prepare_data_root(data_root, os_)
        lease = acquire_writer(root, os_)
        _opened.leases.append(lease)
        secure_subdirectories(root, lease, os_)
        store = Store.open(root, lease, os_, policy or StaticPolicy(), handlers, KindRegistry(DEMO_KINDS))
        _opened.stores.append(store)
        return store

    return open_


@dataclass(frozen=True)
class Env:
    """A runtime opened by ``open_runtime`` on a FakeClock, with that clock."""

    runtime: Runtime
    clock: FakeClock

    @property
    def root(self) -> DataRoot:
        return self.runtime.root

    @property
    def lease(self) -> WriterLease:
        return self.runtime.lease

    @property
    def store(self) -> Store:
        return self.runtime.store

    @property
    def policy(self) -> PolicyStore:
        return self.runtime.policy

    @property
    def os_(self) -> OsAdapters:
        return self.runtime.os_


@pytest.fixture
def env(trusted_tmp: Path, os_: OsAdapters, clock: FakeClock) -> Iterator[Env]:
    """A fresh data root opened from a cached schema template (``DEMO_KINDS``), closed at teardown."""
    runtime = open_cloned_runtime(
        trusted_tmp / "root",
        os_,
        role="storage-env",
        kinds=KindRegistry(DEMO_KINDS),
        store_migrations=STORE_MIGRATIONS,
        policy_migrations=POLICY_MIGRATIONS,
    )
    try:
        yield Env(runtime, clock)
    finally:
        runtime.close()


@contextlib.contextmanager
def maintenance_lease(path: Path, os_: OsAdapters | None = None) -> Iterator[tuple[DataRoot, WriterLease]]:
    """The maintenance start-up sequence without opening Store or PolicyStore: ``prepare_data_root`` ->
    ``acquire_writer`` -> ``recover_interrupted_swaps`` -> ``secure_subdirectories``.

    Yields ``(root, lease)``; the lease is released on exit.
    """
    adapters = os_ if os_ is not None else os_adapters()
    root = prepare_data_root(path, adapters)
    with acquire_writer(root, adapters) as lease:
        recover_interrupted_swaps(root, lease, adapters)
        secure_subdirectories(root, lease, adapters)
        yield root, lease
