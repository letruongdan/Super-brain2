import ast
import dataclasses
import sqlite3
import threading
import uuid
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

import pytest

import superbrain.storage.store as store_module
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.ports.os import DurabilityReport, DurablePublisher, OsAdapters
from superbrain.ports.policy import PolicyView
from superbrain.storage.kinds import KindRegistry
from superbrain.storage.layout import prepare_data_root, secure_subdirectories
from superbrain.storage.ledger import LedgerEntry, Txn
from superbrain.storage.schema import STORE_MIGRATIONS, Migration, initialize
from superbrain.storage.store import Store
from superbrain.storage.writer import acquire_writer
from tests.storage.conftest import (
    DEMO_KINDS,
    STORE_ID,
    CounterProjection,
    StaticPolicy,
    StoreFactory,
    counter,
    seed_store,
)
from tests.support.crash import run_child, run_until_crash

SRC = Path(__file__).resolve().parents[2] / "src"
D = "sha256:" + "ab" * 32
D2 = "sha256:" + "cd" * 32
U = "0192f3a4-5b6c-7d8e-9f01-23456789abcd"
RESERVED_HELPERS = {"Txn.hold", "Txn.release", "Store.reconcile_policy"}


def valid_meta_for(kind: str) -> dict[str, JsonValue]:
    metas: dict[str, dict[str, JsonValue]] = {
        "cas.hold": {"digest": D, "holder_kind": "lesson", "holder_id": U, "retention": "durable", "expires_at": None},
        "cas.release": {"digest": D, "holder_kind": "lesson", "holder_id": U, "reason": "expired"},
        "policy.quarantine": {"digest": D, "intent_id": U},
        "policy.tombstone": {"holder_kind": "lesson", "holder_id": U, "intent_id": U},
    }
    return metas[kind]


def append_n(store: Store, n: int) -> None:
    for i in range(n):
        with store.transaction() as t:
            t.append("demo.count", actor="user:cli", owner_id="dan", meta={"n": i})


def insert_raw_ledger_row(
    store: Store, *, kind: str, handler_version: int, meta: object = b'{"n":7}', refs: object = b"[]"
) -> None:
    """Simulate history written by another binary, bypassing every check."""
    with store.transaction() as t:
        t.db.execute(
            "INSERT INTO ledger (entry_id, kind, schema_version, handler_version, writer_epoch, actor, owner_id,"
            " recorded_at, meta, refs) VALUES (?, ?, 1, ?, 1, 'user:cli', 'dan', '2026-10-30T12:00:00.000000Z', ?, ?)",
            (str(uuid.uuid4()), kind, handler_version, meta, refs),
        )


def table_names(store: Store) -> list[str]:
    with store.transaction() as t:
        rows = t.db.execute("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name").fetchall()
    return [str(r[0]) for r in rows]


def capture(errors: list[BaseException], fn: Callable[[], object]) -> None:
    try:
        fn()
    except BaseException as err:  # noqa: BLE001 - the test inspects whatever the other thread raised
        errors.append(err)


def callers_of(name: str, root: Path) -> set[str]:
    """Qualnames (``Class.method``, ``func``, ``Class.method.inner``) of every function under ``root`` whose body
    refers to ``name`` as an attribute, a bare name or a string constant. A reference outside any function is
    reported as ``<module path>``, so aliasing or module-level calls cannot hide."""
    found: set[str] = set()

    def refers(node: ast.AST) -> bool:
        return (
            (isinstance(node, ast.Attribute) and node.attr == name)
            or (isinstance(node, ast.Name) and node.id == name)
            or (isinstance(node, ast.Constant) and node.value == name)
        )

    def visit(node: ast.AST, scope: list[str], in_function: bool, where: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                visit(child, [*scope, child.name], in_function, where)
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                visit(child, [*scope, child.name], True, where)
            else:
                if refers(child):
                    found.add(".".join(scope) if in_function else f"<module {where}>")
                visit(child, scope, in_function, where)

    for path in sorted(root.rglob("*.py")):
        visit(ast.parse(path.read_text(encoding="utf-8")), [], False, path.as_posix())
    return found


# --- validation before any write -----------------------------------------------------------------------------


@pytest.mark.parametrize("meta", [{"n": 1, "extra": 2}, {"n": "1"}, {"n": {"nested": 1}}, {}, {"n": True}])
def test_meta_outside_schema_is_rejected_before_write(store_factory: StoreFactory, meta: dict[str, JsonValue]) -> None:
    store = store_factory(handlers=[CounterProjection()])
    with pytest.raises(BrainError) as e:
        with store.transaction() as t:
            t.append("demo.count", actor="user:cli", owner_id="dan", meta=meta)
    assert e.value.code == ErrorCode.INVALID_INPUT and list(store.entries()) == []
    assert counter(store) == 0


@pytest.mark.parametrize("refs", [["tiny-secret-7f3a"], [D, D], ["sha256:XYZ"]])
def test_refs_must_be_unique_digests(store_factory: StoreFactory, refs: list[str]) -> None:
    store = store_factory()
    with pytest.raises(BrainError) as e:
        with store.transaction() as t:
            t.append("demo.count", actor="user:cli", owner_id="dan", meta={"n": 1}, refs=refs)
    assert e.value.code == ErrorCode.INVALID_INPUT and list(store.entries()) == []


@pytest.mark.parametrize(("actor", "owner_id"), [("cli", "dan"), ("user:cli", "Dan"), ("user:x y", None)])
def test_actor_and_owner_must_be_identifiers(store_factory: StoreFactory, actor: str, owner_id: str | None) -> None:
    store = store_factory()
    with pytest.raises(BrainError) as e:
        with store.transaction() as t:
            t.append("demo.count", actor=actor, owner_id=owner_id, meta={"n": 1})
    assert e.value.code == ErrorCode.INVALID_INPUT and list(store.entries()) == []


@pytest.mark.parametrize("kind", ["cas.hold", "cas.release", "policy.tombstone", "policy.quarantine"])
def test_reserved_kinds_cannot_be_appended_directly(store_factory: StoreFactory, kind: str) -> None:
    store = store_factory()
    with pytest.raises(BrainError) as e:
        with store.transaction() as t:
            t.append(kind, actor="user:cli", owner_id="dan", meta=valid_meta_for(kind))
    assert e.value.code == ErrorCode.INVALID_INPUT and list(store.entries()) == []


def test_reserved_append_is_only_called_from_its_helpers() -> None:
    # Task 11 tightens this to equality once every helper exists.
    assert callers_of("_append_reserved", SRC / "superbrain") <= RESERVED_HELPERS
    # The shared writer behind append and _append_reserved is no side door around the reserved check.
    assert callers_of("_write_entry", SRC / "superbrain") == {"Txn.append", "Txn._append_reserved"}


def test_callers_of_sees_methods_functions_aliases_and_module_level(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(
        "class Txn:\n"
        "    def hold(self):\n        self._target()\n"
        "    def other(self):\n        def inner():\n            f = self._target\n        return inner\n"
        "def free():\n    getattr(x, '_target')()\n"
        "def _target():\n    pass\n"
        "_target()\n",
        encoding="utf-8",
    )
    module = f"<module {(tmp_path / 'a.py').as_posix()}>"
    assert callers_of("_target", tmp_path) == {"Txn.hold", "Txn.other.inner", "free", module}


def test_unknown_kind_creates_nothing(store_factory: StoreFactory) -> None:
    store = store_factory(handlers=[CounterProjection()])
    with pytest.raises(BrainError) as e:
        with store.transaction() as t:
            t.append("demo.unknown", actor="user:cli", owner_id="dan", meta={})
    assert e.value.code == ErrorCode.INVALID_INPUT
    assert list(store.entries()) == [] and counter(store) == 0


# --- one transaction for ledger and projections --------------------------------------------------------------


def test_append_and_projection_commit_together(store_factory: StoreFactory) -> None:
    store = store_factory(handlers=[CounterProjection()])
    with store.transaction() as t:
        first = t.append("demo.count", actor="user:cli", owner_id="dan", meta={"n": 1})
        second = t.append("demo.count", actor="user:cli", owner_id=None, meta={"n": 2}, refs=[D, D2])
    assert list(store.entries()) == [first, second]
    assert [e.sequence for e in store.entries()] == [1, 2] and second.refs == (D, D2)
    assert counter(store) == 2
    assert [e.meta["n"] for e in store.entries(after=1)] == [2]


def test_exception_rolls_back_ledger_and_projection(store_factory: StoreFactory) -> None:
    store = store_factory(handlers=[CounterProjection()])
    append_n(store, 1)
    with pytest.raises(RuntimeError, match="boom"):
        with store.transaction() as t:
            t.append("demo.count", actor="user:cli", owner_id="dan", meta={"n": 2})
            assert counter_in(t) == 2
            raise RuntimeError("boom")
    assert [e.meta["n"] for e in store.entries()] == [0] and counter(store) == 1


def counter_in(t: Txn) -> int:
    return int(t.db.execute("SELECT entries FROM p_counter_state").fetchone()[0])


class FailingProjection:
    name = "failing"
    handler_version = 1
    kinds = frozenset({"demo.count"})

    def create_tables(self, db: sqlite3.Connection, prefix: str) -> None:
        db.execute(f"CREATE TABLE {prefix}rows (n INTEGER NOT NULL)")

    def apply(self, db: sqlite3.Connection, prefix: str, entry: LedgerEntry, policy: PolicyView) -> None:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "projection refuses")


def test_failing_projection_rolls_back_the_entry(store_factory: StoreFactory) -> None:
    store = store_factory(handlers=[CounterProjection(), FailingProjection()])
    with pytest.raises(BrainError) as e:
        with store.transaction() as t:
            t.append("demo.count", actor="user:cli", owner_id="dan", meta={"n": 1})
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE
    assert list(store.entries()) == [] and counter(store) == 0


class PickyProjection:
    """Records each ``n`` it accepts and refuses ``n == 2``."""

    name = "picky"
    handler_version = 1
    kinds = frozenset({"demo.count"})

    def create_tables(self, db: sqlite3.Connection, prefix: str) -> None:
        db.execute(f"CREATE TABLE {prefix}rows (n INTEGER NOT NULL)")

    def apply(self, db: sqlite3.Connection, prefix: str, entry: LedgerEntry, policy: PolicyView) -> None:
        if entry.meta["n"] == 2:
            raise BrainError(ErrorCode.INVALID_INPUT, "picky refuses n = 2")
        db.execute(f"INSERT INTO {prefix}rows (n) VALUES (?)", (entry.meta["n"],))


def test_caught_projection_failure_undoes_only_that_append(store_factory: StoreFactory) -> None:
    store = store_factory(handlers=[CounterProjection(), PickyProjection()])
    with store.transaction() as t:
        t.append("demo.count", actor="user:cli", owner_id="dan", meta={"n": 1})
        with pytest.raises(BrainError, match="picky"):
            t.append("demo.count", actor="user:cli", owner_id="dan", meta={"n": 2})
    assert [e.meta["n"] for e in store.entries()] == [1] and counter(store) == 1
    with store.transaction() as t:
        assert t.db.execute("SELECT n FROM p_picky_rows").fetchall() == [(1,)]
    assert store.rebuild_projections() == 1 and counter(store) == 1


class OverflowingProjection(CounterProjection):
    name = "overflowing"

    def apply(self, db: sqlite3.Connection, prefix: str, entry: LedgerEntry, policy: PolicyView) -> None:
        super().apply(db, prefix, entry, policy)
        raise OverflowError("handler bug")


def test_non_brain_error_from_a_projection_is_integrity_failure(store_factory: StoreFactory) -> None:
    store = store_factory(handlers=[CounterProjection(), OverflowingProjection()])
    with store.transaction() as t:
        with pytest.raises(BrainError) as e:
            t.append("demo.count", actor="user:cli", owner_id="dan", meta={"n": 1})
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE and isinstance(e.value.__cause__, OverflowError)
    assert list(store.entries()) == [] and counter(store) == 0


def test_entries_record_epoch_and_registry_version(store_factory: StoreFactory) -> None:
    store = store_factory()
    with store.transaction() as t:
        appended = t.append("demo.count", actor="principal:agent.7", owner_id="dan", meta={"n": 5}, refs=[D])
    [entry] = list(store.entries())
    assert entry == appended
    assert entry.writer_epoch == 1 and entry.handler_version == 1 and entry.schema_version == 1
    assert entry.kind == "demo.count" and entry.actor == "principal:agent.7" and entry.owner_id == "dan"
    assert entry.recorded_at == "2026-10-30T12:00:00.000000Z"
    assert entry.meta == {"n": 5} and entry.refs == (D,)
    assert str(uuid.UUID(entry.entry_id)) == entry.entry_id and uuid.UUID(entry.entry_id).version == 7


def test_ledger_stores_canonical_json(store_factory: StoreFactory) -> None:
    store = store_factory()
    with store.transaction() as t:
        t.append("demo.count", actor="user:cli", owner_id="dan", meta={"n": 5}, refs=[D2, D])
        row = t.db.execute("SELECT meta, refs FROM ledger").fetchone()
    assert row == (b'{"n":5}', f'["{D2}","{D}"]'.encode())


def test_txn_cannot_be_used_after_its_transaction(store_factory: StoreFactory) -> None:
    store = store_factory()
    with store.transaction() as t:
        pass
    with pytest.raises(AssertionError):
        t.append("demo.count", actor="user:cli", owner_id="dan", meta={"n": 1})
    assert list(store.entries()) == []


def test_transactions_do_not_nest(store_factory: StoreFactory) -> None:
    store = store_factory()
    with store.transaction():
        with pytest.raises(AssertionError):
            store.transaction()
        with pytest.raises(AssertionError):
            store.rebuild_projections()


def test_mark_intent_applied_once_and_only_on_commit(store_factory: StoreFactory) -> None:
    store = store_factory()
    with pytest.raises(RuntimeError):
        with store.transaction() as t:
            assert t.mark_intent_applied(U) is True
            raise RuntimeError("abort")
    with store.transaction() as t:
        t.append("demo.count", actor="user:cli", owner_id="dan", meta={"n": 1})
        assert t.mark_intent_applied(U) is True
        assert t.mark_intent_applied(U) is False
    with store.transaction() as t:
        assert t.mark_intent_applied(U) is False
        assert t.db.execute("SELECT intent_id, applied_sequence FROM applied_intents").fetchall() == [(U, 1)]
        with pytest.raises(BrainError) as e:
            t.mark_intent_applied("tiny-secret-7f3a")
    assert e.value.code == ErrorCode.INVALID_INPUT


def test_busy_database_is_store_busy(store_factory: StoreFactory) -> None:
    store = store_factory()
    with store.transaction() as t:
        path = Path(t.db.execute("PRAGMA database_list").fetchone()[2])
    store._db.execute("PRAGMA busy_timeout=0")  # avoid waiting the default 5 s for the other connection
    other = sqlite3.connect(path, isolation_level=None)
    try:
        other.execute("BEGIN IMMEDIATE")
        with pytest.raises(BrainError) as e:
            with store.transaction():
                pass
        assert e.value.code == ErrorCode.STORE_BUSY
    finally:
        other.close()
    with store.transaction() as t:
        t.append("demo.count", actor="user:cli", owner_id="dan", meta={"n": 1})
    assert len(list(store.entries())) == 1


# --- projection rebuild --------------------------------------------------------------------------------------


class IndexedProjection:
    """Has a UNIQUE constraint and an explicit index, which must survive repeated rebuilds."""

    name = "indexed"
    handler_version = 1
    kinds = frozenset({"demo.count"})

    def create_tables(self, db: sqlite3.Connection, prefix: str) -> None:
        db.execute(f"CREATE TABLE {prefix}rows (sequence INTEGER UNIQUE NOT NULL, n INTEGER NOT NULL)")
        db.execute(f"CREATE INDEX {prefix}rows_by_n ON {prefix}rows (n)")

    def apply(self, db: sqlite3.Connection, prefix: str, entry: LedgerEntry, policy: PolicyView) -> None:
        db.execute(f"INSERT INTO {prefix}rows (sequence, n) VALUES (?, ?)", (entry.sequence, entry.meta["n"]))


class PolicyRecorder:
    name = "recorder"
    handler_version = 1
    kinds = frozenset({"demo.count"})

    def __init__(self) -> None:
        self.seen: list[tuple[int, PolicyView]] = []

    def create_tables(self, db: sqlite3.Connection, prefix: str) -> None:
        db.execute(f"CREATE TABLE {prefix}none (x INTEGER)")

    def apply(self, db: sqlite3.Connection, prefix: str, entry: LedgerEntry, policy: PolicyView) -> None:
        self.seen.append((entry.sequence, policy))


def test_rebuild_reproduces_projection_without_duplicates(store_factory: StoreFactory) -> None:
    store = store_factory(handlers=[CounterProjection()])
    append_n(store, 5)
    assert store.rebuild_projections() == 5 and counter(store) == 5
    assert store.rebuild_projections() == 5 and counter(store) == 5
    assert not [n for n in table_names(store) if n.startswith("r_")]


def test_rebuild_keeps_indexes_across_repeated_rebuilds(store_factory: StoreFactory) -> None:
    store = store_factory(handlers=[IndexedProjection()])
    append_n(store, 3)
    for _ in range(3):
        assert store.rebuild_projections() == 3
    with store.transaction() as t:
        rows = t.db.execute("SELECT sequence, n FROM p_indexed_rows ORDER BY sequence").fetchall()
        objects = t.db.execute("SELECT type, name, tbl_name FROM sqlite_master ORDER BY name").fetchall()
    assert rows == [(1, 0), (2, 1), (3, 2)]
    assert [o for o in objects if "indexed" in o[1]] == [
        ("table", "p_indexed_rows", "p_indexed_rows"),
        ("index", "p_indexed_rows_by_n", "p_indexed_rows"),
        ("index", "sqlite_autoindex_p_indexed_rows_1", "p_indexed_rows"),
    ]


def test_rebuild_replays_in_order_with_the_store_policy(store_factory: StoreFactory) -> None:
    policy = StaticPolicy(quarantined=[D])
    recorder = PolicyRecorder()
    store = store_factory(handlers=[recorder], policy=policy)
    append_n(store, 3)
    recorder.seen.clear()
    assert store.rebuild_projections() == 3
    assert [s for s, _ in recorder.seen] == [1, 2, 3] and all(p is policy for _, p in recorder.seen)


@pytest.mark.parametrize(
    ("meta", "refs"),
    [(b"not json", b"[]"), ('{"n":7}', b"[]"), (b"[1]", b"[]"), (b'{"n":7}', b'{"a":1}'), (b'{"n":7}', b"[1]")],
)
def test_malformed_ledger_row_is_integrity_failure(store_factory: StoreFactory, meta: object, refs: object) -> None:
    store = store_factory()
    insert_raw_ledger_row(store, kind="demo.count", handler_version=1, meta=meta, refs=refs)
    with pytest.raises(BrainError) as e:
        list(store.entries())
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE


def test_foreign_history_with_newer_handler_stops_rebuild(store_factory: StoreFactory) -> None:
    store = store_factory(handlers=[CounterProjection()])
    append_n(store, 1)
    insert_raw_ledger_row(store, kind="demo.count", handler_version=9)
    with pytest.raises(BrainError) as e:
        store.rebuild_projections()
    assert e.value.code == ErrorCode.UNSUPPORTED_VERSION and counter(store) == 1
    assert not [n for n in table_names(store) if n.startswith("r_")]


def test_projection_tables_outside_the_prefix_are_refused(store_factory: StoreFactory) -> None:
    class Stray(CounterProjection):
        name = "stray"

        def create_tables(self, db: sqlite3.Connection, prefix: str) -> None:
            db.execute("CREATE TABLE stray_rows (x INTEGER)")

    with pytest.raises(AssertionError):
        store_factory(handlers=[Stray()])


@pytest.mark.parametrize("names", [["counter", "counter"], ["Bad-Name"], ["a", "a_b"]])
def test_handler_names_must_be_unique_and_prefix_free(store_factory: StoreFactory, names: list[str]) -> None:
    handlers = []
    for name in names:
        handler = CounterProjection()
        handler.name = name
        handlers.append(handler)
    with pytest.raises(BrainError) as e:
        store_factory(handlers=handlers)
    assert e.value.code == ErrorCode.INVALID_INPUT


def test_handler_for_unregistered_kind_is_refused(store_factory: StoreFactory) -> None:
    class Orphan(CounterProjection):
        kinds = frozenset({"demo.missing"})

    with pytest.raises(BrainError) as e:
        store_factory(handlers=[Orphan()])
    assert e.value.code == ErrorCode.INVALID_INPUT


def test_handler_older_than_registry_kind_is_refused(store_factory: StoreFactory) -> None:
    class Old(CounterProjection):
        handler_version = 0

    with pytest.raises(BrainError) as e:
        store_factory(handlers=[Old()])
    assert e.value.code == ErrorCode.UNSUPPORTED_VERSION


# --- lifecycle -----------------------------------------------------------------------------------------------


def test_store_files_are_owner_only(store_factory: StoreFactory, os_: OsAdapters) -> None:
    store = store_factory()
    with store.transaction() as t:
        path = Path(t.db.execute("PRAGMA database_list").fetchone()[2])
    assert {p.name for p in path.parent.iterdir()} >= {"brain.db", "brain.db-wal", "brain.db-shm"}
    assert os_.permissions.problems(path.parent) == []


def test_reopen_keeps_entries_and_projection(trusted_tmp: Path, os_: OsAdapters) -> None:
    root = prepare_data_root(trusted_tmp / "r", os_)
    with acquire_writer(root, os_) as lease:
        secure_subdirectories(root, lease, os_)
        store = Store.create(root, lease, os_, StaticPolicy(), [CounterProjection()], KindRegistry(DEMO_KINDS))
        append_n(store, 2)
        store.close()
        assert lease.open_handles() == frozenset()
        store = Store.open(root, lease, os_, StaticPolicy(), [CounterProjection()], KindRegistry(DEMO_KINDS))
        assert lease.open_handles() == frozenset({"store"})
        assert [e.meta["n"] for e in store.entries()] == [0, 1] and counter(store) == 2
        assert store.store_id == STORE_ID and store.db_integrity() == "ok"
        store.close()


def test_handler_added_later_is_filled_from_the_ledger(trusted_tmp: Path, os_: OsAdapters) -> None:
    root = prepare_data_root(trusted_tmp / "r", os_)
    kinds = KindRegistry(DEMO_KINDS)
    with acquire_writer(root, os_) as lease:
        secure_subdirectories(root, lease, os_)
        store = Store.create(root, lease, os_, StaticPolicy(), [], kinds)
        append_n(store, 3)
        store.close()
        recorder = PolicyRecorder()
        policy = StaticPolicy()
        store = Store.open(root, lease, os_, policy, [CounterProjection(), recorder], kinds)
        assert counter(store) == 3
        assert [s for s, _ in recorder.seen] == [1, 2, 3] and all(p is policy for _, p in recorder.seen)
        store.close()
        store = Store.open(root, lease, os_, StaticPolicy(), [CounterProjection(), recorder], kinds)
        assert counter(store) == 3 and len(recorder.seen) == 3
        append_n(store, 1)
        assert counter(store) == 4
        store.close()
        # A new handler next to existing ones: only the new one is replayed.
        store = Store.open(root, lease, os_, StaticPolicy(), [CounterProjection(), IndexedProjection()], kinds)
        assert counter(store) == 4
        with store.transaction() as t:
            assert t.db.execute("SELECT count(*) FROM p_indexed_rows").fetchone()[0] == 4
        store.close()


def test_handler_added_later_refuses_history_from_a_newer_handler(trusted_tmp: Path, os_: OsAdapters) -> None:
    root = prepare_data_root(trusted_tmp / "r", os_)
    with acquire_writer(root, os_) as lease:
        secure_subdirectories(root, lease, os_)
        store = Store.create(root, lease, os_, StaticPolicy(), [], KindRegistry(DEMO_KINDS))
        insert_raw_ledger_row(store, kind="demo.count", handler_version=9)
        store.close()
        with pytest.raises(BrainError) as e:
            Store.open(root, lease, os_, StaticPolicy(), [CounterProjection()], KindRegistry(DEMO_KINDS))
        assert e.value.code == ErrorCode.UNSUPPORTED_VERSION and lease.open_handles() == frozenset()
        store = Store.open(root, lease, os_, StaticPolicy(), [], KindRegistry(DEMO_KINDS))
        assert not [n for n in table_names(store) if n.startswith("p_counter_")]
        store.close()


def test_failed_create_leaves_no_store_and_can_be_retried(
    trusted_tmp: Path, os_: OsAdapters, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = 0
    real = initialize

    def initialize_failing_once(db: sqlite3.Connection, migrations: Sequence[Migration], *, store_id: str) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise BrainError(ErrorCode.IO_ERROR, "injected initialize failure")
        real(db, migrations, store_id=store_id)

    monkeypatch.setattr(store_module, "initialize", initialize_failing_once)
    root = prepare_data_root(trusted_tmp / "r", os_)
    with acquire_writer(root, os_) as lease:
        secure_subdirectories(root, lease, os_)
        with pytest.raises(BrainError, match="injected"):
            Store.create(root, lease, os_, StaticPolicy(), [], KindRegistry(DEMO_KINDS))
        assert lease.open_handles() == frozenset()
        assert not root.store_db.exists()
        assert [p.name for p in root.store_dir.iterdir() if p.name.startswith("brain.db.creating-")]
        store = Store.create(root, lease, os_, StaticPolicy(), [CounterProjection()], KindRegistry(DEMO_KINDS))
        append_n(store, 1)
        assert counter(store) == 1 and store.db_integrity() == "ok"
        assert not [p.name for p in root.store_dir.iterdir() if p.name.startswith("brain.db.creating-")]
        store.close()


class TablesAtPublish:
    """Publisher spy: records the tables of the staged database as it is published, then delegates."""

    def __init__(self, real: DurablePublisher) -> None:
        self.real = real
        self.tables: list[str] = []

    def write_new(self, path: Path, data: bytes) -> None:
        self.real.write_new(path, data)

    def rename_dir(self, src: Path, dst: Path) -> None:
        self.real.rename_dir(src, dst)

    def sync_directory(self, directory: Path) -> None:
        self.real.sync_directory(directory)

    def durability(self, directory: Path, env: Mapping[str, str]) -> DurabilityReport:
        return self.real.durability(directory, env)

    def publish(self, staging: Path, final: Path) -> None:
        db = sqlite3.connect(f"{staging.absolute().as_uri()}?immutable=1", uri=True)
        try:
            self.tables = sorted(r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'"))
        finally:
            db.close()
        self.real.publish(staging, final)


def test_handler_tables_exist_before_the_store_is_published(trusted_tmp: Path, os_: OsAdapters) -> None:
    spy = TablesAtPublish(os_.publisher)
    os_ = dataclasses.replace(os_, publisher=spy)
    root = prepare_data_root(trusted_tmp / "r", os_)
    with acquire_writer(root, os_) as lease:
        secure_subdirectories(root, lease, os_)
        Store.create(root, lease, os_, StaticPolicy(), [CounterProjection()], KindRegistry(DEMO_KINDS)).close()
    assert "p_counter_state" in spy.tables and "ledger" in spy.tables


def test_store_id_mismatch_with_policy_is_refused(trusted_tmp: Path, os_: OsAdapters) -> None:
    root = prepare_data_root(trusted_tmp / "r", os_)
    with acquire_writer(root, os_) as lease:
        secure_subdirectories(root, lease, os_)
        Store.create(root, lease, os_, StaticPolicy(), [], KindRegistry(DEMO_KINDS)).close()
        with pytest.raises(BrainError) as e:
            Store.open(root, lease, os_, StaticPolicy(store_id="someone-else"), [], KindRegistry(DEMO_KINDS))
        assert e.value.code == ErrorCode.INTEGRITY_FAILURE and lease.open_handles() == frozenset()


def test_open_refuses_other_schema_versions(trusted_tmp: Path, os_: OsAdapters) -> None:
    v2 = (*STORE_MIGRATIONS, Migration(to_version=2, min_reader_version=1, apply=lambda db: None))
    root = prepare_data_root(trusted_tmp / "r", os_)
    with acquire_writer(root, os_) as lease:
        secure_subdirectories(root, lease, os_)
        Store.create(root, lease, os_, StaticPolicy(), [], KindRegistry(DEMO_KINDS)).close()
        with pytest.raises(BrainError) as e:
            Store.open(root, lease, os_, StaticPolicy(), [], KindRegistry(DEMO_KINDS), migrations=v2)
        assert e.value.code == ErrorCode.MIGRATION_REQUIRED and lease.open_handles() == frozenset()
    newer = prepare_data_root(trusted_tmp / "n", os_)
    with acquire_writer(newer, os_) as lease:
        secure_subdirectories(newer, lease, os_)
        store = Store.create(newer, lease, os_, StaticPolicy(), [], KindRegistry(DEMO_KINDS), migrations=v2)
        with store.transaction() as t:
            t.append("demo.count", actor="user:cli", owner_id="dan", meta={"n": 1})
        assert [e.schema_version for e in store.entries()] == [2]
        store.close()
        with pytest.raises(BrainError) as e:
            Store.open(newer, lease, os_, StaticPolicy(), [], KindRegistry(DEMO_KINDS))
        assert e.value.code == ErrorCode.UNSUPPORTED_VERSION


def test_open_missing_and_create_existing_are_refused(trusted_tmp: Path, os_: OsAdapters) -> None:
    root = prepare_data_root(trusted_tmp / "r", os_)
    with acquire_writer(root, os_) as lease:
        secure_subdirectories(root, lease, os_)
        with pytest.raises(BrainError) as e:
            Store.open(root, lease, os_, StaticPolicy(), [], KindRegistry(DEMO_KINDS))
        assert e.value.code == ErrorCode.NOT_FOUND and not root.store_db.exists()
        Store.create(root, lease, os_, StaticPolicy(), [], KindRegistry(DEMO_KINDS)).close()
        with pytest.raises(BrainError) as e:
            Store.create(root, lease, os_, StaticPolicy(), [], KindRegistry(DEMO_KINDS))
        assert e.value.code == ErrorCode.INVALID_INPUT and lease.open_handles() == frozenset()


def test_second_store_under_one_lease_is_refused(trusted_tmp: Path, os_: OsAdapters) -> None:
    root = prepare_data_root(trusted_tmp / "r", os_)
    with acquire_writer(root, os_) as lease:
        secure_subdirectories(root, lease, os_)
        store = Store.create(root, lease, os_, StaticPolicy(), [], KindRegistry(DEMO_KINDS))
        with pytest.raises(AssertionError):
            Store.open(root, lease, os_, StaticPolicy(), [], KindRegistry(DEMO_KINDS))
        store.close()


def test_closed_store_cannot_be_used(store_factory: StoreFactory) -> None:
    store = store_factory()
    store.close()
    assert store.closed
    for use in (
        store.transaction,
        store.entries,
        store.close,
        store.maintenance,
        store.rebuild_projections,
        store.db_integrity,
        store.reconcile_policy,
        lambda: store.store_id,
    ):
        with pytest.raises(AssertionError, match="store closed"):
            use()


def test_store_refuses_use_from_another_thread(store_factory: StoreFactory) -> None:
    store = store_factory()
    errors: list[BaseException] = []
    t = threading.Thread(target=lambda: capture(errors, lambda: list(store.entries())))
    t.start()
    t.join()
    assert len(errors) == 1 and isinstance(errors[0], AssertionError)
    assert str(errors[0]) == "store used off its owner thread"


def test_txn_refuses_use_from_another_thread(store_factory: StoreFactory) -> None:
    store = store_factory()
    errors: list[BaseException] = []
    with store.transaction() as txn:
        call = lambda: txn.append("demo.count", actor="user:cli", owner_id="dan", meta={"n": 1})  # noqa: E731
        t = threading.Thread(target=lambda: capture(errors, call))
        t.start()
        t.join()
    assert len(errors) == 1 and isinstance(errors[0], AssertionError) and list(store.entries()) == []


def test_maintenance_cannot_nest(store_factory: StoreFactory) -> None:
    store = store_factory()
    with store.maintenance():
        with pytest.raises(BrainError) as e:
            with store.maintenance():
                pass
    assert e.value.code == ErrorCode.STORE_BUSY
    with store.maintenance():
        pass


def test_reconcile_policy_is_a_noop_until_task_11(store_factory: StoreFactory) -> None:
    store = store_factory()
    assert store.reconcile_policy() == 0 and list(store.entries()) == []


# --- crash atomicity -----------------------------------------------------------------------------------------


def test_crash_after_commit_keeps_entry(trusted_tmp: Path, reopen: Callable[..., Store]) -> None:
    root = trusted_tmp / "r"
    seed_store(root)
    run_until_crash("append_demo", "ledger.after_commit", root, STORE_ID)
    assert [e.meta["n"] for e in reopen(root).entries()] == [1]


def test_crash_before_commit_leaves_nothing(trusted_tmp: Path, reopen: Callable[..., Store]) -> None:
    root = trusted_tmp / "r"
    seed_store(root)
    run_until_crash("append_demo", "ledger.before_commit", root, STORE_ID)
    assert list(reopen(root).entries()) == []


def test_append_demo_without_crash_commits(trusted_tmp: Path, reopen: Callable[..., Store]) -> None:
    root = trusted_tmp / "r"
    seed_store(root)
    result = run_child("append_demo", root, STORE_ID)
    assert result.returncode == 0, result.stdout + result.stderr
    assert [e.meta["n"] for e in reopen(root).entries()] == [1]
