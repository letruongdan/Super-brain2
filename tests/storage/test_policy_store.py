import sqlite3
import threading
from collections.abc import Callable
from pathlib import Path

import pytest

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.os import OsAdapters
from superbrain.ports.policy import IntentKind, PolicySource
from superbrain.storage.cas import RetentionClass
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.runtime import open_runtime
from superbrain.storage.schema import POLICY_MIGRATIONS, Migration, read_schema_info
from superbrain.storage.store import Store
from tests.storage.conftest import CLOCK_START, Env, maintenance_lease
from tests.support.fs import digest_tree

E1 = "0192f3a4-5b6c-7d8e-9f01-000000000e01"
V1 = "0192f3a4-5b6c-7d8e-9f01-000000000f01"
D = "sha256:" + "ab" * 32
STORE_ID = "0192f3a4-5b6c-7d8e-9f01-0000000000c1"
POLICY_V2 = (*POLICY_MIGRATIONS, Migration(to_version=2, min_reader_version=1, apply=lambda db: None))


def put_and_hold(store: Store, data: bytes, holders: list[tuple[str, str]]) -> str:
    digest = store.cas.put(data)
    with store.transaction() as t:
        for holder_kind, holder_id in holders:
            t.hold(digest, holder_kind, holder_id, RetentionClass.EVIDENCE, None)
    return digest


def capture(errors: list[BaseException], fn: Callable[[], object]) -> None:
    try:
        fn()
    except BaseException as err:  # noqa: BLE001 - the test inspects whatever the other thread raised
        errors.append(err)


# --- intents block content as soon as they commit --------------------------------------------------------------


def test_quarantine_blocks_every_holder_immediately(env: Env) -> None:
    d = put_and_hold(env.store, b"secret", holders=[("event", E1), ("evidence", V1)])
    env.policy.record_intent(IntentKind.QUARANTINE, {"digest": d})
    with pytest.raises(BrainError) as e:
        env.store.cas.read(d)
    assert e.value.code == ErrorCode.QUARANTINED


def test_tombstone_is_effective_on_commit(env: Env) -> None:
    intent = env.policy.record_intent(IntentKind.TOMBSTONE, {"holder_kind": "event", "holder_id": E1})
    assert env.policy.is_tombstoned("event", E1) and not env.policy.is_tombstoned("evidence", E1)
    assert env.policy.tombstones() == [("event", E1)]
    assert env.policy.intents() == [intent]


def test_record_intent_returns_the_stored_intent(env: Env) -> None:
    first = env.policy.record_intent(IntentKind.QUARANTINE, {"digest": D})
    env.clock.set(CLOCK_START.replace(hour=13))
    second = env.policy.record_intent(IntentKind.TOMBSTONE, {"holder_kind": "lesson", "holder_id": V1})
    assert first.kind is IntentKind.QUARANTINE and first.payload == {"digest": D}
    assert first.created_at == "2026-10-30T12:00:00.000000Z" and second.created_at == "2026-10-30T13:00:00.000000Z"
    assert env.policy.intents() == [first, second]
    assert first.intent_id != second.intent_id


def test_intents_keep_insertion_order_when_the_clock_goes_back(env: Env) -> None:
    first = env.policy.record_intent(IntentKind.QUARANTINE, {"digest": D})
    env.clock.set(CLOCK_START.replace(year=2020))
    second = env.policy.record_intent(IntentKind.QUARANTINE, {"digest": "sha256:" + "cd" * 32})
    assert [i.intent_id for i in env.policy.intents()] == [first.intent_id, second.intent_id]


def test_repeated_effects_record_every_intent_but_one_effect_row(env: Env) -> None:
    env.policy.record_intent(IntentKind.TOMBSTONE, {"holder_kind": "event", "holder_id": E1})
    env.policy.record_intent(IntentKind.TOMBSTONE, {"holder_kind": "event", "holder_id": E1})
    env.policy.record_intent(IntentKind.QUARANTINE, {"digest": D})
    env.policy.record_intent(IntentKind.QUARANTINE, {"digest": D})
    assert len(env.policy.intents()) == 4
    assert env.policy.tombstones() == [("event", E1)] and env.policy.is_quarantined(D)


@pytest.mark.parametrize(
    ("kind", "payload"),
    [
        (IntentKind.TOMBSTONE, {"holder_kind": "bogus", "holder_id": E1}),
        (IntentKind.TOMBSTONE, {"holder_kind": "event"}),
        (IntentKind.TOMBSTONE, {"holder_kind": "event", "holder_id": "not-a-uuid"}),
        (IntentKind.TOMBSTONE, {"holder_kind": "event", "holder_id": E1, "intent_id": E1}),
        (IntentKind.TOMBSTONE, {"holder_kind": "event", "holder_id": E1, "reason": "spam"}),
        (IntentKind.QUARANTINE, {"digest": "sha256:XYZ"}),
        (IntentKind.QUARANTINE, {"digest": D, "reason": "malware"}),
        (IntentKind.QUARANTINE, {"holder_kind": "event", "holder_id": E1}),
        (IntentKind.QUARANTINE, {}),
        ("quarantine", {"digest": D}),
        (IntentKind.QUARANTINE, [("digest", D)]),
    ],
)
def test_invalid_intents_are_rejected_before_any_write(env: Env, kind: object, payload: object) -> None:
    before = digest_tree(env.root.policy_dir)
    with pytest.raises(BrainError) as e:
        env.policy.record_intent(kind, payload)  # type: ignore[arg-type]
    assert e.value.code == ErrorCode.INVALID_INPUT
    assert env.policy.intents() == [] and env.policy.tombstones() == [] and not env.policy.is_quarantined(D)
    assert digest_tree(env.root.policy_dir) == before


def test_policy_store_is_a_policy_source(env: Env) -> None:
    source: PolicySource = env.policy
    assert source.store_id == env.store.store_id and source.intents() == []


# --- trust generation ------------------------------------------------------------------------------------------


def test_create_starts_at_the_lock_hwm(trusted_tmp: Path, os_: OsAdapters) -> None:
    with maintenance_lease(trusted_tmp / "r", os_) as (root, lease):
        lease.raise_trust_hwm(5)
        policy = PolicyStore.create(root, lease, os_, store_id=STORE_ID)
        assert policy.trust_generation() == 5 and lease.state().trust_generation_hwm == 5
        policy.close()


def test_create_on_a_fresh_lock_starts_at_one_and_raises_the_hwm(trusted_tmp: Path, os_: OsAdapters) -> None:
    with maintenance_lease(trusted_tmp / "r", os_) as (root, lease):
        assert lease.state().trust_generation_hwm == 0
        policy = PolicyStore.create(root, lease, os_, store_id=STORE_ID)
        assert policy.trust_generation() == 1 and lease.state().trust_generation_hwm == 1
        policy.close()


def test_generation_above_the_hwm_raises_the_hwm_on_open(trusted_tmp: Path, os_: OsAdapters) -> None:
    with maintenance_lease(trusted_tmp / "r", os_) as (root, lease):
        policy = PolicyStore.create(root, lease, os_, store_id=STORE_ID)
        policy.set_trust_generation(20)
        assert policy.trust_generation() == 20 and lease.state().trust_generation_hwm == 1
        policy.close()
        policy = PolicyStore.open(root, lease, os_)
        assert policy.trust_generation() == 20 and lease.state().trust_generation_hwm == 20
        policy.close()


def test_generation_equal_to_the_hwm_is_kept(trusted_tmp: Path, os_: OsAdapters) -> None:
    with maintenance_lease(trusted_tmp / "r", os_) as (root, lease):
        PolicyStore.create(root, lease, os_, store_id=STORE_ID).close()
        policy = PolicyStore.open(root, lease, os_)
        assert policy.trust_generation() == 1 and lease.state().trust_generation_hwm == 1
        policy.close()


def test_set_trust_generation_writes_any_valid_value(trusted_tmp: Path, os_: OsAdapters) -> None:
    with maintenance_lease(trusted_tmp / "r", os_) as (root, lease):
        policy = PolicyStore.create(root, lease, os_, store_id=STORE_ID)
        policy.set_trust_generation(7)
        policy.set_trust_generation(3)
        assert policy.trust_generation() == 3
        for bad in (0, -1, True, "4", 2.0):
            with pytest.raises(BrainError) as e:
                policy.set_trust_generation(bad)  # type: ignore[arg-type]
            assert e.value.code == ErrorCode.INVALID_INPUT
        assert policy.trust_generation() == 3
        policy.close()


def test_missing_trust_row_is_an_integrity_failure(trusted_tmp: Path, os_: OsAdapters) -> None:
    with maintenance_lease(trusted_tmp / "r", os_) as (root, lease):
        PolicyStore.create(root, lease, os_, store_id=STORE_ID).close()
        db = sqlite3.connect(root.policy_db, isolation_level=None)
        try:
            db.execute("DELETE FROM trust")
        finally:
            db.close()
        with pytest.raises(BrainError) as e:
            PolicyStore.open(root, lease, os_)
        assert e.value.code == ErrorCode.INTEGRITY_FAILURE and lease.open_handles() == frozenset()


# --- lifecycle -------------------------------------------------------------------------------------------------


def test_create_writes_the_store_id_and_the_schema(trusted_tmp: Path, os_: OsAdapters) -> None:
    with maintenance_lease(trusted_tmp / "r", os_) as (root, lease):
        policy = PolicyStore.create(root, lease, os_, store_id=STORE_ID)
        assert policy.store_id == STORE_ID and lease.open_handles() == frozenset({"policy"})
        policy.close()
        assert lease.open_handles() == frozenset()
        info = read_schema_info(root.policy_db)
        assert info is not None and (info.store_id, info.schema_version) == (STORE_ID, 1)
        db = sqlite3.connect(f"{root.policy_db.absolute().as_uri()}?mode=ro", uri=True)
        try:
            tables = sorted(r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'"))
        finally:
            db.close()
        assert tables == ["intents", "meta", "quarantine", "tombstones", "trust"]
        assert not [p.name for p in root.policy_dir.iterdir() if ".creating-" in p.name]


def test_create_refuses_an_existing_policy_store(trusted_tmp: Path, os_: OsAdapters) -> None:
    with maintenance_lease(trusted_tmp / "r", os_) as (root, lease):
        PolicyStore.create(root, lease, os_, store_id=STORE_ID).close()
        before = digest_tree(root.policy_dir)
        with pytest.raises(BrainError) as e:
            PolicyStore.create(root, lease, os_, store_id=STORE_ID)
        assert e.value.code == ErrorCode.INVALID_INPUT and lease.open_handles() == frozenset()
        assert digest_tree(root.policy_dir) == before


def test_open_refuses_a_missing_policy_store(trusted_tmp: Path, os_: OsAdapters) -> None:
    with maintenance_lease(trusted_tmp / "r", os_) as (root, lease):
        with pytest.raises(BrainError) as e:
            PolicyStore.open(root, lease, os_)
        assert e.value.code == ErrorCode.NOT_FOUND and lease.open_handles() == frozenset()
        assert not root.policy_db.exists()


@pytest.mark.parametrize(
    ("created_with", "opened_with", "code"),
    [
        (POLICY_V2, POLICY_MIGRATIONS, ErrorCode.UNSUPPORTED_VERSION),
        (POLICY_MIGRATIONS, POLICY_V2, ErrorCode.MIGRATION_REQUIRED),
    ],
)
def test_open_follows_the_given_migrations(
    trusted_tmp: Path,
    os_: OsAdapters,
    created_with: tuple[Migration, ...],
    opened_with: tuple[Migration, ...],
    code: ErrorCode,
) -> None:
    with maintenance_lease(trusted_tmp / "r", os_) as (root, lease):
        PolicyStore.create(root, lease, os_, store_id=STORE_ID, migrations=created_with).close()
        with pytest.raises(BrainError) as e:
            PolicyStore.open(root, lease, os_, migrations=opened_with)
        assert e.value.code == code and lease.open_handles() == frozenset()
        PolicyStore.open(root, lease, os_, migrations=created_with).close()


def test_failed_create_leaves_no_policy_store_and_can_be_retried(
    trusted_tmp: Path, os_: OsAdapters, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = os_.publisher.publish
    calls = 0

    def publish_failing_once(staging: Path, final: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise BrainError(ErrorCode.IO_ERROR, "injected publish failure")
        real(staging, final)

    monkeypatch.setattr(os_.publisher, "publish", publish_failing_once)
    with maintenance_lease(trusted_tmp / "r", os_) as (root, lease):
        with pytest.raises(BrainError, match="injected"):
            PolicyStore.create(root, lease, os_, store_id=STORE_ID)
        assert lease.open_handles() == frozenset() and not root.policy_db.exists()
        policy = PolicyStore.create(root, lease, os_, store_id=STORE_ID)
        assert policy.trust_generation() == 1
        assert not [p.name for p in root.policy_dir.iterdir() if ".creating-" in p.name]
        policy.close()


def test_open_secures_the_database_files(trusted_tmp: Path, os_: OsAdapters, monkeypatch: pytest.MonkeyPatch) -> None:
    secured: list[str] = []
    real = os_.permissions.secure_file

    def spy(path: Path) -> None:
        secured.append(path.name)
        real(path)

    with maintenance_lease(trusted_tmp / "r", os_) as (root, lease):
        PolicyStore.create(root, lease, os_, store_id=STORE_ID).close()
        monkeypatch.setattr(os_.permissions, "secure_file", spy)
        policy = PolicyStore.open(root, lease, os_)
        assert secured == ["policy.db", "policy.db-wal", "policy.db-shm"]
        policy.close()


def test_closed_policy_store_cannot_be_used(env: Env) -> None:
    policy = env.policy
    policy.close()
    assert policy.closed
    uses: list[Callable[[], object]] = [
        policy.close,
        policy.intents,
        policy.tombstones,
        policy.trust_generation,
        lambda: policy.set_trust_generation(2),
        lambda: policy.record_intent(IntentKind.QUARANTINE, {"digest": D}),
        lambda: policy.is_quarantined(D),
        lambda: policy.is_tombstoned("event", E1),
        lambda: policy.store_id,
    ]
    for use in uses:
        with pytest.raises(AssertionError, match="policy store closed"):
            use()


def test_policy_store_refuses_use_from_another_thread(env: Env) -> None:
    errors: list[BaseException] = []
    t = threading.Thread(target=lambda: capture(errors, env.policy.intents))
    t.start()
    t.join()
    assert len(errors) == 1 and isinstance(errors[0], AssertionError)
    assert str(errors[0]) == "policy store used off its owner thread"


def test_busy_policy_database_is_store_busy(env: Env) -> None:
    env.policy._db.execute("PRAGMA busy_timeout=0")  # avoid waiting the default 5 s for the other connection
    other = sqlite3.connect(env.root.policy_db, isolation_level=None)
    try:
        other.execute("BEGIN IMMEDIATE")
        with pytest.raises(BrainError) as e:
            env.policy.record_intent(IntentKind.QUARANTINE, {"digest": D})
        assert e.value.code == ErrorCode.STORE_BUSY
    finally:
        other.close()
    assert env.policy.intents() == []


def test_corrupt_intent_rows_are_integrity_failures(env: Env) -> None:
    env.policy.record_intent(IntentKind.QUARANTINE, {"digest": D})
    db = sqlite3.connect(env.root.policy_db, isolation_level=None)
    try:
        db.execute("UPDATE intents SET payload = ?", (b'{"digest":"sha256:XYZ"}',))
    finally:
        db.close()
    with pytest.raises(BrainError) as e:
        env.policy.intents()
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE


def test_open_runtime_forwards_policy_migrations(trusted_tmp: Path, os_: OsAdapters) -> None:
    open_runtime(trusted_tmp / "r", os_, policy_migrations=POLICY_V2).close()
    with pytest.raises(BrainError) as e:
        open_runtime(trusted_tmp / "r", os_)
    assert e.value.code == ErrorCode.UNSUPPORTED_VERSION
    runtime = open_runtime(trusted_tmp / "r", os_, policy_migrations=POLICY_V2)
    assert runtime.policy.trust_generation() == 1
    runtime.close()
