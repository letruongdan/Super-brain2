"""Retention: configurable default expiry, the expiry sweep, and scenario 35 (no payload bytes in any DB file)."""

import json
import uuid
from datetime import datetime, timedelta

import pytest

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.policy import IntentKind
from superbrain.storage.cas import RetentionClass
from superbrain.storage.retention import RetentionPolicy, default_expiry, expire_due
from superbrain.storage.store import Store
from tests.storage.conftest import Env
from tests.support.clock import FakeClock
from tests.support.fs import db_files, read_all_bytes

E1 = "0192f3a4-5b6c-7d8e-9f01-000000000e01"
E2 = "0192f3a4-5b6c-7d8e-9f01-000000000e02"


def hold_event(store: Store, clock: FakeClock, data: bytes = b"event payload") -> str:
    expiry = default_expiry(RetentionClass.EVENT_PAYLOAD, clock.now(), RetentionPolicy())
    return store.store_content(data, "event", E1, RetentionClass.EVENT_PAYLOAD, expiry)


def test_configured_retention_is_used(clock: FakeClock) -> None:
    policy = RetentionPolicy(event_payload_days=7)
    assert default_expiry(RetentionClass.EVENT_PAYLOAD, clock.now(), policy) == clock.now() + timedelta(days=7)


def test_default_is_ninety_days_and_other_classes_never_expire(clock: FakeClock) -> None:
    default = RetentionPolicy()
    assert default_expiry(RetentionClass.EVENT_PAYLOAD, clock.now(), default) == clock.now() + timedelta(days=90)
    assert default_expiry(RetentionClass.EVIDENCE, clock.now(), default) is None
    assert default_expiry(RetentionClass.DURABLE, clock.now(), default) is None


@pytest.mark.parametrize("days", [0, 3651, -1, True, 7.0, "7"])
def test_out_of_range_retention_is_rejected(days: object) -> None:
    with pytest.raises(BrainError) as err:
        RetentionPolicy(event_payload_days=days)  # type: ignore[arg-type]
    assert err.value.code is ErrorCode.INVALID_INPUT


def test_naive_now_is_rejected(env: Env) -> None:
    with pytest.raises(BrainError) as err:
        expire_due(env.store, env.policy, datetime(2026, 1, 1))  # noqa: DTZ001
    assert err.value.code is ErrorCode.INVALID_INPUT
    with pytest.raises(AssertionError):
        default_expiry(RetentionClass.EVENT_PAYLOAD, datetime(2026, 1, 1), RetentionPolicy())  # noqa: DTZ001


def test_small_event_payload_expires_and_never_reaches_ledger(env: Env, clock: FakeClock) -> None:
    marker = b"tiny-secret-7f3a"
    d = hold_event(env.store, clock, marker)
    assert env.store.cas.exists(d) and env.store.cas.holders(d) != []
    expire_due(env.store, env.policy, clock.now() + timedelta(days=91))
    env.store.cas.collect_garbage(now=clock.now() + timedelta(days=92), grace=timedelta(0))
    assert not env.store.cas.exists(d)
    scanned = db_files(env.root.store_db) + db_files(env.root.policy_db)
    assert any(p.name.endswith(("-wal", "-shm")) for p in scanned)
    assert marker not in read_all_bytes(scanned)


def test_rebuild_does_not_resurrect_expired_holder(env: Env, clock: FakeClock) -> None:
    d = hold_event(env.store, clock)
    assert env.store.cas.exists(d) and env.store.cas.holders(d) != []
    expire_due(env.store, env.policy, clock.now() + timedelta(days=91))
    env.store.rebuild_projections()
    assert env.store.cas.holders(d) == []


def test_clock_going_backwards_expires_nothing(env: Env, clock: FakeClock) -> None:
    hold_event(env.store, clock)
    assert expire_due(env.store, env.policy, clock.now() - timedelta(days=365)).expired == ()
    assert expire_due(env.store, env.policy, clock.now() + timedelta(days=91)).expired == (("event", E1),)


def test_durable_holders_never_expire(env: Env, clock: FakeClock) -> None:
    d = env.store.store_content(b"lesson", "event", E1, RetentionClass.DURABLE, None)
    assert expire_due(env.store, env.policy, clock.now() + timedelta(days=10_000)).expired == ()
    assert env.store.cas.holders(d) != []


def test_holder_of_several_blobs_gets_one_tombstone(env: Env, clock: FakeClock) -> None:
    a = hold_event(env.store, clock, b"one")
    b = hold_event(env.store, clock, b"two")
    report = expire_due(env.store, env.policy, clock.now() + timedelta(days=91))
    assert report.expired == (("event", E1),)
    assert env.store.cas.holders(a) == [] and env.store.cas.holders(b) == []
    assert [i.kind for i in env.policy.intents()] == [IntentKind.TOMBSTONE]


def test_holder_with_a_durable_hold_is_not_tombstoned(env: Env, clock: FakeClock) -> None:
    expired = hold_event(env.store, clock, b"expiring")
    durable = env.store.store_content(b"keep", "event", E1, RetentionClass.DURABLE, None)
    assert expire_due(env.store, env.policy, clock.now() + timedelta(days=91)).expired == ()
    env.store.cas.collect_garbage(now=clock.now() + timedelta(days=92), grace=timedelta(0))
    assert env.store.cas.exists(expired) and env.store.cas.exists(durable)
    assert env.store.cas.holders(durable) != [] and env.policy.tombstones() == []


def test_holder_with_a_not_yet_due_hold_is_not_tombstoned(env: Env, clock: FakeClock) -> None:
    early = env.store.store_content(
        b"early", "event", E1, RetentionClass.EVENT_PAYLOAD, clock.now() + timedelta(days=1)
    )
    late = env.store.store_content(b"late", "event", E1, RetentionClass.EVENT_PAYLOAD, clock.now() + timedelta(days=90))
    assert expire_due(env.store, env.policy, clock.now() + timedelta(days=2)).expired == ()
    assert env.store.cas.holders(early) != [] and env.store.cas.holders(late) != []


def test_shared_blob_survives_when_only_one_holder_expires(env: Env, clock: FakeClock) -> None:
    short = clock.now() + timedelta(days=1)
    long = clock.now() + timedelta(days=90)
    d = env.store.store_content(b"shared", "event", E1, RetentionClass.EVENT_PAYLOAD, short)
    assert env.store.store_content(b"shared", "event", E2, RetentionClass.EVENT_PAYLOAD, long) == d
    assert expire_due(env.store, env.policy, clock.now() + timedelta(days=2)).expired == (("event", E1),)
    env.store.cas.collect_garbage(now=clock.now() + timedelta(days=3), grace=timedelta(0))
    assert env.store.cas.exists(d)
    assert env.store.cas.holders(d) == [("event", E2, RetentionClass.EVENT_PAYLOAD)]


def test_pending_intent_is_not_recorded_twice(env: Env, clock: FakeClock) -> None:
    hold_event(env.store, clock)
    env.policy.record_intent(IntentKind.TOMBSTONE, {"holder_kind": "event", "holder_id": E1})  # reconcile "failed"
    assert expire_due(env.store, env.policy, clock.now() + timedelta(days=91)).expired == (("event", E1),)
    assert len(env.policy.intents()) == 1
    assert env.store.cas.holders(hold_event_digest(env)) == []


def hold_event_digest(env: Env) -> str:
    from superbrain.core.canonical import digest_bytes

    return digest_bytes(b"event payload")


def test_non_canonical_expiry_in_the_ledger_fails_rebuild(env: Env, clock: FakeClock) -> None:
    d = hold_event(env.store, clock)
    meta = {
        "digest": d,
        "holder_kind": "event",
        "holder_id": E2,
        "retention": "event_payload",
        "expires_at": "2026-11-01T00:00:00Z",
    }
    with env.store.transaction() as t:
        t.db.execute(
            "INSERT INTO ledger (entry_id, kind, schema_version, handler_version, writer_epoch, actor, owner_id,"
            " recorded_at, meta, refs) VALUES (?, 'cas.hold', 1, 1, 1, 'user:cli', NULL,"
            " '2026-10-30T12:00:00.000000Z', ?, ?)",
            (str(uuid.uuid4()), json.dumps(meta).encode(), b"[]"),
        )
    before = env.store.cas.holders(d)
    with pytest.raises(BrainError) as err:
        env.store.rebuild_projections()
    assert err.value.code is ErrorCode.INTEGRITY_FAILURE
    assert env.store.cas.holders(d) == before
    with env.store.transaction() as t:
        tables = {str(r[0]) for r in t.db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert not any(name.startswith("r_") for name in tables)
