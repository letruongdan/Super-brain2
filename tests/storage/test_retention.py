"""Retention: configurable default expiry, the expiry sweep, and scenario 35 (no payload bytes in any DB file)."""

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
    expire_due(env.store, env.policy, clock.now() + timedelta(days=91))
    env.store.cas.collect_garbage(now=clock.now() + timedelta(days=92), grace=timedelta(0))
    assert not env.store.cas.exists(d)
    assert marker not in read_all_bytes(db_files(env.root.store_db) + db_files(env.root.policy_db))


def test_rebuild_does_not_resurrect_expired_holder(env: Env, clock: FakeClock) -> None:
    d = hold_event(env.store, clock)
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
