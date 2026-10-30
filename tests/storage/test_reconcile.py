from pathlib import Path

from superbrain.adapters.os import os_adapters
from superbrain.core.canonical import digest_bytes
from superbrain.ports.policy import IntentKind
from superbrain.storage.cas import RetentionClass
from superbrain.storage.runtime import open_runtime
from superbrain.storage.store import Store
from tests.storage.conftest import Env
from tests.support.crash import run_child, run_until_crash
from tests.support.fs import digest_tree

E1 = "0192f3a4-5b6c-7d8e-9f01-000000000e01"  # crash_child.EVENT_ID
E2 = "0192f3a4-5b6c-7d8e-9f01-000000000e02"
V1 = "0192f3a4-5b6c-7d8e-9f01-000000000f01"
D = digest_bytes(b"event payload")  # crash_child.EVENT_PAYLOAD


def seed_event(data_root: Path) -> None:
    result = run_child("seed_event", data_root)
    assert result.returncode == 0, f"seed_event failed:\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"


def count_entries(store: Store, kind: str) -> int:
    return sum(1 for entry in store.entries() if entry.kind == kind)


def applied_intents(store: Store) -> list[str]:
    with store.transaction() as t:
        rows = t.db.execute("SELECT intent_id FROM applied_intents ORDER BY intent_id").fetchall()
    return [str(row[0]) for row in rows]


def hold(store: Store, data: bytes, holders: list[tuple[str, str]]) -> str:
    digest = store.cas.put(data)
    with store.transaction() as t:
        for holder_kind, holder_id in holders:
            t.hold(digest, holder_kind, holder_id, RetentionClass.EVIDENCE, None)
    return digest


# --- crash between the policy commit and the store apply (scenario 34) -----------------------------------------


def test_crash_between_policy_and_store_applies_exactly_once(trusted_tmp: Path) -> None:
    seed_event(trusted_tmp)
    run_until_crash("tombstone_event", "policy.after_intent_commit", trusted_tmp)
    rt = open_runtime(trusted_tmp, os_adapters())
    assert rt.store.cas.holders(D) == [] and count_entries(rt.store, "policy.tombstone") == 1
    rt.close()
    rt = open_runtime(trusted_tmp, os_adapters())
    assert count_entries(rt.store, "policy.tombstone") == 1
    rt.close()


def test_crash_after_store_apply_does_not_duplicate(trusted_tmp: Path) -> None:
    seed_event(trusted_tmp)
    run_until_crash("tombstone_event", "intents.after_store_apply", trusted_tmp)
    rt = open_runtime(trusted_tmp, os_adapters())
    assert count_entries(rt.store, "policy.tombstone") == 1 and count_entries(rt.store, "cas.release") == 1
    assert rt.store.cas.holders(D) == [] and rt.store.reconcile_policy() == 0
    rt.close()


def test_tombstone_event_without_crash_applies_once(trusted_tmp: Path) -> None:
    seed_event(trusted_tmp)
    result = run_child("tombstone_event", trusted_tmp)
    assert result.returncode == 0, result.stdout + result.stderr
    rt = open_runtime(trusted_tmp, os_adapters())
    assert rt.store.cas.holders(D) == [] and rt.store.cas.orphans() == [D]
    assert count_entries(rt.store, "policy.tombstone") == 1 and count_entries(rt.store, "cas.release") == 1
    rt.close()


# --- reconcile never writes to the policy store ----------------------------------------------------------------


def test_reconcile_does_not_write_to_policy(env: Env) -> None:
    before = digest_tree(env.root.policy_dir)
    env.store.reconcile_policy()
    assert digest_tree(env.root.policy_dir) == before


def test_reconcile_with_pending_intents_does_not_write_to_policy(env: Env) -> None:
    hold(env.store, b"x", [("event", E1)])
    env.policy.record_intent(IntentKind.TOMBSTONE, {"holder_kind": "event", "holder_id": E1})
    env.policy.record_intent(IntentKind.QUARANTINE, {"digest": D})
    env.policy.intents()  # a first read after the writes may take a WAL read mark in -shm; settle it first
    before = digest_tree(env.root.policy_dir)
    assert env.store.reconcile_policy() == 2
    assert digest_tree(env.root.policy_dir) == before


# --- effects ---------------------------------------------------------------------------------------------------


def test_tombstone_releases_every_blob_of_that_holder_only(env: Env) -> None:
    d1 = hold(env.store, b"one", [("event", E1), ("evidence", V1)])
    d2 = hold(env.store, b"two", [("event", E1)])
    d3 = hold(env.store, b"three", [("event", E2)])
    intent = env.policy.record_intent(IntentKind.TOMBSTONE, {"holder_kind": "event", "holder_id": E1})
    assert len(env.store.cas.holders(d1)) == 2  # blocked in policy, not yet applied to the store
    assert env.store.reconcile_policy() == 1
    assert env.store.cas.holders(d1) == [("evidence", V1, RetentionClass.EVIDENCE)]
    assert env.store.cas.holders(d2) == [] and len(env.store.cas.holders(d3)) == 1
    new = [e for e in env.store.entries() if e.kind.startswith("policy.") or e.kind == "cas.release"]
    assert [e.kind for e in new] == ["policy.tombstone", "cas.release", "cas.release"]
    assert new[0].meta == {"holder_kind": "event", "holder_id": E1, "intent_id": intent.intent_id}
    assert sorted(str(e.meta["digest"]) for e in new[1:]) == sorted([d1, d2])
    assert all(e.meta["reason"] == "tombstoned" and e.meta["holder_id"] == E1 for e in new[1:])
    assert new[0].actor == "system:policy" and new[0].owner_id is None
    assert applied_intents(env.store) == [intent.intent_id]


def test_quarantine_is_recorded_and_keeps_holders(env: Env) -> None:
    d = hold(env.store, b"q", [("event", E1)])
    intent = env.policy.record_intent(IntentKind.QUARANTINE, {"digest": d})
    assert env.store.reconcile_policy() == 1
    [entry] = [e for e in env.store.entries() if e.kind == "policy.quarantine"]
    assert entry.meta == {"digest": d, "intent_id": intent.intent_id}
    assert entry.actor == "system:policy" and entry.owner_id is None
    assert len(env.store.cas.holders(d)) == 1


def test_reconcile_applies_each_intent_once_in_order(env: Env) -> None:
    hold(env.store, b"x", [("event", E1)])
    first = env.policy.record_intent(IntentKind.TOMBSTONE, {"holder_kind": "event", "holder_id": E1})
    second = env.policy.record_intent(IntentKind.TOMBSTONE, {"holder_kind": "event", "holder_id": E1})
    third = env.policy.record_intent(IntentKind.QUARANTINE, {"digest": D})
    assert env.store.reconcile_policy() == 3
    assert env.store.reconcile_policy() == 0
    kinds = [e.kind for e in env.store.entries() if e.kind != "cas.hold"]
    assert kinds == ["policy.tombstone", "cas.release", "policy.tombstone", "policy.quarantine"]
    marked = [str(e.meta["intent_id"]) for e in env.store.entries() if e.kind.startswith("policy.")]
    assert marked == [first.intent_id, second.intent_id, third.intent_id]
    assert applied_intents(env.store) == sorted(marked)


def test_tombstone_also_blocks_later_holds(env: Env) -> None:
    env.policy.record_intent(IntentKind.TOMBSTONE, {"holder_kind": "event", "holder_id": E1})
    d = hold(env.store, b"late", [("event", E1)])
    assert env.store.cas.holders(d) == []
    assert env.store.reconcile_policy() == 1 and count_entries(env.store, "cas.release") == 0


def test_store_open_reconciles_pending_intents(trusted_tmp: Path) -> None:
    rt = open_runtime(trusted_tmp / "r", os_adapters())
    d = hold(rt.store, b"pending", [("event", E1)])
    intent = rt.policy.record_intent(IntentKind.TOMBSTONE, {"holder_kind": "event", "holder_id": E1})
    rt.close()
    rt = open_runtime(trusted_tmp / "r", os_adapters())
    assert rt.store.cas.holders(d) == [] and applied_intents(rt.store) == [intent.intent_id]
    assert rt.store.reconcile_policy() == 0
    rt.close()
