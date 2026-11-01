"""SP1-C02 round 4: policy intents remain store history even without the published-store marker.

Requirement (spec 5.4 "Trạng thái bảo mật đi trước": security intents are recorded before they are applied to the
store, so an intent shows the store existed and must receive it; spec 5.7: a policy store can be restored on its
own, from a backup; ledger C02 and the round-2 ruling; owner round-2 survivor "guard ignores intents"): if the
policy store holds TOMBSTONE or QUARANTINE intents but ``meta.store_published`` is absent, losing ``brain.db`` is
still refused with ``INTEGRITY_FAILURE`` and no replacement database is created.

The state is built only through public APIs: the policy store and the store are created with the storage API
(``PolicyStore.create``, ``Store.create``; the marker belongs to ``open_runtime``, which never runs here, so the marker
is never set), an intent is recorded through ``PolicyStore.record_intent`` and applied, and ``brain.db`` is lost. No
database is edited directly; the intent's presence and the marker's absence are only checked, on a copy.

Round 7 (ruling of 2026-11-01, "Owner round 6", blocker 1): the round-4 version reached "intents without a marker"
by restoring an older policy backup after ``open_runtime`` had set the marker. The round-6 ruling makes
``restore_policy`` keep or set the marker whenever ``brain.db`` exists, so that route no longer yields the state. The
state is now built on a root where the marker was never set; the oracle (refusal, no replacement) is unchanged.
"""

import shutil
import sqlite3
from pathlib import Path

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.ports.policy import IntentKind
from superbrain.storage.kinds import KindRegistry
from superbrain.storage.layout import DataRoot
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.runtime import open_runtime
from superbrain.storage.store import Store
from tests.storage.conftest import maintenance_lease

INTENTS = {
    "tombstone": (IntentKind.TOMBSTONE, {"holder_kind": "event", "holder_id": "0192f3a4-5b6c-7d8e-9f01-0000000c0241"}),
    "quarantine": (IntentKind.QUARANTINE, {"digest": "sha256:" + "ab" * 32}),
}


def store_db_files(root: DataRoot) -> list[Path]:
    db = root.store_db
    return [db, db.with_name(db.name + "-wal"), db.with_name(db.name + "-shm")]


def committed_rows(db: Path, scratch: Path, sql: str) -> list[tuple[object, ...]]:
    """``sql`` on what SQLite recovers from a copy of ``db`` (and its ``-wal``); ``db`` itself is not opened."""
    scratch.mkdir()
    copy = scratch / db.name
    shutil.copyfile(db, copy)
    if db.with_name(db.name + "-wal").exists():
        shutil.copyfile(db.with_name(db.name + "-wal"), copy.with_name(copy.name + "-wal"))
    con = sqlite3.connect(copy)
    try:
        return con.execute(sql).fetchall()
    finally:
        con.close()


@pytest.mark.parametrize("intent", sorted(INTENTS))
def test_policy_intents_without_the_published_marker_still_block_a_lost_main_db(trusted_tmp: Path, intent: str) -> None:
    data_root = trusted_tmp / "r"
    kind, payload = INTENTS[intent]
    with maintenance_lease(data_root) as (root, lease):
        # The store and policy store as created by the storage API alone: no ``open_runtime``, so no marker ever.
        policy = PolicyStore.create(root, lease, os_adapters(), store_id=new_id())
        try:
            store = Store.create(root, lease, os_adapters(), policy, (), KindRegistry(()))
            try:
                policy.record_intent(kind, payload)
                store.reconcile_policy()
            finally:
                store.close()
        finally:
            policy.close()
    root = DataRoot.at(data_root)
    assert root.store_db.exists()  # the store was published
    assert committed_rows(root.policy_db, trusted_tmp / "intents", "SELECT kind FROM intents") == [(kind.value,)]
    marker = "SELECT value FROM meta WHERE key = 'store_published'"
    assert committed_rows(root.policy_db, trusted_tmp / "marker", marker) == []  # the marker was never set
    preserved = trusted_tmp / "preserved"
    preserved.mkdir()
    for path in store_db_files(root):
        if path.exists():
            path.rename(preserved / path.name)

    with pytest.raises(BrainError) as refused:
        open_runtime(data_root, os_adapters()).close()

    assert refused.value.code == ErrorCode.INTEGRITY_FAILURE
    assert [p.name for p in store_db_files(root) if p.exists()] == [], "a replacement main database was created"
