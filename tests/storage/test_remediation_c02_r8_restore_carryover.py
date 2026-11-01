"""SP1-C02 round 8: a policy restore keeps every history signal the live policy store holds.

Requirement (spec 5.4: the loss of ACKed data is never hidden behind a new store with the same identity; spec 5.7: a
policy restore never brings back an older security or lifecycle state; ledger C02, ruling "Review round 4" S5: the
staged policy gets ``meta.store_published`` if the backup has it, the live policy has the marker, the live policy has
ANY intent (tombstone or quarantine), or a published ``brain.db`` exists; review R4.5 survivor R2e: the live marker is
read like every other closed-database read, so committed WAL frames count even without ``-shm``):

* S5: on a root never started through ``open_runtime`` (storage API only, so the marker was never set), intents are
  recorded; ``brain.db`` is lost; the policy store is restored from a backup taken BEFORE those intents. The live
  intents are the only history signal left: the restored policy carries the marker, and the next ``open_runtime``
  refuses with ``INTEGRITY_FAILURE`` and creates no replacement.
* R2e: the live marker exists only in the policy WAL, with no ``-shm``; ``brain.db`` is lost; the policy store is
  restored from a pre-publish backup. The restored policy carries the marker, and the next start is refused.

Real storage APIs and the real permission guard throughout. The WAL-only marker is committed by a child that dies
before any checkpoint (the product writes the marker and then checkpoints it, with no crashpoint between), exactly as
the round-5 C01 test does; every other state comes from public APIs.
"""

from pathlib import Path

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.core.ids import new_id
from superbrain.ports.policy import IntentKind
from superbrain.storage.backup import create_policy_backup
from superbrain.storage.kinds import KindRegistry
from superbrain.storage.layout import DataRoot
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.store import Store
from tests.storage.conftest import DEMO_KINDS, maintenance_lease
from tests.storage.test_remediation_c01_r5_policy_wal_reader import MARKER_ROWS, main_file_only
from tests.storage.test_remediation_c01_wal_admission import commit_in_wal_then_crash
from tests.storage.test_remediation_c02_r6_restore_marker import (
    NOW,
    assert_refused_without_replacement,
    lose_brain_db,
    marker,
    restore,
    store_db_files,
)

INTENTS = {
    "tombstone": (IntentKind.TOMBSTONE, {"holder_kind": "event", "holder_id": "0192f3a4-5b6c-7d8e-9f01-0000000c0281"}),
    "quarantine": (IntentKind.QUARANTINE, {"digest": "sha256:" + "cd" * 32}),
}


def storage_api_root(data_root: Path) -> tuple[Path, str]:
    """A policy store and a published ``brain.db`` made with the storage API only (never ``open_runtime``: no
    marker), and a policy backup of that state, with no intent and no marker. Returns ``(backup, store_id)``."""
    with maintenance_lease(data_root) as (root, lease):
        policy = PolicyStore.create(root, lease, os_adapters(), store_id=new_id())
        try:
            Store.create(root, lease, os_adapters(), policy, (), KindRegistry(DEMO_KINDS)).close()
            return create_policy_backup(policy, os_adapters(), NOW), policy.store_id
        finally:
            policy.close()


@pytest.mark.parametrize("intent", sorted(INTENTS))
def test_live_intents_carry_the_signal_through_a_restore_after_brain_db_is_lost(trusted_tmp: Path, intent: str) -> None:
    data_root = trusted_tmp / "r"
    backup, store_id = storage_api_root(data_root)
    kind, payload = INTENTS[intent]
    with maintenance_lease(data_root) as (root, lease):
        policy = PolicyStore.open(root, lease, os_adapters())
        try:
            policy.record_intent(kind, payload)  # recorded after the backup: the backup lacks it
        finally:
            policy.close()
    root = DataRoot.at(data_root)
    assert marker(root, trusted_tmp / "live") == []  # never opened through open_runtime: no marker
    lose_brain_db(root, trusted_tmp / "preserved")
    assert [p for p in store_db_files(root) if p.exists()] == []

    restore(data_root, backup, store_id)

    assert marker(root, trusted_tmp / "restored") == [("1",)], "the restore dropped the live intents' history signal"
    assert_refused_without_replacement(data_root)


def test_a_live_marker_committed_only_in_the_policy_wal_is_carried_through_a_restore(trusted_tmp: Path) -> None:
    data_root = trusted_tmp / "r"
    backup, store_id = storage_api_root(data_root)
    root = DataRoot.at(data_root)
    commit_in_wal_then_crash(root.policy_db, "INSERT INTO meta (key, value) VALUES ('store_published', '1')")
    assert main_file_only(root.policy_db, MARKER_ROWS) == 0  # only the WAL holds the live marker
    assert marker(root, trusted_tmp / "live") == [("1",)]
    lose_brain_db(root, trusted_tmp / "preserved")

    restore(data_root, backup, store_id)

    assert marker(root, trusted_tmp / "restored") == [("1",)], "the restore missed a live marker held in the WAL"
    assert_refused_without_replacement(data_root)
