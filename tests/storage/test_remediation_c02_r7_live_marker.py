"""SP1-C02 round 7: the restored policy store keeps the LIVE policy's marker even when ``brain.db`` is already gone.

Requirement (spec 5.4: the loss of ACKed data is never hidden behind a new store with the same identity; spec 5.7;
ledger C02, ruling of 2026-11-01: the staged policy gets ``meta.store_published`` if the backup, the live policy
store OR a published ``brain.db`` has it; ruling after "Owner round 6": an oracle for the "ignore the live marker"
survivor, which every earlier test masked because ``brain.db`` was still present at restore time):

a store published by ``open_runtime`` (so the live policy has the marker) with one ledger-only entry loses
``brain.db``; then the policy store is restored from a backup taken before the first publish (no marker in the
backup, no ``brain.db`` on disk). The only remaining evidence is the live policy's marker: the restored policy must
carry it, and the next ``open_runtime`` must refuse with ``INTEGRITY_FAILURE`` and create no replacement database.
"""

from pathlib import Path

from superbrain.storage.layout import DataRoot
from tests.storage.test_remediation_c02_r6_restore_marker import (
    assert_refused_without_replacement,
    early_policy_backup,
    lose_brain_db,
    marker,
    publish_with_a_ledger_only_entry,
    restore,
    store_db_files,
)


def test_a_restore_after_brain_db_is_lost_keeps_the_live_marker_and_the_next_start_is_refused(
    trusted_tmp: Path,
) -> None:
    data_root = trusted_tmp / "r"
    backup, store_id = early_policy_backup(data_root)
    publish_with_a_ledger_only_entry(data_root)
    root = DataRoot.at(data_root)
    assert marker(root, trusted_tmp / "live") == [("1",)]  # the live policy says the store was published
    lose_brain_db(root, trusted_tmp / "preserved")
    assert [p for p in store_db_files(root) if p.exists()] == []  # no brain.db can supply the signal

    restore(data_root, backup, store_id)

    assert marker(root, trusted_tmp / "restored") == [("1",)], "the restore dropped the live policy's marker"
    assert_refused_without_replacement(data_root)
