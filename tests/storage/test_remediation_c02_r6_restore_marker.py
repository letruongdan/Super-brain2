"""SP1-C02 round 6: a policy restore never rolls back the published-store signal.

Requirement (spec 5.4: ACKed data is not lost on process death, so its loss is never hidden behind a new store with
the same identity; spec 5.7: the policy store is restored on its own, and a restore must not bring back an older
security/lifecycle state; ledger C02 and the ruling of 2026-11-01, section "Re-opened 2026-11-01"; owner Codex
re-review of 2026-10-31, SP1-C02 P1 counterexample):

* The ruling: in ``restore_policy``'s staged copy, before the swap, ``meta.store_published`` is set to ``'1'`` if the
  backup has it, the live policy store has it, or a published ``brain.db`` exists. So right after a restore the
  restored policy store carries the marker, and a crash before the swap (old policy kept) or after it (new policy
  with the marker) leaves the signal intact.
* Then, once ``brain.db`` is lost, ``open_runtime`` refuses with ``INTEGRITY_FAILURE`` and creates no replacement
  (the re-review's chain: policy backup before the first publish -> ledger-only entry -> restore_policy -> brain.db
  lost -> must not become an empty store with the same ``store_id``).
* Kept valid: a fresh root opens; a restore onto a root whose store was never published invents no marker (and the
  next start creates the store); a restore onto a root with a published ``brain.db`` but no marker sets it.

Everything goes through the real storage API and the real permission guard. The marker is only read, on a copy of
``policy.db`` (and its WAL) recovered by SQLite itself. Crashes are real: a child process dies at the registered
``restoring.policy.*`` crashpoints.
"""

import shutil
import sqlite3
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.storage.backup import create_policy_backup
from superbrain.storage.kinds import KindRegistry
from superbrain.storage.layout import DataRoot
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.restore import restore_policy
from superbrain.storage.runtime import open_runtime
from superbrain.storage.store import Store
from tests.storage.conftest import DEMO_KINDS, maintenance_lease
from tests.support.crash import CHILD_TIMEOUT, CRASH_EXIT, child_env

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
MARKER = "SELECT value FROM meta WHERE key = 'store_published'"
RESTORE_CRASHPOINTS = [
    "restoring.policy.after_generation_persist",  # inside the stage, before the swap
    "restoring.policy.after_stage",  # stage complete, before the swap
    "restoring.policy.between_renames",  # old policy moved aside, stage not yet in place
    "restoring.policy.before_hwm_update",  # after the swap
]

# restore_policy under the maintenance start-up sequence, in a child that the crash tests stop at a crashpoint.
_RESTORE_POLICY = """
import sys
from datetime import UTC, datetime
from pathlib import Path
from superbrain.adapters.os import os_adapters
from superbrain.storage.layout import prepare_data_root, secure_subdirectories
from superbrain.storage.restore import restore_policy
from superbrain.storage.swap import recover_interrupted_swaps
from superbrain.storage.writer import acquire_writer

os_ = os_adapters()
root = prepare_data_root(Path(sys.argv[1]), os_)
with acquire_writer(root, os_) as lease:
    recover_interrupted_swaps(root, lease, os_)
    secure_subdirectories(root, lease, os_)
    restore_policy(root, lease, os_, Path(sys.argv[2]), store_id=sys.argv[3], now=datetime.now(UTC))
sys.stderr.write("RESTORED\\n")
"""


def store_db_files(root: DataRoot) -> list[Path]:
    db = root.store_db
    return [db, db.with_name(db.name + "-wal"), db.with_name(db.name + "-shm")]


def marker(root: DataRoot, scratch: Path) -> list[tuple[object, ...]]:
    """The committed ``meta.store_published`` rows of ``policy.db``, read by SQLite from a copy (+ its WAL)."""
    scratch.mkdir()
    db = root.policy_db
    copy = scratch / db.name
    shutil.copyfile(db, copy)
    if db.with_name(db.name + "-wal").exists():
        shutil.copyfile(db.with_name(db.name + "-wal"), copy.with_name(copy.name + "-wal"))
    con = sqlite3.connect(copy)
    try:
        return con.execute(MARKER).fetchall()
    finally:
        con.close()


def early_policy_backup(data_root: Path, *, publish_without_marker: bool = False) -> tuple[Path, str]:
    """A policy backup taken before ``open_runtime`` ever published the store (so it has no marker).

    With ``publish_without_marker``, ``brain.db`` is also published through the storage API (``Store.create``),
    which writes no marker: the marker belongs to ``open_runtime``."""
    with maintenance_lease(data_root) as (root, lease):
        policy = PolicyStore.create(root, lease, os_adapters(), store_id=new_id())
        try:
            if publish_without_marker:
                Store.create(root, lease, os_adapters(), policy, (), KindRegistry(DEMO_KINDS)).close()
            return create_policy_backup(policy, os_adapters(), NOW), policy.store_id
        finally:
            policy.close()


def publish_with_a_ledger_only_entry(data_root: Path) -> None:
    rt = open_runtime(data_root, os_adapters(), kinds=KindRegistry(DEMO_KINDS))
    try:
        with rt.store.transaction() as txn:
            txn.append("demo.count", actor="user:cli", owner_id="dan", meta={"n": 1})
        assert len(list(rt.store.entries())) == 1
    finally:
        rt.close()
    assert list(DataRoot.at(data_root).cas_dir.iterdir()) == []  # ledger-only: nothing in cas/


def restore(data_root: Path, backup: Path, store_id: str) -> None:
    with maintenance_lease(data_root) as (root, lease):
        restore_policy(root, lease, os_adapters(), backup, store_id=store_id, now=NOW)


def lose_brain_db(root: DataRoot, preserved: Path) -> None:
    preserved.mkdir()
    for path in store_db_files(root):
        if path.exists():
            path.rename(preserved / path.name)


def assert_refused_without_replacement(data_root: Path) -> None:
    with pytest.raises(BrainError) as refused:
        open_runtime(data_root, os_adapters(), kinds=KindRegistry(DEMO_KINDS)).close()
    assert refused.value.code == ErrorCode.INTEGRITY_FAILURE
    left = [p.name for p in store_db_files(DataRoot.at(data_root)) if p.exists()]
    assert left == [], "an empty replacement main database was created with the same store_id"


def test_a_restore_from_a_pre_publish_backup_keeps_the_marker_and_a_lost_main_db_is_refused(trusted_tmp: Path) -> None:
    data_root = trusted_tmp / "r"
    backup, store_id = early_policy_backup(data_root)
    publish_with_a_ledger_only_entry(data_root)
    root = DataRoot.at(data_root)
    assert marker(root, trusted_tmp / "before") == [("1",)]

    restore(data_root, backup, store_id)

    assert marker(root, trusted_tmp / "after") == [("1",)], "restore_policy rolled back meta.store_published"
    lose_brain_db(root, trusted_tmp / "preserved")
    assert_refused_without_replacement(data_root)


@pytest.mark.parametrize("crashpoint", RESTORE_CRASHPOINTS)
def test_a_crashed_policy_restore_keeps_the_signal(trusted_tmp: Path, crashpoint: str) -> None:
    data_root = trusted_tmp / "r"
    backup, store_id = early_policy_backup(data_root)
    publish_with_a_ledger_only_entry(data_root)
    done = subprocess.run(
        [sys.executable, "-I", "-c", _RESTORE_POLICY, str(data_root), str(backup), store_id],
        env=child_env({"SUPERBRAIN_CRASHPOINT": crashpoint}),
        capture_output=True,
        text=True,
        timeout=CHILD_TIMEOUT,
        check=False,
    )
    assert done.returncode == CRASH_EXIT and f"CRASHPOINT_HIT {crashpoint}" in done.stderr, done.stderr
    with maintenance_lease(data_root):
        pass  # the next start-up resolves the interrupted swap
    root = DataRoot.at(data_root)

    assert marker(root, trusted_tmp / "after") == [("1",)], f"a crash at {crashpoint} lost meta.store_published"
    lose_brain_db(root, trusted_tmp / "preserved")
    assert_refused_without_replacement(data_root)


def test_a_restore_onto_a_root_with_a_published_store_but_no_marker_sets_it(trusted_tmp: Path) -> None:
    data_root = trusted_tmp / "r"
    backup, store_id = early_policy_backup(data_root, publish_without_marker=True)
    root = DataRoot.at(data_root)
    assert root.store_db.exists() and marker(root, trusted_tmp / "before") == []

    restore(data_root, backup, store_id)

    assert marker(root, trusted_tmp / "after") == [("1",)], "a published brain.db did not mark the restored policy"
    lose_brain_db(root, trusted_tmp / "preserved")
    assert_refused_without_replacement(data_root)


def test_a_restore_onto_a_never_published_root_invents_no_marker(trusted_tmp: Path) -> None:
    data_root = trusted_tmp / "r"
    backup, store_id = early_policy_backup(data_root)
    root = DataRoot.at(data_root)
    assert not root.store_db.exists()

    restore(data_root, backup, store_id)

    assert marker(root, trusted_tmp / "after") == []
    rt = open_runtime(data_root, os_adapters())  # still a valid first start: the store is created
    try:
        assert rt.store.store_id == store_id and list(rt.store.entries()) == []
    finally:
        rt.close()


def test_a_fresh_root_still_opens(trusted_tmp: Path) -> None:
    rt = open_runtime(trusted_tmp / "r", os_adapters())
    try:
        assert rt.store.store_id == rt.policy.store_id
    finally:
        rt.close()
