"""SP1-C01 round 5: the missing-store guard reads the policy store's committed WAL frames when ``-shm`` is missing.

Requirement (spec 5.8 and 5.4: admission and history decisions reflect the real committed state; review SP1-C01
"Kiểm thêm các reader dùng chung cho intent"; ledger C01 and C02; independent review round 2, item R2.6 #1, mutant
M2g, which reverts this reader to ``immutable=1``): when ``brain.db`` is lost, the start-up guard decides from the
policy store whether the store has history. An intent, or the published-store marker (``meta.store_published``),
committed only in the policy store's ``-wal`` with no ``-shm`` is committed history: ``open_runtime`` refuses with
``INTEGRITY_FAILURE`` and creates no replacement ``brain.db``.

The state is built without ``open_runtime`` (which would write the marker and checkpoint it into the main file and
so mask the reader): ``PolicyStore.create`` and ``Store.create`` under a maintenance lease. Then a real child commits
into the policy WAL and dies before any checkpoint, and only the ``-shm`` is removed:

* the intent case uses the public ``record_intent`` and the registered crashpoint ``policy.after_intent_commit``;
* the marker case: the product writes the marker and then checkpoints it, with no crashpoint between the two, so a
  child commits exactly that row (``meta``: ``store_published`` = ``'1'``) through SQLite and dies. That is the
  committed state a crash between the marker's commit and its checkpoint leaves.

Each test first shows the discriminating precondition: the main file alone (``immutable=1``) has no intent and no
marker, while SQLite's own recovery of a copy of the database and its WAL has it.
"""

import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.storage.kinds import KindRegistry
from superbrain.storage.layout import DataRoot
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.runtime import open_runtime
from superbrain.storage.store import Store
from tests.storage.conftest import maintenance_lease
from tests.storage.test_remediation_c01_wal_admission import commit_in_wal_then_crash, shm, wal
from tests.support.crash import CHILD_TIMEOUT, CRASH_EXIT, child_env

HOLDER = "0192f3a4-5b6c-7d8e-9f01-0000000c0151"
INTENT_ROWS = "SELECT COUNT(*) FROM intents"
MARKER_ROWS = "SELECT COUNT(*) FROM meta WHERE key = 'store_published' AND value = '1'"

# Open the existing policy store under the writer lease (no open_runtime: no marker) and record one intent; the
# child is started with SUPERBRAIN_CRASHPOINT=policy.after_intent_commit, so it dies right after the commit.
_RECORD_INTENT = """
import sys
from pathlib import Path
from superbrain.adapters.os import os_adapters
from superbrain.ports.policy import IntentKind
from superbrain.storage.layout import prepare_data_root
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.writer import acquire_writer

os_ = os_adapters()
root = prepare_data_root(Path(sys.argv[1]), os_)
lease = acquire_writer(root, os_)
policy = PolicyStore.open(root, lease, os_)
policy.record_intent(IntentKind.TOMBSTONE, {"holder_kind": "event", "holder_id": sys.argv[2]})
sys.stderr.write("NOT_CRASHED\\n")
"""


def published_store_without_marker(data_root: Path) -> DataRoot:
    """A policy store and a published ``brain.db`` made with the storage API only: no intent, no marker."""
    with maintenance_lease(data_root) as (root, lease):
        policy = PolicyStore.create(root, lease, os_adapters(), store_id=new_id())
        try:
            Store.create(root, lease, os_adapters(), policy, (), KindRegistry(())).close()
        finally:
            policy.close()
    root = DataRoot.at(data_root)
    assert root.store_db.exists() and not wal(root.policy_db).exists()
    return root


def main_file_only(db: Path, sql: str) -> int:
    """``sql`` on the main database file alone (``immutable=1``: the WAL is ignored, nothing is written)."""
    con = sqlite3.connect(f"{db.absolute().as_uri()}?immutable=1", uri=True)
    try:
        return int(con.execute(sql).fetchone()[0])
    finally:
        con.close()


def recovered(db: Path, scratch: Path, sql: str) -> int:
    """``sql`` on what SQLite recovers from a copy of ``db`` and its ``-wal`` (the oracle; ``db`` is not opened)."""
    scratch.mkdir()
    copy = scratch / db.name
    shutil.copyfile(db, copy)
    shutil.copyfile(wal(db), wal(copy))
    con = sqlite3.connect(copy)
    try:
        return int(con.execute(sql).fetchone()[0])
    finally:
        con.close()


def lose_brain_db(root: DataRoot, preserved: Path) -> None:
    preserved.mkdir()
    for path in (root.store_db, wal(root.store_db), shm(root.store_db)):
        if path.exists():
            path.rename(preserved / path.name)


def assert_refused_without_replacement(data_root: Path, root: DataRoot) -> None:
    with pytest.raises(BrainError) as refused:
        open_runtime(data_root, os_adapters()).close()
    assert refused.value.code == ErrorCode.INTEGRITY_FAILURE
    left = [p.name for p in (root.store_db, wal(root.store_db), shm(root.store_db)) if p.exists()]
    assert left == [], "a replacement main database was created"


def test_an_intent_committed_only_in_the_policy_wal_blocks_a_lost_main_db(trusted_tmp: Path) -> None:
    data_root = trusted_tmp / "r"
    root = published_store_without_marker(data_root)
    done = subprocess.run(
        [sys.executable, "-I", "-c", _RECORD_INTENT, str(data_root), HOLDER],
        env=child_env({"SUPERBRAIN_CRASHPOINT": "policy.after_intent_commit"}),
        capture_output=True,
        text=True,
        timeout=CHILD_TIMEOUT,
        check=False,
    )
    assert done.returncode == CRASH_EXIT and "CRASHPOINT_HIT policy.after_intent_commit" in done.stderr, done.stderr
    assert wal(root.policy_db).stat().st_size > 32 and shm(root.policy_db).exists()
    shm(root.policy_db).unlink()
    assert main_file_only(root.policy_db, INTENT_ROWS) == 0  # only the WAL holds the intent
    assert recovered(root.policy_db, trusted_tmp / "oracle", INTENT_ROWS) == 1
    assert main_file_only(root.policy_db, MARKER_ROWS) == 0
    lose_brain_db(root, trusted_tmp / "preserved")

    assert_refused_without_replacement(data_root, root)


def test_the_published_marker_committed_only_in_the_policy_wal_blocks_a_lost_main_db(trusted_tmp: Path) -> None:
    data_root = trusted_tmp / "r"
    root = published_store_without_marker(data_root)
    commit_in_wal_then_crash(root.policy_db, "INSERT INTO meta (key, value) VALUES ('store_published', '1')")
    assert main_file_only(root.policy_db, MARKER_ROWS) == 0  # only the WAL holds the marker
    assert recovered(root.policy_db, trusted_tmp / "oracle", MARKER_ROWS) == 1
    assert main_file_only(root.policy_db, INTENT_ROWS) == 0
    lose_brain_db(root, trusted_tmp / "preserved")

    assert_refused_without_replacement(data_root, root)
