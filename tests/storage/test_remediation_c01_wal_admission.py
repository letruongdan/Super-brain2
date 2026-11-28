"""SP1-C01: version admission and the shared closed-database readers must see committed WAL frames when the SHM
file is missing.

Requirement (spec 5.8, review SP1-C01, ledger C01): a binary that meets a store whose schema is newer than it
supports refuses **before any write**. The ``-shm`` file is a rebuildable index; its absence says nothing about
whether the ``-wal`` holds committed transactions. So a committed WAL without SHM is committed state, never "stale"
state. The same holds for the readers that look at a closed database: the missing-store guard's intent reader and
the live trust-generation read used by ``restore_policy``.

Every committed WAL here is produced by a real child process that commits through SQLite in WAL mode with
``synchronous=FULL`` and autocheckpoint off, then dies with ``os._exit`` (no close, no checkpoint). The expected
values are computed independently: what SQLite itself recovers from a copy of the database files.
A WAL with no committed frames (empty or garbage) is a separate case and must not be read as committed state.
"""

import os
import shutil
import sqlite3
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.storage.backup import create_policy_backup
from superbrain.storage.cas import RetentionClass
from superbrain.storage.layout import DataRoot
from superbrain.storage.restore import restore_policy
from superbrain.storage.runtime import open_runtime
from superbrain.storage.schema import POLICY_MIGRATIONS, STORE_MIGRATIONS, read_schema_info
from tests.storage.conftest import maintenance_lease
from tests.support.crash import CHILD_TIMEOUT, CRASH_EXIT, run_child, run_until_crash
from tests.support.fs import digest_tree
from tests.support.inc2_fixture import open_cloned_runtime

NOW = datetime(2026, 10, 31, 12, 0, tzinfo=UTC)
HOLDER = "0192f3a4-5b6c-7d8e-9f01-0000000c0101"
PAYLOAD = b"c01: written by a binary that only knows schema 1"
WAL_HEADER_SIZE = 32

# Commit one statement in WAL mode, then die without closing (so neither a checkpoint nor a WAL delete happens).
_COMMIT_THEN_DIE = (
    "import os, sqlite3, sys\n"
    "db = sqlite3.connect(sys.argv[1], isolation_level=None)\n"
    "mode = db.execute('PRAGMA journal_mode=WAL').fetchone()[0]\n"
    "assert str(mode).lower() == 'wal', mode\n"
    "db.execute('PRAGMA synchronous=FULL')\n"
    "db.execute('PRAGMA wal_autocheckpoint=0')\n"
    "db.execute(sys.argv[2])\n"
    "sys.stderr.write('COMMITTED\\n'); sys.stderr.flush()\n"
    f"os._exit({CRASH_EXIT})\n"
)


def wal(db: Path) -> Path:
    return db.with_name(db.name + "-wal")


def shm(db: Path) -> Path:
    return db.with_name(db.name + "-shm")


def commit_in_wal_then_crash(db: Path, sql: str) -> None:
    """A real child commits ``sql`` to ``db`` in WAL mode and dies; then only the ``-shm`` is removed."""
    done = subprocess.run(
        [sys.executable, "-I", "-c", _COMMIT_THEN_DIE, str(db), sql],
        capture_output=True,
        text=True,
        timeout=CHILD_TIMEOUT,
        check=False,
    )
    assert done.returncode == CRASH_EXIT and "COMMITTED" in done.stderr, done.stderr
    assert wal(db).stat().st_size > WAL_HEADER_SIZE, "the child left no committed WAL frames"
    assert shm(db).exists()
    shm(db).unlink()
    assert wal(db).exists() and not shm(db).exists()


def recovered(db: Path, scratch: Path, sql: str) -> list[tuple[object, ...]]:
    """``sql`` on what SQLite itself recovers from a copy of ``db`` and its ``-wal`` (the oracle; ``db`` untouched)."""
    scratch.mkdir(parents=True, exist_ok=False)
    copy = scratch / db.name
    shutil.copyfile(db, copy)
    if wal(db).exists():
        shutil.copyfile(wal(db), wal(copy))
    con = sqlite3.connect(copy)
    try:
        return con.execute(sql).fetchall()
    finally:
        con.close()


def schema_version_of(db: Path, scratch: Path) -> int:
    rows = recovered(db, scratch, "SELECT value FROM meta WHERE key = 'schema_version'")
    return int(str(rows[0][0]))


def fresh_root(data_root: Path) -> DataRoot:
    """A data root created by ``open_runtime`` and closed again (store and policy store at schema 1)."""
    open_cloned_runtime(
        data_root,
        os_adapters(),
        role="c01-wal-v1",
        store_migrations=STORE_MIGRATIONS,
        policy_migrations=POLICY_MIGRATIONS,
    ).close()
    return DataRoot.at(data_root)


def open_and_write(data_root: Path) -> ErrorCode | None:
    """Open the runtime as a v1 binary and store one payload; the refusal code, or ``None`` if it wrote."""
    try:
        rt = open_runtime(data_root, os_adapters())
    except BrainError as err:
        return err.code
    try:
        rt.store.store_content(PAYLOAD, "event", HOLDER, RetentionClass.EVENT_PAYLOAD, None)
    finally:
        rt.close()
    return None


# --- the main store ----------------------------------------------------------------------------------------------


def test_schema_reader_reports_a_version_committed_only_in_the_wal(trusted_tmp: Path) -> None:
    root = fresh_root(trusted_tmp / "r")
    commit_in_wal_then_crash(root.store_db, "UPDATE meta SET value = '2' WHERE key = 'schema_version'")
    assert schema_version_of(root.store_db, trusted_tmp / "oracle") == 2  # what SQLite recovers

    info = read_schema_info(root.store_db)

    assert info is not None
    assert info.schema_version == 2, f"read_schema_info reported {info} for a store whose committed schema is 2"
    assert wal(root.store_db).exists() and not shm(root.store_db).exists()  # the reader changed nothing


def test_v1_binary_refuses_a_store_whose_schema_2_is_committed_only_in_the_wal(trusted_tmp: Path) -> None:
    root = fresh_root(trusted_tmp / "r")
    commit_in_wal_then_crash(root.store_db, "UPDATE meta SET value = '2' WHERE key = 'schema_version'")
    entries_before = recovered(root.store_db, trusted_tmp / "before", "SELECT COUNT(*) FROM ledger")
    cas_before = digest_tree(root.cas_dir)

    outcome = open_and_write(trusted_tmp / "r")

    assert outcome == ErrorCode.UNSUPPORTED_VERSION, (
        f"a v1 binary opened a schema-2 store for writing (outcome {outcome}); spec 5.8 requires a refusal before "
        "any write"
    )
    assert recovered(root.store_db, trusted_tmp / "after", "SELECT COUNT(*) FROM ledger") == entries_before
    assert digest_tree(root.cas_dir) == cas_before, "a payload was written by a binary that refused the store"
    assert schema_version_of(root.store_db, trusted_tmp / "final") == 2


def test_v1_binary_refuses_a_policy_store_whose_schema_2_is_committed_only_in_the_wal(trusted_tmp: Path) -> None:
    root = fresh_root(trusted_tmp / "r")
    commit_in_wal_then_crash(root.policy_db, "UPDATE meta SET value = '2' WHERE key = 'schema_version'")
    entries_before = recovered(root.store_db, trusted_tmp / "before", "SELECT COUNT(*) FROM ledger")
    cas_before = digest_tree(root.cas_dir)

    outcome = open_and_write(trusted_tmp / "r")

    assert outcome == ErrorCode.UNSUPPORTED_VERSION, (
        f"a v1 binary opened a schema-2 policy store for writing (outcome {outcome})"
    )
    assert recovered(root.store_db, trusted_tmp / "after", "SELECT COUNT(*) FROM ledger") == entries_before
    assert digest_tree(root.cas_dir) == cas_before
    assert schema_version_of(root.policy_db, trusted_tmp / "final") == 2


# --- the shared readers of a closed database ---------------------------------------------------------------------


def test_missing_store_guard_sees_an_intent_committed_only_in_the_policy_wal(trusted_tmp: Path) -> None:
    """The intent reader of the missing-store guard: an intent committed in the policy WAL is history, so a lost
    ``brain.db`` must not be silently re-created empty (CAS is empty and there is no backup: only the intent shows
    the history)."""
    data_root = trusted_tmp / "r"
    assert run_child("open_runtime", data_root).returncode == 0
    run_until_crash("tombstone_event", "policy.after_intent_commit", data_root)
    root = DataRoot.at(data_root)
    assert shm(root.policy_db).exists() and wal(root.policy_db).stat().st_size > WAL_HEADER_SIZE
    shm(root.policy_db).unlink()
    assert recovered(root.policy_db, trusted_tmp / "oracle", "SELECT COUNT(*) FROM intents") == [(1,)]
    assert list(root.cas_dir.iterdir()) == []
    lost = trusted_tmp / "lost"
    lost.mkdir()
    for path in (root.store_db, wal(root.store_db), shm(root.store_db)):
        if path.exists():
            path.rename(lost / path.name)

    with pytest.raises(BrainError) as refused:
        open_runtime(data_root, os_adapters()).close()

    assert refused.value.code == ErrorCode.INTEGRITY_FAILURE
    assert not root.store_db.exists(), "an empty replacement brain.db was created next to a policy store with history"


def test_policy_restore_issues_a_generation_above_one_committed_only_in_the_live_wal(trusted_tmp: Path) -> None:
    """The live trust-generation read of ``restore_policy``: a generation the live policy store committed (in its
    WAL) before a crash, above the lock's mark, must not be issued again (spec 5.7: strictly above every earlier
    generation)."""
    data_root = trusted_tmp / "r"
    rt = open_cloned_runtime(
        data_root,
        os_adapters(),
        role="c01-wal-v1",
        store_migrations=STORE_MIGRATIONS,
        policy_migrations=POLICY_MIGRATIONS,
    )
    try:
        backup = create_policy_backup(rt.policy, rt.os_, NOW)
        store_id = rt.store.store_id
        hwm = rt.lease.state().trust_generation_hwm
    finally:
        rt.close()
    root = DataRoot.at(data_root)
    live = hwm + 4
    commit_in_wal_then_crash(root.policy_db, f"UPDATE trust SET generation = {live} WHERE id = 1")
    assert recovered(root.policy_db, trusted_tmp / "oracle", "SELECT generation FROM trust") == [(live,)]

    with maintenance_lease(data_root) as (lease_root, lease):
        report = restore_policy(lease_root, lease, os_adapters(), backup, store_id=store_id, now=NOW)

    assert report.trust_generation is not None
    assert report.trust_generation > live, (
        f"restore issued trust generation {report.trust_generation}, not above the committed live generation {live}"
    )


# --- WAL files with no committed frames are not committed state --------------------------------------------------


def test_an_empty_wal_without_shm_does_not_block_a_valid_store(trusted_tmp: Path) -> None:
    root = fresh_root(trusted_tmp / "r")
    wal(root.store_db).write_bytes(b"")
    assert not shm(root.store_db).exists()

    info = read_schema_info(root.store_db)
    outcome = open_and_write(trusted_tmp / "r")

    assert info is not None and info.schema_version == 1
    assert outcome is None
    assert schema_version_of(root.store_db, trusted_tmp / "after") == 1


def test_a_garbage_wal_without_shm_is_never_read_as_a_newer_schema(trusted_tmp: Path) -> None:
    """A WAL without a valid header holds no committed frame: the committed schema is still 1. Reporting it as 1
    or failing closed with a typed error are both acceptable; inventing another version is not."""
    root = fresh_root(trusted_tmp / "r")
    wal(root.store_db).write_bytes(os.urandom(4096))
    assert not shm(root.store_db).exists()

    try:
        info = read_schema_info(root.store_db)
    except BrainError as err:
        assert err.code in (ErrorCode.INTEGRITY_FAILURE, ErrorCode.IO_ERROR)
    else:
        assert info is not None and info.schema_version == 1
