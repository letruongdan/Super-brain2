"""SP1-C02: losing the main database after data was ACKed must block start-up, not look like a new data root.

Requirement (spec 5.4 "Ref chỉ được trả về sau bước 6" and 5.6/5.7, review SP1-C02, ledger C02): once
``store_content`` returned, the payload is ACKed and held. If ``brain.db`` is later lost while the CAS still holds
that payload, ``open_runtime`` must refuse with ``INTEGRITY_FAILURE``. It must not create a replacement (empty)
``brain.db`` bound to the old ``store_id``, and the held blob must not become an orphan that GC may delete.

Valid starts stay valid: a fresh root, and a root whose very first creation crashed before ``brain.db`` was
published (nothing was ever ACKed there).

Round 2 (controller ruling of 2026-10-31, ledger "Review round 1"): ACKed **ledger-only** data (appended entries, no
blob in ``cas/``, no intent, no backup) is history too. The ruled mechanism is a durable lifecycle marker
(``meta.store_published`` in the policy store) set after the first successful ``Store.create`` publish and again on
every successful ``Store.open``; ``open_runtime`` refuses with ``INTEGRITY_FAILURE`` when ``brain.db`` is missing and
the marker is set. The tests below check the observable behaviour through the real ``open_runtime``: once a store
was published (or opened), losing ``brain.db`` is refused; a crash after the publish but before the marker still
opens, and that start sets the marker.
"""

import subprocess
import sys
from pathlib import Path

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.storage.cas import RetentionClass
from superbrain.storage.kinds import KindRegistry
from superbrain.storage.layout import DataRoot
from superbrain.storage.runtime import open_runtime
from tests.storage.conftest import DEMO_KINDS
from tests.support.crash import CHILD_TIMEOUT, CRASH_EXIT
from tests.support.fs import digest_tree

HOLDER = "0192f3a4-5b6c-7d8e-9f01-0000000c0201"
PAYLOAD = b"c02: an ACKed and held payload"


def store_db_files(root: DataRoot) -> list[Path]:
    db = root.store_db
    return [db, db.with_name(db.name + "-wal"), db.with_name(db.name + "-shm")]


def test_lost_main_db_after_an_acked_hold_blocks_startup(trusted_tmp: Path) -> None:
    data_root = trusted_tmp / "r"
    rt = open_runtime(data_root, os_adapters())
    try:
        digest = rt.store.store_content(PAYLOAD, "event", HOLDER, RetentionClass.EVENT_PAYLOAD, None)
        assert [(kind, holder) for kind, holder, _ in rt.store.cas.holders(digest)] == [("event", HOLDER)]
    finally:
        rt.close()
    root = DataRoot.at(data_root)
    preserved = trusted_tmp / "preserved"
    preserved.mkdir()
    for path in store_db_files(root):
        if path.exists():
            path.rename(preserved / path.name)
    cas_before = digest_tree(root.cas_dir)
    assert len([p for p in cas_before.values() if p != "<dir>"]) == 1

    with pytest.raises(BrainError) as refused:
        open_runtime(data_root, os_adapters()).close()

    assert refused.value.code == ErrorCode.INTEGRITY_FAILURE
    assert [p.name for p in store_db_files(root) if p.exists()] == [], "a replacement main database was created"
    assert digest_tree(root.cas_dir) == cas_before, "the held payload was changed or removed"

    # Putting the lost database back shows the payload was never re-classified: it is still held, not an orphan.
    for moved in preserved.iterdir():
        moved.rename(root.store_dir / moved.name)
    rt = open_runtime(data_root, os_adapters())
    try:
        assert [(kind, holder) for kind, holder, _ in rt.store.cas.holders(digest)] == [("event", HOLDER)]
        assert digest not in rt.store.cas.orphans()
        assert rt.store.cas.read(digest) == PAYLOAD
    finally:
        rt.close()


def test_fresh_root_still_creates_the_store(trusted_tmp: Path) -> None:
    rt = open_runtime(trusted_tmp / "r", os_adapters())
    try:
        assert rt.store.store_id == rt.policy.store_id
        digest = rt.store.store_content(PAYLOAD, "event", HOLDER, RetentionClass.EVENT_PAYLOAD, None)
        assert rt.store.cas.read(digest) == PAYLOAD
    finally:
        rt.close()


# A child runs ``open_runtime`` on a fresh root and dies right before ``brain.db`` would be published: the policy
# store exists, the store database only as an unpublished ``brain.db.creating-*`` file, nothing was ACKed.
_CRASH_WHILE_CREATING_STORE = f"""
import dataclasses, os, sys
from pathlib import Path
from superbrain.adapters.os import os_adapters
from superbrain.storage.runtime import open_runtime

class CrashBeforeStorePublish:
    def __init__(self, inner):
        self._inner = inner

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def publish(self, staging, final):
        if final.name == "brain.db":
            sys.stderr.write("CRASHED_CREATING_STORE\\n")
            sys.stderr.flush()
            os._exit({CRASH_EXIT})
        self._inner.publish(staging, final)

adapters = os_adapters()
open_runtime(Path(sys.argv[1]), dataclasses.replace(adapters, publisher=CrashBeforeStorePublish(adapters.publisher)))
"""


def test_crash_during_the_initial_create_still_opens(trusted_tmp: Path) -> None:
    data_root = trusted_tmp / "r"
    done = subprocess.run(
        [sys.executable, "-I", "-c", _CRASH_WHILE_CREATING_STORE, str(data_root)],
        capture_output=True,
        text=True,
        timeout=CHILD_TIMEOUT,
        check=False,
    )
    assert done.returncode == CRASH_EXIT and "CRASHED_CREATING_STORE" in done.stderr, done.stderr
    root = DataRoot.at(data_root)
    assert root.policy_db.exists() and not root.store_db.exists()
    assert any(p.name.startswith("brain.db.creating-") for p in root.store_dir.iterdir())

    rt = open_runtime(data_root, os_adapters())
    try:
        assert rt.store.store_id == rt.policy.store_id
        assert list(rt.store.entries()) == []
        digest = rt.store.store_content(PAYLOAD, "event", HOLDER, RetentionClass.EVENT_PAYLOAD, None)
        assert rt.store.cas.read(digest) == PAYLOAD
    finally:
        rt.close()


# --- round 2: ledger-only ACKed data and the published-store marker -------------------------------------------------


def lose_brain_db(root: DataRoot, preserved: Path) -> None:
    preserved.mkdir()
    for path in store_db_files(root):
        if path.exists():
            path.rename(preserved / path.name)


def assert_refused_without_replacement(data_root: Path) -> None:
    root = DataRoot.at(data_root)
    with pytest.raises(BrainError) as refused:
        open_runtime(data_root, os_adapters(), kinds=KindRegistry(DEMO_KINDS)).close()
    assert refused.value.code == ErrorCode.INTEGRITY_FAILURE
    assert [p.name for p in store_db_files(root) if p.exists()] == [], "a replacement main database was created"


def test_lost_main_db_after_ledger_only_acked_entries_blocks_startup(trusted_tmp: Path) -> None:
    data_root = trusted_tmp / "r"
    rt = open_runtime(data_root, os_adapters(), kinds=KindRegistry(DEMO_KINDS))
    try:
        with rt.store.transaction() as txn:
            txn.append("demo.count", actor="user:cli", owner_id="dan", meta={"n": 1})
        assert [e.kind for e in rt.store.entries()] == ["demo.count"]  # ACKed: the transaction committed
    finally:
        rt.close()
    root = DataRoot.at(data_root)
    assert list(root.cas_dir.iterdir()) == []  # no blob: only the ledger shows the data
    lose_brain_db(root, trusted_tmp / "preserved")

    assert_refused_without_replacement(data_root)


# A child runs ``open_runtime`` on a fresh root and dies right AFTER ``brain.db`` was published: the store is complete,
# but the start-up never finished (so the published-store marker may not have been written yet).
_CRASH_AFTER_STORE_PUBLISH = f"""
import dataclasses, os, sys
from pathlib import Path
from superbrain.adapters.os import os_adapters
from superbrain.storage.runtime import open_runtime

class CrashAfterStorePublish:
    def __init__(self, inner):
        self._inner = inner

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def publish(self, staging, final):
        self._inner.publish(staging, final)
        if final.name == "brain.db":
            sys.stderr.write("CRASHED_AFTER_STORE_PUBLISH\\n")
            sys.stderr.flush()
            os._exit({CRASH_EXIT})

adapters = os_adapters()
open_runtime(Path(sys.argv[1]), dataclasses.replace(adapters, publisher=CrashAfterStorePublish(adapters.publisher)))
"""


def test_crash_after_the_store_publish_still_opens_and_then_marks_the_store_published(trusted_tmp: Path) -> None:
    data_root = trusted_tmp / "r"
    done = subprocess.run(
        [sys.executable, "-I", "-c", _CRASH_AFTER_STORE_PUBLISH, str(data_root)],
        capture_output=True,
        text=True,
        timeout=CHILD_TIMEOUT,
        check=False,
    )
    assert done.returncode == CRASH_EXIT and "CRASHED_AFTER_STORE_PUBLISH" in done.stderr, done.stderr
    root = DataRoot.at(data_root)
    assert root.store_db.exists()

    rt = open_runtime(data_root, os_adapters())  # the next start opens the published store
    try:
        assert rt.store.store_id == rt.policy.store_id
        assert list(rt.store.entries()) == []
    finally:
        rt.close()
    lose_brain_db(root, trusted_tmp / "preserved")

    # That successful start marked the store as published: losing it now is refused.
    assert_refused_without_replacement(data_root)
