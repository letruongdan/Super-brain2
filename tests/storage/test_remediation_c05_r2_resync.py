"""SP1-C05 round 2: the ``cas/`` re-sync on a retry is itself retried, never swallowed, and happens in a new process.

Requirement (spec 5.4: step 5 "Làm bền thư mục đích" before step 6, the ref only after step 6, and process death is
the main crash case; review SP1-C05; ledger C05 "a retry must re-attempt the parent sync before the ref/ACK; a real
I/O failure is never swallowed"; independent review round 1, mutants M05b, M05d and M05e):

* a retry whose own ``cas/`` re-sync fails again fails with ``IO_ERROR`` and records no ref (M05e: swallowed);
* the next put after that failed re-sync syncs ``cas/`` again before it returns (M05b: marked durable too early);
* a retry in a NEW process, after the process whose ``cas/`` sync failed has died, syncs ``cas/`` before the ref
  (M05d: shards already on disk assumed durable at start-up).

The fault is injected at the ``DurablePublisher`` port; everything else is the real runtime, filesystem and SQLite.
"""

import subprocess
import sys
from pathlib import Path

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.storage.cas import RetentionClass, blob_path
from superbrain.storage.layout import DataRoot
from superbrain.storage.runtime import Runtime, open_runtime
from tests.support.crash import CHILD_TIMEOUT, CRASH_EXIT

PAYLOAD = b"c05 round 2: the first payload of a new shard"
HOLDER = "0192f3a4-5b6c-7d8e-9f01-0000000c0511"


class FailingParentSync:
    """Wraps ``publisher.sync_directory``: records each call and fails the first ``times`` syncs of ``cas/``."""

    def __init__(self, rt: Runtime, *, times: int) -> None:
        self.cas_dir = rt.root.cas_dir
        self.real = rt.os_.publisher.sync_directory
        self.left = times
        self.calls: list[Path] = []

    def __call__(self, directory: Path) -> None:
        self.calls.append(Path(directory))
        if Path(directory) == self.cas_dir and self.left > 0:
            self.left -= 1
            raise BrainError(ErrorCode.IO_ERROR, "injected: syncing the cas/ directory failed")
        self.real(directory)

    def cas_syncs(self) -> int:
        return sum(1 for call in self.calls if call == self.cas_dir)


def store(rt: Runtime) -> str:
    return rt.store.store_content(PAYLOAD, "event", HOLDER, RetentionClass.EVENT_PAYLOAD, None)


def held(rt: Runtime) -> list[tuple[str, str]]:
    return [(kind, holder) for kind, holder, _ in rt.store.cas.holders(digest_bytes(PAYLOAD))]


def test_a_retry_whose_cas_resync_fails_again_fails_and_records_no_ref(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rt = open_runtime(trusted_tmp / "r", os_adapters())
    try:
        sync = FailingParentSync(rt, times=2)
        monkeypatch.setattr(rt.os_.publisher, "sync_directory", sync)
        with pytest.raises(BrainError) as first:
            store(rt)
        assert first.value.code == ErrorCode.IO_ERROR
        sync.calls.clear()

        with pytest.raises(BrainError) as retry:
            store(rt)

        assert retry.value.code == ErrorCode.IO_ERROR
        assert sync.cas_syncs() == 1
        assert held(rt) == [], "a ref was recorded although cas/ was never made durable"
    finally:
        rt.close()


def test_the_put_after_a_failed_resync_syncs_cas_again(trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rt = open_runtime(trusted_tmp / "r", os_adapters())
    try:
        sync = FailingParentSync(rt, times=2)
        monkeypatch.setattr(rt.os_.publisher, "sync_directory", sync)
        for _ in range(2):  # the shard-creating put, then a retry whose re-sync fails too
            try:
                store(rt)
            except BrainError as err:
                assert err.code == ErrorCode.IO_ERROR
        sync.calls.clear()

        store(rt)

        assert sync.cas_syncs() >= 1, (
            f"the put after a failed re-sync returned without syncing cas/; synced only {[str(c) for c in sync.calls]}"
        )
        assert held(rt) == [("event", HOLDER)]
    finally:
        rt.close()


# A child opens the runtime, makes every sync of cas/ fail, puts PAYLOAD (which creates the shard and fails), then
# dies: the shard exists on disk, but its entry in cas/ was never made durable.
_FAIL_CAS_SYNC_THEN_DIE = f"""
import dataclasses, os, sys
from pathlib import Path
from superbrain.adapters.os import os_adapters
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.storage.runtime import open_runtime

class FailCasSync:
    def __init__(self, inner, cas_dir):
        self._inner = inner
        self._cas_dir = cas_dir

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def sync_directory(self, directory):
        if Path(directory) == self._cas_dir:
            raise BrainError(ErrorCode.IO_ERROR, "injected: syncing the cas/ directory failed")
        self._inner.sync_directory(directory)

data_root = Path(sys.argv[1])
adapters = os_adapters()
rt = open_runtime(data_root, dataclasses.replace(adapters, publisher=FailCasSync(adapters.publisher, None)))
rt.os_.publisher._cas_dir = rt.root.cas_dir
try:
    rt.store.cas.put({PAYLOAD!r})
except BrainError as err:
    sys.stderr.write("PUT_FAILED " + err.code.value + "\\n")
    sys.stderr.flush()
    os._exit({CRASH_EXIT})
sys.stderr.write("PUT_SUCCEEDED\\n")
os._exit(1)
"""


def test_a_retry_in_a_new_process_syncs_cas_before_the_ref(trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data_root = trusted_tmp / "r"
    open_runtime(data_root, os_adapters()).close()
    done = subprocess.run(
        [sys.executable, "-I", "-c", _FAIL_CAS_SYNC_THEN_DIE, str(data_root)],
        capture_output=True,
        text=True,
        timeout=CHILD_TIMEOUT,
        check=False,
    )
    assert done.returncode == CRASH_EXIT and "PUT_FAILED io_error" in done.stderr, done.stderr
    shard = blob_path(DataRoot.at(data_root).cas_dir, digest_bytes(PAYLOAD)).parent
    assert shard.is_dir()  # created by the dead process, its cas/ entry never synced

    rt = open_runtime(data_root, os_adapters())
    try:
        sync = FailingParentSync(rt, times=0)
        holders_at_cas_sync: list[int] = []
        real = sync.real

        def observed(directory: Path) -> None:
            if Path(directory) == sync.cas_dir:
                holders_at_cas_sync.append(len(held(rt)))
            real(directory)

        sync.real = observed
        monkeypatch.setattr(rt.os_.publisher, "sync_directory", sync)

        store(rt)

        assert holders_at_cas_sync != [], (
            f"the retry in a new process never synced cas/; synced only {[str(c) for c in sync.calls]}"
        )
        assert holders_at_cas_sync[0] == 0, "cas/ was synced only after the ref was written"
        assert held(rt) == [("event", HOLDER)]
    finally:
        rt.close()
