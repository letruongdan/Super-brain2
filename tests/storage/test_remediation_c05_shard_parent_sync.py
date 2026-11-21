"""SP1-C05: a failed ``cas/`` directory sync after creating a shard is retried before a later put returns.

Requirement (spec 5.4 durable publish: step 5 "Làm bền thư mục đích" precedes step 6 "Transaction DB ghi ref", and
"Ref chỉ được trả về sau bước 6"; review SP1-C05; ledger C05): creating a new ``cas/<aa>`` shard adds an entry to
``cas/``, which is durable only once ``cas/`` is synced. If that sync fails, the put fails. A retry that finds the
shard already there must sync ``cas/`` again before it returns the digest (the point after which a ref and an ACK
can be written). A real I/O failure is never swallowed into success, while an OS/filesystem that cannot sync a
directory at all ("unsupported capability") degrades the durability tier instead of failing the put.

The fault is injected at the ``DurablePublisher`` port of the real runtime (and at the adapter's directory-sync
primitive for the capability cases); everything else is the real filesystem and SQLite.
"""

import errno
from pathlib import Path

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.storage.cas import RetentionClass, blob_path
from superbrain.storage.runtime import Runtime
from tests.support.inc2_fixture import open_cloned_runtime

PAYLOAD = b"c05: the first payload of a new shard"
HOLDER = "0192f3a4-5b6c-7d8e-9f01-0000000c0501"


class FailingParentSync:
    """Wraps ``publisher.sync_directory``: records every call and fails the first ``times`` syncs of ``cas/``."""

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


def test_retry_after_a_failed_cas_sync_syncs_cas_again_before_returning(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rt = open_cloned_runtime(trusted_tmp / "r", os_adapters(), role="c05-shard-sync-1")
    try:
        shard = blob_path(rt.root.cas_dir, digest_bytes(PAYLOAD)).parent
        assert not shard.exists()
        sync = FailingParentSync(rt, times=1)
        monkeypatch.setattr(rt.os_.publisher, "sync_directory", sync)

        with pytest.raises(BrainError) as first:
            rt.store.cas.put(PAYLOAD)
        assert first.value.code == ErrorCode.IO_ERROR
        assert shard.is_dir()  # the shard entry was created, but its parent sync failed
        sync.calls.clear()

        digest = rt.store.cas.put(PAYLOAD)

        assert sync.cas_syncs() >= 1, (
            f"the retry returned without syncing cas/ again; synced only {[str(c) for c in sync.calls]}"
        )
        rt.store.store_content(PAYLOAD, "event", HOLDER, RetentionClass.EVENT_PAYLOAD, None)
        assert rt.store.cas.read(digest) == PAYLOAD
    finally:
        rt.close()


def test_retry_through_store_content_syncs_cas_before_the_ref_is_written(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rt = open_cloned_runtime(trusted_tmp / "r", os_adapters(), role="c05-shard-sync-2")
    try:
        digest = digest_bytes(PAYLOAD)
        sync = FailingParentSync(rt, times=1)
        holders_at_cas_sync: list[int] = []
        real = sync.real

        def observed(directory: Path) -> None:
            if Path(directory) == sync.cas_dir and sync.left == 0:
                holders_at_cas_sync.append(len(rt.store.cas.holders(digest)))
            real(directory)

        sync.real = observed
        monkeypatch.setattr(rt.os_.publisher, "sync_directory", sync)

        with pytest.raises(BrainError) as first:
            rt.store.store_content(PAYLOAD, "event", HOLDER, RetentionClass.EVENT_PAYLOAD, None)
        assert first.value.code == ErrorCode.IO_ERROR
        assert rt.store.cas.holders(digest) == []  # no ref, no ACK

        rt.store.store_content(PAYLOAD, "event", HOLDER, RetentionClass.EVENT_PAYLOAD, None)

        assert holders_at_cas_sync != [], "the ACKed retry never synced cas/"
        assert holders_at_cas_sync[0] == 0, "cas/ was synced only after the ref was written"
        assert [(k, h) for k, h, _ in rt.store.cas.holders(digest)] == [("event", HOLDER)]
    finally:
        rt.close()


def test_a_real_io_error_from_the_directory_sync_primitive_fails_the_put_and_is_retried(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rt = open_cloned_runtime(trusted_tmp / "r", os_adapters(), role="c05-shard-sync-3")
    try:
        cas_dir = rt.root.cas_dir
        publisher = rt.os_.publisher
        failures = [OSError(errno.EIO, "injected: EIO syncing cas/")]
        synced: list[Path] = []

        def sync_dir(directory: Path) -> bool:
            synced.append(Path(directory))
            if Path(directory) == cas_dir and failures:
                raise failures.pop()
            return True

        monkeypatch.setattr(publisher, "_sync_dir", sync_dir)

        with pytest.raises(BrainError) as first:
            rt.store.cas.put(PAYLOAD)
        assert first.value.code == ErrorCode.IO_ERROR, "a real I/O failure was not reported as IO_ERROR"
        synced.clear()

        rt.store.cas.put(PAYLOAD)

        assert cas_dir in synced, f"the retry did not sync cas/ again; synced only {[str(p) for p in synced]}"
    finally:
        rt.close()


def test_an_unsupported_directory_sync_degrades_without_failing_the_put(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``_sync_dir`` returning ``False`` is the adapter's "this OS/filesystem cannot sync a directory" result."""
    rt = open_cloned_runtime(trusted_tmp / "r", os_adapters(), role="c05-shard-sync-4")
    try:
        monkeypatch.setattr(rt.os_.publisher, "_sync_dir", lambda directory: False)

        digest = rt.store.cas.put(PAYLOAD)

        assert rt.store.cas.read(digest) == PAYLOAD
    finally:
        rt.close()
