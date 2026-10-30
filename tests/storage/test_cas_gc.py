from datetime import timedelta

import pytest

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.storage.cas import GcReport
from superbrain.storage.kinds import RetentionClass
from superbrain.storage.store import Store
from tests.storage.conftest import StoreFactory
from tests.storage.test_cas import E1, blob_file, store_dir
from tests.support.clock import FakeClock
from tests.support.fs import set_mtime


@pytest.fixture
def store(store_factory: StoreFactory) -> Store:
    return store_factory()


def hold(store: Store, digest: str, holder_id: str = E1) -> None:
    with store.transaction() as t:
        t.hold(digest, "event", holder_id, RetentionClass.EVENT_PAYLOAD, None)


def gc_once_before_first_hold(monkeypatch: pytest.MonkeyPatch, store: Store, now: object) -> None:
    """Run GC exactly once, after ``put`` and before the transaction of the first ``store_content`` hold."""
    original = Store._hold
    calls: list[str] = []

    def hold_after_gc(self: Store, *args: object, **kwargs: object) -> None:
        if not calls:
            calls.append("gc")
            store.cas.collect_garbage(now=now)  # type: ignore[arg-type]
        original(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Store, "_hold", hold_after_gc)


def test_gc_deletes_old_orphan_only(store: Store, clock: FakeClock) -> None:
    held = store.cas.put(b"held")
    hold(store, held)
    orphan = store.cas.put(b"orphan")
    for d in (held, orphan):
        set_mtime(blob_file(store, d), clock.now() - timedelta(days=3))
    report = store.cas.collect_garbage(now=clock.now())
    assert report == GcReport(deleted=(orphan,), kept_young=())
    assert not store.cas.exists(orphan) and store.cas.read(held) == b"held"
    assert blob_file(store, orphan).parent.is_dir()  # the shard directory stays
    assert store.cas.collect_garbage(now=clock.now()) == GcReport(deleted=(), kept_young=())


def test_gc_keeps_young_orphan(store: Store, clock: FakeClock) -> None:
    young = store.cas.put(b"young")
    old = store.cas.put(b"old")
    set_mtime(blob_file(store, young), clock.now() - timedelta(hours=1))
    set_mtime(blob_file(store, old), clock.now() - timedelta(hours=25))
    report = store.cas.collect_garbage(now=clock.now())
    assert report.deleted == (old,) and report.kept_young == (young,)
    assert store.cas.exists(young) and not store.cas.exists(old)


def test_gc_report_is_sorted_and_grace_is_configurable(store: Store, clock: FakeClock) -> None:
    digests = sorted(store.cas.put(f"blob-{i}".encode()) for i in range(4))
    for d in digests:
        set_mtime(blob_file(store, d), clock.now() - timedelta(hours=2))
    report = store.cas.collect_garbage(now=clock.now(), grace=timedelta(hours=1))
    assert report.deleted == tuple(digests) and report.kept_young == ()


def test_gc_never_deletes_a_held_blob_even_when_old(store: Store, clock: FakeClock) -> None:
    d = store.cas.put(b"held-and-old")
    hold(store, d)
    set_mtime(blob_file(store, d), clock.now() - timedelta(days=30))
    assert store.cas.collect_garbage(now=clock.now() + timedelta(days=30)).deleted == ()
    assert store.cas.read(d) == b"held-and-old"


def test_gc_is_refused_while_maintenance_is_active(store: Store, clock: FakeClock) -> None:
    orphan = store.cas.put(b"orphan")
    with store.maintenance():
        with pytest.raises(BrainError) as e:
            store.cas.collect_garbage(now=clock.now() + timedelta(days=2))
    assert e.value.code == ErrorCode.STORE_BUSY and store.cas.exists(orphan)


def test_gc_releases_the_maintenance_flag(store: Store, clock: FakeClock) -> None:
    store.cas.collect_garbage(now=clock.now())
    with store.maintenance():
        pass


def test_gc_between_put_of_aged_existing_blob_and_hold_never_leaves_dangling_ref(
    store: Store, clock: FakeClock
) -> None:
    aged = store.cas.put(b"dedup-me")
    set_mtime(blob_file(store, aged), clock.now() - timedelta(days=3))
    d = store.cas.put(b"dedup-me")  # existing bytes: put returns the digest without rewriting the file
    store.cas.collect_garbage(now=clock.now())
    with pytest.raises(BrainError) as e:
        hold(store, d)
    assert e.value.code == ErrorCode.NOT_FOUND and store.cas.holders(d) == []


def test_store_content_republishes_after_gc_race(
    store: Store, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    aged = store.cas.put(b"dedup-me")
    set_mtime(blob_file(store, aged), clock.now() - timedelta(days=3))
    gc_once_before_first_hold(monkeypatch, store, now=clock.now())
    d = store.store_content(b"dedup-me", "event", E1, RetentionClass.EVENT_PAYLOAD, None)
    assert store.cas.read(d) == b"dedup-me" and [h[1] for h in store.cas.holders(d)] == [E1]


def test_gc_leaves_no_ledger_entry(store: Store, clock: FakeClock) -> None:
    store.cas.put(b"orphan")
    before = list(store.entries())
    store.cas.collect_garbage(now=clock.now() + timedelta(days=2))
    assert list(store.entries()) == before


def test_gc_ignores_files_that_are_not_blobs(store: Store, clock: FakeClock) -> None:
    d = store.cas.put(b"x")
    stray = blob_file(store, d).parent / "not-a-blob.txt"
    stray.write_bytes(b"keep")
    store.cas.collect_garbage(now=clock.now() + timedelta(days=2))
    assert stray.read_bytes() == b"keep" and store_dir(store).is_dir()
