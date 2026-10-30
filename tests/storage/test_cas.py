import errno
import os
import threading
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path
from typing import NoReturn

import pytest

from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.os import OsAdapters
from superbrain.storage.cas import ContentStore, HolderProjection, RetentionClass
from superbrain.storage.kinds import CORE_KINDS, EntryKind, FieldType, KindRegistry
from superbrain.storage.kinds import RetentionClass as KindsRetentionClass
from superbrain.storage.layout import prepare_data_root, secure_subdirectories
from superbrain.storage.ledger import Txn
from superbrain.storage.store import Store
from superbrain.storage.writer import acquire_writer
from tests.storage.conftest import CLOCK_START, DEMO_KINDS, STORE_ID, StaticPolicy, StoreFactory, seed_store
from tests.support.crash import run_child, run_until_crash
from tests.support.fs import corrupt_bytes

E1 = "0192f3a4-5b6c-7d8e-9f01-000000000e01"
E2 = "0192f3a4-5b6c-7d8e-9f01-000000000e02"
V1 = "0192f3a4-5b6c-7d8e-9f01-000000000f01"
T0 = CLOCK_START
PUT_AND_HOLD_ID = "0192f3a4-5b6c-7d8e-9f01-0000000000aa"  # crash_child.put_and_hold's holder id


def raising(err: Exception) -> Callable[..., NoReturn]:
    def fn(*_args: object, **_kwargs: object) -> NoReturn:
        raise err

    return fn


def store_dir(store: Store) -> Path:
    with store.transaction() as t:
        return Path(t.db.execute("PRAGMA database_list").fetchone()[2]).parent


def staging_dir(store: Store) -> Path:
    return store_dir(store) / "staging"


def blob_file(store: Store, digest: str) -> Path:
    hex_ = digest.removeprefix("sha256:")
    return store_dir(store) / "cas" / hex_[:2] / hex_


def capture(errors: list[BaseException], fn: Callable[[], object]) -> None:
    try:
        fn()
    except BaseException as err:  # noqa: BLE001 - the test inspects whatever the other thread raised
        errors.append(err)


@pytest.fixture
def policy() -> StaticPolicy:
    return StaticPolicy()


@pytest.fixture
def store(store_factory: StoreFactory, policy: StaticPolicy) -> Store:
    return store_factory(policy=policy)


# --- put and read --------------------------------------------------------------------------------------------


def test_put_read_roundtrip_and_dedup(store: Store) -> None:
    d = store.cas.put(b"hello")
    assert d == digest_bytes(b"hello") and store.cas.exists(d) and store.cas.read(d) == b"hello"
    before = blob_file(store, d).stat().st_mtime_ns
    assert store.cas.put(b"hello") == d
    assert blob_file(store, d).stat().st_mtime_ns == before
    assert list(staging_dir(store).iterdir()) == []
    assert isinstance(store.cas, ContentStore)


def test_read_detects_corruption(store: Store) -> None:
    d = store.cas.put(b"some payload")
    corrupt_bytes(blob_file(store, d), offsets=[0])
    with pytest.raises(BrainError) as e:
        store.cas.read(d)
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE


def test_read_missing_blob_is_not_found(store: Store) -> None:
    with pytest.raises(BrainError) as e:
        store.cas.read(digest_bytes(b"never-put"))
    assert e.value.code == ErrorCode.NOT_FOUND and not store.cas.exists(digest_bytes(b"never-put"))


def test_quarantine_is_checked_before_existence_and_hash(store: Store, policy: StaticPolicy) -> None:
    d = store.cas.put(b"bad")
    corrupt_bytes(blob_file(store, d), offsets=[0])
    missing = digest_bytes(b"absent")
    policy.quarantined.extend([d, missing])
    for digest in (d, missing):
        with pytest.raises(BrainError) as e:
            store.cas.read(digest)
        assert e.value.code == ErrorCode.QUARANTINED


def test_put_of_corrupt_existing_blob_is_integrity_failure_and_keeps_it(store: Store) -> None:
    d = store.cas.put(b"original")
    corrupt_bytes(blob_file(store, d), offsets=[1])
    damaged = blob_file(store, d).read_bytes()
    with pytest.raises(BrainError) as e:
        store.cas.put(b"original")
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE
    assert blob_file(store, d).read_bytes() == damaged and list(staging_dir(store).iterdir()) == []


@pytest.mark.parametrize("digest", ["sha256:" + "AB" * 32, "sha256:../x", "md5:" + "ab" * 32, "ab" * 32])
def test_malformed_digest_is_invalid_input(store: Store, digest: str) -> None:
    with pytest.raises(BrainError) as e:
        store.cas.read(digest)
    assert e.value.code == ErrorCode.INVALID_INPUT


def test_put_requires_bytes(store: Store) -> None:
    with pytest.raises(BrainError) as e:
        store.cas.put("text")  # type: ignore[arg-type]
    assert e.value.code == ErrorCode.INVALID_INPUT


def test_disk_full_leaves_no_blob_or_staging(store: Store, monkeypatch: pytest.MonkeyPatch) -> None:  # Focus 2
    monkeypatch.setattr(os, "write", raising(OSError(errno.ENOSPC, "full")))
    with pytest.raises(BrainError) as e:
        store.cas.put(b"x" * 1000)
    assert e.value.code == ErrorCode.STORAGE_FULL
    assert list(staging_dir(store).iterdir()) == [] and not store.cas.exists(digest_bytes(b"x" * 1000))


def test_staging_file_that_does_not_hash_to_the_digest_is_never_published(
    store: Store, os_: OsAdapters, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = os_.publisher.write_new
    published: list[Path] = []
    monkeypatch.setattr(os_.publisher, "write_new", lambda path, data: real(path, data + b"bit rot"))
    monkeypatch.setattr(os_.publisher, "publish", lambda staging, final: published.append(final))
    with pytest.raises(BrainError) as e:
        store.cas.put(b"intended")
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE and published == []
    assert list(staging_dir(store).iterdir()) == [] and not store.cas.exists(digest_bytes(b"intended"))


def test_put_of_an_existing_blob_makes_its_shard_entry_durable_again(
    store: Store, os_: OsAdapters, monkeypatch: pytest.MonkeyPatch
) -> None:
    d = store.cas.put(b"again")
    synced: list[Path] = []
    monkeypatch.setattr(os_.publisher, "sync_directory", synced.append)
    monkeypatch.setattr(os_.publisher, "write_new", raising(AssertionError("an existing blob is not rewritten")))
    assert store.cas.put(b"again") == d
    assert synced == [blob_file(store, d).parent]


def test_failed_publish_removes_staging_and_raises_the_original_error(
    store: Store, os_: OsAdapters, monkeypatch: pytest.MonkeyPatch
) -> None:
    error = BrainError(ErrorCode.FILESYSTEM_BUSY, "injected")
    monkeypatch.setattr(os_.publisher, "publish", raising(error))
    with pytest.raises(BrainError) as e:
        store.cas.put(b"busy")
    assert e.value is error
    assert list(staging_dir(store).iterdir()) == [] and not store.cas.exists(digest_bytes(b"busy"))


def test_new_shard_is_secured_and_recorded_before_the_blob_is_published(
    store: Store, os_: OsAdapters, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[str, Path]] = []
    publisher = os_.publisher
    real_sync, real_publish = publisher.sync_directory, publisher.publish
    real_secure = os_.permissions.secure_directory

    def sync(directory: Path) -> None:
        calls.append(("sync", directory))
        real_sync(directory)

    def publish(staging: Path, final: Path) -> None:
        calls.append(("publish", final))
        real_publish(staging, final)

    def secure(directory: Path) -> None:
        calls.append(("secure", directory))
        real_secure(directory)

    monkeypatch.setattr(publisher, "sync_directory", sync)
    monkeypatch.setattr(publisher, "publish", publish)
    monkeypatch.setattr(os_.permissions, "secure_directory", secure)
    d = store.cas.put(b"first")
    final = blob_file(store, d)
    cas = store_dir(store) / "cas"
    # publish itself then makes the blob's entry in the shard durable.
    assert calls == [("secure", final.parent), ("sync", cas), ("publish", final), ("sync", final.parent)]
    assert os_.permissions.object_problems(final.parent) == []
    # Another blob in the same shard: the shard exists, so it is neither secured again nor recorded in cas/.
    calls.clear()
    other = next(b for b in (str(i).encode() for i in range(1_000_000)) if digest_bytes(b)[7:9] == d[7:9])
    store.cas.put(other)
    assert calls == [("publish", blob_file(store, digest_bytes(other))), ("sync", final.parent)]


def test_content_store_refuses_use_from_another_thread(store: Store) -> None:
    cas = store.cas
    errors: list[BaseException] = []
    thread = threading.Thread(target=capture, args=(errors, lambda: cas.put(b"x")))
    thread.start()
    thread.join()
    assert len(errors) == 1 and isinstance(errors[0], AssertionError)
    assert not cas.exists(digest_bytes(b"x"))


# --- holders -------------------------------------------------------------------------------------------------


def test_shared_blob_has_independent_holders(store: Store) -> None:  # tình huống 25 (phần holder)
    d = store.cas.put(b"shared")
    with store.transaction() as t:
        t.hold(d, "event", E1, RetentionClass.EVENT_PAYLOAD, expires_at=T0 + timedelta(days=90))
        t.hold(d, "evidence", V1, RetentionClass.EVIDENCE, expires_at=None)
    with store.transaction() as t:
        t.release(d, "event", E1, reason="expired")
    assert [h[0] for h in store.cas.holders(d)] == ["evidence"] and store.cas.read(d) == b"shared"
    assert store.cas.holders(d) == [("evidence", V1, RetentionClass.EVIDENCE)]
    assert type(store.cas.holders(d)[0][2]) is RetentionClass


def test_hold_records_a_canonical_expiry(store: Store) -> None:
    d = store.cas.put(b"timed")
    with store.transaction() as t:
        t.hold(d, "event", E1, RetentionClass.EVENT_PAYLOAD, expires_at=T0 + timedelta(days=90))
        t.hold(d, "lesson", E2, RetentionClass.DURABLE, expires_at=None)
    hold, durable = list(store.entries())
    assert hold.kind == "cas.hold" and hold.meta == {
        "digest": d,
        "holder_kind": "event",
        "holder_id": E1,
        "retention": "event_payload",
        "expires_at": "2027-01-28T12:00:00.000000Z",
    }
    assert durable.meta["expires_at"] is None
    with store.transaction() as t:
        rows = t.db.execute("SELECT holder_kind, expires_at FROM p_cas_holders_ ORDER BY holder_kind").fetchall()
    assert rows == [("event", "2027-01-28T12:00:00.000000Z"), ("lesson", None)]


def test_hold_with_a_naive_expiry_is_refused(store: Store) -> None:
    d = store.cas.put(b"naive")
    with pytest.raises(AssertionError):
        with store.transaction() as t:
            t.hold(d, "event", E1, RetentionClass.EVENT_PAYLOAD, datetime(2027, 1, 1))
    assert list(store.entries()) == []


@pytest.mark.parametrize("expires_at", ["2027-01-01T00:00:00Z", 1700000000, T0.date()])
def test_hold_with_a_non_datetime_expiry_is_invalid_input(store: Store, expires_at: object) -> None:
    d = store.cas.put(b"typed")
    with pytest.raises(BrainError) as e:
        with store.transaction() as t:
            t.hold(d, "event", E1, RetentionClass.EVENT_PAYLOAD, expires_at)  # type: ignore[arg-type]
    assert e.value.code == ErrorCode.INVALID_INPUT and list(store.entries()) == []


def test_hold_of_missing_blob_is_refused(store: Store) -> None:
    with pytest.raises(BrainError) as e:
        with store.transaction() as t:
            t.hold(digest_bytes(b"never-put"), "event", E1, RetentionClass.EVENT_PAYLOAD, None)
    assert e.value.code == ErrorCode.NOT_FOUND and list(store.entries()) == []


def test_hold_of_corrupt_blob_is_refused(store: Store) -> None:
    d = store.cas.put(b"rotting")
    corrupt_bytes(blob_file(store, d), offsets=[0])
    with pytest.raises(BrainError) as e:
        with store.transaction() as t:
            t.hold(d, "event", E1, RetentionClass.EVENT_PAYLOAD, None)
    assert e.value.code == ErrorCode.NOT_FOUND and list(store.entries()) == [] and store.cas.holders(d) == []


def test_caught_hold_failure_writes_nothing_and_the_transaction_goes_on(store: Store) -> None:
    d = store.cas.put(b"kept")
    with store.transaction() as t:
        with pytest.raises(BrainError):
            t.hold(digest_bytes(b"never-put"), "event", E1, RetentionClass.EVENT_PAYLOAD, None)
        t.hold(d, "event", E2, RetentionClass.EVENT_PAYLOAD, None)
    assert [e.meta["digest"] for e in store.entries()] == [d]


def test_hold_and_release_validate_their_fields(store: Store) -> None:
    d = store.cas.put(b"fields")
    calls: list[Callable[[Txn], None]] = [
        lambda t: t.hold(d, "unknown", E1, RetentionClass.EVENT_PAYLOAD, None),
        lambda t: t.hold(d, "event", "not-a-uuid", RetentionClass.EVENT_PAYLOAD, None),
        lambda t: t.hold(d, "event", E1, "forever", None),  # type: ignore[arg-type]
        lambda t: t.release(d, "event", E1, reason="because I said so"),
    ]
    for call in calls:
        with pytest.raises(BrainError) as e:
            with store.transaction() as t:
                call(t)
        assert e.value.code == ErrorCode.INVALID_INPUT
    assert list(store.entries()) == []


def test_orphans_are_blobs_without_holders(store: Store) -> None:
    kept, loose = store.cas.put(b"kept"), store.cas.put(b"loose")
    with store.transaction() as t:
        t.hold(kept, "evidence", V1, RetentionClass.EVIDENCE, None)
    assert store.cas.orphans() == [loose]
    with store.transaction() as t:
        t.release(kept, "evidence", V1, reason="deleted_by_owner")
    assert store.cas.orphans() == sorted([kept, loose])


def test_tombstoned_holder_is_skipped_and_replay_applies_new_tombstones(store: Store, policy: StaticPolicy) -> None:
    d = store.cas.put(b"tomb")
    policy.tombstoned.append(("event", E1))
    with store.transaction() as t:
        t.hold(d, "event", E1, RetentionClass.EVENT_PAYLOAD, None)
        t.hold(d, "evidence", V1, RetentionClass.EVIDENCE, None)
    assert [h[0] for h in store.cas.holders(d)] == ["evidence"] and len(list(store.entries())) == 2
    policy.tombstoned.append(("evidence", V1))
    assert store.rebuild_projections() == 2
    assert store.cas.holders(d) == [] and store.cas.orphans() == [d]


def test_rebuild_reproduces_holders(store: Store) -> None:
    d = store.cas.put(b"rebuild")
    with store.transaction() as t:
        t.hold(d, "event", E1, RetentionClass.EVENT_PAYLOAD, T0)
        t.hold(d, "evidence", V1, RetentionClass.EVIDENCE, None)
        t.release(d, "event", E1, reason="expired")
    before = store.cas.holders(d)
    store.rebuild_projections()
    store.rebuild_projections()
    assert store.cas.holders(d) == before == [("evidence", V1, RetentionClass.EVIDENCE)]


# --- store_content -------------------------------------------------------------------------------------------


def test_store_content_puts_and_holds(store: Store) -> None:
    d = store.store_content(b"content", "artifact", E1, RetentionClass.DURABLE, None)
    assert d == digest_bytes(b"content") and store.cas.read(d) == b"content"
    assert store.cas.holders(d) == [("artifact", E1, RetentionClass.DURABLE)] and store.cas.orphans() == []


@pytest.mark.parametrize(
    "fields",
    [
        ("unknown", E1, RetentionClass.EVENT_PAYLOAD, None),
        ("event", "not-a-uuid", RetentionClass.EVENT_PAYLOAD, None),
        ("event", E1, "forever", None),
        ("event", E1, RetentionClass.EVENT_PAYLOAD, "tomorrow"),
    ],
)
def test_store_content_with_invalid_holder_fields_stores_nothing(
    store: Store, fields: tuple[str, str, RetentionClass, datetime | None]
) -> None:
    with pytest.raises(BrainError) as e:
        store.store_content(b"never stored", *fields)
    assert e.value.code == ErrorCode.INVALID_INPUT
    assert store.cas.orphans() == [] and not store.cas.exists(digest_bytes(b"never stored"))
    assert list(store.entries()) == []


def test_store_content_with_a_naive_expiry_stores_nothing(store: Store) -> None:
    with pytest.raises(AssertionError):
        store.store_content(b"naive", "event", E1, RetentionClass.EVENT_PAYLOAD, datetime(2027, 1, 1))
    assert store.cas.orphans() == [] and list(store.entries()) == []


def _vanishing_put(store: Store, monkeypatch: pytest.MonkeyPatch, times: int) -> list[str]:
    """Make the first ``times`` puts lose their blob right after returning, as a concurrent GC would."""
    real = store.cas.put
    calls: list[str] = []

    def put(data: bytes) -> str:
        digest = real(data)
        calls.append(digest)
        if len(calls) <= times:
            blob_file(store, digest).unlink()
        return digest

    monkeypatch.setattr(store.cas, "put", put)
    return calls


def test_store_content_retries_once_when_the_blob_vanished(store: Store, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _vanishing_put(store, monkeypatch, times=1)
    d = store.store_content(b"retry", "event", E1, RetentionClass.EVENT_PAYLOAD, None)
    assert calls == [d, d] and store.cas.read(d) == b"retry"
    assert [h[1] for h in store.cas.holders(d)] == [E1] and len(list(store.entries())) == 1


def test_store_content_gives_up_after_the_second_failure(store: Store, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _vanishing_put(store, monkeypatch, times=3)
    with pytest.raises(BrainError) as e:
        store.store_content(b"gone", "event", E1, RetentionClass.EVENT_PAYLOAD, None)
    assert e.value.code == ErrorCode.NOT_FOUND and len(calls) == 2 and list(store.entries()) == []


# --- registration --------------------------------------------------------------------------------------------


def test_retention_enum_of_cas_hold_is_the_retention_class() -> None:
    hold = next(k for k in CORE_KINDS if k.kind == "cas.hold")
    assert RetentionClass is KindsRetentionClass
    assert hold.enums["retention"] == frozenset(v.value for v in RetentionClass)


def test_holders_and_core_kinds_are_registered_by_default(store_factory: StoreFactory) -> None:
    only_demo = KindRegistry([EntryKind("demo.count", 1, {"n": FieldType.INT}, {})])
    store = store_factory(kinds=only_demo)
    d = store.cas.put(b"default")
    with store.transaction() as t:
        t.hold(d, "event", E1, RetentionClass.EVENT_PAYLOAD, None)
        t.append("demo.count", actor="user:cli", owner_id="dan", meta={"n": 1})
    assert [h[0] for h in store.cas.holders(d)] == ["event"]


def test_explicit_holder_projection_is_not_registered_twice(store_factory: StoreFactory) -> None:
    store = store_factory(handlers=[HolderProjection()], kinds=KindRegistry(CORE_KINDS))
    d = store.store_content(b"once", "event", E1, RetentionClass.EVENT_PAYLOAD, None)
    assert len(store.cas.holders(d)) == 1


def test_conflicting_core_kind_or_holder_name_is_refused(store_factory: StoreFactory) -> None:
    redefined = EntryKind("cas.hold", 1, {"digest": FieldType.DIGEST}, {})
    with pytest.raises(BrainError) as e:
        store_factory(kinds=KindRegistry([redefined]))
    assert e.value.code == ErrorCode.INVALID_INPUT

    class Impostor:
        name = "cas_holders"
        handler_version = 1
        kinds: frozenset[str] = frozenset()

        def create_tables(self, db: object, prefix: str) -> None:
            raise AssertionError("never created")

        def apply(self, db: object, prefix: str, entry: object, policy: object) -> None:
            raise AssertionError("never applied")

    with pytest.raises(BrainError) as e:
        store_factory(handlers=[Impostor()])
    assert e.value.code == ErrorCode.INVALID_INPUT


# --- open and crashes ----------------------------------------------------------------------------------------


def test_store_without_holder_table_replays_holders_on_open(trusted_tmp: Path, os_: OsAdapters) -> None:
    root = prepare_data_root(trusted_tmp / "r", os_)
    with acquire_writer(root, os_) as lease:
        secure_subdirectories(root, lease, os_)
        store = Store.create(root, lease, os_, StaticPolicy(), [], KindRegistry(DEMO_KINDS))
        kept, released = store.cas.put(b"kept"), store.cas.put(b"released")
        with store.transaction() as t:
            t.hold(kept, "evidence", V1, RetentionClass.EVIDENCE, T0)
            t.hold(released, "event", E1, RetentionClass.EVENT_PAYLOAD, None)
            t.release(released, "event", E1, reason="expired")
        # A store from before the holder projection: cas.* entries in the ledger, no p_cas_holders_ table.
        with store.transaction() as t:
            t.db.execute("DROP TABLE p_cas_holders_")
            tables = t.db.execute("SELECT name FROM sqlite_master WHERE name LIKE 'p_cas_holders_%'").fetchall()
        assert tables == []
        store.close()
        store = Store.open(root, lease, os_, StaticPolicy(), [], KindRegistry(DEMO_KINDS))
        assert store.cas.holders(kept) == [("evidence", V1, RetentionClass.EVIDENCE)]
        assert store.cas.holders(released) == [] and store.cas.orphans() == [released]
        with store.transaction() as t:
            expiry = t.db.execute("SELECT expires_at FROM p_cas_holders_").fetchall()
        assert expiry == [("2026-10-30T12:00:00.000000Z",)]
        store.close()


def test_open_removes_unfinished_staging_files(trusted_tmp: Path, reopen: Callable[..., Store]) -> None:
    seed_store(trusted_tmp)
    staging = trusted_tmp / "store" / "staging"
    (staging / "0192f3a4-5b6c-7d8e-9f01-23456789abcd.tmp").write_bytes(b"half a blob")
    (staging / "keep.note").write_bytes(b"not a put leftover")
    store = reopen(trusted_tmp)
    assert sorted(p.name for p in staging.iterdir()) == ["keep.note"] and store.cas.orphans() == []


def test_put_and_hold_without_crash_holds_the_payload(trusted_tmp: Path, reopen: Callable[..., Store]) -> None:
    seed_store(trusted_tmp)
    result = run_child("put_and_hold", trusted_tmp, STORE_ID)
    assert result.returncode == 0, result.stdout + result.stderr
    store = reopen(trusted_tmp)
    d = digest_bytes(b"payload")
    assert store.cas.read(d) == b"payload" and store.cas.orphans() == []
    assert store.cas.holders(d) == [("event", PUT_AND_HOLD_ID, RetentionClass.EVENT_PAYLOAD)]


def test_crash_after_rename_before_hold_leaves_orphan_only(  # tình huống 5 (phần CAS)
    trusted_tmp: Path, reopen: Callable[..., Store]
) -> None:
    seed_store(trusted_tmp)
    run_until_crash("put_and_hold", "cas.after_rename", trusted_tmp, STORE_ID)
    store = reopen(trusted_tmp)
    assert store.cas.orphans() == [digest_bytes(b"payload")] and store.cas.holders(digest_bytes(b"payload")) == []
    assert list(store.entries()) == [] and store.cas.read(digest_bytes(b"payload")) == b"payload"


def test_crash_after_staging_write_leaves_no_blob(trusted_tmp: Path, reopen: Callable[..., Store]) -> None:
    seed_store(trusted_tmp)
    staging = trusted_tmp / "store" / "staging"
    run_until_crash("put_and_hold", "cas.after_staging_write", trusted_tmp, STORE_ID)
    assert [p.suffix for p in staging.iterdir()] == [".tmp"]  # the crash really left the staging file
    store = reopen(trusted_tmp)
    assert not store.cas.exists(digest_bytes(b"payload")) and store.cas.orphans() == []
    assert list(staging.iterdir()) == [] and list(store.entries()) == []
