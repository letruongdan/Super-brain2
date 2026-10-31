"""Backups (spec 5.6, 5.7): self-contained snapshots and a verifier that derives what it checks from the DB."""

import json
import os
import shutil
import sqlite3
from collections.abc import Callable, Iterator
from datetime import timedelta
from pathlib import Path
from typing import NoReturn

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.os import OsAdapters
from superbrain.storage import backup as backup_module
from superbrain.storage.backup import (
    BackupManifest,
    create_maintenance_backup,
    create_policy_backup,
    create_store_backup,
    prune_backups,
    verify_backup,
)
from superbrain.storage.cas import RetentionClass
from superbrain.storage.kinds import KindRegistry
from superbrain.storage.layout import DataRoot
from superbrain.storage.retention import expire_due
from superbrain.storage.runtime import open_runtime
from superbrain.storage.schema import POLICY_MIGRATIONS, STORE_MIGRATIONS, read_schema_info
from superbrain.storage.store import Store
from tests.storage.conftest import CLOCK_START, DEMO_KINDS, Env, maintenance_lease
from tests.storage.test_retention import hold_event
from tests.support.clock import FakeClock
from tests.support.crash import run_child, run_until_crash
from tests.support.fs import corrupt_bytes, digest_tree, set_mtime

E2 = "0192f3a4-5b6c-7d8e-9f01-000000000e02"
E3 = "0192f3a4-5b6c-7d8e-9f01-000000000e03"
HELD = b"held payload"
ORPHAN = b"orphan payload"


# --- helpers ---------------------------------------------------------------------------------------------------


def verify_store(path: Path, store_id: str) -> BackupManifest:
    return verify_backup(path, expected_kind="store", expected_store_id=store_id, migrations=STORE_MIGRATIONS)


def verify_full(path: Path, store_id: str) -> BackupManifest:
    return verify_backup(path, expected_kind="store_full", expected_store_id=store_id, migrations=STORE_MIGRATIONS)


def put_and_hold(store: Store, data: bytes, holder_id: str = E2) -> str:
    return store.store_content(data, "event", holder_id, RetentionClass.EVIDENCE, None)


def store_id_of(data_root: Path) -> str:
    info = read_schema_info(data_root / "store" / "brain.db")
    assert info is not None
    return info.store_id


def seed_held_blob(data_root: Path) -> str:
    runtime = open_runtime(data_root, os_adapters())
    try:
        return put_and_hold(runtime.store, HELD)
    finally:
        runtime.close()


def seed_orphan_blob(data_root: Path) -> str:
    runtime = open_runtime(data_root, os_adapters())
    try:
        return runtime.store.cas.put(ORPHAN)
    finally:
        runtime.close()


def seed_event(data_root: Path) -> None:
    result = run_child("seed_event", data_root)
    assert result.returncode == 0, f"seed_event failed:\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"


def full_backup(data_root: Path, clock: FakeClock) -> Path:
    with maintenance_lease(data_root) as (root, lease):
        return create_maintenance_backup(root, lease, os_adapters(), target="store", now=clock.now())


def blob_in(backup: Path, digest: str) -> Path:
    hex_ = digest.removeprefix("sha256:")
    return backup / "cas" / hex_[:2] / hex_


def listed(backup: Path) -> list[str]:
    blobs = json.loads((backup / "manifest.json").read_bytes())["blobs"]
    assert isinstance(blobs, list)
    return [str(b) for b in blobs]


def rewrite_manifest(backup: Path, **changes: object) -> None:
    manifest = json.loads((backup / "manifest.json").read_bytes())
    manifest.update(changes)
    (backup / "manifest.json").write_bytes(canonical_json(manifest))


def delete_blob_and_manifest_entry(backup: Path, digest: str) -> None:
    blob_in(backup, digest).unlink()
    rewrite_manifest(backup, blobs=[b for b in listed(backup) if b != digest])


def add_blob(backup: Path, data: bytes) -> None:
    path = blob_in(backup, digest_bytes(data))
    path.parent.mkdir(exist_ok=True)
    path.write_bytes(data)


def only_blob(backup: Path) -> Path:
    (digest,) = listed(backup)
    return blob_in(backup, digest)


def only_backup_dir(root: DataRoot) -> Path:
    (entry,) = list(root.backups_dir.iterdir())
    return entry


def set_meta_versions(db: sqlite3.Connection, version: int) -> None:
    db.execute("UPDATE meta SET value = ? WHERE key IN ('schema_version', 'min_reader_version')", (str(version),))


def raising(err: BaseException) -> Callable[..., NoReturn]:
    def fn(*_args: object, **_kwargs: object) -> NoReturn:
        raise err

    return fn


DAMAGE: dict[str, Callable[[Path], None]] = {
    "drop_manifest": lambda p: (p / "manifest.json").unlink(),
    "flip_db_byte": lambda p: corrupt_bytes(p / "brain.db", offsets=[200]),
    "drop_blob": lambda p: only_blob(p).unlink(),
    "flip_blob_byte": lambda p: corrupt_bytes(only_blob(p), offsets=[0]),
    "add_stray_blob": lambda p: add_blob(p, b"stray"),
    "omit_root_from_manifest_and_delete_blob": lambda p: delete_blob_and_manifest_entry(p, listed(p)[0]),
    "manifest_store_id_only": lambda p: rewrite_manifest(p, store_id="0192f3a4-5b6c-7d8e-9f01-0000000000ff"),
    "manifest_schema_only": lambda p: rewrite_manifest(p, schema_version=2),
    "manifest_high_water_only": lambda p: rewrite_manifest(p, ledger_high_water=99),
}
# The check each damage must trip: the error message names it.
DAMAGE_CHECK = {
    "drop_manifest": "manifest",
    "flip_db_byte": "db_digest",
    "drop_blob": "blob files",
    "flip_blob_byte": "sha256",
    "add_stray_blob": "blob files",
    "omit_root_from_manifest_and_delete_blob": "roots",
    "manifest_store_id_only": "store_id",
    "manifest_schema_only": "schema_version",
    "manifest_high_water_only": "ledger_high_water",
}


@pytest.fixture
def other_env(trusted_tmp: Path, os_: OsAdapters, clock: FakeClock) -> Iterator[Env]:
    runtime = open_runtime(trusted_tmp / "other", os_, kinds=KindRegistry(DEMO_KINDS))
    try:
        yield Env(runtime, clock)
    finally:
        runtime.close()


# --- store (closure) backups -------------------------------------------------------------------------------------


def test_store_backup_round_trips_and_survives_live_gc(env: Env, clock: FakeClock) -> None:  # scenarios 7, 25
    d = hold_event(env.store, clock)
    path = create_store_backup(env.store, env.os_, clock.now())
    expire_due(env.store, env.policy, clock.now() + timedelta(days=91))
    env.store.cas.collect_garbage(now=clock.now() + timedelta(days=92), grace=timedelta(0))
    assert not env.store.cas.exists(d)
    m = verify_store(path, env.store.store_id)
    assert m.blobs == (d,) and m.kind == "store" and m.logical_verified is True
    assert blob_in(path, d).read_bytes() == b"event payload"


def test_store_manifest_records_what_the_snapshot_says(env: Env, clock: FakeClock) -> None:
    d = put_and_hold(env.store, HELD)
    path = create_store_backup(env.store, env.os_, clock.now())
    before = digest_tree(path)
    m = verify_store(path, env.store.store_id)
    assert digest_tree(path) == before  # verifying creates and changes nothing
    assert (m.format_version, m.store_id, m.schema_version, m.trust_generation) == (1, env.store.store_id, 1, None)
    assert m.ledger_high_water == max(e.sequence for e in env.store.entries()) and m.ledger_high_water > 0
    assert m.created_at == "2026-10-30T12:00:00.000000Z" and m.blobs == (d,)
    assert m.db_digest == digest_bytes((path / "brain.db").read_bytes())
    assert path.name.startswith("store-20261030T120000Z-")
    raw = (path / "manifest.json").read_bytes()
    assert "logical_verified" not in json.loads(raw) and raw == canonical_json(json.loads(raw))
    assert (path / "brain.db").read_bytes()[18:20] == bytes([1, 1])  # rollback journal: needs no -wal


def test_tombstoned_holder_is_not_a_root(env: Env, clock: FakeClock) -> None:
    kept = put_and_hold(env.store, HELD)
    hold_event(env.store, clock)
    expire_due(env.store, env.policy, clock.now() + timedelta(days=91))
    path = create_store_backup(env.store, env.os_, clock.now())
    assert verify_store(path, env.store.store_id).blobs == (kept,)


@pytest.mark.parametrize("damage", list(DAMAGE))
def test_damaged_or_inconsistent_backup_is_rejected(env: Env, clock: FakeClock, damage: str) -> None:  # I1-04
    put_and_hold(env.store, b"kept")
    path = create_store_backup(env.store, env.os_, clock.now())
    verify_store(path, env.store.store_id)
    DAMAGE[damage](path)
    with pytest.raises(BrainError) as e:
        verify_store(path, env.store.store_id)
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE
    assert DAMAGE_CHECK[damage] in e.value.message


def test_backup_of_other_store_is_rejected(env: Env, other_env: Env, clock: FakeClock) -> None:
    path = create_store_backup(other_env.store, other_env.os_, clock.now())
    verify_store(path, other_env.store.store_id)
    with pytest.raises(BrainError) as e:
        verify_store(path, env.store.store_id)
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE and "expected" in e.value.message


@pytest.mark.parametrize("sidecar", ["brain.db-wal", "brain.db-shm", "brain.db-journal", "extra.txt"])
def test_snapshot_is_one_file_and_extra_entries_are_rejected(env: Env, clock: FakeClock, sidecar: str) -> None:
    path = create_store_backup(env.store, env.os_, clock.now())
    assert sorted(p.name for p in path.iterdir()) == ["brain.db", "cas", "manifest.json"]
    (path / sidecar).write_bytes(b"")
    with pytest.raises(BrainError) as e:
        verify_store(path, env.store.store_id)
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE


@pytest.mark.parametrize("damage", ["zero_index_page", "edit_row_behind_its_indexes"])
def test_snapshot_failing_integrity_check_is_rejected(env: Env, clock: FakeClock, damage: str) -> None:
    put_and_hold(env.store, HELD)
    path = create_store_backup(env.store, env.os_, clock.now())
    snapshot = path / "brain.db"
    name = "p_cas_holders_by_digest" if damage == "zero_index_page" else "p_cas_holders_"
    db = sqlite3.connect(f"{snapshot.absolute().as_uri()}?immutable=1", uri=True)
    try:
        page_size = db.execute("PRAGMA page_size").fetchone()[0]
        page = db.execute("SELECT rootpage FROM sqlite_master WHERE name = ?", (name,)).fetchone()[0]
    finally:
        db.close()
    data = bytearray(snapshot.read_bytes())
    start = (page - 1) * page_size
    if damage == "zero_index_page":  # unreadable: the check itself errors
        data[start : start + page_size] = bytes(page_size)
    else:  # readable, but the indexes no longer match the row: the check reports it
        at = start + data[start : start + page_size].index(digest_bytes(HELD).removeprefix("sha256:").encode())
        data[at] = ord("0") if data[at] != ord("0") else ord("1")
    snapshot.write_bytes(bytes(data))
    rewrite_manifest(path, db_digest=digest_bytes(bytes(data)))  # the digest matches: only the check can tell
    with pytest.raises(BrainError) as e:
        verify_store(path, env.store.store_id)
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE and "integrity_check" in e.value.message


def test_non_canonical_or_malformed_manifest_is_rejected(env: Env, clock: FakeClock) -> None:
    path = create_store_backup(env.store, env.os_, clock.now())
    good = (path / "manifest.json").read_bytes()
    for bad in (good + b" ", b"[]", b"{", canonical_json({**json.loads(good), "extra": 1})):
        (path / "manifest.json").write_bytes(bad)
        with pytest.raises(BrainError) as e:
            verify_store(path, env.store.store_id)
        assert e.value.code == ErrorCode.INTEGRITY_FAILURE and "manifest" in e.value.message


def test_store_backup_holds_maintenance_while_it_runs(
    env: Env, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[ErrorCode] = []
    original = backup_module._snapshot_db

    def snapshot(source: sqlite3.Connection, dest: Path) -> None:
        with pytest.raises(BrainError) as e:
            env.store.cas.collect_garbage(now=clock.now())
        seen.append(e.value.code)
        original(source, dest)

    monkeypatch.setattr(backup_module, "_snapshot_db", snapshot)
    create_store_backup(env.store, env.os_, clock.now())
    assert seen == [ErrorCode.STORE_BUSY]
    env.store.cas.collect_garbage(now=clock.now())  # the flag is released afterwards


def test_every_backup_snapshots_through_the_module_seam(
    env: Env, trusted_tmp: Path, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    boom = BrainError(ErrorCode.IO_ERROR, "injected snapshot failure")
    monkeypatch.setattr(backup_module, "_snapshot_db", raising(boom))
    creators: list[Callable[[], Path]] = [
        lambda: create_store_backup(env.store, env.os_, clock.now()),
        lambda: create_policy_backup(env.policy, env.os_, clock.now()),
    ]
    for create in creators:
        with pytest.raises(BrainError) as e:
            create()
        assert e.value is boom
    seed_held_blob(trusted_tmp / "m")
    for target in ("store", "policy"):
        with maintenance_lease(trusted_tmp / "m") as (root, lease), pytest.raises(BrainError) as e:
            create_maintenance_backup(root, lease, os_adapters(), target=target, now=clock.now())
        assert e.value is boom


def test_naive_now_is_rejected(env: Env) -> None:
    with pytest.raises(BrainError) as e:
        create_store_backup(env.store, env.os_, CLOCK_START.replace(tzinfo=None))
    assert e.value.code == ErrorCode.INVALID_INPUT


def test_unreadable_store_backup_is_unsupported_version(env: Env, clock: FakeClock) -> None:
    with env.store.transaction() as t:
        set_meta_versions(t.db, 2)
    path = create_store_backup(env.store, env.os_, clock.now())
    with pytest.raises(BrainError) as e:
        verify_store(path, env.store.store_id)
    assert e.value.code == ErrorCode.UNSUPPORTED_VERSION


# --- policy backups ----------------------------------------------------------------------------------------------


def test_policy_backup_round_trip_and_corruption(env: Env, clock: FakeClock) -> None:  # R3-02
    path = create_policy_backup(env.policy, env.os_, clock.now())
    m = verify_backup(path, expected_kind="policy", expected_store_id=env.policy.store_id, migrations=POLICY_MIGRATIONS)
    assert m.trust_generation == env.policy.trust_generation()
    assert (m.kind, m.ledger_high_water, m.blobs) == ("policy", 0, ())
    assert path.name.startswith("policy-") and (path / "policy.db").is_file()
    corrupt_bytes(path / "policy.db", offsets=[200])
    with pytest.raises(BrainError) as e:
        verify_backup(path, expected_kind="policy", expected_store_id=env.policy.store_id, migrations=POLICY_MIGRATIONS)
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE and "db_digest" in e.value.message


def test_policy_manifest_trust_generation_must_match_the_snapshot(env: Env, clock: FakeClock) -> None:
    path = create_policy_backup(env.policy, env.os_, clock.now())
    rewrite_manifest(path, trust_generation=env.policy.trust_generation() + 1)
    with pytest.raises(BrainError) as e:
        verify_backup(path, expected_kind="policy", expected_store_id=env.policy.store_id, migrations=POLICY_MIGRATIONS)
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE and "trust_generation" in e.value.message


@pytest.mark.parametrize("trust", [None, 1])
def test_store_backup_relabelled_as_policy_is_rejected(env: Env, clock: FakeClock, trust: int | None) -> None:
    path = create_store_backup(env.store, env.os_, clock.now())
    (path / "brain.db").rename(path / "policy.db")
    shutil.rmtree(path / "cas")
    rewrite_manifest(path, kind="policy", blobs=[], ledger_high_water=0, trust_generation=trust)
    with pytest.raises(BrainError) as e:
        verify_backup(path, expected_kind="policy", expected_store_id=env.store.store_id, migrations=POLICY_MIGRATIONS)
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE and "trust_generation" in e.value.message


@pytest.mark.parametrize(("kind", "trust"), [("policy", None), ("store", 1)])
def test_trust_generation_must_suit_the_kind(env: Env, clock: FakeClock, kind: str, trust: int | None) -> None:
    if kind == "policy":
        path = create_policy_backup(env.policy, env.os_, clock.now())
        expected, migrations = "policy", POLICY_MIGRATIONS
    else:
        path = create_store_backup(env.store, env.os_, clock.now())
        expected, migrations = "store", STORE_MIGRATIONS
    rewrite_manifest(path, trust_generation=trust)
    with pytest.raises(BrainError) as e:
        verify_backup(path, expected_kind=expected, expected_store_id=env.store.store_id, migrations=migrations)  # type: ignore[arg-type]
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE  # refused by the manifest check itself, before any derivation
    assert "check manifest" in e.value.message and "trust_generation" in e.value.message


def test_policy_backup_of_a_db_without_trust_is_refused(trusted_tmp: Path, clock: FakeClock) -> None:
    open_runtime(trusted_tmp, os_adapters()).close()
    db = sqlite3.connect(trusted_tmp / "policy" / "policy.db", isolation_level=None)
    try:
        db.execute("DROP TABLE trust")
    finally:
        db.close()
    with maintenance_lease(trusted_tmp) as (root, lease), pytest.raises(BrainError) as e:
        create_maintenance_backup(root, lease, os_adapters(), target="policy", now=clock.now())
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE and "trust_generation" in e.value.message
    (partial,) = (trusted_tmp / "backups").iterdir()
    assert not (partial / "manifest.json").exists()


def test_kind_mismatch_is_rejected(env: Env, clock: FakeClock) -> None:
    path = create_policy_backup(env.policy, env.os_, clock.now())
    with pytest.raises(BrainError) as e:
        verify_backup(path, expected_kind="store", expected_store_id=env.policy.store_id, migrations=STORE_MIGRATIONS)
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE and "kind" in e.value.message
    m = verify_backup(
        path,
        expected_kind=frozenset({"store", "policy"}),
        expected_store_id=env.policy.store_id,
        migrations=POLICY_MIGRATIONS,
    )
    assert m.kind == "policy"


def test_policy_backup_by_path_round_trips(trusted_tmp: Path, clock: FakeClock) -> None:  # R2-07
    open_runtime(trusted_tmp, os_adapters()).close()
    with maintenance_lease(trusted_tmp) as (root, lease):
        path = create_maintenance_backup(root, lease, os_adapters(), target="policy", now=clock.now())
    m = verify_backup(
        path, expected_kind="policy", expected_store_id=store_id_of(trusted_tmp), migrations=POLICY_MIGRATIONS
    )
    assert m.trust_generation == 1 and sorted(p.name for p in path.iterdir()) == ["manifest.json", "policy.db"]


# --- maintenance (full) backups ----------------------------------------------------------------------------------


FULL_DAMAGE: dict[str, Callable[[Path], None]] = {
    "drop_listed_blob": lambda p: blob_in(p, digest_bytes(ORPHAN)).unlink(),
    "omit_root_from_manifest_and_delete_blob": lambda p: delete_blob_and_manifest_entry(p, digest_bytes(HELD)),
    "add_unlisted_blob": lambda p: add_blob(p, b"unlisted"),
}


@pytest.mark.parametrize("damage", list(FULL_DAMAGE))
def test_full_backup_physical_completeness(trusted_tmp: Path, clock: FakeClock, damage: str) -> None:  # R3-04
    seed_held_blob(trusted_tmp)
    seed_orphan_blob(trusted_tmp)
    path = full_backup(trusted_tmp, clock)
    verify_full(path, store_id_of(trusted_tmp))
    FULL_DAMAGE[damage](path)
    with pytest.raises(BrainError) as e:
        verify_full(path, store_id_of(trusted_tmp))
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE


@pytest.mark.parametrize("failure", ["copy", "snapshot", "snapshot_and_cleanup"])
def test_failed_maintenance_backup_removes_its_work_directory(
    trusted_tmp: Path, clock: FakeClock, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    seed_held_blob(trusted_tmp)
    boom = BrainError(ErrorCode.IO_ERROR, "injected snapshot failure")
    if failure == "copy":
        monkeypatch.setattr(shutil, "copyfile", raising(OSError(28, "injected: no space left")))
    else:
        monkeypatch.setattr(backup_module, "_snapshot_db", raising(boom))
    if failure == "snapshot_and_cleanup":
        monkeypatch.setattr(shutil, "rmtree", raising(PermissionError("injected: cannot remove")))
    with maintenance_lease(trusted_tmp) as (root, lease), pytest.raises(BrainError) as e:
        create_maintenance_backup(root, lease, os_adapters(), target="store", now=clock.now())
    monkeypatch.undo()
    leftovers = [p.relative_to(trusted_tmp).as_posix() for p in (trusted_tmp / "backups").rglob(".work-*")]
    if failure == "copy":
        assert e.value.code == ErrorCode.STORAGE_FULL and "cannot copy" in e.value.message and leftovers == []
    elif failure == "snapshot":
        assert e.value is boom and leftovers == []
    else:  # the original error propagates; the failed cleanup is attached to it, not hidden
        assert e.value is boom and len(leftovers) == 1
        assert any("could not be removed" in note for note in getattr(e.value, "__notes__", []))


def test_finished_backup_with_a_leftover_work_directory_is_rejected(trusted_tmp: Path, clock: FakeClock) -> None:
    seed_held_blob(trusted_tmp)
    path = full_backup(trusted_tmp, clock)
    (path / ".work-0192f3a4-5b6c-7d8e-9f01-000000000001").mkdir()
    (path / ".work-0192f3a4-5b6c-7d8e-9f01-000000000001" / "brain.db").write_bytes(b"copy")
    with pytest.raises(BrainError) as e:
        verify_full(path, store_id_of(trusted_tmp))
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE and "entries" in e.value.message


def test_maintenance_backup_requires_target_closed(env: Env, clock: FakeClock) -> None:
    for target in ("store", "policy"):
        with pytest.raises(BrainError) as e:
            create_maintenance_backup(env.root, env.lease, env.os_, target=target, now=clock.now())
        assert e.value.code == ErrorCode.STORE_BUSY
    assert list(env.root.backups_dir.iterdir()) == []


def test_full_backup_missing_held_root_is_rejected(trusted_tmp: Path, clock: FakeClock) -> None:  # R2-01
    d = seed_held_blob(trusted_tmp)
    path = full_backup(trusted_tmp, clock)
    delete_blob_and_manifest_entry(path, d)
    with pytest.raises(BrainError) as e:
        verify_full(path, store_id_of(trusted_tmp))
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE and "roots" in e.value.message


def test_full_backup_with_extra_orphan_blob_is_accepted(trusted_tmp: Path, clock: FakeClock) -> None:
    held, orphan = seed_held_blob(trusted_tmp), seed_orphan_blob(trusted_tmp)
    (trusted_tmp / "store" / "cas" / "not-a-shard.txt").write_bytes(b"ignored")
    path = full_backup(trusted_tmp, clock)
    m = verify_full(path, store_id_of(trusted_tmp))
    assert m.logical_verified is True and m.kind == "store_full" and m.blobs == tuple(sorted((held, orphan)))
    assert path.name.startswith("store_full-")


def test_full_backup_of_unreadable_schema_checks_physical_facts_only(trusted_tmp: Path, clock: FakeClock) -> None:
    seed_held_blob(trusted_tmp)
    db = sqlite3.connect(trusted_tmp / "store" / "brain.db", isolation_level=None)
    try:
        set_meta_versions(db, 2)
    finally:
        db.close()
    path = full_backup(trusted_tmp, clock)
    m = verify_full(path, store_id_of(trusted_tmp))
    assert m.logical_verified is False and m.schema_version == 2
    good = (path / "manifest.json").read_bytes()
    rewrite_manifest(path, trust_generation=1)  # store kinds never carry one, readable schema or not
    with pytest.raises(BrainError) as e:
        verify_full(path, store_id_of(trusted_tmp))
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE and "trust_generation" in e.value.message
    (path / "manifest.json").write_bytes(good)
    add_blob(path, b"unlisted")
    with pytest.raises(BrainError) as e:
        verify_full(path, store_id_of(trusted_tmp))
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE


@pytest.mark.parametrize("shm", ["kept", "deleted"])
def test_full_backup_includes_committed_wal_of_a_crashed_writer(trusted_tmp: Path, clock: FakeClock, shm: str) -> None:
    run_until_crash("seed_event", "ledger.after_commit", trusted_tmp)
    store = trusted_tmp / "store"
    assert (store / "brain.db-wal").exists() and (store / "brain.db-shm").exists()
    if shm == "deleted":
        (store / "brain.db-shm").unlink()
    sources = [p for p in (store / "brain.db", store / "brain.db-wal", store / "brain.db-shm") if p.exists()]
    before = {p.name: p.read_bytes() for p in sources}
    path = full_backup(trusted_tmp, clock)
    assert {p.name: p.read_bytes() for p in sources} == before  # the source files are only copied
    assert sorted(p.name for p in store.iterdir() if p.name.startswith("brain.db")) == sorted(before)
    m = verify_full(path, store_id_of(trusted_tmp))
    assert m.ledger_high_water == 1 and digest_bytes(b"event payload") in m.blobs
    assert sorted(p.name for p in path.iterdir()) == ["brain.db", "cas", "manifest.json"]  # work directory gone


@pytest.mark.parametrize("crashpoint", ["backup.after_db_snapshot", "backup.after_blob_copy"])
def test_crash_mid_backup_leaves_incomplete_backup_that_never_verifies(trusted_tmp: Path, crashpoint: str) -> None:
    seed_event(trusted_tmp)
    run_until_crash("backup_store", crashpoint, trusted_tmp)
    rt = open_runtime(trusted_tmp, os_adapters())
    try:
        partial = only_backup_dir(rt.root)
        assert not (partial / "manifest.json").exists() and (partial / "brain.db").is_file()
        with pytest.raises(BrainError) as e:
            verify_store(partial, rt.store.store_id)
        assert e.value.code == ErrorCode.INTEGRITY_FAILURE
    finally:
        rt.close()


# --- pruning and permissions -------------------------------------------------------------------------------------


def fake_backup(backups: Path, kind: str, hours_ago: int, *, complete: bool = True) -> Path:
    stamp = (CLOCK_START - timedelta(hours=hours_ago)).strftime("%Y%m%dT%H%M%SZ")
    path = backups / f"{kind}-{stamp}-0192f3a4-5b6c-7d8e-9f01-{hours_ago:012d}"
    path.mkdir()
    if complete:
        (path / "manifest.json").write_bytes(b"{}")
    # mtimes run opposite to the names: pruning must order by the name.
    set_mtime(path, CLOCK_START - timedelta(days=30) + timedelta(hours=hours_ago))
    return path


def test_prune_keeps_seven_complete_per_kind(trusted_tmp: Path, clock: FakeClock) -> None:
    backups = trusted_tmp / "backups"
    backups.mkdir()
    stores = [fake_backup(backups, "store", h) for h in range(1, 10)]
    policies = [fake_backup(backups, "policy", h) for h in (100, 200)]
    full = fake_backup(backups, "store_full", 300)
    old_partial = fake_backup(backups, "store", 25, complete=False)
    young_partial = fake_backup(backups, "policy", 23, complete=False)
    (backups / "unrelated").mkdir()
    changed = prune_backups(backups, os_=os_adapters(), now=clock.now())
    assert changed == sorted([stores[7], stores[8], old_partial.with_name(old_partial.name + ".incomplete")])
    left = sorted(p.name for p in backups.iterdir())
    expected = [p.name for p in (*stores[:7], *policies, full, young_partial)]
    assert left == sorted([*expected, old_partial.name + ".incomplete", "unrelated"])
    assert prune_backups(backups, os_=os_adapters(), now=clock.now()) == []


def test_prune_honours_keep(trusted_tmp: Path, clock: FakeClock) -> None:
    backups = trusted_tmp / "backups"
    backups.mkdir()
    stores = [fake_backup(backups, "store", h) for h in (1, 2, 3)]
    assert sorted(prune_backups(backups, os_=os_adapters(), keep=1, now=clock.now())) == sorted(stores[1:])
    with pytest.raises(BrainError) as e:
        prune_backups(backups, os_=os_adapters(), keep=0, now=clock.now())
    assert e.value.code == ErrorCode.INVALID_INPUT


def test_failed_prune_leaves_no_half_deleted_backup_that_looks_complete(
    trusted_tmp: Path, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    backups = trusted_tmp / "backups"
    backups.mkdir()
    stores = [fake_backup(backups, "store", h) for h in range(1, 9)]
    real_rmtree = shutil.rmtree

    def half_rmtree(path: str | os.PathLike[str], *args: object, **kwargs: object) -> None:
        (Path(path) / "brain.db").write_bytes(b"left behind")
        (Path(path) / "manifest.json").unlink()  # part of the tree goes, then the removal fails
        raise PermissionError("injected rmtree failure")

    monkeypatch.setattr(shutil, "rmtree", half_rmtree)
    with pytest.raises(BrainError) as e:
        prune_backups(backups, os_=os_adapters(), now=clock.now())
    assert e.value.code == ErrorCode.IO_ERROR
    assert not stores[7].exists()
    (doomed,) = [p for p in backups.iterdir() if ".deleting-" in p.name]
    assert doomed.name.startswith(stores[7].name + ".deleting-")
    monkeypatch.setattr(shutil, "rmtree", real_rmtree)
    assert prune_backups(backups, os_=os_adapters(), now=clock.now()) == []  # .deleting-* is not counted
    assert doomed.exists() and all(p.exists() for p in stores[:7])


def test_prune_does_not_count_deleting_entries(trusted_tmp: Path, clock: FakeClock) -> None:
    backups = trusted_tmp / "backups"
    backups.mkdir()
    stores = [fake_backup(backups, "store", h) for h in range(1, 8)]
    leftover = fake_backup(backups, "store", 50)
    leftover = leftover.rename(leftover.with_name(leftover.name + ".deleting-0192f3a4-5b6c-7d8e-9f01-000000000001"))
    assert prune_backups(backups, os_=os_adapters(), now=clock.now()) == []
    assert leftover.exists() and all(p.exists() for p in stores)


def test_backup_directory_is_owner_only(env: Env, clock: FakeClock) -> None:
    put_and_hold(env.store, HELD)
    paths = [
        create_store_backup(env.store, env.os_, clock.now()),
        create_policy_backup(env.policy, env.os_, clock.now()),
    ]
    for path in paths:
        assert env.os_.permissions.problems(path) == []
        if os.name != "nt":
            assert all(p.stat().st_mode & 0o077 == 0 for p in (path, *path.rglob("*")))
