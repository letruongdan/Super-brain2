"""Kernel schema v2 migration, pre-admission byte-immutability, and daemon config tests (Task 2)."""

from __future__ import annotations

import json
import os
import sqlite3
import stat
import sys
from datetime import timedelta
from pathlib import Path
from typing import Literal

import pytest

from superbrain.adapters.os.daemon_config import read_daemon_config
from superbrain.composition.migrate_entry import migrate_offline
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.kernel import DaemonConfig
from superbrain.ports.os import OsAdapters
from superbrain.ports.policy import IntentKind
from superbrain.storage.backup import verify_backup
from superbrain.storage.cas import RetentionClass
from superbrain.storage.kernel_schema import KERNEL_POLICY_MIGRATIONS, KERNEL_STORE_MIGRATIONS
from superbrain.storage.kinds import KindRegistry
from superbrain.storage.layout import DataRoot, prepare_data_root
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.runtime import admit_existing_pair, open_runtime, open_runtime_under_lease
from superbrain.storage.schema import POLICY_MIGRATIONS, STORE_MIGRATIONS, Migration, read_schema_info
from superbrain.storage.store import Store
from superbrain.storage.swap import READY
from tests.storage.conftest import DEMO_KINDS, CounterProjection, counter, maintenance_lease
from tests.support.clock import FakeClock
from tests.support.fs import digest_tree, fake_link


def _loosen_file(path: Path) -> None:
    if sys.platform == "win32":
        from tests.support.winacl import grant

        grant(path, "S-1-1-0", 0x120089)
    else:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)


def test_two_schema_upgrade_restarts_between_swaps(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    root_path = trusted_tmp / "v1-root"
    rt = open_runtime(
        root_path,
        os_,
        handlers=(CounterProjection(),),
        kinds=KindRegistry(DEMO_KINDS),
        store_migrations=STORE_MIGRATIONS,
        policy_migrations=POLICY_MIGRATIONS,
    )
    store_id = rt.store.store_id
    initial_generation = rt.policy.trust_generation()
    blob_bytes = b"increment-1-blob-payload"
    holder_id = new_id()
    blob_digest = rt.store.store_content(blob_bytes, "evidence", holder_id, RetentionClass.DURABLE, None)
    with rt.store.transaction() as txn:
        txn.append("demo.count", actor="user:cli", owner_id="dan", meta={"n": 7})
    quarantined_digest = digest_bytes(b"quarantined-content")
    rt.policy.record_intent(IntentKind.QUARANTINE, {"digest": quarantined_digest})
    assert rt.store.reconcile_policy() == 1
    rt.close()

    # Cert/key paths need not exist on disk during offline migrate (loaded only in serve).
    cfg = DaemonConfig(
        version=1,
        data_root=root_path,
        expected_store_id=store_id,
        cert_path=trusted_tmp / "nonexistent-server.pem",
        key_path=trusted_tmp / "nonexistent-server.key",
    )

    class _SimulatedCrashAfterPolicySwap(RuntimeError):
        pass

    def crash_between_swaps() -> None:
        raise _SimulatedCrashAfterPolicySwap("killed after policy v2 swap")

    clock.advance(timedelta(seconds=10))
    with pytest.raises(_SimulatedCrashAfterPolicySwap):
        migrate_offline(cfg, os_, _after_policy_step=crash_between_swaps)

    data_root = DataRoot.at(root_path)
    policy_info = read_schema_info(data_root.policy_db)
    store_info = read_schema_info(data_root.store_db)
    assert policy_info is not None and policy_info.schema_version == 2
    assert store_info is not None and store_info.schema_version == 1

    # Serve admission refuses mixed (policy=2, store=1) with zero byte changes (including writer.lock byte 0..end).
    mixed_snapshot = digest_tree(root_path)
    with pytest.raises(BrainError) as exc_info:
        admit_existing_pair(root_path, store_id, os_, purpose="serve")
    assert exc_info.value.code is ErrorCode.MIGRATION_REQUIRED
    assert digest_tree(root_path) == mixed_snapshot

    # Resuming offline migrate skips policy (already v2) and migrates only store (v1 -> v2).
    clock.advance(timedelta(seconds=10))
    resumed = migrate_offline(cfg, os_)
    assert resumed.store_id == store_id
    assert resumed.policy_report.status == "skipped"
    assert resumed.policy_report.from_version == 2 and resumed.policy_report.to_version == 2
    assert resumed.store_report.status == "migrated"
    assert resumed.store_report.from_version == 1 and resumed.store_report.to_version == 2
    assert resumed.store_report.report is not None

    # Pre-migration v1 backups taken for both policy and store remain verifiable with v1 migrations.
    backups = sorted(data_root.backups_dir.iterdir())
    assert len(backups) == 2
    policy_backups = [b for b in backups if "policy" in b.name]
    store_backups = [b for b in backups if "store" in b.name]
    assert len(policy_backups) == 1 and len(store_backups) == 1
    verify_backup(
        policy_backups[0],
        expected_kind="policy",
        expected_store_id=store_id,
        migrations=POLICY_MIGRATIONS,
        os_=os_,
    )
    verify_backup(
        store_backups[0],
        expected_kind="store_full",
        expected_store_id=store_id,
        migrations=STORE_MIGRATIONS,
        os_=os_,
    )

    # Open upgraded v2 runtime under admitted writer lease and verify preserved state + new digest key.
    admitted = admit_existing_pair(root_path, store_id, os_, purpose="serve")
    rt2 = open_runtime_under_lease(
        admitted,
        handlers=(CounterProjection(),),
        kinds=KindRegistry(DEMO_KINDS),
    )
    try:
        assert rt2.store.store_id == store_id
        assert rt2.policy.store_id == store_id
        assert rt2.policy.trust_generation() == initial_generation
        assert rt2.store.cas.read(blob_digest) == blob_bytes
        assert counter(rt2.store) == 1
        assert rt2.policy.is_quarantined(quarantined_digest)
        key_id, key_bytes = rt2.policy.request_digest_key()
        assert isinstance(key_id, str) and len(key_id) > 0
        assert isinstance(key_bytes, bytes) and len(key_bytes) == 32
    finally:
        rt2.close()

    # Increment 1 binary (v1 migrations only) refuses the v2 pair with UNSUPPORTED_VERSION and touches 0 DB/CAS bytes.
    policy_dir_hashes = digest_tree(data_root.policy_dir)
    store_dir_hashes = digest_tree(data_root.store_dir)
    with pytest.raises(BrainError) as downgrade_exc:
        open_runtime(
            root_path,
            os_,
            handlers=(CounterProjection(),),
            kinds=KindRegistry(DEMO_KINDS),
            store_migrations=STORE_MIGRATIONS,
            policy_migrations=POLICY_MIGRATIONS,
        )
    assert downgrade_exc.value.code is ErrorCode.UNSUPPORTED_VERSION
    assert digest_tree(data_root.policy_dir) == policy_dir_hashes
    assert digest_tree(data_root.store_dir) == store_dir_hashes

    # Even read-side backup/schema checks from v1 fail closed due to min_reader_version=2 capability fence.
    with maintenance_lease(root_path, os_) as (mroot, mlease):
        with pytest.raises(BrainError) as store_open_exc:
            p2 = PolicyStore.open(mroot, mlease, os_, migrations=KERNEL_POLICY_MIGRATIONS)
            try:
                Store.open(
                    mroot,
                    mlease,
                    os_,
                    p2,
                    (CounterProjection(),),
                    KindRegistry(DEMO_KINDS),
                    migrations=STORE_MIGRATIONS,
                )
            finally:
                p2.close()
        assert store_open_exc.value.code is ErrorCode.UNSUPPORTED_VERSION


def test_two_target_orchestration_with_injected_sequences_and_noop(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    root_path = trusted_tmp / "injected-seq"
    rt = open_runtime(
        root_path,
        os_,
        store_migrations=STORE_MIGRATIONS,
        policy_migrations=POLICY_MIGRATIONS,
    )
    store_id = rt.store.store_id
    rt.close()

    def _store_v3(db: sqlite3.Connection) -> None:
        db.execute("CREATE TABLE operational_test_v3 (id TEXT PRIMARY KEY)")

    injected_store = (*KERNEL_STORE_MIGRATIONS, Migration(to_version=3, min_reader_version=3, apply=_store_v3))
    cfg = DaemonConfig(
        version=1,
        data_root=root_path,
        expected_store_id=store_id,
        cert_path=trusted_tmp / "cert.pem",
        key_path=trusted_tmp / "key.pem",
    )

    clock.advance(timedelta(seconds=5))
    first = migrate_offline(
        cfg,
        os_,
        policy_migrations=KERNEL_POLICY_MIGRATIONS,
        store_migrations=injected_store,
    )
    assert not first.noop
    assert first.policy_report.status == "migrated" and first.policy_report.to_version == 2
    assert first.store_report.status == "migrated" and first.store_report.to_version == 3

    # Re-running when both targets already match target tuple is a clean noop (no new backups or stage swaps).
    backups_before = sorted((root_path / "backups").iterdir())
    clock.advance(timedelta(seconds=5))
    second = migrate_offline(
        cfg,
        os_,
        policy_migrations=KERNEL_POLICY_MIGRATIONS,
        store_migrations=injected_store,
    )
    assert second.noop
    assert second.policy_report.status == "skipped" and second.policy_report.from_version == 2
    assert second.store_report.status == "skipped" and second.store_report.from_version == 3
    assert sorted((root_path / "backups").iterdir()) == backups_before


def _make_v2_root(root_path: Path, os_: OsAdapters) -> str:
    rt = open_runtime(
        root_path,
        os_,
        kinds=KindRegistry(DEMO_KINDS),
        store_migrations=KERNEL_STORE_MIGRATIONS,
        policy_migrations=KERNEL_POLICY_MIGRATIONS,
    )
    store_id = rt.store.store_id
    rt.store.store_content(b"immutable-cas-check", "artifact", new_id(), RetentionClass.DURABLE, None)
    rt.close()
    return store_id


def test_preadmission_refusals_preserve_exact_bytes(trusted_tmp: Path, os_: OsAdapters) -> None:
    # 1. Missing root: refuses NOT_FOUND without creating root or ancestors.
    missing_root = trusted_tmp / "does-not-exist" / "root"
    parent_snapshot = digest_tree(trusted_tmp)
    with pytest.raises(BrainError) as exc_missing:
        admit_existing_pair(missing_root, "store-missing", os_, purpose="serve")
    assert exc_missing.value.code is ErrorCode.NOT_FOUND
    assert not missing_root.exists()
    assert digest_tree(trusted_tmp) == parent_snapshot

    # 2. Missing writer.lock inside an existing owner-only directory: refuses NOT_FOUND without creating lock.
    no_lock_root = trusted_tmp / "no-lock"
    no_lock_root.mkdir()
    os_.permissions.secure_directory(no_lock_root)
    snap_no_lock = digest_tree(no_lock_root)
    with pytest.raises(BrainError) as exc_no_lock:
        admit_existing_pair(no_lock_root, "store-no-lock", os_, purpose="serve")
    assert exc_no_lock.value.code is ErrorCode.NOT_FOUND
    assert digest_tree(no_lock_root) == snap_no_lock

    # 3. Empty root with only writer.lock (no policy/store DBs): refuses NOT_FOUND without bumping epoch.
    lock_only_root = trusted_tmp / "lock-only"
    prepare_data_root(lock_only_root, os_)
    snap_lock_only = digest_tree(lock_only_root)
    with pytest.raises(BrainError) as exc_empty:
        admit_existing_pair(lock_only_root, "store-empty", os_, purpose="serve")
    assert exc_empty.value.code is ErrorCode.NOT_FOUND
    assert digest_tree(lock_only_root) == snap_lock_only

    # 4. Wrong expected_store_id: refuses IDENTITY_MISMATCH with exact lock/DB/CAS bytes preserved.
    valid_root = trusted_tmp / "valid-v2"
    _make_v2_root(valid_root, os_)
    snap_valid = digest_tree(valid_root)
    with pytest.raises(BrainError) as exc_wrong_id:
        admit_existing_pair(valid_root, "wrong-store-id", os_, purpose="serve")
    assert exc_wrong_id.value.code is ErrorCode.IDENTITY_MISMATCH
    assert digest_tree(valid_root) == snap_valid

    # 5. Mismatched store_id between policy.db and brain.db: refuses INTEGRITY_FAILURE with exact bytes preserved.
    mismatch_root = trusted_tmp / "pair-mismatch"
    mismatch_id = _make_v2_root(mismatch_root, os_)
    raw_db = sqlite3.connect(mismatch_root / "store" / "brain.db")
    try:
        raw_db.execute("PRAGMA journal_mode=DELETE")
        raw_db.execute("UPDATE meta SET value = 'foreign-store-999' WHERE key = 'store_id'")
        raw_db.commit()
    finally:
        raw_db.close()
    os_.permissions.secure_file(mismatch_root / "store" / "brain.db")
    snap_mismatch = digest_tree(mismatch_root)
    with pytest.raises(BrainError) as exc_pair:
        admit_existing_pair(mismatch_root, mismatch_id, os_, purpose="serve")
    assert exc_pair.value.code is ErrorCode.INTEGRITY_FAILURE
    assert digest_tree(mismatch_root) == snap_mismatch

    # 6. Future schema committed ONLY in brain.db-wal (tested BOTH with -shm present AND with -shm deleted!).
    wal_root = trusted_tmp / "wal-future"
    wal_store_id = _make_v2_root(wal_root, os_)
    store_db = wal_root / "store" / "brain.db"
    wal_file = wal_root / "store" / "brain.db-wal"
    shm_file = wal_root / "store" / "brain.db-shm"
    conn = sqlite3.connect(store_db, isolation_level=None)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA wal_autocheckpoint=0")
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("UPDATE meta SET value = '99' WHERE key = 'schema_version'")
        conn.execute("UPDATE meta SET value = '99' WHERE key = 'min_reader_version'")
        conn.execute("COMMIT")
        # Copy the uncheckpointed main + -wal + -shm bytes before SQLite's clean close checkpoints them!
        raw_main = store_db.read_bytes()
        raw_wal = wal_file.read_bytes()
        raw_shm = shm_file.read_bytes()
    finally:
        conn.close()
    store_db.write_bytes(raw_main)
    wal_file.write_bytes(raw_wal)
    shm_file.write_bytes(raw_shm)
    for p in (store_db, wal_file, shm_file):
        os_.permissions.secure_file(p)
    assert wal_file.stat().st_size > 32

    # 6a. With BOTH -wal and -shm present: refuses UNSUPPORTED_VERSION without touching -shm, -wal, DB, or lock!
    snap_wal_with_shm = digest_tree(wal_root)
    with pytest.raises(BrainError) as exc_wal_shm:
        admit_existing_pair(wal_root, wal_store_id, os_, purpose="serve")
    assert exc_wal_shm.value.code is ErrorCode.UNSUPPORTED_VERSION
    assert digest_tree(wal_root) == snap_wal_with_shm

    # 6b. With -wal ONLY (-shm removed): recovers via out-of-root owner-only scratch, refuses UNSUPPORTED_VERSION,
    # and leaves zero .reading-* dirs or byte changes inside wal_root!
    shm_file.unlink()
    snap_wal_no_shm = digest_tree(wal_root)
    purposes: tuple[Literal["serve", "migrate"], ...] = ("serve", "migrate")
    for purpose in purposes:
        with pytest.raises(BrainError) as exc_wal_only:
            admit_existing_pair(wal_root, wal_store_id, os_, purpose=purpose)
        assert exc_wal_only.value.code is ErrorCode.UNSUPPORTED_VERSION
        assert digest_tree(wal_root) == snap_wal_no_shm

    # 7. Future schema inside a publishable READY stage (live store/ moved aside): refuses UNSUPPORTED_VERSION
    # before publishing the stage or bumping epoch!
    stage_root = trusted_tmp / "future-stage"
    stage_store_id = _make_v2_root(stage_root, os_)
    live_store = stage_root / "store"
    stage_dir = stage_root / "store.migrating"
    live_store.rename(stage_dir)
    stage_conn = sqlite3.connect(stage_dir / "brain.db")
    try:
        stage_conn.execute("PRAGMA journal_mode=DELETE")
        stage_conn.execute("UPDATE meta SET value = '99' WHERE key = 'schema_version'")
        stage_conn.commit()
    finally:
        stage_conn.close()
    os_.permissions.secure_file(stage_dir / "brain.db")
    os_.publisher.write_new(stage_dir / READY, b"")
    os_.permissions.secure_file(stage_dir / READY)
    snap_stage = digest_tree(stage_root)
    with pytest.raises(BrainError) as exc_stage:
        admit_existing_pair(stage_root, stage_store_id, os_, purpose="serve")
    assert exc_stage.value.code is ErrorCode.UNSUPPORTED_VERSION
    assert digest_tree(stage_root) == snap_stage

    # 7b. Future schema inside a READY stage alongside an intact v2 live store/ (crash at after_stage by newer binary):
    # refuses UNSUPPORTED_VERSION without setting aside store.migrating or bumping writer.lock!
    after_stage_root = trusted_tmp / "future-after-stage"
    after_stage_id = _make_v2_root(after_stage_root, os_)
    co_stage = after_stage_root / "store.migrating"
    co_stage.mkdir()
    os_.permissions.secure_directory(co_stage)
    co_db = co_stage / "brain.db"
    co_db.write_bytes((after_stage_root / "store" / "brain.db").read_bytes())
    co_conn = sqlite3.connect(co_db)
    try:
        co_conn.execute("PRAGMA journal_mode=DELETE")
        co_conn.execute("UPDATE meta SET value = '99' WHERE key = 'schema_version'")
        co_conn.commit()
    finally:
        co_conn.close()
    os_.permissions.secure_file(co_db)
    os_.publisher.write_new(co_stage / READY, b"")
    os_.permissions.secure_file(co_stage / READY)
    snap_after_stage = digest_tree(after_stage_root)
    with pytest.raises(BrainError) as exc_after_stage:
        admit_existing_pair(after_stage_root, after_stage_id, os_, purpose="serve")
    assert exc_after_stage.value.code is ErrorCode.UNSUPPORTED_VERSION
    assert digest_tree(after_stage_root) == snap_after_stage

    # 8. Ambiguous two stages (store.migrating and store.restoring): refuses INTEGRITY_FAILURE untouched.
    ambig_root = trusted_tmp / "ambig-stages"
    ambig_id = _make_v2_root(ambig_root, os_)
    for name in ("store.migrating", "store.restoring"):
        d = ambig_root / name
        d.mkdir()
        os_.permissions.secure_directory(d)
    snap_ambig = digest_tree(ambig_root)
    with pytest.raises(BrainError) as exc_ambig:
        admit_existing_pair(ambig_root, ambig_id, os_, purpose="serve")
    assert exc_ambig.value.code is ErrorCode.INTEGRITY_FAILURE
    assert digest_tree(ambig_root) == snap_ambig


def test_serve_admission_completes_compatible_interrupted_swap(trusted_tmp: Path, os_: OsAdapters) -> None:
    root_path = trusted_tmp / "compat-swap"
    store_id = _make_v2_root(root_path, os_)
    # Simulate crash between_renames during a valid v2 swap: store/ moved to store.replaced-..., store.migrating READY.
    (root_path / "store").rename(root_path / "store.migrating")
    os_.publisher.write_new(root_path / "store.migrating" / READY, b"")
    os_.permissions.secure_file(root_path / "store.migrating" / READY)

    admitted = admit_existing_pair(root_path, store_id, os_, purpose="serve")
    rt = open_runtime_under_lease(admitted, kinds=KindRegistry(DEMO_KINDS))
    try:
        assert (root_path / "store" / "brain.db").is_file()
        assert not (root_path / "store.migrating").exists()
        assert rt.store.store_id == store_id
    finally:
        rt.close()


def test_read_daemon_config_valid_and_refusals(
    trusted_tmp: Path, os_: OsAdapters, monkeypatch: pytest.MonkeyPatch
) -> None:
    data_root = trusted_tmp / "data"
    cert_path = trusted_tmp / "tls" / "server.pem"
    key_path = trusted_tmp / "tls" / "server.key"

    def write_cfg(name: str, raw: bytes) -> Path:
        p = trusted_tmp / name
        os_.publisher.write_new(p, raw)
        os_.permissions.secure_file(p)
        return p

    valid_payload = {
        "version": 1,
        "data_root": str(data_root),
        "expected_store_id": "store-prod-01",
        "cert_path": str(cert_path),
        "key_path": str(key_path),
    }
    valid_file = write_cfg("daemon.json", json.dumps(valid_payload).encode("utf-8"))
    cfg = read_daemon_config(valid_file, os_)
    assert cfg == DaemonConfig(
        version=1,
        data_root=data_root,
        expected_store_id="store-prod-01",
        cert_path=cert_path,
        key_path=key_path,
    )

    # Relative config path refused.
    with pytest.raises(BrainError) as exc_rel:
        read_daemon_config(Path("relative/daemon.json"), os_)
    assert exc_rel.value.code in {ErrorCode.INVALID_INPUT, ErrorCode.UNSAFE_PATH}

    # Missing config file refused with NOT_FOUND.
    with pytest.raises(BrainError) as exc_missing:
        read_daemon_config(trusted_tmp / "missing.json", os_)
    assert exc_missing.value.code is ErrorCode.NOT_FOUND

    # Directory instead of file refused.
    cfg_dir = trusted_tmp / "dir.json"
    cfg_dir.mkdir()
    os_.permissions.secure_directory(cfg_dir)
    with pytest.raises(BrainError) as exc_dir:
        read_daemon_config(cfg_dir, os_)
    assert exc_dir.value.code is ErrorCode.INVALID_INPUT

    # Symlink / reparse point refused with UNSAFE_PATH.
    link_cfg = write_cfg("linked.json", json.dumps(valid_payload).encode("utf-8"))
    with monkeypatch.context() as mp:
        fake_link(mp, link_cfg)
        with pytest.raises(BrainError) as exc_link:
            read_daemon_config(link_cfg, os_)
        assert exc_link.value.code is ErrorCode.UNSAFE_PATH

    # Loose permissions refused with INSECURE_PERMISSIONS.
    loose_cfg = write_cfg("loose.json", json.dumps(valid_payload).encode("utf-8"))
    _loosen_file(loose_cfg)
    with pytest.raises(BrainError) as exc_loose:
        read_daemon_config(loose_cfg, os_)
    assert exc_loose.value.code is ErrorCode.INSECURE_PERMISSIONS

    # > 64 KiB file refused before parsing.
    oversize_cfg = write_cfg("oversize.json", b" " * 65_537)
    with pytest.raises(BrainError) as exc_big:
        read_daemon_config(oversize_cfg, os_)
    assert exc_big.value.code is ErrorCode.INVALID_INPUT

    # Duplicate JSON keys refused.
    dup_raw = (
        b'{"version":1,"version":1,"data_root":'
        + json.dumps(str(data_root)).encode("utf-8")
        + b',"expected_store_id":"store-1","cert_path":'
        + json.dumps(str(cert_path)).encode("utf-8")
        + b',"key_path":'
        + json.dumps(str(key_path)).encode("utf-8")
        + b"}"
    )
    dup_cfg = write_cfg("dup.json", dup_raw)
    with pytest.raises(BrainError) as exc_dup:
        read_daemon_config(dup_cfg, os_)
    assert exc_dup.value.code is ErrorCode.INVALID_INPUT

    # Boolean version, unsupported version, extra field, missing field, relative inner paths refused.
    bad_variants: list[tuple[str, dict[str, object], set[ErrorCode]]] = [
        ("bool-ver.json", {**valid_payload, "version": True}, {ErrorCode.INVALID_INPUT}),
        ("v2-ver.json", {**valid_payload, "version": 2}, {ErrorCode.INVALID_INPUT, ErrorCode.UNSUPPORTED_VERSION}),
        ("extra.json", {**valid_payload, "extra": "nope"}, {ErrorCode.INVALID_INPUT}),
        (
            "missing-key.json",
            {k: v for k, v in valid_payload.items() if k != "key_path"},
            {ErrorCode.INVALID_INPUT},
        ),
        (
            "rel-root.json",
            {**valid_payload, "data_root": "relative/root"},
            {ErrorCode.INVALID_INPUT, ErrorCode.UNSAFE_PATH},
        ),
        (
            "rel-cert.json",
            {**valid_payload, "cert_path": "server.pem"},
            {ErrorCode.INVALID_INPUT, ErrorCode.UNSAFE_PATH},
        ),
        (
            "rel-key.json",
            {**valid_payload, "key_path": "server.key"},
            {ErrorCode.INVALID_INPUT, ErrorCode.UNSAFE_PATH},
        ),
        ("bad-store.json", {**valid_payload, "expected_store_id": "bad id spaces"}, {ErrorCode.INVALID_INPUT}),
    ]
    for idx, (filename, payload, expected_codes) in enumerate(bad_variants):
        bad_file = write_cfg(f"{idx}-{filename}", json.dumps(payload).encode("utf-8"))
        with pytest.raises(BrainError) as exc_bad:
            read_daemon_config(bad_file, os_)
        assert exc_bad.value.code in expected_codes


def test_preadmission_scratch_resists_squatted_tmp_and_rejects_symlink_scratch_base(
    trusted_tmp: Path, os_: OsAdapters, monkeypatch: pytest.MonkeyPatch
) -> None:
    import tempfile as tempfile_mod

    # Build a v2 root with uncheckpointed WAL frames and no -shm so pre-admission scratch MUST run.
    wal_root = trusted_tmp / "wal-scratch-test"
    store_id = _make_v2_root(wal_root, os_)
    store_db = wal_root / "store" / "brain.db"
    wal_file = wal_root / "store" / "brain.db-wal"
    shm_file = wal_root / "store" / "brain.db-shm"
    conn = sqlite3.connect(store_db, isolation_level=None)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA wal_autocheckpoint=0")
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('noop_probe', '1')")
        conn.execute("COMMIT")
        raw_main = store_db.read_bytes()
        raw_wal = wal_file.read_bytes()
    finally:
        conn.close()
    store_db.write_bytes(raw_main)
    wal_file.write_bytes(raw_wal)
    if shm_file.exists():
        shm_file.unlink()
    os_.permissions.secure_file(store_db)
    os_.permissions.secure_file(wal_file)
    assert wal_file.stat().st_size > 32

    # 1. Default scratch_base=None ephemeral temp path resists pre-existing squatted/loose fixed names in temp dir.
    fake_tmp = trusted_tmp / "shared-tmp"
    fake_tmp.mkdir()
    os_.permissions.secure_directory(fake_tmp)
    squatted_names = ["superbrain-scratch"]
    if hasattr(os, "geteuid"):
        squatted_names.append(f"superbrain-scratch-{os.geteuid()}")
    for name in squatted_names:
        squatted = fake_tmp / name
        squatted.mkdir()
        _loosen_file(squatted)

    with monkeypatch.context() as mp:
        mp.delenv("LOCALAPPDATA", raising=False)
        mp.setattr(tempfile_mod, "gettempdir", lambda: str(fake_tmp))
        admitted = admit_existing_pair(wal_root, store_id, os_, purpose="serve", scratch_base=None)
        admitted.release()

    # Re-write uncheckpointed WAL without -shm for the next scratch_base checks.
    store_db.write_bytes(raw_main)
    wal_file.write_bytes(raw_wal)
    if shm_file.exists():
        shm_file.unlink()
    os_.permissions.secure_file(store_db)
    os_.permissions.secure_file(wal_file)

    # 2. Explicit scratch_base that is a symlink/reparse point is rejected with UNSAFE_PATH, leavingwal_root untouched.
    linked_scratch = trusted_tmp / "linked-scratch"
    linked_scratch.mkdir()
    os_.permissions.secure_directory(linked_scratch)
    snap_before_link = digest_tree(wal_root)
    with monkeypatch.context() as mp:
        fake_link(mp, linked_scratch)
        with pytest.raises(BrainError) as exc_link:
            admit_existing_pair(wal_root, store_id, os_, purpose="serve", scratch_base=linked_scratch)
        assert exc_link.value.code is ErrorCode.UNSAFE_PATH
    assert digest_tree(wal_root) == snap_before_link

    # 3. Race during creation of a missing scratch_base (no exist_ok=True): if another actor plants an insecure
    # directory right before mkdir runs, mkdir must NOT swallow FileExistsError + re-secure it; must refuse!
    raced_scratch = trusted_tmp / "raced-scratch"
    real_mkdir = Path.mkdir

    def racing_mkdir(self: Path, mode: int = 0o777, parents: bool = False, exist_ok: bool = False) -> None:
        if self == raced_scratch and not raced_scratch.exists():
            real_mkdir(raced_scratch, mode=0o700, parents=False, exist_ok=False)
            _loosen_file(raced_scratch)
        real_mkdir(self, mode=mode, parents=parents, exist_ok=exist_ok)

    with monkeypatch.context() as mp:
        mp.setattr(Path, "mkdir", racing_mkdir)
        with pytest.raises(BrainError) as exc_race:
            admit_existing_pair(wal_root, store_id, os_, purpose="serve", scratch_base=raced_scratch)
        assert exc_race.value.code is ErrorCode.INSECURE_PERMISSIONS
    assert digest_tree(wal_root) == snap_before_link
