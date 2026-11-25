"""Store and policy restore (spec 5.7): verify first, swap under the lease, reconcile only on the next open."""

import atexit
import os
import shutil
import sqlite3
import sys
import tempfile
import threading
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.policy import IntentKind
from superbrain.storage import backup as backup_module
from superbrain.storage import restore as restore_module
from superbrain.storage.backup import (
    BackupManifest,
    create_maintenance_backup,
    create_policy_backup,
    create_store_backup,
)
from superbrain.storage.cas import RetentionClass
from superbrain.storage.layout import DataRoot
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.restore import RestoreReport, restore_policy, restore_store
from superbrain.storage.retention import expire_due
from superbrain.storage.runtime import Runtime, open_runtime
from superbrain.storage.schema import read_schema_info
from superbrain.storage.sqlite import open_immutable
from superbrain.storage.store import Store
from superbrain.storage.swap import READY
from tests.storage.conftest import Env, maintenance_lease
from tests.storage.test_retention import hold_event
from tests.support.clock import FakeClock
from tests.support.crash import paused_child, run_child, run_until_crash
from tests.support.fs import corrupt_bytes, digest_data_root, digest_tree, file_identity
from tests.support.inc2_fixture import _cleanup_dir, open_cloned_runtime

BEFORE_ID = "0192f3a4-5b6c-7d8e-9f01-0000000000b1"
AFTER_ID = "0192f3a4-5b6c-7d8e-9f01-0000000000a1"
EVENT_ID = "0192f3a4-5b6c-7d8e-9f01-000000000e01"  # crash_child.EVENT_ID
D = digest_bytes(b"event payload")  # crash_child.EVENT_PAYLOAD

_RESTORE_SEED_LOCK = threading.Lock()
_RESTORE_SEED_BASE: Path | None = None
_RESTORE_SEED_CACHE: dict[str, tuple[Path, object]] = {}


def _restore_seed_base() -> Path:
    global _RESTORE_SEED_BASE
    if _RESTORE_SEED_BASE is not None and _RESTORE_SEED_BASE.is_dir():
        return _RESTORE_SEED_BASE
    if sys.platform == "win32":
        from superbrain.adapters.os.permissions import WindowsPermissionGuard

        base = Path(os.environ["LOCALAPPDATA"]) / "superbrain-tests" / f"restore-tpl-{uuid.uuid4()}"
        base.mkdir(parents=True, exist_ok=True)
        WindowsPermissionGuard().secure_directory(base)
    else:
        base = Path(tempfile.mkdtemp(prefix="sb2-restore-tpl-"))
        os.chmod(base, 0o700)
    atexit.register(_cleanup_dir, base)
    _RESTORE_SEED_BASE = base
    return base


def _is_fresh_seed_target(data_root: Path) -> bool:
    """Return True when ``data_root`` does not exist or is an empty real directory safe for template cloning."""
    if not os.path.lexists(data_root):
        return True
    return data_root.is_dir() and not os.path.islink(data_root) and not any(data_root.iterdir())


def _copy_seed_tree(src: Path, dst: Path) -> None:
    shutil.copytree(src, dst, dirs_exist_ok=True)
    if sys.platform != "win32":
        os.chmod(dst, 0o700)
        for cur_dir, dirnames, filenames in os.walk(dst):
            cur_path = Path(cur_dir)
            for dname in dirnames:
                os.chmod(cur_path / dname, 0o700)
            for fname in filenames:
                os.chmod(cur_path / fname, 0o600)


# --- helpers ---------------------------------------------------------------------------------------------------


def now() -> datetime:
    return datetime.now(UTC)


def run_ok(operation: str, data_root: Path) -> None:
    result = run_child(operation, data_root)
    assert result.returncode == 0, f"{operation} failed:\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"


def hold(store: Store, marker: str, holder_id: str) -> None:
    store.store_content(marker.encode(), "event", holder_id, RetentionClass.EVIDENCE, None)


def markers(store: Store) -> list[str]:
    """Which of the ``before``/``after`` contents the store still holds."""
    return [m for m in ("before", "after") if store.cas.holders(digest_bytes(m.encode()))]


def seed_before_backup_after(data_root: Path) -> None:
    """Hold ``before``, take a ``store`` backup, then hold ``after``: the backup knows only ``before``."""
    if not _is_fresh_seed_target(data_root):
        rt = open_runtime(data_root, os_adapters())
        try:
            hold(rt.store, "before", BEFORE_ID)
            create_store_backup(rt.store, rt.os_, now())
            hold(rt.store, "after", AFTER_ID)
        finally:
            rt.close()
        return
    with _RESTORE_SEED_LOCK:
        cached = _RESTORE_SEED_CACHE.get("before_after")
        if cached is None or not cached[0].is_dir():
            tpl = _restore_seed_base() / "before_after"
            rt = open_cloned_runtime(tpl, os_adapters(), role="restore-before-after")
            try:
                hold(rt.store, "before", BEFORE_ID)
                create_store_backup(rt.store, rt.os_, now())
                hold(rt.store, "after", AFTER_ID)
            finally:
                rt.close()
            _RESTORE_SEED_CACHE["before_after"] = (tpl, None)
            cached = (tpl, None)
    _copy_seed_tree(cached[0], data_root)


def latest_store_backup(root: DataRoot) -> Path:
    """The newest ``store``/``store_full`` backup: names are ``<kind>-<UTC stamp>-<UUIDv7>``."""
    found = [p for p in root.backups_dir.iterdir() if p.name.startswith(("store-", "store_full-"))]
    return max(found, key=lambda p: p.name.split("-", 1)[1])


def restore_latest(rt: Runtime) -> RestoreReport:
    """Close the runtime's store, restore the newest store backup under its lease, then close the runtime."""
    try:
        rt.store.close()
        return restore_store(rt.root, rt.lease, rt.os_, latest_store_backup(rt.root), rt.policy, now())
    finally:
        rt.close()


def restore_once(data_root: Path) -> RestoreReport:
    seed_before_backup_after(data_root)
    return restore_latest(open_runtime(data_root, os_adapters()))


def store_siblings(root: Path) -> list[str]:
    return sorted(name for name in os.listdir(root) if name.startswith("store."))


def every_original_dir_still_exists(data_root: Path) -> bool:
    """The data held before the interrupted restore is still on disk: the ``after`` blob exists in some ``store*``
    directory, and the one directory set aside (original or stage) holds a database and its blobs."""
    after = digest_bytes(b"after").removeprefix("sha256:")
    (aside,) = store_siblings(data_root)
    homes = [data_root / "store", data_root / aside]
    return any((home / "cas" / after[:2] / after).is_file() for home in homes) and all(
        (home / "brain.db").is_file() and (home / "cas").is_dir() for home in homes
    )


def count_entries(store: Store, kind: str) -> int:
    return sum(1 for entry in store.entries() if entry.kind == kind)


def seed_event_and_backup(data_root: Path, clock: FakeClock | None = None) -> str:
    """Hold an event payload (expiring after 90 days on ``clock``, else never), then take a ``store`` backup."""
    cache_key = "event_clock" if clock is not None else "event_realtime"
    default_start = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
    if not _is_fresh_seed_target(data_root) or (clock is not None and clock.now() != default_start):
        rt = open_runtime(data_root, os_adapters(clock=clock))
        try:
            if clock is not None:
                d = hold_event(rt.store, clock)
            else:
                d = rt.store.store_content(b"event payload", "event", EVENT_ID, RetentionClass.EVENT_PAYLOAD, None)
            create_store_backup(rt.store, rt.os_, rt.os_.clock.now())
            return d
        finally:
            rt.close()
    with _RESTORE_SEED_LOCK:
        cached = _RESTORE_SEED_CACHE.get(cache_key)
        if cached is None or not cached[0].is_dir():
            tpl = _restore_seed_base() / cache_key
            seed_clk = FakeClock(datetime(2026, 10, 30, 12, 0, tzinfo=UTC)) if clock is not None else None
            rt = open_cloned_runtime(tpl, os_adapters(clock=seed_clk), role=f"restore-{cache_key}")
            try:
                if seed_clk is not None:
                    d = hold_event(rt.store, seed_clk)
                else:
                    d = rt.store.store_content(b"event payload", "event", EVENT_ID, RetentionClass.EVENT_PAYLOAD, None)
                create_store_backup(rt.store, rt.os_, rt.os_.clock.now())
            finally:
                rt.close()
            _RESTORE_SEED_CACHE[cache_key] = (tpl, d)
            cached = (tpl, d)
    _copy_seed_tree(cached[0], data_root)
    return str(cached[1])


def store_id_of(data_root: Path) -> str:
    info = read_schema_info(data_root / "store" / "brain.db")
    assert info is not None
    return info.store_id


def generation_of(data_root: Path) -> int:
    rt = open_runtime(data_root, os_adapters())
    try:
        return rt.policy.trust_generation()
    finally:
        rt.close()


def policy_backup_of(data_root: Path) -> Path:
    rt = (
        open_cloned_runtime(data_root, os_adapters(), role="restore-polbak")
        if _is_fresh_seed_target(data_root)
        else open_runtime(data_root, os_adapters())
    )
    try:
        return create_policy_backup(rt.policy, rt.os_, now())
    finally:
        rt.close()


def seed_policy_backup(data_root: Path) -> int:
    """A runtime whose trust generation was raised to 5, and a ``policy`` backup of it; returns that generation."""
    if not _is_fresh_seed_target(data_root):
        rt = open_runtime(data_root, os_adapters())
        rt.lease.raise_trust_hwm(4)
        rt.close()
        rt = open_runtime(data_root, os_adapters())  # the policy store is aligned to hwm + 1
        try:
            create_policy_backup(rt.policy, rt.os_, now())
            return rt.policy.trust_generation()
        finally:
            rt.close()
    with _RESTORE_SEED_LOCK:
        cached = _RESTORE_SEED_CACHE.get("policy_gen5")
        if cached is None or not cached[0].is_dir():
            tpl = _restore_seed_base() / "policy_gen5"
            rt = open_cloned_runtime(tpl, os_adapters(), role="restore-gen5")
            rt.lease.raise_trust_hwm(4)
            rt.close()
            rt = open_runtime(tpl, os_adapters())
            try:
                create_policy_backup(rt.policy, rt.os_, now())
                gen = rt.policy.trust_generation()
            finally:
                rt.close()
            _RESTORE_SEED_CACHE["policy_gen5"] = (tpl, gen)
            cached = (tpl, gen)
    _copy_seed_tree(cached[0], data_root)
    gen_val = cached[1]
    assert isinstance(gen_val, int)
    return gen_val


def set_meta_versions(path: Path, version: int) -> None:
    db = sqlite3.connect(path, isolation_level=None)
    try:
        db.execute("UPDATE meta SET value = ? WHERE key IN ('schema_version', 'min_reader_version')", (str(version),))
    finally:
        db.close()


def full_backup_with_schema(data_root: Path, *, schema_version: int) -> Path:
    """A ``store_full`` backup of a store whose schema is ``schema_version``; the live store keeps version 1."""
    open_cloned_runtime(data_root, os_adapters(), role="restore-schema").close()
    with maintenance_lease(data_root) as (root, lease):
        set_meta_versions(root.store_db, schema_version)
        path = create_maintenance_backup(root, lease, os_adapters(), target="store", now=now())
        set_meta_versions(root.store_db, 1)
    return path


@pytest.fixture
def other_backup(trusted_tmp: Path) -> Path:
    """A valid ``store`` backup of another data root (another store id)."""
    rt = open_cloned_runtime(trusted_tmp / "other", os_adapters(), role="restore-other")
    try:
        hold(rt.store, "before", BEFORE_ID)
        return create_store_backup(rt.store, rt.os_, now())
    finally:
        rt.close()


# --- store restore: crash and concurrency ------------------------------------------------------------------------


@pytest.mark.parametrize("point", ["restoring.store.after_stage", "restoring.store.between_renames"])
def test_startup_of_second_process_never_touches_an_inflight_restore(trusted_tmp: Path, point: str) -> None:  # I1-01
    seed_before_backup_after(trusted_tmp)
    with paused_child("restore_from_latest", point, trusted_tmp) as child:
        before = digest_data_root(trusted_tmp)
        assert run_child("open_runtime", trusted_tmp).error_code == "writer_held"
        assert digest_data_root(trusted_tmp) == before
    assert child.returncode == 0
    rt = open_runtime(trusted_tmp, os_adapters())
    try:
        assert markers(rt.store) == ["before"]  # the resumed restore finished
    finally:
        rt.close()


@pytest.mark.parametrize(
    ("point", "expected"),
    [
        ("restoring.store.after_stage", ["before", "after"]),
        ("restoring.store.between_renames", ["before"]),
    ],
)
def test_interrupted_restore_recovers_under_lease(trusted_tmp: Path, point: str, expected: list[str]) -> None:
    seed_before_backup_after(trusted_tmp)
    run_until_crash("restore_from_latest", point, trusted_tmp)
    rt = open_runtime(trusted_tmp, os_adapters())
    try:
        assert markers(rt.store) == expected and every_original_dir_still_exists(trusted_tmp)
    finally:
        rt.close()


def test_pending_intent_survives_abandoned_restore_stage(trusted_tmp: Path) -> None:  # I1-03
    seed_event_and_backup(trusted_tmp)
    run_until_crash("tombstone_event", "policy.after_intent_commit", trusted_tmp)  # recorded, not reconciled
    run_until_crash("restore_from_latest", "restoring.store.after_stage", trusted_tmp)
    rt = open_runtime(trusted_tmp, os_adapters())  # the stage is set aside, the original store reconciled
    try:
        assert rt.store.cas.holders(D) == [] and count_entries(rt.store, "policy.tombstone") == 1
        assert [n.split("-")[0] for n in store_siblings(trusted_tmp)] == ["store.restoring.abandoned"]
    finally:
        rt.close()


# --- store restore: behaviour ------------------------------------------------------------------------------------


def test_restore_publishes_the_backup_and_keeps_the_old_store(trusted_tmp: Path) -> None:
    seed_before_backup_after(trusted_tmp)
    rt = open_runtime(trusted_tmp, os_adapters())
    backup = latest_store_backup(rt.root)
    epoch = rt.lease.epoch
    report = restore_latest(rt)
    assert report.restored_from == backup and report.trust_generation is None and report.new_epoch == epoch + 1
    assert report.replaced_dir.name.startswith("store.replaced-") and (report.replaced_dir / "brain.db").is_file()
    store_dir = trusted_tmp / "store"
    assert (store_dir / "brain.db").read_bytes() == (backup / "brain.db").read_bytes()  # not opened yet
    assert digest_tree(store_dir / "cas") == digest_tree(backup / "cas")
    assert (store_dir / "staging").is_dir() and list((store_dir / "staging").iterdir()) == []
    assert (store_dir / READY).is_file() and os_adapters().permissions.problems(store_dir) == []
    rt = open_runtime(trusted_tmp, os_adapters())
    try:
        assert markers(rt.store) == ["before"] and rt.store.db_integrity() == "ok"
    finally:
        rt.close()


def test_restore_reapplies_newer_tombstone_and_quarantine(trusted_tmp: Path, clock: FakeClock) -> None:  # scenario 21
    d = seed_event_and_backup(trusted_tmp, clock)
    rt = open_runtime(trusted_tmp, os_adapters(clock=clock))
    rt.policy.record_intent(IntentKind.QUARANTINE, {"digest": d})
    expire_due(rt.store, rt.policy, clock.now() + timedelta(days=91))
    restore_latest(rt)
    rt = open_runtime(trusted_tmp, os_adapters(clock=clock))
    try:
        assert rt.store.cas.holders(d) == []
        assert count_entries(rt.store, "policy.tombstone") == 1 and count_entries(rt.store, "policy.quarantine") == 1
        with pytest.raises(BrainError) as e:
            rt.store.cas.read(d)
        assert e.value.code == ErrorCode.QUARANTINED
    finally:
        rt.close()


def test_restore_keeps_lock_object_identity(trusted_tmp: Path) -> None:
    open_cloned_runtime(trusted_tmp, os_adapters(), role="restore-lock").close()
    lock = trusted_tmp / "writer.lock"
    before = file_identity(lock)
    restore_once(trusted_tmp)
    assert file_identity(lock) == before


def test_restore_with_store_open_is_refused(env: Env, clock: FakeClock) -> None:
    path = create_store_backup(env.store, env.os_, clock.now())
    before = digest_tree(env.root.store_dir)
    with pytest.raises(BrainError) as e:
        restore_store(env.root, env.lease, env.os_, path, env.policy, clock.now())
    assert e.value.code == ErrorCode.STORE_BUSY
    assert store_siblings(env.root.root) == [] and digest_tree(env.root.store_dir) == before


def test_unverifiable_full_backup_is_not_restored(trusted_tmp: Path) -> None:  # R2-01
    path = full_backup_with_schema(trusted_tmp, schema_version=99)
    with maintenance_lease(trusted_tmp) as (root, lease):
        before = digest_tree(root.store_dir)
        policy = PolicyStore.open(root, lease, os_adapters())
        try:
            with pytest.raises(BrainError) as e:
                restore_store(root, lease, os_adapters(), path, policy, now())
        finally:
            policy.close()
        assert e.value.code == ErrorCode.UNSUPPORTED_VERSION
        assert store_siblings(root.root) == [] and digest_tree(root.store_dir) == before


def test_restore_of_wrong_store_is_refused_before_touching_store_dir(trusted_tmp: Path, other_backup: Path) -> None:
    open_cloned_runtime(trusted_tmp / "r", os_adapters(), role="restore-wrong").close()
    with maintenance_lease(trusted_tmp / "r") as (root, lease):
        before = digest_tree(root.store_dir)
        policy = PolicyStore.open(root, lease, os_adapters())
        try:
            with pytest.raises(BrainError) as e:
                restore_store(root, lease, os_adapters(), other_backup, policy, now())
        finally:
            policy.close()
        assert e.value.code == ErrorCode.INTEGRITY_FAILURE and "store_id" in e.value.message
        assert store_siblings(root.root) == [] and digest_tree(root.store_dir) == before


def test_backup_changed_after_verification_is_not_published(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seed_before_backup_after(trusted_tmp)
    real_verify = backup_module.verify_backup

    def verify_then_damage(path: Path, **kwargs: object) -> BackupManifest:
        manifest = real_verify(path, **kwargs)  # type: ignore[arg-type]
        (blob,) = manifest.blobs
        hex_ = blob.removeprefix("sha256:")
        corrupt_bytes(path / "cas" / hex_[:2] / hex_, offsets=[0])
        return manifest

    monkeypatch.setattr(restore_module, "verify_backup", verify_then_damage)
    rt = open_runtime(trusted_tmp, os_adapters())
    with pytest.raises(BrainError) as e:
        restore_latest(rt)
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE
    assert [n.split("-")[0] for n in store_siblings(trusted_tmp)] == ["store.restoring.abandoned"]
    rt = open_runtime(trusted_tmp, os_adapters())
    try:
        assert markers(rt.store) == ["before", "after"]
    finally:
        rt.close()


# --- policy restore ----------------------------------------------------------------------------------------------


def test_policy_restore_with_store_still_open_is_refused(env: Env, clock: FakeClock) -> None:  # R2-02
    path = create_policy_backup(env.policy, env.os_, clock.now())
    env.policy.close()  # the store stays open
    before = digest_tree(env.root.policy_dir)
    with pytest.raises(BrainError) as e:
        restore_policy(env.root, env.lease, env.os_, path, store_id=env.store.store_id, now=clock.now())
    assert e.value.code == ErrorCode.STORE_BUSY and digest_tree(env.root.policy_dir) == before
    assert not any(name.startswith("policy.") for name in os.listdir(env.root.root))


def test_policy_restore_with_policy_still_open_is_refused(env: Env, clock: FakeClock) -> None:
    path = create_policy_backup(env.policy, env.os_, clock.now())
    store_id = env.store.store_id
    env.store.close()  # the policy store stays open
    with pytest.raises(BrainError) as e:
        restore_policy(env.root, env.lease, env.os_, path, store_id=store_id, now=clock.now())
    assert e.value.code == ErrorCode.STORE_BUSY


def test_after_policy_restore_new_runtime_binds_new_policy(trusted_tmp: Path, clock: FakeClock) -> None:
    g0 = generation_of(trusted_tmp)
    path = policy_backup_of(trusted_tmp)
    with maintenance_lease(trusted_tmp) as (root, lease):
        report = restore_policy(root, lease, os_adapters(), path, store_id=store_id_of(trusted_tmp), now=clock.now())
        assert lease.state().trust_generation_hwm == report.trust_generation == g0 + 1
        assert report.new_epoch == lease.epoch and report.restored_from == path
        assert report.replaced_dir.name.startswith("policy.replaced-") and (report.replaced_dir / "policy.db").is_file()
    rt = open_runtime(trusted_tmp, os_adapters())
    try:
        assert rt.policy.trust_generation() == g0 + 1 > g0 and rt.store.reconcile_policy() == 0
    finally:
        rt.close()


def test_policy_restore_of_another_store_is_refused(trusted_tmp: Path, clock: FakeClock) -> None:
    path = policy_backup_of(trusted_tmp / "other")
    open_cloned_runtime(trusted_tmp / "r", os_adapters(), role="restore-other-pol").close()
    with maintenance_lease(trusted_tmp / "r") as (root, lease):
        before = digest_tree(root.policy_dir)
        with pytest.raises(BrainError) as e:
            restore_policy(root, lease, os_adapters(), path, store_id=store_id_of(root.root), now=clock.now())
        assert e.value.code == ErrorCode.INTEGRITY_FAILURE and digest_tree(root.policy_dir) == before


@pytest.mark.parametrize(
    "point",
    [
        "restoring.policy.after_generation_persist",
        "restoring.policy.after_stage",
        "restoring.policy.between_renames",
        "restoring.policy.before_hwm_update",
    ],
)
def test_policy_restore_crash_never_lowers_generation(trusted_tmp: Path, point: str) -> None:  # I1-14, scenario 32
    g0 = seed_policy_backup(trusted_tmp)
    assert g0 == 5
    run_until_crash("restore_policy_from_latest", point, trusted_tmp)
    rt = open_runtime(trusted_tmp, os_adapters())
    try:
        g1 = rt.policy.trust_generation()
        published = point in ("restoring.policy.between_renames", "restoring.policy.before_hwm_update")
        assert (g1 > g0) == published and g1 >= g0 and rt.lease.state().trust_generation_hwm == g1
    finally:
        rt.close()


def generation_in(policy_db: Path) -> int:
    db = open_immutable(policy_db)
    try:
        (generation,) = db.execute("SELECT generation FROM trust WHERE id = 1").fetchone()
    finally:
        db.close()
    assert type(generation) is int
    return generation


@pytest.mark.parametrize("point", ["restoring.policy.between_renames", "restoring.policy.before_hwm_update"])
def test_restore_after_a_crash_before_the_hwm_update_never_reuses_a_generation(trusted_tmp: Path, point: str) -> None:
    """The published policy store is ahead of the lock's mark; a restore under a lease that never opened it (a
    maintenance lease) must still go above it."""
    seed_policy_backup(trusted_tmp)
    run_until_crash("restore_policy_from_latest", point, trusted_tmp)
    path = max(p for p in (trusted_tmp / "backups").iterdir() if p.name.startswith("policy-"))
    with maintenance_lease(trusted_tmp) as (root, lease):
        live = generation_in(root.policy_db)
        assert live > lease.state().trust_generation_hwm  # the crash left the mark behind
        report = restore_policy(root, lease, os_adapters(), path, store_id=store_id_of(trusted_tmp), now=now())
    assert generation_in(report.replaced_dir / "policy.db") == live
    assert report.trust_generation is not None and report.trust_generation > live
    assert generation_of(trusted_tmp) == report.trust_generation


def test_unreadable_live_policy_store_fails_closed(trusted_tmp: Path) -> None:
    path = policy_backup_of(trusted_tmp)
    with maintenance_lease(trusted_tmp) as (root, lease):
        root.policy_db.write_bytes(b"not a database")
        for companion in ("policy.db-wal", "policy.db-shm"):
            (root.policy_dir / companion).unlink(missing_ok=True)
        before = digest_tree(root.policy_dir)
        with pytest.raises(BrainError) as e:
            restore_policy(root, lease, os_adapters(), path, store_id=store_id_of(trusted_tmp), now=now())
        assert e.value.code == ErrorCode.INTEGRITY_FAILURE and digest_tree(root.policy_dir) == before
        assert not any(name.startswith("policy.") for name in os.listdir(root.root))


def test_successive_policy_restores_strictly_increase_generation(trusted_tmp: Path) -> None:
    g0 = seed_policy_backup(trusted_tmp)
    run_ok("restore_policy_from_latest", trusted_tmp)
    g1 = generation_of(trusted_tmp)
    run_ok("restore_policy_from_latest", trusted_tmp)  # the same backup again
    g2 = generation_of(trusted_tmp)
    assert g0 < g1 < g2
