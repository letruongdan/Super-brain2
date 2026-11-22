"""I4-1 independent oracle tests for read-only ``brain doctor`` snapshot, probes, bounds & privacy.

Requirement sources:
- Spec rev 22 §13, §14.2, §20 cases 13, 14, 15, 21, 24, 26, 28
- Frozen contract ``i4-0-contract.md`` (§4.2, §4.3, §5)
"""

from __future__ import annotations

import base64
import contextlib
import errno
import hashlib
import http.client
import json
import os
import shutil
import socket
import sqlite3
import struct
import sys
import time
import urllib.request
from collections import Counter
from collections.abc import Iterator, Mapping
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.durable import detect_fs, publisher_for
from superbrain.adapters.os.locks import OsLockFactory
from superbrain.application.doctor import DoctorReport, format_doctor_text, inspect_doctor_snapshot
from superbrain.composition.doctor_entry import run_doctor
from superbrain.composition.init_entry import InitReport, InitRequest, init_store
from superbrain.core._kernel_approval import ApprovalChannel, SignerEnrollment
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.ports.os import (
    DurabilityReport,
    FsInfo,
    LockFactory,
    LockHandle,
    LockProbePort,
    NoReplacePublisher,
    OsAdapters,
)
from superbrain.ports.policy import IntentKind
from superbrain.storage._doctor_reader import StorageDoctorReader, read_doctor_snapshot
from superbrain.storage.backup import create_policy_backup, create_store_backup
from superbrain.storage.cas import blob_path
from superbrain.storage.kinds import RetentionClass
from superbrain.storage.layout import DataRoot
from superbrain.storage.writer import acquire_writer
from tests.support.clock import FakeClock
from tests.support.fs import digest_tree
from tests.support.inc2_fixture import reopen_kernel_job_runtime
from tests.support.inc2_transport import FakeMonotonicClock

OWNER = "dan"
MACHINE = "i4-1-box"

ALL_13_GROUPS = frozenset(
    {
        "daemon",
        "identity",
        "storage",
        "permissions",
        "privacy",
        "retention",
        "harness",
        "capture",
        "jev",
        "index",
        "lessons",
        "skill",
    }
)

ALL_7_CANARY_CHANNELS = frozenset(
    {
        "hook",
        "direct_tool",
        "nested_object",
        "error_log",
        "trace",
        "outbox",
        "derived_content",
    }
)


def _ssh_enrollment(tag: str = "i4") -> SignerEnrollment:
    raw = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", len(raw)) + raw
    return SignerEnrollment(
        owner_id=OWNER,
        channel=ApprovalChannel.SSH_KEY,
        public_key="ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + f" {tag}@devbox",
    )


def _local_durable_fs() -> str:
    if sys.platform == "win32":
        return "NTFS"
    if sys.platform == "darwin":
        return "apfs"
    return "ext4"


def _make_os(clock: FakeClock, *, durable: bool = True, real_monotonic: bool = False) -> OsAdapters:
    mono = os_adapters().monotonic if real_monotonic else FakeMonotonicClock(1_000_000_000)
    fs = FsInfo(_local_durable_fs(), False) if durable else FsInfo("nfs", True)
    base = os_adapters(clock=clock, monotonic=mono)
    return replace(base, publisher=publisher_for(sys.platform, fs_info=lambda _p: fs))


def _init_root(
    base: Path, clock: FakeClock, *, tag: str = "i4", durable: bool = True
) -> tuple[InitReport, Path, Path, Path, OsAdapters]:
    os_ = _make_os(clock, durable=durable)
    cfg_dir, data_root, checkout = base / "cfg", base / "data", base / "checkout"
    for d in (cfg_dir, checkout):
        d.mkdir(parents=True, exist_ok=True)
        os_.permissions.secure_directory(d)
    rep = init_store(
        InitRequest(
            data_root=data_root,
            config_dir=cfg_dir,
            owner_id=OWNER,
            machine_id=MACHINE,
            signer=_ssh_enrollment(tag),
        ),
        os_,
    )
    return rep, data_root, cfg_dir, checkout, os_


def _forbid_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def _deny(*_args: object, **_kwargs: object) -> Any:
        raise AssertionError("default doctor must never perform network calls")

    monkeypatch.setattr(socket, "create_connection", _deny)
    monkeypatch.setattr(socket.socket, "connect", _deny)
    monkeypatch.setattr(urllib.request, "urlopen", _deny)
    monkeypatch.setattr(http.client.HTTPConnection, "connect", _deny)
    monkeypatch.setattr(http.client.HTTPSConnection, "connect", _deny)


def _grant_wide_access(path: Path) -> None:
    if sys.platform == "win32":
        import ntsecuritycon

        from tests.support.winacl import grant

        grant(path, "S-1-1-0", ntsecuritycon.FILE_GENERIC_READ)
    else:
        os.chmod(path, 0o755 if path.is_dir() else 0o644)


def _make_dir_link(link: Path, target: Path) -> None:
    if sys.platform == "win32":
        import _winapi

        _winapi.CreateJunction(str(target), str(link))
    else:
        link.symlink_to(target, target_is_directory=True)


@contextlib.contextmanager
def _deny_read_access(path: Path, os_: OsAdapters, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    if sys.platform == "win32":
        import ntsecuritycon
        import win32api
        import win32con
        import win32security

        token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
        try:
            user_sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
        finally:
            win32api.CloseHandle(token)
        dacl = win32security.ACL()
        dacl.AddAccessDeniedAceEx(win32security.ACL_REVISION_DS, 0, ntsecuritycon.FILE_READ_DATA, user_sid)
        dacl.AddAccessAllowedAceEx(
            win32security.ACL_REVISION_DS,
            0,
            ntsecuritycon.WRITE_DAC | ntsecuritycon.WRITE_OWNER | ntsecuritycon.DELETE | ntsecuritycon.READ_CONTROL,
            user_sid,
        )
        win32security.SetNamedSecurityInfo(
            os.fspath(path),
            win32security.SE_FILE_OBJECT,
            win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            dacl,
            None,
        )
        try:
            yield
        finally:
            os_.permissions.secure_file(path)
    elif os.geteuid() != 0:
        os.chmod(path, 0o000)
        try:
            yield
        finally:
            os_.permissions.secure_file(path)
    else:
        orig_open = os.open

        def _eacces(p: os.PathLike[str] | str, flags: int, mode: int = 0o777) -> int:
            if os.fspath(p) == os.fspath(path):
                raise PermissionError(errno.EACCES, "Permission denied", os.fspath(p))
            return orig_open(p, flags, mode)

        monkeypatch.setattr(os, "open", _eacces)
        yield


def _leave_uncheckpointed_runtime_wal(
    data_root: Path,
    store_id: str,
    os_: OsAdapters,
    scratch: Path,
    *,
    blob_count: int = 2,
    include_policy_wal: bool = False,
) -> None:
    """Persist real store/policy transactions into uncheckpointed ``-wal`` files with ``-shm`` removed."""
    root = DataRoot.at(data_root)
    scratch.mkdir(parents=True, exist_ok=True)
    rt = reopen_kernel_job_runtime(data_root, store_id, os_)
    try:
        rt.store._db.execute("PRAGMA wal_autocheckpoint = 0")
        for i in range(blob_count):
            rt.store.store_content(
                (f"wal-frame-payload-{i:03d}-" + "z" * 40).encode(),
                "event",
                new_id(),
                RetentionClass.DURABLE,
                None,
            )
        store_wal = root.store_db.with_name("brain.db-wal")
        assert store_wal.is_file() and store_wal.stat().st_size > 32
        shutil.copy2(root.store_db, scratch / "brain.db")
        shutil.copy2(store_wal, scratch / "brain.db-wal")

        if include_policy_wal:
            rt.policy._db.execute("PRAGMA wal_autocheckpoint = 0")
            rt.policy._db.execute("BEGIN IMMEDIATE")
            rt.policy._db.execute("INSERT OR IGNORE INTO meta (key, value) VALUES ('doctor_wal_probe', '1')")
            rt.policy._db.execute("COMMIT")
            pol_wal = root.policy_db.with_name("policy.db-wal")
            assert pol_wal.is_file() and pol_wal.stat().st_size > 32
            shutil.copy2(root.policy_db, scratch / "policy.db")
            shutil.copy2(pol_wal, scratch / "policy.db-wal")
    finally:
        rt.close()

    targets = [(root.store_db, scratch / "brain.db")]
    if include_policy_wal:
        targets.append((root.policy_db, scratch / "policy.db"))
    for db_dest, db_src in targets:
        wal_dest = db_dest.with_name(db_dest.name + "-wal")
        shm_dest = db_dest.with_name(db_dest.name + "-shm")
        wal_src = db_src.with_name(db_src.name + "-wal")
        for p in (db_dest, wal_dest, shm_dest):
            if p.exists():
                p.unlink()
        shutil.copy2(db_src, db_dest)
        shutil.copy2(wal_src, wal_dest)
        os_.permissions.secure_file(db_dest)
        os_.permissions.secure_file(wal_dest)


def _snapshot_tree_and_mtimes(root: Path) -> tuple[dict[str, tuple[str, int]], dict[str, int]]:
    files: dict[str, tuple[str, int]] = {}
    dirs: dict[str, int] = {".": os.lstat(root).st_mtime_ns}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        prefix = "" if rel_dir == "." else f"{rel_dir}/"
        for dname in sorted(dirnames):
            full_d = Path(dirpath) / dname
            dirs[f"{prefix}{dname}"] = os.lstat(full_d).st_mtime_ns
        for fname in sorted(filenames):
            full_f = Path(dirpath) / fname
            st = os.lstat(full_f)
            with open(full_f, "rb") as handle:
                if fname == "writer.lock":
                    handle.seek(1)
                digest = hashlib.sha256(handle.read()).hexdigest()
            files[f"{prefix}{fname}"] = (digest, st.st_mtime_ns)
    return files, dirs


def _checks_in(report: DoctorReport, group: str) -> list[Any]:
    return [c for c in report.checks if getattr(c, "group", None) == group]


def _check_by(report: DoctorReport, group: str, name: str) -> Any:
    matches = [c for c in report.checks if getattr(c, "group", None) == group and c.name in (name, f"{group}.{name}")]
    assert matches, f"missing check {group}.{name} in {[(getattr(c, 'group', None), c.name) for c in report.checks]}"
    return matches[0]


class _SpyNoAcquireLocks(LockFactory, LockProbePort):
    def __init__(self, inner: LockProbePort) -> None:
        self._inner = inner
        self.probe_calls = 0

    def acquire(self, path: Path) -> LockHandle:
        raise AssertionError(f"read-only doctor must never acquire exclusive writer lock on {path}")

    def probe_held(self, path: Path) -> bool:
        self.probe_calls += 1
        return bool(self._inner.probe_held(path))


class _ReadOnlyPublisherProxy(NoReplacePublisher):
    def __init__(self, inner: Any, protected_roots: tuple[Path, ...]) -> None:
        self._inner = inner
        self._protected = tuple(Path(os.path.abspath(r)) for r in protected_roots)

    def _assert_unprotected(self, path: Path, op: str) -> None:
        abs_p = Path(os.path.abspath(path))
        for root in self._protected:
            if abs_p == root or root in abs_p.parents:
                raise AssertionError(f"read-only doctor called mutating {op} on protected path {path}")

    def write_new(self, path: Path, data: bytes) -> None:
        self._assert_unprotected(path, "write_new")
        self._inner.write_new(path, data)

    def publish(self, staging: Path, final: Path) -> None:
        self._assert_unprotected(staging, "publish(staging)")
        self._assert_unprotected(final, "publish(final)")
        self._inner.publish(staging, final)

    def publish_no_replace(self, staging: Path, final: Path) -> None:
        self._assert_unprotected(staging, "publish_no_replace(staging)")
        self._assert_unprotected(final, "publish_no_replace(final)")
        self._inner.publish_no_replace(staging, final)

    def rename_dir(self, src: Path, dst: Path) -> None:
        self._assert_unprotected(src, "rename_dir(src)")
        self._assert_unprotected(dst, "rename_dir(dst)")
        self._inner.rename_dir(src, dst)

    def sync_directory(self, directory: Path) -> None:
        self._assert_unprotected(directory, "sync_directory")
        self._inner.sync_directory(directory)

    def flush_file(self, path: Path) -> None:
        self._assert_unprotected(path, "flush_file")
        self._inner.flush_file(path)

    def durability(self, directory: Path, env: Mapping[str, str]) -> DurabilityReport:
        res: DurabilityReport = self._inner.durability(directory, env)
        return res

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def test_doctor_snapshot_groups_and_durability_tier(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify §13 groups, PASS/WARN/FAIL reasons, durability tier, WAL/backup/disk/capture/retention & lock probe."""
    _forbid_network(monkeypatch)
    clock = FakeClock(datetime(2026, 11, 21, 12, 0, tzinfo=UTC))
    rep, data_root, _cfg_dir, checkout, os_ = _init_root(trusted_tmp / "groups", clock, tag="g1", durable=True)
    root = DataRoot.at(data_root)

    # 1) Clean baseline report must cover all 12 §13 groups with PASS/WARN/FAIL statuses & distinct reason codes.
    report = run_doctor(rep.daemon_config_path, checkout_root=checkout, os_=os_)
    assert report.checks, "expected diagnostic check items"
    for item in report.checks:
        assert item.status in {"PASS", "WARN", "FAIL"}, f"unexpected status {item.status!r} on {item}"
        assert isinstance(item.group, str) and item.group
        assert isinstance(item.name, str) and item.name
        assert isinstance(item.reason, str) and item.reason
        assert isinstance(item.detail, str) and item.detail
        d = item.to_dict()
        assert {"group", "name", "status", "reason", "detail", "remediation"} <= set(d)

    assert ALL_13_GROUPS <= {c.group for c in report.checks}
    assert report.overall_status == "pass"

    lock_chk = _check_by(report, "daemon", "writer_lock")
    assert lock_chk.status == "PASS"
    schema_chk = _check_by(report, "daemon", "schema_version")
    assert schema_chk.status == "PASS" and schema_chk.reason == "ok"

    cap_items = _checks_in(report, "capture")
    assert cap_items and all(c.status == "PASS" and c.reason == "sp2_not_wired" for c in cap_items)
    for grp in ("index", "lessons", "skill"):
        grp_items = _checks_in(report, grp)
        assert grp_items and all(c.status == "PASS" and c.reason == "deferred_sp_scope" for c in grp_items)
    assert any(c.status == "PASS" and c.reason == "none_recorded" for c in _checks_in(report, "storage"))
    assert any(c.status == "PASS" and "power_loss_durable" in c.detail for c in _checks_in(report, "storage"))
    assert all(c.status == "PASS" for c in _checks_in(report, "jev"))
    assert all(c.status == "PASS" for c in _checks_in(report, "retention"))

    # Default doctor must record 0 ProviderInvocation rows and 0 network calls.
    ro = sqlite3.connect(f"file:{root.store_db}?mode=ro", uri=True)
    pol_ro = sqlite3.connect(f"file:{root.policy_db}?mode=ro", uri=True)
    try:
        assert ro.execute("SELECT COUNT(*) FROM p_provider_invocations_state").fetchone()[0] == 0
        assert pol_ro.execute("SELECT COUNT(*) FROM accounting_invocations").fetchone()[0] == 0
    finally:
        ro.close()
        pol_ro.close()

    # 2) Non-exclusive OsLockFactory.probe_held: unheld vs held vs missing vs link vs PermissionError.
    from superbrain.application.doctor import KernelPrivacyScanner
    from superbrain.ports.doctor import CaptureDoctorProbePort, CaptureDoctorProbeResult, DoctorScanLimits

    lock_factory = OsLockFactory()
    assert lock_factory.probe_held(root.lock_path) is False
    with acquire_writer(root, os_):
        assert lock_factory.probe_held(root.lock_path) is True
        spy_locks = _SpyNoAcquireLocks(lock_factory)
        snap_held = read_doctor_snapshot(
            data_root, replace(os_, locks=spy_locks), privacy_scanner=KernelPrivacyScanner()
        )
        rep_held = inspect_doctor_snapshot(snap_held)
        assert spy_locks.probe_calls >= 1
        assert _check_by(rep_held, "daemon", "writer_lock").status == "PASS"
    assert lock_factory.probe_held(root.lock_path) is False

    # Missing writer.lock -> probe_held False, doctor FAIL.
    assert lock_factory.probe_held(trusted_tmp / "absent.lock") is False
    no_lock_dir = trusted_tmp / "no-lock-copy"
    shutil.copytree(data_root, no_lock_dir)
    os_.permissions.secure_directory(no_lock_dir)
    (no_lock_dir / "writer.lock").unlink()
    rep_no_lock = inspect_doctor_snapshot(
        read_doctor_snapshot(no_lock_dir, os_, privacy_scanner=KernelPrivacyScanner())
    )
    assert _check_by(rep_no_lock, "daemon", "writer_lock").status == "FAIL"
    assert rep_no_lock.overall_status == "fail"

    # Link refusal -> UNSAFE_PATH.
    link_parent_real = trusted_tmp / "real-lock-dir"
    link_parent_real.mkdir()
    os_.permissions.secure_directory(link_parent_real)
    (link_parent_real / "writer.lock").write_bytes(b"")
    link_parent = trusted_tmp / "link-lock-dir"
    _make_dir_link(link_parent, link_parent_real)
    with pytest.raises(BrainError) as link_err:
        lock_factory.probe_held(link_parent / "writer.lock")
    assert link_err.value.code is ErrorCode.UNSAFE_PATH

    # PermissionError / EACCES on open -> INSECURE_PERMISSIONS / IO_ERROR (never returns True!).
    denied_lock = link_parent_real / "denied.lock"
    denied_lock.write_bytes(b"")
    os_.permissions.secure_file(denied_lock)
    with _deny_read_access(denied_lock, os_, monkeypatch):
        with pytest.raises(BrainError) as perm_err:
            lock_factory.probe_held(denied_lock)
        assert perm_err.value.code in {ErrorCode.INSECURE_PERMISSIONS, ErrorCode.IO_ERROR}

    # 3) Degraded durability tier (process_crash_durable -> WARN reason="durability_degraded").
    os_degraded = _make_os(clock, durable=False)
    rep_deg = run_doctor(rep.daemon_config_path, checkout_root=checkout, os_=os_degraded)
    assert rep_deg.overall_status == "warn"
    assert any(
        c.status == "WARN" and c.reason == "durability_degraded" for c in _checks_in(rep_deg, "storage")
    )

    # 4) Disk space thresholds -> WARN / FAIL.
    free_bytes = shutil.disk_usage(data_root).free
    rep_disk_warn = run_doctor(
        rep.daemon_config_path,
        os_=os_,
        limits=DoctorScanLimits(disk_warn_free_bytes=free_bytes + 1024 * 1024, disk_fail_free_bytes=1024),
    )
    assert rep_disk_warn.overall_status == "warn"
    assert any(
        c.status == "WARN" and "disk" in (c.name + c.detail).lower()
        for c in _checks_in(rep_disk_warn, "storage")
    )

    rep_disk_fail = run_doctor(
        rep.daemon_config_path,
        os_=os_,
        limits=DoctorScanLimits(
            disk_warn_free_bytes=free_bytes + 2 * 1024 * 1024,
            disk_fail_free_bytes=free_bytes + 1024 * 1024,
        ),
    )
    assert rep_disk_fail.overall_status == "fail"
    assert any(
        c.status == "FAIL" and "disk" in (c.name + c.detail).lower()
        for c in _checks_in(rep_disk_fail, "storage")
    )

    # 5) Attached CaptureDoctorProbePort degraded -> WARN (never PASS).
    class _DegradedCaptureProbe(CaptureDoctorProbePort):
        def probe_capture(self, target_root: Path) -> CaptureDoctorProbeResult:
            assert target_root == data_root
            return CaptureDoctorProbeResult(
                available=False,
                detail="outbox backlog=5 capture_gaps=1",
                status="WARN",
                reason="probe_unavailable",
                remediation="Inspect capture service and outbox.",
                outbox_backlog=5,
                capture_gaps=1,
            )

    rep_cap = run_doctor(rep.daemon_config_path, os_=os_, capture_probe=_DegradedCaptureProbe())
    assert rep_cap.overall_status == "warn"
    assert all(c.status != "PASS" for c in _checks_in(rep_cap, "capture"))
    assert any(c.status == "WARN" for c in _checks_in(rep_cap, "capture"))

    # 6) Retention tombstone vs CAS holder match vs mismatch.
    rt = reopen_kernel_job_runtime(data_root, rep.store_id, os_)
    holder_id = new_id()
    try:
        rt.store.store_content(b"retention-probe-blob", "event", holder_id, RetentionClass.DURABLE, None)
        rt.policy.record_intent(IntentKind.TOMBSTONE, {"holder_kind": "event", "holder_id": holder_id})
    finally:
        rt.close()
    rep_ret_mismatch = run_doctor(rep.daemon_config_path, os_=os_)
    assert rep_ret_mismatch.overall_status != "pass"
    assert any(c.status in {"WARN", "FAIL"} for c in _checks_in(rep_ret_mismatch, "retention"))

    rt2 = reopen_kernel_job_runtime(data_root, rep.store_id, os_)
    try:
        rt2.store.reconcile_policy()
    finally:
        rt2.close()
    rep_ret_ok = run_doctor(rep.daemon_config_path, os_=os_)
    assert all(c.status == "PASS" for c in _checks_in(rep_ret_ok, "retention"))

    # 7) Backup healthy -> PASS, stale -> WARN, corrupt -> FAIL.
    rt3 = reopen_kernel_job_runtime(data_root, rep.store_id, os_)
    try:
        create_policy_backup(rt3.policy, os_, clock.now())
        clock.advance(timedelta(seconds=5))
        create_store_backup(rt3.store, os_, clock.now())
    finally:
        rt3.close()
    assert run_doctor(rep.daemon_config_path, os_=os_).overall_status == "pass"

    clock.advance(timedelta(days=365))
    rep_bak_stale = run_doctor(rep.daemon_config_path, os_=os_)
    assert rep_bak_stale.overall_status == "warn"
    assert any(
        c.status == "WARN" and "backup" in (c.name + c.detail).lower()
        for c in _checks_in(rep_bak_stale, "storage")
    )

    # Corrupt newest backup manifest -> FAIL.
    clock.advance(timedelta(minutes=5))
    rt4 = reopen_kernel_job_runtime(data_root, rep.store_id, os_)
    try:
        create_policy_backup(rt4.policy, os_, clock.now())
        clock.advance(timedelta(seconds=5))
        corrupt_bak = create_store_backup(rt4.store, os_, clock.now())
    finally:
        rt4.close()
    manifest = corrupt_bak / "manifest.json"
    os_.permissions.secure_file(manifest)
    manifest.write_bytes(b"{corrupt-json")
    os_.permissions.secure_file(manifest)
    rep_bak_corrupt = run_doctor(rep.daemon_config_path, os_=os_)
    assert rep_bak_corrupt.overall_status == "fail"
    assert any(
        c.status == "FAIL" and "backup" in (c.name + c.detail).lower()
        for c in _checks_in(rep_bak_corrupt, "storage")
    )

    # 8) WAL size threshold -> WARN (clean backup-free root with valid uncheckpointed WAL > threshold).
    rep_w, data_w, _cfg_w, _co_w, os_w = _init_root(trusted_tmp / "wal-warn", clock, tag="ww", durable=True)
    wal_root = DataRoot.at(data_w)
    _leave_uncheckpointed_runtime_wal(
        data_w,
        rep_w.store_id,
        os_w,
        trusted_tmp / "wal-snap",
        blob_count=20,
        include_policy_wal=False,
    )
    assert wal_root.store_db.with_name("brain.db-wal").stat().st_size > 1024
    rep_wal = run_doctor(rep_w.daemon_config_path, os_=os_w, limits=DoctorScanLimits(wal_warn_bytes=1024))
    assert rep_wal.overall_status == "warn"
    assert any(
        c.status == "WARN" and "wal" in (c.name + c.detail).lower()
        for c in _checks_in(rep_wal, "storage")
    )


def test_doctor_privacy_canary_channels_and_rescan_no_secret_leak(trusted_tmp: Path) -> None:
    """7-channel in-memory canary suite, broken scanner FAIL, non-UTF8 CAS/log rescan, zero secret leakage."""
    clock = FakeClock(datetime(2026, 11, 21, 12, 0, tzinfo=UTC))
    rep, data_root, _cfg_dir, checkout, os_ = _init_root(trusted_tmp / "priv", clock, tag="pv", durable=True)
    root = DataRoot.at(data_root)

    s_ghp = "ghp_CanarySecretToken1234567890abcdef"
    s_bearer = "CanarySecretBearerToken1234567890"
    s_sk = "sk-CanaryOpenAISecretKey9988776655"
    s_priv = "canary_private_payload_42"
    secrets = (s_ghp, s_bearer, s_sk, s_priv)

    # Seed CAS blobs (including non-UTF8 binary prefix/invalid UTF-8 bytes) and log file with canary secrets.
    rt = reopen_kernel_job_runtime(data_root, rep.store_id, os_)
    try:
        rt.store.store_content(b"completely clean blob text", "event", new_id(), RetentionClass.DURABLE, None)
        d_ghp = rt.store.store_content(
            f"leaked {s_ghp} inside cas".encode(),
            "event",
            new_id(),
            RetentionClass.DURABLE,
            None,
        )
        d_bin = rt.store.store_content(
            b"\xff\xfe\x00\x80\xc3\x28 " + f"Authorization: Bearer {s_bearer}".encode(),
            "event",
            new_id(),
            RetentionClass.DURABLE,
            None,
        )
    finally:
        rt.close()

    log_file = root.logs_dir / "brain.log"
    log_file.write_bytes(
        f"2026-11-21T12:00:00Z ERROR {s_sk}\n".encode()
        + b"\x80\xff binary prefix "
        + f"<private>{s_priv}</private>\n".encode()
    )
    os_.permissions.secure_file(log_file)

    # Baseline check: default run_doctor MUST detect persisted secrets and fail (no raw secret leaked).
    rep_dirty = run_doctor(rep.daemon_config_path, checkout_root=checkout, os_=os_)
    assert rep_dirty.overall_status == "fail"

    from superbrain.application.doctor import KernelPrivacyScanner
    from superbrain.ports.doctor import PrivacyCanaryProbeResult, PrivacyScannerPort

    snap_dirty = read_doctor_snapshot(data_root, os_, privacy_scanner=KernelPrivacyScanner())
    text_out = format_doctor_text(rep_dirty)
    json_out = json.dumps({"ok": True, "data": rep_dirty.to_dict()})

    privacy_checks = _checks_in(rep_dirty, "privacy")
    assert any(c.status == "FAIL" for c in privacy_checks)
    combined_privacy_detail = " ".join(c.detail for c in privacy_checks)
    assert d_ghp in combined_privacy_detail or d_bin in combined_privacy_detail

    # Assert ZERO secret substrings anywhere in snapshot, report, details, remediations, integrity_errors, or JSON.
    for surface in (
        repr(snap_dirty),
        repr(rep_dirty),
        text_out,
        json_out,
        *(c.detail for c in rep_dirty.checks),
        *(c.remediation or "" for c in rep_dirty.checks),
        *rep_dirty.integrity_errors,
    ):
        for secret in secrets:
            assert secret not in surface, f"raw secret {secret!r} leaked into doctor output!"

    # Verify real KernelPrivacyScanner runs strictly in memory (0 disk writes) across all 7 channels.
    clean_rep, clean_root, _c_cfg, _c_co, clean_os = _init_root(trusted_tmp / "priv-clean", clock, tag="pvc")
    tree_before = digest_tree(clean_root)
    scanner = KernelPrivacyScanner()
    canaries = scanner.check_canary_channels()
    assert len(canaries) == 7
    assert {r.channel for r in canaries} == ALL_7_CANARY_CHANNELS
    assert all(r.passed is True for r in canaries)
    assert digest_tree(clean_root) == tree_before

    # Direct scan_bytes checks including binary non-UTF8 prefix & clean binary.
    assert scanner.scan_bytes(b"\x00\x01\xff\xfe benign binary payload") == ()
    hits_bin = scanner.scan_bytes(b"\xff\xfe\x00\x80\xc3\x28 Authorization: Bearer " + s_bearer.encode())
    assert hits_bin and all(s_bearer not in rule_id for rule_id in hits_bin)
    hits_ghp = scanner.scan_bytes(s_ghp.encode())
    assert hits_ghp and all(s_ghp not in rule_id for rule_id in hits_ghp)
    hits_priv = scanner.scan_bytes(f"<private>{s_priv}</private>".encode())
    assert hits_priv and all(s_priv not in rule_id for rule_id in hits_priv)

    # Broken/mocked PrivacyScannerPort passing a canary through -> FAIL!
    class _BrokenCanaryScanner(PrivacyScannerPort):
        def check_canary_channels(self) -> tuple[PrivacyCanaryProbeResult, ...]:
            return (
                PrivacyCanaryProbeResult(channel="hook", passed=False, detail="canary passed through"),
                *(
                    PrivacyCanaryProbeResult(channel=ch, passed=True)
                    for ch in sorted(ALL_7_CANARY_CHANNELS - {"hook"})
                ),
            )

        def scan_bytes(self, data: bytes) -> tuple[str, ...]:
            return ()

    rep_broken = run_doctor(clean_rep.daemon_config_path, os_=clean_os, privacy_scanner=_BrokenCanaryScanner())
    assert rep_broken.overall_status == "fail"
    assert any(c.status == "FAIL" for c in _checks_in(rep_broken, "privacy"))


def test_doctor_bounded_cas_and_privacy_caps_emit_reason(trusted_tmp: Path) -> None:
    """Bounded CAS/privacy caps (64/16 MiB & tiny) emit scan_cap_reached, tamper/orphan/mismatch/bounds/timeout."""
    clock = FakeClock(datetime(2026, 11, 21, 12, 0, tzinfo=UTC))

    # 1) Default 64-blob cap: 70 clean blobs -> stops at cap and emits WARN(reason="scan_cap_reached"), never "ok".
    rep1, root1, _cfg1, _co1, os1 = _init_root(trusted_tmp / "cap64", clock, tag="c64", durable=True)
    rt1 = reopen_kernel_job_runtime(root1, rep1.store_id, os1)
    try:
        for i in range(70):
            rt1.store.store_content(
                f"clean-sample-blob-{i:03d}".encode(),
                "event",
                new_id(),
                RetentionClass.DURABLE,
                None,
            )
    finally:
        rt1.close()
    r_cap64 = run_doctor(rep1.daemon_config_path, os_=os1)
    assert r_cap64.overall_status == "warn"

    from superbrain.ports.doctor import (
        MAX_CAS_SAMPLE_BLOBS,
        MAX_CAS_SAMPLE_BYTES,
        MAX_DOCTOR_REPORT_BYTES,
        MAX_LIST_FINDINGS_PER_GROUP,
        MAX_PRIVACY_RESCAN_ITEMS,
        MAX_REPORT_CHECKS,
        MAX_REPORT_STRING_LEN,
        PROBE_TIMEOUT_S,
        CaptureDoctorProbePort,
        CaptureDoctorProbeResult,
        DoctorScanLimits,
    )

    assert MAX_CAS_SAMPLE_BLOBS == 64
    assert MAX_CAS_SAMPLE_BYTES == 16 * 1024 * 1024
    assert MAX_PRIVACY_RESCAN_ITEMS == 128
    assert PROBE_TIMEOUT_S == 5.0
    assert MAX_REPORT_CHECKS == 64
    assert MAX_REPORT_STRING_LEN == 512
    assert MAX_LIST_FINDINGS_PER_GROUP == 32
    assert MAX_DOCTOR_REPORT_BYTES == 256 * 1024

    assert any(
        c.status == "WARN" and c.reason == "scan_cap_reached" for c in _checks_in(r_cap64, "storage")
    )

    # 2) Custom tiny byte/item cap + tampered CAS SHA-256 -> FAIL.
    rep2, root2, _cfg2, _co2, os2 = _init_root(trusted_tmp / "tinycap", clock, tag="tc", durable=True)
    rt2 = reopen_kernel_job_runtime(root2, rep2.store_id, os2)
    digests2: list[str] = []
    try:
        for i in range(5):
            digests2.append(
                rt2.store.store_content(
                    (f"blob-{i}-" + "x" * 93).encode(),
                    "event",
                    new_id(),
                    RetentionClass.DURABLE,
                    None,
                )
            )
    finally:
        rt2.close()
    r_tiny = run_doctor(
        rep2.daemon_config_path,
        os_=os2,
        limits=DoctorScanLimits(max_cas_sample_blobs=100, max_cas_sample_bytes=256, max_privacy_rescan_items=3),
    )
    assert r_tiny.overall_status == "warn"
    assert any(c.status == "WARN" and c.reason == "scan_cap_reached" for c in _checks_in(r_tiny, "storage"))
    assert any(c.status == "WARN" and c.reason == "scan_cap_reached" for c in _checks_in(r_tiny, "privacy"))

    # Tamper one CAS blob within sample -> FAIL.
    tamper_path = blob_path(DataRoot.at(root2).cas_dir, sorted(digests2)[0])
    tamper_path.write_bytes(b"corrupted-cas-bytes-do-not-match-sha256")
    os2.permissions.secure_file(tamper_path)
    r_tamper = run_doctor(rep2.daemon_config_path, os_=os2)
    assert r_tamper.overall_status == "fail"
    assert any(c.status == "FAIL" for c in _checks_in(r_tamper, "storage"))

    # 3) Orphan CAS blobs -> WARN, plus bounds verification (>32 findings & long strings).
    rep3, root3, _cfg3, _co3, os3 = _init_root(trusted_tmp / "orphan", clock, tag="or", durable=True)
    cas3 = DataRoot.at(root3).cas_dir
    for i in range(45):
        orphan_bytes = f"orphan-cas-payload-{i:03d}".encode()
        odig = digest_bytes(orphan_bytes)
        opath = blob_path(cas3, odig)
        opath.parent.mkdir(parents=True, exist_ok=True)
        os3.permissions.secure_directory(opath.parent)
        opath.write_bytes(orphan_bytes)
        os3.permissions.secure_file(opath)

    class _VerboseProbe(CaptureDoctorProbePort):
        def probe_capture(self, data_root: Path) -> CaptureDoctorProbeResult:
            return CaptureDoctorProbeResult(
                available=False,
                detail="D" * 2000,
                status="WARN",
                reason="probe_unavailable",
                remediation="R" * 2000,
            )

    r_orphan = run_doctor(rep3.daemon_config_path, os_=os3, capture_probe=_VerboseProbe())
    assert r_orphan.overall_status == "warn"
    assert any(c.status == "WARN" for c in _checks_in(r_orphan, "storage"))
    assert len(r_orphan.checks) <= MAX_REPORT_CHECKS
    assert len(r_orphan.integrity_errors) <= MAX_LIST_FINDINGS_PER_GROUP
    assert len(r_orphan.permission_problems) <= MAX_LIST_FINDINGS_PER_GROUP
    assert len(r_orphan.remediations) <= MAX_LIST_FINDINGS_PER_GROUP
    group_counts = Counter(c.group for c in r_orphan.checks)
    assert all(cnt <= MAX_LIST_FINDINGS_PER_GROUP for cnt in group_counts.values())
    for item in r_orphan.checks:
        assert len(item.group) <= MAX_REPORT_STRING_LEN
        assert len(item.name) <= MAX_REPORT_STRING_LEN
        assert len(item.reason) <= MAX_REPORT_STRING_LEN
        assert len(item.detail) <= MAX_REPORT_STRING_LEN
        assert item.remediation is None or len(item.remediation) <= MAX_REPORT_STRING_LEN
    for msg in (*r_orphan.remediations, *r_orphan.integrity_errors, *r_orphan.permission_problems):
        assert len(msg) <= MAX_REPORT_STRING_LEN
    assert len(json.dumps({"ok": True, "data": r_orphan.to_dict()}).encode()) < MAX_DOCTOR_REPORT_BYTES

    # 4) Unapplied policy intents -> WARN.
    rep4, root4, _cfg4, _co4, os4 = _init_root(trusted_tmp / "unapplied", clock, tag="ua", durable=True)
    rt4 = reopen_kernel_job_runtime(root4, rep4.store_id, os4)
    try:
        rt4.policy.record_intent(IntentKind.QUARANTINE, {"digest": "sha256:" + "a" * 64})
    finally:
        rt4.close()
    r_intent = run_doctor(rep4.daemon_config_path, os_=os4)
    assert r_intent.overall_status == "warn"
    assert any(c.status == "WARN" for c in _checks_in(r_intent, "storage"))

    # 5) Ledger-vs-projection mismatch -> FAIL.
    rep5, root5, _cfg5, _co5, os5 = _init_root(trusted_tmp / "mismatch", clock, tag="mm", durable=True)
    rt5 = reopen_kernel_job_runtime(root5, rep5.store_id, os5)
    hid5 = new_id()
    try:
        rt5.store.store_content(b"ledger-projection-check", "event", hid5, RetentionClass.DURABLE, None)
    finally:
        rt5.close()
    conn5 = sqlite3.connect(DataRoot.at(root5).store_db)
    try:
        cur5 = conn5.execute("DELETE FROM p_cas_holders_ WHERE holder_id = ?", (hid5,))
        assert cur5.rowcount == 1
        conn5.commit()
        conn5.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        conn5.close()
    os5.permissions.secure_file(DataRoot.at(root5).store_db)
    r_mm = run_doctor(rep5.daemon_config_path, os_=os5)
    assert r_mm.overall_status == "fail"
    assert any(c.status == "FAIL" for c in _checks_in(r_mm, "storage"))

    # 6) Slow probe honors PROBE_TIMEOUT_S -> WARN(reason="timeout_exceeded").
    rep6, _root6, _cfg6, _co6, _ = _init_root(trusted_tmp / "timeout", clock, tag="to", durable=True)
    os6 = _make_os(clock, durable=True, real_monotonic=True)

    class _SlowProbe(CaptureDoctorProbePort):
        def probe_capture(self, data_root: Path) -> CaptureDoctorProbeResult:
            time.sleep(0.25)
            return CaptureDoctorProbeResult(available=True, detail="too late")

    r_timeout = run_doctor(
        rep6.daemon_config_path,
        os_=os6,
        capture_probe=_SlowProbe(),
        limits=DoctorScanLimits(probe_timeout_s=0.05),
    )
    assert r_timeout.overall_status == "warn"
    assert any(c.status == "WARN" and c.reason == "timeout_exceeded" for c in _checks_in(r_timeout, "capture"))


def test_doctor_schema_newer_fails_without_query_or_write(trusted_tmp: Path) -> None:
    """§20.26 on brain.db & policy.db independently: min_reader_version > code & schema_version > code >= min_reader."""
    clock = FakeClock(datetime(2026, 11, 21, 12, 0, tzinfo=UTC))

    # (a) brain.db min_reader_version > code with altered/missing future tables -> FAIL(reason="unsupported_version").
    rep_s1, root_s1, _cfg_s1, _co_s1, os_s1 = _init_root(trusted_tmp / "fut-store-unreadable", clock, tag="fs1")
    store_db1 = DataRoot.at(root_s1).store_db
    conn1 = sqlite3.connect(store_db1)
    try:
        conn1.execute("DROP TABLE ledger")
        conn1.execute("DROP TABLE p_cas_holders_")
        conn1.execute("CREATE TABLE future_v99_events (id INTEGER PRIMARY KEY)")
        conn1.execute("UPDATE meta SET value = '99' WHERE key = 'schema_version'")
        conn1.execute("UPDATE meta SET value = '99' WHERE key = 'min_reader_version'")
        conn1.commit()
        conn1.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        conn1.close()
    os_s1.permissions.secure_file(store_db1)

    snap_before1 = digest_tree(root_s1)
    rep1_cli = run_doctor(rep_s1.daemon_config_path, os_=os_s1)
    assert rep1_cli.overall_status == "fail"
    sch1 = _check_by(rep1_cli, "daemon", "schema_version")
    assert sch1.status == "FAIL" and sch1.reason == "unsupported_version"
    assert "no such table" not in repr(rep1_cli).lower()
    assert digest_tree(root_s1) == snap_before1

    from superbrain.application.doctor import KernelPrivacyScanner

    snap1 = read_doctor_snapshot(root_s1, os_s1, privacy_scanner=KernelPrivacyScanner())
    rep1 = inspect_doctor_snapshot(snap1)
    assert snap1.schema.store_version == 99
    assert rep1.overall_status == "fail"
    assert _check_by(rep1, "daemon", "schema_version").reason == "unsupported_version"
    assert "no such table" not in repr(snap1).lower()
    assert digest_tree(root_s1) == snap_before1

    # (b) policy.db min_reader_version > code with altered/missing future tables -> FAIL(reason="unsupported_version").
    rep_p1, root_p1, _cfg_p1, _co_p1, os_p1 = _init_root(trusted_tmp / "fut-policy-unreadable", clock, tag="fp1")
    policy_db1 = DataRoot.at(root_p1).policy_db
    pconn1 = sqlite3.connect(policy_db1)
    try:
        pconn1.execute("DROP TABLE trust")
        pconn1.execute("DROP TABLE principal")
        pconn1.execute("DROP TABLE intents")
        pconn1.execute("CREATE TABLE future_v99_policy (k TEXT PRIMARY KEY)")
        pconn1.execute("UPDATE meta SET value = '99' WHERE key = 'schema_version'")
        pconn1.execute("UPDATE meta SET value = '99' WHERE key = 'min_reader_version'")
        pconn1.commit()
        pconn1.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        pconn1.close()
    os_p1.permissions.secure_file(policy_db1)

    snap_before_p1 = digest_tree(root_p1)
    snap_p1 = read_doctor_snapshot(root_p1, os_p1, privacy_scanner=KernelPrivacyScanner())
    rep_p1_insp = inspect_doctor_snapshot(snap_p1)
    rep_p1_cli = run_doctor(rep_p1.daemon_config_path, os_=os_p1)
    assert snap_p1.schema.policy_version == 99
    assert rep_p1_insp.overall_status == "fail" and rep_p1_cli.overall_status == "fail"
    sch_p1 = _check_by(rep_p1_insp, "daemon", "schema_version")
    assert sch_p1.status == "FAIL" and sch_p1.reason == "unsupported_version"
    assert "no such table" not in repr(snap_p1).lower()
    assert "no such table" not in repr(rep_p1_insp).lower()
    assert digest_tree(root_p1) == snap_before_p1

    # (c) brain.db schema_version > code >= min_reader_version -> WARN(reason="unsupported_writable_version").
    rep_s2, root_s2, _cfg_s2, _co_s2, os_s2 = _init_root(trusted_tmp / "fut-store-readable", clock, tag="fs2")
    store_db2 = DataRoot.at(root_s2).store_db
    conn2 = sqlite3.connect(store_db2)
    try:
        conn2.execute("UPDATE meta SET value = '9' WHERE key = 'schema_version'")
        conn2.execute("UPDATE meta SET value = '5' WHERE key = 'min_reader_version'")
        conn2.commit()
        conn2.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        conn2.close()
    os_s2.permissions.secure_file(store_db2)

    snap_before2 = digest_tree(root_s2)
    rep_s2_cli = run_doctor(rep_s2.daemon_config_path, os_=os_s2)
    sch_s2 = _check_by(rep_s2_cli, "daemon", "schema_version")
    assert sch_s2.status == "WARN" and sch_s2.reason == "unsupported_writable_version"
    assert rep_s2_cli.overall_status == "warn"
    assert digest_tree(root_s2) == snap_before2

    # (d) policy.db schema_version > code >= min_reader_version -> WARN(reason="unsupported_writable_version").
    rep_p2, root_p2, _cfg_p2, _co_p2, os_p2 = _init_root(trusted_tmp / "fut-policy-readable", clock, tag="fp2")
    policy_db2 = DataRoot.at(root_p2).policy_db
    pconn2 = sqlite3.connect(policy_db2)
    try:
        pconn2.execute("UPDATE meta SET value = '9' WHERE key = 'schema_version'")
        pconn2.execute("UPDATE meta SET value = '4' WHERE key = 'min_reader_version'")
        pconn2.commit()
        pconn2.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        pconn2.close()
    os_p2.permissions.secure_file(policy_db2)

    snap_before_p2 = digest_tree(root_p2)
    rep_p2_cli = run_doctor(rep_p2.daemon_config_path, os_=os_p2)
    sch_p2 = _check_by(rep_p2_cli, "daemon", "schema_version")
    assert sch_p2.status == "WARN" and sch_p2.reason == "unsupported_writable_version"
    assert rep_p2_cli.overall_status == "warn"
    assert digest_tree(root_p2) == snap_before_p2


def test_doctor_offline_preserves_all_bytes_zero_lock(trusted_tmp: Path) -> None:
    """Offline doctor preserves hashes & mtimes (incl. -wal without -shm), 0 locks, & §20.28 wide ACL FAIL."""
    clock = FakeClock(datetime(2026, 11, 21, 12, 0, tzinfo=UTC))
    os_ = os_adapters(clock=clock, monotonic=FakeMonotonicClock(1_000_000_000))
    cfg_dir, data_root, checkout = (
        trusted_tmp / "off-cfg",
        trusted_tmp / "off-data",
        trusted_tmp / "off-checkout",
    )
    for d in (cfg_dir, checkout):
        d.mkdir(parents=True, exist_ok=True)
        os_.permissions.secure_directory(d)

    rep = init_store(
        InitRequest(
            data_root=data_root,
            config_dir=cfg_dir,
            owner_id=OWNER,
            machine_id=MACHINE,
            signer=_ssh_enrollment("off"),
        ),
        os_,
    )
    root = DataRoot.at(data_root)
    rt = reopen_kernel_job_runtime(data_root, rep.store_id, os_)
    try:
        rt.store.store_content(b"offline-clean-blob", "event", new_id(), RetentionClass.DURABLE, None)
        create_policy_backup(rt.policy, os_, clock.now())
        clock.advance(timedelta(seconds=5))
        create_store_backup(rt.store, os_, clock.now())
    finally:
        rt.close()

    (checkout / "README.md").write_text("# Clean checkout\n", encoding="utf-8")
    log_file = root.logs_dir / "brain.log"
    log_file.write_text("2026-11-21T12:00:00Z INFO daemon stopped cleanly\n", encoding="utf-8")
    os_.permissions.secure_file(log_file)

    # Create uncheckpointed -wal WITHOUT -shm on both brain.db and policy.db.
    _leave_uncheckpointed_runtime_wal(
        data_root,
        rep.store_id,
        os_,
        trusted_tmp / "off-wal-snap",
        blob_count=2,
        include_policy_wal=True,
    )
    assert root.store_db.with_name("brain.db-wal").is_file()
    assert not root.store_db.with_name("brain.db-shm").exists()
    assert root.policy_db.with_name("policy.db-wal").is_file()
    assert not root.policy_db.with_name("policy.db-shm").exists()

    files_before, dirs_before = _snapshot_tree_and_mtimes(data_root)
    co_files_before, co_dirs_before = _snapshot_tree_and_mtimes(checkout)

    locks_spy = _SpyNoAcquireLocks(cast(LockProbePort, os_.locks))
    pub_proxy = _ReadOnlyPublisherProxy(os_.publisher, (data_root, checkout))
    spy_os = replace(os_, locks=locks_spy, publisher=pub_proxy)

    report = run_doctor(rep.daemon_config_path, checkout_root=checkout, os_=spy_os)
    assert locks_spy.probe_calls >= 1

    from superbrain.application.doctor import KernelPrivacyScanner

    snap = read_doctor_snapshot(
        data_root,
        spy_os,
        checkout_root=checkout,
        expected_store_id=rep.store_id,
        privacy_scanner=KernelPrivacyScanner(),
    )
    snap2 = StorageDoctorReader(spy_os).read_snapshot(
        data_root, checkout_root=checkout, expected_store_id=rep.store_id
    )
    _ = snap, snap2

    files_after, dirs_after = _snapshot_tree_and_mtimes(data_root)
    co_files_after, co_dirs_after = _snapshot_tree_and_mtimes(checkout)
    assert files_after == files_before
    assert dirs_after == dirs_before
    assert co_files_after == co_files_before
    assert co_dirs_after == co_dirs_before

    fs_detected = detect_fs(data_root)
    durable_names = {"NTFS", "ReFS", "ext4", "ext3", "xfs", "btrfs", "f2fs", "zfs", "apfs", "hfs"}
    if not fs_detected.remote and fs_detected.fs_type in durable_names:
        assert report.overall_status == "pass"

    # §20.28 wide permissions on file inside data_root -> permissions.* FAIL.
    _grant_wide_access(log_file)
    rep_wide_file = run_doctor(rep.daemon_config_path, os_=os_)
    assert rep_wide_file.overall_status == "fail"
    assert any(c.status == "FAIL" for c in _checks_in(rep_wide_file, "permissions"))
    os_.permissions.secure_file(log_file)

    # §20.28 wide permissions on backups/ -> permissions.* FAIL.
    _grant_wide_access(root.backups_dir)
    rep_wide_bak = run_doctor(rep.daemon_config_path, os_=os_)
    assert rep_wide_bak.overall_status == "fail"
    assert any(c.status == "FAIL" for c in _checks_in(rep_wide_bak, "permissions"))
    os_.permissions.secure_directory(root.backups_dir)

    # §20.28 wide permissions on data_root -> permissions.* FAIL.
    _grant_wide_access(data_root)
    rep_wide_root = run_doctor(rep.daemon_config_path, os_=os_)
    assert rep_wide_root.overall_status == "fail"
    assert any(c.status == "FAIL" for c in _checks_in(rep_wide_root, "permissions"))
    os_.permissions.secure_directory(data_root)

    # Non-link check: directory link/junction inside data_root pointing to wide target never descends into target.
    ext_wide = trusted_tmp / "ext-wide-target"
    ext_wide.mkdir()
    ext_secret = ext_wide / "secret-external-leaf.txt"
    ext_secret.write_text("external", encoding="utf-8")
    _grant_wide_access(ext_wide)
    _grant_wide_access(ext_secret)
    _make_dir_link(root.logs_dir / "linked_dir", ext_wide)

    rep_link = run_doctor(rep.daemon_config_path, os_=os_)
    assert rep_link.overall_status == "fail"
    serialized = json.dumps(rep_link.to_dict())
    assert "secret-external-leaf.txt" not in serialized
    assert all("secret-external-leaf.txt" not in p for p in rep_link.permission_problems)
