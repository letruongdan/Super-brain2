"""Independent oracle tests for SP1 Increment 4 Review Remediation findings.

Findings covered:
1. [P1] DoctorRun Freshness Boundaries (_daemon_health.py):
   Invariant: get_health(deep=True) returns latest DoctorRun and its age (age_s).
   A new job is enqueued (job_id non-null) ONLY if DoctorRun is absent, older than 24h
   (age_s > 86400.0), or an active job exists. If age_s <= 86400.0 and no active job,
   job_id MUST be None.
   Boundaries: 16m (fresh), 24h (fresh), 24h + 1s (stale, job enqueued).

2. [P1] Deep Health Pre-Restore Isolation (_daemon_health.py):
   Invariant: A DoctorRun recorded before a restore (store or policy) must NEVER be
   reported as fresh for the post-restore runtime or paired with the post-restore
   writer_epoch. Both fresh read and replay must reject pre-restore DoctorRuns.

3. [P1] Offline Doctor is Strictly Read-Only (doctor_entry.py, _doctor_fix_wiring.py):
   Invariant: When daemon is stopped, doctor is strictly read-only. Offline doctor
   must NOT acquire writer lease, bump epoch, modify ACLs/permissions, or modify DB bytes.
   Offline --fix must fail closed with DAEMON_UNAVAILABLE (0 writes, 0 epoch bumps, 0 lock acquires).

4. [P1] Consistent Point-in-Time Snapshot for Online Doctor (_daemon_doctor.py):
   Invariant: Online doctor background worker must execute against an atomic point-in-time
   snapshot taken on the owner thread (e.g. SQLite backup to scratch), not directly
   against fluctuating live DBs.

5. [P2] SP2 M1 Probe Receipt & Bootstrap Verification (doctor_probes_sp2.py):
   Invariant: native_verified must verify that the capture receipt matches the expected
   host platform/version, config digest, and run scope. Bootstrap surface must not report
   PASS without applied bootstrap evidence.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
from dataclasses import dataclass, replace
from datetime import timedelta
from pathlib import Path
from typing import Any, cast

import pytest

from superbrain.adapters.os.daemon_config import read_client_endpoint
from superbrain.cli_api.loopback import LoopbackClient, LoopbackTarget
from superbrain.composition import doctor_entry
from superbrain.core._kernel_approval import ApprovalChannel, Layer2State
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import TOTAL_REQUEST_BUDGET_NS, Ready, ToolCommand
from superbrain.ports.doctor import (
    CaptureDoctorSnapshot,
    CaptureHarnessDoctorStatus,
    DoctorSnapshot,
)
from superbrain.ports.os import OsAdapters
from superbrain.storage._doctor_reader import StorageDoctorReader
from superbrain.storage.backup import create_policy_backup, create_store_backup, verify_backup
from superbrain.storage.cas import blob_path
from superbrain.storage.kernel_schema import KERNEL_POLICY_MIGRATIONS, KERNEL_STORE_MIGRATIONS
from superbrain.storage.layout import DataRoot
from tests.integration.test_doctor_jobs import (
    BOUND_WAIT_S,
    MACHINE_ID,
    OWNER_DAN,
    _base_utc_now,
    _init_doctor_root,
    _post_tls,
    _restore_msg,
    _ro_db,
    _running_serve,
    _ssh_sig_b64,
    _validate_envelope,
)
from tests.integration.test_doctor_sp2_probes import (
    _apply_clean_bootstrap,
    _init_store_with_tls,
    _sp2_mod,
)
from tests.support.clock import FakeClock
from tests.support.inc2_fixture import reopen_kernel_job_runtime
from tests.support.inc2_transport import FakeMonotonicClock, register_workspace_direct
from tests.support.kernel_auth import seed_principal_and_credential


def _sha256(path: Path) -> str:
    if not path.is_file():
        return ""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _get_lock_epoch(lock_path: Path) -> int:
    if not lock_path.is_file():
        return 0
    from superbrain.storage.writer import _read_slots
    raw = lock_path.read_bytes()
    if len(raw) < 2:
        return 0
    cur, _ = _read_slots(raw[1:])
    return cur.writer_epoch


def _run_online_restore_helper(
    ready: Ready,
    rep: Any,
    ca_pem: str,
    cli_token: str,
    priv: Any,
    os_: OsAdapters,
    target_kind: str,
    backup_path: Path,
) -> None:
    prev = _post_tls(
        ready,
        ca_pem,
        "/v2/operator/restore",
        cli_token,
        {"target": target_kind, "backup": str(backup_path)},
    )
    assert prev["ok"] is True, prev
    ch = cast(dict[str, Any], prev["data"]["challenge"])
    migs = KERNEL_POLICY_MIGRATIONS if target_kind == "policy" else KERNEL_STORE_MIGRATIONS
    manifest = verify_backup(
        backup_path,
        expected_kind=cast(Any, target_kind),
        expected_store_id=rep.store_id,
        migrations=migs,
        os_=os_,
    )
    msg = _restore_msg(str(ch["store_id"]), OWNER_DAN, ch, manifest.db_digest)
    ap = {
        "message": msg.to_dict(),
        "channel": ApprovalChannel.SSH_KEY.value,
        "signer_id": rep.signer.signer_id,
        "signature": _ssh_sig_b64(priv, msg.canonical_bytes()),
    }
    done = _post_tls(
        ready,
        ca_pem,
        "/v2/operator/restore",
        cli_token,
        {"target": target_kind, "backup": str(backup_path), "approval": ap},
    )
    assert done["ok"] is True, done


# =============================================================================
# Finding 1: [P1] DoctorRun Freshness Boundaries (_daemon_health.py)
# =============================================================================


def _active_store_wide_doctor_jobs(root: DataRoot) -> list[tuple[str, str | None]]:
    """``(job_id, trigger)`` of queued/leased/running store-wide (checkout null) ``system.doctor`` jobs."""
    with _ro_db(root.store_db) as conn:
        rows = conn.execute(
            "SELECT job_id, payload_digest FROM p_jobs_state WHERE kind = 'system.doctor' "
            "AND state IN ('queued', 'leased', 'running') ORDER BY rowid"
        ).fetchall()
    out: list[tuple[str, str | None]] = []
    for job_id, digest in rows:
        payload = json.loads(blob_path(root.cas_dir, str(digest)).read_bytes().decode("utf-8"))
        if payload.get("checkout_root") is None:
            out.append((str(job_id), payload.get("trigger")))
    return out


def test_p1_doctor_run_freshness_boundaries_24h(trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Invariant: get_health(deep=True) returns latest DoctorRun and its age (age_s).

    A new job is enqueued (job_id non-null) ONLY if DoctorRun is absent, older than 24h
    (age_s > 86400.0), or an active job exists. If age_s <= 86400.0 and no active job,
    job_id MUST be None.

    Boundaries tested over TLS loopback using FakeClock:
      - 16 minutes (now = t0 + 16m): doctor_run_id present, age_s = 960.0, job_id = None.
      - Exactly 24 hours (now = t0 + 24h): doctor_run_id present, age_s = 86400.0 (exact 24h is fresh).
        The background schedule is due at elapsed >= 24h (I4-R4-02, plan line 37), so the store-wide
        scheduled job is already active: job_id is that job, never a second deep-health job.
      - 24 hours + 1 second (now = t0 + 24h + 1s): doctor_run_id present, age_s = 86401.0,
        job_id is non-null: the same single store-wide slot.
    The scheduled run is held inside its doctor read so it cannot replace the startup run mid-test.
    """
    t0 = _base_utc_now()
    clock = FakeClock(t0)
    mono = FakeMonotonicClock(1_000_000_000)
    rep, cfg, _priv, ca_pem, leaf_sha256, _cli, os_ = _init_doctor_root(trusted_tmp / "f1-freshness", clock)
    root = DataRoot.at(cfg.data_root)

    rt = reopen_kernel_job_runtime(cfg.data_root, rep.store_id, os_)
    try:
        cred_dan = seed_principal_and_credential(rt.policy, owner_id=OWNER_DAN, machine_id=MACHINE_ID)
    finally:
        rt.close()

    hold, release = threading.Event(), threading.Event()
    orig_read = StorageDoctorReader.read_snapshot

    def _held_read(self_r: Any, *a: Any, **kw: Any) -> Any:
        if hold.is_set():
            release.wait(timeout=BOUND_WAIT_S * 6)
        return orig_read(self_r, *a, **kw)

    monkeypatch.setattr(StorageDoctorReader, "read_snapshot", _held_read)
    try:
        _p1_freshness_boundaries(t0, clock, mono, rep, cfg, ca_pem, leaf_sha256, os_, cred_dan, root, hold, release)
    finally:
        release.set()


def _p1_freshness_boundaries(
    t0: Any,
    clock: FakeClock,
    mono: FakeMonotonicClock,
    rep: Any,
    cfg: Any,
    ca_pem: str,
    leaf_sha256: str,
    os_: OsAdapters,
    cred_dan: Any,
    root: DataRoot,
    hold: threading.Event,
    release: threading.Event,
) -> None:
    with _running_serve(cfg, os_=os_, clock=clock, mono=mono) as (ready, loop):
        assert loop.wait_doctor_settled(timeout=BOUND_WAIT_S)

        target = LoopbackTarget(
            endpoint=ready.endpoint,
            expected_store_id=rep.store_id,
            ca_pem=ca_pem,
            leaf_cert_sha256=leaf_sha256,
        )
        client = LoopbackClient(monotonic_ns=mono.monotonic_ns)

        # Baseline: get_health(deep=True) immediately at t0 returns startup DoctorRun
        startup_res = _validate_envelope(
            "get_health",
            client.call(
                target,
                ToolCommand(
                    "get_health",
                    {"schema_version": "2.0", "deep": True, "idempotency_key": "idem_startup_0001"},
                    token=cred_dan.token,
                ),
                deadline_ns=mono.now + TOTAL_REQUEST_BUDGET_NS,
            ),
        )
        assert startup_res["ok"] is True
        startup_data = cast(dict[str, Any], startup_res["data"])
        startup_run_id = startup_data.get("doctor_run_id")
        assert isinstance(startup_run_id, str) and startup_run_id
        assert startup_data.get("job_id") is None

        # ---------------------------------------------------------------------
        # Boundary 1: 16 minutes (now = t0 + 16m)
        # Expected: doctor_run_id present, age_s = 960.0, job_id = None
        # Unmodified code fails because DOCTOR_FRESHNESS_WINDOW = 15m.
        # ---------------------------------------------------------------------
        clock.set(t0 + timedelta(minutes=16))
        res_16m = _validate_envelope(
            "get_health",
            client.call(
                target,
                ToolCommand(
                    "get_health",
                    {"schema_version": "2.0", "deep": True, "idempotency_key": "idem_fresh_16m_001"},
                    token=cred_dan.token,
                ),
                deadline_ns=mono.now + TOTAL_REQUEST_BUDGET_NS,
            ),
        )
        assert res_16m["ok"] is True
        data_16m = cast(dict[str, Any], res_16m["data"])
        assert data_16m.get("doctor_run_id") == startup_run_id, (
            f"Expected fresh doctor_run_id at 16m, got {data_16m.get('doctor_run_id')}"
        )
        assert data_16m.get("age_s") == 960.0, f"Expected age_s=960.0 at 16m, got {data_16m.get('age_s')}"
        assert data_16m.get("job_id") is None, (
            f"Expected job_id=None at 16m (no active job, age <= 24h), got {data_16m.get('job_id')}"
        )

        # ---------------------------------------------------------------------
        # Boundary 2: Exactly 24 hours (now = t0 + 24h)
        # Expected: doctor_run_id present, age_s = 86400.0 (exact 24h is fresh); job_id is the active
        # store-wide scheduled job (schedule due at elapsed >= 24h, I4-R4-02).
        # ---------------------------------------------------------------------
        hold.set()
        clock.set(t0 + timedelta(hours=24))
        res_24h = _validate_envelope(
            "get_health",
            client.call(
                target,
                ToolCommand(
                    "get_health",
                    {"schema_version": "2.0", "deep": True, "idempotency_key": "idem_fresh_24h_001"},
                    token=cred_dan.token,
                ),
                deadline_ns=mono.now + TOTAL_REQUEST_BUDGET_NS,
            ),
        )
        assert res_24h["ok"] is True
        data_24h = cast(dict[str, Any], res_24h["data"])
        assert data_24h.get("doctor_run_id") == startup_run_id, (
            f"Expected fresh doctor_run_id at exact 24h, got {data_24h.get('doctor_run_id')}"
        )
        assert data_24h.get("age_s") == 86400.0, f"Expected age_s=86400.0 at 24h, got {data_24h.get('age_s')}"
        sched_jobs = _active_store_wide_doctor_jobs(root)
        assert len(sched_jobs) == 1 and sched_jobs[0][1] == "schedule", (
            f"Expected exactly one active store-wide scheduled job at exact 24h, got {sched_jobs}"
        )
        assert data_24h.get("job_id") == sched_jobs[0][0], (
            f"Expected job_id of the active scheduled store-wide job at exact 24h, got {data_24h.get('job_id')}"
        )

        # ---------------------------------------------------------------------
        # Boundary 3: 24 hours + 1 second (now = t0 + 24h + 1s)
        # Expected: doctor_run_id present, age_s = 86401.0, job_id non-null (newly enqueued job)
        # ---------------------------------------------------------------------
        clock.set(t0 + timedelta(hours=24, seconds=1))
        res_24h_1s = _validate_envelope(
            "get_health",
            client.call(
                target,
                ToolCommand(
                    "get_health",
                    {"schema_version": "2.0", "deep": True, "idempotency_key": "idem_stale_24h_1s_01"},
                    token=cred_dan.token,
                ),
                deadline_ns=mono.now + TOTAL_REQUEST_BUDGET_NS,
            ),
        )
        assert res_24h_1s["ok"] is True
        data_24h_1s = cast(dict[str, Any], res_24h_1s["data"])
        assert data_24h_1s.get("doctor_run_id") == startup_run_id, (
            f"Expected latest doctor_run_id present at 24h+1s, got {data_24h_1s.get('doctor_run_id')}"
        )
        assert data_24h_1s.get("age_s") == 86401.0, (
            f"Expected age_s=86401.0 at 24h+1s, got {data_24h_1s.get('age_s')}"
        )
        assert data_24h_1s.get("job_id") is not None, (
            "Expected newly enqueued job_id non-null at 24h+1s (stale run)"
        )
        assert data_24h_1s.get("job_id") == sched_jobs[0][0], (
            f"Expected the single store-wide slot at 24h+1s, got {data_24h_1s.get('job_id')}"
        )
        assert _active_store_wide_doctor_jobs(root) == sched_jobs, "deep health enqueued a second store-wide job"
        release.set()


# =============================================================================
# Finding 2: [P1] Deep Health Pre-Restore Isolation (_daemon_health.py)
# =============================================================================


def test_p1_deep_health_pre_restore_isolation_store(trusted_tmp: Path) -> None:
    """Invariant: A DoctorRun recorded before a store restore must NEVER be reported

    as fresh for the post-restore runtime or paired with the post-restore writer_epoch.
    Both fresh read and replay must reject pre-restore DoctorRuns.
    """
    clock = FakeClock(_base_utc_now())
    mono = FakeMonotonicClock(1_000_000_000)
    rep, cfg, priv, ca_pem, leaf_sha256, cli_token, os_ = _init_doctor_root(trusted_tmp / "f2-store-iso", clock)
    root = DataRoot.at(cfg.data_root)

    rt = reopen_kernel_job_runtime(cfg.data_root, rep.store_id, os_)
    try:
        cred_dan = seed_principal_and_credential(rt.policy, owner_id=OWNER_DAN, machine_id=MACHINE_ID)
    finally:
        rt.close()

    with _running_serve(cfg, os_=os_, clock=clock, mono=mono) as (ready, loop):
        assert loop.wait_doctor_settled(timeout=BOUND_WAIT_S)

        target = LoopbackTarget(
            endpoint=ready.endpoint,
            expected_store_id=rep.store_id,
            ca_pem=ca_pem,
            leaf_cert_sha256=leaf_sha256,
        )
        client = LoopbackClient(monotonic_ns=mono.monotonic_ns)

        # 1. Run doctor at epoch E before restore.
        pre_res = _validate_envelope(
            "get_health",
            client.call(
                target,
                ToolCommand(
                    "get_health",
                    {"schema_version": "2.0", "deep": True, "idempotency_key": "idem_pre_store_restore_01"},
                    token=cred_dan.token,
                ),
                deadline_ns=mono.now + TOTAL_REQUEST_BUDGET_NS,
            ),
        )
        assert pre_res["ok"] is True
        pre_data = cast(dict[str, Any], pre_res["data"])
        pre_doctor_run_id = pre_data.get("doctor_run_id")
        assert isinstance(pre_doctor_run_id, str) and pre_doctor_run_id
        assert pre_data["writer_epoch"] == ready.endpoint.writer_epoch

        # Take backup of store containing this pre-restore DoctorRun
        def _backup_store() -> Path:
            session = cast(Any, loop)._session
            assert session is not None
            return create_store_backup(session.rt.store, os_, clock.now())

        store_bak = loop.run_owner_action(_backup_store).result(timeout=BOUND_WAIT_S)

        # 2. Perform online store restore. Endpoint writer_epoch becomes E + 1.
        _run_online_restore_helper(ready, rep, ca_pem, cli_token, priv, os_, "store", store_bak)
        assert loop.wait_doctor_settled(timeout=BOUND_WAIT_S)

        ep_post = read_client_endpoint(root.endpoint_path, os_)
        assert ep_post.writer_epoch == ready.endpoint.writer_epoch + 1
        target_post = replace(target, endpoint=ep_post)

        # 3. Post-restore Fresh Read: MUST NOT return pre-restore doctor_run_id or age_s!
        fresh_post = _validate_envelope(
            "get_health",
            client.call(
                target_post,
                ToolCommand(
                    "get_health",
                    {"schema_version": "2.0", "deep": True, "idempotency_key": "idem_fresh_post_store_02"},
                    token=cred_dan.token,
                ),
                deadline_ns=mono.now + TOTAL_REQUEST_BUDGET_NS,
            ),
        )
        assert fresh_post["ok"] is True
        fresh_data = cast(dict[str, Any], fresh_post["data"])
        assert fresh_data.get("doctor_run_id") != pre_doctor_run_id, (
            f"Pre-restore doctor_run_id {pre_doctor_run_id} leaked as fresh post-store-restore!"
        )
        assert fresh_data.get("doctor_run_id") is None, (
            "Post-store-restore fresh read must not report pre-restore DoctorRun, "
            f"got {fresh_data.get('doctor_run_id')}"
        )
        assert fresh_data.get("age_s") is None

        # 4. Post-restore Replay of pre-restore idempotency key: MUST reject pre-restore DoctorRun!
        replay_post = _validate_envelope(
            "get_health",
            client.call(
                target_post,
                ToolCommand(
                    "get_health",
                    {"schema_version": "2.0", "deep": True, "idempotency_key": "idem_pre_store_restore_01"},
                    token=cred_dan.token,
                ),
                deadline_ns=mono.now + TOTAL_REQUEST_BUDGET_NS,
            ),
        )
        if replay_post.get("ok") is True:
            replay_data = cast(dict[str, Any], replay_post["data"])
            assert replay_data.get("doctor_run_id") != pre_doctor_run_id, (
                f"Pre-restore doctor_run_id {pre_doctor_run_id} returned on replay post-store-restore!"
            )
            assert replay_data.get("doctor_run_id") is None
        else:
            assert cast(dict[str, Any], replay_post.get("error", {})).get("code") in {
                ErrorCode.REVISION_CONFLICT.value,
                ErrorCode.NOT_FOUND.value,
            }


def test_p1_deep_health_pre_restore_isolation_policy(trusted_tmp: Path) -> None:
    """Invariant: A DoctorRun recorded before a policy restore must NEVER be reported

    as fresh for the post-restore runtime. Both fresh read and replay must reject pre-restore DoctorRuns.
    """
    clock = FakeClock(_base_utc_now())
    mono = FakeMonotonicClock(1_000_000_000)
    rep, cfg, priv, ca_pem, leaf_sha256, cli_token, os_ = _init_doctor_root(trusted_tmp / "f2-policy-iso", clock)
    root = DataRoot.at(cfg.data_root)

    rt = reopen_kernel_job_runtime(cfg.data_root, rep.store_id, os_)
    try:
        cred_dan = seed_principal_and_credential(rt.policy, owner_id=OWNER_DAN, machine_id=MACHINE_ID)
        policy_bak = create_policy_backup(rt.policy, os_, clock.now())
    finally:
        rt.close()

    with _running_serve(cfg, os_=os_, clock=clock, mono=mono) as (ready, loop):
        assert loop.wait_doctor_settled(timeout=BOUND_WAIT_S)

        target = LoopbackTarget(
            endpoint=ready.endpoint,
            expected_store_id=rep.store_id,
            ca_pem=ca_pem,
            leaf_cert_sha256=leaf_sha256,
        )
        client = LoopbackClient(monotonic_ns=mono.monotonic_ns)

        # 1. Run doctor at policy generation G before restore.
        pre_res = _validate_envelope(
            "get_health",
            client.call(
                target,
                ToolCommand(
                    "get_health",
                    {"schema_version": "2.0", "deep": True, "idempotency_key": "idem_pre_policy_restore_01"},
                    token=cred_dan.token,
                ),
                deadline_ns=mono.now + TOTAL_REQUEST_BUDGET_NS,
            ),
        )
        assert pre_res["ok"] is True
        pre_data = cast(dict[str, Any], pre_res["data"])
        pre_doctor_run_id = pre_data.get("doctor_run_id")
        assert isinstance(pre_doctor_run_id, str) and pre_doctor_run_id

        # 2. Perform online policy restore (generation becomes G + 1).
        _run_online_restore_helper(ready, rep, ca_pem, cli_token, priv, os_, "policy", policy_bak)
        assert loop.wait_doctor_settled(timeout=BOUND_WAIT_S)

        ep_post = read_client_endpoint(root.endpoint_path, os_)
        target_post = replace(target, endpoint=ep_post)

        # 3. Post-restore Fresh Read: MUST NOT return pre-restore doctor_run_id or age_s!
        fresh_post = _validate_envelope(
            "get_health",
            client.call(
                target_post,
                ToolCommand(
                    "get_health",
                    {"schema_version": "2.0", "deep": True, "idempotency_key": "idem_fresh_post_policy_02"},
                    token=cred_dan.token,
                ),
                deadline_ns=mono.now + TOTAL_REQUEST_BUDGET_NS,
            ),
        )
        assert fresh_post["ok"] is True
        fresh_data = cast(dict[str, Any], fresh_post["data"])
        assert fresh_data.get("doctor_run_id") != pre_doctor_run_id, (
            f"Pre-policy-restore doctor_run_id {pre_doctor_run_id} leaked as fresh post-policy-restore!"
        )
        assert fresh_data.get("doctor_run_id") is None, (
            "Post-policy-restore fresh read must not report pre-restore DoctorRun, "
            f"got {fresh_data.get('doctor_run_id')}"
        )
        assert fresh_data.get("age_s") is None

        # 4. Post-restore Replay: MUST reject pre-restore DoctorRun!
        replay_post = _validate_envelope(
            "get_health",
            client.call(
                target_post,
                ToolCommand(
                    "get_health",
                    {"schema_version": "2.0", "deep": True, "idempotency_key": "idem_pre_policy_restore_01"},
                    token=cred_dan.token,
                ),
                deadline_ns=mono.now + TOTAL_REQUEST_BUDGET_NS,
            ),
        )
        if replay_post.get("ok") is True:
            replay_data = cast(dict[str, Any], replay_post["data"])
            assert replay_data.get("doctor_run_id") != pre_doctor_run_id, (
                f"Pre-policy-restore doctor_run_id {pre_doctor_run_id} returned on replay post-policy-restore!"
            )
            assert replay_data.get("doctor_run_id") is None
        else:
            assert cast(dict[str, Any], replay_post.get("error", {})).get("code") in {
                ErrorCode.REVISION_CONFLICT.value,
                ErrorCode.NOT_FOUND.value,
            }


# =============================================================================
# Finding 3: [P1] Offline Doctor is Strictly Read-Only (doctor_entry.py)
# =============================================================================


def test_p1_offline_doctor_strictly_read_only(trusted_tmp: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Invariant: When daemon is stopped, doctor is strictly read-only.

    Offline doctor MUST NOT acquire writer lease, bump writer epoch, modify ACL/permissions,
    or modify store/policy database bytes.
    If --fix is passed when offline, it must fail closed with DAEMON_UNAVAILABLE
    (0 writes, 0 epoch bumps, 0 lock acquires).
    """
    clock = FakeClock(_base_utc_now())
    rep, cfg, _priv, _ca, _sha, _cli, os_ = _init_doctor_root(trusted_tmp / "f3-offline", clock)
    root = DataRoot.at(cfg.data_root)

    # Daemon is stopped (no endpoint file, no lock held).
    assert not os.path.lexists(root.endpoint_path)
    probe_fn = getattr(os_.locks, "probe_held", None)
    if callable(probe_fn):
        assert not probe_fn(root.lock_path)

    store_sha_0 = _sha256(root.store_db)
    policy_sha_0 = _sha256(root.policy_db)
    lock_epoch_0 = _get_lock_epoch(root.lock_path)

    # Part A: Read-only offline doctor runs cleanly without mutating anything.
    code_ro = doctor_entry.run_doctor_cli(["doctor", "--config", str(rep.daemon_config_path), "--offline"], os_=os_)
    assert code_ro == 0
    capsys.readouterr()

    assert _sha256(root.store_db) == store_sha_0, "Offline read-only doctor modified store.db bytes!"
    assert _sha256(root.policy_db) == policy_sha_0, "Offline read-only doctor modified policy.db bytes!"
    assert _get_lock_epoch(root.lock_path) == lock_epoch_0, "Offline read-only doctor bumped lock/writer epoch!"

    # Part B: Offline --fix MUST fail closed with DAEMON_UNAVAILABLE (0 writes, 0 epoch bumps, 0 lock acquires).
    code_fix = doctor_entry.run_doctor_cli(
        ["doctor", "--config", str(rep.daemon_config_path), "--offline", "--fix", "--json"],
        os_=os_,
    )
    captured = capsys.readouterr()
    # Invariant: must fail closed with DAEMON_UNAVAILABLE, return non-zero (1).
    assert code_fix == 1, (
        f"Expected offline --fix to fail closed with exit code 1 (DAEMON_UNAVAILABLE), got {code_fix}. "
        f"Output: {captured.out}"
    )
    assert "daemon_unavailable" in (captured.out + captured.err).lower()

    # Verify 0 mutations occurred
    assert _sha256(root.store_db) == store_sha_0, "Offline --fix modified store.db bytes!"
    assert _sha256(root.policy_db) == policy_sha_0, "Offline --fix modified policy.db bytes!"
    assert _get_lock_epoch(root.lock_path) == lock_epoch_0, "Offline --fix bumped lock/writer epoch!"


# =============================================================================
# Finding 4: [P1] Consistent Point-in-Time Snapshot for Online Doctor
# =============================================================================


def test_p1_consistent_point_in_time_snapshot_online_doctor(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Invariant: Online doctor background worker must execute against an atomic point-in-time

    snapshot taken on the owner thread (e.g. SQLite backup to scratch), not directly
    against fluctuating live DBs.
    """
    clock = FakeClock(_base_utc_now())
    mono = FakeMonotonicClock(1_000_000_000)
    rep, cfg, _priv, ca_pem, leaf_sha256, _cli, os_ = _init_doctor_root(trusted_tmp / "f4-snapshot", clock)
    root = DataRoot.at(cfg.data_root)

    rt = reopen_kernel_job_runtime(cfg.data_root, rep.store_id, os_)
    try:
        seed_principal_and_credential(rt.policy, owner_id=OWNER_DAN, machine_id=MACHINE_ID)
    finally:
        rt.close()

    called_targets: list[tuple[Path, Path | None]] = []
    orig_read_snapshot = StorageDoctorReader.read_snapshot

    def _spy_read_snapshot(self: StorageDoctorReader, data_root: Path, **kwargs: Any) -> DoctorSnapshot:
        called_targets.append((data_root, kwargs.get("db_root")))
        return orig_read_snapshot(self, data_root, **kwargs)

    monkeypatch.setattr(StorageDoctorReader, "read_snapshot", _spy_read_snapshot)

    with _running_serve(cfg, os_=os_, clock=clock, mono=mono) as (ready, loop):
        assert loop.wait_doctor_settled(timeout=BOUND_WAIT_S)

        # Worker must have executed against a point-in-time snapshot copy in scratch!
        assert called_targets, "StorageDoctorReader.read_snapshot was never called by online doctor worker"
        live_target, db_target = called_targets[-1]

        # Invariant check: worker must inspect live data_root for permissions,
        # but execute SQLite queries against point-in-time snapshot in scratch!
        assert live_target == root.root
        assert db_target is not None and db_target != root.root, (
            f"Worker read SQLite directly from live DBs {db_target} instead of point-in-time scratch snapshot!"
        )
        assert (
            db_target == root.scratch_dir or root.scratch_dir in db_target.parents
        ), f"Worker DB snapshot target {db_target} is not inside scratch directory {root.scratch_dir}!"


# =============================================================================
# Finding 5: [P2] SP2 M1 Probe Receipt & Bootstrap Verification (doctor_probes_sp2.py)
# =============================================================================


@dataclass(frozen=True)
class CaptureHarnessWithReceipt(CaptureHarnessDoctorStatus):
    """Subclass carrying full native connection capture receipt for verification."""

    receipt: Any = None


def test_p2_sp2_m1_bootstrap_requires_applied_evidence(trusted_tmp: Path) -> None:
    """Invariant: Bootstrap surface must not report PASS without applied bootstrap evidence."""
    sp2 = _sp2_mod()
    clock = FakeClock(_base_utc_now())
    rep, cfg, _priv, _ca, _sha, _cli, os_ = _init_store_with_tls(trusted_tmp / "f5-boot", clock)

    checkout_no_boot = trusted_tmp / "co-no-bootstrap"
    checkout_no_boot.mkdir(parents=True)
    os_.permissions.secure_directory(checkout_no_boot)

    rt = reopen_kernel_job_runtime(cfg.data_root, rep.store_id, os_)
    live_writer_epoch = rt.lease.epoch  # writer generation a live get_health(deep=true) reports
    try:
        cred = seed_principal_and_credential(
            rt.policy, owner_id=OWNER_DAN, harness_id="claude-code", machine_id=MACHINE_ID
        )
        register_workspace_direct(
            rt, clock, cred.principal, alias="ws-no-boot", checkout_dir=checkout_no_boot, remote="https://ex/noboot.git"
        )
        rt.policy.set_layer2_state(
            harness_id="claude-code",
            host_version="2.1.0",
            config_digest=digest_bytes(b"cfg"),
            state=Layer2State.VERIFIED,
        )
    finally:
        rt.close()

    healthy_dh: dict[str, JsonValue] = {
        "ready": True,
        "store_id": rep.store_id,
        "writer_epoch": live_writer_epoch,
        "schema_version": 5,
        "policy_schema_version": 4,
        "degraded_codes": [],
        "doctor_run_id": new_id(),
        "age_s": 1.0,
        "job_id": None,
    }

    def _native_snap(_r: Path) -> CaptureDoctorSnapshot:
        return CaptureDoctorSnapshot(
            harnesses=(
                CaptureHarnessDoctorStatus(
                    harness_id="claude-code",
                    last_event_at="2026-11-21T19:30:00Z",
                    active_layer="hook",
                    outbox_backlog=0,
                    capture_gaps=0,
                    dead_letters=0,
                    receipt_kind="native",
                ),
            ),
            available=True,
        )

    m1_no_boot = sp2.run_m1_handover_probe(
        rep.daemon_config_path,
        checkout_root=checkout_no_boot,
        os_=os_,
        capture_probe=sp2.build_sp2_capture_probe(_native_snap, require_native_receipts=True),
        deep_health=healthy_dh,
        require_native_receipts=True,
    )
    # Invariant: Bootstrap surface must not report PASS without applied bootstrap evidence
    assert m1_no_boot["surfaces"][sp2.M1_SURFACE_BOOTSTRAP_DRIFT]["status"] != "PASS", (
        "Bootstrap surface reported PASS for checkout without applied bootstrap evidence!"
    )
    assert m1_no_boot["m1_ready"] is False


def test_p2_sp2_m1_native_capture_receipt_verification(trusted_tmp: Path) -> None:
    """Invariant: native_verified must verify that the capture receipt matches the expected

    host platform/version, config digest, and run scope.
    """
    sp2 = _sp2_mod()
    clock = FakeClock(_base_utc_now())
    rep, cfg, _priv, _ca, _sha, _cli, os_ = _init_store_with_tls(trusted_tmp / "f5-receipt", clock)

    checkout_clean = trusted_tmp / "co-clean"
    home_dir = trusted_tmp / "home"
    for d in (checkout_clean, home_dir):
        d.mkdir(parents=True)
        os_.permissions.secure_directory(d)

    cfg_digest = digest_bytes(b"expected-config-digest-sp2")
    host_ver = "2.1.0"
    host_name = "claude-code"

    rt = reopen_kernel_job_runtime(cfg.data_root, rep.store_id, os_)
    live_writer_epoch = rt.lease.epoch  # writer generation a live get_health(deep=true) reports
    try:
        cred = seed_principal_and_credential(rt.policy, owner_id=OWNER_DAN, harness_id=host_name, machine_id=MACHINE_ID)
        ws_clean = register_workspace_direct(
            rt, clock, cred.principal, alias="ws-clean", checkout_dir=checkout_clean, remote="https://ex/clean.git"
        )
        rt.policy.set_layer2_state(
            harness_id=host_name,
            host_version=host_ver,
            config_digest=cfg_digest,
            state=Layer2State.VERIFIED,
        )
        _apply_clean_bootstrap(
            rt,
            store_id=rep.store_id,
            signer_id=rep.signer.signer_id,
            owner_id=OWNER_DAN,
            checkout=checkout_clean,
            home_dir=home_dir,
            os_=os_,
            rel_path="CLAUDE.md",
            slice_id="s1",
            body="Bootstrap Applied Clean\n",
        )
    finally:
        rt.close()

    healthy_dh: dict[str, JsonValue] = {
        "ready": True,
        "store_id": rep.store_id,
        "writer_epoch": live_writer_epoch,
        "schema_version": 5,
        "policy_schema_version": 4,
        "degraded_codes": [],
        "doctor_run_id": new_id(),
        "age_s": 1.0,
        "job_id": None,
    }

    valid_receipt = {
        "host": host_name,
        "host_version": host_ver,
        "config_digest": cfg_digest,
        "run_scope": {"repo_id": ws_clean.repo_id, "checkout_id": ws_clean.checkout_id},
        "os": sys.platform,
    }

    # 1. Negative Control: Missing receipt on native capture -> native_verified=False, m1_ready=False
    def _native_snap_no_receipt(_r: Path) -> CaptureDoctorSnapshot:
        return CaptureDoctorSnapshot(
            harnesses=(
                CaptureHarnessWithReceipt(
                    harness_id=host_name,
                    last_event_at="2026-11-21T19:30:00Z",
                    active_layer="hook",
                    outbox_backlog=0,
                    capture_gaps=0,
                    dead_letters=0,
                    receipt_kind="native",
                    receipt=None,
                ),
            ),
            available=True,
        )

    m1_no_receipt = sp2.run_m1_handover_probe(
        rep.daemon_config_path,
        checkout_root=checkout_clean,
        os_=os_,
        capture_probe=sp2.build_sp2_capture_probe(_native_snap_no_receipt, require_native_receipts=True),
        deep_health=healthy_dh,
        require_native_receipts=True,
    )
    assert m1_no_receipt["native_verified"] is False, "native_verified was True when capture receipt was missing!"
    assert m1_no_receipt["m1_ready"] is False

    # 2. Negative Control: Mismatched config digest -> native_verified=False, m1_ready=False
    bad_cfg_receipt = {
        **valid_receipt,
        "config_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    }

    def _native_snap_bad_cfg(_r: Path) -> CaptureDoctorSnapshot:
        return CaptureDoctorSnapshot(
            harnesses=(
                CaptureHarnessWithReceipt(
                    harness_id=host_name,
                    last_event_at="2026-11-21T19:30:00Z",
                    active_layer="hook",
                    outbox_backlog=0,
                    capture_gaps=0,
                    dead_letters=0,
                    receipt_kind="native",
                    receipt=bad_cfg_receipt,
                ),
            ),
            available=True,
        )

    m1_bad_cfg = sp2.run_m1_handover_probe(
        rep.daemon_config_path,
        checkout_root=checkout_clean,
        os_=os_,
        capture_probe=sp2.build_sp2_capture_probe(_native_snap_bad_cfg, require_native_receipts=True),
        deep_health=healthy_dh,
        require_native_receipts=True,
    )
    assert m1_bad_cfg["native_verified"] is False, "native_verified was True with mismatched config_digest!"
    assert m1_bad_cfg["m1_ready"] is False

    # 3. Negative Control: Mismatched scope -> native_verified=False, m1_ready=False
    bad_scope_receipt = {**valid_receipt, "run_scope": {"repo_id": "other-repo", "checkout_id": "other-checkout"}}

    def _native_snap_bad_scope(_r: Path) -> CaptureDoctorSnapshot:
        return CaptureDoctorSnapshot(
            harnesses=(
                CaptureHarnessWithReceipt(
                    harness_id=host_name,
                    last_event_at="2026-11-21T19:30:00Z",
                    active_layer="hook",
                    outbox_backlog=0,
                    capture_gaps=0,
                    dead_letters=0,
                    receipt_kind="native",
                    receipt=bad_scope_receipt,
                ),
            ),
            available=True,
        )

    m1_bad_scope = sp2.run_m1_handover_probe(
        rep.daemon_config_path,
        checkout_root=checkout_clean,
        os_=os_,
        capture_probe=sp2.build_sp2_capture_probe(_native_snap_bad_scope, require_native_receipts=True),
        deep_health=healthy_dh,
        require_native_receipts=True,
    )
    assert m1_bad_scope["native_verified"] is False, "native_verified was True with mismatched scope!"
    assert m1_bad_scope["m1_ready"] is False

    # 4. Positive Control: Valid receipt matches host, config, and scope -> native_verified=True, m1_ready=True
    def _native_snap_clean(_r: Path) -> CaptureDoctorSnapshot:
        return CaptureDoctorSnapshot(
            harnesses=(
                CaptureHarnessWithReceipt(
                    harness_id=host_name,
                    last_event_at="2026-11-21T19:30:00Z",
                    active_layer="hook",
                    outbox_backlog=0,
                    capture_gaps=0,
                    dead_letters=0,
                    receipt_kind="native",
                    receipt=valid_receipt,
                ),
            ),
            available=True,
        )

    m1_pos = sp2.run_m1_handover_probe(
        rep.daemon_config_path,
        checkout_root=checkout_clean,
        os_=os_,
        capture_probe=sp2.build_sp2_capture_probe(_native_snap_clean, require_native_receipts=True),
        deep_health=healthy_dh,
        require_native_receipts=True,
    )
    assert m1_pos["surfaces"][sp2.M1_SURFACE_BOOTSTRAP_DRIFT]["status"] == "PASS"
    assert m1_pos["native_verified"] is True
    assert m1_pos["m1_ready"] is True
    assert m1_pos["overall_status"] == "pass"
