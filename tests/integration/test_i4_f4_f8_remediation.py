"""Independent RED oracle for SP1 increment 4 review findings F4, F5, F6 (STORE_BUSY part), F7 and F8.

Requirement sources:
- Review ``2026-11-23-sp1-increment4-review-09d34c0.md`` F4-F8 (invariants quoted per section below).
- Re-review ``2026-11-23-sp1-increment4-rereview-r3.md`` ("Cac muc truoc va gate"): F4-F8 still open.
- Fix note ``2026-11-23-sp1-increment4-fix-note-f1-f3.md``: F6 transient ``STORE_BUSY`` at commit still open.

Invariants under test:
- F4: every path that decides whether a DoctorRun is still valid uses the same fence set. A run from a previous
  writer epoch, from before an offline restore, or from another trust generation never suppresses the startup
  self-check.
- F5: one durable scope ``(owner, checkout_root)`` has one queued/leased/running slot, and the scope key is read
  from durable data (the job payload), never from process memory.
- F6: each leased job ends in exactly one durable state; a transient commit error is retried, never reported as an
  integrity failure.
- F7: a scan limit either refuses explicitly or keeps scanning; it never silently stops finding the owner's run.
- F8: owner attribution only from authoritative data; ``--offline`` trusts the writer lock over a stale endpoint;
  an unknown lock probe is never "not held"; no dead surface; no raw exception text or paths in reports; log
  rotation recovery keeps every byte; ``doctor --fix`` is authorized per action (store owner only).
"""

from __future__ import annotations

import contextlib
import importlib
import json
import sqlite3
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from typing import Any, cast

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.application._log_rotate import rotate_logs
from superbrain.application.maintenance import restore_offline, restore_offline_preview_payload
from superbrain.composition._maintenance_wiring import ensure_maintenance_backend
from superbrain.composition.doctor_entry import run_doctor, run_doctor_cli
from superbrain.composition.init_entry import reset_signers
from superbrain.composition.operator_entry import make_lazy_ssh_verifier
from superbrain.core._kernel_approval import CLI_HARNESS_ID, ApprovalChannel
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.kernel import KernelRecord, require_aware_utc
from superbrain.ports.os import OsAdapters
from superbrain.storage._doctor_reader import StorageDoctorReader
from superbrain.storage.backup import create_policy_backup, create_store_backup, verify_backup
from superbrain.storage.cas import blob_path
from superbrain.storage.idempotency import StagedKernelStore
from superbrain.storage.kernel_schema import KERNEL_POLICY_MIGRATIONS, KERNEL_STORE_MIGRATIONS
from superbrain.storage.layout import DataRoot
from tests.integration.test_doctor_fix import _acl_or_mode
from tests.integration.test_doctor_jobs import (
    BOUND_WAIT_S,
    MACHINE_ID,
    OWNER_DAN,
    _base_utc_now,
    _init_doctor_root,
    _restore_msg,
    _ro_db,
    _ssh_sig_b64,
    _ssh_signer_key,
    _submit_tool,
)
from tests.integration.test_i4_owner_thread_remediation import _post_operator, _widen_target
from tests.integration.test_i4_r3_remediation import _serve
from tests.integration.test_i4_rereview_remediation import _Daemon
from tests.support.clock import FakeClock
from tests.support.inc2_fixture import kernel_job_service, reopen_kernel_job_runtime
from tests.support.inc2_transport import FakeMonotonicClock
from tests.support.kernel_auth import seed_principal_and_credential

NON_TERMINAL = ("queued", "leased", "running")
OTHER_OWNER = "eve"
SECRET_FRAGMENT = "i4-f8-secret"
SECRET_PATH = rf"C:\{SECRET_FRAGMENT}\private\brain.db"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


class _Env:
    def __init__(self, trusted_tmp: Path, label: str, *, os_: OsAdapters | None = None) -> None:
        self.clock = FakeClock(_base_utc_now())
        self.mono = FakeMonotonicClock(1_000_000_000)
        self.rep, self.cfg, self.priv, self.ca_pem, _leaf, self.cli_token, self.os_ = _init_doctor_root(
            trusted_tmp / label, self.clock, os_=os_
        )
        self.root = DataRoot.at(self.cfg.data_root)
        self.store_id: str = self.rep.store_id

    @contextlib.contextmanager
    def serve(self, os_: OsAdapters | None = None) -> Iterator[_Daemon]:
        with _serve(self.cfg, os_=os_ if os_ is not None else self.os_, clock=self.clock, mono=self.mono) as d:
            yield d

    @contextlib.contextmanager
    def offline_rt(self) -> Iterator[Any]:
        rt = reopen_kernel_job_runtime(self.cfg.data_root, self.store_id, self.os_)
        try:
            yield rt
        finally:
            rt.close()


def _doctor_jobs(root: DataRoot) -> list[dict[str, str]]:
    with _ro_db(root.store_db) as conn:
        rows = conn.execute(
            "SELECT job_id, owner_id, state FROM p_jobs_state WHERE kind = 'system.doctor' ORDER BY rowid"
        ).fetchall()
    return [{"job_id": str(r[0]), "owner_id": str(r[1]), "state": str(r[2])} for r in rows]


def _job_payload(root: DataRoot, job_id: str) -> dict[str, Any]:
    """The durable ``system.doctor`` payload of ``job_id`` (the scope key: trigger and checkout_root)."""
    with _ro_db(root.store_db) as conn:
        row = conn.execute("SELECT payload_digest FROM p_jobs_state WHERE job_id = ?", (job_id,)).fetchone()
    assert row is not None and row[0], f"job {job_id} has no durable payload"
    return cast(dict[str, Any], json.loads(blob_path(root.cas_dir, str(row[0])).read_bytes().decode("utf-8")))


def _doctor_runs(root: DataRoot) -> list[dict[str, Any]]:
    with _ro_db(root.store_db) as conn:
        rows = conn.execute("SELECT meta, refs FROM ledger WHERE kind = 'doctor.run' ORDER BY sequence").fetchall()
    out: list[dict[str, Any]] = []
    for meta, refs in rows:
        m = json.loads(bytes(meta).decode("utf-8"))
        m["_refs"] = json.loads(bytes(refs).decode("utf-8"))
        out.append(m)
    return out


def _wait_until(pred: Callable[[], bool], timeout_s: float) -> bool:
    end = time.monotonic() + timeout_s
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.05)
    return pred()


def _deep_health(d: _Daemon, env: _Env, token: str, key: str) -> dict[str, Any]:
    res = _submit_tool(
        d.loop, env.mono, "get_health", {"schema_version": "2.0", "deep": True, "idempotency_key": key}, token=token
    )
    assert res["ok"] is True, res
    return cast(dict[str, Any], res["data"])


def _report(d: _Daemon, env: _Env, token: str, *, wait_ms: int, checkout: Path | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {"wait_timeout_ms": wait_ms}
    if checkout is not None:
        body["checkout_root"] = str(checkout)
    return _post_operator(d.ready, env.ca_pem, "/v2/operator/doctor/report", token, body, wait_ms / 1000.0 + 8.0)


def _seed_queued_doctor_job(env: _Env, *, owner_id: str, payload: dict[str, Any]) -> str:
    """Durably enqueue a ``system.doctor`` job (daemon stopped) exactly as the daemon's enqueue path records it."""
    job_id = new_id()
    payload_bytes = canonical_json(payload)
    _, now_str = require_aware_utc(env.clock.now())
    with env.offline_rt() as rt:
        _svc, js = kernel_job_service(rt, env.clock)
        js.stage_blob(payload_bytes)

        def _op(tx: Any) -> None:
            digest = tx.hold_blob(payload_bytes, holder_id=job_id)
            tx.append_record(
                KernelRecord(
                    "job.queued",
                    {
                        "job_id": job_id,
                        "owner_id": owner_id,
                        "repo_id": None,
                        "checkout_id": None,
                        "kind": "system.doctor",
                        "payload_digest": digest,
                        "attempt": 1,
                        "retry_at": now_str,
                    },
                )
            )

        js.transact(_op)
    return job_id


def _seed_other_owner_runs(js: StagedKernelStore, transact: Callable[[Any], Any], now_str: str, n: int) -> None:
    """Append ``n`` intact ``doctor.run`` ledger records of other owners through the kernel transaction API."""
    seeds: list[tuple[str, bytes]] = []
    for i in range(n):
        run_id = new_id()
        data = canonical_json({"schema_version": 1, "doctor_run_id": run_id, "owner_id": f"other-{i:03d}"})
        js.stage_blob(data)
        seeds.append((run_id, data))

    def _op(tx: Any) -> None:
        for i, (run_id, data) in enumerate(seeds):
            digest = tx.hold_blob(data, holder_id=run_id)
            tx.append_record(
                KernelRecord(
                    "doctor.run",
                    {
                        "doctor_run_id": run_id,
                        "owner_id": f"other-{i:03d}",
                        "report_digest": digest,
                        "overall_status": "pass",
                        "recorded_at": now_str,
                        "trigger": "schedule",
                        "job_id": new_id(),
                    },
                    actor="system:doctor",
                    refs=(digest,),
                )
            )

    transact(_op)


class _RecordingTx:
    """Proxy over a kernel tx: lets a test observe/refuse ``append_record`` without touching the real commit logic."""

    def __init__(self, inner: Any, on_append: Callable[[KernelRecord], None]) -> None:
        self._inner = inner
        self._on_append = on_append

    def append_record(self, record: KernelRecord) -> Any:
        self._on_append(record)
        return self._inner.append_record(record)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


class _ReadGate:
    """Blocks every background doctor ``read_snapshot`` while armed so jobs stay leased/running."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.armed = threading.Event()
        self.release = threading.Event()
        self.entered = threading.Event()
        orig = StorageDoctorReader.read_snapshot
        gate = self

        def _gated(self_r: Any, *a: Any, **kw: Any) -> Any:
            if gate.armed.is_set():
                gate.entered.set()
                gate.release.wait(timeout=BOUND_WAIT_S * 6)
            return orig(self_r, *a, **kw)

        monkeypatch.setattr(StorageDoctorReader, "read_snapshot", _gated)


def _checkout(env: _Env, name: str) -> Path:
    co = env.cfg.data_root.parent / name
    co.mkdir(parents=True, exist_ok=True)
    env.os_.permissions.secure_directory(co)
    return co


# ---------------------------------------------------------------------------
# F4: startup self-check uses the same fences as deep health
# ---------------------------------------------------------------------------


def _offline_restore(env: _Env, kind: str, backup: Path) -> None:
    backend = ensure_maintenance_backend()
    prev = restore_offline_preview_payload(
        env.cfg.data_root, env.os_, target=cast(Any, kind), backup=backup, store_id=env.store_id, backend=backend
    )
    ch = cast(dict[str, Any], prev.get("challenge", prev))
    migs = KERNEL_POLICY_MIGRATIONS if kind == "policy" else KERNEL_STORE_MIGRATIONS
    manifest = verify_backup(
        backup, expected_kind=cast(Any, kind), expected_store_id=env.store_id, migrations=migs, os_=env.os_
    )
    msg = _restore_msg(env.store_id, OWNER_DAN, ch, manifest.db_digest)
    approval = {
        "message": msg.to_dict(),
        "channel": ApprovalChannel.SSH_KEY.value,
        "signer_id": env.rep.signer.signer_id,
        "signature": _ssh_sig_b64(env.priv, msg.canonical_bytes()),
    }
    restore_offline(
        env.cfg.data_root,
        env.store_id,
        env.os_,
        target=cast(Any, kind),
        backup=backup,
        approval_payload=cast(Any, approval),
        ssh_verifier=make_lazy_ssh_verifier(env.os_),
        backend=backend,
    )


@pytest.mark.parametrize(
    "change",
    [
        "restart",
        "offline_store",
        "offline_policy",
        "offline_store_then_policy",
        "offline_policy_then_store",
        "reset_signers",
    ],
)
def test_f4_startup_self_check_ignores_run_of_other_writer_epoch_restore_or_trust_generation(
    trusted_tmp: Path, change: str
) -> None:
    """A DoctorRun (< 24 h old) that deep health treats as invalid must not suppress the startup self-check."""
    env = _Env(trusted_tmp, f"f4-{change}")
    with env.serve() as d1:
        assert d1.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        runs1 = _doctor_runs(env.root)
        assert len(runs1) == 1, runs1
        # Control: inside the same writer epoch a fresh, valid run suppresses another scheduled run.
        env.clock.advance(timedelta(hours=1))
        d1.loop.run_owner_action(lambda: None).result(timeout=BOUND_WAIT_S)
        assert d1.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        assert len(_doctor_runs(env.root)) == 1, "control: same-epoch fresh run must suppress a duplicate run"
    old_run_id = runs1[0]["doctor_run_id"]

    if change.startswith("offline"):
        with env.offline_rt() as rt:
            store_bak = create_store_backup(rt.store, env.os_, env.clock.now())
            policy_bak = create_policy_backup(rt.policy, env.os_, env.clock.now())
        order = {
            "offline_store": ["store"],
            "offline_policy": ["policy"],
            "offline_store_then_policy": ["store", "policy"],
            "offline_policy_then_store": ["policy", "store"],
        }[change]
        for kind in order:
            _offline_restore(env, kind, store_bak if kind == "store" else policy_bak)
    elif change == "reset_signers":
        priv2, enrollment2 = _ssh_signer_key(OWNER_DAN)
        reset_signers(env.rep.daemon_config_path, enrollment2, env.os_)
        env.priv = priv2

    base_count = len(_doctor_runs(env.root))
    assert any(r["doctor_run_id"] == old_run_id for r in _doctor_runs(env.root)), "precondition: old run in ledger"

    with env.serve() as d2:
        d2.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        _wait_until(lambda: len(_doctor_runs(env.root)) > base_count, 3.0)
        runs2 = _doctor_runs(env.root)
        health = _deep_health(d2, env, env.cli_token, f"idem_i4_f4_{change}_01")

    new_runs = runs2[base_count:]
    assert new_runs, (
        f"F4 ({change}): the daemon started with only a DoctorRun from before the change "
        f"(writer epoch / restore / trust generation) and committed no startup self-check; ledger runs={len(runs2)}"
    )
    assert new_runs[-1]["trigger"] == "startup", new_runs
    assert health.get("doctor_run_id") not in (None, old_run_id), (
        f"F4 ({change}): deep health after startup must reference the new self-check, got {health}"
    )


# ---------------------------------------------------------------------------
# F5: one durable scope, one active slot; scope read from the durable payload
# ---------------------------------------------------------------------------


def test_f5a_cli_report_reuses_durable_job_of_same_owner_and_checkout_after_restart(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A queued (owner, X) job enqueued before this process started (no RAM entry) is the slot CLI (owner, X) joins."""
    env = _Env(trusted_tmp, "f5a")
    co = _checkout(env, "repo-x")
    seeded = _seed_queued_doctor_job(
        env, owner_id=OWNER_DAN, payload={"schema": 1, "trigger": "cli", "checkout_root": str(co)}
    )
    gate = _ReadGate(monkeypatch)
    gate.armed.set()
    try:
        with env.serve() as d:
            assert _wait_until(
                lambda: any(j["job_id"] == seeded and j["state"] in NON_TERMINAL for j in _doctor_jobs(env.root)),
                BOUND_WAIT_S,
            )
            before = {j["job_id"] for j in _doctor_jobs(env.root)}
            env1 = _report(d, env, env.cli_token, wait_ms=0, checkout=co)
            env2 = _report(d, env, env.cli_token, wait_ms=0, checkout=co)
            after = _doctor_jobs(env.root)
            payloads = {j["job_id"]: _job_payload(env.root, j["job_id"]) for j in after}
            gate.release.set()
    finally:
        gate.release.set()
    ids = [cast(dict[str, Any], e.get("data") or {}).get("job_id") for e in (env1, env2)]
    # The store owner's own (dan, None) startup self-check is required after a restart (F4, F5d); any other newly
    # enqueued job (above all a second (dan, X) job) breaks the one-slot-per-scope invariant.
    extra = [
        {**j, "payload": payloads[j["job_id"]]}
        for j in after
        if j["job_id"] not in before
        and not (
            j["owner_id"] == OWNER_DAN
            and payloads[j["job_id"]].get("trigger") == "startup"
            and payloads[j["job_id"]].get("checkout_root") is None
        )
    ]
    assert ids == [seeded, seeded] and not extra, (
        f"F5a: CLI report for ({OWNER_DAN}, {co.name}) must join the durable active job {seeded}; "
        f"got job ids {ids}, newly enqueued {extra}"
    )


def test_f5b_deep_health_does_not_return_job_of_a_checkout_scoped_cli_run(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Deep health for (owner, no checkout) never answers with the job id of a CLI run scoped to checkout X."""
    env = _Env(trusted_tmp, "f5b")
    co = _checkout(env, "repo-x")
    gate = _ReadGate(monkeypatch)
    try:
        with env.serve() as d:
            assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
            env.clock.advance(timedelta(minutes=16))  # beyond the operator reuse window, inside the 24 h window
            gate.armed.set()
            rep_env = _report(d, env, env.cli_token, wait_ms=0, checkout=co)
            cli_job = cast(dict[str, Any], rep_env.get("data") or {}).get("job_id")
            assert isinstance(cli_job, str) and cli_job, rep_env
            assert gate.entered.wait(timeout=BOUND_WAIT_S), "the CLI job never reached the worker"
            health = _deep_health(d, env, env.cli_token, "idem_i4_f5b_health_01")
            gate.release.set()
    finally:
        gate.release.set()
    assert health.get("job_id") != cli_job, (
        f"F5b: deep health for ({OWNER_DAN}, None) returned the job id {cli_job} of the CLI run scoped to "
        f"{co.name}: {health}"
    )


@pytest.mark.parametrize("seeded_scope", ["same_scope", "other_checkout"])
def test_f5c_cli_report_without_checkout_joins_only_its_own_durable_scope(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, seeded_scope: str
) -> None:
    """A CLI (owner, None) report joins a durable (owner, None) deep-health job (control) and never a durable
    (owner, X) job whose scope is only in its payload (no RAM entry in this process)."""
    env = _Env(trusted_tmp, f"f5c-{seeded_scope}")
    if seeded_scope == "other_checkout":
        co = _checkout(env, "repo-x")
        seeded = _seed_queued_doctor_job(
            env, owner_id=OWNER_DAN, payload={"schema": 1, "trigger": "cli", "checkout_root": str(co)}
        )
    else:
        seeded = _seed_queued_doctor_job(env, owner_id=OWNER_DAN, payload={"schema": 1, "trigger": "get_health"})
    gate = _ReadGate(monkeypatch)
    gate.armed.set()
    try:
        with env.serve() as d:
            assert _wait_until(
                lambda: any(j["job_id"] == seeded for j in _doctor_jobs(env.root)), BOUND_WAIT_S
            )
            health = _deep_health(d, env, env.cli_token, "idem_i4_f5c_health_01")
            rep_env = _report(d, env, env.cli_token, wait_ms=0)
            jobs = _doctor_jobs(env.root)
            gate.release.set()
    finally:
        gate.release.set()
    cli_job = cast(dict[str, Any], rep_env.get("data") or {}).get("job_id")
    active_none_scope = [j for j in jobs if j["owner_id"] == OWNER_DAN and j["state"] in NON_TERMINAL]
    if seeded_scope == "other_checkout":
        answers = (("CLI report", cli_job), ("deep health", health.get("job_id")))
        leaked = [label for label, jid in answers if jid == seeded]
        assert not leaked, (
            f"F5c: {leaked} for ({OWNER_DAN}, None) returned the durable job {seeded} scoped to checkout repo-x"
        )
        return
    assert cli_job == health.get("job_id") and cli_job is not None, (
        f"F5c: CLI report ({OWNER_DAN}, None) job {cli_job} differs from the deep-health/startup slot "
        f"{health.get('job_id')}; seeded deep-health job {seeded}; active dan jobs {active_none_scope}"
    )


@pytest.mark.parametrize("other", ["other_checkout", "other_owner"])
def test_f5d_startup_schedule_not_blocked_by_job_of_other_scope(trusted_tmp: Path, other: str) -> None:
    """The startup self-check dedups only on its own (store owner, None) scope."""
    env = _Env(trusted_tmp, f"f5d-{other}")
    if other == "other_checkout":
        co = _checkout(env, "repo-x")
        _seed_queued_doctor_job(
            env, owner_id=OWNER_DAN, payload={"schema": 1, "trigger": "cli", "checkout_root": str(co)}
        )
    else:
        _seed_queued_doctor_job(env, owner_id=OTHER_OWNER, payload={"schema": 1, "trigger": "get_health"})
    with env.serve() as d:
        d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        _wait_until(
            lambda: any(r["owner_id"] == OWNER_DAN and r["trigger"] == "startup" for r in _doctor_runs(env.root)),
            BOUND_WAIT_S,
        )
        runs = _doctor_runs(env.root)
    startup = [r for r in runs if r["owner_id"] == OWNER_DAN and r["trigger"] == "startup"]
    assert startup, (
        f"F5d ({other}): a queued job of another scope blocked the store owner's startup self-check; "
        f"runs={[(r['owner_id'], r['trigger']) for r in runs]}"
    )


# ---------------------------------------------------------------------------
# F6: transient commit error is retried, never INTEGRITY_FAILURE; the job never stays RUNNING
# ---------------------------------------------------------------------------


def _patch_doctor_commit_failure(monkeypatch: pytest.MonkeyPatch, code: ErrorCode) -> threading.Event:
    """Make the next ``doctor.run`` append (the DoctorRun commit) raise ``BrainError(code)`` once."""
    fired = threading.Event()
    armed = threading.Event()
    orig = StagedKernelStore.transact

    def _transact(self: StagedKernelStore, operation: Callable[[Any], Any]) -> Any:
        def _on_append(record: KernelRecord) -> None:
            if armed.is_set() and record.kind == "doctor.run" and not fired.is_set():
                fired.set()
                raise BrainError(code, "injected commit failure")

        return orig(self, lambda tx: operation(_RecordingTx(tx, _on_append)))

    monkeypatch.setattr(StagedKernelStore, "transact", _transact)
    return armed


def test_f6_transient_store_busy_at_doctor_commit_is_retried_not_integrity_failure(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = _Env(trusted_tmp, "f6-busy")
    armed = _patch_doctor_commit_failure(monkeypatch, ErrorCode.STORE_BUSY)
    with env.serve() as d:
        assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        env.clock.advance(timedelta(minutes=16))
        armed.set()
        first = _report(d, env, env.cli_token, wait_ms=3_000)
        data = cast(dict[str, Any], first.get("data") or {})
        err = cast(dict[str, Any], first.get("error") or {})
        assert err.get("code") != ErrorCode.INTEGRITY_FAILURE.value, (
            f"F6: a transient STORE_BUSY at the DoctorRun commit surfaced as INTEGRITY_FAILURE: {first}"
        )
        retryable_error = first.get("ok") is False and err.get("code") == ErrorCode.STORE_BUSY.value
        assert retryable_error or (first.get("ok") is True and data.get("status") in {"completed", "running"}), first
        job_id = data.get("job_id") or _doctor_jobs(env.root)[-1]["job_id"]
        # Let any retry backoff elapse; the same report must then complete.
        for _ in range(6):
            env.clock.advance(timedelta(minutes=5))
            d.loop.run_owner_action(lambda: None).result(timeout=BOUND_WAIT_S)
            d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
            if not any(j["state"] in NON_TERMINAL for j in _doctor_jobs(env.root) if j["job_id"] == job_id):
                break
        jobs = {j["job_id"]: j["state"] for j in _doctor_jobs(env.root)}
        runs = [r for r in _doctor_runs(env.root) if r.get("job_id") == job_id]
    assert jobs.get(str(job_id)) == "succeeded" and runs, (
        f"F6: the job hit by a transient commit error must be retried to success; job state={jobs.get(str(job_id))}, "
        f"runs for job={len(runs)}"
    )


def test_f6_control_non_transient_commit_error_ends_job_failed(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = _Env(trusted_tmp, "f6-hard")
    armed = _patch_doctor_commit_failure(monkeypatch, ErrorCode.INTEGRITY_FAILURE)
    with env.serve() as d:
        assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        env.clock.advance(timedelta(minutes=16))
        armed.set()
        res = _report(d, env, env.cli_token, wait_ms=5_000)
        _wait_until(lambda: not any(j["state"] in NON_TERMINAL for j in _doctor_jobs(env.root)), BOUND_WAIT_S)
        jobs = _doctor_jobs(env.root)
    assert res.get("ok") is False, res
    assert not [j for j in jobs if j["state"] in NON_TERMINAL], jobs
    assert any(j["state"] == "failed" for j in jobs), jobs


# ---------------------------------------------------------------------------
# F7: ledger scan limits never silently hide the owner's run
# ---------------------------------------------------------------------------

SEED_OTHER_RUNS = 200


def test_f7_fresh_run_found_behind_many_other_owner_runs(trusted_tmp: Path) -> None:
    env = _Env(trusted_tmp, "f7-fresh")
    with env.serve() as d:
        assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        target = [r for r in _doctor_runs(env.root) if r["owner_id"] == OWNER_DAN]
        assert len(target) == 1, target
        target_run = target[0]["doctor_run_id"]
        _, now_str = require_aware_utc(env.clock.now())
        ctrl = cast(dict[str, Any], _report(d, env, env.cli_token, wait_ms=0).get("data") or {})
        assert ctrl.get("doctor_run_id") == target_run, f"control: fresh run reused before seeding: {ctrl}"

        def _seed() -> None:
            rt = d.rt
            js = StagedKernelStore(rt.store, rt.policy, writer_epoch=rt.lease.epoch)
            _seed_other_owner_runs(js, js.transact, now_str, SEED_OTHER_RUNS)

        d.loop.run_owner_action(_seed).result(timeout=BOUND_WAIT_S)
        assert len(_doctor_runs(env.root)) == SEED_OTHER_RUNS + 1
        jobs_before = len(_doctor_jobs(env.root))
        rep_env = _report(d, env, env.cli_token, wait_ms=0)
        jobs_after_cli = len(_doctor_jobs(env.root))
        health = _deep_health(d, env, env.cli_token, "idem_i4_f7_health_01")
        jobs_after_health = len(_doctor_jobs(env.root))

    violations: list[str] = []
    rep = cast(dict[str, Any], rep_env.get("data") or {})
    if not (rep_env.get("ok") is True and rep.get("doctor_run_id") == target_run):
        got = rep_env.get("error") or rep.get("status")
        violations.append(f"CLI report did not reuse fresh run {target_run}: {got}")
    if jobs_after_cli != jobs_before:
        violations.append(f"CLI report enqueued {jobs_after_cli - jobs_before} extra job(s)")
    if health.get("doctor_run_id") != target_run or health.get("job_id") is not None:
        violations.append(f"deep health missed fresh run {target_run}: {health}")
    if jobs_after_health != jobs_after_cli:
        violations.append(f"deep health enqueued {jobs_after_health - jobs_after_cli} extra job(s)")
    assert not violations, "F7 fresh lookup stopped at the scan limit:\n" + "\n".join(violations)


def test_f7_succeeded_job_dto_loads_behind_many_other_owner_runs(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = _Env(trusted_tmp, "f7-load")
    seeded = threading.Event()
    armed = threading.Event()
    orig = StagedKernelStore.transact

    def _transact(self: StagedKernelStore, operation: Callable[[Any], Any]) -> Any:
        saw: list[KernelRecord] = []
        result = orig(self, lambda tx: operation(_RecordingTx(tx, saw.append)))
        if (
            armed.is_set()
            and not seeded.is_set()
            and any(r.kind == "doctor.run" and r.meta.get("trigger") == "cli" for r in saw)
        ):
            seeded.set()
            _, now_str = require_aware_utc(env.clock.now())
            _seed_other_owner_runs(self, lambda op: orig(self, op), now_str, SEED_OTHER_RUNS)
        return result

    monkeypatch.setattr(StagedKernelStore, "transact", _transact)
    with env.serve() as d:
        assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        env.clock.advance(timedelta(minutes=16))
        armed.set()
        res = _report(d, env, env.cli_token, wait_ms=10_000)
    assert seeded.is_set(), "precondition: other-owner runs were seeded right after the CLI DoctorRun commit"
    data = cast(dict[str, Any], res.get("data") or {})
    assert res.get("ok") is True and data.get("status") == "completed" and data.get("doctor_run_id"), (
        f"F7: the SUCCEEDED job's committed DoctorRun was not found behind {SEED_OTHER_RUNS} other-owner runs: {res}"
    )


# ---------------------------------------------------------------------------
# F8.1: no guessed owner for scheduled/startup runs
# ---------------------------------------------------------------------------


def _drop_store_owner(env: _Env) -> None:
    with contextlib.closing(sqlite3.connect(env.root.policy_db)) as conn:
        conn.execute("DELETE FROM meta WHERE key = 'owner_id'")
        conn.execute("DELETE FROM signer")
        conn.commit()


@pytest.mark.parametrize("authoritative", [False, True])
def test_f8_1_startup_doctor_never_attributed_to_guessed_owner(trusted_tmp: Path, authoritative: bool) -> None:
    env = _Env(trusted_tmp, f"f81-{authoritative}")
    with env.offline_rt() as rt:
        seed_principal_and_credential(rt.policy, owner_id="aaa", harness_id=CLI_HARNESS_ID, machine_id=MACHINE_ID)
        if not authoritative:
            assert rt.policy.store_owner() == OWNER_DAN
    if not authoritative:
        _drop_store_owner(env)
        with env.offline_rt() as rt:
            assert rt.policy.store_owner() is None, "precondition: store has no authoritative owner"
    with env.serve() as d:
        d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        time.sleep(0.5)
        jobs = _doctor_jobs(env.root)
    owners = sorted({j["owner_id"] for j in jobs})
    if authoritative:
        assert owners == [OWNER_DAN], f"control: startup doctor must be attributed to the store owner, got {owners}"
    else:
        assert owners == [], (
            f"F8.1: with no authoritative store owner the startup doctor was attributed to a guessed owner {owners}"
        )


# ---------------------------------------------------------------------------
# F8.2: --offline trusts the writer lock over a stale endpoint.json
# ---------------------------------------------------------------------------


def _cli(args: list[str], os_: OsAdapters, capsys: pytest.CaptureFixture[str]) -> tuple[int, str]:
    capsys.readouterr()
    rc = run_doctor_cli(args, os_=os_)
    cap = capsys.readouterr()
    return rc, cap.out + cap.err


def test_f8_2_offline_doctor_runs_with_stale_endpoint_when_lock_free(
    trusted_tmp: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    env = _Env(trusted_tmp, "f82")
    args = ["doctor", "--offline", "--json", "--config", str(env.rep.daemon_config_path)]
    with env.serve():
        endpoint_bytes = env.root.endpoint_path.read_bytes()
        rc_held, out_held = _cli(args, env.os_, capsys)
    assert rc_held != 0 and ErrorCode.STORE_BUSY.value in out_held, f"control: lock held must refuse: {out_held}"

    # Simulate a crash: endpoint.json left behind, writer lock released.
    if not env.root.endpoint_path.exists():
        env.root.endpoint_path.write_bytes(endpoint_bytes)
        env.os_.permissions.secure_file(env.root.endpoint_path)
    rc, out = _cli(args, env.os_, capsys)
    assert rc == 0, f"F8.2: --offline with a stale endpoint.json and a free writer lock refused: rc={rc} out={out!r}"
    payload = json.loads(out.strip().splitlines()[0])
    assert payload.get("ok") is True and isinstance(payload.get("data"), dict), payload
    assert "overall_status" in payload["data"], payload


# ---------------------------------------------------------------------------
# F8.3: an unknown lock probe is never "not held"
# ---------------------------------------------------------------------------


class _NoProbeLocks:
    def __init__(self, inner: Any) -> None:
        self._inner = inner

    def acquire(self, path: Path) -> Any:
        return self._inner.acquire(path)


def test_f8_3_missing_lock_probe_is_not_treated_as_lock_free(
    trusted_tmp: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    env = _Env(trusted_tmp, "f83")
    cfg_path = str(env.rep.daemon_config_path)
    no_probe = replace(env.os_, locks=cast(Any, _NoProbeLocks(env.os_.locks)))

    rc_ctrl, out_ctrl = _cli(["doctor", "--offline", "--json", "--config", cfg_path], env.os_, capsys)
    assert rc_ctrl == 0, f"control: offline doctor with a real lock probe and daemon stopped: {out_ctrl}"

    violations: list[str] = []
    for mode in (["--offline"], []):
        rc, out = _cli(["doctor", *mode, "--json", "--config", cfg_path], no_probe, capsys)
        if rc == 0:
            violations.append(f"CLI {mode or ['auto']} returned a report although the lock state is unknown")
    try:
        report = run_doctor(Path(cfg_path), os_=no_probe).to_dict()
    except BrainError:
        report = None
    if report is not None:
        lock_checks = [
            c for c in cast(list[dict[str, Any]], report["checks"]) if c.get("name") == "daemon.writer_lock"
        ]
        if not lock_checks or lock_checks[0].get("status") == "PASS":
            violations.append(f"doctor snapshot reported a confident lock state without a probe: {lock_checks}")
    assert not violations, "F8.3:\n" + "\n".join(violations)


# ---------------------------------------------------------------------------
# F8.4: no dead surface in _doctor_fix_wiring
# ---------------------------------------------------------------------------


def test_f8_4_doctor_fix_wiring_has_no_dead_helpers() -> None:
    mod = importlib.import_module("superbrain.composition._doctor_fix_wiring")
    dead = [
        n
        for n in ("_count_applied_intents", "_locate_effective_db_links_checked", "_verify_offline_profile_credential")
        if hasattr(mod, n)
    ]
    exported = "run_offline_doctor_fix" in getattr(mod, "__all__", ())
    assert not dead and not exported, f"F8.4 dead surface: helpers={dead}, run_offline_doctor_fix exported={exported}"


# ---------------------------------------------------------------------------
# F8.5: no raw exception text or absolute paths in reports / persisted DoctorRun
# ---------------------------------------------------------------------------


class _LeakyPermissions:
    """``problems()`` on the data root raises an OSError that carries an absolute path, as Windows does."""

    def __init__(self, inner: Any, data_root: Path) -> None:
        self._inner = inner
        self._root = data_root

    def problems(self, root: Path) -> Any:
        if Path(root) == self._root:
            raise OSError(13, "Access is denied", SECRET_PATH, 5)
        return self._inner.problems(root)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def test_f8_5_doctor_report_and_doctor_run_hide_exception_text_and_paths(trusted_tmp: Path) -> None:
    env = _Env(trusted_tmp, "f85")
    leaky = replace(env.os_, permissions=cast(Any, _LeakyPermissions(env.os_.permissions, env.cfg.data_root)))

    report = run_doctor(env.rep.daemon_config_path, os_=leaky).to_dict()
    text = json.dumps(report)
    errors = cast(list[str], report.get("integrity_errors") or [])

    with env.serve(leaky) as d:
        assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        runs = _doctor_runs(env.root)
    assert runs, "precondition: the startup DoctorRun was committed"
    blob = blob_path(env.root.cas_dir, runs[-1]["_refs"][0]).read_bytes().decode("utf-8")

    violations: list[str] = []
    for label, body in (("offline report", text), ("persisted DoctorRun", blob)):
        for needle in (SECRET_FRAGMENT, "Access is denied", "WinError"):
            if needle in body:
                violations.append(f"{label} contains raw exception text {needle!r}")
    if not any("permission" in e.lower() for e in errors):
        violations.append(f"offline report lost the stable permission error label: {errors}")
    assert not violations, "F8.5:\n" + "\n".join(violations)


# ---------------------------------------------------------------------------
# F8.6: log rotation recovery when bytes were appended after the digest
# ---------------------------------------------------------------------------


def _pending_rotation(logs: Path, os_: OsAdapters, recorded: bytes, staged: bytes) -> str:
    logs.mkdir(parents=True, exist_ok=True)
    os_.permissions.secure_directory(logs)
    rot_id = new_id()
    state = {
        "id": rot_id,
        "phase": "pending_move",
        "size": len(recorded),
        "digest": digest_bytes(recorded).removeprefix("sha256:"),
        "shift_order": [],
    }
    state_path = logs / f".rotate-state-{rot_id}.json"
    state_path.write_bytes(json.dumps(state, sort_keys=True).encode("utf-8"))
    os_.permissions.secure_file(state_path)
    staged_path = logs / f".brain.log.rotating-{rot_id}"
    staged_path.write_bytes(staged)
    os_.permissions.secure_file(staged_path)
    return rot_id


def test_f8_6_rotation_recovery_keeps_bytes_appended_after_digest(trusted_tmp: Path) -> None:
    os_ = os_adapters()
    logs = trusted_tmp / "f86-logs"
    prefix = b"line-1 recorded before the digest\nline-2 recorded\n"
    appended = b"line-3 appended after the digest\n"
    _pending_rotation(logs, os_, prefix, prefix + appended)
    try:
        rotate_logs(logs, os_)
    except BrainError as err:
        pytest.fail(f"F8.6: recovery of a staged log with appended bytes failed with {err.code.value}")
    rotated = logs / "brain.log.1"
    assert rotated.is_file() and rotated.read_bytes() == prefix + appended, (
        "F8.6: recovered rotation lost bytes appended after the digest"
    )
    assert not list(logs.glob(".brain.log.rotating-*")) and not list(logs.glob(".rotate-state-*")), sorted(
        p.name for p in logs.iterdir()
    )


def test_f8_6_control_rotation_recovery_rejects_mismatched_prefix(trusted_tmp: Path) -> None:
    os_ = os_adapters()
    logs = trusted_tmp / "f86-neg"
    prefix = b"line-1 recorded before the digest\nline-2 recorded\n"
    _pending_rotation(logs, os_, prefix, b"LINE-1 tampered before the digest\nline-2 recorded\nline-3\n")
    with pytest.raises(BrainError) as err:
        rotate_logs(logs, os_)
    assert err.value.code is ErrorCode.INTEGRITY_FAILURE


# ---------------------------------------------------------------------------
# F8.7: doctor --fix is authorized per action (store owner only)
# ---------------------------------------------------------------------------


def test_f8_7_doctor_fix_refused_for_non_store_owner_operator(trusted_tmp: Path) -> None:
    env = _Env(trusted_tmp, "f87")
    with env.offline_rt() as rt:
        eve = seed_principal_and_credential(
            rt.policy, owner_id=OTHER_OWNER, harness_id=CLI_HARNESS_ID, machine_id=MACHINE_ID
        )
    body = {"actions": ["tighten_permissions"]}
    with env.serve() as d:
        assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        target, _tight, widened = _widen_target(env.root, env.os_)
        res_eve = _post_operator(d.ready, env.ca_pem, "/v2/operator/doctor/fix", eve.token, body, 15.0)
        acl_after_eve = _acl_or_mode(target)
        res_dan = _post_operator(d.ready, env.ca_pem, "/v2/operator/doctor/fix", env.cli_token, body, 15.0)
        acl_after_dan = _acl_or_mode(target)
    violations: list[str] = []
    if res_eve.get("ok") is not False:
        violations.append(f"non-owner operator {OTHER_OWNER!r} was allowed to run doctor --fix: {res_eve.get('data')}")
    if acl_after_eve != widened:
        violations.append("non-owner doctor --fix changed the store (widened target was tightened)")
    assert not violations, "F8.7:\n" + "\n".join(violations)
    assert res_dan.get("ok") is True and acl_after_dan != widened, f"control: store owner fix must apply: {res_dan}"
