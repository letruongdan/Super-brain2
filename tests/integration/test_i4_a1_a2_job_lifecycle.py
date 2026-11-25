"""Independent RED oracle for SP1 Increment 4 Package A (A1 & A2 job lifecycle reconciliation).

Requirement source: ``docs/superpowers/plans/2026-11-25-sp1-increment4-acceptance-handoff.md`` (§2.A).

Invariants under test:
- A1.1: Lost ACK after ``job.leased`` commit on an idle doctor-only daemon (``has_job_handlers=False``) wakes
  cleanly without a new client poke, reconciles the orphaned ``LEASED`` job in the current writer epoch,
  commits one ``DoctorRun`` + ``SUCCEEDED``, and settles.
- A1.2: Lost ACK after ``job.leased`` commit with >120 ``queued`` ``system.doctor`` backlog jobs still
  reconciles and completes the leased doctor job (not shadowed by ``active_jobs_by_kinds(..., limit=100)``).
- A1.3: ``lease_next_for_kinds`` rollback before commit leaves no ghost runner state and claims normally on recovery.
- A2.1: ``commit_doctor_run_snapshot`` lost ACK after ``SUCCEEDED`` commit (transient ``STORE_BUSY`` or
  non-transient ``BrainError``) never overwrites cache with ``"failed"``, reconciles SQLite +
  ``iter_owner_doctor_ledger``, caches ``("succeeded", doctor_run_id)``, clears ``_fix_dirty``, and settles.
- A2.2: ``_end_failed`` / ``_abandon_launch`` rollback on ``STORE_BUSY`` never poisons cache with ``"failed"`` or
  surfaces ``INTEGRITY_FAILURE`` while ``RUNNING``; once ``STORE_BUSY`` clears, reconciliation commits ``FAILED``.
- A2.3: Attempt-3 ``_end_failed(..., retryable=True)`` -> ``DEAD_LETTER`` (clean commit and lost ACK) caches
  ``("dead_letter", None)`` and wakes waiters immediately instead of hanging until ``wait_timeout_ms``.
- A2.4: ``fence_on_restore`` / ``rebind_after_restore`` / online restore clears ``_finished_jobs`` so stale
  terminal cache from a prior epoch/store never leaks post-restore.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest

from superbrain.adapters.os.daemon_config import read_client_endpoint
from superbrain.application.jobs import JobService
from superbrain.composition import _daemon_doctor
from superbrain.composition._daemon_doctor import DaemonDoctorRunner
from superbrain.composition._daemon_health import find_active_doctor_job, load_committed_doctor_run_dto
from superbrain.core._kernel_jobs import MAX_JOB_ATTEMPTS, retry_backoff
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import KernelRecord, ShutdownState, require_aware_utc
from superbrain.storage._doctor_reader import StorageDoctorReader
from superbrain.storage.backup import create_store_backup
from superbrain.storage.cas import blob_path
from superbrain.storage.idempotency import StagedKernelStore
from superbrain.workers.executor import JobHandler
from tests.integration.test_doctor_jobs import BOUND_WAIT_S, OWNER_DAN, _ro_db
from tests.integration.test_i4_f4_f8_remediation import (
    OTHER_OWNER,
    _doctor_jobs,
    _doctor_runs,
    _Env,
    _RecordingTx,
    _report,
    _wait_until,
)
from tests.integration.test_i4_owner_thread_remediation import DOCTOR_WORKER_PREFIX, _post_operator
from tests.integration.test_i4_r3_remediation import _serve
from tests.integration.test_i4_r9_doctor_payload_fault_classification import (
    DELAY,
    DOCTOR_KIND,
    PROMPT_S,
    WAIT_MS,
    _blocked_report,
    _durable,
    _err_code,
    _inject_after_commit_once,
    _poke_until,
    _runs_for,
)
from tests.integration.test_i4_rereview_remediation import _Daemon
from tests.integration.test_i4_review_remediation import _run_online_restore_helper

WAKE_BUDGET_S = 5.0


def _runner(d: _Daemon) -> DaemonDoctorRunner:
    session = cast(Any, d.loop)._session
    assert session is not None and session._doctor_runner is not None
    return cast(DaemonDoctorRunner, session._doctor_runner)


def _fault_lease_ack_once(
    monkeypatch: pytest.MonkeyPatch, *, target_job_id: str | None = None
) -> tuple[threading.Event, list[str]]:
    """Let ``lease_next_for_kinds`` commit ``job.leased`` to SQLite once, then raise ``STORE_BUSY``."""
    orig = JobService.lease_next_for_kinds
    fired = threading.Event()
    leased_ids: list[str] = []

    def _wrapped(
        self: JobService,
        epoch: int,
        now: datetime,
        kinds: Sequence[str],
        *,
        emit_crashpoints: bool = True,
        exclude: bool = False,
        commit_guard: Callable[[], bool] | None = None,
    ) -> Any:
        lease = orig(
            self, epoch, now, kinds, emit_crashpoints=emit_crashpoints, exclude=exclude, commit_guard=commit_guard
        )
        if lease is not None and not fired.is_set() and (target_job_id is None or lease.job_id == target_job_id):
            leased_ids.append(lease.job_id)
            fired.set()
            raise BrainError(ErrorCode.STORE_BUSY, "injected lost lease ack after commit")
        return lease

    monkeypatch.setattr(JobService, "lease_next_for_kinds", _wrapped)
    return fired, leased_ids


def _fault_tx_record_gate(
    monkeypatch: pytest.MonkeyPatch,
    job_id: str,
    record_kind: str,
    hold: threading.Event,
    *,
    required_state: str | None = None,
) -> list[int]:
    """Raise ``STORE_BUSY`` before commit for ``record_kind`` targeting ``job_id`` while ``hold`` is set."""
    orig = StagedKernelStore.transact
    hits = [0]

    def _on_append(record: KernelRecord) -> None:
        if (
            hold.is_set()
            and record.kind == record_kind
            and record.meta.get("job_id") == job_id
            and (required_state is None or record.meta.get("state") == required_state)
        ):
            hits[0] += 1
            raise BrainError(ErrorCode.STORE_BUSY, f"injected {record_kind} rollback before commit")

    def _transact(self: StagedKernelStore, operation: Callable[[Any], Any]) -> Any:
        return orig(self, lambda tx: operation(_RecordingTx(tx, _on_append)))

    monkeypatch.setattr(StagedKernelStore, "transact", _transact)
    return hits


def _fault_commit_run_ack_once(
    monkeypatch: pytest.MonkeyPatch, code: ErrorCode
) -> tuple[threading.Event, list[tuple[str, str]]]:
    """Commit ``doctor.run`` + ``job.terminal(succeeded)`` to SQLite once, then raise ``BrainError(code)``."""
    orig = StagedKernelStore.transact
    fired = threading.Event()
    committed: list[tuple[str, str]] = []

    def _transact(self: StagedKernelStore, operation: Callable[[Any], Any]) -> Any:
        seen_run: list[tuple[str, str]] = []
        seen_succeeded = [False]

        def _on_append(record: KernelRecord) -> None:
            if record.kind == "doctor.run":
                seen_run.append((str(record.meta["job_id"]), str(record.meta["doctor_run_id"])))
            elif record.kind == "job.terminal" and record.meta.get("state") == "succeeded":
                seen_succeeded[0] = True

        res = orig(self, lambda tx: operation(_RecordingTx(tx, _on_append)))
        if seen_run and seen_succeeded[0] and not fired.is_set():
            committed.extend(seen_run)
            fired.set()
            raise BrainError(code, "injected post-commit snapshot lost ack")
        return res

    monkeypatch.setattr(StagedKernelStore, "transact", _transact)
    return fired, committed


def _enqueue_jobs_on_owner(
    d: _Daemon, env: _Env, *, owner_id: str, count: int, delay: timedelta, tag: str
) -> list[str]:
    """Seed ``count`` queued ``system.doctor`` jobs due after ``delay`` via the live owner job store."""
    payload = canonical_json({"schema": 1, "trigger": "manual", "checkout_root": None, "tag": tag})
    now_utc, _ = require_aware_utc(env.clock.now())
    retry_at = require_aware_utc(now_utc + delay)[1]
    job_ids = [new_id() for _ in range(count)]

    def _seed() -> None:
        session = cast(Any, d.loop)._session
        assert session is not None
        js = cast(StagedKernelStore, session._job_store)
        js.stage_blob(payload)

        def _op(tx: Any) -> None:
            for jid in job_ids:
                digest = tx.hold_blob(payload, holder_id=jid)
                tx.append_record(
                    KernelRecord(
                        "job.queued",
                        {
                            "job_id": jid,
                            "owner_id": owner_id,
                            "repo_id": None,
                            "checkout_id": None,
                            "kind": DOCTOR_KIND,
                            "payload_digest": digest,
                            "attempt": 1,
                            "retry_at": retry_at,
                        },
                    )
                )

        js.transact(_op)

    d.loop.run_owner_action(_seed).result(timeout=BOUND_WAIT_S)
    return job_ids


# ---------------------------------------------------------------------------
# A1: Lost ACK of job.leased & rollback recovery
# ---------------------------------------------------------------------------


def test_a1_1_lost_lease_ack_wakes_idle_doctor_daemon_and_settles(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Idle doctor-only daemon (has_job_handlers=False) reconciles orphaned LEASED job without client pokes."""
    env = _Env(trusted_tmp, "a11-lost-lease-ack")
    fired, leased_ids = _fault_lease_ack_once(monkeypatch)
    with env.serve() as d:
        session = cast(Any, d.loop)._session
        assert session is not None and session.has_job_handlers is False
        assert fired.wait(timeout=BOUND_WAIT_S), "precondition: startup lease_next_for_kinds lost ACK must fire"
        job_id = leased_ids[0]
        # No new client poke and no wait_doctor_settled poll: read-only SQLite check only.
        assert _wait_until(lambda: _durable(env, job_id)[0] == "succeeded", WAKE_BUDGET_S), (
            f"A1.1: idle daemon failed to wake and reconcile leased job {job_id}: {_durable(env, job_id)}"
        )
        assert _durable(env, job_id) == ("succeeded", 1, None)
        runs = _runs_for(env, job_id)
        assert len(runs) == 1, f"expected one DoctorRun for {job_id}, got {len(runs)}"
        run_id = str(runs[0]["doctor_run_id"])
        assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S) is True
        rep = _report(d, env, env.cli_token, wait_ms=0)
    data = cast(dict[str, Any], rep.get("data") or {})
    assert rep.get("ok") is True and data.get("status") == "completed", rep
    assert data.get("doctor_run_id") == run_id and data.get("job_id") == job_id, rep


def test_a1_2_lost_lease_ack_reconciles_behind_over_100_queued_jobs(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Claimed-state reconciliation must not be shadowed by >100 queued jobs ahead in p_jobs_state."""
    env = _Env(trusted_tmp, "a12-backlog")
    with env.serve() as d:
        assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        env.clock.advance(timedelta(minutes=16))
        target_job_id = _enqueue_jobs_on_owner(d, env, owner_id=OWNER_DAN, count=1, delay=DELAY, tag="a12-target")[0]
        backlog_ids = _enqueue_jobs_on_owner(
            d, env, owner_id=OTHER_OWNER, count=125, delay=timedelta(hours=2), tag="a12-backlog"
        )
        with _blocked_report(d, env, monkeypatch) as waiter:
            fired, _ = _fault_lease_ack_once(monkeypatch, target_job_id=target_job_id)
            env.clock.advance(DELAY + timedelta(milliseconds=1))
            d.loop.run_owner_action(lambda: None).result(timeout=BOUND_WAIT_S)
            assert fired.wait(timeout=BOUND_WAIT_S), "precondition: lost ACK on target doctor lease must fire"
            with _ro_db(env.root.store_db) as conn:
                top_100 = {
                    str(r[0])
                    for r in conn.execute(
                        "SELECT job_id FROM p_jobs_state "
                        "WHERE state IN ('queued', 'leased', 'running') AND kind = ? "
                        "ORDER BY sequence, job_id LIMIT 100",
                        (DOCTOR_KIND,),
                    ).fetchall()
                }
            assert target_job_id not in top_100, "precondition: target leased job must be shadowed beyond LIMIT 100"
            assert _wait_until(lambda: _durable(env, target_job_id)[0] == "succeeded", WAKE_BUDGET_S), (
                f"A1.2: shadowed leased job stayed {_durable(env, target_job_id)}"
            )
            assert _wait_until(lambda: waiter.done_at is not None, PROMPT_S), "blocked report waiter did not wake"
        runs = _runs_for(env, target_job_id)
        assert _durable(env, target_job_id) == ("succeeded", 1, None)
        assert len(runs) == 1
        data = cast(dict[str, Any], waiter.res.get("data") or {})
        assert waiter.res.get("ok") is True and data.get("status") == "completed", waiter.res
        assert data.get("job_id") == target_job_id and data.get("doctor_run_id") == runs[0]["doctor_run_id"]
        with _ro_db(env.root.store_db) as conn:
            queued_backlog = conn.execute(
                "SELECT COUNT(*) FROM p_jobs_state WHERE owner_id = ? AND state = 'queued'", (OTHER_OWNER,)
            ).fetchone()
        assert queued_backlog is not None and int(queued_backlog[0]) == len(backlog_ids)


def test_a1_3_lease_rollback_leaves_no_ghost_state_and_recovers(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pre-commit rollback of lease_next_for_kinds leaves no ghost state and claims normally once cleared."""
    env = _Env(trusted_tmp, "a13-rollback")
    with env.serve() as d:
        assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        env.clock.advance(timedelta(minutes=16))
        job_id = _enqueue_jobs_on_owner(d, env, owner_id=OWNER_DAN, count=1, delay=DELAY, tag="a13-target")[0]
        runner = _runner(d)
        hold = threading.Event()
        hold.set()
        rollbacks = _fault_tx_record_gate(monkeypatch, job_id, "job.leased", hold)
        with _blocked_report(d, env, monkeypatch) as waiter:
            env.clock.advance(DELAY + timedelta(milliseconds=1))
            d.loop.run_owner_action(lambda: None).result(timeout=BOUND_WAIT_S)
            assert _wait_until(lambda: rollbacks[0] >= 1, BOUND_WAIT_S), "precondition: lease rollback did not fire"
            time.sleep(0.1)
            state_during = _durable(env, job_id)
            assert state_during == ("queued", 1, None), f"ghost DB state after rollback: {state_during}"
            with runner._lock:
                assert runner._pending_lease is None
                assert runner._active_lease is None
                assert runner._active_token is None
                assert job_id not in runner._finished_jobs
            assert waiter.done_at is None, f"waiter answered prematurely during lease rollback: {waiter.res}"
            hold.clear()
            assert _wait_until(lambda: _durable(env, job_id)[0] == "succeeded", WAKE_BUDGET_S), (
                f"A1.3: job did not recover after rollback cleared: {_durable(env, job_id)}"
            )
            assert _wait_until(lambda: waiter.done_at is not None, PROMPT_S)
        runs = _runs_for(env, job_id)
        assert _durable(env, job_id) == ("succeeded", 1, None)
        assert len(runs) == 1
        data = cast(dict[str, Any], waiter.res.get("data") or {})
        assert waiter.res.get("ok") is True and data.get("status") == "completed", waiter.res
        assert data.get("doctor_run_id") == runs[0]["doctor_run_id"]
        assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S) is True


# ---------------------------------------------------------------------------
# A2: Snapshot commit lost ACK, failed complete rollback, attempt-3 dead-letter, restore cache isolation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("error_code", [ErrorCode.STORE_BUSY, ErrorCode.IO_ERROR])
def test_a2_1_commit_snapshot_lost_ack_reconciles_run_and_clears_dirty(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, error_code: ErrorCode
) -> None:
    """Post-commit BrainError from commit_doctor_run_snapshot never caches failed; reconciles SUCCEEDED + dirty."""
    env = _Env(trusted_tmp, f"a21-{error_code.value}")
    with env.serve() as d:
        assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        fix_res = _post_operator(
            d.ready, env.ca_pem, "/v2/operator/doctor/fix", env.cli_token, {"actions": ["reconcile_policy"]}, 15.0
        )
        assert fix_res.get("ok") is True, fix_res
        runner = _runner(d)
        with runner._lock:
            assert runner._fix_dirty is True
        env.clock.advance(timedelta(minutes=16))
        fired, committed = _fault_commit_run_ack_once(monkeypatch, error_code)
        jobs_before = len(_doctor_jobs(env.root))
        started_at = time.monotonic()
        with _blocked_report(d, env, monkeypatch) as waiter:
            assert fired.wait(timeout=BOUND_WAIT_S), "precondition: commit_doctor_run_snapshot lost ACK must fire"
            assert _wait_until(lambda: waiter.done_at is not None, PROMPT_S), (
                f"A2.1 ({error_code.value}): blocked waiter hung after committed SUCCEEDED lost ACK"
            )
        job_id, run_id = committed[0]
        woke_after = None if waiter.done_at is None else waiter.done_at - started_at
        assert woke_after is not None and woke_after < PROMPT_S, f"waiter woke too late ({woke_after}s)"
        assert _durable(env, job_id) == ("succeeded", 1, None)
        assert len(_runs_for(env, job_id)) == 1
        with runner._lock:
            assert runner._finished_jobs.get(job_id) == ("succeeded", run_id), (
                f"A2.1: cache poisoned or missing: {runner._finished_jobs.get(job_id)}"
            )
            assert runner._fix_dirty is False, "A2.1: _fix_dirty was not cleared after reconciled SUCCEEDED"
        data = cast(dict[str, Any], waiter.res.get("data") or {})
        assert waiter.res.get("ok") is True and data.get("status") == "completed", waiter.res
        assert data.get("doctor_run_id") == run_id and data.get("job_id") == job_id
        assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S) is True
        reused = _report(d, env, env.cli_token, wait_ms=0)
        reused_data = cast(dict[str, Any], reused.get("data") or {})
        assert reused.get("ok") is True and reused_data.get("doctor_run_id") == run_id, reused
        assert len(_doctor_jobs(env.root)) == jobs_before + 1


@pytest.mark.parametrize("fault_path", ["abandon_launch", "end_failed"])
def test_a2_2_end_failed_and_abandon_launch_store_busy_never_poison_cache(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, fault_path: str
) -> None:
    """STORE_BUSY rollback on FAILED settlement keeps RUNNING without poisoning cache; clears to FAILED."""
    env = _Env(trusted_tmp, f"a22-{fault_path}")
    with env.serve() as d:
        assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        env.clock.advance(timedelta(minutes=16))
        job_id = _enqueue_jobs_on_owner(d, env, owner_id=OWNER_DAN, count=1, delay=DELAY, tag=f"a22-{fault_path}")[0]
        runner = _runner(d)
        fault_fired = threading.Event()
        if fault_path == "abandon_launch":
            orig_start = threading.Thread.start

            def _bad_start(self: threading.Thread) -> None:
                if self.name.startswith(DOCTOR_WORKER_PREFIX) and not fault_fired.is_set():
                    fault_fired.set()
                    raise RuntimeError("injected worker launch failure")
                orig_start(self)

            monkeypatch.setattr(threading.Thread, "start", _bad_start)
        else:
            orig_read = StorageDoctorReader.read_snapshot

            def _bad_snap(self_r: Any, *args: Any, **kwargs: Any) -> Any:
                if not fault_fired.is_set():
                    fault_fired.set()
                    raise BrainError(ErrorCode.INTEGRITY_FAILURE, "injected non-transient snapshot failure")
                return orig_read(self_r, *args, **kwargs)

            monkeypatch.setattr(StorageDoctorReader, "read_snapshot", _bad_snap)

        busy = threading.Event()
        busy.set()
        busy_hits = _fault_tx_record_gate(monkeypatch, job_id, "job.terminal", busy, required_state="failed")
        env.clock.advance(DELAY + timedelta(milliseconds=1))
        d.loop.run_owner_action(lambda: None).result(timeout=BOUND_WAIT_S)
        assert fault_fired.wait(timeout=BOUND_WAIT_S), "precondition: launch/snapshot fault must fire"
        assert _wait_until(lambda: busy_hits[0] >= 1, BOUND_WAIT_S), "precondition: complete must hit STORE_BUSY"

        still_running = _report(d, env, env.cli_token, wait_ms=300)
        assert still_running.get("ok") is True and (still_running.get("data") or {}).get("status") == "running", (
            f"A2.2: poisoned failed response while SQLite still RUNNING: {still_running}"
        )
        assert d.loop.wait_doctor_settled(timeout=0.25) is False
        assert _durable(env, job_id) == ("running", 1, None)
        with runner._lock:
            assert job_id not in runner._finished_jobs, f"A2.2: poisoned _finished_jobs: {runner._finished_jobs}"

        with _blocked_report(d, env, monkeypatch) as waiter:
            busy.clear()
            assert _wait_until(lambda: _durable(env, job_id)[0] == "failed", WAKE_BUDGET_S), (
                f"A2.2: failed settlement never reconciled after STORE_BUSY cleared: {_durable(env, job_id)}"
            )
            assert _wait_until(lambda: waiter.done_at is not None, PROMPT_S)
        assert _durable(env, job_id) == ("failed", 1, "handler_failed")
        with runner._lock:
            assert runner._finished_jobs.get(job_id) == ("failed", None)
        assert _err_code(waiter.res) == ErrorCode.INTEGRITY_FAILURE.value, waiter.res
        assert not _runs_for(env, job_id)
        assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S) is True
        next_rep = _report(d, env, env.cli_token, wait_ms=WAIT_MS)
        next_data = cast(dict[str, Any], next_rep.get("data") or {})
        assert next_rep.get("ok") is True and next_data.get("status") == "completed"
        assert next_data.get("job_id") != job_id


@pytest.mark.parametrize("lost_ack", [False, True])
def test_a2_3_attempt_3_retryable_end_failed_dead_letter_wakes_immediately(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, lost_ack: bool
) -> None:
    """Attempt-3 retryable _end_failed -> DEAD_LETTER caches dead_letter and wakes waiters immediately."""
    env = _Env(trusted_tmp, f"a23-dl-{lost_ack}")
    with env.serve() as d:
        assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        env.clock.advance(timedelta(minutes=16))
        orig_read = StorageDoctorReader.read_snapshot
        hits = [0]

        def _transient_snap(self_r: Any, *args: Any, **kwargs: Any) -> Any:
            if hits[0] < MAX_JOB_ATTEMPTS:
                hits[0] += 1
                raise BrainError(ErrorCode.STORE_BUSY, "injected transient snapshot busy")
            return orig_read(self_r, *args, **kwargs)

        monkeypatch.setattr(StorageDoctorReader, "read_snapshot", _transient_snap)
        first = _report(d, env, env.cli_token, wait_ms=0)
        job_id = str((first.get("data") or {})["job_id"])
        assert _poke_until(d, lambda: _durable(env, job_id)[:2] == ("queued", 2), tries=4)
        env.clock.advance(retry_backoff(1) + timedelta(milliseconds=1))
        assert _poke_until(d, lambda: _durable(env, job_id)[:2] == ("queued", MAX_JOB_ATTEMPTS), tries=4)
        assert hits[0] == 2 and _durable(env, job_id) == ("queued", MAX_JOB_ATTEMPTS, "handler_failed")

        runner = _runner(d)
        with _blocked_report(d, env, monkeypatch) as waiter:
            lost_ack_ev = (
                _inject_after_commit_once(monkeypatch, job_id, "job.terminal", commit=True) if lost_ack else None
            )
            env.clock.advance(retry_backoff(2) + timedelta(milliseconds=1))
            poked_at = time.monotonic()
            d.loop.run_owner_action(lambda: None).result(timeout=BOUND_WAIT_S)
            assert _wait_until(lambda: waiter.done_at is not None, PROMPT_S), (
                f"A2.3 (lost_ack={lost_ack}): attempt-3 DEAD_LETTER waiter hung instead of waking immediately"
            )
        woke_after = None if waiter.done_at is None else waiter.done_at - poked_at
        assert hits[0] == MAX_JOB_ATTEMPTS
        if lost_ack_ev is not None:
            assert lost_ack_ev.is_set()
        assert _durable(env, job_id) == ("dead_letter", MAX_JOB_ATTEMPTS, "handler_failed")
        with runner._lock:
            assert runner._finished_jobs.get(job_id) == ("dead_letter", None), (
                f"A2.3: expected cached ('dead_letter', None), got {runner._finished_jobs.get(job_id)}"
            )
        assert woke_after is not None and woke_after < PROMPT_S, f"waiter hung for {woke_after}s"
        assert _err_code(waiter.res) == ErrorCode.INTEGRITY_FAILURE.value, waiter.res
        assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S) is True
        assert not _runs_for(env, job_id)
        next_rep = _report(d, env, env.cli_token, wait_ms=WAIT_MS)
        next_data = cast(dict[str, Any], next_rep.get("data") or {})
        assert next_rep.get("ok") is True and next_data.get("status") == "completed"
        assert next_data.get("job_id") != job_id


def test_a2_4_restore_clears_finished_cache_and_isolates_prior_epoch(trusted_tmp: Path) -> None:
    """Restore (fence_on_restore / rebind_after_restore) clears _finished_jobs so prior outcomes never leak."""
    env = _Env(trusted_tmp, "a24-restore-cache")
    with env.serve() as d:
        assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        env.clock.advance(timedelta(minutes=16))
        # Seeded through the live owner job store: an offline runtime cannot open while the daemon holds the writer.
        [job_fail_id] = _enqueue_jobs_on_owner(d, env, owner_id=OWNER_DAN, count=1, delay=DELAY, tag="a24-fail")
        payload_fail = canonical_json({"schema": 1, "trigger": "manual", "checkout_root": None, "tag": "a24-fail"})
        store_bak = d.loop.run_owner_action(
            lambda: create_store_backup(cast(Any, d.loop)._session.rt.store, env.os_, env.clock.now())
        ).result(timeout=BOUND_WAIT_S)

        blob_path(env.root.cas_dir, digest_bytes(payload_fail)).unlink()
        env.clock.advance(DELAY + timedelta(milliseconds=1))
        assert _poke_until(d, lambda: _durable(env, job_fail_id)[0] == "failed", tries=4)
        ok_rep = _report(d, env, env.cli_token, wait_ms=WAIT_MS)
        ok_data = cast(dict[str, Any], ok_rep.get("data") or {})
        assert ok_rep.get("ok") is True and ok_data.get("status") == "completed", ok_rep
        job_ok_id = str(ok_data["job_id"])

        runner = _runner(d)
        with runner._lock:
            assert runner._finished_jobs.get(job_fail_id) == ("failed", None)
            assert runner._finished_jobs.get(job_ok_id) == ("succeeded", str(ok_data["doctor_run_id"]))
        pre_epoch = d.ready.identity.writer_epoch

        _run_online_restore_helper(d.ready, env.rep, env.ca_pem, env.cli_token, env.priv, env.os_, "store", store_bak)
        assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S) is True
        ep_post = read_client_endpoint(env.root.endpoint_path, env.os_)
        assert ep_post.writer_epoch == pre_epoch + 1

        with runner._lock:
            assert runner._finished_jobs == {}, f"A2.4: pre-restore _finished_jobs leaked: {runner._finished_jobs}"
            post_gen = runner._generation
        assert _durable(env, job_fail_id)[0] == "cancelled"

        def _finish_cancelled() -> dict[str, JsonValue]:
            return runner.finish_report(
                owner_id=OWNER_DAN, job_id=job_fail_id, generation=post_gen, writer_epoch=ep_post.writer_epoch
            )

        with pytest.raises(BrainError) as exc_cancelled:
            d.loop.run_owner_action(_finish_cancelled).result(timeout=BOUND_WAIT_S)
        assert exc_cancelled.value.code is ErrorCode.REVISION_CONFLICT, (
            f"A2.4: stale 'failed' cache leaked instead of restored CANCELLED: {exc_cancelled.value.code}"
        )

        def _finish_missing() -> dict[str, JsonValue]:
            return runner.finish_report(
                owner_id=OWNER_DAN, job_id=job_ok_id, generation=post_gen, writer_epoch=ep_post.writer_epoch
            )

        with pytest.raises(BrainError) as exc_missing:
            d.loop.run_owner_action(_finish_missing).result(timeout=BOUND_WAIT_S)
        assert exc_missing.value.code is ErrorCode.NOT_FOUND

        ready_post = replace(d.ready, endpoint=ep_post, identity=ep_post.identity)
        post_rep = _post_operator(
            ready_post, env.ca_pem, "/v2/operator/doctor/report", env.cli_token, {"wait_timeout_ms": WAIT_MS}, 16.0
        )
        assert post_rep.get("ok") is True and (post_rep.get("data") or {}).get("status") == "completed", post_rep

        def _direct_fence_and_rebind() -> None:
            session = cast(Any, d.loop)._session
            assert session is not None
            with runner._lock:
                assert runner._finished_jobs
            runner.fence_on_restore()
            with runner._lock:
                assert runner._finished_jobs == {}
                runner._finished_jobs["stale-pre-rebind"] = ("failed", None)
            runner.rebind_after_restore(rt=session.rt, job_store=session._job_store, job_service=session._job_service)
            with runner._lock:
                assert runner._finished_jobs == {}

        d.loop.run_owner_action(_direct_fence_and_rebind).result(timeout=BOUND_WAIT_S)


# ---------------------------------------------------------------------------
# P2 / R1: Doctor retry wakeup, bounded cadence, restore fence & stop safety
# ---------------------------------------------------------------------------


def _patch_doctor_timers(monkeypatch: pytest.MonkeyPatch, *, fail: bool) -> list[threading.Timer]:
    """Record ``threading.Timer.start`` calls in the test and optionally raise ``RuntimeError``."""
    orig_start = threading.Timer.start
    timers: list[threading.Timer] = []

    def _wrapped_start(self: threading.Timer) -> None:
        timers.append(self)
        if fail:
            raise RuntimeError("injected doctor retry timer start failure")
        orig_start(self)

    monkeypatch.setattr(threading.Timer, "start", _wrapped_start)
    return timers


def _spy_runner_wake(
    monkeypatch: pytest.MonkeyPatch,
    on_wake: Callable[[Callable[[], None]], None],
) -> None:
    """Observe ``DaemonDoctorRunner``'s ``wake_owner`` callback without altering public wiring."""
    orig_init = DaemonDoctorRunner.__init__

    def _wrapped_init(self: DaemonDoctorRunner, *args: Any, **kwargs: Any) -> None:
        orig_wake = cast(Callable[[], None], kwargs["wake_owner"])

        def _spied_wake() -> None:
            on_wake(orig_wake)

        kwargs["wake_owner"] = _spied_wake
        orig_init(self, *args, **kwargs)

    monkeypatch.setattr(DaemonDoctorRunner, "__init__", _wrapped_init)


def test_p2_1_clean_startup_completes_doctor_run_on_idle_doctor_only_daemon(trusted_tmp: Path) -> None:
    """Clean startup on an idle doctor-only daemon completes its startup DoctorRun without client requests."""
    env = _Env(trusted_tmp, "p2-1-clean-startup")
    with env.serve() as d:
        session = cast(Any, d.loop)._session
        assert session is not None and session.has_job_handlers is False
        assert _wait_until(lambda: len(_doctor_runs(env.root)) == 1, WAKE_BUDGET_S), (
            f"P2.1: idle doctor-only daemon failed to complete startup DoctorRun: {_doctor_jobs(env.root)}"
        )
        runs = _doctor_runs(env.root)
        assert len(runs) == 1
        assert runs[0].get("trigger") == "startup" and runs[0].get("owner_id") == OWNER_DAN
        job_id = str(runs[0]["job_id"])
        assert _durable(env, job_id) == ("succeeded", 1, None)
        assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S) is True


def test_p2_2_startup_store_busy_with_timer_start_failure_still_completes(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Transient STORE_BUSY during startup schedule still completes DoctorRun even if Timer.start raises."""
    env = _Env(trusted_tmp, "p2-2-startup-timer-fail")
    schedule_failed = threading.Event()
    orig_find_active = find_active_doctor_job

    def _busy_once(*args: Any, **kwargs: Any) -> Any:
        if not schedule_failed.is_set():
            schedule_failed.set()
            raise BrainError(ErrorCode.STORE_BUSY, "transient startup schedule busy")
        return orig_find_active(*args, **kwargs)

    monkeypatch.setattr(_daemon_doctor, "find_active_doctor_job", _busy_once)
    _patch_doctor_timers(monkeypatch, fail=True)

    with env.serve() as d:
        session = cast(Any, d.loop)._session
        assert session is not None and session.has_job_handlers is False
        assert schedule_failed.wait(timeout=BOUND_WAIT_S), "precondition: startup STORE_BUSY must fire"
        assert _wait_until(lambda: bool(_doctor_runs(env.root)), 3.0), (
            f"P2.2: startup DoctorRun stranded after Timer.start RuntimeError: {_doctor_jobs(env.root)}"
        )
        runs = _doctor_runs(env.root)
        assert len(runs) == 1
        assert runs[0].get("trigger") == "startup"
        assert _durable(env, str(runs[0]["job_id"])) == ("succeeded", 1, None)
        assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S) is True


def test_p2_3_periodic_24h_schedule_store_busy_with_timer_start_failure_recovers(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Periodic 24h schedule STORE_BUSY recovers without client pokes even when Timer.start fails."""
    env = _Env(trusted_tmp, "p2-3-periodic-timer-fail")
    with env.serve() as d:
        session = cast(Any, d.loop)._session
        assert session is not None and session.has_job_handlers is False
        assert _wait_until(lambda: len(_doctor_runs(env.root)) == 1, WAKE_BUDGET_S)
        assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S) is True

        # Fail two lookups so Pass 1 (owner wake) and any immediate Pass 2 (GC did_work=True) cannot mask missing retry.
        failures_left = [2]
        schedule_failed = threading.Event()
        orig_find_active = find_active_doctor_job

        def _busy_periodic(*args: Any, **kwargs: Any) -> Any:
            if failures_left[0] > 0:
                failures_left[0] -= 1
                schedule_failed.set()
                raise BrainError(ErrorCode.STORE_BUSY, "transient periodic schedule busy")
            return orig_find_active(*args, **kwargs)

        monkeypatch.setattr(_daemon_doctor, "find_active_doctor_job", _busy_periodic)
        _patch_doctor_timers(monkeypatch, fail=True)

        env.clock.advance(timedelta(hours=24, seconds=1))
        d.loop.run_owner_action(lambda: None).result(timeout=BOUND_WAIT_S)
        assert schedule_failed.wait(timeout=BOUND_WAIT_S), "precondition: periodic schedule STORE_BUSY must fire"
        assert _wait_until(lambda: len(_doctor_runs(env.root)) == 2, 3.0), (
            f"P2.3: periodic 24h DoctorRun stranded after STORE_BUSY + Timer.start failure: {_doctor_jobs(env.root)}"
        )
        runs = _doctor_runs(env.root)
        assert len(runs) == 2 and runs[1].get("trigger") == "schedule"
        assert _durable(env, str(runs[1]["job_id"])) == ("succeeded", 1, None)
        assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S) is True


@pytest.mark.parametrize("fault_path", ["claim_lease", "settlement_failed"])
def test_p2_4_defer_claim_and_settlement_rollback_recover_with_timer_start_failure(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, fault_path: str
) -> None:
    """_defer on claim lease rollback or failed-settlement rollback reconciles without pokes if Timer.start fails."""
    env = _Env(trusted_tmp, f"p2-4-{fault_path}")
    with env.serve() as d:
        session = cast(Any, d.loop)._session
        assert session is not None and session.has_job_handlers is False
        assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S) is True
        env.clock.advance(timedelta(minutes=16))
        [job_id] = _enqueue_jobs_on_owner(d, env, owner_id=OWNER_DAN, count=1, delay=DELAY, tag=f"p2-4-{fault_path}")

        _patch_doctor_timers(monkeypatch, fail=True)
        hold = threading.Event()
        hold.set()
        fault_fired = threading.Event()
        if fault_path == "claim_lease":
            rollbacks = _fault_tx_record_gate(monkeypatch, job_id, "job.leased", hold)
            fault_fired.set()
        else:
            orig_read = StorageDoctorReader.read_snapshot

            def _bad_snap(self_r: Any, *args: Any, **kwargs: Any) -> Any:
                if not fault_fired.is_set():
                    fault_fired.set()
                    raise BrainError(ErrorCode.INTEGRITY_FAILURE, "injected non-transient snapshot failure")
                return orig_read(self_r, *args, **kwargs)

            monkeypatch.setattr(StorageDoctorReader, "read_snapshot", _bad_snap)
            rollbacks = _fault_tx_record_gate(monkeypatch, job_id, "job.terminal", hold, required_state="failed")

        env.clock.advance(DELAY + timedelta(milliseconds=1))
        d.loop.run_owner_action(lambda: None).result(timeout=BOUND_WAIT_S)
        assert fault_fired.wait(timeout=BOUND_WAIT_S), "precondition: non-transient snapshot fault must fire"
        assert _wait_until(lambda: rollbacks[0] >= 2, BOUND_WAIT_S), (
            f"precondition: {fault_path} rollback must trigger retry path ({rollbacks[0]})"
        )
        time.sleep(0.05)
        hold.clear()

        expected_state = "succeeded" if fault_path == "claim_lease" else "failed"
        assert _wait_until(lambda: _durable(env, job_id)[0] == expected_state, WAKE_BUDGET_S), (
            f"P2.4 ({fault_path}): deferred job stranded after Timer.start failure: {_durable(env, job_id)}"
        )
        if fault_path == "claim_lease":
            assert _durable(env, job_id) == ("succeeded", 1, None)
            assert len(_runs_for(env, job_id)) == 1
        else:
            assert _durable(env, job_id) == ("failed", 1, "handler_failed")
            assert not _runs_for(env, job_id)
        assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S) is True


def test_p2_4b_repeated_claim_deferrals_recover_while_firing_timer_thread_alive(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Repeated claim deferrals recover cleanly even if a firing timer thread overlaps the next deferral."""
    env = _Env(trusted_tmp, "p2-4b-timer-overlap")
    release_timer = threading.Event()
    timer_wakes = [0]

    def _slow_timer_wake(orig_wake: Callable[[], None]) -> None:
        orig_wake()
        if isinstance(threading.current_thread(), threading.Timer):
            timer_wakes[0] += 1
            if timer_wakes[0] == 1:
                release_timer.wait(timeout=2.0)

    _spy_runner_wake(monkeypatch, _slow_timer_wake)
    with env.serve() as d:
        assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S) is True
        env.clock.advance(timedelta(minutes=16))
        [job_id] = _enqueue_jobs_on_owner(d, env, owner_id=OWNER_DAN, count=1, delay=DELAY, tag="p2-4b-overlap")

        hold = threading.Event()
        hold.set()
        rollbacks = _fault_tx_record_gate(monkeypatch, job_id, "job.leased", hold)
        env.clock.advance(DELAY + timedelta(milliseconds=1))
        d.loop.run_owner_action(lambda: None).result(timeout=BOUND_WAIT_S)
        try:
            time.sleep(0.5)
            assert rollbacks[0] >= 2, f"precondition: repeated deferrals did not occur ({rollbacks[0]})"
            hold.clear()
        finally:
            release_timer.set()

        assert _wait_until(lambda: _durable(env, job_id)[0] == "succeeded", WAKE_BUDGET_S), (
            f"P2.4b: repeated deferrals lost wakeup during overlapping timer exit: {_durable(env, job_id)}"
        )
        assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S) is True


@pytest.mark.parametrize("has_handlers", [False, True])
def test_p2_5_sustained_store_busy_retries_with_bounded_cadence_and_recovers(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, has_handlers: bool
) -> None:
    """Sustained STORE_BUSY retries at bounded backoff cadence (no stall, no 50ms spin) and recovers."""
    env = _Env(trusted_tmp, f"p2-5-sustained-{has_handlers}")
    busy = threading.Event()
    busy.set()
    first_attempt = threading.Event()
    attempts = [0]
    orig_find_active = find_active_doctor_job

    def _sustained_busy(*args: Any, **kwargs: Any) -> Any:
        if busy.is_set():
            attempts[0] += 1
            first_attempt.set()
            raise BrainError(ErrorCode.STORE_BUSY, "sustained startup store busy")
        return orig_find_active(*args, **kwargs)

    monkeypatch.setattr(_daemon_doctor, "find_active_doctor_job", _sustained_busy)
    _patch_doctor_timers(monkeypatch, fail=True)
    handlers: dict[str, JobHandler] | None = {"fixture.noop": lambda _spec, _ctx: ()} if has_handlers else None

    with _serve(env.cfg, os_=env.os_, clock=env.clock, mono=env.mono, job_handlers=handlers) as d:
        session = cast(Any, d.loop)._session
        assert session is not None and session.has_job_handlers is has_handlers
        assert first_attempt.wait(timeout=BOUND_WAIT_S), "precondition: initial startup lookup must run"
        time.sleep(1.1)
        attempts_in_window = attempts[0]
        runs_during_fault = len(_doctor_runs(env.root))
        busy.clear()

        assert runs_during_fault == 0
        assert 2 <= attempts_in_window <= 6, (
            f"P2.5 (has_job_handlers={has_handlers}): expected bounded retries (2..6) in 1.1s, got {attempts_in_window}"
        )
        assert _wait_until(lambda: len(_doctor_runs(env.root)) == 1, WAKE_BUDGET_S), (
            f"P2.5 (has_job_handlers={has_handlers}): failed to recover after sustained STORE_BUSY cleared"
        )
        runs = _doctor_runs(env.root)
        assert runs[0].get("trigger") == "startup"
        assert _durable(env, str(runs[0]["job_id"])) == ("succeeded", 1, None)
        assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S) is True


def test_p2_6_restore_fences_and_drops_pending_retry_without_executing_stale_work(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Online restore, fence_on_restore, and rebind_after_restore bump generation and drop pre-restore retries."""
    env = _Env(trusted_tmp, "p2-6-restore-fence")
    timers = _patch_doctor_timers(monkeypatch, fail=False)
    with env.serve() as d:
        assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S) is True
        env.clock.advance(timedelta(minutes=16))
        [old_job_id] = _enqueue_jobs_on_owner(d, env, owner_id=OWNER_DAN, count=1, delay=DELAY, tag="p2-6-old")
        store_bak = d.loop.run_owner_action(
            lambda: create_store_backup(cast(Any, d.loop)._session.rt.store, env.os_, env.clock.now())
        ).result(timeout=BOUND_WAIT_S)

        fault_fired = threading.Event()
        orig_read = StorageDoctorReader.read_snapshot

        def _bad_snap(self_r: Any, *args: Any, **kwargs: Any) -> Any:
            if not fault_fired.is_set():
                fault_fired.set()
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, "injected snapshot failure before restore")
            return orig_read(self_r, *args, **kwargs)

        monkeypatch.setattr(StorageDoctorReader, "read_snapshot", _bad_snap)
        busy = threading.Event()
        busy.set()
        busy_hits = _fault_tx_record_gate(monkeypatch, old_job_id, "job.terminal", busy, required_state="failed")

        env.clock.advance(DELAY + timedelta(milliseconds=1))
        d.loop.run_owner_action(lambda: None).result(timeout=BOUND_WAIT_S)
        assert fault_fired.wait(timeout=BOUND_WAIT_S)
        assert _wait_until(lambda: busy_hits[0] >= 1, BOUND_WAIT_S)

        runner = _runner(d)
        with runner._lock:
            gen_before = runner._generation
            assert runner._pending_settle is not None

        _run_online_restore_helper(d.ready, env.rep, env.ca_pem, env.cli_token, env.priv, env.os_, "store", store_bak)
        with runner._lock:
            assert runner._generation > gen_before
            assert runner._pending_settle is None
            assert runner._pending_lease is None
            assert runner._reconcile_claims is False
            assert runner._finished_jobs == {}
        assert _durable(env, old_job_id)[0] == "cancelled"

        busy.clear()
        time.sleep(0.3)
        assert _durable(env, old_job_id)[0] == "cancelled"
        assert not _runs_for(env, old_job_id)

        ep_post = read_client_endpoint(env.root.endpoint_path, env.os_)
        ready_post = replace(d.ready, endpoint=ep_post, identity=ep_post.identity)
        post_rep = _post_operator(
            ready_post, env.ca_pem, "/v2/operator/doctor/report", env.cli_token, {"wait_timeout_ms": WAIT_MS}, 16.0
        )
        post_data = cast(dict[str, Any], post_rep.get("data") or {})
        assert post_rep.get("ok") is True and post_data.get("status") == "completed", post_rep
        assert post_data.get("job_id") != old_job_id
        assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S) is True

        env.clock.advance(timedelta(minutes=16))
        [old_job_2] = _enqueue_jobs_on_owner(d, env, owner_id=OWNER_DAN, count=1, delay=DELAY, tag="p2-6-direct")
        hold2 = threading.Event()
        hold2.set()
        rollbacks2 = _fault_tx_record_gate(monkeypatch, old_job_2, "job.leased", hold2)
        env.clock.advance(DELAY + timedelta(milliseconds=1))
        d.loop.run_owner_action(lambda: None).result(timeout=BOUND_WAIT_S)
        assert _wait_until(lambda: rollbacks2[0] >= 1, BOUND_WAIT_S)

        def _direct_fence_and_rebind() -> None:
            session = cast(Any, d.loop)._session
            assert session is not None
            with runner._lock:
                g0 = runner._generation
            runner.fence_on_restore()
            with runner._lock:
                assert runner._generation == g0 + 1
                assert runner._pending_lease is None
                assert runner._pending_settle is None
                assert runner._reconcile_claims is False
            assert all(t.finished.is_set() for t in timers)
            runner.finish_restore_reconcile()
            runner.rebind_after_restore(rt=session.rt, job_store=session._job_store, job_service=session._job_service)
            with runner._lock:
                assert runner._generation == g0 + 2
                assert runner._pending_lease is None
                assert runner._pending_settle is None
                assert runner._reconcile_claims is False

        d.loop.run_owner_action(_direct_fence_and_rebind).result(timeout=BOUND_WAIT_S)
        hold2.clear()
        time.sleep(0.3)
        assert _durable(env, old_job_2)[0] == "cancelled"
        assert not _runs_for(env, old_job_2)

        post_rep_2 = _post_operator(
            ready_post, env.ca_pem, "/v2/operator/doctor/report", env.cli_token, {"wait_timeout_ms": WAIT_MS}, 16.0
        )
        post_data_2 = cast(dict[str, Any], post_rep_2.get("data") or {})
        assert post_rep_2.get("ok") is True and post_data_2.get("status") == "completed", post_rep_2
        assert post_data_2.get("job_id") != old_job_2


@pytest.mark.parametrize("fail_timer_start", [False, True])
def test_p2_7_stop_while_sustained_retry_pending_completes_promptly_without_post_stop_wakeup(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, fail_timer_start: bool
) -> None:
    """d.loop.stop while sustained retry is pending stops promptly (<1s) with zero post-stop wake_owner calls."""
    env = _Env(trusted_tmp, f"p2-7-stop-{fail_timer_start}")
    attempts = [0]

    def _always_busy(*_args: Any, **_kwargs: Any) -> Any:
        attempts[0] += 1
        raise BrainError(ErrorCode.STORE_BUSY, "sustained busy during stop")

    monkeypatch.setattr(_daemon_doctor, "find_active_doctor_job", _always_busy)
    timers = _patch_doctor_timers(monkeypatch, fail=fail_timer_start)

    post_stop = threading.Event()
    post_stop_wakes: list[float] = []

    def _record_wake(orig_wake: Callable[[], None]) -> None:
        if post_stop.is_set():
            post_stop_wakes.append(time.monotonic())
        orig_wake()

    _spy_runner_wake(monkeypatch, _record_wake)

    with env.serve() as d:
        assert _wait_until(lambda: attempts[0] >= 2, BOUND_WAIT_S), (
            f"P2.7 (fail_timer_start={fail_timer_start}): sustained retry never looped ({attempts[0]})"
        )
        t_stop = time.monotonic()
        report = d.loop.stop(grace_s=2.0)
        stop_elapsed = time.monotonic() - t_stop
        post_stop.set()

        assert report.state is ShutdownState.STOPPED, report
        assert report.error_code is None, report
        assert stop_elapsed < 1.0, f"stop() blocked on retry backoff for {stop_elapsed:.3f}s"

        time.sleep(0.35)
        assert post_stop_wakes == [], f"lingering retry timer called wake_owner after stop: {post_stop_wakes}"
        assert all(t.finished.is_set() and not t.is_alive() for t in timers)


def test_r2_sqlite_error_in_ledger_lookup_never_crashes_owner_or_leaks_raw(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``sqlite3.Error`` in ``_committed_run_id`` / ``load_committed_doctor_run_dto`` must translate cleanly."""
    env = _Env(trusted_tmp, "r2-sqlite")
    with env.serve() as d:
        assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S) is True
        env.clock.advance(timedelta(minutes=16))

        orig_iter = __import__(
            "superbrain.composition._daemon_doctor", fromlist=["iter_owner_doctor_ledger"]
        ).iter_owner_doctor_ledger
        fail_next = [True]

        def _sql_err_once(*args: Any, **kwargs: Any) -> Any:
            if fail_next[0]:
                fail_next[0] = False
                raise sqlite3.OperationalError("database is locked")
            return orig_iter(*args, **kwargs)

        monkeypatch.setattr("superbrain.composition._daemon_doctor.iter_owner_doctor_ledger", _sql_err_once)
        monkeypatch.setattr("superbrain.composition._daemon_health.iter_owner_doctor_ledger", _sql_err_once)

        [job_id] = _enqueue_jobs_on_owner(d, env, owner_id=OWNER_DAN, count=1, delay=DELAY, tag="r2-sql")
        _fault_commit_run_ack_once(monkeypatch, ErrorCode.STORE_BUSY)
        env.clock.advance(DELAY + timedelta(milliseconds=1))
        d.loop.run_owner_action(lambda: None).result(timeout=BOUND_WAIT_S)
        assert _wait_until(lambda: _durable(env, job_id)[0] == "succeeded", WAKE_BUDGET_S)
        assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S) is True, (
            "R2.1: sqlite3.Error in _committed_run_id crashed OwnerLoop instead of falling back cleanly"
        )

        # Direct boundary check: load_committed_doctor_run_dto must translate sqlite3.Error to BrainError, not leak.
        fail_next[0] = True
        with pytest.raises(BrainError) as exc_info:
            d.loop.run_owner_action(
                lambda: load_committed_doctor_run_dto(
                    cast(Any, d.loop)._session.rt,
                    owner_id=OWNER_DAN,
                    job_id=job_id,
                    doctor_run_id=None,
                    now=env.clock.now(),
                )
            ).result(timeout=BOUND_WAIT_S)
        assert exc_info.value.code in (ErrorCode.STORE_BUSY, ErrorCode.IO_ERROR, ErrorCode.INTEGRITY_FAILURE)

        rep = _report(d, env, env.cli_token, wait_ms=WAIT_MS)
        assert rep.get("ok") is True, rep
        assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S) is True
