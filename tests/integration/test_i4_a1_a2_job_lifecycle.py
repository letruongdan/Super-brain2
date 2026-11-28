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

import contextlib
import sqlite3
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.daemon_config import read_client_endpoint
from superbrain.application.jobs import JobService
from superbrain.application.owner_loop import OwnerLoop
from superbrain.composition import _daemon_doctor
from superbrain.composition._daemon_doctor import DaemonDoctorRunner
from superbrain.composition._daemon_health import (
    enqueue_doctor_tx,
    find_active_doctor_job,
    load_committed_doctor_run_dto,
)
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
from superbrain.storage.layout import DataRoot
from superbrain.workers.executor import JobHandler
from tests.integration.test_doctor_jobs import BOUND_WAIT_S, OWNER_DAN, _init_doctor_root, _ro_db
from tests.integration.test_i4_f4_f8_remediation import (
    OTHER_OWNER,
    _doctor_jobs,
    _doctor_runs,
    _Env,
    _job_payload,
    _ReadGate,
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
from tests.support.inc2_fixture import kernel_job_service

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
    handlers: dict[str, JobHandler] | None = {"fixture.noop": lambda _spec, _ctx: ()} if has_handlers else {}

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


# ---------------------------------------------------------------------------
# P2 R4: Independent per-lane retry deadlines (maintenance vs claim vs settle)
# ---------------------------------------------------------------------------


def _count_claimed_reconciles(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Count durable ``claimed_jobs_by_kinds`` reads during orphan lease reconciliation."""
    orig = StagedKernelStore.transact
    counts = [0]

    class _Tx:
        def __init__(self, inner: Any) -> None:
            self._inner = inner

        def claimed_jobs_by_kinds(self, *args: Any, **kwargs: Any) -> Any:
            counts[0] += 1
            return self._inner.claimed_jobs_by_kinds(*args, **kwargs)

        def __getattr__(self, name: str) -> Any:
            return getattr(self._inner, name)

    def _transact(self: StagedKernelStore, operation: Callable[[Any], Any]) -> Any:
        return orig(self, lambda tx: operation(_Tx(tx)))

    monkeypatch.setattr(StagedKernelStore, "transact", _transact)
    return counts


def _enqueue_offline_doctor_job(job_store: StagedKernelStore, env: _Env, *, tag: str) -> str:
    """Enqueue one due store-wide ``system.doctor`` job through the given ``StagedKernelStore``."""
    job_id = new_id()
    payload = canonical_json({"schema": 1, "trigger": "manual", "checkout_root": None, "tag": tag})
    job_store.stage_blob(payload)
    _, now_str = require_aware_utc(env.clock.now())
    job_store.transact(
        lambda tx: enqueue_doctor_tx(tx, job_id=job_id, owner_id=OWNER_DAN, payload_bytes=payload, retry_at=now_str)
    )
    return job_id


@contextlib.contextmanager
def _direct_runner(env: _Env) -> Any:
    """Create a real SQLite-backed ``DaemonDoctorRunner`` without background ``OwnerLoop`` interference."""
    with env.offline_rt() as rt:
        job_service, job_store = kernel_job_service(rt, env.clock)
        runner = DaemonDoctorRunner(
            rt=rt,
            job_store=job_store,
            job_service=job_service,
            adapters=env.os_,
            clock=env.clock,
            tls_not_after=env.clock.now() + timedelta(days=30),
            clock_untrusted_fn=lambda: False,
            prune_idempotency_fn=lambda _now, _limit: 0,
            wake_owner=lambda: None,
        )
        try:
            yield runner, job_store
        finally:
            runner.close()
            runner.join(BOUND_WAIT_S)


def _complete_direct_startup(runner: DaemonDoctorRunner, env: _Env) -> None:
    """Drive initial startup doctor run to completion on a standalone ``DaemonDoctorRunner``."""
    runner.step(allow_new_jobs=True)
    assert _wait_until(lambda: runner.is_drained, BOUND_WAIT_S)
    runner.step(allow_new_jobs=True)
    assert len(_doctor_runs(env.root)) == 1


@pytest.mark.parametrize("mode", ["direct_step", "live_owner_loop"])
def test_p2_8_continuing_maintenance_failures_do_not_starve_due_lease_reconciliation(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    """Continuing maintenance failures must never postpone or starve an already-due lease reconciliation."""
    env = _Env(trusted_tmp, f"p2-8-{mode}")
    reconcile_attempts = _count_claimed_reconciles(monkeypatch)
    maint_busy = threading.Event()
    maint_attempts = [0]
    orig_find_active = find_active_doctor_job

    def _persistent_maint_busy(*args: Any, **kwargs: Any) -> Any:
        if maint_busy.is_set():
            maint_attempts[0] += 1
            raise BrainError(ErrorCode.STORE_BUSY, "persistent maintenance schedule busy")
        return orig_find_active(*args, **kwargs)

    monkeypatch.setattr(_daemon_doctor, "find_active_doctor_job", _persistent_maint_busy)

    if mode == "direct_step":
        with _direct_runner(env) as (runner, job_store):
            _complete_direct_startup(runner, env)

            # Healthy-maintenance twin: lost lease ACK reconciles cleanly on its own retry turn.
            env.clock.advance(timedelta(minutes=16))
            ctrl_job_id = _enqueue_offline_doctor_job(job_store, env, tag="p2-8-ctrl")
            ctrl_fired, _ = _fault_lease_ack_once(monkeypatch, target_job_id=ctrl_job_id)
            runner.step(allow_new_jobs=True)
            assert ctrl_fired.is_set()
            wait_ctrl = runner.next_retry_wait_s()
            assert wait_ctrl is not None
            time.sleep(wait_ctrl + 0.02)
            runner.step(allow_new_jobs=True)
            assert _wait_until(lambda: runner.is_drained, BOUND_WAIT_S)
            runner.step(allow_new_jobs=True)
            assert reconcile_attempts[0] >= 1 and _durable(env, ctrl_job_id) == ("succeeded", 1, None)

            # Fault phase: continuing maintenance STORE_BUSY across continuing retry windows alongside lost lease ACK.
            reconcile_attempts[0] = 0
            env.clock.advance(timedelta(hours=24, seconds=1))
            target_job_id = _enqueue_offline_doctor_job(job_store, env, tag="p2-8-starved")
            fired, _ = _fault_lease_ack_once(monkeypatch, target_job_id=target_job_id)
            maint_busy.set()

            runner.step(allow_new_jobs=True)
            assert fired.is_set(), "precondition: lost lease ACK on target job must fire"
            assert _durable(env, target_job_id) == ("leased", 1, None)

            # Drive earliest due retry turns up to BOUND_WAIT_S. _claim_retry and _maint_retry arm independent
            # deadlines, so a next_retry_wait_s() wakeup for _claim_retry may fire between maintenance backoff windows;
            # verify BOTH that due lease reconciliation succeeds AND that maintenance continues retrying across windows.
            reconcile_deadline = time.monotonic() + BOUND_WAIT_S
            while time.monotonic() < reconcile_deadline and (
                maint_attempts[0] < 5 or _durable(env, target_job_id)[0] != "succeeded"
            ):
                if _durable(env, target_job_id)[0] != "succeeded":
                    if not runner.is_drained:
                        assert _wait_until(lambda: runner.is_drained, BOUND_WAIT_S)
                    runner.step(allow_new_jobs=False)
                    if maint_attempts[0] >= 5 and _durable(env, target_job_id)[0] == "succeeded":
                        break
                wait_s = runner.next_retry_wait_s()
                assert wait_s is not None, "retry wait must remain armed while maintenance keeps failing"
                time.sleep(wait_s + 0.02)
                runner.step(allow_new_jobs=True)

            assert _wait_until(lambda: runner.is_drained, BOUND_WAIT_S)
            runner.step(allow_new_jobs=False)

            assert maint_attempts[0] >= 5, (
                f"expected >=5 maintenance attempts across continuing retry windows within {BOUND_WAIT_S}s, "
                f"got {maint_attempts[0]}"
            )
            assert runner.next_retry_wait_s() is not None, (
                "retry wait must remain armed while maintenance keeps failing"
            )
            assert reconcile_attempts[0] >= 1, (
                f"P2.8 (direct_step): continuing maintenance failures starved due lease reconciliation "
                f"(reconcile_attempts={reconcile_attempts[0]}, durable={_durable(env, target_job_id)})"
            )
            assert _durable(env, target_job_id) == ("succeeded", 1, None)
            assert len(_runs_for(env, target_job_id)) == 1

            maint_busy.clear()
            rem_wait = runner.next_retry_wait_s()
            if rem_wait is not None:
                time.sleep(rem_wait + 0.02)
                runner.step(allow_new_jobs=True)
                assert _wait_until(lambda: runner.is_drained, BOUND_WAIT_S)
                runner.step(allow_new_jobs=True)
        return

    with env.serve() as d:
        assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S) is True
        env.clock.advance(timedelta(minutes=16))
        [target_job_id] = _enqueue_jobs_on_owner(d, env, owner_id=OWNER_DAN, count=1, delay=DELAY, tag="p2-8-live")

        fired, _ = _fault_lease_ack_once(monkeypatch, target_job_id=target_job_id)
        maint_busy.set()
        env.clock.advance(timedelta(hours=24, seconds=1))
        d.loop.run_owner_action(lambda: None).result(timeout=BOUND_WAIT_S)

        assert fired.wait(timeout=BOUND_WAIT_S), "precondition: lost lease ACK on live owner loop must fire"
        assert _wait_until(lambda: maint_attempts[0] >= 5, BOUND_WAIT_S), (
            f"precondition: expected >=5 maintenance attempts within {BOUND_WAIT_S}s, got {maint_attempts[0]}"
        )
        assert _wait_until(lambda: _durable(env, target_job_id)[0] == "succeeded", WAKE_BUDGET_S), (
            f"P2.8 (live_owner_loop): leased job failed to reconcile while maintenance failed: "
            f"{_durable(env, target_job_id)}"
        )
        assert reconcile_attempts[0] >= 1, (
            f"P2.8 (live_owner_loop): continuing maintenance failures starved due lease reconciliation "
            f"(reconcile_attempts={reconcile_attempts[0]}, durable={_durable(env, target_job_id)})"
        )
        assert _durable(env, target_job_id) == ("succeeded", 1, None)
        assert len(_runs_for(env, target_job_id)) == 1

        maint_busy.clear()
        assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S) is True


@pytest.mark.parametrize(
    "case",
    [
        "maint_streak_does_not_delay_settlement",
        "claim_streak_does_not_delay_maintenance",
        "settle_streak_does_not_delay_maintenance",
    ],
)
def test_p2_9_cross_lane_retry_deadlines_remain_independent(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    """Backoff streak or retry failure in one lane must not postpone another lane's earlier deadline."""
    env = _Env(trusted_tmp, f"p2-9-{case}")
    maint_busy = threading.Event()
    maint_lookups = [0]
    orig_find_active = find_active_doctor_job

    def _counting_find_active(*args: Any, **kwargs: Any) -> Any:
        maint_lookups[0] += 1
        if maint_busy.is_set():
            raise BrainError(ErrorCode.STORE_BUSY, "maintenance lookup busy")
        return orig_find_active(*args, **kwargs)

    monkeypatch.setattr(_daemon_doctor, "find_active_doctor_job", _counting_find_active)

    with _direct_runner(env) as (runner, job_store):
        _complete_direct_startup(runner, env)

        if case == "maint_streak_does_not_delay_settlement":
            env.clock.advance(timedelta(hours=24, seconds=1))
            maint_busy.set()
            # Build maintenance backoff streak=3 -> next maintenance retry wait is ~0.8s.
            for _ in range(2):
                runner.step(allow_new_jobs=True)
                wait_m = runner.next_retry_wait_s()
                assert wait_m is not None
                time.sleep(wait_m + 0.02)
            runner.step(allow_new_jobs=True)
            long_maint_wait = runner.next_retry_wait_s()
            assert long_maint_wait is not None and long_maint_wait > 0.5

            job_id = _enqueue_offline_doctor_job(job_store, env, tag="p2-9-settle")
            orig_read = StorageDoctorReader.read_snapshot
            snap_failed = threading.Event()

            def _bad_snap(self_r: Any, *args: Any, **kwargs: Any) -> Any:
                if not snap_failed.is_set():
                    snap_failed.set()
                    raise BrainError(ErrorCode.INTEGRITY_FAILURE, "injected snapshot failure")
                return orig_read(self_r, *args, **kwargs)

            monkeypatch.setattr(StorageDoctorReader, "read_snapshot", _bad_snap)
            settle_hold = threading.Event()
            settle_hold.set()
            _fault_tx_record_gate(monkeypatch, job_id, "job.terminal", settle_hold, required_state="failed")

            assert runner.claim_pending_if_idle() is True
            assert _wait_until(lambda: runner.is_drained, BOUND_WAIT_S)
            runner.step(allow_new_jobs=False)
            settle_hold.clear()

            earliest_wait = runner.next_retry_wait_s()
            assert earliest_wait is not None and earliest_wait <= 0.3, (
                f"P2.9 ({case}): maintenance streak delayed settlement wakeup to {earliest_wait:.3f}s"
            )
            time.sleep(0.25)
            runner.step(allow_new_jobs=True)
            assert _durable(env, job_id) == ("failed", 1, "handler_failed"), (
                f"P2.9 ({case}): due settlement was skipped behind maintenance backoff: {_durable(env, job_id)}"
            )
            maint_busy.clear()
            return

        env.clock.advance(timedelta(minutes=16))
        job_id = _enqueue_offline_doctor_job(job_store, env, tag=f"p2-9-{case}")
        if case == "claim_streak_does_not_delay_maintenance":
            claim_hold = threading.Event()
            claim_hold.set()
            _fault_tx_record_gate(monkeypatch, job_id, "job.leased", claim_hold)
            for _ in range(2):
                runner.step(allow_new_jobs=True)
                wait_c = runner.next_retry_wait_s()
                assert wait_c is not None
                time.sleep(wait_c + 0.02)
            runner.step(allow_new_jobs=True)
        else:
            orig_read = StorageDoctorReader.read_snapshot
            snap_failed = threading.Event()

            def _bad_snap2(self_r: Any, *args: Any, **kwargs: Any) -> Any:
                if not snap_failed.is_set():
                    snap_failed.set()
                    raise BrainError(ErrorCode.INTEGRITY_FAILURE, "injected snapshot failure")
                return orig_read(self_r, *args, **kwargs)

            monkeypatch.setattr(StorageDoctorReader, "read_snapshot", _bad_snap2)
            settle_hold = threading.Event()
            settle_hold.set()
            _fault_tx_record_gate(monkeypatch, job_id, "job.terminal", settle_hold, required_state="failed")
            runner.step(allow_new_jobs=True)
            assert _wait_until(lambda: runner.is_drained, BOUND_WAIT_S)
            for _ in range(2):
                runner.step(allow_new_jobs=False)
                wait_s = runner.next_retry_wait_s()
                assert wait_s is not None
                time.sleep(wait_s + 0.02)
            runner.step(allow_new_jobs=False)

        long_other_wait = runner.next_retry_wait_s()
        assert long_other_wait is not None and long_other_wait > 0.5

        maint_lookups[0] = 0
        maint_busy.set()
        env.clock.advance(timedelta(hours=24, seconds=1))
        runner.step(allow_new_jobs=True)
        assert maint_lookups[0] == 1

        earliest_wait = runner.next_retry_wait_s()
        assert earliest_wait is not None and earliest_wait <= 0.3, (
            f"P2.9 ({case}): long claim/settle streak delayed maintenance wakeup to {earliest_wait:.3f}s"
        )
        maint_busy.clear()
        time.sleep(0.25)
        runner.step(allow_new_jobs=True)
        assert maint_lookups[0] >= 2, (
            f"P2.9 ({case}): due maintenance retry was postponed behind claim/settle backoff"
        )

        if case == "claim_streak_does_not_delay_maintenance":
            claim_hold.clear()
        else:
            settle_hold.clear()
        rem = runner.next_retry_wait_s()
        if rem is not None:
            time.sleep(rem + 0.02)
        runner.step(allow_new_jobs=True)
        assert _wait_until(lambda: runner.is_drained, BOUND_WAIT_S)
        runner.step(allow_new_jobs=True)
        expected = ("succeeded", 1, None) if case == "claim_streak_does_not_delay_maintenance" else (
            "failed",
            1,
            "handler_failed",
        )
        assert _durable(env, job_id) == expected


# ---------------------------------------------------------------------------
# P2 R5 (v2): Single-wait idle periodic schedule, GC, dedup, clock jump & reset
# ---------------------------------------------------------------------------


def _spy_owner_pokes(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Count external ``OwnerLoop.run_owner_action`` and ``wait_doctor_settled`` pokes."""
    from superbrain.application.owner_loop import OwnerLoop

    pokes = [0]
    orig_run = OwnerLoop.run_owner_action
    orig_wait = OwnerLoop.wait_doctor_settled

    def _run(self: OwnerLoop, *args: Any, **kwargs: Any) -> Any:
        pokes[0] += 1
        return orig_run(self, *args, **kwargs)

    def _wait(self: OwnerLoop, *args: Any, **kwargs: Any) -> bool:
        pokes[0] += 1
        return bool(orig_wait(self, *args, **kwargs))

    monkeypatch.setattr(OwnerLoop, "run_owner_action", _run)
    monkeypatch.setattr(OwnerLoop, "wait_doctor_settled", _wait)
    return pokes


def _job_tuple(root: DataRoot, job_id: str) -> tuple[str, int, str | None]:
    with _ro_db(root.store_db) as conn:
        row = conn.execute("SELECT state, attempt, reason FROM p_jobs_state WHERE job_id = ?", (job_id,)).fetchone()
    assert row is not None, f"job {job_id} has no durable row"
    return str(row[0]), int(row[1]), None if row[2] is None else str(row[2])


def _assert_clean_stop(d: _Daemon) -> None:
    t0 = time.monotonic()
    report = d.loop.stop(grace_s=2.0)
    elapsed = time.monotonic() - t0
    assert report.state is ShutdownState.STOPPED, report
    assert report.error_code is None, report
    assert elapsed < 1.0, f"stop() took {elapsed:.3f}s"


@pytest.mark.parametrize("mode", ["real_clock_short_interval", "single_wait_24h_no_fast_poll"])
def test_p2_10_idle_periodic_schedule_uses_single_wait_without_fast_poll_or_timers(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    """Idle doctor-only daemon runs periodic schedule via one bounded wait to due time (no fast poll or timers)."""
    real_os = os_adapters()
    _rep, cfg, _priv, _ca_pem, _leaf, _cli_token, _adapters = _init_doctor_root(
        trusted_tmp / f"p2-10-{mode}", cast(Any, real_os.clock), os_=real_os
    )
    root = DataRoot.at(cfg.data_root)
    pokes = _spy_owner_pokes(monkeypatch)

    if mode == "real_clock_short_interval":
        monkeypatch.setattr(_daemon_doctor, "DOCTOR_SCHEDULE_INTERVAL", timedelta(seconds=0.45))
        t_start = time.monotonic()
        with _serve(cfg, os_=real_os, clock=cast(Any, real_os.clock), mono=cast(Any, real_os.monotonic)) as d:
            session = cast(Any, d.loop)._session
            assert session is not None and session.has_job_handlers is False

            assert _wait_until(lambda: len(_doctor_runs(root)) >= 1, WAKE_BUDGET_S), (
                f"P2.10 ({mode}): startup DoctorRun did not complete: {_doctor_jobs(root)}"
            )
            startup_runs = _doctor_runs(root)
            assert len(startup_runs) == 1 and startup_runs[0].get("trigger") == "startup"
            if time.monotonic() - t_start < 0.30:
                time.sleep(0.08)
                assert len(_doctor_runs(root)) == 1, "P2.10: periodic schedule fired before 0.45s interval"

            assert _wait_until(lambda: len(_doctor_runs(root)) >= 2, WAKE_BUDGET_S), (
                f"P2.10 ({mode}): idle doctor-only daemon never self-triggered periodic DoctorRun: "
                f"{_doctor_jobs(root)}"
            )
            runs = _doctor_runs(root)
            assert len(runs) == 2 and runs[1].get("trigger") == "schedule", runs
            assert _job_tuple(root, str(runs[1]["job_id"])) == ("succeeded", 1, None)
            assert pokes[0] == 0
            _assert_clean_stop(d)
        return

    orig_timer_init = threading.Timer.__init__
    timers_created = [0]

    def _counted_timer_init(self: threading.Timer, *args: Any, **kwargs: Any) -> None:
        timers_created[0] += 1
        orig_timer_init(self, *args, **kwargs)

    monkeypatch.setattr(threading.Timer, "__init__", _counted_timer_init)

    with _serve(cfg, os_=real_os, clock=cast(Any, real_os.clock), mono=cast(Any, real_os.monotonic)) as d:
        session = cast(Any, d.loop)._session
        assert session is not None and session.has_job_handlers is False
        assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S) is True
        assert len(_doctor_runs(root)) == 1

        owner_wake = cast(threading.Event, cast(Any, d.loop)._owner_wake)
        orig_wake_wait = owner_wake.wait
        captured_timeouts: list[float | None] = []
        wait_entered = threading.Event()
        count_steps = threading.Event()
        step_calls = [0]

        def _spied_wait(timeout: float | None = None) -> bool:
            captured_timeouts.append(timeout)
            wait_entered.set()
            return orig_wake_wait(timeout=timeout)

        session_obj = cast(Any, d.loop)._session
        orig_step = session_obj.step_owner_work

        def _spied_step(*, allow_new_jobs: bool) -> bool:
            if count_steps.is_set():
                step_calls[0] += 1
            return cast(bool, orig_step(allow_new_jobs=allow_new_jobs))

        monkeypatch.setattr(owner_wake, "wait", _spied_wait)
        monkeypatch.setattr(session_obj, "step_owner_work", _spied_step)
        d.loop.run_owner_action(lambda: None).result(timeout=BOUND_WAIT_S)
        assert wait_entered.wait(timeout=BOUND_WAIT_S)

        count_steps.set()
        time.sleep(1.0)

        assert timers_created[0] == 0, f"P2.10 ({mode}): Timer threads must not be created ({timers_created[0]})"
        assert captured_timeouts, "P2.10: no idle owner wait observed"
        idle_timeout = captured_timeouts[-1]
        assert idle_timeout is not None and idle_timeout > 86_000.0, (
            f"P2.10 ({mode}): expected single 24h wait (>86000s), got {idle_timeout!r}"
        )
        assert step_calls[0] <= 1, f"P2.10 ({mode}): idle owner loop fast-polled ({step_calls[0]} steps in 1.0s)"
        assert len(_doctor_runs(root)) == 1
        _assert_clean_stop(d)


@pytest.mark.parametrize("path", ["periodic_store_busy_cadence", "periodic_gc_reclaim_on_idle"])
def test_p2_11_idle_periodic_retry_cadence_and_debounced_gc(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, path: str
) -> None:
    """Periodic schedule STORE_BUSY retries at bounded cadence without pokes, and idle GC reclaims aged orphans."""
    import os

    from superbrain.storage.cas import ContentStore
    from tests.support.inc2_fixture import reopen_kernel_job_runtime

    real_os = os_adapters()
    rep, cfg, _priv, _ca_pem, _leaf, _cli_token, _adapters = _init_doctor_root(
        trusted_tmp / f"p2-11-{path}", cast(Any, real_os.clock), os_=real_os
    )
    root = DataRoot.at(cfg.data_root)
    monkeypatch.setattr(_daemon_doctor, "DOCTOR_SCHEDULE_INTERVAL", timedelta(seconds=0.45))
    pokes = _spy_owner_pokes(monkeypatch)

    if path == "periodic_store_busy_cadence":
        lookup_calls = [0]
        periodic_attempts = [0]
        first_periodic_fail = threading.Event()
        periodic_busy = threading.Event()
        periodic_busy.set()
        orig_find_active = find_active_doctor_job

        def _busy_periodic(*args: Any, **kwargs: Any) -> Any:
            lookup_calls[0] += 1
            if lookup_calls[0] >= 2 and periodic_busy.is_set():
                periodic_attempts[0] += 1
                first_periodic_fail.set()
                raise BrainError(ErrorCode.STORE_BUSY, "periodic schedule store busy")
            return orig_find_active(*args, **kwargs)

        monkeypatch.setattr(_daemon_doctor, "find_active_doctor_job", _busy_periodic)

        with _serve(cfg, os_=real_os, clock=cast(Any, real_os.clock), mono=cast(Any, real_os.monotonic)) as d:
            assert first_periodic_fail.wait(timeout=WAKE_BUDGET_S), (
                "P2.11: periodic schedule never woke to attempt lookup"
            )
            time.sleep(1.1)
            attempts_in_window = periodic_attempts[0]
            runs_during_fault = len(_doctor_runs(root))
            periodic_busy.clear()

            assert runs_during_fault == 1
            assert 2 <= attempts_in_window <= 7, (
                f"P2.11: expected bounded periodic retry cadence (2..7 in 1.1s), got {attempts_in_window}"
            )
            assert _wait_until(lambda: len(_doctor_runs(root)) >= 2, WAKE_BUDGET_S), (
                f"P2.11: periodic DoctorRun did not recover after STORE_BUSY cleared: {_doctor_jobs(root)}"
            )
            runs = _doctor_runs(root)
            assert len(runs) == 2 and runs[1].get("trigger") == "schedule"
            assert _job_tuple(root, str(runs[1]["job_id"])) == ("succeeded", 1, None)
            assert pokes[0] == 0
            _assert_clean_stop(d)
        return

    rt = reopen_kernel_job_runtime(cfg.data_root, rep.store_id, real_os)
    try:
        orphan_digest = rt.store.cas.put(b"p2-11-idle-gc-orphan")
    finally:
        rt.close()
    orphan_path = blob_path(root.cas_dir, orphan_digest)
    old_ts = (real_os.clock.now() - timedelta(hours=25)).timestamp()
    os.utime(orphan_path, (old_ts, old_ts))
    assert orphan_path.is_file()

    gc_calls = [0]
    gc_failed = threading.Event()
    orig_gc = ContentStore.collect_garbage

    def _gc_fail_once(self_cas: ContentStore, *args: Any, **kwargs: Any) -> Any:
        gc_calls[0] += 1
        if gc_calls[0] == 1:
            gc_failed.set()
            raise BrainError(ErrorCode.IO_ERROR, "transient gc failure")
        return orig_gc(self_cas, *args, **kwargs)

    monkeypatch.setattr(ContentStore, "collect_garbage", _gc_fail_once)

    with _serve(cfg, os_=real_os, clock=cast(Any, real_os.clock), mono=cast(Any, real_os.monotonic)) as d:
        assert _wait_until(lambda: (not orphan_path.exists()) and len(_doctor_runs(root)) >= 2, WAKE_BUDGET_S), (
            f"P2.11 (gc): idle periodic GC/schedule failed (orphan_exists={orphan_path.exists()}, "
            f"runs={len(_doctor_runs(root))}, gc_calls={gc_calls[0]})"
        )
        assert gc_failed.is_set() and gc_calls[0] >= 2
        runs = _doctor_runs(root)
        assert runs[1].get("trigger") == "schedule"
        assert _job_tuple(root, str(runs[1]["job_id"])) == ("succeeded", 1, None)
        assert pokes[0] == 0
        _assert_clean_stop(d)


class _ControllableOffsetClock:
    """Thread-safe test clock supporting paused anchors, monotonic epochs, signed shifts, and capped progression."""

    def __init__(self, start_utc: datetime | None = None) -> None:
        self._lock = threading.Lock()
        self._anchor_utc = datetime.now(UTC) if start_utc is None else start_utc
        self._running = False
        self._run_started_mono = 0.0
        self._cap_utc: datetime | None = None
        self._epoch = 0
        self._read_seq = 0
        self._last_read_by_thread: dict[int, tuple[int, int, datetime]] = {}
        self._one_shot_delay_s = 0.0
        self._one_shot_delay_min_epoch = 0
        self._one_shot_delay_tid: int | None = None
        self._one_shot_delay_done: threading.Event | None = None

    @property
    def anchor_utc(self) -> datetime:
        with self._lock:
            return self._anchor_utc

    @property
    def epoch(self) -> int:
        with self._lock:
            return self._epoch

    def last_read_for_thread(self, thread_id: int) -> tuple[int, int, datetime] | None:
        with self._lock:
            return self._last_read_by_thread.get(thread_id)

    def arm_one_shot_delay(
        self, *, min_epoch: int, thread_id: int, delay_s: float, done_event: threading.Event
    ) -> None:
        with self._lock:
            self._one_shot_delay_min_epoch = min_epoch
            self._one_shot_delay_tid = thread_id
            self._one_shot_delay_s = delay_s
            self._one_shot_delay_done = done_event

    def clear_one_shot_delay(self) -> None:
        with self._lock:
            self._one_shot_delay_s = 0.0
            self._one_shot_delay_tid = None
            self._one_shot_delay_done = None

    def _current_locked(self) -> datetime:
        if not self._running:
            return self._anchor_utc
        elapsed_s = max(0.0, time.monotonic() - self._run_started_mono)
        current = self._anchor_utc + timedelta(seconds=elapsed_s)
        if self._cap_utc is not None and current > self._cap_utc:
            return self._cap_utc
        return current

    def _pause_locked(self, target_utc: datetime) -> int:
        self._anchor_utc = target_utc
        self._running = False
        self._cap_utc = None
        self._epoch += 1
        return self._epoch

    def now(self) -> datetime:
        while True:
            with self._lock:
                if (
                    self._one_shot_delay_s > 0.0
                    and self._epoch >= self._one_shot_delay_min_epoch
                    and threading.get_ident() == self._one_shot_delay_tid
                ):
                    delay_s = self._one_shot_delay_s
                    self._one_shot_delay_s = 0.0
                    on_delay = self._one_shot_delay_done
                else:
                    current = self._current_locked()
                    self._read_seq += 1
                    self._last_read_by_thread[threading.get_ident()] = (self._read_seq, self._epoch, current)
                    return current
            time.sleep(delay_s)
            if on_delay is not None:
                on_delay.set()

    def shift(self, delta_s: float) -> datetime:
        with self._lock:
            self._anchor_utc = self._current_locked() + timedelta(seconds=delta_s)
            if self._running:
                self._run_started_mono = time.monotonic()
            self._epoch += 1
            return self._anchor_utc

    def shift_paused(self, delta_s: float) -> tuple[datetime, int]:
        with self._lock:
            target_utc = self._current_locked() + timedelta(seconds=delta_s)
            epoch = self._pause_locked(target_utc)
            return self._anchor_utc, epoch

    def pause_at(self, target_utc: datetime | None = None) -> datetime:
        with self._lock:
            target = self._current_locked() if target_utc is None else target_utc
            self._pause_locked(target)
            return self._anchor_utc

    def pause_at_epoch(self, target_utc: datetime) -> int:
        with self._lock:
            return self._pause_locked(target_utc)

    def resume(self, *, cap_utc: datetime | None = None) -> int:
        with self._lock:
            self._anchor_utc = self._current_locked()
            self._run_started_mono = time.monotonic()
            self._cap_utc = cap_utc
            self._running = True
            self._epoch += 1
            return self._epoch


class _ScheduleAndCommitSpies:
    """Records ``DaemonDoctorRunner._schedule_store_run`` calls and committed ``DoctorRun`` milestones."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._schedule_calls: list[tuple[str, bool | None]] = []
        self._commit_count = 0
        self.startup_committed = threading.Event()

    def record_schedule(self, trigger: str, outcome: bool | None) -> None:
        with self._lock:
            self._schedule_calls.append((trigger, outcome))

    def record_commit(self) -> None:
        with self._lock:
            self._commit_count += 1
            if self._commit_count >= 1:
                self.startup_committed.set()

    @property
    def schedule_calls(self) -> list[tuple[str, bool | None]]:
        with self._lock:
            return list(self._schedule_calls)

    @property
    def commit_count(self) -> int:
        with self._lock:
            return self._commit_count


def _install_schedule_and_commit_spies(monkeypatch: pytest.MonkeyPatch) -> _ScheduleAndCommitSpies:
    spies = _ScheduleAndCommitSpies()
    orig_schedule = DaemonDoctorRunner._schedule_store_run
    orig_commit = DaemonDoctorRunner._commit_completed

    def _spied_schedule(self_runner: DaemonDoctorRunner, trigger: str) -> bool | None:
        outcome = orig_schedule(self_runner, trigger)
        spies.record_schedule(trigger, outcome)
        return outcome

    def _spied_commit(self_runner: DaemonDoctorRunner, completed: Any) -> None:
        orig_commit(self_runner, completed)
        spies.record_commit()

    monkeypatch.setattr(DaemonDoctorRunner, "_schedule_store_run", _spied_schedule)
    monkeypatch.setattr(DaemonDoctorRunner, "_commit_completed", _spied_commit)
    return spies


@dataclass(frozen=True)
class _RecordedWait:
    """One observed ``owner_wake.wait`` call paired with the clock epoch/timestamp that produced it."""

    timeout: float | None
    clock_epoch: int | None
    clock_utc: datetime | None
    commit_count: int


class _OwnerWaitSpy:
    """Observes ``owner_wake.wait`` timeouts and synchronizes test clock phases by clock epoch."""

    def __init__(self) -> None:
        self._cond = threading.Condition()
        self._waits: list[_RecordedWait] = []
        self._staged_clock_by_thread: dict[int, tuple[int | None, datetime | None]] = {}

    def stage_clock_read(
        self, thread_id: int, clock_epoch: int | None, clock_utc: datetime | None
    ) -> None:
        with self._cond:
            self._staged_clock_by_thread[thread_id] = (clock_epoch, clock_utc)

    def record_wait(self, thread_id: int, timeout: float | None, commit_count: int) -> None:
        with self._cond:
            clock_epoch, clock_utc = self._staged_clock_by_thread.pop(thread_id, (None, None))
            self._waits.append(
                _RecordedWait(
                    timeout=timeout,
                    clock_epoch=clock_epoch,
                    clock_utc=clock_utc,
                    commit_count=commit_count,
                )
            )
            self._cond.notify_all()

    def wait_for(self, predicate: Callable[[_RecordedWait], bool], timeout: float) -> _RecordedWait | None:
        deadline = time.monotonic() + max(0.0, timeout)
        with self._cond:
            while True:
                for entry in self._waits:
                    if predicate(entry):
                        return entry
                rem = deadline - time.monotonic()
                if rem <= 0.0:
                    return None
                self._cond.wait(timeout=rem)

    @property
    def waits(self) -> list[_RecordedWait]:
        with self._cond:
            return list(self._waits)


def _attach_owner_wait_spy(
    monkeypatch: pytest.MonkeyPatch,
    d: _Daemon,
    spies: _ScheduleAndCommitSpies,
    clk: _ControllableOffsetClock,
) -> _OwnerWaitSpy:
    wait_spy = _OwnerWaitSpy()
    session = cast(Any, d.loop)._session
    orig_next_wait = session.next_doctor_wake_wait_s
    owner_wake = cast(threading.Event, cast(Any, d.loop)._owner_wake)
    orig_wait = owner_wake.wait

    def _spied_next_wait() -> float | None:
        tid = threading.get_ident()
        before = clk.last_read_for_thread(tid)
        clock_epoch: int | None = None
        clock_utc: datetime | None = None
        try:
            return cast(float | None, orig_next_wait())
        finally:
            after = clk.last_read_for_thread(tid)
            if after is not None and (before is None or after[0] != before[0]):
                clock_epoch, clock_utc = after[1], after[2]
            wait_spy.stage_clock_read(tid, clock_epoch, clock_utc)

    def _spied_wait(timeout: float | None = None) -> bool:
        wait_spy.record_wait(threading.get_ident(), timeout, spies.commit_count)
        return orig_wait(timeout=timeout)

    monkeypatch.setattr(session, "next_doctor_wake_wait_s", _spied_next_wait)
    monkeypatch.setattr(owner_wake, "wait", _spied_wait)
    return wait_spy


def _wait_for_idle_epoch(wait_spy: _OwnerWaitSpy, *, min_commits: int, label: str) -> _RecordedWait:
    idle_wait = wait_spy.wait_for(
        lambda w: w.commit_count >= min_commits and w.clock_epoch is not None,
        WAKE_BUDGET_S,
    )
    assert idle_wait is not None, (
        f"P2.12 ({label}): owner did not enter idle wait after commit {min_commits}: {wait_spy.waits}"
    )
    return idle_wait


def _pause_near_due_and_wait(
    clk: _ControllableOffsetClock,
    wait_spy: _OwnerWaitSpy,
    *,
    due_utc: datetime,
    lead_s: float = 0.05,
    label: str,
) -> int:
    near_epoch = clk.pause_at_epoch(due_utc - timedelta(seconds=lead_s))
    near_wait = wait_spy.wait_for(
        lambda w: w.clock_epoch == near_epoch and w.timeout is not None and 0.0 < w.timeout <= lead_s + 1e-6,
        WAKE_BUDGET_S,
    )
    assert near_wait is not None, (
        f"P2.12 ({label}): owner did not observe near-due wait (<= {lead_s}s): {wait_spy.waits}"
    )
    return near_epoch


def _assert_backward_jump_defers_schedule(
    clk: _ControllableOffsetClock,
    root: DataRoot,
    spies: _ScheduleAndCommitSpies,
    wait_spy: _OwnerWaitSpy,
    *,
    due_utc: datetime,
    interval_s: float,
    label: str,
    shift_s: float = -1.0,
) -> int:
    """Verify pre-shift state, observe frozen post-shift epoch wait, then verify bounded pre-deadline progression."""
    assert clk.now() < due_utc
    assert len(_doctor_runs(root)) == 1 and len(_doctor_jobs(root)) == 1
    assert [c for c in spies.schedule_calls if c[0] == "schedule"] == []

    # Phase 1: keep the clock frozen at post_shift_utc until the owner records a wait on shift_epoch.
    post_shift_utc, shift_epoch = clk.shift_paused(shift_s)
    expected_frozen_wait_s = (due_utc - post_shift_utc).total_seconds()
    assert expected_frozen_wait_s >= interval_s
    frozen_wait = wait_spy.wait_for(lambda w: w.clock_epoch == shift_epoch, WAKE_BUDGET_S)
    assert frozen_wait is not None, (
        f"P2.12 ({label}): owner did not record wait on shift_epoch={shift_epoch}: {wait_spy.waits}"
    )
    assert frozen_wait.timeout is not None
    assert frozen_wait.clock_utc == post_shift_utc
    assert frozen_wait.timeout >= expected_frozen_wait_s - 1e-6, (
        f"P2.12 ({label}): wait timeout did not cover frozen post-shift deadline: {frozen_wait!r}"
    )
    assert frozen_wait.timeout >= interval_s, (
        f"P2.12 ({label}): wait timeout did not extend to cover backward jump: {frozen_wait!r}"
    )
    assert [c for c in spies.schedule_calls if c[0] == "schedule"] == [], (
        f"P2.12 ({label}): periodic schedule enqueued during frozen backward window: {spies.schedule_calls}"
    )
    assert len(_doctor_jobs(root)) == 1 and len(_doctor_runs(root)) == 1, (
        f"P2.12 ({label}): periodic run fired prematurely during frozen shift: "
        f"jobs={_doctor_jobs(root)} runs={_doctor_runs(root)}"
    )

    # Phase 2: bounded pre-deadline progression after the frozen wait was recorded.
    resume_epoch = clk.resume(cap_utc=due_utc - timedelta(milliseconds=150))
    time.sleep(0.25)

    assert [c for c in spies.schedule_calls if c[0] == "schedule"] == [], (
        f"P2.12 ({label}): periodic schedule enqueued during backward window: {spies.schedule_calls}"
    )
    assert len(_doctor_jobs(root)) == 1 and len(_doctor_runs(root)) == 1, (
        f"P2.12 ({label}): periodic run fired prematurely after {shift_s:+.1f}s clock jump: "
        f"jobs={_doctor_jobs(root)} runs={_doctor_runs(root)}"
    )
    waits = wait_spy.waits
    assert all(w.timeout is not None and w.timeout >= 0.0 for w in waits), (
        f"P2.12 ({label}): invalid/negative owner wait timeout observed: {waits}"
    )
    for w in waits:
        if w.clock_epoch is not None and w.clock_epoch >= shift_epoch and w.clock_utc is not None:
            assert w.timeout is not None
            expected_wait_s = max(0.0, (due_utc - w.clock_utc).total_seconds())
            assert abs(w.timeout - expected_wait_s) <= 1e-3, (
                f"P2.12 ({label}): recorded wait {w!r} did not match "
                f"clock_utc={w.clock_utc!r} (expected={expected_wait_s})"
            )
    return resume_epoch


def _assert_periodic_schedule_settled(root: DataRoot, pokes: list[int], d: _Daemon, *, label: str) -> None:
    assert _wait_until(lambda: len(_doctor_runs(root)) >= 2, WAKE_BUDGET_S), (
        f"P2.12 ({label}): periodic DoctorRun did not fire after clock reached due: {_doctor_jobs(root)}"
    )
    runs = _doctor_runs(root)
    assert len(_doctor_jobs(root)) == 2 and len(runs) == 2 and runs[1].get("trigger") == "schedule"
    assert _job_tuple(root, str(runs[1]["job_id"])) == ("succeeded", 1, None)
    assert pokes[0] == 0
    _assert_clean_stop(d)


@pytest.mark.parametrize(
    "case",
    [
        "concurrent_active_spanning_due",
        "concurrent_completed_before_due",
        "backward_clock_jump",
        "restore_and_stop_reset",
    ],
)
def test_p2_12_periodic_schedule_dedup_backward_clock_and_restore_reset(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    """Periodic schedule deduplicates concurrent CLI runs, tolerates backward clock jumps, and resets on restore."""
    if case == "concurrent_active_spanning_due":
        real_os = os_adapters()
        _rep, cfg, _priv, ca_pem, _leaf, cli_token, _adapters = _init_doctor_root(
            trusted_tmp / "p2-12-active-dedup", cast(Any, real_os.clock), os_=real_os
        )
        root = DataRoot.at(cfg.data_root)
        # Host-speed independent setup (R6): the periodic interval stays at its 24h default until the CLI job is
        # active, so a slow startup run cannot let the schedule fire before the CLI request. Once the CLI job holds
        # the slot (blocked in read_snapshot) the interval is shortened so the schedule due time has passed, one owner
        # step evaluates it while the CLI job is active, and the interval is restored to 24h before the CLI job is
        # released so no further interval can elapse during a slow tail.
        gate = _ReadGate(monkeypatch)
        schedule_calls: list[tuple[str, bool | None]] = []
        orig_schedule = DaemonDoctorRunner._schedule_store_run

        def _spied_schedule(self_runner: DaemonDoctorRunner, trigger: str) -> bool | None:
            outcome = orig_schedule(self_runner, trigger)
            schedule_calls.append((trigger, outcome))
            return outcome

        monkeypatch.setattr(DaemonDoctorRunner, "_schedule_store_run", _spied_schedule)

        with _serve(cfg, os_=real_os, clock=cast(Any, real_os.clock), mono=cast(Any, real_os.monotonic)) as d:
            assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S) is True
            assert len(_doctor_runs(root)) == 1
            fix_res = _post_operator(
                d.ready, ca_pem, "/v2/operator/doctor/fix", cli_token, {"actions": ["reconcile_policy"]}, 15.0
            )
            assert fix_res.get("ok") is True, fix_res

            gate.armed.set()
            cli_box: dict[str, Any] = {}

            def _call_report() -> None:
                cli_box["res"] = _post_operator(
                    d.ready, ca_pem, "/v2/operator/doctor/report", cli_token, {"wait_timeout_ms": WAIT_MS}, 15.0
                )

            cli_thr = threading.Thread(target=_call_report, name="p2-12-cli-report", daemon=True)
            cli_thr.start()
            try:
                assert gate.entered.wait(timeout=BOUND_WAIT_S), "precondition: CLI doctor job must enter read_snapshot"
                before = len(schedule_calls)
                monkeypatch.setattr(_daemon_doctor, "DOCTOR_SCHEDULE_INTERVAL", timedelta(milliseconds=1))
                time.sleep(0.05)  # the schedule due time (last run + interval) is now in the past
                # wait_doctor_settled runs one doctor step on the owner thread (False: the CLI job is still active).
                d.loop.wait_doctor_settled(timeout=0.5)
                assert ("schedule", False) in schedule_calls[before:], (
                    f"precondition: the due schedule must be evaluated while the CLI job is active: {schedule_calls}"
                )
                monkeypatch.setattr(_daemon_doctor, "DOCTOR_SCHEDULE_INTERVAL", timedelta(hours=24))
            finally:
                gate.release.set()
                cli_thr.join(timeout=BOUND_WAIT_S)

            assert not cli_thr.is_alive()
            cli_res = cast(dict[str, Any], cli_box.get("res") or {})
            assert cli_res.get("ok") is True and (cli_res.get("data") or {}).get("status") == "completed", cli_res

            time.sleep(0.15)
            jobs = _doctor_jobs(root)
            runs = _doctor_runs(root)
            assert len(jobs) == 2 and len(runs) == 2, (
                f"P2.12 ({case}): duplicate schedule job ran alongside spanning CLI job: jobs={jobs}"
            )
            assert runs[1].get("trigger") == "cli"
            _assert_clean_stop(d)
        return

    if case == "concurrent_completed_before_due":
        env = _Env(trusted_tmp, "p2-12-completed-dedup")
        with env.serve() as d:
            assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S) is True
            assert len(_doctor_runs(env.root)) == 1

            env.clock.advance(timedelta(hours=23, minutes=59))
            cli_rep = _report(d, env, env.cli_token, wait_ms=WAIT_MS)
            assert cli_rep.get("ok") is True and (cli_rep.get("data") or {}).get("status") == "completed", cli_rep
            assert len(_doctor_runs(env.root)) == 2 and _doctor_runs(env.root)[1].get("trigger") == "cli"

            env.clock.advance(timedelta(minutes=2))
            assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S) is True
            assert len(_doctor_runs(env.root)) == 2, (
                f"P2.12 ({case}): periodic schedule double-ran right after store-wide CLI completion: "
                f"{_doctor_jobs(env.root)}"
            )

            env.clock.advance(timedelta(hours=24))
            assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S) is True
            runs = _doctor_runs(env.root)
            assert len(runs) == 3 and runs[2].get("trigger") == "schedule"
            _assert_clean_stop(d)
        return

    if case == "backward_clock_jump":
        interval_s = 0.7
        clk = _ControllableOffsetClock()
        real_os = os_adapters(clock=clk)
        _rep, cfg, _priv, _ca_pem, _leaf, _cli_token, _adapters = _init_doctor_root(
            trusted_tmp / "p2-12-back-clock", cast(Any, clk), os_=real_os
        )
        root = DataRoot.at(cfg.data_root)
        pokes = _spy_owner_pokes(monkeypatch)
        monkeypatch.setattr(_daemon_doctor, "DOCTOR_SCHEDULE_INTERVAL", timedelta(seconds=interval_s))
        spies = _install_schedule_and_commit_spies(monkeypatch)

        with _serve(cfg, os_=real_os, clock=cast(Any, clk), mono=cast(Any, real_os.monotonic)) as d:
            wait_spy = _attach_owner_wait_spy(monkeypatch, d, spies, clk)
            _wait_for_idle_epoch(wait_spy, min_commits=1, label=case)
            due_utc = clk.anchor_utc + timedelta(seconds=interval_s)
            _assert_backward_jump_defers_schedule(
                clk, root, spies, wait_spy, due_utc=due_utc, interval_s=interval_s, label=case
            )
            # past due but short of the next period, so the oracle sees exactly this period under any load
            clk.resume(cap_utc=due_utc + timedelta(seconds=interval_s / 2))
            _assert_periodic_schedule_settled(root, pokes, d, label=case)
        return

    env = _Env(trusted_tmp, "p2-12-restore-stop")
    with env.serve() as d:
        assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S) is True
        assert len(_doctor_runs(env.root)) == 1
        store_bak = d.loop.run_owner_action(
            lambda: create_store_backup(cast(Any, d.loop)._session.rt.store, env.os_, env.clock.now())
        ).result(timeout=BOUND_WAIT_S)

        env.clock.advance(timedelta(hours=23, minutes=59))
        _run_online_restore_helper(d.ready, env.rep, env.ca_pem, env.cli_token, env.priv, env.os_, "store", store_bak)
        env.clock.advance(timedelta(minutes=2))
        assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S) is True
        assert len(_doctor_runs(env.root)) == 1, (
            f"P2.12 ({case}): spurious periodic DoctorRun fired 2m after restore: {_doctor_jobs(env.root)}"
        )

        env.clock.advance(timedelta(hours=24))
        assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S) is True
        runs = _doctor_runs(env.root)
        assert len(runs) == 2 and runs[1].get("trigger") == "schedule"
        assert _durable(env, str(runs[1]["job_id"])) == ("succeeded", 1, None)

        session_obj = cast(Any, d.loop)._session
        orig_step = session_obj.step_owner_work
        post_stop = threading.Event()
        post_stop_steps = [0]

        def _count_post_stop_step(*, allow_new_jobs: bool) -> bool:
            if post_stop.is_set():
                post_stop_steps[0] += 1
            return cast(bool, orig_step(allow_new_jobs=allow_new_jobs))

        monkeypatch.setattr(session_obj, "step_owner_work", _count_post_stop_step)
        _assert_clean_stop(d)
        post_stop.set()
        time.sleep(0.25)
        assert post_stop_steps[0] == 0


@pytest.mark.parametrize(
    "edge_case",
    [
        "slow_startup_over_interval",
        "queued_uncommitted_vs_never_enqueued",
        "jump_near_due_and_exact_due_twin",
        "owner_delayed_over_350ms_near_due",
    ],
)
def test_p2_12_backward_clock_jump_slow_startup_uncommitted_and_due_boundary(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, edge_case: str
) -> None:
    """Adjacent backward-clock-jump invariants: slow startup, queued-uncommitted distinction, and == due boundary."""
    interval_s = 0.7
    clk = _ControllableOffsetClock()
    real_os = os_adapters(clock=clk)
    _rep, cfg, _priv, _ca_pem, _leaf, _cli_token, _adapters = _init_doctor_root(
        trusted_tmp / f"p2-12-edge-{edge_case}", cast(Any, clk), os_=real_os
    )
    root = DataRoot.at(cfg.data_root)
    pokes = _spy_owner_pokes(monkeypatch)
    monkeypatch.setattr(_daemon_doctor, "DOCTOR_SCHEDULE_INTERVAL", timedelta(seconds=interval_s))
    spies = _install_schedule_and_commit_spies(monkeypatch)

    if edge_case == "slow_startup_over_interval":
        orig_read_snapshot = StorageDoctorReader.read_snapshot
        delayed_once = threading.Event()

        def _slow_startup_read(self_reader: StorageDoctorReader, *args: Any, **kwargs: Any) -> Any:
            if not delayed_once.is_set():
                delayed_once.set()
                time.sleep(0.85)
            return orig_read_snapshot(self_reader, *args, **kwargs)

        monkeypatch.setattr(StorageDoctorReader, "read_snapshot", _slow_startup_read)
        with _serve(cfg, os_=real_os, clock=cast(Any, clk), mono=cast(Any, real_os.monotonic)) as d:
            wait_spy = _attach_owner_wait_spy(monkeypatch, d, spies, clk)
            _wait_for_idle_epoch(wait_spy, min_commits=1, label=edge_case)
            due_utc = clk.anchor_utc + timedelta(seconds=interval_s)
            _assert_backward_jump_defers_schedule(
                clk, root, spies, wait_spy, due_utc=due_utc, interval_s=interval_s, label=edge_case
            )
            # past due but short of the next period, so the oracle sees exactly this period under any load
            clk.resume(cap_utc=due_utc + timedelta(seconds=interval_s / 2))
            _assert_periodic_schedule_settled(root, pokes, d, label=edge_case)
        return

    if edge_case == "queued_uncommitted_vs_never_enqueued":
        gate = _ReadGate(monkeypatch)
        with _serve(cfg, os_=real_os, clock=cast(Any, clk), mono=cast(Any, real_os.monotonic)) as d:
            wait_spy = _attach_owner_wait_spy(monkeypatch, d, spies, clk)
            _wait_for_idle_epoch(wait_spy, min_commits=1, label=edge_case)
            due_utc = clk.anchor_utc + timedelta(seconds=interval_s)
            _assert_backward_jump_defers_schedule(
                clk, root, spies, wait_spy, due_utc=due_utc, interval_s=interval_s, label=edge_case, shift_s=-1.2
            )

            gate.armed.set()
            try:
                clk.pause_at(due_utc)
                assert gate.entered.wait(timeout=WAKE_BUDGET_S), "periodic schedule job never entered read_snapshot"
                jobs_while_held = _doctor_jobs(root)
                assert len(_doctor_runs(root)) == 1, "periodic run must not commit while snapshot is held"
                assert len(jobs_while_held) == 2, (
                    f"oracle must distinguish queued-uncommitted schedule job from never-enqueued: {jobs_while_held}"
                )
                assert _job_payload(root, jobs_while_held[1]["job_id"]).get("trigger") == "schedule"
                assert ("schedule", True) in spies.schedule_calls
            finally:
                gate.release.set()

            _assert_periodic_schedule_settled(root, pokes, d, label=edge_case)
        return

    if edge_case == "owner_delayed_over_350ms_near_due":
        with _serve(cfg, os_=real_os, clock=cast(Any, clk), mono=cast(Any, real_os.monotonic)) as d:
            wait_spy = _attach_owner_wait_spy(monkeypatch, d, spies, clk)
            _wait_for_idle_epoch(wait_spy, min_commits=1, label=edge_case)
            due_utc = clk.anchor_utc + timedelta(seconds=interval_s)

            near_epoch = _pause_near_due_and_wait(clk, wait_spy, due_utc=due_utc, label=edge_case)

            owner_thread = cast(threading.Thread | None, cast(Any, d.loop)._owner_thread)
            assert owner_thread is not None and owner_thread.ident is not None
            delayed = threading.Event()
            clk.arm_one_shot_delay(
                min_epoch=near_epoch + 1,
                thread_id=owner_thread.ident,
                delay_s=0.50,
                done_event=delayed,
            )
            try:
                resume_epoch = _assert_backward_jump_defers_schedule(
                    clk, root, spies, wait_spy, due_utc=due_utc, interval_s=interval_s, label=edge_case, shift_s=-1.0
                )
            finally:
                clk.clear_one_shot_delay()

            assert delayed.is_set(), "precondition: >350ms owner delay must have fired during shift_epoch"
            assert pokes[0] == 0
            resumed_wait = wait_spy.wait_for(lambda w: w.clock_epoch == resume_epoch, WAKE_BUDGET_S)
            assert resumed_wait is not None and resumed_wait.timeout is not None, (
                f"owner did not compute wait on resumed pre-deadline epoch={resume_epoch}: {wait_spy.waits}"
            )
            assert 0.0 < resumed_wait.timeout <= 0.15 + 1e-3, (
                f"resumed capped pre-deadline wait out of expected (0, 0.15s] range: {resumed_wait!r}"
            )
            assert [c for c in spies.schedule_calls if c[0] == "schedule"] == []
            assert len(_doctor_jobs(root)) == 1 and len(_doctor_runs(root)) == 1

            clk.pause_at(due_utc)
            _assert_periodic_schedule_settled(root, pokes, d, label=edge_case)
        return

    with _serve(cfg, os_=real_os, clock=cast(Any, clk), mono=cast(Any, real_os.monotonic)) as d:
        wait_spy = _attach_owner_wait_spy(monkeypatch, d, spies, clk)
        _wait_for_idle_epoch(wait_spy, min_commits=1, label=edge_case)
        due_utc = clk.anchor_utc + timedelta(seconds=interval_s)

        _pause_near_due_and_wait(clk, wait_spy, due_utc=due_utc, label=edge_case)

        _assert_backward_jump_defers_schedule(
            clk, root, spies, wait_spy, due_utc=due_utc, interval_s=interval_s, label=edge_case
        )

        # Positive twin: advance clock to exact == due_utc (testing >= in _due).
        clk.pause_at(due_utc)
        assert _wait_until(lambda: len(_doctor_runs(root)) >= 2, WAKE_BUDGET_S), (
            f"periodic DoctorRun did not fire at exact due boundary ==: {_doctor_jobs(root)}"
        )
        runs = _doctor_runs(root)
        assert len(_doctor_jobs(root)) == 2 and len(runs) == 2 and runs[1].get("trigger") == "schedule"
        assert _job_tuple(root, str(runs[1]["job_id"])) == ("succeeded", 1, None)

        # Wall-clock progress between step_owner_work and next_schedule_wait_s past due2 must clamp wait to >= 0.0.
        _wait_for_idle_epoch(wait_spy, min_commits=2, label=edge_case)
        due2_utc = due_utc + timedelta(seconds=interval_s)
        _pause_near_due_and_wait(clk, wait_spy, due_utc=due2_utc, label=edge_case)

        session_obj = cast(Any, d.loop)._session
        orig_step = session_obj.step_owner_work
        shifted_past_due = threading.Event()

        def _step_and_advance_past_due(*, allow_new_jobs: bool) -> bool:
            res = cast(bool, orig_step(allow_new_jobs=allow_new_jobs))
            if not res and not shifted_past_due.is_set():
                shifted_past_due.set()
                clk.shift(0.10)
            return res

        monkeypatch.setattr(session_obj, "step_owner_work", _step_and_advance_past_due)
        assert _wait_until(lambda: len(_doctor_runs(root)) >= 3, WAKE_BUDGET_S)
        assert shifted_past_due.is_set()
        assert all(w.timeout is not None and w.timeout >= 0.0 for w in wait_spy.waits), (
            f"negative or None owner wait timeout observed: {wait_spy.waits}"
        )
        assert pokes[0] == 0
        _assert_clean_stop(d)
