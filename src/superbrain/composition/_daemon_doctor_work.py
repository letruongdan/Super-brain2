"""DaemonDoctorRunner owner/worker steps: maintenance, schedule, claim, background snapshot, and commit."""

from __future__ import annotations

import contextlib
import os
import shutil
import sqlite3
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING

from superbrain.composition._daemon_doctor_commit import (
    DoctorFences,
    _CompletedDoctorProbe,
    build_worker_db_snapshot,
    capture_doctor_fences,
    commit_doctor_run_snapshot,
    parse_doctor_payload,
    resolve_store_owner,
    verify_doctor_snapshot_fences,
)
from superbrain.composition._daemon_health import (
    DOCTOR_JOB_KIND,
    find_latest_valid_doctor_run,
)
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import (
    JobLease,
    JobOutcome,
    JobSpec,
    JobState,
    require_aware_utc,
)
from superbrain.ports.doctor import DoctorSnapshot
from superbrain.storage._doctor_reader import StorageDoctorReader
from superbrain.storage.layout import DataRoot

if TYPE_CHECKING:
    from superbrain.composition.doctor_probes_sp2_store import Sp2DoctorReport
from superbrain.composition import _daemon_doctor as _m


def _run_maintenance_and_schedule(self: _m.DaemonDoctorRunner) -> bool:
    with self._lock:
        if self._maint_retry.backoff_active(self._generation, time.monotonic()):
            return False
        gen = self._generation
        self._maint_retry.begin_attempt(gen)
        startup_due = self._startup_due
        last_gc_at = self._last_gc_at
        last_scheduled_at = self._last_scheduled_at
        # GC commits to the store; run during a worker's DB snapshot it splits every pair and starves the run.
        worker_active = self._active_token is not None
    now_utc, _ = require_aware_utc(self._clock.now())
    did_work = False

    if startup_due:
        with self._lock:
            if self._generation == gen and not (self._stopping or self._closed):
                self._last_gc_at = now_utc
        # Same fence set and scope as deep health: only a store-wide run of this store, writer epoch, restore
        # epoch and trust generation counts as a recent self-check.
        try:
            owner_id = resolve_store_owner(self._rt.policy)
            latest = (
                find_latest_valid_doctor_run(self._rt, owner_id, now_utc, checkout_root=None)
                if owner_id is not None
                else None
            )
        except BrainError as err:
            _m._LOGGER.warning("doctor startup lookup failed (code=%s)", err.code.value)
            self._arm_maint_retry(gen)
            return False
        except sqlite3.Error:
            _m._LOGGER.warning("doctor startup lookup failed (code=sqlite_error)")
            self._arm_maint_retry(gen)
            return False
        if latest is not None and not _m._due(latest[0].recorded_at, now_utc):
            with self._lock:
                if self._generation == gen and not (self._stopping or self._closed):
                    self._startup_due = False
                    self._last_scheduled_at = latest[0].recorded_at
                    self._maint_retry.finish_if_settled()
            return False
        outcome = self._schedule_store_run("startup")
        if outcome is None:
            self._arm_maint_retry(gen)
            return False  # still due: owner-loop retry backoff wakes even on a doctor-only daemon
        with self._lock:
            if self._generation == gen and not (self._stopping or self._closed):
                self._startup_due = False
                self._last_scheduled_at = now_utc
                self._maint_retry.finish_if_settled()
        return outcome

    if _m._due(last_gc_at, now_utc) and not worker_active:  # stays due; the worker's completion wakes the owner
        try:
            _m.expire_due(self._rt.store, self._rt.policy, now_utc)
            self._rt.store.cas.collect_garbage(now=now_utc)
            for _ in range(10):
                if self._prune_idempotency_fn(now_utc, 100) < 100:
                    break
            with self._lock:
                if self._generation == gen and not (self._stopping or self._closed):
                    self._last_gc_at = now_utc
            did_work = True
        except BrainError as err:
            _m._LOGGER.warning("debounced maintenance failed (code=%s)", err.code.value)
            if err.code is ErrorCode.STORE_BUSY:
                with self._lock:
                    if self._generation == gen and not (self._stopping or self._closed):
                        self._last_gc_at = now_utc
            else:
                self._arm_maint_retry(gen)
        except sqlite3.Error:
            _m._LOGGER.warning("debounced maintenance failed (code=sqlite_error)")
            self._arm_maint_retry(gen)

    if _m._due(last_scheduled_at, now_utc):
        outcome = self._schedule_store_run("schedule")
        if outcome is not None:  # a failed attempt stays due and is retried on the next due pass
            with self._lock:
                if self._generation == gen and not (self._stopping or self._closed):
                    self._last_scheduled_at = now_utc
        else:
            self._arm_maint_retry(gen)
        if outcome:
            did_work = True

    self._finish_maint_attempt(gen)
    return did_work


def _claim_and_launch_worker(self: _m.DaemonDoctorRunner) -> bool:
    with self._lock:
        if self._stopping or self._closed or self._active_token is not None or self._pending_settle is not None:
            return False
        had_pending_claim = self._pending_lease is not None or self._reconcile_claims
        if had_pending_claim and self._claim_retry.backoff_active(self._generation, time.monotonic()):
            return False
        gen = self._generation
        if had_pending_claim:
            self._claim_retry.begin_attempt(gen)
        pending, self._pending_lease = self._pending_lease, None
        reconcile_claims, self._reconcile_claims = self._reconcile_claims, False

    if pending is None and reconcile_claims:
        try:
            pending = self._orphaned_claim()
        except BrainError as err:
            _m._LOGGER.warning("doctor claim reconcile failed (code=%s)", err.code.value)
            self._defer(gen, claims=True)
            return False
    lease = pending
    if lease is None:
        try:
            lease = self._job_service.lease_next_for_kinds(
                self._rt.lease.epoch,
                self._clock.now(),
                (DOCTOR_JOB_KIND,),
                emit_crashpoints=False,
                commit_guard=self._claim_guard if self._claim_guard is not None else self._can_claim_doctor,
            )
        except BrainError as err:
            _m._LOGGER.warning("doctor lease failed (code=%s)", err.code.value)
            # The lease may have committed before the error: find it by the durable state before claiming again.
            self._defer(gen, claims=True)
            return False
        if lease is None:
            if had_pending_claim:
                with self._lock:
                    self._claim_retry.finish_if_settled()
            return False

    try:
        spec = self._resolve_claim(lease, gen, reconcile=pending is not None)
    except BrainError as err:
        _m._LOGGER.warning("doctor claim unresolved (code=%s)", err.code.value)
        # Keep responsibility until a durable read confirms this lease has been resolved or replaced.
        self._defer(gen, lease=lease)
        return False
    if spec is None:
        if had_pending_claim:
            with self._lock:
                self._claim_retry.finish_if_settled()
        return True

    token = object()
    with self._lock:
        if self._stopping or self._closed or self._generation != gen:
            # A generation bump comes from restore or shutdown, whose reconcile/teardown cancels this job.
            return False
        self._active_token = token
        self._active_lease = lease
        if had_pending_claim:
            self._claim_retry.finish_if_settled()

    # From here the slot is held: every failure must release it and end the job (_abandon_launch).
    thread: threading.Thread | None = None
    try:
        trigger, checkout_root = parse_doctor_payload(spec.payload)
        fences = capture_doctor_fences(self._rt, self._adapters)
        root = self._rt.root
        owner_id = spec.owner_id
        thread = threading.Thread(
            target=self._run_worker,
            args=(lease, token, gen, owner_id, trigger, checkout_root, fences, root),
            name=f"doctor-worker-{lease.job_id[:8]}",
            daemon=True,
        )
        with self._lock:
            self._workers.add(thread)
        thread.start()
    except Exception:  # noqa: BLE001 - any launch failure (I/O, thread creation) ends the job, never the loop
        if thread is not None:
            with self._lock:
                self._workers.discard(thread)
        self._abandon_launch(lease, token, gen)
    return True


def _run_worker(
    self: _m.DaemonDoctorRunner,
    lease: JobLease,
    token: object,
    gen: int,
    owner_id: str,
    trigger: str,
    checkout_root: Path | None,
    fences: DoctorFences,
    root: DataRoot,
) -> None:
    adapters = self._adapters
    snap: DoctorSnapshot | None = None
    sp2: Sp2DoctorReport | None = None
    snap_dir: Path | None = None
    transient = False
    try:
        if checkout_root is not None:
            adapters.paths.reject_unsafe_path(str(checkout_root))
            if os.path.lexists(checkout_root):
                adapters.paths.reject_links(checkout_root)
        snap_dir = build_worker_db_snapshot(root, lease.job_id, adapters)
        snap = StorageDoctorReader(adapters).read_snapshot(
            root.root,
            db_root=snap_dir,
            checkout_root=checkout_root,
            expected_store_id=fences.store_id,
            privacy_scanner=self._scanner,
            capture_probe=self._fix_hooks.capture_probe,
        )
        sp2 = self._sp2_probe(root.root, checkout_root) if self._sp2_probe is not None else None
    except BrainError as err:
        _m._LOGGER.warning("doctor snapshot reader failed in background worker (code=%s)", err.code.value)
        snap = None
        transient = err.code is ErrorCode.STORE_BUSY  # the live pair kept changing: retry later, not fail
    except Exception:  # noqa: BLE001 - convert worker exception into failed job outcome safely
        _m._LOGGER.warning("doctor snapshot reader failed in background worker")
        snap = None
    finally:
        if snap_dir is not None:
            shutil.rmtree(snap_dir, ignore_errors=True)
        with self._lock:
            self._workers.discard(threading.current_thread())
            if self._generation == gen and self._active_token is token:
                self._completed = _CompletedDoctorProbe(
                    generation=gen,
                    lease=lease,
                    owner_id=owner_id,
                    trigger=trigger,
                    checkout_root=checkout_root,
                    snapshot=snap,
                    fences=fences,
                    transient=transient,
                    sp2=sp2,
                )
        self._wake_owner()


def _commit_completed(self: _m.DaemonDoctorRunner, completed: _CompletedDoctorProbe) -> None:
    with self._lock:
        if self._stopping or self._closed or completed.generation != self._generation:
            return  # restore reconcile or shutdown teardown ends this job
    if completed.lease.writer_epoch != self._rt.lease.epoch:
        self._notify_waiters()  # no longer this writer's job; lease recovery ends it
        return
    if completed.snapshot is None:
        self._end_failed(completed, retryable=completed.transient)
        return
    def _is_stale() -> bool:
        with self._lock:
            return self._stopping or self._closed or completed.generation != self._generation

    try:
        if not verify_doctor_snapshot_fences(self._rt, self._adapters, completed.fences):
            # Measured against an identity that no longer holds: rerun on a fresh snapshot instead of dropping it.
            self._end_failed(completed, retryable=True)
            return
        commit_utc, _ = require_aware_utc(self._clock.now())
        doctor_run_id = commit_doctor_run_snapshot(
            rt=self._rt, job_store=self._job_store, scanner=self._scanner,
            lease=completed.lease, owner_id=completed.owner_id, trigger=completed.trigger,
            checkout_root=completed.checkout_root, snapshot=completed.snapshot, now=commit_utc,
            tls_not_after=self._tls_not_after, clock_untrusted=self._clock_untrusted_fn(),
            is_stale_fn=_is_stale, sp2=completed.sp2,
        )
    except BrainError as err:
        # A busy store is transient: the same job reruns with backoff and its waiters keep waiting. If the commit
        # landed before the error, the fenced failure write is refused and the durable row (SUCCEEDED) is published.
        self._end_failed(completed, retryable=err.code in _m._TRANSIENT_COMMIT_CODES)
        return
    except sqlite3.Error:
        _m._LOGGER.warning("doctor run commit failed cleanly (code=sqlite_error)")
        self._end_failed(completed, retryable=True)
        return

    advance_schedule = False
    if completed.checkout_root is None and completed.trigger not in {"startup", "schedule"}:
        with contextlib.suppress(BrainError, sqlite3.Error):
            advance_schedule = resolve_store_owner(self._rt.policy) == completed.owner_id
    with self._lock:
        if completed.generation == self._generation and not (self._stopping or self._closed):
            self._record_finished_locked(completed.lease.job_id, "succeeded", doctor_run_id)
            self._fix_dirty = False
            if (
                advance_schedule
                and not self._startup_due
                and not self._maint_retry.pending
                and commit_utc > self._last_scheduled_at
            ):
                self._last_scheduled_at = commit_utc
    self._notify_waiters()


def _resolve_claim(self: _m.DaemonDoctorRunner, lease: JobLease, gen: int, *, reconcile: bool) -> JobSpec | None:
    already_started = False
    if reconcile:
        row = self._job_store.transact(lambda tx: tx.read_job(lease.job_id))
        if row is None:
            return None
        already_started = row.matches(lease, JobState.RUNNING)
        if not already_started and not row.matches(lease, JobState.LEASED):
            self._record_settled_at_claim(row, gen)
            return None

    if already_started:
        spec = self._job_service.resolve_started_doctor_spec(lease)
    else:
        spec = self._job_service.resolve_leased_spec(lease, fail_missing_payload=True)
        if spec is not None:
            self._job_service.start(lease)
    if spec is None:
        row = self._job_store.transact(lambda tx: tx.read_job(lease.job_id))
        if row is not None:
            self._record_settled_at_claim(row, gen)
    return spec


def _schedule_store_run(self: _m.DaemonDoctorRunner, trigger: str) -> bool | None:
    try:
        owner_id = resolve_store_owner(self._rt.policy)
        if owner_id is None:
            _m._LOGGER.info("doctor %s run skipped: store has no pinned owner", trigger)  # a normal fresh-store state
            return False
        if _m.find_active_doctor_job(self._rt, self._job_store, owner_id=owner_id, checkout_root=None) is not None:
            return False
        self._enqueue_system_doctor_job(owner_id, trigger)
    except BrainError as err:
        _m._LOGGER.warning("doctor %s run not scheduled (code=%s)", trigger, err.code.value)
        return None
    except sqlite3.Error:
        _m._LOGGER.warning("doctor %s run not scheduled (code=sqlite_error)", trigger)
        return None
    return True


def _complete_and_publish(self: _m.DaemonDoctorRunner, lease: JobLease, gen: int, outcome: JobOutcome) -> None:
    write_failed = False
    try:
        self._job_service.complete(lease, outcome)
    except BrainError as err:
        _m._LOGGER.warning("doctor job settlement failed (code=%s)", err.code.value)
        write_failed = True
    read_ok, row = self._read_job(lease.job_id)
    if not read_ok or (write_failed and row is not None and row.matches(lease, JobState.RUNNING)):
        self._defer(gen, settle=_m._PendingSettle(gen=gen, lease=lease, outcome=outcome))
        return
    if row is not None:
        self._publish_durable(row, gen)  # terminal (failed/dead_letter) is cached; a requeued job keeps waiting
    else:
        self._notify_waiters()


def step(self: _m.DaemonDoctorRunner, *, allow_new_jobs: bool) -> bool:
    with self._lock:
        stopped = self._stopping or self._closed
    if stopped:
        self._notify_waiters()
        return False

    did_work = False
    completed: _CompletedDoctorProbe | None = None
    with self._lock:
        if self._completed is not None:
            completed, self._completed = self._completed, None
            self._active_token, self._active_lease = None, None

    if completed is not None:
        self._commit_completed(completed)
        did_work = True

    settle: _m._PendingSettle | None = None
    with self._lock:
        if self._pending_settle is not None and not self._settle_retry.backoff_active(
            self._generation, time.monotonic()
        ):
            settle, self._pending_settle = self._pending_settle, None
            self._settle_retry.begin_attempt(self._generation)
    if settle is not None:
        self._complete_and_publish(settle.lease, settle.gen, settle.outcome)
        with self._lock:
            if self._pending_settle is None:
                self._settle_retry.finish_if_settled()
                did_work = True  # a re-deferred retry waits for the owner loop retry deadline

    if allow_new_jobs and not self._is_stopping_or_closed():
        if self._run_maintenance_and_schedule():
            did_work = True
        if self._claim_and_launch_worker():
            did_work = True

    if self._is_settled_now():
        self._notify_waiters()
    return did_work
