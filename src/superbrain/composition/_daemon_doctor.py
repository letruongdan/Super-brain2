"""Daemon background ``system.doctor`` job runner and 24h schedule/GC debounce."""

from __future__ import annotations

import contextlib
import logging
import os
import shutil
import sqlite3
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from superbrain.application._approvals_types import (
    DoctorFixTicket,
    DoctorOperatorHandler,
    DoctorOperatorTicket,
    FixOwnerRunner,
)
from superbrain.application._doctor_fix import parse_fix_request_body
from superbrain.application._privacy_canary import KernelPrivacyScanner
from superbrain.application.dispatch import PreparedEffect
from superbrain.application.jobs import JobService
from superbrain.composition._daemon_doctor_commit import (
    DoctorFences,
    _CompletedDoctorProbe,
    build_worker_db_snapshot,
    capture_doctor_fences,
    commit_doctor_run_snapshot,
    parse_doctor_payload,
    read_doctor_job_outcome_dto,
    resolve_store_owner,
    verify_doctor_snapshot_fences,
)
from superbrain.composition._daemon_health import (
    DOCTOR_JOB_KIND,
    enqueue_doctor_tx,
    find_active_doctor_job,
    find_fresh_doctor_run_dto,
    find_latest_valid_doctor_run,
    iter_owner_doctor_ledger,
    prepare_deep_health,
    render_deep_health,
)
from superbrain.composition._doctor_fix_wiring import (
    DoctorFixHooks,
    fresh_report_matches_live_state,
    run_fix_store_action,
    run_online_doctor_fix,
    validate_fix_checkout,
)
from superbrain.core.canonical import canonical_json
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    TERMINAL_JOB_STATES,
    Call,
    CallContext,
    JobErrorCode,
    JobLease,
    JobOutcome,
    JobRecord,
    JobSpec,
    JobState,
    Principal,
    Scope,
    StoredResult,
    require_aware_utc,
)
from superbrain.ports.clock import Clock
from superbrain.ports.doctor import DoctorSnapshot
from superbrain.ports.kernel import KernelTx
from superbrain.ports.os import OsAdapters
from superbrain.storage._doctor_reader import StorageDoctorReader
from superbrain.storage.idempotency import StagedKernelStore
from superbrain.storage.layout import DataRoot
from superbrain.storage.retention import expire_due
from superbrain.storage.runtime import Runtime

DOCTOR_SCHEDULE_INTERVAL = timedelta(hours=24)
_MAX_FINISHED_CACHE = 256
_TRANSIENT_COMMIT_CODES = frozenset({ErrorCode.STORE_BUSY, ErrorCode.FILESYSTEM_BUSY})
_SETTLE_RETRY_S = 0.2  # initial delay before retrying a failed startup/schedule/claim/settlement pass
_MAX_RETRY_S = 1.0  # bounded retry backoff ceiling across sustained transient store/OS failures
_MAX_SCHEDULE_WAIT_S = min(604_800.0, float(threading.TIMEOUT_MAX) - 1.0)  # cap above 24h without OS wait overflow
_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class _PendingSettle:
    """A doctor outcome whose write may or may not have committed: retried until the durable row resolves it."""

    gen: int
    lease: JobLease
    outcome: JobOutcome  # the failure to record through ``JobService.complete``


@dataclass
class _RetryLane:
    """Independent per-obligation backoff deadline and streak under ``DaemonDoctorRunner._lock``."""

    pending: bool = False
    due_mono: float | None = None
    gen: int = 0
    streak: int = 0

    def reset(self) -> None:
        self.pending = False
        self.due_mono = None
        self.gen = 0
        self.streak = 0

    def active_wait_s(self, current_gen: int, now_mono: float) -> float | None:
        if not self.pending or self.due_mono is None or self.gen != current_gen:
            return None
        return max(0.0, self.due_mono - now_mono)

    def backoff_active(self, current_gen: int, now_mono: float) -> bool:
        return self.pending and self.due_mono is not None and self.gen == current_gen and now_mono < self.due_mono

    def arm(self, current_gen: int, target_gen: int, now_mono: float) -> None:
        if current_gen != target_gen:
            return
        self.pending = True
        if self.due_mono is not None and self.gen == target_gen and now_mono < self.due_mono:
            return
        self.streak += 1
        delay_s = min(_MAX_RETRY_S, _SETTLE_RETRY_S * (2 ** min(3, self.streak - 1)))
        self.due_mono = now_mono + delay_s
        self.gen = target_gen

    def begin_attempt(self, current_gen: int) -> None:
        self.pending = False
        if self.gen == current_gen:
            self.due_mono = None

    def finish_if_settled(self) -> None:
        if not self.pending:
            self.streak = 0
            self.due_mono = None
            self.gen = 0



def _due(last: datetime, now_utc: datetime) -> bool:
    return now_utc - last >= DOCTOR_SCHEDULE_INTERVAL


class DaemonDoctorRunner(DoctorOperatorHandler):
    """Owns background ``system.doctor`` execution, 24h maintenance cadence, and ``get_health(deep=True)``."""

    def __init__(
        self,
        *,
        rt: Runtime,
        job_store: StagedKernelStore,
        job_service: JobService,
        adapters: OsAdapters,
        clock: Clock,
        tls_not_after: datetime,
        clock_untrusted_fn: Callable[[], bool],
        prune_idempotency_fn: Callable[[datetime, int], int],
        wake_owner: Callable[[], None],
        claim_guard: Callable[[], bool] | None = None,
        fix_hooks: DoctorFixHooks | None = None,
    ) -> None:
        self._rt = rt
        self._job_store = job_store
        self._job_service = job_service
        self._adapters = adapters
        self._clock = clock
        self._tls_not_after = tls_not_after
        self._clock_untrusted_fn = clock_untrusted_fn
        self._prune_idempotency_fn = prune_idempotency_fn
        self._wake_owner = wake_owner
        self._claim_guard = claim_guard
        self._fix_hooks = fix_hooks if fix_hooks is not None else DoctorFixHooks()
        self._fix_dirty = False
        self._scanner = KernelPrivacyScanner()

        self._lock = threading.Lock()
        self._wait_cond = threading.Condition(self._lock)
        self._generation = 1
        self._stopping = False
        self._closed = False
        self._startup_due = True
        now_utc, _ = require_aware_utc(self._clock.now())
        self._last_scheduled_at = now_utc
        self._last_gc_at = now_utc

        self._active_token: object | None = None
        self._active_lease: JobLease | None = None
        self._completed: _CompletedDoctorProbe | None = None
        self._workers: set[threading.Thread] = set()
        self._waiters: list[threading.Event] = []
        self._finished_jobs: dict[str, tuple[str, str | None]] = {}
        self._pending_lease: JobLease | None = None  # claimed doctor lease whose settle/start must be retried
        self._pending_settle: _PendingSettle | None = None  # outcome write not yet confirmed by the durable row
        self._reconcile_claims = False  # a lease attempt failed: it may have committed without returning the lease
        self._maint_retry = _RetryLane()
        self._claim_retry = _RetryLane()
        self._settle_retry = _RetryLane()

    def _record_finished_locked(self, job_id: str, status: str, doctor_run_id: str | None) -> None:
        self._finished_jobs[job_id] = (status, doctor_run_id)
        while len(self._finished_jobs) > _MAX_FINISHED_CACHE:
            oldest = next(iter(self._finished_jobs))
            del self._finished_jobs[oldest]

    def _clear_retry_locked(self) -> None:
        self._maint_retry.reset()
        self._claim_retry.reset()
        self._settle_retry.reset()

    def _drop_inflight_locked(self) -> None:
        self._active_token, self._active_lease, self._completed = None, None, None
        self._pending_lease, self._pending_settle, self._reconcile_claims = None, None, False
        self._clear_retry_locked()

    def fence_on_restore(self) -> None:
        """Invalidate any in-flight background probe before store/policy handles are closed/swapped."""
        with self._lock:
            self._generation += 1
            self._drop_inflight_locked()
            self._finished_jobs.clear()  # outcomes of the pre-restore store/epoch must never answer a later report
            self._wait_cond.notify_all()
        self._notify_waiters()

    def rebind_after_restore(
        self,
        *,
        rt: Runtime,
        job_store: StagedKernelStore,
        job_service: JobService,
        tls_not_after: datetime | None = None,
    ) -> None:
        """Bind new runtime/stores post-restore and invalidate any pre-restore probes."""
        now_utc: datetime | None = None
        try:
            now_utc, _ = require_aware_utc(self._clock.now())
        except BrainError:
            now_utc = None
        with self._lock:
            self._generation += 1
            self._drop_inflight_locked()
            self._finished_jobs.clear()
            if now_utc is not None:
                self._last_scheduled_at = now_utc
                self._last_gc_at = now_utc
            self._rt = rt
            self._job_store = job_store
            self._job_service = job_service
            if tls_not_after is not None:
                self._tls_not_after = tls_not_after
            self._wait_cond.notify_all()
        self._notify_waiters()

    def finish_restore_reconcile(self) -> None:
        """Cancel all pre-restore queued/active ``system.doctor`` jobs after epoch recovery."""
        self._job_service.cancel_jobs_by_kinds((DOCTOR_JOB_KIND,))
        self._notify_waiters()

    def begin_stop(self) -> None:
        with self._lock:
            self._stopping = True
            self._startup_due = False
            self._generation += 1
            self._drop_inflight_locked()
        self._notify_waiters()

    @property
    def is_drained(self) -> bool:
        with self._lock:
            return not any(w.is_alive() for w in self._workers)

    def join(self, timeout_s: float) -> bool:
        with self._lock:
            workers = list(self._workers)
        if not workers:
            return True
        deadline_mono = time.monotonic() + max(0.0, timeout_s)
        all_done = True
        for w in workers:
            rem = max(0.0, deadline_mono - time.monotonic())
            w.join(timeout=rem)
            if w.is_alive():
                all_done = False
        return all_done

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._stopping = True
            self._clear_retry_locked()
        self._notify_waiters()

    def cancel_on_teardown(self) -> None:
        """Cancel any unfinished ``system.doctor`` jobs before runtime closes on daemon shutdown."""
        with self._lock:
            self._closed, self._stopping, self._generation = True, True, self._generation + 1
            self._drop_inflight_locked()
        self._notify_waiters()
        if not self._rt.store.closed and not self._rt.policy.closed:
            with contextlib.suppress(BrainError):
                self._job_service.cancel_jobs_by_kinds((DOCTOR_JOB_KIND,))

    def claim_pending_if_idle(self) -> bool:
        """Immediately claim and launch any queued ``system.doctor`` job when idle."""
        return self._claim_and_launch_worker()

    def _notify_waiters(self) -> None:
        with self._lock:
            waiters = self._waiters
            self._waiters = []
            self._wait_cond.notify_all()
        for ev in waiters:
            ev.set()

    def poll_settled(self, wake_event: threading.Event) -> bool:
        """Called on owner thread by ``wait_doctor_settled``: advance work and report if completely settled."""
        with self._lock:
            if self._stopping or self._closed:
                return False
        self.step(allow_new_jobs=True)
        now_utc, _ = require_aware_utc(self._clock.now())
        with self._lock:
            if self._stopping or self._closed:
                return False
            if not self._is_busy_locked(now_utc) and not self._has_active_doctor_job():
                return True
            self._waiters.append(wake_event)
            return False

    def next_retry_wait_s(self) -> float | None:
        """Seconds until the earliest due doctor retry lane, or ``None`` when no retry is pending."""
        with self._lock:
            if self._stopping or self._closed:
                return None
            now_mono = time.monotonic()
            waits = [
                wait
                for lane in (self._maint_retry, self._claim_retry, self._settle_retry)
                if (wait := lane.active_wait_s(self._generation, now_mono)) is not None
            ]
            return min(waits) if waits else None

    def next_schedule_wait_s(self) -> float | None:
        """Seconds until the next periodic maintenance/doctor check, or ``None`` if startup/retry owns wakeups."""
        with self._lock:
            if self._stopping or self._closed or self._startup_due or self._maint_retry.pending:
                return None
        try:
            now_utc, _ = require_aware_utc(self._clock.now())
        except BrainError:
            return _MAX_RETRY_S
        with self._lock:
            if self._stopping or self._closed or self._startup_due or self._maint_retry.pending:
                return None
            next_due_utc = min(self._last_scheduled_at, self._last_gc_at) + DOCTOR_SCHEDULE_INTERVAL
            due_in_s = max(0.0, (next_due_utc - now_utc).total_seconds())
            return min(due_in_s, _MAX_SCHEDULE_WAIT_S)

    def next_wake_wait_s(self) -> float | None:
        """Seconds until the owner loop must next wake for retries or due periodic doctor/GC maintenance."""
        waits = [w for w in (self.next_retry_wait_s(), self.next_schedule_wait_s()) if w is not None]
        return min(waits) if waits else None

    def step(self, *, allow_new_jobs: bool) -> bool:
        """Advance background doctor work and 24h maintenance on the owner thread."""
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

        settle: _PendingSettle | None = None
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

    def _is_stopping_or_closed(self) -> bool:
        with self._lock:
            return self._stopping or self._closed

    def _can_claim_doctor(self) -> bool:
        return not self._is_stopping_or_closed()

    def _is_busy_locked(self, now_utc: datetime) -> bool:
        return (
            self._startup_due
            or self._maint_retry.pending
            or self._claim_retry.pending
            or self._settle_retry.pending
            or self._active_token is not None
            or self._completed is not None
            or self._has_unresolved_locked()
            or self._maintenance_due_locked(now_utc)
        )

    def _is_settled_now(self) -> bool:
        now_utc, _ = require_aware_utc(self._clock.now())
        with self._lock:
            if self._is_busy_locked(now_utc):
                return False
        return not self._has_active_doctor_job()

    def _has_unresolved_locked(self) -> bool:
        return self._pending_lease is not None or self._pending_settle is not None or self._reconcile_claims

    def _arm_maint_retry(self, gen: int) -> None:
        """Arm the maintenance/schedule retry lane for ``gen`` without delaying claim/settle lanes."""
        with self._lock:
            if not (self._stopping or self._closed):
                self._maint_retry.arm(self._generation, gen, time.monotonic())

    def _defer(
        self, gen: int, *, lease: JobLease | None = None, settle: _PendingSettle | None = None, claims: bool = False
    ) -> None:
        """Keep responsibility for an unresolved write of generation ``gen`` and schedule its retry lane."""
        with self._lock:
            if self._generation != gen or self._stopping or self._closed:
                return
            now_mono = time.monotonic()
            if lease is not None:
                self._pending_lease = lease
            if claims:
                self._reconcile_claims = True
            if lease is not None or claims:
                self._claim_retry.arm(self._generation, gen, now_mono)
            if settle is not None:
                self._pending_settle = settle
                self._settle_retry.arm(self._generation, gen, now_mono)

    def _maintenance_due_locked(self, now_utc: datetime) -> bool:
        """Background work is due once a full interval has elapsed (``>=``), the one rule settle and schedule share."""
        return _due(self._last_scheduled_at, now_utc) or _due(self._last_gc_at, now_utc)

    def _has_active_doctor_job(self) -> bool:
        try:
            rows = self._job_store.transact(lambda tx: tx.active_jobs_by_kinds((DOCTOR_JOB_KIND,), 1))
        except BrainError:
            return False
        return bool(rows)

    def _enqueue_system_doctor_job(
        self, owner_id: str, trigger: str, *, checkout_root: Path | None = None
    ) -> str:
        job_id = new_id()
        co_str = str(checkout_root) if checkout_root is not None else None
        payload_bytes = canonical_json({"schema": 1, "trigger": trigger, "checkout_root": co_str})
        self._job_store.stage_blob(payload_bytes)
        _, now_str = require_aware_utc(self._clock.now())

        def enqueue(tx: KernelTx) -> None:
            enqueue_doctor_tx(tx, job_id=job_id, owner_id=owner_id, payload_bytes=payload_bytes, retry_at=now_str)

        self._job_store.transact(enqueue)
        return job_id

    def _schedule_store_run(self, trigger: str) -> bool | None:
        """Enqueue a background run for the store owner's ``(owner, None)`` scope unless that slot is taken.

        ``True`` enqueued, ``False`` nothing to do (slot taken or no pinned owner), ``None`` the attempt failed and
        must be retried: the caller keeps the work due instead of deferring it a whole interval.
        """
        try:
            owner_id = resolve_store_owner(self._rt.policy)
            if owner_id is None:
                _LOGGER.info("doctor %s run skipped: store has no pinned owner", trigger)  # a normal fresh-store state
                return False
            if find_active_doctor_job(self._rt, self._job_store, owner_id=owner_id, checkout_root=None) is not None:
                return False
            self._enqueue_system_doctor_job(owner_id, trigger)
        except BrainError as err:
            _LOGGER.warning("doctor %s run not scheduled (code=%s)", trigger, err.code.value)
            return None
        except sqlite3.Error:
            _LOGGER.warning("doctor %s run not scheduled (code=sqlite_error)", trigger)
            return None
        return True

    def _finish_maint_attempt(self, gen: int) -> None:
        with self._lock:
            if self._generation == gen and not (self._stopping or self._closed):
                self._maint_retry.finish_if_settled()

    def _run_maintenance_and_schedule(self) -> bool:
        with self._lock:
            if self._maint_retry.backoff_active(self._generation, time.monotonic()):
                return False
            gen = self._generation
            self._maint_retry.begin_attempt(gen)
            startup_due = self._startup_due
            last_gc_at = self._last_gc_at
            last_scheduled_at = self._last_scheduled_at
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
                _LOGGER.warning("doctor startup lookup failed (code=%s)", err.code.value)
                self._arm_maint_retry(gen)
                return False
            except sqlite3.Error:
                _LOGGER.warning("doctor startup lookup failed (code=sqlite_error)")
                self._arm_maint_retry(gen)
                return False
            if latest is not None and not _due(latest[0].recorded_at, now_utc):
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

        if _due(last_gc_at, now_utc):
            try:
                expire_due(self._rt.store, self._rt.policy, now_utc)
                self._rt.store.cas.collect_garbage(now=now_utc)
                for _ in range(10):
                    if self._prune_idempotency_fn(now_utc, 100) < 100:
                        break
                with self._lock:
                    if self._generation == gen and not (self._stopping or self._closed):
                        self._last_gc_at = now_utc
                did_work = True
            except BrainError as err:
                _LOGGER.warning("debounced maintenance failed (code=%s)", err.code.value)
                if err.code is ErrorCode.STORE_BUSY:
                    with self._lock:
                        if self._generation == gen and not (self._stopping or self._closed):
                            self._last_gc_at = now_utc
                else:
                    self._arm_maint_retry(gen)
            except sqlite3.Error:
                _LOGGER.warning("debounced maintenance failed (code=sqlite_error)")
                self._arm_maint_retry(gen)

        if _due(last_scheduled_at, now_utc):
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

    def _claim_and_launch_worker(self) -> bool:
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
                _LOGGER.warning("doctor claim reconcile failed (code=%s)", err.code.value)
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
                _LOGGER.warning("doctor lease failed (code=%s)", err.code.value)
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
            _LOGGER.warning("doctor claim unresolved (code=%s)", err.code.value)
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

    def _resolve_claim(self, lease: JobLease, gen: int, *, reconcile: bool) -> JobSpec | None:
        """Resolve a new claim or check the durable state after an uncertain write."""
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

    def _orphaned_claim(self) -> JobLease | None:
        """The doctor lease this writer epoch committed but never received, read from the durable job state."""
        epoch = self._rt.lease.epoch
        rows = self._job_store.transact(lambda tx: tx.claimed_jobs_by_kinds((DOCTOR_JOB_KIND,), epoch, 1))
        for row in rows:
            if row.writer_epoch is not None and row.lease_id is not None:
                return JobLease(row.job_id, row.attempt, row.writer_epoch, row.lease_id)
        return None

    def _record_settled_at_claim(self, row: JobRecord, gen: int) -> None:
        """Publish only terminal outcomes observed in the durable store."""
        self._publish_durable(row, gen)

    def _publish_durable(self, row: JobRecord, gen: int) -> None:
        """Answer waiters from a durable row: a terminal state is cached (with its committed run), else they wait."""
        if row.state in TERMINAL_JOB_STATES:
            run_id = self._committed_run_id(row) if row.state is JobState.SUCCEEDED else None
            with self._lock:
                if self._generation == gen:
                    self._record_finished_locked(row.job_id, row.state.value, run_id)
                    if row.state is JobState.SUCCEEDED:
                        self._fix_dirty = False
        self._notify_waiters()

    def _committed_run_id(self, row: JobRecord) -> str | None:
        try:
            for meta, _refs in iter_owner_doctor_ledger(self._rt, owner_id=row.owner_id, job_id=row.job_id):
                run_id = meta.get("doctor_run_id")
                if isinstance(run_id, str):
                    return run_id
        except BrainError as err:
            _LOGGER.warning("doctor run lookup failed (code=%s)", err.code.value)
        except sqlite3.Error:
            _LOGGER.warning("doctor run lookup failed (code=sqlite_error)")
        return None  # finish_report then resolves the run from the store by job

    def _read_job(self, job_id: str) -> tuple[bool, JobRecord | None]:
        """``(read_ok, row)``: a failed read is not a conclusion about the job."""
        try:
            return True, self._job_store.transact(lambda tx: tx.read_job(job_id))
        except BrainError as err:
            _LOGGER.warning("doctor job read failed (code=%s)", err.code.value)
            return False, None

    def _complete_and_publish(self, lease: JobLease, gen: int, outcome: JobOutcome) -> None:
        """Write a failure outcome, then publish only what the durable row confirms; an unconfirmed write retries."""
        write_failed = False
        try:
            self._job_service.complete(lease, outcome)
        except BrainError as err:
            _LOGGER.warning("doctor job settlement failed (code=%s)", err.code.value)
            write_failed = True
        read_ok, row = self._read_job(lease.job_id)
        if not read_ok or (write_failed and row is not None and row.matches(lease, JobState.RUNNING)):
            self._defer(gen, settle=_PendingSettle(gen=gen, lease=lease, outcome=outcome))
            return
        if row is not None:
            self._publish_durable(row, gen)  # terminal (failed/dead_letter) is cached; a requeued job keeps waiting
        else:
            self._notify_waiters()

    def _abandon_launch(self, lease: JobLease, token: object, gen: int) -> None:
        """Owner thread: release a claimed slot whose worker never started and fail its job durably."""
        _LOGGER.warning("doctor worker launch failed (job=%s)", lease.job_id[:8])
        with self._lock:
            if self._active_token is token:
                self._active_token, self._active_lease = None, None
            current = self._generation == gen
        if current:
            self._complete_and_publish(lease, gen, JobOutcome.failure(JobErrorCode.HANDLER_FAILED, retryable=False))
        else:
            self._notify_waiters()

    def _run_worker(
        self,
        lease: JobLease,
        token: object,
        gen: int,
        owner_id: str,
        trigger: str,
        checkout_root: Path | None,
        fences: DoctorFences,
        root: DataRoot,
    ) -> None:
        """Worker thread: take the minimal DB snapshot, read it, and hand the result back to the owner."""
        adapters = self._adapters
        snap: DoctorSnapshot | None = None
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
        except BrainError as err:
            _LOGGER.warning("doctor snapshot reader failed in background worker (code=%s)", err.code.value)
            snap = None
            transient = err.code is ErrorCode.STORE_BUSY  # the live pair kept changing: retry later, not fail
        except Exception:  # noqa: BLE001 - convert worker exception into failed job outcome safely
            _LOGGER.warning("doctor snapshot reader failed in background worker")
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
                    )
            self._wake_owner()

    def _end_failed(self, completed: _CompletedDoctorProbe, *, retryable: bool) -> None:
        """Owner thread: end a probe that cannot commit; a retryable failure requeues the same job with backoff."""
        with self._lock:
            current = not (self._stopping or self._closed) and completed.generation == self._generation
        if current:
            self._complete_and_publish(
                completed.lease,
                completed.generation,
                JobOutcome.failure(JobErrorCode.HANDLER_FAILED, retryable=retryable),
            )
        else:
            self._notify_waiters()

    def _commit_completed(self, completed: _CompletedDoctorProbe) -> None:
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
                is_stale_fn=_is_stale,
            )
        except BrainError as err:
            # A busy store is transient: the same job reruns with backoff and its waiters keep waiting. If the commit
            # landed before the error, the fenced failure write is refused and the durable row (SUCCEEDED) is published.
            self._end_failed(completed, retryable=err.code in _TRANSIENT_COMMIT_CODES)
            return
        except sqlite3.Error:
            _LOGGER.warning("doctor run commit failed cleanly (code=sqlite_error)")
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

    def prepare_report(self, *, owner_id: str, checkout_root: Path | None = None) -> DoctorOperatorTicket:
        """Phase 1 (owner thread): reuse fresh ``DoctorRun`` or enqueue/join ``system.doctor`` for ``owner_id``."""
        with self._lock:
            if self._stopping or self._closed:
                raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")
            gen = self._generation
            dirty = self._fix_dirty
        if checkout_root is not None:
            self._adapters.paths.reject_unsafe_path(str(checkout_root))
            if not checkout_root.is_absolute():
                raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
            if os.path.lexists(checkout_root):
                self._adapters.paths.reject_links(checkout_root)
        fresh = find_fresh_doctor_run_dto(
            self._rt, self._adapters, owner_id, self._clock.now(), checkout_root=checkout_root
        )
        if fresh is not None and not fresh_report_matches_live_state(
            self._rt, self._adapters, fresh, fix_dirty=dirty
        ):
            fresh = None
        if fresh is not None:
            return DoctorOperatorTicket(
                job_id=str(fresh.get("job_id") or ""),
                generation=gen,
                writer_epoch=self._rt.lease.epoch,
                checkout_root=checkout_root,
                immediate=fresh,
            )
        co_str = str(checkout_root) if checkout_root is not None else None
        job_id = find_active_doctor_job(self._rt, self._job_store, owner_id=owner_id, checkout_root=co_str)
        if job_id is None:
            job_id = self._enqueue_system_doctor_job(owner_id, "cli", checkout_root=checkout_root)
        self._claim_and_launch_worker()
        with self._lock:
            return DoctorOperatorTicket(
                job_id=job_id,
                generation=self._generation,
                writer_epoch=self._rt.lease.epoch,
                checkout_root=checkout_root,
            )

    def wait_report(self, job_id: str, *, generation: int, timeout_s: float) -> None:
        """Phase 2 (off owner thread): wait up to ``timeout_s`` for job finish, restore/fence, or shutdown."""
        deadline = time.monotonic() + max(0.0, timeout_s)
        with self._wait_cond:
            while not (
                self._stopping or self._closed or self._generation != generation or job_id in self._finished_jobs
            ):
                rem = deadline - time.monotonic()
                if rem <= 0.0:
                    break
                self._wait_cond.wait(timeout=rem)

    def finish_report(
        self, *, owner_id: str, job_id: str, generation: int, writer_epoch: int
    ) -> dict[str, JsonValue]:
        """Phase 3 (owner thread): enforce generation/epoch fences and return completed DTO or ``running``."""
        with self._lock:
            if self._stopping or self._closed:
                raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")
            if generation != self._generation or writer_epoch != self._rt.lease.epoch:
                raise BrainError(ErrorCode.REVISION_CONFLICT, "revision conflict")
            outcome = self._finished_jobs.get(job_id)
        return read_doctor_job_outcome_dto(
            rt=self._rt, job_store=self._job_store, owner_id=owner_id,
            job_id=job_id, cached_outcome=outcome, now=self._clock.now(),
        )

    def prepare_fix(self, *, owner_id: str, body: Mapping[str, JsonValue]) -> DoctorFixTicket:
        """Phase 1 (owner thread, bounded): validate the request and pin the generation it runs under.

        Every fix action changes the whole store (permissions, logs, projections, policy, daemon), so the operator
        must be the store's pinned owner; any other owner sees ``NOT_FOUND`` and nothing runs.
        """
        store_owner = self._rt.policy.store_owner()
        if store_owner is None or owner_id != store_owner:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        actions, checkout_root = parse_fix_request_body(body)
        validate_fix_checkout(checkout_root, self._adapters)
        with self._lock:
            if self._stopping or self._closed:
                raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")
            # Any fix may change what a cached DoctorRun measured.
            self._fix_dirty = True
            return DoctorFixTicket(
                generation=self._generation,
                store_id=self._rt.store.store_id,
                actions=actions,
                explicit_actions="actions" in body,
                checkout_root=checkout_root,
            )

    def execute_fix(
        self,
        ticket: DoctorFixTicket,
        *,
        should_stop: Callable[[], bool],
        run_on_owner: FixOwnerRunner,
    ) -> dict[str, JsonValue]:
        """Phase 2 (off owner thread): filesystem repairs and the recheck run here; store repairs go to the owner.

        Stops between steps once ``should_stop`` (the request cutoff) fires or the runtime changes generation, and
        returns ``status: interrupted`` with each action's definite state. Nothing of this fix runs afterwards.
        """
        with self._lock:
            root = self._rt.root

        def _stop() -> bool:
            with self._lock:
                if self._stopping or self._closed or self._generation != ticket.generation:
                    return True
            return should_stop()

        def _live_rt() -> Runtime:
            # Owner thread, at the moment the step starts (not when it was queued): a step that waited past the
            # cutoff, a restore or a shutdown never runs.
            if _stop():
                raise BrainError(ErrorCode.REVISION_CONFLICT, "revision conflict")
            with self._lock:
                return self._rt

        def _store_action(name: str) -> dict[str, JsonValue]:
            return run_on_owner(
                lambda: run_fix_store_action(
                    _live_rt(),
                    name,
                    explicit_actions=ticket.explicit_actions,
                    adapters=self._adapters,
                    hooks=self._fix_hooks,
                )
            )

        def _authorize() -> None:
            run_on_owner(_live_rt)

        result = run_online_doctor_fix(
            root,
            store_id=ticket.store_id,
            actions=ticket.actions,
            checkout_root=ticket.checkout_root,
            adapters=self._adapters,
            hooks=self._fix_hooks,
            privacy_scanner=self._scanner,
            should_stop=_stop,
            run_store_action=_store_action,
            authorize=_authorize,
        )
        with self._lock:
            self._fix_dirty = True
        return result

    def prepare_deep_health(self, call: Call, ctx: CallContext, *, now: datetime) -> PreparedEffect:
        """Prepare idempotent ``get_health(deep=True)`` effect scoped strictly by ``ctx.principal.owner_id``."""
        _ = call
        return prepare_deep_health(self._rt, self._job_store, owner_id=ctx.principal.owner_id, now=now)

    def render_deep_health(
        self, result: StoredResult, principal: Principal, *, selected_scope: Scope | None
    ) -> dict[str, JsonValue]:
        """Render ``get_health(deep=True)`` from CAS descriptor & live policy/quarantine/clock checks."""
        _ = selected_scope
        return render_deep_health(
            self._rt, self._job_store, result, principal, now=self._clock.now(),
            tls_not_after=self._tls_not_after, clock_untrusted_fn=self._clock_untrusted_fn,
        )
