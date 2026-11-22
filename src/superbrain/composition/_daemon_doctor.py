"""Daemon background ``system.doctor`` job runner and 24h schedule/GC debounce."""

from __future__ import annotations

import contextlib
import logging
import os
import shutil
import threading
import time
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta
from pathlib import Path

from superbrain.application._approvals_types import DoctorOperatorHandler, DoctorOperatorTicket
from superbrain.application._privacy_canary import KernelPrivacyScanner
from superbrain.application.dispatch import PreparedEffect
from superbrain.application.jobs import JobService
from superbrain.composition._daemon_doctor_commit import (
    _CompletedDoctorProbe,
    commit_doctor_run_snapshot,
    create_doctor_scratch_snapshot,
    find_latest_intact_doctor_run,
    parse_doctor_payload,
    read_doctor_job_outcome_dto,
    resolve_store_owner,
    verify_doctor_snapshot_fences,
)
from superbrain.composition._daemon_health import (
    DOCTOR_JOB_KIND,
    enqueue_doctor_tx,
    find_fresh_doctor_run_dto,
    prepare_deep_health,
    render_deep_health,
)
from superbrain.composition._doctor_fix_wiring import (
    DoctorFixHooks,
    fresh_report_matches_live_state,
    run_online_doctor_fix,
)
from superbrain.core.canonical import canonical_json
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    Call,
    CallContext,
    JobErrorCode,
    JobLease,
    JobOutcome,
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
from superbrain.storage.retention import expire_due
from superbrain.storage.runtime import Runtime

DOCTOR_SCHEDULE_INTERVAL = timedelta(hours=24)
_MAX_FINISHED_CACHE = 256
_LOGGER = logging.getLogger(__name__)



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
        self._job_checkouts: dict[str, str | None] = {}

    def _record_finished_locked(self, job_id: str, status: str, doctor_run_id: str | None) -> None:
        self._finished_jobs[job_id] = (status, doctor_run_id)
        self._job_checkouts.pop(job_id, None)
        while len(self._finished_jobs) > _MAX_FINISHED_CACHE:
            oldest = next(iter(self._finished_jobs))
            del self._finished_jobs[oldest]

    def fence_on_restore(self) -> None:
        """Invalidate any in-flight background probe before store/policy handles are closed/swapped."""
        with self._lock:
            self._generation += 1
            self._active_token, self._active_lease, self._completed = None, None, None
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
        with self._lock:
            self._generation += 1
            self._active_token = None
            self._active_lease = None
            self._completed = None
            self._job_checkouts.clear()
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
            self._active_token, self._active_lease, self._completed = None, None, None
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
        self._notify_waiters()

    def cancel_on_teardown(self) -> None:
        """Cancel any unfinished ``system.doctor`` jobs before runtime closes on daemon shutdown."""
        with self._lock:
            self._closed, self._stopping, self._generation = True, True, self._generation + 1
            self._active_token, self._active_lease, self._completed = None, None, None
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
            busy = (
                self._startup_due
                or self._active_token is not None
                or self._completed is not None
                or (now_utc - self._last_scheduled_at > DOCTOR_SCHEDULE_INTERVAL)
                or (now_utc - self._last_gc_at > DOCTOR_SCHEDULE_INTERVAL)
            )
            if not busy and not self._has_active_doctor_job():
                return True
            self._waiters.append(wake_event)
            return False

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

    def _is_settled_now(self) -> bool:
        now_utc, _ = require_aware_utc(self._clock.now())
        with self._lock:
            if self._startup_due or self._active_token is not None or self._completed is not None:
                return False
            if (now_utc - self._last_scheduled_at > DOCTOR_SCHEDULE_INTERVAL) or (
                now_utc - self._last_gc_at > DOCTOR_SCHEDULE_INTERVAL
            ):
                return False
        return not self._has_active_doctor_job()

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
        with self._lock:
            self._job_checkouts[job_id] = co_str
            while len(self._job_checkouts) > _MAX_FINISHED_CACHE:
                oldest = next(iter(self._job_checkouts))
                del self._job_checkouts[oldest]
        return job_id

    def _run_maintenance_and_schedule(self) -> bool:
        now_utc, _ = require_aware_utc(self._clock.now())
        did_work = False

        if self._startup_due:
            self._startup_due = False
            owner_id = resolve_store_owner(self._rt.policy)
            latest = find_latest_intact_doctor_run(
                self._rt, owner_id, now_utc, max_age=DOCTOR_SCHEDULE_INTERVAL
            )
            if latest is None and not self._has_active_doctor_job():
                self._enqueue_system_doctor_job(owner_id, "startup")
                did_work = True
            elif latest is not None:
                self._last_scheduled_at = latest[2]
            self._last_gc_at = now_utc
            return did_work

        if now_utc - self._last_gc_at > DOCTOR_SCHEDULE_INTERVAL:
            try:
                expire_due(self._rt.store, self._rt.policy, now_utc)
                self._rt.store.cas.collect_garbage(now=now_utc)
                for _ in range(10):
                    if self._prune_idempotency_fn(now_utc, 100) < 100:
                        break
                self._last_gc_at = now_utc
                did_work = True
            except BrainError as err:
                _LOGGER.warning("debounced maintenance failed (code=%s)", err.code.value)
                if err.code is ErrorCode.STORE_BUSY:
                    self._last_gc_at = now_utc

        if now_utc - self._last_scheduled_at > DOCTOR_SCHEDULE_INTERVAL:
            self._last_scheduled_at = now_utc
            if not self._has_active_doctor_job():
                owner_id = resolve_store_owner(self._rt.policy)
                self._enqueue_system_doctor_job(owner_id, "schedule")
                did_work = True

        return did_work

    def _claim_and_launch_worker(self) -> bool:
        with self._lock:
            if self._stopping or self._closed or self._active_token is not None:
                return False
            gen = self._generation

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
            return False
        if lease is None:
            return False

        try:
            spec = self._job_service.resolve_leased_spec(lease)
            if spec is None:
                return True
            self._job_service.start(lease)
        except BrainError as err:
            if err.code is ErrorCode.REVISION_CONFLICT:
                return True
            _LOGGER.warning("doctor job start failed (code=%s)", err.code.value)
            return False

        trigger, checkout_root = parse_doctor_payload(spec.payload)
        token = object()
        with self._lock:
            if self._stopping or self._closed or self._generation != gen:
                return False
            self._active_token = token
            self._active_lease = lease

        try:
            snap_dir, f_sid, f_wep, f_rep, f_tgen = create_doctor_scratch_snapshot(
                self._rt, lease.job_id, self._adapters
            )
        except Exception as exc:  # noqa: BLE001
            _LOGGER.warning("failed creating doctor scratch snapshot on owner thread: %r", exc)
            return False

        expected_store_id = self._rt.store.store_id
        adapters = self._adapters
        scanner = self._scanner
        capture_probe = self._fix_hooks.capture_probe
        owner_id = spec.owner_id

        def _worker() -> None:
            snap: DoctorSnapshot | None = None
            try:
                if checkout_root is not None:
                    adapters.paths.reject_unsafe_path(str(checkout_root))
                    if os.path.lexists(checkout_root):
                        adapters.paths.reject_links(checkout_root)
                snap = StorageDoctorReader(adapters).read_snapshot(
                    self._rt.root.root,
                    db_root=snap_dir,
                    checkout_root=checkout_root,
                    expected_store_id=expected_store_id,
                    privacy_scanner=scanner,
                    capture_probe=capture_probe,
                )
            except Exception:  # noqa: BLE001 - convert worker exception into failed job outcome safely
                _LOGGER.warning("doctor snapshot reader failed in background worker")
                snap = None
            cur = threading.current_thread()
            with self._lock:
                self._workers.discard(cur)
                if self._generation == gen and self._active_token is token:
                    self._completed = _CompletedDoctorProbe(
                        generation=gen, lease=lease, owner_id=owner_id, trigger=trigger,
                        checkout_root=checkout_root, snapshot=snap, scratch_dir=snap_dir,
                        fence_store_id=f_sid, fence_writer_epoch=f_wep,
                        fence_restore_epoch=f_rep, fence_trust_generation=f_tgen,
                    )
            self._wake_owner()

        thread = threading.Thread(target=_worker, name=f"doctor-worker-{lease.job_id[:8]}", daemon=True)
        with self._lock:
            self._workers.add(thread)
        thread.start()
        return True

    def _commit_completed(self, completed: _CompletedDoctorProbe) -> None:
        try:
            with self._lock:
                if self._stopping or self._closed or completed.generation != self._generation:
                    return
            if completed.lease.writer_epoch != self._rt.lease.epoch:
                return
            if not verify_doctor_snapshot_fences(
                self._rt, self._adapters,
                fence_store_id=completed.fence_store_id,
                fence_writer_epoch=completed.fence_writer_epoch,
                fence_restore_epoch=completed.fence_restore_epoch,
                fence_trust_generation=completed.fence_trust_generation,
            ):
                return

            if completed.snapshot is None:
                with contextlib.suppress(BrainError):
                    self._job_service.complete(
                        completed.lease,
                        JobOutcome.failure(JobErrorCode.HANDLER_FAILED, retryable=False),
                    )
                with self._lock:
                    if completed.generation == self._generation:
                        self._record_finished_locked(completed.lease.job_id, "failed", None)
                self._notify_waiters()
                return

            def _is_stale() -> bool:
                with self._lock:
                    return self._stopping or self._closed or completed.generation != self._generation

            try:
                doctor_run_id = commit_doctor_run_snapshot(
                    rt=self._rt, job_store=self._job_store, scanner=self._scanner,
                    lease=completed.lease, owner_id=completed.owner_id, trigger=completed.trigger,
                    checkout_root=completed.checkout_root, snapshot=completed.snapshot, now=self._clock.now(),
                    tls_not_after=self._tls_not_after, clock_untrusted=self._clock_untrusted_fn(),
                    is_stale_fn=_is_stale,
                )
            except BrainError:
                with self._lock:
                    if completed.generation == self._generation:
                        self._record_finished_locked(completed.lease.job_id, "failed", None)
                self._notify_waiters()
                return

            with self._lock:
                self._record_finished_locked(completed.lease.job_id, "succeeded", doctor_run_id)
                self._fix_dirty = False
            self._notify_waiters()
        finally:
            if completed.scratch_dir is not None:
                shutil.rmtree(completed.scratch_dir, ignore_errors=True)

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
        job_id: str | None = None
        active = self._job_store.transact(lambda tx: tx.active_jobs_by_kinds((DOCTOR_JOB_KIND,), 100))
        with self._lock:
            for row in active:
                if row.owner_id == owner_id and self._job_checkouts.get(row.job_id) == co_str:
                    job_id = row.job_id
                    break
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

    def run_fix(self, *, owner_id: str, body: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
        """Owner thread: validate and execute safe §13 repairs against the running daemon runtime."""
        _ = owner_id
        with self._lock:
            if self._stopping or self._closed:
                raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")
        result = run_online_doctor_fix(
            self._rt, body, adapters=self._adapters, hooks=self._fix_hooks, privacy_scanner=self._scanner,
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
            self._rt, result, principal, now=self._clock.now(),
            tls_not_after=self._tls_not_after, clock_untrusted_fn=self._clock_untrusted_fn,
        )
