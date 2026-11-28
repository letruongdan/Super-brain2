"""DaemonDoctorRunner operator surfaces: doctor report, doctor --fix, and restore rebind."""

from __future__ import annotations

import os
import time
from collections.abc import Callable, Mapping
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from superbrain.application._approvals_types import (
    DoctorFixTicket,
    DoctorOperatorTicket,
    FixOwnerRunner,
)
from superbrain.application._doctor_fix import parse_fix_request_body
from superbrain.application.jobs import JobService
from superbrain.composition._daemon_doctor_commit import (
    read_doctor_job_outcome_dto,
)
from superbrain.composition._daemon_health import (
    find_fresh_doctor_run_dto,
)
from superbrain.composition._doctor_fix_wiring import (
    fresh_report_matches_live_state,
    run_fix_store_action,
    run_online_doctor_fix,
    validate_fix_checkout,
)
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    require_aware_utc,
)
from superbrain.storage.idempotency import StagedKernelStore
from superbrain.storage.runtime import Runtime

if TYPE_CHECKING:
    pass
from superbrain.composition import _daemon_doctor as _m


def prepare_report(
    self: _m.DaemonDoctorRunner, *, owner_id: str, checkout_root: Path | None = None
) -> DoctorOperatorTicket:
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
    job_id = _m.find_active_doctor_job(self._rt, self._job_store, owner_id=owner_id, checkout_root=co_str)
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


def wait_report(self: _m.DaemonDoctorRunner, job_id: str, *, generation: int, timeout_s: float) -> None:
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
    self: _m.DaemonDoctorRunner, *, owner_id: str, job_id: str, generation: int, writer_epoch: int
) -> dict[str, JsonValue]:
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


def prepare_fix(self: _m.DaemonDoctorRunner, *, owner_id: str, body: Mapping[str, JsonValue]) -> DoctorFixTicket:
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
    self: _m.DaemonDoctorRunner,
    ticket: DoctorFixTicket,
    *,
    should_stop: Callable[[], bool],
    run_on_owner: FixOwnerRunner,
) -> dict[str, JsonValue]:
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


def rebind_after_restore(
    self: _m.DaemonDoctorRunner,
    *,
    rt: Runtime,
    job_store: StagedKernelStore,
    job_service: JobService,
    tls_not_after: datetime | None = None,
) -> None:
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
