"""Owner-thread work, job claims and teardown of ``_daemon_session._AdmittedOwnerSession``."""

from __future__ import annotations

from concurrent.futures import Future

from superbrain.application._future_notify import safe_set_result
from superbrain.application.deadlines import Reservation
from superbrain.composition import _daemon_session as _m
from superbrain.composition._daemon_handoff_factory import build_default_handoff_domain as build_default_handoff_domain
from superbrain.composition._daemon_handoff_factory import (
    make_default_handoff_domain_factory as make_default_handoff_domain_factory,
)
from superbrain.composition._daemon_health import DOCTOR_JOB_KIND
from superbrain.composition._daemon_job_recovery import UNREADABLE
from superbrain.composition._endpoint import remove_own_endpoint
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import (
    AuthGrantStamp,
    CallResult,
    OwnerReply,
    SendAttemptCompletion,
    ShutdownReport,
    ShutdownState,
    WorkerCompleted,
    WorkerFailed,
)
from superbrain.ports.continuity import CONTINUITY_REFRESH_JOB_KIND
from superbrain.workers.executor import WorkItem


def teardown_on_owner(self: _m._AdmittedOwnerSession, *, overrun: bool, cancelled_requests: int = 0) -> ShutdownReport:
    self._listener.close()
    self._auth_gate.close()
    if self._operator is not None:
        self._operator.unbind()
    self._close_claim_gate()
    if self._doctor_runner is not None:
        self._doctor_runner.cancel_on_teardown()
    drained, worker_drained = self.shutdown_metrics()
    removed = False
    try:
        removed = remove_own_endpoint(self._rt.root, self._rt.lease, self._ready.endpoint, self._rt.os_)
    except BrainError as err:
        return ShutdownReport(
            state=ShutdownState.CLOSE_FAILED,
            drained_requests=drained,
            cancelled_requests=cancelled_requests,
            worker_drained=worker_drained,
            endpoint_removed=False,
            error_code=err.code,
        )
    try:
        if self._hooks.before_runtime_close is not None:
            self._hooks.before_runtime_close(self._rt)
        self._rt.close()
    except BrainError as err:
        return ShutdownReport(
            state=ShutdownState.CLOSE_FAILED,
            drained_requests=drained,
            cancelled_requests=cancelled_requests,
            worker_drained=worker_drained,
            endpoint_removed=removed,
            error_code=err.code,
        )
    except Exception:  # noqa: BLE001
        return ShutdownReport(
            state=ShutdownState.CLOSE_FAILED,
            drained_requests=drained,
            cancelled_requests=cancelled_requests,
            worker_drained=worker_drained,
            endpoint_removed=removed,
            error_code=ErrorCode.IO_ERROR,
        )
    if overrun:
        return ShutdownReport(
            state=ShutdownState.OVERRUN,
            drained_requests=drained,
            cancelled_requests=cancelled_requests,
            worker_drained=worker_drained,
            endpoint_removed=removed,
            error_code=ErrorCode.DEADLINE_EXCEEDED,
        )
    return ShutdownReport(
        state=ShutdownState.STOPPED,
        drained_requests=drained,
        cancelled_requests=cancelled_requests,
        worker_drained=worker_drained,
        endpoint_removed=removed,
        error_code=None,
    )


def _claim_and_submit_job(self: _m._AdmittedOwnerSession) -> bool:
    assert self._executor is not None
    if self._is_stopping() or self._executor.is_closed or self._executor.in_flight != 0:
        return False
    if not self._is_claim_open():
        return False
    try:
        # system.doctor jobs belong to the doctor runner; the generic executor must never lease them
        lease = self._job_service.lease_next_for_kinds(
            self._rt.lease.epoch, self._clock.now(), (DOCTOR_JOB_KIND,), exclude=True
        )
    except BrainError as err:
        if err.code is ErrorCode.POLICY_UNAVAILABLE:
            self._auth_gate.invalidate()
        _m._LOGGER.warning("daemon job lease failed (code=%s)", err.code.value)
        return False
    if lease is None:
        return False
    if not self._can_start_claimed_job():
        return True
    try:
        spec = self._job_service.resolve_leased_spec(lease)
        if spec is None:
            return True
        if not self._can_start_claimed_job():
            return True
        if spec.kind == CONTINUITY_REFRESH_JOB_KIND:
            run_spec = self._continuity_worker.admit_claimed(lease, spec, now=self._clock.now())
            if run_spec is None:
                return True
            self._leased.remember_spec(lease, spec)  # task and cutoff for the completion, without a re-read
            spec = run_spec
        else:
            self._job_service.start(lease)
        item = WorkItem(
            lease=lease,
            spec=spec,
            invocation_ids=(),
            deadline_ns=self._monotonic_clock.monotonic_ns() + _m._DAEMON_WORKER_ITEM_BUDGET_NS,
        )
        self._executor.submit(item)
        return True
    except BrainError as err:
        if err.code in (ErrorCode.REVISION_CONFLICT, ErrorCode.DAEMON_UNAVAILABLE):
            return True
        if err.code is ErrorCode.POLICY_UNAVAILABLE:
            self._auth_gate.invalidate()
        _m._LOGGER.warning("daemon job claim failed (code=%s)", err.code.value)
        if err.code in UNREADABLE:
            self._leased.retry(lease)  # leased but not handed to the worker: queue the attempt again
        return False


def _resolve_reply_future(
    self: _m._AdmittedOwnerSession,
    future: Future[OwnerReply],
    holder: list[Reservation],
    envelope: CallResult,
) -> None:
    stamp: AuthGrantStamp | None = None
    completion: SendAttemptCompletion | None = None
    if holder:
        with self._reply_meta_lock:
            meta = self._reply_meta.pop(holder[0].reservation_id, None)
        if envelope.get("ok") is True and meta is not None:
            stamp, completion = meta
    safe_set_result(
        future,
        OwnerReply(
            envelope=envelope,
            grant_stamp=stamp,
            send_completion=completion,
        ),
    )


def step_owner_work(self: _m._AdmittedOwnerSession, *, allow_new_jobs: bool) -> bool:
    did_work = False
    if self._executor is not None:
        self._leased.retry_unfinished()
        while (wcmd := self._executor.next_command(0.0)) is not None:
            if self._bridge.reservations.expire_shutdown_if_due():
                break
            try:
                self._dispatch_worker_command(wcmd)
            except BrainError as err:
                # The command is consumed: without a fenced retry the job would stay running with no work.
                _m._LOGGER.warning("daemon job completion failed (code=%s)", err.code.value)
                if err.code in UNREADABLE and isinstance(wcmd, (WorkerCompleted, WorkerFailed)):
                    self._leased.retry(wcmd.lease)
            did_work = True
        if allow_new_jobs:
            self._scan_continuity_if_due()
            did_work = self._claim_and_submit_job() or did_work
    if self._doctor_runner is not None and self._doctor_runner.step(allow_new_jobs=allow_new_jobs):
        did_work = True
    if self._bridge.process_next_queued(block=False):
        did_work = True
        if allow_new_jobs and self._doctor_runner is not None:
            did_work = self._doctor_runner.claim_pending_if_idle() or did_work
    return did_work
