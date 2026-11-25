"""Private composite domain and admitted owner-session adapter for Task 6a daemon composition."""

from __future__ import annotations

import contextlib
import logging
import threading
import time
from collections.abc import Callable, Mapping
from concurrent.futures import Future
from dataclasses import dataclass
from datetime import datetime

from superbrain.application._future_notify import safe_set_result
from superbrain.application.approvals import OperatorHandle
from superbrain.application.deadlines import Reservation
from superbrain.application.dispatch import KernelToolDomain, PreparedEffect
from superbrain.application.jobs import JobService
from superbrain.application.owner_loop import AuthGate, OwnerSession
from superbrain.composition._daemon_doctor import DaemonDoctorRunner
from superbrain.composition._endpoint import BoundLoopbackListener, remove_own_endpoint
from superbrain.composition.kernel_bridge import KernelBridge
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    ArtifactSendAttempt,
    ArtifactSendSpec,
    AuthGrantStamp,
    BootstrapAuthorization,
    Call,
    CallContext,
    CallResult,
    Endpoint,
    InvocationRecord,
    JobRecord,
    OwnerReply,
    Principal,
    Ready,
    RequestAuthView,
    Scope,
    SendAttemptCompletion,
    ShutdownReport,
    ShutdownState,
    StoredResult,
    ToolCommand,
    WorkerCommand,
    WorkerUsage,
    WorkspaceBinding,
    WorkspaceRegistration,
)
from superbrain.ports.clock import Clock, MonotonicClock
from superbrain.ports.policy import Intent
from superbrain.storage.idempotency import StagedKernelStore
from superbrain.storage.runtime import Runtime
from superbrain.workers.executor import JobExecutor, WorkItem

_DAEMON_WORKER_ITEM_BUDGET_NS = 60_000_000_000
_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class DaemonTestHooks:
    """Optional deterministic barriers/fault seams for daemon lifecycle integration tests."""

    after_tls_verify: Callable[[], None] | None = None
    after_open_before_rebuild: Callable[[Runtime], None] | None = None
    before_job_recover: Callable[[Runtime], None] | None = None
    before_bind: Callable[[Runtime], None] | None = None
    before_endpoint_publish: Callable[[Endpoint], None] | None = None
    after_endpoint_publish_before_final_tls_check: Callable[[Endpoint], None] | None = None
    before_auth_gate_publish: Callable[[RequestAuthView], None] | None = None
    before_enter_commit: Callable[[Reservation | None], None] | None = None
    after_reserve_before_enqueue: Callable[[Reservation], None] | None = None
    before_runtime_close: Callable[[Runtime], None] | None = None


class _DaemonCompositeDomain:
    """Serves ``get_job``, ``get_health(deep=True)``, and delegates any injected test/business domain tools."""

    def __init__(
        self,
        job_service: JobService,
        delegate: KernelToolDomain | None,
        doctor_runner: DaemonDoctorRunner | None = None,
    ) -> None:
        self._job_service = job_service
        self._delegate = delegate
        self._doctor_runner = doctor_runner

    def bind_doctor_runner(self, doctor_runner: DaemonDoctorRunner) -> None:
        self._doctor_runner = doctor_runner

    def rebind_job_service(self, job_service: JobService) -> None:
        """Point subsequent job queries at the post-restore ``JobService``."""
        self._job_service = job_service

    @property
    def store(self) -> object:
        return getattr(self._delegate, "store", None) if self._delegate is not None else None

    @property
    def policy(self) -> object:
        return getattr(self._delegate, "policy", None) if self._delegate is not None else None

    @property
    def monotonic_ns(self) -> object:
        return getattr(self._delegate, "monotonic_ns", None) if self._delegate is not None else None

    def supports_tool(self, tool: str, *, deep: bool = False) -> bool:
        if tool == "get_job" and not deep:
            if self._delegate is not None and self._delegate.supports_tool(tool, deep=deep):
                return True
            return True
        if tool == "get_health" and deep and self._doctor_runner is not None:
            return True
        if self._delegate is None:
            return False
        return self._delegate.supports_tool(tool, deep=deep)

    def execute_readonly(self, call: Call, ctx: CallContext) -> dict[str, JsonValue]:
        if call.tool == "get_job":
            if self._delegate is not None and self._delegate.supports_tool("get_job", deep=False):
                return self._delegate.execute_readonly(call, ctx)
            job_id = call.arguments.get("job_id")
            if not isinstance(job_id, str):
                raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
            return self._job_service.get_job(job_id, ctx.principal, selected_scope=ctx.selected_scope).to_dict()
        if self._delegate is None:
            raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")
        return self._delegate.execute_readonly(call, ctx)

    def prepare_mutation(self, call: Call, ctx: CallContext, *, now: datetime) -> PreparedEffect:
        if call.tool == "get_health" and self._doctor_runner is not None:
            return self._doctor_runner.prepare_deep_health(call, ctx, now=now)
        if self._delegate is None:
            raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")
        return self._delegate.prepare_mutation(call, ctx, now=now)

    def render_stored(
        self,
        result: StoredResult,
        principal: Principal,
        *,
        selected_scope: Scope | None,
    ) -> dict[str, JsonValue]:
        if result.refs and result.refs[0].kind in {"doctor_run", "get_health_descriptor"}:
            if self._doctor_runner is None:
                raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")
            return self._doctor_runner.render_deep_health(result, principal, selected_scope=selected_scope)
        if self._delegate is None:
            raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")
        return self._delegate.render_stored(result, principal, selected_scope=selected_scope)

    def describe_artifact_send(
        self,
        result: StoredResult,
        rendered: Mapping[str, JsonValue],
        principal: Principal,
        *,
        selected_scope: Scope | None,
    ) -> ArtifactSendSpec | None:
        if self._delegate is None:
            return None
        return self._delegate.describe_artifact_send(result, rendered, principal, selected_scope=selected_scope)


class _AdmittedOwnerSession(OwnerSession):
    def __init__(
        self,
        *,
        rt: Runtime,
        ready: Ready,
        auth_gate: AuthGate,
        bridge: KernelBridge,
        job_store: StagedKernelStore,
        job_service: JobService,
        executor: JobExecutor | None,
        listener: BoundLoopbackListener,
        clock: Clock,
        monotonic_clock: MonotonicClock,
        hooks: DaemonTestHooks,
        reply_meta_lock: threading.Lock,
        reply_meta: dict[str, tuple[AuthGrantStamp | None, SendAttemptCompletion | None]],
        operator: OperatorHandle | None = None,
        doctor_runner: DaemonDoctorRunner | None = None,
    ) -> None:
        self._rt = rt
        self._ready = ready
        self._auth_gate = auth_gate
        self._bridge = bridge
        self._job_store = job_store
        self._job_service = job_service
        self._executor = executor
        self._listener = listener
        self._clock = clock
        self._monotonic_clock = monotonic_clock
        self._hooks = hooks
        self._reply_meta_lock = reply_meta_lock
        self._reply_meta = reply_meta
        self._operator = operator
        self._doctor_runner = doctor_runner
        self._claim_lock = threading.Lock()
        self._claim_closed = False
        self._metrics_lock = threading.Lock()
        self._stopping = False
        self._overrun = False
        self._drained_requests = 0
        self._worker_join_failed = False
        self._job_service.set_claim_commit_guard(self._admit_claim_commit)

    def poll_doctor_settled(self, wake_event: threading.Event) -> bool:
        if self._doctor_runner is None:
            return True
        return self._doctor_runner.poll_settled(wake_event)

    def next_doctor_retry_wait_s(self) -> float | None:
        if self._doctor_runner is None:
            return None
        return self._doctor_runner.next_retry_wait_s()

    def begin_restore_doctor_fence(self) -> None:
        if self._doctor_runner is not None:
            self._doctor_runner.fence_on_restore()

    def finish_restore_doctor_reconcile(self) -> None:
        if self._doctor_runner is not None:
            self._doctor_runner.finish_restore_reconcile()

    @property
    def ready(self) -> Ready:
        return self._ready

    @property
    def rt(self) -> Runtime:
        return self._rt

    @property
    def listener(self) -> BoundLoopbackListener:
        return self._listener

    @property
    def auth_gate(self) -> AuthGate:
        return self._auth_gate

    def bridge_clock_untrusted(self) -> bool:
        return self._bridge.clock_untrusted()

    def rebind_after_restore(
        self,
        *,
        rt: Runtime,
        job_store: StagedKernelStore,
        job_service: JobService,
        ready: Ready | None = None,
    ) -> None:
        """Atomically rebind owner-thread session handles after an online store/policy restore."""
        self._rt = rt
        self._job_store = job_store
        self._job_service = job_service
        self._job_service.set_claim_commit_guard(self._admit_claim_commit)
        if ready is not None:
            self._ready = ready
        self._bridge.rebind_stores(store=rt.store, policy=rt.policy, writer_epoch=rt.lease.epoch)
        if self._doctor_runner is not None:
            self._doctor_runner.rebind_after_restore(
                rt=rt,
                job_store=job_store,
                job_service=job_service,
                tls_not_after=self._ready.tls_not_after,
            )

    @property
    def clock(self) -> Clock:
        return self._clock

    @property
    def monotonic_clock(self) -> MonotonicClock:
        return self._monotonic_clock

    @property
    def has_job_handlers(self) -> bool:
        return self._executor is not None

    def submit_queued_reply(
        self,
        command: ToolCommand,
        receive_ns: int,
        future: Future[OwnerReply],
    ) -> None:
        holder: list[Reservation] = []
        self._bridge.submit_request(
            command.tool,
            command.arguments,
            token=command.token,
            selected_scope=command.selected_scope,
            correlation_id=command.correlation_id,
            receive_ns=receive_ns,
            on_response=lambda env: self._resolve_reply_future(future, holder, env),
            on_reserved=holder.append,
        )

    def _resolve_reply_future(
        self,
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

    def arbitrate_deadlines(self) -> bool:
        self._bridge.arbitrate_deadlines()
        return self._bridge.reservations.has_tracked()

    def next_deadline_ns(self) -> int | None:
        return self._bridge.next_deadline_ns()

    def step_owner_work(self, *, allow_new_jobs: bool) -> bool:
        did_work = False
        if self._executor is not None:
            while (wcmd := self._executor.next_command(0.0)) is not None:
                if self._bridge.reservations.expire_shutdown_if_due():
                    break
                with contextlib.suppress(BrainError):
                    self._job_service.apply_command(wcmd)
                did_work = True
            if allow_new_jobs:
                did_work = self._claim_and_submit_job() or did_work
        if self._doctor_runner is not None and self._doctor_runner.step(allow_new_jobs=allow_new_jobs):
            did_work = True
        if self._bridge.process_next_queued(block=False):
            did_work = True
            if allow_new_jobs and self._doctor_runner is not None:
                did_work = self._doctor_runner.claim_pending_if_idle() or did_work
        return did_work

    def _is_stopping(self) -> bool:
        with self._metrics_lock:
            return self._stopping

    def _is_doctor_claim_open(self) -> bool:
        with self._claim_lock:
            return (not self._claim_closed) and (not self._is_stopping())

    def doctor_claim_guard(self) -> bool:
        return self._is_doctor_claim_open()

    def _is_claim_open(self) -> bool:
        if self._executor is None:
            return False
        with self._claim_lock:
            if self._claim_closed or self._is_stopping():
                return False
            return self._executor.can_claim()

    def _admit_claim_commit(self) -> bool:
        return self._is_claim_open()

    def _can_start_claimed_job(self) -> bool:
        if self._executor is None or self._is_stopping() or self._executor.is_closed:
            return False
        return self._is_claim_open()

    def _close_claim_gate(self) -> None:
        with self._claim_lock:
            self._claim_closed = True
            if self._executor is not None:
                self._executor.close(0.0)

    def _claim_and_submit_job(self) -> bool:
        assert self._executor is not None
        if self._is_stopping() or self._executor.is_closed or self._executor.in_flight != 0:
            return False
        if not self._is_claim_open():
            return False
        try:
            lease = self._job_service.lease_next(self._rt.lease.epoch, self._clock.now())
        except BrainError as err:
            if err.code is ErrorCode.POLICY_UNAVAILABLE:
                self._auth_gate.invalidate()
            _LOGGER.warning("daemon job lease failed (code=%s)", err.code.value)
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
            self._job_service.start(lease)
            item = WorkItem(
                lease=lease,
                spec=spec,
                invocation_ids=(),
                deadline_ns=self._monotonic_clock.monotonic_ns() + _DAEMON_WORKER_ITEM_BUDGET_NS,
            )
            self._executor.submit(item)
            return True
        except BrainError as err:
            if err.code in (ErrorCode.REVISION_CONFLICT, ErrorCode.DAEMON_UNAVAILABLE):
                return True
            if err.code is ErrorCode.POLICY_UNAVAILABLE:
                self._auth_gate.invalidate()
            _LOGGER.warning("daemon job claim failed (code=%s)", err.code.value)
            return False

    def has_pending_owner_work(self) -> bool:
        return self._bridge.queue_depth() > 0

    def pin_stop_cutoff(self, deadline: float, expire: Callable[[], None]) -> None:
        self._bridge.reservations.pin_stop_cutoff(deadline, expire)

    def mark_stopping(self) -> None:
        with self._metrics_lock:
            self._stopping = True

    def mark_overrun(self) -> None:
        with self._metrics_lock:
            self._overrun = True

    def record_request_drained(self) -> None:
        with self._metrics_lock:
            if self._stopping and not self._overrun:
                self._drained_requests += 1

    def shutdown_metrics(self) -> tuple[int, bool]:
        with self._metrics_lock:
            drained = self._drained_requests
            join_failed = self._worker_join_failed
        exec_drained = self._executor is None or self._executor.is_drained
        doc_drained = self._doctor_runner is None or self._doctor_runner.is_drained
        worker_drained = (not join_failed) and exec_drained and doc_drained
        return drained, worker_drained

    def begin_stop(self) -> None:
        self._listener.close()
        self._auth_gate.close()
        self._bridge.close_admissions()
        self._close_claim_gate()
        if self._doctor_runner is not None:
            self._doctor_runner.begin_stop()

    def join_worker(self, timeout_s: float) -> bool:
        deadline_mono = time.monotonic() + max(0.0, timeout_s)
        exec_ok = True if self._executor is None else self._executor.close(max(0.0, timeout_s))
        rem = max(0.0, deadline_mono - time.monotonic())
        doc_ok = True if self._doctor_runner is None else self._doctor_runner.join(rem)
        drained = exec_ok and doc_ok
        if not drained:
            with self._metrics_lock:
                self._worker_join_failed = True
        return drained

    def prepare_cancel_uncommitted_for_shutdown(
        self,
    ) -> tuple[int, tuple[Callable[[], None], ...]]:
        return self._bridge.prepare_cancel_uncommitted_for_shutdown()

    def cancel_uncommitted_for_shutdown(self) -> int:
        return self._bridge.cancel_uncommitted_for_shutdown()

    def apply_worker_command(self, cmd: WorkerCommand) -> JobRecord | InvocationRecord:
        self._job_service.apply_command(cmd)
        if isinstance(cmd, WorkerUsage):
            inv = self._job_store.transact(lambda tx: tx.read_invocation(cmd.invocation_id))
            if inv is None:
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
            return inv
        job = self._job_store.transact(lambda tx: tx.read_job(cmd.lease.job_id))
        if job is None:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
        return job

    def finalize_send_attempt(self, completion: SendAttemptCompletion) -> ArtifactSendAttempt:
        return self._bridge.finalize_send_attempt(completion)

    def interrupt_send_attempt(self, send_attempt_id: str) -> ArtifactSendAttempt:
        return self._bridge.interrupt_send_attempt(send_attempt_id)

    def revoke_credential(self, credential_id: str, authorization: BootstrapAuthorization) -> Intent:
        return self._bridge.revoke_credential(credential_id, authorization)

    def register_workspace(
        self,
        registration: WorkspaceRegistration,
        authorization: BootstrapAuthorization,
    ) -> WorkspaceBinding:
        return self._bridge.register_workspace(registration, authorization)

    def teardown_on_owner(self, *, overrun: bool, cancelled_requests: int = 0) -> ShutdownReport:
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

    def adopt_after_owner_exit(self, exited_owner: threading.Thread) -> None:
        if exited_owner.ident is None or exited_owner.is_alive():
            return
        if not self._rt.store.closed and self._rt.store.owner_thread_id == exited_owner.ident:
            self._rt.store.adopt_after_owner_exit(exited_owner)
        if not self._rt.policy.closed and self._rt.policy.owner_thread_id == exited_owner.ident:
            self._rt.policy.adopt_after_owner_exit(exited_owner)
