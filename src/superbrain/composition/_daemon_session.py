"""Private composite domain and admitted owner-session adapter for Task 6a daemon composition."""

from __future__ import annotations

import contextlib
import threading
from collections.abc import Callable, Mapping
from concurrent.futures import Future
from dataclasses import dataclass
from datetime import datetime

from superbrain.application.deadlines import Reservation
from superbrain.application.dispatch import KernelToolDomain, PreparedEffect
from superbrain.application.jobs import JobService
from superbrain.application.owner_loop import AuthGate, OwnerSession
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
    """Serves ``get_job`` via ``JobService`` and delegates any injected test/business domain tools."""

    def __init__(self, job_service: JobService, delegate: KernelToolDomain | None) -> None:
        self._job_service = job_service
        self._delegate = delegate

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
        self._metrics_lock = threading.Lock()
        self._stopping = False
        self._overrun = False
        self._drained_requests = 0
        self._worker_join_failed = False

    @property
    def ready(self) -> Ready:
        return self._ready

    @property
    def auth_gate(self) -> AuthGate:
        return self._auth_gate

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
        if envelope.get("ok") is True and holder:
            with self._reply_meta_lock:
                meta = self._reply_meta.pop(holder[0].reservation_id, None)
            if meta is not None:
                stamp, completion = meta
        if not future.done():
            future.set_result(
                OwnerReply(
                    envelope=envelope,
                    grant_stamp=stamp,
                    send_completion=completion,
                )
            )

    def arbitrate_deadlines(self) -> bool:
        self._bridge.arbitrate_deadlines()
        return self._bridge.reservations.has_tracked()

    def step_owner_work(self, *, allow_new_jobs: bool) -> bool:
        did_work = False
        if self._executor is not None:
            while (wcmd := self._executor.next_command(0.0)) is not None:
                with contextlib.suppress(BrainError):
                    self._job_service.apply_command(wcmd)
                did_work = True
            if allow_new_jobs:
                with contextlib.suppress(BrainError):
                    lease = self._job_service.lease_next(self._rt.lease.epoch, self._clock.now())
                    if lease is not None:
                        spec = self._job_service.job_spec(lease)
                        self._job_service.start(lease)
                        item = WorkItem(
                            lease=lease,
                            spec=spec,
                            invocation_ids=(),
                            deadline_ns=self._monotonic_clock.monotonic_ns() + _DAEMON_WORKER_ITEM_BUDGET_NS,
                        )
                        self._executor.submit(item)
                        did_work = True
        if self._bridge.process_next_queued(block=False):
            did_work = True
        return did_work

    def has_pending_owner_work(self) -> bool:
        return self._bridge.queue_depth() > 0

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
        worker_drained = self._executor is None or (not join_failed and self._executor.is_drained)
        return drained, worker_drained

    def begin_stop(self) -> None:
        self._listener.close()
        self._auth_gate.close()
        self._bridge.close_admissions()
        if self._executor is not None:
            self._executor.close(0.0)

    def join_worker(self, timeout_s: float) -> bool:
        if self._executor is None:
            return True
        drained = self._executor.close(max(0.0, timeout_s))
        if not drained:
            with self._metrics_lock:
                self._worker_join_failed = True
        return drained

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
        if self._executor is not None:
            self._executor.close(0.0)
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
