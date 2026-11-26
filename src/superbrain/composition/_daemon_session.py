"""Private composite domain and admitted owner-session adapter for Task 6a daemon composition."""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Mapping
from concurrent.futures import Future
from dataclasses import dataclass
from datetime import datetime, timedelta

from superbrain.application._future_notify import safe_set_result
from superbrain.application.approvals import OperatorHandle
from superbrain.application.continuity_worker import ContinuityWorkerCoordinator
from superbrain.application.deadlines import Reservation
from superbrain.application.dispatch import KernelToolDomain, PreparedEffect
from superbrain.application.handoff_service import HandoffKernelDomain
from superbrain.application.jobs import JobService
from superbrain.application.owner_loop import AuthGate, OwnerSession
from superbrain.composition._daemon_job_recovery import UNREADABLE, LeasedAttempts
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
    CaptureBatchCommand,
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
    WorkerCompleted,
    WorkerFailed,
    WorkerUsage,
    WorkspaceBinding,
    WorkspaceRegistration,
)
from superbrain.core.wire import encode_envelope, make_success_envelope
from superbrain.ports.clock import Clock, MonotonicClock
from superbrain.ports.continuity import CONTINUITY_REFRESH_JOB_KIND
from superbrain.ports.policy import Intent
from superbrain.storage.handoffs import HandoffStore
from superbrain.storage.idempotency import StagedKernelStore
from superbrain.storage.runtime import Runtime
from superbrain.storage.send_attempts import KernelSendAttemptStore
from superbrain.workers.executor import JobExecutor, WorkItem

_DAEMON_WORKER_ITEM_BUDGET_NS = 60_000_000_000
_LOGGER = logging.getLogger(__name__)
_CONTINUITY_SCAN_INTERVAL = timedelta(seconds=1)


@dataclass(frozen=True)
class DaemonTestHooks:
    """Optional deterministic barriers/fault seams for daemon lifecycle integration tests."""

    after_tls_verify: Callable[[], None] | None = None
    after_open_before_rebuild: Callable[[Runtime], None] | None = None
    before_job_recover: Callable[[Runtime], None] | None = None
    before_bind: Callable[[Runtime], None] | None = None
    before_endpoint_publish: Callable[[Endpoint], None] | None = None
    after_endpoint_publish_before_final_tls_check: Callable[[Endpoint], None] | None = None
    before_continuity_worker_commit: Callable[[Runtime], None] | None = None
    before_auth_gate_publish: Callable[[RequestAuthView], None] | None = None
    before_enter_commit: Callable[[Reservation | None], None] | None = None
    after_reserve_before_enqueue: Callable[[Reservation], None] | None = None
    before_runtime_close: Callable[[Runtime], None] | None = None


_STORED_REF_TOOL: dict[str, str] = {
    "delivery_result": "prepare_task",
    "artifact_result": "get_artifact",
    "episode_result": "submit_episode",
}


def build_default_handoff_domain(
    *,
    rt: Runtime,
    clock: Clock,
    writer_epoch: int,
) -> HandoffKernelDomain | None:
    """Build the production SP2-4 ``HandoffKernelDomain`` when store v8 and policy v5 are admitted."""
    if rt.store.schema_version < 8 or rt.policy.schema_version < 5:
        return None
    return HandoffKernelDomain(
        handoffs=HandoffStore(rt.store, rt.policy),
        policy=rt.policy,
        clock=clock,
        send_attempts=KernelSendAttemptStore(rt.store, rt.policy, writer_epoch=writer_epoch),
    )


class _DaemonCompositeDomain:
    """Serves ``get_job``, SP2-4 handoff tools, and any injected test/business domain tools."""

    def __init__(
        self,
        job_service: JobService,
        delegate: KernelToolDomain | None,
        *,
        fallback: KernelToolDomain | None = None,
    ) -> None:
        self._job_service = job_service
        self._delegate = delegate
        self._fallback = fallback

    def rebind_job_service(self, job_service: JobService) -> None:
        """Point subsequent job queries at the post-restore ``JobService``."""
        self._job_service = job_service

    def rebind_fallback(self, fallback: KernelToolDomain | None) -> None:
        """Point SP2-4 continuity tools at the post-restore ``HandoffKernelDomain``."""
        self._fallback = fallback

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
            return True
        if self._delegate is not None and self._delegate.supports_tool(tool, deep=deep):
            return True
        if self._fallback is not None and self._fallback.supports_tool(tool, deep=deep):
            return True
        return False

    def execute_readonly(self, call: Call, ctx: CallContext) -> dict[str, JsonValue]:
        if call.tool == "get_job":
            if self._delegate is not None and self._delegate.supports_tool("get_job", deep=False):
                return self._delegate.execute_readonly(call, ctx)
            job_id = call.arguments.get("job_id")
            if not isinstance(job_id, str):
                raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
            return self._job_service.get_job(job_id, ctx.principal, selected_scope=ctx.selected_scope).to_dict()
        if self._delegate is not None and self._delegate.supports_tool(call.tool, deep=False):
            return self._delegate.execute_readonly(call, ctx)
        if self._fallback is not None and self._fallback.supports_tool(call.tool, deep=False):
            return self._fallback.execute_readonly(call, ctx)
        raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")

    def prepare_mutation(self, call: Call, ctx: CallContext, *, now: datetime) -> PreparedEffect:
        if self._delegate is not None and self._delegate.supports_tool(call.tool, deep=False):
            return self._delegate.prepare_mutation(call, ctx, now=now)
        if self._fallback is not None and self._fallback.supports_tool(call.tool, deep=False):
            return self._fallback.prepare_mutation(call, ctx, now=now)
        raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")

    def _stored_target(self, result: StoredResult) -> KernelToolDomain | None:
        tool = _STORED_REF_TOOL.get(result.refs[0].kind) if result.refs else None
        if self._delegate is not None and (tool is None or self._delegate.supports_tool(tool, deep=False)):
            return self._delegate
        if self._fallback is not None and tool is not None and self._fallback.supports_tool(tool, deep=False):
            return self._fallback
        return self._delegate

    def render_stored(
        self,
        result: StoredResult,
        principal: Principal,
        *,
        selected_scope: Scope | None,
    ) -> dict[str, JsonValue]:
        target = self._stored_target(result)
        if target is None:
            raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")
        return target.render_stored(result, principal, selected_scope=selected_scope)

    def describe_artifact_send(
        self,
        result: StoredResult,
        rendered: Mapping[str, JsonValue],
        principal: Principal,
        *,
        selected_scope: Scope | None,
    ) -> ArtifactSendSpec | None:
        target = self._stored_target(result)
        if target is None:
            return None
        return target.describe_artifact_send(result, rendered, principal, selected_scope=selected_scope)


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
    ) -> None:
        self._rt = rt
        self._ready = ready
        self._auth_gate = auth_gate
        self._bridge = bridge
        self._job_store = job_store
        self._job_service = job_service
        self._leased = LeasedAttempts(lambda: self._job_service)
        self._executor = executor
        self._listener = listener
        self._clock = clock
        self._monotonic_clock = monotonic_clock
        self._hooks = hooks
        self._reply_meta_lock = reply_meta_lock
        self._reply_meta = reply_meta
        self._operator = operator
        self._claim_lock = threading.Lock()
        self._claim_closed = False
        self._metrics_lock = threading.Lock()
        self._stopping = False
        self._overrun = False
        self._drained_requests = 0
        self._worker_join_failed = False
        self._job_service.set_claim_commit_guard(self._admit_claim_commit)
        cw_hook = hooks.before_continuity_worker_commit
        self._continuity_worker = ContinuityWorkerCoordinator(
            rt=rt,
            job_service=job_service,
            executor=executor,
            clock=clock,
            mono=monotonic_clock.monotonic_ns,
            before_commit_hook=(lambda: cw_hook(self._rt)) if cw_hook is not None else None,
        )
        self._next_continuity_scan: datetime | None = None
        self._bridge.on_continuity_tasks = self._schedule_continuity_tasks

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
        self._continuity_worker.rebind(rt=rt, job_service=job_service)

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

    def ingest_capture_batch(
        self,
        command: CaptureBatchCommand,
        *,
        deadline_ns: int | None = None,
    ) -> CallResult:
        """Process one capture batch on the owner thread and return an encoded ``CallResult``."""
        ack = self._bridge.ingest_capture_batch(command, deadline_ns=deadline_ns)
        envelope = make_success_envelope(ack.to_dict())
        encode_envelope(envelope)
        return envelope

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
            self._leased.retry_unfinished()
            while (wcmd := self._executor.next_command(0.0)) is not None:
                if self._bridge.reservations.expire_shutdown_if_due():
                    break
                try:
                    self._dispatch_worker_command(wcmd)
                except BrainError as err:
                    # The command is consumed: without a fenced retry the job would stay running with no work.
                    _LOGGER.warning("daemon job completion failed (code=%s)", err.code.value)
                    if err.code in UNREADABLE and isinstance(wcmd, (WorkerCompleted, WorkerFailed)):
                        self._leased.retry(wcmd.lease)
                did_work = True
            if allow_new_jobs:
                self._scan_continuity_if_due()
                did_work = self._claim_and_submit_job() or did_work
        if self._bridge.process_next_queued(block=False):
            did_work = True
        return did_work

    def _is_stopping(self) -> bool:
        with self._metrics_lock:
            return self._stopping

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
            if err.code in UNREADABLE:
                self._leased.retry(lease)  # leased but not handed to the worker: queue the attempt again
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
        worker_drained = self._executor is None or (not join_failed and self._executor.is_drained)
        return drained, worker_drained

    def begin_stop(self) -> None:
        self._listener.close()
        self._auth_gate.close()
        self._bridge.close_admissions()
        self._close_claim_gate()

    def join_worker(self, timeout_s: float) -> bool:
        if self._executor is None:
            return True
        drained = self._executor.close(max(0.0, timeout_s))
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

    def _schedule_continuity_tasks(self, task_ids: tuple[str, ...]) -> None:
        now = self._clock.now()
        for task_id in task_ids:
            try:
                self._continuity_worker.enqueue_if_due(task_id=task_id, now=now)
            except BrainError as err:
                # The durable scan retries; the capture ACK already committed.
                _LOGGER.warning("continuity schedule failed (code=%s)", err.code.value)

    def _scan_continuity_if_due(self) -> None:
        """Durable wake: committed-but-unsummarized events are rescheduled after a crash and at the 60 s mark."""
        now = self._clock.now()
        if self._next_continuity_scan is not None and now < self._next_continuity_scan:
            return
        self._next_continuity_scan = now + _CONTINUITY_SCAN_INTERVAL
        try:
            self._continuity_worker.enqueue_due(now=now)
        except BrainError as err:
            _LOGGER.warning("continuity scan failed (code=%s)", err.code.value)

    def _dispatch_worker_command(self, cmd: WorkerCommand) -> None:
        if isinstance(cmd, (WorkerCompleted, WorkerFailed)):
            row = self._job_store.transact(lambda tx: tx.read_job(cmd.lease.job_id))
            if row is not None and row.kind == CONTINUITY_REFRESH_JOB_KIND:
                spec = self._leased.take_spec(cmd.lease) or self._job_service.job_spec(cmd.lease)
                if isinstance(cmd, WorkerCompleted):
                    self._continuity_worker.commit_worker_completed(cmd, now=self._clock.now(), spec=spec)
                else:
                    self._continuity_worker.handle_worker_failed(cmd, now=self._clock.now(), spec=spec)
                return
        self._job_service.apply_command(cmd)

    def apply_worker_command(self, cmd: WorkerCommand) -> JobRecord | InvocationRecord:
        self._dispatch_worker_command(cmd)
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
