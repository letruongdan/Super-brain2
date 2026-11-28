"""Private composite domain and admitted owner-session adapter for Task 6a daemon composition."""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable, Mapping
from concurrent.futures import Future
from dataclasses import dataclass
from datetime import datetime, timedelta

from superbrain.application.approvals import OperatorHandle
from superbrain.application.continuity_worker import ContinuityWorkerCoordinator
from superbrain.application.deadlines import Reservation
from superbrain.application.dispatch import KernelToolDomain, PreparedEffect
from superbrain.application.jobs import JobService
from superbrain.application.owner_loop import AuthGate, OwnerSession
from superbrain.composition import _daemon_session_work
from superbrain.composition._daemon_doctor import DaemonDoctorRunner
from superbrain.composition._daemon_handoff_factory import build_default_handoff_domain as build_default_handoff_domain
from superbrain.composition._daemon_handoff_factory import (
    make_default_handoff_domain_factory as make_default_handoff_domain_factory,
)
from superbrain.composition._daemon_job_recovery import LeasedAttempts
from superbrain.composition._endpoint import BoundLoopbackListener
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
from superbrain.storage.idempotency import StagedKernelStore
from superbrain.storage.runtime import Runtime
from superbrain.workers.executor import JobExecutor

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
    host_version_resolver: Callable[[str], str | None] | None = None


_DEFAULT_HANDOFF_TOOLS: frozenset[str] = frozenset({"prepare_task", "get_artifact", "submit_episode", "get_health"})

_STORED_REF_TOOL: dict[str, str] = {
    "delivery_result": "prepare_task",
    "artifact_result": "get_artifact",
    "episode_result": "submit_episode",
    "health_result": "get_health",
}


class _DaemonCompositeDomain:
    """Serves ``get_job``, ``get_health(deep=True)`` via the doctor runner, SP2-4 handoff tools, and any injected
    test/business domain tools."""

    def __init__(
        self,
        job_service: JobService,
        delegate: KernelToolDomain | None,
        *,
        fallback: KernelToolDomain | None = None,
        fallback_factory: Callable[[], KernelToolDomain | None] | None = None,
        doctor_runner: DaemonDoctorRunner | None = None,
    ) -> None:
        self._job_service = job_service
        self._delegate = delegate
        self._fallback = fallback
        self._fallback_factory = fallback_factory
        self._doctor_runner = doctor_runner

    def bind_doctor_runner(self, doctor_runner: DaemonDoctorRunner) -> None:
        self._doctor_runner = doctor_runner

    def _get_fallback(self) -> KernelToolDomain | None:
        if self._fallback is None and self._fallback_factory is not None:
            self._fallback = self._fallback_factory()
            self._fallback_factory = None
        return self._fallback

    def rebind_job_service(self, job_service: JobService) -> None:
        """Point subsequent job queries at the post-restore ``JobService``."""
        self._job_service = job_service

    def rebind_fallback(self, fallback: KernelToolDomain | None) -> None:
        """Point SP2-4 continuity tools at the post-restore ``HandoffKernelDomain``."""
        if self._delegate is None:
            self._fallback = fallback
            self._fallback_factory = None

    def rebind_fallback_factory(
        self,
        factory: Callable[[], KernelToolDomain | None] | None,
    ) -> None:
        """Reset SP2-4 continuity fallback to a post-restore lazy factory."""
        if self._delegate is None:
            self._fallback = None
            self._fallback_factory = factory

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
        if tool == "get_health" and deep and self._doctor_runner is not None:
            return True
        if self._delegate is not None and self._delegate.supports_tool(tool, deep=deep):
            return True
        if self._fallback is not None:
            return self._fallback.supports_tool(tool, deep=deep)
        if self._fallback_factory is not None:
            return tool in {"prepare_task", "get_artifact", "submit_episode"} and not deep
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
        if self._fallback is not None or (
            self._fallback_factory is not None and call.tool in _DEFAULT_HANDOFF_TOOLS
        ):
            fb = self._get_fallback()
            if fb is not None and fb.supports_tool(call.tool, deep=False):
                return fb.execute_readonly(call, ctx)
        raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")

    def prepare_mutation(self, call: Call, ctx: CallContext, *, now: datetime) -> PreparedEffect:
        deep = call.tool == "get_health" and bool(call.arguments.get("deep"))
        if call.tool == "get_health" and self._doctor_runner is not None:
            return self._doctor_runner.prepare_deep_health(call, ctx, now=now)
        if self._delegate is not None and self._delegate.supports_tool(call.tool, deep=deep):
            return self._delegate.prepare_mutation(call, ctx, now=now)
        if self._fallback is not None or (
            self._fallback_factory is not None and call.tool in _DEFAULT_HANDOFF_TOOLS
        ):
            fb = self._get_fallback()
            if fb is not None and fb.supports_tool(call.tool, deep=deep):
                return fb.prepare_mutation(call, ctx, now=now)
        raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")

    def _stored_target(self, result: StoredResult) -> KernelToolDomain | None:
        tool = _STORED_REF_TOOL.get(result.refs[0].kind) if result.refs else None
        deep = tool == "get_health"
        if self._delegate is not None and (tool is None or self._delegate.supports_tool(tool, deep=deep)):
            return self._delegate
        if tool is not None and (
            self._fallback is not None or (self._fallback_factory is not None and tool in _DEFAULT_HANDOFF_TOOLS)
        ):
            fb = self._get_fallback()
            if fb is not None and fb.supports_tool(tool, deep=deep):
                return fb
        return self._delegate

    def render_stored(
        self,
        result: StoredResult,
        principal: Principal,
        *,
        selected_scope: Scope | None,
    ) -> dict[str, JsonValue]:
        # every deep-health render (doctor-backed, or replayed from SP2-5) goes through the one doctor renderer
        if result.refs and result.refs[0].kind in {"doctor_run", "get_health_descriptor", "health_result"}:
            if self._doctor_runner is None:
                raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")
            return self._doctor_runner.render_deep_health(result, principal, selected_scope=selected_scope)
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
        doctor_runner: DaemonDoctorRunner | None = None,
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
        self._doctor_runner = doctor_runner
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

    def poll_doctor_settled(self, wake_event: threading.Event) -> bool:
        if self._doctor_runner is None:
            return True
        return self._doctor_runner.poll_settled(wake_event)

    def next_doctor_wake_wait_s(self) -> float | None:
        if self._doctor_runner is None:
            return None
        return self._doctor_runner.next_wake_wait_s()

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
        self._continuity_worker.rebind(rt=rt, job_service=job_service)
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
        _daemon_session_work._resolve_reply_future(self, future, holder, envelope)

    def arbitrate_deadlines(self) -> bool:
        self._bridge.arbitrate_deadlines()
        return self._bridge.reservations.has_tracked()

    def next_deadline_ns(self) -> int | None:
        return self._bridge.next_deadline_ns()

    def step_owner_work(self, *, allow_new_jobs: bool) -> bool:
        return _daemon_session_work.step_owner_work(self, allow_new_jobs=allow_new_jobs)

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
        return _daemon_session_work._claim_and_submit_job(self)

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
        return _daemon_session_work.teardown_on_owner(self, overrun=overrun, cancelled_requests=cancelled_requests)

    def adopt_after_owner_exit(self, exited_owner: threading.Thread) -> None:
        if exited_owner.ident is None or exited_owner.is_alive():
            return
        if not self._rt.store.closed and self._rt.store.owner_thread_id == exited_owner.ident:
            self._rt.store.adopt_after_owner_exit(exited_owner)
        if not self._rt.policy.closed and self._rt.policy.owner_thread_id == exited_owner.ident:
            self._rt.policy.adopt_after_owner_exit(exited_owner)
