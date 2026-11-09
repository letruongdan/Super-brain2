"""Task 6a owner loop, startup/shutdown lifecycle coordinator, and RAM ``AuthGate``."""

from __future__ import annotations

import contextlib
import logging
import math
import threading
import time
from collections import deque
from collections.abc import Callable, Mapping
from concurrent.futures import Future
from typing import Protocol, TypeVar

from superbrain.application._auth_gate import AuthGate, evaluate_shallow_health
from superbrain.application._future_notify import (
    dispatch_async_thunks,
    safe_set_exception,
    safe_set_result,
)
from superbrain.application._reservation import make_checked_error
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import (
    DEFAULT_SHUTDOWN_GRACE_S,
    TOTAL_REQUEST_BUDGET_NS,
    ArtifactSendAttempt,
    BootstrapAuthorization,
    CallResult,
    DaemonConfig,
    InvocationRecord,
    JobRecord,
    OwnerReply,
    Ready,
    SendAttemptCompletion,
    ShutdownReport,
    ShutdownState,
    ToolCommand,
    WorkerCommand,
    WorkspaceBinding,
    WorkspaceRegistration,
    is_strict_int,
    require_aware_utc,
)
from superbrain.ports.clock import Clock, MonotonicClock
from superbrain.ports.policy import Intent

_T = TypeVar("_T")

_ARBITER_ACTIVE_POLL_S = 0.004
_WORKER_IDLE_POLL_S = 0.05
_LOGGER = logging.getLogger(__name__)

__all__ = ["AuthGate", "OwnerLoop", "OwnerSession", "OwnerSessionFactory"]


def _unavailable_error() -> BrainError:
    return BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")


def _failed_future(error: BrainError) -> Future[_T]:
    fut: Future[_T] = Future()
    safe_set_exception(fut, error)
    return fut


def _resolved_reply_future(reply: OwnerReply) -> Future[OwnerReply]:
    fut: Future[OwnerReply] = Future()
    safe_set_result(fut, reply)
    return fut


class OwnerSession(Protocol):
    """Port implemented by ``composition`` for one admitted owner-thread daemon session."""

    @property
    def ready(self) -> Ready: ...

    @property
    def auth_gate(self) -> AuthGate: ...

    @property
    def clock(self) -> Clock: ...

    @property
    def monotonic_clock(self) -> MonotonicClock: ...

    @property
    def has_job_handlers(self) -> bool: ...

    def submit_queued_reply(
        self,
        command: ToolCommand,
        receive_ns: int,
        future: Future[OwnerReply],
    ) -> None: ...

    def arbitrate_deadlines(self) -> bool: ...

    def step_owner_work(self, *, allow_new_jobs: bool) -> bool: ...

    def has_pending_owner_work(self) -> bool: ...

    def mark_stopping(self) -> None: ...

    def mark_overrun(self) -> None: ...

    def shutdown_metrics(self) -> tuple[int, bool]: ...

    def begin_stop(self) -> None: ...

    def join_worker(self, timeout_s: float) -> bool: ...

    def prepare_cancel_uncommitted_for_shutdown(
        self,
    ) -> tuple[int, tuple[Callable[[], None], ...]]: ...

    def cancel_uncommitted_for_shutdown(self) -> int: ...

    def apply_worker_command(self, cmd: WorkerCommand) -> JobRecord | InvocationRecord: ...

    def finalize_send_attempt(self, completion: SendAttemptCompletion) -> ArtifactSendAttempt: ...

    def interrupt_send_attempt(self, send_attempt_id: str) -> ArtifactSendAttempt: ...

    def revoke_credential(self, credential_id: str, authorization: BootstrapAuthorization) -> Intent: ...

    def register_workspace(
        self,
        registration: WorkspaceRegistration,
        authorization: BootstrapAuthorization,
    ) -> WorkspaceBinding: ...

    def teardown_on_owner(self, *, overrun: bool, cancelled_requests: int = 0) -> ShutdownReport: ...

    def adopt_after_owner_exit(self, exited_owner: threading.Thread) -> None: ...


OwnerSessionFactory = Callable[[DaemonConfig, Callable[[], None], Callable[[], None]], OwnerSession]


class OwnerLoop:
    """Single-owner daemon lifecycle and request/worker/send-attempt coordinator."""

    def __init__(self, session_factory: OwnerSessionFactory | None = None) -> None:
        self._session_factory = session_factory
        self._lifecycle_lock = threading.Lock()
        self._started = False
        self._stop_requested = False
        self._stopping = False
        self._drain_expired = False
        self._arbiter_stop = False
        self._stop_wall_deadline = 0.0
        self._session: OwnerSession | None = None
        self._ready_value: Ready | None = None
        self._startup_error: BaseException | None = None
        self._final_report: ShutdownReport | None = None

        self._startup_done = threading.Event()
        self._closed_done = threading.Event()
        self._owner_wake = threading.Event()
        self._arbiter_wake = threading.Event()

        self._internal_lock = threading.Lock()
        self._internal_queue: deque[Callable[[], None]] = deque()
        self._overrun_lock = threading.Lock()
        self._overrun_cancelled = False
        self._cancelled_requests = 0
        self._owner_thread: threading.Thread | None = None
        self._arbiter_thread: threading.Thread | None = None

    @property
    def ready(self) -> Ready | None:
        with self._lifecycle_lock:
            if self._stopping or self._ready_value is None or self._session is None:
                return None
            rdy = self._ready_value
            clk = self._session.clock
        try:
            now_utc, _ = require_aware_utc(clk.now())
        except BrainError:
            return None
        if now_utc >= rdy.tls_not_after:
            return None
        return rdy

    @property
    def auth_gate(self) -> AuthGate:
        with self._lifecycle_lock:
            if self._session is None:
                raise _unavailable_error()
            return self._session.auth_gate

    def start(self, config: DaemonConfig) -> Ready:
        if not isinstance(config, DaemonConfig):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if self._session_factory is None:
            raise _unavailable_error()
        with self._lifecycle_lock:
            if self._started:
                raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
            self._started = True

        owner_thread = threading.Thread(
            target=self._owner_main,
            args=(config,),
            name="superbrain-owner-loop",
            daemon=True,
        )
        self._owner_thread = owner_thread
        owner_thread.start()
        self._startup_done.wait()
        if self._startup_error is not None:
            owner_thread.join()
            raise self._startup_error
        with self._lifecycle_lock:
            assert self._session is not None
            return self._session.ready

    def submit(self, command: ToolCommand, deadline_ns: int) -> Future[CallResult]:
        reply_fut = self.submit_reply(command, deadline_ns)
        out_fut: Future[CallResult] = Future()

        def _forward(done: Future[OwnerReply]) -> None:
            try:
                rep = done.result()
            except BaseException as exc:  # noqa: BLE001
                safe_set_exception(out_fut, exc)
                return
            safe_set_result(out_fut, rep.envelope)

        reply_fut.add_done_callback(_forward)
        return out_fut

    def submit_reply(self, command: ToolCommand, deadline_ns: int) -> Future[OwnerReply]:
        if not isinstance(command, ToolCommand):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if not is_strict_int(deadline_ns):
            raise BrainError(ErrorCode.INVALID_INPUT, "boolean not allowed for integer")

        with self._lifecycle_lock:
            session = self._session
            stopping = self._stopping

        if session is None or stopping:
            return _resolved_reply_future(
                OwnerReply(
                    envelope=make_checked_error(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable"),
                    grant_stamp=None,
                    send_completion=None,
                )
            )

        is_shallow_health = command.tool == "get_health" and not (
            isinstance(command.arguments, Mapping) and command.arguments.get("deep") is True
        )
        if is_shallow_health:
            try:
                reply = evaluate_shallow_health(
                    command,
                    deadline_ns,
                    auth_gate=session.auth_gate,
                    clock=session.clock,
                    monotonic_clock=session.monotonic_clock,
                    loop_ready=(self.ready is not None),
                )
            except BrainError as err:
                reply = OwnerReply(
                    envelope=make_checked_error(err.code, err.message),
                    grant_stamp=None,
                    send_completion=None,
                )
            return _resolved_reply_future(reply)

        try:
            now_utc, _ = require_aware_utc(session.clock.now())
        except BrainError as err:
            return _resolved_reply_future(
                OwnerReply(
                    envelope=make_checked_error(err.code, err.message),
                    grant_stamp=None,
                    send_completion=None,
                )
            )
        if now_utc >= session.ready.tls_not_after:
            return _resolved_reply_future(
                OwnerReply(
                    envelope=make_checked_error(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable"),
                    grant_stamp=None,
                    send_completion=None,
                )
            )

        receive_ns = deadline_ns - TOTAL_REQUEST_BUDGET_NS
        fut: Future[OwnerReply] = Future()
        session.submit_queued_reply(command, receive_ns, fut)
        return fut

    def _enqueue_internal(self, fn: Callable[[OwnerSession], _T]) -> Future[_T]:
        fut: Future[_T] = Future()
        with self._lifecycle_lock:
            session = self._session
            if session is None or self._stopping:
                safe_set_exception(fut, _unavailable_error())
                return fut

            def _task() -> None:
                if self._drain_expired:
                    safe_set_exception(fut, _unavailable_error())
                    return
                try:
                    res = fn(session)
                except BrainError as err:
                    safe_set_exception(fut, err)
                except Exception:  # noqa: BLE001
                    safe_set_exception(fut, BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure"))
                else:
                    safe_set_result(fut, res)

            with self._internal_lock:
                self._internal_queue.append(_task)
            self._owner_wake.set()
        return fut

    def apply_worker_command(self, cmd: WorkerCommand) -> Future[JobRecord | InvocationRecord]:
        return self._enqueue_internal(lambda s: s.apply_worker_command(cmd))

    def finalize_send_attempt(self, completion: SendAttemptCompletion) -> Future[ArtifactSendAttempt]:
        return self._enqueue_internal(lambda s: s.finalize_send_attempt(completion))

    def interrupt_send_attempt(self, send_attempt_id: str) -> Future[ArtifactSendAttempt]:
        return self._enqueue_internal(lambda s: s.interrupt_send_attempt(send_attempt_id))

    def revoke_credential(
        self,
        credential_id: str,
        authorization: BootstrapAuthorization,
    ) -> Future[Intent]:
        return self._enqueue_internal(lambda s: s.revoke_credential(credential_id, authorization))

    def register_workspace(
        self,
        registration: WorkspaceRegistration,
        authorization: BootstrapAuthorization,
    ) -> Future[WorkspaceBinding]:
        return self._enqueue_internal(lambda s: s.register_workspace(registration, authorization))

    def run_owner_action(self, action: Callable[[], _T]) -> Future[_T]:
        if not callable(action):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        return self._enqueue_internal(lambda _s: action())

    def _trigger_overrun(self, session: OwnerSession) -> int:
        reply_thunks: tuple[Callable[[], None], ...] = ()
        internal_tasks: tuple[Callable[[], None], ...] = ()
        with self._overrun_lock:
            if not self._overrun_cancelled and not self._closed_done.is_set():
                self._overrun_cancelled = True
                self._drain_expired = True
                session.mark_overrun()
                cancelled_now, reply_thunks = session.prepare_cancel_uncommitted_for_shutdown()
                self._cancelled_requests += cancelled_now
                internal_tasks = self._drain_pending_internal()
                self._owner_wake.set()
            cancelled_total = self._cancelled_requests
        dispatch_async_thunks((*reply_thunks, *internal_tasks))
        return cancelled_total

    def stop(self, grace_s: float = DEFAULT_SHUTDOWN_GRACE_S) -> ShutdownReport:
        if (
            isinstance(grace_s, bool)
            or not isinstance(grace_s, (int, float))
            or not math.isfinite(grace_s)
            or grace_s < 0
        ):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")

        candidate_deadline = time.perf_counter() + float(grace_s)
        with self._lifecycle_lock:
            if not self._started or self._session is None:
                raise _unavailable_error()
            session = self._session
            first_stopper = not self._stop_requested
            if first_stopper:
                self._stop_requested = True
                self._stopping = True
                self._ready_value = None
                self._stop_wall_deadline = candidate_deadline
                session.mark_stopping()
                wall_deadline = candidate_deadline
            else:
                wall_deadline = self._stop_wall_deadline

        if first_stopper:
            session.begin_stop()
            self._owner_wake.set()
            self._arbiter_wake.set()

        remaining = max(0.0, wall_deadline - time.perf_counter())
        if self._closed_done.wait(timeout=remaining):
            self._join_and_adopt_if_failed(session)
            assert self._final_report is not None
            return self._final_report

        # Grace budget expired while owner thread is still busy/blocked -> cancel uncommitted & report OVERRUN!
        cancelled_total = self._trigger_overrun(session)
        if self._closed_done.is_set():
            self._join_and_adopt_if_failed(session)
            assert self._final_report is not None
            return self._final_report
        drained, worker_drained = session.shutdown_metrics()
        return ShutdownReport(
            state=ShutdownState.OVERRUN,
            drained_requests=drained,
            cancelled_requests=cancelled_total,
            worker_drained=worker_drained,
            endpoint_removed=False,
            error_code=ErrorCode.DEADLINE_EXCEEDED,
        )

    def wait_closed(self, timeout: float | None = None) -> ShutdownReport | None:
        if not self._closed_done.wait(timeout=timeout):
            return None
        if self._owner_thread is not None and threading.current_thread() is not self._owner_thread:
            self._owner_thread.join(timeout=timeout)
            if self._session is not None and not self._owner_thread.is_alive():
                self._adopt_failed_close(self._session, self._owner_thread)
        if self._arbiter_thread is not None and threading.current_thread() is not self._arbiter_thread:
            self._arbiter_thread.join(timeout=timeout)
        return self._final_report

    def _join_and_adopt_if_failed(self, session: OwnerSession) -> None:
        if self._owner_thread is not None and threading.current_thread() is not self._owner_thread:
            self._owner_thread.join()
            self._adopt_failed_close(session, self._owner_thread)
        if self._arbiter_thread is not None and threading.current_thread() is not self._arbiter_thread:
            self._arbiter_thread.join()

    def _adopt_failed_close(self, session: OwnerSession, owner_thread: threading.Thread) -> None:
        with self._lifecycle_lock:
            if (
                self._final_report is not None
                and self._final_report.state is ShutdownState.CLOSE_FAILED
                and not owner_thread.is_alive()
            ):
                session.adopt_after_owner_exit(owner_thread)

    def _drain_pending_internal(self) -> tuple[Callable[[], None], ...]:
        with self._internal_lock:
            pending = tuple(self._internal_queue)
            self._internal_queue.clear()
        return pending

    def _pop_internal(self) -> Callable[[], None] | None:
        with self._internal_lock:
            return self._internal_queue.popleft() if self._internal_queue else None

    def _has_internal(self) -> bool:
        with self._internal_lock:
            return bool(self._internal_queue)

    def _arbiter_main(self, session: OwnerSession) -> None:
        while not self._arbiter_stop:
            self._arbiter_wake.clear()
            has_tracked = False
            with contextlib.suppress(Exception):
                has_tracked = session.arbitrate_deadlines()
            if self._arbiter_stop:
                break
            if has_tracked:
                self._arbiter_wake.wait(timeout=_ARBITER_ACTIVE_POLL_S)
            else:
                self._arbiter_wake.wait()

    def _owner_main(self, config: DaemonConfig) -> None:
        assert self._session_factory is not None
        try:
            session = self._session_factory(config, self._owner_wake.set, self._arbiter_wake.set)
        except BaseException as err:  # noqa: BLE001
            self._startup_error = err
            self._closed_done.set()
            self._startup_done.set()
            return

        with self._lifecycle_lock:
            self._session = session
            self._ready_value = session.ready
        arbiter = threading.Thread(
            target=self._arbiter_main,
            args=(session,),
            name="superbrain-deadline-arbiter",
            daemon=True,
        )
        self._arbiter_thread = arbiter
        arbiter.start()
        self._startup_done.set()

        unexpected_error_code: ErrorCode | None = None
        try:
            while True:
                self._owner_wake.clear()
                if self._drain_expired:
                    break

                did_work = False
                while not self._drain_expired and (task := self._pop_internal()) is not None:
                    task()
                    did_work = True

                if self._drain_expired:
                    break

                if session.step_owner_work(allow_new_jobs=not self._stopping):
                    did_work = True

                if did_work:
                    self._owner_wake.set()
                    continue

                if self._stopping and not self._has_internal() and not session.has_pending_owner_work():
                    rem_worker = max(0.0, self._stop_wall_deadline - time.perf_counter())
                    if not session.join_worker(rem_worker):
                        self._trigger_overrun(session)
                    else:
                        session.step_owner_work(allow_new_jobs=False)
                    break

                if session.has_job_handlers and not self._stopping:
                    self._owner_wake.wait(timeout=_WORKER_IDLE_POLL_S)
                else:
                    self._owner_wake.wait()
        except Exception as err:  # noqa: BLE001
            unexpected_error_code = err.code if isinstance(err, BrainError) else ErrorCode.INTEGRITY_FAILURE
            _LOGGER.error("owner loop exited unexpectedly (code=%s)", unexpected_error_code.value)
            with self._lifecycle_lock:
                self._stopping = True
                self._ready_value = None
                self._drain_expired = True
                session.mark_stopping()
            with contextlib.suppress(Exception):
                session.begin_stop()
            self._trigger_overrun(session)
        finally:
            with self._lifecycle_lock:
                unplanned_exit = not self._stop_requested
                self._stopping = True
                self._ready_value = None
                if unplanned_exit:
                    self._drain_expired = True
                session.mark_stopping()
            if unplanned_exit and unexpected_error_code is None:
                unexpected_error_code = ErrorCode.INTEGRITY_FAILURE
                with contextlib.suppress(Exception):
                    session.begin_stop()
                self._trigger_overrun(session)
            with self._overrun_lock:
                overrun = self._drain_expired
                cancelled_total = self._cancelled_requests
                self._drain_expired = True
            dispatch_async_thunks(self._drain_pending_internal())
            self._arbiter_stop = True
            self._arbiter_wake.set()
            arbiter.join(timeout=1.0)
            report = session.teardown_on_owner(
                overrun=overrun,
                cancelled_requests=cancelled_total,
            )
            if unexpected_error_code is not None and report.state is not ShutdownState.CLOSE_FAILED:
                report = ShutdownReport(
                    state=ShutdownState.CLOSE_FAILED,
                    drained_requests=report.drained_requests,
                    cancelled_requests=report.cancelled_requests,
                    worker_drained=False,
                    endpoint_removed=report.endpoint_removed,
                    error_code=unexpected_error_code,
                )
            self._final_report = report
            self._closed_done.set()
