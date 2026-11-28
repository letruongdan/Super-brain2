"""Internal queue, reply submission and capture-batch submission of ``owner_loop.OwnerLoop``."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from concurrent.futures import Future

from superbrain.application import owner_loop as _m
from superbrain.application._auth_gate import evaluate_shallow_health
from superbrain.application._future_notify import (
    DeferredCallbackFuture,
    is_collecting_deferred_callbacks,
    safe_set_exception,
    safe_set_result,
    settle_and_submit_callbacks,
)
from superbrain.application._reservation import make_checked_error
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import (
    TOTAL_REQUEST_BUDGET_NS,
    CallResult,
    CaptureBatchCommand,
    OwnerReply,
    ToolCommand,
    is_strict_int,
    require_aware_utc,
)


def submit_reply(self: _m.OwnerLoop, command: ToolCommand, deadline_ns: int) -> Future[OwnerReply]:
    if not isinstance(command, ToolCommand):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if not is_strict_int(deadline_ns):
        raise BrainError(ErrorCode.INVALID_INPUT, "boolean not allowed for integer")

    with self._lifecycle_lock:
        session = self._session
        stopping = self._stopping

    if session is None or stopping:
        return _m._error_reply_future(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")

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
            return _m._error_reply_future(err.code, err.message)
        return _m._resolved_reply_future(reply)

    try:
        now_utc, _ = require_aware_utc(session.clock.now())
    except BrainError as err:
        return _m._error_reply_future(err.code, err.message)
    if now_utc >= session.ready.tls_not_after:
        return _m._error_reply_future(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")

    receive_ns = deadline_ns - TOTAL_REQUEST_BUDGET_NS
    fut: DeferredCallbackFuture[OwnerReply] = DeferredCallbackFuture()
    session.submit_queued_reply(command, receive_ns, fut)
    return fut


def _enqueue_internal(self: _m.OwnerLoop, fn: Callable[[_m.OwnerSession], _m._T]) -> Future[_m._T]:
    fut: DeferredCallbackFuture[_m._T] = DeferredCallbackFuture()
    with self._lifecycle_lock:
        session = self._session
        if session is None or self._stopping:
            safe_set_exception(fut, _m._unavailable_error())
            return fut

        def _task() -> None:
            if self._expire_drain_if_due(session):
                if is_collecting_deferred_callbacks():
                    safe_set_exception(fut, _m._unavailable_error())
                else:
                    settle_and_submit_callbacks(
                        self._notifier,
                        (lambda: safe_set_exception(fut, _m._unavailable_error()),),
                    )
                return
            try:
                res = fn(session)
            except BrainError as err:
                safe_set_exception(fut, BrainError(err.code, err.message))
            except Exception:  # noqa: BLE001
                safe_set_exception(fut, BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure"))
            else:
                safe_set_result(fut, res)

        with self._internal_lock:
            self._internal_queue.append(_task)
        self._owner_wake.set()
    return fut


def submit_capture_batch(self: _m.OwnerLoop, command: CaptureBatchCommand, deadline_ns: int) -> Future[CallResult]:
    if not isinstance(command, CaptureBatchCommand):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if not is_strict_int(deadline_ns):
        raise BrainError(ErrorCode.INVALID_INPUT, "boolean not allowed for integer")
    with self._lifecycle_lock:
        session = self._session
        stopping = self._stopping
    if session is None or stopping:
        fut_err: DeferredCallbackFuture[CallResult] = DeferredCallbackFuture()
        safe_set_result(fut_err, make_checked_error(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable"))
        return fut_err

    def _run_capture(sess: _m.OwnerSession) -> CallResult:
        try:
            now_utc, _ = require_aware_utc(sess.clock.now())
            if now_utc >= sess.ready.tls_not_after:
                return make_checked_error(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")
            if sess.monotonic_clock.monotonic_ns() >= deadline_ns:
                return make_checked_error(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")
            handler = getattr(sess, "ingest_capture_batch", None)
            if handler is None:
                return make_checked_error(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")
            result: CallResult = handler(command, deadline_ns=deadline_ns)
            return result
        except BrainError as err:
            return make_checked_error(err.code, err.message)

    return self._enqueue_internal(_run_capture)
