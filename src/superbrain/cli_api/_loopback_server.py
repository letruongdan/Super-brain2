"""Bounded TLS/HTTP loopback server enforcing two-request admission on the owner listener."""

from __future__ import annotations

import contextlib
import logging
import socket
import ssl
import threading
import time as time  # re-exported: tests and _loopback_server_flow reach it through this module
from collections.abc import Callable
from concurrent.futures import Future
from concurrent.futures import TimeoutError as FuturesTimeoutError
from typing import TypeVar

from superbrain.application.owner_loop import OwnerLoop
from superbrain.cli_api import _loopback_server_flow
from superbrain.cli_api._http_frames import HttpFramingError
from superbrain.cli_api._server_http import (
    _abort_socket as _abort_socket,
)
from superbrain.cli_api._server_http import (
    _graceful_close_conn as _graceful_close_conn,
)
from superbrain.cli_api._server_http import (
    _graceful_reject_socket as _graceful_reject_socket,
)
from superbrain.cli_api._server_http import (
    _safe_join,
    _validate_stop_deadline,
    join_before_cutoff,
)
from superbrain.cli_api._server_http import (
    handle_identity_request as handle_identity_request,
)
from superbrain.cli_api._server_http import (
    read_admitted_tool_command as read_admitted_tool_command,
)
from superbrain.cli_api._server_http import (
    write_json_response as write_json_response,
)
from superbrain.cli_api.operator import OperatorExecutor
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import (
    ArtifactSendAttempt,
    CaptureBatchCommand,
    OwnerReply,
    Ready,
    SendAttemptCompletion,
)

MAX_ACTIVE_CONNECTIONS = 32
SERVER_HANDSHAKE_BUDGET_NS = 1_000_000_000
_ACCEPT_POLL_S = 0.005
_REPLY_WAIT_SLICE_S = 0.005
_JOIN_WAIT_SLICE_S = 0.001

_LOGGER = logging.getLogger(__name__)
_join_before_cutoff = join_before_cutoff


_T = TypeVar("_T")


class LoopbackServer:
    """Bounded loopback TLS server delegating authorized tool calls to ``OwnerLoop``."""

    def __init__(
        self,
        listener: socket.socket,
        ssl_context: ssl.SSLContext,
        ready: Ready,
        owner: OwnerLoop,
        monotonic_ns: Callable[[], int],
        stop_event: threading.Event,
        operator: OperatorExecutor | None = None,
    ) -> None:
        if (
            not isinstance(listener, socket.socket)
            or not isinstance(ssl_context, ssl.SSLContext)
            or not isinstance(ready, Ready)
            or not isinstance(owner, OwnerLoop)
            or not callable(monotonic_ns)
            or not callable(getattr(stop_event, "is_set", None))
            or not callable(getattr(stop_event, "set", None))
        ):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        self._listener = listener
        self._ssl_context = ssl_context
        self._ready = ready
        self._owner = owner
        self._monotonic_ns = monotonic_ns
        self._stop_event = stop_event
        self._operator = operator

        self._lock = threading.Lock()
        self._accept_ready = threading.Event()
        self._accept_thread: threading.Thread | None = None
        self._abort_wake = threading.Event()
        self._abort_thread: threading.Thread | None = None

        self._started = False
        self._quiesced = False
        self._aborted = False
        self._unexpected_error = False
        self._accept_ready_ok = False
        self._stop_deadline: float | None = None
        self._conn_seq = 0
        self._active_slots = 0
        self._slot_owners: set[int] = set()
        self._sockets: dict[int, socket.socket] = {}
        self._workers: dict[int, threading.Thread] = {}

    def _fail_start_cleanup(self) -> None:
        with self._lock:
            self._quiesced = True
            accept_thread = self._accept_thread
        self._stop_event.set()
        with contextlib.suppress(OSError):
            self._listener.close()
        self._abort_all_active_sockets()
        _safe_join(accept_thread, 0.05)
        self._abort_all_active_sockets()

    def start(self) -> None:
        with self._lock:
            if self._quiesced:
                raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")
            if self._started:
                raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
            self._started = True

        if self._stop_event.is_set():
            self._fail_start_cleanup()
            raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")

        try:
            self._listener.settimeout(0.001)
        except OSError as err:
            self._fail_start_cleanup()
            raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable") from err

        accept_thread = threading.Thread(target=self._accept_loop, name="superbrain-loopback-accept", daemon=True)
        try:
            accept_thread.start()
        except RuntimeError as err:
            self._fail_start_cleanup()
            raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable") from err
        with self._lock:
            self._accept_thread = accept_thread

        if not self._accept_ready.wait(timeout=2.0):
            self._fail_start_cleanup()
            raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")
        with self._lock:
            failed = not self._accept_ready_ok or self._unexpected_error or self._quiesced or self._stop_event.is_set()
        if failed:
            self._fail_start_cleanup()
            raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")

    def quiesce(self, stop_deadline: float) -> None:
        dl = _validate_stop_deadline(stop_deadline)
        start_abort_timer = False
        with self._lock:
            self._quiesced = True
            if self._stop_deadline is None:
                self._stop_deadline = dl
            effective_dl = self._stop_deadline
            if self._started and self._abort_thread is None:
                start_abort_timer = True

        with contextlib.suppress(OSError):
            self._listener.close()

        if time.perf_counter() >= effective_dl:
            self._abort_all_active_sockets()
            return

        if start_abort_timer:
            timer_thread = threading.Thread(
                target=self._cutoff_abort_worker,
                args=(effective_dl,),
                name="superbrain-loopback-cutoff",
                daemon=True,
            )
            try:
                timer_thread.start()
            except RuntimeError:
                with self._lock:
                    self._unexpected_error = True
                self._abort_all_active_sockets()
                return
            with self._lock:
                self._abort_thread = timer_thread

    def finish(self, stop_deadline: float) -> bool:
        dl = _validate_stop_deadline(stop_deadline)
        self.quiesce(dl)
        with self._lock:
            effective_dl = self._stop_deadline if self._stop_deadline is not None else dl
            accept_thread = self._accept_thread

        _join_before_cutoff(accept_thread, effective_dl)

        while True:
            with self._lock:
                workers = [w for w in self._workers.values() if w.is_alive()]
            if not workers:
                break
            rem = effective_dl - time.perf_counter()
            if rem <= 0:
                break
            _join_before_cutoff(workers[0], effective_dl)

        self._abort_wake.set()
        with self._lock:
            remaining_workers = [w for w in self._workers.values() if w.is_alive()]
            accept_alive = accept_thread is not None and accept_thread.is_alive()
            abort_thread = self._abort_thread

        timed_out = bool(remaining_workers) or accept_alive
        if timed_out or time.perf_counter() >= effective_dl:
            self._abort_all_active_sockets()

        if abort_thread is not None:
            _join_before_cutoff(abort_thread, effective_dl)

        with self._lock:
            still_alive = any(w.is_alive() for w in self._workers.values()) or (
                accept_thread is not None and accept_thread.is_alive()
            )
            ok = not self._unexpected_error and not timed_out and not still_alive
        return ok

    def _cutoff_abort_worker(self, effective_dl: float) -> None:
        wait_s = max(0.0, effective_dl - time.perf_counter())
        if not self._abort_wake.wait(timeout=wait_s):
            self._abort_all_active_sockets()

    def _abort_all_active_sockets(self) -> None:
        with self._lock:
            self._aborted = True
            socks = list(self._sockets.values())
        for sock in socks:
            _abort_socket(sock)

    def _is_quiesced(self) -> bool:
        with self._lock:
            return self._quiesced or self._stop_event.is_set()

    def _past_stop_deadline(self) -> bool:
        with self._lock:
            if not self._quiesced or self._stop_deadline is None:
                return False
            dl = self._stop_deadline
        return time.perf_counter() >= dl

    def _handshake_timeout_s(self, handshake_deadline_ns: int) -> float:
        rem_ns = handshake_deadline_ns - int(self._monotonic_ns())
        if rem_ns <= 0:
            return 0.0
        rem_s = rem_ns / 1_000_000_000.0
        with self._lock:
            stop_dl = self._stop_deadline if self._quiesced else None
        if stop_dl is not None:
            rem_s = min(rem_s, max(0.0, stop_dl - time.perf_counter()))
        return rem_s

    def _signal_accept_ready(self, ready_signaled: bool) -> bool:
        if ready_signaled:
            return True
        with contextlib.suppress(OSError):
            self._listener.settimeout(_ACCEPT_POLL_S)
        with self._lock:
            if not (self._quiesced or self._stop_event.is_set() or self._unexpected_error or self._aborted):
                self._accept_ready_ok = True
        self._accept_ready.set()
        return True

    def _accept_loop(self) -> None:
        _loopback_server_flow._accept_loop(self)

    def _poll_future_until(
        self,
        fut: Future[_T],
        deadline_ns: int,
        *,
        on_abandon: Callable[[Future[_T]], None] | None = None,
    ) -> _T | None:
        while True:
            rem_ns = deadline_ns - int(self._monotonic_ns())
            if rem_ns <= 0 or self._past_stop_deadline():
                if on_abandon is not None:
                    on_abandon(fut)
                return None
            wait_s = min(_REPLY_WAIT_SLICE_S, max(0.001, rem_ns / 1_000_000_000.0))
            with self._lock:
                stop_dl = self._stop_deadline if self._quiesced else None
            if stop_dl is not None:
                stop_rem = stop_dl - time.perf_counter()
                if stop_rem <= 0:
                    if on_abandon is not None:
                        on_abandon(fut)
                    return None
                wait_s = min(wait_s, max(0.001, stop_rem))
            try:
                return fut.result(timeout=wait_s)
            except FuturesTimeoutError:
                continue

    def _await_owner_reply(self, reply_fut: Future[OwnerReply], deadline_ns: int) -> OwnerReply | None:
        return self._poll_future_until(reply_fut, deadline_ns, on_abandon=self._abandon_reply_future)

    def _abandon_reply_future(self, reply_fut: Future[OwnerReply]) -> None:
        _loopback_server_flow._abandon_reply_future(self, reply_fut)

    def _attach_send_settle_log(self, fut: Future[ArtifactSendAttempt], phase: str) -> None:
        def _on_done(done_fut: Future[ArtifactSendAttempt]) -> None:
            try:
                done_fut.result()
            except BrainError as err:
                if err.code is not ErrorCode.DAEMON_UNAVAILABLE:
                    _LOGGER.error("loopback send settle failed (phase=%s, code=%s)", phase, err.code.value)
            except Exception:  # noqa: BLE001
                _LOGGER.error(
                    "loopback send settle failed (phase=%s, code=%s)",
                    phase,
                    ErrorCode.INTEGRITY_FAILURE.value,
                )

        fut.add_done_callback(_on_done)

    def _finalize_send(self, completion: SendAttemptCompletion) -> None:
        try:
            fut = self._owner.finalize_send_attempt(completion)
        except BrainError as err:
            if err.code is not ErrorCode.DAEMON_UNAVAILABLE:
                _LOGGER.error(
                    "loopback finalize_send_attempt failed (phase=loopback_finalize_send, code=%s)",
                    err.code.value,
                )
            return
        self._attach_send_settle_log(fut, "loopback_finalize_send")

    def _interrupt_send(self, completion: SendAttemptCompletion) -> None:
        try:
            fut = self._owner.interrupt_send_attempt(completion.send_attempt_id)
        except BrainError as err:
            if err.code is not ErrorCode.DAEMON_UNAVAILABLE:
                _LOGGER.error(
                    "loopback interrupt_send_attempt failed (phase=loopback_interrupt_send, code=%s)",
                    err.code.value,
                )
            return
        self._attach_send_settle_log(fut, "loopback_interrupt_send")

    def _write_200_best_effort(self, ssl_sock: ssl.SSLSocket, body: bytes, deadline_ns: int) -> None:
        if int(self._monotonic_ns()) >= deadline_ns or self._past_stop_deadline():
            return
        with contextlib.suppress(HttpFramingError, TimeoutError, ssl.SSLError, OSError):
            write_json_response(
                ssl_sock,
                status=200,
                body=body,
                close_conn=True,
                deadline_ns=deadline_ns,
                monotonic_ns=self._monotonic_ns,
            )

    def _release_owner_reply(self, ssl_sock: ssl.SSLSocket, reply: OwnerReply, tool_deadline_ns: int) -> None:
        _loopback_server_flow._release_owner_reply(self, ssl_sock, reply, tool_deadline_ns)

    def _conn_worker(self, conn_id: int, raw_sock: socket.socket, accept_ns: int) -> None:
        _loopback_server_flow._conn_worker(self, conn_id, raw_sock, accept_ns)

    def _handle_capture_batch(
        self,
        ssl_sock: ssl.SSLSocket,
        command: CaptureBatchCommand,
        deadline_ns: int,
    ) -> None:
        _loopback_server_flow._handle_capture_batch(self, ssl_sock, command, deadline_ns)

    def _reject_non_mcp_tool_token(
        self,
        ssl_sock: ssl.SSLSocket,
        token: str,
        deadline_ns: int,
    ) -> bool:
        return _loopback_server_flow._reject_non_mcp_tool_token(self, ssl_sock, token, deadline_ns)

    def _release_conn(
        self,
        conn_id: int,
        raw_sock: socket.socket | None,
        ssl_sock: ssl.SSLSocket | None,
        *,
        drain: bool,
    ) -> None:
        _loopback_server_flow._release_conn(self, conn_id, raw_sock, ssl_sock, drain=drain)
