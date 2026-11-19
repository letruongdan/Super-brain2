"""Bounded TLS/HTTP loopback server enforcing two-request admission on the owner listener."""

from __future__ import annotations

import contextlib
import logging
import socket
import ssl
import threading
import time
from collections.abc import Callable
from concurrent.futures import Future
from concurrent.futures import TimeoutError as FuturesTimeoutError

from superbrain.application.owner_loop import OwnerLoop
from superbrain.cli_api._http_frames import FramedReader, HttpFramingError
from superbrain.cli_api._server_http import (
    _abort_socket,
    _graceful_close_conn,
    _graceful_reject_socket,
    _safe_join,
    _validate_stop_deadline,
    handle_identity_request,
    read_admitted_tool_command,
    write_error_response,
    write_json_response,
)
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import (
    CAPABILITY_MCP_TOOL,
    TOTAL_REQUEST_BUDGET_NS,
    ArtifactSendAttempt,
    CallResult,
    CaptureBatchCommand,
    OwnerReply,
    Ready,
    RequestAuthView,
    SendAttemptCompletion,
)
from superbrain.core.wire import encode_envelope, make_error_envelope

MAX_ACTIVE_CONNECTIONS = 32
SERVER_HANDSHAKE_BUDGET_NS = 1_000_000_000
_ACCEPT_POLL_S = 0.005
_REPLY_WAIT_SLICE_S = 0.005
_JOIN_WAIT_SLICE_S = 0.001

_LOGGER = logging.getLogger(__name__)


def _join_before_cutoff(thread: threading.Thread | None, deadline: float) -> None:
    if thread is None or thread is threading.current_thread():
        return
    while thread.is_alive():
        remaining = deadline - time.perf_counter()
        if remaining <= 0:
            return
        # Long timed joins can return well past their requested timeout on
        # coalescing OS timers. Recheck the shared cutoff after short waits.
        _safe_join(thread, min(remaining, _JOIN_WAIT_SLICE_S))


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
        ready_signaled = False
        try:
            while not self._stop_event.is_set():
                if self._is_quiesced():
                    break
                try:
                    raw_sock, peer_addr = self._listener.accept()
                except TimeoutError:
                    ready_signaled = self._signal_accept_ready(ready_signaled)
                    continue
                except OSError:
                    if self._is_quiesced() or self._stop_event.is_set():
                        break
                    with self._lock:
                        self._unexpected_error = True
                    _LOGGER.error(
                        "loopback accept failed (phase=loopback_accept, code=%s)",
                        ErrorCode.IO_ERROR.value,
                    )
                    self._stop_event.set()
                    break

                accept_ns = int(self._monotonic_ns())
                peer_ip = peer_addr[0] if isinstance(peer_addr, tuple) and len(peer_addr) >= 1 else ""
                if peer_ip != "127.0.0.1":
                    _abort_socket(raw_sock)
                    ready_signaled = self._signal_accept_ready(ready_signaled)
                    continue

                with self._lock:
                    shutting_down = self._quiesced or self._stop_event.is_set() or self._aborted
                    if shutting_down or self._active_slots >= MAX_ACTIVE_CONNECTIONS:
                        admitted = False
                        conn_id = -1
                    else:
                        self._conn_seq += 1
                        conn_id = self._conn_seq
                        self._active_slots += 1
                        self._slot_owners.add(conn_id)
                        self._sockets[conn_id] = raw_sock
                        admitted = True

                if not admitted:
                    if shutting_down:
                        _abort_socket(raw_sock)
                        break
                    _graceful_reject_socket(raw_sock)
                    ready_signaled = self._signal_accept_ready(ready_signaled)
                    continue

                worker = threading.Thread(
                    target=self._conn_worker,
                    args=(conn_id, raw_sock, accept_ns),
                    name=f"superbrain-loopback-conn-{conn_id}",
                    daemon=True,
                )
                with self._lock:
                    self._workers[conn_id] = worker
                try:
                    worker.start()
                except RuntimeError:
                    self._release_conn(conn_id, raw_sock, None, drain=False)
                ready_signaled = self._signal_accept_ready(ready_signaled)
        finally:
            self._accept_ready.set()

    def _await_owner_reply(self, reply_fut: Future[OwnerReply], deadline_ns: int) -> OwnerReply | None:
        while True:
            rem_ns = deadline_ns - int(self._monotonic_ns())
            if rem_ns <= 0 or self._past_stop_deadline():
                self._abandon_reply_future(reply_fut)
                return None
            wait_s = min(_REPLY_WAIT_SLICE_S, max(0.001, rem_ns / 1_000_000_000.0))
            with self._lock:
                stop_dl = self._stop_deadline if self._quiesced else None
            if stop_dl is not None:
                stop_rem = stop_dl - time.perf_counter()
                if stop_rem <= 0:
                    self._abandon_reply_future(reply_fut)
                    return None
                wait_s = min(wait_s, max(0.001, stop_rem))
            try:
                return reply_fut.result(timeout=wait_s)
            except FuturesTimeoutError:
                continue

    def _abandon_reply_future(self, reply_fut: Future[OwnerReply]) -> None:
        claimed = False

        def _on_late_reply(fut: Future[OwnerReply]) -> None:
            nonlocal claimed
            with self._lock:
                if claimed:
                    return
                claimed = True
            with contextlib.suppress(BaseException):
                rep = fut.result()
                if rep.send_completion is not None:
                    self._interrupt_send(rep.send_completion)

        if reply_fut.done():
            _on_late_reply(reply_fut)
            return
        reply_fut.add_done_callback(_on_late_reply)

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
        attempt_settled = False
        try:
            payload = encode_envelope(reply.envelope)
            if reply.envelope.get("ok") is True:
                if int(self._monotonic_ns()) >= tool_deadline_ns or self._past_stop_deadline():
                    return
                try:
                    granted = reply.grant_stamp is not None and self._owner.auth_gate.authorize_stamp(reply.grant_stamp)
                except BrainError:
                    granted = False

                if not granted:
                    revoked_env: CallResult = make_error_envelope(
                        BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable")
                    )
                    revoked_payload = encode_envelope(revoked_env)
                    self._write_200_best_effort(ssl_sock, revoked_payload, tool_deadline_ns)
                    if reply.send_completion is not None:
                        attempt_settled = True
                        self._interrupt_send(reply.send_completion)
                    return

                if int(self._monotonic_ns()) >= tool_deadline_ns or self._past_stop_deadline():
                    return
                try:
                    write_json_response(
                        ssl_sock,
                        status=200,
                        body=payload,
                        close_conn=True,
                        deadline_ns=tool_deadline_ns,
                        monotonic_ns=self._monotonic_ns,
                    )
                except (HttpFramingError, TimeoutError, ssl.SSLError, OSError):
                    if reply.send_completion is not None:
                        attempt_settled = True
                        self._interrupt_send(reply.send_completion)
                    return

                if reply.send_completion is not None:
                    attempt_settled = True
                    self._finalize_send(reply.send_completion)
                return

            self._write_200_best_effort(ssl_sock, payload, tool_deadline_ns)
        finally:
            if reply.send_completion is not None and not attempt_settled:
                self._interrupt_send(reply.send_completion)

    def _conn_worker(self, conn_id: int, raw_sock: socket.socket, accept_ns: int) -> None:
        ssl_sock: ssl.SSLSocket | None = None
        handshake_completed = False
        clean_done = False
        try:
            handshake_deadline_ns = accept_ns + SERVER_HANDSHAKE_BUDGET_NS
            rem_s = self._handshake_timeout_s(handshake_deadline_ns)
            if rem_s <= 0.0:
                return

            raw_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            raw_sock.setblocking(True)
            ssl_sock = self._ssl_context.wrap_socket(raw_sock, server_side=True, do_handshake_on_connect=False)
            with self._lock:
                if self._aborted:
                    return
                self._sockets[conn_id] = ssl_sock

            rem_s = self._handshake_timeout_s(handshake_deadline_ns)
            if rem_s <= 0.0:
                return
            ssl_sock.settimeout(rem_s)
            ssl_sock.do_handshake()
            handshake_completed = True
            if int(self._monotonic_ns()) >= handshake_deadline_ns or self._past_stop_deadline():
                return

            reader = FramedReader(ssl_sock, self._monotonic_ns)

            if self._is_quiesced():
                return
            t0_ident = int(self._monotonic_ns())
            ident_deadline_ns = t0_ident + TOTAL_REQUEST_BUDGET_NS
            if not handle_identity_request(
                ssl_sock,
                reader,
                self._ready,
                deadline_ns=ident_deadline_ns,
                monotonic_ns=self._monotonic_ns,
            ):
                return

            if self._is_quiesced():
                return
            t0_tool = int(self._monotonic_ns())
            tool_deadline_ns = t0_tool + TOTAL_REQUEST_BUDGET_NS
            command = read_admitted_tool_command(
                ssl_sock,
                reader,
                self._ready,
                deadline_ns=tool_deadline_ns,
                monotonic_ns=self._monotonic_ns,
            )
            if command is None:
                return

            if self._is_quiesced():
                unavail: CallResult = make_error_envelope(
                    BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")
                )
                self._write_200_best_effort(ssl_sock, encode_envelope(unavail), tool_deadline_ns)
                return

            if isinstance(command, CaptureBatchCommand):
                self._handle_capture_batch(ssl_sock, command, tool_deadline_ns)
                clean_done = True
                return

            if self._reject_non_mcp_tool_token(ssl_sock, command.token, tool_deadline_ns):
                clean_done = True
                return

            try:
                reply_fut = self._owner.submit_reply(command, tool_deadline_ns)
                reply = self._await_owner_reply(reply_fut, tool_deadline_ns)
            except BrainError as err:
                err_env: CallResult = make_error_envelope(err)
                self._write_200_best_effort(ssl_sock, encode_envelope(err_env), tool_deadline_ns)
                return

            if reply is None:
                return
            self._release_owner_reply(ssl_sock, reply, tool_deadline_ns)
            clean_done = True
        except (TimeoutError, ssl.SSLError, OSError):
            return
        except BrainError as err:
            _LOGGER.error("loopback connection failed (phase=loopback_conn, code=%s)", err.code.value)
        except Exception:  # noqa: BLE001
            _LOGGER.error(
                "loopback connection failed (phase=loopback_conn, code=%s)",
                ErrorCode.INTEGRITY_FAILURE.value,
            )
        finally:
            self._release_conn(conn_id, raw_sock, ssl_sock, drain=handshake_completed and not clean_done)

    def _handle_capture_batch(
        self,
        ssl_sock: ssl.SSLSocket,
        command: CaptureBatchCommand,
        deadline_ns: int,
    ) -> None:
        try:
            view = self._owner.auth_gate.current()
        except BrainError as err:
            self._write_200_best_effort(ssl_sock, encode_envelope(make_error_envelope(err)), deadline_ns)
            return
        if view is None:
            policy_err: CallResult = make_error_envelope(
                BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable")
            )
            self._write_200_best_effort(ssl_sock, encode_envelope(policy_err), deadline_ns)
            return
        try:
            view.auth.authorize_capture_producer(
                command.token,
                producer_stream=command.producer_stream,
                repo_id=command.repo_id,
                checkout_id=command.checkout_id,
            )
        except BrainError as err:
            status = (
                401
                if err.code is ErrorCode.UNAUTHENTICATED
                else 409
                if err.code is ErrorCode.IDENTITY_MISMATCH
                else 400
            )
            write_error_response(
                ssl_sock,
                status=status,
                code=err.code,
                message=err.message,
                deadline_ns=deadline_ns,
                monotonic_ns=self._monotonic_ns,
            )
            return
        stub_err: CallResult = make_error_envelope(
            BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")
        )
        self._write_200_best_effort(ssl_sock, encode_envelope(stub_err), deadline_ns)

    def _reject_non_mcp_tool_token(
        self,
        ssl_sock: ssl.SSLSocket,
        token: str,
        deadline_ns: int,
    ) -> bool:
        view: RequestAuthView | None = None
        with contextlib.suppress(BrainError):
            view = self._owner.auth_gate.current()
        if view is None:
            return False
        try:
            rec = view.auth.resolve_credential_record(token)
        except BrainError as err:
            if err.code is ErrorCode.UNAUTHENTICATED:
                return False
            raise
        if CAPABILITY_MCP_TOOL in rec.capabilities:
            return False
        write_error_response(
            ssl_sock,
            status=409,
            code=ErrorCode.IDENTITY_MISMATCH,
            message="identity mismatch",
            deadline_ns=deadline_ns,
            monotonic_ns=self._monotonic_ns,
        )
        return True

    def _release_conn(
        self,
        conn_id: int,
        raw_sock: socket.socket | None,
        ssl_sock: ssl.SSLSocket | None,
        *,
        drain: bool,
    ) -> None:
        with self._lock:
            stop_dl = self._stop_deadline if self._quiesced else None
            aborted = self._aborted
        if aborted:
            if ssl_sock is not None:
                _abort_socket(ssl_sock)
            if raw_sock is not None and raw_sock is not ssl_sock:
                _abort_socket(raw_sock)
        _graceful_close_conn(ssl_sock, raw_sock, drain=drain and not aborted, stop_deadline=stop_dl)
        with self._lock:
            self._sockets.pop(conn_id, None)
            self._workers.pop(conn_id, None)
            if conn_id in self._slot_owners:
                self._slot_owners.remove(conn_id)
                self._active_slots -= 1
