"""Bounded TLS/HTTP loopback server enforcing two-request admission on the owner listener."""

from __future__ import annotations

import contextlib
import logging
import math
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
    handle_identity_request,
    read_admitted_tool_command,
    write_json_response,
)
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import TOTAL_REQUEST_BUDGET_NS, CallResult, OwnerReply, Ready
from superbrain.core.wire import encode_envelope, make_error_envelope

MAX_ACTIVE_CONNECTIONS = 32
SERVER_HANDSHAKE_BUDGET_NS = 1_000_000_000
_ACCEPT_POLL_S = 0.05
_REPLY_WAIT_SLICE_S = 0.02

_LOGGER = logging.getLogger(__name__)


def _graceful_reject_socket(sock: socket.socket) -> None:
    with contextlib.suppress(OSError):
        sock.shutdown(socket.SHUT_WR)
    with contextlib.suppress(OSError):
        sock.close()


def _abort_socket(sock: socket.socket) -> None:
    with contextlib.suppress(OSError):
        sock.shutdown(socket.SHUT_RDWR)
    with contextlib.suppress(OSError):
        sock.close()


def _graceful_close_conn(
    ssl_sock: ssl.SSLSocket | None,
    raw_sock: socket.socket | None,
    *,
    drain: bool,
) -> None:
    target: socket.socket | None = ssl_sock if ssl_sock is not None else raw_sock
    if target is not None:
        with contextlib.suppress(OSError):
            target.shutdown(socket.SHUT_WR)
        if drain:
            with contextlib.suppress(ssl.SSLError, OSError):
                target.settimeout(0.05)
                drained = 0
                while drained < 65_536:
                    chunk = target.recv(4096)
                    if not chunk:
                        break
                    drained += len(chunk)
    if ssl_sock is not None:
        with contextlib.suppress(OSError):
            ssl_sock.close()
    if raw_sock is not None and raw_sock is not ssl_sock:
        with contextlib.suppress(OSError):
            raw_sock.close()


def _validate_stop_deadline(stop_deadline: float) -> float:
    if (
        isinstance(stop_deadline, bool)
        or not isinstance(stop_deadline, (int, float))
        or not math.isfinite(stop_deadline)
    ):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    return float(stop_deadline)


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
        self._stop_deadline: float | None = None
        self._conn_seq = 0
        self._active_slots = 0
        self._slot_owners: set[int] = set()
        self._sockets: dict[int, socket.socket] = {}
        self._workers: dict[int, threading.Thread] = {}

    def start(self) -> None:
        with self._lock:
            if self._quiesced:
                raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")
            if self._started:
                raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
            self._started = True

        try:
            self._listener.settimeout(_ACCEPT_POLL_S)
        except OSError as err:
            raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable") from err

        accept_thread = threading.Thread(
            target=self._accept_loop,
            name="superbrain-loopback-accept",
            daemon=True,
        )
        self._accept_thread = accept_thread
        try:
            accept_thread.start()
        except RuntimeError as err:
            raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable") from err

        if not self._accept_ready.wait(timeout=2.0):
            raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")

    def quiesce(self, stop_deadline: float) -> None:
        dl = _validate_stop_deadline(stop_deadline)
        start_abort_timer = False
        with self._lock:
            already_quiesced = self._quiesced
            self._quiesced = True
            if self._stop_deadline is None:
                self._stop_deadline = dl
            effective_dl = self._stop_deadline
            if not already_quiesced and self._started:
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
            with self._lock:
                self._abort_thread = timer_thread
            with contextlib.suppress(RuntimeError):
                timer_thread.start()

    def finish(self, stop_deadline: float) -> bool:
        dl = _validate_stop_deadline(stop_deadline)
        self.quiesce(dl)
        with self._lock:
            effective_dl = self._stop_deadline if self._stop_deadline is not None else dl
            accept_thread = self._accept_thread

        if accept_thread is not None and threading.current_thread() is not accept_thread:
            accept_thread.join(timeout=max(0.005, effective_dl - time.perf_counter()))

        while True:
            with self._lock:
                workers = list(self._workers.values())
            if not workers:
                break
            rem = effective_dl - time.perf_counter()
            if rem <= 0:
                break
            workers[0].join(timeout=rem)

        self._abort_wake.set()
        with self._lock:
            remaining_workers = [w for w in self._workers.values() if w.is_alive()]
            accept_alive = accept_thread is not None and accept_thread.is_alive()
            abort_thread = self._abort_thread

        timed_out = bool(remaining_workers) or accept_alive
        if timed_out:
            self._abort_all_active_sockets()
            for w in remaining_workers:
                if threading.current_thread() is not w:
                    w.join(timeout=0.05)
            if accept_thread is not None and threading.current_thread() is not accept_thread:
                accept_thread.join(timeout=0.05)

        if abort_thread is not None and threading.current_thread() is not abort_thread:
            abort_thread.join(timeout=0.05)

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

    def _accept_loop(self) -> None:
        self._accept_ready.set()
        while not self._stop_event.is_set():
            if self._is_quiesced():
                break
            try:
                raw_sock, peer_addr = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                if self._is_quiesced() or self._stop_event.is_set():
                    break
                with self._lock:
                    self._unexpected_error = True
                _LOGGER.error("loopback accept failed (phase=loopback_accept, code=%s)", ErrorCode.IO_ERROR.value)
                self._stop_event.set()
                break

            accept_ns = int(self._monotonic_ns())
            peer_ip = peer_addr[0] if isinstance(peer_addr, tuple) and len(peer_addr) >= 1 else ""
            if peer_ip != "127.0.0.1":
                _abort_socket(raw_sock)
                continue

            with self._lock:
                if self._quiesced or self._stop_event.is_set() or self._active_slots >= MAX_ACTIVE_CONNECTIONS:
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
                _graceful_reject_socket(raw_sock)
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

    def _await_owner_reply(self, reply_fut: Future[OwnerReply], deadline_ns: int) -> OwnerReply | None:
        while True:
            rem_ns = deadline_ns - int(self._monotonic_ns())
            if rem_ns <= 0 or self._past_stop_deadline():
                return None
            wait_s = min(_REPLY_WAIT_SLICE_S, max(0.001, rem_ns / 1_000_000_000.0))
            with self._lock:
                stop_dl = self._stop_deadline if self._quiesced else None
            if stop_dl is not None:
                stop_rem = stop_dl - time.perf_counter()
                if stop_rem <= 0:
                    return None
                wait_s = min(wait_s, max(0.001, stop_rem))
            try:
                return reply_fut.result(timeout=wait_s)
            except FuturesTimeoutError:
                continue

    def _conn_worker(self, conn_id: int, raw_sock: socket.socket, accept_ns: int) -> None:
        ssl_sock: ssl.SSLSocket | None = None
        handshake_completed = False
        try:
            handshake_deadline_ns = accept_ns + SERVER_HANDSHAKE_BUDGET_NS
            rem_s = self._handshake_timeout_s(handshake_deadline_ns)
            if rem_s <= 0.0:
                return

            raw_sock.setblocking(True)
            ssl_sock = self._ssl_context.wrap_socket(
                raw_sock,
                server_side=True,
                do_handshake_on_connect=False,
            )
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
                with contextlib.suppress(HttpFramingError, OSError):
                    write_json_response(
                        ssl_sock,
                        status=200,
                        body=encode_envelope(unavail),
                        close_conn=True,
                        deadline_ns=tool_deadline_ns,
                        monotonic_ns=self._monotonic_ns,
                    )
                return

            try:
                reply_fut = self._owner.submit_reply(command, tool_deadline_ns)
                reply = self._await_owner_reply(reply_fut, tool_deadline_ns)
            except BrainError as err:
                envelope: CallResult = make_error_envelope(err)
            else:
                if reply is None:
                    return
                envelope = reply.envelope

            if int(self._monotonic_ns()) >= tool_deadline_ns or self._past_stop_deadline():
                return
            payload = encode_envelope(envelope)
            with contextlib.suppress(HttpFramingError, OSError):
                write_json_response(
                    ssl_sock,
                    status=200,
                    body=payload,
                    close_conn=True,
                    deadline_ns=tool_deadline_ns,
                    monotonic_ns=self._monotonic_ns,
                )
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
            self._release_conn(conn_id, raw_sock, ssl_sock, drain=handshake_completed)

    def _release_conn(
        self,
        conn_id: int,
        raw_sock: socket.socket | None,
        ssl_sock: ssl.SSLSocket | None,
        *,
        drain: bool,
    ) -> None:
        _graceful_close_conn(ssl_sock, raw_sock, drain=drain)
        with self._lock:
            self._sockets.pop(conn_id, None)
            self._workers.pop(conn_id, None)
            if conn_id in self._slot_owners:
                self._slot_owners.remove(conn_id)
                self._active_slots -= 1
