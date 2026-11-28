"""Connection worker, accept loop, owner-reply release and capture batches of ``_loopback_server.LoopbackServer``.

Names that tests patch on ``_loopback_server`` are reached through that module (``_m``)."""

from __future__ import annotations

import contextlib
import socket
import ssl
import threading
from concurrent.futures import Future

from superbrain.cli_api import _loopback_server as _m
from superbrain.cli_api._http_frames import FramedReader, HttpFramingError
from superbrain.cli_api._server_http import (
    try_handle_operator_request,
    write_error_response,
)
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.faults import crashpoint
from superbrain.core.kernel import (
    CAPABILITY_MCP_TOOL,
    OPERATOR_REQUEST_BUDGET_NS,
    TOTAL_REQUEST_BUDGET_NS,
    CallResult,
    CaptureBatchCommand,
    OwnerReply,
    RequestAuthView,
)
from superbrain.core.wire import encode_envelope, make_error_envelope


def _conn_worker(self: _m.LoopbackServer, conn_id: int, raw_sock: socket.socket, accept_ns: int) -> None:
    ssl_sock: ssl.SSLSocket | None = None
    handshake_completed = False
    clean_done = False
    try:
        handshake_deadline_ns = accept_ns + _m.SERVER_HANDSHAKE_BUDGET_NS
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
        if not _m.handle_identity_request(
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
        handled, op_clean = try_handle_operator_request(
            ssl_sock,
            reader,
            self._ready,
            auth_gate=lambda: self._owner.auth_gate,
            operator=self._operator,
            deadline_ns=tool_deadline_ns,
            operator_deadline_ns=t0_tool + OPERATOR_REQUEST_BUDGET_NS,
            monotonic_ns=self._monotonic_ns,
            is_quiesced=self._is_quiesced,
            past_stop_deadline=self._past_stop_deadline,
        )
        if handled:
            clean_done = op_clean
            return
        command = _m.read_admitted_tool_command(
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
        _m._LOGGER.error("loopback connection failed (phase=loopback_conn, code=%s)", err.code.value)
    except Exception:  # noqa: BLE001
        _m._LOGGER.error(
            "loopback connection failed (phase=loopback_conn, code=%s)",
            ErrorCode.INTEGRITY_FAILURE.value,
        )
    finally:
        self._release_conn(conn_id, raw_sock, ssl_sock, drain=handshake_completed and not clean_done)


def _accept_loop(self: _m.LoopbackServer) -> None:
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
                _m._LOGGER.error(
                    "loopback accept failed (phase=loopback_accept, code=%s)",
                    ErrorCode.IO_ERROR.value,
                )
                self._stop_event.set()
                break

            accept_ns = int(self._monotonic_ns())
            peer_ip = peer_addr[0] if isinstance(peer_addr, tuple) and len(peer_addr) >= 1 else ""
            if peer_ip != "127.0.0.1":
                _m._abort_socket(raw_sock)
                ready_signaled = self._signal_accept_ready(ready_signaled)
                continue

            with self._lock:
                shutting_down = self._quiesced or self._stop_event.is_set() or self._aborted
                if shutting_down or self._active_slots >= _m.MAX_ACTIVE_CONNECTIONS:
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
                    _m._abort_socket(raw_sock)
                    break
                _m._graceful_reject_socket(raw_sock)
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


def _release_owner_reply(
    self: _m.LoopbackServer, ssl_sock: ssl.SSLSocket, reply: OwnerReply, tool_deadline_ns: int
) -> None:
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
            if reply.send_completion is not None:
                crashpoint("artifact_send.after_pending_before_flush")
            try:
                _m.write_json_response(
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


def _handle_capture_batch(
    self: _m.LoopbackServer,
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
    try:
        reply_fut = self._owner.submit_capture_batch(command, deadline_ns)
        envelope = self._poll_future_until(reply_fut, deadline_ns)
    except BrainError as err:
        self._write_200_best_effort(ssl_sock, encode_envelope(make_error_envelope(err)), deadline_ns)
        return
    if envelope is None:
        return
    self._write_200_best_effort(ssl_sock, encode_envelope(envelope), deadline_ns)


def _reject_non_mcp_tool_token(
    self: _m.LoopbackServer,
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


def _abandon_reply_future(self: _m.LoopbackServer, reply_fut: Future[OwnerReply]) -> None:
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


def _release_conn(
    self: _m.LoopbackServer,
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
            _m._abort_socket(ssl_sock)
        if raw_sock is not None and raw_sock is not ssl_sock:
            _m._abort_socket(raw_sock)
    _m._graceful_close_conn(ssl_sock, raw_sock, drain=drain and not aborted, stop_deadline=stop_dl)
    with self._lock:
        self._sockets.pop(conn_id, None)
        self._workers.pop(conn_id, None)
        if conn_id in self._slot_owners:
            self._slot_owners.remove(conn_id)
            self._active_slots -= 1
