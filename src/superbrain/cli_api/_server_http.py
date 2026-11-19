"""HTTP/1.1 request admission and response framing helpers for ``LoopbackServer``."""

from __future__ import annotations

import contextlib
import math
import socket
import ssl
import threading
import time
from collections.abc import Callable

from superbrain.application.owner_loop import AuthGate
from superbrain.cli_api._http_frames import (
    FramedReader,
    HttpFramingError,
    RequestHead,
    write_all,
)
from superbrain.cli_api._loopback_wire import (
    HEADER_INSTANCE_ID,
    HEADER_STORE_ID,
    HEADER_WRITER_EPOCH,
    IDENTITY_PATH,
    TOOL_CALL_PATH,
    decode_call,
    encode_identity_response,
)
from superbrain.cli_api.operator import (
    OPERATOR_PATHS,
    OperatorExecutor,
    OperatorRequest,
    admit_operator_principal,
    parse_operator_body,
)
from superbrain.core.errors import (
    BrainError,
    ErrorCode,
    is_safe_wire_message,
)
from superbrain.core.kernel import CallResult, Principal, Ready, ToolCommand
from superbrain.core.wire import encode_envelope, make_error_envelope

_STATUS_REASON: dict[int, str] = {
    200: "OK",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    409: "Conflict",
    413: "Content Too Large",
}


class _AdmissionRejectedError(Exception):
    """Internal control-flow signal when an HTTP admission guard rejects a request."""

    def __init__(self, status: int, code: ErrorCode, message: str) -> None:
        super().__init__(code.value)
        self.status = status
        self.code = code
        self.message = message


def write_json_response(
    sock: socket.socket,
    *,
    status: int,
    body: bytes,
    close_conn: bool,
    deadline_ns: int,
    monotonic_ns: Callable[[], int],
) -> None:
    """Write a complete HTTP/1.1 JSON response frame within ``deadline_ns``."""
    reason = _STATUS_REASON.get(status, "Bad Request")
    conn_val = "close" if close_conn else "keep-alive"
    head = (
        f"HTTP/1.1 {status} {reason}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: {conn_val}\r\n\r\n"
    ).encode("ascii")
    write_all(sock, head + body, deadline_ns, monotonic_ns)


def write_error_response(
    sock: socket.socket,
    *,
    status: int,
    code: ErrorCode,
    message: str,
    deadline_ns: int,
    monotonic_ns: Callable[[], int],
) -> None:
    """Encode and write a safe v2 error envelope over HTTP, ignoring secondary send errors."""
    safe_msg = message if is_safe_wire_message(message) else "invalid input"
    envelope: CallResult = make_error_envelope(BrainError(code, safe_msg))
    payload = encode_envelope(envelope)
    try:
        write_json_response(
            sock,
            status=status,
            body=payload,
            close_conn=True,
            deadline_ns=deadline_ns,
            monotonic_ns=monotonic_ns,
        )
    except (HttpFramingError, OSError):
        return None


def _validate_common_headers(head: RequestHead, *, expected_port: int) -> None:
    if head.version != "HTTP/1.1":
        raise _AdmissionRejectedError(400, ErrorCode.INVALID_INPUT, "invalid input")
    if head.get_all("Origin"):
        raise _AdmissionRejectedError(403, ErrorCode.INVALID_INPUT, "invalid input")
    hosts = head.get_all("Host")
    if len(hosts) != 1 or hosts[0] != f"127.0.0.1:{expected_port}":
        raise _AdmissionRejectedError(400, ErrorCode.INVALID_INPUT, "invalid input")


def _extract_bearer_token(head: RequestHead) -> str:
    auth_values = head.get_all("Authorization")
    if len(auth_values) != 1:
        raise _AdmissionRejectedError(401, ErrorCode.UNAUTHENTICATED, "unauthenticated")
    raw_auth = auth_values[0]
    if not raw_auth.startswith("Bearer "):
        raise _AdmissionRejectedError(401, ErrorCode.UNAUTHENTICATED, "unauthenticated")
    token = raw_auth[7:]
    if not token or any(ord(ch) <= 0x20 or ord(ch) >= 0x7F for ch in token):
        raise _AdmissionRejectedError(401, ErrorCode.UNAUTHENTICATED, "unauthenticated")
    return token


def _validate_identity_headers(head: RequestHead, ready: Ready) -> None:
    store_vals = head.get_all(HEADER_STORE_ID)
    epoch_vals = head.get_all(HEADER_WRITER_EPOCH)
    inst_vals = head.get_all(HEADER_INSTANCE_ID)
    if len(store_vals) != 1 or len(epoch_vals) != 1 or len(inst_vals) != 1:
        raise _AdmissionRejectedError(409, ErrorCode.IDENTITY_MISMATCH, "identity mismatch")
    expected_epoch = str(ready.identity.writer_epoch)
    if (
        store_vals[0] != ready.identity.store_id
        or epoch_vals[0] != expected_epoch
        or inst_vals[0] != ready.identity.instance_id
    ):
        raise _AdmissionRejectedError(409, ErrorCode.IDENTITY_MISMATCH, "identity mismatch")


def handle_framing_failure(
    sock: socket.socket,
    err: HttpFramingError,
    *,
    deadline_ns: int,
    monotonic_ns: Callable[[], int],
) -> None:
    """Respond to framing errors when appropriate; stay silent on clean EOF or deadline cutoff."""
    if err.empty_eof or err.code is ErrorCode.DEADLINE_EXCEEDED:
        return None
    status = 413 if err.http_status == 413 else 400
    msg = "payload exceeds size limit" if status == 413 else "invalid input"
    write_error_response(
        sock,
        status=status,
        code=ErrorCode.INVALID_INPUT,
        message=msg,
        deadline_ns=deadline_ns,
        monotonic_ns=monotonic_ns,
    )


def handle_identity_request(
    sock: socket.socket,
    reader: FramedReader,
    ready: Ready,
    *,
    deadline_ns: int,
    monotonic_ns: Callable[[], int],
) -> bool:
    """Execute State 0 (``GET /v2/identity``); return ``True`` iff State 0 succeeded."""
    try:
        head = reader.read_request_head(deadline_ns)
        _validate_common_headers(head, expected_port=ready.endpoint.port)
        if head.method != "GET" or head.target != IDENTITY_PATH:
            raise _AdmissionRejectedError(400, ErrorCode.INVALID_INPUT, "invalid input")
        if head.content_length not in (None, 0):
            raise _AdmissionRejectedError(400, ErrorCode.INVALID_INPUT, "invalid input")
        if head.get_all("Authorization"):
            raise _AdmissionRejectedError(400, ErrorCode.INVALID_INPUT, "invalid input")
        if reader.has_pipelined_bytes(deadline_ns):
            raise _AdmissionRejectedError(400, ErrorCode.INVALID_INPUT, "invalid input")
        payload = encode_identity_response(ready.identity, ready.endpoint.contract)
        write_json_response(
            sock,
            status=200,
            body=payload,
            close_conn=False,
            deadline_ns=deadline_ns,
            monotonic_ns=monotonic_ns,
        )
        return True
    except _AdmissionRejectedError as rej:
        write_error_response(
            sock,
            status=rej.status,
            code=rej.code,
            message=rej.message,
            deadline_ns=deadline_ns,
            monotonic_ns=monotonic_ns,
        )
        return False
    except HttpFramingError as err:
        handle_framing_failure(sock, err, deadline_ns=deadline_ns, monotonic_ns=monotonic_ns)
        return False


def _read_admitted_common(
    reader: FramedReader,
    ready: Ready,
    *,
    is_operator: bool,
    auth_gate: Callable[[], AuthGate] | None,
    deadline_ns: int,
) -> tuple[RequestHead, str, Principal | None, bytes]:
    head = reader.read_request_head(deadline_ns)
    _validate_common_headers(head, expected_port=ready.endpoint.port)
    target_ok = (head.target in OPERATOR_PATHS) if is_operator else (head.target == TOOL_CALL_PATH)
    if head.method != "POST" or not target_ok or head.content_length is None:
        raise _AdmissionRejectedError(400, ErrorCode.INVALID_INPUT, "invalid input")
    token = _extract_bearer_token(head)
    _validate_identity_headers(head, ready)
    principal = _admit_operator(token, auth_gate) if (is_operator and auth_gate is not None) else None
    body = reader.read_exact(head.content_length, deadline_ns)
    if reader.has_pipelined_bytes(deadline_ns):
        raise _AdmissionRejectedError(400, ErrorCode.INVALID_INPUT, "invalid input")
    return head, token, principal, body


def read_admitted_tool_command(
    sock: socket.socket,
    reader: FramedReader,
    ready: Ready,
    *,
    deadline_ns: int,
    monotonic_ns: Callable[[], int],
) -> ToolCommand | None:
    """Validate and read State 1 (``POST /v2/tools/call``) before ``OwnerLoop`` handoff."""
    try:
        _head, token, _principal, body = _read_admitted_common(
            reader, ready, is_operator=False, auth_gate=None, deadline_ns=deadline_ns
        )
        try:
            return decode_call(body, token)
        except BrainError as err:
            raise _AdmissionRejectedError(400, ErrorCode.INVALID_INPUT, err.message) from err
    except _AdmissionRejectedError as rej:
        write_error_response(
            sock,
            status=rej.status,
            code=rej.code,
            message=rej.message,
            deadline_ns=deadline_ns,
            monotonic_ns=monotonic_ns,
        )
        return None
    except HttpFramingError as err:
        handle_framing_failure(sock, err, deadline_ns=deadline_ns, monotonic_ns=monotonic_ns)
        return None


def read_admitted_operator_request(
    sock: socket.socket,
    reader: FramedReader,
    ready: Ready,
    *,
    auth_gate: Callable[[], AuthGate],
    deadline_ns: int,
    monotonic_ns: Callable[[], int],
) -> OperatorRequest | None:
    """Validate and read State 1 (``POST /v2/operator/*``), admitting ``user:cli`` before body parsing."""
    try:
        head, token, principal, body = _read_admitted_common(
            reader, ready, is_operator=True, auth_gate=auth_gate, deadline_ns=deadline_ns
        )
        assert principal is not None
        try:
            return OperatorRequest(path=head.target, principal=principal, body=parse_operator_body(body), token=token)
        except BrainError as err:
            raise _AdmissionRejectedError(400, ErrorCode.INVALID_INPUT, err.message) from err
    except _AdmissionRejectedError as rej:
        write_error_response(
            sock,
            status=rej.status,
            code=rej.code,
            message=rej.message,
            deadline_ns=deadline_ns,
            monotonic_ns=monotonic_ns,
        )
        return None
    except HttpFramingError as err:
        handle_framing_failure(sock, err, deadline_ns=deadline_ns, monotonic_ns=monotonic_ns)
        return None


def _admit_operator(token: str, auth_gate: Callable[[], AuthGate]) -> Principal:
    try:
        return admit_operator_principal(token, auth_gate())
    except BrainError as err:
        status = {ErrorCode.UNAUTHENTICATED: 401, ErrorCode.IDENTITY_MISMATCH: 409}.get(err.code, 400)
        raise _AdmissionRejectedError(status, err.code, err.message) from err


def serve_operator(
    ssl_sock: ssl.SSLSocket,
    request: OperatorRequest,
    operator: OperatorExecutor | None,
    deadline_ns: int,
    monotonic_ns: Callable[[], int],
    *,
    past_stop_deadline: Callable[[], bool] | None = None,
) -> None:
    """Run one admitted operator request and write its envelope (``CAPABILITY_UNAVAILABLE`` if none is wired)."""
    if operator is None:
        unavailable = BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")
        envelope: CallResult = make_error_envelope(unavailable)
    else:
        try:
            envelope = operator(request, deadline_ns)
        except BrainError as err:
            envelope = make_error_envelope(err)
    if int(monotonic_ns()) >= deadline_ns or (past_stop_deadline is not None and past_stop_deadline()):
        return
    with contextlib.suppress(HttpFramingError, TimeoutError, ssl.SSLError, OSError):
        write_json_response(
            ssl_sock,
            status=200,
            body=encode_envelope(envelope),
            close_conn=True,
            deadline_ns=deadline_ns,
            monotonic_ns=monotonic_ns,
        )


def try_handle_operator_request(
    ssl_sock: ssl.SSLSocket,
    reader: FramedReader,
    ready: Ready,
    *,
    auth_gate: Callable[[], AuthGate],
    operator: OperatorExecutor | None,
    deadline_ns: int,
    monotonic_ns: Callable[[], int],
    is_quiesced: Callable[[], bool] | None = None,
    past_stop_deadline: Callable[[], bool] | None = None,
) -> tuple[bool, bool]:
    """Peek request target; handle operator path or framing error and return ``(handled, clean_done)``."""
    try:
        target = reader.peek_request_target(deadline_ns)
    except HttpFramingError as err:
        handle_framing_failure(ssl_sock, err, deadline_ns=deadline_ns, monotonic_ns=monotonic_ns)
        return True, False
    if target not in OPERATOR_PATHS:
        return False, False
    op_req = read_admitted_operator_request(
        ssl_sock,
        reader,
        ready,
        auth_gate=auth_gate,
        deadline_ns=deadline_ns,
        monotonic_ns=monotonic_ns,
    )
    if op_req is None:
        return True, False
    if is_quiesced is not None and is_quiesced():
        if not (past_stop_deadline is not None and past_stop_deadline()):
            unavail: CallResult = make_error_envelope(BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable"))
            with contextlib.suppress(HttpFramingError, TimeoutError, ssl.SSLError, OSError):
                write_json_response(
                    ssl_sock,
                    status=200,
                    body=encode_envelope(unavail),
                    close_conn=True,
                    deadline_ns=deadline_ns,
                    monotonic_ns=monotonic_ns,
                )
        return True, True
    serve_operator(
        ssl_sock,
        op_req,
        operator,
        deadline_ns,
        monotonic_ns,
        past_stop_deadline=past_stop_deadline,
    )
    return True, True


def join_before_cutoff(thread: threading.Thread | None, deadline: float, slice_s: float = 0.001) -> None:
    """Join ``thread`` in short slices until ``deadline``."""
    if thread is None or thread is threading.current_thread():
        return
    while thread.is_alive():
        remaining = deadline - time.perf_counter()
        if remaining <= 0:
            return
        _safe_join(thread, min(remaining, slice_s))


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
    stop_deadline: float | None = None,
) -> None:
    target: socket.socket | None = ssl_sock if ssl_sock is not None else raw_sock
    if target is not None:
        with contextlib.suppress(OSError):
            target.shutdown(socket.SHUT_WR)
        if drain:
            drain_deadline = time.perf_counter() + 0.002
            if stop_deadline is not None:
                drain_deadline = min(drain_deadline, stop_deadline)
            with contextlib.suppress(ssl.SSLError, OSError):
                for _ in range(4):
                    rem = drain_deadline - time.perf_counter()
                    if rem <= 0:
                        break
                    target.settimeout(rem)
                    chunk = target.recv(4096)
                    if not chunk:
                        break
    if ssl_sock is not None:
        with contextlib.suppress(OSError):
            ssl_sock.close()
    if raw_sock is not None and raw_sock is not ssl_sock:
        with contextlib.suppress(OSError):
            raw_sock.close()


def _safe_join(thread: threading.Thread | None, timeout: float) -> None:
    if thread is None or threading.current_thread() is thread:
        return
    with contextlib.suppress(RuntimeError):
        thread.join(timeout=max(0.0, timeout))


def _validate_stop_deadline(stop_deadline: float) -> float:
    if (
        isinstance(stop_deadline, bool)
        or not isinstance(stop_deadline, (int, float))
        or not math.isfinite(stop_deadline)
    ):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    return float(stop_deadline)
