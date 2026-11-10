"""HTTP/1.1 request admission and response framing helpers for ``LoopbackServer``."""

from __future__ import annotations

import socket
from collections.abc import Callable

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
from superbrain.core.errors import (
    BrainError,
    ErrorCode,
    is_safe_wire_message,
)
from superbrain.core.kernel import CallResult, Ready, ToolCommand
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
        head = reader.read_request_head(deadline_ns)
        _validate_common_headers(head, expected_port=ready.endpoint.port)
        if head.method != "POST" or head.target != TOOL_CALL_PATH:
            raise _AdmissionRejectedError(400, ErrorCode.INVALID_INPUT, "invalid input")
        if head.content_length is None:
            raise _AdmissionRejectedError(400, ErrorCode.INVALID_INPUT, "invalid input")
        token = _extract_bearer_token(head)
        _validate_identity_headers(head, ready)
        body = reader.read_exact(head.content_length, deadline_ns)
        if reader.has_pipelined_bytes(deadline_ns):
            raise _AdmissionRejectedError(400, ErrorCode.INVALID_INPUT, "invalid input")
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
