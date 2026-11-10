"""Pin-before-secret TLS loopback client with single-use identity-fenced connections."""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import re
import socket
import ssl
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from superbrain.cli_api._http_frames import FramedReader, HttpFramingError, write_all
from superbrain.cli_api._loopback_wire import (
    HEADER_INSTANCE_ID,
    HEADER_STORE_ID,
    HEADER_WRITER_EPOCH,
    IDENTITY_PATH,
    TOOL_CALL_PATH,
    decode_identity_response,
    decode_result,
    encode_call,
)
from superbrain.core.errors import (
    SAFE_WIRE_MESSAGES_BY_CODE,
    BrainError,
    ErrorCode,
    is_safe_wire_message,
)
from superbrain.core.kernel import CallResult, Endpoint, ToolCommand, require_opaque_id

CLIENT_CONNECT_BUDGET_NS = 2_000_000_000
CLIENT_TOOL_BUDGET_NS = 2_000_000_000

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_ERROR_STATUS_EXPECTED_CODE: dict[int, str] = {
    400: ErrorCode.INVALID_INPUT.value,
    401: ErrorCode.UNAUTHENTICATED.value,
    403: ErrorCode.INVALID_INPUT.value,
    409: ErrorCode.IDENTITY_MISMATCH.value,
    413: ErrorCode.INVALID_INPUT.value,
}


class LoopbackTransportError(BrainError):
    """Typed loopback transport failure carrying whether the POST tool call may have executed."""

    request_may_have_run: bool

    def __init__(self, code: ErrorCode, message: str, *, request_may_have_run: bool) -> None:
        if type(request_may_have_run) is not bool:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        super().__init__(code, message)
        self.request_may_have_run = request_may_have_run


@dataclass(frozen=True)
class LoopbackTarget:
    """Pre-loaded trust and endpoint parameters for connecting to a loopback daemon."""

    endpoint: Endpoint
    expected_store_id: str
    ca_pem: str
    leaf_cert_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.endpoint, Endpoint):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        require_opaque_id(self.expected_store_id, label="expected_store_id")
        if not isinstance(self.ca_pem, str) or not self.ca_pem.strip():
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if not isinstance(self.leaf_cert_sha256, str) or _HEX64_RE.fullmatch(self.leaf_cert_sha256) is None:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")


def _quiet_close(sock: socket.socket | None) -> None:
    if sock is not None:
        with contextlib.suppress(OSError):
            sock.close()


def _validate_optional_deadline(deadline_ns: int | None, *, request_may_have_run: bool) -> int | None:
    if deadline_ns is None:
        return None
    if isinstance(deadline_ns, bool):
        raise LoopbackTransportError(
            ErrorCode.INVALID_INPUT,
            "boolean not allowed for integer",
            request_may_have_run=request_may_have_run,
        )
    if not isinstance(deadline_ns, int):
        raise LoopbackTransportError(
            ErrorCode.INVALID_INPUT,
            "invalid input",
            request_may_have_run=request_may_have_run,
        )
    return deadline_ns


def _remaining_budget_s(
    monotonic_ns: Callable[[], int],
    deadline_ns: int,
    *,
    request_may_have_run: bool,
) -> float:
    rem_ns = deadline_ns - int(monotonic_ns())
    if rem_ns <= 0:
        raise LoopbackTransportError(
            ErrorCode.DEADLINE_EXCEEDED,
            "deadline exceeded",
            request_may_have_run=request_may_have_run,
        )
    return rem_ns / 1_000_000_000.0


def _has_connection_close(headers: tuple[str, ...]) -> bool:
    for header_val in headers:
        for token in header_val.split(","):
            if token.strip().lower() == "close":
                return True
    return False


class PinnedConnection:
    """Single-use TLS connection bound to a verified loopback daemon identity."""

    def __init__(
        self,
        *,
        sock: ssl.SSLSocket,
        reader: FramedReader,
        endpoint: Endpoint,
        tool_deadline_ns: int,
        monotonic_ns: Callable[[], int],
    ) -> None:
        self._lock = threading.Lock()
        self._sock: ssl.SSLSocket | None = sock
        self._reader: FramedReader | None = reader
        self._endpoint = endpoint
        self._tool_deadline_ns = tool_deadline_ns
        self._monotonic_ns = monotonic_ns
        self._claimed = False
        self._in_flight = False
        self._closed = False

    def call(self, command: ToolCommand, *, deadline_ns: int | None = None) -> CallResult:
        with self._lock:
            if self._claimed or self._closed or self._sock is None or self._reader is None:
                raise LoopbackTransportError(
                    ErrorCode.INVALID_INPUT,
                    "invalid input",
                    request_may_have_run=False,
                )
            self._claimed = True
            self._in_flight = True
            sock = self._sock
            reader = self._reader

        write_started = False
        eff_deadline_ns = self._tool_deadline_ns
        try:
            explicit_dl = _validate_optional_deadline(deadline_ns, request_may_have_run=False)
            if explicit_dl is not None:
                eff_deadline_ns = min(explicit_dl, self._tool_deadline_ns)

            if not isinstance(command, ToolCommand):
                raise LoopbackTransportError(
                    ErrorCode.INVALID_INPUT,
                    "invalid input",
                    request_may_have_run=False,
                )
            if (
                not isinstance(command.token, str)
                or not command.token
                or any(ord(ch) <= 0x20 or ord(ch) >= 0x7F for ch in command.token)
            ):
                raise LoopbackTransportError(
                    ErrorCode.INVALID_INPUT,
                    "invalid input",
                    request_may_have_run=False,
                )

            try:
                body_bytes = encode_call(command)
            except BrainError as err:
                msg = err.message if is_safe_wire_message(err.message) else SAFE_WIRE_MESSAGES_BY_CODE[err.code]
                raise LoopbackTransportError(err.code, msg, request_may_have_run=False) from err
            except (TypeError, ValueError, UnicodeError) as err:
                raise LoopbackTransportError(
                    ErrorCode.INVALID_INPUT,
                    "invalid input",
                    request_may_have_run=False,
                ) from err

            _remaining_budget_s(self._monotonic_ns, eff_deadline_ns, request_may_have_run=False)
            if reader.has_pipelined_bytes(eff_deadline_ns):
                raise LoopbackTransportError(
                    ErrorCode.DAEMON_UNAVAILABLE,
                    "daemon unavailable",
                    request_may_have_run=False,
                )

            ep = self._endpoint
            post_head = (
                f"POST {TOOL_CALL_PATH} HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{ep.port}\r\n"
                f"Authorization: Bearer {command.token}\r\n"
                f"{HEADER_STORE_ID}: {ep.store_id}\r\n"
                f"{HEADER_WRITER_EPOCH}: {ep.writer_epoch}\r\n"
                f"{HEADER_INSTANCE_ID}: {ep.instance_id}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(body_bytes)}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("ascii")
            request_frame = post_head + body_bytes

            _remaining_budget_s(self._monotonic_ns, eff_deadline_ns, request_may_have_run=False)
            write_started = True
            write_all(sock, request_frame, eff_deadline_ns, self._monotonic_ns)

            resp_head = reader.read_response_head(eff_deadline_ns)
            if resp_head.content_length is None:
                raise LoopbackTransportError(
                    ErrorCode.DAEMON_UNAVAILABLE,
                    "daemon unavailable",
                    request_may_have_run=True,
                )
            if resp_head.status != 200 and resp_head.status not in _ERROR_STATUS_EXPECTED_CODE:
                raise LoopbackTransportError(
                    ErrorCode.DAEMON_UNAVAILABLE,
                    "daemon unavailable",
                    request_may_have_run=True,
                )

            resp_body = reader.read_exact(resp_head.content_length, eff_deadline_ns)
            if reader.has_pipelined_bytes(eff_deadline_ns):
                raise LoopbackTransportError(
                    ErrorCode.DAEMON_UNAVAILABLE,
                    "daemon unavailable",
                    request_may_have_run=True,
                )

            try:
                envelope = decode_result(resp_body)
            except BrainError as err:
                raise LoopbackTransportError(
                    ErrorCode.DAEMON_UNAVAILABLE,
                    "daemon unavailable",
                    request_may_have_run=True,
                ) from err

            if resp_head.status != 200:
                expected_code = _ERROR_STATUS_EXPECTED_CODE[resp_head.status]
                err_obj = envelope.get("error")
                if (
                    envelope.get("ok") is not False
                    or not isinstance(err_obj, dict)
                    or err_obj.get("code") != expected_code
                ):
                    raise LoopbackTransportError(
                        ErrorCode.DAEMON_UNAVAILABLE,
                        "daemon unavailable",
                        request_may_have_run=True,
                    )

            _remaining_budget_s(self._monotonic_ns, eff_deadline_ns, request_may_have_run=True)
            return envelope
        except LoopbackTransportError:
            raise
        except HttpFramingError as err:
            if err.code is ErrorCode.DEADLINE_EXCEEDED:
                raise LoopbackTransportError(
                    ErrorCode.DEADLINE_EXCEEDED,
                    "deadline exceeded",
                    request_may_have_run=write_started,
                ) from err
            raise LoopbackTransportError(
                ErrorCode.DAEMON_UNAVAILABLE,
                "daemon unavailable",
                request_may_have_run=write_started,
            ) from err
        except (TimeoutError, ssl.SSLWantReadError, ssl.SSLWantWriteError) as err:
            raise LoopbackTransportError(
                ErrorCode.DEADLINE_EXCEEDED,
                "deadline exceeded",
                request_may_have_run=write_started,
            ) from err
        except (ssl.SSLError, OSError) as err:
            if int(self._monotonic_ns()) >= eff_deadline_ns:
                raise LoopbackTransportError(
                    ErrorCode.DEADLINE_EXCEEDED,
                    "deadline exceeded",
                    request_may_have_run=write_started,
                ) from err
            raise LoopbackTransportError(
                ErrorCode.DAEMON_UNAVAILABLE,
                "daemon unavailable",
                request_may_have_run=write_started,
            ) from err
        finally:
            with self._lock:
                self._in_flight = False
                self._closed = True
                self._sock = None
                self._reader = None
            _quiet_close(sock)

    def close(self) -> None:
        sock_to_close: ssl.SSLSocket | None = None
        with self._lock:
            self._closed = True
            if not self._in_flight and self._sock is not None:
                sock_to_close = self._sock
                self._sock = None
                self._reader = None
        _quiet_close(sock_to_close)


class LoopbackClient:
    """TLS loopback client verifying leaf pin and live identity before sending bearer credentials."""

    def __init__(self, monotonic_ns: Callable[[], int] = time.monotonic_ns) -> None:
        if not callable(monotonic_ns):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        self._monotonic_ns = monotonic_ns

    def connect(self, target: LoopbackTarget, deadline_ns: int | None = None) -> PinnedConnection:
        if not isinstance(target, LoopbackTarget):
            raise LoopbackTransportError(
                ErrorCode.INVALID_INPUT,
                "invalid input",
                request_may_have_run=False,
            )
        explicit_dl = _validate_optional_deadline(deadline_ns, request_may_have_run=False)
        if target.endpoint.store_id != target.expected_store_id:
            raise LoopbackTransportError(
                ErrorCode.IDENTITY_MISMATCH,
                "identity mismatch",
                request_may_have_run=False,
            )

        start_ns = int(self._monotonic_ns())
        connect_deadline_ns = (
            start_ns + CLIENT_CONNECT_BUDGET_NS
            if explicit_dl is None
            else min(explicit_dl, start_ns + CLIENT_CONNECT_BUDGET_NS)
        )
        _remaining_budget_s(self._monotonic_ns, connect_deadline_ns, request_may_have_run=False)
        if not target.ca_pem.strip() or not target.ca_pem.isascii():
            raise LoopbackTransportError(
                ErrorCode.INVALID_INPUT,
                "invalid input",
                request_may_have_run=False,
            )

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True
        try:
            ctx.load_verify_locations(cadata=target.ca_pem)
        except (ssl.SSLError, ValueError, TypeError) as err:
            raise LoopbackTransportError(
                ErrorCode.INVALID_INPUT,
                "invalid input",
                request_may_have_run=False,
            ) from err

        raw_sock: socket.socket | None = None
        ssl_sock: ssl.SSLSocket | None = None
        handed_off = False
        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            rem_s = _remaining_budget_s(self._monotonic_ns, connect_deadline_ns, request_may_have_run=False)
            raw_sock.settimeout(rem_s)
            raw_sock.connect(("127.0.0.1", target.endpoint.port))

            _remaining_budget_s(self._monotonic_ns, connect_deadline_ns, request_may_have_run=False)
            ssl_sock = ctx.wrap_socket(
                raw_sock,
                server_hostname="127.0.0.1",
                do_handshake_on_connect=False,
            )

            rem_s = _remaining_budget_s(self._monotonic_ns, connect_deadline_ns, request_may_have_run=False)
            ssl_sock.settimeout(rem_s)
            ssl_sock.do_handshake()

            _remaining_budget_s(self._monotonic_ns, connect_deadline_ns, request_may_have_run=False)
            der_cert = ssl_sock.getpeercert(binary_form=True)
            if not der_cert:
                raise LoopbackTransportError(
                    ErrorCode.IDENTITY_MISMATCH,
                    "identity mismatch",
                    request_may_have_run=False,
                )
            actual_sha256 = hashlib.sha256(der_cert).hexdigest()
            if not hmac.compare_digest(actual_sha256, target.leaf_cert_sha256):
                raise LoopbackTransportError(
                    ErrorCode.IDENTITY_MISMATCH,
                    "identity mismatch",
                    request_may_have_run=False,
                )

            _remaining_budget_s(self._monotonic_ns, connect_deadline_ns, request_may_have_run=False)
            reader = FramedReader(ssl_sock, self._monotonic_ns)
            probe_frame = (f"GET {IDENTITY_PATH} HTTP/1.1\r\nHost: 127.0.0.1:{target.endpoint.port}\r\n\r\n").encode(
                "ascii"
            )

            try:
                write_all(ssl_sock, probe_frame, connect_deadline_ns, self._monotonic_ns)
                resp_head = reader.read_response_head(connect_deadline_ns)
            except HttpFramingError as err:
                if err.code is ErrorCode.DEADLINE_EXCEEDED:
                    raise LoopbackTransportError(
                        ErrorCode.DEADLINE_EXCEEDED,
                        "deadline exceeded",
                        request_may_have_run=False,
                    ) from err
                if err.code is ErrorCode.IO_ERROR or err.empty_eof:
                    raise LoopbackTransportError(
                        ErrorCode.DAEMON_UNAVAILABLE,
                        "daemon unavailable",
                        request_may_have_run=False,
                    ) from err
                raise LoopbackTransportError(
                    ErrorCode.IDENTITY_MISMATCH,
                    "identity mismatch",
                    request_may_have_run=False,
                ) from err

            if resp_head.status != 200 or resp_head.content_length is None:
                raise LoopbackTransportError(
                    ErrorCode.IDENTITY_MISMATCH,
                    "identity mismatch",
                    request_may_have_run=False,
                )
            if _has_connection_close(resp_head.get_all("Connection")):
                raise LoopbackTransportError(
                    ErrorCode.DAEMON_UNAVAILABLE,
                    "daemon unavailable",
                    request_may_have_run=False,
                )

            try:
                ident_body = reader.read_exact(resp_head.content_length, connect_deadline_ns)
            except HttpFramingError as err:
                if err.code is ErrorCode.DEADLINE_EXCEEDED:
                    raise LoopbackTransportError(
                        ErrorCode.DEADLINE_EXCEEDED,
                        "deadline exceeded",
                        request_may_have_run=False,
                    ) from err
                raise LoopbackTransportError(
                    ErrorCode.DAEMON_UNAVAILABLE,
                    "daemon unavailable",
                    request_may_have_run=False,
                ) from err

            try:
                actual_ident, actual_contract = decode_identity_response(ident_body)
            except BrainError as err:
                raise LoopbackTransportError(
                    ErrorCode.IDENTITY_MISMATCH,
                    "identity mismatch",
                    request_may_have_run=False,
                ) from err

            if actual_ident != target.endpoint.identity or actual_contract != target.endpoint.contract:
                raise LoopbackTransportError(
                    ErrorCode.IDENTITY_MISMATCH,
                    "identity mismatch",
                    request_may_have_run=False,
                )

            try:
                pipelined = reader.has_pipelined_bytes(connect_deadline_ns)
            except HttpFramingError as err:
                if err.code is ErrorCode.DEADLINE_EXCEEDED:
                    raise LoopbackTransportError(
                        ErrorCode.DEADLINE_EXCEEDED,
                        "deadline exceeded",
                        request_may_have_run=False,
                    ) from err
                raise LoopbackTransportError(
                    ErrorCode.DAEMON_UNAVAILABLE,
                    "daemon unavailable",
                    request_may_have_run=False,
                ) from err
            if pipelined:
                raise LoopbackTransportError(
                    ErrorCode.IDENTITY_MISMATCH,
                    "identity mismatch",
                    request_may_have_run=False,
                )

            _remaining_budget_s(self._monotonic_ns, connect_deadline_ns, request_may_have_run=False)
            tool_deadline_ns = int(self._monotonic_ns()) + CLIENT_TOOL_BUDGET_NS
            conn = PinnedConnection(
                sock=ssl_sock,
                reader=reader,
                endpoint=target.endpoint,
                tool_deadline_ns=tool_deadline_ns,
                monotonic_ns=self._monotonic_ns,
            )
            handed_off = True
            return conn
        except LoopbackTransportError:
            raise
        except (TimeoutError, ssl.SSLWantReadError, ssl.SSLWantWriteError) as err:
            raise LoopbackTransportError(
                ErrorCode.DEADLINE_EXCEEDED,
                "deadline exceeded",
                request_may_have_run=False,
            ) from err
        except ssl.SSLCertVerificationError as err:
            raise LoopbackTransportError(
                ErrorCode.IDENTITY_MISMATCH,
                "identity mismatch",
                request_may_have_run=False,
            ) from err
        except ssl.SSLError as err:
            if int(self._monotonic_ns()) >= connect_deadline_ns:
                raise LoopbackTransportError(
                    ErrorCode.DEADLINE_EXCEEDED,
                    "deadline exceeded",
                    request_may_have_run=False,
                ) from err
            raise LoopbackTransportError(
                ErrorCode.IDENTITY_MISMATCH,
                "identity mismatch",
                request_may_have_run=False,
            ) from err
        except OSError as err:
            if int(self._monotonic_ns()) >= connect_deadline_ns:
                raise LoopbackTransportError(
                    ErrorCode.DEADLINE_EXCEEDED,
                    "deadline exceeded",
                    request_may_have_run=False,
                ) from err
            raise LoopbackTransportError(
                ErrorCode.DAEMON_UNAVAILABLE,
                "daemon unavailable",
                request_may_have_run=False,
            ) from err
        finally:
            if not handed_off:
                _quiet_close(ssl_sock)
                _quiet_close(raw_sock)

    def call(
        self,
        target: LoopbackTarget,
        command: ToolCommand,
        *,
        deadline_ns: int | None = None,
    ) -> CallResult:
        conn = self.connect(target, deadline_ns=deadline_ns)
        try:
            return conn.call(command, deadline_ns=deadline_ns)
        finally:
            conn.close()
