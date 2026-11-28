"""Pinned TLS connect and handshake of ``loopback.LoopbackClient``."""

from __future__ import annotations

import hashlib
import hmac
import socket
import ssl

from superbrain.cli_api import loopback as _m
from superbrain.cli_api._http_frames import FramedReader, HttpFramingError
from superbrain.cli_api._loopback_wire import (
    IDENTITY_PATH,
    parse_identity_response,
)
from superbrain.core.errors import (
    BrainError,
    ErrorCode,
)
from superbrain.core.kernel import (
    SHA256_DIGEST_RE,
)
from superbrain.core.wire import load_catalog


def connect(
    self: _m.LoopbackClient,
    target: _m.LoopbackTarget,
    deadline_ns: int | None = None,
    *,
    post_budget_ns: int,
) -> _m.PinnedConnection:
    if not isinstance(target, _m.LoopbackTarget):
        raise _m.LoopbackTransportError(
            ErrorCode.INVALID_INPUT,
            "invalid input",
            request_may_have_run=False,
        )
    explicit_dl = _m._validate_optional_deadline(deadline_ns, request_may_have_run=False)
    if target.endpoint.store_id != target.expected_store_id:
        raise _m.LoopbackTransportError(
            ErrorCode.IDENTITY_MISMATCH,
            "identity mismatch",
            request_may_have_run=False,
        )

    start_ns = int(self._monotonic_ns())
    connect_deadline_ns = (
        start_ns + _m.CLIENT_CONNECT_BUDGET_NS
        if explicit_dl is None
        else min(explicit_dl, start_ns + _m.CLIENT_CONNECT_BUDGET_NS)
    )
    _m._remaining_budget_s(self._monotonic_ns, connect_deadline_ns, request_may_have_run=False)
    if not target.ca_pem.strip() or not target.ca_pem.isascii():
        raise _m.LoopbackTransportError(
            ErrorCode.INVALID_INPUT,
            "invalid input",
            request_may_have_run=False,
        )

    raw_sock: socket.socket | None = None
    ssl_sock: ssl.SSLSocket | None = None
    handed_off = False
    in_handshake = False
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True
        try:
            ctx.load_verify_locations(cadata=target.ca_pem)
        except (ssl.SSLError, ValueError, TypeError) as err:
            raise _m.LoopbackTransportError(
                ErrorCode.INVALID_INPUT,
                "invalid input",
                request_may_have_run=False,
            ) from err

        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        rem_s = _m._remaining_budget_s(self._monotonic_ns, connect_deadline_ns, request_may_have_run=False)
        raw_sock.settimeout(rem_s)
        raw_sock.connect(("127.0.0.1", target.endpoint.port))

        _m._remaining_budget_s(self._monotonic_ns, connect_deadline_ns, request_may_have_run=False)
        ssl_sock = ctx.wrap_socket(
            raw_sock,
            server_hostname="127.0.0.1",
            do_handshake_on_connect=False,
        )

        rem_s = _m._remaining_budget_s(self._monotonic_ns, connect_deadline_ns, request_may_have_run=False)
        ssl_sock.settimeout(rem_s)
        in_handshake = True
        ssl_sock.do_handshake()
        in_handshake = False

        _m._remaining_budget_s(self._monotonic_ns, connect_deadline_ns, request_may_have_run=False)
        der_cert = ssl_sock.getpeercert(binary_form=True)
        if not der_cert:
            raise _m.LoopbackTransportError(
                ErrorCode.IDENTITY_MISMATCH,
                "identity mismatch",
                request_may_have_run=False,
            )
        actual_sha256 = hashlib.sha256(der_cert).hexdigest()
        if not hmac.compare_digest(actual_sha256, target.leaf_cert_sha256):
            raise _m.LoopbackTransportError(
                ErrorCode.IDENTITY_MISMATCH,
                "identity mismatch",
                request_may_have_run=False,
            )

        _m._remaining_budget_s(self._monotonic_ns, connect_deadline_ns, request_may_have_run=False)
        reader = FramedReader(ssl_sock, self._monotonic_ns)
        probe_frame = (f"GET {IDENTITY_PATH} HTTP/1.1\r\nHost: 127.0.0.1:{target.endpoint.port}\r\n\r\n").encode(
            "ascii"
        )

        try:
            _m.write_all(ssl_sock, probe_frame, connect_deadline_ns, self._monotonic_ns)
            resp_head = reader.read_response_head(connect_deadline_ns)
        except HttpFramingError as err:
            if err.code is ErrorCode.DEADLINE_EXCEEDED:
                raise _m.LoopbackTransportError(
                    ErrorCode.DEADLINE_EXCEEDED,
                    "deadline exceeded",
                    request_may_have_run=False,
                ) from err
            if err.code is ErrorCode.IO_ERROR or err.empty_eof:
                raise _m.LoopbackTransportError(
                    ErrorCode.DAEMON_UNAVAILABLE,
                    "daemon unavailable",
                    request_may_have_run=False,
                ) from err
            raise _m.LoopbackTransportError(
                ErrorCode.IDENTITY_MISMATCH,
                "identity mismatch",
                request_may_have_run=False,
            ) from err

        if resp_head.status != 200 or resp_head.content_length is None:
            raise _m.LoopbackTransportError(
                ErrorCode.IDENTITY_MISMATCH,
                "identity mismatch",
                request_may_have_run=False,
            )
        if _m._has_connection_close(resp_head.get_all("Connection")):
            raise _m.LoopbackTransportError(
                ErrorCode.DAEMON_UNAVAILABLE,
                "daemon unavailable",
                request_may_have_run=False,
            )

        try:
            ident_body = reader.read_exact(resp_head.content_length, connect_deadline_ns)
        except HttpFramingError as err:
            if err.code is ErrorCode.DEADLINE_EXCEEDED:
                raise _m.LoopbackTransportError(
                    ErrorCode.DEADLINE_EXCEEDED,
                    "deadline exceeded",
                    request_may_have_run=False,
                ) from err
            raise _m.LoopbackTransportError(
                ErrorCode.DAEMON_UNAVAILABLE,
                "daemon unavailable",
                request_may_have_run=False,
            ) from err

        try:
            actual_ident, actual_contract, actual_digest = parse_identity_response(ident_body)
        except BrainError as err:
            raise _m.LoopbackTransportError(
                ErrorCode.IDENTITY_MISMATCH,
                "identity mismatch",
                request_may_have_run=False,
            ) from err

        if actual_ident != target.endpoint.identity or actual_contract != target.endpoint.contract:
            raise _m.LoopbackTransportError(
                ErrorCode.IDENTITY_MISMATCH,
                "identity mismatch",
                request_may_have_run=False,
            )

        try:
            pipelined = reader.has_pipelined_bytes(connect_deadline_ns)
        except HttpFramingError as err:
            if err.code is ErrorCode.DEADLINE_EXCEEDED:
                raise _m.LoopbackTransportError(
                    ErrorCode.DEADLINE_EXCEEDED,
                    "deadline exceeded",
                    request_may_have_run=False,
                ) from err
            raise _m.LoopbackTransportError(
                ErrorCode.DAEMON_UNAVAILABLE,
                "daemon unavailable",
                request_may_have_run=False,
            ) from err
        if pipelined:
            raise _m.LoopbackTransportError(
                ErrorCode.IDENTITY_MISMATCH,
                "identity mismatch",
                request_may_have_run=False,
            )

        expected_digest = load_catalog().schema_digest
        if (
            actual_digest is None
            or not SHA256_DIGEST_RE.fullmatch(actual_digest)
            or not hmac.compare_digest(actual_digest, expected_digest)
        ):
            raise _m.LoopbackTransportError(
                ErrorCode.UNSUPPORTED_VERSION,
                "unsupported version",
                request_may_have_run=False,
            )

        _m._remaining_budget_s(self._monotonic_ns, connect_deadline_ns, request_may_have_run=False)
        tool_deadline_ns = int(self._monotonic_ns()) + post_budget_ns
        conn = _m.PinnedConnection(
            sock=ssl_sock,
            reader=reader,
            endpoint=target.endpoint,
            tool_deadline_ns=tool_deadline_ns,
            monotonic_ns=self._monotonic_ns,
        )
        handed_off = True
        return conn
    except _m.LoopbackTransportError:
        raise
    except (TimeoutError, ssl.SSLWantReadError, ssl.SSLWantWriteError) as err:
        raise _m.LoopbackTransportError(
            ErrorCode.DEADLINE_EXCEEDED,
            "deadline exceeded",
            request_may_have_run=False,
        ) from err
    except ssl.SSLCertVerificationError as err:
        raise _m.LoopbackTransportError(
            ErrorCode.IDENTITY_MISMATCH,
            "identity mismatch",
            request_may_have_run=False,
        ) from err
    except ssl.SSLError as err:
        if int(self._monotonic_ns()) >= connect_deadline_ns:
            raise _m.LoopbackTransportError(
                ErrorCode.DEADLINE_EXCEEDED,
                "deadline exceeded",
                request_may_have_run=False,
            ) from err
        if in_handshake and not isinstance(err, (ssl.SSLEOFError, ssl.SSLZeroReturnError, ssl.SSLSyscallError)):
            raise _m.LoopbackTransportError(
                ErrorCode.IDENTITY_MISMATCH,
                "identity mismatch",
                request_may_have_run=False,
            ) from err
        raise _m.LoopbackTransportError(
            ErrorCode.DAEMON_UNAVAILABLE,
            "daemon unavailable",
            request_may_have_run=False,
        ) from err
    except (OSError, ValueError) as err:
        if int(self._monotonic_ns()) >= connect_deadline_ns:
            raise _m.LoopbackTransportError(
                ErrorCode.DEADLINE_EXCEEDED,
                "deadline exceeded",
                request_may_have_run=False,
            ) from err
        raise _m.LoopbackTransportError(
            ErrorCode.DAEMON_UNAVAILABLE,
            "daemon unavailable",
            request_may_have_run=False,
        ) from err
    finally:
        if not handed_off:
            _m._quiet_close(ssl_sock)
            _m._quiet_close(raw_sock)
