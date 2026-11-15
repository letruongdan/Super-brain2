"""Pure Task 6b.1 HTTP/1.1 framing and internal loopback wire regression suite."""

from __future__ import annotations

import contextlib
import datetime as dt
import random
import socket
import ssl
import threading
import time
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from typing import Any, cast

import pytest

from superbrain.application.owner_loop import OwnerLoop, OwnerSession
from superbrain.cli_api import _loopback_server as loopback_server_module
from superbrain.cli_api._http_frames import (
    MAX_BODY_BYTES,
    MAX_HEADER_BLOCK_BYTES,
    MAX_HEADER_FIELDS,
    MAX_REQUEST_LINE_BYTES,
    FramedReader,
    HttpFramingError,
    RequestHead,
    ResponseHead,
    write_all,
)
from superbrain.cli_api._loopback_server import SERVER_HANDSHAKE_BUDGET_NS, LoopbackServer
from superbrain.cli_api._loopback_wire import (
    HEADER_INSTANCE_ID,
    HEADER_STORE_ID,
    HEADER_WRITER_EPOCH,
    IDENTITY_PATH,
    MAX_CORRELATION_ID_BYTES,
    TOOL_CALL_PATH,
    decode_call,
    decode_identity_response,
    decode_result,
    encode_call,
    encode_identity_response,
)
from superbrain.cli_api.loopback import CLIENT_CONNECT_BUDGET_NS
from superbrain.composition._endpoint import build_server_ssl_context
from superbrain.core._wire_catalog import EXPECTED_TOOL_ORDER
from superbrain.core.canonical import canonical_json
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import (
    ENDPOINT_CONTRACT,
    ENDPOINT_HOST,
    ENDPOINT_VERSION,
    DaemonConfig,
    Endpoint,
    Identity,
    Ready,
    Scope,
    ToolCommand,
)
from superbrain.core.wire import encode_envelope
from tests.support.inc2_fixture import SampleTlsMaterial


class FakeClock:
    """Deterministic monotonic clock advancing strictly under test control."""

    def __init__(self, start_ns: int = 1_000_000_000) -> None:
        self.now_ns: int = start_ns

    def __call__(self) -> int:
        return self.now_ns

    def advance(self, delta_ns: int) -> int:
        self.now_ns += delta_ns
        return self.now_ns

    def set(self, value_ns: int) -> None:
        self.now_ns = value_ns


class TrackingSocket(socket.socket):
    """Socket subclass recording settimeout invocations and supporting custom recv/send hooks."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.recorded_timeouts: list[float] = []
        self.recv_hook: Callable[[int, int], bytes] | None = None
        self.send_hook: Callable[[Any, int], int] | None = None

    def settimeout(self, value: float | None) -> None:
        if value is not None:
            self.recorded_timeouts.append(value)
        super().settimeout(value)

    def raw_recv(self, bufsize: int, flags: int = 0) -> bytes:
        data = super().recv(bufsize, flags)
        return data if isinstance(data, bytes) else bytes(data)

    def raw_send(self, data: Any, flags: int = 0) -> int:
        return int(super().send(data, flags))

    def recv(self, bufsize: int, flags: int = 0) -> bytes:
        if self.recv_hook is not None:
            return self.recv_hook(bufsize, flags)
        return self.raw_recv(bufsize, flags)

    def send(self, data: Any, flags: int = 0) -> int:
        if self.send_hook is not None:
            return self.send_hook(data, flags)
        return self.raw_send(data, flags)


@contextlib.contextmanager
def socket_pair() -> Iterator[tuple[socket.socket, socket.socket]]:
    client_sock, server_sock = socket.socketpair()
    try:
        yield client_sock, server_sock
    finally:
        client_sock.close()
        server_sock.close()


@contextlib.contextmanager
def feed_frame(payload: bytes) -> Iterator[socket.socket]:
    """Feed a complete frame while the reader drains the bounded socket buffer."""
    with socket_pair() as (receiver, sender), ThreadPoolExecutor(max_workers=1) as executor:
        sender.settimeout(5.0)

        def send() -> None:
            try:
                sender.sendall(payload)
            finally:
                sender.shutdown(socket.SHUT_WR)

        sent = executor.submit(send)
        yield receiver
        sent.result()


@contextlib.contextmanager
def tracking_socket_pair() -> Iterator[tuple[TrackingSocket, socket.socket]]:
    client_sock, server_sock = socket.socketpair()
    track_sock = TrackingSocket(fileno=client_sock.detach())
    try:
        yield track_sock, server_sock
    finally:
        track_sock.close()
        server_sock.close()


@contextlib.contextmanager
def tls_pair(
    tls: SampleTlsMaterial,
) -> Iterator[tuple[ssl.SSLSocket, ssl.SSLSocket]]:
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(certfile=str(tls.leaf_cert_path), keyfile=str(tls.leaf_key_path))

    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_ctx.load_verify_locations(cafile=str(tls.ca_cert_path))
    client_ctx.check_hostname = True

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    raw_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_client.connect(("127.0.0.1", port))
    raw_server, _ = listener.accept()
    listener.close()

    server_ssl = server_ctx.wrap_socket(raw_server, server_side=True, do_handshake_on_connect=False)
    client_ssl = client_ctx.wrap_socket(raw_client, server_hostname="127.0.0.1", do_handshake_on_connect=False)

    handshake_err: list[OSError] = []

    def run_server_handshake() -> None:
        try:
            server_ssl.do_handshake()
        except OSError as err:
            handshake_err.append(err)

    handshake_thread = threading.Thread(target=run_server_handshake, daemon=True)
    handshake_thread.start()
    try:
        client_ssl.do_handshake()
    finally:
        handshake_thread.join(timeout=5.0)

    if handshake_thread.is_alive():
        raise TimeoutError("TLS handshake timed out")
    if handshake_err:
        raise handshake_err[0]

    try:
        yield client_ssl, server_ssl
    finally:
        client_ssl.close()
        server_ssl.close()


def test_header_caps_apply_before_stdlib_parser() -> None:
    """Framing bounds apply before stdlib parsers on request and response heads and bodies."""
    assert MAX_REQUEST_LINE_BYTES == 8_192
    assert MAX_HEADER_BLOCK_BYTES == 16_384
    assert MAX_HEADER_FIELDS == 32
    assert MAX_BODY_BYTES == 1_048_576

    clock = FakeClock(1_000_000_000)
    ample_deadline = clock.now_ns + 10_000_000_000

    # 1. Exact request line cap: 8,192 bytes accepted; 8,193 bytes refused.
    prefix = b"GET /"
    suffix = b" HTTP/1.1\r\n"
    pad_len_exact = 8_192 - len(prefix) - len(suffix)
    line_8192 = prefix + (b"a" * pad_len_exact) + suffix
    assert len(line_8192) == 8_192

    with feed_frame(line_8192 + b"\r\n") as client_sock:
        reader = FramedReader(client_sock, clock)
        head = reader.read_request_head(ample_deadline)
        assert isinstance(head, RequestHead)
        assert head.method == "GET"
        assert head.version == "HTTP/1.1"
        assert len(head.target) == pad_len_exact + 1
        assert head.headers == ()
        assert head.content_length is None

    line_8193 = prefix + (b"a" * (pad_len_exact + 1)) + suffix
    assert len(line_8193) == 8_193
    with feed_frame(line_8193 + b"\r\n") as client_sock:
        reader = FramedReader(client_sock, clock)
        with pytest.raises(HttpFramingError) as exc_req_cap:
            reader.read_request_head(ample_deadline)
        assert exc_req_cap.value.code is ErrorCode.INVALID_INPUT
        assert exc_req_cap.value.http_status == 400
        assert exc_req_cap.value.empty_eof is False

    # 2. Exact status line cap: 8,192 bytes accepted; 8,193 bytes refused.
    status_pfx = b"HTTP/1.1 200 "
    status_sfx = b"\r\n"
    status_pad_exact = 8_192 - len(status_pfx) - len(b"OK") - len(status_sfx)
    status_8192 = status_pfx + b"OK" + (b" " * status_pad_exact) + status_sfx
    assert len(status_8192) == 8_192

    with feed_frame(status_8192 + b"\r\n") as client_sock:
        reader = FramedReader(client_sock, clock)
        resp = reader.read_response_head(ample_deadline)
        assert isinstance(resp, ResponseHead)
        assert resp.status == 200
        assert resp.version == "HTTP/1.1"
        assert resp.headers == ()

    status_8193 = status_pfx + b"OK" + (b" " * (status_pad_exact + 1)) + status_sfx
    assert len(status_8193) == 8_193
    with feed_frame(status_8193 + b"\r\n") as client_sock:
        reader = FramedReader(client_sock, clock)
        with pytest.raises(HttpFramingError) as exc_resp_cap:
            reader.read_response_head(ample_deadline)
        assert exc_resp_cap.value.code is ErrorCode.INVALID_INPUT
        assert exc_resp_cap.value.http_status == 400

    # 3. Exact header block boundary: 16,384 bytes counted from first byte of first header through empty CRLF inclusive.
    h_pfx = b"X-Pad: "
    h_sfx = b"\r\n\r\n"
    h_pad_exact = 16_384 - len(h_pfx) - len(h_sfx)
    block_16384 = h_pfx + (b"x" * h_pad_exact) + h_sfx
    assert len(block_16384) == 16_384

    with feed_frame(b"GET / HTTP/1.1\r\n" + block_16384) as client_sock:
        reader = FramedReader(client_sock, clock)
        head_block = reader.read_request_head(ample_deadline)
        assert len(head_block.headers) == 1
        assert head_block.headers[0][0].lower() == "x-pad"

    block_16385 = h_pfx + (b"x" * (h_pad_exact + 1)) + h_sfx
    assert len(block_16385) == 16_385
    with feed_frame(b"GET / HTTP/1.1\r\n" + block_16385) as client_sock:
        reader = FramedReader(client_sock, clock)
        with pytest.raises(HttpFramingError) as exc_hb_req:
            reader.read_request_head(ample_deadline)
        assert exc_hb_req.value.code is ErrorCode.INVALID_INPUT
        assert exc_hb_req.value.http_status == 400

    with feed_frame(b"HTTP/1.1 200 OK\r\n" + block_16384) as client_sock:
        reader = FramedReader(client_sock, clock)
        resp_block = reader.read_response_head(ample_deadline)
        assert len(resp_block.headers) == 1

    with feed_frame(b"HTTP/1.1 200 OK\r\n" + block_16385) as client_sock:
        reader = FramedReader(client_sock, clock)
        with pytest.raises(HttpFramingError) as exc_hb_resp:
            reader.read_response_head(ample_deadline)
        assert exc_hb_resp.value.code is ErrorCode.INVALID_INPUT
        assert exc_hb_resp.value.http_status == 400

    # 4. Header field count limit: 32 accepted, 33 refused before stdlib parser.
    fields_32 = b"".join(f"X-Field-{i:02d}: val{i}\r\n".encode("ascii") for i in range(32)) + b"\r\n"
    with socket_pair() as (client_sock, server_sock):
        server_sock.sendall(b"GET / HTTP/1.1\r\n" + fields_32)
        reader = FramedReader(client_sock, clock)
        head_32 = reader.read_request_head(ample_deadline)
        assert len(head_32.headers) == 32

    with socket_pair() as (client_sock, server_sock):
        server_sock.sendall(b"HTTP/1.1 200 OK\r\n" + fields_32)
        reader = FramedReader(client_sock, clock)
        resp_32 = reader.read_response_head(ample_deadline)
        assert len(resp_32.headers) == 32

    fields_33 = b"".join(f"X-Field-{i:02d}: val{i}\r\n".encode("ascii") for i in range(33)) + b"\r\n"
    with socket_pair() as (client_sock, server_sock):
        server_sock.sendall(b"GET / HTTP/1.1\r\n" + fields_33)
        reader = FramedReader(client_sock, clock)
        with pytest.raises(HttpFramingError) as exc_f33_req:
            reader.read_request_head(ample_deadline)
        assert exc_f33_req.value.code is ErrorCode.INVALID_INPUT
        assert exc_f33_req.value.http_status == 400

    with socket_pair() as (client_sock, server_sock):
        server_sock.sendall(b"HTTP/1.1 200 OK\r\n" + fields_33)
        reader = FramedReader(client_sock, clock)
        with pytest.raises(HttpFramingError) as exc_f33_resp:
            reader.read_response_head(ample_deadline)
        assert exc_f33_resp.value.code is ErrorCode.INVALID_INPUT
        assert exc_f33_resp.value.http_status == 400

    # 5. Body cap: 1,048,576 B accepted; 1,048,577 B refused with 413 before body buffer allocation.
    with socket_pair() as (client_sock, server_sock):
        server_sock.sendall(b"POST /v2/tools/call HTTP/1.1\r\nContent-Length: 1048576\r\n\r\n")
        reader = FramedReader(client_sock, clock)
        head_1mib = reader.read_request_head(ample_deadline)
        assert head_1mib.content_length == 1_048_576

    with socket_pair() as (client_sock, server_sock):
        server_sock.sendall(b"POST /v2/tools/call HTTP/1.1\r\nContent-Length: 1048577\r\n\r\n")
        reader = FramedReader(client_sock, clock)
        with pytest.raises(HttpFramingError) as exc_body_req:
            reader.read_request_head(ample_deadline)
        assert exc_body_req.value.code is ErrorCode.INVALID_INPUT
        assert exc_body_req.value.http_status == 413

    with socket_pair() as (client_sock, server_sock):
        server_sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1048577\r\n\r\n")
        reader = FramedReader(client_sock, clock)
        with pytest.raises(HttpFramingError) as exc_body_resp:
            reader.read_response_head(ample_deadline)
        assert exc_body_resp.value.code is ErrorCode.INVALID_INPUT
        assert exc_body_resp.value.http_status == 413

    # 5a. Content-Length with 5,000 digits: '9' * 5000 raises HttpFramingError(413) on both request and response
    cl_9_5000 = b"Content-Length: " + (b"9" * 5000) + b"\r\n\r\n"
    with socket_pair() as (client_sock, server_sock):
        server_sock.sendall(b"POST /v2/tools/call HTTP/1.1\r\n" + cl_9_5000)
        reader = FramedReader(client_sock, clock)
        with pytest.raises(HttpFramingError) as exc_cl_req:
            reader.read_request_head(ample_deadline)
        assert exc_cl_req.value.code is ErrorCode.INVALID_INPUT
        assert exc_cl_req.value.http_status == 413

    with socket_pair() as (client_sock, server_sock):
        server_sock.sendall(b"HTTP/1.1 200 OK\r\n" + cl_9_5000)
        reader = FramedReader(client_sock, clock)
        with pytest.raises(HttpFramingError) as exc_cl_resp:
            reader.read_response_head(ample_deadline)
        assert exc_cl_resp.value.code is ErrorCode.INVALID_INPUT
        assert exc_cl_resp.value.http_status == 413

    # 5b. Content-Length: '0' * 5000 succeeds with content_length == 0
    cl_0_5000 = b"Content-Length: " + (b"0" * 5000) + b"\r\n\r\n"
    with socket_pair() as (client_sock, server_sock):
        server_sock.sendall(b"GET /v2/identity HTTP/1.1\r\n" + cl_0_5000)
        reader = FramedReader(client_sock, clock)
        head_cl0 = reader.read_request_head(ample_deadline)
        assert head_cl0.content_length == 0

    with socket_pair() as (client_sock, server_sock):
        server_sock.sendall(b"HTTP/1.1 200 OK\r\n" + cl_0_5000)
        reader = FramedReader(client_sock, clock)
        resp_cl0 = reader.read_response_head(ample_deadline)
        assert resp_cl0.content_length == 0

    # 5c. Content-Length: '0' * 5000 + '1048576' succeeds; '0' * 5000 + '1048577' raises 413
    cl_zeros_exact = b"Content-Length: " + (b"0" * 5000) + b"1048576\r\n\r\n"
    with socket_pair() as (client_sock, server_sock):
        server_sock.sendall(b"POST /v2/tools/call HTTP/1.1\r\n" + cl_zeros_exact)
        reader = FramedReader(client_sock, clock)
        head_cl_exact = reader.read_request_head(ample_deadline)
        assert head_cl_exact.content_length == 1_048_576

    with socket_pair() as (client_sock, server_sock):
        server_sock.sendall(b"HTTP/1.1 200 OK\r\n" + cl_zeros_exact)
        reader = FramedReader(client_sock, clock)
        resp_cl_exact = reader.read_response_head(ample_deadline)
        assert resp_cl_exact.content_length == 1_048_576

    cl_zeros_over = b"Content-Length: " + (b"0" * 5000) + b"1048577\r\n\r\n"
    with socket_pair() as (client_sock, server_sock):
        server_sock.sendall(b"POST /v2/tools/call HTTP/1.1\r\n" + cl_zeros_over)
        reader = FramedReader(client_sock, clock)
        with pytest.raises(HttpFramingError) as exc_cl_over_req:
            reader.read_request_head(ample_deadline)
        assert exc_cl_over_req.value.code is ErrorCode.INVALID_INPUT
        assert exc_cl_over_req.value.http_status == 413

    with socket_pair() as (client_sock, server_sock):
        server_sock.sendall(b"HTTP/1.1 200 OK\r\n" + cl_zeros_over)
        reader = FramedReader(client_sock, clock)
        with pytest.raises(HttpFramingError) as exc_cl_over_resp:
            reader.read_response_head(ample_deadline)
        assert exc_cl_over_resp.value.code is ErrorCode.INVALID_INPUT
        assert exc_cl_over_resp.value.http_status == 413

    with socket_pair() as (client_sock, _):
        reader = FramedReader(client_sock, clock)
        with pytest.raises(HttpFramingError) as exc_exact_max:
            reader.read_exact(MAX_BODY_BYTES + 1, ample_deadline)
        assert exc_exact_max.value.code is ErrorCode.INVALID_INPUT
        assert exc_exact_max.value.http_status == 413

        with pytest.raises(BrainError) as exc_exact_neg:
            reader.read_exact(-1, ample_deadline)
        assert exc_exact_neg.value.code is ErrorCode.INVALID_INPUT

        with pytest.raises(BrainError) as exc_exact_bool:
            reader.read_exact(True, ample_deadline)
        assert exc_exact_bool.value.code is ErrorCode.INVALID_INPUT

    # 6. Raw target preservation.
    for raw_target in ("//v2/identity", "http://127.0.0.1:8080/v2/identity", "/v2/tools/call?foo=bar"):
        with socket_pair() as (client_sock, server_sock):
            server_sock.sendall(f"GET {raw_target} HTTP/1.1\r\n\r\n".encode("ascii"))
            reader = FramedReader(client_sock, clock)
            head_target = reader.read_request_head(ample_deadline)
            assert head_target.target == raw_target

    # 7. Multi-value duplicate header retention and case-insensitive get_all.
    multi_headers = b"GET / HTTP/1.1\r\nX-Foo: alpha\r\nX-Bar: only\r\nx-foo: beta\r\nX-FOO: gamma\r\n\r\n"
    with socket_pair() as (client_sock, server_sock):
        server_sock.sendall(multi_headers)
        reader = FramedReader(client_sock, clock)
        head_multi = reader.read_request_head(ample_deadline)
        assert len(head_multi.headers) == 4
        assert head_multi.get_all("X-Foo") == ("alpha", "beta", "gamma")
        assert head_multi.get_all("x-foo") == ("alpha", "beta", "gamma")
        assert head_multi.get_all("X-Bar") == ("only",)
        assert head_multi.get_all("X-Missing") == ()

    resp_multi = b"HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nset-cookie: b=2\r\n\r\n"
    with socket_pair() as (client_sock, server_sock):
        server_sock.sendall(resp_multi)
        reader = FramedReader(client_sock, clock)
        resp_m = reader.read_response_head(ample_deadline)
        assert resp_m.get_all("Set-Cookie") == ("a=1", "b=2")
        assert resp_m.get_all("set-cookie") == ("a=1", "b=2")

    # 8. Clean 0-byte EOF vs partial-line EOF.
    with socket_pair() as (client_sock, server_sock):
        server_sock.close()
        reader = FramedReader(client_sock, clock)
        with pytest.raises(HttpFramingError) as exc_clean_req:
            reader.read_request_head(ample_deadline)
        assert exc_clean_req.value.code is ErrorCode.INVALID_INPUT
        assert exc_clean_req.value.http_status == 400
        assert exc_clean_req.value.empty_eof is True

    with socket_pair() as (client_sock, server_sock):
        server_sock.close()
        reader = FramedReader(client_sock, clock)
        with pytest.raises(HttpFramingError) as exc_clean_resp:
            reader.read_response_head(ample_deadline)
        assert exc_clean_resp.value.code is ErrorCode.INVALID_INPUT
        assert exc_clean_resp.value.http_status == 400
        assert exc_clean_resp.value.empty_eof is True

    with socket_pair() as (client_sock, server_sock):
        server_sock.sendall(b"GET /")
        server_sock.close()
        reader = FramedReader(client_sock, clock)
        with pytest.raises(HttpFramingError) as exc_partial_req:
            reader.read_request_head(ample_deadline)
        assert exc_partial_req.value.code is ErrorCode.INVALID_INPUT
        assert exc_partial_req.value.http_status == 400
        assert exc_partial_req.value.empty_eof is False

    with socket_pair() as (client_sock, server_sock):
        server_sock.sendall(b"HTTP/1.1 200")
        server_sock.close()
        reader = FramedReader(client_sock, clock)
        with pytest.raises(HttpFramingError) as exc_partial_resp:
            reader.read_response_head(ample_deadline)
        assert exc_partial_resp.value.code is ErrorCode.INVALID_INPUT
        assert exc_partial_resp.value.http_status == 400
        assert exc_partial_resp.value.empty_eof is False


def test_malformed_http_corpus_is_refused() -> None:
    """Fixed-seed corpus and explicit RFC 9110 / RFC 9112 violations are rejected with INVALID_INPUT."""
    clock = FakeClock(1_000_000_000)
    ample_deadline = clock.now_ns + 10_000_000_000

    explicit_cases: list[tuple[bytes, bool]] = [
        # (payload, is_request)
        # Duplicate Content-Length
        (b"POST / HTTP/1.1\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\ntest", True),
        (b"POST / HTTP/1.1\r\ncontent-length: 4\r\nCONTENT-LENGTH: 4\r\n\r\ntest", True),
        (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\ncontent-length: 2\r\n\r\nok", False),
        # Negative, signed, comma, non-ASCII digits, internal whitespace, empty
        (b"POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n", True),
        (b"POST / HTTP/1.1\r\nContent-Length: +1\r\n\r\n", True),
        (b"POST / HTTP/1.1\r\nContent-Length: +4\r\n\r\ntest", True),
        (b"POST / HTTP/1.1\r\nContent-Length: 4, 4\r\n\r\n", True),
        (b"POST / HTTP/1.1\r\nContent-Length: \xe0\xa5\xab\r\n\r\n", True),  # Devanagari digit 5
        (b"POST / HTTP/1.1\r\nContent-Length: \xc2\xb2\r\n\r\n", True),  # Superscript 2
        (b"POST / HTTP/1.1\r\nContent-Length: 1 2\r\n\r\n", True),
        (b"POST / HTTP/1.1\r\nContent-Length:\r\n\r\n", True),
        (b"POST / HTTP/1.1\r\nContent-Length:   \r\n\r\n", True),
        # obs-fold continuation lines
        (b"GET / HTTP/1.1\r\nX-Header: val\r\n continuation\r\n\r\n", True),
        (b"GET / HTTP/1.1\r\nX-Header: val\r\n\tcontinuation\r\n\r\n", True),
        (b"HTTP/1.1 200 OK\r\nX-Header: val\r\n continuation\r\n\r\n", False),
        # Transfer-Encoding forbidden
        (b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n", True),
        (b"POST / HTTP/1.1\r\ntransfer-encoding: gzip, chunked\r\n\r\n", True),
        (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", False),
        (b"HTTP/1.1 200 OK\r\nTRANSFER-ENCODING: identity\r\n\r\n", False),
        # Bare \n without \r
        (b"GET / HTTP/1.1\nHost: localhost\r\n\r\n", True),
        (b"GET / HTTP/1.1\r\nHost: localhost\n\r\n", True),
        (b"HTTP/1.1 200 OK\nHost: localhost\r\n\r\n", False),
        # Bare \r inside line
        (b"GET / HTTP/1.1\r\nBad\rHeader: val\r\n\r\n", True),
        # Whitespace before colon
        (b"GET / HTTP/1.1\r\nBad-Header : val\r\n\r\n", True),
        (b"GET / HTTP/1.1\r\nBad-Header\t: val\r\n\r\n", True),
        (b"HTTP/1.1 200 OK\r\nBad-Header : val\r\n\r\n", False),
        # Invalid RFC 9110 tchar field name characters
        (b"GET / HTTP/1.1\r\nBad Header: val\r\n\r\n", True),
        (b"GET / HTTP/1.1\r\nBad@Header: val\r\n\r\n", True),
        (b"GET / HTTP/1.1\r\nBad(Header): val\r\n\r\n", True),
        # CTL bytes in header value
        (b"GET / HTTP/1.1\r\nX-Header: bad\x00val\r\n\r\n", True),
        (b"GET / HTTP/1.1\r\nX-Header: bad\x07val\r\n\r\n", True),
        (b"GET / HTTP/1.1\r\nX-Header: bad\x1fval\r\n\r\n", True),
        (b"GET / HTTP/1.1\r\nX-Header: bad\x7fval\r\n\r\n", True),
        # HTTP/1.0 or malformed versions / statuses
        (b"GET / HTTP/1.0\r\n\r\n", True),
        (b"GET / HTTP/2.0\r\n\r\n", True),
        (b"GET / BOGUS\r\n\r\n", True),
        (b"HTTP/1.0 200 OK\r\n\r\n", False),
        (b"HTTP/1.1 99 OK\r\n\r\n", False),
        (b"HTTP/1.1 1000 OK\r\n\r\n", False),
        (b"HTTP/1.1 abc OK\r\n\r\n", False),
    ]

    for payload, is_request in explicit_cases:
        with socket_pair() as (client_sock, server_sock):
            server_sock.sendall(payload)
            reader = FramedReader(client_sock, clock)
            with pytest.raises(HttpFramingError) as exc_info:
                if is_request:
                    reader.read_request_head(ample_deadline)
                else:
                    reader.read_response_head(ample_deadline)
            assert exc_info.value.code is ErrorCode.INVALID_INPUT
            assert exc_info.value.http_status == 400

    # Expect: 100-continue must be rejected with 0 bytes emitted on socket.
    expect_payload = b"POST / HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 4\r\n\r\ntest"
    with socket_pair() as (client_sock, server_sock):
        server_sock.sendall(expect_payload)
        reader = FramedReader(client_sock, clock)
        with pytest.raises(HttpFramingError) as exc_expect:
            reader.read_request_head(ample_deadline)
        assert exc_expect.value.code is ErrorCode.INVALID_INPUT
        assert exc_expect.value.http_status == 400
        # Affirm zero response bytes were emitted on socket.
        server_sock.settimeout(0.02)
        try:
            recv_bytes = server_sock.recv(1024)
            assert recv_bytes == b""
        except (TimeoutError, BlockingIOError):
            pass

    # Truncated body (EOF before Content-Length).
    with socket_pair() as (client_sock, server_sock):
        server_sock.sendall(b"POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\n12345")
        server_sock.close()
        reader = FramedReader(client_sock, clock)
        head_trunc = reader.read_request_head(ample_deadline)
        assert head_trunc.content_length == 10
        with pytest.raises(HttpFramingError) as exc_trunc:
            reader.read_exact(10, ample_deadline)
        assert exc_trunc.value.code is ErrorCode.INVALID_INPUT
        assert exc_trunc.value.empty_eof is False

    # Mid-line EOF on request line and header line.
    for partial_frame in (b"GET / HTTP/1.1", b"GET / HTTP/1.1\r\nHost: local"):
        with socket_pair() as (client_sock, server_sock):
            server_sock.sendall(partial_frame)
            server_sock.close()
            reader = FramedReader(client_sock, clock)
            with pytest.raises(HttpFramingError) as exc_mid:
                reader.read_request_head(ample_deadline)
            assert exc_mid.value.code is ErrorCode.INVALID_INPUT
            assert exc_mid.value.empty_eof is False

    # Deterministic pseudo-random fuzz corpus (zero external fuzz dependencies).
    rng = random.Random(20261110)
    base_template = b"GET /v2/identity HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n"
    for _ in range(60):
        mut_kind = rng.randint(0, 5)
        raw = bytearray(base_template)
        if mut_kind == 0:  # Inject CTL
            idx = rng.randint(0, len(raw) - 1)
            raw.insert(idx, rng.choice([0, 1, 7, 11, 31, 127]))
        elif mut_kind == 1:  # Corrupt CRLF
            raw = bytearray(bytes(raw).replace(b"\r\n", b"\n", 1))
        elif mut_kind == 2:  # Whitespace before colon
            raw = bytearray(bytes(raw).replace(b":", b" :", 1))
        elif mut_kind == 3:  # Corrupt HTTP version
            raw = bytearray(bytes(raw).replace(b"HTTP/1.1", b"HTTP/1.0"))
        elif mut_kind == 4:  # Duplicate invalid Content-Length
            raw = bytearray(b"Content-Length: bad\r\n" + bytes(raw))
        else:  # Truncate mid-stream
            cut = rng.randint(1, len(raw) - 3)
            raw = raw[:cut]

        with socket_pair() as (client_sock, server_sock):
            server_sock.sendall(bytes(raw))
            server_sock.close()
            reader = FramedReader(client_sock, clock)
            with pytest.raises(BrainError) as exc_fuzz:
                reader.read_request_head(ample_deadline)
            assert exc_fuzz.value.code is ErrorCode.INVALID_INPUT


def test_slow_header_and_body_share_absolute_deadline() -> None:
    """Fake monotonic clock verifies monotonically shrinking settimeout across slow chunks."""
    clock = FakeClock(1_000_000_000)
    start_ns = clock.now_ns
    shared_deadline_ns = start_ns + 1_500_000_000  # 1.5 s absolute budget

    # 1. Fake monotonic clock advancing per chunk where each chunk arrives under per-recv timeout.
    # 8 chunks x 200 ms = 1,600 ms > 1,500 ms shared deadline.
    chunks: list[bytes] = [
        b"POST /v2/tools/call ",
        b"HTTP/1.1\r\n",
        b"Host: 127.0.0.1:8080\r\n",
        b"Content-Type: text/plain\r\n",
        b"Content-Length: 10\r\n",
        b"\r\n",
        b"12345",
        b"67890",
    ]

    chunks_to_send = list(chunks)

    with tracking_socket_pair() as (track_sock, server_sock):

        def drip_recv(bufsize: int, flags: int = 0) -> bytes:
            if chunks_to_send:
                server_sock.sendall(chunks_to_send.pop(0))
                data = track_sock.raw_recv(bufsize, flags)
                clock.advance(200_000_000)  # advance 200 ms per chunk
                return data
            return b""

        track_sock.recv_hook = drip_recv

        # Verify drip hook delivers one chunk at a time before calling reader
        test_probe = track_sock.recv(1024)
        assert test_probe == chunks[0]
        assert clock.now_ns == start_ns + 200_000_000
        # Reset chunks_to_send and clock for the FramedReader test
        chunks_to_send = list(chunks)
        clock.set(start_ns)

        reader = FramedReader(track_sock, clock)
        with pytest.raises(HttpFramingError) as exc_slow:
            head = reader.read_request_head(shared_deadline_ns)
            assert head.content_length == 10
            reader.read_exact(10, shared_deadline_ns)

        assert exc_slow.value.code is ErrorCode.DEADLINE_EXCEEDED
        assert exc_slow.value.http_status == 408

        # Verify settimeout shrank monotonically rather than resetting to 1.5s per chunk.
        assert len(track_sock.recorded_timeouts) >= 2
        for i in range(len(track_sock.recorded_timeouts) - 1):
            assert track_sock.recorded_timeouts[i] >= track_sock.recorded_timeouts[i + 1]


def test_slow_header_exact_deadline_boundary_cases() -> None:
    """Exact now == deadline_ns boundary tested in all 3 required cases."""
    clock = FakeClock(1_000_000_000)

    # Case (a): Bytes already prefetched inside FramedReader's internal buffer before read.
    with socket_pair() as (client_sock, server_sock):
        server_sock.sendall(b"0123456789")
        clock.set(1_000_000_000)
        reader = FramedReader(client_sock, clock)
        # Prefetch 5 bytes; remaining 5 bytes are now buffered in reader._buf.
        first_5 = reader.read_exact(5, clock.now_ns + 10_000_000_000)
        assert first_5 == b"01234"

        # Advance clock to exact deadline.
        exact_deadline = clock.now_ns + 500_000_000
        clock.set(exact_deadline)
        with pytest.raises(HttpFramingError) as exc_pref_exact:
            reader.read_exact(5, exact_deadline)
        assert exc_pref_exact.value.code is ErrorCode.DEADLINE_EXCEEDED
        assert exc_pref_exact.value.http_status == 408

    with socket_pair() as (client_sock, server_sock):
        server_sock.sendall(b"GET /v2/identity HTTP/1.1\r\n\r\n")
        clock.set(1_000_000_000)
        reader = FramedReader(client_sock, clock)
        assert reader.has_pipelined_bytes(clock.now_ns + 10_000_000_000) is True

        exact_dl = clock.now_ns + 100_000_000
        clock.set(exact_dl)
        with pytest.raises(HttpFramingError) as exc_req_buffered:
            reader.read_request_head(exact_dl)
        assert exc_req_buffered.value.code is ErrorCode.DEADLINE_EXCEEDED

    with socket_pair() as (client_sock, server_sock):
        server_sock.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
        clock.set(1_000_000_000)
        reader = FramedReader(client_sock, clock)
        assert reader.has_pipelined_bytes(clock.now_ns + 10_000_000_000) is True

        exact_dl = clock.now_ns + 100_000_000
        clock.set(exact_dl)
        with pytest.raises(HttpFramingError) as exc_resp_buffered:
            reader.read_response_head(exact_dl)
        assert exc_resp_buffered.value.code is ErrorCode.DEADLINE_EXCEEDED

    # Case (b): Clock reaching deadline_ns immediately after sock.recv delivers the final byte.
    with tracking_socket_pair() as (track_client, server_sock):
        server_sock.sendall(b"GET / HTTP/1.1\r\n\r\n")
        clock.set(1_000_000_000)
        target_dl = clock.now_ns + 500_000_000

        def recv_hit_deadline(bufsize: int, flags: int = 0) -> bytes:
            data = track_client.raw_recv(bufsize, flags)
            clock.set(target_dl)  # reach exact deadline immediately after recv
            return data

        track_client.recv_hook = recv_hit_deadline
        # Self-verify hook functionality
        probe_chunk = track_client.recv(4)
        assert probe_chunk == b"GET "
        assert clock.now_ns == target_dl

        # Reset clock for FramedReader invocation
        clock.set(1_000_000_000)
        reader = FramedReader(track_client, clock)
        with pytest.raises(HttpFramingError) as exc_post_recv:
            reader.read_request_head(target_dl)
        assert exc_post_recv.value.code is ErrorCode.DEADLINE_EXCEEDED
        assert exc_post_recv.value.http_status == 408

    # Case (c): Clock reaching deadline_ns immediately after final sock.send in write_all.
    with tracking_socket_pair() as (track_client, server_sock):
        clock.set(1_000_000_000)
        target_dl = clock.now_ns + 500_000_000

        def send_hit_deadline(data: bytes, flags: int = 0) -> int:
            sent = track_client.raw_send(data, flags)
            clock.set(target_dl)  # reach exact deadline immediately after send
            return sent

        track_client.send_hook = send_hit_deadline
        probe_sent = track_client.send(b"ping")
        assert probe_sent == 4
        assert clock.now_ns == target_dl

        # Reset clock for write_all invocation
        clock.set(1_000_000_000)
        with pytest.raises(HttpFramingError) as exc_post_send:
            write_all(track_client, b"HTTP/1.1 200 OK\r\n\r\n", target_dl, clock)
        assert exc_post_send.value.code is ErrorCode.DEADLINE_EXCEEDED
        assert exc_post_send.value.http_status == 408

    # Also verify write_all at entry when now >= deadline_ns.
    with socket_pair() as (client_sock, _):
        clock.set(2_000_000_000)
        with pytest.raises(HttpFramingError) as exc_write_entry:
            write_all(client_sock, b"", 2_000_000_000, clock)
        assert exc_write_entry.value.code is ErrorCode.DEADLINE_EXCEEDED


def test_slow_header_pipelined_bytes_and_tls(inc2_tls_material: SampleTlsMaterial) -> None:
    """Shared buffer across two sequential requests and has_pipelined_bytes over raw and TLS sockets."""
    clock = FakeClock(1_000_000_000)

    # (i) Real TLS socket with unread SSLSocket.pending() / OS-readable bytes (exercises tls_pair handshake).
    with tls_pair(inc2_tls_material) as (client_ssl, server_ssl):
        # Self-verify live TLS communication
        server_ssl.sendall(b"TLS_READY")
        assert client_ssl.recv(9) == b"TLS_READY"

        orig_to = client_ssl.gettimeout()
        clock.set(1_000_000_000)
        tls_reader = FramedReader(client_ssl, clock)
        deadline_ns = clock.now_ns + 10_000_000_000
        assert tls_reader.has_pipelined_bytes(deadline_ns) is False
        server_ssl.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        # sendall acknowledges the sending socket, not receipt of application bytes. This probe is
        # deliberately nonblocking, including when a TLS control record precedes the application record.
        wall_deadline_ns = time.monotonic_ns() + deadline_ns - clock.now_ns
        while not tls_reader.has_pipelined_bytes(deadline_ns):
            assert client_ssl.gettimeout() == orig_to
            assert time.monotonic_ns() < wall_deadline_ns, "sent TLS response did not become readable"
            time.sleep(0.001)
        assert tls_reader.has_pipelined_bytes(deadline_ns) is True
        # Verify original timeout was restored.
        assert client_ssl.gettimeout() == orig_to
        # Verify bytes are preserved and readable.
        tls_resp = tls_reader.read_response_head(clock.now_ns + 10_000_000_000)
        assert tls_resp.status == 200

    # (ii) Prefetched bytes already in FramedReader buffer -> True.
    req1 = b"GET /v2/identity HTTP/1.1\r\n\r\n"
    req2 = b"POST /v2/tools/call HTTP/1.1\r\nContent-Length: 0\r\n\r\n"
    with socket_pair() as (client_sock, server_sock):
        server_sock.sendall(req1 + req2)
        clock.set(1_000_000_000)
        reader = FramedReader(client_sock, clock)
        head1 = reader.read_request_head(clock.now_ns + 10_000_000_000)
        assert head1.target == "/v2/identity"
        assert reader.has_pipelined_bytes(clock.now_ns + 10_000_000_000) is True
        head2 = reader.read_request_head(clock.now_ns + 10_000_000_000)
        assert head2.target == "/v2/tools/call"

    # (iii) Clean peer half-close -> False.
    with socket_pair() as (client_sock, server_sock):
        server_sock.sendall(b"GET / HTTP/1.1\r\n\r\n")
        clock.set(1_000_000_000)
        reader = FramedReader(client_sock, clock)
        reader.read_request_head(clock.now_ns + 10_000_000_000)
        server_sock.shutdown(socket.SHUT_WR)
        assert reader.has_pipelined_bytes(clock.now_ns + 10_000_000_000) is False

    # (iv) has_pipelined_bytes with now >= deadline_ns -> DEADLINE_EXCEEDED.
    with socket_pair() as (client_sock, _):
        clock.set(2_000_000_000)
        reader = FramedReader(client_sock, clock)
        with pytest.raises(HttpFramingError) as exc_pipe_dl:
            reader.has_pipelined_bytes(2_000_000_000)
        assert exc_pipe_dl.value.code is ErrorCode.DEADLINE_EXCEEDED


def test_wire_call_preserves_scope_and_arguments() -> None:
    """KernelHttpCall wire codecs preserve raw arguments, validate scope, and enforce envelope invariants."""
    assert IDENTITY_PATH == "/v2/identity"
    assert TOOL_CALL_PATH == "/v2/tools/call"
    assert HEADER_STORE_ID == "X-Store-Id"
    assert HEADER_WRITER_EPOCH == "X-Writer-Epoch"
    assert HEADER_INSTANCE_ID == "X-Superbrain-Instance"
    assert MAX_CORRELATION_ID_BYTES == 128

    # 1. Round-trip without scope and with unnormalized arguments.
    cmd_no_scope = ToolCommand(
        tool="get_health",
        arguments={"probe": "deep", "unnormalized_extra": 123},
        token="token-abc",
        selected_scope=None,
        correlation_id="corr-123",
    )
    enc_no_scope = encode_call(cmd_no_scope)
    dec_no_scope = decode_call(enc_no_scope, token="token-abc")
    assert dec_no_scope.tool == "get_health"
    assert dec_no_scope.arguments == {"probe": "deep", "unnormalized_extra": 123}
    assert dec_no_scope.token == "token-abc"
    assert dec_no_scope.selected_scope is None
    assert dec_no_scope.correlation_id == "corr-123"

    # 2. Round-trip with Scope and correlation_id=None.
    cmd_with_scope = ToolCommand(
        tool="prepare_task",
        arguments={"raw_field": ["a", "b"], "nested": {"k": "v"}},
        token="token-xyz",
        selected_scope=Scope(repo_id="repo-01", checkout_id="chk-01"),
        correlation_id=None,
    )
    enc_with_scope = encode_call(cmd_with_scope)
    dec_with_scope = decode_call(enc_with_scope, token="token-xyz")
    assert dec_with_scope.tool == "prepare_task"
    assert dec_with_scope.arguments == {"raw_field": ["a", "b"], "nested": {"k": "v"}}
    assert dec_with_scope.token == "token-xyz"
    assert dec_with_scope.selected_scope == Scope(repo_id="repo-01", checkout_id="chk-01")
    assert dec_with_scope.correlation_id is None

    # 3. All 8 tools in EXPECTED_TOOL_ORDER accepted.
    for tool_name in EXPECTED_TOOL_ORDER:
        cmd_tool = ToolCommand(tool=tool_name, arguments={}, token="tok", selected_scope=None, correlation_id=None)
        dec_tool = decode_call(encode_call(cmd_tool), token="tok")
        assert dec_tool.tool == tool_name

    # 4. Invalid decode_call payloads rejected with INVALID_INPUT.
    # Missing required keys
    with pytest.raises(BrainError) as exc_missing_tool:
        decode_call(canonical_json({"arguments": {}, "correlation_id": None, "selected_scope": None}), token="t")
    assert exc_missing_tool.value.code is ErrorCode.INVALID_INPUT

    with pytest.raises(BrainError) as exc_missing_args:
        decode_call(canonical_json({"tool": "get_health", "correlation_id": None, "selected_scope": None}), token="t")
    assert exc_missing_args.value.code is ErrorCode.INVALID_INPUT

    with pytest.raises(BrainError) as exc_missing_cid:
        decode_call(canonical_json({"tool": "get_health", "arguments": {}, "selected_scope": None}), token="t")
    assert exc_missing_cid.value.code is ErrorCode.INVALID_INPUT

    with pytest.raises(BrainError) as exc_missing_scope:
        decode_call(canonical_json({"tool": "get_health", "arguments": {}, "correlation_id": None}), token="t")
    assert exc_missing_scope.value.code is ErrorCode.INVALID_INPUT

    # Extra keys
    with pytest.raises(BrainError) as exc_extra_key:
        decode_call(
            canonical_json(
                {"tool": "get_health", "arguments": {}, "correlation_id": None, "selected_scope": None, "extra": 1}
            ),
            token="t",
        )
    assert exc_extra_key.value.code is ErrorCode.INVALID_INPUT

    # Unknown tool
    with pytest.raises(BrainError) as exc_bad_tool:
        decode_call(
            canonical_json({"tool": "bad_tool", "arguments": {}, "correlation_id": None, "selected_scope": None}),
            token="t",
        )
    assert exc_bad_tool.value.code is ErrorCode.INVALID_INPUT

    # Non-object arguments
    bad_args_list: list[Any] = [[], "str", 123, None, True]
    for bad_args in bad_args_list:
        with pytest.raises(BrainError) as exc_bad_args:
            decode_call(
                canonical_json(
                    {"tool": "get_health", "arguments": bad_args, "correlation_id": None, "selected_scope": None}
                ),
                token="t",
            )
        assert exc_bad_args.value.code is ErrorCode.INVALID_INPUT

    # Duplicate JSON keys
    dup_json = b'{"tool":"get_health","tool":"get_health","arguments":{},"correlation_id":null,"selected_scope":null}'
    with pytest.raises(BrainError) as exc_dup_keys:
        decode_call(dup_json, token="t")
    assert exc_dup_keys.value.code is ErrorCode.INVALID_INPUT

    # correlation_id edge cases: empty string, > 128 bytes, unpaired surrogate
    with pytest.raises(BrainError) as exc_empty_cid:
        decode_call(
            canonical_json({"tool": "get_health", "arguments": {}, "correlation_id": "", "selected_scope": None}),
            token="t",
        )
    assert exc_empty_cid.value.code is ErrorCode.INVALID_INPUT

    # 128 ASCII chars is accepted
    cid_128 = "a" * 128
    cmd_128 = ToolCommand(tool="get_health", arguments={}, token="t", selected_scope=None, correlation_id=cid_128)
    assert decode_call(encode_call(cmd_128), token="t").correlation_id == cid_128

    # 129 ASCII chars is rejected
    with pytest.raises(BrainError) as exc_cid_129:
        decode_call(
            canonical_json(
                {"tool": "get_health", "arguments": {}, "correlation_id": "a" * 129, "selected_scope": None}
            ),
            token="t",
        )
    assert exc_cid_129.value.code is ErrorCode.INVALID_INPUT

    # 43 x 3-byte UTF-8 + 1 byte = 130 bytes (44 chars) is rejected
    cid_130_bytes = ("\u20ac" * 43) + "a"
    assert len(cid_130_bytes.encode("utf-8")) == 130
    with pytest.raises(BrainError) as exc_cid_utf8:
        decode_call(
            canonical_json(
                {"tool": "get_health", "arguments": {}, "correlation_id": cid_130_bytes, "selected_scope": None}
            ),
            token="t",
        )
    assert exc_cid_utf8.value.code is ErrorCode.INVALID_INPUT

    # Unpaired UTF-16 surrogate
    unpaired_json = b'{"tool":"get_health","arguments":{},"correlation_id":"\\ud800","selected_scope":null}'
    with pytest.raises(BrainError) as exc_unpaired:
        decode_call(unpaired_json, token="t")
    assert exc_unpaired.value.code is ErrorCode.INVALID_INPUT

    # selected_scope edge cases: non-dict, missing/extra key, invalid OpaqueId
    bad_scope_list: list[Any] = [
        "str",
        123,
        [],
        {"repo_id": "r1"},  # missing checkout_id
        {"checkout_id": "c1"},  # missing repo_id
        {"repo_id": "r1", "checkout_id": "c1", "extra": 1},  # extra key
        {"repo_id": "", "checkout_id": "c1"},  # empty opaque ID
        {"repo_id": "r 1", "checkout_id": "c1"},  # space in opaque ID
        {"repo_id": "r\n1", "checkout_id": "c1"},  # newline in opaque ID
    ]
    for bad_scope in bad_scope_list:
        with pytest.raises(BrainError) as exc_scope:
            decode_call(
                canonical_json(
                    {"tool": "get_health", "arguments": {}, "correlation_id": None, "selected_scope": bad_scope}
                ),
                token="t",
            )
        assert exc_scope.value.code is ErrorCode.INVALID_INPUT

    # 5. decode_result accepts valid v2 CallResult and rejects invalid envelopes.
    valid_ok = encode_envelope({"ok": True, "data": {"health": "healthy"}})
    res_ok = decode_result(valid_ok)
    assert res_ok == {"ok": True, "data": {"health": "healthy"}}

    valid_err = encode_envelope({"ok": False, "error": {"code": "invalid_input", "message": "invalid input"}})
    res_err = decode_result(valid_err)
    assert res_err == {"ok": False, "error": {"code": "invalid_input", "message": "invalid input"}}

    for bad_result in (
        canonical_json({"ok": True, "data": {}, "extra": 1}),
        canonical_json({"ok": False, "error": {"code": "invalid_input", "message": "sqlite error leaked details"}}),
        canonical_json({"ok": False, "error": {"code": "unknown_code", "message": "invalid input"}}),
        canonical_json({"ok": 1, "data": {}}),
        canonical_json({"ok": True}),
        canonical_json({"ok": False}),
        b"[]",
    ):
        with pytest.raises(BrainError) as exc_res:
            decode_result(bad_result)
        assert exc_res.value.code is ErrorCode.INVALID_INPUT

    # 6. encode_identity_response / decode_identity_response round-trip and validation.
    ident = Identity(store_id="store-alpha", writer_epoch=42, instance_id="inst-beta")
    enc_ident = encode_identity_response(ident)
    dec_ident, contract = decode_identity_response(enc_ident)
    assert dec_ident == ident
    assert contract == ENDPOINT_CONTRACT

    # Reject missing/extra fields, bool writer_epoch, writer_epoch <= 0, wrong contract.
    for bad_ident_payload in (
        canonical_json({"store_id": "s1", "writer_epoch": 1, "contract": "mcp-tools-v2"}),  # missing instance_id
        canonical_json(
            {"store_id": "s1", "writer_epoch": 1, "instance_id": "i1", "contract": "mcp-tools-v2", "extra": 1}
        ),
        canonical_json({"store_id": "s1", "writer_epoch": True, "instance_id": "i1", "contract": "mcp-tools-v2"}),
        canonical_json({"store_id": "s1", "writer_epoch": 0, "instance_id": "i1", "contract": "mcp-tools-v2"}),
        canonical_json({"store_id": "s1", "writer_epoch": -5, "instance_id": "i1", "contract": "mcp-tools-v2"}),
        canonical_json({"store_id": "s1", "writer_epoch": 1, "instance_id": "i1", "contract": "mcp-v1"}),
        canonical_json({"store_id": "", "writer_epoch": 1, "instance_id": "i1", "contract": "mcp-tools-v2"}),
        canonical_json({"store_id": "s1", "writer_epoch": 1, "instance_id": "bad inst", "contract": "mcp-tools-v2"}),
    ):
        with pytest.raises(BrainError) as exc_ident:
            decode_identity_response(bad_ident_payload)
        assert exc_ident.value.code is ErrorCode.INVALID_INPUT


def test_loopback_server_and_client_keep_separate_handshake_connect_budgets() -> None:
    """D5: server handshake cap 1s; client TLS + identity aggregate cap 2s."""
    assert SERVER_HANDSHAKE_BUDGET_NS == 1_000_000_000
    assert CLIENT_CONNECT_BUDGET_NS == 2_000_000_000


@pytest.mark.parametrize(
    ("elapsed_ns", "expected_remaining_ns"),
    (
        (0, 1_000_000_000),
        (500_000_000, 500_000_000),
        (999_999_999, 1),
        (1_000_000_000, 0),
        (1_250_000_000, 0),
        (2_000_000_000, 0),
    ),
)
def test_loopback_server_handshake_timeout_uses_one_second_absolute_cap(
    elapsed_ns: int,
    expected_remaining_ns: int,
) -> None:
    server = object.__new__(LoopbackServer)
    clock = FakeClock(10_000_000_000 + elapsed_ns)
    server._monotonic_ns = clock
    server._lock = threading.Lock()
    server._quiesced = False
    server._stop_deadline = None
    # Match the actual worker's accept timestamp + server phase budget. The
    # expected values are independently specified above, not derived from it.
    handshake_deadline = 10_000_000_000 + SERVER_HANDSHAKE_BUDGET_NS
    assert server._handshake_timeout_s(handshake_deadline) == expected_remaining_ns / 1_000_000_000


@pytest.mark.parametrize("stop_remaining_s", (0.05, -0.05))
def test_loopback_server_handshake_timeout_keeps_earlier_stop_cutoff(
    monkeypatch: pytest.MonkeyPatch,
    stop_remaining_s: float,
) -> None:
    server = object.__new__(LoopbackServer)
    server._monotonic_ns = FakeClock(10_000_000_000)
    server._lock = threading.Lock()
    server._quiesced = True
    server._stop_deadline = 100.0 + stop_remaining_s
    monkeypatch.setattr(loopback_server_module, "time", SimpleNamespace(perf_counter=lambda: 100.0))
    assert server._handshake_timeout_s(11_000_000_000) == pytest.approx(max(0.0, stop_remaining_s))


def test_loopback_server_reuses_prevalidated_ssl_context(inc2_tls_material: SampleTlsMaterial) -> None:
    """LoopbackServer must keep the prevalidated SSLContext passed from build_server_ssl_context."""
    cfg = DaemonConfig(
        version=1,
        data_root=inc2_tls_material.directory,
        expected_store_id="store-tls-reuse",
        cert_path=inc2_tls_material.leaf_cert_path,
        key_path=inc2_tls_material.leaf_key_path,
    )
    ssl_ctx = build_server_ssl_context(cfg)
    assert isinstance(ssl_ctx, ssl.SSLContext)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((ENDPOINT_HOST, 0))
        sock.listen(1)
        port = int(sock.getsockname()[1])
        ep = Endpoint(
            version=ENDPOINT_VERSION,
            host=ENDPOINT_HOST,
            port=port,
            store_id="store-tls-reuse",
            writer_epoch=1,
            instance_id="inst-tls-reuse",
        )
        ready = Ready(
            endpoint=ep,
            identity=ep.identity,
            tls_not_after=dt.datetime.now(dt.UTC) + dt.timedelta(days=1),
            leaf_cert_sha256=inc2_tls_material.leaf_cert_sha256,
        )
        owner = OwnerLoop(lambda *_args: cast(OwnerSession, object()))
        server = LoopbackServer(
            listener=sock,
            ssl_context=ssl_ctx,
            ready=ready,
            owner=owner,
            monotonic_ns=time.monotonic_ns,
            stop_event=threading.Event(),
        )
        assert server._ssl_context is ssl_ctx
    finally:
        sock.close()
