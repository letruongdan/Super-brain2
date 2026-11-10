"""Stage A regressions for SP1 Increment 2 Task 6b.2 (Pin-before-secret TLS loopback client).

Covers all mandatory invariants from interface-spec.md Section 3 and task-6b-2-brief.md:
1. test_pin_checked_before_any_http:
   Leaf certificate hash and TLS trust verification occur before any HTTP bytes are emitted.
2. test_wrong_identity_receives_only_probe:
   Direct pre-connect store guard and identity probe verification with zero token leakage.
3. test_connection_budget_includes_slow_handshake_without_consuming_tool_budget:
   Separate connect and tool budgets with independent fake monotonic clock tracking.
4. test_response_loss_after_post_is_transport_uncertain:
   Safe request_may_have_run classification once POST transmission begins.
5. test_lost_pinned_socket_cannot_send_to_rebound_port:
   Dead pinned sockets fail locally without re-establishing to rebound ports.
6. test_pinned_connection_sends_at_most_one_post:
   Single-use socket ownership, concurrent caller isolation, and token header safety.
"""

from __future__ import annotations

import datetime as dt
import errno
import ipaddress
import json
import socket
import ssl
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from superbrain.cli_api.loopback import (
    LoopbackClient,
    LoopbackTarget,
    LoopbackTransportError,
    PinnedConnection,
)
from superbrain.core.errors import SAFE_WIRE_MESSAGES_BY_CODE, BrainError, ErrorCode
from superbrain.core.kernel import Endpoint, ToolCommand
from superbrain.core.wire import encode_envelope
from tests.support.inc2_fixture import SampleTlsMaterial

# -----------------------------------------------------------------------------
# Fake Monotonic Clock for deterministic budget testing (zero time.sleep)
# -----------------------------------------------------------------------------


class FakeClock:
    """Thread-safe controllable clock for testing nano-second deadlines."""

    def __init__(self, initial_ns: int = 10_000_000_000) -> None:
        self._current_ns = initial_ns
        self._lock = threading.Lock()

    def now_ns(self) -> int:
        with self._lock:
            return self._current_ns

    def advance_ns(self, delta_ns: int) -> int:
        with self._lock:
            self._current_ns += delta_ns
            return self._current_ns

    def advance_ms(self, delta_ms: int) -> int:
        return self.advance_ns(delta_ms * 1_000_000)


# -----------------------------------------------------------------------------
# Certificate Generation Helpers for Negative TLS Handshake Tests
# -----------------------------------------------------------------------------


def make_wrong_ca_server_ctx(tmp_dir: Path) -> ssl.SSLContext:
    """Create a server SSLContext using a certificate signed by an untrusted CA."""
    now = dt.datetime.now(dt.UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "untrusted-test-ca")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(1)
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(2)
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    tmp_dir.mkdir(parents=True, exist_ok=True)
    cert_path = tmp_dir / "wrong_ca_leaf.pem"
    key_path = tmp_dir / "wrong_ca_key.pem"
    cert_path.write_bytes(leaf_cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert_path), str(key_path))
    return ctx


def make_missing_ip_san_server_ctx(tls: SampleTlsMaterial, tmp_dir: Path) -> ssl.SSLContext:
    """Create a server SSLContext signed by valid CA but missing IP SAN (DNS localhost only)."""
    ca_key = serialization.load_pem_private_key(tls.ca_key_path.read_bytes(), password=None)
    assert isinstance(ca_key, ec.EllipticCurvePrivateKey)
    ca_cert = x509.load_pem_x509_certificate(tls.ca_cert_path.read_bytes())
    now = dt.datetime.now(dt.UTC)

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    tmp_dir.mkdir(parents=True, exist_ok=True)
    cert_path = tmp_dir / "missing_san_leaf.pem"
    key_path = tmp_dir / "missing_san_key.pem"
    cert_path.write_bytes(leaf_cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert_path), str(key_path))
    return ctx


def make_expired_leaf_server_ctx(tls: SampleTlsMaterial, tmp_dir: Path) -> ssl.SSLContext:
    """Create a server SSLContext signed by valid CA with valid IP SAN but expired validity dates."""
    ca_key = serialization.load_pem_private_key(tls.ca_key_path.read_bytes(), password=None)
    assert isinstance(ca_key, ec.EllipticCurvePrivateKey)
    ca_cert = x509.load_pem_x509_certificate(tls.ca_cert_path.read_bytes())
    now = dt.datetime.now(dt.UTC)

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=10))
        .not_valid_after(now - dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    tmp_dir.mkdir(parents=True, exist_ok=True)
    cert_path = tmp_dir / "expired_leaf.pem"
    key_path = tmp_dir / "expired_key.pem"
    cert_path.write_bytes(leaf_cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert_path), str(key_path))
    return ctx


# -----------------------------------------------------------------------------
# Mock TLS Server with Decrypted Traffic Inspection & Protocol Hooks
# -----------------------------------------------------------------------------


class MockHttpRequest:
    """Parsed representation of an incoming HTTP request on the mock server."""

    def __init__(
        self,
        method: str,
        path: str,
        version: str,
        headers: dict[str, str],
        body: bytes,
    ) -> None:
        self.method = method
        self.path = path
        self.version = version
        self.headers = headers
        self.body = body


class MockTlsServer:
    """Mock TLS listener running on 127.0.0.1 with byte counters and request inspection."""

    def __init__(
        self,
        ssl_ctx: ssl.SSLContext,
        store_id: str = "store-1",
        writer_epoch: int = 1,
        instance_id: str = "inst-1",
        handler: Callable[[MockHttpRequest, ssl.SSLSocket], bytes | None] | None = None,
        port: int = 0,
    ) -> None:
        self.ssl_ctx = ssl_ctx
        self.store_id = store_id
        self.writer_epoch = writer_epoch
        self.instance_id = instance_id
        self.custom_handler = handler

        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._client_sockets: list[socket.socket] = []

        self.accept_count = 0
        self.handshake_count = 0
        self.get_count = 0
        self.post_count = 0
        self.raw_http_bytes = bytearray()
        self.requests: list[MockHttpRequest] = []

        self.on_before_handshake: Callable[[], Any] | None = None
        self.on_after_handshake: Callable[[], Any] | None = None

        self.listener_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener_sock.bind(("127.0.0.1", port))
        self.listener_sock.listen(16)
        self.port: int = self.listener_sock.getsockname()[1]

        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def __enter__(self) -> MockTlsServer:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def _accept_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                raw_conn, _ = self.listener_sock.accept()
            except OSError:
                break
            with self._lock:
                self.accept_count += 1
                self._client_sockets.append(raw_conn)
            client_thread = threading.Thread(target=self._handle_conn, args=(raw_conn,), daemon=True)
            client_thread.start()

    def _handle_conn(self, raw_conn: socket.socket) -> None:
        ssl_conn: ssl.SSLSocket | None = None
        try:
            ssl_conn = self.ssl_ctx.wrap_socket(raw_conn, server_side=True, do_handshake_on_connect=False)
            with self._lock:
                self._client_sockets.append(ssl_conn)
            if self.on_before_handshake:
                self.on_before_handshake()
            ssl_conn.do_handshake()
            with self._lock:
                self.handshake_count += 1
            if self.on_after_handshake:
                self.on_after_handshake()

            # Read decrypted HTTP requests
            read_buf = bytearray()
            while not self._stop_event.is_set():
                chunk = ssl_conn.recv(4096)
                if not chunk:
                    break
                with self._lock:
                    self.raw_http_bytes.extend(chunk)
                read_buf.extend(chunk)

                # Parse complete HTTP frame if headers delimiter is present
                header_end = read_buf.find(b"\r\n\r\n")
                if header_end != -1:
                    header_bytes = bytes(read_buf[:header_end])
                    lines = header_bytes.split(b"\r\n")
                    req_line = lines[0].decode("iso-8859-1")
                    parts = req_line.split(" ")
                    if len(parts) != 3:
                        break
                    method, path, version = parts[0], parts[1], parts[2]
                    headers: dict[str, str] = {}
                    for hl in lines[1:]:
                        if b":" in hl:
                            k, v = hl.split(b":", 1)
                            headers[k.strip().lower().decode("iso-8859-1")] = v.strip().decode("iso-8859-1")

                    content_length = int(headers.get("content-length", "0"))
                    total_needed = header_end + 4 + content_length
                    while len(read_buf) < total_needed:
                        more = ssl_conn.recv(4096)
                        if not more:
                            break
                        with self._lock:
                            self.raw_http_bytes.extend(more)
                        read_buf.extend(more)

                    if len(read_buf) < total_needed:
                        break

                    body = bytes(read_buf[header_end + 4 : total_needed])
                    del read_buf[:total_needed]

                    req = MockHttpRequest(method, path, version, headers, body)
                    with self._lock:
                        self.requests.append(req)
                        if method == "GET":
                            self.get_count += 1
                        elif method == "POST":
                            self.post_count += 1

                    # Generate and send response
                    if self.custom_handler is not None:
                        resp_bytes = self.custom_handler(req, ssl_conn)
                    else:
                        resp_bytes = self._default_handler(req)

                    if resp_bytes is not None:
                        ssl_conn.sendall(resp_bytes)
                    else:
                        # Handler chose to close connection abruptly
                        break
        except (ssl.SSLError, OSError):
            pass
        finally:
            if ssl_conn is not None:
                try:
                    ssl_conn.close()
                except OSError:
                    pass
            try:
                raw_conn.close()
            except OSError:
                pass

    def _default_handler(self, req: MockHttpRequest) -> bytes | None:
        if req.method == "GET" and req.path == "/v2/identity":
            body = json.dumps(
                {
                    "store_id": self.store_id,
                    "writer_epoch": self.writer_epoch,
                    "instance_id": self.instance_id,
                    "contract": "mcp-tools-v2",
                }
            ).encode("utf-8")
            return (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n\r\n" + body
            )
        if req.method == "POST" and req.path == "/v2/tools/call":
            res_envelope = encode_envelope({"ok": True, "data": {"health": "ok"}})
            return (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: " + str(len(res_envelope)).encode("ascii") + b"\r\n"
                b"Connection: close\r\n\r\n" + res_envelope
            )
        return b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"

    def close(self) -> None:
        self._stop_event.set()
        try:
            self.listener_sock.close()
        except OSError:
            pass
        with self._lock:
            for s in self._client_sockets:
                try:
                    s.close()
                except OSError:
                    pass
            self._client_sockets.clear()
        self._thread.join(timeout=2.0)


def _make_server_ctx(tls: SampleTlsMaterial) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(tls.leaf_cert_path), keyfile=str(tls.leaf_key_path))
    return ctx


# -----------------------------------------------------------------------------
# Test 1: test_pin_checked_before_any_http
# -----------------------------------------------------------------------------


def test_pin_checked_before_any_http(
    inc2_tls_material: SampleTlsMaterial,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify wrong CA, missing IP SAN, expired leaf, and wrong leaf pin emit zero HTTP bytes."""
    valid_ca_pem = inc2_tls_material.ca_cert_path.read_text()
    valid_leaf_sha = inc2_tls_material.leaf_cert_sha256
    client = LoopbackClient()
    command = ToolCommand(tool="get_health", arguments={"idempotency_key": "k1"}, token="secret-token-1")

    # Subcase A: Wrong CA (signed by an untrusted test authority)
    wrong_ca_ctx = make_wrong_ca_server_ctx(tmp_path / "wrong_ca")
    with MockTlsServer(wrong_ca_ctx) as server:
        ep = Endpoint(
            version=1,
            host="127.0.0.1",
            port=server.port,
            store_id="store-1",
            writer_epoch=1,
            instance_id="inst-1",
            contract="mcp-tools-v2",
        )
        target = LoopbackTarget(ep, "store-1", valid_ca_pem, valid_leaf_sha)
        with pytest.raises(LoopbackTransportError) as exc_info:
            client.connect(target)
        assert exc_info.value.code == ErrorCode.IDENTITY_MISMATCH
        assert exc_info.value.request_may_have_run is False
        assert len(server.raw_http_bytes) == 0
        assert server.get_count == 0
        assert server.post_count == 0

    # Subcase B: Leaf cert missing IPv4 SAN 127.0.0.1 (DNS localhost only)
    missing_san_ctx = make_missing_ip_san_server_ctx(inc2_tls_material, tmp_path / "missing_san")
    with MockTlsServer(missing_san_ctx) as server:
        ep = Endpoint(
            version=1,
            host="127.0.0.1",
            port=server.port,
            store_id="store-1",
            writer_epoch=1,
            instance_id="inst-1",
            contract="mcp-tools-v2",
        )
        target = LoopbackTarget(ep, "store-1", valid_ca_pem, valid_leaf_sha)
        with pytest.raises(LoopbackTransportError) as exc_info:
            client.call(target, command)
        assert exc_info.value.code == ErrorCode.IDENTITY_MISMATCH
        assert exc_info.value.request_may_have_run is False
        assert len(server.raw_http_bytes) == 0
        assert server.get_count == 0
        assert server.post_count == 0

    # Subcase C: Expired leaf cert
    expired_ctx = make_expired_leaf_server_ctx(inc2_tls_material, tmp_path / "expired")
    with MockTlsServer(expired_ctx) as server:
        ep = Endpoint(
            version=1,
            host="127.0.0.1",
            port=server.port,
            store_id="store-1",
            writer_epoch=1,
            instance_id="inst-1",
            contract="mcp-tools-v2",
        )
        target = LoopbackTarget(ep, "store-1", valid_ca_pem, valid_leaf_sha)
        with pytest.raises(LoopbackTransportError) as exc_info:
            client.connect(target)
        assert exc_info.value.code == ErrorCode.IDENTITY_MISMATCH
        assert exc_info.value.request_may_have_run is False
        assert len(server.raw_http_bytes) == 0
        assert server.get_count == 0
        assert server.post_count == 0

    # Subcase D: Wrong 64-hex leaf_cert_sha256 pin on a completely valid CA/SAN/unexpired cert
    valid_server_ctx = _make_server_ctx(inc2_tls_material)
    with MockTlsServer(valid_server_ctx) as server:
        ep = Endpoint(
            version=1,
            host="127.0.0.1",
            port=server.port,
            store_id="store-1",
            writer_epoch=1,
            instance_id="inst-1",
            contract="mcp-tools-v2",
        )
        # Flip the last character of the valid pin
        corrupted_pin = valid_leaf_sha[:-1] + ("0" if valid_leaf_sha[-1] != "0" else "1")
        target = LoopbackTarget(ep, "store-1", valid_ca_pem, corrupted_pin)
        with pytest.raises(LoopbackTransportError) as exc_info:
            client.connect(target)
        assert exc_info.value.code == ErrorCode.IDENTITY_MISMATCH
        assert exc_info.value.request_may_have_run is False
        assert len(server.raw_http_bytes) == 0
        assert server.get_count == 0
        assert server.post_count == 0

    # Subcase E: Invalid CA strings (non-ASCII or malformed PEM) fail closed before network connect
    with MockTlsServer(valid_server_ctx) as server:
        ep = Endpoint(
            version=1,
            host="127.0.0.1",
            port=server.port,
            store_id="store-1",
            writer_epoch=1,
            instance_id="inst-1",
            contract="mcp-tools-v2",
        )
        bad_ca = LoopbackTarget(
            endpoint=ep,
            expected_store_id="store-1",
            ca_pem="non-ASCII PEM \u00e9",
            leaf_cert_sha256="a" * 64,
        )
        bad_pem = LoopbackTarget(
            endpoint=ep,
            expected_store_id="store-1",
            ca_pem="not-a-valid-pem",
            leaf_cert_sha256="a" * 64,
        )
        with pytest.raises(LoopbackTransportError) as exc_ca:
            client.connect(bad_ca)
        assert exc_ca.value.code == ErrorCode.INVALID_INPUT
        assert exc_ca.value.request_may_have_run is False
        assert server.accept_count == 0

        with pytest.raises(LoopbackTransportError) as exc_pem:
            client.call(bad_pem, command)
        assert exc_pem.value.code == ErrorCode.INVALID_INPUT
        assert exc_pem.value.request_may_have_run is False
        assert server.accept_count == 0

    # Subcase F: Pre-HTTP OS/SSL failure normalization and socket cleanup in connect() and call()
    with MockTlsServer(valid_server_ctx) as server:
        ep_valid = Endpoint(
            version=1,
            host="127.0.0.1",
            port=server.port,
            store_id="store-1",
            writer_epoch=1,
            instance_id="inst-1",
            contract="mcp-tools-v2",
        )
        valid_target = LoopbackTarget(ep_valid, "store-1", valid_ca_pem, valid_leaf_sha)

        # 1. socket.socket() raises OSError(EMFILE)
        def fail_socket(*_args: Any, **_kwargs: Any) -> Any:
            raise OSError(errno.EMFILE, "fixture emfile")

        with monkeypatch.context() as mp:
            mp.setattr("superbrain.cli_api.loopback.socket.socket", fail_socket)
            with pytest.raises(LoopbackTransportError) as exc_emfile_conn:
                client.connect(valid_target)
            assert exc_emfile_conn.value.code == ErrorCode.DAEMON_UNAVAILABLE
            assert exc_emfile_conn.value.request_may_have_run is False

            with pytest.raises(LoopbackTransportError) as exc_emfile_call:
                client.call(valid_target, command)
            assert exc_emfile_call.value.code == ErrorCode.DAEMON_UNAVAILABLE
            assert exc_emfile_call.value.request_may_have_run is False

        # 2. wrap_socket() raises ConnectionResetError(ECONNRESET) -> underlying raw socket closed
        orig_wrap = ssl.SSLContext.wrap_socket
        wrap_reset_socks: list[socket.socket] = []

        def fail_wrap_reset(_self: ssl.SSLContext, sock: socket.socket, *args: Any, **kwargs: Any) -> Any:
            if kwargs.get("server_side"):
                return orig_wrap(_self, sock, *args, **kwargs)
            wrap_reset_socks.append(sock)
            raise ConnectionResetError(errno.ECONNRESET, "fixture wrap reset")

        with monkeypatch.context() as mp:
            mp.setattr(ssl.SSLContext, "wrap_socket", fail_wrap_reset)
            with pytest.raises(LoopbackTransportError) as exc_reset_conn:
                client.connect(valid_target)
            assert exc_reset_conn.value.code == ErrorCode.DAEMON_UNAVAILABLE
            assert exc_reset_conn.value.request_may_have_run is False
            assert len(wrap_reset_socks) == 1
            assert wrap_reset_socks[0].fileno() == -1

            with pytest.raises(LoopbackTransportError) as exc_reset_call:
                client.call(valid_target, command)
            assert exc_reset_call.value.code == ErrorCode.DAEMON_UNAVAILABLE
            assert exc_reset_call.value.request_may_have_run is False
            assert len(wrap_reset_socks) == 2
            assert wrap_reset_socks[1].fileno() == -1

        # 3. wrap_socket() raises TimeoutError -> DEADLINE_EXCEEDED and underlying socket closed
        wrap_timeout_socks: list[socket.socket] = []

        def fail_wrap_timeout(_self: ssl.SSLContext, sock: socket.socket, *args: Any, **kwargs: Any) -> Any:
            if kwargs.get("server_side"):
                return orig_wrap(_self, sock, *args, **kwargs)
            wrap_timeout_socks.append(sock)
            raise TimeoutError("fixture wrap timeout")

        with monkeypatch.context() as mp:
            mp.setattr(ssl.SSLContext, "wrap_socket", fail_wrap_timeout)
            with pytest.raises(LoopbackTransportError) as exc_wrap_to:
                client.connect(valid_target)
            assert exc_wrap_to.value.code == ErrorCode.DEADLINE_EXCEEDED
            assert exc_wrap_to.value.request_may_have_run is False
            assert len(wrap_timeout_socks) == 1
            assert wrap_timeout_socks[0].fileno() == -1

        # 4. wrap_socket() raises SSLCertVerificationError -> IDENTITY_MISMATCH and underlying socket closed
        wrap_cert_socks: list[socket.socket] = []

        def fail_wrap_cert(_self: ssl.SSLContext, sock: socket.socket, *args: Any, **kwargs: Any) -> Any:
            if kwargs.get("server_side"):
                return orig_wrap(_self, sock, *args, **kwargs)
            wrap_cert_socks.append(sock)
            raise ssl.SSLCertVerificationError("fixture wrap cert verify")

        with monkeypatch.context() as mp:
            mp.setattr(ssl.SSLContext, "wrap_socket", fail_wrap_cert)
            with pytest.raises(LoopbackTransportError) as exc_wrap_cert:
                client.connect(valid_target)
            assert exc_wrap_cert.value.code == ErrorCode.IDENTITY_MISMATCH
            assert exc_wrap_cert.value.request_may_have_run is False
            assert len(wrap_cert_socks) == 1
            assert wrap_cert_socks[0].fileno() == -1

        # 5. getpeercert() raises OSError(ECONNRESET) -> DAEMON_UNAVAILABLE and ssl_sock closed
        wrapped_ssl_socks: list[ssl.SSLSocket] = []

        def intercept_wrap_peercert(
            self_ctx: ssl.SSLContext,
            sock: socket.socket,
            *args: Any,
            **kwargs: Any,
        ) -> ssl.SSLSocket:
            if kwargs.get("server_side"):
                return orig_wrap(self_ctx, sock, *args, **kwargs)
            ssl_sock = orig_wrap(self_ctx, sock, *args, **kwargs)
            wrapped_ssl_socks.append(ssl_sock)

            def fail_peercert(*_a: Any, **_k: Any) -> Any:
                raise OSError(errno.ECONNRESET, "fixture getpeercert reset")

            ssl_sock.getpeercert = fail_peercert  # type: ignore[method-assign]
            return ssl_sock

        with monkeypatch.context() as mp:
            mp.setattr(ssl.SSLContext, "wrap_socket", intercept_wrap_peercert)
            with pytest.raises(LoopbackTransportError) as exc_peer_conn:
                client.connect(valid_target)
            assert exc_peer_conn.value.code == ErrorCode.DAEMON_UNAVAILABLE
            assert exc_peer_conn.value.request_may_have_run is False
            assert len(wrapped_ssl_socks) == 1
            assert wrapped_ssl_socks[0].fileno() == -1


# -----------------------------------------------------------------------------
# Test 2: test_wrong_identity_receives_only_probe
# -----------------------------------------------------------------------------


def test_wrong_identity_receives_only_probe(inc2_tls_material: SampleTlsMaterial) -> None:
    """Verify pre-connect guard and negative identity responses transmit at most 1 probe with 0 secrets."""
    valid_ca_pem = inc2_tls_material.ca_cert_path.read_text()
    valid_leaf_sha = inc2_tls_material.leaf_cert_sha256
    valid_server_ctx = _make_server_ctx(inc2_tls_material)
    client = LoopbackClient()
    secret_token = "ultra-secret-test-bearer-token"
    command = ToolCommand(tool="get_health", arguments={"idempotency_key": "k2"}, token=secret_token)

    # Pre-connect check: target expected_store_id != endpoint.store_id rejects before opening socket
    with MockTlsServer(valid_server_ctx) as server:
        ep = Endpoint(
            version=1,
            host="127.0.0.1",
            port=server.port,
            store_id="store-expected-a",
            writer_epoch=1,
            instance_id="inst-1",
            contract="mcp-tools-v2",
        )
        mismatch_target = LoopbackTarget(ep, "store-different-b", valid_ca_pem, valid_leaf_sha)
        with pytest.raises(LoopbackTransportError) as exc_info:
            client.connect(mismatch_target)
        assert exc_info.value.code == ErrorCode.IDENTITY_MISMATCH
        assert exc_info.value.request_may_have_run is False
        assert server.accept_count == 0

        with pytest.raises(LoopbackTransportError) as exc_info_call:
            client.call(mismatch_target, command)
        assert exc_info_call.value.code == ErrorCode.IDENTITY_MISMATCH
        assert exc_info_call.value.request_may_have_run is False
        assert server.accept_count == 0

    # Negative identity probe subcases
    test_cases: list[tuple[str, bytes]] = [
        # 1. Wrong store_id
        (
            "wrong_store",
            json.dumps(
                {"store_id": "other-store", "writer_epoch": 1, "instance_id": "inst-1", "contract": "mcp-tools-v2"}
            ).encode(),
        ),
        # 2. Wrong writer_epoch
        (
            "wrong_epoch",
            json.dumps(
                {"store_id": "store-1", "writer_epoch": 999, "instance_id": "inst-1", "contract": "mcp-tools-v2"}
            ).encode(),
        ),
        # 3. Wrong instance_id
        (
            "wrong_instance",
            json.dumps(
                {"store_id": "store-1", "writer_epoch": 1, "instance_id": "other-inst", "contract": "mcp-tools-v2"}
            ).encode(),
        ),
        # 4. Wrong contract
        (
            "wrong_contract",
            json.dumps(
                {"store_id": "store-1", "writer_epoch": 1, "instance_id": "inst-1", "contract": "mcp-tools-v1"}
            ).encode(),
        ),
        # 5. Missing field
        ("missing_field", json.dumps({"store_id": "store-1", "writer_epoch": 1, "contract": "mcp-tools-v2"}).encode()),
        # 6. Extra field
        (
            "extra_field",
            json.dumps(
                {
                    "store_id": "store-1",
                    "writer_epoch": 1,
                    "instance_id": "inst-1",
                    "contract": "mcp-tools-v2",
                    "port": 8080,
                }
            ).encode(),
        ),
        # 7. Boolean writer_epoch (JSON true instead of strict integer)
        ("bool_epoch", b'{"store_id":"store-1","writer_epoch":true,"instance_id":"inst-1","contract":"mcp-tools-v2"}'),
        # 8. HTTP 404 status
        ("http_404", b"HTTP_STATUS_404"),
        # 9. HTTP 503 status
        ("http_503", b"HTTP_STATUS_503"),
        # 10. Pipelined extra bytes trailing identity response
        ("pipelined_bytes", b"PIPELINED_DATA"),
    ]

    for label, payload in test_cases:

        def make_handler(resp_payload: bytes) -> Callable[[MockHttpRequest, ssl.SSLSocket], bytes | None]:
            def _handler(req: MockHttpRequest, sock: ssl.SSLSocket) -> bytes | None:
                if req.method == "GET" and req.path == "/v2/identity":
                    if resp_payload == b"HTTP_STATUS_404":
                        return b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
                    if resp_payload == b"HTTP_STATUS_503":
                        return b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n"
                    if resp_payload == b"PIPELINED_DATA":
                        valid_body = json.dumps(
                            {
                                "store_id": "store-1",
                                "writer_epoch": 1,
                                "instance_id": "inst-1",
                                "contract": "mcp-tools-v2",
                            }
                        ).encode()
                        # Send valid response immediately followed by pipelined trailing bytes
                        return (
                            b"HTTP/1.1 200 OK\r\n"
                            b"Content-Type: application/json\r\n"
                            b"Content-Length: "
                            + str(len(valid_body)).encode()
                            + b"\r\n\r\n"
                            + valid_body
                            + b"UNEXPECTED_PIPELINED_TRAILING_BYTES"
                        )
                    return (
                        b"HTTP/1.1 200 OK\r\n"
                        b"Content-Type: application/json\r\n"
                        b"Content-Length: " + str(len(resp_payload)).encode() + b"\r\n\r\n" + resp_payload
                    )
                return b"HTTP/1.1 500 Unexpected\r\nContent-Length: 0\r\n\r\n"

            return _handler

        with MockTlsServer(valid_server_ctx, handler=make_handler(payload)) as server:
            ep = Endpoint(
                version=1,
                host="127.0.0.1",
                port=server.port,
                store_id="store-1",
                writer_epoch=1,
                instance_id="inst-1",
                contract="mcp-tools-v2",
            )
            target = LoopbackTarget(ep, "store-1", valid_ca_pem, valid_leaf_sha)

            with pytest.raises(LoopbackTransportError) as exc_info:
                client.call(target, command)
            assert exc_info.value.request_may_have_run is False, f"Failed request_may_have_run on subcase {label}"
            assert server.get_count == 1, f"Expected exactly 1 probe on {label}"
            assert server.post_count == 0, f"Expected 0 POSTs on {label}"
            # Verify the GET request had NO Authorization header
            assert len(server.requests) >= 1
            assert "authorization" not in server.requests[0].headers
            # Verify zero token or tool args leaked across raw decrypted wire
            assert secret_token.encode() not in server.raw_http_bytes
            assert b"get_health" not in server.raw_http_bytes

    # Subcase: Overlong 5,000-digit Content-Length on GET /v2/identity fails identity verification with 0 POSTs
    def overlong_cl_identity_handler(req: MockHttpRequest, sock: ssl.SSLSocket) -> bytes | None:
        if req.method == "GET":
            return b"HTTP/1.1 200 OK\r\nContent-Length: " + (b"9" * 5000) + b"\r\n\r\n"
        return None

    with MockTlsServer(valid_server_ctx, handler=overlong_cl_identity_handler) as server:
        ep = Endpoint(
            version=1,
            host="127.0.0.1",
            port=server.port,
            store_id="store-1",
            writer_epoch=1,
            instance_id="inst-1",
            contract="mcp-tools-v2",
        )
        target = LoopbackTarget(ep, "store-1", valid_ca_pem, valid_leaf_sha)
        with pytest.raises(LoopbackTransportError) as exc_info:
            client.call(target, command)
        assert exc_info.value.code == ErrorCode.IDENTITY_MISMATCH
        assert exc_info.value.request_may_have_run is False
        assert server.get_count == 1
        assert server.post_count == 0


# -----------------------------------------------------------------------------
# Test 3: test_connection_budget_includes_slow_handshake_without_consuming_tool_budget
# -----------------------------------------------------------------------------


def test_connection_budget_includes_slow_handshake_without_consuming_tool_budget(
    inc2_tls_material: SampleTlsMaterial,
) -> None:
    """Verify slow handshake and identity consume connect budget without diminishing fresh tool budget."""
    valid_ca_pem = inc2_tls_material.ca_cert_path.read_text()
    valid_leaf_sha = inc2_tls_material.leaf_cert_sha256
    valid_server_ctx = _make_server_ctx(inc2_tls_material)

    command = ToolCommand(tool="get_health", arguments={"idempotency_key": "k3"}, token="valid-token-3")

    # Subcase 1: Slow handshake (~950 ms) + slow identity (~950 ms) = ~1,900 ms connect.
    # Tool call advances clock by ~1,800 ms (total elapsed 3.7 s > 2.0 s connect budget).
    # Since fresh 2.0 s tool budget was minted upon identity validation, tool call succeeds!
    clock = FakeClock(10_000_000_000)
    client = LoopbackClient(monotonic_ns=clock.now_ns)

    def slow_connect_handler(req: MockHttpRequest, sock: ssl.SSLSocket) -> bytes | None:
        if req.method == "GET" and req.path == "/v2/identity":
            # Advance clock near connect cutoff (950 ms on handshake + 950 ms on identity = 1,900 ms)
            clock.advance_ms(950)
            body = json.dumps(
                {
                    "store_id": "store-1",
                    "writer_epoch": 1,
                    "instance_id": "inst-1",
                    "contract": "mcp-tools-v2",
                }
            ).encode()
            return (
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                + str(len(body)).encode()
                + b"\r\n\r\n"
                + body
            )
        if req.method == "POST" and req.path == "/v2/tools/call":
            # Advance clock by 1,800 ms during tool execution
            clock.advance_ms(1800)
            envelope = encode_envelope({"ok": True, "data": {"health": "passed"}})
            return (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: " + str(len(envelope)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n" + envelope
            )
        return None

    with MockTlsServer(valid_server_ctx, handler=slow_connect_handler) as server:
        server.on_before_handshake = lambda: clock.advance_ms(950)
        ep = Endpoint(
            version=1,
            host="127.0.0.1",
            port=server.port,
            store_id="store-1",
            writer_epoch=1,
            instance_id="inst-1",
            contract="mcp-tools-v2",
        )
        target = LoopbackTarget(ep, "store-1", valid_ca_pem, valid_leaf_sha)

        result = client.call(target, command)
        assert result == {"ok": True, "data": {"health": "passed"}}
        assert server.get_count == 1
        assert server.post_count == 1

    # Subcase 2: Identity response dripping past 2.0 s connect cutoff
    clock_drip_ident = FakeClock(10_000_000_000)
    client_drip_ident = LoopbackClient(monotonic_ns=clock_drip_ident.now_ns)

    def identity_drip_handler(req: MockHttpRequest, sock: ssl.SSLSocket) -> bytes | None:
        if req.method == "GET":
            # Advance clock past 2.0 s connect budget during identity handling
            clock_drip_ident.advance_ms(2050)
            body = json.dumps(
                {
                    "store_id": "store-1",
                    "writer_epoch": 1,
                    "instance_id": "inst-1",
                    "contract": "mcp-tools-v2",
                }
            ).encode()
            return (
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                + str(len(body)).encode()
                + b"\r\n\r\n"
                + body
            )
        return None

    with MockTlsServer(valid_server_ctx, handler=identity_drip_handler) as server:
        ep = Endpoint(
            version=1,
            host="127.0.0.1",
            port=server.port,
            store_id="store-1",
            writer_epoch=1,
            instance_id="inst-1",
            contract="mcp-tools-v2",
        )
        target = LoopbackTarget(ep, "store-1", valid_ca_pem, valid_leaf_sha)

        with pytest.raises(LoopbackTransportError) as exc_info:
            client_drip_ident.connect(target)
        assert exc_info.value.code == ErrorCode.DEADLINE_EXCEEDED
        assert exc_info.value.request_may_have_run is False
        assert server.post_count == 0

    # Subcase 3: Explicit earlier caller deadline_ns honored on connect()
    clock_early_dl = FakeClock(10_000_000_000)
    client_early_dl = LoopbackClient(monotonic_ns=clock_early_dl.now_ns)

    with MockTlsServer(valid_server_ctx) as server:
        # Advance by 600 ms during handshake when caller deadline is 500 ms
        server.on_before_handshake = lambda: clock_early_dl.advance_ms(600)
        ep = Endpoint(
            version=1,
            host="127.0.0.1",
            port=server.port,
            store_id="store-1",
            writer_epoch=1,
            instance_id="inst-1",
            contract="mcp-tools-v2",
        )
        target = LoopbackTarget(ep, "store-1", valid_ca_pem, valid_leaf_sha)
        explicit_deadline_ns = clock_early_dl.now_ns() + 500_000_000

        with pytest.raises(LoopbackTransportError) as exc_info:
            client_early_dl.connect(target, deadline_ns=explicit_deadline_ns)
        assert exc_info.value.code == ErrorCode.DEADLINE_EXCEEDED
        assert exc_info.value.request_may_have_run is False

    # Subcase 4: Tool response dripping past fresh 2.0 s tool cutoff
    clock_tool_drip = FakeClock(10_000_000_000)
    client_tool_drip = LoopbackClient(monotonic_ns=clock_tool_drip.now_ns)

    def tool_drip_handler(req: MockHttpRequest, sock: ssl.SSLSocket) -> bytes | None:
        if req.method == "GET":
            body = json.dumps(
                {
                    "store_id": "store-1",
                    "writer_epoch": 1,
                    "instance_id": "inst-1",
                    "contract": "mcp-tools-v2",
                }
            ).encode()
            return (
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                + str(len(body)).encode()
                + b"\r\n\r\n"
                + body
            )
        if req.method == "POST":
            # Exceed 2.0 s tool cutoff
            clock_tool_drip.advance_ms(2050)
            envelope = encode_envelope({"ok": True, "data": {"health": "late"}})
            return (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: " + str(len(envelope)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n" + envelope
            )
        return None

    with MockTlsServer(valid_server_ctx, handler=tool_drip_handler) as server:
        ep = Endpoint(
            version=1,
            host="127.0.0.1",
            port=server.port,
            store_id="store-1",
            writer_epoch=1,
            instance_id="inst-1",
            contract="mcp-tools-v2",
        )
        target = LoopbackTarget(ep, "store-1", valid_ca_pem, valid_leaf_sha)

        with pytest.raises(LoopbackTransportError) as exc_info:
            client_tool_drip.call(target, command)
        assert exc_info.value.code == ErrorCode.DEADLINE_EXCEEDED
        assert exc_info.value.request_may_have_run is True


# -----------------------------------------------------------------------------
# Test 4: test_response_loss_after_post_is_transport_uncertain
# -----------------------------------------------------------------------------


def test_response_loss_after_post_is_transport_uncertain(inc2_tls_material: SampleTlsMaterial) -> None:
    """Verify failures once POST begins have request_may_have_run=True and intact envelopes pass."""
    valid_ca_pem = inc2_tls_material.ca_cert_path.read_text()
    valid_leaf_sha = inc2_tls_material.leaf_cert_sha256
    valid_server_ctx = _make_server_ctx(inc2_tls_material)
    client = LoopbackClient()

    # Subcase 1: mid-response body EOF after POST write begins
    def mid_eof_handler(req: MockHttpRequest, sock: ssl.SSLSocket) -> bytes | None:
        if req.method == "GET":
            body = json.dumps(
                {"store_id": "store-1", "writer_epoch": 1, "instance_id": "inst-1", "contract": "mcp-tools-v2"}
            ).encode()
            return (
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                + str(len(body)).encode()
                + b"\r\n\r\n"
                + body
            )
        if req.method == "POST":
            # Send partial headers and truncated body, then abruptly close socket
            sock.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{"ok":')
            return None
        return None

    with MockTlsServer(valid_server_ctx, handler=mid_eof_handler) as server:
        ep = Endpoint(
            version=1,
            host="127.0.0.1",
            port=server.port,
            store_id="store-1",
            writer_epoch=1,
            instance_id="inst-1",
            contract="mcp-tools-v2",
        )
        target = LoopbackTarget(ep, "store-1", valid_ca_pem, valid_leaf_sha)
        cmd1 = ToolCommand(tool="get_health", arguments={"idempotency_key": "k-eof"}, token="tok-1")

        with pytest.raises(LoopbackTransportError) as exc_info:
            client.call(target, cmd1)
        assert exc_info.value.request_may_have_run is True
        assert isinstance(cmd1.arguments, dict)
        assert cmd1.arguments["idempotency_key"] == "k-eof"
        assert server.post_count == 1

    # Subcase 2: Tool timeout after POST write begins
    clock_timeout = FakeClock(10_000_000_000)
    client_timeout = LoopbackClient(monotonic_ns=clock_timeout.now_ns)

    def hang_handler(req: MockHttpRequest, sock: ssl.SSLSocket) -> bytes | None:
        if req.method == "GET":
            body = json.dumps(
                {"store_id": "store-1", "writer_epoch": 1, "instance_id": "inst-1", "contract": "mcp-tools-v2"}
            ).encode()
            return (
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                + str(len(body)).encode()
                + b"\r\n\r\n"
                + body
            )
        if req.method == "POST":
            # Advance clock past tool cutoff and drop socket
            clock_timeout.advance_ms(2500)
            return None
        return None

    with MockTlsServer(valid_server_ctx, handler=hang_handler) as server:
        ep = Endpoint(
            version=1,
            host="127.0.0.1",
            port=server.port,
            store_id="store-1",
            writer_epoch=1,
            instance_id="inst-1",
            contract="mcp-tools-v2",
        )
        target = LoopbackTarget(ep, "store-1", valid_ca_pem, valid_leaf_sha)
        cmd2 = ToolCommand(tool="get_health", arguments={"idempotency_key": "k-timeout"}, token="tok-2")

        with pytest.raises(LoopbackTransportError) as exc_info:
            client_timeout.call(target, cmd2)
        assert exc_info.value.code == ErrorCode.DEADLINE_EXCEEDED
        assert exc_info.value.request_may_have_run is True
        assert isinstance(cmd2.arguments, dict)
        assert cmd2.arguments["idempotency_key"] == "k-timeout"
        assert server.post_count == 1

    # Subcase 3: HTTP 302 / 307 redirect status
    def redirect_handler(req: MockHttpRequest, sock: ssl.SSLSocket) -> bytes | None:
        if req.method == "GET":
            body = json.dumps(
                {"store_id": "store-1", "writer_epoch": 1, "instance_id": "inst-1", "contract": "mcp-tools-v2"}
            ).encode()
            return (
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                + str(len(body)).encode()
                + b"\r\n\r\n"
                + body
            )
        if req.method == "POST":
            return b"HTTP/1.1 302 Found\r\nLocation: https://127.0.0.1:9999/other\r\nContent-Length: 0\r\n\r\n"
        return None

    with MockTlsServer(valid_server_ctx, handler=redirect_handler) as server:
        ep = Endpoint(
            version=1,
            host="127.0.0.1",
            port=server.port,
            store_id="store-1",
            writer_epoch=1,
            instance_id="inst-1",
            contract="mcp-tools-v2",
        )
        target = LoopbackTarget(ep, "store-1", valid_ca_pem, valid_leaf_sha)
        cmd3 = ToolCommand(tool="get_health", arguments={"idempotency_key": "k-redir"}, token="tok-3")

        with pytest.raises(LoopbackTransportError) as exc_info:
            client.call(target, cmd3)
        assert exc_info.value.request_may_have_run is True
        assert isinstance(cmd3.arguments, dict)
        assert cmd3.arguments["idempotency_key"] == "k-redir"
        assert server.post_count == 1

    # Subcase 4: HTTP 502 / non-JSON response
    def bad_gw_handler(req: MockHttpRequest, sock: ssl.SSLSocket) -> bytes | None:
        if req.method == "GET":
            body = json.dumps(
                {"store_id": "store-1", "writer_epoch": 1, "instance_id": "inst-1", "contract": "mcp-tools-v2"}
            ).encode()
            return (
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                + str(len(body)).encode()
                + b"\r\n\r\n"
                + body
            )
        if req.method == "POST":
            return b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 11\r\n\r\nBad Gateway"
        return None

    with MockTlsServer(valid_server_ctx, handler=bad_gw_handler) as server:
        ep = Endpoint(
            version=1,
            host="127.0.0.1",
            port=server.port,
            store_id="store-1",
            writer_epoch=1,
            instance_id="inst-1",
            contract="mcp-tools-v2",
        )
        target = LoopbackTarget(ep, "store-1", valid_ca_pem, valid_leaf_sha)
        cmd4 = ToolCommand(tool="get_health", arguments={"idempotency_key": "k-502"}, token="tok-4")

        with pytest.raises(LoopbackTransportError) as exc_info:
            client.call(target, cmd4)
        assert exc_info.value.request_may_have_run is True
        assert isinstance(cmd4.arguments, dict)
        assert cmd4.arguments["idempotency_key"] == "k-502"
        assert server.post_count == 1

    # Subcase 5: Overlong 5,000-digit Content-Length on POST /v2/tools/call response
    # is DAEMON_UNAVAILABLE with request_may_have_run=True
    def overlong_cl_post_handler(req: MockHttpRequest, sock: ssl.SSLSocket) -> bytes | None:
        if req.method == "GET":
            body = json.dumps(
                {"store_id": "store-1", "writer_epoch": 1, "instance_id": "inst-1", "contract": "mcp-tools-v2"}
            ).encode()
            return (
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                + str(len(body)).encode()
                + b"\r\n\r\n"
                + body
            )
        if req.method == "POST":
            return b"HTTP/1.1 200 OK\r\nContent-Length: " + (b"9" * 5000) + b"\r\n\r\n"
        return None

    with MockTlsServer(valid_server_ctx, handler=overlong_cl_post_handler) as server:
        ep = Endpoint(
            version=1,
            host="127.0.0.1",
            port=server.port,
            store_id="store-1",
            writer_epoch=1,
            instance_id="inst-1",
            contract="mcp-tools-v2",
        )
        target = LoopbackTarget(ep, "store-1", valid_ca_pem, valid_leaf_sha)
        cmd_cl = ToolCommand(tool="get_health", arguments={"idempotency_key": "k-cl-5000"}, token="tok-cl")

        with pytest.raises(LoopbackTransportError) as exc_info:
            client.call(target, cmd_cl)
        assert exc_info.value.code == ErrorCode.DAEMON_UNAVAILABLE
        assert exc_info.value.request_may_have_run is True
        assert server.get_count == 1
        assert server.post_count == 1

    # Complementary success cases: valid daemon error envelopes returned intact
    daemon_envelopes = [
        # in_progress envelope
        {"ok": False, "error": {"code": "in_progress", "message": SAFE_WIRE_MESSAGES_BY_CODE[ErrorCode.IN_PROGRESS]}},
        # commit_outcome_unknown envelope
        {
            "ok": False,
            "error": {
                "code": "commit_outcome_unknown",
                "message": SAFE_WIRE_MESSAGES_BY_CODE[ErrorCode.COMMIT_OUTCOME_UNKNOWN],
            },
        },
        # invalid_input envelope
        {
            "ok": False,
            "error": {"code": "invalid_input", "message": SAFE_WIRE_MESSAGES_BY_CODE[ErrorCode.INVALID_INPUT]},
        },
    ]

    def make_envelope_handler(
        target_env: dict[str, Any],
    ) -> Callable[[MockHttpRequest, ssl.SSLSocket], bytes | None]:
        def _handler(req: MockHttpRequest, sock: ssl.SSLSocket) -> bytes | None:
            if req.method == "GET":
                body = json.dumps(
                    {"store_id": "store-1", "writer_epoch": 1, "instance_id": "inst-1", "contract": "mcp-tools-v2"}
                ).encode()
                return (
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                    + str(len(body)).encode()
                    + b"\r\n\r\n"
                    + body
                )
            if req.method == "POST":
                encoded = encode_envelope(target_env)
                status = b"400 Bad Request" if target_env["error"]["code"] == "invalid_input" else b"200 OK"
                return (
                    b"HTTP/1.1 " + status + b"\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Content-Length: " + str(len(encoded)).encode() + b"\r\n"
                    b"Connection: close\r\n\r\n" + encoded
                )
            return None

        return _handler

    for env in daemon_envelopes:
        with MockTlsServer(valid_server_ctx, handler=make_envelope_handler(env)) as server:
            ep = Endpoint(
                version=1,
                host="127.0.0.1",
                port=server.port,
                store_id="store-1",
                writer_epoch=1,
                instance_id="inst-1",
                contract="mcp-tools-v2",
            )
            target = LoopbackTarget(ep, "store-1", valid_ca_pem, valid_leaf_sha)
            cmd_env = ToolCommand(tool="get_health", arguments={"idempotency_key": "k-env"}, token="tok-env")

            result = client.call(target, cmd_env)
            assert result == env


# -----------------------------------------------------------------------------
# Test 5: test_lost_pinned_socket_cannot_send_to_rebound_port
# -----------------------------------------------------------------------------


def test_lost_pinned_socket_cannot_send_to_rebound_port(inc2_tls_material: SampleTlsMaterial) -> None:
    """Verify dead pinned sockets fail without re-establishing connections to a rebound listener."""
    valid_ca_pem = inc2_tls_material.ca_cert_path.read_text()
    valid_leaf_sha = inc2_tls_material.leaf_cert_sha256
    valid_server_ctx = _make_server_ctx(inc2_tls_material)
    client = LoopbackClient()
    command = ToolCommand(tool="get_health", arguments={"idempotency_key": "k5"}, token="tok-5")

    # Step 1: Establish pinned connection on server 1
    server1 = MockTlsServer(valid_server_ctx)
    pinned_port = server1.port
    ep = Endpoint(
        version=1,
        host="127.0.0.1",
        port=pinned_port,
        store_id="store-1",
        writer_epoch=1,
        instance_id="inst-1",
        contract="mcp-tools-v2",
    )
    target = LoopbackTarget(ep, "store-1", valid_ca_pem, valid_leaf_sha)

    conn: PinnedConnection = client.connect(target)
    assert server1.get_count == 1

    # Step 2: Abruptly terminate server 1
    server1.close()

    # Step 3: Rebind rogue server 2 to the exact same port
    server2 = MockTlsServer(valid_server_ctx, port=pinned_port)
    try:
        # Step 4: Attempt to send tool command on the old pinned connection
        with pytest.raises((LoopbackTransportError, BrainError)):
            conn.call(command)

        # Critical invariant: rogue server 2 must observe 0 accepts and 0 bytes from conn.call
        assert server2.accept_count == 0
        assert len(server2.raw_http_bytes) == 0
        assert server2.post_count == 0
    finally:
        server2.close()


# -----------------------------------------------------------------------------
# Test 6: test_pinned_connection_sends_at_most_one_post
# -----------------------------------------------------------------------------


def test_pinned_connection_sends_at_most_one_post(inc2_tls_material: SampleTlsMaterial) -> None:
    """Verify single-use socket ownership, concurrent caller isolation, and token header safety."""
    valid_ca_pem = inc2_tls_material.ca_cert_path.read_text()
    valid_leaf_sha = inc2_tls_material.leaf_cert_sha256
    valid_server_ctx = _make_server_ctx(inc2_tls_material)
    client = LoopbackClient()

    # Part A: Concurrent caller isolation and single-use ownership
    post_arrived = threading.Event()
    release_post = threading.Event()

    def concurrent_barrier_handler(req: MockHttpRequest, sock: ssl.SSLSocket) -> bytes | None:
        if req.method == "GET":
            body = json.dumps(
                {"store_id": "store-1", "writer_epoch": 1, "instance_id": "inst-1", "contract": "mcp-tools-v2"}
            ).encode()
            return (
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                + str(len(body)).encode()
                + b"\r\n\r\n"
                + body
            )
        if req.method == "POST":
            post_arrived.set()
            # Hold caller 1 at barrier while caller 2 attempts concurrent call
            if not release_post.wait(timeout=5.0):
                return None
            res = encode_envelope({"ok": True, "data": {"health": "caller-1-ok"}})
            return (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: " + str(len(res)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n" + res
            )
        return None

    with MockTlsServer(valid_server_ctx, handler=concurrent_barrier_handler) as server:
        ep = Endpoint(
            version=1,
            host="127.0.0.1",
            port=server.port,
            store_id="store-1",
            writer_epoch=1,
            instance_id="inst-1",
            contract="mcp-tools-v2",
        )
        target = LoopbackTarget(ep, "store-1", valid_ca_pem, valid_leaf_sha)

        conn = client.connect(target)
        cmd1 = ToolCommand(tool="get_health", arguments={"idempotency_key": "c1"}, token="tok-c1")
        cmd2 = ToolCommand(tool="get_health", arguments={"idempotency_key": "c2"}, token="tok-c2")
        cmd3 = ToolCommand(tool="get_health", arguments={"idempotency_key": "c3"}, token="tok-c3")

        caller1_result: list[dict[str, Any]] = []
        caller1_error: list[Exception] = []

        def run_caller1() -> None:
            try:
                res = conn.call(cmd1)
                caller1_result.append(res)
            except (LoopbackTransportError, BrainError, OSError) as err:
                caller1_error.append(err)

        t1 = threading.Thread(target=run_caller1, daemon=True)
        t1.start()

        # Wait until caller 1's POST has arrived at the server
        assert post_arrived.wait(timeout=5.0), "Caller 1 POST did not arrive at server"

        # Concurrent caller 2 MUST immediately fail with INVALID_INPUT without disrupting caller 1
        with pytest.raises(LoopbackTransportError) as exc_info2:
            conn.call(cmd2)
        assert exc_info2.value.code == ErrorCode.INVALID_INPUT
        assert exc_info2.value.request_may_have_run is False

        # Concurrent close() marks close-pending without closing socket while caller 1 is in-flight
        conn.close()

        # Release barrier to allow caller 1 to complete
        release_post.set()
        t1.join(timeout=5.0)

        assert len(caller1_error) == 0, f"Caller 1 raised unexpected error: {caller1_error}"
        assert len(caller1_result) == 1
        assert caller1_result[0] == {"ok": True, "data": {"health": "caller-1-ok"}}

        # Third call after completion and close MUST fail with INVALID_INPUT
        with pytest.raises(LoopbackTransportError) as exc_info3:
            conn.call(cmd3)
        assert exc_info3.value.code == ErrorCode.INVALID_INPUT
        assert exc_info3.value.request_may_have_run is False

    # Part B: Header safety - invalid tokens containing control bytes or whitespace
    bad_tokens = [
        "token\r\ninjection",
        "token with space",
        "token\twith\ttab",
        "token\x00zero",
        "token\x1fctl",
        "token\x7fdel",
    ]

    with MockTlsServer(valid_server_ctx) as server:
        ep = Endpoint(
            version=1,
            host="127.0.0.1",
            port=server.port,
            store_id="store-1",
            writer_epoch=1,
            instance_id="inst-1",
            contract="mcp-tools-v2",
        )
        target = LoopbackTarget(ep, "store-1", valid_ca_pem, valid_leaf_sha)

        for bad_tok in bad_tokens:
            bad_cmd = ToolCommand(tool="get_health", arguments={"idempotency_key": "bad"}, token=bad_tok)
            with pytest.raises(LoopbackTransportError) as exc_info_tok:
                client.call(target, bad_cmd)
            assert exc_info_tok.value.code == ErrorCode.INVALID_INPUT
            assert exc_info_tok.value.request_may_have_run is False

        # Server must have observed 0 POSTs across all bad tokens
        assert server.post_count == 0
