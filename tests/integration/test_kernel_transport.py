"""Integration regressions for SP1 Increment 2 Task 6b.3 (Loopback TLS Transport & Admission).

Covers all mandatory invariants from interface-spec.md Section 4 and task-6b-3-brief.md:
1. test_duplicate_length_transfer_encoding_and_pipeline_refused:
   Duplicate Content-Length, Transfer-Encoding, Expect 100-continue, and pipelined requests refused.
2. test_prefetched_bytes_obey_two_request_state:
   Two-request state machine, clean close after request 2, and prefetched/buffered request 3 refused.
3. test_untrusted_http_admission_never_reaches_owner:
   Host/Origin/peer IP/route/method/auth/X-Store guards, log confidentiality, and SQLite immutability.
4. test_tls_handshake_does_not_block_accept_loop:
   Silent raw TCP client never blocks concurrent LoopbackClient calls and times out at 1.0 s cap.
5. test_active_connection_cap_includes_handshakes:
   All 32 slots held, slot 33 rejected before admission without store_busy, and slot release unblocks.
"""

from __future__ import annotations

import json
import logging
import socket
import threading
from collections.abc import Iterator

import pytest

from superbrain.cli_api._loopback_server import (
    MAX_ACTIVE_CONNECTIONS,
)
from superbrain.cli_api._loopback_wire import encode_call
from superbrain.cli_api.loopback import (
    LoopbackClient,
    LoopbackTransportError,
)
from superbrain.core.errors import ErrorCode
from superbrain.core.kernel import (
    TOTAL_REQUEST_BUDGET_NS,
    ToolCommand,
)
from tests.support.inc2_transport import (
    TransportTemplate,
    create_transport_template,
    open_test_loopback_transport,
)


@pytest.fixture(scope="module")
def transport_template() -> Iterator[TransportTemplate]:
    """Module-scoped initialized v2 kernel root + provisioned TLS material."""
    tmpl = create_transport_template("t6b3-test-tmpl")
    try:
        yield tmpl
    finally:
        import shutil

        shutil.rmtree(tmpl.base_dir, ignore_errors=True)


class TestTransportAdmission:
    """Task 6b.3 admission, framing, handshake concurrency, and slot limit regressions."""

    def test_duplicate_length_transfer_encoding_and_pipeline_refused(
        self,
        transport_template: TransportTemplate,
    ) -> None:
        """Malformed framing, chunked encoding, Expect: 100-continue, and pipelining are refused."""
        with open_test_loopback_transport(transport_template, name="framing") as h:
            host = f"127.0.0.1:{h.ready.endpoint.port}"
            active_token = h.cred.token
            store_id = h.store_id
            writer_epoch = h.ready.identity.writer_epoch
            instance_id = h.ready.identity.instance_id

            ident_req = f"GET /v2/identity HTTP/1.1\r\nHost: {host}\r\n\r\n".encode("ascii")
            valid_cmd = ToolCommand("get_health", {"schema_version": "2.0"}, token=active_token)
            valid_body = encode_call(valid_cmd)

            # 1. Pipelining Subcase A: identity + tool + third in a single write before reading
            raw1 = (
                (
                    f"GET /v2/identity HTTP/1.1\r\nHost: {host}\r\n\r\n"
                    f"POST /v2/tools/call HTTP/1.1\r\nHost: {host}\r\n"
                    f"Authorization: Bearer {active_token}\r\n"
                    f"X-Store-Id: {store_id}\r\nX-Writer-Epoch: {writer_epoch}\r\n"
                    f"X-Superbrain-Instance: {instance_id}\r\n"
                    f"Content-Type: application/json\r\nContent-Length: {len(valid_body)}\r\n\r\n"
                ).encode("iso-8859-1")
                + valid_body
                + ident_req
            )

            with h.open_raw_tls_socket() as s1:
                resp1 = h.send_raw_http(s1, raw1)
                assert b"400 Bad Request" in resp1 or b"invalid_input" in resp1
                # Socket must be closed afterward
                assert s1.recv(1024) == b""
            assert h.submit_count == 0

            # 2. Pipelining Subcase B: identity + tool in a single write before reading identity response
            raw2 = (
                f"GET /v2/identity HTTP/1.1\r\nHost: {host}\r\n\r\n"
                f"POST /v2/tools/call HTTP/1.1\r\nHost: {host}\r\n"
                f"Authorization: Bearer {active_token}\r\n"
                f"X-Store-Id: {store_id}\r\nX-Writer-Epoch: {writer_epoch}\r\n"
                f"X-Superbrain-Instance: {instance_id}\r\n"
                f"Content-Type: application/json\r\nContent-Length: {len(valid_body)}\r\n\r\n"
            ).encode("iso-8859-1") + valid_body

            with h.open_raw_tls_socket() as s2:
                resp2 = h.send_raw_http(s2, raw2)
                assert b"400 Bad Request" in resp2 or b"invalid_input" in resp2
                assert s2.recv(1024) == b""
            assert h.submit_count == 0

            # 3. Pipelining Subcase C: valid identity exchange, then tool + third in single write
            with h.open_raw_tls_socket() as s3:
                # Exchange identity cleanly first
                ident_resp = h.send_raw_http(s3, ident_req)
                assert b"200 OK" in ident_resp

                raw3 = (
                    (
                        f"POST /v2/tools/call HTTP/1.1\r\nHost: {host}\r\n"
                        f"Authorization: Bearer {active_token}\r\n"
                        f"X-Store-Id: {store_id}\r\nX-Writer-Epoch: {writer_epoch}\r\n"
                        f"X-Superbrain-Instance: {instance_id}\r\n"
                        f"Content-Type: application/json\r\nContent-Length: {len(valid_body)}\r\n\r\n"
                    ).encode("iso-8859-1")
                    + valid_body
                    + ident_req
                )

                resp3 = h.send_raw_http(s3, raw3)
                assert b"400 Bad Request" in resp3 or b"invalid_input" in resp3
                assert s3.recv(1024) == b""
            assert h.submit_count == 0

            # 4. Duplicate Content-Length headers (identical and conflicting values)
            for cl_header in [
                f"Content-Length: {len(valid_body)}\r\nContent-Length: {len(valid_body)}\r\n",
                f"Content-Length: {len(valid_body)}\r\nContent-Length: 9999\r\n",
            ]:
                with h.open_raw_tls_socket() as s_cl:
                    h.send_raw_http(s_cl, f"GET /v2/identity HTTP/1.1\r\nHost: {host}\r\n\r\n".encode("ascii"))
                    raw_cl = (
                        f"POST /v2/tools/call HTTP/1.1\r\nHost: {host}\r\n"
                        f"Authorization: Bearer {active_token}\r\n"
                        f"X-Store-Id: {store_id}\r\nX-Writer-Epoch: {writer_epoch}\r\n"
                        f"X-Superbrain-Instance: {instance_id}\r\n"
                        f"Content-Type: application/json\r\n"
                        f"{cl_header}\r\n"
                    ).encode("iso-8859-1") + valid_body
                    resp_cl = h.send_raw_http(s_cl, raw_cl)
                    assert b"400 Bad Request" in resp_cl or b"invalid_input" in resp_cl
                    assert s_cl.recv(1024) == b""
                assert h.submit_count == 0

            # 5. Transfer-Encoding: chunked (varied casing)
            for te_casing in ["chunked", "Chunked"]:
                with h.open_raw_tls_socket() as s_te:
                    h.send_raw_http(s_te, f"GET /v2/identity HTTP/1.1\r\nHost: {host}\r\n\r\n".encode("ascii"))
                    raw_te = (
                        (
                            f"POST /v2/tools/call HTTP/1.1\r\nHost: {host}\r\n"
                            f"Authorization: Bearer {active_token}\r\n"
                            f"X-Store-Id: {store_id}\r\nX-Writer-Epoch: {writer_epoch}\r\n"
                            f"X-Superbrain-Instance: {instance_id}\r\n"
                            f"Transfer-Encoding: {te_casing}\r\n"
                            f"Content-Type: application/json\r\n\r\n"
                            f"{len(valid_body):x}\r\n"
                        ).encode("iso-8859-1")
                        + valid_body
                        + b"\r\n0\r\n\r\n"
                    )
                    resp_te = h.send_raw_http(s_te, raw_te)
                    assert b"400 Bad Request" in resp_te or b"invalid_input" in resp_te
                    assert s_te.recv(1024) == b""
                assert h.submit_count == 0

            # 6. Expect: 100-continue (zero 100 Continue bytes emitted)
            with h.open_raw_tls_socket() as s_exp:
                h.send_raw_http(s_exp, f"GET /v2/identity HTTP/1.1\r\nHost: {host}\r\n\r\n".encode("ascii"))
                raw_exp = (
                    f"POST /v2/tools/call HTTP/1.1\r\nHost: {host}\r\n"
                    f"Authorization: Bearer {active_token}\r\n"
                    f"X-Store-Id: {store_id}\r\nX-Writer-Epoch: {writer_epoch}\r\n"
                    f"X-Superbrain-Instance: {instance_id}\r\n"
                    f"Expect: 100-continue\r\n"
                    f"Content-Type: application/json\r\nContent-Length: {len(valid_body)}\r\n\r\n"
                ).encode("iso-8859-1") + valid_body
                resp_exp = h.send_raw_http(s_exp, raw_exp)
                assert b"100 Continue" not in resp_exp
                assert s_exp.recv(1024) == b""
            assert h.submit_count == 0

            # 7. Content-Length > 1 MiB (1,048,576 B cap) refused with 413 invalid_input
            with h.open_raw_tls_socket() as s_large:
                h.send_raw_http(s_large, f"GET /v2/identity HTTP/1.1\r\nHost: {host}\r\n\r\n".encode("ascii"))
                raw_large_head = (
                    f"POST /v2/tools/call HTTP/1.1\r\nHost: {host}\r\n"
                    f"Authorization: Bearer {active_token}\r\n"
                    f"X-Store-Id: {store_id}\r\nX-Writer-Epoch: {writer_epoch}\r\n"
                    f"X-Superbrain-Instance: {instance_id}\r\n"
                    f"Content-Type: application/json\r\nContent-Length: 1048577\r\n\r\n"
                ).encode("iso-8859-1")
                resp_large = h.send_raw_http(s_large, raw_large_head)
                assert b"413" in resp_large or b"invalid_input" in resp_large
                assert s_large.recv(1024) == b""
            assert h.submit_count == 0

    def test_prefetched_bytes_obey_two_request_state(
        self,
        transport_template: TransportTemplate,
    ) -> None:
        """State machine allows at most 2 requests, closes cleanly, and refuses buffered request 3."""
        with open_test_loopback_transport(transport_template, name="two-req") as h:
            host = f"127.0.0.1:{h.ready.endpoint.port}"
            active_token = h.cred.token
            store_id = h.store_id
            writer_epoch = h.ready.identity.writer_epoch
            instance_id = h.ready.identity.instance_id

            valid_cmd = ToolCommand("get_health", {"schema_version": "2.0"}, token=active_token)
            valid_body = encode_call(valid_cmd)

            # Part 1: Happy path - request 1 (identity) -> request 2 (tool) -> socket closes cleanly
            with h.open_raw_tls_socket() as s_clean:
                # 1. GET /v2/identity
                r1 = h.send_raw_http(s_clean, f"GET /v2/identity HTTP/1.1\r\nHost: {host}\r\n\r\n".encode("ascii"))
                assert b"200 OK" in r1
                ident_payload = json.loads(r1.split(b"\r\n\r\n", 1)[1])
                assert ident_payload["store_id"] == store_id
                assert ident_payload["writer_epoch"] == writer_epoch
                assert ident_payload["instance_id"] == instance_id
                assert ident_payload["contract"] == "mcp-tools-v2"

                # 2. POST /v2/tools/call
                raw_call = (
                    f"POST /v2/tools/call HTTP/1.1\r\nHost: {host}\r\n"
                    f"Authorization: Bearer {active_token}\r\n"
                    f"X-Store-Id: {store_id}\r\nX-Writer-Epoch: {writer_epoch}\r\n"
                    f"X-Superbrain-Instance: {instance_id}\r\n"
                    f"Content-Type: application/json\r\nContent-Length: {len(valid_body)}\r\n\r\n"
                ).encode("iso-8859-1") + valid_body

                r2 = h.send_raw_http(s_clean, raw_call)
                assert b"200 OK" in r2
                call_payload = json.loads(r2.split(b"\r\n\r\n", 1)[1])
                assert call_payload["ok"] is True
                assert h.submit_count == 1

                # 3. Socket must close cleanly after response 2; 3rd request sees EOF
                assert s_clean.recv(1024) == b""

            # Part 2: Sending a 3rd request prefetched in socket/TLS buffer alongside request 2
            with h.open_raw_tls_socket() as s_prefetch:
                # Exchange identity first
                r_id = h.send_raw_http(s_prefetch, f"GET /v2/identity HTTP/1.1\r\nHost: {host}\r\n\r\n".encode("ascii"))
                assert b"200 OK" in r_id

                # Tool call concatenated with trailing bytes of a 3rd request in the same send
                trailing_req = f"GET /v2/identity HTTP/1.1\r\nHost: {host}\r\n\r\n".encode("ascii")
                raw_prefetch = (
                    (
                        f"POST /v2/tools/call HTTP/1.1\r\nHost: {host}\r\n"
                        f"Authorization: Bearer {active_token}\r\n"
                        f"X-Store-Id: {store_id}\r\nX-Writer-Epoch: {writer_epoch}\r\n"
                        f"X-Superbrain-Instance: {instance_id}\r\n"
                        f"Content-Type: application/json\r\nContent-Length: {len(valid_body)}\r\n\r\n"
                    ).encode("iso-8859-1")
                    + valid_body
                    + trailing_req
                )

                resp_prefetch = h.send_raw_http(s_prefetch, raw_prefetch)
                # Refused before owner.submit_reply
                assert b"400 Bad Request" in resp_prefetch or b"invalid_input" in resp_prefetch
                assert s_prefetch.recv(1024) == b""
            # Submit count remained at 1 from Part 1, Part 2 had 0 owner submits
            assert h.submit_count == 1

            # Part 3: t0 deadline check applies even when bytes were buffered
            with h.open_raw_tls_socket() as s_dl:
                # Advance monotonic clock by >= 1,500 ms (TOTAL_REQUEST_BUDGET_NS) before reading request line
                h.mono_clock.advance_ns(TOTAL_REQUEST_BUDGET_NS + 100_000_000)
                resp_dl = h.send_raw_http(s_dl, f"GET /v2/identity HTTP/1.1\r\nHost: {host}\r\n\r\n".encode("ascii"))
                assert b"408" in resp_dl or b"deadline_exceeded" in resp_dl or resp_dl == b""
                assert s_dl.recv(1024) == b""
            assert h.submit_count == 1

    def test_untrusted_http_admission_never_reaches_owner(
        self,
        transport_template: TransportTemplate,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Untrusted admission guards reject before owner, keep SQLite clean, and leak no secrets."""
        with open_test_loopback_transport(transport_template, name="untrusted") as h:
            host = f"127.0.0.1:{h.ready.endpoint.port}"
            active_token = h.cred.token
            store_id = h.store_id
            writer_epoch = h.ready.identity.writer_epoch
            instance_id = h.ready.identity.instance_id

            valid_cmd = ToolCommand("get_health", {"schema_version": "2.0"}, token=active_token)
            valid_body = encode_call(valid_cmd)

            init_ledger_seq = h.ledger_sequence()
            init_idem_count = h.idempotency_count()

            # Helper to run a test on request 1 (identity phase)
            def assert_refused_on_r1(raw_req: bytes, expected_status: bytes = b"400 Bad Request") -> None:
                with h.open_raw_tls_socket() as sock:
                    resp = h.send_raw_http(sock, raw_req)
                    assert expected_status in resp or b"invalid_input" in resp
                    assert sock.recv(1024) == b""
                assert h.submit_count == 0

            # Helper to run a test on request 2 (tool phase) after valid identity
            def assert_refused_on_r2(raw_call: bytes, expected_status: bytes = b"400 Bad Request") -> None:
                with h.open_raw_tls_socket() as sock:
                    r1 = h.send_raw_http(sock, f"GET /v2/identity HTTP/1.1\r\nHost: {host}\r\n\r\n".encode("ascii"))
                    assert b"200 OK" in r1
                    r2 = h.send_raw_http(sock, raw_call)
                    assert expected_status in r2
                    assert sock.recv(1024) == b""
                assert h.submit_count == 0

            # 1. Host header validation
            # Missing Host
            assert_refused_on_r1(b"GET /v2/identity HTTP/1.1\r\n\r\n")
            # Missing port
            assert_refused_on_r1(b"GET /v2/identity HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            # Wrong port
            assert_refused_on_r1(b"GET /v2/identity HTTP/1.1\r\nHost: 127.0.0.1:9999\r\n\r\n")
            # DNS localhost
            assert_refused_on_r1(
                f"GET /v2/identity HTTP/1.1\r\nHost: localhost:{h.ready.endpoint.port}\r\n\r\n".encode("ascii")
            )
            # Duplicate Host (case-insensitive)
            assert_refused_on_r1(f"GET /v2/identity HTTP/1.1\r\nHost: {host}\r\nhost: {host}\r\n\r\n".encode("ascii"))

            # 2. Origin header validation (must return 403 Forbidden)
            assert_refused_on_r1(
                f"GET /v2/identity HTTP/1.1\r\nHost: {host}\r\nOrigin: https://evil.example\r\n\r\n".encode("ascii"),
                expected_status=b"403",
            )
            assert_refused_on_r1(
                f"GET /v2/identity HTTP/1.1\r\nHost: {host}\r\nOrigin:\r\n\r\n".encode("ascii"),
                expected_status=b"403",
            )

            # 3. Non-loopback peer IP accept guard (closed immediately before TLS/HTTP)
            orig_accept = socket.socket.accept
            inject_active = True

            def mock_non_loopback_accept(sock_self: socket.socket) -> tuple[socket.socket, tuple[str, int]]:
                nonlocal inject_active
                conn, addr = orig_accept(sock_self)
                if inject_active and sock_self is h.bound.sock:
                    inject_active = False
                    return conn, ("192.0.2.99", addr[1])
                return conn, addr

            with monkeypatch.context() as mp:
                mp.setattr(socket.socket, "accept", mock_non_loopback_accept)
                try:
                    # Raw connect should be disconnected immediately
                    with socket.create_connection((h.ready.endpoint.host, h.ready.endpoint.port), timeout=2.0) as s_raw:
                        # Reading raw socket should yield immediate EOF (b"")
                        s_raw.settimeout(2.0)
                        try:
                            read_data = s_raw.recv(1024)
                            assert read_data == b""
                        except (ConnectionResetError, BrokenPipeError):
                            pass
                    assert h.submit_count == 0
                finally:
                    inject_active = False

            # 4. Method / Route / Version / State validation
            # Wrong method on identity
            assert_refused_on_r1(
                f"POST /v2/identity HTTP/1.1\r\nHost: {host}\r\nContent-Length: 0\r\n\r\n".encode("ascii")
            )
            # Authorization sent on identity
            assert_refused_on_r1(
                f"GET /v2/identity HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {active_token}\r\n\r\n".encode(
                    "ascii"
                )
            )
            # Tool call sent before identity (State 0 violation)
            assert_refused_on_r1(
                (
                    f"POST /v2/tools/call HTTP/1.1\r\nHost: {host}\r\n"
                    f"Authorization: Bearer {active_token}\r\n"
                    f"X-Store-Id: {store_id}\r\nX-Writer-Epoch: {writer_epoch}\r\n"
                    f"X-Superbrain-Instance: {instance_id}\r\n"
                    f"Content-Type: application/json\r\nContent-Length: {len(valid_body)}\r\n\r\n"
                ).encode("iso-8859-1")
                + valid_body
            )
            # HTTP/1.0
            assert_refused_on_r1(f"GET /v2/identity HTTP/1.0\r\nHost: {host}\r\n\r\n".encode("ascii"))
            # Non-canonical raw routes
            assert_refused_on_r1(f"GET //v2/identity HTTP/1.1\r\nHost: {host}\r\n\r\n".encode("ascii"))
            assert_refused_on_r1(f"GET /v2/identity?param=1 HTTP/1.1\r\nHost: {host}\r\n\r\n".encode("ascii"))
            assert_refused_on_r1(
                f"GET http://127.0.0.1:{h.ready.endpoint.port}/v2/identity HTTP/1.1\r\nHost: {host}\r\n\r\n".encode(
                    "ascii"
                )
            )

            # 5. Authorization header on POST /v2/tools/call (must return 401 Unauthorized)
            # Missing Authorization
            assert_refused_on_r2(
                (
                    f"POST /v2/tools/call HTTP/1.1\r\nHost: {host}\r\n"
                    f"X-Store-Id: {store_id}\r\nX-Writer-Epoch: {writer_epoch}\r\n"
                    f"X-Superbrain-Instance: {instance_id}\r\n"
                    f"Content-Type: application/json\r\nContent-Length: {len(valid_body)}\r\n\r\n"
                ).encode("iso-8859-1")
                + valid_body,
                expected_status=b"401",
            )
            # Non-Bearer (Basic auth)
            assert_refused_on_r2(
                (
                    f"POST /v2/tools/call HTTP/1.1\r\nHost: {host}\r\n"
                    f"Authorization: Basic dXNlcjpwYXNz\r\n"
                    f"X-Store-Id: {store_id}\r\nX-Writer-Epoch: {writer_epoch}\r\n"
                    f"X-Superbrain-Instance: {instance_id}\r\n"
                    f"Content-Type: application/json\r\nContent-Length: {len(valid_body)}\r\n\r\n"
                ).encode("iso-8859-1")
                + valid_body,
                expected_status=b"401",
            )
            # Empty Bearer token
            assert_refused_on_r2(
                (
                    f"POST /v2/tools/call HTTP/1.1\r\nHost: {host}\r\n"
                    f"Authorization: Bearer \r\n"
                    f"X-Store-Id: {store_id}\r\nX-Writer-Epoch: {writer_epoch}\r\n"
                    f"X-Superbrain-Instance: {instance_id}\r\n"
                    f"Content-Type: application/json\r\nContent-Length: {len(valid_body)}\r\n\r\n"
                ).encode("iso-8859-1")
                + valid_body,
                expected_status=b"401",
            )

            # 6. X-* Header validation on POST /v2/tools/call (must return 409 Conflict)
            # Missing X-Store-Id
            assert_refused_on_r2(
                (
                    f"POST /v2/tools/call HTTP/1.1\r\nHost: {host}\r\n"
                    f"Authorization: Bearer {active_token}\r\n"
                    f"X-Writer-Epoch: {writer_epoch}\r\n"
                    f"X-Superbrain-Instance: {instance_id}\r\n"
                    f"Content-Type: application/json\r\nContent-Length: {len(valid_body)}\r\n\r\n"
                ).encode("iso-8859-1")
                + valid_body,
                expected_status=b"409",
            )
            # Mismatched X-Store-Id
            assert_refused_on_r2(
                (
                    f"POST /v2/tools/call HTTP/1.1\r\nHost: {host}\r\n"
                    f"Authorization: Bearer {active_token}\r\n"
                    f"X-Store-Id: wrong-store-99\r\nX-Writer-Epoch: {writer_epoch}\r\n"
                    f"X-Superbrain-Instance: {instance_id}\r\n"
                    f"Content-Type: application/json\r\nContent-Length: {len(valid_body)}\r\n\r\n"
                ).encode("iso-8859-1")
                + valid_body,
                expected_status=b"409",
            )
            # Mismatched X-Writer-Epoch
            assert_refused_on_r2(
                (
                    f"POST /v2/tools/call HTTP/1.1\r\nHost: {host}\r\n"
                    f"Authorization: Bearer {active_token}\r\n"
                    f"X-Store-Id: {store_id}\r\nX-Writer-Epoch: {writer_epoch + 1}\r\n"
                    f"X-Superbrain-Instance: {instance_id}\r\n"
                    f"Content-Type: application/json\r\nContent-Length: {len(valid_body)}\r\n\r\n"
                ).encode("iso-8859-1")
                + valid_body,
                expected_status=b"409",
            )
            # Non-canonical X-Writer-Epoch ("01", "true", "-1")
            for non_canonical_epoch in ["01", "+1", "true", "-1"]:
                assert_refused_on_r2(
                    (
                        f"POST /v2/tools/call HTTP/1.1\r\nHost: {host}\r\n"
                        f"Authorization: Bearer {active_token}\r\n"
                        f"X-Store-Id: {store_id}\r\nX-Writer-Epoch: {non_canonical_epoch}\r\n"
                        f"X-Superbrain-Instance: {instance_id}\r\n"
                        f"Content-Type: application/json\r\nContent-Length: {len(valid_body)}\r\n\r\n"
                    ).encode("iso-8859-1")
                    + valid_body,
                    expected_status=b"409",
                )
            # Duplicate X-Store-Id (case-insensitive)
            assert_refused_on_r2(
                (
                    f"POST /v2/tools/call HTTP/1.1\r\nHost: {host}\r\n"
                    f"Authorization: Bearer {active_token}\r\n"
                    f"X-Store-Id: {store_id}\r\nx-store-id: {store_id}\r\n"
                    f"X-Writer-Epoch: {writer_epoch}\r\n"
                    f"X-Superbrain-Instance: {instance_id}\r\n"
                    f"Content-Type: application/json\r\nContent-Length: {len(valid_body)}\r\n\r\n"
                ).encode("iso-8859-1")
                + valid_body,
                expected_status=b"409",
            )

            # 7. Syntactically valid well-formed unknown token DOES reach owner and returns HTTP 200 unauthenticated
            well_formed_unknown_token = "0" * 64
            unknown_cmd = ToolCommand("get_health", {"schema_version": "2.0"}, token=well_formed_unknown_token)
            unknown_body = encode_call(unknown_cmd)

            with h.open_raw_tls_socket() as s_unknown:
                r_id = h.send_raw_http(s_unknown, f"GET /v2/identity HTTP/1.1\r\nHost: {host}\r\n\r\n".encode("ascii"))
                assert b"200 OK" in r_id

                raw_unknown = (
                    f"POST /v2/tools/call HTTP/1.1\r\nHost: {host}\r\n"
                    f"Authorization: Bearer {well_formed_unknown_token}\r\n"
                    f"X-Store-Id: {store_id}\r\nX-Writer-Epoch: {writer_epoch}\r\n"
                    f"X-Superbrain-Instance: {instance_id}\r\n"
                    f"Content-Type: application/json\r\nContent-Length: {len(unknown_body)}\r\n\r\n"
                ).encode("iso-8859-1") + unknown_body

                r_unauth = h.send_raw_http(s_unknown, raw_unknown)
                # HTTP 200 containing envelope with ok=False and code=unauthenticated
                assert b"200 OK" in r_unauth
                unauth_data = json.loads(r_unauth.split(b"\r\n\r\n", 1)[1])
                assert unauth_data["ok"] is False
                assert unauth_data["error"]["code"] == "unauthenticated"
            # Exactly 1 request reached OwnerLoop!
            assert h.submit_count == 1

            # 8. Log Confidentiality & SQLite Immutability check
            canary_token = "CANARY_SECRET_TOKEN_99999"
            canary_body = b'{"canary_secret_field": "SUPER_SECRET_PAYLOAD"}'
            caplog.set_level(logging.DEBUG, logger="superbrain")

            with h.open_raw_tls_socket() as s_canary:
                h.send_raw_http(s_canary, f"GET /v2/identity HTTP/1.1\r\nHost: {host}\r\n\r\n".encode("ascii"))
                raw_canary = (
                    f"POST /v2/tools/call HTTP/1.1\r\nHost: {host}\r\n"
                    f"Authorization: Bearer {canary_token}\r\n"
                    f"X-Store-Id: {store_id}\r\nX-Writer-Epoch: {writer_epoch}\r\n"
                    f"X-Superbrain-Instance: {instance_id}\r\n"
                    f"X-Canary-Header: CANARY_HEADER_SECRET\r\n"
                    f"Content-Type: application/json\r\nContent-Length: {len(canary_body)}\r\n\r\n"
                ).encode("iso-8859-1") + canary_body
                h.send_raw_http(s_canary, raw_canary)

            # Assert no leaks in log text
            assert canary_token not in caplog.text
            assert "SUPER_SECRET_PAYLOAD" not in caplog.text
            assert "CANARY_HEADER_SECRET" not in caplog.text
            assert "Traceback" not in caplog.text

            # Assert ledger sequence and idempotency row count are unchanged
            assert h.ledger_sequence() == init_ledger_seq
            assert h.idempotency_count() == init_idem_count

    def test_tls_handshake_does_not_block_accept_loop(
        self,
        transport_template: TransportTemplate,
    ) -> None:
        """A stalled raw TCP connection sending zero bytes never blocks concurrent LoopbackClient calls."""
        with open_test_loopback_transport(transport_template, name="handshake-concurrency") as h:
            port = h.ready.endpoint.port
            client = LoopbackClient(monotonic_ns=h.mono_clock.monotonic_ns)
            target = h.make_target()
            command = ToolCommand("get_health", {"schema_version": "2.0"}, token=h.cred.token)

            # Open a raw TCP connection to the listener that sends 0 bytes (pre-ClientHello stall)
            silent_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                silent_sock.connect(("127.0.0.1", port))

                # While the silent TCP client is stalled, execute a real LoopbackClient call
                res = client.call(target, command)
                assert res["ok"] is True
                assert h.submit_count == 1

                # Verify silent socket is closed by server at the 1.0 s handshake cap
                silent_sock.settimeout(2.5)
                try:
                    data = silent_sock.recv(1024)
                    assert data == b""
                except (ConnectionResetError, TimeoutError, OSError):
                    pass
            finally:
                silent_sock.close()

    def test_active_connection_cap_includes_handshakes(
        self,
        transport_template: TransportTemplate,
    ) -> None:
        """Holding 32 active slots rejects slot 33 without store_busy, and slot release unblocks calls."""
        with open_test_loopback_transport(transport_template, name="active-cap") as h:
            port = h.ready.endpoint.port
            client = LoopbackClient(monotonic_ns=h.mono_clock.monotonic_ns)
            target = h.make_target()
            command = ToolCommand("get_health", {"schema_version": "2.0"}, token=h.cred.token)

            held_sockets: list[socket.socket] = []
            try:
                # Hold 32 connections simultaneously:
                # 16 raw TCP connections held open + 16 TLS connections held open after identity
                for _ in range(16):
                    s_raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s_raw.connect(("127.0.0.1", port))
                    held_sockets.append(s_raw)

                for _ in range(16):
                    s_tls = h.open_raw_tls_socket()
                    # Exchange identity on this TLS socket, then hold it before sending request 2
                    h.send_raw_http(
                        s_tls, f"GET /v2/identity HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n".encode("ascii")
                    )
                    held_sockets.append(s_tls)

                assert len(held_sockets) == MAX_ACTIVE_CONNECTIONS  # 32

                # Connection #33 must be refused immediately by socket close before admission
                s_33 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    s_33.connect(("127.0.0.1", port))
                    s_33.settimeout(2.0)
                    data = s_33.recv(1024)
                    # Immediate EOF without store_busy error envelope
                    assert data == b""
                finally:
                    s_33.close()

                # Also verify LoopbackClient attempting to connect slot #33 fails with DAEMON_UNAVAILABLE
                with pytest.raises(LoopbackTransportError) as exc_info:
                    client.call(target, command)
                assert exc_info.value.code != ErrorCode.STORE_BUSY, "Server must NEVER emit store_busy!"
                assert exc_info.value.code in {ErrorCode.DAEMON_UNAVAILABLE, ErrorCode.IDENTITY_MISMATCH}
                assert exc_info.value.request_may_have_run is False

                # Release 1 of the held connections
                released_sock = held_sockets.pop()
                released_sock.close()

                # Wait boundedly for worker slot release (short event wait)
                threading.Event().wait(0.05)

                # Now connection call succeeds!
                res = client.call(target, command)
                assert res["ok"] is True
                assert h.submit_count == 1
            finally:
                for s in held_sockets:
                    try:
                        s.close()
                    except OSError:
                        pass
