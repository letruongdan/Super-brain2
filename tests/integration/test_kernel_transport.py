"""Integration regressions for SP1 Increment 2 Task 6b.3 and 6b.4 (Loopback TLS Transport).

Covers all mandatory invariants from interface-spec.md Section 4, task-6b-3-brief.md, and task-6b-4-brief.md:
- TestTransportAdmission (6b.3):
  1. test_duplicate_length_transfer_encoding_and_pipeline_refused
  2. test_prefetched_bytes_obey_two_request_state
  3. test_untrusted_http_admission_never_reaches_owner
  4. test_tls_handshake_does_not_block_accept_loop
  5. test_active_connection_cap_includes_handshakes
- TestTransportLifecycleAndRelease (6b.4):
  1. test_identity_and_tool_share_one_socket
  2. test_shutdown_drains_with_one_grace_and_closes_transport
  3. test_policy_revoke_wins_before_release_grant
  4. test_grant_won_before_revoke_can_finish_inflight_write
  5. test_artifact_send_finalizes_only_after_full_flush
  6. test_abandoned_send_recovers_without_read_ack
  7. test_writable_client_gets_commit_unknown_before_owner_unblocks
  8. test_slow_request_bytes_consume_owner_budget
"""

from __future__ import annotations

import contextlib
import datetime as dt
import errno
import hashlib
import json
import logging
import shutil
import socket
import ssl
import threading
import time
from collections.abc import Callable, Iterator
from concurrent.futures import Future
from typing import Any

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.application.dispatch import PreparedEffect
from superbrain.application.owner_loop import OwnerLoop
from superbrain.cli_api import _loopback_server
from superbrain.cli_api._loopback_server import (
    MAX_ACTIVE_CONNECTIONS,
    LoopbackServer,
)
from superbrain.cli_api._loopback_wire import encode_call
from superbrain.cli_api.loopback import (
    LoopbackClient,
    LoopbackTarget,
    LoopbackTransportError,
)
from superbrain.composition.daemon_entry import serve
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    TOTAL_REQUEST_BUDGET_NS,
    ArtifactReadAck,
    AuthGrantStamp,
    Call,
    CallContext,
    CallResult,
    DaemonConfig,
    ObjectRef,
    OwnerReply,
    Principal,
    Ready,
    Scope,
    SendAttemptState,
    ShutdownReport,
    StoredResult,
    ToolCommand,
)
from superbrain.ports.kernel import KernelTx
from superbrain.storage.runtime import admit_existing_pair
from tests.support.inc2_child import spawn_serve_child
from tests.support.inc2_transport import (
    TransportTemplate,
    TransportTestDomain,
    clone_owner_only_tree,
    create_transport_template,
    make_trusted_test_dir,
    open_test_loopback_transport,
    read_raw_http_response,
    write_daemon_config_file,
)
from tests.support.kernel_auth import make_bootstrap_auth


@pytest.fixture(scope="module")
def transport_template() -> Iterator[TransportTemplate]:
    """Module-scoped initialized v2 kernel root + provisioned TLS material."""
    tmpl = create_transport_template("t6b-test-tmpl")
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
            active_token = transport_template.cred.token
            store_id = h.ready.endpoint.store_id
            writer_epoch = h.ready.endpoint.writer_epoch
            instance_id = h.ready.endpoint.instance_id

            valid_body = encode_call(ToolCommand("get_health", {"schema_version": "2.0"}, token=active_token))

            # 1. Duplicate Content-Length headers -> 400 Bad Request
            with h.open_raw_tls_socket() as s_dup:
                dup_req = (
                    f"GET /v2/identity HTTP/1.1\r\nHost: {host}\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n"
                ).encode("ascii")
                resp_dup = h.send_raw_http(s_dup, dup_req)
                assert b"400 Bad Request" in resp_dup or b"invalid_input" in resp_dup
                assert s_dup.recv(1024) == b""
            assert h.submit_count == 0

            # 2. Transfer-Encoding: chunked (varied casing) -> 400 Bad Request
            for te in ("chunked", "Chunked", "CHUNKED"):
                with h.open_raw_tls_socket() as s_chunked:
                    te_req = (
                        f"POST /v2/tools/call HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: {te}\r\n\r\n"
                    ).encode("ascii")
                    resp_te = h.send_raw_http(s_chunked, te_req)
                    assert b"400 Bad Request" in resp_te or b"invalid_input" in resp_te
                    assert s_chunked.recv(1024) == b""
            assert h.submit_count == 0

            # 3. Expect: 100-continue -> 0 100 Continue bytes emitted
            with h.open_raw_tls_socket() as s_expect:
                exp_req = (f"GET /v2/identity HTTP/1.1\r\nHost: {host}\r\nExpect: 100-continue\r\n\r\n").encode("ascii")
                resp_exp = h.send_raw_http(s_expect, exp_req)
                assert b"100 Continue" not in resp_exp
            assert h.submit_count == 0

            # 4. Pipelined requests refused with 400 and socket closed immediately
            with h.open_raw_tls_socket() as s_pipe1:
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
                    + b"GET /v2/identity HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
                )
                resp_pipe1 = h.send_raw_http(s_pipe1, raw1)
                assert b"400 Bad Request" in resp_pipe1 or b"invalid_input" in resp_pipe1
                assert s_pipe1.recv(1024) == b""
            assert h.submit_count == 0

            with h.open_raw_tls_socket() as s_pipe2:
                raw2 = (
                    f"GET /v2/identity HTTP/1.1\r\nHost: {host}\r\n\r\n"
                    f"POST /v2/tools/call HTTP/1.1\r\nHost: {host}\r\n"
                    f"Authorization: Bearer {active_token}\r\n"
                    f"X-Store-Id: {store_id}\r\nX-Writer-Epoch: {writer_epoch}\r\n"
                    f"X-Superbrain-Instance: {instance_id}\r\n"
                    f"Content-Type: application/json\r\nContent-Length: {len(valid_body)}\r\n\r\n"
                ).encode("iso-8859-1") + valid_body
                resp_pipe2 = h.send_raw_http(s_pipe2, raw2)
                assert b"400 Bad Request" in resp_pipe2 or b"invalid_input" in resp_pipe2
                assert s_pipe2.recv(1024) == b""
            assert h.submit_count == 0

            with h.open_raw_tls_socket() as s_pipe3:
                h.send_raw_http(s_pipe3, f"GET /v2/identity HTTP/1.1\r\nHost: {host}\r\n\r\n".encode("ascii"))
                raw3 = (
                    (
                        f"POST /v2/tools/call HTTP/1.1\r\nHost: {host}\r\n"
                        f"Authorization: Bearer {active_token}\r\n"
                        f"X-Store-Id: {store_id}\r\nX-Writer-Epoch: {writer_epoch}\r\n"
                        f"X-Superbrain-Instance: {instance_id}\r\n"
                        f"Content-Type: application/json\r\nContent-Length: {len(valid_body)}\r\n\r\n"
                    ).encode("iso-8859-1")
                    + valid_body
                    + b"GET /v2/identity HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
                )
                resp_pipe3 = h.send_raw_http(s_pipe3, raw3)
                assert b"400 Bad Request" in resp_pipe3 or b"invalid_input" in resp_pipe3
                assert s_pipe3.recv(1024) == b""
            assert h.submit_count == 0

            # 5. Oversized Content-Length > 1 MiB -> 413 Payload Too Large
            with h.open_raw_tls_socket() as s_over:
                over_req = (
                    f"POST /v2/tools/call HTTP/1.1\r\nHost: {host}\r\n"
                    f"Authorization: Bearer {active_token}\r\n"
                    f"X-Store-Id: {store_id}\r\nX-Writer-Epoch: {writer_epoch}\r\n"
                    f"X-Superbrain-Instance: {instance_id}\r\n"
                    f"Content-Type: application/json\r\nContent-Length: 1048577\r\n\r\n"
                ).encode("ascii")
                resp_over = h.send_raw_http(s_over, over_req)
                assert b"413" in resp_over or b"invalid_input" in resp_over
                assert s_over.recv(1024) == b""
            assert h.submit_count == 0

            # 6. Overlong 5,000-digit Content-Length -> 413 and clean subsequent call
            with h.open_raw_tls_socket() as s_cl5000:
                raw_cl5000 = (
                    f"GET /v2/identity HTTP/1.1\r\nHost: {host}\r\nContent-Length: " + ("9" * 5000) + "\r\n\r\n"
                ).encode("ascii")
                resp_cl5000 = h.send_raw_http(s_cl5000, raw_cl5000)
                assert b"413" in resp_cl5000 and b"invalid_input" in resp_cl5000
                assert s_cl5000.recv(1024) == b""
            assert h.submit_count == 0

            client_rec = h.open_client()
            target_rec = h.make_target()
            res_rec = client_rec.call(
                target_rec,
                ToolCommand("get_health", {"schema_version": "2.0"}, token=active_token),
            )
            assert res_rec["ok"] is True
            assert h.submit_count == 1

    def test_prefetched_bytes_obey_two_request_state(
        self,
        transport_template: TransportTemplate,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """State machine allows at most 2 requests, closes cleanly, and refuses buffered request 3."""
        with open_test_loopback_transport(transport_template, name="two-req") as h:
            host = f"127.0.0.1:{h.ready.endpoint.port}"
            active_token = transport_template.cred.token
            store_id = h.ready.endpoint.store_id
            writer_epoch = h.ready.endpoint.writer_epoch
            instance_id = h.ready.endpoint.instance_id

            valid_body = encode_call(ToolCommand("get_health", {"schema_version": "2.0"}, token=active_token))

            # Part 1: Normal 2-request lifecycle closes cleanly on EOF
            with h.open_raw_tls_socket() as s_clean:
                # Request 1: GET /v2/identity
                resp1 = h.send_raw_http(s_clean, f"GET /v2/identity HTTP/1.1\r\nHost: {host}\r\n\r\n".encode("ascii"))
                assert b"200 OK" in resp1
                ident = json.loads(resp1.split(b"\r\n\r\n", 1)[1].decode("utf-8"))
                assert ident == {
                    "store_id": store_id,
                    "writer_epoch": writer_epoch,
                    "instance_id": instance_id,
                    "contract": "mcp-tools-v2",
                }

                # Request 2: POST /v2/tools/call
                req2 = (
                    f"POST /v2/tools/call HTTP/1.1\r\nHost: {host}\r\n"
                    f"Authorization: Bearer {active_token}\r\n"
                    f"X-Store-Id: {store_id}\r\nX-Writer-Epoch: {writer_epoch}\r\n"
                    f"X-Superbrain-Instance: {instance_id}\r\n"
                    f"Content-Type: application/json\r\nContent-Length: {len(valid_body)}\r\n\r\n"
                ).encode("iso-8859-1") + valid_body
                resp2 = h.send_raw_http(s_clean, req2)
                assert b"200 OK" in resp2
                tool_data = json.loads(resp2.split(b"\r\n\r\n", 1)[1].decode("utf-8"))
                assert tool_data.get("ok") is True

                # Socket must close on EOF
                assert s_clean.recv(1024) == b""
            assert h.submit_count == 1

            # Part 2: Prefetched 3rd request in same TLS/socket record after request 2
            with h.open_raw_tls_socket() as s_prefetch:
                h.send_raw_http(s_prefetch, f"GET /v2/identity HTTP/1.1\r\nHost: {host}\r\n\r\n".encode("ascii"))
                req2_and_3 = (
                    (
                        f"POST /v2/tools/call HTTP/1.1\r\nHost: {host}\r\n"
                        f"Authorization: Bearer {active_token}\r\n"
                        f"X-Store-Id: {store_id}\r\nX-Writer-Epoch: {writer_epoch}\r\n"
                        f"X-Superbrain-Instance: {instance_id}\r\n"
                        f"Content-Type: application/json\r\nContent-Length: {len(valid_body)}\r\n\r\n"
                    ).encode("iso-8859-1")
                    + valid_body
                    + f"GET /v2/identity HTTP/1.1\r\nHost: {host}\r\n\r\n".encode("ascii")
                )

                resp_prefetch = h.send_raw_http(s_prefetch, req2_and_3)
                assert b"400 Bad Request" in resp_prefetch or b"invalid_input" in resp_prefetch
                assert s_prefetch.recv(1024) == b""
            assert h.submit_count == 1

            # Part 3: t0 deadline check applies even when bytes were buffered
            ident_entered = threading.Event()
            orig_handle_ident: Callable[..., bool] = vars(_loopback_server)["handle_identity_request"]

            def _sync_handle_ident(*args: Any, **kwargs: Any) -> bool:
                ident_entered.set()
                return bool(orig_handle_ident(*args, **kwargs))

            with monkeypatch.context() as mp:
                mp.setattr(_loopback_server, "handle_identity_request", _sync_handle_ident)
                with h.open_raw_tls_socket() as s_dl:
                    assert ident_entered.wait(timeout=2.0), "server did not enter handle_identity_request"
                    h.mono_clock.advance_ns(TOTAL_REQUEST_BUDGET_NS + 100_000_000)
                    try:
                        req_dl = f"GET /v2/identity HTTP/1.1\r\nHost: {host}\r\n\r\n".encode("ascii")
                        resp_dl = h.send_raw_http(s_dl, req_dl)
                        assert b"408" in resp_dl or b"deadline_exceeded" in resp_dl or resp_dl == b""
                        assert s_dl.recv(1024) == b""
                    except (ConnectionError, ssl.SSLError):
                        pass
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
            port = h.ready.endpoint.port
            active_token = transport_template.cred.token
            store_id = h.ready.endpoint.store_id
            writer_epoch = h.ready.endpoint.writer_epoch
            instance_id = h.ready.endpoint.instance_id

            canary_token = "canary-token-secret-7733"
            canary_arg = "canary-arg-payload-9944"
            valid_body = encode_call(
                ToolCommand("get_health", {"schema_version": "2.0", "canary": canary_arg}, token=active_token)
            )

            init_ledger_seq = h.ledger_sequence()
            init_idem_count = h.idempotency_count()
            caplog.set_level(logging.DEBUG)

            def assert_refused_on_r1(request_bytes: bytes, expected_status: bytes = b"400") -> None:
                with h.open_raw_tls_socket() as s:
                    resp = h.send_raw_http(s, request_bytes)
                    assert expected_status in resp or resp == b""
                    assert s.recv(1024) == b""
                assert h.submit_count == 0

            # 1. Host header validation
            assert_refused_on_r1(b"GET /v2/identity HTTP/1.1\r\n\r\n")
            assert_refused_on_r1(f"GET /v2/identity HTTP/1.1\r\nHost: 127.0.0.1:{port + 1}\r\n\r\n".encode("ascii"))
            assert_refused_on_r1(b"GET /v2/identity HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            assert_refused_on_r1(f"GET /v2/identity HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n".encode("ascii"))
            assert_refused_on_r1(f"GET /v2/identity HTTP/1.1\r\nHost: {host}\r\nhost: {host}\r\n\r\n".encode("ascii"))

            # 2. Origin header validation -> 403 Forbidden
            assert_refused_on_r1(
                f"GET /v2/identity HTTP/1.1\r\nHost: {host}\r\nOrigin: https://evil.example\r\n\r\n".encode("ascii"),
                expected_status=b"403",
            )
            assert_refused_on_r1(
                f"GET /v2/identity HTTP/1.1\r\nHost: {host}\r\nOrigin:\r\n\r\n".encode("ascii"),
                expected_status=b"403",
            )

            # 3. Non-loopback peer IP accept guard
            orig_accept = socket.socket.accept
            inject_active = False
            hook_entered = threading.Event()

            def mock_non_loopback_accept(sock_self: socket.socket) -> tuple[socket.socket, tuple[str, int]]:
                nonlocal inject_active
                if sock_self is h.bound.sock:
                    hook_entered.set()
                conn, addr = orig_accept(sock_self)
                if inject_active and sock_self is h.bound.sock:
                    inject_active = False
                    return conn, ("192.0.2.99", addr[1])
                return conn, addr

            with monkeypatch.context() as mp:
                mp.setattr(socket.socket, "accept", mock_non_loopback_accept)
                assert hook_entered.wait(timeout=1.0), "server accept loop did not enter patched accept"
                inject_active = True
                try:
                    with socket.create_connection((h.ready.endpoint.host, h.ready.endpoint.port), timeout=2.0) as s_raw:
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
            assert_refused_on_r1(
                f"POST /v2/identity HTTP/1.1\r\nHost: {host}\r\nContent-Length: 0\r\n\r\n".encode("ascii")
            )
            assert_refused_on_r1(
                f"GET /v2/identity HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {active_token}\r\n\r\n".encode(
                    "ascii"
                )
            )
            assert_refused_on_r1(f"GET /v2/identity HTTP/1.0\r\nHost: {host}\r\n\r\n".encode("ascii"))
            assert_refused_on_r1(f"GET //v2/identity HTTP/1.1\r\nHost: {host}\r\n\r\n".encode("ascii"))
            assert_refused_on_r1(f"GET /v2/identity?query=1 HTTP/1.1\r\nHost: {host}\r\n\r\n".encode("ascii"))
            assert_refused_on_r1(
                f"GET http://127.0.0.1:{port}/v2/identity HTTP/1.1\r\nHost: {host}\r\n\r\n".encode("ascii")
            )
            assert_refused_on_r1(
                f"POST /v2/tools/call HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {active_token}\r\n"
                f"X-Store-Id: {store_id}\r\nX-Writer-Epoch: {writer_epoch}\r\n"
                f"X-Superbrain-Instance: {instance_id}\r\nContent-Length: {len(valid_body)}\r\n\r\n".encode(
                    "iso-8859-1"
                )
                + valid_body
            )

            # 5. Authorization header on State 1 -> 401 Unauthorized
            def assert_refused_on_r2(tool_headers: str, expected_status: bytes = b"401") -> None:
                with h.open_raw_tls_socket() as s:
                    h.send_raw_http(s, f"GET /v2/identity HTTP/1.1\r\nHost: {host}\r\n\r\n".encode("ascii"))
                    req = (
                        f"POST /v2/tools/call HTTP/1.1\r\nHost: {host}\r\n{tool_headers}"
                        f"X-Store-Id: {store_id}\r\nX-Writer-Epoch: {writer_epoch}\r\n"
                        f"X-Superbrain-Instance: {instance_id}\r\n"
                        f"Content-Type: application/json\r\nContent-Length: {len(valid_body)}\r\n\r\n"
                    ).encode("iso-8859-1") + valid_body
                    resp = h.send_raw_http(s, req)
                    assert expected_status in resp or resp == b""
                    assert s.recv(1024) == b""
                assert h.submit_count == 0

            assert_refused_on_r2("")
            assert_refused_on_r2("Authorization: Basic dXNlcjpwYXNz\r\n")
            assert_refused_on_r2("Authorization: Bearer \r\n")
            assert_refused_on_r2(f"Authorization: Bearer {active_token}\r\nauthorization: Bearer {active_token}\r\n")
            assert_refused_on_r2("Authorization: Bearer token with spaces\r\n")

            # 6. Identity tuple on State 1 -> 409 Conflict
            def assert_identity_mismatch_on_r2(tuple_headers: str) -> None:
                with h.open_raw_tls_socket() as s:
                    h.send_raw_http(s, f"GET /v2/identity HTTP/1.1\r\nHost: {host}\r\n\r\n".encode("ascii"))
                    req = (
                        f"POST /v2/tools/call HTTP/1.1\r\nHost: {host}\r\n"
                        f"Authorization: Bearer {active_token}\r\n{tuple_headers}"
                        f"Content-Type: application/json\r\nContent-Length: {len(valid_body)}\r\n\r\n"
                    ).encode("iso-8859-1") + valid_body
                    resp = h.send_raw_http(s, req)
                    assert b"409" in resp or b"identity_mismatch" in resp or resp == b""
                    assert s.recv(1024) == b""
                assert h.submit_count == 0

            assert_identity_mismatch_on_r2(
                f"X-Writer-Epoch: {writer_epoch}\r\nX-Superbrain-Instance: {instance_id}\r\n"
            )
            assert_identity_mismatch_on_r2(
                f"X-Store-Id: {store_id}-wrong\r\nX-Writer-Epoch: {writer_epoch}\r\n"
                f"X-Superbrain-Instance: {instance_id}\r\n"
            )
            assert_identity_mismatch_on_r2(
                f"X-Store-Id: {store_id}\r\nX-Writer-Epoch: {writer_epoch + 1}\r\n"
                f"X-Superbrain-Instance: {instance_id}\r\n"
            )
            assert_identity_mismatch_on_r2(
                f"X-Store-Id: {store_id}\r\nX-Writer-Epoch: {writer_epoch}\r\n"
                f"X-Superbrain-Instance: {instance_id}-wrong\r\n"
            )
            assert_identity_mismatch_on_r2(
                f"X-Store-Id: {store_id}\r\nX-Writer-Epoch: 0{writer_epoch}\r\nX-Superbrain-Instance: {instance_id}\r\n"
            )
            assert_identity_mismatch_on_r2(
                f"X-Store-Id: {store_id}\r\nX-Writer-Epoch: +{writer_epoch}\r\nX-Superbrain-Instance: {instance_id}\r\n"
            )

            # 7. Positive unauthenticated token DOES reach owner
            unknown_token = f"cred-unknown-0000.{'a' * 43}"
            unknown_body = encode_call(ToolCommand("get_health", {"schema_version": "2.0"}, token=unknown_token))
            with h.open_raw_tls_socket() as s_unauth:
                h.send_raw_http(s_unauth, f"GET /v2/identity HTTP/1.1\r\nHost: {host}\r\n\r\n".encode("ascii"))
                req_unauth = (
                    f"POST /v2/tools/call HTTP/1.1\r\nHost: {host}\r\n"
                    f"Authorization: Bearer {unknown_token}\r\n"
                    f"X-Store-Id: {store_id}\r\nX-Writer-Epoch: {writer_epoch}\r\n"
                    f"X-Superbrain-Instance: {instance_id}\r\n"
                    f"Content-Type: application/json\r\nContent-Length: {len(unknown_body)}\r\n\r\n"
                ).encode("iso-8859-1") + unknown_body
                resp_unauth = h.send_raw_http(s_unauth, req_unauth)
                assert b"200 OK" in resp_unauth
                payload = json.loads(resp_unauth.split(b"\r\n\r\n", 1)[1].decode("utf-8"))
                assert payload.get("ok") is False
                assert payload.get("error", {}).get("code") == "unauthenticated"
            assert h.submit_count == 1

            # 8. Confidentiality & Immutability checks
            with h.open_raw_tls_socket() as s_leak:
                leak_req = (
                    f"GET /v2/identity HTTP/1.1\r\nHost: {host}\r\nX-Canary-Header: {canary_token}\r\n\r\n"
                ).encode("ascii")
                h.send_raw_http(s_leak, leak_req)

            all_logs = caplog.text
            assert canary_token not in all_logs, f"Canary token leaked in logs: {all_logs}"
            assert canary_arg not in all_logs, f"Canary arg leaked in logs: {all_logs}"
            assert "Traceback" not in all_logs, f"Traceback leaked in admission logs: {all_logs}"

            # 9. Hostile slow drip during graceful close drain cannot hold connection slot
            with h.open_raw_tls_socket() as s_drip:
                s_drip.sendall(f"GET /wrong-path HTTP/1.1\r\nHost: {host}\r\n\r\n".encode("ascii"))
                resp_400 = read_raw_http_response(s_drip)
                assert b"400 Bad Request" in resp_400

                drip_stop = threading.Event()

                def _drip_worker() -> None:
                    for _ in range(250):
                        if drip_stop.is_set():
                            break
                        try:
                            s_drip.send(b"x")
                            time.sleep(0.0004)
                        except OSError:
                            break

                th_drip = threading.Thread(target=_drip_worker)
                th_drip.start()
                try:
                    t_drain_start = time.perf_counter()
                    while time.perf_counter() - t_drain_start < 0.20:
                        with h.server._lock:
                            if h.server._active_slots == 0:
                                break
                        time.sleep(0.002)
                    drain_duration = time.perf_counter() - t_drain_start
                    assert drain_duration < 0.035, f"Graceful close drain held for {drain_duration:.4f}s (> 0.035s)"
                finally:
                    drip_stop.set()
                    th_drip.join(timeout=1.0)

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

            silent_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                silent_sock.connect(("127.0.0.1", port))
                res = client.call(target, command)
                assert res["ok"] is True
                assert h.submit_count == 1
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
                for _ in range(16):
                    s_raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s_raw.connect(("127.0.0.1", port))
                    held_sockets.append(s_raw)

                for _ in range(16):
                    s_tls = h.open_raw_tls_socket()
                    h.send_raw_http(
                        s_tls, f"GET /v2/identity HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n".encode("ascii")
                    )
                    held_sockets.append(s_tls)

                assert len(held_sockets) == MAX_ACTIVE_CONNECTIONS

                s_33 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    s_33.connect(("127.0.0.1", port))
                    s_33.settimeout(2.0)
                    data = s_33.recv(1024)
                    assert data == b""
                finally:
                    s_33.close()

                with pytest.raises(LoopbackTransportError) as exc_info:
                    client.call(target, command)
                assert exc_info.value.code != ErrorCode.STORE_BUSY, "Server must NEVER emit store_busy!"
                assert exc_info.value.code in {ErrorCode.DAEMON_UNAVAILABLE, ErrorCode.IDENTITY_MISMATCH}
                assert exc_info.value.request_may_have_run is False

                released_sock = held_sockets.pop()
                released_sock.close()

                threading.Event().wait(0.05)

                res = client.call(target, command)
                assert res["ok"] is True
                assert h.submit_count == 1
            finally:
                for s in held_sockets:
                    try:
                        s.close()
                    except OSError:
                        pass


class FinalizeFlushDomain(TransportTestDomain):
    """Transport test domain that records and enforces read_acks on record_outcome."""

    def supports_tool(self, tool: str, *, deep: bool = False) -> bool:
        if deep:
            return False
        return tool in {"get_health", "get_artifact", "prepare_task", "submit_episode", "get_job", "record_outcome"}

    def prepare_mutation(self, call: Call, ctx: CallContext, *, now: dt.datetime) -> PreparedEffect:
        if call.tool != "record_outcome":
            return super().prepare_mutation(call, ctx, now=now)

        res_uuid = new_id()
        raw_acks = call.arguments.get("read_acks")
        blob = canonical_json(
            {
                "schema": "transport-test-domain-v1",
                "tool": "record_outcome",
                "result_id": res_uuid,
            }
        )
        ref = ObjectRef(kind="episode", id=res_uuid, revision=1, digest=digest_bytes(blob))

        def _apply(tx: KernelTx) -> StoredResult:
            if isinstance(raw_acks, list) and raw_acks:
                for ack_dict in raw_acks:
                    if isinstance(ack_dict, dict):
                        rec_id = str(ack_dict.get("served_receipt_id", ""))
                        attempt = tx.read_send_attempt(rec_id)
                        if attempt is not None and attempt.state is SendAttemptState.PENDING:
                            raise BrainError(ErrorCode.IN_PROGRESS, "operation in progress")
                        if attempt is not None and attempt.state is SendAttemptState.SERVED_ONLY:
                            ack_obj = ArtifactReadAck(
                                ack_id=new_id(),
                                served_receipt_id=rec_id,
                                principal_id=ctx.principal.principal_id,
                                task_id=attempt.task_id,
                                revision=attempt.revision,
                                resource_digests=attempt.resource_digests,
                            )
                            tx.save_read_ack(ack_obj)
            tx.hold_blob(blob, holder_id=res_uuid)
            return StoredResult(result_id=res_uuid, assignment_id=None, refs=(ref,))

        return PreparedEffect(blobs=(blob,), apply=_apply)

    def render_stored(
        self,
        result: StoredResult,
        principal: Principal,
        *,
        selected_scope: Scope | None,
    ) -> dict[str, JsonValue]:
        if result.refs and result.refs[0].kind == "episode":
            return {"outcome": "success", "status": "declared"}
        return super().render_stored(result, principal, selected_scope=selected_scope)


class TestTransportLifecycleAndRelease:
    """Task 6b.4 release gate, send attempt finalization, and daemon lifecycle regressions."""

    def test_identity_and_tool_share_one_socket(
        self,
        transport_template: TransportTemplate,
    ) -> None:
        """Foreground serve child shares 1 socket for identity->tool->EOF, and LoopbackClient calls match ACLs."""
        assert transport_template.global_job_id is not None
        assert transport_template.scoped_job_id is not None
        assert transport_template.ws_a is not None
        assert transport_template.cred_bob is not None

        case_dir = make_trusted_test_dir("t6b4-child-share")
        data_root = case_dir / "data"
        clone_owner_only_tree(transport_template.root, data_root)
        config_path = case_dir / "daemon-config.json"
        write_daemon_config_file(
            config_path,
            data_root=data_root,
            expected_store_id=transport_template.store_id,
            cert_path=transport_template.tls.cert_path,
            key_path=transport_template.tls.key_path,
        )

        try:
            with spawn_serve_child(config_path) as child:
                ep, sha = child.wait_ready()
                assert sha == transport_template.tls.leaf_cert_sha256
                endpoint_path = data_root / "endpoint.json"
                assert endpoint_path.read_bytes() == ep.encode_canonical()

                # 1. Manual TLS socket: GET -> POST -> EOF on SAME socket
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.load_verify_locations(cadata=transport_template.tls.ca_cert_path.read_text(encoding="utf-8"))
                ctx.check_hostname = True
                with socket.create_connection((ep.host, ep.port), timeout=2.0) as raw_sock:
                    with ctx.wrap_socket(raw_sock, server_hostname="127.0.0.1") as tls_sock:
                        der = tls_sock.getpeercert(binary_form=True)
                        assert der is not None
                        actual_sha = hashlib.sha256(der).hexdigest()
                        assert actual_sha == sha

                        # GET /v2/identity
                        tls_sock.sendall(
                            f"GET /v2/identity HTTP/1.1\r\nHost: 127.0.0.1:{ep.port}\r\n\r\n".encode("ascii")
                        )
                        ident_raw = read_raw_http_response(tls_sock)
                        assert b"200 OK" in ident_raw
                        ident_json = json.loads(ident_raw.split(b"\r\n\r\n", 1)[1].decode("utf-8"))
                        assert ident_json == {
                            "store_id": ep.store_id,
                            "writer_epoch": ep.writer_epoch,
                            "instance_id": ep.instance_id,
                            "contract": "mcp-tools-v2",
                        }

                        # POST /v2/tools/call on that SAME socket
                        body = encode_call(
                            ToolCommand(
                                "get_health",
                                {"schema_version": "2.0"},
                                token=transport_template.cred.token,
                            )
                        )
                        req = (
                            f"POST /v2/tools/call HTTP/1.1\r\n"
                            f"Host: 127.0.0.1:{ep.port}\r\n"
                            f"Authorization: Bearer {transport_template.cred.token}\r\n"
                            f"X-Store-Id: {ep.store_id}\r\n"
                            f"X-Writer-Epoch: {ep.writer_epoch}\r\n"
                            f"X-Superbrain-Instance: {ep.instance_id}\r\n"
                            f"Content-Type: application/json\r\n"
                            f"Content-Length: {len(body)}\r\n\r\n"
                        ).encode("iso-8859-1") + body
                        tls_sock.sendall(req)
                        tool_raw = read_raw_http_response(tls_sock)
                        assert b"200 OK" in tool_raw
                        tool_json = json.loads(tool_raw.split(b"\r\n\r\n", 1)[1].decode("utf-8"))
                        assert tool_json.get("ok") is True

                        # EOF immediately afterward
                        tls_sock.settimeout(1.5)
                        assert tls_sock.recv(1024) == b""

                # 2. Independent LoopbackClient calls against live subprocess daemon
                client = LoopbackClient(monotonic_ns=time.monotonic_ns)
                target = LoopbackTarget(
                    endpoint=ep,
                    expected_store_id=transport_template.store_id,
                    ca_pem=transport_template.tls.ca_cert_path.read_text(encoding="utf-8"),
                    leaf_cert_sha256=sha,
                )
                call_budget = 1_500_000_000

                # Authorized global get_job (Dan) -> ok=True
                dl = time.monotonic_ns() + call_budget
                res_global = client.call(
                    target,
                    ToolCommand(
                        "get_job",
                        {"schema_version": "2.0", "job_id": transport_template.global_job_id},
                        token=transport_template.cred.token,
                    ),
                    deadline_ns=dl,
                )
                assert res_global["ok"] is True
                assert isinstance(res_global["data"], dict)
                assert res_global["data"]["job_id"] == transport_template.global_job_id

                # Authorized matching-scope get_job (Dan) -> ok=True
                scope_a = Scope(transport_template.ws_a.repo_id, transport_template.ws_a.checkout_id)
                dl = time.monotonic_ns() + call_budget
                res_scoped = client.call(
                    target,
                    ToolCommand(
                        "get_job",
                        {"schema_version": "2.0", "job_id": transport_template.scoped_job_id},
                        token=transport_template.cred.token,
                        selected_scope=scope_a,
                    ),
                    deadline_ns=dl,
                )
                assert res_scoped["ok"] is True
                assert isinstance(res_scoped["data"], dict)
                assert res_scoped["data"]["job_id"] == transport_template.scoped_job_id

                # Cross-scope / other-principal get_job (Bob) -> ok=False, code="not_found"
                dl = time.monotonic_ns() + call_budget
                res_cross = client.call(
                    target,
                    ToolCommand(
                        "get_job",
                        {"schema_version": "2.0", "job_id": transport_template.global_job_id},
                        token=transport_template.cred_bob.token,
                    ),
                    deadline_ns=dl,
                )
                assert res_cross["ok"] is False
                assert isinstance(res_cross["error"], dict)
                assert res_cross["error"]["code"] == "not_found"

                # Production capability_unavailable (prepare_task) -> ok=False, code="capability_unavailable"
                dl = time.monotonic_ns() + call_budget
                res_prep = client.call(
                    target,
                    ToolCommand(
                        "prepare_task",
                        {
                            "schema_version": "2.0",
                            "workspace_id": transport_template.ws_a.repo_id,
                            "checkout_id": transport_template.ws_a.checkout_id,
                            "task_id": "t-1",
                            "description": "test task",
                            "context_budget_tokens": 100,
                            "idempotency_key": "idem-prep-task-0001",
                        },
                        token=transport_template.cred.token,
                        selected_scope=scope_a,
                    ),
                    deadline_ns=dl,
                )
                assert res_prep["ok"] is False
                assert isinstance(res_prep["error"], dict)
                assert res_prep["error"]["code"] == "capability_unavailable"

                # Production capability_unavailable (get_health deep=True) -> ok=False, code="capability_unavailable"
                dl = time.monotonic_ns() + call_budget
                res_deep = client.call(
                    target,
                    ToolCommand(
                        "get_health",
                        {"schema_version": "2.0", "deep": True, "idempotency_key": "idem-health-deep-1"},
                        token=transport_template.cred.token,
                    ),
                    deadline_ns=dl,
                )
                assert res_deep["ok"] is False
                assert isinstance(res_deep["error"], dict)
                assert res_deep["error"]["code"] == "capability_unavailable"

                # Stop child cleanly via control pipe
                stop_out = child.request_stop_and_wait()
                assert stop_out.ok is True
                assert stop_out.exit_code == 0
        finally:
            shutil.rmtree(case_dir, ignore_errors=True)

    def test_shutdown_drains_with_one_grace_and_closes_transport(
        self,
        transport_template: TransportTemplate,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Shutdown drains with one grace, closes transport sockets at cutoff, and recovers cleanly on restart."""
        case_dir = make_trusted_test_dir("t6b4-shutdown-drain")
        data_root = case_dir / "data"
        clone_owner_only_tree(transport_template.root, data_root)
        cfg = DaemonConfig(
            version=1,
            data_root=data_root,
            expected_store_id=transport_template.store_id,
            cert_path=transport_template.tls.cert_path,
            key_path=transport_template.tls.key_path,
        )

        assert transport_template.ws_a is not None
        try:
            # (a) Clean single-grace drain + cutoff abort
            stop_event = threading.Event()
            ready_ev = threading.Event()
            ready_holder: list[Ready] = []
            owner_holder: list[OwnerLoop] = []
            domain = TransportTestDomain(
                ws_a=transport_template.ws_a,
                pause_idem_keys={"idem-shut-pause-001"},
            )
            domain.allow_apply_finish.clear()
            serve_res: list[int] = []

            def _on_ready(r: Ready, owner: OwnerLoop) -> None:
                ready_holder.append(r)
                owner_holder.append(owner)
                ready_ev.set()

            t: threading.Thread | None = None
            th_call: threading.Thread | None = None
            s_raw: socket.socket | None = None
            s_post_raw: socket.socket | None = None
            s_post: ssl.SSLSocket | None = None
            try:
                t = threading.Thread(
                    target=lambda: serve_res.append(
                        serve(
                            cfg,
                            stop_event=stop_event,
                            shutdown_grace_s=0.06,
                            on_ready=_on_ready,
                            domain=domain,
                        )
                    )
                )
                t.start()
                assert ready_ev.wait(timeout=5.0), "serve did not emit on_ready"
                ep = ready_holder[0].endpoint

                # Open a stalled raw TCP connection (sends 0 bytes)
                s_raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s_raw.connect(("127.0.0.1", ep.port))

                # Open a TLS connection and send partial POST body
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.load_verify_locations(cadata=transport_template.tls.ca_cert_path.read_text(encoding="utf-8"))
                s_post_raw = socket.create_connection(("127.0.0.1", ep.port), timeout=2.0)
                s_post = ctx.wrap_socket(s_post_raw, server_hostname="127.0.0.1")
                # Complete State 0 (GET /v2/identity) on s_post first
                s_post.sendall(f"GET /v2/identity HTTP/1.1\r\nHost: 127.0.0.1:{ep.port}\r\n\r\n".encode("ascii"))
                assert b"200 OK" in read_raw_http_response(s_post)

                s_post.sendall(
                    (
                        f"POST /v2/tools/call HTTP/1.1\r\nHost: 127.0.0.1:{ep.port}\r\n"
                        f"Authorization: Bearer {transport_template.cred.token}\r\n"
                        f"X-Store-Id: {ep.store_id}\r\nX-Writer-Epoch: {ep.writer_epoch}\r\n"
                        f"X-Superbrain-Instance: {ep.instance_id}\r\n"
                        f"Content-Type: application/json\r\nContent-Length: 100\r\n\r\npartial"
                    ).encode("iso-8859-1")
                )

                # Trigger an in-flight tool call that pauses inside SQLite transaction
                client = LoopbackClient(monotonic_ns=time.monotonic_ns)
                target = LoopbackTarget(
                    endpoint=ep,
                    expected_store_id=transport_template.store_id,
                    ca_pem=transport_template.tls.ca_cert_path.read_text(encoding="utf-8"),
                    leaf_cert_sha256=transport_template.tls.leaf_cert_sha256,
                )
                cmd_pause = ToolCommand(
                    "submit_episode",
                    {
                        "schema_version": "2.0",
                        "task_id": "task-ep-1",
                        "session_id": "sess-1",
                        "workspace_id": transport_template.ws_a.repo_id,
                        "checkout_id": transport_template.ws_a.checkout_id,
                        "evidence": [],
                        "idempotency_key": "idem-shut-pause-001",
                    },
                    token=transport_template.cred.token,
                    selected_scope=Scope(transport_template.ws_a.repo_id, transport_template.ws_a.checkout_id),
                )

                def _run_pause_call() -> None:
                    with contextlib.suppress(LoopbackTransportError):
                        client.call(
                            target,
                            cmd_pause,
                            deadline_ns=time.monotonic_ns() + 1_500_000_000,
                        )

                th_call = threading.Thread(target=_run_pause_call)
                th_call.start()
                assert domain.apply_entered.wait(timeout=2.0)

                # Trigger stop
                stop_event.set()

                # Accepted sockets are closed promptly at cutoff
                s_raw.settimeout(1.0)
                try:
                    assert s_raw.recv(1024) == b""
                except TimeoutError:
                    pytest.fail("accepted socket s_raw remained open past cutoff")
                except OSError:
                    pass

                s_post.settimeout(1.0)
                try:
                    assert s_post.recv(1024) == b""
                except TimeoutError:
                    pytest.fail("accepted socket s_post remained open past cutoff")
                except OSError:
                    pass

                # writer.lock remains held while SQLite transaction is still held
                with pytest.raises(BrainError) as exc_lock:
                    admit_existing_pair(data_root, transport_template.store_id, os_adapters(), purpose="serve")
                assert exc_lock.value.code == ErrorCode.WRITER_HELD

                # EOF on either accepted socket can precede the owner cutoff.
                # Keep the SQLite operation parked through the actual pinned cutoff.
                owner = owner_holder[0]
                observe_cutoff_until = time.perf_counter() + 1.0
                while owner.ready is not None and time.perf_counter() < observe_cutoff_until:
                    threading.Event().wait(0.001)
                assert owner.ready is None, "owner did not begin shutdown after transport quiesce"
                owner_cutoff = owner._stop_wall_deadline
                assert 0.0 < owner_cutoff <= observe_cutoff_until + 0.06
                while (remaining := owner_cutoff - time.perf_counter()) > 0:
                    threading.Event().wait(remaining)

                domain.allow_apply_finish.set()
                t.join(timeout=3.0)
                th_call.join(timeout=2.0)
                assert serve_res == [1], f"Expected OVERRUN exit code 1, got {serve_res!r}"
            finally:
                stop_event.set()
                domain.allow_apply_finish.set()
                if s_raw is not None:
                    try:
                        s_raw.close()
                    except OSError:
                        pass
                if s_post is not None:
                    try:
                        s_post.close()
                    except OSError:
                        pass
                if s_post_raw is not None:
                    try:
                        s_post_raw.close()
                    except OSError:
                        pass
                if th_call is not None:
                    th_call.join(timeout=2.0)
                if t is not None:
                    t.join(timeout=3.0)

            # Restart serve on the same root: increments epoch with fresh instance_id
            stop_event2 = threading.Event()
            ready_ev2 = threading.Event()
            ready_holder2: list[Ready] = []

            def _on_ready2(r: Ready, _l: OwnerLoop) -> None:
                ready_holder2.append(r)
                ready_ev2.set()

            t2: threading.Thread | None = None
            try:
                t2 = threading.Thread(
                    target=lambda: serve(
                        cfg,
                        stop_event=stop_event2,
                        shutdown_grace_s=0.05,
                        on_ready=_on_ready2,
                    )
                )
                t2.start()
                assert ready_ev2.wait(timeout=5.0)
                ep2 = ready_holder2[0].endpoint
                assert ep2.writer_epoch == ep.writer_epoch + 1
                assert ep2.instance_id != ep.instance_id

                target2 = LoopbackTarget(
                    endpoint=ep2,
                    expected_store_id=transport_template.store_id,
                    ca_pem=transport_template.tls.ca_cert_path.read_text(encoding="utf-8"),
                    leaf_cert_sha256=transport_template.tls.leaf_cert_sha256,
                )
                res_clean = client.call(
                    target2,
                    ToolCommand("get_health", {"schema_version": "2.0"}, token=transport_template.cred.token),
                    deadline_ns=time.monotonic_ns() + 1_500_000_000,
                )
                assert res_clean["ok"] is True
            finally:
                stop_event2.set()
                if t2 is not None:
                    t2.join(timeout=3.0)

            # (b) Transport startup failure after endpoint.json publish
            case_dir_b = make_trusted_test_dir("t6b4-fail-start")
            data_root_b = case_dir_b / "data"
            clone_owner_only_tree(transport_template.root, data_root_b)
            cfg_b = DaemonConfig(
                version=1,
                data_root=data_root_b,
                expected_store_id=transport_template.store_id,
                cert_path=transport_template.tls.cert_path,
                key_path=transport_template.tls.key_path,
            )
            try:
                with monkeypatch.context() as mp:

                    def mock_fail_start(self: Any) -> None:
                        raise BrainError(ErrorCode.IO_ERROR, "I/O error")

                    mp.setattr(LoopbackServer, "start", mock_fail_start)
                    on_ready_b_called = False

                    def _on_ready_b(_r: Ready, _l: OwnerLoop) -> None:
                        nonlocal on_ready_b_called
                        on_ready_b_called = True

                    ret = serve(cfg_b, on_ready=_on_ready_b)
                    assert ret == 1
                    assert on_ready_b_called is False
                    assert not (data_root_b / "endpoint.json").exists()
                    with admit_existing_pair(
                        data_root_b, transport_template.store_id, os_adapters(), purpose="serve"
                    ) as admitted:
                        assert admitted is not None
            finally:
                shutil.rmtree(case_dir_b, ignore_errors=True)

            # (c) finish(stop_deadline) with 5 held workers returns False within 60 ms of the cutoff, not waiting
            with open_test_loopback_transport(transport_template, name="finish-held-workers") as h_held:
                all_entered = threading.Event()
                hold = threading.Event()
                entered_count = 0
                entered_lock = threading.Lock()
                import superbrain.cli_api._loopback_server as lb_server

                orig_handle_id = lb_server.handle_identity_request  # type: ignore[attr-defined]

                def wrap_handle_id(*args: Any, **kwargs: Any) -> Any:
                    nonlocal entered_count
                    with entered_lock:
                        entered_count += 1
                        if entered_count == 5:
                            all_entered.set()
                    hold.wait(2.0)  # released in the finally below; far longer than any finish() bound here
                    return orig_handle_id(*args, **kwargs)

                held_socks: list[ssl.SSLSocket] = []
                client_threads: list[threading.Thread] = []
                with monkeypatch.context() as mp:
                    mp.setattr(lb_server, "handle_identity_request", wrap_handle_id)
                    try:
                        id_payload = (
                            f"GET /v2/identity HTTP/1.1\r\nHost: 127.0.0.1:{h_held.ready.endpoint.port}\r\n\r\n"
                        ).encode("ascii")
                        for _ in range(5):
                            s = h_held.open_raw_tls_socket()
                            held_socks.append(s)
                            th = threading.Thread(target=lambda sock=s: sock.sendall(id_payload))
                            client_threads.append(th)
                            th.start()

                        assert all_entered.wait(timeout=2.0), "5 workers did not enter handle_identity_request"

                        grace_c = 0.03
                        dl_c = time.perf_counter() + grace_c
                        h_held.server.quiesce(dl_c)
                        fin_ok = h_held.server.finish(dl_c)
                        past_cutoff = time.perf_counter() - dl_c
                        with h_held.server._lock:
                            still_held = [w for w in h_held.server._workers.values() if w.is_alive()]
                        assert fin_ok is False, "Expected finish() to return False when workers are held past cutoff"
                        # I2-T6B-R02: finish() joins only within the remaining time of the same cutoff, with no extra
                        # grace, so it returns at most 60 ms after the cutoff instant and every held worker is still
                        # held when it does.
                        assert len(still_held) == 5 and not hold.is_set(), "finish() waited for held workers"
                        assert past_cutoff <= 0.06, f"finish() returned {past_cutoff:.4f}s after the cutoff (> 0.06s)"
                    finally:
                        hold.set()
                        for s in held_socks:
                            try:
                                s.close()
                            except OSError:
                                pass
                        for th in client_threads:
                            th.join(timeout=1.0)

            # (d) Invalid shutdown_grace_s rejected before loop.start()
            def _stop_on_ready(bs: threading.Event) -> Callable[[Ready, OwnerLoop], None]:
                def _ready_cb(_r: Ready, _l: OwnerLoop) -> None:
                    bs.set()

                return _ready_cb

            for bad_grace in (0.0, -0.5, float("nan"), True):
                bad_stop = threading.Event()
                with pytest.raises(BrainError) as exc_bad_grace:
                    serve(
                        cfg,
                        stop_event=bad_stop,
                        shutdown_grace_s=bad_grace,
                        on_ready=_stop_on_ready(bad_stop),
                    )
                assert exc_bad_grace.value.code == ErrorCode.INVALID_INPUT

            # (e) RuntimeError on accept thread start returns 1 cleanly, cleans endpoint.json, and releases lock
            case_dir_accept = make_trusted_test_dir("t6b4-fail-accept-thread")
            data_root_accept = case_dir_accept / "data"
            clone_owner_only_tree(transport_template.root, data_root_accept)
            cfg_accept = DaemonConfig(
                version=1,
                data_root=data_root_accept,
                expected_store_id=transport_template.store_id,
                cert_path=transport_template.tls.cert_path,
                key_path=transport_template.tls.key_path,
            )
            try:
                orig_thread_start_e = threading.Thread.start

                def mock_thread_start_accept(thread_self: threading.Thread) -> None:
                    if thread_self.name == "superbrain-loopback-accept":
                        raise RuntimeError("simulated accept thread spawn failure")
                    orig_thread_start_e(thread_self)

                with monkeypatch.context() as mp:
                    mp.setattr(threading.Thread, "start", mock_thread_start_accept)
                    on_ready_accept_called = False

                    def _on_ready_accept(_r: Ready, _l: OwnerLoop) -> None:
                        nonlocal on_ready_accept_called
                        on_ready_accept_called = True

                    ret_accept = serve(cfg_accept, on_ready=_on_ready_accept)
                    assert ret_accept == 1
                    assert on_ready_accept_called is False
                    assert not (data_root_accept / "endpoint.json").exists()
                    with admit_existing_pair(
                        data_root_accept, transport_template.store_id, os_adapters(), purpose="serve"
                    ) as admitted:
                        assert admitted is not None
            finally:
                shutil.rmtree(case_dir_accept, ignore_errors=True)

            # (f) RuntimeError on cutoff thread start fails closed,
            # aborting sockets within <= 0.09s before 0.16s owner commit finishes
            case_dir_cutoff = make_trusted_test_dir("t6b4-fail-cutoff-thread")
            data_root_cutoff = case_dir_cutoff / "data"
            clone_owner_only_tree(transport_template.root, data_root_cutoff)
            cfg_cutoff = DaemonConfig(
                version=1,
                data_root=data_root_cutoff,
                expected_store_id=transport_template.store_id,
                cert_path=transport_template.tls.cert_path,
                key_path=transport_template.tls.key_path,
            )
            try:
                stop_cutoff = threading.Event()
                ready_cutoff = threading.Event()
                ready_holder_cutoff: list[Ready] = []
                domain_cutoff = TransportTestDomain(
                    ws_a=transport_template.ws_a,
                    pause_idem_keys={"idem-shut-cutoff-001"},
                )
                domain_cutoff.allow_apply_finish.clear()

                orig_thread_start_f = threading.Thread.start

                def mock_thread_start_cutoff(thread_self: threading.Thread) -> None:
                    if thread_self.name == "superbrain-loopback-cutoff":
                        raise RuntimeError("simulated cutoff timer thread spawn failure")
                    orig_thread_start_f(thread_self)

                serve_res_cutoff: list[int] = []
                th_cutoff_client: threading.Thread | None = None
                s_cutoff_tls: ssl.SSLSocket | None = None

                def _on_cutoff_ready(r: Ready, _l: OwnerLoop) -> None:
                    ready_holder_cutoff.append(r)
                    ready_cutoff.set()

                with monkeypatch.context() as mp:
                    mp.setattr(threading.Thread, "start", mock_thread_start_cutoff)
                    t_cutoff_serve = threading.Thread(
                        target=lambda: serve_res_cutoff.append(
                            serve(
                                cfg_cutoff,
                                stop_event=stop_cutoff,
                                shutdown_grace_s=0.045,
                                on_ready=_on_cutoff_ready,
                                domain=domain_cutoff,
                            )
                        )
                    )
                    t_cutoff_serve.start()
                    assert ready_cutoff.wait(timeout=5.0)
                    ep_c = ready_holder_cutoff[0].endpoint

                    # Open an accepted TLS connection
                    ctx_c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx_c.load_verify_locations(cadata=transport_template.tls.ca_cert_path.read_text(encoding="utf-8"))
                    s_cutoff_raw = socket.create_connection(("127.0.0.1", ep_c.port), timeout=2.0)
                    s_cutoff_tls = ctx_c.wrap_socket(s_cutoff_raw, server_hostname="127.0.0.1")
                    # Send identity request so it is admitted
                    id_req = f"GET /v2/identity HTTP/1.1\r\nHost: 127.0.0.1:{ep_c.port}\r\n\r\n".encode("ascii")
                    s_cutoff_tls.sendall(id_req)
                    assert b"200 OK" in read_raw_http_response(s_cutoff_tls)

                    # Trigger tool call that enters SQLite transaction and pauses
                    client_c = LoopbackClient(monotonic_ns=time.monotonic_ns)
                    target_c = LoopbackTarget(
                        endpoint=ep_c,
                        expected_store_id=transport_template.store_id,
                        ca_pem=transport_template.tls.ca_cert_path.read_text(encoding="utf-8"),
                        leaf_cert_sha256=transport_template.tls.leaf_cert_sha256,
                    )
                    cmd_cutoff = ToolCommand(
                        "submit_episode",
                        {
                            "schema_version": "2.0",
                            "task_id": "task-ep-cutoff",
                            "session_id": "sess-cutoff",
                            "workspace_id": transport_template.ws_a.repo_id,
                            "checkout_id": transport_template.ws_a.checkout_id,
                            "evidence": [],
                            "idempotency_key": "idem-shut-cutoff-001",
                        },
                        token=transport_template.cred.token,
                        selected_scope=Scope(transport_template.ws_a.repo_id, transport_template.ws_a.checkout_id),
                    )

                    def _run_call_c() -> None:
                        with contextlib.suppress(LoopbackTransportError):
                            client_c.call(target_c, cmd_cutoff, deadline_ns=time.monotonic_ns() + 1_500_000_000)

                    th_cutoff_client = threading.Thread(target=_run_call_c)
                    th_cutoff_client.start()
                    assert domain_cutoff.apply_entered.wait(timeout=2.0)

                    # Trigger stop while owner is paused in COMMIT
                    t_stop_trigger = time.perf_counter()
                    stop_cutoff.set()

                    # Accepted socket must be aborted within <= 0.09s (fail closed!)
                    s_cutoff_tls.settimeout(0.5)
                    try:
                        recv_c = s_cutoff_tls.recv(1024)
                        assert recv_c == b""
                    except (ConnectionResetError, BrokenPipeError):
                        pass
                    except TimeoutError:
                        pytest.fail("accepted socket was not aborted when cutoff thread failed")
                    abort_elapsed = time.perf_counter() - t_stop_trigger
                    assert abort_elapsed <= 0.09, f"Socket abort took {abort_elapsed:.4f}s (> 0.09s)"

                    # Hold owner in SQLite COMMIT for 0.16s total from stop
                    time.sleep(max(0.0, 0.16 - (time.perf_counter() - t_stop_trigger)))
                    domain_cutoff.allow_apply_finish.set()

                    t_cutoff_serve.join(timeout=3.0)
                    th_cutoff_client.join(timeout=2.0)
                    assert serve_res_cutoff == [1], f"Expected returncode 1, got {serve_res_cutoff!r}"
                    assert not (data_root_cutoff / "endpoint.json").exists()
                    with admit_existing_pair(
                        data_root_cutoff, transport_template.store_id, os_adapters(), purpose="serve"
                    ) as admitted:
                        assert admitted is not None
            finally:
                if s_cutoff_tls is not None:
                    try:
                        s_cutoff_tls.close()
                    except OSError:
                        pass
                domain_cutoff.allow_apply_finish.set()
                stop_cutoff.set()
                shutil.rmtree(case_dir_cutoff, ignore_errors=True)

            # (g) Pre-set stop_event returns 1 cleanly without publishing endpoint or invoking on_ready (I2-T6B-R01)
            case_dir_preset = make_trusted_test_dir("t6b4-stop-preset")
            data_root_preset = case_dir_preset / "data"
            clone_owner_only_tree(transport_template.root, data_root_preset)
            cfg_preset = DaemonConfig(
                version=1,
                data_root=data_root_preset,
                expected_store_id=transport_template.store_id,
                cert_path=transport_template.tls.cert_path,
                key_path=transport_template.tls.key_path,
            )
            try:
                preset_stop = threading.Event()
                preset_stop.set()
                ready_preset: list[Ready] = []

                def _on_ready_preset(r: Ready, _l: OwnerLoop) -> None:
                    ready_preset.append(r)

                rc_preset = serve(
                    cfg_preset,
                    stop_event=preset_stop,
                    on_ready=_on_ready_preset,
                )
                assert rc_preset == 1, f"Expected returncode 1 for preset stop_event, got {rc_preset}"
                assert ready_preset == [], "on_ready must not be called when stop_event is pre-set"
                assert not (data_root_preset / "endpoint.json").exists(), "endpoint.json must not exist"
                with admit_existing_pair(
                    data_root_preset, transport_template.store_id, os_adapters(), purpose="serve"
                ) as admitted:
                    assert admitted is not None
            finally:
                shutil.rmtree(case_dir_preset, ignore_errors=True)

            # (h) Startup partial-accept failure while owner is held in OVERRUN aborts
            # accepted peer socket within grace (<= 0.09s) (I2-T6B-R01)
            case_dir_partial = make_trusted_test_dir("t6b4-fail-start-partial")
            data_root_partial = case_dir_partial / "data"
            clone_owner_only_tree(transport_template.root, data_root_partial)
            cfg_partial = DaemonConfig(
                version=1,
                data_root=data_root_partial,
                expected_store_id=transport_template.store_id,
                cert_path=transport_template.tls.cert_path,
                key_path=transport_template.tls.key_path,
            )
            client_sock_partial: socket.socket | None = None
            t_partial_serve: threading.Thread | None = None
            owner_release_ev = threading.Event()
            try:
                serve_res_partial: list[int] = []
                ready_partial: list[Ready] = []

                def _on_ready_partial(r: Ready, _l: OwnerLoop) -> None:
                    ready_partial.append(r)

                listener_filenos: set[int] = set()
                orig_init = LoopbackServer.__init__
                client_connected = threading.Event()

                def mock_server_init(self_srv: LoopbackServer, *args: Any, **kwargs: Any) -> None:
                    nonlocal client_sock_partial
                    orig_init(self_srv, *args, **kwargs)
                    listener_filenos.add(self_srv._listener.fileno())
                    srv_port = self_srv._listener.getsockname()[1]
                    client_sock_partial = socket.create_connection(("127.0.0.1", srv_port))
                    client_connected.set()

                    orig_ready_wait = self_srv._accept_ready.wait

                    def mock_ready_wait(timeout: float | None = None) -> bool:
                        res = orig_ready_wait(timeout)
                        self_srv._stop_event.wait(timeout=2.0)
                        return res

                    self_srv._accept_ready.wait = mock_ready_wait  # type: ignore[method-assign]

                orig_accept = socket.socket.accept
                accept_count = 0

                def mock_accept(self_sock: socket.socket) -> tuple[socket.socket, Any]:
                    nonlocal accept_count
                    if self_sock.fileno() in listener_filenos:
                        accept_count += 1
                        if accept_count == 1:
                            return orig_accept(self_sock)
                        raise OSError(errno.ECONNABORTED, "Software caused connection abort")
                    return orig_accept(self_sock)

                orig_loop_stop = OwnerLoop.stop

                def mock_loop_stop(self_loop: OwnerLoop, grace_s: float = 0.0) -> ShutdownReport:
                    owner_release_ev.wait(timeout=0.22)
                    return orig_loop_stop(self_loop, grace_s)

                with monkeypatch.context() as mp:
                    mp.setattr(LoopbackServer, "__init__", mock_server_init)
                    mp.setattr(socket.socket, "accept", mock_accept)
                    mp.setattr(OwnerLoop, "stop", mock_loop_stop)

                    t_partial_serve = threading.Thread(
                        target=lambda: serve_res_partial.append(
                            serve(
                                cfg_partial,
                                shutdown_grace_s=0.045,
                                on_ready=_on_ready_partial,
                            )
                        )
                    )
                    t_partial_serve.start()

                    assert client_connected.wait(timeout=2.0), "client_sock_partial was never connected"
                    assert client_sock_partial is not None

                    # The peer socket must be aborted by transport within grace (<= 0.09s),
                    # even while owner loop stop is held for 0.22s.
                    client_sock_partial.settimeout(0.5)
                    t_wait_abort = time.perf_counter()
                    try:
                        data = client_sock_partial.recv(1024)
                        assert data == b""
                    except (ConnectionResetError, BrokenPipeError):
                        pass
                    except TimeoutError:
                        pytest.fail("accepted peer socket was not aborted within cutoff grace")
                    finally:
                        owner_release_ev.set()

                    abort_elapsed = time.perf_counter() - t_wait_abort
                    assert abort_elapsed <= 0.09, f"Peer socket abort took {abort_elapsed:.4f}s (> 0.09s)"

                    t_partial_serve.join(timeout=3.0)
                    assert serve_res_partial == [1], f"Expected returncode 1, got {serve_res_partial!r}"
                    assert ready_partial == [], "on_ready must not be called on startup failure"
                    assert not (data_root_partial / "endpoint.json").exists(), "endpoint.json must not exist"
                    with admit_existing_pair(
                        data_root_partial, transport_template.store_id, os_adapters(), purpose="serve"
                    ) as admitted:
                        assert admitted is not None
            finally:
                owner_release_ev.set()
                if client_sock_partial is not None:
                    try:
                        client_sock_partial.close()
                    except OSError:
                        pass
                if t_partial_serve is not None and t_partial_serve.is_alive():
                    t_partial_serve.join(timeout=3.0)
                shutil.rmtree(case_dir_partial, ignore_errors=True)

            # (i) Busy-listener startup under continuous inbound backlog including > 32-slot saturation (I2-T6B-R01)
            case_dir_busy = make_trusted_test_dir("t6b4-busy-startup")
            data_root_busy = case_dir_busy / "data"
            clone_owner_only_tree(transport_template.root, data_root_busy)
            cfg_busy = DaemonConfig(
                version=1,
                data_root=data_root_busy,
                expected_store_id=transport_template.store_id,
                cert_path=transport_template.tls.cert_path,
                key_path=transport_template.tls.key_path,
            )
            held_busy_socks: list[socket.socket] = []
            overflow_socks: list[socket.socket] = []
            transient_socks: list[socket.socket] = []
            t_busy_serve: threading.Thread | None = None
            busy_stop = threading.Event()
            stop_feeding = threading.Event()
            overflow_done_ev = threading.Event()
            busy_ready_ev = threading.Event()
            ready_busy: list[Ready] = []
            serve_rc_busy: list[int] = []

            def _on_ready_busy(r: Ready, _l: OwnerLoop) -> None:
                ready_busy.append(r)
                busy_ready_ev.set()

            orig_accept_busy = socket.socket.accept
            accept_feed_count = 0

            def mock_accept_busy(self_sock: socket.socket) -> tuple[socket.socket, Any]:
                nonlocal accept_feed_count
                if threading.current_thread().name == "superbrain-loopback-accept" and not stop_feeding.is_set():
                    srv_addr = self_sock.getsockname()
                    accept_feed_count += 1
                    if accept_feed_count <= MAX_ACTIVE_CONNECTIONS:
                        s_held = socket.create_connection(srv_addr, timeout=0.5)
                        held_busy_socks.append(s_held)
                    elif accept_feed_count <= MAX_ACTIVE_CONNECTIONS + 6:
                        s_over = socket.create_connection(srv_addr, timeout=0.5)
                        overflow_socks.append(s_over)
                        if len(overflow_socks) == 6:
                            overflow_done_ev.set()
                    else:
                        s_trans = socket.create_connection(srv_addr, timeout=0.5)
                        transient_socks.append(s_trans)
                        time.sleep(0.01)
                return orig_accept_busy(self_sock)

            try:
                t0_busy = time.perf_counter()
                with monkeypatch.context() as mp:
                    mp.setattr(socket.socket, "accept", mock_accept_busy)
                    t_busy_serve = threading.Thread(
                        target=lambda: serve_rc_busy.append(
                            serve(
                                cfg_busy,
                                stop_event=busy_stop,
                                shutdown_grace_s=0.5,
                                on_ready=_on_ready_busy,
                            )
                        )
                    )
                    t_busy_serve.start()

                    # 1. on_ready must fire promptly (< 1.0s) despite busy accept backlog
                    assert busy_ready_ev.wait(timeout=2.5), "serve did not emit on_ready under busy accept backlog"
                    startup_elapsed = time.perf_counter() - t0_busy
                    assert len(ready_busy) == 1
                    assert startup_elapsed < 1.0, f"Busy startup took too long: {startup_elapsed:.4f}s (>= 1.0s)"

                    # 2. Wait for 6 overflow connections to be admitted/processed at cap
                    assert overflow_done_ev.wait(timeout=2.0), "overflow connections not generated"
                    stop_feeding.set()

                    # 3. All 6 overflow sockets must receive EOF or reset within 1.0s
                    for s_over in overflow_socks:
                        s_over.settimeout(1.0)
                        try:
                            data = s_over.recv(1024)
                            assert data == b""
                        except (ConnectionResetError, BrokenPipeError):
                            pass
                        except TimeoutError:
                            pytest.fail("overflow socket was not gracefully closed or reset at connection cap")

                    # With all 32 held sockets open, a new call is rejected at transport cap
                    ep_busy = ready_busy[0].endpoint
                    target_busy = LoopbackTarget(
                        ep_busy,
                        transport_template.store_id,
                        transport_template.tls.ca_cert_path.read_text(encoding="utf-8"),
                        transport_template.tls.leaf_cert_sha256,
                    )
                    client_busy = LoopbackClient(monotonic_ns=time.monotonic_ns)
                    cmd_health = ToolCommand(
                        "get_health",
                        {"schema_version": "2.0"},
                        token=transport_template.cred.token,
                    )
                    with pytest.raises(LoopbackTransportError) as exc_cap:
                        client_busy.call(target_busy, cmd_health, deadline_ns=time.monotonic_ns() + 1_000_000_000)
                    assert exc_cap.value.code != ErrorCode.STORE_BUSY
                    assert exc_cap.value.request_may_have_run is False

                    # 4. Free one slot from held_busy_socks and execute positive twin call
                    freed_sock = held_busy_socks.pop()
                    try:
                        freed_sock.close()
                    except OSError:
                        pass

                    call_deadline = time.perf_counter() + 0.5
                    res_call: dict[str, Any] | None = None
                    last_exc: Exception | None = None
                    while time.perf_counter() < call_deadline:
                        try:
                            res_call = client_busy.call(
                                target_busy,
                                cmd_health,
                                deadline_ns=time.monotonic_ns() + 500_000_000,
                            )
                            break
                        except LoopbackTransportError as err:
                            last_exc = err
                            time.sleep(0.02)
                    assert res_call is not None, f"Expected successful health call after freeing slot: {last_exc}"
                    assert res_call.get("ok") is True

                    # 5. Clean shutdown after closing held sockets
                    for busy_s in held_busy_socks + overflow_socks + transient_socks:
                        try:
                            busy_s.close()
                        except OSError:
                            pass
                    busy_stop.set()
                    t_busy_serve.join(timeout=3.0)
                    assert serve_rc_busy == [0], f"Expected returncode 0, got {serve_rc_busy!r}"
                    assert not (data_root_busy / "endpoint.json").exists()
                    with admit_existing_pair(
                        data_root_busy, transport_template.store_id, os_adapters(), purpose="serve"
                    ) as admitted:
                        assert admitted is not None
            finally:
                busy_stop.set()
                stop_feeding.set()
                for busy_s in held_busy_socks + overflow_socks + transient_socks:
                    try:
                        busy_s.close()
                    except OSError:
                        pass
                if t_busy_serve is not None and t_busy_serve.is_alive():
                    t_busy_serve.join(timeout=3.0)
                shutil.rmtree(case_dir_busy, ignore_errors=True)
        finally:
            shutil.rmtree(case_dir, ignore_errors=True)

    def test_policy_revoke_wins_before_release_grant(
        self,
        transport_template: TransportTemplate,
    ) -> None:
        """Revoking credential or invalidating AuthGate before release grant returns policy_unavailable."""
        assert transport_template.dan is not None
        assert transport_template.cred_b is not None
        assert transport_template.ws_a is not None

        domain = TransportTestDomain(ws_a=transport_template.ws_a)
        with open_test_loopback_transport(transport_template, name="revoke-release", domain=domain) as h:
            target = h.make_target()
            client = h.open_client()

            orig_submit = h.loop.submit_reply
            orig_authorize = h.loop.auth_gate.authorize_stamp
            rendered_ev = threading.Event()
            release_ev = threading.Event()
            pause_active = True

            def intercept_submit(cmd: ToolCommand, dl: int) -> Future[OwnerReply]:
                fut = orig_submit(cmd, dl)
                if pause_active and cmd.tool == "get_artifact":
                    fut.add_done_callback(lambda _f: rendered_ev.set())
                return fut

            def intercept_authorize(stamp: AuthGrantStamp) -> bool:
                if pause_active:
                    release_ev.wait(timeout=5.0)
                return orig_authorize(stamp)

            h.loop.submit_reply = intercept_submit  # type: ignore[method-assign,assignment]
            h.loop.auth_gate.authorize_stamp = intercept_authorize  # type: ignore[method-assign]

            scope_a = Scope(transport_template.ws_a.repo_id, transport_template.ws_a.checkout_id)

            # Subcase A: Credential A revoked while paused before release
            cmd_a = ToolCommand(
                "get_artifact",
                {
                    "schema_version": "2.0",
                    "workspace_id": transport_template.ws_a.repo_id,
                    "task_id": "task-art-1",
                    "artifact_id": "art-skill-1",
                    "revision": 1,
                    "level": "L1",
                    "idempotency_key": "idem-art-a-00000001",
                },
                token=transport_template.cred.token,
                selected_scope=scope_a,
            )
            res_box: list[CallResult] = []
            th_a = threading.Thread(target=lambda: res_box.append(client.call(target, cmd_a)))
            try:
                th_a.start()
                assert rendered_ev.wait(timeout=2.0)

                # Revoke cred_a
                ws_auth = make_bootstrap_auth(
                    store_id=transport_template.store_id,
                    owner_id="dan",
                    action="credential_revoke",
                    subject_id=transport_template.cred.credential_id,
                    trust_generation=1,
                    expires_at=h.clock.now() + dt.timedelta(hours=1),
                )
                h.loop.revoke_credential(transport_template.cred.credential_id, ws_auth).result(timeout=5.0)

                # Advance mono clock to 1,490 ms (10 ms remaining before 1,500 ms deadline)
                h.mono_clock.advance_ms(1490)

                # Hold owner thread in run_owner_action
                owner_hold_ev = threading.Event()
                owner_held_ev = threading.Event()

                def _hold_owner() -> None:
                    owner_held_ev.set()
                    owner_hold_ev.wait(timeout=5.0)

                h.loop.run_owner_action(_hold_owner)
                assert owner_held_ev.wait(timeout=2.0)

                # Intercept interrupt_send_attempt to advance clock by 10 ms (reaching 1,500 ms) as soon as called
                orig_interrupt = h.loop.interrupt_send_attempt

                def _intercept_interrupt(send_attempt_id: str) -> Future[Any]:
                    h.mono_clock.advance_ns(10_000_000)
                    return orig_interrupt(send_attempt_id)

                h.loop.interrupt_send_attempt = _intercept_interrupt  # type: ignore[method-assign]

                # Unblock release: transport worker must write policy_unavailable FIRST without waiting on held owner
                t_rel_start = time.perf_counter()
                release_ev.set()
                th_a.join(timeout=0.20)
                call_duration = time.perf_counter() - t_rel_start
                assert call_duration < 0.15, f"Call took {call_duration:.4f}s while owner held (> 0.15s)"

                assert len(res_box) == 1
                res_a = res_box[0]
                assert res_a["ok"] is False
                assert isinstance(res_a["error"], dict)
                assert res_a["error"]["code"] == "policy_unavailable"
                assert "# Loaded Skill L1" not in canonical_json(res_a).decode("utf-8")

                # Release owner hold and sync
                owner_hold_ev.set()
                h.loop.run_owner_action(lambda: None).result(timeout=2.0)

                assert h.count_send_attempts("served_only") == 0
                assert h.count_send_attempts("unknown") == 1
            finally:
                release_ev.set()
                th_a.join(timeout=2.0)

            # Credential B of same principal still succeeds
            pause_active = False
            cmd_b = ToolCommand(
                "get_artifact",
                {
                    "schema_version": "2.0",
                    "workspace_id": transport_template.ws_a.repo_id,
                    "task_id": "task-art-1",
                    "artifact_id": "art-skill-1",
                    "revision": 1,
                    "level": "L1",
                    "idempotency_key": "idem-art-b-00000001",
                },
                token=transport_template.cred_b.token,
                selected_scope=scope_a,
            )
            res_b = client.call(target, cmd_b)
            assert res_b["ok"] is True

            # Subcase B: AuthGate invalidation / unpublished transition
            rendered_ev.clear()
            release_ev.clear()
            pause_active = True
            res_box_b: list[CallResult] = []
            cmd_b2 = ToolCommand(
                "get_artifact",
                {
                    "schema_version": "2.0",
                    "workspace_id": transport_template.ws_a.repo_id,
                    "task_id": "task-art-1",
                    "artifact_id": "art-skill-1",
                    "revision": 1,
                    "level": "L1",
                    "idempotency_key": "idem-art-b-00000002",
                },
                token=transport_template.cred_b.token,
                selected_scope=scope_a,
            )
            th_b = threading.Thread(target=lambda: res_box_b.append(client.call(target, cmd_b2)))
            try:
                th_b.start()
                assert rendered_ev.wait(timeout=2.0)

                h.loop.auth_gate.invalidate()
                release_ev.set()
                th_b.join(timeout=2.0)

                res_b2 = res_box_b[0]
                assert res_b2["ok"] is False
                assert isinstance(res_b2["error"], dict)
                assert res_b2["error"]["code"] == "policy_unavailable"
                assert "# Loaded Skill L1" not in canonical_json(res_b2).decode("utf-8")
                assert h.count_send_attempts("served_only") == 1
            finally:
                release_ev.set()
                th_b.join(timeout=2.0)

    def test_grant_won_before_revoke_can_finish_inflight_write(
        self,
        transport_template: TransportTemplate,
    ) -> None:
        """In-flight response write whose release was granted completes even if credential is revoked concurrently."""
        assert transport_template.dan is not None
        assert transport_template.ws_a is not None

        domain = TransportTestDomain(ws_a=transport_template.ws_a)
        with open_test_loopback_transport(transport_template, name="grant-won-write", domain=domain) as h:
            target = h.make_target()
            client = h.open_client()

            write_entered_ev = threading.Event()
            allow_write_ev = threading.Event()
            pause_write = True
            orig_wrap = h.bound.ssl_context.wrap_socket

            def wrap_interceptor(sock: socket.socket, **kwargs: Any) -> ssl.SSLSocket:
                ssl_sock = orig_wrap(sock, **kwargs)
                orig_send = ssl_sock.send

                def paused_send(data: bytes | memoryview, flags: int = 0) -> int:
                    nonlocal pause_write
                    raw = bytes(data)
                    if pause_write and b"art-skill-1" in raw:
                        pause_write = False
                        write_entered_ev.set()
                        allow_write_ev.wait(timeout=5.0)
                    return orig_send(data, flags)

                ssl_sock.send = paused_send  # type: ignore[method-assign,assignment]
                return ssl_sock

            h.bound.ssl_context.wrap_socket = wrap_interceptor  # type: ignore[method-assign,assignment]

            cmd = ToolCommand(
                "get_artifact",
                {
                    "schema_version": "2.0",
                    "workspace_id": transport_template.ws_a.repo_id,
                    "task_id": "task-art-1",
                    "artifact_id": "art-skill-1",
                    "revision": 1,
                    "level": "L1",
                    "idempotency_key": "idem-art-inflight-1",
                },
                token=transport_template.cred.token,
                selected_scope=Scope(transport_template.ws_a.repo_id, transport_template.ws_a.checkout_id),
            )
            res_box: list[CallResult] = []
            th = threading.Thread(target=lambda: res_box.append(client.call(target, cmd)))
            try:
                th.start()
                assert write_entered_ev.wait(timeout=2.0)

                # While write is paused, revoke credential A
                ws_auth = make_bootstrap_auth(
                    store_id=transport_template.store_id,
                    owner_id="dan",
                    action="credential_revoke",
                    subject_id=transport_template.cred.credential_id,
                    trust_generation=1,
                    expires_at=h.clock.now() + dt.timedelta(hours=1),
                )
                h.loop.revoke_credential(transport_template.cred.credential_id, ws_auth).result(timeout=2.0)

                # New call with cred_a fails unauthenticated
                cmd_unauth = ToolCommand("get_health", {"schema_version": "2.0"}, token=transport_template.cred.token)
                res_unauth = client.call(target, cmd_unauth)
                assert res_unauth["ok"] is False
                assert isinstance(res_unauth["error"], dict)
                assert res_unauth["error"]["code"] == "unauthenticated"

                # Allow the already-granted in-flight write to finish
                allow_write_ev.set()
                th.join(timeout=2.0)

                assert res_box[0]["ok"] is True
                assert isinstance(res_box[0]["data"], dict)
                assert res_box[0]["data"]["artifact_id"] == "art-skill-1"
            finally:
                allow_write_ev.set()
                th.join(timeout=2.0)

    def test_artifact_send_finalizes_only_after_full_flush(
        self,
        transport_template: TransportTemplate,
    ) -> None:
        """Artifact send attempt remains pending until full response flush, and does not create automatic ReadAcks."""
        assert transport_template.ws_a is not None

        domain = FinalizeFlushDomain(ws_a=transport_template.ws_a)
        with open_test_loopback_transport(transport_template, name="send-finalize", domain=domain) as h:
            target = h.make_target()
            client = h.open_client()

            held_finalize = threading.Event()
            orig_finalize = h.loop.finalize_send_attempt

            def intercept_finalize(completion: Any) -> Future[Any]:
                deferred: Future[Any] = Future()

                def _bg() -> None:
                    held_finalize.wait(timeout=5.0)
                    real_fut = orig_finalize(completion)
                    try:
                        res = real_fut.result(timeout=2.0)
                        deferred.set_result(res)
                    except Exception as exc:  # noqa: BLE001
                        deferred.set_exception(exc)

                threading.Thread(target=_bg, daemon=True).start()
                return deferred

            h.loop.finalize_send_attempt = intercept_finalize  # type: ignore[method-assign]

            flush_pause = True
            flush_entered_ev = threading.Event()
            allow_flush_ev = threading.Event()
            orig_wrap = h.bound.ssl_context.wrap_socket

            def wrap_interceptor(sock: socket.socket, **kwargs: Any) -> ssl.SSLSocket:
                ssl_sock = orig_wrap(sock, **kwargs)
                orig_send = ssl_sock.send

                def paused_send(data: bytes | memoryview, flags: int = 0) -> int:
                    nonlocal flush_pause
                    raw = bytes(data)
                    if flush_pause and b"art-skill-1" in raw:
                        flush_pause = False
                        sent = orig_send(raw[:20], flags)
                        flush_entered_ev.set()
                        allow_flush_ev.wait(timeout=5.0)
                        return sent
                    return orig_send(data, flags)

                ssl_sock.send = paused_send  # type: ignore[method-assign,assignment]
                return ssl_sock

            h.bound.ssl_context.wrap_socket = wrap_interceptor  # type: ignore[method-assign,assignment]

            scope_a = Scope(transport_template.ws_a.repo_id, transport_template.ws_a.checkout_id)
            cmd = ToolCommand(
                "get_artifact",
                {
                    "schema_version": "2.0",
                    "workspace_id": transport_template.ws_a.repo_id,
                    "task_id": "task-art-1",
                    "artifact_id": "art-skill-1",
                    "revision": 1,
                    "level": "L1",
                    "idempotency_key": "idem-art-flush-1",
                },
                token=transport_template.cred.token,
                selected_scope=scope_a,
            )
            res_box: list[CallResult] = []
            th = threading.Thread(target=lambda: res_box.append(client.call(target, cmd)))
            try:
                th.start()
                assert flush_entered_ev.wait(timeout=2.0)

                # While paused mid-flush: attempt is pending in SQLite
                assert h.count_send_attempts("pending") == 1
                assert h.count_send_attempts("served_only") == 0

                # Allow flush to complete
                allow_flush_ev.set()
                th.join(timeout=2.0)

                # Transport worker must exit without blocking on finalize Future
                t_poll_active = time.perf_counter()
                while time.perf_counter() - t_poll_active < 0.05 and h.server._active_slots > 0:
                    time.sleep(0.002)
                assert h.server._active_slots == 0, "transport worker remained blocked waiting on finalize Future"

                res = res_box[0]
                assert res["ok"] is True
                assert isinstance(res["data"], dict)
                receipt_id = str(res["data"]["served_receipt_id"])

                # While finalize_send_attempt is still queued/held behind async worker,
                # attempt in SQLite is STILL pending
                assert h.count_send_attempts("pending") == 1
                assert h.count_send_attempts("served_only") == 0
                assert h.get_send_attempt_state(receipt_id) == "pending"

                # Client submits explicit ReadAck while attempt is still pending -> in_progress!
                content_digest = digest_bytes(b"# Loaded Skill L1\n")
                cmd_ack_pend = ToolCommand(
                    "record_outcome",
                    {
                        "schema_version": "2.0",
                        "workspace_id": transport_template.ws_a.repo_id,
                        "delivery_id": "deliv-art-flush-1",
                        "outcome": "success",
                        "read_acks": [
                            {
                                "served_receipt_id": receipt_id,
                                "task_id": "task-art-1",
                                "revision": 1,
                                "resource_digests": [{"name": "L1.md", "digest": content_digest}],
                            }
                        ],
                        "idempotency_key": "idem-out-flush-pend-1",
                    },
                    token=transport_template.cred.token,
                    selected_scope=scope_a,
                )
                res_ack_pend = client.call(target, cmd_ack_pend)
                assert res_ack_pend["ok"] is False
                assert isinstance(res_ack_pend["error"], dict)
                assert res_ack_pend["error"]["code"] == "in_progress"
                assert h.count_read_acks() == 0

                # Unblock held_finalize and wait for async worker to commit finalize_send_attempt
                held_finalize.set()
                deadline = time.perf_counter() + 1.0
                while time.perf_counter() < deadline and h.count_send_attempts("served_only") == 0:
                    time.sleep(0.005)
                h.loop.run_owner_action(lambda: None).result(timeout=2.0)

                # After full flush + finalize: attempt transitioned to served_only
                assert h.count_send_attempts("served_only") == 1
                assert h.count_send_attempts("pending") == 0
                assert h.get_send_attempt_state(receipt_id) == "served_only"
                # 0 automatic artifact_read_ack rows before client ACK
                assert h.count_read_acks() == 0

                # Retrying record_outcome with read_acks succeeds after finalize commits
                cmd_ack_done = ToolCommand(
                    "record_outcome",
                    {
                        "schema_version": "2.0",
                        "workspace_id": transport_template.ws_a.repo_id,
                        "delivery_id": "deliv-art-flush-1",
                        "outcome": "success",
                        "read_acks": [
                            {
                                "served_receipt_id": receipt_id,
                                "task_id": "task-art-1",
                                "revision": 1,
                                "resource_digests": [{"name": "L1.md", "digest": content_digest}],
                            }
                        ],
                        "idempotency_key": "idem-out-flush-done-1",
                    },
                    token=transport_template.cred.token,
                    selected_scope=scope_a,
                )
                res_ack_done = client.call(target, cmd_ack_done)
                assert res_ack_done["ok"] is True
                assert h.count_read_acks() == 1
            finally:
                allow_flush_ev.set()
                held_finalize.set()
                th.join(timeout=2.0)

    def test_abandoned_send_recovers_without_read_ack(
        self,
        transport_template: TransportTemplate,
    ) -> None:
        """Non-flush terminal cases leave attempt unknown, retries mint new attempt, and pending recovers on startup."""
        assert transport_template.ws_a is not None

        domain = TransportTestDomain(ws_a=transport_template.ws_a)
        with open_test_loopback_transport(transport_template, name="send-recovery", domain=domain) as h:
            target = h.make_target()
            client = h.open_client()

            # (a) Partial write / peer disconnect mid-write
            disconnect_done = threading.Event()
            orig_wrap = h.bound.ssl_context.wrap_socket

            def wrap_interceptor(sock: socket.socket, **kwargs: Any) -> ssl.SSLSocket:
                ssl_sock = orig_wrap(sock, **kwargs)
                orig_send = ssl_sock.send

                def failing_send(data: bytes | memoryview, flags: int = 0) -> int:
                    raw = bytes(data)
                    if b"art-skill-1" in raw:
                        orig_send(raw[:24], flags)
                        disconnect_done.set()
                        raise BrokenPipeError("client disconnected mid-write")
                    return orig_send(data, flags)

                ssl_sock.send = failing_send  # type: ignore[method-assign,assignment]
                return ssl_sock

            h.bound.ssl_context.wrap_socket = wrap_interceptor  # type: ignore[method-assign,assignment]

            scope_a = Scope(transport_template.ws_a.repo_id, transport_template.ws_a.checkout_id)
            cmd_a = ToolCommand(
                "get_artifact",
                {
                    "schema_version": "2.0",
                    "workspace_id": transport_template.ws_a.repo_id,
                    "task_id": "task-art-1",
                    "artifact_id": "art-skill-1",
                    "revision": 1,
                    "level": "L1",
                    "idempotency_key": "idem-art-abandon-1",
                },
                token=transport_template.cred.token,
                selected_scope=scope_a,
            )
            with pytest.raises(LoopbackTransportError) as exc_info:
                client.call(target, cmd_a)
            assert exc_info.value.request_may_have_run is True
            assert disconnect_done.wait(timeout=2.0)

            # Poll boundedly until server worker finishes interrupt_send_attempt
            deadline = time.perf_counter() + 1.0
            while time.perf_counter() < deadline and h.count_send_attempts("unknown") == 0:
                time.sleep(0.005)
            h.loop.run_owner_action(lambda: None).result(timeout=2.0)

            # Attempt transitioned to unknown (0 served_only, 0 read_ack)
            assert h.count_send_attempts("unknown") == 1
            assert h.count_send_attempts("served_only") == 0
            assert h.count_read_acks() == 0

            # Restore normal wrap and retry with SAME idempotency_key
            h.bound.ssl_context.wrap_socket = orig_wrap  # type: ignore[method-assign]
            res_retry = client.call(target, cmd_a)
            assert res_retry["ok"] is True
            assert isinstance(res_retry["data"], dict)
            new_receipt_id = str(res_retry["data"]["served_receipt_id"])

            deadline = time.perf_counter() + 1.0
            while time.perf_counter() < deadline and h.count_send_attempts("served_only") == 0:
                time.sleep(0.005)
            h.loop.run_owner_action(lambda: None).result(timeout=2.0)

            assert h.count_send_attempts("served_only") == 1
            assert h.get_send_attempt_state(new_receipt_id) == "served_only"

            # (b) Crash / stop after write_all before finalize_send_attempt commits
            def crashing_finalize(completion: Any) -> Future[None]:
                f: Future[None] = Future()
                f.set_exception(BrainError(ErrorCode.IO_ERROR, "simulated finalize crash"))
                return f

            h.loop.finalize_send_attempt = crashing_finalize  # type: ignore[method-assign,assignment]

            cmd_crash = ToolCommand(
                "get_artifact",
                {
                    "schema_version": "2.0",
                    "workspace_id": transport_template.ws_a.repo_id,
                    "task_id": "task-art-1",
                    "artifact_id": "art-skill-1",
                    "revision": 1,
                    "level": "L1",
                    "idempotency_key": "idem-art-crash-1",
                },
                token=transport_template.cred.token,
                selected_scope=scope_a,
            )
            try:
                client.call(target, cmd_crash)
            except LoopbackTransportError:
                pass

        # Reopen on next epoch: pending recovers to unknown on startup!
        with open_test_loopback_transport(transport_template, name="send-recovered", domain=domain) as h2:
            assert h2.count_send_attempts("pending") == 0
            assert h2.count_read_acks() == 0

    def test_writable_client_gets_commit_unknown_before_owner_unblocks(
        self,
        transport_template: TransportTemplate,
    ) -> None:
        """Client receives commit_outcome_unknown while SQLite is blocked in COMMITTING, and RAM health succeeds."""
        assert transport_template.ws_a is not None
        domain = TransportTestDomain(
            ws_a=transport_template.ws_a,
            pause_idem_keys={"idem-commit-blocked-1"},
        )
        domain.allow_apply_finish.clear()

        with open_test_loopback_transport(transport_template, name="commit-unknown", domain=domain) as h:
            target = h.make_target()
            client = h.open_client()
            init_seq = h.ledger_sequence()

            cmd_write = ToolCommand(
                "submit_episode",
                {
                    "schema_version": "2.0",
                    "task_id": "task-ep-1",
                    "session_id": "sess-1",
                    "workspace_id": transport_template.ws_a.repo_id,
                    "checkout_id": transport_template.ws_a.checkout_id,
                    "evidence": [],
                    "idempotency_key": "idem-commit-blocked-1",
                },
                token=transport_template.cred.token,
                selected_scope=Scope(transport_template.ws_a.repo_id, transport_template.ws_a.checkout_id),
            )
            client_res_box: list[CallResult] = []
            th = threading.Thread(target=lambda: client_res_box.append(client.call(target, cmd_write)))
            try:
                th.start()
                assert domain.apply_entered.wait(timeout=2.0), "apply_entered did not fire"

                # Advance monotonic clock past 1,475 ms commit cutoff (into 1,475 ms..1,500 ms window)
                h.mono_clock.advance_ms(1480)
                th.join(timeout=3.0)

                # Client receives commit_outcome_unknown BEFORE SQLite barrier is released!
                res = client_res_box[0]
                assert res["ok"] is False
                assert isinstance(res["error"], dict)
                assert res["error"]["code"] == "commit_outcome_unknown"

                # While owner is STILL blocked in SQLite COMMITTING:
                # 1. Shallow get_health succeeds promptly from RAM
                res_health = client.call(
                    target,
                    ToolCommand("get_health", {"schema_version": "2.0"}, token=transport_template.cred.token),
                    deadline_ns=h.mono_clock.now + TOTAL_REQUEST_BUDGET_NS,
                )
                assert res_health["ok"] is True

                # 2. Retrying the write tool receives in_progress
                res_in_prog = client.call(
                    target,
                    cmd_write,
                    deadline_ns=h.mono_clock.now + TOTAL_REQUEST_BUDGET_NS,
                )
                assert res_in_prog["ok"] is False
                assert isinstance(res_in_prog["error"], dict)
                assert res_in_prog["error"]["code"] == "in_progress"

                # Release SQLite barrier
                domain.allow_apply_finish.set()
                h.loop.run_owner_action(lambda: None).result(timeout=2.0)

                # Retrying returns ok=True and SQLite has exactly 1 ledger effect
                res_done = client.call(
                    target,
                    cmd_write,
                    deadline_ns=h.mono_clock.now + TOTAL_REQUEST_BUDGET_NS,
                )
                assert res_done["ok"] is True
                assert h.ledger_sequence() == init_seq + 1
            finally:
                domain.allow_apply_finish.set()
                th.join(timeout=3.0)

    def test_slow_request_bytes_consume_owner_budget(
        self,
        transport_template: TransportTemplate,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Slow body bytes arriving in (1,300 ms, 1,500 ms) receive deadline_exceeded with 0 durable writes."""
        import threading

        import superbrain.cli_api._loopback_server as loopback_server

        entered_read_cmd = threading.Event()
        orig_read_cmd = loopback_server.read_admitted_tool_command  # type: ignore[attr-defined]

        def _hooked_read_cmd(*args: Any, **kwargs: Any) -> Any:
            entered_read_cmd.set()
            return orig_read_cmd(*args, **kwargs)

        monkeypatch.setattr(loopback_server, "read_admitted_tool_command", _hooked_read_cmd)

        assert transport_template.ws_a is not None
        with open_test_loopback_transport(transport_template, name="slow-bytes") as h:
            port = h.ready.endpoint.port
            host = f"127.0.0.1:{port}"
            init_seq = h.ledger_sequence()

            # 1. Writable client sends body slowly: last byte arrives between 1,300 ms and 1,500 ms
            with h.open_raw_tls_socket() as s_tls:
                entered_read_cmd.clear()
                h.send_raw_http(s_tls, f"GET /v2/identity HTTP/1.1\r\nHost: {host}\r\n\r\n".encode("ascii"))

                cmd = ToolCommand(
                    "submit_episode",
                    {
                        "schema_version": "2.0",
                        "task_id": "task-ep-1",
                        "session_id": "sess-1",
                        "workspace_id": transport_template.ws_a.repo_id,
                        "checkout_id": transport_template.ws_a.checkout_id,
                        "evidence": [],
                        "idempotency_key": "idem-slow-body-0001",
                    },
                    token=transport_template.cred.token,
                    selected_scope=Scope(transport_template.ws_a.repo_id, transport_template.ws_a.checkout_id),
                )
                body = encode_call(cmd)
                headers = (
                    f"POST /v2/tools/call HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Authorization: Bearer {transport_template.cred.token}\r\n"
                    f"X-Store-Id: {h.ready.endpoint.store_id}\r\n"
                    f"X-Writer-Epoch: {h.ready.endpoint.writer_epoch}\r\n"
                    f"X-Superbrain-Instance: {h.ready.endpoint.instance_id}\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(body)}\r\n\r\n"
                ).encode("iso-8859-1")

                # Send headers and body except the last byte, then wait until t0_tool is stamped
                s_tls.sendall(headers + body[:-1])
                assert entered_read_cmd.wait(timeout=2.0), "server did not enter read_admitted_tool_command"

                # Advance mono clock to t0 + 1,360 ms (after handler cutoff 1,300 ms, before deadline 1,500 ms)
                h.mono_clock.advance_ms(1360)

                # Send final byte
                s_tls.sendall(body[-1:])

                # Writable socket receives HTTP 200 with deadline_exceeded
                resp_bytes = h.send_raw_http(s_tls, b"", read_timeout=2.0)
                assert b"200 OK" in resp_bytes
                resp_json = json.loads(resp_bytes.split(b"\r\n\r\n", 1)[1].decode("utf-8"))
                assert resp_json.get("ok") is False
                assert resp_json.get("error", {}).get("code") == "deadline_exceeded"
                assert h.ledger_sequence() == init_seq

            # 2. Unwritable / stalled client socket exceeding 1,500 ms total deadline
            with h.open_raw_tls_socket() as s_stall:
                entered_read_cmd.clear()
                h.send_raw_http(s_stall, f"GET /v2/identity HTTP/1.1\r\nHost: {host}\r\n\r\n".encode("ascii"))
                s_stall.sendall(headers + body[:10])
                assert entered_read_cmd.wait(timeout=2.0), "server did not enter read_admitted_tool_command"

                # Advance clock past total deadline 1,500 ms
                h.mono_clock.advance_ms(1600)

                # Socket is closed by server (FramedReader waits up to remaining 1.5s kernel recv timeout)
                s_stall.settimeout(3.0)
                try:
                    data = s_stall.recv(1024)
                    assert data == b""
                except TimeoutError:
                    pytest.fail("stalled socket remained open past total deadline")
                except OSError:
                    pass
