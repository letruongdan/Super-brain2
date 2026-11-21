"""Behavioral regressions for SP2-1 bidirectional schema_digest handshake, capability separation, discover, and ReadAck.

Covers all M1-M6 behavioral invariants and all 7 SP2-1 groups while keeping imports of
brand-new SP2-1 symbols lazy inside test functions so collection succeeds against baseline.
"""

from __future__ import annotations

import contextlib
import dataclasses
import datetime as dt
import io
import json
import socket
import ssl
import threading
from collections.abc import Callable, Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.application.dispatch import KernelToolDomain, PreparedEffect
from superbrain.application.idempotency import tool_uses_idempotency
from superbrain.cli_api import loopback
from superbrain.cli_api.loopback import LoopbackClient, LoopbackTarget, LoopbackTransportError
from superbrain.composition.client_entry import build_tool_caller, read_status
from superbrain.composition.client_entry import main as client_main
from superbrain.composition.shim_entry import main as shim_main
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    ArtifactReadAck,
    ArtifactSendAttempt,
    Call,
    CallContext,
    Endpoint,
    Identity,
    ObjectRef,
    Principal,
    ReadAckInput,
    ResourceDigest,
    Scope,
    SelectorPath,
    SelectorReason,
    SendAttemptState,
    SnapshotStatus,
    StoredResult,
    TaskBinding,
    ToolCommand,
)
from superbrain.core.wire import encode_envelope, load_catalog, parse_json
from tests.support.inc2_cli import (
    get_shared_t7_transport_template,
    mcp_call_frame,
    mcp_init_frames,
    run_inprocess_stdio,
    write_client_profile_file,
    write_credential_file,
    write_owner_only_bytes,
)
from tests.support.inc2_fixture import SampleTlsMaterial
from tests.support.inc2_transport import (
    TransportTestDomain,
    make_trusted_test_dir,
    open_test_loopback_transport,
    read_raw_http_response,
)
from tests.support.kernel_auth import generate_bearer_token, seed_principal_and_credential, seed_repo_grant


def _make_server_ssl_ctx(tls_material: SampleTlsMaterial) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(tls_material.leaf_cert_path), keyfile=str(tls_material.leaf_key_path))
    return ctx


def _read_http_frame(sock: ssl.SSLSocket) -> tuple[str, str, dict[str, str], bytes, bytes]:
    raw = bytearray()
    sock.settimeout(2.0)
    while b"\r\n\r\n" not in raw:
        chunk = sock.recv(4096)
        if not chunk:
            return "", "", {}, b"", bytes(raw)
        raw.extend(chunk)
    head_end = raw.index(b"\r\n\r\n")
    head_text = raw[:head_end].decode("iso-8859-1")
    lines = head_text.split("\r\n")
    parts = lines[0].split(" ", 2)
    method = parts[0] if len(parts) >= 1 else ""
    path = parts[1] if len(parts) >= 2 else ""
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    cl = int(headers.get("content-length", "0"))
    body_start = head_end + 4
    while len(raw) < body_start + cl:
        chunk = sock.recv(4096)
        if not chunk:
            break
        raw.extend(chunk)
    body = bytes(raw[body_start : body_start + cl])
    return method, path, headers, body, bytes(raw[: body_start + cl])


class _LocalTlsMockServer:
    """Minimal multi-request TLS server capturing raw bytes and POST counts."""

    def __init__(
        self,
        ssl_ctx: ssl.SSLContext,
        handler: Callable[[str, str, dict[str, str], bytes, ssl.SSLSocket], tuple[bytes, bool] | None],
    ) -> None:
        self._ssl_ctx = ssl_ctx
        self._handler = handler
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self._sock.settimeout(0.2)
        self.port = int(self._sock.getsockname()[1])
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._lock = threading.Lock()
        self.raw_bytes = bytearray()
        self.requests: list[tuple[str, str, dict[str, str], bytes]] = []
        self.post_count = 0

    def __enter__(self) -> _LocalTlsMockServer:
        self._thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self._stop.set()
        with contextlib.suppress(OSError):
            self._sock.close()
        self._thread.join(timeout=3.0)

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                raw_conn, _ = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_conn, args=(raw_conn,), daemon=True).start()

    def _handle_conn(self, raw_conn: socket.socket) -> None:
        ssl_conn: ssl.SSLSocket | None = None
        try:
            ssl_conn = self._ssl_ctx.wrap_socket(raw_conn, server_side=True)
            while True:
                method, path, headers, body, wire_chunk = _read_http_frame(ssl_conn)
                if not method:
                    break
                with self._lock:
                    self.raw_bytes.extend(wire_chunk)
                    self.requests.append((method, path, headers, body))
                    if method == "POST":
                        self.post_count += 1
                outcome = self._handler(method, path, headers, body, ssl_conn)
                if outcome is None:
                    break
                resp_bytes, keep_open = outcome
                ssl_conn.sendall(resp_bytes)
                if not keep_open:
                    break
        except (TimeoutError, ssl.SSLError, OSError):
            pass
        finally:
            if ssl_conn is not None:
                with contextlib.suppress(OSError):
                    ssl_conn.close()
            with contextlib.suppress(OSError):
                raw_conn.close()


def _http_response(status_line: str, body: bytes, *, close: bool = False) -> bytes:
    conn_hdr = b"Connection: close\r\n" if close else b""
    return (
        f"HTTP/1.1 {status_line}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"{conn_hdr.decode('ascii')}\r\n"
    ).encode("ascii") + body


def _make_profile_bundle(
    case_dir: Path,
    tls_material: SampleTlsMaterial,
    *,
    port: int,
    store_id: str,
    writer_epoch: int,
    instance_id: str,
    token: str,
    workspace: dict[str, JsonValue] | None = None,
) -> tuple[Endpoint, LoopbackTarget, Path]:
    ep = Endpoint(
        version=1,
        host="127.0.0.1",
        port=port,
        store_id=store_id,
        writer_epoch=writer_epoch,
        instance_id=instance_id,
        contract="mcp-tools-v2",
    )
    ep_path = write_owner_only_bytes(case_dir / "endpoint.json", ep.encode_canonical())
    ca_path = write_owner_only_bytes(case_dir / "ca.pem", tls_material.ca_cert_path.read_bytes())
    cred_path = write_credential_file(case_dir / "credential.txt", token)
    prof_path, _ = write_client_profile_file(
        case_dir / "client-profile.json",
        endpoint_path=ep_path,
        expected_store_id=store_id,
        ca_file=ca_path,
        leaf_cert_sha256=tls_material.leaf_cert_sha256,
        credential_file=cred_path,
        workspace=workspace,
    )
    target = LoopbackTarget(
        endpoint=ep,
        expected_store_id=store_id,
        ca_pem=tls_material.ca_cert_path.read_text(encoding="utf-8"),
        leaf_cert_sha256=tls_material.leaf_cert_sha256,
    )
    return ep, target, prof_path


def _extract_mcp_tool_envelope(frame: Mapping[str, JsonValue]) -> dict[str, Any]:
    res = frame["result"]
    assert isinstance(res, dict)
    sc = res["structuredContent"]
    assert isinstance(sc, dict)
    return dict(sc)


# ---------------------------------------------------------------------------
# 1. Matching 5-key identity + matching schema_digest succeeds end-to-end
# ---------------------------------------------------------------------------


def test_matching_five_key_identity_and_envelope_digest_succeeds(
    inc2_tls_material: SampleTlsMaterial,
    trusted_tmp: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """5-key /v2/identity + matching envelope schema_digest succeeds via LoopbackClient, shim, and status."""
    digest = load_catalog().schema_digest
    _, token, _, _ = generate_bearer_token()
    observed_calls: list[dict[str, Any]] = []

    def handler(
        method: str, path: str, headers: dict[str, str], body: bytes, _sock: ssl.SSLSocket
    ) -> tuple[bytes, bool]:
        if method == "GET" and path == "/v2/identity":
            ident = canonical_json(
                {
                    "store_id": "store-match",
                    "writer_epoch": 3,
                    "instance_id": "inst-match",
                    "contract": "mcp-tools-v2",
                    "schema_digest": digest,
                }
            )
            return _http_response("200 OK", ident, close=False), True
        if method == "POST" and path == "/v2/tools/call":
            assert headers.get("authorization") == f"Bearer {token}"
            parsed = json.loads(body.decode("utf-8"))
            observed_calls.append(parsed)
            assert parsed.get("schema_digest") == digest
            env = encode_envelope(
                {
                    "ok": True,
                    "data": {
                        "ready": True,
                        "store_id": "store-match",
                        "writer_epoch": 3,
                        "schema_version": 4,
                        "policy_schema_version": 3,
                        "degraded_codes": [],
                    },
                }
            )
            return _http_response("200 OK", env, close=True), False
        return _http_response("400 Bad Request", b"{}", close=True), False

    case_dir = make_trusted_test_dir("sp2-1-match")
    with _LocalTlsMockServer(_make_server_ssl_ctx(inc2_tls_material), handler) as srv:
        _, target, prof_path = _make_profile_bundle(
            case_dir,
            inc2_tls_material,
            port=srv.port,
            store_id="store-match",
            writer_epoch=3,
            instance_id="inst-match",
            token=token,
        )

        # LoopbackClient
        res_client = LoopbackClient().call(target, ToolCommand("get_health", {"schema_version": "2.0"}, token=token))
        assert res_client["ok"] is True

        # build_tool_caller + run_stdio (brain-mcp / brain mcp caller path)
        caller = build_tool_caller(prof_path, trusted_tmp, os_adapters())
        rc, frames = run_inprocess_stdio(
            caller, [*mcp_init_frames(1), mcp_call_frame(2, "get_health", {"schema_version": "2.0"})]
        )
        assert rc == 0
        assert _extract_mcp_tool_envelope(frames[1])["ok"] is True

        # read_status + brain status CLI entrypoint
        status_env = read_status(prof_path, os_adapters())
        assert status_env["ok"] is True
        capsys.readouterr()
        cli_rc = client_main(["status", "--profile", str(prof_path)])
        assert cli_rc == 0
        out_line = capsys.readouterr().out.strip()
        assert json.loads(out_line)["ok"] is True

        assert len(observed_calls) == 4
        assert all(c["schema_digest"] == digest for c in observed_calls)


# ---------------------------------------------------------------------------
# 2. Missing 4-key digest OR mismatched/invalid 5-key digest -> UNSUPPORTED_VERSION
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "case_kind",
    ["missing_digest_4key", "mismatched_digest", "malformed_digest"],
)
def test_missing_or_mismatched_identity_digest_returns_unsupported_version_zero_secrets(
    case_kind: str,
    inc2_tls_material: SampleTlsMaterial,
    trusted_tmp: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Missing/mismatched/malformed /v2/identity schema_digest fails with unsupported_version and 0 bearer bytes."""
    _, secret_token, _, secret_b64 = generate_bearer_token()
    payload_obj: dict[str, Any] = {
        "store_id": "store-ver",
        "writer_epoch": 2,
        "instance_id": "inst-ver",
        "contract": "mcp-tools-v2",
    }
    if case_kind == "mismatched_digest":
        payload_obj["schema_digest"] = "sha256:" + ("0" * 64)
    elif case_kind == "malformed_digest":
        payload_obj["schema_digest"] = "sha256:not-valid"
    ident_bytes = canonical_json(payload_obj)

    dispatches = 0

    def handler(
        method: str, path: str, _headers: dict[str, str], _body: bytes, _sock: ssl.SSLSocket
    ) -> tuple[bytes, bool]:
        nonlocal dispatches
        if method == "GET" and path == "/v2/identity":
            return _http_response("200 OK", ident_bytes, close=False), True
        if method == "POST":
            dispatches += 1
        return _http_response("500 Internal Server Error", b"{}", close=True), False

    case_dir = make_trusted_test_dir(f"sp2-1-ver-{case_kind}")
    with _LocalTlsMockServer(_make_server_ssl_ctx(inc2_tls_material), handler) as srv:
        _, target, prof_path = _make_profile_bundle(
            case_dir,
            inc2_tls_material,
            port=srv.port,
            store_id="store-ver",
            writer_epoch=2,
            instance_id="inst-ver",
            token=secret_token,
        )

        # LoopbackClient
        with pytest.raises(LoopbackTransportError) as exc_cl:
            LoopbackClient().call(target, ToolCommand("get_health", {"schema_version": "2.0"}, token=secret_token))
        assert exc_cl.value.code is ErrorCode.UNSUPPORTED_VERSION
        assert exc_cl.value.request_may_have_run is False

        # shim_entry brain-mcp and brain mcp paths
        for argv in (["--profile", str(prof_path)], ["mcp", "--profile", str(prof_path)]):
            stdin_bytes = b"".join(
                canonical_json(f) + b"\n"
                for f in (*mcp_init_frames(1), mcp_call_frame(2, "get_health", {"schema_version": "2.0"}))
            )
            stdin_stream = type("_In", (), {"buffer": io.BytesIO(stdin_bytes)})()
            stdout_buf = io.BytesIO()
            stdout_stream = type("_Out", (), {"buffer": stdout_buf})()
            with monkeypatch.context() as mp:
                mp.setattr("sys.stdin", stdin_stream)
                mp.setattr("sys.stdout", stdout_stream)
                mp.chdir(trusted_tmp)
                rc = shim_main(argv)
            assert rc == 0
            frames = [
                parse_json(line.encode("utf-8"))
                for line in stdout_buf.getvalue().decode("utf-8").splitlines()
                if line
            ]
            tool_res = _extract_mcp_tool_envelope(cast(Mapping[str, JsonValue], frames[1]))
            assert tool_res == {
                "ok": False,
                "error": {"code": "unsupported_version", "message": "unsupported version"},
            }

        # read_status + brain status
        st = read_status(prof_path, os_adapters())
        assert st == {"ok": False, "error": {"code": "unsupported_version", "message": "unsupported version"}}
        capsys.readouterr()
        assert client_main(["status", "--profile", str(prof_path)]) == 1
        assert json.loads(capsys.readouterr().out)["error"]["code"] == "unsupported_version"

        with srv._lock:
            requests_snapshot = list(srv.requests)
            raw_wire_bytes = bytes(srv.raw_bytes)
            post_count = srv.post_count
        ident_probes = sum(1 for m, p, _, _ in requests_snapshot if m == "GET" and p == "/v2/identity")
        assert ident_probes == 5
        assert post_count == 0
        assert dispatches == 0
        assert secret_b64.encode("ascii") not in raw_wire_bytes
        assert b"Authorization" not in raw_wire_bytes


# ---------------------------------------------------------------------------
# 3. Wrong 4-key identity -> IDENTITY_MISMATCH with or without schema_digest (Kills M2)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("with_digest", [True, False], ids=["with_digest", "without_digest"])
@pytest.mark.parametrize(
    ("field", "bad_value"),
    [
        ("store_id", "wrong-store"),
        ("writer_epoch", 999),
        ("instance_id", "wrong-inst"),
        ("contract", "mcp-tools-v1"),
    ],
)
def test_wrong_identity_fields_still_return_identity_mismatch_with_or_without_digest(
    field: str,
    bad_value: Any,
    with_digest: bool,
    inc2_tls_material: SampleTlsMaterial,
    trusted_tmp: Path,
) -> None:
    """Kill M2: bad store_id/writer_epoch/instance_id/contract returns identity_mismatch even if digest missing."""
    digest = load_catalog().schema_digest
    _, secret_token, _, secret_b64 = generate_bearer_token()
    payload_obj: dict[str, Any] = {
        "store_id": "store-m2",
        "writer_epoch": 1,
        "instance_id": "inst-m2",
        "contract": "mcp-tools-v2",
    }
    payload_obj[field] = bad_value
    if with_digest:
        payload_obj["schema_digest"] = digest
    ident_bytes = canonical_json(payload_obj)

    def handler(
        method: str, path: str, _headers: dict[str, str], _body: bytes, _sock: ssl.SSLSocket
    ) -> tuple[bytes, bool]:
        if method == "GET" and path == "/v2/identity":
            return _http_response("200 OK", ident_bytes, close=False), True
        return _http_response("500 Internal Server Error", b"{}", close=True), False

    case_dir = make_trusted_test_dir(f"sp2-1-m2-{field}-{int(with_digest)}")
    with _LocalTlsMockServer(_make_server_ssl_ctx(inc2_tls_material), handler) as srv:
        _, target, prof_path = _make_profile_bundle(
            case_dir,
            inc2_tls_material,
            port=srv.port,
            store_id="store-m2",
            writer_epoch=1,
            instance_id="inst-m2",
            token=secret_token,
        )
        with pytest.raises(LoopbackTransportError) as exc_cl:
            LoopbackClient().call(target, ToolCommand("get_health", {"schema_version": "2.0"}, token=secret_token))
        assert exc_cl.value.code is ErrorCode.IDENTITY_MISMATCH
        assert exc_cl.value.request_may_have_run is False

        caller = build_tool_caller(prof_path, trusted_tmp, os_adapters())
        _, frames = run_inprocess_stdio(
            caller, [*mcp_init_frames(1), mcp_call_frame(2, "get_health", {"schema_version": "2.0"})]
        )
        assert _extract_mcp_tool_envelope(frames[1])["error"]["code"] == "identity_mismatch"

        status_res = read_status(prof_path, os_adapters())
        assert status_res["error"]["code"] == "identity_mismatch"

        with srv._lock:
            requests_snapshot = list(srv.requests)
            raw_wire_bytes = bytes(srv.raw_bytes)
            post_count = srv.post_count
        ident_probes = sum(1 for m, p, _, _ in requests_snapshot if m == "GET" and p == "/v2/identity")
        assert ident_probes == 3
        assert post_count == 0
        assert secret_b64.encode("ascii") not in raw_wire_bytes
        assert b"Authorization" not in raw_wire_bytes


def test_parse_identity_response_codec_contract() -> None:
    """Lazy-imported parse_identity_response parses 4-key and 5-key identity separately from digest verification."""
    from superbrain.cli_api._loopback_wire import parse_identity_response

    digest = load_catalog().schema_digest
    ident_4, contract_4, dig_4 = parse_identity_response(
        canonical_json(
            {
                "store_id": "s-codec",
                "writer_epoch": 7,
                "instance_id": "i-codec",
                "contract": "mcp-tools-v2",
            }
        )
    )
    assert ident_4 == Identity(store_id="s-codec", writer_epoch=7, instance_id="i-codec")
    assert contract_4 == "mcp-tools-v2"
    assert dig_4 is None

    ident_5, contract_5, dig_5 = parse_identity_response(
        canonical_json(
            {
                "store_id": "s-codec",
                "writer_epoch": 7,
                "instance_id": "i-codec",
                "contract": "mcp-tools-v2",
                "schema_digest": digest,
            }
        )
    )
    assert ident_5 == ident_4
    assert contract_5 == "mcp-tools-v2"
    assert dig_5 == digest

    for bad in (
        canonical_json({"store_id": "s", "writer_epoch": 1, "contract": "mcp-tools-v2"}),
        canonical_json(
            {"store_id": "s", "writer_epoch": 1, "instance_id": "i", "contract": "mcp-tools-v2", "extra": 1}
        ),
        canonical_json({"store_id": "s", "writer_epoch": True, "instance_id": "i", "contract": "mcp-tools-v2"}),
    ):
        with pytest.raises(BrainError) as exc:
            parse_identity_response(bad)
        assert exc.value.code is ErrorCode.INVALID_INPUT


# ---------------------------------------------------------------------------
# 4. HTTP 426 unsupported_version from POST /v2/tools/call (Kills M1)
# ---------------------------------------------------------------------------


def test_http_426_unsupported_version_surfaces_without_daemon_unavailable(
    inc2_tls_material: SampleTlsMaterial,
    trusted_tmp: Path,
) -> None:
    """Kill M1: HTTP 426 unsupported_version returns envelope intact without raising DAEMON_UNAVAILABLE."""
    assert loopback._ERROR_STATUS_EXPECTED_CODE.get(426) == ErrorCode.UNSUPPORTED_VERSION.value

    digest = load_catalog().schema_digest
    _, token, _, _ = generate_bearer_token()
    return_wrong_code = False

    def handler(
        method: str, path: str, _headers: dict[str, str], _body: bytes, _sock: ssl.SSLSocket
    ) -> tuple[bytes, bool]:
        if method == "GET" and path == "/v2/identity":
            ident = canonical_json(
                {
                    "store_id": "store-426",
                    "writer_epoch": 1,
                    "instance_id": "inst-426",
                    "contract": "mcp-tools-v2",
                    "schema_digest": digest,
                }
            )
            return _http_response("200 OK", ident, close=False), True
        if method == "POST" and path == "/v2/tools/call":
            err_code = ErrorCode.INVALID_INPUT if return_wrong_code else ErrorCode.UNSUPPORTED_VERSION
            msg = "invalid input" if return_wrong_code else "unsupported version"
            env = encode_envelope(
                {
                    "ok": False,
                    "error": {"code": err_code.value, "message": msg},
                }
            )
            return _http_response("426 Upgrade Required", env, close=True), False
        return _http_response("400 Bad Request", b"{}", close=True), False

    case_dir = make_trusted_test_dir("sp2-1-426")
    with _LocalTlsMockServer(_make_server_ssl_ctx(inc2_tls_material), handler) as srv:
        _, target, prof_path = _make_profile_bundle(
            case_dir,
            inc2_tls_material,
            port=srv.port,
            store_id="store-426",
            writer_epoch=1,
            instance_id="inst-426",
            token=token,
        )

        # Positive 426 -> envelope returned directly (NO ToolCallUncertain / DAEMON_UNAVAILABLE)
        res = LoopbackClient().call(target, ToolCommand("get_health", {"schema_version": "2.0"}, token=token))
        assert res == {"ok": False, "error": {"code": "unsupported_version", "message": "unsupported version"}}

        caller = build_tool_caller(prof_path, trusted_tmp, os_adapters())
        _, frames = run_inprocess_stdio(
            caller, [*mcp_init_frames(1), mcp_call_frame(2, "get_health", {"schema_version": "2.0"})]
        )
        assert _extract_mcp_tool_envelope(frames[1]) == res

        st = read_status(prof_path, os_adapters())
        assert st == res

        # Negative twin: 426 with mismatched body error code still fails closed as uncertain transport error
        return_wrong_code = True
        with pytest.raises(LoopbackTransportError) as exc_bad_426:
            LoopbackClient().call(target, ToolCommand("get_health", {"schema_version": "2.0"}, token=token))
        assert exc_bad_426.value.code is ErrorCode.DAEMON_UNAVAILABLE
        assert exc_bad_426.value.request_may_have_run is True


# ---------------------------------------------------------------------------
# 5. POST /v2/capture/events + capability separation (Kills M5)
# ---------------------------------------------------------------------------


def test_capture_events_codec_and_capability_binding_unit_contract() -> None:
    """Lazy-imported capture codec & CaptureProducerBinding enforce schema_digest and strict validation."""
    from superbrain.cli_api._loopback_wire import (
        CAPTURE_EVENTS_PATH,
        decode_capture_batch,
        encode_capture_batch,
    )
    from superbrain.core.kernel import (
        CAPABILITY_CAPTURE_PRODUCER,
        CAPABILITY_OPERATOR_CLI,
        CaptureBatchCommand,
        CaptureProducerBinding,
    )

    assert CAPTURE_EVENTS_PATH == "/v2/capture/events"
    assert CAPABILITY_CAPTURE_PRODUCER == "capture_producer"
    assert CAPABILITY_OPERATOR_CLI == "operator_cli"
    assert len(load_catalog().tools) == 8

    binding = CaptureProducerBinding(producer_stream="claude-hook-v1", repo_id="repo-1", checkout_id="chk-1")
    assert (binding.producer_stream, binding.repo_id, binding.checkout_id) == ("claude-hook-v1", "repo-1", "chk-1")

    with pytest.raises(BrainError):
        CaptureProducerBinding(producer_stream="", repo_id="repo-1", checkout_id="chk-1")

    cmd = CaptureBatchCommand(
        producer_stream="claude-hook-v1",
        repo_id="repo-1",
        checkout_id="chk-1",
        events=({"event_id": "ev-1", "kind": "tool_post", "payload": {"ok": True}},),
        token="cap-token",
        correlation_id="cap-corr-1",
    )
    encoded = encode_capture_batch(cmd)
    parsed = json.loads(encoded.decode("utf-8"))
    assert parsed["schema_digest"] == load_catalog().schema_digest
    decoded = decode_capture_batch(encoded, token="cap-token")
    assert decoded == cmd

    # Missing or mismatched digest -> UNSUPPORTED_VERSION
    no_digest = canonical_json({k: v for k, v in parsed.items() if k != "schema_digest"})
    with pytest.raises(BrainError) as exc_nd:
        decode_capture_batch(no_digest, token="cap-token")
    assert exc_nd.value.code is ErrorCode.UNSUPPORTED_VERSION

    wrong_digest = canonical_json({**parsed, "schema_digest": "sha256:" + ("0" * 64)})
    with pytest.raises(BrainError) as exc_wd:
        decode_capture_batch(wrong_digest, token="cap-token")
    assert exc_wd.value.code is ErrorCode.UNSUPPORTED_VERSION

    # Extra key or invalid events -> INVALID_INPUT
    with pytest.raises(BrainError) as exc_ex:
        decode_capture_batch(canonical_json({**parsed, "extra": 1}), token="cap-token")
    assert exc_ex.value.code is ErrorCode.INVALID_INPUT


def _raw_tls_post_after_identity(
    *,
    host: str,
    port: int,
    ca_pem: str,
    token: str,
    store_id: str,
    writer_epoch: int,
    instance_id: str,
    path: str,
    body_bytes: bytes,
) -> tuple[int, dict[str, Any]]:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cadata=ca_pem)
    ctx.check_hostname = True
    with socket.create_connection((host, port), timeout=2.0) as raw:
        with ctx.wrap_socket(raw, server_hostname="127.0.0.1") as tls_sock:
            tls_sock.sendall(f"GET /v2/identity HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode("ascii"))
            id_raw = read_raw_http_response(tls_sock)
            assert b"200 OK" in id_raw
            post = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                f"Authorization: Bearer {token}\r\n"
                f"X-Store-Id: {store_id}\r\n"
                f"X-Writer-Epoch: {writer_epoch}\r\n"
                f"X-Superbrain-Instance: {instance_id}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(body_bytes)}\r\n\r\n"
            ).encode("ascii") + body_bytes
            tls_sock.sendall(post)
            resp_raw = read_raw_http_response(tls_sock)
    head_text = resp_raw.split(b"\r\n\r\n", 1)[0].decode("iso-8859-1")
    status_code = int(head_text.split("\r\n")[0].split(" ")[1])
    resp_body = json.loads(resp_raw.split(b"\r\n\r\n", 1)[1].decode("utf-8"))
    return status_code, resp_body


def test_capture_events_route_capability_separation_and_digest_gate_on_live_server() -> None:
    """Kill M5: POST /v2/capture/events enforces 426 digest gate, capability isolation, and stream/repo/checkout."""
    from superbrain.core.kernel import (
        CAPABILITY_CAPTURE_PRODUCER,
        CAPABILITY_OPERATOR_CLI,
        CaptureProducerBinding,
    )

    tpl = get_shared_t7_transport_template()
    dan = tpl.dan
    ws_a = tpl.ws_a
    ws_b = tpl.ws_b
    assert dan is not None
    assert ws_a is not None
    assert ws_b is not None
    domain = TransportTestDomain(ws_a=ws_a)
    digest = load_catalog().schema_digest

    with open_test_loopback_transport(tpl, name="sp2-1-capture", domain=domain) as h:
        # Seed capture_producer and operator_cli credentials into policy & publish capabilities to AuthGate
        cap_cred_holder: list[Any] = []
        cli_cred_holder: list[Any] = []

        def _publish_cap_auth() -> None:
            session: Any = h.loop._session
            assert session is not None
            rt = session._rt
            cap_seeded = seed_principal_and_credential(
                rt.policy, owner_id=dan.owner_id, harness_id="capture-hook", machine_id=dan.machine_id
            )
            seed_repo_grant(
                rt.policy,
                principal_id=cap_seeded.principal.principal_id,
                repo_id=ws_a.repo_id,
                owner_id=dan.owner_id,
            )
            cli_seeded = seed_principal_and_credential(
                rt.policy, owner_id=dan.owner_id, harness_id="operator-cli-tool", machine_id=dan.machine_id
            )
            seed_repo_grant(
                rt.policy,
                principal_id=cli_seeded.principal.principal_id,
                repo_id=ws_a.repo_id,
                owner_id=dan.owner_id,
            )
            base_snap = rt.policy.snapshot()
            cap_rec = replace(
                base_snap.credentials[cap_seeded.credential_id],
                capabilities=frozenset({CAPABILITY_CAPTURE_PRODUCER}),
                capture_binding=CaptureProducerBinding(
                    producer_stream="claude-hook-v1",
                    repo_id=ws_a.repo_id,
                    checkout_id=ws_a.checkout_id,
                ),
            )
            cli_rec = replace(
                base_snap.credentials[cli_seeded.credential_id],
                capabilities=frozenset({CAPABILITY_OPERATOR_CLI}),
            )
            new_snap = replace(
                base_snap,
                credentials={
                    **base_snap.credentials,
                    cap_seeded.credential_id: cap_rec,
                    cli_seeded.credential_id: cli_rec,
                },
            )
            session.auth_gate.publish(new_snap)
            cap_cred_holder.append(cap_seeded)
            cli_cred_holder.append(cli_seeded)

        h.loop.run_owner_action(_publish_cap_auth).result(timeout=5.0)
        cap_cred = cap_cred_holder[0]
        cli_cred = cli_cred_holder[0]
        ep = h.ready.endpoint
        ca_pem = h.tls.ca_cert_path.read_text(encoding="utf-8")
        seq_before = h.ledger_sequence()

        valid_capture_payload = {
            "producer_stream": "claude-hook-v1",
            "repo_id": ws_a.repo_id,
            "checkout_id": ws_a.checkout_id,
            "events": [
                {
                    "event_id": "ev-01",
                    "producer_stream": "claude-hook-v1",
                    "sequence": 1,
                    "harness_id": "capture-hook",
                    "kind": "stop",
                    "recorded_at": "2026-11-19T00:00:00.000000Z",
                    "payload": {"ok": True},
                }
            ],
            "correlation_id": None,
            "schema_digest": digest,
        }
        valid_tool_payload = {
            "tool": "get_health",
            "arguments": {"schema_version": "2.0"},
            "correlation_id": None,
            "selected_scope": None,
            "schema_digest": digest,
        }

        def send(path: str, payload: dict[str, Any], tok: str) -> tuple[int, dict[str, Any]]:
            return _raw_tls_post_after_identity(
                host=ep.host,
                port=ep.port,
                ca_pem=ca_pem,
                token=tok,
                store_id=ep.store_id,
                writer_epoch=ep.writer_epoch,
                instance_id=ep.instance_id,
                path=path,
                body_bytes=canonical_json(payload),
            )

        # Positive control: MCP shim token succeeds on POST /v2/tools/call
        st_mcp_ok, body_mcp_ok = send("/v2/tools/call", valid_tool_payload, tpl.cred.token)
        assert st_mcp_ok == 200 and body_mcp_ok["ok"] is True

        # 1) Missing or mismatched schema_digest on BOTH endpoints -> 426 unsupported_version, 0 mutations
        for bad_dig_patch in ({}, {"schema_digest": "sha256:" + ("f" * 64)}):
            tool_no_dig = {k: v for k, v in valid_tool_payload.items() if k != "schema_digest"} | bad_dig_patch
            st_t, body_t = send("/v2/tools/call", tool_no_dig, tpl.cred.token)
            assert st_t == 426 and body_t["error"]["code"] == "unsupported_version"

            cap_no_dig = {k: v for k, v in valid_capture_payload.items() if k != "schema_digest"} | bad_dig_patch
            st_c, body_c = send("/v2/capture/events", cap_no_dig, cap_cred.token)
            assert st_c == 426 and body_c["error"]["code"] == "unsupported_version"

        # 2) MCP token & operator_cli token on POST /v2/capture/events -> 409 identity_mismatch (Kills M5)
        for non_cap_tok in (tpl.cred.token, cli_cred.token):
            st_nc, body_nc = send("/v2/capture/events", valid_capture_payload, non_cap_tok)
            assert st_nc == 409 and body_nc["error"]["code"] == "identity_mismatch"

        # 3) Capture producer token & operator_cli token on POST /v2/tools/call -> 409 identity_mismatch
        for non_mcp_tok in (cap_cred.token, cli_cred.token):
            st_sym, body_sym = send("/v2/tools/call", valid_tool_payload, non_mcp_tok)
            assert st_sym == 409 and body_sym["error"]["code"] == "identity_mismatch"

        # 4) Capture producer token with wrong stream/repo/checkout -> 409 identity_mismatch
        for mismatch_field, mismatch_val in (
            ("producer_stream", "codex-hook-v1"),
            ("repo_id", ws_b.repo_id),
            ("checkout_id", "wrong-chk"),
        ):
            st_m, body_m = send(
                "/v2/capture/events",
                {**valid_capture_payload, mismatch_field: mismatch_val},
                cap_cred.token,
            )
            assert st_m == 409 and body_m["error"]["code"] == "identity_mismatch"

        # 5) Steps 1-4 caused 0 ledger writes; SP2-2 ingest rejects malformed events and commits valid events.
        assert h.ledger_sequence() == seq_before
        malformed_capture_payload = {
            **valid_capture_payload,
            "events": [{"event_id": "ev-bad", "kind": "stop"}],
        }
        st_bad, body_bad = send("/v2/capture/events", malformed_capture_payload, cap_cred.token)
        assert st_bad == 200
        assert body_bad["ok"] is False and body_bad["error"]["code"] == "invalid_input"
        assert h.ledger_sequence() == seq_before

        st_ok, body_ok = send("/v2/capture/events", valid_capture_payload, cap_cred.token)
        assert st_ok == 200
        assert body_ok["ok"] is True
        assert body_ok["data"]["accepted_count"] == 1
        assert body_ok["data"]["committed_event_sequences"] == [1]
        assert domain.executed_keys == []


# ---------------------------------------------------------------------------
# 6. prepare_task(mode="discover") readonly routing & checkout guard (Kills M3, M4)
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class _DiscoverSpyDomain(KernelToolDomain):
    repo_id: str
    checkout_id: str
    spoof_repo_id: str | None = None
    spoof_checkout_id: str | None = None
    readonly_calls: int = 0
    mutation_calls: int = 0

    def supports_tool(self, tool: str, *, deep: bool = False) -> bool:
        return (not deep) and tool in {"prepare_task", "get_health"}

    def prepare_mutation(self, call: Call, ctx: CallContext, *, now: dt.datetime) -> PreparedEffect:
        del call, ctx, now
        self.mutation_calls += 1
        blob = canonical_json({"kind": "work"})
        ref = ObjectRef(kind="delivery_result", id=new_id(), revision=1, digest=digest_bytes(blob))

        def _apply(tx: Any) -> StoredResult:
            tx.hold_blob(blob, holder_id=ref.id)
            return StoredResult(result_id=ref.id, assignment_id=None, refs=(ref,))

        return PreparedEffect(blobs=(blob,), apply=_apply)

    def execute_readonly(self, call: Call, ctx: CallContext) -> dict[str, JsonValue]:
        del ctx
        if call.tool == "prepare_task" and call.arguments.get("mode") == "discover":
            self.readonly_calls += 1
            return {
                "workspace_id": self.spoof_repo_id or self.repo_id,
                "checkout_id": self.spoof_checkout_id or self.checkout_id,
                "continuity": [
                    {
                        "kind": "handoff",
                        "id": "hand-disc-1",
                        "revision_epoch": 0,
                        "revision": 1,
                        "digest": "sha256:" + ("a" * 64),
                        "summary": "Goal: active continuity item",
                        "status": "ok",
                    }
                ],
                "degraded_codes": [],
            }
        raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")

    def render_stored(
        self, result: StoredResult, principal: Principal, *, selected_scope: Scope | None
    ) -> dict[str, JsonValue]:
        del result, principal, selected_scope
        return {
            "workspace_id": self.repo_id,
            "checkout_id": self.checkout_id,
            "source_snapshot_id": "snap-1",
            "snapshot_status": "available",
            "degraded_codes": [],
            "task_id": "task-1",
            "delivery_id": "deliv-1",
            "skills": [],
            "lessons": [],
            "continuity": [],
            "context": [],
            "finishing_gates": [],
        }


def test_prepare_task_discover_skips_idempotency_routes_readonly_and_enforces_checkout_match(
    trusted_tmp: Path,
) -> None:
    """Kill M3 & M4: discover is non-idempotent readonly and build_tool_caller rejects spoofed workspace/checkout."""
    tpl = get_shared_t7_transport_template()
    assert tpl.ws_a is not None
    scope_a = Scope(tpl.ws_a.repo_id, tpl.ws_a.checkout_id)

    # Unit M3 gate
    discover_call = Call(
        tool="prepare_task",
        arguments={
            "schema_version": "2.0",
            "mode": "discover",
            "workspace_id": tpl.ws_a.repo_id,
            "checkout_id": tpl.ws_a.checkout_id,
            "context_budget_tokens": 4000,
        },
        correlation_id=None,
        selected_scope=scope_a,
    )
    work_call = Call(
        tool="prepare_task",
        arguments={
            "schema_version": "2.0",
            "mode": "work",
            "workspace_id": tpl.ws_a.repo_id,
            "checkout_id": tpl.ws_a.checkout_id,
            "description": "work call",
            "context_budget_tokens": 4000,
            "idempotency_key": "idem_work_m3_check_1",
        },
        correlation_id=None,
        selected_scope=scope_a,
    )
    assert tool_uses_idempotency(discover_call) is False
    assert tool_uses_idempotency(work_call) is True

    # End-to-end daemon + shim caller routing + M4 checkout spoof guard
    domain = _DiscoverSpyDomain(repo_id=tpl.ws_a.repo_id, checkout_id=tpl.ws_a.checkout_id)
    with open_test_loopback_transport(tpl, name="sp2-1-discover", domain=domain) as h:
        ws_dict: dict[str, JsonValue] = {
            "alias": tpl.ws_a.alias,
            "checkout_path": str(tpl.ws_a.checkout_path),
            "expected_workspace_id": tpl.ws_a.repo_id,
            "expected_checkout_id": tpl.ws_a.checkout_id,
        }
        prof_path = trusted_tmp / "disc-client"
        ep_path = write_owner_only_bytes(prof_path / "ep.json", h.ready.endpoint.encode_canonical())
        ca_path = write_owner_only_bytes(prof_path / "ca.pem", h.tls.ca_cert_path.read_bytes())
        cred_path = write_credential_file(prof_path / "cred.txt", h.cred.token)
        profile_file, _ = write_client_profile_file(
            prof_path / "profile.json",
            endpoint_path=ep_path,
            expected_store_id=h.store_id,
            ca_file=ca_path,
            leaf_cert_sha256=h.ready.leaf_cert_sha256,
            credential_file=cred_path,
            workspace=ws_dict,
        )
        caller = build_tool_caller(profile_file, Path(tpl.ws_a.checkout_path), os_adapters())
        seq_before = h.ledger_sequence()
        idem_before = h.idempotency_count()

        # Positive discover: 0 idempotency rows, 0 ledger advance, execute_readonly called once
        _, frames_ok = run_inprocess_stdio(
            caller,
            [*mcp_init_frames(1), mcp_call_frame(2, "prepare_task", {"schema_version": "2.0", "mode": "discover"})],
        )
        env_ok = _extract_mcp_tool_envelope(frames_ok[1])
        assert env_ok["ok"] is True
        assert env_ok["data"]["workspace_id"] == tpl.ws_a.repo_id
        assert env_ok["data"]["checkout_id"] == tpl.ws_a.checkout_id
        assert len(env_ok["data"]["continuity"]) == 1
        assert domain.readonly_calls == 1
        assert domain.mutation_calls == 0
        assert h.idempotency_count() == idem_before
        assert h.ledger_sequence() == seq_before

        # M4: Spoofed wrong workspace_id OR wrong checkout_id on discover -> identity_mismatch
        domain.spoof_checkout_id = "chk-spoofed"
        _, frames_spoof_chk = run_inprocess_stdio(
            caller,
            [*mcp_init_frames(1), mcp_call_frame(2, "prepare_task", {"schema_version": "2.0", "mode": "discover"})],
        )
        assert _extract_mcp_tool_envelope(frames_spoof_chk[1])["error"]["code"] == "identity_mismatch"

        domain.spoof_checkout_id = None
        domain.spoof_repo_id = "repo-spoofed"
        _, frames_spoof_repo = run_inprocess_stdio(
            caller,
            [*mcp_init_frames(1), mcp_call_frame(2, "prepare_task", {"schema_version": "2.0", "mode": "discover"})],
        )
        assert _extract_mcp_tool_envelope(frames_spoof_repo[1])["error"]["code"] == "identity_mismatch"


# ---------------------------------------------------------------------------
# 7. ReadAck validates artifact_id & revision_epoch against SendAttempt (Kills M6)
# ---------------------------------------------------------------------------


def test_read_ack_enforces_artifact_id_and_revision_epoch_match() -> None:
    """Kill M6: mismatched artifact_id or revision_epoch -> INVALID_INPUT; match persists both on ArtifactReadAck."""
    from superbrain.application.send_attempts import (
        ProjectedReadAck,
        extract_projected_read_acks,
        record_projected_read_acks,
        record_read_acks,
    )

    principal = Principal(
        principal_id="princ-m6",
        owner_id="owner-m6",
        harness_id="codex",
        machine_id="mach-m6",
    )
    scope = Scope(repo_id="repo-m6", checkout_id="chk-m6")
    digest_hdr = digest_bytes(b"header bytes")
    attempt = ArtifactSendAttempt(
        send_attempt_id=new_id(),
        logical_result_id=new_id(),
        principal_id=principal.principal_id,
        task_id="task-m6",
        artifact_id="hand-m6-1",
        revision_epoch=2,
        revision=3,
        level="L1",
        resource_digests=(ResourceDigest(name="handoff_header", digest=digest_hdr),),
        state=SendAttemptState.SERVED_ONLY,
    )
    binding = TaskBinding(
        task_id="task-m6",
        owner_id=principal.owner_id,
        repo_id=scope.repo_id,
        checkout_id="chk-m6",
        delivery_id="deliv-m6",
        assignment_id=None,
        source_snapshot_id=None,
        snapshot_status=SnapshotStatus.UNAVAILABLE,
        selector_path=SelectorPath.RULES,
        selector_reason=SelectorReason.PROVIDER_UNAVAILABLE,
    )

    # 1) extract_projected_read_acks accepts artifact_id + revision_epoch (including 0) and rejects invalid/missing
    extracted = extract_projected_read_acks(
        {
            "read_acks": [
                {
                    "served_receipt_id": attempt.send_attempt_id,
                    "task_id": "task-m6",
                    "artifact_id": "hand-m6-1",
                    "revision_epoch": 0,
                    "revision": 3,
                    "resource_digests": [{"name": "handoff_header", "digest": digest_hdr}],
                }
            ]
        }
    )
    assert len(extracted) == 1
    assert extracted[0].artifact_id == "hand-m6-1"
    assert extracted[0].revision_epoch == 0

    for bad_raw_ack in (
        {
            "served_receipt_id": attempt.send_attempt_id,
            "task_id": "task-m6",
            "revision_epoch": 0,
            "revision": 3,
            "resource_digests": [{"name": "handoff_header", "digest": digest_hdr}],
        },
        {
            "served_receipt_id": attempt.send_attempt_id,
            "task_id": "task-m6",
            "artifact_id": "bad art",
            "revision_epoch": 0,
            "revision": 3,
            "resource_digests": [{"name": "handoff_header", "digest": digest_hdr}],
        },
        {
            "served_receipt_id": attempt.send_attempt_id,
            "task_id": "task-m6",
            "artifact_id": "hand-m6-1",
            "revision_epoch": -1,
            "revision": 3,
            "resource_digests": [{"name": "handoff_header", "digest": digest_hdr}],
        },
        {
            "served_receipt_id": attempt.send_attempt_id,
            "task_id": "task-m6",
            "artifact_id": "hand-m6-1",
            "revision_epoch": True,
            "revision": 3,
            "resource_digests": [{"name": "handoff_header", "digest": digest_hdr}],
        },
    ):
        with pytest.raises(BrainError) as exc_ext:
            extract_projected_read_acks({"read_acks": [cast(JsonValue, bad_raw_ack)]})
        assert exc_ext.value.code is ErrorCode.INVALID_INPUT

    class _PolicyStub:
        def allows(self, p: Principal, s: Scope | None, *, action: str) -> bool:
            return p == principal and s == scope and action == "record_outcome"

    saved_acks: list[ArtifactReadAck] = []

    class _TxStub:
        def read_send_attempt(self, send_attempt_id: str) -> ArtifactSendAttempt | None:
            return attempt if send_attempt_id == attempt.send_attempt_id else None

        def read_task_binding(self, task_id: str) -> TaskBinding | None:
            return binding if task_id == "task-m6" else None

        def read_read_ack_by_receipt(self, served_receipt_id: str) -> ArtifactReadAck | None:
            for item in saved_acks:
                if item.served_receipt_id == served_receipt_id:
                    return item
            return None

        def save_read_ack(self, ack: ArtifactReadAck) -> None:
            saved_acks.append(ack)

    tx: Any = _TxStub()
    policy: Any = _PolicyStub()

    # 2) Mismatched artifact_id -> INVALID_INPUT (both record_read_acks AND record_projected_read_acks)
    bad_art_input = ReadAckInput(
        served_receipt_id=attempt.send_attempt_id,
        task_id="task-m6",
        artifact_id="hand-wrong",
        revision_epoch=2,
        revision=3,
        resource_digests=(ResourceDigest(name="handoff_header", digest=digest_hdr),),
    )
    with pytest.raises(BrainError) as exc_art:
        record_read_acks(
            tx,
            policy=policy,
            principal=principal,
            effective_scope=scope,
            expected_task_id="task-m6",
            acks=(bad_art_input,),
        )
    assert exc_art.value.code is ErrorCode.INVALID_INPUT
    assert saved_acks == []

    bad_art_epoch0_proj = ProjectedReadAck(
        served_receipt_id=attempt.send_attempt_id,
        task_id="task-m6",
        artifact_id="hand-wrong",
        revision_epoch=0,
        revision=3,
        resource_digests=(("handoff_header", digest_hdr),),
    )
    with pytest.raises(BrainError) as exc_art_proj:
        record_projected_read_acks(
            tx,
            policy=policy,
            principal=principal,
            effective_scope=scope,
            expected_task_id="task-m6",
            acks=(bad_art_epoch0_proj,),
        )
    assert exc_art_proj.value.code is ErrorCode.INVALID_INPUT
    assert saved_acks == []

    # 3) Matching artifact_id + mismatched revision_epoch -> INVALID_INPUT (both entrypoints)
    bad_epoch_input = ReadAckInput(
        served_receipt_id=attempt.send_attempt_id,
        task_id="task-m6",
        artifact_id="hand-m6-1",
        revision_epoch=1,
        revision=3,
        resource_digests=(ResourceDigest(name="handoff_header", digest=digest_hdr),),
    )
    with pytest.raises(BrainError) as exc_ep_in:
        record_read_acks(
            tx,
            policy=policy,
            principal=principal,
            effective_scope=scope,
            expected_task_id="task-m6",
            acks=(bad_epoch_input,),
        )
    assert exc_ep_in.value.code is ErrorCode.INVALID_INPUT
    assert saved_acks == []

    bad_epoch_proj = ProjectedReadAck(
        served_receipt_id=attempt.send_attempt_id,
        task_id="task-m6",
        artifact_id="hand-m6-1",
        revision_epoch=1,
        revision=3,
        resource_digests=(("handoff_header", digest_hdr),),
    )
    with pytest.raises(BrainError) as exc_ep:
        record_projected_read_acks(
            tx,
            policy=policy,
            principal=principal,
            effective_scope=scope,
            expected_task_id="task-m6",
            acks=(bad_epoch_proj,),
        )
    assert exc_ep.value.code is ErrorCode.INVALID_INPUT
    assert saved_acks == []

    # 4) Exact match -> persisted ArtifactReadAck carries artifact_id & revision_epoch
    good_input = ReadAckInput(
        served_receipt_id=attempt.send_attempt_id,
        task_id="task-m6",
        artifact_id="hand-m6-1",
        revision_epoch=2,
        revision=3,
        resource_digests=(ResourceDigest(name="handoff_header", digest=digest_hdr),),
    )
    persisted = record_read_acks(
        tx, policy=policy, principal=principal, effective_scope=scope, expected_task_id="task-m6", acks=(good_input,)
    )
    assert len(persisted) == 1
    assert persisted[0].artifact_id == "hand-m6-1"
    assert persisted[0].revision_epoch == 2
    assert saved_acks == list(persisted)

    # 5) Second pass: idempotent check still verifies artifact_id & revision_epoch match stored ack
    persisted_dup = record_read_acks(
        tx, policy=policy, principal=principal, effective_scope=scope, expected_task_id="task-m6", acks=(good_input,)
    )
    assert persisted_dup == persisted

    # 6) Stored existing_ack mismatch on artifact_id OR revision_epoch -> INTEGRITY_FAILURE
    good_proj = ProjectedReadAck(
        served_receipt_id=attempt.send_attempt_id,
        task_id="task-m6",
        artifact_id="hand-m6-1",
        revision_epoch=2,
        revision=3,
        resource_digests=(("handoff_header", digest_hdr),),
    )
    for corrupt_patch in ({"artifact_id": "hand-corrupt"}, {"revision_epoch": 99}):
        saved_acks[:] = [replace(persisted[0], **corrupt_patch)]
        with pytest.raises(BrainError) as exc_int:
            record_projected_read_acks(
                tx,
                policy=policy,
                principal=principal,
                effective_scope=scope,
                expected_task_id="task-m6",
                acks=(good_proj,),
            )
        assert exc_int.value.code is ErrorCode.INTEGRITY_FAILURE
