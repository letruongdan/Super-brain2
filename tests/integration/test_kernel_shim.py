"""Integration tests for the bound MCP stdio shim (`T7b.2`).

Covers all 13 mandatory requirement-derived tests from the Task 7 plan:
1. ``test_installed_shim_exposes_packaged_catalog_and_calls_daemon``
2. ``test_shim_invalid_launch_refuses_before_trust_and_transport``
3. ``test_shim_injects_profile_alias_before_request_fingerprint``
4. ``test_shim_refuses_binding_response_mismatch``
5. ``test_no_workspace_profile_allows_health_but_refuses_workspace_tools``
6. ``test_same_repo_other_checkout_outcome_and_artifact_are_refused``
7. ``test_profile_switch_same_key_conflicts_even_when_outcome_args_are_unchanged``
8. ``test_missing_scope_is_refused_for_workspace_job_and_global_job_is_authorized``
9. ``test_shim_pins_before_bearer_and_never_reconnects``
10. ``test_shim_post_response_loss_preserves_uncertainty_and_key``
11. ``test_shim_stdout_failure_does_not_create_read_ack``
12. ``test_shim_slow_identity_preserves_tool_budget_and_commit_unknown``
13. ``test_native_lifecycle_report_fails_on_workspace_switch_with_same_shim``
"""

from __future__ import annotations

import contextlib
import dataclasses
import datetime as dt
import hashlib
import io
import ipaddress
import shutil
import socket
import sqlite3
import ssl
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from superbrain.adapters.os import os_adapters
from superbrain.composition.client_entry import (
    build_tool_caller,
    read_status,
    select_workspace,
)
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    ENDPOINT_VERSION,
    Endpoint,
    Scope,
    WorkspaceBinding,
)
from superbrain.core.wire import MAX_WIRE_BODY_BYTES, WORKSPACE_SCOPED_TOOLS, load_catalog
from superbrain.mcp.stdio import MCP_PROTOCOL_VERSION, run_stdio
from tests.support.clock import FakeClock
from tests.support.inc2_cli import (
    InstalledMcpPipeSession,
    ShimTestDomain,
    decode_stdio_frames,
    encode_stdio_frames,
    get_shared_t7_transport_template,
    mcp_call_frame,
    mcp_init_frames,
    run_inprocess_stdio,
    run_installed_command,
    spawn_installed_brain_serve,
    spawn_installed_fixture_daemon,
    verify_installed_wheel_isolation,
    write_ca_file,
    write_client_profile_file,
    write_credential_file,
    write_daemon_config_file,
    write_owner_only_bytes,
)
from tests.support.inc2_fixture import (
    InstalledEnv,
    enqueue_job,
    kernel_job_service,
    open_kernel_job_runtime,
)
from tests.support.inc2_lifecycle import (
    ShimLaunchObservation,
    workspace_transition_matches,
)
from tests.support.inc2_transport import (
    TransportHarness,
    TransportTemplate,
    clone_owner_only_tree,
    make_trusted_test_dir,
    open_test_loopback_transport,
    register_workspace_direct,
)


@dataclasses.dataclass(frozen=True)
class ShimTemplateBundle:
    """Extended module-scoped template including a second checkout of ``ws_a``'s repository."""

    template: TransportTemplate
    ws_a: WorkspaceBinding
    ws_a2: WorkspaceBinding
    ws_b: WorkspaceBinding
    global_job_id: str
    scoped_job_id: str
    bob_job_id: str


@pytest.fixture(scope="module")
def shim_scratch_root() -> Iterator[Path]:
    """Module-scoped trusted scratch directory cleaned up on teardown."""
    root = make_trusted_test_dir("inc2-t7-shim")
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


@pytest.fixture(scope="module")
def shim_bundle() -> Iterator[ShimTemplateBundle]:
    """Module-scoped transport template with ``ws_a``, same-repo ``ws_a2``, ``ws_b``, and seeded jobs."""
    shared_tpl = get_shared_t7_transport_template()
    bundle_dir = make_trusted_test_dir("inc2-t7-shim-tpl")
    try:
        assert shared_tpl.dan is not None
        assert shared_tpl.bob is not None
        assert shared_tpl.ws_a is not None
        assert shared_tpl.ws_b is not None
        assert shared_tpl.global_job_id is not None
        assert shared_tpl.scoped_job_id is not None

        cloned_root = bundle_dir / "template-data"
        clone_owner_only_tree(shared_tpl.root, cloned_root)
        os_adapters().permissions.secure_directory(cloned_root)

        clock = FakeClock(shared_tpl.base_time + dt.timedelta(seconds=5))
        adapters = os_adapters(clock=clock)
        rt = open_kernel_job_runtime(cloned_root, adapters)
        try:
            ws_a2 = register_workspace_direct(
                rt,
                clock,
                shared_tpl.dan,
                alias="ws-a-2",
                checkout_dir=bundle_dir / "chk-a-2",
                remote="https://github.example/dan/repo-transport-a.git",
            )
            assert ws_a2.repo_id == shared_tpl.ws_a.repo_id
            assert ws_a2.checkout_id != shared_tpl.ws_a.checkout_id

            service, staged_store = kernel_job_service(rt, clock)
            bob_job = enqueue_job(service, staged_store, owner_id="bob", payload=b"bob job payload")
        finally:
            rt.close()

        tpl = dataclasses.replace(shared_tpl, base_dir=bundle_dir, root=cloned_root)
        yield ShimTemplateBundle(
            template=tpl,
            ws_a=shared_tpl.ws_a,
            ws_a2=ws_a2,
            ws_b=shared_tpl.ws_b,
            global_job_id=shared_tpl.global_job_id,
            scoped_job_id=shared_tpl.scoped_job_id,
            bob_job_id=bob_job.job_id,
        )
    finally:
        shutil.rmtree(bundle_dir, ignore_errors=True)


def _workspace_dict(binding: WorkspaceBinding) -> dict[str, JsonValue]:
    return {
        "alias": binding.alias,
        "checkout_path": str(binding.checkout_path),
        "expected_workspace_id": binding.repo_id,
        "expected_checkout_id": binding.checkout_id,
    }


def _make_domain(bundle: ShimTemplateBundle) -> ShimTestDomain:
    return ShimTestDomain(
        alias_to_scope={
            bundle.ws_a.alias: Scope(bundle.ws_a.repo_id, bundle.ws_a.checkout_id),
            bundle.ws_a2.alias: Scope(bundle.ws_a2.repo_id, bundle.ws_a2.checkout_id),
            bundle.ws_b.alias: Scope(bundle.ws_b.repo_id, bundle.ws_b.checkout_id),
        }
    )


def _write_harness_profile(
    h: TransportHarness,
    name: str,
    *,
    workspace: WorkspaceBinding | Mapping[str, JsonValue] | None = None,
    leaf_cert_sha256: str | None = None,
    expected_store_id: str | None = None,
    endpoint_path: Path | None = None,
    ca_file: Path | None = None,
    credential_file: Path | None = None,
) -> tuple[Path, str]:
    client_dir = h.base_dir / f"client-{name}"
    cred_path = (
        credential_file
        if credential_file is not None
        else write_credential_file(client_dir / "credential.txt", h.cred.token)
    )
    ws_dict: Mapping[str, JsonValue] | None
    if isinstance(workspace, WorkspaceBinding):
        ws_dict = _workspace_dict(workspace)
    else:
        ws_dict = workspace
    return write_client_profile_file(
        client_dir / "profile.json",
        endpoint_path=endpoint_path if endpoint_path is not None else (h.data_root / "endpoint.json"),
        expected_store_id=expected_store_id if expected_store_id is not None else h.store_id,
        ca_file=ca_file if ca_file is not None else h.tls.ca_cert_path,
        leaf_cert_sha256=leaf_cert_sha256 if leaf_cert_sha256 is not None else h.ready.leaf_cert_sha256,
        credential_file=cred_path,
        workspace=ws_dict,
    )


def _extract_tool_result(resp_frame: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    assert resp_frame.get("jsonrpc") == "2.0"
    assert "error" not in resp_frame, f"Unexpected JSON-RPC error frame: {resp_frame}"
    result = resp_frame.get("result")
    assert isinstance(result, dict)
    return result


class _FakeTlsLoopbackServer:
    """Single-shot or multi-shot raw TLS listener for testing pin-before-bearer and response mismatch."""

    def __init__(
        self,
        ssl_context: ssl.SSLContext,
        handler: Callable[[ssl.SSLSocket, _FakeTlsLoopbackServer], object],
    ) -> None:
        self._ssl_context = ssl_context
        self._handler = handler
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(8)
        self._listener.settimeout(0.05)
        self.port = int(self._listener.getsockname()[1])
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.accept_count = 0
        self.post_handshake_bytes: list[bytes] = []
        self.post_call_count = 0
        self._thread = threading.Thread(target=self._serve, name="fake-tls-loopback", daemon=True)
        self._thread.start()

    def record_bytes(self, data: bytes) -> None:
        with self._lock:
            self.post_handshake_bytes.append(data)
            if b"POST /v2/tools/call" in data:
                self.post_call_count += 1

    @property
    def all_received_bytes(self) -> bytes:
        with self._lock:
            return b"".join(self.post_handshake_bytes)

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                raw_sock, _ = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            with self._lock:
                self.accept_count += 1
            try:
                raw_sock.settimeout(2.0)
                with self._ssl_context.wrap_socket(raw_sock, server_side=True) as ssl_sock:
                    ssl_sock.settimeout(2.0)
                    self._handler(ssl_sock, self)
            except (ssl.SSLError, OSError):
                pass
            finally:
                with contextlib.suppress(OSError):
                    raw_sock.close()

    def close(self) -> None:
        self._stop.set()
        with contextlib.suppress(OSError):
            self._listener.close()
        self._thread.join(timeout=2.0)

    def __enter__(self) -> _FakeTlsLoopbackServer:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def _read_http_request(ssl_sock: ssl.SSLSocket, srv: _FakeTlsLoopbackServer) -> bytes:
    buf = bytearray()
    while True:
        chunk = ssl_sock.recv(4096)
        if not chunk:
            break
        srv.record_bytes(chunk)
        buf.extend(chunk)
        if b"\r\n\r\n" in buf:
            head_end = buf.index(b"\r\n\r\n")
            headers = buf[:head_end].decode("iso-8859-1")
            cl = 0
            for line in headers.split("\r\n"):
                if line.lower().startswith("content-length:"):
                    cl = int(line.split(":", 1)[1].strip())
            if len(buf) >= head_end + 4 + cl:
                break
    return bytes(buf)


def _write_http_json(ssl_sock: ssl.SSLSocket, status: str, payload: Mapping[str, JsonValue], *, close: bool) -> None:
    body = canonical_json(dict(payload))
    conn_hdr = "Connection: close\r\n" if close else ""
    head = (
        f"HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n{conn_hdr}\r\n"
    ).encode("ascii")
    ssl_sock.sendall(head + body)


def _generate_self_signed_or_expired_tls(
    scratch_dir: Path,
    *,
    expired: bool,
) -> tuple[ssl.SSLContext, Path, str]:
    """Generate a CA + 127.0.0.1 leaf certificate (either expired or valid) and return server SSLContext."""
    now = dt.datetime.now(dt.UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "superbrain-fake-ca")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=10))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    if expired:
        not_before = now - dt.timedelta(days=5)
        not_after = now - dt.timedelta(days=1)
    else:
        not_before = now - dt.timedelta(minutes=5)
        not_after = now + dt.timedelta(days=30)

    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    leaf_pem = leaf_cert.public_bytes(serialization.Encoding.PEM)
    leaf_der = leaf_cert.public_bytes(serialization.Encoding.DER)
    leaf_key_pem = leaf_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    leaf_sha256 = hashlib.sha256(leaf_der).hexdigest()

    ca_path = write_ca_file(scratch_dir / "ca.pem", ca_pem)
    cert_path = write_ca_file(scratch_dir / "leaf.pem", leaf_pem)
    key_path = write_ca_file(scratch_dir / "leaf.key", leaf_key_pem)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    return ctx, ca_path, leaf_sha256


# ---------------------------------------------------------------------------
# 1. Installed wheel shim catalog + production & fixture daemon calls
# ---------------------------------------------------------------------------


def test_installed_shim_exposes_packaged_catalog_and_calls_daemon(
    inc2_installed_env: InstalledEnv,
    shim_bundle: ShimTemplateBundle,
    shim_scratch_root: Path,
    request: pytest.FixtureRequest,
) -> None:
    """Installed ``brain mcp`` and ``brain-mcp`` expose packaged catalog and call production/fixture daemons."""
    assert callable(select_workspace)
    assert callable(read_status)

    case_dir = shim_scratch_root / "installed-shim"
    data_root = case_dir / "data"
    clone_owner_only_tree(shim_bundle.template.root, data_root)
    os_adapters().permissions.secure_directory(data_root)

    config_path = write_daemon_config_file(
        case_dir / "daemon-config.json",
        data_root=data_root,
        expected_store_id=shim_bundle.template.store_id,
        cert_path=shim_bundle.template.tls.cert_path,
        key_path=shim_bundle.template.tls.key_path,
    )
    cred_file = write_credential_file(case_dir / "client" / "credential.txt", shim_bundle.template.cred.token)
    profile_path, _ = write_client_profile_file(
        case_dir / "client" / "profile.json",
        endpoint_path=data_root / "endpoint.json",
        expected_store_id=shim_bundle.template.store_id,
        ca_file=shim_bundle.template.tls.ca_cert_path,
        leaf_cert_sha256=shim_bundle.template.tls.leaf_cert_sha256,
        credential_file=cred_file,
        workspace=_workspace_dict(shim_bundle.ws_a),
    )

    chk_a_path = Path(shim_bundle.ws_a.checkout_path)
    wheel_info = verify_installed_wheel_isolation(inc2_installed_env, cwd=chk_a_path)
    assert wheel_info["schema_sha256"] == inc2_installed_env.source_schema_sha256
    expected_catalog = load_catalog()
    assert expected_catalog.schema_sha256 == inc2_installed_env.source_schema_sha256

    init_pair = mcp_init_frames(1)
    init_req_frame = init_pair[0]
    initialized_notif_frame = init_pair[1]
    list_req_frame: dict[str, JsonValue] = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
    health_req_bytes = canonical_json(mcp_call_frame(3, "get_health", {"schema_version": "2.0"}))
    split_health_chunks = [
        health_req_bytes[:24],
        health_req_bytes[24:] + b"\r",
        b"\n",
    ]
    prep_prod_frame = mcp_call_frame(
        4,
        "prepare_task",
        {
            "schema_version": "2.0",
            "idempotency_key": "idem-wheel-prod-0001",
            "task_id": "task-wheel-prod-1",
            "harness_id": "claude-code",
            "description": "verify packaged catalog against production daemon",
        },
    )

    # Part A (R01 & R07): Wheel-installed `brain serve` production daemon + open-pipe wheel-installed shims
    # (`brain mcp` and `brain-mcp`), waiting for each response while stdin stays open before sending the next frame.
    with spawn_installed_brain_serve(
        inc2_installed_env,
        config_path,
        data_root=data_root,
        cwd=chk_a_path,
    ) as prod_daemon:
        prod_daemon.wait_ready()

        for script_name, base_args in (
            ("brain", ("mcp", "--profile", str(profile_path))),
            ("brain-mcp", ("--profile", str(profile_path))),
        ):
            with InstalledMcpPipeSession(
                inc2_installed_env,
                script_name,
                base_args,
                cwd=chk_a_path,
            ) as pipe_sess:
                # 1. initialize answered on stdout while stdin remains open and process is alive
                resp_init = pipe_sess.send_frames_and_expect_response([init_req_frame])
                assert resp_init.get("id") == 1
                init_res = _extract_tool_result(resp_init)
                assert init_res.get("protocolVersion") == MCP_PROTOCOL_VERSION

                # 2. notifications/initialized + tools/list answered while stdin remains open
                resp_list = pipe_sess.send_frames_and_expect_response([initialized_notif_frame, list_req_frame])
                assert resp_list.get("id") == 2
                list_res = _extract_tool_result(resp_list)
                assert list_res.get("tools") == expected_catalog.mcp_tools_list()
                assert digest_bytes(canonical_json(list_res)) == digest_bytes(
                    canonical_json({"tools": expected_catalog.mcp_tools_list()})
                )

                # 3. get_health split across multiple writes (with split CRLF) answered while stdin remains open
                resp_health = pipe_sess.write_chunks_and_expect_response(split_health_chunks)
                assert resp_health.get("id") == 3
                health_res = _extract_tool_result(resp_health)
                assert health_res.get("isError") is False
                health_sc = health_res.get("structuredContent")
                assert isinstance(health_sc, dict) and health_sc.get("ok") is True
                health_data = health_sc.get("data")
                assert isinstance(health_data, dict)
                assert health_data.get("store_id") == shim_bundle.template.store_id

                # 4. prepare_task on production daemon returns capability_unavailable while stdin remains open
                resp_prep = pipe_sess.send_frames_and_expect_response([prep_prod_frame])
                assert resp_prep.get("id") == 4
                prep_res = _extract_tool_result(resp_prep)
                assert prep_res.get("isError") is True
                assert "_meta" not in prep_res
                prep_sc = prep_res.get("structuredContent")
                assert prep_sc == {
                    "ok": False,
                    "error": {
                        "code": "capability_unavailable",
                        "message": "capability unavailable",
                    },
                }

                # 5. For brain-mcp, also verify the 1 MiB per-frame cap is enforced over the open pipe.
                if script_name == "brain-mcp":
                    oversize_line = b'{"jsonrpc":"2.0","id":99,"pad":"' + (b"X" * MAX_WIRE_BODY_BYTES) + b'"}\n'
                    resp_cap = pipe_sess.write_chunks_and_expect_response(
                        [oversize_line],
                        require_alive_after=False,
                    )
                    assert resp_cap == {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32700, "message": "parse error"},
                    }

                rc_proc, stderr_proc = pipe_sess.finish()
                assert rc_proc == 0, (
                    f"{script_name} failed (rc={rc_proc}): stderr={stderr_proc.decode('utf-8', errors='replace')!r}"
                )
                assert stderr_proc == b""

        rc_prod, _, _, _ = prod_daemon.signal_and_wait_exit()
        assert rc_prod == 0

    # Part B: Fixture daemon running on the SAME installed wheel commits positive result & verifies schema sha256.
    with spawn_installed_fixture_daemon(
        inc2_installed_env,
        config_path,
        data_root=data_root,
        cwd=chk_a_path,
    ) as fix_daemon:
        fix_daemon.wait_ready()

        delivery_ids: list[str] = []
        assignment_ids: list[str] = []
        for script_name, base_args in (
            ("brain-mcp", ("--profile", str(profile_path))),
            ("brain", ("mcp", "--profile", str(profile_path))),
        ):
            prep_fix_frame = mcp_call_frame(
                2,
                "prepare_task",
                {
                    "schema_version": "2.0",
                    "idempotency_key": "idem-wheel-fixture-0001",
                    "task_id": "task-wheel-fixture-1",
                    "harness_id": "claude-code",
                    "description": "verify positive call and schema digest across wheel",
                },
            )
            with InstalledMcpPipeSession(
                inc2_installed_env,
                script_name,
                base_args,
                cwd=chk_a_path,
            ) as fix_sess:
                fix_init = fix_sess.send_frames_and_expect_response([init_req_frame])
                assert fix_init.get("id") == 1
                fix_call = fix_sess.send_frames_and_expect_response([initialized_notif_frame, prep_fix_frame])
                assert fix_call.get("id") == 2
                first_result = _extract_tool_result(fix_call)
                first_sc = first_result.get("structuredContent")
                first_error = first_sc.get("error") if isinstance(first_sc, dict) else None
                committed_assignment: str | None = None
                if (
                    first_result.get("isError") is True
                    and isinstance(first_sc, dict)
                    and first_sc.get("ok") is False
                    and isinstance(first_error, dict)
                    and first_error.get("code") == ErrorCode.COMMIT_OUTCOME_UNKNOWN.value
                ):
                    request.node.user_properties.append(
                        ("initial_prepare_error", ErrorCode.COMMIT_OUTCOME_UNKNOWN.value)
                    )
                    # Durable visibility is D4's completion authority. This is
                    # a bounded wait for this fixture's sole prepare commit,
                    # followed by one same-key protocol replay, never a test rerun.
                    until = time.monotonic() + 5.0
                    with sqlite3.connect(f"file:{data_root / 'store' / 'brain.db'}?mode=ro", uri=True) as conn:
                        while True:
                            rows = conn.execute(
                                "SELECT assignment_id FROM idempotency WHERE tool = 'prepare_task'"
                            ).fetchall()
                            if rows:
                                assert len(rows) == 1 and isinstance(rows[0][0], str)
                                committed_assignment = rows[0][0]
                                break
                            assert time.monotonic() < until, "the unknown prepare attempt never committed"
                            threading.Event().wait(0.01)
                    fix_call = fix_sess.send_frames_and_expect_response([prep_fix_frame | {"id": 3}])
                    assert fix_call.get("id") == 3
                rc_fix_proc, stderr_fix_proc = fix_sess.finish()
                assert rc_fix_proc == 0
                assert stderr_fix_proc == b""

            call_res = _extract_tool_result(fix_call)
            assert call_res.get("isError") is False
            sc = call_res.get("structuredContent")
            assert isinstance(sc, dict) and sc.get("ok") is True
            data = sc.get("data")
            assert isinstance(data, dict)
            assert data.get("workspace_id") == shim_bundle.ws_a.repo_id
            assert data.get("checkout_id") == shim_bundle.ws_a.checkout_id
            ctx_obj = data.get("context")
            assert isinstance(ctx_obj, dict)
            assert ctx_obj.get("summary_md") == f"catalog_sha256={inc2_installed_env.source_schema_sha256}"
            delivery_ids.append(str(data["delivery_id"]))
            assignment_ids.append(str(data["assignment_id"]))
            if committed_assignment is not None:
                assert data["assignment_id"] == committed_assignment

        # Both entrypoints replayed the exact same committed delivery/assignment.
        assert len(delivery_ids) == 2 and delivery_ids[0] == delivery_ids[1]
        assert len(assignment_ids) == 2 and assignment_ids[0] == assignment_ids[1]

        rc_fix, _, _, _ = fix_daemon.signal_and_wait_exit()
        assert rc_fix == 0

    # Verify durable idempotency & ledger records were committed in SQLite.
    store_db = data_root / "store" / "brain.db"
    with sqlite3.connect(f"file:{store_db}?mode=ro", uri=True) as conn:
        idem_rows = conn.execute("SELECT COUNT(*) FROM idempotency WHERE tool = 'prepare_task'").fetchone()
        assert idem_rows is not None and int(idem_rows[0]) == 1


# ---------------------------------------------------------------------------
# 2. Invalid launch CWD refuses before reading trust/credentials or connecting
# ---------------------------------------------------------------------------


def test_shim_invalid_launch_refuses_before_trust_and_transport(
    inc2_installed_env: InstalledEnv,
    shim_bundle: ShimTemplateBundle,
    shim_scratch_root: Path,
) -> None:
    """Wrong launch CWD fails with identity_mismatch before reading CA/credential/endpoint or opening sockets."""
    case_dir = shim_scratch_root / "invalid-launch"
    wrong_cwd = case_dir / "unrelated-cwd"
    sibling_prefix_cwd = Path(f"{shim_bundle.ws_a.checkout_path}-sibling")
    wrong_cwd.mkdir(parents=True, exist_ok=True)
    sibling_prefix_cwd.mkdir(parents=True, exist_ok=True)
    os_adapters().permissions.secure_directory(wrong_cwd)
    os_adapters().permissions.secure_directory(sibling_prefix_cwd)

    # Point ca_file, credential_file, and endpoint_path at NON-EXISTENT files!
    # If `build_tool_caller` or `shim_entry` read them before checking `launch_cwd`,
    # it would fail with `not_found` / `daemon_unavailable` instead of `identity_mismatch`.
    absent_ca = case_dir / "never-read-ca.pem"
    absent_cred = case_dir / "never-read-credential.txt"
    absent_endpoint = case_dir / "never-read-endpoint.json"
    profile_path, _ = write_client_profile_file(
        case_dir / "profile-missing-secrets.json",
        endpoint_path=absent_endpoint,
        expected_store_id=shim_bundle.template.store_id,
        ca_file=absent_ca,
        leaf_cert_sha256=shim_bundle.template.tls.leaf_cert_sha256,
        credential_file=absent_cred,
        workspace=_workspace_dict(shim_bundle.ws_a),
    )

    # Also start a fake TLS listener on loopback to prove zero TCP connections are made.
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain(
        certfile=str(shim_bundle.template.tls.cert_path),
        keyfile=str(shim_bundle.template.tls.key_path),
    )
    with _FakeTlsLoopbackServer(ssl_ctx, lambda _s, _srv: None) as spy_srv:
        for bad_cwd in (None, wrong_cwd, sibling_prefix_cwd):
            with pytest.raises(BrainError) as exc_info:
                build_tool_caller(profile_path, bad_cwd, os_adapters())
            assert exc_info.value.code is ErrorCode.IDENTITY_MISMATCH

        # Subprocess `brain-mcp --profile <abs>` and `brain mcp --profile <abs>` in wrong CWD exit 1
        # with static `identity_mismatch` on stderr and 0 bytes on stdout without reading stdin.
        init_bytes = encode_stdio_frames(mcp_init_frames(1))
        for script_name, args in (
            ("brain-mcp", ("--profile", str(profile_path))),
            ("brain", ("mcp", "--profile", str(profile_path))),
        ):
            proc_res = run_installed_command(
                inc2_installed_env,
                script_name,
                args,
                cwd=wrong_cwd,
                stdin_bytes=init_bytes,
            )
            assert proc_res.returncode == 1
            assert proc_res.stdout == b""
            assert proc_res.stderr.decode("utf-8", errors="replace").strip() == "identity_mismatch"

        assert spy_srv.accept_count == 0
        assert not absent_ca.exists()
        assert not absent_cred.exists()
        assert not absent_endpoint.exists()


# ---------------------------------------------------------------------------
# 3. Shim injects profile alias before request fingerprint (Kills Mutant 1)
# ---------------------------------------------------------------------------


def test_shim_injects_profile_alias_before_request_fingerprint(
    shim_bundle: ShimTemplateBundle,
) -> None:
    """Omitting selector on ``prepare_task`` injects ``workspace_hint`` so explicit-alias retry replays one Delivery."""
    domain = _make_domain(shim_bundle)
    with open_test_loopback_transport(shim_bundle.template, name="alias-inject", domain=domain) as h:
        profile_path, _ = _write_harness_profile(h, "ws-a", workspace=shim_bundle.ws_a)
        chk_a_path = Path(shim_bundle.ws_a.checkout_path)
        caller = build_tool_caller(profile_path, chk_a_path, os_adapters(clock=h.clock, monotonic=h.mono_clock))

        base_args: dict[str, JsonValue] = {
            "schema_version": "2.0",
            "idempotency_key": "idem-alias-fingerprint-0001",
            "task_id": "task-alias-fp-1",
            "harness_id": "claude-code",
            "description": "verify alias injection before request digest",
        }
        explicit_alias_args: dict[str, JsonValue] = {
            **base_args,
            "workspace_hint": shim_bundle.ws_a.alias,
        }
        explicit_ids_args: dict[str, JsonValue] = {
            **base_args,
            "idempotency_key": "idem-alias-fingerprint-0002",
            "task_id": "task-alias-fp-2",
            "workspace_id": shim_bundle.ws_a.repo_id,
            "checkout_id": shim_bundle.ws_a.checkout_id,
        }

        rc, responses = run_inprocess_stdio(
            caller,
            [
                *mcp_init_frames(1),
                mcp_call_frame(2, "prepare_task", base_args, meta={"progressToken": "strip-me"}),
                mcp_call_frame(3, "prepare_task", explicit_alias_args),
                mcp_call_frame(4, "prepare_task", explicit_ids_args),
            ],
        )
        assert rc == 0
        assert len(responses) == 4

        res_injected = _extract_tool_result(responses[1])
        res_replayed = _extract_tool_result(responses[2])
        res_explicit_ids = _extract_tool_result(responses[3])
        assert res_injected.get("isError") is False
        assert res_replayed.get("isError") is False
        assert res_explicit_ids.get("isError") is False

        sc1 = cast(dict[str, Any], res_injected["structuredContent"])
        sc2 = cast(dict[str, Any], res_replayed["structuredContent"])
        assert sc1["ok"] is True and sc2["ok"] is True
        assert sc1["data"]["delivery_id"] == sc2["data"]["delivery_id"]
        assert sc1["data"]["assignment_id"] == sc2["data"]["assignment_id"]
        assert sc1["data"]["workspace_id"] == shim_bundle.ws_a.repo_id
        assert sc1["data"]["checkout_id"] == shim_bundle.ws_a.checkout_id

        # Only 2 distinct mutations were prepared (call 2 and call 3 shared the exact same fingerprint!).
        assert len(domain.prepared_calls) == 2
        first_call = domain.prepared_calls[0]
        assert first_call.arguments.get("workspace_hint") == shim_bundle.ws_a.alias
        assert "_meta" not in first_call.arguments
        assert first_call.selected_scope == Scope(shim_bundle.ws_a.repo_id, shim_bundle.ws_a.checkout_id)

        # Physical checkout path must never appear anywhere in wire arguments sent to daemon.
        for submitted in h.submitted_commands:
            wire_json = canonical_json(submitted.arguments).decode("utf-8")
            assert str(chk_a_path) not in wire_json


# ---------------------------------------------------------------------------
# 4. Shim refuses prepare_task response with mismatched binding (Kills Mutant 2)
# ---------------------------------------------------------------------------


def test_shim_refuses_binding_response_mismatch(
    shim_bundle: ShimTemplateBundle,
    shim_scratch_root: Path,
) -> None:
    """Shim verifies ``prepare_task`` response ``(workspace_id, checkout_id)`` matches bound scope before stdout."""
    case_dir = shim_scratch_root / "response-mismatch"
    store_id = shim_bundle.template.store_id
    instance_id = new_id()
    writer_epoch = 1

    # Responses to return on successive `/v2/tools/call` requests:
    # 1. Mismatched workspace_id
    # 2. Mismatched checkout_id
    # 3. Missing checkout_id
    # 4. Exact matching (workspace_id, checkout_id) -> allowed
    canned_payloads: list[dict[str, JsonValue]] = [
        {
            "ok": True,
            "data": {
                "workspace_id": shim_bundle.ws_b.repo_id,
                "checkout_id": shim_bundle.ws_a.checkout_id,
                "source_snapshot_id": None,
                "snapshot_status": "unavailable",
                "degraded_codes": ["snapshot_unavailable"],
                "task_id": "task-mismatch-1",
                "delivery_id": "deliv-rogue-1",
                "assignment_id": "assign-rogue-1",
                "skills": [],
                "lessons": [],
                "continuity": [],
                "context": {"summary_md": "rogue-ws", "sources": [], "unknown_source": False},
                "finishing_gates": [],
            },
        },
        {
            "ok": True,
            "data": {
                "workspace_id": shim_bundle.ws_a.repo_id,
                "checkout_id": shim_bundle.ws_a2.checkout_id,
                "source_snapshot_id": None,
                "snapshot_status": "unavailable",
                "degraded_codes": ["snapshot_unavailable"],
                "task_id": "task-mismatch-2",
                "delivery_id": "deliv-rogue-2",
                "assignment_id": "assign-rogue-2",
                "skills": [],
                "lessons": [],
                "continuity": [],
                "context": {"summary_md": "rogue-chk", "sources": [], "unknown_source": False},
                "finishing_gates": [],
            },
        },
        {
            "ok": True,
            "data": {
                "workspace_id": shim_bundle.ws_a.repo_id,
                "task_id": "task-mismatch-3",
                "delivery_id": "deliv-rogue-3",
                "assignment_id": "assign-rogue-3",
            },
        },
        {
            "ok": True,
            "data": {
                "workspace_id": shim_bundle.ws_a.repo_id,
                "checkout_id": shim_bundle.ws_a.checkout_id,
                "source_snapshot_id": None,
                "snapshot_status": "unavailable",
                "degraded_codes": ["snapshot_unavailable"],
                "task_id": "task-match-4",
                "delivery_id": "deliv-good-4",
                "assignment_id": "assign-good-4",
                "skills": [],
                "lessons": [],
                "continuity": [],
                "context": {"summary_md": "valid-match", "sources": [], "unknown_source": False},
                "finishing_gates": [],
            },
        },
    ]
    call_idx = 0

    def _handler(ssl_sock: ssl.SSLSocket, srv: _FakeTlsLoopbackServer) -> None:
        nonlocal call_idx
        req1 = _read_http_request(ssl_sock, srv)
        if not req1.startswith(b"GET /v2/identity "):
            return
        _write_http_json(
            ssl_sock,
            "200 OK",
            {
                "store_id": store_id,
                "writer_epoch": writer_epoch,
                "instance_id": instance_id,
                "contract": "mcp-tools-v2",
                "schema_digest": load_catalog().schema_digest,
            },
            close=False,
        )
        req2 = _read_http_request(ssl_sock, srv)
        if not req2.startswith(b"POST /v2/tools/call "):
            return
        payload = canned_payloads[min(call_idx, len(canned_payloads) - 1)]
        call_idx += 1
        _write_http_json(ssl_sock, "200 OK", payload, close=True)

    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain(
        certfile=str(shim_bundle.template.tls.cert_path),
        keyfile=str(shim_bundle.template.tls.key_path),
    )

    with _FakeTlsLoopbackServer(ssl_ctx, _handler) as fake_srv:
        endpoint = Endpoint(
            version=ENDPOINT_VERSION,
            host="127.0.0.1",
            port=fake_srv.port,
            store_id=store_id,
            writer_epoch=writer_epoch,
            instance_id=instance_id,
        )
        ep_path = write_owner_only_bytes(case_dir / "endpoint.json", endpoint.encode_canonical())
        cred_path = write_credential_file(case_dir / "credential.txt", shim_bundle.template.cred.token)
        profile_path, _ = write_client_profile_file(
            case_dir / "profile.json",
            endpoint_path=ep_path,
            expected_store_id=store_id,
            ca_file=shim_bundle.template.tls.ca_cert_path,
            leaf_cert_sha256=shim_bundle.template.tls.leaf_cert_sha256,
            credential_file=cred_path,
            workspace=_workspace_dict(shim_bundle.ws_a),
        )

        caller = build_tool_caller(profile_path, Path(shim_bundle.ws_a.checkout_path), os_adapters())
        frames = [
            *mcp_init_frames(1),
            mcp_call_frame(
                2,
                "prepare_task",
                {
                    "schema_version": "2.0",
                    "idempotency_key": "idem-resp-mismatch-0001",
                    "task_id": "task-mismatch-1",
                    "harness_id": "claude-code",
                    "description": "case 1 wrong workspace_id",
                },
            ),
            mcp_call_frame(
                3,
                "prepare_task",
                {
                    "schema_version": "2.0",
                    "idempotency_key": "idem-resp-mismatch-0002",
                    "task_id": "task-mismatch-2",
                    "harness_id": "claude-code",
                    "description": "case 2 wrong checkout_id",
                },
            ),
            mcp_call_frame(
                4,
                "prepare_task",
                {
                    "schema_version": "2.0",
                    "idempotency_key": "idem-resp-mismatch-0003",
                    "task_id": "task-mismatch-3",
                    "harness_id": "claude-code",
                    "description": "case 3 missing checkout_id",
                },
            ),
            mcp_call_frame(
                5,
                "prepare_task",
                {
                    "schema_version": "2.0",
                    "idempotency_key": "idem-resp-mismatch-0004",
                    "task_id": "task-match-4",
                    "harness_id": "claude-code",
                    "description": "case 4 matching binding",
                },
            ),
        ]

        stdin_buf = io.BytesIO(encode_stdio_frames(frames))
        stdout_buf = io.BytesIO()
        rc = run_stdio(stdin_buf, stdout_buf, caller)
        assert rc == 0

        raw_stdout = stdout_buf.getvalue().decode("utf-8")
        assert "deliv-rogue-1" not in raw_stdout
        assert "deliv-rogue-2" not in raw_stdout
        assert "deliv-rogue-3" not in raw_stdout
        assert "rogue-ws" not in raw_stdout
        assert "rogue-chk" not in raw_stdout

        responses = decode_stdio_frames(stdout_buf.getvalue())
        assert len(responses) == 5
        for idx in (1, 2, 3):
            err_res = _extract_tool_result(responses[idx])
            assert err_res.get("isError") is True
            assert err_res.get("structuredContent") == {
                "ok": False,
                "error": {
                    "code": "identity_mismatch",
                    "message": "identity mismatch",
                },
            }

        ok_res = _extract_tool_result(responses[4])
        assert ok_res.get("isError") is False
        ok_sc = cast(dict[str, Any], ok_res["structuredContent"])
        assert ok_sc["ok"] is True
        assert ok_sc["data"]["delivery_id"] == "deliv-good-4"


# ---------------------------------------------------------------------------
# 5. Profile without workspace allows health & global job, refuses workspace tools
# ---------------------------------------------------------------------------


def test_no_workspace_profile_allows_health_but_refuses_workspace_tools(
    shim_bundle: ShimTemplateBundle,
) -> None:
    """Scopeless profile permits ``get_health`` and global ``get_job``, refusing workspace tools locally."""
    domain = _make_domain(shim_bundle)
    with open_test_loopback_transport(shim_bundle.template, name="no-ws-profile", domain=domain) as h:
        profile_no_ws, _ = _write_harness_profile(h, "no-ws", workspace=None)
        unrelated_cwd = h.base_dir / "arbitrary-cwd"
        unrelated_cwd.mkdir(parents=True, exist_ok=True)
        adapters = os_adapters(clock=h.clock, monotonic=h.mono_clock)

        caller = build_tool_caller(profile_no_ws, unrelated_cwd, adapters)

        # 1. Every workspace-scoped tool is refused locally at the shim with 0 loopback requests.
        ws_calls: list[dict[str, JsonValue]] = []
        req_id = 2
        for tool_name in sorted(WORKSPACE_SCOPED_TOOLS):
            ws_calls.append(mcp_call_frame(req_id, tool_name, {"schema_version": "2.0"}))
            req_id += 1

        rc, responses = run_inprocess_stdio(caller, [*mcp_init_frames(1), *ws_calls])
        assert rc == 0
        assert h.submit_count == 0, "Workspace tools on a no-workspace profile must fail before loopback transport"

        for resp in responses[1:]:
            tool_res = _extract_tool_result(resp)
            assert tool_res.get("isError") is True
            assert tool_res.get("structuredContent") == {
                "ok": False,
                "error": {
                    "code": "capability_unavailable",
                    "message": "capability unavailable",
                },
            }

        # 2. `get_health` and authorized global `get_job` succeed; scoped job and unknown job return `not_found`.
        rc2, responses2 = run_inprocess_stdio(
            caller,
            [
                *mcp_init_frames(1),
                mcp_call_frame(2, "get_health", {"schema_version": "2.0"}),
                mcp_call_frame(3, "get_job", {"schema_version": "2.0", "job_id": shim_bundle.global_job_id}),
                mcp_call_frame(4, "get_job", {"schema_version": "2.0", "job_id": shim_bundle.scoped_job_id}),
                mcp_call_frame(5, "get_job", {"schema_version": "2.0", "job_id": "job-nonexistent-999"}),
            ],
        )
        assert rc2 == 0
        health_res = _extract_tool_result(responses2[1])
        assert health_res.get("isError") is False
        assert cast(dict[str, Any], health_res["structuredContent"])["ok"] is True

        gjob_res = _extract_tool_result(responses2[2])
        assert gjob_res.get("isError") is False
        gjob_sc = cast(dict[str, Any], gjob_res["structuredContent"])
        assert gjob_sc["ok"] is True
        assert gjob_sc["data"]["job_id"] == shim_bundle.global_job_id

        for idx in (3, 4):
            denied_res = _extract_tool_result(responses2[idx])
            assert denied_res.get("isError") is True
            assert denied_res.get("structuredContent") == {
                "ok": False,
                "error": {
                    "code": "not_found",
                    "message": "not found",
                },
            }


# ---------------------------------------------------------------------------
# 6. Same repo, other checkout: outcome and artifact refs are refused
# ---------------------------------------------------------------------------


def test_same_repo_other_checkout_outcome_and_artifact_are_refused(
    shim_bundle: ShimTemplateBundle,
) -> None:
    """Checkout B of the same repo cannot read checkout A's artifacts or record outcomes for checkout A's delivery."""
    domain = _make_domain(shim_bundle)
    scope_a1 = Scope(shim_bundle.ws_a.repo_id, shim_bundle.ws_a.checkout_id)
    scope_a2 = Scope(shim_bundle.ws_a2.repo_id, shim_bundle.ws_a2.checkout_id)
    assert scope_a1.repo_id == scope_a2.repo_id
    assert scope_a1.checkout_id != scope_a2.checkout_id

    domain.checkout_scoped_artifacts["art-only-chk-a1"] = scope_a1

    with open_test_loopback_transport(shim_bundle.template, name="same-repo-checkouts", domain=domain) as h:
        adapters = os_adapters(clock=h.clock, monotonic=h.mono_clock)
        profile_a1, _ = _write_harness_profile(h, "ws-a1", workspace=shim_bundle.ws_a)
        profile_a2, _ = _write_harness_profile(h, "ws-a2", workspace=shim_bundle.ws_a2)

        caller_a1 = build_tool_caller(profile_a1, Path(shim_bundle.ws_a.checkout_path), adapters)
        caller_a2 = build_tool_caller(profile_a2, Path(shim_bundle.ws_a2.checkout_path), adapters)

        # 1. Prepare task on checkout A1 and positively read checkout A1's artifact from A1.
        rc_a1, resp_a1 = run_inprocess_stdio(
            caller_a1,
            [
                *mcp_init_frames(1),
                mcp_call_frame(
                    2,
                    "prepare_task",
                    {
                        "schema_version": "2.0",
                        "idempotency_key": "idem-same-repo-prep-a1",
                        "task_id": "task-same-repo-a1",
                        "harness_id": "claude-code",
                        "description": "prepare on checkout A1",
                    },
                ),
                mcp_call_frame(
                    3,
                    "get_artifact",
                    {
                        "schema_version": "2.0",
                        "idempotency_key": "idem-same-repo-art-a1-ok",
                        "workspace_id": shim_bundle.ws_a.repo_id,
                        "task_id": "task-same-repo-a1",
                        "artifact_id": "art-only-chk-a1",
                        "revision": 1,
                        "level": "L1",
                    },
                ),
            ],
        )
        assert rc_a1 == 0
        prep_a1_sc = cast(dict[str, Any], _extract_tool_result(resp_a1[1])["structuredContent"])
        assert prep_a1_sc["ok"] is True
        delivery_a1 = str(prep_a1_sc["data"]["delivery_id"])
        assert str(prep_a1_sc["data"]["assignment_id"])

        art_a1_sc = cast(dict[str, Any], _extract_tool_result(resp_a1[2])["structuredContent"])
        assert art_a1_sc["ok"] is True
        assert art_a1_sc["data"]["artifact_id"] == "art-only-chk-a1"

        # Also prepare a task on checkout A2 so A2 has its own valid task/delivery.
        rc_a2_prep, resp_a2_prep = run_inprocess_stdio(
            caller_a2,
            [
                *mcp_init_frames(1),
                mcp_call_frame(
                    2,
                    "prepare_task",
                    {
                        "schema_version": "2.0",
                        "idempotency_key": "idem-same-repo-prep-a2",
                        "task_id": "task-same-repo-a2",
                        "harness_id": "claude-code",
                        "description": "prepare on checkout A2",
                    },
                ),
            ],
        )
        assert rc_a2_prep == 0
        prep_a2_sc = cast(dict[str, Any], _extract_tool_result(resp_a2_prep[1])["structuredContent"])
        assert prep_a2_sc["ok"] is True

        seq_before = h.ledger_sequence()
        idem_before = h.idempotency_count()
        sends_before = h.count_send_attempts()

        # 2. From checkout A2 (same repo_id, different checkout_id), attempt to:
        #    (a) get_artifact using A1's task_id
        #    (b) get_artifact using A2's task_id but A1-scoped artifact `art-only-chk-a1`
        #    (c) record_outcome referencing A1's delivery_id
        rc_cross, resp_cross = run_inprocess_stdio(
            caller_a2,
            [
                *mcp_init_frames(1),
                mcp_call_frame(
                    2,
                    "get_artifact",
                    {
                        "schema_version": "2.0",
                        "idempotency_key": "idem-cross-art-task-a1",
                        "workspace_id": shim_bundle.ws_a2.repo_id,
                        "task_id": "task-same-repo-a1",
                        "artifact_id": "art-shared-1",
                        "revision": 1,
                        "level": "L1",
                    },
                ),
                mcp_call_frame(
                    3,
                    "get_artifact",
                    {
                        "schema_version": "2.0",
                        "idempotency_key": "idem-cross-art-ref-a1",
                        "workspace_id": shim_bundle.ws_a2.repo_id,
                        "task_id": "task-same-repo-a2",
                        "artifact_id": "art-only-chk-a1",
                        "revision": 1,
                        "level": "L1",
                    },
                ),
                mcp_call_frame(
                    4,
                    "record_outcome",
                    {
                        "schema_version": "2.0",
                        "idempotency_key": "idem-cross-outcome-a1",
                        "workspace_id": shim_bundle.ws_a2.repo_id,
                        "delivery_id": delivery_a1,
                        "outcome": "success",
                        "applied_refs": [],
                    },
                ),
            ],
        )
        assert rc_cross == 0
        for idx in (1, 2, 3):
            refused = _extract_tool_result(resp_cross[idx])
            assert refused.get("isError") is True
            assert refused.get("structuredContent") == {
                "ok": False,
                "error": {
                    "code": "not_found",
                    "message": "not found",
                },
            }

        # Refusals must happen BEFORE staging CAS blobs or mutating idempotency/ledger/send_attempts!
        assert h.ledger_sequence() == seq_before
        assert h.idempotency_count() == idem_before
        assert h.count_send_attempts() == sends_before

        # 3. Positive check: recording outcome for A1's delivery from shim A1 succeeds.
        rc_pos, resp_pos = run_inprocess_stdio(
            caller_a1,
            [
                *mcp_init_frames(1),
                mcp_call_frame(
                    2,
                    "record_outcome",
                    {
                        "schema_version": "2.0",
                        "idempotency_key": "idem-pos-outcome-a1",
                        "workspace_id": shim_bundle.ws_a.repo_id,
                        "delivery_id": delivery_a1,
                        "outcome": "success",
                        "applied_refs": [],
                    },
                ),
            ],
        )
        assert rc_pos == 0
        pos_sc = cast(dict[str, Any], _extract_tool_result(resp_pos[1])["structuredContent"])
        assert pos_sc["ok"] is True
        assert pos_sc["data"]["status"] == "declared"


# ---------------------------------------------------------------------------
# 7. Profile switch with same idempotency_key conflicts even with identical args
# ---------------------------------------------------------------------------


def test_profile_switch_same_key_conflicts_even_when_outcome_args_are_unchanged(
    shim_bundle: ShimTemplateBundle,
) -> None:
    """Replaying ``record_outcome`` under same profile replays ID; switching profile with same key conflicts."""
    domain = _make_domain(shim_bundle)
    with open_test_loopback_transport(shim_bundle.template, name="profile-switch-key", domain=domain) as h:
        adapters = os_adapters(clock=h.clock, monotonic=h.mono_clock)
        profile_a1, _ = _write_harness_profile(h, "ws-a1", workspace=shim_bundle.ws_a)
        profile_a2, _ = _write_harness_profile(h, "ws-a2", workspace=shim_bundle.ws_a2)

        caller_a1 = build_tool_caller(profile_a1, Path(shim_bundle.ws_a.checkout_path), adapters)

        # 1. Prepare task on A1 and commit record_outcome with arguments that omit checkout_id.
        _, prep_res = run_inprocess_stdio(
            caller_a1,
            [
                *mcp_init_frames(1),
                mcp_call_frame(
                    2,
                    "prepare_task",
                    {
                        "schema_version": "2.0",
                        "idempotency_key": "idem-switch-prep-0001",
                        "task_id": "task-switch-1",
                        "harness_id": "claude-code",
                        "description": "prepare task for outcome replay and conflict test",
                    },
                ),
            ],
        )
        prep_data = cast(dict[str, Any], _extract_tool_result(prep_res[1])["structuredContent"])["data"]
        delivery_id = str(prep_data["delivery_id"])
        assert str(prep_data["assignment_id"])

        shared_outcome_args: dict[str, JsonValue] = {
            "schema_version": "2.0",
            "idempotency_key": "idem-outcome-shared-key-0001",
            "workspace_id": shim_bundle.ws_a.repo_id,
            "delivery_id": delivery_id,
            "outcome": "success",
            "applied_refs": [],
        }

        _, out_res1 = run_inprocess_stdio(
            caller_a1,
            [*mcp_init_frames(1), mcp_call_frame(2, "record_outcome", shared_outcome_args)],
        )
        sc1 = cast(dict[str, Any], _extract_tool_result(out_res1[1])["structuredContent"])
        assert sc1["ok"] is True
        outcome_id_1 = str(sc1["data"]["outcome_id"])

        # 2. Relaunch a fresh shim with the SAME profile_a1 and replay the identical outcome call -> same logical ID.
        caller_a1_restarted = build_tool_caller(profile_a1, Path(shim_bundle.ws_a.checkout_path), adapters)
        _, out_res2 = run_inprocess_stdio(
            caller_a1_restarted,
            [*mcp_init_frames(1), mcp_call_frame(2, "record_outcome", shared_outcome_args)],
        )
        sc2 = cast(dict[str, Any], _extract_tool_result(out_res2[1])["structuredContent"])
        assert sc2["ok"] is True
        assert sc2["data"]["outcome_id"] == outcome_id_1

        # 3. Relaunch with profile_a2 (bound to checkout A2) and send the EXACT SAME outcome arguments & key.
        # Because `selected_scope` is included in the daemon's request HMAC, this must return `idempotency_conflict`.
        caller_a2 = build_tool_caller(profile_a2, Path(shim_bundle.ws_a2.checkout_path), adapters)
        _, out_res3 = run_inprocess_stdio(
            caller_a2,
            [*mcp_init_frames(1), mcp_call_frame(2, "record_outcome", shared_outcome_args)],
        )
        res3 = _extract_tool_result(out_res3[1])
        assert res3.get("isError") is True
        assert res3.get("structuredContent") == {
            "ok": False,
            "error": {
                "code": "idempotency_conflict",
                "message": "idempotency conflict",
            },
        }


# ---------------------------------------------------------------------------
# 8. Job scope authorization across scopeless and workspace-bound profiles
# ---------------------------------------------------------------------------


def test_missing_scope_is_refused_for_workspace_job_and_global_job_is_authorized(
    shim_bundle: ShimTemplateBundle,
) -> None:
    """Scopeless shim authorizes global job and returns ``not_found`` for scoped/other-owner/missing jobs."""
    domain = _make_domain(shim_bundle)
    with open_test_loopback_transport(shim_bundle.template, name="job-scope-auth", domain=domain) as h:
        adapters = os_adapters(clock=h.clock, monotonic=h.mono_clock)
        profile_no_ws, _ = _write_harness_profile(h, "no-ws", workspace=None)
        profile_a1, _ = _write_harness_profile(h, "ws-a1", workspace=shim_bundle.ws_a)
        profile_b, _ = _write_harness_profile(h, "ws-b", workspace=shim_bundle.ws_b)

        caller_no_ws = build_tool_caller(profile_no_ws, h.base_dir, adapters)
        caller_a1 = build_tool_caller(profile_a1, Path(shim_bundle.ws_a.checkout_path), adapters)
        caller_b = build_tool_caller(profile_b, Path(shim_bundle.ws_b.checkout_path), adapters)

        # 1. Scopeless shim: global_job succeeds; scoped_job, bob_job, and unknown_job all return identical not_found.
        _, no_ws_res = run_inprocess_stdio(
            caller_no_ws,
            [
                *mcp_init_frames(1),
                mcp_call_frame(2, "get_job", {"schema_version": "2.0", "job_id": shim_bundle.global_job_id}),
                mcp_call_frame(3, "get_job", {"schema_version": "2.0", "job_id": shim_bundle.scoped_job_id}),
                mcp_call_frame(4, "get_job", {"schema_version": "2.0", "job_id": shim_bundle.bob_job_id}),
                mcp_call_frame(5, "get_job", {"schema_version": "2.0", "job_id": "job-missing-opaque-id"}),
            ],
        )
        g_sc = cast(dict[str, Any], _extract_tool_result(no_ws_res[1])["structuredContent"])
        assert g_sc["ok"] is True and g_sc["data"]["job_id"] == shim_bundle.global_job_id

        expected_not_found: dict[str, JsonValue] = {
            "ok": False,
            "error": {"code": "not_found", "message": "not found"},
        }
        for idx in (2, 3, 4):
            assert _extract_tool_result(no_ws_res[idx])["structuredContent"] == expected_not_found

        # 2. Shim bound to ws_a: both global_job and ws_a's scoped_job succeed; bob_job returns not_found.
        _, a1_res = run_inprocess_stdio(
            caller_a1,
            [
                *mcp_init_frames(1),
                mcp_call_frame(2, "get_job", {"schema_version": "2.0", "job_id": shim_bundle.global_job_id}),
                mcp_call_frame(3, "get_job", {"schema_version": "2.0", "job_id": shim_bundle.scoped_job_id}),
                mcp_call_frame(4, "get_job", {"schema_version": "2.0", "job_id": shim_bundle.bob_job_id}),
            ],
        )
        assert cast(dict[str, Any], _extract_tool_result(a1_res[1])["structuredContent"])["ok"] is True
        s_sc = cast(dict[str, Any], _extract_tool_result(a1_res[2])["structuredContent"])
        assert s_sc["ok"] is True and s_sc["data"]["job_id"] == shim_bundle.scoped_job_id
        assert _extract_tool_result(a1_res[3])["structuredContent"] == expected_not_found

        # 3. Shim bound to ws_b: global_job succeeds, but ws_a's scoped_job returns not_found.
        _, b_res = run_inprocess_stdio(
            caller_b,
            [
                *mcp_init_frames(1),
                mcp_call_frame(2, "get_job", {"schema_version": "2.0", "job_id": shim_bundle.global_job_id}),
                mcp_call_frame(3, "get_job", {"schema_version": "2.0", "job_id": shim_bundle.scoped_job_id}),
            ],
        )
        assert cast(dict[str, Any], _extract_tool_result(b_res[1])["structuredContent"])["ok"] is True
        assert _extract_tool_result(b_res[2])["structuredContent"] == expected_not_found


# ---------------------------------------------------------------------------
# 9. Shim pins leaf cert & identity before sending bearer and never reconnects
# ---------------------------------------------------------------------------


def test_shim_pins_before_bearer_and_never_reconnects(
    shim_bundle: ShimTemplateBundle,
    shim_scratch_root: Path,
) -> None:
    """Shim verifies leaf pin and ``/v2/identity`` before sending bearer token, and never auto-reconnects."""
    case_dir = shim_scratch_root / "pin-and-no-reconnect"
    chk_a_path = Path(shim_bundle.ws_a.checkout_path)
    store_id = shim_bundle.template.store_id
    cred_file = write_credential_file(case_dir / "credential.txt", shim_bundle.template.cred.token)

    valid_ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    valid_ssl_ctx.load_cert_chain(
        certfile=str(shim_bundle.template.tls.cert_path),
        keyfile=str(shim_bundle.template.tls.key_path),
    )

    # Sub-case 1: Wrong leaf pin -> 0 post-handshake bytes sent (no GET /v2/identity, no Bearer token).
    with _FakeTlsLoopbackServer(valid_ssl_ctx, lambda s, srv: _read_http_request(s, srv)) as wrong_pin_srv:
        ep1 = Endpoint(
            version=ENDPOINT_VERSION,
            host="127.0.0.1",
            port=wrong_pin_srv.port,
            store_id=store_id,
            writer_epoch=1,
            instance_id=new_id(),
        )
        ep1_path = write_owner_only_bytes(case_dir / "ep-wrong-pin.json", ep1.encode_canonical())
        prof_wrong_pin, _ = write_client_profile_file(
            case_dir / "prof-wrong-pin.json",
            endpoint_path=ep1_path,
            expected_store_id=store_id,
            ca_file=shim_bundle.template.tls.ca_cert_path,
            leaf_cert_sha256="f" * 64,
            credential_file=cred_file,
            workspace=_workspace_dict(shim_bundle.ws_a),
        )
        caller_wrong_pin = build_tool_caller(prof_wrong_pin, chk_a_path, os_adapters())
        _, res_wp = run_inprocess_stdio(
            caller_wrong_pin,
            [*mcp_init_frames(1), mcp_call_frame(2, "get_health", {"schema_version": "2.0"})],
        )
        wp_tool = _extract_tool_result(res_wp[1])
        assert wp_tool.get("isError") is True
        assert "_meta" not in wp_tool
        assert wp_tool.get("structuredContent") == {
            "ok": False,
            "error": {"code": "identity_mismatch", "message": "identity mismatch"},
        }
        assert wrong_pin_srv.accept_count == 1
        assert wrong_pin_srv.all_received_bytes == b""

    # Sub-case 2: Expired leaf cert (even with matching SHA-256 pin) -> rejected during TLS handshake, 0 bytes sent.
    exp_ctx, exp_ca_path, exp_leaf_sha = _generate_self_signed_or_expired_tls(case_dir / "expired-tls", expired=True)
    with _FakeTlsLoopbackServer(exp_ctx, lambda s, srv: _read_http_request(s, srv)) as exp_srv:
        ep2 = Endpoint(
            version=ENDPOINT_VERSION,
            host="127.0.0.1",
            port=exp_srv.port,
            store_id=store_id,
            writer_epoch=1,
            instance_id=new_id(),
        )
        ep2_path = write_owner_only_bytes(case_dir / "ep-expired.json", ep2.encode_canonical())
        prof_exp, _ = write_client_profile_file(
            case_dir / "prof-expired.json",
            endpoint_path=ep2_path,
            expected_store_id=store_id,
            ca_file=exp_ca_path,
            leaf_cert_sha256=exp_leaf_sha,
            credential_file=cred_file,
            workspace=_workspace_dict(shim_bundle.ws_a),
        )
        caller_exp = build_tool_caller(prof_exp, chk_a_path, os_adapters())
        _, res_exp = run_inprocess_stdio(
            caller_exp,
            [*mcp_init_frames(1), mcp_call_frame(2, "get_health", {"schema_version": "2.0"})],
        )
        exp_tool = _extract_tool_result(res_exp[1])
        assert exp_tool.get("isError") is True
        assert "_meta" not in exp_tool
        assert exp_tool.get("structuredContent") == {
            "ok": False,
            "error": {"code": "identity_mismatch", "message": "identity mismatch"},
        }
        assert exp_srv.accept_count == 1
        assert exp_srv.all_received_bytes == b""

    # Sub-case 3: Matching leaf pin, but `/v2/identity` returns wrong tuple -> 0 POST /v2/tools/call, 0 Bearer bytes.
    inst3 = new_id()

    def _wrong_tuple_handler(ssl_sock: ssl.SSLSocket, srv: _FakeTlsLoopbackServer) -> None:
        _read_http_request(ssl_sock, srv)
        _write_http_json(
            ssl_sock,
            "200 OK",
            {
                "store_id": store_id,
                "writer_epoch": 999,
                "instance_id": inst3,
                "contract": "mcp-tools-v2",
                "schema_digest": load_catalog().schema_digest,
            },
            close=False,
        )
        _read_http_request(ssl_sock, srv)

    with _FakeTlsLoopbackServer(valid_ssl_ctx, _wrong_tuple_handler) as tuple_srv:
        ep3 = Endpoint(
            version=ENDPOINT_VERSION,
            host="127.0.0.1",
            port=tuple_srv.port,
            store_id=store_id,
            writer_epoch=1,
            instance_id=inst3,
        )
        ep3_path = write_owner_only_bytes(case_dir / "ep-wrong-tuple.json", ep3.encode_canonical())
        prof_tuple, _ = write_client_profile_file(
            case_dir / "prof-wrong-tuple.json",
            endpoint_path=ep3_path,
            expected_store_id=store_id,
            ca_file=shim_bundle.template.tls.ca_cert_path,
            leaf_cert_sha256=shim_bundle.template.tls.leaf_cert_sha256,
            credential_file=cred_file,
            workspace=_workspace_dict(shim_bundle.ws_a),
        )
        caller_tuple = build_tool_caller(prof_tuple, chk_a_path, os_adapters())
        _, res_tuple = run_inprocess_stdio(
            caller_tuple,
            [*mcp_init_frames(1), mcp_call_frame(2, "get_health", {"schema_version": "2.0"})],
        )
        tuple_tool = _extract_tool_result(res_tuple[1])
        assert tuple_tool.get("isError") is True
        assert "_meta" not in tuple_tool
        assert tuple_tool.get("structuredContent") == {
            "ok": False,
            "error": {"code": "identity_mismatch", "message": "identity mismatch"},
        }
        assert tuple_srv.accept_count == 1
        assert tuple_srv.post_call_count == 0
        assert b"Authorization" not in tuple_srv.all_received_bytes
        assert shim_bundle.template.cred.token.encode("utf-8") not in tuple_srv.all_received_bytes

    # Sub-case 4: Socket drops right after `/v2/identity` (with `Connection: close`) -> never auto-reconnects!
    inst4 = new_id()

    def _drop_after_identity_handler(ssl_sock: ssl.SSLSocket, srv: _FakeTlsLoopbackServer) -> None:
        _read_http_request(ssl_sock, srv)
        _write_http_json(
            ssl_sock,
            "200 OK",
            {
                "store_id": store_id,
                "writer_epoch": 1,
                "instance_id": inst4,
                "contract": "mcp-tools-v2",
                "schema_digest": load_catalog().schema_digest,
            },
            close=True,
        )

    with _FakeTlsLoopbackServer(valid_ssl_ctx, _drop_after_identity_handler) as drop_srv:
        ep4 = Endpoint(
            version=ENDPOINT_VERSION,
            host="127.0.0.1",
            port=drop_srv.port,
            store_id=store_id,
            writer_epoch=1,
            instance_id=inst4,
        )
        ep4_path = write_owner_only_bytes(case_dir / "ep-drop.json", ep4.encode_canonical())
        prof_drop, _ = write_client_profile_file(
            case_dir / "prof-drop.json",
            endpoint_path=ep4_path,
            expected_store_id=store_id,
            ca_file=shim_bundle.template.tls.ca_cert_path,
            leaf_cert_sha256=shim_bundle.template.tls.leaf_cert_sha256,
            credential_file=cred_file,
            workspace=_workspace_dict(shim_bundle.ws_a),
        )
        caller_drop = build_tool_caller(prof_drop, chk_a_path, os_adapters())
        _, res_drop = run_inprocess_stdio(
            caller_drop,
            [*mcp_init_frames(1), mcp_call_frame(2, "get_health", {"schema_version": "2.0"})],
        )
        drop_tool = _extract_tool_result(res_drop[1])
        assert drop_tool.get("isError") is True
        assert "_meta" not in drop_tool
        assert drop_tool.get("structuredContent") == {
            "ok": False,
            "error": {"code": "daemon_unavailable", "message": "daemon unavailable"},
        }
        assert drop_srv.accept_count == 1
        assert drop_srv.post_call_count == 0
        assert b"Authorization" not in drop_srv.all_received_bytes

    # Sub-case 5: Valid TLS daemon has 1 POST; explicit retry across daemon restart re-reads endpoint.json.
    domain = _make_domain(shim_bundle)
    with open_test_loopback_transport(shim_bundle.template, name="pin-valid-restart", domain=domain) as h1:
        profile_path, _ = _write_harness_profile(h1, "valid", workspace=shim_bundle.ws_a)
        caller_live = build_tool_caller(profile_path, chk_a_path, os_adapters(clock=h1.clock, monotonic=h1.mono_clock))

        prep_frame = mcp_call_frame(
            2,
            "prepare_task",
            {
                "schema_version": "2.0",
                "idempotency_key": "idem-pin-restart-replay-0001",
                "task_id": "task-pin-restart-1",
                "harness_id": "claude-code",
                "description": "verify single POST and replay after endpoint epoch change",
            },
        )
        _, live_res1 = run_inprocess_stdio(caller_live, [*mcp_init_frames(1), prep_frame])
        sc_live1 = cast(dict[str, Any], _extract_tool_result(live_res1[1])["structuredContent"])
        assert sc_live1["ok"] is True
        deliv_1 = str(sc_live1["data"]["delivery_id"])
        assert h1.submit_count == 1

        # Stop h1's server & loop cleanly, then start a second OwnerLoop + LoopbackServer on the SAME h1.data_root!
        stop_dl = time.perf_counter() + 2.0
        h1.server.quiesce(stop_dl)
        h1.loop.stop(grace_s=2.0)
        h1.server.finish(stop_dl)

        from superbrain.cli_api._loopback_server import LoopbackServer
        from superbrain.composition.daemon_entry import BoundLoopbackListener, create_daemon_owner_loop

        bound2_list: list[BoundLoopbackListener] = []
        loop2 = create_daemon_owner_loop(
            os_=os_adapters(clock=h1.clock),
            clock=h1.clock,
            monotonic_clock=h1.mono_clock,
            domain=domain,
            on_listener_bound=bound2_list.append,
        )
        stop_ev2 = threading.Event()
        srv2: LoopbackServer | None = None
        try:
            ready2 = loop2.start(h1.config)
            assert ready2.endpoint.writer_epoch == h1.ready.endpoint.writer_epoch + 1
            assert ready2.endpoint.instance_id != h1.ready.endpoint.instance_id
            srv2 = LoopbackServer(
                listener=bound2_list[0].sock,
                ssl_context=bound2_list[0].ssl_context,
                ready=ready2,
                owner=loop2,
                monotonic_ns=h1.mono_clock.monotonic_ns,
                stop_event=stop_ev2,
            )
            srv2.start()

            # Same `caller_live` instance re-reads `endpoint.json` on the explicit retry and replays `deliv_1`!
            _, live_res2 = run_inprocess_stdio(caller_live, [*mcp_init_frames(1), prep_frame])
            sc_live2 = cast(dict[str, Any], _extract_tool_result(live_res2[1])["structuredContent"])
            assert sc_live2["ok"] is True
            assert sc_live2["data"]["delivery_id"] == deliv_1
            assert len(domain.prepared_calls) == 1
        finally:
            if srv2 is not None:
                srv2.quiesce(time.perf_counter() + 2.0)
            loop2.stop(grace_s=2.0)
            if srv2 is not None:
                srv2.finish(time.perf_counter() + 2.0)


# ---------------------------------------------------------------------------
# 10. Post-response loss preserves uncertainty metadata & idempotency key (Kills Mutant 3)
# ---------------------------------------------------------------------------


def test_shim_post_response_loss_preserves_uncertainty_and_key(
    shim_bundle: ShimTemplateBundle,
) -> None:
    """Socket/framing loss after POST sets ``superbrain/request_may_have_run=True`` and replays on retry."""
    domain = _make_domain(shim_bundle)
    with open_test_loopback_transport(shim_bundle.template, name="post-loss-uncertainty", domain=domain) as h:
        profile_path, _ = _write_harness_profile(h, "ws-a", workspace=shim_bundle.ws_a)
        caller = build_tool_caller(
            profile_path,
            Path(shim_bundle.ws_a.checkout_path),
            os_adapters(clock=h.clock, monotonic=h.mono_clock),
        )

        # Inject a mid-response socket drop on the first `/v2/tools/call` response write (after commit).
        drop_mode = "partial_body"
        orig_wrap = h.bound.ssl_context.wrap_socket

        def _wrap_interceptor(sock: socket.socket, **kwargs: Any) -> ssl.SSLSocket:
            ssl_sock = orig_wrap(sock, **kwargs)
            orig_send = ssl_sock.send

            def _faulty_send(data: bytes | memoryview, flags: int = 0) -> int:
                nonlocal drop_mode
                raw = bytes(data)
                if drop_mode == "partial_body" and b"task-post-loss-1" in raw:
                    drop_mode = "empty_drop"
                    orig_send(raw[:24], flags)
                    raise BrokenPipeError("simulated socket drop mid-response after commit")
                if drop_mode == "empty_drop" and b"task-post-loss-1" in raw:
                    drop_mode = "healthy"
                    raise ConnectionResetError("simulated socket reset before response head after commit")
                return orig_send(data, flags)

            ssl_sock.send = _faulty_send  # type: ignore[method-assign,assignment]
            return ssl_sock

        h.bound.ssl_context.wrap_socket = _wrap_interceptor  # type: ignore[method-assign,assignment]

        prep_call = mcp_call_frame(
            2,
            "prepare_task",
            {
                "schema_version": "2.0",
                "idempotency_key": "idem-post-loss-preserve-0001",
                "task_id": "task-post-loss-1",
                "harness_id": "claude-code",
                "description": "verify post-response loss uncertainty and idempotent replay",
            },
        )

        # Attempt 1 (partial response drop) and Attempt 2 (reset before response head) both surface uncertainty.
        for _ in range(2):
            rc_loss, res_loss = run_inprocess_stdio(caller, [*mcp_init_frames(1), prep_call])
            assert rc_loss == 0
            loss_tool = _extract_tool_result(res_loss[1])
            assert loss_tool.get("isError") is True
            assert loss_tool.get("_meta") == {"superbrain/request_may_have_run": True}
            assert loss_tool.get("structuredContent") == {
                "ok": False,
                "error": {
                    "code": "daemon_unavailable",
                    "message": "daemon unavailable",
                },
            }

        # Attempt 3 (healthy socket, SAME idempotency_key) replays the committed delivery from Attempt 1!
        rc_ok, res_ok = run_inprocess_stdio(caller, [*mcp_init_frames(1), prep_call])
        assert rc_ok == 0
        ok_tool = _extract_tool_result(res_ok[1])
        assert ok_tool.get("isError") is False
        assert "_meta" not in ok_tool
        ok_sc = cast(dict[str, Any], ok_tool["structuredContent"])
        assert ok_sc["ok"] is True
        assert ok_sc["data"]["task_id"] == "task-post-loss-1"
        assert len(domain.prepared_calls) == 1
        assert h.idempotency_count() == 1


# ---------------------------------------------------------------------------
# 11. Stdout write failure after daemon `served_only` does not create ReadAck
# ---------------------------------------------------------------------------


class _FailOnSecondWriteBuffer(io.RawIOBase):
    """Binary stdout sink that succeeds on ``initialize`` and fails with ``BrokenPipeError`` on ``tools/call``."""

    def __init__(self) -> None:
        self.lines_written: list[bytes] = []
        self._buf = bytearray()

    def writable(self) -> bool:
        return True

    def write(self, b: Any) -> int:
        raw = bytes(b)
        self._buf.extend(raw)
        while b"\n" in self._buf:
            idx = self._buf.index(b"\n")
            line = bytes(self._buf[: idx + 1])
            del self._buf[: idx + 1]
            if len(self.lines_written) >= 1:
                raise BrokenPipeError("simulated host stdout broken pipe after daemon served_only")
            self.lines_written.append(line)
        return len(raw)

    def flush(self) -> None:
        return None


def test_shim_stdout_failure_does_not_create_read_ack(
    shim_bundle: ShimTemplateBundle,
) -> None:
    """When daemon finalizes ``served_only`` and shim stdout breaks, ``served_only`` stays and 0 ReadAcks exist."""
    domain = _make_domain(shim_bundle)
    with open_test_loopback_transport(shim_bundle.template, name="stdout-fail-no-ack", domain=domain) as h:
        profile_path, _ = _write_harness_profile(h, "ws-a", workspace=shim_bundle.ws_a)
        caller = build_tool_caller(
            profile_path,
            Path(shim_bundle.ws_a.checkout_path),
            os_adapters(clock=h.clock, monotonic=h.mono_clock),
        )

        # 1. Prepare task first so task lineage exists.
        _, prep_res = run_inprocess_stdio(
            caller,
            [
                *mcp_init_frames(1),
                mcp_call_frame(
                    2,
                    "prepare_task",
                    {
                        "schema_version": "2.0",
                        "idempotency_key": "idem-stdout-fail-prep-0001",
                        "task_id": "task-stdout-fail-1",
                        "harness_id": "claude-code",
                        "description": "prepare task before artifact stdout failure",
                    },
                ),
            ],
        )
        assert cast(dict[str, Any], _extract_tool_result(prep_res[1])["structuredContent"])["ok"] is True

        # 2. Call `get_artifact` through `run_stdio` where stdout raises BrokenPipeError on the tool result frame.
        art_frames = [
            *mcp_init_frames(1),
            mcp_call_frame(
                2,
                "get_artifact",
                {
                    "schema_version": "2.0",
                    "idempotency_key": "idem-stdout-fail-art-0001",
                    "workspace_id": shim_bundle.ws_a.repo_id,
                    "task_id": "task-stdout-fail-1",
                    "artifact_id": "art-stdout-skill-1",
                    "revision": 1,
                    "level": "L1",
                },
            ),
        ]
        stdin_buf = io.BytesIO(encode_stdio_frames(art_frames))
        failing_stdout = _FailOnSecondWriteBuffer()
        rc = run_stdio(stdin_buf, cast(Any, failing_stdout), caller)
        assert rc == 1
        assert len(failing_stdout.lines_written) == 1

        # Wait for the daemon's loopback worker to settle `finalize_send_attempt` -> `served_only`.
        deadline = time.perf_counter() + 1.0
        while time.perf_counter() < deadline and h.count_send_attempts("served_only") == 0:
            time.sleep(0.005)
        h.loop.run_owner_action(lambda: None).result(timeout=2.0)

        assert h.count_send_attempts("served_only") == 1
        assert h.count_send_attempts("pending") == 0
        assert h.count_read_acks() == 0


# ---------------------------------------------------------------------------
# 12. Slow handshake + slow identity preserves tool budget & commit_outcome_unknown
# ---------------------------------------------------------------------------


def test_shim_slow_identity_preserves_tool_budget_and_commit_unknown(
    shim_bundle: ShimTemplateBundle,
) -> None:
    """Near-cap handshake + slow ``/v2/identity`` preserves full tool budget and surfaces ``commit_outcome_unknown``."""
    domain = _make_domain(shim_bundle)
    domain.pause_idem_keys.add("idem-slow-ident-commit-blocked")
    domain.allow_apply_finish.clear()

    with open_test_loopback_transport(shim_bundle.template, name="slow-identity-budget", domain=domain) as h:
        adapters = os_adapters(clock=h.clock, monotonic=h.mono_clock)
        profile_path, _ = _write_harness_profile(h, "ws-a", workspace=shim_bundle.ws_a)
        caller = build_tool_caller(profile_path, Path(shim_bundle.ws_a.checkout_path), adapters)

        # Advance fake monotonic clock by 900 ms during TLS handshake (just under 1,000 ms server handshake cap)
        # and by another 950 ms during GET /v2/identity (1,850 ms total < 2,000 ms client connect budget).
        orig_wrap = h.bound.ssl_context.wrap_socket

        def _slow_ident_wrap(sock: socket.socket, **kwargs: Any) -> ssl.SSLSocket:
            ssl_sock = orig_wrap(sock, **kwargs)
            orig_handshake = ssl_sock.do_handshake
            orig_send = ssl_sock.send

            def _slow_handshake(*a: Any, **kw: Any) -> Any:
                res = orig_handshake(*a, **kw)
                h.mono_clock.advance_ms(900)
                return res

            def _slow_send(data: bytes | memoryview, flags: int = 0) -> int:
                raw = bytes(data)
                if b'"contract":"mcp-tools-v2"' in raw:
                    h.mono_clock.advance_ms(950)
                return orig_send(data, flags)

            ssl_sock.do_handshake = _slow_handshake  # type: ignore[method-assign]
            ssl_sock.send = _slow_send  # type: ignore[method-assign,assignment]
            return ssl_sock

        h.bound.ssl_context.wrap_socket = _slow_ident_wrap  # type: ignore[method-assign,assignment]

        # Part 1: Normal write tool call taking 600 ms in `apply` succeeds even though 900 + 950 + 600 = 2,450 ms > 2 s,
        # because `POST /v2/tools/call` gets its own fresh budget after `/v2/identity` completes!
        def _advance_on_fast_call(idem_key: str, _ep_id: str) -> None:
            if idem_key == "idem-slow-ident-fast-tool":
                h.mono_clock.advance_ms(600)

        domain.on_apply_hook = _advance_on_fast_call
        _, res_fast = run_inprocess_stdio(
            caller,
            [
                *mcp_init_frames(1),
                mcp_call_frame(
                    2,
                    "submit_episode",
                    {
                        "schema_version": "2.0",
                        "idempotency_key": "idem-slow-ident-fast-tool",
                        "task_id": "task-slow-ident-1",
                        "session_id": "sess-slow-1",
                        "workspace_id": shim_bundle.ws_a.repo_id,
                        "checkout_id": shim_bundle.ws_a.checkout_id,
                        "evidence": [],
                    },
                ),
            ],
        )
        fast_tool = _extract_tool_result(res_fast[1])
        assert fast_tool.get("isError") is False
        assert cast(dict[str, Any], fast_tool["structuredContent"])["ok"] is True
        domain.on_apply_hook = None

        # Part 2: Blocked commit enters `apply` after 1,850 ms connect phase; advancing 1,480 ms into the
        # (1,475 ms .. 1,500 ms) commit cutoff window returns `commit_outcome_unknown` while owner is still held!
        blocked_frame = mcp_call_frame(
            2,
            "submit_episode",
            {
                "schema_version": "2.0",
                "idempotency_key": "idem-slow-ident-commit-blocked",
                "task_id": "task-slow-ident-2",
                "session_id": "sess-slow-2",
                "workspace_id": shim_bundle.ws_a.repo_id,
                "checkout_id": shim_bundle.ws_a.checkout_id,
                "evidence": [],
            },
        )
        box: list[tuple[int, list[dict[str, JsonValue]]]] = []
        th = threading.Thread(
            target=lambda: box.append(run_inprocess_stdio(caller, [*mcp_init_frames(1), blocked_frame]))
        )
        try:
            th.start()
            assert domain.apply_entered.wait(timeout=2.0), "Blocked submit_episode did not enter apply()"

            # Advance clock 1,480 ms past t0_tool (into the 1,475..1,500 ms commit cutoff window).
            h.mono_clock.advance_ms(1480)
            th.join(timeout=3.0)
            assert not th.is_alive(), "Client call did not return at commit cutoff while owner was held"

            rc_blk, res_blk = box[0]
            assert rc_blk == 0
            blk_tool = _extract_tool_result(res_blk[1])
            assert blk_tool.get("isError") is True
            assert "_meta" not in blk_tool
            assert blk_tool.get("structuredContent") == {
                "ok": False,
                "error": {
                    "code": "commit_outcome_unknown",
                    "message": "commit outcome unknown",
                },
            }

            # Disable slow wrap so follow-up checks while owner is still blocked run at normal speed.
            h.bound.ssl_context.wrap_socket = orig_wrap  # type: ignore[method-assign]

            # While owner is STILL held in `apply`:
            # (a) `get_health` succeeds from RAM
            # (b) retrying `submit_episode` with the same key returns `in_progress`
            _, res_while_held = run_inprocess_stdio(
                caller,
                [
                    *mcp_init_frames(1),
                    mcp_call_frame(2, "get_health", {"schema_version": "2.0"}),
                    blocked_frame,
                ],
            )
            health_held = _extract_tool_result(res_while_held[1])
            assert health_held.get("isError") is False
            assert cast(dict[str, Any], health_held["structuredContent"])["ok"] is True

            in_prog_tool = _extract_tool_result(res_while_held[2])
            assert in_prog_tool.get("isError") is True
            assert in_prog_tool.get("structuredContent") == {
                "ok": False,
                "error": {
                    "code": "in_progress",
                    "message": "operation in progress",
                },
            }

            # Release SQLite commit barrier and verify retry replays the committed episode!
            domain.allow_apply_finish.set()
            h.loop.run_owner_action(lambda: None).result(timeout=2.0)

            _, res_after_release = run_inprocess_stdio(caller, [*mcp_init_frames(1), blocked_frame])
            done_tool = _extract_tool_result(res_after_release[1])
            assert done_tool.get("isError") is False
            assert cast(dict[str, Any], done_tool["structuredContent"])["ok"] is True
        finally:
            domain.allow_apply_finish.set()
            th.join(timeout=3.0)


# ---------------------------------------------------------------------------
# 13. Native lifecycle classifier fails on workspace switch with same shim
# ---------------------------------------------------------------------------


def test_native_lifecycle_report_fails_on_workspace_switch_with_same_shim(
    shim_bundle: ShimTemplateBundle,
) -> None:
    """``workspace_transition_matches`` rejects reusing the same shim/profile across workspace switches."""
    domain = _make_domain(shim_bundle)
    scope_a = Scope(shim_bundle.ws_a.repo_id, shim_bundle.ws_a.checkout_id)
    scope_b = Scope(shim_bundle.ws_b.repo_id, shim_bundle.ws_b.checkout_id)

    with open_test_loopback_transport(shim_bundle.template, name="native-lifecycle", domain=domain) as h:
        adapters = os_adapters(clock=h.clock, monotonic=h.mono_clock)
        profile_a, digest_a = _write_harness_profile(h, "ws-a", workspace=shim_bundle.ws_a)
        profile_b, digest_b = _write_harness_profile(h, "ws-b", workspace=shim_bundle.ws_b)
        assert digest_a != digest_b

        caller_a = build_tool_caller(profile_a, Path(shim_bundle.ws_a.checkout_path), adapters)
        caller_b = build_tool_caller(profile_b, Path(shim_bundle.ws_b.checkout_path), adapters)

        # Observe shim A on checkout A via `prepare_task`.
        _, res_a = run_inprocess_stdio(
            caller_a,
            [
                *mcp_init_frames(1),
                mcp_call_frame(
                    2,
                    "prepare_task",
                    {
                        "schema_version": "2.0",
                        "idempotency_key": "idem-lifecycle-obs-a",
                        "task_id": "task-lifecycle-a",
                        "harness_id": "claude-code",
                        "description": "observe workspace A",
                    },
                ),
            ],
        )
        data_a = cast(dict[str, Any], _extract_tool_result(res_a[1])["structuredContent"])["data"]
        observed_a = Scope(str(data_a["workspace_id"]), str(data_a["checkout_id"]))
        assert observed_a == scope_a

        obs_a = ShimLaunchObservation(
            pid=10101,
            started_at="2026-11-10T12:00:00Z",
            profile_digest=digest_a,
            observed_scope=observed_a,
            profile_path=profile_a,
            launch_cwd=Path(shim_bundle.ws_a.checkout_path),
            reported_alias=shim_bundle.ws_a.alias,
        )

        # 1. Attempting to switch to workspace B while keeping shim A (same PID/start time or same profile_a) FAILS.
        assert (
            workspace_transition_matches(
                obs_a,
                obs_a,
                expected_scope=scope_b,
                expected_profile_digest=digest_b,
            )
            is False
        )
        # Even if a buggy host claims scope_b/digest_b without relaunching a new shim process (same pid + started_at):
        obs_reused_proc = ShimLaunchObservation(
            pid=obs_a.pid,
            started_at=obs_a.started_at,
            profile_digest=digest_b,
            observed_scope=scope_b,
        )
        assert (
            workspace_transition_matches(
                obs_a,
                obs_reused_proc,
                expected_scope=scope_b,
                expected_profile_digest=digest_b,
            )
            is False
        )
        # Even if a new process is spawned, if it still loads profile_a (digest_a):
        obs_stale_profile = ShimLaunchObservation(
            pid=20202,
            started_at="2026-11-10T12:01:00Z",
            profile_digest=digest_a,
            observed_scope=scope_a,
        )
        assert (
            workspace_transition_matches(
                obs_a,
                obs_stale_profile,
                expected_scope=scope_b,
                expected_profile_digest=digest_b,
            )
            is False
        )

        # Also verify that calling workspace B on live `caller_a` is refused with `identity_mismatch`.
        _, res_a_wrong_ws = run_inprocess_stdio(
            caller_a,
            [
                *mcp_init_frames(1),
                mcp_call_frame(
                    2,
                    "prepare_task",
                    {
                        "schema_version": "2.0",
                        "idempotency_key": "idem-lifecycle-wrong-ws",
                        "task_id": "task-lifecycle-wrong",
                        "harness_id": "claude-code",
                        "workspace_hint": shim_bundle.ws_b.alias,
                        "description": "attempt workspace B on shim A",
                    },
                ),
            ],
        )
        wrong_tool = _extract_tool_result(res_a_wrong_ws[1])
        assert wrong_tool.get("isError") is True
        assert wrong_tool.get("structuredContent") == {
            "ok": False,
            "error": {"code": "identity_mismatch", "message": "identity mismatch"},
        }

        # 2. Relaunching a distinct shim process with profile_b in checkout_b binds to scope_b and PASSES.
        _, res_b = run_inprocess_stdio(
            caller_b,
            [
                *mcp_init_frames(1),
                mcp_call_frame(
                    2,
                    "prepare_task",
                    {
                        "schema_version": "2.0",
                        "idempotency_key": "idem-lifecycle-obs-b",
                        "task_id": "task-lifecycle-b",
                        "harness_id": "claude-code",
                        "description": "observe workspace B",
                    },
                ),
            ],
        )
        data_b = cast(dict[str, Any], _extract_tool_result(res_b[1])["structuredContent"])["data"]
        observed_b = Scope(str(data_b["workspace_id"]), str(data_b["checkout_id"]))
        assert observed_b == scope_b

        obs_b = ShimLaunchObservation(
            pid=20202,
            started_at="2026-11-10T12:02:00Z",
            profile_digest=digest_b,
            observed_scope=observed_b,
            profile_path=profile_b,
            launch_cwd=Path(shim_bundle.ws_b.checkout_path),
            reported_alias=shim_bundle.ws_b.alias,
        )
        assert (
            workspace_transition_matches(
                obs_a,
                obs_b,
                expected_scope=scope_b,
                expected_profile_digest=digest_b,
                expected_first_scope=scope_a,
                expected_alias=shim_bundle.ws_b.alias,
            )
            is True
        )
