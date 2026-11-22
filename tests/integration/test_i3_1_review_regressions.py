"""Round-2 RED regression oracle for I3-1-R02 and I3-1-R04."""

from __future__ import annotations

import base64
import hashlib
import json
import socket
import sqlite3
import ssl
import struct
import sys
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from superbrain.adapters.auth.ssh_sig import SshSigVerifier
from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.daemon_config import read_daemon_config
from superbrain.application.approvals import OperatorHandle
from superbrain.application.owner_loop import OwnerLoop
from superbrain.cli_api import _server_http
from superbrain.cli_api._loopback_server import LoopbackServer
from superbrain.cli_api.operator import OperatorRequest, parse_operator_body
from superbrain.composition import daemon_entry
from superbrain.composition.daemon_entry import BoundLoopbackListener, create_daemon_owner_loop
from superbrain.composition.init_entry import InitReport, InitRequest, init_store, reset_signers
from superbrain.composition.operator_entry import make_operator_executor
from superbrain.core._kernel_approval import (
    APPROVAL_NAMESPACE,
    CLI_HARNESS_ID,
    RISK_POLICY_VERSION,
    ApprovalAction,
    ApprovalChannel,
    ApprovalMessage,
    AssuranceLevel,
    RecoveryScope,
    RiskLevel,
    SignerEnrollment,
)
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import (
    TOTAL_REQUEST_BUDGET_NS,
    DaemonConfig,
    Principal,
    Ready,
    ResourceDigest,
    ShutdownState,
)
from superbrain.core.wire import load_catalog, make_error_envelope
from superbrain.ports.os import OsAdapters
from superbrain.storage.layout import DataRoot
from tests.support.clock import FakeClock
from tests.support.fs import digest_tree
from tests.support.inc2_fixture import reopen_kernel_job_runtime
from tests.support.inc2_transport import FakeMonotonicClock, read_raw_http_response
from tests.support.kernel_auth import make_bootstrap_auth, seed_principal_and_credential

OWNER = "dan"
MACHINE = "devbox-1"
ENROLL = "/v2/operator/signer/enroll"


def _s(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def _ssh_enrollment(owner_id: str = OWNER) -> tuple[Ed25519PrivateKey, SignerEnrollment, str]:
    priv = Ed25519PrivateKey.generate()
    raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    blob = _s(b"ssh-ed25519") + _s(raw)
    line = "ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + " r2-int@devbox"
    return priv, SignerEnrollment(owner_id=owner_id, channel=ApprovalChannel.SSH_KEY, public_key=line), line


def _ssh_sign(priv: Ed25519PrivateKey, data: bytes) -> str:
    raw_pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    blob = _s(b"ssh-ed25519") + _s(raw_pub)
    signed = (
        b"SSHSIG"
        + _s(APPROVAL_NAMESPACE.encode())
        + _s(b"")
        + _s(b"sha512")
        + _s(hashlib.sha512(data).digest())
    )
    sig = _s(b"ssh-ed25519") + _s(priv.sign(signed))
    hdr = b"SSHSIG" + struct.pack(">I", 1) + _s(blob) + _s(APPROVAL_NAMESPACE.encode()) + _s(b"")
    body = hdr + _s(b"sha512") + _s(sig)
    armored = base64.b64encode(body).decode("ascii")
    lines = [armored[i : i + 70] for i in range(0, len(armored), 70)]
    pem = ("-----BEGIN SSH SIGNATURE-----\n" + "\n".join(lines) + "\n-----END SSH SIGNATURE-----\n").encode("ascii")
    return base64.b64encode(pem).decode("ascii")


def _msg_from_challenge(ch: dict[str, Any]) -> ApprovalMessage:
    return ApprovalMessage(
        store_id=str(ch["store_id"]), owner_id=OWNER, trust_generation=int(ch["trust_generation"]),
        action=ApprovalAction(str(ch["action"])), subject_id=str(ch["subject_id"]), subject_revision=1,
        resource_digests=(ResourceDigest("CLAUDE.md", "sha256:" + "a" * 64),), target_files=(),
        risk_level=RiskLevel(str(ch["risk_level"])), risk_policy_version=RISK_POLICY_VERSION,
        recovery_scope=RecoveryScope.NONE, nonce=str(ch["nonce"]),
        expires_at=datetime.fromisoformat(str(ch["expires_at"]).replace("Z", "+00:00")),
    )


def _hold_owner(loop: OwnerLoop) -> tuple[threading.Event, threading.Event, Any]:
    entered, release = threading.Event(), threading.Event()

    def _wait() -> None:
        entered.set()
        release.wait(timeout=3.0)

    fut = loop.run_owner_action(_wait)
    assert entered.wait(timeout=2.0)
    return entered, release, fut


def _arm_run_owner_spy(loop: OwnerLoop, monkeypatch: pytest.MonkeyPatch) -> threading.Event:
    queued_evt = threading.Event()
    orig_run = loop.run_owner_action

    def _spy(fn: Callable[[], Any]) -> Any:
        fut = orig_run(fn)
        queued_evt.set()
        return fut

    monkeypatch.setattr(loop, "run_owner_action", _spy)
    return queued_evt


def _enroll_body(public_line: str) -> dict[str, object]:
    return {"enrollment": {"channel": ApprovalChannel.SSH_KEY.value, "public_key": public_line}}


def _post_behind_blocked_owner(
    loop: OwnerLoop,
    arm_evt: Callable[[], threading.Event], post_fn: Callable[[], bytes], after_queue: Callable[[], Any],
) -> list[bytes]:
    _ent, blk_release, blk_fut = _hold_owner(loop)
    wait_evt, out = arm_evt(), list[bytes]()
    client_thr = _run_bg(post_fn, out)
    try:
        assert wait_evt.wait(timeout=2.0)
        after_queue()
    finally:
        blk_release.set()
    blk_fut.result(timeout=2.0)
    client_thr.join(timeout=2.0)
    return out


def _run_bg(fn: Callable[[], bytes] | Any, out: list[bytes] | None = None) -> threading.Thread:
    def _target() -> None:
        res = fn()
        if out is not None:
            out.append(res)

    thr = threading.Thread(target=_target, daemon=True)
    thr.start()
    return thr


def _init_fixture(
    trusted_tmp: Path, clock: FakeClock, mono: FakeMonotonicClock, *, owner_id: str = OWNER
) -> tuple[InitRequest, InitReport, Ed25519PrivateKey, DaemonConfig, str, str, OsAdapters]:
    os_, cfg_dir = os_adapters(clock=clock, monotonic=mono), trusted_tmp / "config"
    cfg_dir.mkdir()
    os_.permissions.secure_directory(cfg_dir)
    priv, enrollment, _line = _ssh_enrollment(owner_id)
    req = InitRequest(trusted_tmp / "data", cfg_dir, owner_id, MACHINE, enrollment)
    report = init_store(req, os_)
    cfg = read_daemon_config(report.daemon_config_path, os_)
    ca = (cfg_dir / "tls" / "ca.pem").read_text(encoding="utf-8")
    tok = report.cli_credential_path.read_text(encoding="ascii").strip()
    return req, report, priv, cfg, ca, tok, os_


@contextmanager
def _running_daemon(
    cfg: DaemonConfig, *, os_: OsAdapters, clock: FakeClock, mono: FakeMonotonicClock, shutdown_grace_s: float = 1.0
) -> Iterator[tuple[Ready, OwnerLoop, threading.Event, threading.Thread]]:
    ready_evt, stop_evt, box, exits = threading.Event(), threading.Event(), dict[str, Any](), list[int]()

    def _on_ready(rdy: Ready, lp: OwnerLoop) -> None:
        box.update(ready=rdy, loop=lp)
        ready_evt.set()

    def _run() -> None:
        exits.append(
            daemon_entry.serve(
                cfg, os_=os_, clock=clock, monotonic_clock=mono,
                stop_event=stop_evt, shutdown_grace_s=shutdown_grace_s, on_ready=_on_ready,
            )
        )

    thread = threading.Thread(target=_run, name="test-r2-daemon", daemon=True)
    thread.start()
    try:
        assert ready_evt.wait(timeout=5.0), f"daemon did not become ready (exited={exits})"
        yield cast(Ready, box["ready"]), cast(OwnerLoop, box["loop"]), stop_evt, thread
    finally:
        stop_evt.set()
        thread.join(timeout=5.0)
        assert not thread.is_alive()


def _post_loopback(
    ready: Ready, ca_pem: str, path: str, token: str, payload: object, *, read_timeout: float = 2.0
) -> bytes:
    host = f"{ready.endpoint.host}:{ready.endpoint.port}"
    body = json.dumps(payload).encode("utf-8")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cadata=ca_pem)
    ctx.check_hostname = True
    with socket.create_connection((ready.endpoint.host, ready.endpoint.port), timeout=2.0) as raw:
        with ctx.wrap_socket(raw, server_hostname="127.0.0.1") as sock:
            sock.settimeout(read_timeout)
            sock.sendall(f"GET /v2/identity HTTP/1.1\r\nHost: {host}\r\n\r\n".encode("ascii"))
            ident = read_raw_http_response(sock, timeout=read_timeout)
            if not ident.startswith(b"HTTP/1.1 200 "):
                return ident
            req = (
                f"POST {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {token}\r\n"
                f"X-Store-Id: {ready.identity.store_id}\r\nX-Writer-Epoch: {ready.identity.writer_epoch}\r\n"
                f"X-Superbrain-Instance: {ready.identity.instance_id}\r\n"
                f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n"
            ).encode("iso-8859-1") + body
            sock.sendall(req)
            return read_raw_http_response(sock, timeout=read_timeout)


def _envelope(raw_resp: bytes) -> dict[str, Any]:
    head, sep, payload = raw_resp.partition(b"\r\n\r\n")
    assert sep and head.startswith(b"HTTP/1.1 "), raw_resp[:200]
    parsed = json.loads(payload)
    assert isinstance(parsed, dict)
    return parsed


def _error_code(env: dict[str, Any]) -> str | None:
    if env.get("ok") is True:
        return None
    err = env.get("error")
    assert isinstance(err, dict)
    return str(err.get("code"))


def _count_nonces(data_root: Path) -> int:
    db_path = DataRoot.at(data_root).policy_db
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        row = conn.execute("SELECT COUNT(*) FROM approval_nonce").fetchone()
    finally:
        conn.close()
    assert row is not None
    return int(row[0])


# --- I3-1-R02(a): slow SSH verify must not block OwnerLoop ----------------------------------------------------------


def test_slow_ssh_verify_does_not_block_owner_loop(trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    clock = FakeClock(datetime.now(UTC).replace(microsecond=0))
    mono = FakeMonotonicClock(1_000_000_000)
    req, report, priv_s1, cfg, ca_pem, cli_token, os_ = _init_fixture(trusted_tmp, clock, mono)

    rt = reopen_kernel_job_runtime(req.data_root, report.store_id, os_)
    try:
        harness = seed_principal_and_credential(rt.policy, owner_id=OWNER, harness_id="claude-code", machine_id=MACHINE)
    finally:
        rt.close()

    _priv_s2, _enr_s2, s2_line = _ssh_enrollment(OWNER)
    enroll_payload = _enroll_body(s2_line)

    verify_entered, verify_release = threading.Event(), threading.Event()
    verify_threads: list[str] = []

    def _blocked_verify(*_args: Any, **_kwargs: Any) -> AssuranceLevel:
        verify_threads.append(threading.current_thread().name)
        verify_entered.set()
        assert verify_release.wait(timeout=3.0)
        return AssuranceLevel.KEY_AUTHORIZATION

    with _running_daemon(cfg, os_=os_, clock=clock, mono=mono) as (ready, _loop, _stop, _thr):
        ch_env = _envelope(_post_loopback(ready, ca_pem, ENROLL, cli_token, enroll_payload))
        assert ch_env["ok"] is True
        msg = _msg_from_challenge(ch_env["data"]["challenge"])
        approval = {
            "message": msg.to_dict(), "channel": ApprovalChannel.SSH_KEY.value,
            "signer_id": report.signer.signer_id, "signature": _ssh_sign(priv_s1, msg.canonical_bytes()),
        }
        signed_payload = {**enroll_payload, "approval": approval}
        monkeypatch.setattr(SshSigVerifier, "verify", _blocked_verify)
        op_out: list[bytes] = []
        client_thr = _run_bg(
            lambda: _post_loopback(ready, ca_pem, ENROLL, cli_token, signed_payload, read_timeout=4.0), op_out
        )
        try:
            assert verify_entered.wait(timeout=2.0)
            # While ssh-keygen is parked, OwnerLoop must still service deep health calls without timing out.
            health_probe = {
                "schema_digest": load_catalog().schema_digest,
                "tool": "get_health", "correlation_id": None, "selected_scope": None,
                "arguments": {"schema_version": "2.0", "deep": True, "idempotency_key": "idem-deep-health-0001"},
            }
            health_raw = _post_loopback(ready, ca_pem, "/v2/tools/call", harness.token, health_probe, read_timeout=0.7)
            assert b"\r\n\r\n" in health_raw, "OwnerLoop was blocked while ssh-keygen verification waited"
            assert health_raw.startswith(b"HTTP/1.1 200 ")
            health_env = _envelope(health_raw)
            # Production deep health is now supported and returns a live doctor_run_id or queued job_id.
            assert health_env["ok"] is True
            health_data = cast(dict[str, Any], health_env["data"])
            assert health_data["ready"] is True
            assert (health_data.get("doctor_run_id") is not None) or (health_data.get("job_id") is not None)
            assert verify_threads and verify_threads[0] != "superbrain-owner-loop"
        finally:
            verify_release.set()
            client_thr.join(timeout=3.0)
        assert not client_thr.is_alive() and len(op_out) == 1
        assert _envelope(op_out[0])["ok"] is True


# --- I3-1-R02(b): expired and queued-past-deadline requests refuse without policy mutation -----------------------


def test_expired_and_queued_past_deadline_operator_requests_do_not_mutate_policy(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from superbrain.core.kernel import OPERATOR_REQUEST_BUDGET_NS

    assert OPERATOR_REQUEST_BUDGET_NS == 15_000_000_000 and TOTAL_REQUEST_BUDGET_NS == 1_500_000_000
    clock = FakeClock(datetime.now(UTC).replace(microsecond=0))
    mono = FakeMonotonicClock(1_000_000_000)
    req, rep, _priv, cfg, ca_pem, cli_token, os_ = _init_fixture(trusted_tmp, clock, mono)
    rt = reopen_kernel_job_runtime(req.data_root, rep.store_id, os_)
    try:
        harness = seed_principal_and_credential(rt.policy, owner_id=OWNER, harness_id="claude-code", machine_id=MACHINE)
    finally:
        rt.close()
    _priv2, _enr2, s2_line = _ssh_enrollment(OWNER)
    body = _enroll_body(s2_line)

    # 1. Direct executor check: deadline already expired returns DEADLINE_EXCEEDED without mutating policy.
    op_handle = OperatorHandle()
    loop_direct = create_daemon_owner_loop(os_=os_, clock=clock, monotonic_clock=mono, operator=op_handle)
    loop_direct.start(cfg)
    try:
        execute = make_operator_executor(loop_direct, op_handle, mono.monotonic_ns)
        cli_p = Principal(principal_id="p-cli", owner_id=OWNER, harness_id=CLI_HARNESS_ID, machine_id=MACHINE)
        res = execute(
            OperatorRequest(path="/v2/operator/signer/enroll", principal=cli_p, body=cast(dict[str, Any], body)),
            mono.monotonic_ns() - 1,
        )
        assert res["ok"] is False and cast(dict[str, Any], res["error"])["code"] == ErrorCode.DEADLINE_EXCEEDED.value
    finally:
        loop_direct.stop(grace_s=1.0)
    assert _count_nonces(req.data_root) == 0

    # 2. Operator uses 15s budget (2.0s passes) while /v2/tools/call keeps 1.5s; >15s refuses with 0 nonces.
    advance_on_parse_ns = [0]

    def _spy_parse(raw: bytes) -> dict[str, Any]:
        parsed = parse_operator_body(raw)
        if advance_on_parse_ns[0]:
            mono.advance(advance_on_parse_ns[0])
        return parsed

    monkeypatch.setattr(_server_http, "parse_operator_body", _spy_parse)
    with _running_daemon(cfg, os_=os_, clock=clock, mono=mono) as (ready, loop, _stop, _thr):
        advance_on_parse_ns[0] = TOTAL_REQUEST_BUDGET_NS + 500_000_000  # 2.0s < 15.0s
        op_2s = _post_loopback(ready, ca_pem, "/v2/operator/signer/list", cli_token, {}, read_timeout=2.0)
        assert _envelope(op_2s)["ok"] is True

        # Confirm /v2/tools/call keeps strict 1.5s budget when delayed by 2.0s behind OwnerLoop.
        tool_queued, orig_submit, tool_dl = threading.Event(), loop.submit_reply, list[tuple[int, int]]()

        def _spy_submit(cmd: Any, dl: int) -> Any:
            tool_dl.append((mono.monotonic_ns(), dl))
            tool_queued.set()
            return orig_submit(cmd, dl)

        monkeypatch.setattr(loop, "submit_reply", _spy_submit)
        health_arg = {
            "schema_digest": load_catalog().schema_digest,
            "tool": "get_health", "correlation_id": None, "selected_scope": None,
            "arguments": {"schema_version": "2.0", "deep": True, "idempotency_key": "idem-deep-health-0002"},
        }
        tool_out = _post_behind_blocked_owner(
            loop, lambda: tool_queued,
            lambda: _post_loopback(ready, ca_pem, "/v2/tools/call", harness.token, health_arg),
            lambda: mono.advance(TOTAL_REQUEST_BUDGET_NS + 500_000_000),
        )
        assert len(tool_dl) == 1 and 0 < (tool_dl[0][1] - tool_dl[0][0]) <= TOTAL_REQUEST_BUDGET_NS
        assert tool_out and (
            not tool_out[0] or _error_code(_envelope(tool_out[0])) == ErrorCode.DEADLINE_EXCEEDED.value
        )
        monkeypatch.setattr(loop, "submit_reply", orig_submit)

        advance_on_parse_ns[0] = OPERATOR_REQUEST_BUDGET_NS + 1_000_000
        pre_exp = _post_loopback(ready, ca_pem, "/v2/operator/signer/enroll", cli_token, body, read_timeout=2.0)
        advance_on_parse_ns[0] = 0
        if pre_exp:
            assert _error_code(_envelope(pre_exp)) == ErrorCode.DEADLINE_EXCEEDED.value

        queued_out = _post_behind_blocked_owner(
            loop,
            lambda: _arm_run_owner_spy(loop, monkeypatch),
            lambda: _post_loopback(ready, ca_pem, ENROLL, cli_token, body),
            lambda: mono.advance(OPERATOR_REQUEST_BUDGET_NS + 1_000_000),
        )
        if queued_out and queued_out[0]:
            assert _error_code(_envelope(queued_out[0])) == ErrorCode.DEADLINE_EXCEEDED.value

    assert _count_nonces(req.data_root) == 0


# --- I3-1-R02(c): TLS expiry and quiesce / stop_deadline enforcement ------------------------------------------------


def test_quiesce_stop_deadline_and_tls_expiry_reject_operator_calls(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = FakeClock(datetime.now(UTC).replace(microsecond=0))
    mono = FakeMonotonicClock(1_000_000_000)
    req, _rep, _priv, cfg, ca_pem, cli_token, os_ = _init_fixture(trusted_tmp, clock, mono)
    _priv2, _enr2, s2_line = _ssh_enrollment(OWNER)
    enroll_body = _enroll_body(s2_line)

    # 1. TLS expiry (loop.ready becomes None) refuses /v2/operator/* with DAEMON_UNAVAILABLE.
    with _running_daemon(cfg, os_=os_, clock=clock, mono=mono) as (ready, loop, _stop, _thr):
        assert _envelope(_post_loopback(ready, ca_pem, "/v2/operator/signer/list", cli_token, {}))["ok"] is True
        clock.set(ready.tls_not_after)
        assert loop.ready is None
        for ep, pl in (("/v2/operator/signer/list", {}), (ENROLL, enroll_body)):
            env = _envelope(_post_loopback(ready, ca_pem, ep, cli_token, pl))
            assert _error_code(env) == ErrorCode.DAEMON_UNAVAILABLE.value
    assert _count_nonces(req.data_root) == 0

    # 2. Quiesce triggered while operator body is parsed must stop dispatch before issuing nonces.
    clock.set(datetime.now(UTC).replace(microsecond=0))
    stop_box: list[threading.Event] = []

    def _quiesce_after_parse(raw: bytes) -> dict[str, Any]:
        parsed = parse_operator_body(raw)
        if stop_box:
            stop_box[0].set()
        return parsed

    monkeypatch.setattr(_server_http, "parse_operator_body", _quiesce_after_parse)
    with _running_daemon(cfg, os_=os_, clock=clock, mono=mono) as (ready, _loop, stop_evt, _thr):
        stop_box.append(stop_evt)
        q_raw = _post_loopback(ready, ca_pem, "/v2/operator/signer/enroll", cli_token, enroll_body, read_timeout=2.0)
        if q_raw:
            assert _error_code(_envelope(q_raw)) == ErrorCode.DAEMON_UNAVAILABLE.value
    assert _count_nonces(req.data_root) == 0

    # 3. Direct LoopbackServer.finish(stop_deadline) remains bounded even when operator executor blocks.
    bound_list: list[BoundLoopbackListener] = []
    loop = create_daemon_owner_loop(os_=os_, clock=clock, monotonic_clock=mono, on_listener_bound=bound_list.append)
    ready2 = loop.start(cfg)
    op_entered, op_release = threading.Event(), threading.Event()

    def _blocking_op(_req: OperatorRequest, _dl: int) -> Any:
        op_entered.set()
        op_release.wait(timeout=4.0)
        return make_error_envelope(BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable"))

    srv = LoopbackServer(
        listener=bound_list[0].sock,
        ssl_context=bound_list[0].ssl_context,
        ready=ready2,
        owner=loop,
        monotonic_ns=mono.monotonic_ns,
        stop_event=threading.Event(),
        operator=_blocking_op,
    )
    srv.start()
    client_thr = _run_bg(
        lambda: _post_loopback(ready2, ca_pem, "/v2/operator/signer/list", cli_token, {}, read_timeout=4.0)
    )
    try:
        assert op_entered.wait(timeout=2.0)
        t0 = time.perf_counter()
        assert srv.finish(t0 + 0.08) is False and (time.perf_counter() - t0) < 0.5
    finally:
        op_release.set()
        client_thr.join(timeout=2.0)
        loop.stop(grace_s=1.0)


# --- I3-1-R02(d): OperatorHandle.unbind() on teardown & startup failure rollback -----------------------------------


def test_operator_handle_unbound_on_owner_teardown_and_startup_failure(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = FakeClock(datetime.now(UTC).replace(microsecond=0))
    mono = FakeMonotonicClock(1_000_000_000)
    _req, _rep, _priv, cfg, _ca, _tok, os_ = _init_fixture(trusted_tmp, clock, mono)

    # Normal teardown unbinds handle.
    handle = OperatorHandle()
    loop = create_daemon_owner_loop(os_=os_, clock=clock, monotonic_clock=mono, operator=handle)
    loop.start(cfg)
    assert handle.service() is not None
    rep = loop.stop(grace_s=2.0)
    assert rep.state is ShutdownState.STOPPED and handle.service() is None

    # Startup failure after bind() rolls back handle to None.
    handle_fail = OperatorHandle()
    orig_bind = OperatorHandle.bind

    def _fail_right_after_bind(self: OperatorHandle, service: Any) -> None:
        orig_bind(self, service)
        raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "simulated post-bind failure")

    monkeypatch.setattr(OperatorHandle, "bind", _fail_right_after_bind)
    loop_fail = create_daemon_owner_loop(os_=os_, clock=clock, monotonic_clock=mono, operator=handle_fail)
    with pytest.raises(BrainError):
        loop_fail.start(cfg)
    assert handle_fail.service() is None


# --- I3-1-R02(e): live user:cli credential re-check on owner thread -------------------------------------------------


def test_revoked_user_cli_credential_rechecked_live_on_owner_thread(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = FakeClock(datetime.now(UTC).replace(microsecond=0))
    mono = FakeMonotonicClock(1_000_000_000)
    req, _rep, _priv, cfg, ca_pem, cli_token, os_ = _init_fixture(trusted_tmp, clock, mono)
    _priv2, _enr2, s2_line = _ssh_enrollment(OWNER)
    enroll_body, cli_cred_id = _enroll_body(s2_line), cli_token.split(".", 1)[0]

    with _running_daemon(cfg, os_=os_, clock=clock, mono=mono) as (ready, loop, _stop, _thr):
        _ent, blk_release, blk_fut = _hold_owner(loop)
        rev_auth = make_bootstrap_auth(
            store_id=ready.identity.store_id, owner_id=OWNER,
            action="credential_revoke", subject_id=cli_cred_id, expires_at=clock.now() + timedelta(hours=1),
        )
        rev_fut = loop.revoke_credential(cli_cred_id, rev_auth)
        op_queued = _arm_run_owner_spy(loop, monkeypatch)
        out: list[bytes] = []
        client_thr = _run_bg(lambda: _post_loopback(ready, ca_pem, ENROLL, cli_token, enroll_body), out)
        try:
            assert op_queued.wait(timeout=2.0)
        finally:
            blk_release.set()
        blk_fut.result(timeout=2.0)
        rev_fut.result(timeout=2.0)
        client_thr.join(timeout=2.0)
        assert len(out) == 1 and _error_code(_envelope(out[0])) == ErrorCode.UNAUTHENTICATED.value
    assert _count_nonces(req.data_root) == 0


def test_reset_signers_owner_mismatch_and_init_store_preflight_do_not_mutate_fs(trusted_tmp: Path) -> None:
    clock = FakeClock(datetime.now(UTC).replace(microsecond=0))
    mono = FakeMonotonicClock(1_000_000_000)
    req, rep, _priv, _cfg, _ca, _tok, os_ = _init_fixture(trusted_tmp, clock, mono, owner_id=OWNER)
    rt = reopen_kernel_job_runtime(req.data_root, rep.store_id, os_)
    try:
        rt.policy.issue_nonce(action=ApprovalAction.APPROVE, subject_id="proposal-keep", risk_level=RiskLevel.HIGH)
    finally:
        rt.close()
    before_bytes = digest_tree(req.data_root)
    _bad_priv, wrong_owner_signer, _line = _ssh_enrollment(owner_id="mallory")
    with pytest.raises(BrainError) as mismatch_exc:
        reset_signers(rep.daemon_config_path, wrong_owner_signer, os_)
    assert mismatch_exc.value.code is ErrorCode.IDENTITY_MISMATCH and digest_tree(req.data_root) == before_bytes
    rt2 = reopen_kernel_job_runtime(req.data_root, rep.store_id, os_)
    try:
        assert [s.signer_id for s in rt2.policy.active_signers()] == [rep.signer.signer_id]
        assert rt2.policy.trust_generation() == 1 and rt2.policy.signer_reset_recorded() is False
    finally:
        rt2.close()
    existing_data, cfg_a, cfg_b = (
        trusted_tmp / "existing-data", trusted_tmp / "nonexistent-cfg-a", trusted_tmp / "nonexistent-cfg-b"
    )
    existing_data.mkdir()
    os_.permissions.secure_directory(existing_data)
    (existing_data / "writer.lock").write_bytes(b"")
    _p1, enr_a, _l1 = _ssh_enrollment(OWNER)
    with pytest.raises(BrainError) as exists_exc:
        init_store(InitRequest(existing_data, cfg_a, OWNER, MACHINE, enr_a), os_)
    assert exists_exc.value.code is ErrorCode.INVALID_INPUT and not cfg_a.exists()
    target_data, sym_data = trusted_tmp / "symlink-target", trusted_tmp / "symlink-data"
    target_data.mkdir()
    if sys.platform == "win32":
        import _winapi

        _winapi.CreateJunction(str(target_data), str(sym_data))
    else:
        sym_data.symlink_to(target_data, target_is_directory=True)
    with pytest.raises(BrainError):
        init_store(InitRequest(sym_data, cfg_b, OWNER, MACHINE, enr_a), os_)
    assert not cfg_b.exists()
