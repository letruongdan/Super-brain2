"""Round-2 regressions for SP2-5 AuthGate/Capture-Producer coexistence (F1, F2, F4, F5, F6)."""

from __future__ import annotations

import base64
import hashlib
import json
import socket
import ssl
import struct
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.daemon_config import read_daemon_config
from superbrain.application._auth_gate import AuthGate
from superbrain.application._prequeue import AtomicRequestAuthState
from superbrain.application.owner_loop import OwnerLoop
from superbrain.cli_api.capture_client import CaptureClient
from superbrain.cli_api.loopback import LoopbackClient, LoopbackTarget
from superbrain.composition import daemon_entry, init_entry
from superbrain.composition._daemon_session import build_default_handoff_domain
from superbrain.composition.kernel_bridge import KernelBridge
from superbrain.core._kernel_approval import (
    APPROVAL_NAMESPACE,
    RISK_POLICY_VERSION,
    ApprovalAction,
    ApprovalChannel,
    ApprovalMessage,
    RecoveryScope,
    RiskLevel,
    SignerEnrollment,
)
from superbrain.core._kernel_auth import _DEFAULT_MCP_CAPABILITIES
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    CAPABILITY_CAPTURE_PRODUCER,
    CAPABILITY_OPERATOR_CLI,
    HANDLER_RESERVE_NS,
    AuthGrantStamp,
    Call,
    CallContext,
    CaptureBatchCommand,
    CaptureProducerBinding,
    DaemonConfig,
    Identity,
    Principal,
    PrivateRequestAuth,
    Ready,
    RequestAuthView,
    RequestDeadlines,
    ResourceDigest,
    Scope,
    ShallowHealthMeta,
    StoredResult,
    ToolCommand,
)
from superbrain.core.wire import SCHEMA_VERSION, normalize_call
from superbrain.ports.capture import CaptureEventRecord
from superbrain.ports.os import OsAdapters
from superbrain.storage.backup import create_policy_backup
from superbrain.storage.runtime import Runtime
from tests.support.clock import FakeClock
from tests.support.inc2_fixture import open_kernel_job_runtime, reopen_kernel_job_runtime
from tests.support.inc2_transport import FakeMonotonicClock, read_raw_http_response, register_workspace_direct
from tests.support.kernel_auth import (
    SeededCredential,
    generate_bearer_token,
    make_bootstrap_auth,
    seed_principal_and_credential,
    seed_repo_grant,
)

_OWNER = "dan"
_MACHINE = "m-r2"


def _make_bridge_env(
    trusted_tmp: Path,
    *,
    name: str,
) -> tuple[FakeClock, FakeMonotonicClock, OsAdapters, Runtime, KernelBridge, AuthGate]:
    clock = FakeClock(datetime(2026, 11, 26, 13, 0, tzinfo=UTC))
    mono = FakeMonotonicClock(10_000_000_000)
    os_ = os_adapters(clock=clock, monotonic=mono)
    rt = open_kernel_job_runtime(trusted_tmp / name / "data", os_, role=f"r2-{name}")
    gate = AuthGate(rt.store.store_id, rt.lease.epoch, f"inst-{name}")
    domain = build_default_handoff_domain(rt=rt, clock=clock, writer_epoch=rt.lease.epoch)
    assert domain is not None
    bridge = KernelBridge(
        store=rt.store,
        policy=rt.policy,
        clock=clock,
        monotonic_clock=mono,
        writer_epoch=rt.lease.epoch,
        instance_id=f"inst-{name}",
        domain=domain,
        auth_state=gate,
    )
    return clock, mono, os_, rt, bridge, gate


def _publish_mixed_view(
    rt: Runtime,
    gate: AuthGate,
    *,
    cap_updates: dict[str, tuple[frozenset[str], CaptureProducerBinding | None]],
) -> RequestAuthView:
    snap = rt.policy.snapshot()
    merged = dict(snap.credentials)
    for cid, (caps, binding) in cap_updates.items():
        merged[cid] = replace(merged[cid], capabilities=caps, capture_binding=binding)
    key_id, key_bytes = rt.policy.request_digest_key()
    view = RequestAuthView(
        version=gate.next_version(),
        auth=replace(snap, credentials=merged),
        active_request_key_id=key_id,
        active_request_key_bytes=key_bytes,
    )
    return gate.publish_view(view)


def _health_ctx(
    rt: Runtime,
    principal: Principal,
    mono: FakeMonotonicClock,
    *,
    instance_id: str,
    deadlines: RequestDeadlines | None = None,
) -> CallContext:
    dl = deadlines if deadlines is not None else RequestDeadlines.from_receive_ns(mono.monotonic_ns())
    return CallContext(
        principal=principal,
        identity=Identity(store_id=rt.store.store_id, writer_epoch=rt.lease.epoch, instance_id=instance_id),
        deadline_ns=dl.total_deadline_ns,
        local_deadline_ns=dl.handler_deadline_ns,
        selected_scope=None,
    )


def _health_call(principal: Principal) -> Call:
    return normalize_call(
        "get_health", {"schema_version": SCHEMA_VERSION, "deep": False}, principal, selected_scope=None
    )


def _auth_for(cred: SeededCredential, *, token_override: str | None = None) -> PrivateRequestAuth:
    return PrivateRequestAuth(
        credential_id=cred.credential_id,
        principal=cred.principal,
        token=token_override if token_override is not None else cred.token,
    )


def _ssh_signer() -> tuple[Ed25519PrivateKey, SignerEnrollment]:
    priv = Ed25519PrivateKey.generate()
    raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", len(raw)) + raw
    return priv, SignerEnrollment(
        owner_id=_OWNER,
        channel=ApprovalChannel.SSH_KEY,
        public_key="ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + " r2@devbox",
    )


def _ssh_sig_b64(priv: Ed25519PrivateKey, payload: bytes) -> str:
    raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", len(raw)) + raw

    def _s(data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + data

    ns = APPROVAL_NAMESPACE.encode()
    signed = b"SSHSIG" + _s(ns) + _s(b"") + _s(b"sha512") + _s(hashlib.sha512(payload).digest())
    sig = _s(b"ssh-ed25519") + _s(priv.sign(signed))
    body = b"SSHSIG" + struct.pack(">I", 1) + _s(blob) + _s(ns) + _s(b"") + _s(b"sha512") + _s(sig)
    armored = base64.b64encode(body).decode("ascii")
    pem = (
        "-----BEGIN SSH SIGNATURE-----\n"
        + "\n".join(armored[i : i + 70] for i in range(0, len(armored), 70))
        + "\n-----END SSH SIGNATURE-----\n"
    ).encode("ascii")
    return base64.b64encode(pem).decode("ascii")


@contextmanager
def _serve_daemon(
    cfg: DaemonConfig,
    os_: OsAdapters,
    clock: FakeClock,
    mono: FakeMonotonicClock,
) -> Iterator[tuple[Ready, OwnerLoop]]:
    ready_evt = threading.Event()
    stop_evt = threading.Event()
    box: dict[str, Any] = {}
    exits: list[int] = []

    def _on_ready(ready: Ready, loop: OwnerLoop) -> None:
        box["ready"] = ready
        box["loop"] = loop
        ready_evt.set()

    def _bg() -> None:
        exits.append(
            daemon_entry.serve(
                cfg,
                os_=os_,
                clock=clock,
                monotonic_clock=mono,
                stop_event=stop_evt,
                shutdown_grace_s=1.0,
                on_ready=_on_ready,
            )
        )

    thr = threading.Thread(target=_bg, name="sp25-r2-restore-daemon", daemon=True)
    thr.start()
    try:
        assert ready_evt.wait(timeout=5.0), f"daemon not ready (exits={exits})"
        yield cast(Ready, box["ready"]), cast(OwnerLoop, box["loop"])
    finally:
        stop_evt.set()
        thr.join(timeout=5.0)
        assert not thr.is_alive()


def _post_tls(ready: Ready, ca_pem: str, path: str, token: str, body_obj: object) -> tuple[int, dict[str, Any]]:
    host = f"{ready.endpoint.host}:{ready.endpoint.port}"
    body = json.dumps(body_obj).encode("utf-8")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cadata=ca_pem)
    ctx.check_hostname = True
    with (
        socket.create_connection((ready.endpoint.host, ready.endpoint.port), timeout=2.0) as raw,
        ctx.wrap_socket(raw, server_hostname="127.0.0.1") as sock,
    ):
        sock.settimeout(3.0)
        sock.sendall(f"GET /v2/identity HTTP/1.1\r\nHost: {host}\r\n\r\n".encode("ascii"))
        assert read_raw_http_response(sock, timeout=3.0).startswith(b"HTTP/1.1 200 ")
        hdr = (
            f"POST {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {token}\r\n"
            f"X-Store-Id: {ready.identity.store_id}\r\nX-Writer-Epoch: {ready.identity.writer_epoch}\r\n"
            f"X-Superbrain-Instance: {ready.identity.instance_id}\r\n"
            f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n"
        ).encode("iso-8859-1")
        sock.sendall(hdr + body)
        resp = read_raw_http_response(sock, timeout=5.0)
    head, sep, data = resp.partition(b"\r\n\r\n")
    assert sep and head.startswith(b"HTTP/1.1 "), resp[:200]
    status = int(head.splitlines()[0].split()[1])
    return status, cast(dict[str, Any], json.loads(data))


# ---------------------------------------------------------------------------
# F1a: Fail-open on cleared auth view
# ---------------------------------------------------------------------------


def test_f1a_cleared_auth_view_still_rejects_non_mcp_and_allows_mcp(trusted_tmp: Path) -> None:
    """Clearing AuthGate/bridge view must never let capture_producer or operator_cli dispatch MCP calls."""
    clock, mono, _os, rt, bridge, gate = _make_bridge_env(trusted_tmp, name="f1a")
    try:
        mcp_c = seed_principal_and_credential(rt.policy, owner_id=_OWNER, harness_id="claude-code", machine_id=_MACHINE)
        cap_c = seed_principal_and_credential(rt.policy, owner_id=_OWNER, harness_id="claude-code", machine_id=_MACHINE)
        op_c = seed_principal_and_credential(rt.policy, owner_id=_OWNER, harness_id="operator-cli", machine_id=_MACHINE)
        ws_a = register_workspace_direct(
            rt, clock, mcp_c.principal, alias="ws-f1a", checkout_dir=trusted_tmp / "chk-f1a"
        )
        seed_repo_grant(rt.policy, principal_id=op_c.principal.principal_id, repo_id=ws_a.repo_id, owner_id=_OWNER)
        rt.store.reconcile_policy()

        _publish_mixed_view(
            rt,
            gate,
            cap_updates={
                cap_c.credential_id: (
                    frozenset({CAPABILITY_CAPTURE_PRODUCER}),
                    CaptureProducerBinding("stream-f1a", ws_a.repo_id, ws_a.checkout_id),
                ),
                op_c.credential_id: (frozenset({CAPABILITY_OPERATOR_CLI}), None),
            },
        )

        # Exercise both bridge.clear_auth_view() and gate.invalidate().
        for clear_fn in (bridge.clear_auth_view, gate.invalidate):
            clear_fn()
            assert gate.current() is None

            # Positive twin: mcp_c succeeds on both dispatch and _run_reserved_on_owner even when view is cleared.
            ok_disp = bridge.dispatch(
                _health_call(mcp_c.principal),
                _health_ctx(rt, mcp_c.principal, mono, instance_id="inst-f1a"),
                auth=_auth_for(mcp_c),
            )
            assert ok_disp.get("ok") is True, ok_disp

            dl_mcp = RequestDeadlines.from_receive_ns(mono.monotonic_ns())
            res_mcp = bridge.reservations.create_unscoped_ticket(deadlines=dl_mcp)
            ok_res = bridge._run_reserved_on_owner(
                _health_call(mcp_c.principal),
                _health_ctx(rt, mcp_c.principal, mono, instance_id="inst-f1a", deadlines=dl_mcp),
                _auth_for(mcp_c),
                res_mcp,
            )
            assert ok_res.get("ok") is True, ok_res

            # Negative twins: cap_c and op_c fail with IDENTITY_MISMATCH on dispatch & _run_reserved_on_owner.
            for bad_cred in (cap_c, op_c):
                res_disp = bridge.dispatch(
                    _health_call(bad_cred.principal),
                    _health_ctx(rt, bad_cred.principal, mono, instance_id="inst-f1a"),
                    auth=_auth_for(bad_cred),
                )
                assert res_disp["ok"] is False, (bad_cred.principal.harness_id, res_disp)
                assert cast(dict[str, Any], res_disp["error"])["code"] == ErrorCode.IDENTITY_MISMATCH.value

                dl_bad = RequestDeadlines.from_receive_ns(mono.monotonic_ns())
                ticket = bridge.reservations.create_unscoped_ticket(deadlines=dl_bad)
                res_owner = bridge._run_reserved_on_owner(
                    _health_call(bad_cred.principal),
                    _health_ctx(rt, bad_cred.principal, mono, instance_id="inst-f1a", deadlines=dl_bad),
                    _auth_for(bad_cred),
                    ticket,
                )
                assert res_owner["ok"] is False, (bad_cred.principal.harness_id, res_owner)
                assert cast(dict[str, Any], res_owner["error"])["code"] == ErrorCode.IDENTITY_MISMATCH.value

            # Re-publish view before testing the second clear path.
            bridge.publish_auth_view()
    finally:
        rt.close()


# ---------------------------------------------------------------------------
# F1b: Auth precedence & live revocation divergence
# ---------------------------------------------------------------------------


def test_f1b_auth_precedence_and_live_revocation_divergence(trusted_tmp: Path) -> None:
    """Bad secret yields UNAUTHENTICATED preserving view; direct SQLite revocation clears diverged view."""
    clock, mono, _os, rt, bridge, gate = _make_bridge_env(trusted_tmp, name="f1b")
    try:
        mcp_c = seed_principal_and_credential(rt.policy, owner_id=_OWNER, harness_id="claude-code", machine_id=_MACHINE)
        cap_c = seed_principal_and_credential(rt.policy, owner_id=_OWNER, harness_id="claude-code", machine_id=_MACHINE)
        cap_c2 = seed_principal_and_credential(
            rt.policy, owner_id=_OWNER, harness_id="claude-code", machine_id=_MACHINE
        )
        ws_a = register_workspace_direct(
            rt, clock, mcp_c.principal, alias="ws-f1b", checkout_dir=trusted_tmp / "chk-f1b"
        )
        rt.store.reconcile_policy()

        _publish_mixed_view(
            rt,
            gate,
            cap_updates={
                cap_c.credential_id: (
                    frozenset({CAPABILITY_CAPTURE_PRODUCER}),
                    CaptureProducerBinding("stream-f1b-1", ws_a.repo_id, ws_a.checkout_id),
                ),
                cap_c2.credential_id: (
                    frozenset({CAPABILITY_CAPTURE_PRODUCER}),
                    CaptureProducerBinding("stream-f1b-2", ws_a.repo_id, ws_a.checkout_id),
                ),
            },
        )

        # Positive twin before divergence: mcp_c works and valid cap_c gets IDENTITY_MISMATCH.
        assert (
            bridge.dispatch(
                _health_call(mcp_c.principal),
                _health_ctx(rt, mcp_c.principal, mono, instance_id="inst-f1b"),
                auth=_auth_for(mcp_c),
            ).get("ok")
            is True
        )
        valid_cap_err = bridge.dispatch(
            _health_call(cap_c.principal),
            _health_ctx(rt, cap_c.principal, mono, instance_id="inst-f1b"),
            auth=_auth_for(cap_c),
        )
        assert valid_cap_err["ok"] is False
        assert cast(dict[str, Any], valid_cap_err["error"])["code"] == ErrorCode.IDENTITY_MISMATCH.value

        # 1. Auth precedence: cap_c.credential_id with a bogus secret -> UNAUTHENTICATED (NOT IDENTITY_MISMATCH),
        #    and healthy published auth_state.current() MUST remain non-None!
        _, bogus_token, _, _ = generate_bearer_token(credential_id=cap_c.credential_id)
        bogus_res = bridge.dispatch(
            _health_call(cap_c.principal),
            _health_ctx(rt, cap_c.principal, mono, instance_id="inst-f1b"),
            auth=_auth_for(cap_c, token_override=bogus_token),
        )
        assert bogus_res["ok"] is False
        assert cast(dict[str, Any], bogus_res["error"])["code"] == ErrorCode.UNAUTHENTICATED.value
        assert gate.current() is not None

        # 2. Revoke cap_c directly in SQLite (bypassing bridge.revoke_credential) -> dispatch returns UNAUTHENTICATED
        #    and clears the diverged auth_state.current() to None.
        proof_1 = make_bootstrap_auth(
            store_id=rt.policy.store_id,
            owner_id=_OWNER,
            action="credential_revoke",
            subject_id=cap_c.credential_id,
            trust_generation=rt.policy.trust_generation(),
            expires_at=clock.now() + timedelta(hours=1),
        )
        rt.policy.record_authorized_revocation(cap_c.credential_id, proof_1)
        assert gate.current() is not None

        rev_disp = bridge.dispatch(
            _health_call(cap_c.principal),
            _health_ctx(rt, cap_c.principal, mono, instance_id="inst-f1b"),
            auth=_auth_for(cap_c),
        )
        assert rev_disp["ok"] is False
        assert cast(dict[str, Any], rev_disp["error"])["code"] == ErrorCode.UNAUTHENTICATED.value
        assert gate.current() is None

        # 3. Re-publish view (still holding cap_c2 unrevoked in RAM), then revoke cap_c2 directly in SQLite
        #    and invoke ingest_capture_batch -> raises UNAUTHENTICATED and clears diverged auth_state.current()!
        bridge.publish_auth_view()
        assert gate.current() is not None
        proof_2 = make_bootstrap_auth(
            store_id=rt.policy.store_id,
            owner_id=_OWNER,
            action="credential_revoke",
            subject_id=cap_c2.credential_id,
            trust_generation=rt.policy.trust_generation(),
            expires_at=clock.now() + timedelta(hours=1),
        )
        rt.policy.record_authorized_revocation(cap_c2.credential_id, proof_2)

        ev = CaptureEventRecord(
            event_id="ev-f1b-revoked",
            producer_stream="stream-f1b-2",
            sequence=1,
            harness_id="claude-code",
            kind="tool_post",
            recorded_at="2026-11-26T13:01:00Z",
            payload={"k": "v"},
        ).to_dict()
        with pytest.raises(BrainError) as exc_ing:
            bridge.ingest_capture_batch(
                CaptureBatchCommand("stream-f1b-2", ws_a.repo_id, ws_a.checkout_id, (ev,), cap_c2.token)
            )
        assert exc_ing.value.code is ErrorCode.UNAUTHENTICATED
        assert gate.current() is None
    finally:
        rt.close()


# ---------------------------------------------------------------------------
# F1c: Same-principal mcp + cap coexistence (real M1 topology)
# ---------------------------------------------------------------------------


def test_f1c_same_principal_mcp_revoked_blocks_render_current_while_cap_active(trusted_tmp: Path) -> None:
    """Revoking mcp_c while same-principal cap_c stays active must block render_current with NOT_FOUND."""
    clock, mono, _os, rt, bridge, gate = _make_bridge_env(trusted_tmp, name="f1c")
    try:
        mcp_c = seed_principal_and_credential(rt.policy, owner_id=_OWNER, harness_id="claude-code", machine_id=_MACHINE)
        cap_c = seed_principal_and_credential(rt.policy, owner_id=_OWNER, harness_id="claude-code", machine_id=_MACHINE)
        assert mcp_c.principal == cap_c.principal
        shared_principal = mcp_c.principal

        ws_a = register_workspace_direct(
            rt, clock, shared_principal, alias="ws-f1c", checkout_dir=trusted_tmp / "chk-f1c"
        )
        scope_a = Scope(ws_a.repo_id, ws_a.checkout_id)
        rt.store.reconcile_policy()

        _publish_mixed_view(
            rt,
            gate,
            cap_updates={
                cap_c.credential_id: (
                    frozenset({CAPABILITY_CAPTURE_PRODUCER}),
                    CaptureProducerBinding("stream-f1c", ws_a.repo_id, ws_a.checkout_id),
                ),
            },
        )

        # Positive twin: mcp_c dispatches prepare_task(work) and bridge.render_current succeeds while mcp_c is active.
        prep_call = normalize_call(
            "prepare_task",
            {
                "schema_version": SCHEMA_VERSION,
                "mode": "work",
                "workspace_id": ws_a.repo_id,
                "checkout_id": ws_a.checkout_id,
                "description": "Shared principal M1 topology test",
                "idempotency_key": f"idem-f1c-work-{new_id()}",
            },
            shared_principal,
            selected_scope=scope_a,
        )
        prep_ctx = CallContext(
            principal=shared_principal,
            identity=Identity(store_id=rt.store.store_id, writer_epoch=rt.lease.epoch, instance_id="inst-f1c"),
            deadline_ns=mono.monotonic_ns() + HANDLER_RESERVE_NS + 1_000_000_000,
            selected_scope=scope_a,
        )
        prep_res = bridge.dispatch(prep_call, prep_ctx, auth=_auth_for(mcp_c))
        assert prep_res.get("ok") is True, prep_res

        with rt.store.transaction() as stxn:
            row = stxn.db.execute(
                "SELECT result_id, assignment_id, refs_json FROM idempotency WHERE principal_id = ? AND tool = ?",
                (shared_principal.principal_id, "prepare_task"),
            ).fetchone()
        assert row is not None
        stored = StoredResult(
            result_id=str(row[0]),
            assignment_id=None if row[1] is None else str(row[1]),
            refs=StoredResult.decode_refs_json(str(row[2])),
        )
        rendered = bridge.render_current(stored, shared_principal, selected_scope=scope_a)
        assert isinstance(rendered, dict) and isinstance(rendered["task_id"], str)

        # Revoke ONLY mcp_c, keeping cap_c active on the SAME principal.
        proof = make_bootstrap_auth(
            store_id=rt.policy.store_id,
            owner_id=_OWNER,
            action="credential_revoke",
            subject_id=mcp_c.credential_id,
            trust_generation=rt.policy.trust_generation(),
            expires_at=clock.now() + timedelta(hours=1),
        )
        bridge.revoke_credential(mcp_c.credential_id, proof)

        # 1. mcp_c dispatch -> UNAUTHENTICATED.
        revoked_mcp_res = bridge.dispatch(
            _health_call(shared_principal),
            _health_ctx(rt, shared_principal, mono, instance_id="inst-f1c"),
            auth=_auth_for(mcp_c),
        )
        assert revoked_mcp_res["ok"] is False
        assert cast(dict[str, Any], revoked_mcp_res["error"])["code"] == ErrorCode.UNAUTHENTICATED.value

        # 2. cap_c dispatch -> IDENTITY_MISMATCH.
        cap_mcp_res = bridge.dispatch(
            _health_call(shared_principal),
            _health_ctx(rt, shared_principal, mono, instance_id="inst-f1c"),
            auth=_auth_for(cap_c),
        )
        assert cap_mcp_res["ok"] is False
        assert cast(dict[str, Any], cap_mcp_res["error"])["code"] == ErrorCode.IDENTITY_MISMATCH.value

        # 3. cap_c capture batch still works (capture_producer remains active).
        ev = CaptureEventRecord(
            event_id="ev-f1c-cap-still-ok",
            producer_stream="stream-f1c",
            sequence=1,
            harness_id="claude-code",
            kind="tool_post",
            recorded_at="2026-11-26T13:02:00Z",
            payload={"ok": True},
        ).to_dict()
        ack = bridge.ingest_capture_batch(
            CaptureBatchCommand("stream-f1c", ws_a.repo_id, ws_a.checkout_id, (ev,), cap_c.token)
        )
        assert ack.accepted_count == 1

        # 4. render_current for shared_principal MUST raise NOT_FOUND (must NOT treat active cap_c as active MCP).
        with pytest.raises(BrainError) as exc_rc:
            bridge.render_current(stored, shared_principal, selected_scope=scope_a)
        assert exc_rc.value.code is ErrorCode.NOT_FOUND
    finally:
        rt.close()


# ---------------------------------------------------------------------------
# F2: AuthGate.authorize_release & AuthGate.authorize_stamp
# ---------------------------------------------------------------------------


def test_f2_auth_gate_authorize_release_and_stamp_reject_non_mcp(trusted_tmp: Path) -> None:
    """AuthGate.authorize_release and authorize_stamp allow mcp_tool and reject capture_producer/operator_cli."""
    clock, _mono, _os, rt, _bridge, gate = _make_bridge_env(trusted_tmp, name="f2")
    try:
        mcp_c = seed_principal_and_credential(rt.policy, owner_id=_OWNER, harness_id="claude-code", machine_id=_MACHINE)
        cap_c = seed_principal_and_credential(rt.policy, owner_id=_OWNER, harness_id="claude-code", machine_id=_MACHINE)
        op_c = seed_principal_and_credential(rt.policy, owner_id=_OWNER, harness_id="operator-cli", machine_id=_MACHINE)
        ws_a = register_workspace_direct(rt, clock, mcp_c.principal, alias="ws-f2", checkout_dir=trusted_tmp / "chk-f2")
        seed_repo_grant(rt.policy, principal_id=op_c.principal.principal_id, repo_id=ws_a.repo_id, owner_id=_OWNER)
        rt.store.reconcile_policy()

        view = _publish_mixed_view(
            rt,
            gate,
            cap_updates={
                cap_c.credential_id: (
                    frozenset({CAPABILITY_CAPTURE_PRODUCER}),
                    CaptureProducerBinding("stream-f2", ws_a.repo_id, ws_a.checkout_id),
                ),
                op_c.credential_id: (frozenset({CAPABILITY_OPERATOR_CLI}), None),
            },
        )

        def _stamp_for(cred: SeededCredential) -> AuthGrantStamp:
            return AuthGrantStamp(
                credential_id=cred.credential_id,
                generation=view.version,
                trust_generation=view.auth.trust_generation,
                identity=gate.identity,
            )

        # Positive twins: mcp_c passes both checks at exact current version/trust_generation.
        assert gate.authorize_release(mcp_c.credential_id, view.version) is True
        assert gate.authorize_stamp(_stamp_for(mcp_c)) is True

        # Negative twins: active cap_c and op_c fail both checks at exact current version/trust_generation.
        for non_mcp in (cap_c, op_c):
            assert gate.authorize_release(non_mcp.credential_id, view.version) is False
            assert gate.authorize_stamp(_stamp_for(non_mcp)) is False
    finally:
        rt.close()


# ---------------------------------------------------------------------------
# F4: AuthGate store_id mismatch and close() clear credential bindings
# ---------------------------------------------------------------------------


def test_f4_auth_gate_store_id_mismatch_and_close_clear_credential_bindings(trusted_tmp: Path) -> None:
    """Mismatched store_id on publish_view/rebind_writer_epoch and close() clear cached credential bindings."""
    clock, _mono, _os, rt, _bridge, gate = _make_bridge_env(trusted_tmp, name="f4")
    try:
        mcp_c = seed_principal_and_credential(rt.policy, owner_id=_OWNER, harness_id="claude-code", machine_id=_MACHINE)
        cap_c = seed_principal_and_credential(rt.policy, owner_id=_OWNER, harness_id="claude-code", machine_id=_MACHINE)
        ws_a = register_workspace_direct(rt, clock, mcp_c.principal, alias="ws-f4", checkout_dir=trusted_tmp / "chk-f4")
        rt.store.reconcile_policy()

        raw_snap = rt.policy.snapshot()
        key_id, key_bytes = rt.policy.request_digest_key()
        cap_binding = CaptureProducerBinding("stream-f4", ws_a.repo_id, ws_a.checkout_id)

        def _seed_valid_view(*, epoch: int = 1) -> RequestAuthView:
            merged = dict(raw_snap.credentials)
            merged[cap_c.credential_id] = replace(
                merged[cap_c.credential_id],
                capabilities=frozenset({CAPABILITY_CAPTURE_PRODUCER}),
                capture_binding=cap_binding,
            )
            view = RequestAuthView(
                version=gate.next_version(),
                auth=replace(raw_snap, credentials=merged),
                active_request_key_id=key_id,
                active_request_key_bytes=key_bytes,
            )
            meta = ShallowHealthMeta(
                store_id=rt.store.store_id,
                writer_epoch=epoch,
                instance_id=gate.identity.instance_id,
                schema_version=rt.store.schema_version,
                policy_schema_version=rt.policy.schema_version,
                tls_not_after=clock.now() + timedelta(days=30),
            )
            published = gate.publish_view(view, health_meta=meta)
            assert (
                gate.merge_runtime_capabilities(raw_snap).credentials[cap_c.credential_id].capabilities
                == frozenset({CAPABILITY_CAPTURE_PRODUCER})
            )
            return published

        # 1. publish_view with mismatched view.auth.store_id clears current() AND cached bindings.
        _seed_valid_view()
        bad_view = RequestAuthView(
            version=gate.next_version(),
            auth=replace(raw_snap, store_id="wrong-store-id"),
            active_request_key_id=key_id,
            active_request_key_bytes=key_bytes,
        )
        with pytest.raises(BrainError) as exc_1:
            gate.publish_view(bad_view)
        assert exc_1.value.code is ErrorCode.INTEGRITY_FAILURE
        assert gate.current() is None
        assert gate.merge_runtime_capabilities(raw_snap) == raw_snap

        # 2. publish_view with mismatched health_meta.store_id clears current() AND cached bindings.
        _seed_valid_view()
        good_view_2 = RequestAuthView(
            version=gate.next_version(),
            auth=raw_snap,
            active_request_key_id=key_id,
            active_request_key_bytes=key_bytes,
        )
        bad_meta = ShallowHealthMeta(
            store_id="wrong-store-id",
            writer_epoch=gate.identity.writer_epoch,
            instance_id=gate.identity.instance_id,
            schema_version=rt.store.schema_version,
            policy_schema_version=rt.policy.schema_version,
            tls_not_after=clock.now() + timedelta(days=30),
        )
        with pytest.raises(BrainError) as exc_2:
            gate.publish_view(good_view_2, health_meta=bad_meta)
        assert exc_2.value.code is ErrorCode.INTEGRITY_FAILURE
        assert gate.current() is None
        assert gate.merge_runtime_capabilities(raw_snap) == raw_snap

        # 3a. rebind_writer_epoch with mismatched view.auth.store_id clears current() AND cached bindings.
        _seed_valid_view()
        good_meta_ep2 = ShallowHealthMeta(
            store_id=rt.store.store_id,
            writer_epoch=2,
            instance_id=gate.identity.instance_id,
            schema_version=rt.store.schema_version,
            policy_schema_version=rt.policy.schema_version,
            tls_not_after=clock.now() + timedelta(days=30),
        )
        bad_view_ep2 = RequestAuthView(
            version=gate.next_version(),
            auth=replace(raw_snap, store_id="wrong-store-id"),
            active_request_key_id=key_id,
            active_request_key_bytes=key_bytes,
        )
        with pytest.raises(BrainError) as exc_3a:
            gate.rebind_writer_epoch(2, bad_view_ep2, health_meta=good_meta_ep2)
        assert exc_3a.value.code is ErrorCode.INTEGRITY_FAILURE
        assert gate.current() is None
        assert gate.merge_runtime_capabilities(raw_snap) == raw_snap

        # 3b. rebind_writer_epoch with mismatched health_meta.store_id clears current() AND cached bindings.
        _seed_valid_view()
        good_view_ep2 = RequestAuthView(
            version=gate.next_version(),
            auth=raw_snap,
            active_request_key_id=key_id,
            active_request_key_bytes=key_bytes,
        )
        bad_meta_ep2 = ShallowHealthMeta(
            store_id="wrong-store-id",
            writer_epoch=2,
            instance_id=gate.identity.instance_id,
            schema_version=rt.store.schema_version,
            policy_schema_version=rt.policy.schema_version,
            tls_not_after=clock.now() + timedelta(days=30),
        )
        with pytest.raises(BrainError) as exc_3b:
            gate.rebind_writer_epoch(2, good_view_ep2, health_meta=bad_meta_ep2)
        assert exc_3b.value.code is ErrorCode.INTEGRITY_FAILURE
        assert gate.current() is None
        assert gate.merge_runtime_capabilities(raw_snap) == raw_snap

        # 4. close() clears current() AND cached bindings identically.
        _seed_valid_view()
        gate.close()
        assert gate.current() is None
        assert gate.merge_runtime_capabilities(raw_snap) == raw_snap
    finally:
        rt.close()


# ---------------------------------------------------------------------------
# F5: Double online policy restore + AtomicRequestAuthState / explicit demote
# ---------------------------------------------------------------------------


def test_f5_double_online_policy_restore_and_explicit_demote_to_mcp(trusted_tmp: Path) -> None:
    """Double online policy restore preserves cap_c binding; explicit MCP re-publish clears old binding."""
    clock = FakeClock(datetime.now(UTC).replace(microsecond=0))
    mono = FakeMonotonicClock(1_000_000_000)
    os_ = os_adapters(clock=clock, monotonic=mono)
    priv, s_enr = _ssh_signer()
    cfg_dir = trusted_tmp / "cfg"
    data_root = trusted_tmp / "data"
    chk_dir = trusted_tmp / "chk-r2"
    for d in (cfg_dir, chk_dir):
        d.mkdir(parents=True, exist_ok=True)
        os_.permissions.secure_directory(d)

    rep = init_entry.init_store(
        init_entry.InitRequest(
            data_root=data_root, config_dir=cfg_dir, owner_id=_OWNER, machine_id=_MACHINE, signer=s_enr
        ),
        os_,
    )
    cfg = read_daemon_config(rep.daemon_config_path, os_)
    ca_pem = (cfg_dir / "tls" / "ca.pem").read_text(encoding="utf-8")
    cli_token = rep.cli_credential_path.read_text(encoding="ascii").strip()

    rt = reopen_kernel_job_runtime(data_root, rep.store_id, os_)
    try:
        mcp_c = seed_principal_and_credential(rt.policy, owner_id=_OWNER, harness_id="claude-code", machine_id=_MACHINE)
        ws_a = register_workspace_direct(rt, clock, mcp_c.principal, alias="ws-restore", checkout_dir=chk_dir)
        rt.store.reconcile_policy()
        bak_without_cap = create_policy_backup(rt.policy, os_, clock.now())
    finally:
        rt.close()

    with _serve_daemon(cfg, os_, clock, mono) as (ready, loop):
        cap_box: list[tuple[SeededCredential, Path]] = []

        def _seed_cap_and_backup_2() -> None:
            session = cast(Any, loop._session)
            assert session is not None
            live_rt = session._rt
            cap_c = seed_principal_and_credential(
                live_rt.policy, owner_id=_OWNER, harness_id="claude-code", machine_id=_MACHINE
            )
            seed_repo_grant(
                live_rt.policy, principal_id=cap_c.principal.principal_id, repo_id=ws_a.repo_id, owner_id=_OWNER
            )
            live_rt.store.reconcile_policy()
            clock.advance(timedelta(seconds=2))
            bak_with_cap = create_policy_backup(live_rt.policy, os_, clock.now())

            snap = live_rt.policy.snapshot()
            merged = dict(snap.credentials)
            merged[cap_c.credential_id] = replace(
                merged[cap_c.credential_id],
                capabilities=frozenset({CAPABILITY_CAPTURE_PRODUCER}),
                capture_binding=CaptureProducerBinding("stream-restore-a", ws_a.repo_id, ws_a.checkout_id),
            )
            session.auth_gate.publish(replace(snap, credentials=merged))
            cap_box.append((cap_c, bak_with_cap))

        loop.run_owner_action(_seed_cap_and_backup_2).result(timeout=10.0)
        cap_c, bak_with_cap = cap_box[0]

        target = LoopbackTarget(
            endpoint=ready.endpoint,
            expected_store_id=rep.store_id,
            ca_pem=ca_pem,
            leaf_cert_sha256=ready.leaf_cert_sha256,
        )
        lb_client = LoopbackClient(monotonic_ns=mono.monotonic_ns)
        cap_client = CaptureClient(lb_client)

        def _run_online_policy_restore(backup_path: Path) -> None:
            st_p, prev_env = _post_tls(
                ready, ca_pem, "/v2/operator/restore", cli_token, {"target": "policy", "backup": str(backup_path)}
            )
            assert st_p == 200 and prev_env.get("ok") is True, (st_p, prev_env)
            ch = cast(dict[str, Any], prev_env["data"]["challenge"])
            msg = ApprovalMessage(
                store_id=rep.store_id,
                owner_id=_OWNER,
                trust_generation=int(ch["trust_generation"]),
                action=ApprovalAction.RESTORE,
                subject_id=str(ch["subject_id"]),
                subject_revision=1,
                resource_digests=(ResourceDigest("backup", str(prev_env["data"]["backup_db_digest"])),),
                target_files=(),
                risk_level=RiskLevel.HIGH,
                risk_policy_version=RISK_POLICY_VERSION,
                recovery_scope=RecoveryScope.NONE,
                nonce=str(ch["nonce"]),
                expires_at=datetime.fromisoformat(str(ch["expires_at"]).replace("Z", "+00:00")),
            )
            st_e, exec_env = _post_tls(
                ready,
                ca_pem,
                "/v2/operator/restore",
                cli_token,
                {
                    "target": "policy",
                    "backup": str(backup_path),
                    "approval": {
                        "message": msg.to_dict(),
                        "channel": ApprovalChannel.SSH_KEY.value,
                        "signer_id": rep.signer.signer_id,
                        "signature": _ssh_sig_b64(priv, msg.canonical_bytes()),
                    },
                },
            )
            assert st_e == 200 and exec_env.get("ok") is True, (st_e, exec_env)

        def _ev(seq: int) -> dict[str, JsonValue]:
            return CaptureEventRecord(
                event_id=f"ev-f5-{seq}",
                producer_stream="stream-restore-a",
                sequence=seq,
                harness_id="claude-code",
                kind="tool_post",
                recorded_at=f"2026-11-26T13:10:0{seq}Z",
                payload={"seq": seq},
            ).to_dict()

        # Pre-restore baseline: cap_c succeeds on capture and is rejected on MCP; mcp_c succeeds on MCP.
        assert (
            cap_client.post_batch(
                target, CaptureBatchCommand("stream-restore-a", ws_a.repo_id, ws_a.checkout_id, (_ev(1),), cap_c.token)
            ).accepted_count
            == 1
        )
        assert (
            lb_client.call(target, ToolCommand("get_health", {"schema_version": SCHEMA_VERSION}, token=mcp_c.token))[
                "ok"
            ]
            is True
        )

        # Online restore #1 -> backup WITHOUT cap_c.
        _run_online_policy_restore(bak_without_cap)
        view_r1 = loop.auth_gate.current()
        assert view_r1 is not None and cap_c.credential_id not in view_r1.auth.credentials
        with pytest.raises(BrainError) as exc_r1:
            cap_client.post_batch(
                target, CaptureBatchCommand("stream-restore-a", ws_a.repo_id, ws_a.checkout_id, (_ev(2),), cap_c.token)
            )
        assert exc_r1.value.code is ErrorCode.UNAUTHENTICATED

        # Online restore #2 -> backup WITH cap_c.
        _run_online_policy_restore(bak_with_cap)
        view_r2 = loop.auth_gate.current()
        assert view_r2 is not None
        restored_cap = view_r2.auth.credentials[cap_c.credential_id]
        assert restored_cap.capabilities == frozenset({CAPABILITY_CAPTURE_PRODUCER})
        assert restored_cap.capture_binding == CaptureProducerBinding(
            "stream-restore-a", ws_a.repo_id, ws_a.checkout_id
        )

        # cap_c MUST still be rejected on MCP tools and still work for capture ingest.
        cap_as_mcp = lb_client.call(
            target, ToolCommand("get_health", {"schema_version": SCHEMA_VERSION}, token=cap_c.token)
        )
        assert cap_as_mcp["ok"] is False
        assert cast(dict[str, Any], cap_as_mcp["error"])["code"] == ErrorCode.IDENTITY_MISMATCH.value

        assert (
            cap_client.post_batch(
                target, CaptureBatchCommand("stream-restore-a", ws_a.repo_id, ws_a.checkout_id, (_ev(2),), cap_c.token)
            ).accepted_count
            == 1
        )
        assert (
            lb_client.call(target, ToolCommand("get_health", {"schema_version": SCHEMA_VERSION}, token=mcp_c.token))[
                "ok"
            ]
            is True
        )

        # Part B: AtomicRequestAuthState.install absent-then-present preservation AND explicit demote clearing.
        key_id = view_r2.active_request_key_id
        key_bytes = view_r2.active_request_key_bytes
        snap_with_cap_default = replace(
            view_r2.auth,
            credentials={
                **view_r2.auth.credentials,
                cap_c.credential_id: replace(
                    restored_cap, capabilities=_DEFAULT_MCP_CAPABILITIES, capture_binding=None
                ),
            },
        )
        snap_without_cap = replace(
            view_r2.auth,
            credentials={cid: rec for cid, rec in view_r2.auth.credentials.items() if cid != cap_c.credential_id},
        )
        state = AtomicRequestAuthState(rep.store_id)
        state.install(RequestAuthView(1, view_r2.auth, key_id, key_bytes))
        state.install(RequestAuthView(2, snap_without_cap, key_id, key_bytes))

        # Absent-then-present restore preserves cap_c's capture binding.
        reattached = state.merge_runtime_capabilities(snap_with_cap_default)
        assert reattached.credentials[cap_c.credential_id].capabilities == frozenset({CAPABILITY_CAPTURE_PRODUCER})
        assert reattached.credentials[cap_c.credential_id].capture_binding == restored_cap.capture_binding

        # Explicit re-publish where cap_c IS present with default MCP capabilities clears old non-MCP binding.
        state.install(RequestAuthView(3, snap_with_cap_default, key_id, key_bytes))
        after_explicit = state.merge_runtime_capabilities(snap_with_cap_default)
        assert after_explicit.credentials[cap_c.credential_id].capabilities == _DEFAULT_MCP_CAPABILITIES
        assert after_explicit.credentials[cap_c.credential_id].capture_binding is None

        # Same explicit-demote behavior on AuthGate.publish_view.
        gate2 = AuthGate(rep.store_id, 1, "inst-explicit-demote")
        gate2.publish_view(RequestAuthView(1, view_r2.auth, key_id, key_bytes))
        gate2.publish_view(RequestAuthView(2, snap_without_cap, key_id, key_bytes))
        assert (
            gate2.merge_runtime_capabilities(snap_with_cap_default).credentials[cap_c.credential_id].capabilities
            == frozenset({CAPABILITY_CAPTURE_PRODUCER})
        )
        gate2.publish_view(RequestAuthView(3, snap_with_cap_default, key_id, key_bytes))
        demoted = gate2.merge_runtime_capabilities(snap_with_cap_default).credentials[cap_c.credential_id]
        assert demoted.capabilities == _DEFAULT_MCP_CAPABILITIES and demoted.capture_binding is None


# ---------------------------------------------------------------------------
# F6: Direct coverage of remaining helpers
# ---------------------------------------------------------------------------


def test_f6_direct_helpers_merge_clear_if_diverged_and_matches_persisted_policy(trusted_tmp: Path) -> None:
    """Direct tests for merge_runtime_capabilities, _clear_auth_if_diverged, and matches_persisted_policy."""
    clock, _mono, _os, rt, bridge, gate = _make_bridge_env(trusted_tmp, name="f6")
    try:
        mcp_c = seed_principal_and_credential(rt.policy, owner_id=_OWNER, harness_id="claude-code", machine_id=_MACHINE)
        cap_c = seed_principal_and_credential(rt.policy, owner_id=_OWNER, harness_id="claude-code", machine_id=_MACHINE)
        ws_a = register_workspace_direct(rt, clock, mcp_c.principal, alias="ws-f6", checkout_dir=trusted_tmp / "chk-f6")
        rt.store.reconcile_policy()

        base_snap = rt.policy.snapshot()
        key_id, key_bytes = rt.policy.request_digest_key()
        cap_binding = CaptureProducerBinding("stream-f6", ws_a.repo_id, ws_a.checkout_id)

        # 1. AtomicRequestAuthState.merge_runtime_capabilities: empty, matching, and mismatched secret_digest.
        state = AtomicRequestAuthState(rt.store.store_id)
        assert state.merge_runtime_capabilities(base_snap) == base_snap

        cap_view_snap = replace(
            base_snap,
            credentials={
                **base_snap.credentials,
                cap_c.credential_id: replace(
                    base_snap.credentials[cap_c.credential_id],
                    capabilities=frozenset({CAPABILITY_CAPTURE_PRODUCER}),
                    capture_binding=cap_binding,
                ),
            },
        )
        state.install(RequestAuthView(1, cap_view_snap, key_id, key_bytes))
        merged = state.merge_runtime_capabilities(base_snap)
        assert merged.credentials[cap_c.credential_id].capabilities == frozenset({CAPABILITY_CAPTURE_PRODUCER})
        assert merged.credentials[cap_c.credential_id].capture_binding == cap_binding

        mismatched_digest_snap = replace(
            base_snap,
            credentials={
                **base_snap.credentials,
                cap_c.credential_id: replace(
                    base_snap.credentials[cap_c.credential_id],
                    secret_digest="sha256:" + ("f" * 64),
                ),
            },
        )
        not_merged = state.merge_runtime_capabilities(mismatched_digest_snap)
        assert not_merged.credentials[cap_c.credential_id].capabilities == _DEFAULT_MCP_CAPABILITIES
        assert not_merged.credentials[cap_c.credential_id].capture_binding is None

        # 2. AuthSnapshot.matches_persisted_policy persisted-non-default branch.
        assert cap_view_snap.matches_persisted_policy(base_snap) is True

        pol_non_default = replace(
            base_snap,
            credentials={
                **base_snap.credentials,
                cap_c.credential_id: replace(
                    base_snap.credentials[cap_c.credential_id],
                    capabilities=frozenset({CAPABILITY_CAPTURE_PRODUCER}),
                    capture_binding=cap_binding,
                ),
            },
        )
        assert cap_view_snap.matches_persisted_policy(pol_non_default) is True
        assert base_snap.matches_persisted_policy(pol_non_default) is False

        other_binding_view = replace(
            base_snap,
            credentials={
                **base_snap.credentials,
                cap_c.credential_id: replace(
                    base_snap.credentials[cap_c.credential_id],
                    capabilities=frozenset({CAPABILITY_CAPTURE_PRODUCER}),
                    capture_binding=CaptureProducerBinding("stream-other", ws_a.repo_id, ws_a.checkout_id),
                ),
            },
        )
        assert other_binding_view.matches_persisted_policy(pol_non_default) is False

        # 3. KernelBridge._clear_auth_if_diverged.
        bridge._clear_auth_if_diverged(mcp_c.credential_id)
        assert gate.current() is None

        _publish_mixed_view(
            rt,
            gate,
            cap_updates={cap_c.credential_id: (frozenset({CAPABILITY_CAPTURE_PRODUCER}), cap_binding)},
        )
        assert gate.current() is not None

        # Non-MCP credential without policy divergence preserves auth_gate.
        bridge._clear_auth_if_diverged(cap_c.credential_id)
        assert gate.current() is not None

        # Active MCP credential (unexpected UNAUTHENTICATED) clears auth_gate.
        bridge._clear_auth_if_diverged(mcp_c.credential_id)
        assert gate.current() is None

        # Non-MCP credential WITH SQLite divergence clears auth_gate.
        _publish_mixed_view(
            rt,
            gate,
            cap_updates={cap_c.credential_id: (frozenset({CAPABILITY_CAPTURE_PRODUCER}), cap_binding)},
        )
        proof = make_bootstrap_auth(
            store_id=rt.policy.store_id,
            owner_id=_OWNER,
            action="credential_revoke",
            subject_id=cap_c.credential_id,
            trust_generation=rt.policy.trust_generation(),
            expires_at=clock.now() + timedelta(hours=1),
        )
        rt.policy.record_authorized_revocation(cap_c.credential_id, proof)
        bridge._clear_auth_if_diverged(cap_c.credential_id)
        assert gate.current() is None
    finally:
        rt.close()
