"""SP2-5 production wiring regressions for Layer-2 live invalidation, bootstrap/hooks, doctor & deep health."""

from __future__ import annotations

import base64
import hashlib
import inspect
import json
import os
import shlex
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import jsonschema
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from superbrain.adapters.harness.layer2_probe import (
    AuthorityCommandProbeResult,
    NativeHostReceipt,
    compute_harness_config_digest,
)
from superbrain.adapters.harness_config.bootstrap_templates import (
    AUTHORITY_ASK_COMMANDS,
    MANAGED_HOOK_EVENTS,
    plan_claude_bootstrap,
    plan_codex_bootstrap,
)
from superbrain.adapters.harness_config.markdown_blocks import merge_markdown_block
from superbrain.adapters.harness_config.merger import SharedConfigMergerAdapter
from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.daemon_config import read_daemon_config
from superbrain.application.owner_loop import OwnerLoop
from superbrain.application.review_apply import ReviewApplyService, TargetWriteInput
from superbrain.cli_api.capture_client import CaptureClient
from superbrain.cli_api.loopback import LoopbackClient, LoopbackTarget
from superbrain.composition import daemon_entry, hook_entry, init_entry
from superbrain.composition._layer2_live import verify_live_layer2_harness
from superbrain.composition.capture_drain_entry import drain_outbox
from superbrain.composition.doctor_entry import run_doctor
from superbrain.composition.doctor_probes_sp2_store import reconcile_harness_layer2_in_policy
from superbrain.core._kernel_approval import (
    APPROVAL_NAMESPACE,
    RISK_POLICY_VERSION,
    ApprovalAction,
    ApprovalChannel,
    ApprovalMessage,
    Layer2State,
    RecoveryScope,
    RiskLevel,
    RiskResource,
    SignerEnrollment,
)
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.kernel import (
    CAPABILITY_CAPTURE_PRODUCER,
    CaptureBatchCommand,
    CaptureProducerBinding,
    DaemonConfig,
    Ready,
    ResourceDigest,
    ToolCommand,
    WorkspaceBinding,
)
from superbrain.core.proposals import ManagedFormat
from superbrain.core.wire import SCHEMA_VERSION
from superbrain.ports.capture import (
    OUTBOX_RECORD_EVENT,
    OUTBOX_RECORD_GAP,
    CaptureBatchAck,
    CaptureEventRecord,
    require_iso_utc_timestamp,
)
from superbrain.ports.os import OsAdapters
from superbrain.storage.backup import create_policy_backup
from superbrain.storage.kernel_schema import KERNEL_POLICY_MIGRATIONS
from superbrain.storage.outbox import OutboxSpool
from superbrain.storage.proposals import PolicyApplyAuthority, StoreProposalAdapter
from superbrain.storage.restore import restore_policy
from superbrain.storage.sessions import SessionStore
from tests.storage.conftest import maintenance_lease
from tests.support.clock import FakeClock
from tests.support.fs import digest_tree
from tests.support.inc2_cli import (
    clean_installed_subprocess_env,
    get_shared_t7_transport_template,
    write_client_profile_file,
    write_credential_file,
)
from tests.support.inc2_fixture import reopen_kernel_job_runtime
from tests.support.inc2_transport import (
    FakeMonotonicClock,
    open_test_loopback_transport,
    read_raw_http_response,
    register_workspace_direct,
)
from tests.support.kernel_auth import SeededCredential, seed_principal_and_credential, seed_repo_grant

_OWNER = "dan"
_MACHINE = "m-sp25-prod"
_CLAUDE_VER = "2.1.325"
_CODEX_VER = "26.1111.2228.0"
_REPO_ROOT = Path(__file__).resolve().parents[2]
_SCHEMA_PATH = _REPO_ROOT / "schemas" / "mcp-tools-v2.json"


def _ssh_signer() -> tuple[Ed25519PrivateKey, SignerEnrollment]:
    priv = Ed25519PrivateKey.generate()
    raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", len(raw)) + raw
    return priv, SignerEnrollment(
        owner_id=_OWNER,
        channel=ApprovalChannel.SSH_KEY,
        public_key="ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + " sp25@devbox",
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


def _write_plan_targets(checkout: Path, targets: tuple[Any, ...]) -> None:
    for tgt in targets:
        dest = checkout / Path(*tgt.rel_path.split("/"))
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(tgt.preview_text, encoding="utf-8")


def _build_receipt(*, harness_id: str, host_version: str, config_digest: str) -> NativeHostReceipt:
    probes = tuple(
        AuthorityCommandProbeResult(
            command_pattern=cmd,
            prompted_user=True,
            blocked_without_approval=True,
        )
        for cmd in AUTHORITY_ASK_COMMANDS
    )
    return NativeHostReceipt.build(
        receipt_id=f"rcpt-{harness_id}-{host_version}-{new_id()[:8]}",
        harness_id=harness_id,
        host_version=host_version,
        config_digest=config_digest,
        probe_mode="approved_sandbox_probe",
        command_probes=probes,
        observed_at="2026-11-26T14:00:00Z",
    )


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

    thr = threading.Thread(target=_bg, name="sp25-prod-daemon", daemon=True)
    thr.start()
    try:
        assert ready_evt.wait(timeout=5.0), f"daemon not ready (exits={exits})"
        # the startup DoctorRun (SP1-I4) writes CAS before its holder commits; let it settle before tests read storage
        assert cast(OwnerLoop, box["loop"]).wait_doctor_settled(timeout=10.0)
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


def _create_low_risk_proposal(
    rt: Any,
    os_: OsAdapters,
    *,
    data_root: Path,
    home: Path,
    checkout: Path,
    note_name: str,
) -> str:
    svc = ReviewApplyService(
        StoreProposalAdapter(rt.store, os_),
        PolicyApplyAuthority(rt.policy),
        os_,
        data_root=data_root,
        home_dir=home,
        config_merger=SharedConfigMergerAdapter(),
    )
    m = merge_markdown_block("", slice_id="note-1", block_body=f"Confirm {note_name}\n", expected_slice_digest=None)
    targets = [
        TargetWriteInput(
            checkout,
            note_name,
            m.updated_text.encode("utf-8"),
            ManagedFormat.MARKDOWN,
            "note-1",
            m.slice_digest,
        )
    ]
    prop = svc.create_proposal(
        owner_id=_OWNER,
        kind="lesson_confirm",
        reason=f"low-risk-{note_name}",
        resources=[RiskResource(component="c1")],
        targets=targets,
    )
    assert prop.risk_level is RiskLevel.LOW
    return prop.proposal_id


def _publish_capture_creds(
    loop: OwnerLoop,
    bindings: list[tuple[SeededCredential, str, WorkspaceBinding]],
) -> None:
    def _act() -> None:
        session = cast(Any, loop._session)
        assert session is not None
        snap = session._rt.policy.snapshot()
        merged = dict(snap.credentials)
        for cred, stream, ws in bindings:
            merged[cred.credential_id] = replace(
                merged[cred.credential_id],
                capabilities=frozenset({CAPABILITY_CAPTURE_PRODUCER}),
                capture_binding=CaptureProducerBinding(stream, ws.repo_id, ws.checkout_id),
            )
        session.auth_gate.publish(replace(snap, credentials=merged))

    loop.run_owner_action(_act).result(timeout=10.0)


def _capture_event_row(loop: OwnerLoop, event_id: str) -> tuple[str, str]:
    def _read() -> tuple[str, str]:
        session = cast(Any, loop._session)
        assert session is not None
        row = session._rt.store._db.execute(
            "SELECT source, source_verification FROM capture_events WHERE event_id = ?",
            (event_id,),
        ).fetchone()
        assert row is not None, f"missing capture_events row for {event_id}"
        return str(row[0]), str(row[1])

    return loop.run_owner_action(_read).result(timeout=10.0)


def _terminal_approve_proposal(
    ready: Ready,
    ca_pem: str,
    cli_token: str,
    proposal_id: str,
) -> tuple[int, dict[str, Any]]:
    st_c, ch_env = _post_tls(
        ready,
        ca_pem,
        "/v2/operator/proposal/approve",
        cli_token,
        {"proposal_id": proposal_id},
    )
    if st_c != 200 or ch_env.get("ok") is not True:
        return st_c, ch_env
    return _post_tls(
        ready,
        ca_pem,
        "/v2/operator/proposal/approve",
        cli_token,
        {
            "proposal_id": proposal_id,
            "approval": {
                "message": ch_env["data"]["challenge"],
                "channel": ApprovalChannel.TERMINAL.value,
            },
        },
    )


def _split_cmd(val: str) -> list[str]:
    tokens: list[str] = []
    for tok in shlex.split(val, posix=False):
        if len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in {"'", '"'}:
            tokens.append(tok[1:-1])
        else:
            tokens.append(tok)
    return tokens


def _find_hook_commands(node: Any) -> list[list[str]]:
    found: list[list[str]] = []
    if isinstance(node, dict):
        args = node.get("args")
        if isinstance(node.get("command"), str) and isinstance(args, list) and any(
            isinstance(x, str) and "superbrain.composition.hook_entry" in x for x in args
        ):
            return [[str(node["command"]), *(str(x) for x in args)]]  # Claude Code exec-form handler
        for key, val in node.items():
            if key in {"commandWindows", "command_windows"}:
                continue  # same argv as "command", spelled for Windows
            if key in {"command", "args"} and isinstance(val, str) and "superbrain.composition.hook_entry" in val:
                found.append(_split_cmd(val))
            elif (
                key in {"command", "args"}
                and isinstance(val, list)
                and all(isinstance(x, str) for x in val)
                and any("superbrain.composition.hook_entry" in x for x in val)
            ):
                found.append([str(x) for x in val])
            else:
                found.extend(_find_hook_commands(val))
    elif isinstance(node, list):
        if (
            all(isinstance(x, str) for x in node)
            and any("superbrain.composition.hook_entry" in x for x in node)
        ):
            found.append([str(x) for x in node])
        else:
            for item in node:
                found.extend(_find_hook_commands(item))
    elif isinstance(node, str) and "superbrain.composition.hook_entry" in node:
        found.append(_split_cmd(node))
    return found


def _extract_outbox_arg(cmd: list[str]) -> str:
    idx = cmd.index("--outbox")
    return cmd[idx + 1]


def _extract_harness_arg(cmd: list[str]) -> str:
    idx = cmd.index("--harness")
    return cmd[idx + 1]


def _validate_get_health_schema(data: dict[str, Any]) -> None:
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    ref_schema = {
        "$schema": schema["$schema"],
        "$defs": schema["$defs"],
        "$ref": "#/$defs/GetHealthResult",
    }
    jsonschema.validate(instance=data, schema=ref_schema)


# ---------------------------------------------------------------------------
# P1 Finding 1: Live Layer-2 invalidation & policy restore
# ---------------------------------------------------------------------------


def _install_fake_host_bins(
    trusted_tmp: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    claude_ver: str = _CLAUDE_VER,
    codex_ver: str = _CODEX_VER,
) -> Path:
    bin_dir = trusted_tmp / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    os_adapters().permissions.secure_directory(bin_dir)
    _write_fake_host_bin(bin_dir, "claude", f"{claude_ver} (Claude Code)")
    _write_fake_host_bin(bin_dir, "codex", f"codex-cli {codex_ver}")
    ssh_dir = (
        Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "OpenSSH"
        if sys.platform == "win32"
        else Path(shutil.which("ssh-keygen") or "/usr/bin/ssh-keygen").parent  # the SSH approval verifier needs it
    )
    isolated_path = f"{bin_dir}{os.pathsep}{ssh_dir}"
    monkeypatch.setenv("PATH", isolated_path)
    return bin_dir


def test_p1_finding1_live_layer2_config_drift_and_host_version_drift_fail_closed(
    trusted_tmp: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Checkout config drift & host version drift fail-close capture and terminal approval without helper calls."""
    _install_fake_host_bins(trusted_tmp, monkeypatch)
    clock = FakeClock(datetime.now(UTC).replace(microsecond=0))
    mono = FakeMonotonicClock(1_000_000_000)
    os_ = os_adapters(clock=clock, monotonic=mono)
    _priv, s_enr = _ssh_signer()

    cfg_dir = trusted_tmp / "cfg"
    data_root = trusted_tmp / "data"
    chk_a = trusted_tmp / "chk-a"
    home_dir = trusted_tmp / "home"
    for d in (cfg_dir, chk_a, home_dir):
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

    prof_path = cfg_dir / "claude-profile.json"
    _write_plan_targets(chk_a, plan_claude_bootstrap(checkout_root=chk_a, profile_path=prof_path).targets)
    _write_plan_targets(chk_a, plan_codex_bootstrap(checkout_root=chk_a, profile_path=prof_path).targets)
    c_dig1 = compute_harness_config_digest("claude-code", chk_a, os_)
    x_dig1 = compute_harness_config_digest("codex", chk_a, os_)
    assert c_dig1 is not None and x_dig1 is not None

    rt = reopen_kernel_job_runtime(data_root, rep.store_id, os_)
    try:
        mcp_c = seed_principal_and_credential(rt.policy, owner_id=_OWNER, harness_id="claude-code", machine_id=_MACHINE)
        cap_c = seed_principal_and_credential(rt.policy, owner_id=_OWNER, harness_id="claude-code", machine_id=_MACHINE)
        cap_x = seed_principal_and_credential(rt.policy, owner_id=_OWNER, harness_id="codex", machine_id=_MACHINE)
        ws_a = register_workspace_direct(rt, clock, mcp_c.principal, alias="ws-l2-live", checkout_dir=chk_a)
        seed_repo_grant(rt.policy, principal_id=cap_x.principal.principal_id, repo_id=ws_a.repo_id, owner_id=_OWNER)
        rt.store.reconcile_policy()

        assert (
            reconcile_harness_layer2_in_policy(
                rt.policy,
                harness_id="claude-code",
                checkout_root=chk_a,
                observed_host_version=_CLAUDE_VER,
                os_=os_,
                receipt=_build_receipt(harness_id="claude-code", host_version=_CLAUDE_VER, config_digest=c_dig1),
            )[0]
            is Layer2State.VERIFIED
        )
        assert (
            reconcile_harness_layer2_in_policy(
                rt.policy,
                harness_id="codex",
                checkout_root=chk_a,
                observed_host_version=_CODEX_VER,
                os_=os_,
                receipt=_build_receipt(harness_id="codex", host_version=_CODEX_VER, config_digest=x_dig1),
            )[0]
            is Layer2State.VERIFIED
        )
        prop_ok = _create_low_risk_proposal(
            rt, os_, data_root=data_root, home=home_dir, checkout=chk_a, note_name="n1.md"
        )
        prop_codex_drift = _create_low_risk_proposal(
            rt, os_, data_root=data_root, home=home_dir, checkout=chk_a, note_name="n1b.md"
        )
        prop_cfg_drift = _create_low_risk_proposal(
            rt, os_, data_root=data_root, home=home_dir, checkout=chk_a, note_name="n2.md"
        )
        prop_ver_ok = _create_low_risk_proposal(
            rt, os_, data_root=data_root, home=home_dir, checkout=chk_a, note_name="n3.md"
        )
        prop_ver_drift = _create_low_risk_proposal(
            rt, os_, data_root=data_root, home=home_dir, checkout=chk_a, note_name="n4.md"
        )
    finally:
        rt.close()

    with _serve_daemon(cfg, os_, clock, mono) as (ready, loop):
        _publish_capture_creds(
            loop,
            [
                (cap_c, "stream-claude-l2", ws_a),
                (cap_x, "stream-codex-l2", ws_a),
            ],
        )
        target = LoopbackTarget(
            endpoint=ready.endpoint,
            expected_store_id=rep.store_id,
            ca_pem=ca_pem,
            leaf_cert_sha256=ready.leaf_cert_sha256,
        )
        cap_client = CaptureClient(LoopbackClient(monotonic_ns=mono.monotonic_ns))

        def _send_ev(seq: int, *, event_id: str, host_ver: str, cfg_dig: str) -> None:
            ev = CaptureEventRecord(
                event_id=event_id,
                producer_stream="stream-claude-l2",
                sequence=seq,
                harness_id="claude-code",
                kind="command_result",
                recorded_at=f"2026-11-26T14:00:{seq:02d}Z",
                payload={"cmd": "pytest", "seq": seq},
                source_metadata={"host_version": host_ver, "config_digest": cfg_dig},
            ).to_dict()
            ack = cap_client.post_batch(
                target,
                CaptureBatchCommand("stream-claude-l2", ws_a.repo_id, ws_a.checkout_id, (ev,), cap_c.token),
            )
            assert ack.accepted_count == 1

        # Positive baseline: verified live binding -> verified_host + terminal approval succeeds.
        _send_ev(1, event_id="ev-l2-live-1", host_ver=_CLAUDE_VER, cfg_dig=c_dig1)
        assert _capture_event_row(loop, "ev-l2-live-1") == ("tool_observed", "verified_host")

        st_ok, app_ok = _terminal_approve_proposal(ready, ca_pem, cli_token, prop_ok)
        assert st_ok == 200 and app_ok.get("ok") is True, (st_ok, app_ok)
        assert app_ok["data"]["proposal"]["status"] == "approved"

        # Case 1a-direct: Mutate .codex/hooks.json on disk and call terminal approval DIRECTLY before any capture
        # batch is sent -> MUST immediately fail closed with CAPABILITY_UNAVAILABLE.
        codex_hooks_path = chk_a / ".codex" / "hooks.json"
        codex_hooks_obj = json.loads(codex_hooks_path.read_text(encoding="utf-8"))
        codex_hooks_obj["extra_drift_flag"] = True
        codex_hooks_path.write_bytes(canonical_json(codex_hooks_obj))

        st_cd, app_cd = _terminal_approve_proposal(ready, ca_pem, cli_token, prop_codex_drift)
        assert app_cd.get("ok") is False, (st_cd, app_cd)
        assert app_cd["error"]["code"] == ErrorCode.CAPABILITY_UNAVAILABLE.value

        # Case 1a: Mutate .claude/settings.local.json on disk WITHOUT calling reconcile_harness_layer2_in_policy.
        settings_path = chk_a / ".claude" / "settings.local.json"
        settings_obj = json.loads(settings_path.read_text(encoding="utf-8"))
        settings_obj["permissions"]["allow"] = ["Bash(pytest *)"]
        settings_path.write_bytes(canonical_json(settings_obj))

        # Capture claiming old c_dig1 MUST immediately fall back to ("unknown", "unverified").
        _send_ev(2, event_id="ev-l2-live-cfg-drift", host_ver=_CLAUDE_VER, cfg_dig=c_dig1)
        assert _capture_event_row(loop, "ev-l2-live-cfg-drift") == ("unknown", "unverified")

        # Terminal approval MUST immediately fail closed with CAPABILITY_UNAVAILABLE.
        st_drift, app_drift = _terminal_approve_proposal(ready, ca_pem, cli_token, prop_cfg_drift)
        assert app_drift.get("ok") is False, (st_drift, app_drift)
        assert app_drift["error"]["code"] == ErrorCode.CAPABILITY_UNAVAILABLE.value

        # Production run_doctor MUST reflect drifted Layer-2 state & terminal_channel_eligible=False.
        doc = run_doctor(rep.daemon_config_path, checkout_root=chk_a, os_=os_)
        assert doc.terminal_channel_eligible is False
        by_h = {h.harness_id: h for h in doc.layer2_harnesses}
        assert by_h["claude-code"].state is Layer2State.UNKNOWN
        assert by_h["codex"].state is Layer2State.UNKNOWN

        # Case 1b: Re-verify at c_dig2 & x_dig2 as clean baseline, then observe live host_version drift ("2.1.326").
        c_dig2 = compute_harness_config_digest("claude-code", chk_a, os_)
        x_dig2 = compute_harness_config_digest("codex", chk_a, os_)
        assert c_dig2 is not None and c_dig2 != c_dig1
        assert x_dig2 is not None and x_dig2 != x_dig1

        def _reverify_c2() -> None:
            session = cast(Any, loop._session)
            assert session is not None
            st2, _ = reconcile_harness_layer2_in_policy(
                session._rt.policy,
                harness_id="claude-code",
                checkout_root=chk_a,
                observed_host_version=_CLAUDE_VER,
                os_=os_,
                receipt=_build_receipt(harness_id="claude-code", host_version=_CLAUDE_VER, config_digest=c_dig2),
            )
            assert st2 is Layer2State.VERIFIED
            stx2, _ = reconcile_harness_layer2_in_policy(
                session._rt.policy,
                harness_id="codex",
                checkout_root=chk_a,
                observed_host_version=_CODEX_VER,
                os_=os_,
                receipt=_build_receipt(harness_id="codex", host_version=_CODEX_VER, config_digest=x_dig2),
            )
            assert stx2 is Layer2State.VERIFIED

        loop.run_owner_action(_reverify_c2).result(timeout=10.0)
        st_vok, app_vok = _terminal_approve_proposal(ready, ca_pem, cli_token, prop_ver_ok)
        assert st_vok == 200 and app_vok.get("ok") is True, (st_vok, app_vok)

        # Host reports drifted version "2.1.326" -> both seq 3 AND subsequent stale "2.1.325" seq 4 MUST be
        # unverified, and terminal approval MUST refuse with CAPABILITY_UNAVAILABLE without calling
        # reconcile_harness_layer2_in_policy!
        _send_ev(3, event_id="ev-l2-live-ver-drift", host_ver="2.1.326", cfg_dig=c_dig2)
        assert _capture_event_row(loop, "ev-l2-live-ver-drift") == ("unknown", "unverified")

        _send_ev(4, event_id="ev-l2-live-ver-stale", host_ver=_CLAUDE_VER, cfg_dig=c_dig2)
        assert _capture_event_row(loop, "ev-l2-live-ver-stale") == ("unknown", "unverified")

        st_vd, app_vd = _terminal_approve_proposal(ready, ca_pem, cli_token, prop_ver_drift)
        assert app_vd.get("ok") is False, (st_vd, app_vd)
        assert app_vd["error"]["code"] == ErrorCode.CAPABILITY_UNAVAILABLE.value


def test_p1_finding1_policy_restore_with_old_verified_row_fails_closed(
    trusted_tmp: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Restoring a policy backup with an old VERIFIED row (online or offline) fails-closes terminal & capture."""
    _install_fake_host_bins(trusted_tmp, monkeypatch)
    clock = FakeClock(datetime.now(UTC).replace(microsecond=0))
    mono = FakeMonotonicClock(1_000_000_000)
    os_ = os_adapters(clock=clock, monotonic=mono)
    priv, s_enr = _ssh_signer()

    cfg_dir = trusted_tmp / "cfg"
    data_root = trusted_tmp / "data"
    chk_a = trusted_tmp / "chk-restore"
    home_dir = trusted_tmp / "home"
    for d in (cfg_dir, chk_a, home_dir):
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

    prof_path = cfg_dir / "claude-profile.json"
    _write_plan_targets(chk_a, plan_claude_bootstrap(checkout_root=chk_a, profile_path=prof_path).targets)
    _write_plan_targets(chk_a, plan_codex_bootstrap(checkout_root=chk_a, profile_path=prof_path).targets)
    c_dig1 = compute_harness_config_digest("claude-code", chk_a, os_)
    x_dig1 = compute_harness_config_digest("codex", chk_a, os_)
    assert c_dig1 is not None and x_dig1 is not None

    rt = reopen_kernel_job_runtime(data_root, rep.store_id, os_)
    try:
        mcp_c = seed_principal_and_credential(rt.policy, owner_id=_OWNER, harness_id="claude-code", machine_id=_MACHINE)
        cap_c = seed_principal_and_credential(rt.policy, owner_id=_OWNER, harness_id="claude-code", machine_id=_MACHINE)
        cap_x = seed_principal_and_credential(rt.policy, owner_id=_OWNER, harness_id="codex", machine_id=_MACHINE)
        ws_a = register_workspace_direct(rt, clock, mcp_c.principal, alias="ws-l2-res", checkout_dir=chk_a)
        seed_repo_grant(rt.policy, principal_id=cap_x.principal.principal_id, repo_id=ws_a.repo_id, owner_id=_OWNER)
        rt.store.reconcile_policy()

        assert (
            reconcile_harness_layer2_in_policy(
                rt.policy,
                harness_id="claude-code",
                checkout_root=chk_a,
                observed_host_version=_CLAUDE_VER,
                os_=os_,
                receipt=_build_receipt(harness_id="claude-code", host_version=_CLAUDE_VER, config_digest=c_dig1),
            )[0]
            is Layer2State.VERIFIED
        )
        assert (
            reconcile_harness_layer2_in_policy(
                rt.policy,
                harness_id="codex",
                checkout_root=chk_a,
                observed_host_version=_CODEX_VER,
                os_=os_,
                receipt=_build_receipt(harness_id="codex", host_version=_CODEX_VER, config_digest=x_dig1),
            )[0]
            is Layer2State.VERIFIED
        )
        bak_verified = create_policy_backup(rt.policy, os_, clock.now())
        prop_same_cfg = _create_low_risk_proposal(
            rt, os_, data_root=data_root, home=home_dir, checkout=chk_a, note_name="r-same.md"
        )
        prop_reverified = _create_low_risk_proposal(
            rt, os_, data_root=data_root, home=home_dir, checkout=chk_a, note_name="r-reverify.md"
        )
        prop_online = _create_low_risk_proposal(
            rt, os_, data_root=data_root, home=home_dir, checkout=chk_a, note_name="r-on.md"
        )
        prop_offline = _create_low_risk_proposal(
            rt, os_, data_root=data_root, home=home_dir, checkout=chk_a, note_name="r-off.md"
        )
    finally:
        rt.close()

    def _run_online_restore(ready_obj: Any, loop_obj: Any) -> Any:
        """Restore online; returns the live ``Ready`` (restore bumps the writer epoch)."""
        st_p, prev_env = _post_tls(
            ready_obj, ca_pem, "/v2/operator/restore", cli_token, {"target": "policy", "backup": str(bak_verified)}
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
            ready_obj,
            ca_pem,
            "/v2/operator/restore",
            cli_token,
            {
                "target": "policy",
                "backup": str(bak_verified),
                "approval": {
                    "message": msg.to_dict(),
                    "channel": ApprovalChannel.SSH_KEY.value,
                    "signer_id": rep.signer.signer_id,
                    "signature": _ssh_sig_b64(priv, msg.canonical_bytes()),
                },
            },
        )
        assert st_e == 200 and exec_env.get("ok") is True, (st_e, exec_env)
        return loop_obj.ready

    # Subcase 1c-match: Restore bak_verified WHILE disk checkout config still matches c_dig1/x_dig1 (no drift).
    # Restored policy MUST STILL fail-close both terminal & capture until explicitly re-verified!
    with _serve_daemon(cfg, os_, clock, mono) as (ready0, loop0):
        _publish_capture_creds(loop0, [(cap_c, "stream-claude-r-match", ws_a)])
        ready0 = _run_online_restore(ready0, loop0)

        st_same, app_same = _terminal_approve_proposal(ready0, ca_pem, cli_token, prop_same_cfg)
        assert app_same.get("ok") is False, (st_same, app_same)
        assert app_same["error"]["code"] == ErrorCode.CAPABILITY_UNAVAILABLE.value

        target0 = LoopbackTarget(
            endpoint=ready0.endpoint,
            expected_store_id=rep.store_id,
            ca_pem=ca_pem,
            leaf_cert_sha256=ready0.leaf_cert_sha256,
        )
        cap_client0 = CaptureClient(LoopbackClient(monotonic_ns=mono.monotonic_ns))
        ev_same = CaptureEventRecord(
            event_id="ev-l2-restored-match",
            producer_stream="stream-claude-r-match",
            sequence=1,
            harness_id="claude-code",
            kind="command_result",
            recorded_at="2026-11-26T14:04:01Z",
            payload={"cmd": "pytest"},
            source_metadata={"host_version": _CLAUDE_VER, "config_digest": c_dig1},
        ).to_dict()
        assert (
            cap_client0.post_batch(
                target0,
                CaptureBatchCommand("stream-claude-r-match", ws_a.repo_id, ws_a.checkout_id, (ev_same,), cap_c.token),
            ).accepted_count
            == 1
        )
        assert _capture_event_row(loop0, "ev-l2-restored-match") == ("unknown", "unverified")

        def _reverify_after_restore() -> None:
            session = cast(Any, loop0._session)
            assert session is not None
            assert (
                reconcile_harness_layer2_in_policy(
                    session._rt.policy,
                    harness_id="claude-code",
                    checkout_root=chk_a,
                    observed_host_version=_CLAUDE_VER,
                    os_=os_,
                    receipt=_build_receipt(harness_id="claude-code", host_version=_CLAUDE_VER, config_digest=c_dig1),
                )[0]
                is Layer2State.VERIFIED
            )
            assert (
                reconcile_harness_layer2_in_policy(
                    session._rt.policy,
                    harness_id="codex",
                    checkout_root=chk_a,
                    observed_host_version=_CODEX_VER,
                    os_=os_,
                    receipt=_build_receipt(harness_id="codex", host_version=_CODEX_VER, config_digest=x_dig1),
                )[0]
                is Layer2State.VERIFIED
            )

        loop0.run_owner_action(_reverify_after_restore).result(timeout=10.0)
        st_rv, app_rv = _terminal_approve_proposal(ready0, ca_pem, cli_token, prop_reverified)
        assert st_rv == 200 and app_rv.get("ok") is True, (st_rv, app_rv)

    # Mutate checkout on disk AFTER backup so restored policy row has stale c_dig1 != live c_dig2.
    settings_path = chk_a / ".claude" / "settings.local.json"
    settings_obj = json.loads(settings_path.read_text(encoding="utf-8"))
    settings_obj["permissions"]["allow"] = ["Bash(pytest *)"]
    settings_path.write_bytes(canonical_json(settings_obj))

    # Subcase 1c-live: Online /v2/operator/restore to bak_verified -> terminal & capture MUST fail closed immediately.
    clock.advance(timedelta(seconds=5))
    with _serve_daemon(cfg, os_, clock, mono) as (ready, loop):
        _publish_capture_creds(loop, [(cap_c, "stream-claude-r", ws_a)])
        ready = _run_online_restore(ready, loop)

        st_term_on, app_term_on = _terminal_approve_proposal(ready, ca_pem, cli_token, prop_online)
        assert app_term_on.get("ok") is False, (st_term_on, app_term_on)
        assert app_term_on["error"]["code"] == ErrorCode.CAPABILITY_UNAVAILABLE.value

        target = LoopbackTarget(
            endpoint=ready.endpoint,
            expected_store_id=rep.store_id,
            ca_pem=ca_pem,
            leaf_cert_sha256=ready.leaf_cert_sha256,
        )
        cap_client = CaptureClient(LoopbackClient(monotonic_ns=mono.monotonic_ns))
        ev_on = CaptureEventRecord(
            event_id="ev-l2-restored-on",
            producer_stream="stream-claude-r",
            sequence=1,
            harness_id="claude-code",
            kind="command_result",
            recorded_at="2026-11-26T14:05:01Z",
            payload={"cmd": "pytest"},
            source_metadata={"host_version": _CLAUDE_VER, "config_digest": c_dig1},
        ).to_dict()
        assert (
            cap_client.post_batch(
                target, CaptureBatchCommand("stream-claude-r", ws_a.repo_id, ws_a.checkout_id, (ev_on,), cap_c.token)
            ).accepted_count
            == 1
        )
        assert _capture_event_row(loop, "ev-l2-restored-on") == ("unknown", "unverified")

    # Subcase 1c-offline: Offline restore_policy + daemon restart -> terminal & capture STILL fail closed.
    clock.advance(timedelta(seconds=5))
    with maintenance_lease(data_root, os_) as (root_obj, lease):
        restore_policy(
            root_obj,
            lease,
            os_,
            bak_verified,
            store_id=rep.store_id,
            now=clock.now(),
            migrations=KERNEL_POLICY_MIGRATIONS,
        )

    with _serve_daemon(cfg, os_, clock, mono) as (ready2, loop2):
        _publish_capture_creds(loop2, [(cap_c, "stream-claude-r", ws_a)])
        st_term_off, app_term_off = _terminal_approve_proposal(ready2, ca_pem, cli_token, prop_offline)
        assert app_term_off.get("ok") is False, (st_term_off, app_term_off)
        assert app_term_off["error"]["code"] == ErrorCode.CAPABILITY_UNAVAILABLE.value

        target2 = LoopbackTarget(
            endpoint=ready2.endpoint,
            expected_store_id=rep.store_id,
            ca_pem=ca_pem,
            leaf_cert_sha256=ready2.leaf_cert_sha256,
        )
        cap_client2 = CaptureClient(LoopbackClient(monotonic_ns=mono.monotonic_ns))
        ev_off = CaptureEventRecord(
            event_id="ev-l2-restored-off",
            producer_stream="stream-claude-r",
            sequence=2,
            harness_id="claude-code",
            kind="command_result",
            recorded_at="2026-11-26T14:05:10Z",
            payload={"cmd": "pytest"},
            source_metadata={"host_version": _CLAUDE_VER, "config_digest": c_dig1},
        ).to_dict()
        assert (
            cap_client2.post_batch(
                target2, CaptureBatchCommand("stream-claude-r", ws_a.repo_id, ws_a.checkout_id, (ev_off,), cap_c.token)
            ).accepted_count
            == 1
        )
        assert _capture_event_row(loop2, "ev-l2-restored-off") == ("unknown", "unverified")


# ---------------------------------------------------------------------------
# P1 Finding 2: Production Bootstrap + Hook Adapter End-to-End
# ---------------------------------------------------------------------------


def test_p1_finding2_bootstrap_and_installed_hook_adapters_end_to_end(trusted_tmp: Path) -> None:
    """Bootstrapped checkout hooks invoke hook_entry + host adapters with strict checkout/transcript isolation."""
    clock = FakeClock(datetime.now(UTC).replace(microsecond=0))
    mono = FakeMonotonicClock(1_000_000_000)
    os_ = os_adapters(clock=clock, monotonic=mono)
    priv, s_enr = _ssh_signer()

    cfg_dir = trusted_tmp / "cfg"
    data_root = trusted_tmp / "data"
    chk_a = trusted_tmp / "chk-a"
    chk_b = trusted_tmp / "chk-b"
    prof_dir = trusted_tmp / "profiles"
    for d in (cfg_dir, chk_a, chk_b, prof_dir):
        d.mkdir(parents=True, exist_ok=True)
        os_.permissions.secure_directory(d)

    rep = init_entry.init_store(
        init_entry.InitRequest(
            data_root=data_root, config_dir=cfg_dir, owner_id=_OWNER, machine_id=_MACHINE, signer=s_enr
        ),
        os_,
    )
    cfg = read_daemon_config(rep.daemon_config_path, os_)
    ca_path = cfg_dir / "tls" / "ca.pem"
    ca_pem = ca_path.read_text(encoding="utf-8")
    cli_token = rep.cli_credential_path.read_text(encoding="ascii").strip()

    rt = reopen_kernel_job_runtime(data_root, rep.store_id, os_)
    try:
        mcp_c = seed_principal_and_credential(rt.policy, owner_id=_OWNER, harness_id="claude-code", machine_id=_MACHINE)
        mcp_x = seed_principal_and_credential(rt.policy, owner_id=_OWNER, harness_id="codex", machine_id=_MACHINE)
        cap_c = seed_principal_and_credential(rt.policy, owner_id=_OWNER, harness_id="claude-code", machine_id=_MACHINE)
        cap_x = seed_principal_and_credential(rt.policy, owner_id=_OWNER, harness_id="codex", machine_id=_MACHINE)
        ws_a = register_workspace_direct(
            rt,
            clock,
            mcp_c.principal,
            alias="ws-hook-a",
            checkout_dir=chk_a,
            remote="https://github.example/dan/repo-hook-a.git",
        )
        ws_b = register_workspace_direct(
            rt,
            clock,
            mcp_c.principal,
            alias="ws-hook-b",
            checkout_dir=chk_b,
            remote="https://github.example/dan/repo-hook-b.git",
        )
        for pid in (mcp_x.principal.principal_id, cap_x.principal.principal_id):
            seed_repo_grant(rt.policy, principal_id=pid, repo_id=ws_a.repo_id, owner_id=_OWNER)
            seed_repo_grant(rt.policy, principal_id=pid, repo_id=ws_b.repo_id, owner_id=_OWNER)
        rt.store.reconcile_policy()
    finally:
        rt.close()

    with _serve_daemon(cfg, os_, clock, mono) as (ready, loop):
        _publish_capture_creds(
            loop,
            [
                (cap_c, "stream-claude-a", ws_a),
                (cap_x, "stream-codex-a", ws_a),
            ],
        )

        # Build isolated ClientProfile files for (chk_a, chk_b) x (claude-code, codex) and bootstrap via /v2/operator.
        ep_path = data_root / "endpoint.json"
        cred_c_file = write_credential_file(prof_dir / "claude.cred", mcp_c.token)
        cred_x_file = write_credential_file(prof_dir / "codex.cred", mcp_x.token)

        def _make_profile(name: str, cred_file: Path, ws: WorkspaceBinding, chk: Path) -> Path:
            p, _ = write_client_profile_file(
                prof_dir / name,
                endpoint_path=ep_path,
                expected_store_id=rep.store_id,
                ca_file=ca_path,
                leaf_cert_sha256=ready.leaf_cert_sha256,
                credential_file=cred_file,
                workspace={
                    "alias": ws.alias,
                    "expected_workspace_id": ws.repo_id,
                    "expected_checkout_id": ws.checkout_id,
                    "checkout_path": str(chk),
                },
            )
            return p

        profiles = {
            ("chk_a", "claude-code"): _make_profile("a-claude.json", cred_c_file, ws_a, chk_a),
            ("chk_a", "codex"): _make_profile("a-codex.json", cred_x_file, ws_a, chk_a),
            ("chk_b", "claude-code"): _make_profile("b-claude.json", cred_c_file, ws_b, chk_b),
            ("chk_b", "codex"): _make_profile("b-codex.json", cred_x_file, ws_b, chk_b),
        }

        # Direct planner sanity check also requires executable hook_entry commands.
        direct_c = plan_claude_bootstrap(checkout_root=chk_a, profile_path=profiles[("chk_a", "claude-code")])
        direct_x = plan_codex_bootstrap(checkout_root=chk_a, profile_path=profiles[("chk_a", "codex")])
        assert any(
            t.rel_path == ".claude/settings.local.json" and "superbrain.composition.hook_entry" in t.preview_text
            for t in direct_c.targets
        ), "plan_claude_bootstrap must emit executable capture hook command via build_capture_hook_command"
        assert any(
            t.rel_path == ".codex/hooks.json" and "superbrain.composition.hook_entry" in t.preview_text
            for t in direct_x.targets
        ), "plan_codex_bootstrap must emit executable capture hook command via build_capture_hook_command"

        def _bootstrap_approve_apply(harness: str, chk: Path, prof: Path) -> None:
            st_b, b_env = _post_tls(
                ready,
                ca_pem,
                "/v2/operator/proposal/bootstrap",
                cli_token,
                {"harness": harness, "checkout_root": str(chk), "harness_profile_path": str(prof)},
            )
            assert st_b == 200 and b_env.get("ok") is True, (st_b, b_env)
            pid = str(b_env["data"]["proposal"]["proposal_id"])

            for op_path in ("/v2/operator/proposal/approve", "/v2/operator/proposal/apply"):
                st_c, ch_env = _post_tls(ready, ca_pem, op_path, cli_token, {"proposal_id": pid})
                assert st_c == 200 and ch_env.get("ok") is True, (op_path, ch_env)
                ch = cast(dict[str, Any], ch_env["data"]["challenge"])
                msg = ApprovalMessage.from_dict(ch)
                st_x, ex_env = _post_tls(
                    ready,
                    ca_pem,
                    op_path,
                    cli_token,
                    {
                        "proposal_id": pid,
                        "approval": {
                            "message": ch,
                            "channel": ApprovalChannel.SSH_KEY.value,
                            "signer_id": rep.signer.signer_id,
                            "signature": _ssh_sig_b64(priv, msg.canonical_bytes()),
                        },
                    },
                )
                assert st_x == 200 and ex_env.get("ok") is True, (op_path, ex_env)

        _bootstrap_approve_apply("claude-code", chk_a, profiles[("chk_a", "claude-code")])
        _bootstrap_approve_apply("codex", chk_a, profiles[("chk_a", "codex")])
        _bootstrap_approve_apply("claude-code", chk_b, profiles[("chk_b", "claude-code")])
        _bootstrap_approve_apply("codex", chk_b, profiles[("chk_b", "codex")])

        # Inspect bootstrapped hook configs on chk_a & chk_b.
        cfg_a_claude = json.loads((chk_a / ".claude" / "settings.local.json").read_text(encoding="utf-8"))
        cfg_b_claude = json.loads((chk_b / ".claude" / "settings.local.json").read_text(encoding="utf-8"))
        cfg_a_codex = json.loads((chk_a / ".codex" / "hooks.json").read_text(encoding="utf-8"))
        cfg_b_codex = json.loads((chk_b / ".codex" / "hooks.json").read_text(encoding="utf-8"))

        # Host schema: per managed event one all-tools matcher group with a command handler; all 11 ask rules.
        for cfg_obj in (cfg_a_claude, cfg_b_claude, cfg_a_codex, cfg_b_codex):
            for event in MANAGED_HOOK_EVENTS:
                groups = cfg_obj["hooks"][event]
                assert isinstance(groups, list) and len(groups) == 1 and groups[0]["matcher"] == "*"
                assert [h["type"] for h in groups[0]["hooks"]] == ["command"]
        assert len(cfg_a_claude["permissions"]["ask"]) == len(AUTHORITY_ASK_COMMANDS)

        cmds_a_claude = _find_hook_commands(cfg_a_claude)
        cmds_b_claude = _find_hook_commands(cfg_b_claude)
        cmds_a_codex = _find_hook_commands(cfg_a_codex)
        cmds_b_codex = _find_hook_commands(cfg_b_codex)
        assert cmds_a_claude and cmds_b_claude and cmds_a_codex and cmds_b_codex

        cmd_a_claude = cmds_a_claude[0]
        cmd_b_claude = cmds_b_claude[0]
        cmd_a_codex = cmds_a_codex[0]
        cmd_b_codex = cmds_b_codex[0]

        assert _extract_harness_arg(cmd_a_claude) == "claude-code"
        assert _extract_harness_arg(cmd_a_codex) == "codex"
        outbox_a_claude = Path(_extract_outbox_arg(cmd_a_claude))
        outbox_b_claude = Path(_extract_outbox_arg(cmd_b_claude))
        outbox_a_codex = Path(_extract_outbox_arg(cmd_a_codex))
        outbox_b_codex = Path(_extract_outbox_arg(cmd_b_codex))
        assert outbox_a_claude.resolve() != outbox_b_claude.resolve()
        assert outbox_a_codex.resolve() != outbox_b_codex.resolve()

        def _invoke_hook(cmd: list[str], payload: dict[str, Any], *, cwd: Path) -> None:
            run_cmd = [sys.executable, *cmd[1:]] if Path(cmd[0]).name.lower().startswith("python") else cmd
            t0 = time.perf_counter()
            proc = subprocess.run(
                run_cmd,
                cwd=cwd,
                env=clean_installed_subprocess_env(),
                input=json.dumps(payload).encode("utf-8"),
                capture_output=True,
                timeout=5.0,
                check=False,
            )
            elapsed = time.perf_counter() - t0
            assert proc.returncode == 0
            assert elapsed < 2.0

        # Prepare transcripts: one valid in allowed dir, one outside allowed root, one with chk_b cross-leak.
        outside_tr = chk_b / "outside-transcript.jsonl"
        outside_tr.write_text(
            json.dumps(
                {
                    "event_id": "tr-outside-1",
                    "event_name": "UserPromptSubmit",
                    "recorded_at": "2026-11-26T14:10:00Z",
                    "cwd": str(chk_b),
                    "payload": {"role": "user", "text": "SECRET_OUTSIDE_CHK_B"},
                }
            )
            + "\n",
            encoding="utf-8",
        )

        # Positive case: native-shaped payloads for BOTH claude-code and codex in chk_a.
        target = LoopbackTarget(
            endpoint=ready.endpoint,
            expected_store_id=rep.store_id,
            ca_pem=ca_pem,
            leaf_cert_sha256=ready.leaf_cert_sha256,
        )
        cap_client = CaptureClient(LoopbackClient(monotonic_ns=mono.monotonic_ns))

        for harness_id, cmd_a, outbox_a, stream, cred, event_name, ev_id in (
            ("claude-code", cmd_a_claude, outbox_a_claude, "stream-claude-a", cap_c, "PostToolUse", "ev-hook-c-1"),
            ("codex", cmd_a_codex, outbox_a_codex, "stream-codex-a", cap_x, "command_completed", "ev-hook-x-1"),
        ):
            _invoke_hook(
                cmd_a,
                {
                    "event_id": ev_id,
                    "sequence": 1,
                    "event_name": event_name,
                    "recorded_at": "2026-11-26T14:11:00Z",
                    "cwd": str(chk_a),
                    "producer_stream": stream,
                    "session_id": "RAW_NATIVE_SID_MUST_NOT_LEAK",
                    "payload": {"command": "pytest -q", "exit_code": 0},
                    "channel_kind": "local_capture",
                },
                cwd=chk_a,
            )
            spool = OutboxSpool(outbox_a, permissions=os_.permissions)
            pending = spool.read_pending(limit=10, producer_stream=stream)
            assert len(pending) >= 1, f"{harness_id} hook must enqueue normalized event into {outbox_a}"
            assert all("RAW_NATIVE_SID_MUST_NOT_LEAK" not in entry.payload_json for entry in pending)

            ack = drain_outbox(
                spool,
                client=cap_client,
                target=target,
                producer_stream=stream,
                repo_id=ws_a.repo_id,
                checkout_id=ws_a.checkout_id,
                token=cred.token,
            )
            assert ack is not None and ack.accepted_count >= 1
            assert spool.read_pending(limit=10, producer_stream=stream) == []

            # Workspace switch (cwd = chk_b sent to chk_a's hook) -> rc=0, 0 events written to chk_a outbox.
            _invoke_hook(
                cmd_a,
                {
                    "event_id": f"{ev_id}-wrong-ws",
                    "sequence": 2,
                    "event_name": event_name,
                    "recorded_at": "2026-11-26T14:11:05Z",
                    "cwd": str(chk_b),
                    "producer_stream": stream,
                    "payload": {"command": "echo secret-b"},
                },
                cwd=chk_b,
            )
            assert spool.read_pending(limit=10, producer_stream=stream) == []

            # Transcript mismatch (pointing outside allowed root / chk_b data) -> zero chk_b leak.
            _invoke_hook(
                cmd_a,
                {
                    "event_id": f"{ev_id}-tr-mismatch",
                    "sequence": 3,
                    "event_name": event_name,
                    "recorded_at": "2026-11-26T14:11:10Z",
                    "cwd": str(chk_a),
                    "producer_stream": stream,
                    "transcript_path": str(outside_tr),
                    "payload": {"command": "pytest"},
                },
                cwd=chk_a,
            )
            after_tr = spool.read_pending(limit=10, producer_stream=stream)
            assert all("SECRET_OUTSIDE_CHK_B" not in entry.payload_json for entry in after_tr)

            # Missing evidence / unknown native event kind -> fail-closed (no promoted sent_to_recipient/tool_observed).
            _invoke_hook(
                cmd_a,
                {
                    "event_id": f"{ev_id}-unknown-kind",
                    "sequence": 4,
                    "event_name": "UndocumentedHostEvent",
                    "recorded_at": "2026-11-26T14:11:15Z",
                    "cwd": str(chk_a),
                    "producer_stream": stream,
                    "channel_kind": "model_io",
                    "exposure_evidence": "sent_to_recipient",
                    "payload": {"note": "missing model call"},
                },
                cwd=chk_a,
            )
            after_unk = spool.read_pending(limit=10, producer_stream=stream)
            assert all('"exposure_evidence": "sent_to_recipient"' not in entry.payload_json for entry in after_unk)

        # Verify drained events landed in brain.db without raw session_id or chk_b secrets.
        def _db_check() -> None:
            session = cast(Any, loop._session)
            assert session is not None
            rows = session._rt.store._db.execute(
                "SELECT event_id, source, source_verification FROM capture_events ORDER BY sequence"
            ).fetchall()
            ids = {str(r[0]) for r in rows}
            assert "ev-hook-c-1" in ids and "ev-hook-x-1" in ids

        loop.run_owner_action(_db_check).result(timeout=10.0)


# ---------------------------------------------------------------------------
# P2 Finding 3: Production doctor CLI & MCP get_health(deep=true)
# ---------------------------------------------------------------------------


def test_p2_finding3_doctor_cli_sp2_diagnostics_and_readonly_preservation(trusted_tmp: Path) -> None:
    """Production doctor CLI & run_doctor report SP2 outbox/gaps/sessions/Layer-2 read-only."""
    clock = FakeClock(datetime.now(UTC).replace(microsecond=0))
    mono = FakeMonotonicClock(1_000_000_000)
    os_ = os_adapters(clock=clock, monotonic=mono)
    _priv, s_enr = _ssh_signer()

    cfg_dir = trusted_tmp / "cfg"
    data_root = trusted_tmp / "data"
    chk_a = trusted_tmp / "chk-doc"
    outbox_dir = trusted_tmp / "outbox-doc"
    for d in (cfg_dir, chk_a):
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

    prof_path = cfg_dir / "claude-profile.json"
    _write_plan_targets(chk_a, plan_claude_bootstrap(checkout_root=chk_a, profile_path=prof_path).targets)
    c_dig1 = compute_harness_config_digest("claude-code", chk_a, os_)
    assert c_dig1 is not None

    rt = reopen_kernel_job_runtime(data_root, rep.store_id, os_)
    try:
        mcp_c = seed_principal_and_credential(rt.policy, owner_id=_OWNER, harness_id="claude-code", machine_id=_MACHINE)
        cap_c = seed_principal_and_credential(rt.policy, owner_id=_OWNER, harness_id="claude-code", machine_id=_MACHINE)
        ws_a = register_workspace_direct(rt, clock, mcp_c.principal, alias="ws-doc-prod", checkout_dir=chk_a)
        rt.store.reconcile_policy()
        reconcile_harness_layer2_in_policy(
            rt.policy,
            harness_id="claude-code",
            checkout_root=chk_a,
            observed_host_version=_CLAUDE_VER,
            os_=os_,
            receipt=_build_receipt(harness_id="claude-code", host_version=_CLAUDE_VER, config_digest=c_dig1),
        )
        SessionStore(rt.store, rt.policy).bind_session(
            principal_id=mcp_c.principal.principal_id,
            repo_id=ws_a.repo_id,
            checkout_id=ws_a.checkout_id,
            harness_id="claude-code",
            raw_session_id="RAW_DOC_PROD_SID",
            now=clock.now(),
        )
    finally:
        rt.close()

    # Seed pending outbox event + open daemon gap via out-of-order capture batch (seq 1, 3 omitting 2).
    spool = OutboxSpool(outbox_dir, permissions=os_.permissions)
    spool.enqueue_event(
        CaptureEventRecord(
            event_id="ev-doc-pending-1",
            producer_stream="stream-doc-prod",
            sequence=2,
            harness_id="claude-code",
            kind="tool_post",
            recorded_at="2026-11-26T14:20:02Z",
            payload={"pending": True},
        )
    )
    with _serve_daemon(cfg, os_, clock, mono) as (ready, loop):
        _publish_capture_creds(loop, [(cap_c, "stream-doc-prod", ws_a)])
        target = LoopbackTarget(
            endpoint=ready.endpoint,
            expected_store_id=rep.store_id,
            ca_pem=ca_pem,
            leaf_cert_sha256=ready.leaf_cert_sha256,
        )
        cap_client = CaptureClient(LoopbackClient(monotonic_ns=mono.monotonic_ns))
        evs = tuple(
            CaptureEventRecord(
                event_id=f"ev-doc-ooo-{seq}",
                producer_stream="stream-doc-prod",
                sequence=seq,
                harness_id="claude-code",
                kind="tool_post",
                recorded_at=f"2026-11-26T14:20:0{seq}Z",
                payload={"seq": seq},
            ).to_dict()
            for seq in (1, 3)
        )
        ack = cap_client.post_batch(
            target,
            CaptureBatchCommand("stream-doc-prod", ws_a.repo_id, ws_a.checkout_id, evs, cap_c.token),
        )
        assert ack.accepted_count == 2

    # Mutate checkout config on disk so Layer-2 is drifted.
    settings_path = chk_a / ".claude" / "settings.local.json"
    settings_obj = json.loads(settings_path.read_text(encoding="utf-8"))
    settings_obj["permissions"]["allow"] = ["Bash(pytest *)"]
    settings_path.write_bytes(canonical_json(settings_obj))

    snap_data = digest_tree(data_root)
    snap_outbox = digest_tree(outbox_dir)
    snap_chk = digest_tree(chk_a)

    # Run real isolated doctor CLI.
    proc = subprocess.run(
        [
            sys.executable,
            "-I",
            "-m",
            "superbrain.cli.main",
            "doctor",
            "--config",
            str(rep.daemon_config_path),
            "--checkout",
            str(chk_a),
            "--json",
        ],
        env=clean_installed_subprocess_env(),
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=15.0,
        check=False,
    )
    assert proc.returncode == 0, (proc.returncode, proc.stderr)
    parsed = json.loads(proc.stdout)
    assert parsed.get("ok") is True, parsed
    doc_data = parsed["data"]

    # Also test run_doctor directly (passing outbox_dir if supported).
    sig_params = inspect.signature(run_doctor).parameters
    if "outbox_dir" in sig_params:
        direct_report = cast(Any, run_doctor)(
            rep.daemon_config_path, checkout_root=chk_a, outbox_dir=outbox_dir, os_=os_
        )
        doc_data = direct_report.to_dict()

    sp2_view = doc_data.get("sp2") if isinstance(doc_data.get("sp2"), dict) else doc_data
    assert "gaps" in sp2_view, f"doctor JSON missing SP2 gaps diagnostics: {list(doc_data)}"
    assert "sessions" in sp2_view, f"doctor JSON missing SP2 sessions diagnostics: {list(doc_data)}"
    assert "outbox" in sp2_view, f"doctor JSON missing SP2 outbox diagnostics: {list(doc_data)}"
    assert "terminal_channel_eligible_effective" in sp2_view
    assert sp2_view["gaps"]["open_daemon_gaps"] >= 1
    assert sp2_view["sessions"]["total_sessions"] >= 1
    assert sp2_view["terminal_channel_eligible_effective"] is False
    assert "RAW_DOC_PROD_SID" not in proc.stdout

    # Strict read-only invariant: zero bytes created, modified, or deleted.
    assert digest_tree(data_root) == snap_data
    assert digest_tree(outbox_dir) == snap_outbox
    assert digest_tree(chk_a) == snap_chk


def test_p2_finding3_mcp_get_health_deep_and_shallow_contracts(trusted_tmp: Path) -> None:
    """MCP get_health(deep=true) returns schema-valid SP2 diagnostics without mutating domain tables."""
    tpl = get_shared_t7_transport_template()
    ws_a = tpl.ws_a
    assert ws_a is not None

    with open_test_loopback_transport(tpl, name="sp25-deep-health", domain=None) as h:
        def _seed_sp2_state() -> SeededCredential:
            session = cast(Any, h.loop._session)
            assert session is not None
            rt = session._rt
            cap_c = seed_principal_and_credential(
                rt.policy, owner_id="dan", harness_id="claude-code", machine_id="m-1"
            )
            seed_repo_grant(rt.policy, principal_id=cap_c.principal.principal_id, repo_id=ws_a.repo_id, owner_id="dan")
            snap = rt.policy.snapshot()
            merged = dict(snap.credentials)
            merged[cap_c.credential_id] = replace(
                merged[cap_c.credential_id],
                capabilities=frozenset({CAPABILITY_CAPTURE_PRODUCER}),
                capture_binding=CaptureProducerBinding("stream-deep-health", ws_a.repo_id, ws_a.checkout_id),
            )
            session.auth_gate.publish(replace(snap, credentials=merged))
            SessionStore(rt.store, rt.policy).bind_session(
                principal_id=h.cred.principal.principal_id,
                repo_id=ws_a.repo_id,
                checkout_id=ws_a.checkout_id,
                harness_id="claude-code",
                raw_session_id="RAW_DEEP_HEALTH_SID",
                now=h.clock.now(),
            )
            return cap_c

        cap_c = h.loop.run_owner_action(_seed_sp2_state).result(timeout=10.0)
        target = h.make_target()
        cap_client = CaptureClient(h.open_client())

        # Create an open daemon CaptureGap (seq 1 and 3, omitting 2).
        evs = tuple(
            CaptureEventRecord(
                event_id=f"ev-dh-{seq}",
                producer_stream="stream-deep-health",
                sequence=seq,
                harness_id="claude-code",
                kind="tool_post",
                recorded_at=f"2026-11-26T14:30:0{seq}Z",
                payload={"seq": seq},
            ).to_dict()
            for seq in (1, 3)
        )
        assert (
            cap_client.post_batch(
                target,
                CaptureBatchCommand("stream-deep-health", ws_a.repo_id, ws_a.checkout_id, evs, cap_c.token),
            ).accepted_count
            == 2
        )

        def _snapshot_domain_tables() -> dict[str, list[tuple[Any, ...]]]:
            session = cast(Any, h.loop._session)
            assert session is not None
            db = session._rt.store._db
            pol_db = session._rt.policy._db
            return {
                "capture_events": db.execute("SELECT * FROM capture_events ORDER BY event_id").fetchall(),
                "capture_gaps": db.execute("SELECT * FROM capture_gaps ORDER BY gap_id").fetchall(),
                "sessions": db.execute("SELECT * FROM sessions ORDER BY session_ref").fetchall(),
                "task_handoffs": db.execute("SELECT * FROM task_handoffs ORDER BY task_id").fetchall(),
                "harness_layer2_state": pol_db.execute("SELECT * FROM harness_layer2_state ORDER BY seq").fetchall(),
            }

        before_tables = h.loop.run_owner_action(_snapshot_domain_tables).result(timeout=10.0)

        # Shallow get_health(deep=False) still succeeds fast without idempotency_key.
        shallow = h.open_client().call(
            target,
            ToolCommand(
                tool="get_health",
                arguments={"schema_version": SCHEMA_VERSION, "deep": False},
                token=tpl.cred.token,
                selected_scope=None,
            ),
        )
        assert shallow.get("ok") is True, shallow
        shallow_data = cast(dict[str, Any], shallow["data"])
        _validate_get_health_schema(shallow_data)
        assert "capture_gap_present" in shallow_data["degraded_codes"]

        # Deep get_health(deep=True) must succeed (NOT CAPABILITY_UNAVAILABLE) and match GetHealthResult schema.
        deep = h.open_client().call(
            target,
            ToolCommand(
                tool="get_health",
                arguments={
                    "schema_version": SCHEMA_VERSION,
                    "deep": True,
                    "idempotency_key": f"idem-deep-health-{new_id()}",
                },
                token=tpl.cred.token,
                selected_scope=None,
            ),
        )
        assert deep.get("ok") is True, deep
        deep_data = cast(dict[str, Any], deep["data"])
        _validate_get_health_schema(deep_data)
        assert deep_data["store_id"] == h.store_id
        assert deep_data["writer_epoch"] == h.ready.identity.writer_epoch
        assert deep_data["schema_version"] == 8
        assert deep_data["policy_schema_version"] == 5
        assert "capture_gap_present" in deep_data["degraded_codes"]
        assert any(
            "layer2" in str(code) or "terminal" in str(code) or "unverified" in str(code)
            for code in deep_data["degraded_codes"]
        ), deep_data["degraded_codes"]

        # Domain tables must NOT be mutated by get_health(deep=True).
        after_tables = h.loop.run_owner_action(_snapshot_domain_tables).result(timeout=10.0)
        assert after_tables == before_tables


# ---------------------------------------------------------------------------
# Round-4 Review Regressions (4 findings: malformed host_version, deleted/broken link,
# hook session_ref & raw key sanitization, multi-checkout doctor/deep health parity)
# ---------------------------------------------------------------------------


def _make_dangling_claude_link(checkout_root: Path) -> None:
    """Create a real dangling junction (Windows) or symlink (POSIX) at ``checkout_root/.claude``."""
    link_path = checkout_root / ".claude"
    if sys.platform == "win32":
        import _winapi

        missing_target = checkout_root.parent / f"_missing_target_{new_id()}"
        missing_target.mkdir(parents=True, exist_ok=True)
        _winapi.CreateJunction(str(missing_target), str(link_path))
        missing_target.rmdir()
    else:
        link_path.symlink_to(checkout_root.parent / f"_missing_target_{new_id()}", target_is_directory=True)


def _remove_dangling_claude_link(checkout_root: Path) -> None:
    link_path = checkout_root / ".claude"
    if not os.path.lexists(link_path):
        return
    if link_path.is_symlink():
        link_path.unlink()
    else:
        link_path.rmdir()
    assert not os.path.lexists(link_path)


def test_r4_finding1_malformed_host_version_and_resolver_error_fail_closed(trusted_tmp: Path) -> None:
    """Non-opaque/empty/overlong host_version or crashing resolver fails closed to UNKNOWN, never INVALID_INPUT."""
    clock = FakeClock(datetime.now(UTC).replace(microsecond=0))
    mono = FakeMonotonicClock(1_000_000_000)
    os_ = os_adapters(clock=clock, monotonic=mono)
    _priv, s_enr = _ssh_signer()

    cfg_dir = trusted_tmp / "cfg"
    data_root = trusted_tmp / "data"
    chk_a = trusted_tmp / "chk-r4-f1"
    home_dir = trusted_tmp / "home"
    for d in (cfg_dir, chk_a, home_dir):
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

    prof_path = cfg_dir / "claude-profile.json"
    _write_plan_targets(chk_a, plan_claude_bootstrap(checkout_root=chk_a, profile_path=prof_path).targets)
    c_dig1 = compute_harness_config_digest("claude-code", chk_a, os_)
    assert c_dig1 is not None

    rt = reopen_kernel_job_runtime(data_root, rep.store_id, os_)
    try:
        mcp_c = seed_principal_and_credential(rt.policy, owner_id=_OWNER, harness_id="claude-code", machine_id=_MACHINE)
        cap_c = seed_principal_and_credential(rt.policy, owner_id=_OWNER, harness_id="claude-code", machine_id=_MACHINE)
        ws_a = register_workspace_direct(rt, clock, mcp_c.principal, alias="ws-r4-f1", checkout_dir=chk_a)
        rt.store.reconcile_policy()

        def _reverify_c1() -> None:
            st, _ = reconcile_harness_layer2_in_policy(
                rt.policy,
                harness_id="claude-code",
                checkout_root=chk_a,
                observed_host_version=_CLAUDE_VER,
                os_=os_,
                receipt=_build_receipt(harness_id="claude-code", host_version=_CLAUDE_VER, config_digest=c_dig1),
            )
            assert st is Layer2State.VERIFIED

        # Direct verify_live_layer2_harness checks for non-opaque values & resolver error.
        for bad_ver in ("2.1.326 (Claude Code)", "", "v" + "9" * 130, "2.1.325-\u00e9"):
            _reverify_c1()
            res = verify_live_layer2_harness(
                rt.policy,
                harness_id="claude-code",
                os_=os_,
                repo_id=ws_a.repo_id,
                checkout_id=ws_a.checkout_id,
                reported_host_version=bad_ver,
            )
            assert res is None
            latest = rt.policy.layer2_state("claude-code")
            assert latest is not None and latest[3] is Layer2State.UNKNOWN

        _reverify_c1()

        def _boom(_hid: str) -> str | None:
            raise RuntimeError("host version probe crashed")

        res_err = verify_live_layer2_harness(
            rt.policy,
            harness_id="claude-code",
            os_=os_,
            repo_id=ws_a.repo_id,
            checkout_id=ws_a.checkout_id,
            host_version_resolver=_boom,
        )
        assert res_err is None
        latest_err = rt.policy.layer2_state("claude-code")
        assert latest_err is not None and latest_err[3] is Layer2State.UNKNOWN

        # Re-verify cleanly for live daemon HTTP capture + terminal approval checks.
        _reverify_c1()
        prop_space = _create_low_risk_proposal(
            rt, os_, data_root=data_root, home=home_dir, checkout=chk_a, note_name="r4-f1-space.md"
        )
        prop_long = _create_low_risk_proposal(
            rt, os_, data_root=data_root, home=home_dir, checkout=chk_a, note_name="r4-f1-long.md"
        )
    finally:
        rt.close()

    with _serve_daemon(cfg, os_, clock, mono) as (ready, loop):
        _publish_capture_creds(loop, [(cap_c, "stream-r4-f1", ws_a)])
        target = LoopbackTarget(
            endpoint=ready.endpoint,
            expected_store_id=rep.store_id,
            ca_pem=ca_pem,
            leaf_cert_sha256=ready.leaf_cert_sha256,
        )
        cap_client = CaptureClient(LoopbackClient(monotonic_ns=mono.monotonic_ns))

        def _send_ver(seq: int, event_id: str, host_ver: str) -> None:
            ev = CaptureEventRecord(
                event_id=event_id,
                producer_stream="stream-r4-f1",
                sequence=seq,
                harness_id="claude-code",
                kind="command_result",
                recorded_at=f"2026-11-26T16:00:{seq:02d}Z",
                payload={"cmd": "pytest", "seq": seq},
                source_metadata={"host_version": host_ver, "config_digest": c_dig1},
            ).to_dict()
            ack = cap_client.post_batch(
                target,
                CaptureBatchCommand("stream-r4-f1", ws_a.repo_id, ws_a.checkout_id, (ev,), cap_c.token),
            )
            assert ack.accepted_count == 1

        # 1) Non-opaque version with spaces/parens via live capture MUST succeed ingestion as ("unknown", "unverified")
        # and immediately refuse terminal approvals.
        _send_ver(1, "ev-r4-f1-space", "2.1.326 (Claude Code)")
        assert _capture_event_row(loop, "ev-r4-f1-space") == ("unknown", "unverified")

        st_sp, app_sp = _terminal_approve_proposal(ready, ca_pem, cli_token, prop_space)
        assert app_sp.get("ok") is False, (st_sp, app_sp)
        assert app_sp["error"]["code"] == ErrorCode.CAPABILITY_UNAVAILABLE.value

        # 2) Re-verify live on owner loop, then send overlong (>128) host_version -> still fails closed without error.
        def _reverify_live() -> None:
            session = cast(Any, loop._session)
            assert session is not None
            st, _ = reconcile_harness_layer2_in_policy(
                session._rt.policy,
                harness_id="claude-code",
                checkout_root=chk_a,
                observed_host_version=_CLAUDE_VER,
                os_=os_,
                receipt=_build_receipt(harness_id="claude-code", host_version=_CLAUDE_VER, config_digest=c_dig1),
            )
            assert st is Layer2State.VERIFIED

        loop.run_owner_action(_reverify_live).result(timeout=10.0)
        _send_ver(2, "ev-r4-f1-long", "a" * 130)
        assert _capture_event_row(loop, "ev-r4-f1-long") == ("unknown", "unverified")

        st_ln, app_ln = _terminal_approve_proposal(ready, ca_pem, cli_token, prop_long)
        assert app_ln.get("ok") is False, (st_ln, app_ln)
        assert app_ln["error"]["code"] == ErrorCode.CAPABILITY_UNAVAILABLE.value


def test_r4_finding2_deleted_config_and_dangling_link_across_restart_and_restore(
    trusted_tmp: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Deleted checkout config & dangling links fail closed across fresh daemon restart and consecutive restores."""
    _install_fake_host_bins(trusted_tmp, monkeypatch)
    clock = FakeClock(datetime.now(UTC).replace(microsecond=0))
    mono = FakeMonotonicClock(1_000_000_000)
    os_ = os_adapters(clock=clock, monotonic=mono)
    priv, s_enr = _ssh_signer()

    cfg_dir = trusted_tmp / "cfg"
    data_root = trusted_tmp / "data"
    chk_a = trusted_tmp / "chk-r4-f2"
    home_dir = trusted_tmp / "home"
    for d in (cfg_dir, chk_a, home_dir):
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

    prof_path = cfg_dir / "claude-profile.json"
    _write_plan_targets(chk_a, plan_claude_bootstrap(checkout_root=chk_a, profile_path=prof_path).targets)
    c_dig1 = compute_harness_config_digest("claude-code", chk_a, os_)
    assert c_dig1 is not None

    rt = reopen_kernel_job_runtime(data_root, rep.store_id, os_)
    try:
        mcp_c = seed_principal_and_credential(rt.policy, owner_id=_OWNER, harness_id="claude-code", machine_id=_MACHINE)
        cap_c = seed_principal_and_credential(rt.policy, owner_id=_OWNER, harness_id="claude-code", machine_id=_MACHINE)
        ws_a = register_workspace_direct(rt, clock, mcp_c.principal, alias="ws-r4-f2", checkout_dir=chk_a)
        rt.store.reconcile_policy()
        assert (
            reconcile_harness_layer2_in_policy(
                rt.policy,
                harness_id="claude-code",
                checkout_root=chk_a,
                observed_host_version=_CLAUDE_VER,
                os_=os_,
                receipt=_build_receipt(harness_id="claude-code", host_version=_CLAUDE_VER, config_digest=c_dig1),
            )[0]
            is Layer2State.VERIFIED
        )
        bak_verified = create_policy_backup(rt.policy, os_, clock.now())
        prop_base = _create_low_risk_proposal(
            rt, os_, data_root=data_root, home=home_dir, checkout=chk_a, note_name="f2-base.md"
        )
        prop_del = _create_low_risk_proposal(
            rt, os_, data_root=data_root, home=home_dir, checkout=chk_a, note_name="f2-del.md"
        )
        prop_lnk = _create_low_risk_proposal(
            rt, os_, data_root=data_root, home=home_dir, checkout=chk_a, note_name="f2-lnk.md"
        )
        prop_r1 = _create_low_risk_proposal(
            rt, os_, data_root=data_root, home=home_dir, checkout=chk_a, note_name="f2-r1.md"
        )
        prop_r2_ok = _create_low_risk_proposal(
            rt, os_, data_root=data_root, home=home_dir, checkout=chk_a, note_name="f2-r2-ok.md"
        )
        prop_r2_del = _create_low_risk_proposal(
            rt, os_, data_root=data_root, home=home_dir, checkout=chk_a, note_name="f2-r2-del.md"
        )
    finally:
        rt.close()

    # Daemon 1: confirm positive baseline while config is present (persisting configured-checkout marker).
    with _serve_daemon(cfg, os_, clock, mono) as (ready1, loop1):
        _publish_capture_creds(loop1, [(cap_c, "stream-r4-f2", ws_a)])
        st_b, app_b = _terminal_approve_proposal(ready1, ca_pem, cli_token, prop_base)
        assert st_b == 200 and app_b.get("ok") is True, (st_b, app_b)

    # Delete .claude AND CLAUDE.md completely while daemon is stopped.
    shutil.rmtree(chk_a / ".claude")
    (chk_a / "CLAUDE.md").unlink()

    # Daemon 2: fresh start with deleted config MUST fail closed on capture, terminal, AND doctor (with/without
    # checkout).
    clock.advance(timedelta(seconds=5))
    with _serve_daemon(cfg, os_, clock, mono) as (ready2, loop2):
        _publish_capture_creds(loop2, [(cap_c, "stream-r4-f2", ws_a)])
        target2 = LoopbackTarget(
            endpoint=ready2.endpoint,
            expected_store_id=rep.store_id,
            ca_pem=ca_pem,
            leaf_cert_sha256=ready2.leaf_cert_sha256,
        )
        cap_client2 = CaptureClient(LoopbackClient(monotonic_ns=mono.monotonic_ns))
        ev_del = CaptureEventRecord(
            event_id="ev-r4-f2-deleted",
            producer_stream="stream-r4-f2",
            sequence=1,
            harness_id="claude-code",
            kind="command_result",
            recorded_at="2026-11-26T16:02:01Z",
            payload={"cmd": "pytest"},
            source_metadata={"host_version": _CLAUDE_VER, "config_digest": c_dig1},
        ).to_dict()
        assert (
            cap_client2.post_batch(
                target2, CaptureBatchCommand("stream-r4-f2", ws_a.repo_id, ws_a.checkout_id, (ev_del,), cap_c.token)
            ).accepted_count
            == 1
        )
        assert _capture_event_row(loop2, "ev-r4-f2-deleted") == ("unknown", "unverified")

        st_d, app_d = _terminal_approve_proposal(ready2, ca_pem, cli_token, prop_del)
        assert app_d.get("ok") is False, (st_d, app_d)
        assert app_d["error"]["code"] == ErrorCode.CAPABILITY_UNAVAILABLE.value

    for doc_chk in (None, chk_a):
        doc_del = run_doctor(rep.daemon_config_path, checkout_root=doc_chk, os_=os_)
        assert doc_del.terminal_channel_eligible is False
        assert {h.harness_id: h.state for h in doc_del.layer2_harnesses}["claude-code"] is Layer2State.UNKNOWN

    # Part B: Replace .claude with a dangling link -> fail closed on verify_live_layer2_harness, daemon, & doctor.
    _make_dangling_claude_link(chk_a)
    try:
        clock.advance(timedelta(seconds=5))
        with _serve_daemon(cfg, os_, clock, mono) as (ready3, loop3):
            _publish_capture_creds(loop3, [(cap_c, "stream-r4-f2", ws_a)])

            def _reverify_then_check_dangling() -> None:
                session = cast(Any, loop3._session)
                assert session is not None
                # Even if an old VERIFIED row existed, live link check must downgrade to UNKNOWN.
                st_v, _ = reconcile_harness_layer2_in_policy(
                    session._rt.policy,
                    harness_id="claude-code",
                    checkout_root=chk_a,
                    observed_host_version=_CLAUDE_VER,
                    os_=os_,
                    receipt=_build_receipt(harness_id="claude-code", host_version=_CLAUDE_VER, config_digest=c_dig1),
                )
                # reconcile_harness_layer2_in_policy already sees None/UNKNOWN; verify direct helper fail-closes too.
                assert st_v is Layer2State.UNKNOWN
                assert (
                    verify_live_layer2_harness(
                        session._rt.policy,
                        harness_id="claude-code",
                        os_=os_,
                        repo_id=ws_a.repo_id,
                        checkout_id=ws_a.checkout_id,
                    )
                    is None
                )

            loop3.run_owner_action(_reverify_then_check_dangling).result(timeout=10.0)
            target3 = LoopbackTarget(
                endpoint=ready3.endpoint,
                expected_store_id=rep.store_id,
                ca_pem=ca_pem,
                leaf_cert_sha256=ready3.leaf_cert_sha256,
            )
            ev_lnk = CaptureEventRecord(
                event_id="ev-r4-f2-link",
                producer_stream="stream-r4-f2",
                sequence=2,
                harness_id="claude-code",
                kind="command_result",
                recorded_at="2026-11-26T16:02:02Z",
                payload={"cmd": "pytest"},
                source_metadata={"host_version": _CLAUDE_VER, "config_digest": c_dig1},
            ).to_dict()
            assert (
                CaptureClient(LoopbackClient(monotonic_ns=mono.monotonic_ns))
                .post_batch(
                    target3, CaptureBatchCommand("stream-r4-f2", ws_a.repo_id, ws_a.checkout_id, (ev_lnk,), cap_c.token)
                )
                .accepted_count
                == 1
            )
            assert _capture_event_row(loop3, "ev-r4-f2-link") == ("unknown", "unverified")

            st_lk, app_lk = _terminal_approve_proposal(ready3, ca_pem, cli_token, prop_lnk)
            assert app_lk.get("ok") is False, (st_lk, app_lk)
            assert app_lk["error"]["code"] == ErrorCode.CAPABILITY_UNAVAILABLE.value

        for doc_chk in (None, chk_a):
            doc_lnk = run_doctor(rep.daemon_config_path, checkout_root=doc_chk, os_=os_)
            assert doc_lnk.terminal_channel_eligible is False
            assert {h.harness_id: h.state for h in doc_lnk.layer2_harnesses}["claude-code"] is Layer2State.UNKNOWN
    finally:
        _remove_dangling_claude_link(chk_a)

    # Part C: Consecutive online /v2/operator/restore rebinds preserve configured-checkout detection.
    def _online_restore(ready_obj: Any, loop_obj: Any) -> Any:
        """Restore online; returns the live ``Ready`` (restore bumps the writer epoch)."""
        st_p, prev_env = _post_tls(
            ready_obj, ca_pem, "/v2/operator/restore", cli_token, {"target": "policy", "backup": str(bak_verified)}
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
            ready_obj,
            ca_pem,
            "/v2/operator/restore",
            cli_token,
            {
                "target": "policy",
                "backup": str(bak_verified),
                "approval": {
                    "message": msg.to_dict(),
                    "channel": ApprovalChannel.SSH_KEY.value,
                    "signer_id": rep.signer.signer_id,
                    "signature": _ssh_sig_b64(priv, msg.canonical_bytes()),
                },
            },
        )
        assert st_e == 200 and exec_env.get("ok") is True, (st_e, exec_env)
        return loop_obj.ready

    clock.advance(timedelta(seconds=5))
    with _serve_daemon(cfg, os_, clock, mono) as (ready4, loop4):
        _publish_capture_creds(loop4, [(cap_c, "stream-r4-f2", ws_a)])
        # Restore #1 while config is deleted -> must fail closed.
        ready4 = _online_restore(ready4, loop4)
        st_r1, app_r1 = _terminal_approve_proposal(ready4, ca_pem, cli_token, prop_r1)
        assert app_r1.get("ok") is False, (st_r1, app_r1)
        assert app_r1["error"]["code"] == ErrorCode.CAPABILITY_UNAVAILABLE.value

        # Re-bootstrap, re-verify cleanly, prove terminal succeeds (recording configured checkout in new policy DB).
        mcp_json = chk_a / ".mcp.json"
        if mcp_json.exists():
            mcp_json.unlink()
        _write_plan_targets(chk_a, plan_claude_bootstrap(checkout_root=chk_a, profile_path=prof_path).targets)
        assert compute_harness_config_digest("claude-code", chk_a, os_) == c_dig1

        def _reverify_after_r1() -> None:
            session = cast(Any, loop4._session)
            assert session is not None
            st, _ = reconcile_harness_layer2_in_policy(
                session._rt.policy,
                harness_id="claude-code",
                checkout_root=chk_a,
                observed_host_version=_CLAUDE_VER,
                os_=os_,
                receipt=_build_receipt(harness_id="claude-code", host_version=_CLAUDE_VER, config_digest=c_dig1),
            )
            assert st is Layer2State.VERIFIED

        loop4.run_owner_action(_reverify_after_r1).result(timeout=10.0)
        st_r2ok, app_r2ok = _terminal_approve_proposal(ready4, ca_pem, cli_token, prop_r2_ok)
        assert st_r2ok == 200 and app_r2ok.get("ok") is True, (st_r2ok, app_r2ok)

        # Delete config again and perform consecutive online Restore #2 -> still fails closed!
        shutil.rmtree(chk_a / ".claude")
        (chk_a / "CLAUDE.md").unlink()
        clock.advance(timedelta(seconds=5))
        ready4 = _online_restore(ready4, loop4)
        st_r2d, app_r2d = _terminal_approve_proposal(ready4, ca_pem, cli_token, prop_r2_del)
        assert app_r2d.get("ok") is False, (st_r2d, app_r2d)
        assert app_r2d["error"]["code"] == ErrorCode.CAPABILITY_UNAVAILABLE.value


def test_r4_finding3_hook_session_sanitization_and_minimal_imports(trusted_tmp: Path) -> None:
    """Hook entry strips raw session keys, rejects forged session_ref, redacts secrets, and skips tomlkit."""
    os_ = os_adapters()
    chk_a = trusted_tmp / "chk-r4-f3"
    outbox_dir = trusted_tmp / "outbox-r4-f3"
    log_path = trusted_tmp / "hook-r4-f3.log"
    chk_a.mkdir(parents=True, exist_ok=True)
    os_.permissions.secure_directory(chk_a)

    # Variant A1: Clean payload with raw_session_id, sessionId, conversation_id -> enqueued with stripped keys,
    # non-anonymous server-derived session_ref, and zero raw secret in outbox frames or log.
    secrets = (
        ("raw_session_id", "secret-raw-sid-999"),
        ("sessionId", "secret-camelsid-888"),
        ("conversation_id", "secret-conv-777"),
    )
    anon_ref = digest_bytes(f"hook-session:claude-code:{chk_a}:anonymous".encode())
    seen_refs: list[str] = []
    for idx, (key_name, secret_val) in enumerate(secrets, start=1):
        payload = {
            "event_id": f"ev-r4-f3-san-{idx}",
            "sequence": idx,
            "event_name": "PostToolUse",
            "recorded_at": f"2026-11-26T16:05:0{idx}Z",
            "cwd": str(chk_a),
            "producer_stream": "stream-r4-f3-a",
            key_name: secret_val,
            "payload": {"command": "pytest -q", "note": f"step-{idx}"},
        }
        rc = hook_entry.run_hook(
            json.dumps(payload).encode("utf-8"),
            outbox_dir=outbox_dir,
            log_path=log_path,
            default_harness_id="claude-code",
            checkout_root=chk_a,
        )
        assert rc == 0

    spool = OutboxSpool(outbox_dir, permissions=os_.permissions)
    entries = spool.read_pending(limit=20, producer_stream="stream-r4-f3-a")
    assert len(entries) == len(secrets)
    for entry in entries:
        ev_obj = cast(dict[str, Any], json.loads(entry.payload_json))
        sref = str(ev_obj.get("session_ref") or "")
        assert sref != ""
        assert sref != anon_ref
        seen_refs.append(sref)
    assert len(set(seen_refs)) == len(secrets)

    # Variant A2: Poisoned payload containing raw_session_id/sessionId/conversation_id secret in tool payload ->
    # PrivacyGate must fail closed (0 enqueued records) and NEVER leak the secret into outbox frames or logs.
    for idx, (key_name, secret_val) in enumerate(secrets, start=1):
        poisoned_payload = {
            "event_id": f"ev-r4-f3-leak-{idx}",
            "sequence": idx,
            "event_name": "PostToolUse",
            "recorded_at": f"2026-11-26T16:05:1{idx}Z",
            "cwd": str(chk_a),
            "producer_stream": "stream-r4-f3-leak",
            key_name: secret_val,
            "payload": {"command": f"echo {secret_val}", "note": secret_val},
        }
        assert (
            hook_entry.run_hook(
                json.dumps(poisoned_payload).encode("utf-8"),
                outbox_dir=outbox_dir,
                log_path=log_path,
                default_harness_id="claude-code",
                checkout_root=chk_a,
            )
            == 0
        )
    assert spool.read_pending(limit=20, producer_stream="stream-r4-f3-leak") == []

    # Raw secret must NEVER appear anywhere in outbox frame bytes or log file across both clean & poisoned calls.
    for frame in (outbox_dir / "streams").rglob("*"):
        if frame.is_file():
            raw = frame.read_bytes()
            for _, secret_val in secrets:
                assert secret_val.encode("utf-8") not in raw
    if log_path.exists():
        log_txt = log_path.read_text(encoding="utf-8", errors="replace")
        for _, secret_val in secrets:
            assert secret_val not in log_txt

    # Variant B: Client-forged session_ref must be ignored in favor of server-derived digest (both hosts).
    forged_ref = digest_bytes(b"custom-client-controlled")
    for idx, (hid, ev_name) in enumerate(
        (("claude-code", "PostToolUse"), ("codex", "command_completed")),
        start=10,
    ):
        forged_payload = {
            "event_id": f"ev-r4-f3-forged-{hid}",
            "sequence": idx,
            "event_name": ev_name,
            "recorded_at": "2026-11-26T16:06:00Z",
            "cwd": str(chk_a),
            "producer_stream": f"stream-r4-f3-{hid}",
            "sessionId": f"real-sid-{hid}-42",
            "session_ref": forged_ref,
            "payload": {"command": "git status"},
        }
        assert (
            hook_entry.run_hook(
                json.dumps(forged_payload).encode("utf-8"),
                outbox_dir=outbox_dir,
                log_path=log_path,
                default_harness_id=hid,
                checkout_root=chk_a,
            )
            == 0
        )
        got = spool.read_pending(limit=10, producer_stream=f"stream-r4-f3-{hid}")
        assert len(got) == 1
        got_obj = cast(dict[str, Any], json.loads(got[0].payload_json))
        expected_ref = digest_bytes(f"hook-session:{hid}:{chk_a}:real-sid-{hid}-42".encode())
        assert got_obj.get("session_ref") != forged_ref
        assert got_obj.get("session_ref") == expected_ref

    # Variant C: Isolated python -I cold-start import check -> "tomlkit" MUST NOT be imported.
    script = (
        "import json, sys\n"
        "from pathlib import Path\n"
        "from superbrain.composition import hook_entry\n"
        "assert 'tomlkit' not in sys.modules, 'tomlkit imported eagerly by hook_entry'\n"
        "chk = Path(sys.argv[1])\n"
        "ob = Path(sys.argv[2])\n"
        "for hid, ev in (('claude-code', 'PostToolUse'), ('codex', 'command_completed')):\n"
        "    p = {'event_id': f'ev-iso-{hid}', 'sequence': 1, 'event_name': ev, "
        "'recorded_at': '2026-11-26T16:07:00Z', 'cwd': str(chk), "
        "'producer_stream': f'stream-iso-{hid}', 'payload': {'command': 'echo ok'}}\n"
        "    rc = hook_entry.run_hook(json.dumps(p).encode(), outbox_dir=ob, default_harness_id=hid, "
        "checkout_root=chk)\n"
        "    assert rc == 0\n"
        "assert 'tomlkit' not in sys.modules, 'tomlkit imported during run_hook'\n"
    )
    proc = subprocess.run(
        [sys.executable, "-I", "-c", script, str(chk_a), str(outbox_dir)],
        env=clean_installed_subprocess_env(),
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=15.0,
        check=False,
    )
    assert proc.returncode == 0, (proc.returncode, proc.stdout, proc.stderr)


def test_r4_finding4_multi_checkout_doctor_and_deep_health_parity(
    trusted_tmp: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Multi-checkout doctor (without --checkout) & MCP get_health(deep=true) agree without false positives."""
    _install_fake_host_bins(trusted_tmp, monkeypatch)
    clock = FakeClock(datetime.now(UTC).replace(microsecond=0))
    mono = FakeMonotonicClock(1_000_000_000)
    os_ = os_adapters(clock=clock, monotonic=mono)
    _priv, s_enr = _ssh_signer()

    cfg_dir = trusted_tmp / "cfg"
    data_root = trusted_tmp / "data"
    chk_a = trusted_tmp / "chk-r4-f4-a"
    chk_b = trusted_tmp / "chk-r4-f4-b"
    for d in (cfg_dir, chk_a, chk_b):
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

    prof_a = cfg_dir / "prof-a.json"
    prof_b = cfg_dir / "prof-b.json"
    # Phase A: chk_a configured for claude-code ONLY; chk_b configured for codex ONLY.
    _write_plan_targets(chk_a, plan_claude_bootstrap(checkout_root=chk_a, profile_path=prof_a).targets)
    _write_plan_targets(chk_b, plan_codex_bootstrap(checkout_root=chk_b, profile_path=prof_b).targets)
    c_dig_a = compute_harness_config_digest("claude-code", chk_a, os_)
    x_dig_b = compute_harness_config_digest("codex", chk_b, os_)
    assert c_dig_a is not None and x_dig_b is not None

    rt = reopen_kernel_job_runtime(data_root, rep.store_id, os_)
    try:
        mcp_c = seed_principal_and_credential(rt.policy, owner_id=_OWNER, harness_id="claude-code", machine_id=_MACHINE)
        mcp_x = seed_principal_and_credential(rt.policy, owner_id=_OWNER, harness_id="codex", machine_id=_MACHINE)
        ws_a = register_workspace_direct(
            rt, clock, mcp_c.principal, alias="ws-f4-a", checkout_dir=chk_a, remote="https://example.invalid/a.git"
        )
        ws_b = register_workspace_direct(
            rt, clock, mcp_c.principal, alias="ws-f4-b", checkout_dir=chk_b, remote="https://example.invalid/b.git"
        )
        seed_repo_grant(rt.policy, principal_id=mcp_x.principal.principal_id, repo_id=ws_a.repo_id, owner_id=_OWNER)
        seed_repo_grant(rt.policy, principal_id=mcp_x.principal.principal_id, repo_id=ws_b.repo_id, owner_id=_OWNER)
        rt.store.reconcile_policy()

        assert (
            reconcile_harness_layer2_in_policy(
                rt.policy,
                harness_id="claude-code",
                checkout_root=chk_a,
                observed_host_version=_CLAUDE_VER,
                os_=os_,
                receipt=_build_receipt(harness_id="claude-code", host_version=_CLAUDE_VER, config_digest=c_dig_a),
            )[0]
            is Layer2State.VERIFIED
        )
        assert (
            reconcile_harness_layer2_in_policy(
                rt.policy,
                harness_id="codex",
                checkout_root=chk_b,
                observed_host_version=_CODEX_VER,
                os_=os_,
                receipt=_build_receipt(harness_id="codex", host_version=_CODEX_VER, config_digest=x_dig_b),
            )[0]
            is Layer2State.VERIFIED
        )
    finally:
        rt.close()

    # Phase A assertion: run_doctor WITHOUT --checkout MUST NOT false-positive on chk_a lacking .codex/ or chk_b
    # lacking .claude/. Both must stay VERIFIED, terminal_channel_eligible(_effective)=True, layer2 check='ok'.
    doc_clean = run_doctor(rep.daemon_config_path, os_=os_)
    doc_clean_dict = doc_clean.to_dict()
    assert doc_clean.terminal_channel_eligible is True
    assert cast(dict[str, Any], doc_clean_dict["sp2"])["terminal_channel_eligible_effective"] is True
    assert {h.harness_id: h.state for h in doc_clean.layer2_harnesses} == {
        "claude-code": Layer2State.VERIFIED,
        "codex": Layer2State.VERIFIED,
    }
    l2_clean_checks = [c for c in doc_clean.checks if c.name == "harness.layer2"]
    assert len(l2_clean_checks) == 1 and l2_clean_checks[0].status == "PASS"

    # Phase B: chk_b ALSO hosts claude-code and drifts its .claude/settings.local.json while chk_a remains clean!
    _write_plan_targets(chk_b, plan_claude_bootstrap(checkout_root=chk_b, profile_path=prof_b).targets)
    b_settings = chk_b / ".claude" / "settings.local.json"
    b_obj = json.loads(b_settings.read_text(encoding="utf-8"))
    b_obj["permissions"]["allow"] = ["Bash(pytest *)"]
    b_settings.write_bytes(canonical_json(b_obj))

    # run_doctor WITHOUT --checkout (both direct API & real CLI) must detect drift on chk_b!
    doc_drift = run_doctor(rep.daemon_config_path, os_=os_)
    assert doc_drift.terminal_channel_eligible is False
    doc_drift_dict = doc_drift.to_dict()
    assert cast(dict[str, Any], doc_drift_dict["sp2"])["terminal_channel_eligible_effective"] is False
    assert {h.harness_id: h.state for h in doc_drift.layer2_harnesses}["claude-code"] is Layer2State.UNKNOWN
    l2_drift_checks = [c for c in doc_drift.checks if c.name == "harness.layer2"]
    assert len(l2_drift_checks) == 1
    assert l2_drift_checks[0].status == "WARN"
    assert "terminal_channel_eligible=false" in l2_drift_checks[0].detail

    proc = subprocess.run(
        [
            sys.executable,
            "-I",
            "-m",
            "superbrain.cli.main",
            "doctor",
            "--config",
            str(rep.daemon_config_path),
            "--json",
        ],
        env=clean_installed_subprocess_env(),
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=15.0,
        check=False,
    )
    assert proc.returncode == 0, (proc.returncode, proc.stderr)
    cli_data = json.loads(proc.stdout)["data"]
    assert cli_data["terminal_channel_eligible"] is False
    assert cli_data["sp2"]["terminal_channel_eligible_effective"] is False
    cli_l2 = [c for c in cli_data["checks"] if c["name"] == "harness.layer2"]
    assert len(cli_l2) == 1 and cli_l2[0]["status"] == "WARN"
    assert any(c["name"] == "sp2.layer2_drift" and c["status"] == "WARN" for c in cli_data["checks"])

    # Live daemon get_health(deep=True) over TLS MUST agree: the doctor's harness.layer2 code is degraded.
    with _serve_daemon(cfg, os_, clock, mono) as (ready, _loop):
        target = LoopbackTarget(
            endpoint=ready.endpoint,
            expected_store_id=rep.store_id,
            ca_pem=ca_pem,
            leaf_cert_sha256=ready.leaf_cert_sha256,
        )
        deep = LoopbackClient(monotonic_ns=mono.monotonic_ns).call(
            target,
            ToolCommand(
                tool="get_health",
                arguments={"schema_version": SCHEMA_VERSION, "deep": True, "idempotency_key": f"idem-f4-{new_id()}"},
                token=mcp_c.token,
                selected_scope=None,
            ),
        )
        assert deep.get("ok") is True, deep
        deep_data = cast(dict[str, Any], deep["data"])
        _validate_get_health_schema(deep_data)
        assert "harness.layer2" in deep_data["degraded_codes"], deep_data["degraded_codes"]


# ---------------------------------------------------------------------------
# Round-5 Review Regressions (2 x P1: observed host hook payloads & active host_version drift)
# ---------------------------------------------------------------------------


def _run_installed_hook_cmd(cmd: list[str], payload: dict[str, Any], *, cwd: Path) -> None:
    run_cmd = [sys.executable, *cmd[1:]] if Path(cmd[0]).name.lower().startswith("python") else cmd
    t0 = time.perf_counter()
    proc = subprocess.run(
        run_cmd,
        cwd=cwd,
        env=clean_installed_subprocess_env(),
        input=json.dumps(payload).encode("utf-8"),
        capture_output=True,
        timeout=5.0,
        check=False,
    )
    elapsed = time.perf_counter() - t0
    assert proc.returncode == 0, (proc.returncode, proc.stdout, proc.stderr)
    assert elapsed < 2.0


def _capture_events_for_stream(loop: OwnerLoop, producer_stream: str) -> list[tuple[int, str, str]]:
    def _read() -> list[tuple[int, str, str]]:
        session = cast(Any, loop._session)
        assert session is not None
        rows = session._rt.store._db.execute(
            "SELECT sequence, event_id, kind FROM capture_events WHERE producer_stream = ? ORDER BY sequence",
            (producer_stream,),
        ).fetchall()
        return [(int(r[0]), str(r[1]), str(r[2])) for r in rows]

    return loop.run_owner_action(_read).result(timeout=10.0)


def _write_fake_host_bin(bin_dir: Path, name: str, stdout_line: str) -> Path:
    if sys.platform == "win32":
        p = bin_dir / f"{name}.cmd"
        p.write_text(f"@echo off\r\necho {stdout_line}\r\n", encoding="ascii")
    else:
        p = bin_dir / name
        p.write_text(f"#!/bin/sh\nprintf '%s\\n' '{stdout_line}'\n", encoding="utf-8")
        p.chmod(0o755)
    return p


def test_r5_finding1_observed_host_payloads_consecutive_retry_and_ws_switch(trusted_tmp: Path) -> None:
    """Installed bootstrap hooks convert observed Claude/Codex host payloads -> drain ACK, retry, & ws switch."""
    clock = FakeClock(datetime.now(UTC).replace(microsecond=0))
    mono = FakeMonotonicClock(1_000_000_000)
    os_ = os_adapters(clock=clock, monotonic=mono)
    priv, s_enr = _ssh_signer()

    cfg_dir = trusted_tmp / "cfg"
    data_root = trusted_tmp / "data"
    chk_a = trusted_tmp / "chk-r5-f1-a"
    chk_b = trusted_tmp / "chk-r5-f1-b"
    prof_dir = trusted_tmp / "profiles"
    for d in (cfg_dir, chk_a, chk_b, prof_dir):
        d.mkdir(parents=True, exist_ok=True)
        os_.permissions.secure_directory(d)

    rep = init_entry.init_store(
        init_entry.InitRequest(
            data_root=data_root, config_dir=cfg_dir, owner_id=_OWNER, machine_id=_MACHINE, signer=s_enr
        ),
        os_,
    )
    cfg = read_daemon_config(rep.daemon_config_path, os_)
    ca_path = cfg_dir / "tls" / "ca.pem"
    ca_pem = ca_path.read_text(encoding="utf-8")
    cli_token = rep.cli_credential_path.read_text(encoding="ascii").strip()

    rt = reopen_kernel_job_runtime(data_root, rep.store_id, os_)
    try:
        mcp_c = seed_principal_and_credential(rt.policy, owner_id=_OWNER, harness_id="claude-code", machine_id=_MACHINE)
        mcp_x = seed_principal_and_credential(rt.policy, owner_id=_OWNER, harness_id="codex", machine_id=_MACHINE)
        cap_c = seed_principal_and_credential(rt.policy, owner_id=_OWNER, harness_id="claude-code", machine_id=_MACHINE)
        cap_x = seed_principal_and_credential(rt.policy, owner_id=_OWNER, harness_id="codex", machine_id=_MACHINE)
        ws_a = register_workspace_direct(
            rt,
            clock,
            mcp_c.principal,
            alias="ws-r5-a",
            checkout_dir=chk_a,
            remote="https://github.example/dan/repo-r5-a.git",
        )
        ws_b = register_workspace_direct(
            rt,
            clock,
            mcp_c.principal,
            alias="ws-r5-b",
            checkout_dir=chk_b,
            remote="https://github.example/dan/repo-r5-b.git",
        )
        for pid in (mcp_x.principal.principal_id, cap_x.principal.principal_id):
            seed_repo_grant(rt.policy, principal_id=pid, repo_id=ws_a.repo_id, owner_id=_OWNER)
            seed_repo_grant(rt.policy, principal_id=pid, repo_id=ws_b.repo_id, owner_id=_OWNER)
        rt.store.reconcile_policy()
    finally:
        rt.close()

    with _serve_daemon(cfg, os_, clock, mono) as (ready, loop):
        ep_path = data_root / "endpoint.json"
        cred_c_file = write_credential_file(prof_dir / "claude.cred", mcp_c.token)
        cred_x_file = write_credential_file(prof_dir / "codex.cred", mcp_x.token)

        def _make_profile(name: str, cred_file: Path, ws: WorkspaceBinding, chk: Path) -> Path:
            p, _ = write_client_profile_file(
                prof_dir / name,
                endpoint_path=ep_path,
                expected_store_id=rep.store_id,
                ca_file=ca_path,
                leaf_cert_sha256=ready.leaf_cert_sha256,
                credential_file=cred_file,
                workspace={
                    "alias": ws.alias,
                    "expected_workspace_id": ws.repo_id,
                    "expected_checkout_id": ws.checkout_id,
                    "checkout_path": str(chk),
                },
            )
            return p

        prof_a_claude = _make_profile("a-claude.json", cred_c_file, ws_a, chk_a)
        prof_a_codex = _make_profile("a-codex.json", cred_x_file, ws_a, chk_a)

        def _bootstrap_apply(harness: str, chk: Path, prof: Path) -> None:
            st_b, b_env = _post_tls(
                ready,
                ca_pem,
                "/v2/operator/proposal/bootstrap",
                cli_token,
                {"harness": harness, "checkout_root": str(chk), "harness_profile_path": str(prof)},
            )
            assert st_b == 200 and b_env.get("ok") is True, (st_b, b_env)
            pid = str(b_env["data"]["proposal"]["proposal_id"])
            for op_path in ("/v2/operator/proposal/approve", "/v2/operator/proposal/apply"):
                st_c, ch_env = _post_tls(ready, ca_pem, op_path, cli_token, {"proposal_id": pid})
                assert st_c == 200 and ch_env.get("ok") is True, (op_path, ch_env)
                ch = cast(dict[str, Any], ch_env["data"]["challenge"])
                msg = ApprovalMessage.from_dict(ch)
                st_x, ex_env = _post_tls(
                    ready,
                    ca_pem,
                    op_path,
                    cli_token,
                    {
                        "proposal_id": pid,
                        "approval": {
                            "message": ch,
                            "channel": ApprovalChannel.SSH_KEY.value,
                            "signer_id": rep.signer.signer_id,
                            "signature": _ssh_sig_b64(priv, msg.canonical_bytes()),
                        },
                    },
                )
                assert st_x == 200 and ex_env.get("ok") is True, (op_path, ex_env)

        _bootstrap_apply("claude-code", chk_a, prof_a_claude)
        _bootstrap_apply("codex", chk_a, prof_a_codex)

        cfg_claude = json.loads((chk_a / ".claude" / "settings.local.json").read_text(encoding="utf-8"))
        cfg_codex = json.loads((chk_a / ".codex" / "hooks.json").read_text(encoding="utf-8"))

        cmd_claude = _find_hook_commands(cfg_claude["hooks"]["PostToolUse"])[0]
        cmd_codex = _find_hook_commands(cfg_codex["hooks"]["PostToolUse"])[0]
        assert "--producer-stream" not in cmd_claude and "--sequence" not in cmd_claude
        assert "--producer-stream" not in cmd_codex and "--sequence" not in cmd_codex

        outbox_c = Path(_extract_outbox_arg(cmd_claude))
        outbox_x = Path(_extract_outbox_arg(cmd_codex))
        assert outbox_c.resolve() != outbox_x.resolve()

        target = LoopbackTarget(
            endpoint=ready.endpoint,
            expected_store_id=rep.store_id,
            ca_pem=ca_pem,
            leaf_cert_sha256=ready.leaf_cert_sha256,
        )
        cap_client = CaptureClient(LoopbackClient(monotonic_ns=mono.monotonic_ns))

        # --- Harness 1: Claude Code observed host payload (no envelope keys, no transcript_path) ---
        claude_ev1: dict[str, Any] = {
            "cwd": str(chk_a),
            "hook_event_name": "PostToolUse",
            "session_id": "claude-sid-r5-1",
            "tool_name": "Bash",
            "tool_input": {"command": "pytest -q"},
            "tool_response": {"exit_code": 0, "stdout": "ok"},
            "tool_use_id": "toolu_r5_1",
            "duration_ms": 42,
            "permission_mode": "default",
            "effort": "medium",
        }
        _run_installed_hook_cmd(cmd_claude, claude_ev1, cwd=chk_a)

        spool_c = OutboxSpool(outbox_c, permissions=os_.permissions)
        pending_c1 = spool_c.read_pending(limit=10)
        assert len(pending_c1) == 1, f"expected 1 outbox event for observed PostToolUse, got {pending_c1}"
        ev_c1 = cast(dict[str, Any], json.loads(pending_c1[0].payload_json))
        assert "session_id" not in ev_c1
        assert "claude-sid-r5-1" not in pending_c1[0].payload_json
        assert str(ev_c1["session_ref"]).startswith("sha256:")
        assert isinstance(ev_c1["payload"], dict) and ev_c1["payload"]
        require_iso_utc_timestamp(str(ev_c1["recorded_at"]))
        c_seq1 = pending_c1[0].sequence
        c_ev1_id = str(ev_c1["event_id"])
        stream_c = pending_c1[0].producer_stream
        assert c_seq1 >= 1 and stream_c

        # Idempotent retry BEFORE drain: re-sending identical Event 1 keeps a single pending entry.
        _run_installed_hook_cmd(cmd_claude, claude_ev1, cwd=chk_a)
        pending_c1_retry = spool_c.read_pending(limit=10)
        assert len(pending_c1_retry) == 1
        assert pending_c1_retry[0].sequence == c_seq1

        _publish_capture_creds(loop, [(cap_c, stream_c, ws_a)])
        ack_c1 = drain_outbox(
            spool_c,
            client=cap_client,
            target=target,
            producer_stream=stream_c,
            repo_id=ws_a.repo_id,
            checkout_id=ws_a.checkout_id,
            token=cap_c.token,
        )
        assert ack_c1 is not None and ack_c1.accepted_count == 1
        assert c_seq1 in ack_c1.committed_event_sequences
        assert spool_c.read_pending(limit=10) == []

        # Consecutive Event 2 (PostToolUse with toolu_r5_2) -> strictly higher monotonic sequence -> drain ACK.
        claude_ev2: dict[str, Any] = {
            "cwd": str(chk_a),
            "hook_event_name": "PostToolUse",
            "session_id": "claude-sid-r5-1",
            "tool_name": "Read",
            "tool_input": {"file_path": str(chk_a / "CLAUDE.md")},
            "tool_response": {"bytes": 120},
            "tool_use_id": "toolu_r5_2",
            "duration_ms": 12,
            "permission_mode": "default",
            "effort": "low",
        }
        _run_installed_hook_cmd(cmd_claude, claude_ev2, cwd=chk_a)
        pending_c2 = spool_c.read_pending(limit=10)
        assert len(pending_c2) == 1
        assert pending_c2[0].producer_stream == stream_c
        c_seq2 = pending_c2[0].sequence
        assert c_seq2 > c_seq1

        ack_c2 = drain_outbox(
            spool_c,
            client=cap_client,
            target=target,
            producer_stream=stream_c,
            repo_id=ws_a.repo_id,
            checkout_id=ws_a.checkout_id,
            token=cap_c.token,
        )
        assert ack_c2 is not None and ack_c2.accepted_count == 1
        assert c_seq2 in ack_c2.committed_event_sequences
        assert spool_c.read_pending(limit=10) == []
        rows_c = _capture_events_for_stream(loop, stream_c)
        assert len(rows_c) == 2

        # Idempotent retry AFTER drain: either skipped locally (0 pending) or same (seq1, event_id) deduped by daemon.
        _run_installed_hook_cmd(cmd_claude, claude_ev1, cwd=chk_a)
        pending_c_after = spool_c.read_pending(limit=10)
        if pending_c_after:
            assert len(pending_c_after) == 1
            re_obj = cast(dict[str, Any], json.loads(pending_c_after[0].payload_json))
            assert pending_c_after[0].sequence == c_seq1
            assert str(re_obj["event_id"]) == c_ev1_id
            ack_cr = drain_outbox(
                spool_c,
                client=cap_client,
                target=target,
                producer_stream=stream_c,
                repo_id=ws_a.repo_id,
                checkout_id=ws_a.checkout_id,
                token=cap_c.token,
            )
            assert ack_cr is not None and ack_cr.accepted_count == 0 and ack_cr.deduped_count == 1
        assert len(_capture_events_for_stream(loop, stream_c)) == 2

        # Workspace switch for chk_a Claude hook: cwd=chk_b -> rc=0, 0 new events, zero chk_b leak.
        _run_installed_hook_cmd(
            cmd_claude,
            {
                "cwd": str(chk_b),
                "hook_event_name": "PostToolUse",
                "session_id": "claude-sid-ws-b",
                "tool_name": "Bash",
                "tool_input": {"command": "echo secret-chk-b-only"},
                "tool_response": {"exit_code": 0},
                "tool_use_id": "toolu_r5_ws_b",
                "duration_ms": 5,
                "permission_mode": "default",
                "effort": "low",
            },
            cwd=chk_b,
        )
        assert spool_c.read_pending(limit=10) == []
        assert len(_capture_events_for_stream(loop, stream_c)) == 2

        # --- Harness 2: Codex native payload on supported mode (no envelope keys) ---
        codex_ev1: dict[str, Any] = {
            "cwd": str(chk_a),
            "event_type": "command_completed",
            "session_id": "codex-sid-r5-1",
            "call_id": "call_codex_r5_1",
            "command": "pytest -q tests/unit",
            "exit_code": 0,
        }
        _run_installed_hook_cmd(cmd_codex, codex_ev1, cwd=chk_a)
        spool_x = OutboxSpool(outbox_x, permissions=os_.permissions)
        pending_x1 = spool_x.read_pending(limit=10)
        assert len(pending_x1) == 1, f"expected 1 outbox event for Codex command_completed, got {pending_x1}"
        ev_x1 = cast(dict[str, Any], json.loads(pending_x1[0].payload_json))
        assert "session_id" not in ev_x1
        assert "codex-sid-r5-1" not in pending_x1[0].payload_json
        assert str(ev_x1["session_ref"]).startswith("sha256:")
        assert isinstance(ev_x1["payload"], dict) and ev_x1["payload"]
        require_iso_utc_timestamp(str(ev_x1["recorded_at"]))
        x_seq1 = pending_x1[0].sequence
        x_ev1_id = str(ev_x1["event_id"])
        stream_x = pending_x1[0].producer_stream
        assert x_seq1 >= 1 and stream_x != stream_c

        _run_installed_hook_cmd(cmd_codex, codex_ev1, cwd=chk_a)
        assert len(spool_x.read_pending(limit=10)) == 1

        _publish_capture_creds(loop, [(cap_c, stream_c, ws_a), (cap_x, stream_x, ws_a)])
        ack_x1 = drain_outbox(
            spool_x,
            client=cap_client,
            target=target,
            producer_stream=stream_x,
            repo_id=ws_a.repo_id,
            checkout_id=ws_a.checkout_id,
            token=cap_x.token,
        )
        assert ack_x1 is not None and ack_x1.accepted_count == 1
        assert x_seq1 in ack_x1.committed_event_sequences
        assert spool_x.read_pending(limit=10) == []

        codex_ev2: dict[str, Any] = {
            "cwd": str(chk_a),
            "event_type": "agent_turn_end",
            "session_id": "codex-sid-r5-1",
            "turn_id": "turn_codex_r5_2",
            "summary": "All unit tests passed",
        }
        _run_installed_hook_cmd(cmd_codex, codex_ev2, cwd=chk_a)
        pending_x2 = spool_x.read_pending(limit=10)
        assert len(pending_x2) == 1
        x_seq2 = pending_x2[0].sequence
        assert x_seq2 > x_seq1

        ack_x2 = drain_outbox(
            spool_x,
            client=cap_client,
            target=target,
            producer_stream=stream_x,
            repo_id=ws_a.repo_id,
            checkout_id=ws_a.checkout_id,
            token=cap_x.token,
        )
        assert ack_x2 is not None and ack_x2.accepted_count == 1
        assert x_seq2 in ack_x2.committed_event_sequences
        assert len(_capture_events_for_stream(loop, stream_x)) == 2

        # Codex retry after drain + workspace switch.
        _run_installed_hook_cmd(cmd_codex, codex_ev1, cwd=chk_a)
        pending_x_after = spool_x.read_pending(limit=10)
        if pending_x_after:
            assert len(pending_x_after) == 1
            rx_obj = cast(dict[str, Any], json.loads(pending_x_after[0].payload_json))
            assert pending_x_after[0].sequence == x_seq1 and str(rx_obj["event_id"]) == x_ev1_id
            ack_xr = drain_outbox(
                spool_x,
                client=cap_client,
                target=target,
                producer_stream=stream_x,
                repo_id=ws_a.repo_id,
                checkout_id=ws_a.checkout_id,
                token=cap_x.token,
            )
            assert ack_xr is not None and ack_xr.accepted_count == 0 and ack_xr.deduped_count == 1
        assert len(_capture_events_for_stream(loop, stream_x)) == 2

        _run_installed_hook_cmd(
            cmd_codex,
            {
                "cwd": str(chk_b),
                "event_type": "command_completed",
                "session_id": "codex-sid-ws-b",
                "call_id": "call_codex_ws_b",
                "command": "echo secret-codex-b",
                "exit_code": 0,
            },
            cwd=chk_b,
        )
        assert spool_x.read_pending(limit=10) == []
        assert len(_capture_events_for_stream(loop, stream_x)) == 2


def test_r5_finding2_active_host_version_drift_on_terminal_and_doctor(
    trusted_tmp: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Host upgrade or unverifiable binary fails closed on already-running daemon terminal & doctor without capture."""
    clock = FakeClock(datetime.now(UTC).replace(microsecond=0))
    mono = FakeMonotonicClock(1_000_000_000)
    os_ = os_adapters(clock=clock, monotonic=mono)
    _priv, s_enr = _ssh_signer()

    bin_dir = trusted_tmp / "bin"
    cfg_dir = trusted_tmp / "cfg"
    data_root = trusted_tmp / "data"
    chk_a = trusted_tmp / "chk-r5-f2"
    home_dir = trusted_tmp / "home"
    for d in (bin_dir, cfg_dir, chk_a, home_dir):
        d.mkdir(parents=True, exist_ok=True)
        os_.permissions.secure_directory(d)

    claude_bin = _write_fake_host_bin(bin_dir, "claude", f"{_CLAUDE_VER} (Claude Code)")
    _write_fake_host_bin(bin_dir, "codex", "codex-cli 0.171.0")
    ssh_dir = (
        Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "OpenSSH"
        if sys.platform == "win32"
        else Path(shutil.which("ssh-keygen") or "/usr/bin/ssh-keygen").parent  # the SSH approval verifier needs it
    )
    isolated_path = f"{bin_dir}{os.pathsep}{ssh_dir}"
    monkeypatch.setenv("PATH", isolated_path)

    rep = init_entry.init_store(
        init_entry.InitRequest(
            data_root=data_root, config_dir=cfg_dir, owner_id=_OWNER, machine_id=_MACHINE, signer=s_enr
        ),
        os_,
    )
    cfg = read_daemon_config(rep.daemon_config_path, os_)
    ca_pem = (cfg_dir / "tls" / "ca.pem").read_text(encoding="utf-8")
    cli_token = rep.cli_credential_path.read_text(encoding="ascii").strip()

    prof_path = cfg_dir / "claude-profile.json"
    _write_plan_targets(chk_a, plan_claude_bootstrap(checkout_root=chk_a, profile_path=prof_path).targets)
    _write_plan_targets(chk_a, plan_codex_bootstrap(checkout_root=chk_a, profile_path=prof_path).targets)
    c_dig = compute_harness_config_digest("claude-code", chk_a, os_)
    x_dig = compute_harness_config_digest("codex", chk_a, os_)
    assert c_dig is not None and x_dig is not None

    rt = reopen_kernel_job_runtime(data_root, rep.store_id, os_)
    try:
        mcp_c = seed_principal_and_credential(rt.policy, owner_id=_OWNER, harness_id="claude-code", machine_id=_MACHINE)
        seed_principal_and_credential(rt.policy, owner_id=_OWNER, harness_id="codex", machine_id=_MACHINE)
        register_workspace_direct(rt, clock, mcp_c.principal, alias="ws-r5-f2", checkout_dir=chk_a)
        rt.store.reconcile_policy()
        assert (
            reconcile_harness_layer2_in_policy(
                rt.policy,
                harness_id="claude-code",
                checkout_root=chk_a,
                observed_host_version=_CLAUDE_VER,
                os_=os_,
                receipt=_build_receipt(harness_id="claude-code", host_version=_CLAUDE_VER, config_digest=c_dig),
            )[0]
            is Layer2State.VERIFIED
        )
        assert (
            reconcile_harness_layer2_in_policy(
                rt.policy,
                harness_id="codex",
                checkout_root=chk_a,
                observed_host_version="0.171.0",
                os_=os_,
                receipt=_build_receipt(harness_id="codex", host_version="0.171.0", config_digest=x_dig),
            )[0]
            is Layer2State.VERIFIED
        )
    finally:
        rt.close()

    with _serve_daemon(cfg, os_, clock, mono) as (ready, loop):
        def _new_prop(note_name: str) -> str:
            def _make() -> str:
                session = cast(Any, loop._session)
                assert session is not None
                return _create_low_risk_proposal(
                    session._rt, os_, data_root=data_root, home=home_dir, checkout=chk_a, note_name=note_name
                )

            return loop.run_owner_action(_make).result(timeout=10.0)

        # Positive twin: live daemon (default hooks, NO custom resolver override) + run_doctor (NO observed override)
        # report VERIFIED / pass / terminal_channel_eligible=True, and TERMINAL approval succeeds.
        doc_ok = run_doctor(rep.daemon_config_path, checkout_root=chk_a, os_=os_)
        assert doc_ok.terminal_channel_eligible is True
        assert doc_ok.overall_status == "pass"
        assert {h.harness_id: h.state for h in doc_ok.layer2_harnesses} == {
            "claude-code": Layer2State.VERIFIED,
            "codex": Layer2State.VERIFIED,
        }

        prop_ok = _new_prop("r5-f2-ok.md")
        st_ok, app_ok = _terminal_approve_proposal(ready, ca_pem, cli_token, prop_ok)
        assert st_ok == 200 and app_ok.get("ok") is True, (st_ok, app_ok)

        # Upgrade claude binary to 2.1.332 WITHOUT changing checkout config on disk and BEFORE next capture batch!
        _write_fake_host_bin(bin_dir, "claude", "2.1.332 (Claude Code)")

        # a) Read-only doctor (direct + CLI subprocess, NO observed_host_versions) detects host_version_changed.
        def _l2_row_count() -> int:
            session = cast(Any, loop._session)
            assert session is not None
            return int(session._rt.policy._db.execute("SELECT COUNT(*) FROM harness_layer2_state").fetchone()[0])

        l2_rows_before = loop.run_owner_action(_l2_row_count).result(timeout=10.0)
        snap_chk = digest_tree(chk_a)
        doc_upg = run_doctor(rep.daemon_config_path, checkout_root=chk_a, os_=os_)
        assert doc_upg.terminal_channel_eligible is False
        assert doc_upg.overall_status == "warn"
        assert any(c.name == "harness.layer2" and c.status == "WARN" for c in doc_upg.checks)
        assert any(c.name == "sp2.layer2_drift" and c.status == "WARN" for c in doc_upg.checks)
        sp2_upg = cast(dict[str, Any], doc_upg.to_dict()["sp2"])
        assert sp2_upg["terminal_channel_eligible_effective"] is False
        upg_by_id = {str(h["harness_id"]): h for h in cast(list[dict[str, Any]], sp2_upg["layer2_harnesses"])}
        assert upg_by_id["claude-code"]["effective_state"] == Layer2State.UNKNOWN.value
        assert upg_by_id["claude-code"]["invalidated_reason"] == "host_version_changed"

        cli_proc = subprocess.run(
            [
                sys.executable,
                "-I",
                "-m",
                "superbrain.cli.main",
                "doctor",
                "--config",
                str(rep.daemon_config_path),
                "--checkout",
                str(chk_a),
                "--json",
            ],
            env=clean_installed_subprocess_env(),
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=15.0,
            check=False,
        )
        assert cli_proc.returncode == 0, (cli_proc.returncode, cli_proc.stderr)
        cli_doc = json.loads(cli_proc.stdout)["data"]
        assert cli_doc["terminal_channel_eligible"] is False
        assert cli_doc["overall_status"] == "warn"
        cli_l2 = {str(h["harness_id"]): h for h in cli_doc["sp2"]["layer2_harnesses"]}
        assert cli_l2["claude-code"]["effective_state"] == Layer2State.UNKNOWN.value
        assert cli_l2["claude-code"]["invalidated_reason"] == "host_version_changed"
        assert loop.run_owner_action(_l2_row_count).result(timeout=10.0) == l2_rows_before
        assert digest_tree(chk_a) == snap_chk

        # b) Already-running daemon BEFORE any capture batch MUST detect 2.1.332 != 2.1.325, downgrade in DB,
        # and REFUSE terminal approval with CAPABILITY_UNAVAILABLE!
        prop_upgrade = _new_prop("r5-f2-upg.md")
        st_up, app_up = _terminal_approve_proposal(ready, ca_pem, cli_token, prop_upgrade)
        assert app_up.get("ok") is False, (st_up, app_up)
        assert app_up["error"]["code"] == ErrorCode.CAPABILITY_UNAVAILABLE.value

        def _read_claude_l2_state() -> Layer2State | None:
            session = cast(Any, loop._session)
            assert session is not None
            latest = session._rt.policy.layer2_state("claude-code")
            return None if latest is None else latest[3]

        assert loop.run_owner_action(_read_claude_l2_state).result(timeout=10.0) is Layer2State.UNKNOWN

        # Part 3: Unverifiable host binary (removed from PATH / resolver returns None) -> MUST fail closed.
        _write_fake_host_bin(bin_dir, "claude", f"{_CLAUDE_VER} (Claude Code)")

        def _reverify_claude() -> None:
            session = cast(Any, loop._session)
            assert session is not None
            st_rv, _ = reconcile_harness_layer2_in_policy(
                session._rt.policy,
                harness_id="claude-code",
                checkout_root=chk_a,
                observed_host_version=_CLAUDE_VER,
                os_=os_,
                receipt=_build_receipt(harness_id="claude-code", host_version=_CLAUDE_VER, config_digest=c_dig),
            )
            assert st_rv is Layer2State.VERIFIED

        loop.run_owner_action(_reverify_claude).result(timeout=10.0)
        claude_bin.unlink()

        # Check verify_live_layer2_harness fails closed when resolver returns None.
        def _check_resolver_none() -> Layer2State | None:
            session = cast(Any, loop._session)
            assert session is not None
            assert (
                verify_live_layer2_harness(
                    session._rt.policy,
                    harness_id="claude-code",
                    os_=os_,
                    host_version_resolver=lambda _: None,
                )
                is None
            )
            latest = session._rt.policy.layer2_state("claude-code")
            return None if latest is None else latest[3]

        assert loop.run_owner_action(_check_resolver_none).result(timeout=10.0) is Layer2State.UNKNOWN

        # Re-verify once more to test doctor & running daemon terminal with claude binary missing from PATH!
        loop.run_owner_action(_reverify_claude).result(timeout=10.0)
        doc_miss = run_doctor(rep.daemon_config_path, checkout_root=chk_a, os_=os_)
        assert doc_miss.terminal_channel_eligible is False
        sp2_miss = cast(dict[str, Any], doc_miss.to_dict()["sp2"])
        miss_by_id = {str(h["harness_id"]): h for h in cast(list[dict[str, Any]], sp2_miss["layer2_harnesses"])}
        assert miss_by_id["claude-code"]["effective_state"] == Layer2State.UNKNOWN.value

        prop_missing = _new_prop("r5-f2-miss.md")
        st_ms, app_ms = _terminal_approve_proposal(ready, ca_pem, cli_token, prop_missing)
        assert app_ms.get("ok") is False, (st_ms, app_ms)
        assert app_ms["error"]["code"] == ErrorCode.CAPABILITY_UNAVAILABLE.value
        assert loop.run_owner_action(_read_claude_l2_state).result(timeout=10.0) is Layer2State.UNKNOWN


# ---------------------------------------------------------------------------
# Round-6 Review Regression (P1: durable hook envelope binding across crashes,
# post-ACK retry, gap fallback, and post-ACK payload conflict)
# ---------------------------------------------------------------------------


def _observed_claude_post_tool(chk: Path, *, tool_use_id: str, cmd: str) -> dict[str, Any]:
    return {
        "cwd": str(chk),
        "hook_event_name": "PostToolUse",
        "session_id": "claude-sid-r6",
        "tool_name": "Bash",
        "tool_input": {"command": cmd},
        "tool_response": {"exit_code": 0, "stdout": "ok"},
        "tool_use_id": tool_use_id,
        "duration_ms": 25,
        "permission_mode": "default",
        "effort": "medium",
    }


def _pending_event_tuples(spool: OutboxSpool, *, producer_stream: str | None = None) -> list[tuple[int, str]]:
    entries = spool.read_pending(limit=20, producer_stream=producer_stream)
    out: list[tuple[int, str]] = []
    for ent in entries:
        if ent.record_kind != OUTBOX_RECORD_EVENT:
            continue
        obj = cast(dict[str, Any], json.loads(ent.payload_json))
        out.append((ent.sequence, str(obj["event_id"])))
    return out


def _capture_gaps_for_stream(loop: OwnerLoop, producer_stream: str) -> list[tuple[Any, ...]]:
    def _read() -> list[tuple[Any, ...]]:
        session = cast(Any, loop._session)
        assert session is not None
        return [
            tuple(r)
            for r in session._rt.store._db.execute(
                "SELECT gap_id, sequence, reason, status FROM capture_gaps WHERE producer_stream = ? ORDER BY sequence",
                (producer_stream,),
            ).fetchall()
        ]

    return loop.run_owner_action(_read).result(timeout=10.0)


def _run_hook_cli_subproc(
    outbox_dir: Path,
    chk: Path,
    payload: dict[str, Any],
    *,
    producer_stream: str | None = None,
    crashpoint: str | None = None,
) -> subprocess.CompletedProcess[str]:
    cmd = [
        sys.executable,
        "-I",
        "-m",
        "superbrain.composition.hook_entry",
        "--outbox",
        str(outbox_dir),
        "--harness",
        "claude-code",
        "--checkout",
        str(chk),
    ]
    if producer_stream is not None:
        cmd.extend(["--producer-stream", producer_stream])
    extra = {"SUPERBRAIN_CRASHPOINT": crashpoint} if crashpoint is not None else None
    return subprocess.run(
        cmd,
        cwd=chk,
        env=clean_installed_subprocess_env(extra=extra),
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=15.0,
        check=False,
    )


def _run_hook_crash_post_publish_cursor(
    outbox_dir: Path,
    chk: Path,
    payload: dict[str, Any],
    *,
    producer_stream: str,
) -> subprocess.CompletedProcess[str]:
    script = (
        "import os, sys\n"
        "from pathlib import Path\n"
        "import superbrain.storage.outbox as ob_mod\n"
        "import superbrain.storage._outbox_seq as seq_mod\n"
        "from superbrain.composition import hook_entry\n"
        "orig_write = ob_mod.write_stream_cursor\n"
        "def _crash_after_frame(sdir, cursor, perms):\n"
        "    if any(Path(sdir).glob('*.frame')):\n"
        "        sys.stderr.write('CRASHPOINT_HIT post_publish_cursor\\n')\n"
        "        sys.stderr.flush()\n"
        "        os._exit(86)\n"
        "    return orig_write(sdir, cursor, perms)\n"
        "ob_mod.write_stream_cursor = _crash_after_frame\n"
        "seq_mod.write_stream_cursor = _crash_after_frame\n"
        "raise SystemExit(hook_entry.main(sys.argv[1:]))\n"
    )
    return subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            script,
            "--outbox",
            str(outbox_dir),
            "--harness",
            "claude-code",
            "--checkout",
            str(chk),
            "--producer-stream",
            producer_stream,
        ],
        cwd=chk,
        env=clean_installed_subprocess_env(),
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=15.0,
        check=False,
    )


def test_r6_finding1_hook_binding_survives_pre_and_post_publish_crashes_and_post_ack_retry(
    trusted_tmp: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Hook binding keeps exact (stream, sequence, event_id) across pre/post-publish crashes, ACK, & conflict."""
    _install_fake_host_bins(trusted_tmp, monkeypatch)
    clock = FakeClock(datetime.now(UTC).replace(microsecond=0))
    mono = FakeMonotonicClock(1_000_000_000)
    os_ = os_adapters(clock=clock, monotonic=mono)
    _priv, s_enr = _ssh_signer()

    cfg_dir = trusted_tmp / "cfg"
    data_root = trusted_tmp / "data"
    chk_a = trusted_tmp / "chk-r6"
    for d in (cfg_dir, chk_a):
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

    rt = reopen_kernel_job_runtime(data_root, rep.store_id, os_)
    try:
        mcp_c = seed_principal_and_credential(rt.policy, owner_id=_OWNER, harness_id="claude-code", machine_id=_MACHINE)
        cap_a = seed_principal_and_credential(rt.policy, owner_id=_OWNER, harness_id="claude-code", machine_id=_MACHINE)
        cap_b = seed_principal_and_credential(rt.policy, owner_id=_OWNER, harness_id="claude-code", machine_id=_MACHINE)
        cap_c2 = seed_principal_and_credential(
            rt.policy, owner_id=_OWNER, harness_id="claude-code", machine_id=_MACHINE
        )
        ws_a = register_workspace_direct(rt, clock, mcp_c.principal, alias="ws-r6", checkout_dir=chk_a)
        rt.store.reconcile_policy()
    finally:
        rt.close()

    with _serve_daemon(cfg, os_, clock, mono) as (ready, loop):
        target = LoopbackTarget(
            endpoint=ready.endpoint,
            expected_store_id=rep.store_id,
            ca_pem=ca_pem,
            leaf_cert_sha256=ready.leaf_cert_sha256,
        )
        cap_client = CaptureClient(LoopbackClient(monotonic_ns=mono.monotonic_ns))

        # --- Case A: Window 1 crash (before frame publish via SUPERBRAIN_CRASHPOINT) ---
        outbox_a = trusted_tmp / "outbox-r6-w1"
        ev_w1_1 = _observed_claude_post_tool(chk_a, tool_use_id="toolu_r6_w1", cmd="pytest -k w1")
        ev_w1_2 = _observed_claude_post_tool(chk_a, tool_use_id="toolu_r6_w1_2", cmd="pytest -k w1_2")

        p_w1_crash = _run_hook_cli_subproc(
            outbox_a,
            chk_a,
            ev_w1_1,
            crashpoint="capture.outbox.after_write_before_fsync",
        )
        assert p_w1_crash.returncode == 86, (p_w1_crash.returncode, p_w1_crash.stderr)
        assert "CRASHPOINT_HIT capture.outbox.after_write_before_fsync" in p_w1_crash.stderr

        spool_a = OutboxSpool(outbox_a, permissions=os_.permissions)
        assert spool_a.read_pending(limit=10) == []

        p_w1_retry = _run_hook_cli_subproc(outbox_a, chk_a, ev_w1_1)
        assert p_w1_retry.returncode == 0, p_w1_retry.stderr
        pend_a1 = _pending_event_tuples(spool_a)
        assert len(pend_a1) == 1 and pend_a1[0][0] == 1
        ev_id_1 = pend_a1[0][1]
        stream_a = spool_a.read_pending(limit=10)[0].producer_stream

        p_w1_next = _run_hook_cli_subproc(outbox_a, chk_a, ev_w1_2)
        assert p_w1_next.returncode == 0, p_w1_next.stderr
        pend_a2 = _pending_event_tuples(spool_a, producer_stream=stream_a)
        assert len(pend_a2) == 2
        assert pend_a2[0] == (1, ev_id_1)
        assert pend_a2[1][0] == 2 and pend_a2[1][1] != ev_id_1
        ev_id_2 = pend_a2[1][1]

        _publish_capture_creds(loop, [(cap_a, stream_a, ws_a)])
        ack_a = drain_outbox(
            spool_a,
            client=cap_client,
            target=target,
            producer_stream=stream_a,
            repo_id=ws_a.repo_id,
            checkout_id=ws_a.checkout_id,
            token=cap_a.token,
        )
        assert ack_a is not None and ack_a.accepted_count == 2
        assert ack_a.contiguous_event_acked_through == 2
        assert [(r[0], r[1]) for r in _capture_events_for_stream(loop, stream_a)] == [(1, ev_id_1), (2, ev_id_2)]
        assert _capture_gaps_for_stream(loop, stream_a) == []

        # --- Case B: Window 2 crash (AFTER frame publish, BEFORE post-publish cursor update) + retry while pending ---
        outbox_b = trusted_tmp / "outbox-r6-w2a"
        stream_b = "stream-r6-w2a"
        ev_w2a_1 = _observed_claude_post_tool(chk_a, tool_use_id="toolu_r6_w2a", cmd="pytest -k w2a")
        ev_w2a_2 = _observed_claude_post_tool(chk_a, tool_use_id="toolu_r6_w2a_2", cmd="pytest -k w2a_2")

        p_w2a_crash = _run_hook_crash_post_publish_cursor(outbox_b, chk_a, ev_w2a_1, producer_stream=stream_b)
        assert p_w2a_crash.returncode == 86, (p_w2a_crash.returncode, p_w2a_crash.stderr)

        spool_b = OutboxSpool(outbox_b, permissions=os_.permissions)
        pend_b1 = _pending_event_tuples(spool_b, producer_stream=stream_b)
        assert len(pend_b1) == 1 and pend_b1[0][0] == 1
        ev_id_a = pend_b1[0][1]

        p_w2a_retry = _run_hook_cli_subproc(outbox_b, chk_a, ev_w2a_1, producer_stream=stream_b)
        assert p_w2a_retry.returncode == 0, p_w2a_retry.stderr
        assert _pending_event_tuples(spool_b, producer_stream=stream_b) == [(1, ev_id_a)]

        p_w2a_next = _run_hook_cli_subproc(outbox_b, chk_a, ev_w2a_2, producer_stream=stream_b)
        assert p_w2a_next.returncode == 0, p_w2a_next.stderr
        pend_b2 = _pending_event_tuples(spool_b, producer_stream=stream_b)
        assert len(pend_b2) == 2 and pend_b2[0] == (1, ev_id_a) and pend_b2[1][0] == 2
        ev_id_b = pend_b2[1][1]
        assert ev_id_b != ev_id_a

        _publish_capture_creds(loop, [(cap_a, stream_a, ws_a), (cap_b, stream_b, ws_a)])
        ack_b = drain_outbox(
            spool_b,
            client=cap_client,
            target=target,
            producer_stream=stream_b,
            repo_id=ws_a.repo_id,
            checkout_id=ws_a.checkout_id,
            token=cap_b.token,
        )
        assert ack_b is not None and ack_b.accepted_count == 2
        assert ack_b.contiguous_event_acked_through == 2
        assert [(r[0], r[1]) for r in _capture_events_for_stream(loop, stream_b)] == [(1, ev_id_a), (2, ev_id_b)]
        assert _capture_gaps_for_stream(loop, stream_b) == []

        # --- Case C: Window 2 crash + drain/ACK eviction FIRST + retry AFTER ACK + subsequent new event ---
        outbox_c = trusted_tmp / "outbox-r6-w2b"
        stream_c = "stream-r6-w2b"
        ev_w2b_1 = _observed_claude_post_tool(chk_a, tool_use_id="toolu_r6_w2b", cmd="pytest -k w2b")
        ev_w2b_2 = _observed_claude_post_tool(chk_a, tool_use_id="toolu_r6_w2b_2", cmd="pytest -k w2b_2")

        p_w2b_crash = _run_hook_crash_post_publish_cursor(outbox_c, chk_a, ev_w2b_1, producer_stream=stream_c)
        assert p_w2b_crash.returncode == 86, (p_w2b_crash.returncode, p_w2b_crash.stderr)

        spool_c = OutboxSpool(outbox_c, permissions=os_.permissions)
        pend_c1 = _pending_event_tuples(spool_c, producer_stream=stream_c)
        assert len(pend_c1) == 1 and pend_c1[0][0] == 1
        ev_id_b1 = pend_c1[0][1]

        _publish_capture_creds(
            loop,
            [(cap_a, stream_a, ws_a), (cap_b, stream_b, ws_a), (cap_c2, stream_c, ws_a)],
        )
        ack_c1 = drain_outbox(
            spool_c,
            client=cap_client,
            target=target,
            producer_stream=stream_c,
            repo_id=ws_a.repo_id,
            checkout_id=ws_a.checkout_id,
            token=cap_c2.token,
        )
        assert ack_c1 is not None and ack_c1.accepted_count == 1
        assert ack_c1.contiguous_event_acked_through == 1
        assert spool_c.read_pending(limit=10, producer_stream=stream_c) == []

        p_w2b_retry = _run_hook_cli_subproc(outbox_c, chk_a, ev_w2b_1, producer_stream=stream_c)
        assert p_w2b_retry.returncode == 0, p_w2b_retry.stderr
        pend_c_retry = _pending_event_tuples(spool_c, producer_stream=stream_c)
        assert pend_c_retry in ([], [(1, ev_id_b1)]), f"retry must never allocate seq=2: {pend_c_retry}"
        if pend_c_retry:
            ack_cr = drain_outbox(
                spool_c,
                client=cap_client,
                target=target,
                producer_stream=stream_c,
                repo_id=ws_a.repo_id,
                checkout_id=ws_a.checkout_id,
                token=cap_c2.token,
            )
            assert ack_cr is not None and ack_cr.accepted_count == 0 and ack_cr.deduped_count == 1

        p_w2b_next = _run_hook_cli_subproc(outbox_c, chk_a, ev_w2b_2, producer_stream=stream_c)
        assert p_w2b_next.returncode == 0, p_w2b_next.stderr
        pend_c2 = _pending_event_tuples(spool_c, producer_stream=stream_c)
        assert len(pend_c2) == 1 and pend_c2[0][0] == 2 and pend_c2[0][1] != ev_id_b1
        ev_id_b2 = pend_c2[0][1]

        ack_c2 = drain_outbox(
            spool_c,
            client=cap_client,
            target=target,
            producer_stream=stream_c,
            repo_id=ws_a.repo_id,
            checkout_id=ws_a.checkout_id,
            token=cap_c2.token,
        )
        assert ack_c2 is not None and ack_c2.accepted_count == 1
        assert ack_c2.contiguous_event_acked_through == 2
        assert [(r[0], r[1]) for r in _capture_events_for_stream(loop, stream_c)] == [(1, ev_id_b1), (2, ev_id_b2)]
        assert _capture_gaps_for_stream(loop, stream_c) == []

    # --- Case D1: Gap fallback uses bound sequence, retry publishes event at seq=1, next gets seq=2 ---
    outbox_d1 = trusted_tmp / "outbox-r6-d1"
    stream_d1 = "stream-r6-d1"
    ev_d1_1 = _observed_claude_post_tool(chk_a, tool_use_id="toolu_r6_d1", cmd="pytest -k d1")
    ev_d1_2 = _observed_claude_post_tool(chk_a, tool_use_id="toolu_r6_d1_2", cmd="pytest -k d1_2")

    publish_failed = [False]

    class _FailPublishOnceSpool(OutboxSpool):
        def _atomic_publish_frame(
            self,
            final_path: Path,
            part_path: Path,
            frame_bytes: bytes,
            *,
            crashpoint_name: str | None = None,
            deadline_ns: int | None = None,
        ) -> None:
            if f"_{OUTBOX_RECORD_EVENT}_" in final_path.name and not publish_failed[0]:
                publish_failed[0] = True
                raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "simulated frame publish deadline exceeded")
            super()._atomic_publish_frame(
                final_path,
                part_path,
                frame_bytes,
                crashpoint_name=crashpoint_name,
                deadline_ns=deadline_ns,
            )

    assert (
        hook_entry.run_hook(
            json.dumps(ev_d1_1).encode("utf-8"),
            outbox_dir=outbox_d1,
            default_harness_id="claude-code",
            checkout_root=chk_a,
            producer_stream=stream_d1,
            spool_factory=lambda ob: _FailPublishOnceSpool(ob, permissions=os_.permissions),
        )
        == 0
    )
    spool_d1 = OutboxSpool(outbox_d1, permissions=os_.permissions)
    d1_gap_entries = spool_d1.read_pending(limit=10, producer_stream=stream_d1)
    assert len(d1_gap_entries) == 1
    assert d1_gap_entries[0].record_kind == OUTBOX_RECORD_GAP
    assert d1_gap_entries[0].sequence == 1

    assert (
        hook_entry.run_hook(
            json.dumps(ev_d1_1).encode("utf-8"),
            outbox_dir=outbox_d1,
            default_harness_id="claude-code",
            checkout_root=chk_a,
            producer_stream=stream_d1,
        )
        == 0
    )
    d1_ev_pend = _pending_event_tuples(spool_d1, producer_stream=stream_d1)
    assert len(d1_ev_pend) == 1 and d1_ev_pend[0][0] == 1
    ev_id_d1 = d1_ev_pend[0][1]

    assert (
        hook_entry.run_hook(
            json.dumps(ev_d1_2).encode("utf-8"),
            outbox_dir=outbox_d1,
            default_harness_id="claude-code",
            checkout_root=chk_a,
            producer_stream=stream_d1,
        )
        == 0
    )
    d1_ev_pend2 = _pending_event_tuples(spool_d1, producer_stream=stream_d1)
    assert len(d1_ev_pend2) == 2 and d1_ev_pend2[0] == (1, ev_id_d1) and d1_ev_pend2[1][0] == 2

    # --- Case D2: Payload conflict on same dedup_key AFTER ACK fails closed with IDEMPOTENCY_CONFLICT ---
    outbox_d2 = trusted_tmp / "outbox-r6-d2"
    spool_d2 = OutboxSpool(outbox_d2, permissions=os_.permissions)
    stream_d2 = "stream-r6-d2"
    dk_d2 = digest_bytes(b"r6-conflict-dedup-key")

    rec_orig = spool_d2.enqueue_hook_event(
        producer_stream=stream_d2,
        build_event=lambda seq, ev_id, rec_at: CaptureEventRecord(
            event_id=ev_id,
            producer_stream=stream_d2,
            sequence=seq,
            harness_id="claude-code",
            kind="command_result",
            recorded_at=rec_at,
            payload={"command": "pytest -k original"},
        ),
        dedup_key=dk_d2,
        fallback_recorded_at="2026-11-27T05:00:00Z",
    )
    assert rec_orig.sequence == 1
    assert (
        spool_d2.apply_ack(
            CaptureBatchAck(
                producer_stream=stream_d2,
                repo_id="repo-d2",
                checkout_id="chk-d2",
                committed_event_sequences=(1,),
                contiguous_event_acked_through=1,
                acked_producer_gap_sequences=(),
                accepted_count=1,
                deduped_count=0,
                policy_disabled=False,
            )
        )
        == 1
    )
    assert spool_d2.read_pending(limit=10, producer_stream=stream_d2) == []

    with pytest.raises(BrainError) as conflict_err:
        spool_d2.enqueue_hook_event(
            producer_stream=stream_d2,
            build_event=lambda seq, ev_id, rec_at: CaptureEventRecord(
                event_id=ev_id,
                producer_stream=stream_d2,
                sequence=seq,
                harness_id="claude-code",
                kind="command_result",
                recorded_at=rec_at,
                payload={"command": "pytest -k tampered-different-payload"},
            ),
            dedup_key=dk_d2,
            fallback_recorded_at="2026-11-27T05:00:05Z",
        )
    assert conflict_err.value.code is ErrorCode.IDEMPOTENCY_CONFLICT


# ---------------------------------------------------------------------------
# Round-7 Review Regression (P1: durable hook dedup across >=512 ACKed entries
# and fail-closed binding cap)
# ---------------------------------------------------------------------------


def test_r7_finding1_hook_dedup_survives_512_entries_and_fails_closed_at_cap(
    trusted_tmp: Path,
) -> None:
    """Hook dedup preserves exact (stream, sequence, event_id) past 512 entries & fails closed at cap."""
    os_ = os_adapters()
    # Seeding the first ~510 entries only fills the dedup window; skipping fsync there (about 70% of an enqueue)
    # keeps the test off the gate's critical path. Every boundary entry, crash and retry below 511 runs real fsync.
    seeding = pytest.MonkeyPatch()
    chk_a = trusted_tmp / "chk-r7"
    chk_a.mkdir(parents=True, exist_ok=True)
    os_.permissions.secure_directory(chk_a)

    def _enqueue_seq(
        sp: OutboxSpool,
        *,
        stream: str,
        dk: str,
        payload: dict[str, Any],
        rec_at: str = "2026-11-27T07:00:00Z",
    ) -> CaptureEventRecord:
        return sp.enqueue_hook_event(
            producer_stream=stream,
            build_event=lambda seq, ev_id, ts: CaptureEventRecord(
                event_id=ev_id,
                producer_stream=stream,
                sequence=seq,
                harness_id="claude-code",
                kind="command_result",
                recorded_at=ts,
                payload=payload,
            ),
            dedup_key=dk,
            fallback_recorded_at=rec_at,
        )

    def _ack_range(sp: OutboxSpool, *, stream: str, start_seq: int, end_seq: int) -> None:
        evicted = sp.apply_ack(
            CaptureBatchAck(
                producer_stream=stream,
                repo_id="repo-r7",
                checkout_id="chk-r7",
                committed_event_sequences=tuple(range(start_seq, end_seq + 1)),
                contiguous_event_acked_through=end_seq,
                acked_producer_gap_sequences=(),
                accepted_count=end_seq - start_seq + 1,
                deduped_count=0,
                policy_disabled=False,
            )
        )
        assert evicted == end_seq - start_seq + 1

    # --- Case A (MUST RUN FIRST): Default OutboxSpool past 511 / 512 / 513 ACKed entries + in-flight 514 ---
    outbox_a = trusted_tmp / "outbox-r7-default"
    stream_a = "stream-r7-default"
    spool = OutboxSpool(outbox_a, permissions=os_.permissions)

    dk_1 = digest_bytes(b"r7-dk-1")
    ev_1 = _enqueue_seq(spool, stream=stream_a, dk=dk_1, payload={"idx": 1})
    assert ev_1.sequence == 1
    _ack_range(spool, stream=stream_a, start_seq=1, end_seq=1)

    batch_start = 2
    ev_513: CaptureEventRecord | None = None
    seeding.setattr(os, "fsync", lambda _fd: None)
    for idx in range(2, 514):
        if idx == 511:
            seeding.undo()
        rec = _enqueue_seq(spool, stream=stream_a, dk=digest_bytes(f"r7-dk-{idx}".encode()), payload={"idx": idx})
        if idx in (511, 512, 513):
            assert rec.sequence == idx
        if idx == 513:
            ev_513 = rec
        if idx in (100, 200, 300, 400, 510, 511, 512, 513):
            _ack_range(spool, stream=stream_a, start_seq=batch_start, end_seq=idx)
            batch_start = idx + 1
    assert ev_513 is not None
    assert spool.read_pending(limit=10, producer_stream=stream_a) == []

    # In-flight "bound" event at seq=514 via python -I crash before frame publish.
    ev_inflight_514 = _observed_claude_post_tool(chk_a, tool_use_id="toolu_r7_inflight_514", cmd="pytest -k r7_514")
    p_crash = _run_hook_cli_subproc(
        outbox_a,
        chk_a,
        ev_inflight_514,
        producer_stream=stream_a,
        crashpoint="capture.outbox.after_write_before_fsync",
    )
    assert p_crash.returncode == 86, (p_crash.returncode, p_crash.stderr)
    assert spool.read_pending(limit=10, producer_stream=stream_a) == []

    # Reopen spool (simulating restart) and verify retries, conflict, in-flight retry, and next sequence.
    spool2 = OutboxSpool(outbox_a, permissions=os_.permissions)

    retry_1 = _enqueue_seq(spool2, stream=stream_a, dk=dk_1, payload={"idx": 1})
    assert (retry_1.event_id, retry_1.sequence) == (ev_1.event_id, 1)
    assert spool2.read_pending(limit=10, producer_stream=stream_a) == []

    dk_513 = digest_bytes(b"r7-dk-513")
    retry_513 = _enqueue_seq(spool2, stream=stream_a, dk=dk_513, payload={"idx": 513})
    assert (retry_513.event_id, retry_513.sequence) == (ev_513.event_id, 513)
    assert spool2.read_pending(limit=10, producer_stream=stream_a) == []

    with pytest.raises(BrainError) as err_tamper:
        _enqueue_seq(spool2, stream=stream_a, dk=dk_1, payload={"idx": 1, "tampered": True})
    assert err_tamper.value.code is ErrorCode.IDEMPOTENCY_CONFLICT

    p_retry_514 = _run_hook_cli_subproc(outbox_a, chk_a, ev_inflight_514, producer_stream=stream_a)
    assert p_retry_514.returncode == 0, p_retry_514.stderr
    pend_514 = _pending_event_tuples(spool2, producer_stream=stream_a)
    assert len(pend_514) == 1 and pend_514[0][0] == 514
    ev_514_id = pend_514[0][1]

    ev_515 = _enqueue_seq(spool2, stream=stream_a, dk=digest_bytes(b"r7-dk-515"), payload={"idx": 515})
    assert ev_515.sequence == 515
    assert _pending_event_tuples(spool2, producer_stream=stream_a) == [(514, ev_514_id), (515, ev_515.event_id)]

    # --- Case B: Explicit contract cap boundary max_binding_keys=512 at 511 / 512 / 513 ---
    outbox_b = trusted_tmp / "outbox-r7-cap512"
    stream_b = "stream-r7-cap512"
    spool_b: OutboxSpool = cast(Any, OutboxSpool)(outbox_b, permissions=os_.permissions, max_binding_keys=512)

    dk_1_b = digest_bytes(b"r7b-dk-1")
    ev_1_b = _enqueue_seq(spool_b, stream=stream_b, dk=dk_1_b, payload={"idx": 1})
    assert ev_1_b.sequence == 1

    b_batch_start = 1
    ev_511_b: CaptureEventRecord | None = None
    seeding.setattr(os, "fsync", lambda _fd: None)
    for idx in range(2, 512):
        if idx == 511:
            seeding.undo()
        rec_b = _enqueue_seq(spool_b, stream=stream_b, dk=digest_bytes(f"r7b-dk-{idx}".encode()), payload={"idx": idx})
        if idx == 511:
            assert rec_b.sequence == 511
            ev_511_b = rec_b
        if idx in (100, 200, 300, 400, 500, 511):
            _ack_range(spool_b, stream=stream_b, start_seq=b_batch_start, end_seq=idx)
            b_batch_start = idx + 1
    assert ev_511_b is not None
    assert spool_b.read_pending(limit=10, producer_stream=stream_b) == []

    # Bind Event 512 as in-flight "bound" (no .frame published) right at cap 512.
    class _FailBound512Spool(OutboxSpool):
        def _atomic_publish_frame(
            self,
            final_path: Path,
            part_path: Path,
            frame_bytes: bytes,
            *,
            crashpoint_name: str | None = None,
            deadline_ns: int | None = None,
        ) -> None:
            raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "simulated pre-publish failure at cap 512")

    dk_512_b = digest_bytes(b"r7b-dk-512")
    bound_512_ids: list[str] = []
    spool_b_fail: OutboxSpool = cast(Any, _FailBound512Spool)(
        outbox_b, permissions=os_.permissions, max_binding_keys=512
    )

    def _build_512(seq: int, ev_id: str, ts: str) -> CaptureEventRecord:
        bound_512_ids.append(ev_id)
        return CaptureEventRecord(
            event_id=ev_id,
            producer_stream=stream_b,
            sequence=seq,
            harness_id="claude-code",
            kind="command_result",
            recorded_at=ts,
            payload={"idx": 512},
        )

    with pytest.raises(BrainError) as err_512:
        spool_b_fail.enqueue_hook_event(
            producer_stream=stream_b,
            build_event=_build_512,
            dedup_key=dk_512_b,
            fallback_recorded_at="2026-11-27T07:05:12Z",
        )
    assert err_512.value.code is ErrorCode.DEADLINE_EXCEEDED
    assert len(bound_512_ids) == 1
    ev_512_expected_id = bound_512_ids[0]
    assert spool_b.read_pending(limit=10, producer_stream=stream_b) == []

    # Reopen with max_binding_keys=512 and verify exact cap semantics.
    spool_b2: OutboxSpool = cast(Any, OutboxSpool)(outbox_b, permissions=os_.permissions, max_binding_keys=512)

    rb_1 = _enqueue_seq(spool_b2, stream=stream_b, dk=dk_1_b, payload={"idx": 1})
    assert (rb_1.event_id, rb_1.sequence) == (ev_1_b.event_id, 1)
    assert spool_b2.read_pending(limit=10, producer_stream=stream_b) == []

    dk_511_b = digest_bytes(b"r7b-dk-511")
    rb_511 = _enqueue_seq(spool_b2, stream=stream_b, dk=dk_511_b, payload={"idx": 511})
    assert (rb_511.event_id, rb_511.sequence) == (ev_511_b.event_id, 511)
    assert spool_b2.read_pending(limit=10, producer_stream=stream_b) == []

    dk_513_b = digest_bytes(b"r7b-dk-513")
    with pytest.raises(BrainError) as full_err_1:
        _enqueue_seq(spool_b2, stream=stream_b, dk=dk_513_b, payload={"idx": 513})
    assert full_err_1.value.code is ErrorCode.STORAGE_FULL

    rb_512 = _enqueue_seq(
        spool_b2, stream=stream_b, dk=dk_512_b, payload={"idx": 512}, rec_at="2026-11-27T07:05:12Z"
    )
    assert (rb_512.event_id, rb_512.sequence) == (ev_512_expected_id, 512)
    assert _pending_event_tuples(spool_b2, producer_stream=stream_b) == [(512, ev_512_expected_id)]

    rb_1_again = _enqueue_seq(spool_b2, stream=stream_b, dk=dk_1_b, payload={"idx": 1})
    assert (rb_1_again.event_id, rb_1_again.sequence) == (ev_1_b.event_id, 1)
    assert _pending_event_tuples(spool_b2, producer_stream=stream_b) == [(512, ev_512_expected_id)]

    _ack_range(spool_b2, stream=stream_b, start_seq=512, end_seq=512)
    assert spool_b2.read_pending(limit=10, producer_stream=stream_b) == []

    with pytest.raises(BrainError) as full_err_2:
        _enqueue_seq(spool_b2, stream=stream_b, dk=dk_513_b, payload={"idx": 513})
    assert full_err_2.value.code is ErrorCode.STORAGE_FULL
