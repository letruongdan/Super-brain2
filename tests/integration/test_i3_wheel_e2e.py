"""I3-5 installed-wheel synthetic E2E oracle covering §20 cases 12, 14, 15, 31 within Gate F4 budget.

Uses session-scoped ``inc2_installed_env`` and clean isolated checkouts for Claude Code and Codex.
"""

from __future__ import annotations

import base64
import hashlib
import json
import socket
import ssl
import struct
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import cbor2
import pytest
import tomlkit
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from superbrain.adapters.harness_config.bootstrap_templates import (
    AUTHORITY_ASK_COMMANDS,
    HANDOFF_RULE_TEXT,
    LAYER1_RULE_TEXT,
)
from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.daemon_config import read_daemon_config
from superbrain.core._kernel_approval import (
    APPROVAL_NAMESPACE,
    RISK_POLICY_VERSION,
    ApprovalAction,
    ApprovalChannel,
    ApprovalMessage,
    Layer2State,
    RecoveryScope,
    RiskLevel,
    SignerEnrollment,
)
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import Endpoint, ResourceDigest
from superbrain.storage.backup import create_policy_backup, create_store_backup
from tests.support import rereview_1d666f5 as rr
from tests.support.clock import FakeClock
from tests.support.fs import digest_tree
from tests.support.inc2_cli import (
    InstalledMcpPipeSession,
    is_writer_lock_held,
    mcp_call_frame,
    mcp_init_frames,
    run_installed_command,
    spawn_installed_fixture_daemon,
    write_client_profile_file,
    write_credential_file,
    write_owner_only_bytes,
)
from tests.support.inc2_fixture import InstalledEnv, reopen_kernel_job_runtime
from tests.support.inc2_transport import read_raw_http_response, register_workspace_direct
from tests.support.kernel_auth import seed_principal_and_credential

OWNER = "dan"
MACHINE = "e2e-box"


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _ssh_sig_b64(priv: Ed25519PrivateKey, payload: bytes) -> str:
    raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def _s(d: bytes) -> bytes:
        return struct.pack(">I", len(d)) + d

    blob = _s(b"ssh-ed25519") + _s(raw)
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


def _passkey_sign(
    key: ec.EllipticCurvePrivateKey, cred_id: bytes, challenge: bytes, *, origin: str, sign_count: int
) -> str:
    auth_data = hashlib.sha256(b"localhost").digest() + bytes([0x05]) + struct.pack(">I", sign_count)
    client_data = json.dumps(
        {"type": "webauthn.get", "challenge": _b64u(challenge), "origin": origin, "crossOrigin": False}
    ).encode("utf-8")
    sig = key.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
    return json.dumps(
        {
            "id": _b64u(cred_id),
            "rawId": _b64u(cred_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": _b64u(client_data),
                "authenticatorData": _b64u(auth_data),
                "signature": _b64u(sig),
                "userHandle": None,
            },
        }
    )


def _post_daemon(endpoint: Endpoint, ca_pem: str, path: str, token: str, obj: object) -> dict[str, Any]:
    host = f"{endpoint.host}:{endpoint.port}"
    body = json.dumps(obj).encode("utf-8")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cadata=ca_pem)
    ctx.check_hostname = True
    with (
        socket.create_connection((endpoint.host, endpoint.port), timeout=2.0) as raw,
        ctx.wrap_socket(raw, server_hostname="127.0.0.1") as sock,
    ):
        sock.settimeout(3.0)
        sock.sendall(f"GET /v2/identity HTTP/1.1\r\nHost: {host}\r\n\r\n".encode("ascii"))
        assert read_raw_http_response(sock, timeout=3.0).startswith(b"HTTP/1.1 200 ")
        hdr = (
            f"POST {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {token}\r\n"
            f"X-Store-Id: {endpoint.store_id}\r\nX-Writer-Epoch: {endpoint.writer_epoch}\r\n"
            f"X-Superbrain-Instance: {endpoint.instance_id}\r\n"
            f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n"
        ).encode("iso-8859-1")
        sock.sendall(hdr + body)
        resp = read_raw_http_response(sock, timeout=5.0)
    _, _, payload = resp.partition(b"\r\n\r\n")
    return cast(dict[str, Any], json.loads(payload))


def _web_http(
    port: int, method: str, target: str, headers: list[tuple[str, str]], body: bytes = b""
) -> tuple[int, str | None, dict[str, Any]]:
    lines = [f"{method} {target} HTTP/1.1".encode("ascii")]
    for k, v in headers:
        lines.append(f"{k}: {v}".encode("latin-1"))
    if body:
        lines.append(f"Content-Length: {len(body)}".encode("ascii"))
    with socket.create_connection(("127.0.0.1", port), timeout=15.0) as sock:
        sock.settimeout(15.0)
        sock.sendall(b"\r\n".join(lines) + b"\r\n\r\n" + body)
        resp = read_raw_http_response(sock, timeout=15.0)
    head_raw, _, payload = resp.partition(b"\r\n\r\n")
    head_lines = head_raw.decode("iso-8859-1").split("\r\n")
    status = int(head_lines[0].split(" ", 2)[1])
    cookie: str | None = None
    for hl in head_lines[1:]:
        if hl.lower().startswith("set-cookie:"):
            cookie = hl.split(":", 1)[1].strip().split(";", 1)[0]
    return status, cookie, cast(dict[str, Any], json.loads(payload))


def test_i3_wheel_synthetic_lifecycle_e2e(inc2_installed_env: InstalledEnv, trusted_tmp: Path) -> None:
    """I3-5 §20 cases 12, 14, 15, 31: init -> doctor -> bootstrap -> SSH & WebAuthn -> rollback -> restore."""
    import superbrain.composition.review_web_entry as review_web_entry

    os_ = os_adapters()
    cwd = trusted_tmp / "outside"
    cwd.mkdir()
    os_.permissions.secure_directory(cwd)
    cfg_dir, data_root = trusted_tmp / "cfg", trusted_tmp / "data"
    cfg_dir.mkdir()
    os_.permissions.secure_directory(cfg_dir)

    priv_ssh = Ed25519PrivateKey.generate()
    raw_ssh = priv_ssh.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ssh_blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", len(raw_ssh)) + raw_ssh
    ssh_pub = "ssh-ed25519 " + base64.b64encode(ssh_blob).decode("ascii") + " e2e@box"
    init_req_file = trusted_tmp / "init-req.json"
    write_owner_only_bytes(
        init_req_file,
        json.dumps(
            {
                "version": 1,
                "data_root": str(data_root),
                "config_dir": str(cfg_dir),
                "owner_id": OWNER,
                "machine_id": MACHINE,
                "signer": {"channel": "ssh_key", "public_key": ssh_pub},
            }
        ).encode("utf-8"),
    )

    # 1. Installed `brain init` + initial `brain doctor --json`.
    init_res = run_installed_command(inc2_installed_env, "brain", ["init", "--config", str(init_req_file)], cwd=cwd)
    assert init_res.returncode == 0, init_res.stderr.decode()
    store_id = json.loads(init_res.stdout)["data"]["store_id"]
    daemon_cfg_path = cfg_dir / "daemon.json"
    cfg = read_daemon_config(daemon_cfg_path, os_)
    ca_pem = (cfg_dir / "tls" / "ca.pem").read_text(encoding="utf-8")
    cli_token = (cfg_dir / "cli.credential").read_text(encoding="ascii").strip()

    doc_init = run_installed_command(
        inc2_installed_env, "brain", ["doctor", "--config", str(daemon_cfg_path), "--json"], cwd=cwd
    )
    assert doc_init.returncode == 0
    doc0 = json.loads(doc_init.stdout)["data"]
    assert doc0["schema"]["store_version"] == 7 and doc0["schema"]["policy_version"] == 5
    assert doc0["restore_epoch"] == 0 and doc0["terminal_channel_eligible"] is False

    # Prepare synthetic WebAuthn key & CLI profile before launching foreground `brain serve`.
    pk_key = ec.generate_private_key(ec.SECP256R1())
    pk_nums = pk_key.public_key().public_numbers()
    pk_cred = b"i3-5-e2e-passkey"
    pk_cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: pk_nums.x.to_bytes(32, "big"), -3: pk_nums.y.to_bytes(32, "big")})
    pk_enr = SignerEnrollment(
        owner_id=OWNER,
        channel=ApprovalChannel.PASSKEY_UV,
        public_key=_b64u(pk_cose),
        credential_id=_b64u(pk_cred),
    )

    # Prepare isolated checkouts A (Claude) and B (Codex) with pre-existing owner content.
    co_a, co_b = trusted_tmp / "co-claude", trusted_tmp / "co-codex"
    for d in (co_a, co_b):
        d.mkdir()
        os_.permissions.secure_directory(d)
    (co_a / "CLAUDE.md").write_text("# Claude User Header\n", encoding="utf-8")
    (co_b / "AGENTS.md").write_text("# Codex User Header\n", encoding="utf-8")
    (co_b / ".codex").mkdir()
    os_.permissions.secure_directory(co_b / ".codex")
    (co_b / ".codex" / "config.toml").write_text("# User toml comment\n[profiles.dev]\nkeep = true\n", encoding="utf-8")

    leaf_sha = hashlib.sha256(
        ssl.PEM_cert_to_DER_cert(cfg.cert_path.read_text(encoding="utf-8"))
    ).hexdigest()
    profile_path, _ = write_client_profile_file(
        trusted_tmp / "cli.profile.json",
        endpoint_path=data_root / "endpoint.json",
        expected_store_id=store_id,
        ca_file=cfg_dir / "tls" / "ca.pem",
        leaf_cert_sha256=leaf_sha,
        credential_file=cfg_dir / "cli.credential",
    )

    seed_clock = FakeClock(datetime.now(UTC).replace(microsecond=0))
    rt_seed = reopen_kernel_job_runtime(data_root, store_id, os_adapters(clock=seed_clock))
    try:
        cred_claude = seed_principal_and_credential(
            rt_seed.policy, owner_id=OWNER, harness_id="claude-code", machine_id=MACHINE
        )
        cred_codex = seed_principal_and_credential(
            rt_seed.policy, owner_id=OWNER, harness_id="codex", machine_id=MACHINE
        )
        ws_a = register_workspace_direct(
            rt_seed,
            seed_clock,
            cred_claude.principal,
            alias="ws-claude-a",
            checkout_dir=co_a,
            remote="https://github.example/dan/repo-a.git",
        )
        ws_b = register_workspace_direct(
            rt_seed,
            seed_clock,
            cred_codex.principal,
            alias="ws-codex-b",
            checkout_dir=co_b,
            remote="https://github.example/dan/repo-b.git",
        )
        rt_seed.policy.set_layer2_state(
            harness_id="claude-code",
            host_version="1.0.0",
            config_digest="sha256:" + "1" * 64,
            state=Layer2State.VERIFIED,
        )
        rt_seed.policy.set_layer2_state(
            harness_id="codex",
            host_version="1.0.0",
            config_digest="sha256:" + "2" * 64,
            state=Layer2State.VERIFIED,
        )
        rt_seed.store.reconcile_policy()
    finally:
        rt_seed.close()

    claude_cred_path = write_credential_file(cfg_dir / "claude-a.credential", cred_claude.token)
    codex_cred_path = write_credential_file(cfg_dir / "codex-b.credential", cred_codex.token)
    claude_a_profile, _ = write_client_profile_file(
        trusted_tmp / "claude-a.profile.json",
        endpoint_path=data_root / "endpoint.json",
        expected_store_id=store_id,
        ca_file=cfg_dir / "tls" / "ca.pem",
        leaf_cert_sha256=leaf_sha,
        credential_file=claude_cred_path,
        workspace={
            "alias": ws_a.alias,
            "checkout_path": str(co_a),
            "expected_workspace_id": ws_a.repo_id,
            "expected_checkout_id": ws_a.checkout_id,
        },
    )
    codex_b_profile, _ = write_client_profile_file(
        trusted_tmp / "codex-b.profile.json",
        endpoint_path=data_root / "endpoint.json",
        expected_store_id=store_id,
        ca_file=cfg_dir / "tls" / "ca.pem",
        leaf_cert_sha256=leaf_sha,
        credential_file=codex_cred_path,
        workspace={
            "alias": ws_b.alias,
            "checkout_path": str(co_b),
            "expected_workspace_id": ws_b.repo_id,
            "expected_checkout_id": ws_b.checkout_id,
        },
    )

    srv_proc = spawn_installed_fixture_daemon(inc2_installed_env, daemon_cfg_path, data_root=data_root, cwd=cwd)
    try:
        ep = srv_proc.wait_ready()
        assert isinstance(ep, Endpoint)

        # 2. Enroll passkey signer using TOFU SSH signer via `/v2/operator/signer/enroll`.
        signers_list = _post_daemon(ep, ca_pem, "/v2/operator/signer/list", cli_token, {})
        tofu_id = signers_list["data"]["signers"][0]["signer_id"]
        enr_payload: dict[str, Any] = {
            "channel": "passkey_uv",
            "public_key": pk_enr.public_key,
            "credential_id": pk_enr.credential_id,
        }
        enr_prev = _post_daemon(ep, ca_pem, "/v2/operator/signer/enroll", cli_token, {"enrollment": enr_payload})
        enr_ch = enr_prev["data"]["challenge"]
        enr_msg = ApprovalMessage(
            store_id=store_id,
            owner_id=OWNER,
            trust_generation=int(enr_ch["trust_generation"]),
            action=ApprovalAction.SIGNER_ENROLL,
            subject_id=str(enr_ch["subject_id"]),
            subject_revision=1,
            resource_digests=(ResourceDigest("signer", pk_enr.key_digest),),
            target_files=(),
            risk_level=RiskLevel.HIGH,
            risk_policy_version=RISK_POLICY_VERSION,
            recovery_scope=RecoveryScope.NONE,
            nonce=str(enr_ch["nonce"]),
            expires_at=datetime.fromisoformat(str(enr_ch["expires_at"]).replace("Z", "+00:00")),
        )
        enr_done = _post_daemon(
            ep,
            ca_pem,
            "/v2/operator/signer/enroll",
            cli_token,
            {
                "enrollment": enr_payload,
                "approval": {
                    "message": enr_msg.to_dict(),
                    "channel": "ssh_key",
                    "signer_id": tofu_id,
                    "signature": _ssh_sig_b64(priv_ssh, enr_msg.canonical_bytes()),
                },
            },
        )
        assert enr_done["ok"] is True
        passkey_signer_id = enr_done["data"]["signer"]["signer_id"]

        # 3. Installed `brain bootstrap` rejects CLI/swapped harness profiles (exit 1) & accepts dedicated ones.
        for bad_hp in (profile_path, codex_b_profile):
            bad_res = run_installed_command(
                inc2_installed_env,
                "brain",
                [
                    "bootstrap",
                    "--harness",
                    "claude-code",
                    "--checkout",
                    str(co_a),
                    "--profile",
                    str(profile_path),
                    "--harness-profile",
                    str(bad_hp),
                    "--json",
                ],
                cwd=cwd,
            )
            assert bad_res.returncode == 1
        assert not (co_a / ".mcp.json").exists()

        # 3b. F1 (1d666f5): a wrong TLS pin / endpoint path / foreign CA never yields a proposal, on BOTH harnesses.
        foreign_base = trusted_tmp / "foreign"
        foreign_base.mkdir()
        os_.permissions.secure_directory(foreign_base)
        foreign_ca = rr.foreign_ca_file(
            foreign_base, os_, owner_id=OWNER, machine_id=MACHINE, signer=rr.ssh_enrollment("foreign", OWNER)
        )
        overrides: dict[str, dict[str, Any]] = {
            "pin": {"leaf_cert_sha256": rr.flip_last_hex_char(leaf_sha)},
            "dir": {"endpoint_path": trusted_tmp / "other-data" / "endpoint.json"},
            "name": {"endpoint_path": data_root / "other.json"},
            "ca": {"ca_file": foreign_ca},
        }
        for harness, co_dir, cred_path, ws_bind in (
            ("claude-code", co_a, claude_cred_path, ws_a),
            ("codex", co_b, codex_cred_path, ws_b),
        ):
            snap_co = digest_tree(co_dir)
            for variant, override in overrides.items():
                profile_args: dict[str, Any] = {
                    "endpoint_path": data_root / "endpoint.json",
                    "expected_store_id": store_id,
                    "ca_file": cfg_dir / "tls" / "ca.pem",
                    "leaf_cert_sha256": leaf_sha,
                    "credential_file": cred_path,
                    "workspace": rr.ws_dict(ws_bind, co_dir),
                    **override,
                }
                bad_path = trusted_tmp / f"{harness}-bad-{variant}.profile.json"
                bad_hp, _ = write_client_profile_file(bad_path, **profile_args)
                direct = _post_daemon(
                    ep, ca_pem, "/v2/operator/proposal/bootstrap", cli_token,
                    {"harness": harness, "checkout_root": str(co_dir), "harness_profile_path": str(bad_hp)},
                )
                assert direct["ok"] is False and direct["error"]["code"] == ErrorCode.IDENTITY_MISMATCH.value, direct
                if (harness, variant) not in {("claude-code", "pin"), ("claude-code", "dir"), ("codex", "name")}:
                    continue
                cli_bad = run_installed_command(
                    inc2_installed_env,
                    "brain",
                    [
                        "bootstrap", "--harness", harness, "--checkout", str(co_dir), "--profile", str(profile_path),
                        "--harness-profile", str(bad_hp), "--json",
                    ],
                    cwd=cwd,
                )
                assert cli_bad.returncode == 1, (harness, variant, cli_bad.stderr)
                assert ErrorCode.IDENTITY_MISMATCH.value in cli_bad.stderr.decode("utf-8", errors="replace")
            assert digest_tree(co_dir) == snap_co

        b_a = run_installed_command(
            inc2_installed_env,
            "brain",
            [
                "bootstrap",
                "--harness",
                "claude-code",
                "--checkout",
                str(co_a),
                "--profile",
                str(profile_path),
                "--harness-profile",
                str(claude_a_profile),
                "--json",
            ],
            cwd=cwd,
        )
        b_b = run_installed_command(
            inc2_installed_env,
            "brain",
            [
                "bootstrap",
                "--harness",
                "codex",
                "--checkout",
                str(co_b),
                "--profile",
                str(profile_path),
                "--harness-profile",
                str(codex_b_profile),
                "--json",
            ],
            cwd=cwd,
        )
        assert b_a.returncode == 0, b_a.stderr.decode()
        assert b_b.returncode == 0, b_b.stderr.decode()
        pid_a = json.loads(b_a.stdout)["data"]["proposal"]["proposal_id"]
        pid_b = json.loads(b_b.stdout)["data"]["proposal"]["proposal_id"]
        assert not (co_a / ".mcp.json").exists() and not (co_b / ".codex" / "hooks.json").exists()

        # 4a. Approve & Apply Claude via installed CLI + `ssh_key`.
        for cli_sub, op_path, scope in (
            (["review", "approve", pid_a], "/v2/operator/proposal/approve", "none"),
            (["apply", pid_a], "/v2/operator/proposal/apply", "continue_or_rollback"),
        ):
            ch_r = _post_daemon(
                ep, ca_pem, op_path, cli_token, {"proposal_id": pid_a, "recovery_scope": scope}
            )["data"]["challenge"]
            msg = ApprovalMessage.from_dict(ch_r)
            ap_file = trusted_tmp / f"ap-{cli_sub[-1]}.json"
            write_owner_only_bytes(
                ap_file,
                json.dumps(
                    {
                        "message": msg.to_dict(),
                        "channel": "ssh_key",
                        "signer_id": tofu_id,
                        "signature": _ssh_sig_b64(priv_ssh, msg.canonical_bytes()),
                    }
                ).encode("utf-8"),
            )
            r_cli = run_installed_command(
                inc2_installed_env,
                "brain",
                [*cli_sub, "--profile", str(profile_path), "--approval-file", str(ap_file)],
                cwd=cwd,
            )
            assert r_cli.returncode == 0, r_cli.stderr.decode()
        claude_md = (co_a / "CLAUDE.md").read_text(encoding="utf-8")
        assert "# Claude User Header" in claude_md and LAYER1_RULE_TEXT in claude_md
        assert HANDOFF_RULE_TEXT in claude_md and str(claude_a_profile) in claude_md
        rr.assert_f2_rule_scope(claude_md)
        assert str(profile_path) not in claude_md
        for cmd in AUTHORITY_ASK_COMMANDS:
            assert cmd in (co_a / ".claude" / "settings.local.json").read_text(encoding="utf-8")

        # 4b. Approve & Apply Codex via `review_web` synthetic WebAuthn `passkey_uv` ceremony!
        for idx, act in enumerate((ApprovalAction.APPROVE, ApprovalAction.APPLY), start=1):
            with review_web_entry.open_review_web_server(profile_path, proposal_id=pid_b, action=act, os_=os_) as wsrv:
                token = wsrv.launch_url.split("#token=", 1)[1]
                st_s, cookie, s_env = _web_http(
                    wsrv.port,
                    "POST",
                    "/api/session",
                    [("Host", f"localhost:{wsrv.port}"), ("Origin", wsrv.origin), ("Content-Type", "application/json")],
                    json.dumps({"token": token}).encode("utf-8"),
                )
                assert st_s == 200 and cookie is not None
                csrf = str(s_env["data"]["csrf_token"])
                st_g, _, g_env = _web_http(
                    wsrv.port,
                    "GET",
                    f"/api/state?action={act.value}",
                    [("Host", f"localhost:{wsrv.port}"), ("Cookie", cookie)],
                )
                assert st_g == 200
                ch_m = g_env["data"]["challenge"]
                ch_bytes = ApprovalMessage.from_dict(ch_m).canonical_bytes()
                resp_json = _passkey_sign(pk_key, pk_cred, ch_bytes, origin=wsrv.origin, sign_count=idx)
                st_sub, _, sub_env = _web_http(
                    wsrv.port,
                    "POST",
                    "/api/submit",
                    [
                        ("Host", f"localhost:{wsrv.port}"),
                        ("Origin", wsrv.origin),
                        ("Cookie", cookie),
                        ("X-CSRF-Token", csrf),
                        ("Content-Type", "application/json"),
                    ],
                    json.dumps(
                        {
                            "action": act.value,
                            "signer_id": passkey_signer_id,
                            "challenge_message": ch_m,
                            "response_json": resp_json,
                        }
                    ).encode("utf-8"),
                )
                assert st_sub == 200 and sub_env["ok"] is True, sub_env

        agents_md = (co_b / "AGENTS.md").read_text(encoding="utf-8")
        assert "# Codex User Header" in agents_md and LAYER1_RULE_TEXT in agents_md
        assert HANDOFF_RULE_TEXT in agents_md and str(codex_b_profile) in agents_md
        rr.assert_f2_rule_scope(agents_md)
        assert str(profile_path) not in agents_md

        # 4c. Parse installed MCP configs directly, run wheel shims in co_a & co_b, and check wrong-CWD refusal!
        mcp_json = json.loads((co_a / ".mcp.json").read_text(encoding="utf-8"))
        entry_a = mcp_json["mcpServers"]["super-brain"]
        assert entry_a["command"] == "brain"
        assert str(claude_a_profile) in entry_a["args"] and str(profile_path) not in entry_a["args"]

        codex_toml = tomlkit.parse((co_b / ".codex" / "config.toml").read_text(encoding="utf-8")).unwrap()
        entry_b = codex_toml["mcp_servers"]["super-brain"]
        assert entry_b["command"] == "brain"
        assert str(codex_b_profile) in entry_b["args"] and str(profile_path) not in entry_b["args"]

        for entry, harness_id, co_dir, expected_ws in (
            (entry_a, "claude-code", co_a, ws_a),
            (entry_b, "codex", co_b, ws_b),
        ):
            init_frames = mcp_init_frames(1)
            prep_frame = mcp_call_frame(
                2,
                "prepare_task",
                {
                    "schema_version": "2.0",
                    "idempotency_key": f"idem-e2e-{harness_id}-1",
                    "task_id": f"task-e2e-{harness_id}-1",
                    "harness_id": harness_id,
                    "description": f"wheel e2e prepare_task for {harness_id}",
                },
            )
            with InstalledMcpPipeSession(
                inc2_installed_env,
                str(entry["command"]),
                [str(a) for a in entry["args"]],
                cwd=co_dir,
            ) as shim_sess:
                resp_init = shim_sess.send_frames_and_expect_response([init_frames[0]])
                assert resp_init.get("id") == 1 and "error" not in resp_init
                resp_prep = shim_sess.send_frames_and_expect_response([init_frames[1], prep_frame])
                assert resp_prep.get("id") == 2 and "error" not in resp_prep
                prep_res = resp_prep["result"]
                assert isinstance(prep_res, dict) and prep_res.get("isError") is False
                sc = prep_res.get("structuredContent")
                assert isinstance(sc, dict) and sc.get("ok") is True
                pdata = sc.get("data")
                assert isinstance(pdata, dict)
                assert pdata.get("workspace_id") == expected_ws.repo_id
                assert pdata.get("checkout_id") == expected_ws.checkout_id
                rc_shim, stderr_shim = shim_sess.finish()
                assert rc_shim == 0 and stderr_shim == b""

        wrong_cwd_res = run_installed_command(
            inc2_installed_env,
            str(entry_a["command"]),
            [str(a) for a in entry_a["args"]],
            cwd=co_b,
            stdin_bytes=b"",
        )
        assert wrong_cwd_res.returncode == 1
        assert ErrorCode.IDENTITY_MISMATCH.value in wrong_cwd_res.stderr.decode("utf-8", errors="replace")

        # 5. Out-of-band U1 edit -> `brain rollback` preserves U1 byte-for-byte!
        toml_u1 = (co_b / ".codex" / "config.toml").read_text(encoding="utf-8") + (
            '\n# U1 comment\n[profiles.u1]\nowner = "keep"\n'
        )
        (co_b / ".codex" / "config.toml").write_text(toml_u1, encoding="utf-8")
        rb_ch = _post_daemon(
            ep, ca_pem, "/v2/operator/proposal/rollback", cli_token, {"proposal_id": pid_b}
        )["data"]["challenge"]
        rb_msg = ApprovalMessage.from_dict(rb_ch)
        rb_file = trusted_tmp / "ap-rb.json"
        write_owner_only_bytes(
            rb_file,
            json.dumps(
                {
                    "message": rb_msg.to_dict(),
                    "channel": "ssh_key",
                    "signer_id": tofu_id,
                    "signature": _ssh_sig_b64(priv_ssh, rb_msg.canonical_bytes()),
                }
            ).encode("utf-8"),
        )
        rb_res = run_installed_command(
            inc2_installed_env,
            "brain",
            ["rollback", pid_b, "--profile", str(profile_path), "--approval-file", str(rb_file)],
            cwd=cwd,
        )
        assert rb_res.returncode == 0, rb_res.stderr.decode()
        final_toml = (co_b / ".codex" / "config.toml").read_text(encoding="utf-8")
        assert "super-brain" not in final_toml and "# User toml comment" in final_toml and "# U1 comment" in final_toml
        assert tomlkit.parse(final_toml).unwrap()["profiles"]["u1"]["owner"] == "keep"
        rc_srv, _, _, _ = srv_proc.signal_and_wait_exit()
        assert rc_srv == 0
    finally:
        srv_proc.close()
        assert not is_writer_lock_held(data_root)

    # 6. Offline backup -> `brain restore --offline` -> `brain doctor` surfaces lock -> reconcile -> clean doctor!
    rt_bak = reopen_kernel_job_runtime(data_root, store_id, os_)
    try:
        store_bak = create_store_backup(rt_bak.store, os_, os_.clock.now())
        pol_bak = create_policy_backup(rt_bak.policy, os_, os_.clock.now())
    finally:
        rt_bak.close()

    for kind, bak_path in (("policy", pol_bak), ("store", store_bak)):
        prev_r = run_installed_command(
            inc2_installed_env,
            "brain",
            [
                "restore",
                "--offline",
                "--kind",
                kind,
                "--backup",
                str(bak_path),
                "--preview",
                "--config",
                str(daemon_cfg_path),
            ],
            cwd=cwd,
        )
        assert prev_r.returncode == 0
        pdata = json.loads(prev_r.stdout)["data"]
        ch = pdata["challenge"]
        msg_r = ApprovalMessage(
            store_id=store_id,
            owner_id=OWNER,
            trust_generation=int(ch["trust_generation"]),
            action=ApprovalAction.RESTORE,
            subject_id=str(ch["subject_id"]),
            subject_revision=1,
            resource_digests=(ResourceDigest("backup", str(pdata["backup_db_digest"])),),
            target_files=(),
            risk_level=RiskLevel.HIGH,
            risk_policy_version=RISK_POLICY_VERSION,
            recovery_scope=RecoveryScope.NONE,
            nonce=str(ch["nonce"]),
            expires_at=datetime.fromisoformat(str(ch["expires_at"]).replace("Z", "+00:00")),
        )
        ap_r = trusted_tmp / f"ap-rest-{kind}.json"
        write_owner_only_bytes(
            ap_r,
            json.dumps(
                {
                    "message": msg_r.to_dict(),
                    "channel": "ssh_key",
                    "signer_id": tofu_id,
                    "signature": _ssh_sig_b64(priv_ssh, msg_r.canonical_bytes()),
                }
            ).encode("utf-8"),
        )
        ex_r = run_installed_command(
            inc2_installed_env,
            "brain",
            [
                "restore",
                "--offline",
                "--kind",
                kind,
                "--backup",
                str(bak_path),
                "--approval-file",
                str(ap_r),
                "--config",
                str(daemon_cfg_path),
            ],
            cwd=cwd,
        )
        assert ex_r.returncode == 0, ex_r.stderr.decode()

    doc_locked = json.loads(
        run_installed_command(
            inc2_installed_env, "brain", ["doctor", "--config", str(daemon_cfg_path), "--json"], cwd=cwd
        ).stdout
    )["data"]
    assert doc_locked["restore_epoch"] >= 1 and len(doc_locked["unresolved_accounting_locks"]) >= 1

    # Reconcile locks: stale restore_epoch refused; current restore_epoch succeeds -> clean doctor!
    rt_rec = reopen_kernel_job_runtime(data_root, store_id, os_)
    try:
        cur_ep = doc_locked["restore_epoch"]
        rev_c = rt_rec.policy.policy_revision()
        gen_c = rt_rec.policy.trust_generation()
        diff_d = "sha256:" + "d" * 64
        from superbrain.core._kernel_approval import policy_change_subject_id

        stale_subj = policy_change_subject_id(
            repo_id_or_global="global",
            base_policy_revision=rev_c,
            base_trust_generation=gen_c,
            base_restore_epoch=0,
            policy_diff_digest=diff_d,
        )
        n_st = rt_rec.policy.issue_nonce(
            action=ApprovalAction.POLICY_CHANGE, subject_id=stale_subj, risk_level=RiskLevel.HIGH
        )
        m_st = ApprovalMessage(
            store_id=store_id, owner_id=OWNER, trust_generation=gen_c, action=ApprovalAction.POLICY_CHANGE,
            subject_id=stale_subj, subject_revision=1, resource_digests=(ResourceDigest("policy_diff", diff_d),),
            target_files=(), risk_level=RiskLevel.HIGH, risk_policy_version=RISK_POLICY_VERSION,
            recovery_scope=RecoveryScope.NONE, nonce=n_st.nonce, expires_at=n_st.expires_at,
        )
        with pytest.raises(BrainError) as err_st:
            rt_rec.policy.reconcile_accounting_locks(
                base_policy_revision=rev_c, base_restore_epoch=0, policy_diff_digest=diff_d,
                approval=m_st, signer_id=tofu_id, channel=ApprovalChannel.SSH_KEY, expected_restore_epoch=cur_ep,
            )
        assert err_st.value.code is ErrorCode.REVISION_CONFLICT

        cur_subj = policy_change_subject_id(
            repo_id_or_global="global",
            base_policy_revision=rev_c,
            base_trust_generation=gen_c,
            base_restore_epoch=cur_ep,
            policy_diff_digest=diff_d,
        )
        n_ok = rt_rec.policy.issue_nonce(
            action=ApprovalAction.POLICY_CHANGE, subject_id=cur_subj, risk_level=RiskLevel.HIGH
        )
        m_ok = ApprovalMessage(
            store_id=store_id, owner_id=OWNER, trust_generation=gen_c, action=ApprovalAction.POLICY_CHANGE,
            subject_id=cur_subj, subject_revision=1, resource_digests=(ResourceDigest("policy_diff", diff_d),),
            target_files=(), risk_level=RiskLevel.HIGH, risk_policy_version=RISK_POLICY_VERSION,
            recovery_scope=RecoveryScope.NONE, nonce=n_ok.nonce, expires_at=n_ok.expires_at,
        )
        rt_rec.policy.reconcile_accounting_locks(
            base_policy_revision=rev_c, base_restore_epoch=cur_ep, policy_diff_digest=diff_d,
            approval=m_ok, signer_id=tofu_id, channel=ApprovalChannel.SSH_KEY, expected_restore_epoch=cur_ep,
        )
    finally:
        rt_rec.close()

    doc_clean = json.loads(
        run_installed_command(
            inc2_installed_env, "brain", ["doctor", "--config", str(daemon_cfg_path), "--json"], cwd=cwd
        ).stdout
    )["data"]
    assert doc_clean["unresolved_accounting_locks"] == [] and doc_clean["overall_status"] == "pass"
