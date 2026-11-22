"""Independent I4-3 oracle tests for online/offline ``brain doctor`` CLI & ``/v2/operator/doctor/report``.

Requirement sources:
- Spec rev 22 §11.3, §13, §14.2, §20.1, §20.26
- Frozen contract ``i4-0-contract.md`` (§4.2 lines 95-119)
- Plan I4-3 (Online & Offline CLI Full Report & Operator Profile Discovery)
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import socket
import sqlite3
import struct
import threading
import time
from collections.abc import Iterator, Mapping
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import superbrain.composition.doctor_entry as doctor_entry
from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.daemon_config import read_client_endpoint, read_daemon_config
from superbrain.adapters.os.tls_material import verify_server_tls_files
from superbrain.application.doctor import DoctorReport
from superbrain.application.owner_loop import OwnerLoop
from superbrain.cli_api.loopback import LoopbackClient, LoopbackTarget, LoopbackTransportError
from superbrain.cli_api.operator import OPERATOR_PATHS
from superbrain.composition import daemon_entry
from superbrain.composition.init_entry import InitReport, InitRequest, init_store
from superbrain.core._kernel_approval import (
    CLI_HARNESS_ID,
    RISK_POLICY_VERSION,
    ApprovalAction,
    ApprovalChannel,
    ApprovalMessage,
    RecoveryScope,
    RiskLevel,
    SignerEnrollment,
)
from superbrain.core._kernel_base import ResourceDigest
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import SAFE_WIRE_MESSAGES, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.kernel import (
    TOTAL_REQUEST_BUDGET_NS,
    DaemonConfig,
    Endpoint,
    Ready,
    ToolCommand,
)
from superbrain.ports.doctor import DoctorSnapshot
from superbrain.ports.os import DurabilityReport, LockFactory, LockHandle, LockProbePort, NoReplacePublisher, OsAdapters
from superbrain.ports.policy import IntentKind
from superbrain.storage._doctor_reader import StorageDoctorReader
from superbrain.storage.backup import create_policy_backup, create_store_backup, verify_backup
from superbrain.storage.cas import blob_path
from superbrain.storage.kernel_schema import KERNEL_POLICY_MIGRATIONS, KERNEL_STORE_MIGRATIONS
from superbrain.storage.layout import DataRoot
from superbrain.storage.writer import acquire_writer_unbumped
from tests.support.clock import FakeClock
from tests.support.fs import digest_tree
from tests.support.inc2_cli import (
    is_writer_lock_held,
    run_installed_command,
    spawn_installed_brain_serve,
    write_client_profile_file,
    write_credential_file,
    write_owner_only_bytes,
)
from tests.support.inc2_fixture import InstalledEnv, reopen_kernel_job_runtime
from tests.support.inc2_transport import register_workspace_direct
from tests.support.kernel_auth import make_bootstrap_auth, seed_principal_and_credential
from tests.support.rereview_1d666f5 import flip_last_hex_char, leaf_sha

OWNER = "dan"
MACHINE = "i4-3-box"
BOUND_WAIT_S = 10.0

DOCTOR_REPORT_DTO_KEYS: frozenset[str] = frozenset(
    {
        "overall_status",
        "data_root",
        "store_id",
        "schema",
        "restore_epoch",
        "trust_generation",
        "signer_reset_recorded",
        "signers",
        "terminal_channel_eligible",
        "layer2_harnesses",
        "unresolved_accounting_locks",
        "pending_restore_tombstones",
        "pending_proposals",
        "bootstrap_drifts",
        "checks",
        "remediations",
        "integrity_errors",
        "active_turn_intents",
        "incomplete_journals",
        "permission_problems",
    }
)


def _base_utc_now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0) - timedelta(minutes=10)


def _ssh_signer_key(owner_id: str = OWNER) -> tuple[Ed25519PrivateKey, SignerEnrollment]:
    priv = Ed25519PrivateKey.generate()
    raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", len(raw)) + raw
    line = "ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + f" {owner_id}@i4-3"
    return priv, SignerEnrollment(owner_id=owner_id, channel=ApprovalChannel.SSH_KEY, public_key=line)


def _ssh_sig_b64(priv: Ed25519PrivateKey, payload: bytes) -> str:
    raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", len(raw)) + raw

    def _s(data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + data

    ns = b"ensemble-brain-approval"
    signed = b"SSHSIG" + _s(ns) + _s(b"") + _s(b"sha512") + _s(hashlib.sha512(payload).digest())
    sig = _s(b"ssh-ed25519") + _s(priv.sign(signed))
    body = b"SSHSIG" + struct.pack(">I", 1) + _s(blob) + _s(ns) + _s(b"") + _s(b"sha512") + _s(sig)
    armored = base64.b64encode(body).decode("ascii")
    lines = [armored[i : i + 70] for i in range(0, len(armored), 70)]
    pem = ("-----BEGIN SSH SIGNATURE-----\n" + "\n".join(lines) + "\n-----END SSH SIGNATURE-----\n").encode("ascii")
    return base64.b64encode(pem).decode("ascii")


def _init_store_with_tls(
    base: Path,
    clock: FakeClock | None = None,
    *,
    owner_id: str = OWNER,
    os_: OsAdapters | None = None,
) -> tuple[InitReport, DaemonConfig, Ed25519PrivateKey, str, str, str, OsAdapters]:
    adapters = os_ if os_ is not None else os_adapters(clock=clock)
    cfg_dir, data_root = base / "cfg", base / "data"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    adapters.permissions.secure_directory(cfg_dir)
    priv, enrollment = _ssh_signer_key(owner_id)
    rep = init_store(
        InitRequest(
            data_root=data_root,
            config_dir=cfg_dir,
            owner_id=owner_id,
            machine_id=MACHINE,
            signer=enrollment,
        ),
        adapters,
    )
    cfg = read_daemon_config(rep.daemon_config_path, adapters)
    verified_tls = verify_server_tls_files(cfg, adapters.clock, adapters)
    ca_pem = (cfg_dir / "tls" / "ca.pem").read_text(encoding="utf-8")
    cli_token = rep.cli_credential_path.read_text(encoding="utf-8").strip()
    return rep, cfg, priv, ca_pem, verified_tls.leaf_cert_sha256, cli_token, adapters


def _init_via_installed_wheel(
    env: InstalledEnv,
    base: Path,
    *,
    cwd: Path,
    owner_id: str = OWNER,
) -> tuple[Path, Path, Path, str, str, str, str]:
    os_ = os_adapters()
    cfg_dir, data_root = base / "cfg", base / "data"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    os_.permissions.secure_directory(cfg_dir)
    priv, enrollment = _ssh_signer_key(owner_id)
    _ = priv
    init_req_file = base / "init-req.json"
    write_owner_only_bytes(
        init_req_file,
        json.dumps(
            {
                "version": 1,
                "data_root": str(data_root),
                "config_dir": str(cfg_dir),
                "owner_id": owner_id,
                "machine_id": MACHINE,
                "signer": {"channel": "ssh_key", "public_key": enrollment.public_key},
            }
        ).encode("utf-8"),
    )
    res = run_installed_command(env, "brain", ["init", "--config", str(init_req_file)], cwd=cwd)
    assert res.returncode == 0, res.stderr.decode("utf-8", errors="replace")
    store_id = str(json.loads(res.stdout)["data"]["store_id"])
    daemon_cfg_path = cfg_dir / "daemon.json"
    ca_pem = (cfg_dir / "tls" / "ca.pem").read_text(encoding="utf-8")
    cli_token = (cfg_dir / "cli.credential").read_text(encoding="utf-8").strip()
    server_sha = leaf_sha(cfg_dir / "tls" / "server.pem")
    return data_root, cfg_dir, daemon_cfg_path, store_id, ca_pem, server_sha, cli_token


def _unused_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _assert_error_envelope(env: object, expected_code: str) -> dict[str, Any]:
    assert isinstance(env, dict), f"expected JSON dict envelope, got {env!r}"
    assert set(env) == {"ok", "error"} and env.get("ok") is False, env
    err = env.get("error")
    assert isinstance(err, dict) and set(err) == {"code", "message"}, env
    assert err.get("code") == expected_code, env
    msg = err.get("message")
    assert isinstance(msg, str) and msg in SAFE_WIRE_MESSAGES, env
    return cast(dict[str, Any], env)


def _assert_cli_error(
    proc_rc: int,
    stdout: bytes,
    stderr: bytes,
    *,
    expected_rc: int,
    expected_code: str,
    as_json: bool,
    label: object = "",
) -> None:
    err_text = stderr.decode("utf-8", errors="replace").strip()
    assert proc_rc == expected_rc, f"{label}: rc={proc_rc} != {expected_rc}, stdout={stdout!r}, stderr={err_text!r}"
    if as_json:
        raw_out = stdout.decode("utf-8", errors="strict").strip()
        assert raw_out, f"{label}: expected JSON error on stdout, got empty (stderr={err_text!r})"
        parsed = json.loads(raw_out)
        _assert_error_envelope(parsed, expected_code)
        assert err_text in ("", expected_code), f"{label}: unexpected stderr in --json error mode: {err_text!r}"
    else:
        assert stdout == b"", f"{label}: plain error must not write to stdout: {stdout!r}"
        assert err_text.splitlines() and err_text.splitlines()[-1] == expected_code, (
            f"{label}: expected stderr {expected_code!r}, got {err_text!r}"
        )


def _assert_completed_doctor_json(
    stdout: bytes,
    stderr: bytes,
    rc: int,
    *,
    expected_store_id: str | None = None,
    online: bool = False,
) -> dict[str, Any]:
    assert rc == 0, f"expected exit 0, got {rc} (stdout={stdout!r}, stderr={stderr!r})"
    assert stderr == b"", f"expected empty stderr on exit 0, got {stderr!r}"
    env = json.loads(stdout.decode("utf-8", errors="strict"))
    assert isinstance(env, dict) and set(env) == {"ok", "data"} and env.get("ok") is True, env
    data = env["data"]
    assert isinstance(data, dict), env
    missing_keys = DOCTOR_REPORT_DTO_KEYS - set(data)
    assert not missing_keys, f"missing DoctorReport DTO keys {sorted(missing_keys)} in {sorted(data)}"
    assert data["overall_status"] in {"pass", "warn", "fail"}, data
    if expected_store_id is not None:
        assert data["store_id"] == expected_store_id
    checks = data["checks"]
    assert isinstance(checks, list) and len(checks) > 0
    for chk in checks:
        assert isinstance(chk, dict)
        assert {"group", "name", "status", "reason", "detail", "remediation"} <= set(chk)
        assert chk["status"] in {"PASS", "WARN", "FAIL"}
    schema = data["schema"]
    assert isinstance(schema, dict)
    assert {"store_version", "policy_version", "expected_store_version", "expected_policy_version"} <= set(schema)
    if online:
        assert data.get("status") != "running"
        assert isinstance(data.get("doctor_run_id"), str) and data["doctor_run_id"]
        assert isinstance(data.get("job_id"), str) and data["job_id"]
    return cast(dict[str, Any], data)


def _assert_human_doctor_text(
    stdout: bytes,
    stderr: bytes,
    rc: int,
    *,
    reference_data: Mapping[str, Any],
) -> str:
    assert rc == 0, f"expected exit 0, got {rc} (stdout={stdout!r}, stderr={stderr!r})"
    assert stderr == b"", f"expected empty stderr on exit 0, got {stderr!r}"
    text = stdout.decode("utf-8", errors="strict")
    assert f"Overall status: {reference_data['overall_status']}" in text
    expected_store = reference_data["store_id"] or "unknown"
    assert f"Store ID: {expected_store}" in text
    sch = cast(Mapping[str, Any], reference_data["schema"])
    assert (
        f"Schema: store={sch['store_version']}/{sch['expected_store_version']}, "
        f"policy={sch['policy_version']}/{sch['expected_policy_version']}" in text
    )
    assert "Checks:" in text
    for chk in cast(list[Mapping[str, Any]], reference_data["checks"]):
        line_prefix = f"[{chk['status']}] {chk['group']}/{chk['name']} ({chk['reason']}):"
        assert line_prefix in text, f"missing check line {line_prefix!r} in human report:\n{text}"
    return text


class _SpyNoAcquireLocks(LockFactory, LockProbePort):
    def __init__(self, inner: LockProbePort) -> None:
        self._inner = inner
        self.probe_calls = 0

    def acquire(self, path: Path) -> LockHandle:
        raise AssertionError(f"read-only offline doctor must never acquire exclusive writer lock on {path}")

    def probe_held(self, path: Path) -> bool:
        self.probe_calls += 1
        return bool(self._inner.probe_held(path))


class _ReadOnlyPublisherProxy(NoReplacePublisher):
    def __init__(self, inner: Any, protected_roots: tuple[Path, ...]) -> None:
        self._inner = inner
        self._protected = tuple(Path(os.path.abspath(r)) for r in protected_roots)

    def _assert_unprotected(self, path: Path, op: str) -> None:
        abs_p = Path(os.path.abspath(path))
        for root in self._protected:
            if abs_p == root or root in abs_p.parents:
                raise AssertionError(f"read-only offline doctor called mutating {op} on {path}")

    def write_new(self, path: Path, data: bytes) -> None:
        self._assert_unprotected(path, "write_new")
        self._inner.write_new(path, data)

    def publish(self, staging: Path, final: Path) -> None:
        self._assert_unprotected(staging, "publish(staging)")
        self._assert_unprotected(final, "publish(final)")
        self._inner.publish(staging, final)

    def publish_no_replace(self, staging: Path, final: Path) -> None:
        self._assert_unprotected(staging, "publish_no_replace(staging)")
        self._assert_unprotected(final, "publish_no_replace(final)")
        self._inner.publish_no_replace(staging, final)

    def rename_dir(self, src: Path, dst: Path) -> None:
        self._assert_unprotected(src, "rename_dir(src)")
        self._assert_unprotected(dst, "rename_dir(dst)")
        self._inner.rename_dir(src, dst)

    def sync_directory(self, directory: Path) -> None:
        self._assert_unprotected(directory, "sync_directory")
        self._inner.sync_directory(directory)

    def flush_file(self, path: Path) -> None:
        self._assert_unprotected(path, "flush_file")
        self._inner.flush_file(path)

    def durability(self, directory: Path, env: dict[str, str] | Any) -> DurabilityReport:
        res: DurabilityReport = self._inner.durability(directory, env)
        return res

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


@contextlib.contextmanager
def _running_serve(
    cfg: DaemonConfig,
    *,
    os_: OsAdapters,
    clock: FakeClock,
    mono: Any,
) -> Iterator[tuple[Ready, OwnerLoop]]:
    ready_ev = threading.Event()
    stop_ev = threading.Event()
    box: dict[str, Any] = {}
    exits: list[int] = []

    def _on_ready(ready: Ready, loop: OwnerLoop) -> None:
        box["ready"] = ready
        box["loop"] = loop
        ready_ev.set()

    def _bg() -> None:
        exits.append(
            daemon_entry.serve(
                cfg,
                os_=os_,
                clock=clock,
                monotonic_clock=mono,
                stop_event=stop_ev,
                shutdown_grace_s=2.0,
                on_ready=_on_ready,
            )
        )

    thr = threading.Thread(target=_bg, name="i4-3-serve", daemon=True)
    thr.start()
    try:
        assert ready_ev.wait(timeout=BOUND_WAIT_S), f"serve() did not become ready (exits={exits})"
        yield cast(Ready, box["ready"]), cast(OwnerLoop, box["loop"])
    finally:
        stop_ev.set()
        thr.join(timeout=BOUND_WAIT_S)
        assert not thr.is_alive(), "daemon serve thread leaked"


@contextlib.contextmanager
def _ro_db(db_path: Path) -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        yield conn
    finally:
        conn.close()


def _call_operator_json(
    endpoint: Endpoint,
    *,
    store_id: str,
    ca_pem: str,
    leaf_sha256: str,
    token: str,
    path: str,
    body: dict[str, object],
    monotonic_ns: Any,
) -> dict[str, Any]:
    target = LoopbackTarget(
        endpoint=endpoint,
        expected_store_id=store_id,
        ca_pem=ca_pem,
        leaf_cert_sha256=leaf_sha256,
    )
    res = LoopbackClient(monotonic_ns=monotonic_ns).call_operator(
        target,
        path,
        json.dumps(body).encode("utf-8"),
        token,
    )
    assert isinstance(res, dict)
    return cast(dict[str, Any], res)


def _restore_msg(store_id: str, owner_id: str, ch: dict[str, Any], db_digest: str) -> ApprovalMessage:
    return ApprovalMessage(
        store_id=store_id,
        owner_id=owner_id,
        trust_generation=int(cast(int | str, ch["trust_generation"])),
        action=ApprovalAction.RESTORE,
        subject_id=str(ch["subject_id"]),
        subject_revision=1,
        resource_digests=(ResourceDigest("backup", db_digest),),
        target_files=(),
        risk_level=RiskLevel.HIGH,
        risk_policy_version=RISK_POLICY_VERSION,
        recovery_scope=RecoveryScope.NONE,
        nonce=str(ch["nonce"]),
        expires_at=datetime.fromisoformat(str(ch["expires_at"]).replace("Z", "+00:00")),
    )


def _run_online_restore(
    ready: Ready,
    *,
    store_id: str,
    ca_pem: str,
    leaf_sha256: str,
    cli_token: str,
    priv: Ed25519PrivateKey,
    signer_id: str,
    target_kind: str,
    backup_path: Path,
    os_: OsAdapters,
    monotonic_ns: Any,
) -> None:
    prev = _call_operator_json(
        ready.endpoint,
        store_id=store_id,
        ca_pem=ca_pem,
        leaf_sha256=leaf_sha256,
        token=cli_token,
        path="/v2/operator/restore",
        body={"target": target_kind, "backup": str(backup_path)},
        monotonic_ns=monotonic_ns,
    )
    assert prev.get("ok") is True, prev
    ch = cast(dict[str, Any], prev["data"]["challenge"])
    migs = KERNEL_POLICY_MIGRATIONS if target_kind == "policy" else KERNEL_STORE_MIGRATIONS
    manifest = verify_backup(
        backup_path,
        expected_kind=cast(Any, target_kind),
        expected_store_id=store_id,
        migrations=migs,
        os_=os_,
    )
    msg = _restore_msg(str(ch["store_id"]), OWNER, ch, manifest.db_digest)
    ap = {
        "message": msg.to_dict(),
        "channel": ApprovalChannel.SSH_KEY.value,
        "signer_id": signer_id,
        "signature": _ssh_sig_b64(priv, msg.canonical_bytes()),
    }
    done = _call_operator_json(
        ready.endpoint,
        store_id=store_id,
        ca_pem=ca_pem,
        leaf_sha256=leaf_sha256,
        token=cli_token,
        path="/v2/operator/restore",
        body={"target": target_kind, "backup": str(backup_path), "approval": ap},
        monotonic_ns=monotonic_ns,
    )
    assert done.get("ok") is True, done


# ---------------------------------------------------------------------------
# Requirement 1: CLI Flag & Output/Exit Contract
# ---------------------------------------------------------------------------


def test_doctor_cli_flag_parsing_and_exit_output_contract(
    inc2_installed_env: InstalledEnv,
    trusted_tmp: Path,
) -> None:
    """Exit 2 on invalid flags/paths/wait-ms, exit 1 on BrainError, exit 0 on pass/warn/fail (JSON & text)."""
    os_ = os_adapters()
    cwd = trusted_tmp / "outside"
    cwd.mkdir()
    os_.permissions.secure_directory(cwd)

    data_root, cfg_dir, daemon_cfg, store_id, _ca_pem, server_sha, _cli_tok = _init_via_installed_wheel(
        inc2_installed_env, trusted_tmp / "root", cwd=cwd
    )
    prof_path, _ = write_client_profile_file(
        cfg_dir / "cli.profile.json",
        endpoint_path=data_root / "endpoint.json",
        expected_store_id=store_id,
        ca_file=cfg_dir / "tls" / "ca.pem",
        leaf_cert_sha256=server_sha,
        credential_file=cfg_dir / "cli.credential",
    )
    co_dir = trusted_tmp / "co"
    co_dir.mkdir()
    os_.permissions.secure_directory(co_dir)

    # 1. Invalid flags / duplicates / mutual exclusion / relative paths / traversal / invalid --wait-ms -> exit 2.
    invalid_cases: tuple[list[str], ...] = (
        ["doctor"],
        ["doctor", "--offline"],
        ["doctor", "--unknown-flag", "--config", str(daemon_cfg)],
        ["doctor", "--config", str(daemon_cfg), "--profile", str(prof_path)],
        ["doctor", "--config", str(daemon_cfg), "--offline", "--offline"],
        ["doctor", "--config", str(daemon_cfg), "--config", str(daemon_cfg)],
        ["doctor", "--profile", str(prof_path), "--profile", str(prof_path)],
        ["doctor", "--config", str(daemon_cfg), "--checkout", str(co_dir), "--checkout", str(co_dir)],
        ["doctor", "--config", "relative/daemon.json"],
        ["doctor", "--profile", "relative/cli.profile.json"],
        ["doctor", "--config", str(daemon_cfg), "--checkout", "relative/co"],
        ["doctor", "--config", str(cfg_dir / "sub" / ".." / "daemon.json")],
        ["doctor", "--profile", str(prof_path), "--wait-ms", "-1"],
        ["doctor", "--profile", str(prof_path), "--wait-ms", "10001"],
        ["doctor", "--profile", str(prof_path), "--wait-ms", "abc"],
        ["doctor", "--profile", str(prof_path), "--wait-ms"],
        ["doctor", "--profile", str(prof_path), "--wait-ms", "50", "--wait-ms", "100"],
    )
    for base_args in invalid_cases:
        res_plain = run_installed_command(inc2_installed_env, "brain", base_args, cwd=cwd)
        _assert_cli_error(
            res_plain.returncode,
            res_plain.stdout,
            res_plain.stderr,
            expected_rc=2,
            expected_code=ErrorCode.INVALID_INPUT.value,
            as_json=False,
            label=("plain", base_args),
        )
        if "--json" not in base_args:
            json_args = [*base_args, "--json"]
            res_json = run_installed_command(inc2_installed_env, "brain", json_args, cwd=cwd)
            _assert_cli_error(
                res_json.returncode,
                res_json.stdout,
                res_json.stderr,
                expected_rc=2,
                expected_code=ErrorCode.INVALID_INPUT.value,
                as_json=True,
                label=("json", json_args),
            )
    # Also verify duplicate --json alongside --json.
    dup_json = run_installed_command(
        inc2_installed_env, "brain", ["doctor", "--config", str(daemon_cfg), "--json", "--json"], cwd=cwd
    )
    _assert_cli_error(
        dup_json.returncode,
        dup_json.stdout,
        dup_json.stderr,
        expected_rc=2,
        expected_code=ErrorCode.INVALID_INPUT.value,
        as_json=True,
        label="dup-json",
    )

    # 2. Runtime BrainError -> exit 1 in both --json and plain text.
    missing_cfg = trusted_tmp / "missing-daemon.json"
    missing_prof = trusted_tmp / "missing-profile.json"
    for flag, target in (("--config", missing_cfg), ("--profile", missing_prof)):
        r_err_plain = run_installed_command(inc2_installed_env, "brain", ["doctor", flag, str(target)], cwd=cwd)
        _assert_cli_error(
            r_err_plain.returncode,
            r_err_plain.stdout,
            r_err_plain.stderr,
            expected_rc=1,
            expected_code=ErrorCode.NOT_FOUND.value,
            as_json=False,
            label=("missing-plain", flag),
        )
        r_err_json = run_installed_command(
            inc2_installed_env, "brain", ["doctor", flag, str(target), "--json"], cwd=cwd
        )
        _assert_cli_error(
            r_err_json.returncode,
            r_err_json.stdout,
            r_err_json.stderr,
            expected_rc=1,
            expected_code=ErrorCode.NOT_FOUND.value,
            as_json=True,
            label=("missing-json", flag),
        )

    # 3. Completed report with overall_status in {"pass", "warn", "fail"} -> exit 0 in BOTH JSON & plain text.
    # (a) pass
    r_pass_json = run_installed_command(
        inc2_installed_env, "brain", ["doctor", "--config", str(daemon_cfg), "--json"], cwd=cwd
    )
    d_pass = _assert_completed_doctor_json(
        r_pass_json.stdout, r_pass_json.stderr, r_pass_json.returncode, expected_store_id=store_id
    )
    assert d_pass["overall_status"] == "pass"
    r_pass_txt = run_installed_command(inc2_installed_env, "brain", ["doctor", "--config", str(daemon_cfg)], cwd=cwd)
    _assert_human_doctor_text(r_pass_txt.stdout, r_pass_txt.stderr, r_pass_txt.returncode, reference_data=d_pass)

    # (b) warn (unapplied policy intent)
    rt = reopen_kernel_job_runtime(data_root, store_id, os_)
    try:
        rt.policy.record_intent(IntentKind.QUARANTINE, {"digest": "sha256:" + "a" * 64})
    finally:
        rt.close()
    r_warn_json = run_installed_command(
        inc2_installed_env, "brain", ["doctor", "--config", str(daemon_cfg), "--json"], cwd=cwd
    )
    d_warn = _assert_completed_doctor_json(
        r_warn_json.stdout, r_warn_json.stderr, r_warn_json.returncode, expected_store_id=store_id
    )
    assert d_warn["overall_status"] == "warn"
    r_warn_txt = run_installed_command(inc2_installed_env, "brain", ["doctor", "--config", str(daemon_cfg)], cwd=cwd)
    _assert_human_doctor_text(r_warn_txt.stdout, r_warn_txt.stderr, r_warn_txt.returncode, reference_data=d_warn)

    # (c) fail (missing writer.lock)
    (data_root / "writer.lock").unlink()
    r_fail_json = run_installed_command(
        inc2_installed_env, "brain", ["doctor", "--config", str(daemon_cfg), "--json"], cwd=cwd
    )
    d_fail = _assert_completed_doctor_json(
        r_fail_json.stdout, r_fail_json.stderr, r_fail_json.returncode, expected_store_id=store_id
    )
    assert d_fail["overall_status"] == "fail"
    r_fail_txt = run_installed_command(inc2_installed_env, "brain", ["doctor", "--config", str(daemon_cfg)], cwd=cwd)
    _assert_human_doctor_text(r_fail_txt.stdout, r_fail_txt.stderr, r_fail_txt.returncode, reference_data=d_fail)


# ---------------------------------------------------------------------------
# Requirement 2: Installed Wheel Online & Offline + Profile Discovery
# ---------------------------------------------------------------------------


def test_installed_wheel_doctor_offline_and_online_config_discovery_and_profile(
    inc2_installed_env: InstalledEnv,
    trusted_tmp: Path,
) -> None:
    """Wheel E2E: offline (0 bytes/0 locks), live --offline refusal (store_busy), online --config & --profile parity."""
    os_ = os_adapters()
    cwd = trusted_tmp / "outside"
    cwd.mkdir()
    os_.permissions.secure_directory(cwd)

    data_root, cfg_dir, daemon_cfg, store_id, _ca_pem, server_sha, _cli_tok = _init_via_installed_wheel(
        inc2_installed_env, trusted_tmp / "e2e", cwd=cwd
    )
    co_dir = trusted_tmp / "checkout"
    co_dir.mkdir()
    os_.permissions.secure_directory(co_dir)
    (co_dir / "README.md").write_text("# Clean checkout\n", encoding="utf-8")

    cli_profile, _ = write_client_profile_file(
        trusted_tmp / "cli.profile.json",
        endpoint_path=data_root / "endpoint.json",
        expected_store_id=store_id,
        ca_file=cfg_dir / "tls" / "ca.pem",
        leaf_cert_sha256=server_sha,
        credential_file=cfg_dir / "cli.credential",
    )

    # 1. Stopped daemon -> offline doctor succeeds (0 bytes mutated, 0 writer locks acquired).
    snap_data_0 = digest_tree(data_root)
    snap_co_0 = digest_tree(co_dir)

    for cmd_args in (
        ["doctor", "--config", str(daemon_cfg), "--checkout", str(co_dir), "--json"],
        ["doctor", "--offline", "--config", str(daemon_cfg), "--checkout", str(co_dir), "--json"],
        ["doctor", "--offline", "--profile", str(cli_profile), "--json"],
    ):
        off_json = run_installed_command(inc2_installed_env, "brain", cmd_args, cwd=cwd)
        off_data = _assert_completed_doctor_json(
            off_json.stdout, off_json.stderr, off_json.returncode, expected_store_id=store_id
        )
        assert off_data["overall_status"] == "pass"
        assert off_data["schema"]["store_version"] == 5 and off_data["schema"]["policy_version"] == 4

    off_txt = run_installed_command(
        inc2_installed_env, "brain", ["doctor", "--offline", "--config", str(daemon_cfg)], cwd=cwd
    )
    assert off_txt.returncode == 0 and off_txt.stderr == b""
    assert "Overall status: pass" in off_txt.stdout.decode("utf-8")

    assert digest_tree(data_root) == snap_data_0
    assert digest_tree(co_dir) == snap_co_0

    # Spy check: offline doctor never acquires exclusive writer.lock and never calls mutating publisher APIs.
    locks_spy = _SpyNoAcquireLocks(cast(LockProbePort, os_.locks))
    pub_proxy = _ReadOnlyPublisherProxy(os_.publisher, (data_root, co_dir))
    spy_os = replace(os_, locks=locks_spy, publisher=pub_proxy)
    assert (
        doctor_entry.run_doctor_cli(
            ["doctor", "--offline", "--config", str(daemon_cfg), "--checkout", str(co_dir), "--json"], os_=spy_os
        )
        == 0
    )
    assert locks_spy.probe_calls >= 1
    assert digest_tree(data_root) == snap_data_0
    assert digest_tree(co_dir) == snap_co_0

    # 2. Start real live daemon subprocess (`brain serve --config <abs>`).
    with spawn_installed_brain_serve(inc2_installed_env, daemon_cfg, data_root=data_root, cwd=cwd) as srv_proc:
        ep = srv_proc.wait_ready()
        assert ep.store_id == store_id
        assert is_writer_lock_held(data_root) is True

        # 2a. `--offline` MUST fail closed with exit 1 & store_busy while daemon is live.
        for off_live_flag, off_live_path in (("--config", daemon_cfg), ("--profile", cli_profile)):
            r_busy_json = run_installed_command(
                inc2_installed_env,
                "brain",
                ["doctor", "--offline", off_live_flag, str(off_live_path), "--json"],
                cwd=cwd,
            )
            _assert_cli_error(
                r_busy_json.returncode,
                r_busy_json.stdout,
                r_busy_json.stderr,
                expected_rc=1,
                expected_code=ErrorCode.STORE_BUSY.value,
                as_json=True,
                label=("offline-live-json", off_live_flag),
            )
            r_busy_txt = run_installed_command(
                inc2_installed_env,
                "brain",
                ["doctor", "--offline", off_live_flag, str(off_live_path)],
                cwd=cwd,
            )
            _assert_cli_error(
                r_busy_txt.returncode,
                r_busy_txt.stdout,
                r_busy_txt.stderr,
                expected_rc=1,
                expected_code=ErrorCode.STORE_BUSY.value,
                as_json=False,
                label=("offline-live-txt", off_live_flag),
            )

        # 2b. Online `brain doctor --config <abs>` (discovers cli.credential, tls/ca.pem, daemon.json cert_path).
        on_cfg_json = run_installed_command(
            inc2_installed_env,
            "brain",
            ["doctor", "--config", str(daemon_cfg), "--checkout", str(co_dir), "--json"],
            cwd=cwd,
        )
        cfg_data = _assert_completed_doctor_json(
            on_cfg_json.stdout,
            on_cfg_json.stderr,
            on_cfg_json.returncode,
            expected_store_id=store_id,
            online=True,
        )
        on_cfg_txt = run_installed_command(
            inc2_installed_env, "brain", ["doctor", "--config", str(daemon_cfg), "--checkout", str(co_dir)], cwd=cwd
        )
        _assert_human_doctor_text(on_cfg_txt.stdout, on_cfg_txt.stderr, on_cfg_txt.returncode, reference_data=cfg_data)

        # Verify online report matches owner's committed `doctor.run` ledger entry & CAS blob in store.db.
        root = DataRoot.at(data_root)
        with _ro_db(root.store_db) as conn:
            doc_rows = conn.execute(
                "SELECT meta, refs FROM ledger WHERE kind = 'doctor.run' ORDER BY sequence DESC"
            ).fetchall()
            assert doc_rows, "expected committed doctor.run ledger entry"
            matched_meta: dict[str, Any] | None = None
            matched_refs: list[str] = []
            for raw_meta, raw_refs in doc_rows:
                meta_obj = cast(dict[str, Any], json.loads(bytes(raw_meta).decode("utf-8")))
                if meta_obj.get("doctor_run_id") == cfg_data["doctor_run_id"]:
                    matched_meta = meta_obj
                    matched_refs = cast(list[str], json.loads(bytes(raw_refs).decode("utf-8")))
                    break
            assert matched_meta is not None, (
                f"online doctor_run_id {cfg_data['doctor_run_id']} not found in doctor.run ledger"
            )
            assert matched_meta["owner_id"] == OWNER
            assert matched_meta["overall_status"] == cfg_data["overall_status"]
            assert matched_meta["job_id"] == cfg_data["job_id"]
            report_digest = str(matched_meta["report_digest"])
            assert matched_refs == [report_digest]

        cas_blob = blob_path(root.cas_dir, report_digest)
        assert cas_blob.is_file()
        cas_bytes = cas_blob.read_bytes()
        assert digest_bytes(cas_bytes) == report_digest
        cas_doc = cast(dict[str, Any], json.loads(cas_bytes.decode("utf-8")))
        assert cas_doc["doctor_run_id"] == cfg_data["doctor_run_id"]
        assert cas_doc["overall_status"] == cfg_data["overall_status"]
        assert cas_doc["store_id"] == cfg_data["store_id"] == store_id
        assert cas_doc["job_id"] == cfg_data["job_id"]
        cas_report = cast(dict[str, Any], cas_doc["report"])
        assert cas_report["checks"] == cfg_data["checks"]
        assert cas_report["schema"] == cfg_data["schema"]

        # 2c. Online `brain doctor --profile <cli_profile>` (--json & text).
        on_prof_json = run_installed_command(
            inc2_installed_env, "brain", ["doctor", "--profile", str(cli_profile), "--json"], cwd=cwd
        )
        prof_data = _assert_completed_doctor_json(
            on_prof_json.stdout,
            on_prof_json.stderr,
            on_prof_json.returncode,
            expected_store_id=store_id,
            online=True,
        )
        assert prof_data["store_id"] == store_id
        on_prof_txt = run_installed_command(
            inc2_installed_env, "brain", ["doctor", "--profile", str(cli_profile)], cwd=cwd
        )
        _assert_human_doctor_text(
            on_prof_txt.stdout, on_prof_txt.stderr, on_prof_txt.returncode, reference_data=prof_data
        )

        rc_srv, _, _, _ = srv_proc.signal_and_wait_exit()
        assert rc_srv == 0
    assert not is_writer_lock_held(data_root)

    # 3. After daemon shutdown, offline mode works again.
    post_stop = run_installed_command(
        inc2_installed_env, "brain", ["doctor", "--offline", "--config", str(daemon_cfg), "--json"], cwd=cwd
    )
    _assert_completed_doctor_json(post_stop.stdout, post_stop.stderr, post_stop.returncode, expected_store_id=store_id)


# ---------------------------------------------------------------------------
# Requirement 3: Fail-Closed Security, Anti-Fallback & Lock-Probe Ordering
# ---------------------------------------------------------------------------


def test_doctor_fail_closed_security_anti_fallback_and_lock_probe_ordering(
    inc2_installed_env: InstalledEnv,
    trusted_tmp: Path,
) -> None:
    """Anti-fallback on stale endpoint/wrong pin/revoked cred/harness/checkout mismatch & lock probe precedence."""
    os_ = os_adapters()
    cwd = trusted_tmp / "outside"
    cwd.mkdir()
    os_.permissions.secure_directory(cwd)

    data_root, cfg_dir, daemon_cfg, store_id, ca_pem, server_sha, _cli_tok = _init_via_installed_wheel(
        inc2_installed_env, trusted_tmp / "sec", cwd=cwd
    )
    root = DataRoot.at(data_root)
    cli_profile, _ = write_client_profile_file(
        trusted_tmp / "cli.profile.json",
        endpoint_path=root.endpoint_path,
        expected_store_id=store_id,
        ca_file=cfg_dir / "tls" / "ca.pem",
        leaf_cert_sha256=server_sha,
        credential_file=cfg_dir / "cli.credential",
    )

    # --- Case A: Stale/dead port in endpoint.json (DB healthy on disk) -> daemon_unavailable, NEVER offline ---
    dead_port = _unused_loopback_port()
    stale_ep = Endpoint(
        version=1,
        host="127.0.0.1",
        port=dead_port,
        store_id=store_id,
        writer_epoch=1,
        instance_id=new_id(),
    )
    write_owner_only_bytes(root.endpoint_path, stale_ep.encode_canonical())
    snap_with_stale_ep = digest_tree(data_root)
    for flag, path in (("--config", daemon_cfg), ("--profile", cli_profile)):
        r_stale_json = run_installed_command(
            inc2_installed_env, "brain", ["doctor", flag, str(path), "--json"], cwd=cwd
        )
        _assert_cli_error(
            r_stale_json.returncode,
            r_stale_json.stdout,
            r_stale_json.stderr,
            expected_rc=1,
            expected_code=ErrorCode.DAEMON_UNAVAILABLE.value,
            as_json=True,
            label=("stale-ep-json", flag),
        )
        r_stale_txt = run_installed_command(inc2_installed_env, "brain", ["doctor", flag, str(path)], cwd=cwd)
        _assert_cli_error(
            r_stale_txt.returncode,
            r_stale_txt.stdout,
            r_stale_txt.stderr,
            expected_rc=1,
            expected_code=ErrorCode.DAEMON_UNAVAILABLE.value,
            as_json=False,
            label=("stale-ep-txt", flag),
        )
    assert digest_tree(data_root) == snap_with_stale_ep
    root.endpoint_path.unlink()

    # --- Case B: Missing endpoint.json WHILE writer.lock IS held -> probe_held precedes cli.credential / ca.pem! ---
    cred_backup = (cfg_dir / "cli.credential").read_bytes()
    ca_backup = (cfg_dir / "tls" / "ca.pem").read_bytes()
    (cfg_dir / "cli.credential").unlink()
    (cfg_dir / "tls" / "ca.pem").unlink()
    try:
        with acquire_writer_unbumped(root, os_):
            assert not os.path.lexists(root.endpoint_path)
            for flag, path in (("--config", daemon_cfg), ("--profile", cli_profile)):
                r_lock_json = run_installed_command(
                    inc2_installed_env, "brain", ["doctor", flag, str(path), "--json"], cwd=cwd
                )
                _assert_cli_error(
                    r_lock_json.returncode,
                    r_lock_json.stdout,
                    r_lock_json.stderr,
                    expected_rc=1,
                    expected_code=ErrorCode.DAEMON_UNAVAILABLE.value,
                    as_json=True,
                    label=("lock-held-no-cred-json", flag),
                )
                r_lock_txt = run_installed_command(inc2_installed_env, "brain", ["doctor", flag, str(path)], cwd=cwd)
                _assert_cli_error(
                    r_lock_txt.returncode,
                    r_lock_txt.stdout,
                    r_lock_txt.stderr,
                    expected_rc=1,
                    expected_code=ErrorCode.DAEMON_UNAVAILABLE.value,
                    as_json=False,
                    label=("lock-held-no-cred-txt", flag),
                )
                r_off_lock = run_installed_command(
                    inc2_installed_env,
                    "brain",
                    ["doctor", "--offline", flag, str(path), "--json"],
                    cwd=cwd,
                )
                _assert_cli_error(
                    r_off_lock.returncode,
                    r_off_lock.stdout,
                    r_off_lock.stderr,
                    expected_rc=1,
                    expected_code=ErrorCode.STORE_BUSY.value,
                    as_json=True,
                    label=("lock-held-offline", flag),
                )
    finally:
        write_owner_only_bytes(cfg_dir / "cli.credential", cred_backup)
        write_owner_only_bytes(cfg_dir / "tls" / "ca.pem", ca_backup)

    # --- Case C: Live daemon -> bad TLS pin, revoked user:cli, harness profile/RPC, mismatched --checkout ---
    co_a = trusted_tmp / "co-a"
    co_b = trusted_tmp / "co-b"
    for d in (co_a, co_b):
        d.mkdir()
        os_.permissions.secure_directory(d)

    seed_clock = FakeClock(_base_utc_now())
    rt_seed = reopen_kernel_job_runtime(data_root, store_id, os_adapters(clock=seed_clock))
    try:
        cred_claude = seed_principal_and_credential(
            rt_seed.policy, owner_id=OWNER, harness_id="claude-code", machine_id=MACHINE
        )
        cred_codex = seed_principal_and_credential(
            rt_seed.policy, owner_id=OWNER, harness_id="codex", machine_id=MACHINE
        )
        cred_cli_revoked = seed_principal_and_credential(
            rt_seed.policy, owner_id=OWNER, harness_id=CLI_HARNESS_ID, machine_id=MACHINE
        )
        rt_seed.policy.record_authorized_revocation(
            cred_cli_revoked.credential_id,
            make_bootstrap_auth(
                store_id=store_id,
                owner_id=OWNER,
                action="credential_revoke",
                subject_id=cred_cli_revoked.credential_id,
                trust_generation=rt_seed.policy.trust_generation(),
                expires_at=seed_clock.now() + timedelta(hours=1),
            ),
        )
        ws_a = register_workspace_direct(
            rt_seed,
            seed_clock,
            cred_claude.principal,
            alias="ws-a",
            checkout_dir=co_a,
            remote="https://github.example/dan/ws-a.git",
        )
    finally:
        rt_seed.close()

    bad_pin_profile, _ = write_client_profile_file(
        trusted_tmp / "bad-pin.profile.json",
        endpoint_path=root.endpoint_path,
        expected_store_id=store_id,
        ca_file=cfg_dir / "tls" / "ca.pem",
        leaf_cert_sha256=flip_last_hex_char(server_sha),
        credential_file=cfg_dir / "cli.credential",
    )
    revoked_cred_file = write_credential_file(trusted_tmp / "revoked-cli.credential", cred_cli_revoked.token)
    revoked_profile, _ = write_client_profile_file(
        trusted_tmp / "revoked-cli.profile.json",
        endpoint_path=root.endpoint_path,
        expected_store_id=store_id,
        ca_file=cfg_dir / "tls" / "ca.pem",
        leaf_cert_sha256=server_sha,
        credential_file=revoked_cred_file,
    )
    claude_cred_file = write_credential_file(trusted_tmp / "claude.credential", cred_claude.token)
    codex_cred_file = write_credential_file(trusted_tmp / "codex.credential", cred_codex.token)
    claude_profile, _ = write_client_profile_file(
        trusted_tmp / "claude.profile.json",
        endpoint_path=root.endpoint_path,
        expected_store_id=store_id,
        ca_file=cfg_dir / "tls" / "ca.pem",
        leaf_cert_sha256=server_sha,
        credential_file=claude_cred_file,
        workspace={
            "alias": ws_a.alias,
            "checkout_path": str(co_a),
            "expected_workspace_id": ws_a.repo_id,
            "expected_checkout_id": ws_a.checkout_id,
        },
    )
    codex_profile, _ = write_client_profile_file(
        trusted_tmp / "codex.profile.json",
        endpoint_path=root.endpoint_path,
        expected_store_id=store_id,
        ca_file=cfg_dir / "tls" / "ca.pem",
        leaf_cert_sha256=server_sha,
        credential_file=codex_cred_file,
    )
    cli_ws_profile, _ = write_client_profile_file(
        trusted_tmp / "cli-ws-a.profile.json",
        endpoint_path=root.endpoint_path,
        expected_store_id=store_id,
        ca_file=cfg_dir / "tls" / "ca.pem",
        leaf_cert_sha256=server_sha,
        credential_file=cfg_dir / "cli.credential",
        workspace={
            "alias": ws_a.alias,
            "checkout_path": str(co_a),
            "expected_workspace_id": ws_a.repo_id,
            "expected_checkout_id": ws_a.checkout_id,
        },
    )

    with spawn_installed_brain_serve(inc2_installed_env, daemon_cfg, data_root=data_root, cwd=cwd) as srv_proc:
        ep = srv_proc.wait_ready()

        # 1) Wrong leaf_cert_sha256 pin -> exit 1, never falls back to offline.
        r_pin = run_installed_command(
            inc2_installed_env, "brain", ["doctor", "--profile", str(bad_pin_profile), "--json"], cwd=cwd
        )
        _assert_cli_error(
            r_pin.returncode,
            r_pin.stdout,
            r_pin.stderr,
            expected_rc=1,
            expected_code=ErrorCode.IDENTITY_MISMATCH.value,
            as_json=True,
            label="bad-pin",
        )

        # 2) Revoked user:cli credential -> exit 1 (unauthenticated), never falls back to offline.
        r_rev_prof = run_installed_command(
            inc2_installed_env, "brain", ["doctor", "--profile", str(revoked_profile), "--json"], cwd=cwd
        )
        _assert_cli_error(
            r_rev_prof.returncode,
            r_rev_prof.stdout,
            r_rev_prof.stderr,
            expected_rc=1,
            expected_code=ErrorCode.UNAUTHENTICATED.value,
            as_json=True,
            label="revoked-profile",
        )

        # 3) Harness profiles calling `brain doctor` online -> identity_mismatch.
        for h_name, h_prof, h_tok in (
            ("claude-code", claude_profile, cred_claude.token),
            ("codex", codex_profile, cred_codex.token),
        ):
            r_h = run_installed_command(
                inc2_installed_env, "brain", ["doctor", "--profile", str(h_prof), "--json"], cwd=cwd
            )
            _assert_cli_error(
                r_h.returncode,
                r_h.stdout,
                r_h.stderr,
                expected_rc=1,
                expected_code=ErrorCode.IDENTITY_MISMATCH.value,
                as_json=True,
                label=("harness-cli", h_name),
            )
            direct_h = _call_operator_json(
                ep,
                store_id=store_id,
                ca_pem=ca_pem,
                leaf_sha256=server_sha,
                token=h_tok,
                path="/v2/operator/doctor/report",
                body={},
                monotonic_ns=os_.monotonic.monotonic_ns,
            )
            _assert_error_envelope(direct_h, ErrorCode.IDENTITY_MISMATCH.value)

        # 4) Workspace-bound --profile with mismatched --checkout -> identity_mismatch (never scans co_b or offline).
        r_co_mismatch_json = run_installed_command(
            inc2_installed_env,
            "brain",
            ["doctor", "--profile", str(cli_ws_profile), "--checkout", str(co_b), "--json"],
            cwd=cwd,
        )
        _assert_cli_error(
            r_co_mismatch_json.returncode,
            r_co_mismatch_json.stdout,
            r_co_mismatch_json.stderr,
            expected_rc=1,
            expected_code=ErrorCode.IDENTITY_MISMATCH.value,
            as_json=True,
            label="checkout-mismatch-json",
        )
        r_co_mismatch_txt = run_installed_command(
            inc2_installed_env,
            "brain",
            ["doctor", "--profile", str(cli_ws_profile), "--checkout", str(co_b)],
            cwd=cwd,
        )
        _assert_cli_error(
            r_co_mismatch_txt.returncode,
            r_co_mismatch_txt.stdout,
            r_co_mismatch_txt.stderr,
            expected_rc=1,
            expected_code=ErrorCode.IDENTITY_MISMATCH.value,
            as_json=False,
            label="checkout-mismatch-txt",
        )
        # Positive twin: matching --checkout co_a succeeds.
        r_co_ok = run_installed_command(
            inc2_installed_env,
            "brain",
            ["doctor", "--profile", str(cli_ws_profile), "--checkout", str(co_a), "--json"],
            cwd=cwd,
        )
        _assert_completed_doctor_json(
            r_co_ok.stdout, r_co_ok.stderr, r_co_ok.returncode, expected_store_id=store_id, online=True
        )

        rc_srv, _, _, _ = srv_proc.signal_and_wait_exit()
        assert rc_srv == 0

    # --- Case D: `--config` discovery with revoked `cli.credential` against live daemon -> unauthenticated ---
    rev_root, rev_cfg_dir, rev_daemon_cfg, rev_store_id, _rca, _rsha, rev_tok = _init_via_installed_wheel(
        inc2_installed_env, trusted_tmp / "rev-cfg", cwd=cwd
    )
    rt_rev = reopen_kernel_job_runtime(rev_root, rev_store_id, os_)
    try:
        seed_principal_and_credential(rt_rev.policy, owner_id=OWNER, harness_id="claude-code", machine_id=MACHINE)
        rev_cred_id = rev_tok.split(".", 1)[0]
        rt_rev.policy.record_authorized_revocation(
            rev_cred_id,
            make_bootstrap_auth(
                store_id=rev_store_id,
                owner_id=OWNER,
                action="credential_revoke",
                subject_id=rev_cred_id,
                trust_generation=rt_rev.policy.trust_generation(),
                expires_at=os_.clock.now() + timedelta(hours=1),
            ),
        )
        rt_rev.store.reconcile_policy()
    finally:
        rt_rev.close()

    with spawn_installed_brain_serve(inc2_installed_env, rev_daemon_cfg, data_root=rev_root, cwd=cwd) as rev_srv:
        rev_srv.wait_ready()
        r_cfg_rev = run_installed_command(
            inc2_installed_env, "brain", ["doctor", "--config", str(rev_daemon_cfg), "--json"], cwd=cwd
        )
        _assert_cli_error(
            r_cfg_rev.returncode,
            r_cfg_rev.stdout,
            r_cfg_rev.stderr,
            expected_rc=1,
            expected_code=ErrorCode.UNAUTHENTICATED.value,
            as_json=True,
            label="config-revoked-cli-cred",
        )
        rc_rev, _, _, _ = rev_srv.signal_and_wait_exit()
        assert rc_rev == 0


# ---------------------------------------------------------------------------
# Requirement 4: /v2/operator/doctor/report 3-Phase Behavior & Isolation
# ---------------------------------------------------------------------------


def test_operator_doctor_report_nonblocking_cutoff_and_cli_wait_ms(
    inc2_installed_env: InstalledEnv,
    trusted_tmp: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Phase 2 off-owner wait honors cutoff returning status='running'+job_id while OwnerLoop stays unblocked."""
    assert "/v2/operator/doctor/report" in OPERATOR_PATHS

    clock = FakeClock(_base_utc_now())
    real_mono = os_adapters().monotonic
    base_os = os_adapters(clock=clock, monotonic=real_mono)
    rep, cfg, _priv, ca_pem, leaf_sha256, cli_token, os_ = _init_store_with_tls(
        trusted_tmp / "cutoff", clock, os_=base_os
    )
    root = DataRoot.at(cfg.data_root)
    cwd = trusted_tmp / "outside"
    cwd.mkdir()
    os_.permissions.secure_directory(cwd)

    rt = reopen_kernel_job_runtime(cfg.data_root, rep.store_id, os_)
    try:
        cred_mcp = seed_principal_and_credential(
            rt.policy, owner_id=OWNER, harness_id="claude-code", machine_id=MACHINE
        )
    finally:
        rt.close()

    cli_profile, _ = write_client_profile_file(
        trusted_tmp / "cli.profile.json",
        endpoint_path=root.endpoint_path,
        expected_store_id=rep.store_id,
        ca_file=rep.daemon_config_path.parent / "tls" / "ca.pem",
        leaf_cert_sha256=leaf_sha256,
        credential_file=rep.cli_credential_path,
    )

    orig_read_snapshot = StorageDoctorReader.read_snapshot
    gate_lock = threading.Lock()
    pause_next = [False]
    probe_entered = threading.Event()
    allow_probe_finish = threading.Event()

    def _gated_read_snapshot(
        self: StorageDoctorReader,
        data_root: Path,
        *,
        checkout_root: Path | None = None,
        expected_store_id: str | None = None,
        privacy_scanner: Any = None,
        capture_probe: Any = None,
        limits: Any = None,
        **kwargs: Any,
    ) -> DoctorSnapshot:
        with gate_lock:
            should_pause = pause_next[0]
            if should_pause:
                pause_next[0] = False
        snap = orig_read_snapshot(
            self,
            data_root,
            checkout_root=checkout_root,
            expected_store_id=expected_store_id,
            privacy_scanner=privacy_scanner,
            capture_probe=capture_probe,
            limits=limits,
            **kwargs,
        )
        if should_pause:
            probe_entered.set()
            assert allow_probe_finish.wait(timeout=BOUND_WAIT_S), "doctor snapshot probe barrier timed out"
        return snap

    monkeypatch.setattr(StorageDoctorReader, "read_snapshot", _gated_read_snapshot)

    with _running_serve(cfg, os_=os_, clock=clock, mono=real_mono) as (ready, loop):
        try:
            assert loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
            clock.advance(timedelta(minutes=16))

            # Arm pause on next doctor probe, then call /v2/operator/doctor/report with wait_timeout_ms=100.
            with gate_lock:
                pause_next[0] = True
            probe_entered.clear()
            allow_probe_finish.clear()

            t0 = time.monotonic()
            cutoff_env = _call_operator_json(
                ready.endpoint,
                store_id=rep.store_id,
                ca_pem=ca_pem,
                leaf_sha256=leaf_sha256,
                token=cli_token,
                path="/v2/operator/doctor/report",
                body={"wait_timeout_ms": 100},
                monotonic_ns=real_mono.monotonic_ns,
            )
            elapsed = time.monotonic() - t0
            assert probe_entered.wait(timeout=BOUND_WAIT_S), "doctor worker did not enter Phase 2 wait"
            assert elapsed >= 0.08, f"wait_timeout_ms=100 returned too early ({elapsed:.3f}s)"
            assert cutoff_env.get("ok") is True, cutoff_env
            cutoff_data = cast(dict[str, Any], cutoff_env["data"])
            assert cutoff_data.get("status") == "running"
            active_job_id = cutoff_data.get("job_id")
            assert isinstance(active_job_id, str) and active_job_id

            # While Phase 2 probe is STILL blocked, OwnerLoop must serve shallow health and normal requests unimpeded.
            client = LoopbackClient(monotonic_ns=real_mono.monotonic_ns)
            target = LoopbackTarget(
                endpoint=ready.endpoint,
                expected_store_id=rep.store_id,
                ca_pem=ca_pem,
                leaf_cert_sha256=leaf_sha256,
            )
            shallow = client.call(
                target,
                ToolCommand("get_health", {"schema_version": "2.0", "deep": False}, token=cred_mcp.token),
                deadline_ns=real_mono.monotonic_ns() + TOTAL_REQUEST_BUDGET_NS,
            )
            assert shallow.get("ok") is True and cast(dict[str, Any], shallow["data"]).get("ready") is True

            signer_list = _call_operator_json(
                ready.endpoint,
                store_id=rep.store_id,
                ca_pem=ca_pem,
                leaf_sha256=leaf_sha256,
                token=cli_token,
                path="/v2/operator/signer/list",
                body={},
                monotonic_ns=real_mono.monotonic_ns,
            )
            assert signer_list.get("ok") is True

            job_query = client.call(
                target,
                ToolCommand("get_job", {"schema_version": "2.0", "job_id": active_job_id}, token=cred_mcp.token),
                deadline_ns=real_mono.monotonic_ns() + TOTAL_REQUEST_BUDGET_NS,
            )
            assert job_query.get("ok") is True and cast(dict[str, Any], job_query["data"])["job_id"] == active_job_id

            # Installed CLI `brain doctor --profile ... --wait-ms 50 --json` returns running + same job_id cleanly.
            cli_cutoff = run_installed_command(
                inc2_installed_env,
                "brain",
                ["doctor", "--profile", str(cli_profile), "--wait-ms", "50", "--json"],
                cwd=cwd,
            )
            assert cli_cutoff.returncode == 0, cli_cutoff.stderr.decode("utf-8", errors="replace")
            assert cli_cutoff.stderr == b""
            cli_cutoff_env = json.loads(cli_cutoff.stdout.decode("utf-8"))
            assert cli_cutoff_env.get("ok") is True
            assert cli_cutoff_env["data"]["status"] == "running"
            assert cli_cutoff_env["data"]["job_id"] == active_job_id

            # Start a wait_timeout_ms=5000 caller in background, release probe, and verify early wakeup + full DTO.
            done_box: list[dict[str, Any]] = []

            def _waiter() -> None:
                done_box.append(
                    _call_operator_json(
                        ready.endpoint,
                        store_id=rep.store_id,
                        ca_pem=ca_pem,
                        leaf_sha256=leaf_sha256,
                        token=cli_token,
                        path="/v2/operator/doctor/report",
                        body={"wait_timeout_ms": 5000},
                        monotonic_ns=real_mono.monotonic_ns,
                    )
                )

            wait_thr = threading.Thread(target=_waiter, daemon=True)
            wait_thr.start()
            time.sleep(0.05)
            allow_probe_finish.set()
            wait_thr.join(timeout=BOUND_WAIT_S)
            assert len(done_box) == 1 and done_box[0].get("ok") is True, done_box
            full_data = cast(dict[str, Any], done_box[0]["data"])
            assert DOCTOR_REPORT_DTO_KEYS <= set(full_data)
            assert full_data["job_id"] == active_job_id
            assert isinstance(full_data.get("doctor_run_id"), str) and full_data["doctor_run_id"]
            assert full_data.get("status") != "running"

            # Reject invalid /v2/operator/doctor/report bodies cleanly.
            for bad_body in (
                {"wait_timeout_ms": -1},
                {"wait_timeout_ms": 10001},
                {"wait_timeout_ms": True},
                {"wait_timeout_ms": "100"},
                {"owner_id": "dan"},
            ):
                bad_res = _call_operator_json(
                    ready.endpoint,
                    store_id=rep.store_id,
                    ca_pem=ca_pem,
                    leaf_sha256=leaf_sha256,
                    token=cli_token,
                    path="/v2/operator/doctor/report",
                    body=cast(dict[str, object], bad_body),
                    monotonic_ns=real_mono.monotonic_ns,
                )
                _assert_error_envelope(bad_res, ErrorCode.INVALID_INPUT.value)
        finally:
            allow_probe_finish.set()


def test_operator_doctor_report_state_change_between_phase1_and_phase3(
    trusted_tmp: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Auth revocation or online policy/store restore during Phase 2 fails closed in Phase 3."""
    clock = FakeClock(_base_utc_now())
    real_mono = os_adapters().monotonic
    base_os = os_adapters(clock=clock, monotonic=real_mono)
    rep, cfg, priv, ca_pem, leaf_sha256, cli_token, os_ = _init_store_with_tls(
        trusted_tmp / "phase-fence", clock, os_=base_os
    )
    root = DataRoot.at(cfg.data_root)

    rt = reopen_kernel_job_runtime(cfg.data_root, rep.store_id, os_)
    try:
        cli_ephemeral = seed_principal_and_credential(
            rt.policy, owner_id=OWNER, harness_id=CLI_HARNESS_ID, machine_id=MACHINE
        )
        policy_bak = create_policy_backup(rt.policy, os_, clock.now())
        rt.policy.record_intent(IntentKind.QUARANTINE, {"digest": digest_bytes(b"post-policy-bak-i43")})
        rt.store.reconcile_policy()
        store_bak = create_store_backup(rt.store, os_, clock.now())
    finally:
        rt.close()

    orig_read_snapshot = StorageDoctorReader.read_snapshot
    gate_lock = threading.Lock()
    pause_next = [False]
    tag_stale = [False]
    probe_cond = threading.Condition()
    probe_entered = threading.Event()
    allow_probe_finish = threading.Event()

    def _gated_read_snapshot(
        self: StorageDoctorReader,
        data_root: Path,
        *,
        checkout_root: Path | None = None,
        expected_store_id: str | None = None,
        privacy_scanner: Any = None,
        capture_probe: Any = None,
        limits: Any = None,
        **kwargs: Any,
    ) -> DoctorSnapshot:
        with gate_lock:
            should_pause = pause_next[0]
            should_tag = tag_stale[0]
            if should_pause:
                pause_next[0] = False
                tag_stale[0] = False
        snap = orig_read_snapshot(
            self,
            data_root,
            checkout_root=checkout_root,
            expected_store_id=expected_store_id,
            privacy_scanner=privacy_scanner,
            capture_probe=capture_probe,
            limits=limits,
            **kwargs,
        )
        if should_pause:
            with probe_cond:
                probe_entered.set()
                probe_cond.notify_all()
            assert allow_probe_finish.wait(timeout=BOUND_WAIT_S), "phase-change probe barrier timed out"
            if should_tag:
                return replace(snap, integrity_errors=(*snap.integrity_errors, "stale_prerestore_report_marker"))
        return snap

    def _wait_probe_or_fail(
        call_done: threading.Event,
        out_list: list[dict[str, Any]],
        err_list: list[BaseException],
        label: str,
    ) -> None:
        with probe_cond:
            woke = probe_cond.wait_for(
                lambda: probe_entered.is_set() or call_done.is_set(),
                timeout=BOUND_WAIT_S,
            )
        assert woke and probe_entered.is_set(), (
            f"{label}: doctor probe never entered Phase 2 (out={out_list}, err={err_list})"
        )

    monkeypatch.setattr(StorageDoctorReader, "read_snapshot", _gated_read_snapshot)

    with _running_serve(cfg, os_=os_, clock=clock, mono=real_mono) as (ready, loop):
        try:
            assert loop.wait_doctor_settled(timeout=BOUND_WAIT_S)

            # (a) Revoke calling user:cli credential WHILE Phase 2 is waiting -> Phase 3 fails closed (unauthenticated).
            clock.advance(timedelta(minutes=16))
            with gate_lock:
                pause_next[0] = True
                tag_stale[0] = False
            probe_entered.clear()
            allow_probe_finish.clear()

            rev_out: list[dict[str, Any]] = []
            rev_err: list[BaseException] = []
            rev_done = threading.Event()

            def _call_revoked() -> None:
                try:
                    rev_out.append(
                        _call_operator_json(
                            ready.endpoint,
                            store_id=rep.store_id,
                            ca_pem=ca_pem,
                            leaf_sha256=leaf_sha256,
                            token=cli_ephemeral.token,
                            path="/v2/operator/doctor/report",
                            body={"wait_timeout_ms": 5000},
                            monotonic_ns=real_mono.monotonic_ns,
                        )
                    )
                except BaseException as exc:  # noqa: BLE001
                    rev_err.append(exc)
                finally:
                    with probe_cond:
                        rev_done.set()
                        probe_cond.notify_all()

            thr_rev = threading.Thread(target=_call_revoked, daemon=True)
            thr_rev.start()
            _wait_probe_or_fail(rev_done, rev_out, rev_err, "revoke")
            time.sleep(0.05)  # Ensure caller is actively waiting in Phase 2 before revocation.

            rev_auth = make_bootstrap_auth(
                store_id=rep.store_id,
                owner_id=OWNER,
                action="credential_revoke",
                subject_id=cli_ephemeral.credential_id,
                trust_generation=1,
                expires_at=clock.now() + timedelta(hours=1),
            )
            loop.revoke_credential(cli_ephemeral.credential_id, rev_auth).result(timeout=BOUND_WAIT_S)
            allow_probe_finish.set()
            thr_rev.join(timeout=BOUND_WAIT_S)
            assert not rev_err, rev_err
            assert len(rev_out) == 1
            _assert_error_envelope(rev_out[0], ErrorCode.UNAUTHENTICATED.value)
            assert loop.wait_doctor_settled(timeout=BOUND_WAIT_S)

            # (b1) Online policy restore WHILE Phase 2 is waiting -> Phase 3 fails closed (revision_conflict/unavail).
            for target_kind, bak_path in (("policy", policy_bak), ("store", store_bak)):
                clock.advance(timedelta(minutes=16))
                live_ep = read_client_endpoint(root.endpoint_path, os_)
                live_ready = replace(ready, endpoint=live_ep, identity=live_ep.identity)
                with gate_lock:
                    pause_next[0] = True
                    tag_stale[0] = True
                probe_entered.clear()
                allow_probe_finish.clear()

                rest_out: list[dict[str, Any]] = []
                rest_err: list[BaseException] = []
                rest_done = threading.Event()

                def _call_restore_raced(
                    cur_ep: Endpoint = live_ep,
                    out_list: list[dict[str, Any]] = rest_out,
                    err_list: list[BaseException] = rest_err,
                    done_ev: threading.Event = rest_done,
                ) -> None:
                    try:
                        out_list.append(
                            _call_operator_json(
                                cur_ep,
                                store_id=rep.store_id,
                                ca_pem=ca_pem,
                                leaf_sha256=leaf_sha256,
                                token=cli_token,
                                path="/v2/operator/doctor/report",
                                body={"wait_timeout_ms": 5000},
                                monotonic_ns=real_mono.monotonic_ns,
                            )
                        )
                    except BaseException as exc:  # noqa: BLE001
                        err_list.append(exc)
                    finally:
                        with probe_cond:
                            done_ev.set()
                            probe_cond.notify_all()

                thr_rest = threading.Thread(target=_call_restore_raced, daemon=True)
                thr_rest.start()
                _wait_probe_or_fail(rest_done, rest_out, rest_err, f"{target_kind}-restore")
                time.sleep(0.05)

                _run_online_restore(
                    live_ready,
                    store_id=rep.store_id,
                    ca_pem=ca_pem,
                    leaf_sha256=leaf_sha256,
                    cli_token=cli_token,
                    priv=priv,
                    signer_id=rep.signer.signer_id,
                    target_kind=target_kind,
                    backup_path=bak_path,
                    os_=os_,
                    monotonic_ns=real_mono.monotonic_ns,
                )

                thr_rest.join(timeout=1.0)
                if thr_rest.is_alive():
                    allow_probe_finish.set()
                    thr_rest.join(timeout=BOUND_WAIT_S)
                else:
                    allow_probe_finish.set()
                assert loop.wait_doctor_settled(timeout=BOUND_WAIT_S)

                if rest_err:
                    assert len(rest_err) == 1 and isinstance(rest_err[0], LoopbackTransportError), rest_err
                    assert rest_err[0].code in {ErrorCode.REVISION_CONFLICT, ErrorCode.DAEMON_UNAVAILABLE}
                else:
                    assert len(rest_out) == 1
                    err_env = rest_out[0]
                    assert err_env.get("ok") is False, f"{target_kind} restore allowed stale report: {err_env}"
                    err_code = cast(dict[str, Any], err_env["error"])["code"]
                    assert err_code in {ErrorCode.REVISION_CONFLICT.value, ErrorCode.DAEMON_UNAVAILABLE.value}
                    assert "stale_prerestore_report_marker" not in json.dumps(err_env)

            # Fresh post-restore /v2/operator/doctor/report succeeds cleanly on refreshed endpoint epoch.
            post_ep = read_client_endpoint(root.endpoint_path, os_)
            post_ok = _call_operator_json(
                post_ep,
                store_id=rep.store_id,
                ca_pem=ca_pem,
                leaf_sha256=leaf_sha256,
                token=cli_token,
                path="/v2/operator/doctor/report",
                body={"wait_timeout_ms": 5000},
                monotonic_ns=real_mono.monotonic_ns,
            )
            assert post_ok.get("ok") is True, post_ok
            assert "stale_prerestore_report_marker" not in json.dumps(post_ok)
        finally:
            allow_probe_finish.set()


def test_operator_doctor_report_multi_owner_isolation(
    trusted_tmp: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Distinct ``user:cli`` owners on ``/v2/operator/doctor/report`` get owner-isolated jobs & ``DoctorRun``s."""
    clock = FakeClock(_base_utc_now())
    real_mono = os_adapters().monotonic
    base_os = os_adapters(clock=clock, monotonic=real_mono)
    rep, cfg, _priv, ca_pem, leaf_sha256, cli_dan_token, os_ = _init_store_with_tls(
        trusted_tmp / "multi-owner", clock, os_=base_os
    )
    root = DataRoot.at(cfg.data_root)

    rt = reopen_kernel_job_runtime(cfg.data_root, rep.store_id, os_)
    try:
        cli_bob = seed_principal_and_credential(
            rt.policy, owner_id="bob", harness_id=CLI_HARNESS_ID, machine_id=MACHINE
        )
        cli_carol = seed_principal_and_credential(
            rt.policy, owner_id="carol", harness_id=CLI_HARNESS_ID, machine_id=MACHINE
        )
    finally:
        rt.close()

    orig_read_snapshot = StorageDoctorReader.read_snapshot
    gate_lock = threading.Lock()
    pause_next = [False]
    probe_entered = threading.Event()
    allow_probe_finish = threading.Event()

    def _gated_read_snapshot(
        self: StorageDoctorReader,
        data_root: Path,
        *,
        checkout_root: Path | None = None,
        expected_store_id: str | None = None,
        privacy_scanner: Any = None,
        capture_probe: Any = None,
        limits: Any = None,
        **kwargs: Any,
    ) -> DoctorSnapshot:
        with gate_lock:
            should_pause = pause_next[0]
            if should_pause:
                pause_next[0] = False
        snap = orig_read_snapshot(
            self,
            data_root,
            checkout_root=checkout_root,
            expected_store_id=expected_store_id,
            privacy_scanner=privacy_scanner,
            capture_probe=capture_probe,
            limits=limits,
            **kwargs,
        )
        if should_pause:
            probe_entered.set()
            assert allow_probe_finish.wait(timeout=BOUND_WAIT_S)
        return snap

    monkeypatch.setattr(StorageDoctorReader, "read_snapshot", _gated_read_snapshot)

    with _running_serve(cfg, os_=os_, clock=clock, mono=real_mono) as (ready, loop):
        try:
            assert loop.wait_doctor_settled(timeout=BOUND_WAIT_S)

            # Completed runs: dan vs bob never share DoctorRun or job_id.
            dan_res = _call_operator_json(
                ready.endpoint,
                store_id=rep.store_id,
                ca_pem=ca_pem,
                leaf_sha256=leaf_sha256,
                token=cli_dan_token,
                path="/v2/operator/doctor/report",
                body={"wait_timeout_ms": 5000},
                monotonic_ns=real_mono.monotonic_ns,
            )
            assert dan_res.get("ok") is True, dan_res
            dan_data = cast(dict[str, Any], dan_res["data"])

            bob_res = _call_operator_json(
                ready.endpoint,
                store_id=rep.store_id,
                ca_pem=ca_pem,
                leaf_sha256=leaf_sha256,
                token=cli_bob.token,
                path="/v2/operator/doctor/report",
                body={"wait_timeout_ms": 5000},
                monotonic_ns=real_mono.monotonic_ns,
            )
            assert bob_res.get("ok") is True, bob_res
            bob_data = cast(dict[str, Any], bob_res["data"])

            assert DOCTOR_REPORT_DTO_KEYS <= set(dan_data) and DOCTOR_REPORT_DTO_KEYS <= set(bob_data)
            assert bob_data["doctor_run_id"] != dan_data["doctor_run_id"]
            assert bob_data["job_id"] != dan_data["job_id"]

            # In-flight isolation: while dan's job is paused running, carol gets her OWN job_id!
            clock.advance(timedelta(minutes=16))
            with gate_lock:
                pause_next[0] = True
            probe_entered.clear()
            allow_probe_finish.clear()

            dan_inflight = _call_operator_json(
                ready.endpoint,
                store_id=rep.store_id,
                ca_pem=ca_pem,
                leaf_sha256=leaf_sha256,
                token=cli_dan_token,
                path="/v2/operator/doctor/report",
                body={"wait_timeout_ms": 50},
                monotonic_ns=real_mono.monotonic_ns,
            )
            assert probe_entered.wait(timeout=BOUND_WAIT_S)
            assert dan_inflight.get("ok") is True
            dan_inflight_job = str(dan_inflight["data"]["job_id"])

            carol_inflight = _call_operator_json(
                ready.endpoint,
                store_id=rep.store_id,
                ca_pem=ca_pem,
                leaf_sha256=leaf_sha256,
                token=cli_carol.token,
                path="/v2/operator/doctor/report",
                body={"wait_timeout_ms": 50},
                monotonic_ns=real_mono.monotonic_ns,
            )
            assert carol_inflight.get("ok") is True
            carol_job_id = str(carol_inflight["data"]["job_id"])
            assert carol_job_id and carol_job_id != dan_inflight_job

            allow_probe_finish.set()
            assert loop.wait_doctor_settled(timeout=BOUND_WAIT_S)

            # Verify ledger & p_jobs_state owner_id partitioning in store.db.
            with _ro_db(root.store_db) as conn:
                job_owners = {
                    str(jid): str(own)
                    for jid, own in conn.execute(
                        "SELECT job_id, owner_id FROM p_jobs_state WHERE kind = 'system.doctor'"
                    ).fetchall()
                }
                assert job_owners[str(dan_data["job_id"])] == OWNER
                assert job_owners[str(bob_data["job_id"])] == "bob"
                assert job_owners[dan_inflight_job] == OWNER
                assert job_owners[carol_job_id] == "carol"

                run_owners: dict[str, str] = {}
                for (raw_meta,) in conn.execute("SELECT meta FROM ledger WHERE kind = 'doctor.run'").fetchall():
                    m = cast(dict[str, Any], json.loads(bytes(raw_meta).decode("utf-8")))
                    run_owners[str(m["doctor_run_id"])] = str(m["owner_id"])
                assert run_owners[str(dan_data["doctor_run_id"])] == OWNER
                assert run_owners[str(bob_data["doctor_run_id"])] == "bob"
        finally:
            allow_probe_finish.set()


# ---------------------------------------------------------------------------
# Requirement 5: Offline Read-Only Safety on Newer Schema
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bumped_db", ("store", "policy"))
def test_doctor_offline_readonly_on_newer_schema_99(
    inc2_installed_env: InstalledEnv,
    trusted_tmp: Path,
    bumped_db: str,
) -> None:
    """Offline CLI on schema_version=99/min_reader_version=99 exits 0 with safe fail report & 0 writes/0 locks."""
    os_ = os_adapters()
    cwd = trusted_tmp / "outside"
    cwd.mkdir()
    os_.permissions.secure_directory(cwd)

    data_root, _cfg_dir, daemon_cfg, store_id, _ca, _sha, _tok = _init_via_installed_wheel(
        inc2_installed_env, trusted_tmp / f"schema99-{bumped_db}", cwd=cwd
    )
    root = DataRoot.at(data_root)

    if bumped_db == "store":
        db_path = root.store_db
        conn = sqlite3.connect(db_path)
        try:
            conn.execute("DROP TABLE ledger")
            conn.execute("DROP TABLE p_cas_holders_")
            conn.execute("CREATE TABLE future_v99_events (id INTEGER PRIMARY KEY)")
            conn.execute("UPDATE meta SET value = '99' WHERE key = 'schema_version'")
            conn.execute("UPDATE meta SET value = '99' WHERE key = 'min_reader_version'")
            conn.commit()
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            conn.close()
    else:
        db_path = root.policy_db
        conn = sqlite3.connect(db_path)
        try:
            conn.execute("DROP TABLE trust")
            conn.execute("DROP TABLE principal")
            conn.execute("DROP TABLE intents")
            conn.execute("CREATE TABLE future_v99_policy (k TEXT PRIMARY KEY)")
            conn.execute("UPDATE meta SET value = '99' WHERE key = 'schema_version'")
            conn.execute("UPDATE meta SET value = '99' WHERE key = 'min_reader_version'")
            conn.commit()
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            conn.close()
    os_.permissions.secure_file(db_path)

    snap_before = digest_tree(data_root)

    for args in (
        ["doctor", "--config", str(daemon_cfg), "--json"],
        ["doctor", "--offline", "--config", str(daemon_cfg), "--json"],
    ):
        res = run_installed_command(inc2_installed_env, "brain", args, cwd=cwd)
        data = _assert_completed_doctor_json(res.stdout, res.stderr, res.returncode, expected_store_id=store_id)
        assert data["overall_status"] == "fail"
        sch = cast(dict[str, Any], data["schema"])
        if bumped_db == "store":
            assert sch["store_version"] == 99 and sch["min_store_reader_version"] == 99
        else:
            assert sch["policy_version"] == 99 and sch["min_policy_reader_version"] == 99
        assert any(
            chk["group"] == "daemon" and chk["status"] == "FAIL" and chk["reason"] == "unsupported_version"
            for chk in cast(list[dict[str, Any]], data["checks"])
        )
        assert "no such table" not in res.stdout.decode("utf-8", errors="replace").lower()

    res_txt = run_installed_command(
        inc2_installed_env, "brain", ["doctor", "--offline", "--config", str(daemon_cfg)], cwd=cwd
    )
    assert res_txt.returncode == 0 and res_txt.stderr == b""
    txt_out = res_txt.stdout.decode("utf-8", errors="strict")
    assert "Overall status: fail" in txt_out
    assert "unsupported_version" in txt_out
    assert "no such table" not in txt_out.lower()

    # Verify zero bytes mutated and zero exclusive locks acquired.
    assert digest_tree(data_root) == snap_before
    locks_spy = _SpyNoAcquireLocks(cast(LockProbePort, os_.locks))
    pub_proxy = _ReadOnlyPublisherProxy(os_.publisher, (data_root,))
    spy_os = replace(os_, locks=locks_spy, publisher=pub_proxy)
    rep_inproc: DoctorReport = doctor_entry.run_doctor(daemon_cfg, os_=spy_os)
    assert rep_inproc.overall_status == "fail"
    assert locks_spy.probe_calls >= 1
    assert digest_tree(data_root) == snap_before
