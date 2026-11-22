"""Independent I4-4 oracle tests for safe ``brain doctor --fix`` & crash matrix.

Requirement sources:
- Spec rev 22 §11.3, §13, §14.2, §20.28
- Frozen contract ``I4-4`` (§13 Safe Repairs ``--fix`` & Crash Matrix)
"""

from __future__ import annotations

import base64
import contextlib
import json
import os
import sqlite3
import stat
import struct
import subprocess
import sys
import threading
from collections.abc import Iterator, Mapping
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import superbrain.composition.doctor_entry as doctor_entry
import superbrain.storage.restore as storage_restore
from superbrain.adapters.harness_config.markdown_blocks import merge_markdown_block
from superbrain.adapters.harness_config.merger import SharedConfigMergerAdapter
from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.daemon_config import read_daemon_config
from superbrain.adapters.os.tls_material import verify_server_tls_files
from superbrain.application._doctor_fix import tighten_data_root_permissions
from superbrain.application.owner_loop import OwnerLoop
from superbrain.application.review_apply import ReviewApplyService, TargetWriteInput
from superbrain.cli_api.loopback import LoopbackClient, LoopbackTarget
from superbrain.cli_api.operator import OPERATOR_PATHS
from superbrain.composition import daemon_entry
from superbrain.composition._daemon_session import DaemonTestHooks
from superbrain.composition.init_entry import InitReport, InitRequest, init_store
from superbrain.core._kernel_approval import (
    CLI_HARNESS_ID,
    RISK_POLICY_VERSION,
    ApprovalAction,
    ApprovalChannel,
    ApprovalMessage,
    RecoveryScope,
    RiskResource,
    SignerEnrollment,
)
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import SAFE_WIRE_MESSAGES, BrainError, ErrorCode
from superbrain.core.faults import KNOWN_CRASHPOINTS
from superbrain.core.ids import new_id
from superbrain.core.kernel import DaemonConfig, Endpoint, Ready
from superbrain.core.proposals import ManagedFormat, ProposalStatus
from superbrain.ports.doctor import (
    MAX_LOG_BYTES,
    OutboxReplayPort,
    OutboxReplayResult,
    SupervisorControlPort,
    SupervisorRestartResult,
)
from superbrain.ports.os import DurabilityReport, LockFactory, LockHandle, LockProbePort, NoReplacePublisher, OsAdapters
from superbrain.ports.policy import IntentKind
from superbrain.storage.backup import create_store_backup
from superbrain.storage.cas import RetentionClass, active_held_digests
from superbrain.storage.layout import DataRoot
from superbrain.storage.proposals import PolicyApplyAuthority, StoreProposalAdapter
from superbrain.storage.restore import read_restore_epoch
from superbrain.storage.runtime import Runtime
from superbrain.storage.sqlite import open_readonly
from superbrain.storage.writer import acquire_writer_unbumped
from tests.support.clock import FakeClock
from tests.support.crash_cases import (
    KernelCrashContext,
    assert_entered,
    assert_wheel_provenance,
    lock_epoch,
    pair_rows,
)
from tests.support.fs import digest_tree
from tests.support.inc2_cli import (
    clean_installed_subprocess_env,
    get_shared_t7_transport_template,
    run_installed_command,
    spawn_installed_brain_serve,
    write_client_profile_file,
    write_credential_file,
    write_owner_only_bytes,
)
from tests.support.inc2_fixture import InstalledEnv, reopen_kernel_job_runtime
from tests.support.inc2_transport import register_workspace_direct
from tests.support.inc3_crash_child import raw_i33_policy, raw_i33_store
from tests.support.inc4_crash_cases import (
    I4_4_CRASH_CASES,
    I4_4_CRASHPOINTS,
    I44_CHILD,
    I44CrashCase,
    prepare_i44_seed,
    run_i44_child,
    run_i44_crash_case,
)
from tests.support.kernel_auth import make_bootstrap_auth, seed_principal_and_credential
from tests.support.rereview_1d666f5 import flip_last_hex_char, leaf_sha

OWNER = "dan"
MACHINE = "i4-4-box"
BOUND_WAIT_S = 10.0

SAFE_FIX_ACTIONS: frozenset[str] = frozenset(
    {
        "tighten_permissions",
        "reconcile_policy",
        "rebuild_projections",
        "rotate_logs",
        "replay_outbox",
        "restart_daemon",
    }
)
SAFE_FIX_STATUSES: frozenset[str] = frozenset({"applied", "noop", "capability_unavailable", "failed"})

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
    line = "ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + f" {owner_id}@i4-4"
    return priv, SignerEnrollment(owner_id=owner_id, channel=ApprovalChannel.SSH_KEY, public_key=line)


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
    _priv, enrollment = _ssh_signer_key(owner_id)
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


def _unused_loopback_port() -> int:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _grant_wide_access(path: Path) -> None:
    if sys.platform == "win32":
        import ntsecuritycon

        from tests.support.winacl import grant

        grant(path, "S-1-1-0", ntsecuritycon.FILE_GENERIC_READ)
    else:
        os.chmod(path, 0o755 if path.is_dir() else 0o644)


def _acl_or_mode(path: Path) -> str:
    if sys.platform == "win32":
        from tests.support.winacl import security_sddl

        return security_sddl(path)
    return f"{stat.S_IMODE(os.lstat(path).st_mode):04o}"


def _make_dir_link(link: Path, target: Path) -> None:
    if sys.platform == "win32":
        import _winapi

        _winapi.CreateJunction(str(target), str(link))
    else:
        link.symlink_to(target, target_is_directory=True)


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


def _assert_completed_fix_json(
    stdout: bytes,
    stderr: bytes,
    rc: int,
    *,
    expected_store_id: str | None = None,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    assert rc == 0, f"expected exit 0, got {rc} (stdout={stdout!r}, stderr={stderr!r})"
    assert stderr == b"", f"expected empty stderr on exit 0, got {stderr!r}"
    env = json.loads(stdout.decode("utf-8", errors="strict"))
    assert isinstance(env, dict) and set(env) == {"ok", "data"} and env.get("ok") is True, env
    data = cast(dict[str, Any], env["data"])
    assert isinstance(data, dict), env
    missing_keys = (DOCTOR_REPORT_DTO_KEYS | {"fix"}) - set(data)
    assert not missing_keys, f"missing DoctorFix DTO keys {sorted(missing_keys)} in {sorted(data)}"
    assert data["overall_status"] in {"pass", "warn", "fail"}, data
    if expected_store_id is not None:
        assert data["store_id"] == expected_store_id
    fix = data["fix"]
    assert isinstance(fix, dict), fix
    assert {"actions", "rechecked_checks"} <= set(fix), fix
    actions = fix["actions"]
    assert isinstance(actions, list) and len(actions) > 0, fix
    by_name: dict[str, dict[str, Any]] = {}
    for item in actions:
        assert isinstance(item, dict), item
        assert {"action", "status", "detail"} <= set(item), item
        name = item["action"]
        assert isinstance(name, str) and name in SAFE_FIX_ACTIONS, item
        assert name not in by_name, f"duplicate action {name!r} in {actions}"
        assert item["status"] in SAFE_FIX_STATUSES, item
        assert isinstance(item["detail"], str), item
        by_name[name] = item
    rechecked = fix["rechecked_checks"]
    assert isinstance(rechecked, list) and len(rechecked) > 0, fix
    return data, by_name


def _check_by(data: Mapping[str, Any], group: str, name: str) -> dict[str, Any]:
    for chk in cast(list[dict[str, Any]], data["checks"]):
        if chk.get("group") == group and chk.get("name") in (name, f"{group}.{name}"):
            return chk
    raise AssertionError(f"missing check {group}.{name} in {data['checks']}")


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


class _SpyNoAcquireLocks(LockFactory, LockProbePort):
    def __init__(self, inner: LockProbePort) -> None:
        self._inner = inner
        self.probe_calls = 0

    def acquire(self, path: Path) -> LockHandle:
        raise AssertionError(f"fail-closed doctor --fix must never acquire exclusive writer lock on {path}")

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
                raise AssertionError(f"refused doctor --fix called mutating {op} on {path}")

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

    def durability(self, directory: Path, env: Mapping[str, str]) -> DurabilityReport:
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
    hooks: DaemonTestHooks | None = None,
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
                hooks=hooks,
            )
        )

    thr = threading.Thread(target=_bg, name="i4-4-serve", daemon=True)
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


# ---------------------------------------------------------------------------
# 1. CLI Syntax, Invalid Flags & Response JSON Schema
# ---------------------------------------------------------------------------


def test_doctor_fix_cli_syntax_and_clean_response_schema(
    inc2_installed_env: InstalledEnv,
    trusted_tmp: Path,
) -> None:
    """Exit 2 on duplicate/invalid --fix flags, exit 0 schema with SAFE_FIX_ACTIONS & capability_unavailable."""
    os_ = os_adapters()
    cwd = trusted_tmp / "outside"
    cwd.mkdir()
    os_.permissions.secure_directory(cwd)

    data_root, cfg_dir, daemon_cfg, store_id, _ca, server_sha, _tok = _init_via_installed_wheel(
        inc2_installed_env, trusted_tmp / "cli-syntax", cwd=cwd
    )
    co_dir = trusted_tmp / "co"
    co_dir.mkdir()
    os_.permissions.secure_directory(co_dir)
    prof_path, _ = write_client_profile_file(
        cfg_dir / "cli.profile.json",
        endpoint_path=data_root / "endpoint.json",
        expected_store_id=store_id,
        ca_file=cfg_dir / "tls" / "ca.pem",
        leaf_cert_sha256=server_sha,
        credential_file=cfg_dir / "cli.credential",
    )

    invalid_cases: tuple[list[str], ...] = (
        ["doctor", "--fix"],
        ["doctor", "--fix", "--offline"],
        ["doctor", "--fix", "--fix", "--config", str(daemon_cfg)],
        ["doctor", "--offline", "--fix", "--fix", "--profile", str(prof_path)],
        ["doctor", "--fix", "--config", str(daemon_cfg), "--profile", str(prof_path)],
        ["doctor", "--fix", "--unknown-flag", "--config", str(daemon_cfg)],
        ["doctor", "--fix", "--config", "relative/daemon.json"],
        ["doctor", "--fix", "--profile", "relative/cli.profile.json"],
        ["doctor", "--fix", "--config", str(daemon_cfg), "--checkout", "relative/co"],
        ["doctor", "--fix", "--config", str(cfg_dir / "sub" / ".." / "daemon.json")],
        ["doctor", "--fix", "--profile", str(prof_path), "--wait-ms", "-1"],
        ["doctor", "--fix", "--profile", str(prof_path), "--wait-ms", "10001"],
        ["doctor", "--fix", "--profile", str(prof_path), "--wait-ms", "abc"],
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
        res_json = run_installed_command(inc2_installed_env, "brain", [*base_args, "--json"], cwd=cwd)
        _assert_cli_error(
            res_json.returncode,
            res_json.stdout,
            res_json.stderr,
            expected_rc=2,
            expected_code=ErrorCode.INVALID_INPUT.value,
            as_json=True,
            label=("json", base_args),
        )

    # Clean offline `--fix --json` and plain text via `--config` and `--profile`.
    # Per §13 invariant: daemon stopped -> doctor is strictly read-only.
    # Offline --fix MUST fail closed with rc=1 and ErrorCode.DAEMON_UNAVAILABLE.
    for selector_flag, selector_path in (("--config", daemon_cfg), ("--profile", prof_path)):
        res_fail = run_installed_command(
            inc2_installed_env,
            "brain",
            ["doctor", "--offline", "--fix", selector_flag, str(selector_path), "--checkout", str(co_dir), "--json"],
            cwd=cwd,
        )
        _assert_cli_error(
            res_fail.returncode,
            res_fail.stdout,
            res_fail.stderr,
            expected_rc=1,
            expected_code=ErrorCode.DAEMON_UNAVAILABLE.value,
            as_json=True,
            label=("offline-fix-json", selector_flag),
        )

    res_txt = run_installed_command(
        inc2_installed_env,
        "brain",
        ["doctor", "--offline", "--fix", "--config", str(daemon_cfg)],
        cwd=cwd,
    )
    _assert_cli_error(
        res_txt.returncode,
        res_txt.stdout,
        res_txt.stderr,
        expected_rc=1,
        expected_code=ErrorCode.DAEMON_UNAVAILABLE.value,
        as_json=False,
        label=("offline-fix-txt", "--config"),
    )


# ---------------------------------------------------------------------------
# 2. Fail-Closed Security, Lock Ordering & Unsupported Schema Matrix
# ---------------------------------------------------------------------------


def test_doctor_fix_fail_closed_security_anti_fallback_and_lock_ordering(
    inc2_installed_env: InstalledEnv,
    trusted_tmp: Path,
) -> None:
    """Stopped --fix requires --offline; live --offline fails store_busy; revoked/harness/bad-pin fail closed."""
    os_ = os_adapters()
    cwd = trusted_tmp / "outside"
    cwd.mkdir()
    os_.permissions.secure_directory(cwd)

    data_root, cfg_dir, daemon_cfg, store_id, ca_pem, server_sha, _cli_tok = _init_via_installed_wheel(
        inc2_installed_env, trusted_tmp / "sec-fix", cwd=cwd
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

    revoked_cred_file = write_credential_file(trusted_tmp / "revoked-cli.credential", cred_cli_revoked.token)
    revoked_profile, _ = write_client_profile_file(
        trusted_tmp / "revoked-cli.profile.json",
        endpoint_path=root.endpoint_path,
        expected_store_id=store_id,
        ca_file=cfg_dir / "tls" / "ca.pem",
        leaf_cert_sha256=server_sha,
        credential_file=revoked_cred_file,
    )
    unknown_cred_file = write_credential_file(trusted_tmp / "unknown.credential", "unknown-id.unknown-secret")
    unknown_profile, _ = write_client_profile_file(
        trusted_tmp / "unknown.profile.json",
        endpoint_path=root.endpoint_path,
        expected_store_id=store_id,
        ca_file=cfg_dir / "tls" / "ca.pem",
        leaf_cert_sha256=server_sha,
        credential_file=unknown_cred_file,
    )
    claude_cred_file = write_credential_file(trusted_tmp / "claude.credential", cred_claude.token)
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
    bad_pin_profile, _ = write_client_profile_file(
        trusted_tmp / "bad-pin.profile.json",
        endpoint_path=root.endpoint_path,
        expected_store_id=store_id,
        ca_file=cfg_dir / "tls" / "ca.pem",
        leaf_cert_sha256=flip_last_hex_char(server_sha),
        credential_file=cfg_dir / "cli.credential",
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

    # 1) Daemon stopped cleanly: `--fix` WITHOUT `--offline` MUST fail closed daemon_unavailable (0 locks, 0 writes).
    snap_0 = digest_tree(data_root)
    epoch_0 = lock_epoch(data_root)
    for flag, path in (("--config", daemon_cfg), ("--profile", cli_profile)):
        r_no_off = run_installed_command(
            inc2_installed_env, "brain", ["doctor", "--fix", flag, str(path), "--json"], cwd=cwd
        )
        _assert_cli_error(
            r_no_off.returncode,
            r_no_off.stdout,
            r_no_off.stderr,
            expected_rc=1,
            expected_code=ErrorCode.DAEMON_UNAVAILABLE.value,
            as_json=True,
            label=("stopped-fix-no-offline", flag),
        )
        locks_spy = _SpyNoAcquireLocks(cast(LockProbePort, os_.locks))
        pub_proxy = _ReadOnlyPublisherProxy(os_.publisher, (data_root,))
        spy_os = replace(os_, locks=locks_spy, publisher=pub_proxy)
        assert doctor_entry.run_doctor_cli(["doctor", "--fix", flag, str(path), "--json"], os_=spy_os) == 1
    assert digest_tree(data_root) == snap_0
    assert lock_epoch(data_root) == epoch_0

    # 2) Offline `--offline --fix` fails closed with daemon_unavailable BEFORE taking or bumping lock.
    offline_auth_cases: tuple[list[str], ...] = (
        ["doctor", "--offline", "--fix", "--profile", str(revoked_profile), "--json"],
        ["doctor", "--offline", "--fix", "--profile", str(unknown_profile), "--json"],
        ["doctor", "--offline", "--fix", "--profile", str(claude_profile), "--json"],
        ["doctor", "--offline", "--fix", "--profile", str(cli_ws_profile), "--checkout", str(co_b), "--json"],
    )
    for args in offline_auth_cases:
        res_auth = run_installed_command(inc2_installed_env, "brain", args, cwd=cwd)
        _assert_cli_error(
            res_auth.returncode,
            res_auth.stdout,
            res_auth.stderr,
            expected_rc=1,
            expected_code=ErrorCode.DAEMON_UNAVAILABLE.value,
            as_json=True,
            label=("offline-fix-auth", args),
        )
        locks_spy = _SpyNoAcquireLocks(cast(LockProbePort, os_.locks))
        pub_proxy = _ReadOnlyPublisherProxy(os_.publisher, (data_root,))
        spy_os = replace(os_, locks=locks_spy, publisher=pub_proxy)
        assert doctor_entry.run_doctor_cli(args, os_=spy_os) == 1
    assert digest_tree(data_root) == snap_0
    assert lock_epoch(data_root) == epoch_0

    # Offline `--offline --fix` fails closed even with matching `--checkout co_a`.
    res_co_match = run_installed_command(
        inc2_installed_env,
        "brain",
        ["doctor", "--offline", "--fix", "--profile", str(cli_ws_profile), "--checkout", str(co_a), "--json"],
        cwd=cwd,
    )
    _assert_cli_error(
        res_co_match.returncode,
        res_co_match.stdout,
        res_co_match.stderr,
        expected_rc=1,
        expected_code=ErrorCode.DAEMON_UNAVAILABLE.value,
        as_json=True,
        label="offline-fix-co-match",
    )

    # 3) endpoint.json absent AND writer.lock held -> fails daemon_unavailable BEFORE reading --profile cred/CA.
    cred_backup = (cfg_dir / "cli.credential").read_bytes()
    ca_backup = (cfg_dir / "tls" / "ca.pem").read_bytes()
    (cfg_dir / "cli.credential").unlink()
    (cfg_dir / "tls" / "ca.pem").unlink()
    try:
        with acquire_writer_unbumped(root, os_):
            assert not os.path.lexists(root.endpoint_path)
            for flag, path in (("--config", daemon_cfg), ("--profile", cli_profile)):
                r_held = run_installed_command(
                    inc2_installed_env, "brain", ["doctor", "--fix", flag, str(path), "--json"], cwd=cwd
                )
                _assert_cli_error(
                    r_held.returncode,
                    r_held.stdout,
                    r_held.stderr,
                    expected_rc=1,
                    expected_code=ErrorCode.DAEMON_UNAVAILABLE.value,
                    as_json=True,
                    label=("lock-held-no-cred", flag),
                )
                r_held_off = run_installed_command(
                    inc2_installed_env, "brain", ["doctor", "--offline", "--fix", flag, str(path), "--json"], cwd=cwd
                )
                _assert_cli_error(
                    r_held_off.returncode,
                    r_held_off.stdout,
                    r_held_off.stderr,
                    expected_rc=1,
                    expected_code=ErrorCode.DAEMON_UNAVAILABLE.value,
                    as_json=True,
                    label=("lock-held-offline", flag),
                )
    finally:
        write_owner_only_bytes(cfg_dir / "cli.credential", cred_backup)
        write_owner_only_bytes(cfg_dir / "tls" / "ca.pem", ca_backup)

    # 4) Stale/dead endpoint.json -> daemon_unavailable, never offline fallback.
    stale_ep = Endpoint(
        version=1,
        host="127.0.0.1",
        port=_unused_loopback_port(),
        store_id=store_id,
        writer_epoch=1,
        instance_id=new_id(),
    )
    write_owner_only_bytes(root.endpoint_path, stale_ep.encode_canonical())
    r_stale = run_installed_command(
        inc2_installed_env, "brain", ["doctor", "--fix", "--profile", str(cli_profile), "--json"], cwd=cwd
    )
    _assert_cli_error(
        r_stale.returncode,
        r_stale.stdout,
        r_stale.stderr,
        expected_rc=1,
        expected_code=ErrorCode.DAEMON_UNAVAILABLE.value,
        as_json=True,
        label="stale-ep-fix",
    )
    root.endpoint_path.unlink()

    # 5) Live daemon: `--offline --fix` fails store_busy; wrong pin/revoked/harness/mismatch checkout fail closed.
    with spawn_installed_brain_serve(inc2_installed_env, daemon_cfg, data_root=data_root, cwd=cwd) as srv_proc:
        ep = srv_proc.wait_ready()
        assert ep.store_id == store_id

        for flag, path in (("--config", daemon_cfg), ("--profile", cli_profile)):
            r_live_off = run_installed_command(
                inc2_installed_env, "brain", ["doctor", "--offline", "--fix", flag, str(path), "--json"], cwd=cwd
            )
            _assert_cli_error(
                r_live_off.returncode,
                r_live_off.stdout,
                r_live_off.stderr,
                expected_rc=1,
                expected_code=ErrorCode.DAEMON_UNAVAILABLE.value,
                as_json=True,
                label=("live-offline-fix", flag),
            )

        for args, expected_code in (
            (["doctor", "--fix", "--profile", str(bad_pin_profile), "--json"], ErrorCode.IDENTITY_MISMATCH.value),
            (["doctor", "--fix", "--profile", str(revoked_profile), "--json"], ErrorCode.UNAUTHENTICATED.value),
            (["doctor", "--fix", "--profile", str(unknown_profile), "--json"], ErrorCode.UNAUTHENTICATED.value),
            (["doctor", "--fix", "--profile", str(claude_profile), "--json"], ErrorCode.IDENTITY_MISMATCH.value),
            (
                ["doctor", "--fix", "--profile", str(cli_ws_profile), "--checkout", str(co_b), "--json"],
                ErrorCode.IDENTITY_MISMATCH.value,
            ),
        ):
            r_live_err = run_installed_command(inc2_installed_env, "brain", args, cwd=cwd)
            _assert_cli_error(
                r_live_err.returncode,
                r_live_err.stdout,
                r_live_err.stderr,
                expected_rc=1,
                expected_code=expected_code,
                as_json=True,
                label=("live-fix-auth", args),
            )

        # Direct RPC auth matrix on /v2/operator/doctor/fix.
        for tok, code in (
            (cred_claude.token, ErrorCode.IDENTITY_MISMATCH.value),
            (cred_cli_revoked.token, ErrorCode.UNAUTHENTICATED.value),
            ("unknown-id.unknown-secret", ErrorCode.UNAUTHENTICATED.value),
        ):
            rpc_err = _call_operator_json(
                ep,
                store_id=store_id,
                ca_pem=ca_pem,
                leaf_sha256=server_sha,
                token=tok,
                path="/v2/operator/doctor/fix",
                body={},
                monotonic_ns=os_.monotonic.monotonic_ns,
            )
            _assert_error_envelope(rpc_err, code)

        # Live positive control via --config & --profile.
        r_live_ok = run_installed_command(
            inc2_installed_env, "brain", ["doctor", "--fix", "--profile", str(cli_profile), "--json"], cwd=cwd
        )
        _assert_completed_fix_json(r_live_ok.stdout, r_live_ok.stderr, r_live_ok.returncode, expected_store_id=store_id)

        rc_srv, _, _, _ = srv_proc.signal_and_wait_exit()
        assert rc_srv == 0


@pytest.mark.parametrize(
    ("bumped_db", "min_reader"),
    (
        ("store", 99),
        ("store", 5),
        ("policy", 99),
        ("policy", 4),
    ),
)
def test_doctor_fix_offline_rejects_schema_99_before_any_mutation_or_epoch_bump(
    inc2_installed_env: InstalledEnv,
    trusted_tmp: Path,
    bumped_db: str,
    min_reader: int,
) -> None:
    """Offline --fix on schema_version=99 (store or policy) fails unsupported_version with 0 mutations/epoch bump."""
    os_ = os_adapters()
    cwd = trusted_tmp / "outside"
    cwd.mkdir()
    os_.permissions.secure_directory(cwd)

    data_root, cfg_dir, daemon_cfg, store_id, _ca, server_sha, _tok = _init_via_installed_wheel(
        inc2_installed_env, trusted_tmp / f"schema99-{bumped_db}-{min_reader}", cwd=cwd
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

    # Seed oversized + wide-permission log BEFORE setting schema_version=99 to verify no pre-check tightening/rotation.
    root.logs_dir.mkdir(parents=True, exist_ok=True)
    os_.permissions.secure_directory(root.logs_dir)
    oversized_log = root.logs_dir / "brain.log"
    oversized_log.write_bytes(b"SCHEMA99-LOG\n" + (b"X" * (MAX_LOG_BYTES + 1024)))
    _grant_wide_access(oversized_log)
    log_acl_before = _acl_or_mode(oversized_log)

    db_path = root.store_db if bumped_db == "store" else root.policy_db
    conn = sqlite3.connect(db_path)
    try:
        if min_reader == 99 and bumped_db == "store":
            conn.execute("DROP TABLE ledger")
        conn.execute("UPDATE meta SET value = '99' WHERE key = 'schema_version'")
        conn.execute("UPDATE meta SET value = ? WHERE key = 'min_reader_version'", (str(min_reader),))
        conn.commit()
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        conn.close()
    os_.permissions.secure_file(db_path)

    snap_before = digest_tree(data_root)
    epoch_before = lock_epoch(data_root)

    res_cfg = run_installed_command(
        inc2_installed_env, "brain", ["doctor", "--offline", "--fix", "--config", str(daemon_cfg), "--json"], cwd=cwd
    )
    _assert_cli_error(
        res_cfg.returncode,
        res_cfg.stdout,
        res_cfg.stderr,
        expected_rc=1,
        expected_code=ErrorCode.DAEMON_UNAVAILABLE.value,
        as_json=True,
        label=("schema99-config", bumped_db, min_reader),
    )
    if bumped_db == "store" or min_reader < 99:
        res_prof = run_installed_command(
            inc2_installed_env,
            "brain",
            ["doctor", "--offline", "--fix", "--profile", str(cli_profile), "--json"],
            cwd=cwd,
        )
        _assert_cli_error(
            res_prof.returncode,
            res_prof.stdout,
            res_prof.stderr,
            expected_rc=1,
            expected_code=ErrorCode.DAEMON_UNAVAILABLE.value,
            as_json=True,
            label=("schema99-profile", bumped_db, min_reader),
        )

    assert digest_tree(data_root) == snap_before
    assert lock_epoch(data_root) == epoch_before
    assert _acl_or_mode(oversized_log) == log_acl_before
    assert not (root.logs_dir / "brain.log.1").exists()


# ---------------------------------------------------------------------------
# 3. tighten_permissions (§20.28, Offline & Live Online, Ancestors, Symlink/Junction)
# ---------------------------------------------------------------------------


def test_doctor_fix_tighten_permissions_offline_online_ancestors_and_links(
    inc2_installed_env: InstalledEnv,
    trusted_tmp: Path,
) -> None:
    """§20.28: offline + online permission repair inside data_root(+backups), ancestors untouched, links rejected."""
    os_ = os_adapters()
    cwd = trusted_tmp / "outside"
    cwd.mkdir()
    os_.permissions.secure_directory(cwd)

    parent_dir = trusted_tmp / "owner-parent"
    parent_dir.mkdir()
    os_.permissions.secure_directory(parent_dir)
    parent_acl_before = _acl_or_mode(parent_dir)

    data_root, _cfg_dir, daemon_cfg, store_id, _ca, _sha, _tok = _init_via_installed_wheel(
        inc2_installed_env, parent_dir / "root", cwd=cwd
    )
    root = DataRoot.at(data_root)

    # Create real backup + log file, then relax permissions on logs/brain.log, store/brain.db, backups/.
    rt = reopen_kernel_job_runtime(data_root, store_id, os_)
    try:
        bak_dir = create_store_backup(rt.store, os_, _base_utc_now())
    finally:
        rt.close()
    root.logs_dir.mkdir(parents=True, exist_ok=True)
    os_.permissions.secure_directory(root.logs_dir)
    log_file = root.logs_dir / "brain.log"
    write_owner_only_bytes(log_file, b"perm-test-log\n")

    _grant_wide_access(log_file)
    _grant_wide_access(root.store_db)
    _grant_wide_access(root.backups_dir)
    _grant_wide_access(bak_dir / "manifest.json")

    pre_off = run_installed_command(
        inc2_installed_env, "brain", ["doctor", "--offline", "--config", str(daemon_cfg), "--json"], cwd=cwd
    )
    assert pre_off.returncode == 0
    pre_data = cast(dict[str, Any], json.loads(pre_off.stdout.decode("utf-8"))["data"])
    assert _check_by(pre_data, "permissions", "tree")["status"] == "FAIL"

    # Offline --offline --fix is strictly read-only per §13; fails closed with daemon_unavailable and preserves ACLs.
    fix_off = run_installed_command(
        inc2_installed_env,
        "brain",
        ["doctor", "--offline", "--fix", "--config", str(daemon_cfg), "--json"],
        cwd=cwd,
    )
    _assert_cli_error(
        fix_off.returncode,
        fix_off.stdout,
        fix_off.stderr,
        expected_rc=1,
        expected_code=ErrorCode.DAEMON_UNAVAILABLE.value,
        as_json=True,
        label="offline-fix-strictly-read-only",
    )
    assert len(os_.permissions.problems(data_root)) > 0
    assert _acl_or_mode(parent_dir) == parent_acl_before

    # Secure data_root before starting daemon so daemon preflight passes:
    tighten_data_root_permissions((root.root, root.backups_dir), os_)

    # Live online `--fix`: start daemon, relax permissions again, repair live.
    with spawn_installed_brain_serve(inc2_installed_env, daemon_cfg, data_root=data_root, cwd=cwd) as srv_proc:
        srv_proc.wait_ready()
        _grant_wide_access(log_file)
        _grant_wide_access(root.store_db)
        _grant_wide_access(root.backups_dir)

        pre_on = run_installed_command(
            inc2_installed_env, "brain", ["doctor", "--config", str(daemon_cfg), "--json"], cwd=cwd
        )
        pre_on_data = cast(dict[str, Any], json.loads(pre_on.stdout.decode("utf-8"))["data"])
        assert _check_by(pre_on_data, "permissions", "tree")["status"] == "FAIL"

        fix_on = run_installed_command(
            inc2_installed_env, "brain", ["doctor", "--fix", "--config", str(daemon_cfg), "--json"], cwd=cwd
        )
        fix_on_data, fix_on_actions = _assert_completed_fix_json(
            fix_on.stdout, fix_on.stderr, fix_on.returncode, expected_store_id=store_id
        )
        assert fix_on_actions["tighten_permissions"]["status"] == "applied", fix_on_actions
        assert _check_by(fix_on_data, "permissions", "tree")["status"] == "PASS"
        assert fix_on_data["permission_problems"] == []
        assert _acl_or_mode(parent_dir) == parent_acl_before

        # Planted symlink/junction while online MUST fail unsafe_path and leave outside target untouched.
        outside_target = trusted_tmp / "outside-target"
        outside_target.mkdir()
        outside_file = outside_target / "secret.txt"
        outside_file.write_bytes(b"external-secret\n")
        _grant_wide_access(outside_target)
        _grant_wide_access(outside_file)
        outside_dir_acl = _acl_or_mode(outside_target)
        outside_file_acl = _acl_or_mode(outside_file)

        planted_link = root.logs_dir / "evil-link"
        _make_dir_link(planted_link, outside_target)

        r_link_online = run_installed_command(
            inc2_installed_env, "brain", ["doctor", "--fix", "--config", str(daemon_cfg), "--json"], cwd=cwd
        )
        _assert_cli_error(
            r_link_online.returncode,
            r_link_online.stdout,
            r_link_online.stderr,
            expected_rc=1,
            expected_code=ErrorCode.UNSAFE_PATH.value,
            as_json=True,
            label="online-fix-planted-link",
        )
        assert _acl_or_mode(outside_target) == outside_dir_acl
        assert _acl_or_mode(outside_file) == outside_file_acl

        rc_srv, _, _, _ = srv_proc.signal_and_wait_exit()
        assert rc_srv == 0

    # Offline `--offline --fix` with planted symlink/junction MUST also reject unsafe_path without following.
    outside_dir_acl = _acl_or_mode(outside_target)
    outside_file_acl = _acl_or_mode(outside_file)
    epoch_before = lock_epoch(data_root)
    r_link_offline = run_installed_command(
        inc2_installed_env,
        "brain",
        ["doctor", "--offline", "--fix", "--config", str(daemon_cfg), "--json"],
        cwd=cwd,
    )
    _assert_cli_error(
        r_link_offline.returncode,
        r_link_offline.stdout,
        r_link_offline.stderr,
        expected_rc=1,
        expected_code=ErrorCode.DAEMON_UNAVAILABLE.value,
        as_json=True,
        label="offline-fix-planted-link",
    )
    assert _acl_or_mode(outside_target) == outside_dir_acl
    assert _acl_or_mode(outside_file) == outside_file_acl
    assert lock_epoch(data_root) == epoch_before


# ---------------------------------------------------------------------------
# 4. reconcile_policy (Offline & Online)
# ---------------------------------------------------------------------------


def test_doctor_fix_reconcile_policy_offline_and_online(
    inc2_installed_env: InstalledEnv,
    trusted_tmp: Path,
) -> None:
    """Seeded unapplied TOMBSTONE/QUARANTINE intents become WARN -> --fix applies -> enforced & PASS."""
    os_ = os_adapters()
    cwd = trusted_tmp / "outside"
    cwd.mkdir()
    os_.permissions.secure_directory(cwd)

    # --- Offline ---
    data_root, _cfg_dir, daemon_cfg, store_id, _ca, _sha, _tok = _init_via_installed_wheel(
        inc2_installed_env, trusted_tmp / "reconcile-off", cwd=cwd
    )
    holder_off = new_id()
    rt = reopen_kernel_job_runtime(data_root, store_id, os_)
    try:
        _dig_tomb = rt.store.store_content(b"tombstone-target-off", "event", holder_off, RetentionClass.DURABLE, None)
        dig_quar = rt.store.store_content(b"quarantine-target-off", "event", new_id(), RetentionClass.DURABLE, None)
        intent_tomb = rt.policy.record_intent(IntentKind.TOMBSTONE, {"holder_kind": "event", "holder_id": holder_off})
        intent_quar = rt.policy.record_intent(IntentKind.QUARANTINE, {"digest": dig_quar})
    finally:
        rt.close()

    pre_off = run_installed_command(
        inc2_installed_env, "brain", ["doctor", "--offline", "--config", str(daemon_cfg), "--json"], cwd=cwd
    )
    pre_data = cast(dict[str, Any], json.loads(pre_off.stdout.decode("utf-8"))["data"])
    assert _check_by(pre_data, "storage", "policy_reconcile")["status"] == "WARN"

    fix_off = run_installed_command(
        inc2_installed_env, "brain", ["doctor", "--offline", "--fix", "--config", str(daemon_cfg), "--json"], cwd=cwd
    )
    _assert_cli_error(
        fix_off.returncode,
        fix_off.stdout,
        fix_off.stderr,
        expected_rc=1,
        expected_code=ErrorCode.DAEMON_UNAVAILABLE.value,
        as_json=True,
        label="offline-fix-reconcile-policy",
    )

    scratch = trusted_tmp / "ro-scratch"
    scratch.mkdir()
    with contextlib.closing(open_readonly(DataRoot.at(data_root).store_db, scratch_dir=scratch)) as ro_store:
        applied = {str(r[0]) for r in ro_store.execute("SELECT intent_id FROM applied_intents").fetchall()}
    assert {intent_tomb.intent_id, intent_quar.intent_id}.isdisjoint(applied)

    # --- Online ---
    clock = FakeClock(_base_utc_now())
    real_mono = os_adapters().monotonic
    base_os = os_adapters(clock=clock, monotonic=real_mono)
    rep, cfg, _priv, ca_pem, leaf_sha256, cli_token, live_os = _init_store_with_tls(
        trusted_tmp / "reconcile-on", clock, os_=base_os
    )
    live_rt_box: list[Runtime] = []
    hooks = DaemonTestHooks(before_job_recover=lambda rt_arg: live_rt_box.append(rt_arg))

    with _running_serve(cfg, os_=live_os, clock=clock, mono=real_mono, hooks=hooks) as (ready, loop):
        assert loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        live_rt = live_rt_box[0]
        holder_on = new_id()

        def _seed_unapplied_online() -> tuple[str, str]:
            d = live_rt.store.store_content(b"tombstone-target-on", "event", holder_on, RetentionClass.DURABLE, None)
            i = live_rt.policy.record_intent(IntentKind.TOMBSTONE, {"holder_kind": "event", "holder_id": holder_on})
            return d, i.intent_id

        dig_on, intent_on_id = loop.run_owner_action(_seed_unapplied_online).result(timeout=BOUND_WAIT_S)

        clock.advance(timedelta(minutes=16))
        pre_on_env = _call_operator_json(
            ready.endpoint,
            store_id=rep.store_id,
            ca_pem=ca_pem,
            leaf_sha256=leaf_sha256,
            token=cli_token,
            path="/v2/operator/doctor/report",
            body={"wait_timeout_ms": 5000},
            monotonic_ns=real_mono.monotonic_ns,
        )
        assert pre_on_env.get("ok") is True, pre_on_env
        assert _check_by(cast(dict[str, Any], pre_on_env["data"]), "storage", "policy_reconcile")["status"] == "WARN"

        fix_on_env = _call_operator_json(
            ready.endpoint,
            store_id=rep.store_id,
            ca_pem=ca_pem,
            leaf_sha256=leaf_sha256,
            token=cli_token,
            path="/v2/operator/doctor/fix",
            body={},
            monotonic_ns=real_mono.monotonic_ns,
        )
        assert fix_on_env.get("ok") is True, fix_on_env
        fix_on_data = cast(dict[str, Any], fix_on_env["data"])
        fix_on_actions = {a["action"]: a for a in cast(list[dict[str, Any]], fix_on_data["fix"]["actions"])}
        assert fix_on_actions["reconcile_policy"]["status"] == "applied", fix_on_actions
        assert _check_by(fix_on_data, "storage", "policy_reconcile")["status"] == "PASS"

        def _verify_enforced() -> bool:
            with live_rt.store.transaction() as txn:
                rows = txn.db.execute("SELECT 1 FROM applied_intents WHERE intent_id = ?", (intent_on_id,)).fetchall()
                held = active_held_digests(txn.db, "event", holder_on, now=clock.now())
            try:
                live_rt.store.cas.read_held(dig_on, holder_kind="event", holder_id=holder_on, now=clock.now())
                return False
            except BrainError as err:
                return len(rows) == 1 and held == [] and err.code is ErrorCode.NOT_FOUND

        assert loop.run_owner_action(_verify_enforced).result(timeout=BOUND_WAIT_S) is True


# ---------------------------------------------------------------------------
# 5. rebuild_projections & rotate_logs Crash Matrix + Online Rebuild
# ---------------------------------------------------------------------------


def test_i4_4_crashpoints_registered_in_known_crashpoints() -> None:
    assert I4_4_CRASHPOINTS <= KNOWN_CRASHPOINTS


@pytest.mark.parametrize("case", I4_4_CRASH_CASES, ids=lambda c: c.node_id)
def test_doctor_fix_crash_matrix(
    inc2_installed_env: InstalledEnv,
    trusted_tmp: Path,
    case: I44CrashCase,
) -> None:
    """Crash recovery matrix for ``doctor.fix.before_projection_swap`` and ``doctor.fix.after_log_rotate_stage``."""
    cwd = trusted_tmp / "outside-cwd"
    cwd.mkdir()
    os_adapters().permissions.secure_directory(cwd)
    ctx = KernelCrashContext(
        env=inc2_installed_env,
        template=get_shared_t7_transport_template(),
        case_dir=trusted_tmp,
        cwd=cwd,
    )
    run_i44_crash_case(ctx, case)


def test_doctor_fix_positive_control_and_omission_detection(
    inc2_installed_env: InstalledEnv,
    trusted_tmp: Path,
) -> None:
    """Positive control succeeds without fault env, and SUPERBRAIN_DISABLE_CRASHPOINTS_FOR_TEST detects omissions."""
    os_ = os_adapters()
    for cp in sorted(I4_4_CRASHPOINTS):
        case_dir = trusted_tmp / f"omit-{cp.replace('.', '_')}"
        cwd = case_dir / "outside-cwd"
        case_dir.mkdir(parents=True)
        cwd.mkdir()
        os_.permissions.secure_directory(cwd)
        ctx = KernelCrashContext(
            env=inc2_installed_env,
            template=get_shared_t7_transport_template(),
            case_dir=case_dir,
            cwd=cwd,
        )
        seed = prepare_i44_seed(ctx, crashpoint=cp)

        # Positive control (no crashpoint armed) on projection case:
        if cp == "doctor.fix.before_projection_swap":
            pos_run = run_i44_child(ctx.env, "doctor-fix-offline", seed.config_path, seed.payload_path, cwd=cwd)
            assert_entered(pos_run)
            assert_wheel_provenance(pos_run, ctx)
            assert pos_run.result.returncode == 0 and pos_run.result.hit is None, pos_run.describe()
            # Re-tamper for omission detection test:
            conn = sqlite3.connect(DataRoot.at(seed.data_root).store_db)
            try:
                conn.execute("DELETE FROM p_cas_holders_ WHERE holder_id = ?", (seed.holder_id,))
                conn.commit()
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            finally:
                conn.close()
            os_.permissions.secure_file(DataRoot.at(seed.data_root).store_db)

        env = clean_installed_subprocess_env(
            {"SUPERBRAIN_CRASHPOINT": cp, "SUPERBRAIN_DISABLE_CRASHPOINTS_FOR_TEST": cp}
        )
        res = subprocess.run(
            [
                str(ctx.env.venv_python),
                "-I",
                str(I44_CHILD),
                "doctor-fix-offline",
                str(seed.config_path),
                str(seed.payload_path),
            ],
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=45.0,
        )
        assert res.returncode == 0 and "CRASHPOINT_HIT" not in res.stderr, (cp, res.returncode, res.stderr)


def test_doctor_fix_rebuild_projections_online(
    inc2_installed_env: InstalledEnv,
    trusted_tmp: Path,
) -> None:
    """Live online ``brain doctor --fix`` rebuilds tampered projections and passes recheck."""
    os_ = os_adapters()
    cwd = trusted_tmp / "outside"
    cwd.mkdir()
    os_.permissions.secure_directory(cwd)

    data_root, _cfg_dir, daemon_cfg, store_id, _ca, _sha, _tok = _init_via_installed_wheel(
        inc2_installed_env, trusted_tmp / "proj-online", cwd=cwd
    )
    holder_id = new_id()
    rt = reopen_kernel_job_runtime(data_root, store_id, os_)
    try:
        rt.store.store_content(b"online-rebuild-payload", "event", holder_id, RetentionClass.DURABLE, None)
    finally:
        rt.close()

    store_db = DataRoot.at(data_root).store_db
    conn = sqlite3.connect(store_db)
    try:
        cur = conn.execute("DELETE FROM p_cas_holders_ WHERE holder_id = ?", (holder_id,))
        assert cur.rowcount == 1
        conn.commit()
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        conn.close()
    os_.permissions.secure_file(store_db)

    with spawn_installed_brain_serve(inc2_installed_env, daemon_cfg, data_root=data_root, cwd=cwd) as srv_proc:
        srv_proc.wait_ready()
        pre = run_installed_command(
            inc2_installed_env, "brain", ["doctor", "--config", str(daemon_cfg), "--json"], cwd=cwd
        )
        pre_data = cast(dict[str, Any], json.loads(pre.stdout.decode("utf-8"))["data"])
        assert _check_by(pre_data, "storage", "ledger_projection_match")["status"] == "FAIL"

        fix_res = run_installed_command(
            inc2_installed_env, "brain", ["doctor", "--fix", "--config", str(daemon_cfg), "--json"], cwd=cwd
        )
        fix_data, fix_actions = _assert_completed_fix_json(
            fix_res.stdout, fix_res.stderr, fix_res.returncode, expected_store_id=store_id
        )
        assert fix_actions["rebuild_projections"]["status"] == "applied", fix_actions
        assert _check_by(fix_data, "storage", "ledger_projection_match")["status"] == "PASS"

        rc_srv, _, _, _ = srv_proc.signal_and_wait_exit()
        assert rc_srv == 0


# ---------------------------------------------------------------------------
# 6. rotate_logs FILESYSTEM_BUSY & Clean Online Rotation When Unblocked
# ---------------------------------------------------------------------------


def test_doctor_fix_rotate_logs_filesystem_busy_and_online_unblocked(
    inc2_installed_env: InstalledEnv,
    trusted_tmp: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Locked active log returns FILESYSTEM_BUSY without data loss; unblocked online --fix rotates cleanly."""
    oversized_bytes = b"HDR-BUSY-LOG\n" + (b"B" * (MAX_LOG_BYTES + 2048)) + b"\nEND-BUSY-LOG\n"

    if sys.platform == "win32":
        os_ = os_adapters()
        cwd = trusted_tmp / "outside"
        cwd.mkdir()
        os_.permissions.secure_directory(cwd)
        data_root, _cfg_dir, daemon_cfg, store_id, _ca, _sha, _tok = _init_via_installed_wheel(
            inc2_installed_env, trusted_tmp / "rot-busy-win", cwd=cwd
        )
        logs_dir = DataRoot.at(data_root).logs_dir
        logs_dir.mkdir(parents=True, exist_ok=True)
        os_.permissions.secure_directory(logs_dir)
        log_file = logs_dir / "brain.log"
        write_owner_only_bytes(log_file, oversized_bytes)

        with spawn_installed_brain_serve(inc2_installed_env, daemon_cfg, data_root=data_root, cwd=cwd) as srv_proc:
            srv_proc.wait_ready()
            # Open without FILE_SHARE_DELETE on Windows to trigger real ERROR_SHARING_VIOLATION -> FILESYSTEM_BUSY.
            with open(log_file, "ab"):
                busy_res = run_installed_command(
                    inc2_installed_env, "brain", ["doctor", "--fix", "--config", str(daemon_cfg), "--json"], cwd=cwd
                )
            if busy_res.returncode == 1:
                _assert_cli_error(
                    busy_res.returncode,
                    busy_res.stdout,
                    busy_res.stderr,
                    expected_rc=1,
                    expected_code=ErrorCode.FILESYSTEM_BUSY.value,
                    as_json=True,
                    label="win32-log-busy",
                )
            else:
                _, busy_actions = _assert_completed_fix_json(
                    busy_res.stdout, busy_res.stderr, busy_res.returncode, expected_store_id=store_id
                )
                rot = busy_actions["rotate_logs"]
                assert rot["status"] == "failed", rot
                norm = json.dumps(rot).lower().replace(" ", "_")
                assert ErrorCode.FILESYSTEM_BUSY.value in norm, rot

            # Zero bytes lost while blocked.
            assert log_file.read_bytes() == oversized_bytes
            assert not (logs_dir / "brain.log.1").exists()

            # Unblocked: online rotation succeeds cleanly.
            ok_res = run_installed_command(
                inc2_installed_env, "brain", ["doctor", "--fix", "--config", str(daemon_cfg), "--json"], cwd=cwd
            )
            _, ok_actions = _assert_completed_fix_json(
                ok_res.stdout, ok_res.stderr, ok_res.returncode, expected_store_id=store_id
            )
            assert ok_actions["rotate_logs"]["status"] == "applied", ok_actions
            assert (logs_dir / "brain.log.1").read_bytes() == oversized_bytes
            assert not log_file.exists() or log_file.stat().st_size == 0

            rc_srv, _, _, _ = srv_proc.signal_and_wait_exit()
            assert rc_srv == 0
        return

    # POSIX branch: simulate sharing lock on brain.log through publisher, then unblock.
    clock = FakeClock(_base_utc_now())
    real_mono = os_adapters().monotonic
    base_os = os_adapters(clock=clock, monotonic=real_mono)
    rep, cfg, _priv, ca_pem, leaf_sha256, cli_token, os_ = _init_store_with_tls(
        trusted_tmp / "rot-busy-posix", clock, os_=base_os
    )
    logs_dir = DataRoot.at(cfg.data_root).logs_dir
    logs_dir.mkdir(parents=True, exist_ok=True)
    os_.permissions.secure_directory(logs_dir)
    log_file = logs_dir / "brain.log"
    write_owner_only_bytes(log_file, oversized_bytes)

    orig_publish = os_.publisher.publish
    locked_flag = [True]

    def _busy_publish(staging: Path, final: Path) -> None:
        if locked_flag[0] and staging.name.startswith(("brain.log", ".brain.log.rotating-")):
            raise BrainError(ErrorCode.FILESYSTEM_BUSY, "active log handle held")
        orig_publish(staging, final)

    monkeypatch.setattr(os_.publisher, "publish", _busy_publish)
    with _running_serve(cfg, os_=os_, clock=clock, mono=real_mono) as (ready, loop):
        assert loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        busy_env = _call_operator_json(
            ready.endpoint,
            store_id=rep.store_id,
            ca_pem=ca_pem,
            leaf_sha256=leaf_sha256,
            token=cli_token,
            path="/v2/operator/doctor/fix",
            body={},
            monotonic_ns=real_mono.monotonic_ns,
        )
        if busy_env.get("ok") is False:
            _assert_error_envelope(busy_env, ErrorCode.FILESYSTEM_BUSY.value)
        else:
            busy_actions = {
                a["action"]: a for a in cast(list[dict[str, Any]], busy_env["data"]["fix"]["actions"])
            }
            rot = busy_actions["rotate_logs"]
            assert rot["status"] == "failed", rot
            assert ErrorCode.FILESYSTEM_BUSY.value in json.dumps(rot).lower().replace(" ", "_"), rot
        assert log_file.read_bytes() == oversized_bytes

        locked_flag[0] = False
        ok_env = _call_operator_json(
            ready.endpoint,
            store_id=rep.store_id,
            ca_pem=ca_pem,
            leaf_sha256=leaf_sha256,
            token=cli_token,
            path="/v2/operator/doctor/fix",
            body={},
            monotonic_ns=real_mono.monotonic_ns,
        )
        assert ok_env.get("ok") is True, ok_env
        ok_actions = {a["action"]: a for a in cast(list[dict[str, Any]], ok_env["data"]["fix"]["actions"])}
        assert ok_actions["rotate_logs"]["status"] == "applied", ok_actions
        assert (logs_dir / "brain.log.1").read_bytes() == oversized_bytes


# ---------------------------------------------------------------------------
# 7. OutboxReplayPort / SupervisorControlPort Delegation & Action Allowlist
# ---------------------------------------------------------------------------


class _StubOutboxReplay(OutboxReplayPort):
    def __init__(self, result: OutboxReplayResult) -> None:
        self._result = result
        self.calls: list[datetime] = []

    def replay_outbox(self, *, now: datetime) -> OutboxReplayResult:
        self.calls.append(now)
        return self._result


class _StubSupervisorControl(SupervisorControlPort):
    def __init__(self, result: SupervisorRestartResult) -> None:
        self._result = result
        self.calls: list[Path] = []

    def restart_daemon(self, config_path: Path) -> SupervisorRestartResult:
        self.calls.append(config_path)
        return self._result


def test_doctor_fix_port_delegation_capability_unavailable_and_allowlist(
    trusted_tmp: Path,
) -> None:
    """Unattached returns capability_unavailable; attached ports delegate; non-allowlisted fail invalid_input."""
    assert "/v2/operator/doctor/fix" in OPERATOR_PATHS

    clock = FakeClock(_base_utc_now())
    real_mono = os_adapters().monotonic
    base_os = os_adapters(clock=clock, monotonic=real_mono)
    rep, cfg, _priv, ca_pem, leaf_sha256, cli_token, os_ = _init_store_with_tls(
        trusted_tmp / "ports", clock, os_=base_os
    )

    # 1) Unattached SP1 default -> capability_unavailable + non-allowlisted action rejection.
    with _running_serve(cfg, os_=os_, clock=clock, mono=real_mono) as (ready, loop):
        assert loop.wait_doctor_settled(timeout=BOUND_WAIT_S)

        default_env = _call_operator_json(
            ready.endpoint,
            store_id=rep.store_id,
            ca_pem=ca_pem,
            leaf_sha256=leaf_sha256,
            token=cli_token,
            path="/v2/operator/doctor/fix",
            body={},
            monotonic_ns=real_mono.monotonic_ns,
        )
        assert default_env.get("ok") is True, default_env
        default_actions = {a["action"]: a for a in cast(list[dict[str, Any]], default_env["data"]["fix"]["actions"])}
        assert default_actions["replay_outbox"]["status"] == "capability_unavailable"
        assert default_actions["restart_daemon"]["status"] == "capability_unavailable"

        bad_bodies: tuple[dict[str, object], ...] = (
            {"actions": ["delete_data"]},
            {"actions": ["edit_harness"]},
            {"actions": ["resolve_journal"]},
            {"actions": ["restore"]},
            {"actions": ["unknown_action"]},
            {"actions": []},
            {"actions": [123]},
            {"actions": "tighten_permissions"},
            {"unknown_field": True},
        )
        for bad_body in bad_bodies:
            bad_env = _call_operator_json(
                ready.endpoint,
                store_id=rep.store_id,
                ca_pem=ca_pem,
                leaf_sha256=leaf_sha256,
                token=cli_token,
                path="/v2/operator/doctor/fix",
                body=bad_body,
                monotonic_ns=real_mono.monotonic_ns,
            )
            _assert_error_envelope(bad_env, ErrorCode.INVALID_INPUT.value)

    # 2) Attached OutboxReplayPort & SupervisorControlPort via serve_config_path -> delegates cleanly.
    stub_outbox = _StubOutboxReplay(
        OutboxReplayResult(
            status="applied",
            replayed_events=3,
            committed_event_sequences=(10, 11, 12),
            contiguous_event_acked_through=12,
            acked_producer_gap_sequences=(),
            pending_remaining=0,
            detail="replayed 3 outbox events",
        )
    )
    stub_sup = _StubSupervisorControl(
        SupervisorRestartResult(status="applied", restarted=True, pid=43210, detail="daemon restarted")
    )

    ready_ev = threading.Event()
    stop_ev = threading.Event()
    box: dict[str, Any] = {}
    exits: list[int] = []

    def _on_ready(rdy: Ready, lp: OwnerLoop) -> None:
        box["ready"] = rdy
        box["loop"] = lp
        ready_ev.set()

    def _run_srv() -> None:
        exits.append(
            cast(Any, daemon_entry.serve_config_path)(
                rep.daemon_config_path,
                os_=os_,
                clock=clock,
                monotonic_clock=real_mono,
                stop_event=stop_ev,
                shutdown_grace_s=2.0,
                on_ready=_on_ready,
                outbox_replay=stub_outbox,
                supervisor_control=stub_sup,
            )
        )

    thr = threading.Thread(target=_run_srv, name="i4-4-serve-ports", daemon=True)
    thr.start()
    try:
        assert ready_ev.wait(timeout=BOUND_WAIT_S), f"serve_config_path failed to start: {exits}"
        rdy = cast(Ready, box["ready"])
        lp = cast(OwnerLoop, box["loop"])
        assert lp.wait_doctor_settled(timeout=BOUND_WAIT_S)

        deleg_env = _call_operator_json(
            rdy.endpoint,
            store_id=rep.store_id,
            ca_pem=ca_pem,
            leaf_sha256=leaf_sha256,
            token=cli_token,
            path="/v2/operator/doctor/fix",
            body={"actions": ["replay_outbox", "restart_daemon"]},
            monotonic_ns=real_mono.monotonic_ns,
        )
        assert deleg_env.get("ok") is True, deleg_env
        deleg_actions = {a["action"]: a for a in cast(list[dict[str, Any]], deleg_env["data"]["fix"]["actions"])}
        assert deleg_actions["replay_outbox"]["status"] == "applied", deleg_actions
        assert deleg_actions["restart_daemon"]["status"] == "applied", deleg_actions
        assert len(stub_outbox.calls) == 1
        assert stub_outbox.calls[0].tzinfo is not None and stub_outbox.calls[0].utcoffset() == timedelta(0)
        assert stub_sup.calls == [rep.daemon_config_path]
    finally:
        stop_ev.set()
        thr.join(timeout=BOUND_WAIT_S)
        assert not thr.is_alive()


# ---------------------------------------------------------------------------
# 8. Non-Destruction Invariants (Journals, Proposals, Drift, Quarantine, Restore)
# ---------------------------------------------------------------------------


def test_doctor_fix_never_destroys_data_harness_journals_or_invokes_restore(
    inc2_installed_env: InstalledEnv,
    trusted_tmp: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """--fix never deletes data, edits harness files, mutates ApplyJournal/grant, or invokes restore."""
    os_ = os_adapters()
    cwd = trusted_tmp / "outside"
    cwd.mkdir()
    os_.permissions.secure_directory(cwd)

    clock = FakeClock(_base_utc_now())
    rep, cfg, _priv, _ca_pem, _sha, _tok, adapters = _init_store_with_tls(
        trusted_tmp / "nondestruct", clock
    )
    data_root = cfg.data_root
    checkout = trusted_tmp / "checkout"
    home = trusted_tmp / "home"
    for d in (checkout, home):
        d.mkdir()
        adapters.permissions.secure_directory(d)

    claude_path = checkout / "CLAUDE.md"
    agents_path = checkout / "AGENTS.md"
    claude_path.write_bytes(b"# Original Claude\n")
    agents_path.write_bytes(b"# User Agents\n")

    rt = reopen_kernel_job_runtime(data_root, rep.store_id, adapters)
    try:
        # 1. Seed normal & quarantined CAS blobs.
        _ = rt.store.store_content(b"keep-durable-blob", "event", new_id(), RetentionClass.DURABLE, None)
        q_dig = rt.store.store_content(b"keep-quarantined-blob", "event", new_id(), RetentionClass.DURABLE, None)
        rt.policy.record_intent(IntentKind.QUARANTINE, {"digest": q_dig})
        rt.store.reconcile_policy()

        svc = ReviewApplyService(
            StoreProposalAdapter(rt.store, adapters),
            PolicyApplyAuthority(rt.policy),
            adapters,
            data_root=data_root,
            home_dir=home,
            config_merger=SharedConfigMergerAdapter(),
        )

        # 2. Applied proposal -> then out-of-band edit to create bootstrap_drifts.
        m1 = merge_markdown_block(
            "# Original Claude\n", slice_id="s1", block_body="Managed\n", expected_slice_digest=None
        )
        p_applied = svc.create_proposal(
            owner_id=OWNER,
            kind="bootstrap",
            reason="applied drift seed",
            resources=(RiskResource("c2"),),
            targets=(
                TargetWriteInput(
                    checkout,
                    "CLAUDE.md",
                    m1.updated_text.encode("utf-8"),
                    ManagedFormat.MARKDOWN,
                    "s1",
                    m1.slice_digest,
                ),
            ),
        )
        n_ap = rt.policy.issue_nonce(
            action=ApprovalAction.APPROVE, subject_id=p_applied.proposal_id, risk_level=p_applied.risk_level
        )
        svc.approve_proposal(
            p_applied.proposal_id,
            approval=ApprovalMessage(
                store_id=rep.store_id,
                owner_id=OWNER,
                trust_generation=rt.policy.trust_generation(),
                action=ApprovalAction.APPROVE,
                subject_id=p_applied.proposal_id,
                subject_revision=p_applied.subject_revision,
                resource_digests=p_applied.resource_digests,
                target_files=p_applied.to_target_files(),
                risk_level=p_applied.risk_level,
                risk_policy_version=RISK_POLICY_VERSION,
                recovery_scope=RecoveryScope.NONE,
                nonce=n_ap.nonce,
                expires_at=n_ap.expires_at,
            ),
            signer_id=rep.signer.signer_id,
            channel=ApprovalChannel.SSH_KEY,
        )
        n_run = rt.policy.issue_nonce(
            action=ApprovalAction.APPLY, subject_id=p_applied.proposal_id, risk_level=p_applied.risk_level
        )
        svc.apply_proposal(
            p_applied.proposal_id,
            approval=ApprovalMessage(
                store_id=rep.store_id,
                owner_id=OWNER,
                trust_generation=rt.policy.trust_generation(),
                action=ApprovalAction.APPLY,
                subject_id=p_applied.proposal_id,
                subject_revision=p_applied.subject_revision,
                resource_digests=p_applied.resource_digests,
                target_files=p_applied.to_target_files(),
                risk_level=p_applied.risk_level,
                risk_policy_version=RISK_POLICY_VERSION,
                recovery_scope=RecoveryScope.CONTINUE_OR_ROLLBACK,
                nonce=n_run.nonce,
                expires_at=n_run.expires_at,
            ),
            signer_id=rep.signer.signer_id,
            channel=ApprovalChannel.SSH_KEY,
        )
        # Create bootstrap drift without touching brain.db.
        claude_path.write_bytes(b"# Drifted By User\n")

        # 3. Pending proposal (status=PENDING).
        m_pend = merge_markdown_block(
            m1.updated_text, slice_id="s2", block_body="Pending\n", expected_slice_digest=None
        )
        _p_pending = svc.create_proposal(
            owner_id=OWNER,
            kind="bootstrap",
            reason="pending seed",
            resources=(RiskResource("c2"),),
            targets=(
                TargetWriteInput(
                    checkout,
                    "CLAUDE.md",
                    m_pend.updated_text.encode("utf-8"),
                    ManagedFormat.MARKDOWN,
                    "s2",
                    m_pend.slice_digest,
                ),
            ),
        )

        # 4. Incomplete APPLYING ApplyJournal with active recovery_grant.
        agents_bytes = b"# Brain Agents\n"
        m_int = merge_markdown_block(
            "# Drifted By User\n", slice_id="s3", block_body="Interrupted\n", expected_slice_digest=None
        )
        p_int = svc.create_proposal(
            owner_id=OWNER,
            kind="bootstrap",
            reason="interrupted journal seed",
            resources=(RiskResource("c2"),),
            targets=(
                TargetWriteInput(
                    checkout,
                    "CLAUDE.md",
                    m_int.updated_text.encode("utf-8"),
                    ManagedFormat.MARKDOWN,
                    "s3",
                    m_int.slice_digest,
                ),
                TargetWriteInput(
                    checkout,
                    "AGENTS.md",
                    agents_bytes,
                    ManagedFormat.RAW,
                    "raw-ag",
                    digest_bytes(agents_bytes),
                ),
            ),
        )
        n_ap2 = rt.policy.issue_nonce(
            action=ApprovalAction.APPROVE, subject_id=p_int.proposal_id, risk_level=p_int.risk_level
        )
        svc.approve_proposal(
            p_int.proposal_id,
            approval=ApprovalMessage(
                store_id=rep.store_id,
                owner_id=OWNER,
                trust_generation=rt.policy.trust_generation(),
                action=ApprovalAction.APPROVE,
                subject_id=p_int.proposal_id,
                subject_revision=p_int.subject_revision,
                resource_digests=p_int.resource_digests,
                target_files=p_int.to_target_files(),
                risk_level=p_int.risk_level,
                risk_policy_version=RISK_POLICY_VERSION,
                recovery_scope=RecoveryScope.NONE,
                nonce=n_ap2.nonce,
                expires_at=n_ap2.expires_at,
            ),
            signer_id=rep.signer.signer_id,
            channel=ApprovalChannel.SSH_KEY,
        )
        n_run2 = rt.policy.issue_nonce(
            action=ApprovalAction.APPLY, subject_id=p_int.proposal_id, risk_level=p_int.risk_level
        )
        pub = cast(NoReplacePublisher, adapters.publisher)
        orig_noreplace = pub.publish_no_replace
        hits = [0]

        def _interrupt_second(staging: Path, final: Path) -> None:
            hits[0] += 1
            if hits[0] == 2:
                raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "interrupted before target 2")
            orig_noreplace(staging, final)

        monkeypatch.setattr(pub, "publish_no_replace", _interrupt_second)
        with pytest.raises(BrainError):
            svc.apply_proposal(
                p_int.proposal_id,
                approval=ApprovalMessage(
                    store_id=rep.store_id,
                    owner_id=OWNER,
                    trust_generation=rt.policy.trust_generation(),
                    action=ApprovalAction.APPLY,
                    subject_id=p_int.proposal_id,
                    subject_revision=p_int.subject_revision,
                    resource_digests=p_int.resource_digests,
                    target_files=p_int.to_target_files(),
                    risk_level=p_int.risk_level,
                    risk_policy_version=RISK_POLICY_VERSION,
                    recovery_scope=RecoveryScope.CONTINUE,
                    nonce=n_run2.nonce,
                    expires_at=n_run2.expires_at,
                ),
                signer_id=rep.signer.signer_id,
                channel=ApprovalChannel.SSH_KEY,
            )
        monkeypatch.undo()
        # Ensure AGENTS.md also drifted so startup journal continuation halts non-destructively in incomplete_journals.
        agents_path.write_bytes(b"# User Agents Drifted\n")
    finally:
        rt.close()

    layout = DataRoot.at(data_root)
    scratch = trusted_tmp / "ro-scratch"
    scratch.mkdir()

    co_snap_before = digest_tree(checkout)
    claude_before = claude_path.read_bytes()
    agents_before = agents_path.read_bytes()
    cas_snap_before = digest_tree(layout.cas_dir)
    i33_store_before = raw_i33_store(data_root, scratch)
    i33_policy_before = raw_i33_policy(data_root, scratch)
    pair_before = pair_rows(data_root, scratch)
    restore_epoch_before = read_restore_epoch(layout, schema_version=5, os_=adapters)

    assert len(i33_store_before["journals"]) == 2
    assert sum(1 for _, _, _, st, _ in i33_store_before["journals"] if st == "partially_applied") == 1
    assert len(i33_policy_before["grants"]) >= 1
    assert any(st == ProposalStatus.PENDING.value for _, st, _ in i33_store_before["proposals"])

    # Spy: restore_store / restore_policy must NEVER be invoked.
    def _forbid_restore(*_args: object, **_kwargs: object) -> Any:
        raise AssertionError("brain doctor --fix must never invoke restore")

    monkeypatch.setattr(storage_restore, "restore_store", _forbid_restore)
    monkeypatch.setattr(storage_restore, "restore_policy", _forbid_restore)

    assert (
        doctor_entry.run_doctor_cli(
            [
                "doctor",
                "--offline",
                "--fix",
                "--config",
                str(rep.daemon_config_path),
                "--checkout",
                str(checkout),
                "--json",
            ],
            os_=adapters,
        )
        == 1
    )

    wheel_fix = run_installed_command(
        inc2_installed_env,
        "brain",
        [
            "doctor",
            "--offline",
            "--fix",
            "--config",
            str(rep.daemon_config_path),
            "--checkout",
            str(checkout),
            "--json",
        ],
        cwd=cwd,
    )
    _assert_cli_error(
        wheel_fix.returncode,
        wheel_fix.stdout,
        wheel_fix.stderr,
        expected_rc=1,
        expected_code=ErrorCode.DAEMON_UNAVAILABLE.value,
        as_json=True,
        label="offline-fix-never-destroys",
    )

    assert digest_tree(checkout) == co_snap_before
    assert claude_path.read_bytes() == claude_before
    assert agents_path.read_bytes() == agents_before
    assert digest_tree(layout.cas_dir) == cas_snap_before
    assert raw_i33_store(data_root, scratch) == i33_store_before
    assert raw_i33_policy(data_root, scratch) == i33_policy_before
    assert pair_rows(data_root, scratch)["quarantine"] == pair_before["quarantine"]
    assert pair_rows(data_root, scratch)["intents"] == pair_before["intents"]
    assert read_restore_epoch(layout, schema_version=5, os_=adapters) == restore_epoch_before

    # Online `--fix` under live daemon likewise never deletes data, edits CLAUDE.md/AGENTS.md,
    # mutates ApplyJournal/recovery_grant, or invokes restore.
    monkeypatch.undo()
    with spawn_installed_brain_serve(inc2_installed_env, rep.daemon_config_path, data_root=data_root, cwd=cwd) as srv:
        srv.wait_ready()
        # Settle the daemon's automatic startup `system.doctor` background run before
        # snapshotting `cas_dir`, so its startup DoctorRun CAS blobs do not race `--fix`.
        settle_startup = run_installed_command(
            inc2_installed_env,
            "brain",
            ["doctor", "--wait-ms", "10000", "--config", str(rep.daemon_config_path), "--json"],
            cwd=cwd,
        )
        assert settle_startup.returncode == 0
        settle_data = cast(dict[str, Any], json.loads(settle_startup.stdout.decode("utf-8"))["data"])
        assert settle_data.get("status") != "running"
        live_co_before = digest_tree(checkout)
        live_cas_before = digest_tree(layout.cas_dir)
        live_i33_store_before = raw_i33_store(data_root, scratch)
        live_i33_policy_before = raw_i33_policy(data_root, scratch)
        live_pair_before = pair_rows(data_root, scratch)
        live_epoch_before = read_restore_epoch(layout, schema_version=5, os_=adapters)

        online_fix = run_installed_command(
            inc2_installed_env,
            "brain",
            [
                "doctor",
                "--fix",
                "--config",
                str(rep.daemon_config_path),
                "--checkout",
                str(checkout),
                "--json",
            ],
            cwd=cwd,
        )
        online_data, online_actions = _assert_completed_fix_json(
            online_fix.stdout, online_fix.stderr, online_fix.returncode, expected_store_id=rep.store_id
        )
        assert not ({"delete_data", "edit_harness", "resolve_journal", "restore"} & set(online_actions))
        assert len(cast(list[Any], online_data["pending_proposals"])) >= 2
        assert len(cast(list[Any], online_data["incomplete_journals"])) == 1
        assert len(cast(list[Any], online_data["bootstrap_drifts"])) >= 1
        assert digest_tree(checkout) == live_co_before
        assert claude_path.read_bytes() == claude_before
        assert agents_path.read_bytes() == agents_before
        assert digest_tree(layout.cas_dir) == live_cas_before
        assert raw_i33_store(data_root, scratch) == live_i33_store_before
        assert raw_i33_policy(data_root, scratch) == live_i33_policy_before
        assert pair_rows(data_root, scratch)["quarantine"] == live_pair_before["quarantine"]
        assert pair_rows(data_root, scratch)["intents"] == live_pair_before["intents"]
        assert read_restore_epoch(layout, schema_version=5, os_=adapters) == live_epoch_before

        rc_srv, _, _, _ = srv.signal_and_wait_exit()
        assert rc_srv == 0
