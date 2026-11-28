"""Crash cases and wheel assertions for ``brain doctor --fix`` (SP1 I4-4)."""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import sqlite3
import struct
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from superbrain.adapters.os import os_adapters
from superbrain.composition.init_entry import InitRequest, init_store
from superbrain.core._kernel_approval import ApprovalChannel, SignerEnrollment
from superbrain.core.ids import new_id
from superbrain.ports.doctor import MAX_LOG_BYTES
from superbrain.storage.cas import RetentionClass
from superbrain.storage.layout import DataRoot
from superbrain.storage.sqlite import open_readonly
from tests.support.clock import FakeClock
from tests.support.crash_cases import (
    KernelCrashContext,
    MarkedRun,
    assert_entered,
    assert_t8_crashed,
    assert_wheel_provenance,
    run_marked,
    store_rows,
)
from tests.support.inc2_cli import (
    is_writer_lock_held,
    run_installed_command,
    spawn_installed_brain_serve,
    write_daemon_config_file,
    write_owner_only_bytes,
)
from tests.support.inc2_fixture import (
    InstalledEnv,
    ensure_template_base,
    reopen_kernel_job_runtime,
)
from tests.support.inc2_transport import clone_owner_only_tree


@dataclass(frozen=True)
class I44CrashCase:
    operation: str
    crashpoint: str

    @property
    def node_id(self) -> str:
        return f"{self.operation}@{self.crashpoint}"


I4_4_CRASH_CASES: tuple[I44CrashCase, ...] = (
    I44CrashCase("doctor-fix-offline", "doctor.fix.before_projection_swap"),
    I44CrashCase("doctor-fix-offline", "doctor.fix.after_log_rotate_stage"),
)

I4_4_CRASHPOINTS: frozenset[str] = frozenset(
    {
        "doctor.fix.before_projection_swap",
        "doctor.fix.after_log_rotate_stage",
    }
)
I44_CHILD = Path(__file__).resolve().with_name("inc4_crash_child.py")
OWNER = "dan"
MACHINE = "i4-4-box"
PROJECTION_PAYLOAD = b"i44-projection-rebuild-durable-blob-payload"
ORIG_LOG_BYTES = b"HDR-I44-LOG-ORIG\n" + (b"L" * (MAX_LOG_BYTES + 4096)) + b"\nEND-I44-LOG-ORIG\n"
PRIOR_ROT1_BYTES = b"PRIOR-ROTATED-GEN-1-BYTES\n"


@dataclass(frozen=True)
class I44Seed:
    data_root: Path
    config_path: Path
    payload_path: Path
    store_id: str
    holder_id: str
    blob_digest: str
    orig_log_bytes: bytes
    prior_rot1_bytes: bytes


@dataclass(frozen=True)
class _I44Template:
    root: Path
    store_id: str


_I44_TEMPLATE: _I44Template | None = None


def _ssh_enrollment(owner_id: str = OWNER) -> SignerEnrollment:
    raw = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", len(raw)) + raw
    line = "ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + f" {owner_id}@i4-4"
    return SignerEnrollment(owner_id=owner_id, channel=ApprovalChannel.SSH_KEY, public_key=line)


def _i44_template() -> _I44Template:
    """Build once per session: clean initialized store + valid TLS + CLI credential under template base."""
    global _I44_TEMPLATE
    if _I44_TEMPLATE is not None and _I44_TEMPLATE.root.is_dir():
        return _I44_TEMPLATE
    root = ensure_template_base() / f"i44-seed-{uuid.uuid4().hex}"
    root.mkdir()
    now = dt.datetime.now(dt.UTC).replace(microsecond=0) - dt.timedelta(minutes=10)
    adapters = os_adapters(clock=FakeClock(now))
    cfg_dir = root / "cfg"
    cfg_dir.mkdir()
    adapters.permissions.secure_directory(cfg_dir)
    rep = init_store(
        InitRequest(
            data_root=root / "data",
            config_dir=cfg_dir,
            owner_id=OWNER,
            machine_id=MACHINE,
            signer=_ssh_enrollment(),
        ),
        adapters,
    )
    _I44_TEMPLATE = _I44Template(root=root, store_id=rep.store_id)
    return _I44_TEMPLATE


def prepare_i44_seed(ctx: KernelCrashContext, *, crashpoint: str) -> I44Seed:
    """Clone the cached seed and prepare either a projection mismatch or an oversized log + .1 file."""
    tpl = _i44_template()
    data_root = ctx.case_dir / "data"
    cfg_dir = ctx.case_dir / "config"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    adapters = os_adapters()
    adapters.permissions.secure_directory(cfg_dir)
    clone_owner_only_tree(tpl.root / "data", data_root)
    clone_owner_only_tree(tpl.root / "cfg" / "tls", cfg_dir / "tls")
    write_owner_only_bytes(cfg_dir / "cli.credential", (tpl.root / "cfg" / "cli.credential").read_bytes())
    cfg_path = write_daemon_config_file(
        cfg_dir / "daemon.json",
        data_root=data_root,
        expected_store_id=tpl.store_id,
        cert_path=cfg_dir / "tls" / "server.pem",
        key_path=cfg_dir / "tls" / "server.key",
    )

    layout = DataRoot.at(data_root)
    holder_id = new_id()
    blob_digest = ""

    if crashpoint == "doctor.fix.before_projection_swap":
        rt = reopen_kernel_job_runtime(data_root, tpl.store_id, adapters)
        try:
            blob_digest = rt.store.store_content(
                PROJECTION_PAYLOAD, "event", holder_id, RetentionClass.DURABLE, None
            )
        finally:
            rt.close()
        conn = sqlite3.connect(layout.store_db)
        try:
            cur = conn.execute("DELETE FROM p_cas_holders_ WHERE holder_id = ?", (holder_id,))
            assert cur.rowcount == 1
            conn.commit()
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            conn.close()
        adapters.permissions.secure_file(layout.store_db)
    elif crashpoint == "doctor.fix.after_log_rotate_stage":
        layout.logs_dir.mkdir(parents=True, exist_ok=True)
        adapters.permissions.secure_directory(layout.logs_dir)
        write_owner_only_bytes(layout.logs_dir / "brain.log", ORIG_LOG_BYTES)
        write_owner_only_bytes(layout.logs_dir / "brain.log.1", PRIOR_ROT1_BYTES)
    else:
        raise ValueError(f"unsupported I4-4 crashpoint: {crashpoint!r}")

    payload_path = ctx.case_dir / "i44-payload.json"
    write_owner_only_bytes(payload_path, json.dumps({"crashpoint": crashpoint}).encode("utf-8"))
    return I44Seed(
        data_root=data_root,
        config_path=cfg_path,
        payload_path=payload_path,
        store_id=tpl.store_id,
        holder_id=holder_id,
        blob_digest=blob_digest,
        orig_log_bytes=ORIG_LOG_BYTES,
        prior_rot1_bytes=PRIOR_ROT1_BYTES,
    )


def run_i44_child(
    env: InstalledEnv,
    mode: str,
    config_path: Path,
    payload_path: Path,
    *,
    cwd: Path,
    crashpoint: str | None = None,
) -> MarkedRun:
    cmd = [str(env.venv_python), "-I", str(I44_CHILD), mode, str(config_path), str(payload_path)]
    return run_marked(cmd, cwd=cwd, crashpoint=crashpoint)


def _action_map(fix_data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    actions = fix_data.get("actions")
    assert isinstance(actions, list), fix_data
    out: dict[str, dict[str, Any]] = {}
    for item in actions:
        assert isinstance(item, dict) and isinstance(item.get("action"), str), item
        name = item["action"]
        assert name not in out, f"duplicate fix action {name!r} in {actions}"
        out[name] = item
    return out


def _check_by(checks: list[dict[str, Any]], group: str, name: str) -> dict[str, Any]:
    for chk in checks:
        if chk.get("group") == group and chk.get("name") in (name, f"{group}.{name}"):
            return chk
    raise AssertionError(f"missing check {group}.{name} in {checks}")


def _assert_projection_swap_crash(ctx: KernelCrashContext, case: I44CrashCase, seed: I44Seed) -> None:
    layout = DataRoot.at(seed.data_root)
    scratch = ctx.case_dir / "ro-scratch"
    scratch.mkdir(parents=True, exist_ok=True)
    before_ledger = store_rows(seed.data_root, scratch)["ledger"]

    crashed = run_i44_child(
        ctx.env,
        case.operation,
        seed.config_path,
        seed.payload_path,
        cwd=ctx.cwd,
        crashpoint=case.crashpoint,
    )
    assert_wheel_provenance(crashed, ctx)
    assert_entered(crashed)
    assert_t8_crashed(crashed, case.crashpoint)
    assert not is_writer_lock_held(seed.data_root)

    # Post-crash state BEFORE recovery: 0 r_* tables, SQLite integrity ok, ledger intact, holder still missing.
    ro_db = open_readonly(layout.store_db, scratch_dir=scratch)
    try:
        r_tables = ro_db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'r_%'"
        ).fetchall()
        assert r_tables == [], f"unexpected leftover r_* tables after rollback: {r_tables}"
        integrity = [str(r[0]) for r in ro_db.execute("PRAGMA integrity_check").fetchall()]
        assert integrity == ["ok"], integrity
        held_after_crash = ro_db.execute(
            "SELECT holder_id FROM p_cas_holders_ WHERE holder_id = ?", (seed.holder_id,)
        ).fetchall()
        assert held_after_crash == [], f"projection swap unexpectedly committed: {held_after_crash}"
    finally:
        ro_db.close()
    assert store_rows(seed.data_root, scratch)["ledger"][:len(before_ledger)] == before_ledger

    # Re-run `brain doctor --fix --json` cleanly via installed wheel while daemon is serving.
    with spawn_installed_brain_serve(ctx.env, seed.config_path, data_root=seed.data_root, cwd=ctx.cwd) as srv_proc:
        srv_proc.wait_ready()
        recovered = run_installed_command(
            ctx.env,
            "brain",
            ["doctor", "--fix", "--config", str(seed.config_path), "--json"],
            cwd=ctx.cwd,
        )
        assert recovered.returncode == 0, recovered.stderr.decode("utf-8", errors="replace")
        assert recovered.stderr == b""
        env = cast(dict[str, Any], json.loads(recovered.stdout.decode("utf-8")))
        assert env.get("ok") is True, env
        data = cast(dict[str, Any], env["data"])
        actions = _action_map(cast(dict[str, Any], data["fix"]))
        assert actions["rebuild_projections"]["status"] == "applied", actions
        proj_chk = _check_by(cast(list[dict[str, Any]], data["checks"]), "storage", "ledger_projection_match")
        assert proj_chk["status"] == "PASS", proj_chk

    adapters = os_adapters()
    rt = reopen_kernel_job_runtime(seed.data_root, seed.store_id, adapters)
    try:
        assert rt.store.db_integrity() == "ok"
        assert (
            rt.store.cas.read_held(
                seed.blob_digest,
                holder_kind="event",
                holder_id=seed.holder_id,
                now=dt.datetime.now(dt.UTC),
            )
            == PROJECTION_PAYLOAD
        )
    finally:
        rt.close()

    # Second run STILL arming the crashpoint succeeds idempotently (noop, no crashpoint hit).
    again = run_i44_child(
        ctx.env,
        case.operation,
        seed.config_path,
        seed.payload_path,
        cwd=ctx.cwd,
        crashpoint=case.crashpoint,
    )
    assert again.result.returncode == 0 and again.result.hit is None, again.describe()
    again_data = cast(dict[str, Any], json.loads(again.result.stdout)["data"])
    again_actions = _action_map(cast(dict[str, Any], again_data["fix"]))
    assert again_actions["rebuild_projections"]["status"] == "noop", again_actions


def _assert_log_rotate_stage_crash(ctx: KernelCrashContext, case: I44CrashCase, seed: I44Seed) -> None:
    layout = DataRoot.at(seed.data_root)
    logs_dir = layout.logs_dir

    crashed = run_i44_child(
        ctx.env,
        case.operation,
        seed.config_path,
        seed.payload_path,
        cwd=ctx.cwd,
        crashpoint=case.crashpoint,
    )
    assert_wheel_provenance(crashed, ctx)
    assert_entered(crashed)
    assert_t8_crashed(crashed, case.crashpoint)
    assert not is_writer_lock_held(seed.data_root)

    # Post-crash state BEFORE recovery: .rotate-state-<id>.json (phase=='pending_move', size & sha256)
    # AND .brain.log.rotating-<id> must both be on disk; .1 unchanged; no .2 yet.
    state_files = sorted(logs_dir.glob(".rotate-state-*.json"))
    assert len(state_files) == 1, f"expected 1 rotate state file in {list(logs_dir.iterdir())}"
    state_file = state_files[0]
    rot_id = state_file.name.removeprefix(".rotate-state-").removesuffix(".json")
    assert rot_id, state_file.name
    state_obj = cast(dict[str, Any], json.loads(state_file.read_bytes().decode("utf-8")))
    assert state_obj.get("phase") == "pending_move", state_obj

    expected_sha256 = hashlib.sha256(seed.orig_log_bytes).hexdigest()
    raw_size = state_obj.get("size") if "size" in state_obj else state_obj.get("byte_size")
    assert raw_size == len(seed.orig_log_bytes), state_obj
    raw_digest = state_obj.get("sha256") if "sha256" in state_obj else state_obj.get("digest")
    assert isinstance(raw_digest, str) and raw_digest.removeprefix("sha256:") == expected_sha256, state_obj

    rotating_file = logs_dir / f".brain.log.rotating-{rot_id}"
    assert rotating_file.is_file(), f"missing staged rotating log {rotating_file}"
    assert rotating_file.read_bytes() == seed.orig_log_bytes
    assert (logs_dir / "brain.log.1").read_bytes() == seed.prior_rot1_bytes
    assert not (logs_dir / "brain.log.2").exists()
    active_log = logs_dir / "brain.log"
    assert not active_log.exists() or active_log.stat().st_size == 0

    # Write newer bytes to logs/brain.log before recovery.
    newer_bytes = b"NEWER-POST-CRASH-LOG-ENTRY-001\n"
    write_owner_only_bytes(active_log, newer_bytes)

    with spawn_installed_brain_serve(ctx.env, seed.config_path, data_root=seed.data_root, cwd=ctx.cwd) as srv_proc:
        srv_proc.wait_ready()
        recovered = run_installed_command(
            ctx.env,
            "brain",
            ["doctor", "--fix", "--config", str(seed.config_path), "--json"],
            cwd=ctx.cwd,
        )
        assert recovered.returncode == 0, recovered.stderr.decode("utf-8", errors="replace")
        assert recovered.stderr == b""
        env = cast(dict[str, Any], json.loads(recovered.stdout.decode("utf-8")))
        assert env.get("ok") is True, env
        data = cast(dict[str, Any], env["data"])
        actions = _action_map(cast(dict[str, Any], data["fix"]))
        assert actions["rotate_logs"]["status"] == "applied", actions

    # Zero bytes lost, no double-shift, state & staging files cleaned up.
    assert (logs_dir / "brain.log.2").read_bytes() == seed.prior_rot1_bytes
    assert not (logs_dir / "brain.log.3").exists()
    assert (logs_dir / "brain.log.1").read_bytes() == seed.orig_log_bytes
    assert active_log.read_bytes() == newer_bytes
    assert list(logs_dir.glob(".rotate-state-*")) == []
    assert list(logs_dir.glob(".brain.log.rotating-*")) == []

    # Second run STILL arming crashpoint succeeds idempotently without hitting crashpoint again.
    again = run_i44_child(
        ctx.env,
        case.operation,
        seed.config_path,
        seed.payload_path,
        cwd=ctx.cwd,
        crashpoint=case.crashpoint,
    )
    assert again.result.returncode == 0 and again.result.hit is None, again.describe()
    again_data = cast(dict[str, Any], json.loads(again.result.stdout)["data"])
    again_actions = _action_map(cast(dict[str, Any], again_data["fix"]))
    assert again_actions["rotate_logs"]["status"] == "noop", again_actions
    assert (logs_dir / "brain.log.2").read_bytes() == seed.prior_rot1_bytes
    assert (logs_dir / "brain.log.1").read_bytes() == seed.orig_log_bytes
    assert active_log.read_bytes() == newer_bytes


def run_i44_crash_case(ctx: KernelCrashContext, case: I44CrashCase) -> I44Seed:
    """Seed, crash at ``case.crashpoint``, inspect pre-recovery state, recover via ``--offline --fix``, verify."""
    seed = prepare_i44_seed(ctx, crashpoint=case.crashpoint)
    if case.crashpoint == "doctor.fix.before_projection_swap":
        _assert_projection_swap_crash(ctx, case, seed)
    elif case.crashpoint == "doctor.fix.after_log_rotate_stage":
        _assert_log_rotate_stage_crash(ctx, case, seed)
    else:
        raise AssertionError(f"unhandled crashpoint {case.crashpoint!r}")
    return seed
