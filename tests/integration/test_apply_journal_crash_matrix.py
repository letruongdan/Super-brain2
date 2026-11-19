"""ApplyJournal & recovery_grant crash recovery through the installed wheel (SP1 I3-3).

Exercises every ``I3_3_CRASH_CASES`` row (all 10 ``apply.*`` / ``rollback.*`` boundaries), plus interrupted-rollback
resumption (R21-01), Case 107 corrupt-backup halts, offline ``brain init --reset-signers`` between crash and daemon
restart, and omission detection via ``SUPERBRAIN_DISABLE_CRASHPOINTS_FOR_TEST``.
"""

from __future__ import annotations

import base64
import datetime as dt
import json
import struct
import subprocess
from pathlib import Path
from typing import cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from superbrain.adapters.harness_config.merger import SharedConfigMergerAdapter
from superbrain.adapters.os import os_adapters
from superbrain.application.review_apply import ReviewApplyService
from superbrain.core._kernel_approval import ApprovalChannel, RecoveryScope
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.proposals import ProposalStatus
from superbrain.ports.os import NoReplacePublisher
from superbrain.storage.proposals import PolicyApplyAuthority, StoreProposalAdapter
from tests.support.clock import FakeClock
from tests.support.crash_cases import (
    I3_3_CRASH_CASES,
    KernelCrashContext,
    assert_entered,
    assert_t8_crashed,
    assert_wheel_provenance,
)
from tests.support.inc2_cli import (
    clean_installed_subprocess_env,
    get_shared_t7_transport_template,
    run_installed_command,
    write_owner_only_bytes,
)
from tests.support.inc2_fixture import InstalledEnv, reopen_kernel_job_runtime
from tests.support.inc3_crash_cases import (
    I33_CHILD,
    OWNER,
    I33CrashCase,
    I33Seed,
    prepare_i33_seed,
    raw_i33_policy,
    raw_i33_store,
    run_i33_child,
    run_i33_crash_case,
)


def _context(env: InstalledEnv, trusted_tmp: Path) -> KernelCrashContext:
    cwd = trusted_tmp / "outside-cwd"
    cwd.mkdir()
    return KernelCrashContext(env=env, template=get_shared_t7_transport_template(), case_dir=trusted_tmp, cwd=cwd)


def _write_json(path: Path, payload: dict[str, object]) -> Path:
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    return path


def _seed_interrupted_apply(
    ctx: KernelCrashContext, monkeypatch: pytest.MonkeyPatch, *, scope: RecoveryScope
) -> tuple[I33Seed, str, str | None]:
    """Run ``prepare_i33_seed``, execute target 0 (CLAUDE.md), interrupt on target 1 (AGENTS.md)."""
    seed = prepare_i33_seed(ctx, recovery_scope=scope)
    payload = json.loads(seed.payload_path.read_text(encoding="utf-8"))
    from tests.support.inc3_crash_child import _parse_approval

    clock = FakeClock(seed.base_time)
    adapters = os_adapters(clock=clock)
    rt = reopen_kernel_job_runtime(seed.data_root, seed.store_id, adapters)
    try:
        svc = ReviewApplyService(
            StoreProposalAdapter(rt.store, adapters),
            PolicyApplyAuthority(rt.policy),
            adapters,
            data_root=seed.data_root,
            home_dir=seed.home,
            config_merger=SharedConfigMergerAdapter(),
        )
        pub = cast(NoReplacePublisher, adapters.publisher)
        orig = pub.publish_no_replace
        hits = [0]

        def _interrupt_second(staging: Path, final: Path) -> None:
            hits[0] += 1
            if hits[0] == 2:
                raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "interrupted before target 2")
            orig(staging, final)

        monkeypatch.setattr(pub, "publish_no_replace", _interrupt_second)
        msg = _parse_approval(payload["approval"])
        with pytest.raises(BrainError):
            svc.apply_proposal(
                seed.proposal_id,
                approval=msg,
                signer_id=seed.signer_id,
                channel=ApprovalChannel.SSH_KEY,
            )
        monkeypatch.undo()
        prop = svc.get_proposal(seed.proposal_id)
        assert prop.active_journal_id is not None
        journal = svc.get_journal(prop.active_journal_id)
        return seed, journal.journal_id, journal.files[0].backup_path
    finally:
        rt.close()


@pytest.mark.parametrize("case", I3_3_CRASH_CASES, ids=lambda c: c.node_id)
def test_apply_journal_crash_matrix(
    inc2_installed_env: InstalledEnv, trusted_tmp: Path, case: I33CrashCase
) -> None:
    run_i33_crash_case(case, _context(inc2_installed_env, trusted_tmp))


def test_positive_control_apply_succeeds_without_fault_env(
    inc2_installed_env: InstalledEnv, trusted_tmp: Path
) -> None:
    ctx = _context(inc2_installed_env, trusted_tmp)
    seed = prepare_i33_seed(ctx, recovery_scope=RecoveryScope.CONTINUE_OR_ROLLBACK)
    run = run_i33_child(ctx.env, "apply", seed.config, seed.payload_path, cwd=ctx.cwd)
    assert_entered(run)
    assert_wheel_provenance(run, ctx)
    assert run.result.returncode == 0 and run.result.hit is None, run.describe()
    assert b"## Managed" in seed.claude_path.read_bytes()
    assert seed.agents_path.read_bytes() == b"# Brain Agents\n"

    rec_iso = (seed.base_time + dt.timedelta(seconds=30)).isoformat()
    rec_payload = _write_json(ctx.case_dir / "rec.json", {"now_iso": rec_iso})
    rec = run_i33_child(ctx.env, "serve-recover", seed.config, rec_payload, cwd=ctx.cwd)
    assert rec.ready is not None and rec.result.returncode == 0, rec.describe()


def test_interrupted_rollback_resume_after_crash_through_wheel(
    inc2_installed_env: InstalledEnv, trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R21-01 wheel check: interrupted rollback crashing mid-rollback converges to ROLLED_BACK past TTL."""
    ctx = _context(inc2_installed_env, trusted_tmp)
    seed, journal_id, _ = _seed_interrupted_apply(ctx, monkeypatch, scope=RecoveryScope.CONTINUE_OR_ROLLBACK)
    rb_payload = _write_json(
        ctx.case_dir / "rb-int.json",
        {
            "journal_id": journal_id,
            "home_dir": str(seed.home),
            "now_iso": (seed.base_time + dt.timedelta(seconds=900)).isoformat(),
        },
    )
    cp = "rollback.after_move_replacement"
    crash = run_i33_child(ctx.env, "rollback-interrupted", seed.config, rb_payload, cwd=ctx.cwd, crashpoint=cp)
    assert_t8_crashed(crash, cp)
    assert_wheel_provenance(crash, ctx)

    scratch = ctx.case_dir / "ro-scratch"
    pol = raw_i33_policy(seed.data_root, scratch)
    assert pol["turns"][-1][3:] == ("rollback", "active")

    rec_payload = _write_json(
        ctx.case_dir / "recover-rb.json",
        {"now_iso": (seed.base_time + dt.timedelta(seconds=1500)).isoformat()},
    )
    rec = run_i33_child(ctx.env, "serve-recover", seed.config, rec_payload, cwd=ctx.cwd, crashpoint=cp)
    assert rec.ready is not None and rec.result.returncode == 0 and rec.result.hit is None, rec.describe()
    assert seed.claude_path.read_bytes() == b"# U0\n# Base line\n"
    assert not seed.agents_path.exists()
    st_after = raw_i33_store(seed.data_root, scratch)
    pol_after = raw_i33_policy(seed.data_root, scratch)
    assert st_after["proposals"] == [(seed.proposal_id, ProposalStatus.ROLLED_BACK.value, None)]
    assert pol_after["turns"][-1][3:] == ("rollback", "rolled_back")
    assert all(g[4:] == ("ended", "journal_closed") for g in pol_after["grants"])


def test_case_107_corrupt_backup_halts_rollback_recovery_required(
    inc2_installed_env: InstalledEnv, trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Case 107: corrupt backup before first move on interrupted rollback halts RECOVERY_REQUIRED."""
    ctx = _context(inc2_installed_env, trusted_tmp)
    seed, journal_id, backup_path = _seed_interrupted_apply(
        ctx, monkeypatch, scope=RecoveryScope.CONTINUE_OR_ROLLBACK
    )
    assert backup_path is not None and Path(backup_path).exists()
    before_claude = seed.claude_path.read_bytes()

    rb_payload = _write_json(
        ctx.case_dir / "rb-107.json",
        {"journal_id": journal_id, "home_dir": str(seed.home), "now_iso": seed.base_time.isoformat()},
    )
    cp = "rollback.before_first_move"
    crash = run_i33_child(ctx.env, "rollback-interrupted", seed.config, rb_payload, cwd=ctx.cwd, crashpoint=cp)
    assert_t8_crashed(crash, cp)
    Path(backup_path).write_bytes(b"corrupted-by-operator-or-fs-corruption")

    rec_payload = _write_json(
        ctx.case_dir / "rec-107.json",
        {"now_iso": (seed.base_time + dt.timedelta(seconds=60)).isoformat()},
    )
    rec = run_i33_child(ctx.env, "serve-recover", seed.config, rec_payload, cwd=ctx.cwd, crashpoint=cp)
    assert rec.ready is not None and rec.result.returncode == 0, rec.describe()
    scratch = ctx.case_dir / "ro-scratch"
    st = raw_i33_store(seed.data_root, scratch)
    assert st["proposals"] == [(seed.proposal_id, ProposalStatus.RECOVERY_REQUIRED.value, journal_id)]
    assert seed.claude_path.read_bytes() == before_claude and not seed.agents_path.exists()


def test_reset_signers_between_crash_and_restart_marks_recovery_required(
    inc2_installed_env: InstalledEnv, trusted_tmp: Path
) -> None:
    ctx = _context(inc2_installed_env, trusted_tmp)
    seed = prepare_i33_seed(ctx, recovery_scope=RecoveryScope.CONTINUE_OR_ROLLBACK)
    cp = "apply.after_publish_before_phase"
    crash = run_i33_child(ctx.env, "apply", seed.config, seed.payload_path, cwd=ctx.cwd, crashpoint=cp)
    assert_t8_crashed(crash, cp)
    claude_after_crash = seed.claude_path.read_bytes()

    raw_pub = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", len(raw_pub)) + raw_pub
    new_key = "ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + " replacement@devbox"
    init_req = write_owner_only_bytes(
        ctx.case_dir / "reset-init.json",
        json.dumps({
            "version": 1,
            "data_root": str(seed.data_root),
            "config_dir": str(seed.config.parent),
            "owner_id": OWNER,
            "machine_id": "m-i33",
            "signer": {"channel": "ssh_key", "public_key": new_key},
        }).encode("utf-8"),
    )
    done = run_installed_command(ctx.env, "brain", ("init", "--reset-signers", "--config", str(init_req)), cwd=ctx.cwd)
    assert done.returncode == 0, (done.returncode, done.stdout, done.stderr)

    rec_payload = _write_json(
        ctx.case_dir / "rec-reset.json",
        {"now_iso": (seed.base_time + dt.timedelta(seconds=60)).isoformat()},
    )
    rec = run_i33_child(ctx.env, "serve-recover", seed.config, rec_payload, cwd=ctx.cwd, crashpoint=cp)
    assert rec.ready is not None and rec.result.returncode == 0, rec.describe()

    scratch = ctx.case_dir / "ro-scratch"
    st = raw_i33_store(seed.data_root, scratch)
    pol = raw_i33_policy(seed.data_root, scratch)
    assert st["proposals"][0][1] == ProposalStatus.RECOVERY_REQUIRED.value
    assert pol["grants"][0][4:] == ("ended", "trust_reset")
    assert pol["turns"][0][4] == "recovery_required"
    assert seed.claude_path.read_bytes() == claude_after_crash and not seed.agents_path.exists()


def test_matrix_detects_omitted_i33_crashpoint(inc2_installed_env: InstalledEnv, trusted_tmp: Path) -> None:
    ctx = _context(inc2_installed_env, trusted_tmp)
    seed = prepare_i33_seed(ctx, recovery_scope=RecoveryScope.CONTINUE_OR_ROLLBACK)
    cp = "apply.after_policy_grant_ended"
    env = clean_installed_subprocess_env(
        {"SUPERBRAIN_CRASHPOINT": cp, "SUPERBRAIN_DISABLE_CRASHPOINTS_FOR_TEST": cp}
    )
    res = subprocess.run(
        [str(ctx.env.venv_python), "-I", str(I33_CHILD), "apply", str(seed.config), str(seed.payload_path)],
        cwd=ctx.cwd,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30.0,
    )
    assert res.returncode == 0 and "CRASHPOINT_HIT" not in res.stderr, (res.returncode, res.stderr)
