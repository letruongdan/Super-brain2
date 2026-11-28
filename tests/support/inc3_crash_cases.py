"""Crash cases and wheel assertions for ``ApplyJournal`` & ``recovery_grant`` (SP1 I3-3).

Every entry in ``I3_3_CRASH_CASES`` exercises one of the 10 ``apply.*`` / ``rollback.*`` crashpoints through
``tests/support/inc3_crash_child.py`` inside the installed wheel venv, inspects raw SQLite + filesystem state left
by the crash before any recovery runs, then restarts ``daemon_entry.serve`` to prove startup journal recovery
converges and remains idempotent across a second restart.
"""

from __future__ import annotations

import base64
import datetime as dt
import json
import struct
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from superbrain.adapters.harness_config.markdown_blocks import merge_markdown_block
from superbrain.adapters.harness_config.merger import SharedConfigMergerAdapter
from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.tls_material import create_store_tls
from superbrain.application.review_apply import ReviewApplyService, TargetWriteInput
from superbrain.core._kernel_approval import (
    CLI_HARNESS_ID,
    RISK_POLICY_VERSION,
    ApprovalAction,
    ApprovalChannel,
    ApprovalMessage,
    RecoveryScope,
    RiskResource,
    SignerEnrollment,
    TargetFile,
)
from superbrain.core._kernel_base import ResourceDigest
from superbrain.core.canonical import digest_bytes
from superbrain.core.proposals import ChangeProposal, ManagedFormat, ProposalStatus
from superbrain.ports.os import OsAdapters
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.proposals import PolicyApplyAuthority, StoreProposalAdapter
from tests.support.clock import FakeClock
from tests.support.crash_cases import (
    KernelCrashContext,
    MarkedRun,
    assert_entered,
    assert_t8_crashed,
    assert_wheel_provenance,
    run_marked,
)
from tests.support.inc2_cli import is_writer_lock_held, write_daemon_config_file
from tests.support.inc2_fixture import (
    InstalledEnv,
    ensure_template_base,
    open_kernel_job_runtime,
    reopen_kernel_job_runtime,
)
from tests.support.inc2_transport import clone_owner_only_tree
from tests.support.inc3_crash_child import raw_i33_policy as raw_i33_policy
from tests.support.inc3_crash_child import raw_i33_store as raw_i33_store
from tests.support.kernel_auth import make_bootstrap_auth, seed_principal_and_credential

OWNER = "dan"
I33_CHILD = Path(__file__).with_name("inc3_crash_child.py")

I3_3_CRASHPOINTS: frozenset[str] = frozenset({
    "apply.after_policy_turn_intent",
    "apply.before_move_original",
    "apply.after_move_before_phase",
    "apply.before_publish_replacement",
    "apply.after_publish_before_phase",
    "rollback.after_policy_turn_intent",
    "rollback.before_first_move",
    "rollback.after_move_replacement",
    "rollback.after_restore_last_original",
    "apply.after_policy_grant_ended",
})


def _ssh_enrollment() -> SignerEnrollment:
    raw = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", len(raw)) + raw
    line = "ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + " i3-3@devbox"
    return SignerEnrollment(owner_id=OWNER, channel=ApprovalChannel.SSH_KEY, public_key=line)


def serialize_approval(msg: ApprovalMessage) -> dict[str, object]:
    return {
        "store_id": msg.store_id,
        "owner_id": msg.owner_id,
        "trust_generation": msg.trust_generation,
        "action": msg.action.value,
        "subject_id": msg.subject_id,
        "subject_revision": msg.subject_revision,
        "resource_digests": [[r.name, r.digest] for r in msg.resource_digests],
        "target_files": [f.to_dict() for f in msg.target_files],
        "risk_level": msg.risk_level.value,
        "risk_policy_version": msg.risk_policy_version,
        "recovery_scope": msg.recovery_scope.value,
        "nonce": msg.nonce,
        "expires_at": msg.expires_at.isoformat(),
    }


def _sign_proposal(
    policy: PolicyStore,
    store_id: str,
    prop: ChangeProposal,
    *,
    action: ApprovalAction,
    recovery_scope: RecoveryScope,
    target_files: tuple[TargetFile, ...] | None = None,
    resource_digests: tuple[ResourceDigest, ...] | None = None,
) -> ApprovalMessage:
    issued = policy.issue_nonce(action=action, subject_id=prop.proposal_id, risk_level=prop.risk_level)
    return ApprovalMessage(
        store_id=store_id,
        owner_id=OWNER,
        trust_generation=issued.trust_generation,
        action=action,
        subject_id=prop.proposal_id,
        subject_revision=prop.subject_revision,
        resource_digests=resource_digests if resource_digests is not None else prop.resource_digests,
        target_files=target_files if target_files is not None else prop.to_target_files(),
        risk_level=issued.risk_level,
        risk_policy_version=RISK_POLICY_VERSION,
        recovery_scope=recovery_scope,
        nonce=issued.nonce,
        expires_at=issued.expires_at,
    )


@dataclass(frozen=True)
class I33Seed:
    data_root: Path
    config: Path
    checkout: Path
    home: Path
    claude_path: Path
    agents_path: Path
    store_id: str
    proposal_id: str
    signer_id: str
    base_time: dt.datetime
    payload_path: Path


@dataclass(frozen=True)
class I33CrashCase:
    operation: Literal["apply", "rollback-applied"]
    crashpoint: str
    recovery_scope: RecoveryScope
    seed_rollback_applied: bool = False
    preserve_u1: bool = False
    advance_past_ttl: bool = False
    expected_terminal: ProposalStatus = ProposalStatus.APPLIED
    expect_post_crash: Callable[[I33Seed, Path], None] | None = None

    @property
    def node_id(self) -> str:
        return f"{self.operation}@{self.crashpoint}"


def run_i33_child(
    env: InstalledEnv,
    mode: str,
    config: Path,
    payload_path: Path,
    *,
    cwd: Path,
    crashpoint: str | None = None,
) -> MarkedRun:
    cmd = [str(env.venv_python), "-I", str(I33_CHILD), mode, str(config), str(payload_path)]
    return run_marked(cmd, cwd=cwd, crashpoint=crashpoint)


def _write_payload(path: Path, data: dict[str, object]) -> Path:
    path.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")
    return path


@dataclass(frozen=True)
class _SeedTemplate:
    """Session-cached pre-seeded base: schema'd data root + enrolled signer + principal + TLS (no proposals)."""

    root: Path
    store_id: str
    signer_id: str
    cert_name: str
    key_name: str


_SEED_TEMPLATE: _SeedTemplate | None = None


def _seed_template(adapters: OsAdapters, clock: FakeClock, base_time: dt.datetime) -> _SeedTemplate:
    global _SEED_TEMPLATE
    if _SEED_TEMPLATE is not None and _SEED_TEMPLATE.root.is_dir():
        return _SEED_TEMPLATE
    root = ensure_template_base() / f"i33-seed-{uuid.uuid4().hex}"
    root.mkdir()
    rt = open_kernel_job_runtime(root / "data", adapters, role="i3-3-seed")
    try:
        signer = rt.policy.enroll_first_signer(_ssh_enrollment())
        seed_principal_and_credential(rt.policy, owner_id=OWNER, harness_id=CLI_HARNESS_ID, machine_id="m-i33")
        store_id, generation = rt.store.store_id, rt.policy.trust_generation()
    finally:
        rt.close()
    auth = make_bootstrap_auth(
        store_id=store_id,
        owner_id=OWNER,
        action="provision_tls",
        subject_id=store_id,
        trust_generation=generation,
        expires_at=base_time + dt.timedelta(hours=4),
        destination=root / "tls",
    )
    tls = create_store_tls(store_id, root / "tls", auth, clock, adapters)
    _SEED_TEMPLATE = _SeedTemplate(root, store_id, signer.signer_id, tls.cert_path.name, tls.key_path.name)
    return _SEED_TEMPLATE


def prepare_i33_seed(
    ctx: KernelCrashContext,
    *,
    recovery_scope: RecoveryScope,
    seed_rollback_applied: bool = False,
    preserve_u1: bool = False,
) -> I33Seed:
    base_time = dt.datetime.now(dt.UTC).replace(microsecond=0)
    clock = FakeClock(base_time)
    adapters = os_adapters(clock=clock)
    data_root = ctx.case_dir / "data"
    checkout = ctx.case_dir / "checkout"
    home = ctx.case_dir / "home"
    checkout.mkdir()
    home.mkdir()
    adapters.permissions.secure_directory(checkout)
    adapters.permissions.secure_directory(home)

    claude = checkout / "CLAUDE.md"
    agents = checkout / "AGENTS.md"
    claude.write_bytes(b"# U0\n# Base line\n")
    merged = merge_markdown_block(
        "# U0\n# Base line\n",
        slice_id="md-i33",
        block_body="## Managed\nBody\n",
        expected_slice_digest=None,
    )
    agents_bytes = b"# Brain Agents\n"

    tpl = _seed_template(adapters, clock, base_time)
    clone_owner_only_tree(tpl.root / "data", data_root)
    rt = reopen_kernel_job_runtime(data_root, tpl.store_id, adapters)
    try:
        proposals = StoreProposalAdapter(rt.store, adapters)
        authority = PolicyApplyAuthority(rt.policy)
        svc = ReviewApplyService(
            proposals,
            authority,
            adapters,
            data_root=data_root,
            home_dir=home,
            config_merger=SharedConfigMergerAdapter(),
        )
        prop = svc.create_proposal(
            owner_id=OWNER,
            kind="bootstrap",
            reason="i3-3 crash recovery test",
            resources=(RiskResource("c2"),),
            targets=(
                TargetWriteInput(
                    checkout,
                    "CLAUDE.md",
                    merged.updated_text.encode("utf-8"),
                    ManagedFormat.MARKDOWN,
                    "md-i33",
                    merged.slice_digest,
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
        if seed_rollback_applied:
            apply_msg = _sign_proposal(
                rt.policy,
                rt.store.store_id,
                prop,
                action=ApprovalAction.APPLY,
                recovery_scope=RecoveryScope.CONTINUE_OR_ROLLBACK,
            )
            svc.apply_proposal(
                prop.proposal_id,
                approval=apply_msg,
                signer_id=tpl.signer_id,
                channel=ApprovalChannel.SSH_KEY,
            )
            if preserve_u1:
                claude.write_bytes(claude.read_bytes() + b"\n# Out-of-band U1\n")
            prop = proposals.get_proposal(prop.proposal_id)
            plan = svc.plan_rollback_targets(prop.proposal_id)
            msg = _sign_proposal(
                rt.policy,
                rt.store.store_id,
                prop,
                action=ApprovalAction.ROLLBACK,
                recovery_scope=recovery_scope,
                target_files=plan.target_files,
                resource_digests=plan.resource_digests,
            )
        else:
            msg = _sign_proposal(
                rt.policy,
                rt.store.store_id,
                prop,
                action=ApprovalAction.APPLY,
                recovery_scope=recovery_scope,
            )
    finally:
        rt.close()

    cfg_dir = ctx.case_dir / "cfg"
    cfg_dir.mkdir()
    adapters.permissions.secure_directory(cfg_dir)
    config = write_daemon_config_file(
        cfg_dir / "daemon.json",
        data_root=data_root,
        expected_store_id=tpl.store_id,
        cert_path=tpl.root / "tls" / tpl.cert_name,
        key_path=tpl.root / "tls" / tpl.key_name,
    )
    payload_path = _write_payload(
        ctx.case_dir / "op-payload.json",
        {
            "proposal_id": prop.proposal_id,
            "approval": serialize_approval(msg),
            "signer_id": tpl.signer_id,
            "channel": ApprovalChannel.SSH_KEY.value,
            "home_dir": str(home),
            "now_iso": base_time.isoformat(),
        },
    )
    return I33Seed(
        data_root=data_root,
        config=config,
        checkout=checkout,
        home=home,
        claude_path=claude,
        agents_path=agents,
        store_id=tpl.store_id,
        proposal_id=prop.proposal_id,
        signer_id=tpl.signer_id,
        base_time=base_time,
        payload_path=payload_path,
    )


def _post_after_policy_turn_intent(seed: I33Seed, scratch: Path) -> None:
    pol = raw_i33_policy(seed.data_root, scratch)
    st = raw_i33_store(seed.data_root, scratch)
    assert len(pol["turns"]) == 1 and pol["turns"][0][3:] == ("apply", "active")
    assert len(pol["grants"]) == 1 and pol["grants"][0][4] == "active"
    assert st["journals"] == [] and seed.claude_path.read_bytes() == b"# U0\n# Base line\n"
    assert not seed.agents_path.exists()


def _post_before_move_original(seed: I33Seed, scratch: Path) -> None:
    st = raw_i33_store(seed.data_root, scratch)
    assert len(st["journals"]) == 1 and st["journals"][0][3] == "applying"
    assert seed.claude_path.read_bytes() == b"# U0\n# Base line\n" and not seed.agents_path.exists()


def _post_after_move_before_phase(seed: I33Seed, scratch: Path) -> None:
    pol = raw_i33_policy(seed.data_root, scratch)
    assert len(pol["grants"]) == 1 and pol["grants"][0][4] == "active"
    assert not seed.claude_path.exists(), "original moved to backup before replacement published"


def _post_before_publish_replacement(seed: I33Seed, scratch: Path) -> None:
    st = raw_i33_store(seed.data_root, scratch)
    assert len(st["journals"]) == 1 and not seed.claude_path.exists()


def _post_after_publish_before_phase(seed: I33Seed, scratch: Path) -> None:
    pol = raw_i33_policy(seed.data_root, scratch)
    assert len(pol["grants"]) == 1 and pol["grants"][0][4] == "active"
    assert b"## Managed" in seed.claude_path.read_bytes()


def _post_after_policy_grant_ended(seed: I33Seed, scratch: Path) -> None:
    pol = raw_i33_policy(seed.data_root, scratch)
    st = raw_i33_store(seed.data_root, scratch)
    assert len(pol["grants"]) == 1 and pol["grants"][0][4:] == ("ended", "journal_closed")
    assert len(pol["turns"]) == 1 and pol["turns"][0][3:] == ("apply", "applied")
    assert st["proposals"][0][1] != "applied", "case 93: brain.db must not be applied yet"


def _post_rollback_after_policy_turn_intent(seed: I33Seed, scratch: Path) -> None:
    pol = raw_i33_policy(seed.data_root, scratch)
    st = raw_i33_store(seed.data_root, scratch)
    assert pol["turns"][-1][3:] == ("rollback", "active")
    assert len(st["journals"]) == 1 and st["journals"][0][2] == "apply"


def _post_rollback_before_first_move(seed: I33Seed, scratch: Path) -> None:
    st = raw_i33_store(seed.data_root, scratch)
    assert st["journals"][-1][2:4] == ("rollback", "rolling_back")
    assert b"## Managed" in seed.claude_path.read_bytes() and seed.agents_path.exists()


def _post_rollback_after_move_replacement(seed: I33Seed, scratch: Path) -> None:
    pol = raw_i33_policy(seed.data_root, scratch)
    assert pol["grants"][-1][4] == "active"
    assert not seed.claude_path.exists()


def _post_rollback_after_restore_last_original(seed: I33Seed, scratch: Path) -> None:
    pol = raw_i33_policy(seed.data_root, scratch)
    st = raw_i33_store(seed.data_root, scratch)
    assert pol["grants"][-1][4] == "active" and st["journals"][-1][3] == "rolling_back"
    assert b"# U0" in seed.claude_path.read_bytes() and not seed.agents_path.exists()


def run_i33_crash_case(case: I33CrashCase, ctx: KernelCrashContext) -> None:
    assert case.crashpoint in I3_3_CRASHPOINTS
    seed = prepare_i33_seed(
        ctx,
        recovery_scope=case.recovery_scope,
        seed_rollback_applied=case.seed_rollback_applied,
        preserve_u1=case.preserve_u1,
    )
    crash_run = run_i33_child(
        ctx.env, case.operation, seed.config, seed.payload_path, cwd=ctx.cwd, crashpoint=case.crashpoint
    )
    assert_t8_crashed(crash_run, case.crashpoint)
    assert_wheel_provenance(crash_run, ctx)
    assert is_writer_lock_held(seed.data_root) is False

    scratch = ctx.case_dir / "ro-scratch"
    grants_before = len(raw_i33_policy(seed.data_root, scratch)["grants"])
    if case.expect_post_crash is not None:
        case.expect_post_crash(seed, scratch)

    offset_s = 1500 if case.advance_past_ttl else 60
    rec_payload = _write_payload(
        ctx.case_dir / "recover-payload.json",
        {
            "now_iso": (seed.base_time + dt.timedelta(seconds=offset_s)).isoformat(),
            "ro_scratch": str(scratch),
            "watch_files": [str(seed.claude_path), str(seed.agents_path)],
        },
    )
    # One wheel process runs recovery twice: each ``serve`` stops cleanly from ``on_ready``, the writer lock is
    # released after each, and the child fails (``DRIVER_ERROR``) unless recovery 2 left policy/store/files untouched.
    rec = run_i33_child(
        ctx.env, "serve-recover-twice", seed.config, rec_payload, cwd=ctx.cwd, crashpoint=case.crashpoint
    )
    assert rec.result.returncode == 0 and rec.result.hit is None and not rec.timed_out, rec.describe()
    assert "READY_1 " in rec.result.stderr and "READY_2 " in rec.result.stderr, rec.describe()
    assert "DRIVER_ERROR" not in rec.result.stderr, rec.describe()
    assert_entered(rec)
    assert_wheel_provenance(rec, ctx)
    assert is_writer_lock_held(seed.data_root) is False

    pol_after = raw_i33_policy(seed.data_root, scratch)
    st_after = raw_i33_store(seed.data_root, scratch)
    assert all(g[4:] == ("ended", "journal_closed") for g in pol_after["grants"]), pol_after["grants"]
    assert st_after["proposals"] == [(seed.proposal_id, case.expected_terminal.value, None)]
    assert len(pol_after["grants"]) == grants_before, "startup recovery must not open a new grant"

    if case.expected_terminal is ProposalStatus.APPLIED:
        claude_text = seed.claude_path.read_text(encoding="utf-8")
        assert "## Managed" in claude_text and "Body" in claude_text
        assert seed.agents_path.read_bytes() == b"# Brain Agents\n"
        assert pol_after["turns"][-1][3:] == ("apply", "applied")
        assert st_after["manifests"], "manifests must be recorded for applied structured slice"
    else:
        claude_text = seed.claude_path.read_text(encoding="utf-8")
        assert "# U0\n# Base line" in claude_text and "## Managed" not in claude_text
        if case.preserve_u1:
            assert "# Out-of-band U1" in claude_text
        assert not seed.agents_path.exists()
        assert pol_after["turns"][-1][3:] == ("rollback", "rolled_back")


I3_3_CRASH_CASES: tuple[I33CrashCase, ...] = (
    I33CrashCase(
        "apply",
        "apply.after_policy_turn_intent",
        RecoveryScope.CONTINUE_OR_ROLLBACK,
        expected_terminal=ProposalStatus.APPLIED,
        expect_post_crash=_post_after_policy_turn_intent,
    ),
    I33CrashCase(
        "apply",
        "apply.before_move_original",
        RecoveryScope.CONTINUE,
        expected_terminal=ProposalStatus.APPLIED,
        expect_post_crash=_post_before_move_original,
    ),
    I33CrashCase(
        "apply",
        "apply.after_move_before_phase",
        RecoveryScope.CONTINUE_OR_ROLLBACK,
        expected_terminal=ProposalStatus.APPLIED,
        expect_post_crash=_post_after_move_before_phase,
    ),
    I33CrashCase(
        "apply",
        "apply.before_publish_replacement",
        RecoveryScope.CONTINUE_OR_ROLLBACK,
        expected_terminal=ProposalStatus.APPLIED,
        expect_post_crash=_post_before_publish_replacement,
    ),
    I33CrashCase(
        "apply",
        "apply.after_publish_before_phase",
        RecoveryScope.CONTINUE,
        advance_past_ttl=True,
        expected_terminal=ProposalStatus.APPLIED,
        expect_post_crash=_post_after_publish_before_phase,
    ),
    I33CrashCase(
        "apply",
        "apply.after_policy_grant_ended",
        RecoveryScope.CONTINUE_OR_ROLLBACK,
        expected_terminal=ProposalStatus.APPLIED,
        expect_post_crash=_post_after_policy_grant_ended,
    ),
    I33CrashCase(
        "rollback-applied",
        "rollback.after_policy_turn_intent",
        RecoveryScope.ROLLBACK,
        seed_rollback_applied=True,
        preserve_u1=True,
        expected_terminal=ProposalStatus.ROLLED_BACK,
        expect_post_crash=_post_rollback_after_policy_turn_intent,
    ),
    I33CrashCase(
        "rollback-applied",
        "rollback.before_first_move",
        RecoveryScope.ROLLBACK,
        seed_rollback_applied=True,
        preserve_u1=True,
        expected_terminal=ProposalStatus.ROLLED_BACK,
        expect_post_crash=_post_rollback_before_first_move,
    ),
    I33CrashCase(
        "rollback-applied",
        "rollback.after_move_replacement",
        RecoveryScope.ROLLBACK,
        seed_rollback_applied=True,
        preserve_u1=True,
        expected_terminal=ProposalStatus.ROLLED_BACK,
        expect_post_crash=_post_rollback_after_move_replacement,
    ),
    I33CrashCase(
        "rollback-applied",
        "rollback.after_restore_last_original",
        RecoveryScope.ROLLBACK,
        seed_rollback_applied=True,
        preserve_u1=True,
        expected_terminal=ProposalStatus.ROLLED_BACK,
        expect_post_crash=_post_rollback_after_restore_last_original,
    ),
)
