"""I3-2 oracle: ChangeProposal lifecycle, Q25 skill-dir ban, CAS/projection rebuild, and ApplyJournal apply guards.

Requirement sources: spec rev 22 §5.4, §8.11 (Q25), §11.2, §11.3 (server risk rules), §20 cases 12, 19, 27,
92, 94, 95, 105, 106; ledger §2.2, §4; plan I3-2 Steps 1-4.
"""

from __future__ import annotations

import hashlib
import os
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from superbrain.adapters.os import os_adapters
from superbrain.application.review_apply import ReviewApplyService, TargetWriteInput
from superbrain.core._kernel_approval import (
    RISK_POLICY_VERSION,
    ApprovalAction,
    ApprovalChannel,
    ApprovalMessage,
    RecoveryScope,
    RiskLevel,
    RiskResource,
    SignerEnrollment,
    SignerRecord,
)
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.proposals import (
    ApplyJournal,
    ChangeProposal,
    FileJournalPhase,
    FileOriginalState,
    JournalDirection,
    ManagedFormat,
    ManagedSliceManifest,
    ProposalStatus,
    assert_not_skill_or_internal_target,
    normalize_proposal_rel_path,
)
from superbrain.ports.os import NoReplacePublisher, OsAdapters
from superbrain.storage.proposals import PolicyApplyAuthority, StoreProposalAdapter
from superbrain.storage.runtime import Runtime
from tests.support.clock import FakeClock
from tests.support.inc2_fixture import open_kernel_job_runtime

OWNER = "dan"
D_RES = "sha256:" + "a" * 64


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _ssh_enrollment() -> SignerEnrollment:
    import base64
    import struct

    raw = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", len(raw)) + raw
    line = "ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + " i3-2@devbox"
    return SignerEnrollment(owner_id=OWNER, channel=ApprovalChannel.SSH_KEY, public_key=line)


def _make_dir_link(link: Path, target: Path) -> None:
    if sys.platform == "win32":
        import _winapi

        _winapi.CreateJunction(str(target), str(link))
    else:
        link.symlink_to(target, target_is_directory=True)


@dataclass
class Ctx:
    rt: Runtime
    root: Path
    checkout: Path
    home: Path
    clock: FakeClock
    os_: OsAdapters
    signer: SignerRecord
    proposals: StoreProposalAdapter
    authority: PolicyApplyAuthority
    svc: ReviewApplyService


@pytest.fixture
def ctx(trusted_tmp: Path) -> Iterator[Ctx]:
    clock = FakeClock(datetime(2026, 11, 19, 8, 0, tzinfo=UTC))
    os_ = os_adapters(clock=clock)
    root = trusted_tmp / "data"
    checkout = trusted_tmp / "checkout"
    home = trusted_tmp / "home"
    checkout.mkdir()
    home.mkdir()
    os_.permissions.secure_directory(checkout)
    os_.permissions.secure_directory(home)
    rt = open_kernel_job_runtime(root, os_, role="i3-2-app")
    try:
        signer = rt.policy.enroll_first_signer(_ssh_enrollment())
        proposals = StoreProposalAdapter(rt.store, os_)
        authority = PolicyApplyAuthority(rt.policy)
        svc = ReviewApplyService(proposals, authority, os_, data_root=root, home_dir=home)
        yield Ctx(
            rt=rt,
            root=root,
            checkout=checkout,
            home=home,
            clock=clock,
            os_=os_,
            signer=signer,
            proposals=proposals,
            authority=authority,
            svc=svc,
        )
    finally:
        rt.close()


def _sign_msg(
    c: Ctx,
    prop: ChangeProposal,
    *,
    action: ApprovalAction,
    recovery_scope: RecoveryScope = RecoveryScope.NONE,
    target_overrides: tuple[Any, ...] | None = None,
) -> ApprovalMessage:
    issued = c.rt.policy.issue_nonce(action=action, subject_id=prop.proposal_id, risk_level=prop.risk_level)
    targets = target_overrides if target_overrides is not None else prop.to_target_files()
    return ApprovalMessage(
        store_id=c.rt.store.store_id,
        owner_id=OWNER,
        trust_generation=issued.trust_generation,
        action=action,
        subject_id=prop.proposal_id,
        subject_revision=prop.subject_revision,
        resource_digests=prop.resource_digests,
        target_files=targets,
        risk_level=issued.risk_level,
        risk_policy_version=RISK_POLICY_VERSION,
        recovery_scope=recovery_scope,
        nonce=issued.nonce,
        expires_at=issued.expires_at,
    )


def test_q25_skill_dir_ban_and_internal_path_guards(ctx: Ctx) -> None:
    """Case 92: ChangeProposal targets inside any harness skill dir or data_root/git are refused pre-approval."""
    forbidden_rels = (
        ".claude/skills/my-skill/SKILL.md",
        ".CLAUDE/Skills/case-variant.md",
        ".claude\\skills\\win\\a.md",
        "nested/../.codex/skills/x.md",
        ".codex/skills/my-skill/SKILL.md",
        ".agents/skills/shared/SKILL.md",
        ".gemini/skills/a/SKILL.md",
        ".gemini/antigravity/skills/a/SKILL.md",
        ".gemini/config/skills/a/SKILL.md",
        ".git/hooks/pre-commit",
    )
    for raw in forbidden_rels:
        with pytest.raises(BrainError) as exc:
            ctx.svc.create_proposal(
                owner_id=OWNER,
                kind="improvement",
                reason="bad skill write",
                resources=(RiskResource("c1"),),
                targets=(TargetWriteInput(ctx.checkout, raw, b"x", ManagedFormat.RAW, "s"),),
            )
        assert exc.value.code in {ErrorCode.UNSAFE_PATH, ErrorCode.INVALID_INPUT}, raw

    # Home-dir skill directory (~/.claude/skills, ~/.codex/skills, ~/.agents/skills) is also banned.
    for home_sub in (".claude/skills/x", ".codex/skills/x", ".agents/skills/x"):
        home_skill_root = ctx.home / home_sub
        home_skill_root.mkdir(parents=True)
        with pytest.raises(BrainError) as home_exc:
            assert_not_skill_or_internal_target(
                str(home_skill_root),
                "SKILL.md",
                data_root=str(ctx.root),
                home_dir=str(ctx.home),
            )
        assert home_exc.value.code in {ErrorCode.UNSAFE_PATH, ErrorCode.INVALID_INPUT}

    # Targeting anything inside data_root is also forbidden.
    with pytest.raises(BrainError) as data_exc:
        assert_not_skill_or_internal_target(
            str(ctx.root), "policy/policy.db", data_root=str(ctx.root), home_dir=str(ctx.home)
        )
    assert data_exc.value.code in {ErrorCode.UNSAFE_PATH, ErrorCode.INVALID_INPUT}

    assert normalize_proposal_rel_path("sub\\CLAUDE.md") == "sub/CLAUDE.md"
    assert ctx.svc.list_proposals() == ()


def test_server_risk_classification_approve_reject_and_projection_rebuild(ctx: Ctx) -> None:
    """Case 19: client 'low' hint is ignored for c2/c5/c7/c8/exec/outside-guidance; ledger rebuild preserves state."""
    target = ctx.checkout / "CLAUDE.md"
    target.write_bytes(b"# Old\n")

    prop_high = ctx.svc.create_proposal(
        owner_id=OWNER,
        kind="bootstrap",
        reason="c2 mcp hook",
        resources=(RiskResource("c2"),),
        targets=(TargetWriteInput(ctx.checkout, "CLAUDE.md", b"# New\n", ManagedFormat.MARKDOWN, "r1", D_RES),),
        client_risk_hint="low",
    )
    assert prop_high.risk_level is RiskLevel.HIGH
    assert prop_high.status is ProposalStatus.PENDING

    prop_low = ctx.svc.create_proposal(
        owner_id=OWNER,
        kind="improvement",
        reason="c1 guidance",
        resources=(RiskResource("c1"),),
        targets=(TargetWriteInput(ctx.checkout, "CLAUDE.md", b"# Low\n", ManagedFormat.MARKDOWN, "r2", D_RES),),
        client_risk_hint="low",
    )
    assert prop_low.risk_level is RiskLevel.LOW

    # Approving high-risk proposal with subject tamper fails; valid SSH_KEY approval succeeds.
    good_msg = _sign_msg(ctx, prop_high, action=ApprovalAction.APPROVE)
    tampered_msg = ApprovalMessage(
        store_id=good_msg.store_id,
        owner_id=good_msg.owner_id,
        trust_generation=good_msg.trust_generation,
        action=good_msg.action,
        subject_id="tampered-proposal-id",
        subject_revision=good_msg.subject_revision,
        resource_digests=good_msg.resource_digests,
        target_files=good_msg.target_files,
        risk_level=good_msg.risk_level,
        risk_policy_version=good_msg.risk_policy_version,
        recovery_scope=good_msg.recovery_scope,
        nonce=good_msg.nonce,
        expires_at=good_msg.expires_at,
    )
    with pytest.raises(BrainError) as tamper_exc:
        ctx.svc.approve_proposal(
            prop_high.proposal_id,
            approval=tampered_msg,
            signer_id=ctx.signer.signer_id,
            channel=ApprovalChannel.SSH_KEY,
        )
    assert tamper_exc.value.code in {ErrorCode.INVALID_INPUT, ErrorCode.UNAUTHENTICATED, ErrorCode.REVISION_CONFLICT}
    assert ctx.svc.get_proposal(prop_high.proposal_id).status is ProposalStatus.PENDING

    ctx.svc.approve_proposal(
        prop_high.proposal_id,
        approval=good_msg,
        signer_id=ctx.signer.signer_id,
        channel=ApprovalChannel.SSH_KEY,
    )
    assert ctx.svc.get_proposal(prop_high.proposal_id).status is ProposalStatus.APPROVED

    # Rebuilding projections from ledger reconstructs identical proposal, targets, and status!
    ctx.rt.store.rebuild_projections()
    rebuilt = ctx.svc.get_proposal(prop_high.proposal_id)
    assert rebuilt.status is ProposalStatus.APPROVED
    assert rebuilt.risk_level is RiskLevel.HIGH
    assert len(rebuilt.targets) == 1 and rebuilt.targets[0].normalized_rel_path == "CLAUDE.md"

    # Rejecting second proposal uses LOW risk and transitions to REJECTED.
    rej_msg = _sign_msg(ctx, prop_low, action=ApprovalAction.REJECT)
    rejected = ctx.svc.reject_proposal(
        prop_low.proposal_id,
        approval=rej_msg,
        signer_id=ctx.signer.signer_id,
        channel=ApprovalChannel.SSH_KEY,
    )
    assert rejected.status is ProposalStatus.REJECTED


def test_multi_file_apply_journal_handles_present_and_absent_and_persists_manifest(ctx: Ctx) -> None:
    """ApplyJournal atomically updates both present and absent files, saves manifests, and ends its grant."""
    existing = ctx.checkout / "CLAUDE.md"
    existing.write_bytes(b"# Existing\n")
    created = ctx.checkout / "AGENTS.md"
    assert not created.exists()

    prop = ctx.svc.create_proposal(
        owner_id=OWNER,
        kind="bootstrap",
        reason="multi-file bootstrap",
        resources=(RiskResource("c2"), RiskResource("c5")),
        targets=(
            TargetWriteInput(
                ctx.checkout, "CLAUDE.md", b"# Existing\n<!-- managed -->\n", ManagedFormat.MARKDOWN, "md1", D_RES
            ),
            TargetWriteInput(
                ctx.checkout, "AGENTS.md", b"# New AGENTS\n", ManagedFormat.MARKDOWN, "ag1", _sha256(b"# New AGENTS\n")
            ),
        ),
    )
    apply_msg = _sign_msg(ctx, prop, action=ApprovalAction.APPLY, recovery_scope=RecoveryScope.CONTINUE_OR_ROLLBACK)
    journal = ctx.svc.apply_proposal(
        prop.proposal_id,
        approval=apply_msg,
        signer_id=ctx.signer.signer_id,
        channel=ApprovalChannel.SSH_KEY,
    )
    assert isinstance(journal, ApplyJournal)
    assert journal.direction is JournalDirection.APPLY
    assert journal.status is ProposalStatus.APPLIED
    assert len(journal.files) == 2
    assert journal.files[0].original is FileOriginalState.PRESENT
    assert journal.files[1].original is FileOriginalState.ABSENT
    assert all(f.phase is FileJournalPhase.REPLACEMENT_PUBLISHED for f in journal.files)
    assert existing.read_bytes() == b"# Existing\n<!-- managed -->\n"
    assert created.read_bytes() == b"# New AGENTS\n"

    grant = ctx.rt.policy.recovery_grant(journal.grant_id)
    assert grant.state == "ended" and grant.end_reason == "journal_closed"

    manifests = ctx.proposals.list_manifests(prop.proposal_id)
    assert len(manifests) == 2 and all(isinstance(m, ManagedSliceManifest) for m in manifests)

    ctx.rt.store.rebuild_projections()
    assert ctx.svc.get_journal(journal.journal_id).status is ProposalStatus.APPLIED


def test_apply_rejects_post_approval_drift_same_path_replacement_and_surrogate_link(ctx: Ctx) -> None:
    """Cases 12, 94: byte drift, PhysicalObjectId swap with identical bytes, and linked parent all refuse."""
    # 1. Same-path replacement with identical bytes -> PhysicalObjectId changed -> refused before write.
    p_swap = ctx.checkout / "swap.md"
    p_swap.write_bytes(b"identical\n")
    prop_swap = ctx.svc.create_proposal(
        owner_id=OWNER,
        kind="bootstrap",
        reason="swap check",
        resources=(RiskResource("c2"),),
        targets=(TargetWriteInput(ctx.checkout, "swap.md", b"replaced\n", ManagedFormat.RAW, "r1"),),
    )
    other_tmp = ctx.checkout / "swap-tmp.md"
    other_tmp.write_bytes(b"identical\n")
    p_swap.unlink()
    os.replace(other_tmp, p_swap)
    msg_swap = _sign_msg(ctx, prop_swap, action=ApprovalAction.APPLY, recovery_scope=RecoveryScope.CONTINUE_OR_ROLLBACK)
    with pytest.raises(BrainError) as swap_exc:
        ctx.svc.apply_proposal(
            prop_swap.proposal_id, approval=msg_swap, signer_id=ctx.signer.signer_id, channel=ApprovalChannel.SSH_KEY
        )
    assert swap_exc.value.code in {ErrorCode.REVISION_CONFLICT, ErrorCode.UNSAFE_PATH}
    assert p_swap.read_bytes() == b"identical\n"

    # 2. Byte drift after approval -> refused.
    p_drift = ctx.checkout / "drift.md"
    p_drift.write_bytes(b"v0\n")
    prop_drift = ctx.svc.create_proposal(
        owner_id=OWNER,
        kind="bootstrap",
        reason="drift check",
        resources=(RiskResource("c2"),),
        targets=(TargetWriteInput(ctx.checkout, "drift.md", b"v1\n", ManagedFormat.RAW, "r2"),),
    )
    p_drift.write_bytes(b"user-edited\n")
    msg_drift = _sign_msg(
        ctx, prop_drift, action=ApprovalAction.APPLY, recovery_scope=RecoveryScope.CONTINUE_OR_ROLLBACK
    )
    with pytest.raises(BrainError) as drift_exc:
        ctx.svc.apply_proposal(
            prop_drift.proposal_id, approval=msg_drift, signer_id=ctx.signer.signer_id, channel=ApprovalChannel.SSH_KEY
        )
    assert drift_exc.value.code is ErrorCode.REVISION_CONFLICT
    assert p_drift.read_bytes() == b"user-edited\n"

    # 3. Case 94: parent subdir swapped to a junction/symlink to a surrogate directory holding identical bytes.
    sub = ctx.checkout / "cfg"
    sub.mkdir()
    target_in_sub = sub / "item.json"
    target_in_sub.write_bytes(b'{"a":1}\n')
    prop_link = ctx.svc.create_proposal(
        owner_id=OWNER,
        kind="bootstrap",
        reason="link check",
        resources=(RiskResource("c2"),),
        targets=(TargetWriteInput(ctx.checkout, "cfg/item.json", b'{"a":2}\n', ManagedFormat.JSON, "j1"),),
    )
    surrogate = ctx.checkout.parent / "surrogate-cfg"
    surrogate.mkdir()
    (surrogate / "item.json").write_bytes(b'{"a":1}\n')
    target_in_sub.unlink()
    sub.rmdir()
    _make_dir_link(sub, surrogate)

    msg_link = _sign_msg(ctx, prop_link, action=ApprovalAction.APPLY, recovery_scope=RecoveryScope.CONTINUE_OR_ROLLBACK)
    with pytest.raises(BrainError) as link_exc:
        ctx.svc.apply_proposal(
            prop_link.proposal_id, approval=msg_link, signer_id=ctx.signer.signer_id, channel=ApprovalChannel.SSH_KEY
        )
    assert link_exc.value.code is ErrorCode.UNSAFE_PATH
    assert (surrogate / "item.json").read_bytes() == b'{"a":1}\n'


def test_late_user_file_at_publish_no_replace_halts_in_recovery_required_preserving_all_bytes(
    ctx: Ctx, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Case 95: if user creates a file right before publish_no_replace, keep user file, backup & staging intact."""
    orig = ctx.checkout / "CLAUDE.md"
    orig.write_bytes(b"U0 original\n")
    prop = ctx.svc.create_proposal(
        owner_id=OWNER,
        kind="bootstrap",
        reason="late file race",
        resources=(RiskResource("c2"),),
        targets=(TargetWriteInput(ctx.checkout, "CLAUDE.md", b"U0 replacement\n", ManagedFormat.RAW, "r1"),),
    )

    real_pub = cast(NoReplacePublisher, ctx.os_.publisher)
    orig_pub_nr = real_pub.publish_no_replace
    injected = [False]

    def _race_publish_no_replace(staging: Path, final: Path) -> None:
        if not injected[0] and final == orig:
            injected[0] = True
            # Simulate a concurrent user file appearing after original was moved to backup!
            final.write_bytes(b"LATE USER BYTES\n")
        orig_pub_nr(staging, final)

    monkeypatch.setattr(real_pub, "publish_no_replace", _race_publish_no_replace)
    msg = _sign_msg(ctx, prop, action=ApprovalAction.APPLY, recovery_scope=RecoveryScope.CONTINUE_OR_ROLLBACK)
    with pytest.raises(BrainError) as race_exc:
        ctx.svc.apply_proposal(
            prop.proposal_id, approval=msg, signer_id=ctx.signer.signer_id, channel=ApprovalChannel.SSH_KEY
        )
    assert race_exc.value.code in {ErrorCode.REVISION_CONFLICT, ErrorCode.INTEGRITY_FAILURE, ErrorCode.IO_ERROR}

    # Verify late user file was NEVER overwritten, AND backup + staging are preserved in recovery_required!
    assert orig.read_bytes() == b"LATE USER BYTES\n"
    updated_prop = ctx.svc.get_proposal(prop.proposal_id)
    assert updated_prop.status is ProposalStatus.RECOVERY_REQUIRED
    assert updated_prop.active_journal_id is not None
    journal = ctx.svc.get_journal(updated_prop.active_journal_id)
    assert journal.status is ProposalStatus.RECOVERY_REQUIRED
    fentry = journal.files[0]
    assert fentry.backup_path is not None and Path(fentry.backup_path).read_bytes() == b"U0 original\n"
    assert Path(fentry.replacement_staging_path).read_bytes() == b"U0 replacement\n"
