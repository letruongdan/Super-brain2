"""I3-3 Round-3 RED regressions for review findings I3-3-R06 and I3-3-R07.

Covers:
- I3-3-R06: Q25 ban on repo-scoped skill directory ``target_root`` paths via
  ``assert_not_skill_or_internal_target`` and ``ReviewApplyService.create_proposal``.
- I3-3-R07: ``stage_apply_journal`` / ``apply_proposal`` succeeding on proposals targeting
  not-yet-existing subdirectories (``nested/sub/new.md``), while rejecting recovery when an
  attacker pre-creates the missing subdirectory after ``apply.after_policy_turn_intent``.
"""

from __future__ import annotations

import base64
import struct
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from superbrain.adapters.harness_config.merger import SharedConfigMergerAdapter
from superbrain.adapters.os import os_adapters
from superbrain.application.journal_recovery import reconcile_and_classify_journals
from superbrain.application.review_apply import ReviewApplyService, TargetWriteInput
from superbrain.core._kernel_approval import (
    RISK_POLICY_VERSION,
    ApprovalAction,
    ApprovalChannel,
    ApprovalMessage,
    RecoveryScope,
    RiskResource,
    SignerEnrollment,
    canonical_utc,
)
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.proposals import (
    ChangeProposal,
    JournalDirection,
    ManagedFormat,
    ProposalStatus,
    assert_not_skill_or_internal_target,
)
from superbrain.storage.proposals import PolicyApplyAuthority, StoreProposalAdapter
from superbrain.storage.runtime import Runtime
from tests.support.clock import FakeClock
from tests.support.inc2_fixture import open_kernel_job_runtime

OWNER = "dan"


def _ssh_enrollment(tag: str = "r3") -> SignerEnrollment:
    raw = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", len(raw)) + raw
    return SignerEnrollment(
        owner_id=OWNER,
        channel=ApprovalChannel.SSH_KEY,
        public_key="ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + f" {tag}@devbox",
    )


def _sign(rt: Runtime, prop: ChangeProposal) -> ApprovalMessage:
    issued = rt.policy.issue_nonce(
        action=ApprovalAction.APPLY, subject_id=prop.proposal_id, risk_level=prop.risk_level
    )
    return ApprovalMessage(
        store_id=rt.store.store_id,
        owner_id=OWNER,
        trust_generation=issued.trust_generation,
        action=ApprovalAction.APPLY,
        subject_id=prop.proposal_id,
        subject_revision=prop.subject_revision,
        resource_digests=prop.resource_digests,
        target_files=prop.to_target_files(),
        risk_level=issued.risk_level,
        risk_policy_version=RISK_POLICY_VERSION,
        recovery_scope=RecoveryScope.CONTINUE_OR_ROLLBACK,
        nonce=issued.nonce,
        expires_at=issued.expires_at,
    )


def test_r06_q25_bans_repo_scoped_skill_dir_target_roots(trusted_tmp: Path) -> None:
    """I3-3-R06: root_path inside any repo skill directory MUST refuse with UNSAFE_PATH."""
    data_dir = trusted_tmp / "data"
    unrelated_home = trusted_tmp / "unrelated-home"
    repo_skill_roots = (
        trusted_tmp / "repo" / ".claude" / "skills" / "evil",
        trusted_tmp / "repo" / ".codex" / "skills" / "evil",
        trusted_tmp / "repo" / ".agents" / "skills" / "evil",
        trusted_tmp / "repo" / ".gemini" / "skills" / "evil",
        trusted_tmp / "repo" / ".gemini" / "antigravity" / "skills" / "evil",
        trusted_tmp / "repo" / ".gemini" / "config" / "skills" / "evil",
    )
    for skill_root in repo_skill_roots:
        with pytest.raises(BrainError) as exc:
            assert_not_skill_or_internal_target(
                str(skill_root),
                "SKILL.md",
                data_root=str(data_dir),
                home_dir=str(unrelated_home),
            )
        assert exc.value.code is ErrorCode.UNSAFE_PATH

    clock = FakeClock(datetime(2026, 11, 19, 14, 0, tzinfo=UTC))
    os_ = os_adapters(clock=clock)
    checkout, home = trusted_tmp / "repo2", trusted_tmp / "home2"
    evil_dir = checkout / ".claude" / "skills" / "evil"
    evil_dir.mkdir(parents=True)
    home.mkdir()
    for d in (checkout, checkout / ".claude", checkout / ".claude" / "skills", evil_dir, home):
        os_.permissions.secure_directory(d)
    rt = open_kernel_job_runtime(trusted_tmp / "data2", os_, role="i3-3-r06")
    try:
        proposals, authority = StoreProposalAdapter(rt.store, os_), PolicyApplyAuthority(rt.policy)
        svc = ReviewApplyService(proposals, authority, os_, data_root=trusted_tmp / "data2", home_dir=home)
        with pytest.raises(BrainError) as svc_exc:
            svc.create_proposal(
                owner_id=OWNER, kind="bootstrap", reason="r06 ban", resources=(RiskResource("c2"),),
                targets=(TargetWriteInput(evil_dir, "SKILL.md", b"evil\n", ManagedFormat.RAW, "r06"),),
            )
        assert svc_exc.value.code in {ErrorCode.UNSAFE_PATH, ErrorCode.INVALID_INPUT}
    finally:
        rt.close()


def test_r07_apply_missing_subdirectory_succeeds_and_blocks_precreated_subdir_on_recovery(
    trusted_tmp: Path,
) -> None:
    """I3-3-R07: missing subdir apply succeeds to APPLIED; pre-creating it post-crash halts RECOVERY_REQUIRED."""
    clock = FakeClock(datetime(2026, 11, 19, 14, 30, tzinfo=UTC))
    os_ = os_adapters(clock=clock)
    root, checkout, home = trusted_tmp / "data", trusted_tmp / "checkout", trusted_tmp / "home"
    for d in (checkout, home):
        d.mkdir()
        os_.permissions.secure_directory(d)
    rt = open_kernel_job_runtime(root, os_, role="i3-3-r07")
    try:
        signer = rt.policy.enroll_first_signer(_ssh_enrollment())
        proposals, authority = StoreProposalAdapter(rt.store, os_), PolicyApplyAuthority(rt.policy)
        svc = ReviewApplyService(
            proposals, authority, os_, data_root=root, home_dir=home, config_merger=SharedConfigMergerAdapter()
        )

        # 1. Happy path: nested/sub does not exist yet at create_proposal or apply_proposal.
        prop_ok = svc.create_proposal(
            owner_id=OWNER, kind="bootstrap", reason="new subdir", resources=(RiskResource("c2"),),
            targets=(TargetWriteInput(checkout, "nested/sub/new.md", b"# new\n", ManagedFormat.RAW, "r1"),),
        )
        journal_ok = svc.apply_proposal(
            prop_ok.proposal_id,
            approval=_sign(rt, prop_ok),
            signer_id=signer.signer_id,
            channel=ApprovalChannel.SSH_KEY,
        )
        assert journal_ok.status is ProposalStatus.APPLIED
        assert proposals.get_proposal(prop_ok.proposal_id).status is ProposalStatus.APPLIED
        assert (checkout / "nested" / "sub" / "new.md").read_bytes() == b"# new\n"
        assert [g for g in authority.list_recovery_grants() if g.state == "active"] == []
        assert [t for t in authority.list_turn_intents() if t.state == "active"] == []

        # 2. Pre-creating nested2/sub after apply.after_policy_turn_intent changes ancestor -> RECOVERY_REQUIRED.
        prop_pre = svc.create_proposal(
            owner_id=OWNER, kind="bootstrap", reason="precreated subdir", resources=(RiskResource("c2"),),
            targets=(TargetWriteInput(checkout, "nested2/sub/new.md", b"# blocked\n", ManagedFormat.RAW, "r2"),),
        )
        rec = authority.consume_approval(
            _sign(rt, prop_pre), signer_id=signer.signer_id, channel=ApprovalChannel.SSH_KEY
        )
        jid_pre = new_id()
        authority.begin_journal_turn(approval_id=rec.approval_id, journal_id=jid_pre, direction=JournalDirection.APPLY)

        pre_sub = checkout / "nested2" / "sub"
        pre_sub.mkdir(parents=True)
        os_.permissions.secure_directory(checkout / "nested2")
        os_.permissions.secure_directory(pre_sub)

        rep = reconcile_and_classify_journals(
            proposals, authority, os_, data_root=root, home_dir=home,
            config_merger=SharedConfigMergerAdapter(), now_utc_fn=lambda: str(canonical_utc(clock.now())),
        )
        assert rep.recovery_required_journals == 1 and rep.continued_journals == 0
        assert proposals.get_proposal(prop_pre.proposal_id).status is ProposalStatus.RECOVERY_REQUIRED
        grant = authority.find_recovery_grant_for_journal(jid_pre)
        assert grant is not None and grant.state == "ended"
        assert not (pre_sub / "new.md").exists()
    finally:
        rt.close()
