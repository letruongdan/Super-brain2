"""I3-3 Round-2 RED regressions for review finding I3-3-R05 (policy turn/grant binding).

Covers:
- ``approval_message(approval_id)`` lookup on ``PolicyStore`` & ``PolicyApplyAuthority``.
- Refusal of ``APPROVE`` (and wrong-action) receipts in ``open_turn_intent`` and ``begin_journal_turn``.
- Refusal of stale ``trust_generation`` receipts after ``reset_signers_offline()``.
- Refusal of ``CONTINUE``-only active grant flipping to ``ROLLBACK``.
- Refusal of cross-proposal / unrelated ``approval_id`` hijacking an existing ``journal_id``.
"""

from __future__ import annotations

import base64
import struct
from datetime import UTC, datetime
from pathlib import Path

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
    RiskResource,
    SignerEnrollment,
)
from superbrain.core.errors import BrainError
from superbrain.core.ids import new_id
from superbrain.core.proposals import ChangeProposal, JournalDirection, ManagedFormat
from superbrain.storage.proposals import PolicyApplyAuthority, StoreProposalAdapter
from superbrain.storage.runtime import Runtime
from tests.support.clock import FakeClock
from tests.support.inc2_fixture import open_kernel_job_runtime

OWNER = "dan"


def _ssh_enrollment(tag: str = "r05") -> SignerEnrollment:
    raw = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", len(raw)) + raw
    return SignerEnrollment(
        owner_id=OWNER,
        channel=ApprovalChannel.SSH_KEY,
        public_key="ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + f" {tag}@devbox",
    )


def _sign(
    rt: Runtime,
    prop: ChangeProposal,
    *,
    action: ApprovalAction,
    recovery_scope: RecoveryScope,
) -> ApprovalMessage:
    issued = rt.policy.issue_nonce(action=action, subject_id=prop.proposal_id, risk_level=prop.risk_level)
    return ApprovalMessage(
        store_id=rt.store.store_id,
        owner_id=OWNER,
        trust_generation=issued.trust_generation,
        action=action,
        subject_id=prop.proposal_id,
        subject_revision=prop.subject_revision,
        resource_digests=prop.resource_digests,
        target_files=prop.to_target_files(),
        risk_level=issued.risk_level,
        risk_policy_version=RISK_POLICY_VERSION,
        recovery_scope=recovery_scope,
        nonce=issued.nonce,
        expires_at=issued.expires_at,
    )


def test_r05_turn_intent_and_begin_turn_enforce_action_generation_scope_and_subject(trusted_tmp: Path) -> None:
    clock = FakeClock(datetime(2026, 11, 19, 13, 0, tzinfo=UTC))
    os_ = os_adapters(clock=clock)
    root, checkout = trusted_tmp / "data", trusted_tmp / "checkout"
    checkout.mkdir()
    os_.permissions.secure_directory(checkout)
    rt = open_kernel_job_runtime(root, os_, role="i3-3-r05")
    try:
        signer = rt.policy.enroll_first_signer(_ssh_enrollment())
        proposals, authority = StoreProposalAdapter(rt.store, os_), PolicyApplyAuthority(rt.policy)
        svc = ReviewApplyService(proposals, authority, os_, data_root=root, home_dir=trusted_tmp)

        (checkout / "p1.md").write_bytes(b"u0-1\n")
        (checkout / "p2.md").write_bytes(b"u0-2\n")
        p1 = svc.create_proposal(
            owner_id=OWNER, kind="bootstrap", reason="p1", resources=(RiskResource("c2"),),
            targets=(TargetWriteInput(checkout, "p1.md", b"u1-1\n", ManagedFormat.RAW, "r1"),),
        )
        p2 = svc.create_proposal(
            owner_id=OWNER, kind="bootstrap", reason="p2", resources=(RiskResource("c2"),),
            targets=(TargetWriteInput(checkout, "p2.md", b"u1-2\n", ManagedFormat.RAW, "r2"),),
        )

        # Consume APPROVE receipt on p2 and CONTINUE-only / CONTINUE_OR_ROLLBACK APPLY receipts on p1.
        p2_approve_msg = _sign(rt, p2, action=ApprovalAction.APPROVE, recovery_scope=RecoveryScope.NONE)
        p2_approve_rec = authority.consume_approval(
            p2_approve_msg, signer_id=signer.signer_id, channel=ApprovalChannel.SSH_KEY
        )

        # 1. APPROVE receipt must NEVER open or begin a journal turn (APPLY or ROLLBACK).
        for direction in (JournalDirection.APPLY, JournalDirection.ROLLBACK):
            bad_jid = new_id()
            with pytest.raises(BrainError):
                authority.open_turn_intent(
                    journal_id=bad_jid, approval_id=p2_approve_rec.approval_id, direction=direction
                )
            with pytest.raises(BrainError):
                authority.begin_journal_turn(
                    approval_id=p2_approve_rec.approval_id, journal_id=bad_jid, direction=direction
                )
            assert authority.turn_intent_for_journal(bad_jid) is None
            assert authority.find_recovery_grant_for_journal(bad_jid) is None

        # 2. CONTINUE-only grant must refuse ROLLBACK flip, and cross-proposal p2 receipt must NOT hijack p1 turn.
        p1_cont_rec = authority.consume_approval(
            _sign(rt, p1, action=ApprovalAction.APPLY, recovery_scope=RecoveryScope.CONTINUE),
            signer_id=signer.signer_id, channel=ApprovalChannel.SSH_KEY,
        )
        jid_cont = new_id()
        authority.begin_journal_turn(
            approval_id=p1_cont_rec.approval_id, journal_id=jid_cont, direction=JournalDirection.APPLY
        )
        with pytest.raises(BrainError):
            authority.open_turn_intent(
                journal_id=jid_cont, approval_id=p1_cont_rec.approval_id, direction=JournalDirection.ROLLBACK
            )
        with pytest.raises(BrainError):
            authority.begin_journal_turn(
                approval_id=p1_cont_rec.approval_id, journal_id=jid_cont, direction=JournalDirection.ROLLBACK
            )
        with pytest.raises(BrainError):
            authority.begin_journal_turn(
                approval_id=p2_approve_rec.approval_id, journal_id=jid_cont, direction=JournalDirection.ROLLBACK
            )
        turn_cont = authority.turn_intent_for_journal(jid_cont)
        assert turn_cont is not None
        assert turn_cont.direction is JournalDirection.APPLY and turn_cont.approval_id == p1_cont_rec.approval_id

        # 3. Cross-proposal APPLY/ROLLBACK receipt cannot hijack an existing CONTINUE_OR_ROLLBACK journal.
        p1_both_rec = authority.consume_approval(
            _sign(rt, p1, action=ApprovalAction.APPLY, recovery_scope=RecoveryScope.CONTINUE_OR_ROLLBACK),
            signer_id=signer.signer_id, channel=ApprovalChannel.SSH_KEY,
        )
        p2_apply_rec = authority.consume_approval(
            _sign(rt, p2, action=ApprovalAction.APPLY, recovery_scope=RecoveryScope.CONTINUE_OR_ROLLBACK),
            signer_id=signer.signer_id, channel=ApprovalChannel.SSH_KEY,
        )
        jid_both = new_id()
        authority.begin_journal_turn(
            approval_id=p1_both_rec.approval_id, journal_id=jid_both, direction=JournalDirection.APPLY
        )
        for bad_rec in (p2_approve_rec, p2_apply_rec):
            with pytest.raises(BrainError):
                authority.open_turn_intent(
                    journal_id=jid_both, approval_id=bad_rec.approval_id, direction=JournalDirection.ROLLBACK
                )
            with pytest.raises(BrainError):
                authority.begin_journal_turn(
                    approval_id=bad_rec.approval_id, journal_id=jid_both, direction=JournalDirection.ROLLBACK
                )
        turn_both = authority.turn_intent_for_journal(jid_both)
        assert turn_both is not None
        assert turn_both.direction is JournalDirection.APPLY and turn_both.approval_id == p1_both_rec.approval_id

        # 4. Stale gen=1 APPLY receipt rejected after reset_signers_offline() bumps trust_generation to 2.
        p2_gen1_apply = authority.consume_approval(
            _sign(rt, p2, action=ApprovalAction.APPLY, recovery_scope=RecoveryScope.CONTINUE_OR_ROLLBACK),
            signer_id=signer.signer_id, channel=ApprovalChannel.SSH_KEY,
        )
        new_gen = rt.policy.reset_signers_offline()
        assert new_gen == 2
        stale_jid = new_id()
        with pytest.raises(BrainError):
            authority.open_turn_intent(
                journal_id=stale_jid, approval_id=p2_gen1_apply.approval_id, direction=JournalDirection.APPLY
            )
        with pytest.raises(BrainError):
            authority.begin_journal_turn(
                approval_id=p2_gen1_apply.approval_id, journal_id=stale_jid, direction=JournalDirection.APPLY
            )
        assert authority.turn_intent_for_journal(stale_jid) is None
        assert authority.find_recovery_grant_for_journal(stale_jid) is None

        # 5. approval_message(approval_id) returns the decoded signed ApprovalMessage or None.
        assert rt.policy.approval_message(p2_approve_rec.approval_id) == p2_approve_msg
        assert authority.approval_message(p2_approve_rec.approval_id) == p2_approve_msg
        assert authority.approval_message("nonexistent-approval-id") is None
    finally:
        rt.close()
