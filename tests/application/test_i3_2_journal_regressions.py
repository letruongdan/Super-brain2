"""I3-2 Round-2 RED regressions for I3-2-R01 and I3-2-R07.

Covers wrong-digest backup no-replace restore/keep-both, replacement_physical_id pre-pinning before publish,
policy-before-store grant close order, PLANNED+moved-backup recovery, pre-move validation across ALL entries
on interrupted rollback, FileExistsError mapping, ended-grant RECOVERY_REQUIRED, ROLLING_BACK phase, multi-volume
per-root staging, structured managed_slice_digest + target_root manifests, and removal of dead store v5 tables.
"""

from __future__ import annotations

import base64
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from superbrain.adapters.harness_config.merger import SharedConfigMergerAdapter
from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.physical_fs import stat_physical_identity
from superbrain.application.review_apply import ReviewApplyService, TargetWriteInput
from superbrain.core._kernel_approval import (
    RISK_POLICY_VERSION,
    ApprovalAction,
    ApprovalChannel,
    ApprovalMessage,
    RecoveryScope,
    RiskResource,
    SignerEnrollment,
    SignerRecord,
)
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.proposals import (
    ApplyJournal,
    ChangeProposal,
    ManagedFormat,
    ProposalStatus,
)
from superbrain.ports.os import NoReplacePublisher, OsAdapters
from superbrain.storage.proposals import PolicyApplyAuthority, StoreProposalAdapter
from superbrain.storage.runtime import Runtime
from tests.support.clock import FakeClock
from tests.support.inc2_fixture import open_kernel_job_runtime

OWNER = "dan"


def _ssh_enrollment() -> SignerEnrollment:
    raw = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", len(raw)) + raw
    line = "ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + " r2-app@devbox"
    return SignerEnrollment(owner_id=OWNER, channel=ApprovalChannel.SSH_KEY, public_key=line)


@dataclass
class _Ctx:
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
def rctx(trusted_tmp: Path) -> Iterator[_Ctx]:
    clock = FakeClock(datetime(2026, 11, 19, 10, 0, tzinfo=UTC))
    os_ = os_adapters(clock=clock)
    root = trusted_tmp / "data"
    checkout = trusted_tmp / "checkout"
    home = trusted_tmp / "home"
    checkout.mkdir()
    home.mkdir()
    os_.permissions.secure_directory(checkout)
    os_.permissions.secure_directory(home)
    rt = open_kernel_job_runtime(root, os_, role="i3-2-r2-app")
    try:
        signer = rt.policy.enroll_first_signer(_ssh_enrollment())
        proposals = StoreProposalAdapter(rt.store, os_)
        authority = PolicyApplyAuthority(rt.policy)
        svc = ReviewApplyService(
            proposals,
            authority,
            os_,
            data_root=root,
            home_dir=home,
            config_merger=SharedConfigMergerAdapter(),
        )
        yield _Ctx(
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


def _sign(
    c: _Ctx,
    prop: ChangeProposal,
    *,
    action: ApprovalAction,
    recovery_scope: RecoveryScope,
    target_files: tuple[Any, ...] | None = None,
    resource_digests: tuple[Any, ...] | None = None,
) -> ApprovalMessage:
    issued = c.rt.policy.issue_nonce(action=action, subject_id=prop.proposal_id, risk_level=prop.risk_level)
    return ApprovalMessage(
        store_id=c.rt.store.store_id,
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


def test_r01_wrong_digest_backup_restores_via_no_replace_and_keeps_concurrent_file(
    rctx: _Ctx, monkeypatch: pytest.MonkeyPatch
) -> None:
    """I3-2-R01.1: wrong-digest move must restore edited file via publish_no_replace or keep both."""
    tgt_a = rctx.checkout / "A1.md"
    tgt_a.write_bytes(b"U0 original\n")
    prop_a = rctx.svc.create_proposal(
        owner_id=OWNER,
        kind="bootstrap",
        reason="wrong digest restore empty target",
        resources=(RiskResource("c2"),),
        targets=(TargetWriteInput(rctx.checkout, "A1.md", b"U1 replacement\n", ManagedFormat.RAW, "r1"),),
    )

    real_pub = rctx.os_.publisher
    orig_publish = real_pub.publish

    def _race_empty(src: Path, dst: Path) -> None:
        if src == tgt_a:
            src.write_bytes(b"CONCURRENT EDIT A\n")
        orig_publish(src, dst)

    monkeypatch.setattr(real_pub, "publish", _race_empty)
    msg_a = _sign(rctx, prop_a, action=ApprovalAction.APPLY, recovery_scope=RecoveryScope.CONTINUE_OR_ROLLBACK)
    with pytest.raises(BrainError) as exc_a:
        rctx.svc.apply_proposal(
            prop_a.proposal_id, approval=msg_a, signer_id=rctx.signer.signer_id, channel=ApprovalChannel.SSH_KEY
        )
    monkeypatch.undo()
    assert exc_a.value.code in {ErrorCode.REVISION_CONFLICT, ErrorCode.INTEGRITY_FAILURE}
    assert tgt_a.is_file() and tgt_a.read_bytes() == b"CONCURRENT EDIT A\n"
    assert rctx.svc.get_proposal(prop_a.proposal_id).status is ProposalStatus.RECOVERY_REQUIRED

    # Case B: another user file occupies tgt_a right after move -> keep BOTH tgt_a AND backup, mark RECOVERY_REQUIRED.
    tgt_b = rctx.checkout / "B1.md"
    tgt_b.write_bytes(b"U0 B\n")
    prop_b = rctx.svc.create_proposal(
        owner_id=OWNER,
        kind="bootstrap",
        reason="wrong digest restore occupied target",
        resources=(RiskResource("c2"),),
        targets=(TargetWriteInput(rctx.checkout, "B1.md", b"U1 B\n", ManagedFormat.RAW, "r2"),),
    )

    def _race_occupied(src: Path, dst: Path) -> None:
        if src == tgt_b:
            src.write_bytes(b"CONCURRENT MOVE BYTES\n")
            orig_publish(src, dst)
            src.write_bytes(b"NEW OCCUPIER BYTES\n")
            return
        orig_publish(src, dst)

    monkeypatch.setattr(real_pub, "publish", _race_occupied)
    msg_b = _sign(rctx, prop_b, action=ApprovalAction.APPLY, recovery_scope=RecoveryScope.CONTINUE_OR_ROLLBACK)
    with pytest.raises(BrainError):
        rctx.svc.apply_proposal(
            prop_b.proposal_id, approval=msg_b, signer_id=rctx.signer.signer_id, channel=ApprovalChannel.SSH_KEY
        )
    monkeypatch.undo()
    assert tgt_b.read_bytes() == b"NEW OCCUPIER BYTES\n"
    p_b = rctx.svc.get_proposal(prop_b.proposal_id)
    assert p_b.status is ProposalStatus.RECOVERY_REQUIRED and p_b.active_journal_id is not None
    j_b = rctx.svc.get_journal(p_b.active_journal_id)
    bak_p = j_b.files[0].backup_path
    assert bak_p is not None and Path(bak_p).read_bytes() == b"CONCURRENT MOVE BYTES\n"


def test_r01_pins_replacement_physical_id_before_publish_and_closes_grant_before_store(
    rctx: _Ctx, monkeypatch: pytest.MonkeyPatch
) -> None:
    """I3-2-R01.2 & R01.3: pin staged replacement_physical_id BEFORE publish_no_replace & end grant BEFORE brain.db."""
    tgt = rctx.checkout / "PIN.md"
    tgt.write_bytes(b"U0 pin\n")
    prop = rctx.svc.create_proposal(
        owner_id=OWNER,
        kind="bootstrap",
        reason="pin + policy order",
        resources=(RiskResource("c2"),),
        targets=(TargetWriteInput(rctx.checkout, "PIN.md", b"U1 pin\n", ManagedFormat.RAW, "r1"),),
    )

    pub_nr = cast(NoReplacePublisher, rctx.os_.publisher)
    orig_nr = pub_nr.publish_no_replace
    seen_pinned: list[bool] = []
    events: list[str] = []

    def _spy_nr(staging: Path, final: Path) -> None:
        staged_id = stat_physical_identity(staging)
        p_now = rctx.svc.get_proposal(prop.proposal_id)
        assert staged_id is not None and p_now.active_journal_id is not None
        j_now = rctx.svc.get_journal(p_now.active_journal_id)
        seen_pinned.append(j_now.files[0].replacement_physical_id == staged_id.token())
        orig_nr(staging, final)

    orig_end = rctx.authority.end_recovery_grant
    orig_upd_j = rctx.proposals.update_journal
    orig_upd_p = rctx.proposals.update_proposal_status

    def _spy_end(*, grant_id: str, reason: str = "journal_closed", final_status: str) -> Any:
        events.append(f"end_grant:{final_status}")
        return orig_end(grant_id=grant_id, reason=reason, final_status=final_status)

    def _spy_upd_j(journal: ApplyJournal) -> ApplyJournal:
        if journal.status in (ProposalStatus.APPLIED, ProposalStatus.ROLLED_BACK):
            events.append(f"update_journal:{journal.status.value}")
        return orig_upd_j(journal)

    def _spy_upd_p(proposal_id: str, status: ProposalStatus, **kw: Any) -> ChangeProposal:
        if status in (ProposalStatus.APPLIED, ProposalStatus.ROLLED_BACK):
            events.append(f"update_proposal:{status.value}")
        return orig_upd_p(proposal_id, status, **kw)

    monkeypatch.setattr(pub_nr, "publish_no_replace", _spy_nr)
    monkeypatch.setattr(rctx.authority, "end_recovery_grant", _spy_end)
    monkeypatch.setattr(rctx.proposals, "update_journal", _spy_upd_j)
    monkeypatch.setattr(rctx.proposals, "update_proposal_status", _spy_upd_p)

    apply_msg = _sign(rctx, prop, action=ApprovalAction.APPLY, recovery_scope=RecoveryScope.CONTINUE_OR_ROLLBACK)
    rctx.svc.apply_proposal(
        prop.proposal_id, approval=apply_msg, signer_id=rctx.signer.signer_id, channel=ApprovalChannel.SSH_KEY
    )
    assert seen_pinned == [True], "replacement_physical_id must be durably pinned BEFORE publish_no_replace!"
    assert events.index("end_grant:applied") < events.index("update_journal:applied")
    assert events.index("end_grant:applied") < events.index("update_proposal:applied")

    # Verify same policy-before-store order on post-applied rollback.
    events.clear()
    monkeypatch.setattr(pub_nr, "publish_no_replace", orig_nr)
    plan = rctx.svc.plan_rollback_targets(prop.proposal_id)
    rb_msg = _sign(
        rctx,
        prop,
        action=ApprovalAction.ROLLBACK,
        recovery_scope=RecoveryScope.ROLLBACK,
        target_files=plan.target_files,
        resource_digests=plan.resource_digests,
    )
    rctx.svc.rollback_applied_proposal(
        prop.proposal_id, approval=rb_msg, signer_id=rctx.signer.signer_id, channel=ApprovalChannel.SSH_KEY, plan=plan
    )
    assert events.index("end_grant:rolled_back") < events.index("update_journal:rolled_back")
    assert events.index("end_grant:rolled_back") < events.index("update_proposal:rolled_back")


def test_r01_interrupted_rollback_planned_move_all_backups_first_fileexists_and_ended_grant(
    rctx: _Ctx, monkeypatch: pytest.MonkeyPatch
) -> None:
    """I3-2-R01.4: crash in PLANNED w/ bak-0, all-backup precheck before file 1, FileExistsError map, ended grant."""
    # 1. Crash after publish(tgt, bak-0) before ORIGINAL_MOVED leaves phase=PLANNED while tgt is missing & bak-0 exists.
    tgt_p = rctx.checkout / "CRASH_PLANNED.md"
    tgt_p.write_bytes(b"U0 crash planned\n")
    prop_p = rctx.svc.create_proposal(
        owner_id=OWNER,
        kind="bootstrap",
        reason="crash planned w/ backup",
        resources=(RiskResource("c2"),),
        targets=(TargetWriteInput(rctx.checkout, "CRASH_PLANNED.md", b"U1 rep\n", ManagedFormat.RAW, "r1"),),
    )
    real_pub = rctx.os_.publisher
    orig_publish = real_pub.publish

    def _crash_after_bak(src: Path, dst: Path) -> None:
        orig_publish(src, dst)
        if src == tgt_p:
            raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "crash before ORIGINAL_MOVED")

    monkeypatch.setattr(real_pub, "publish", _crash_after_bak)
    msg_p = _sign(rctx, prop_p, action=ApprovalAction.APPLY, recovery_scope=RecoveryScope.CONTINUE_OR_ROLLBACK)
    with pytest.raises(BrainError):
        rctx.svc.apply_proposal(
            prop_p.proposal_id, approval=msg_p, signer_id=rctx.signer.signer_id, channel=ApprovalChannel.SSH_KEY
        )
    monkeypatch.undo()
    assert not tgt_p.exists()
    j_p_id = rctx.svc.get_proposal(prop_p.proposal_id).active_journal_id
    assert j_p_id is not None

    # rollback_interrupted_journal MUST NEVER close as ROLLED_BACK leaving CRASH_PLANNED.md missing!
    try:
        res_j = rctx.svc.rollback_interrupted_journal(j_p_id)
        assert res_j.status is ProposalStatus.ROLLED_BACK
        assert tgt_p.is_file() and tgt_p.read_bytes() == b"U0 crash planned\n"
    except BrainError:
        assert rctx.svc.get_journal(j_p_id).status is ProposalStatus.RECOVERY_REQUIRED

    # 2. Missing backup on file 0 in 2-file PARTIALLY_APPLIED journal refuses BEFORE mutating file 1.
    rb0 = rctx.checkout / "RB0.md"
    rb1 = rctx.checkout / "RB1.md"
    rb0.write_bytes(b"U0 rb0\n")
    rb1.write_bytes(b"U0 rb1\n")
    prop_2 = rctx.svc.create_proposal(
        owner_id=OWNER,
        kind="bootstrap",
        reason="precheck all backups",
        resources=(RiskResource("c2"),),
        targets=(
            TargetWriteInput(rctx.checkout, "RB0.md", b"U1 rb0\n", ManagedFormat.RAW, "r0"),
            TargetWriteInput(rctx.checkout, "RB1.md", b"U1 rb1\n", ManagedFormat.RAW, "r1"),
            TargetWriteInput(rctx.checkout, "RB2.md", b"U1 rb2\n", ManagedFormat.RAW, "r2"),
        ),
    )
    pub_nr = cast(NoReplacePublisher, rctx.os_.publisher)
    orig_nr = pub_nr.publish_no_replace
    seen_nr = [0]

    def _stop_on_3rd(staging: Path, final: Path) -> None:
        seen_nr[0] += 1
        if seen_nr[0] == 3:
            raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "stop before 3rd")
        orig_nr(staging, final)

    monkeypatch.setattr(pub_nr, "publish_no_replace", _stop_on_3rd)
    msg_2 = _sign(rctx, prop_2, action=ApprovalAction.APPLY, recovery_scope=RecoveryScope.CONTINUE_OR_ROLLBACK)
    with pytest.raises(BrainError):
        rctx.svc.apply_proposal(
            prop_2.proposal_id, approval=msg_2, signer_id=rctx.signer.signer_id, channel=ApprovalChannel.SSH_KEY
        )
    monkeypatch.undo()
    j2_id = rctx.svc.get_proposal(prop_2.proposal_id).active_journal_id
    assert j2_id is not None
    j2 = rctx.svc.get_journal(j2_id)
    assert j2.files[0].backup_path is not None
    Path(j2.files[0].backup_path).unlink()

    with pytest.raises(BrainError):
        rctx.svc.rollback_interrupted_journal(j2_id)
    assert rb1.read_bytes() == b"U1 rb1\n", "MUST verify ALL backups before mutating RB1.md!"
    assert rctx.svc.get_journal(j2_id).status is ProposalStatus.RECOVERY_REQUIRED

    # 3. Late file before restore publish_no_replace maps FileExistsError -> REVISION_CONFLICT.
    f_late = rctx.checkout / "LATE_RESTORE.md"
    f_late.write_bytes(b"U0 late\n")
    prop_l = rctx.svc.create_proposal(
        owner_id=OWNER,
        kind="bootstrap",
        reason="late restore conflict",
        resources=(RiskResource("c2"),),
        targets=(
            TargetWriteInput(rctx.checkout, "LATE_RESTORE.md", b"U1 late\n", ManagedFormat.RAW, "l1"),
            TargetWriteInput(rctx.checkout, "LATE_NEXT.md", b"U1 next\n", ManagedFormat.RAW, "l2"),
        ),
    )
    seen_nr[0] = 0

    def _stop_on_2nd(staging: Path, final: Path) -> None:
        seen_nr[0] += 1
        if seen_nr[0] == 2:
            raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "stop")
        orig_nr(staging, final)

    monkeypatch.setattr(pub_nr, "publish_no_replace", _stop_on_2nd)
    msg_l = _sign(rctx, prop_l, action=ApprovalAction.APPLY, recovery_scope=RecoveryScope.CONTINUE_OR_ROLLBACK)
    with pytest.raises(BrainError):
        rctx.svc.apply_proposal(
            prop_l.proposal_id, approval=msg_l, signer_id=rctx.signer.signer_id, channel=ApprovalChannel.SSH_KEY
        )
    monkeypatch.undo()

    def _inject_late_at_restore(staging: Path, final: Path) -> None:
        if final == f_late and not final.exists():
            final.write_bytes(b"USER RACE BEFORE RESTORE\n")
        orig_nr(staging, final)

    monkeypatch.setattr(pub_nr, "publish_no_replace", _inject_late_at_restore)
    jl_id = rctx.svc.get_proposal(prop_l.proposal_id).active_journal_id
    assert jl_id is not None
    with pytest.raises(BrainError) as race_exc:
        rctx.svc.rollback_interrupted_journal(jl_id)
    monkeypatch.undo()
    assert race_exc.value.code is ErrorCode.REVISION_CONFLICT
    assert f_late.read_bytes() == b"USER RACE BEFORE RESTORE\n"
    assert rctx.svc.get_journal(jl_id).status is ProposalStatus.RECOVERY_REQUIRED

    # 4. Ended recovery_grant transitions interrupted journal & proposal to RECOVERY_REQUIRED.
    f_end = rctx.checkout / "ENDED_GRANT.md"
    f_end.write_bytes(b"U0 ended\n")
    prop_e = rctx.svc.create_proposal(
        owner_id=OWNER,
        kind="bootstrap",
        reason="ended grant check",
        resources=(RiskResource("c2"),),
        targets=(
            TargetWriteInput(rctx.checkout, "ENDED_GRANT.md", b"U1 ended\n", ManagedFormat.RAW, "e1"),
            TargetWriteInput(rctx.checkout, "ENDED_2.md", b"U1 e2\n", ManagedFormat.RAW, "e2"),
        ),
    )
    seen_nr[0] = 0
    monkeypatch.setattr(pub_nr, "publish_no_replace", _stop_on_2nd)
    msg_e = _sign(rctx, prop_e, action=ApprovalAction.APPLY, recovery_scope=RecoveryScope.CONTINUE_OR_ROLLBACK)
    with pytest.raises(BrainError):
        rctx.svc.apply_proposal(
            prop_e.proposal_id, approval=msg_e, signer_id=rctx.signer.signer_id, channel=ApprovalChannel.SSH_KEY
        )
    monkeypatch.undo()
    je_id = rctx.svc.get_proposal(prop_e.proposal_id).active_journal_id
    assert je_id is not None
    je = rctx.svc.get_journal(je_id)
    rctx.authority.end_recovery_grant(grant_id=je.grant_id, reason="trust_reset", final_status="recovery_required")
    with pytest.raises(BrainError):
        rctx.svc.rollback_interrupted_journal(je_id)
    assert rctx.svc.get_journal(je_id).status is ProposalStatus.RECOVERY_REQUIRED
    assert rctx.svc.get_proposal(prop_e.proposal_id).status is ProposalStatus.RECOVERY_REQUIRED
