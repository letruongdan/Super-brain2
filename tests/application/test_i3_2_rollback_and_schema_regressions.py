"""I3-2 Round-2 RED regressions for I3-2-R01.5/.6/.7 (applied rollback, multi-volume staging, manifests, v5 schema)."""

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

from superbrain.adapters.harness_config.markdown_blocks import merge_markdown_block
from superbrain.adapters.harness_config.merger import SharedConfigMergerAdapter
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
    SignerRecord,
)
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.proposals import ChangeProposal, ManagedFormat, ProposalStatus
from superbrain.ports.os import NoReplacePublisher, OsAdapters, PhysicalFsPort, PhysicalObjectId
from superbrain.storage.proposals import PolicyApplyAuthority, StoreProposalAdapter
from superbrain.storage.runtime import Runtime
from tests.support.clock import FakeClock
from tests.support.inc2_fixture import open_kernel_job_runtime

OWNER = "dan"


def _ssh_enrollment() -> SignerEnrollment:
    raw = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", len(raw)) + raw
    line = "ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + " r2-rb@devbox"
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
def rbctx(trusted_tmp: Path) -> Iterator[_Ctx]:
    clock = FakeClock(datetime(2026, 11, 19, 10, 15, tzinfo=UTC))
    os_ = os_adapters(clock=clock)
    root = trusted_tmp / "data"
    checkout = trusted_tmp / "checkout"
    home = trusted_tmp / "home"
    checkout.mkdir()
    home.mkdir()
    os_.permissions.secure_directory(checkout)
    os_.permissions.secure_directory(home)
    rt = open_kernel_job_runtime(root, os_, role="i3-2-r2-rb")
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


def test_r07_store_v5_has_no_dead_unused_proposal_tables(rbctx: _Ctx) -> None:
    """I3-2-R07: store v5 MUST NOT carry empty unused proposal/journal/manifest tables alongside p_proposals_*."""
    with rbctx.rt.store.transaction() as txn:
        rows = txn.db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    names = {str(r[0]) for r in rows}
    dead = {"proposals", "proposal_targets", "apply_journals", "apply_journal_files", "managed_slice_manifests"}
    assert names.isdisjoint(dead), f"dead unused tables still present: {names & dead}"
    assert {"p_proposals_proposals", "p_proposals_journals", "p_proposals_manifests"} <= names


def test_r01_applied_rollback_rolling_back_fileexists_multi_volume_and_manifest(
    trusted_tmp: Path, rbctx: _Ctx, monkeypatch: pytest.MonkeyPatch
) -> None:
    """I3-2-R01.5/.6/.7: ROLLING_BACK + FileExistsError, multi-volume staging, required manifest & target_root."""
    # 1. Structured target without managed_slice_digest MUST be refused at creation.
    (rbctx.checkout / "S1.md").write_text("# S1\n", encoding="utf-8", newline="\n")
    with pytest.raises(BrainError) as noman_exc:
        rbctx.svc.create_proposal(
            owner_id=OWNER,
            kind="bootstrap",
            reason="missing slice digest",
            resources=(RiskResource("c2"),),
            targets=(TargetWriteInput(rbctx.checkout, "S1.md", b"# S1\n", ManagedFormat.MARKDOWN, "s1", None),),
        )
    assert noman_exc.value.code is ErrorCode.INVALID_INPUT

    # 2. Multi-volume proposal across two distinct target roots stages each on its own volume.
    root2_parent = trusted_tmp / "vol2-parent"
    root2_parent.mkdir()
    rbctx.os_.permissions.secure_directory(root2_parent)
    root2 = root2_parent / "repo-vol2"
    root2.mkdir()
    (rbctx.checkout / "SHARED.md").write_text("# Root1\n", encoding="utf-8", newline="\n")
    (root2 / "SHARED.md").write_text("# Root2\n", encoding="utf-8", newline="\n")
    m1 = merge_markdown_block("# Root1\n", slice_id="same-id", block_body="Body1", expected_slice_digest=None)
    m2 = merge_markdown_block("# Root2\n", slice_id="same-id", block_body="Body2", expected_slice_digest=None)

    base_phys = rbctx.os_.physical
    assert base_phys is not None
    phys_port: PhysicalFsPort = base_phys

    class _TwoVolumePhys:
        def stat_physical_identity(self, path: Path) -> PhysicalObjectId | None:
            return phys_port.stat_physical_identity(path)

        def same_volume(self, first: Path, second: Path) -> bool:
            def _in_root2(p: Path) -> bool:
                rp = p.resolve()
                rr2 = root2.resolve()
                return rp == rr2 or rr2 in rp.parents

            return not (_in_root2(first) ^ _in_root2(second)) and phys_port.same_volume(first, second)

    mv_os = OsAdapters(
        paths=rbctx.os_.paths,
        permissions=rbctx.os_.permissions,
        publisher=rbctx.os_.publisher,
        locks=rbctx.os_.locks,
        clock=rbctx.os_.clock,
        traits=rbctx.os_.traits,
        monotonic=rbctx.os_.monotonic,
        physical=_TwoVolumePhys(),
    )
    mv_svc = ReviewApplyService(
        rbctx.proposals,
        rbctx.authority,
        mv_os,
        data_root=rbctx.root,
        home_dir=rbctx.home,
        config_merger=SharedConfigMergerAdapter(),
    )
    mv_prop = mv_svc.create_proposal(
        owner_id=OWNER,
        kind="bootstrap",
        reason="multi-volume + multi-root manifest",
        resources=(RiskResource("c2"),),
        targets=(
            TargetWriteInput(
                rbctx.checkout,
                "SHARED.md",
                m1.updated_text.encode(),
                ManagedFormat.MARKDOWN,
                "same-id",
                m1.slice_digest,
            ),
            TargetWriteInput(
                root2,
                "SHARED.md",
                m2.updated_text.encode(),
                ManagedFormat.MARKDOWN,
                "same-id",
                m2.slice_digest,
            ),
        ),
    )
    mv_apply = _sign(rbctx, mv_prop, action=ApprovalAction.APPLY, recovery_scope=RecoveryScope.CONTINUE_OR_ROLLBACK)
    mv_journal = mv_svc.apply_proposal(
        mv_prop.proposal_id, approval=mv_apply, signer_id=rbctx.signer.signer_id, channel=ApprovalChannel.SSH_KEY
    )
    assert Path(mv_journal.files[0].replacement_staging_path).is_relative_to(rbctx.root)
    assert Path(mv_journal.files[1].replacement_staging_path).is_relative_to(root2_parent)
    manifests = rbctx.proposals.list_manifests(mv_prop.proposal_id)
    assert {m.slice_digest for m in manifests} == {m1.slice_digest, m2.slice_digest}

    # 3. Applied rollback transitions proposal to ROLLING_BACK before publish_no_replace, AND maps FileExistsError.
    seen_rb_status: list[ProposalStatus] = []
    pub_nr = cast(NoReplacePublisher, mv_os.publisher)
    orig_nr = pub_nr.publish_no_replace

    def _spy_rb(staging: Path, final: Path) -> None:
        seen_rb_status.append(mv_svc.get_proposal(mv_prop.proposal_id).status)
        orig_nr(staging, final)

    monkeypatch.setattr(pub_nr, "publish_no_replace", _spy_rb)
    plan_mv = mv_svc.plan_rollback_targets(mv_prop.proposal_id)
    rb_mv = _sign(
        rbctx,
        mv_prop,
        action=ApprovalAction.ROLLBACK,
        recovery_scope=RecoveryScope.ROLLBACK,
        target_files=plan_mv.target_files,
        resource_digests=plan_mv.resource_digests,
    )
    mv_svc.rollback_applied_proposal(
        mv_prop.proposal_id,
        approval=rb_mv,
        signer_id=rbctx.signer.signer_id,
        channel=ApprovalChannel.SSH_KEY,
        plan=plan_mv,
    )
    monkeypatch.undo()
    assert seen_rb_status and all(st is ProposalStatus.ROLLING_BACK for st in seen_rb_status)

    # Applied rollback late FileExistsError -> REVISION_CONFLICT + RECOVERY_REQUIRED keeping late file & backup.
    late_tgt = rbctx.checkout / "RB_RACE.md"
    late_tgt.write_bytes(b"U0 rb race\n")
    p_race = rbctx.svc.create_proposal(
        owner_id=OWNER,
        kind="bootstrap",
        reason="applied rollback late file race",
        resources=(RiskResource("c2"),),
        targets=(TargetWriteInput(rbctx.checkout, "RB_RACE.md", b"U1 rb race\n", ManagedFormat.RAW, "r1"),),
    )
    ap_race = _sign(rbctx, p_race, action=ApprovalAction.APPLY, recovery_scope=RecoveryScope.CONTINUE_OR_ROLLBACK)
    rbctx.svc.apply_proposal(
        p_race.proposal_id, approval=ap_race, signer_id=rbctx.signer.signer_id, channel=ApprovalChannel.SSH_KEY
    )
    plan_race = rbctx.svc.plan_rollback_targets(p_race.proposal_id)
    msg_race = _sign(
        rbctx,
        p_race,
        action=ApprovalAction.ROLLBACK,
        recovery_scope=RecoveryScope.ROLLBACK,
        target_files=plan_race.target_files,
        resource_digests=plan_race.resource_digests,
    )
    svc_nr = cast(NoReplacePublisher, rbctx.os_.publisher)
    orig_svc_nr = svc_nr.publish_no_replace

    def _inject_applied_rb_race(staging: Path, final: Path) -> None:
        if final == late_tgt and not final.exists():
            final.write_bytes(b"LATE USER APPLIED RB\n")
        orig_svc_nr(staging, final)

    monkeypatch.setattr(svc_nr, "publish_no_replace", _inject_applied_rb_race)
    with pytest.raises(BrainError) as app_race_exc:
        rbctx.svc.rollback_applied_proposal(
            p_race.proposal_id,
            approval=msg_race,
            signer_id=rbctx.signer.signer_id,
            channel=ApprovalChannel.SSH_KEY,
            plan=plan_race,
        )
    monkeypatch.undo()
    assert app_race_exc.value.code is ErrorCode.REVISION_CONFLICT
    assert late_tgt.read_bytes() == b"LATE USER APPLIED RB\n"
    p_race_after = rbctx.svc.get_proposal(p_race.proposal_id)
    assert p_race_after.status is ProposalStatus.RECOVERY_REQUIRED and p_race_after.active_journal_id is not None
    j_race = rbctx.svc.get_journal(p_race_after.active_journal_id)
    assert j_race.files[0].backup_path is not None and Path(j_race.files[0].backup_path).read_bytes() == b"U1 rb race\n"

    # 4. Out-of-band non-UTF-8 fails cleanly; missing manifest fails closed.
    b_path = rbctx.checkout / "DOC.md"
    b_path.write_text("# Doc\n", encoding="utf-8", newline="\n")
    mb = merge_markdown_block("# Doc\n", slice_id="doc-s", block_body="Rule", expected_slice_digest=None)
    p_doc = rbctx.svc.create_proposal(
        owner_id=OWNER,
        kind="bootstrap",
        reason="missing manifest / bad utf8",
        resources=(RiskResource("c2"),),
        targets=(
            TargetWriteInput(
                rbctx.checkout, "DOC.md", mb.updated_text.encode(), ManagedFormat.MARKDOWN, "doc-s", mb.slice_digest
            ),
        ),
    )
    ap_doc = _sign(rbctx, p_doc, action=ApprovalAction.APPLY, recovery_scope=RecoveryScope.CONTINUE_OR_ROLLBACK)
    rbctx.svc.apply_proposal(
        p_doc.proposal_id, approval=ap_doc, signer_id=rbctx.signer.signer_id, channel=ApprovalChannel.SSH_KEY
    )
    b_path.write_bytes(b"\xff\xfeinvalid-utf8")
    with pytest.raises(BrainError):
        rbctx.svc.plan_rollback_targets(p_doc.proposal_id)

    b_path.write_text(mb.updated_text + "\n## U1 extra\n", encoding="utf-8", newline="\n")
    monkeypatch.setattr(rbctx.proposals, "list_manifests", lambda _pid: ())
    with pytest.raises(BrainError) as missing_man_exc:
        rbctx.svc.plan_rollback_targets(p_doc.proposal_id)
    assert missing_man_exc.value.code in {ErrorCode.REVISION_CONFLICT, ErrorCode.INTEGRITY_FAILURE}
