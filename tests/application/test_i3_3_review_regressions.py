"""I3-3 Round-2 RED regressions for review findings I3-3-R01..I3-3-R04.

Covers:
- I3-3-R01: stage_apply_journal preserving ProposalTarget.parent_physical_id across swapped parent dir,
  enforcing Q25 during recovery staging, reject_links before staged existence/secure_file, and
  plan_rollback_targets/stage_applied_rollback_journal parent_physical_id checks.
- I3-3-R02: rollback.after_policy_turn_intent binding strictly to signed ApprovalMessage in policy.db,
  blocking staging under already-ended grants, and _save_recovery_marker closing active grants.
- I3-3-R03: applied & interrupted rollback crash classifiers recovering cleanly after publish/restore
  before per-entry phase save, plus Case 106 refusal on identical bytes with new PhysicalObjectId.
- I3-3-R04: Case 93 _verify_rolled_back_on_disk enforcing original_physical_id & parent_physical_id,
  and _verify_applied_on_disk enforcing parent_physical_id across swapped parents.
"""

from __future__ import annotations

import base64
import os
import struct
import sys
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
from superbrain.application._review_apply_continue import stage_apply_journal
from superbrain.application._review_apply_ops import select_staging_dir, target_path
from superbrain.application._review_apply_rollback import stage_applied_rollback_journal
from superbrain.application.journal_recovery import reconcile_and_classify_journals
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
    canonical_utc,
)
from superbrain.core._kernel_base import ResourceDigest
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.proposals import (
    ApplyJournal,
    ChangeProposal,
    FileJournalEntry,
    FileJournalPhase,
    FileOriginalState,
    JournalDirection,
    ManagedFormat,
    ProposalStatus,
    ProposalTarget,
)
from superbrain.ports.os import NoReplacePublisher, OsAdapters
from superbrain.storage.proposals import PolicyApplyAuthority, StoreProposalAdapter
from superbrain.storage.runtime import Runtime
from tests.support.clock import FakeClock
from tests.support.inc2_fixture import open_kernel_job_runtime

OWNER = "dan"


def _ssh_enrollment(tag: str = "r2") -> SignerEnrollment:
    raw = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", len(raw)) + raw
    return SignerEnrollment(
        owner_id=OWNER,
        channel=ApprovalChannel.SSH_KEY,
        public_key="ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + f" {tag}@devbox",
    )


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

    def now_str(self) -> str:
        return str(canonical_utc(self.clock.now()))


@pytest.fixture
def ctx(trusted_tmp: Path) -> Iterator[Ctx]:
    clock = FakeClock(datetime(2026, 11, 19, 12, 0, tzinfo=UTC))
    os_ = os_adapters(clock=clock)
    root, checkout, home = trusted_tmp / "data", trusted_tmp / "checkout", trusted_tmp / "home"
    for d in (checkout, home):
        d.mkdir(parents=True, exist_ok=True)
        os_.permissions.secure_directory(d)
    rt = open_kernel_job_runtime(root, os_, role="i3-3-r2")
    try:
        signer = rt.policy.enroll_first_signer(_ssh_enrollment())
        proposals, authority = StoreProposalAdapter(rt.store, os_), PolicyApplyAuthority(rt.policy)
        svc = ReviewApplyService(
            proposals, authority, os_, data_root=root, home_dir=home, config_merger=SharedConfigMergerAdapter()
        )
        yield Ctx(rt, root, checkout, home, clock, os_, signer, proposals, authority, svc)
    finally:
        rt.close()


def _sign(
    c: Ctx,
    prop: ChangeProposal,
    *,
    action: ApprovalAction = ApprovalAction.APPLY,
    recovery_scope: RecoveryScope = RecoveryScope.CONTINUE_OR_ROLLBACK,
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


def _reconcile(c: Ctx, *, home_dir: Path | None = None) -> Any:
    return reconcile_and_classify_journals(
        c.proposals,
        c.authority,
        c.os_,
        data_root=c.root,
        home_dir=c.home if home_dir is None else home_dir,
        config_merger=SharedConfigMergerAdapter(),
        now_utc_fn=c.now_str,
    )


def test_r01_parent_swap_after_turn_intent_and_rollback_planning_and_staged_link_order(
    ctx: Ctx, trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # 1. Parent directory replaced after apply.after_policy_turn_intent on original=ABSENT target -> RECOVERY_REQUIRED.
    sub = ctx.checkout / "sub"
    sub.mkdir()
    ctx.os_.permissions.secure_directory(sub)
    prop = ctx.svc.create_proposal(
        owner_id=OWNER, kind="bootstrap", reason="r01 parent swap", resources=(RiskResource("c2"),),
        targets=(TargetWriteInput(ctx.checkout, "sub/new.md", b"# Approved\n", ManagedFormat.RAW, "r1"),),
    )
    msg = _sign(ctx, prop)
    rec = ctx.authority.consume_approval(msg, signer_id=ctx.signer.signer_id, channel=ApprovalChannel.SSH_KEY)
    jid = new_id()
    ctx.authority.begin_journal_turn(approval_id=rec.approval_id, journal_id=jid, direction=JournalDirection.APPLY)

    swapped_old = ctx.checkout / "sub-old"
    sub.rename(swapped_old)
    sub.mkdir()
    ctx.os_.permissions.secure_directory(sub)
    rep = _reconcile(ctx)
    assert rep.recovery_required_journals == 1 and rep.continued_journals == 0
    assert ctx.proposals.get_proposal(prop.proposal_id).status is ProposalStatus.RECOVERY_REQUIRED
    grant = ctx.authority.find_recovery_grant_for_journal(jid)
    assert grant is not None and grant.state == "ended"
    assert not (sub / "new.md").exists()

    # 2. Moving applied file into a swapped parent directory -> plan_rollback_targets & stage_applied_rollback refuse.
    sub_b = ctx.checkout / "sub_b"
    sub_b.mkdir()
    ctx.os_.permissions.secure_directory(sub_b)
    (sub_b / "f.md").write_bytes(b"u0\n")
    prop_b = ctx.svc.create_proposal(
        owner_id=OWNER, kind="bootstrap", reason="r01 rb parent", resources=(RiskResource("c2"),),
        targets=(TargetWriteInput(ctx.checkout, "sub_b/f.md", b"u1\n", ManagedFormat.RAW, "rb"),),
    )
    ctx.svc.apply_proposal(
        prop_b.proposal_id, approval=_sign(ctx, prop_b), signer_id=ctx.signer.signer_id, channel=ApprovalChannel.SSH_KEY
    )
    plan_before = ctx.svc.plan_rollback_targets(prop_b.proposal_id)
    sub_b_old = ctx.checkout / "sub_b_old"
    sub_b.rename(sub_b_old)
    sub_b.mkdir()
    ctx.os_.permissions.secure_directory(sub_b)
    os.replace(sub_b_old / "f.md", sub_b / "f.md")
    with pytest.raises(BrainError) as plan_exc:
        ctx.svc.plan_rollback_targets(prop_b.proposal_id)
    assert plan_exc.value.code in {ErrorCode.UNSAFE_PATH, ErrorCode.REVISION_CONFLICT}

    rb_msg = _sign(
        ctx, prop_b, action=ApprovalAction.ROLLBACK, recovery_scope=RecoveryScope.ROLLBACK,
        target_files=plan_before.target_files, resource_digests=plan_before.resource_digests,
    )
    rb_rec = ctx.authority.consume_approval(rb_msg, signer_id=ctx.signer.signer_id, channel=ApprovalChannel.SSH_KEY)
    rb_jid = new_id()
    rb_grant, _ = ctx.authority.begin_journal_turn(
        approval_id=rb_rec.approval_id, journal_id=rb_jid, direction=JournalDirection.ROLLBACK
    )
    with pytest.raises(BrainError) as stg_exc:
        stage_applied_rollback_journal(
            ctx.proposals, ctx.os_, prop=ctx.proposals.get_proposal(prop_b.proposal_id),
            plan=plan_before, journal_id=rb_jid, grant=rb_grant, data_root=ctx.root, now_utc=ctx.now_str(),
        )
    assert stg_exc.value.code in {ErrorCode.UNSAFE_PATH, ErrorCode.REVISION_CONFLICT}
    ctx.authority.end_recovery_grant(
        grant_id=rb_grant.grant_id, reason="journal_closed", final_status="recovery_required"
    )

    # 3. reject_links MUST run BEFORE staged.exists() / secure_file(staged) in stage_apply_journal.
    victim = trusted_tmp / "victim-dir"
    victim.mkdir()
    (ctx.checkout / "lnk.md").write_bytes(b"u0\n")
    prop_l = ctx.svc.create_proposal(
        owner_id=OWNER, kind="bootstrap", reason="r01 staged link", resources=(RiskResource("c2"),),
        targets=(TargetWriteInput(ctx.checkout, "lnk.md", b"u1\n", ManagedFormat.RAW, "rl"),),
    )
    rec_l = ctx.authority.consume_approval(
        _sign(ctx, prop_l), signer_id=ctx.signer.signer_id, channel=ApprovalChannel.SSH_KEY
    )
    jid_l = new_id()
    grant_l, _ = ctx.authority.begin_journal_turn(
        approval_id=rec_l.approval_id, journal_id=jid_l, direction=JournalDirection.APPLY
    )
    stg_dir = select_staging_dir(ctx.checkout, ctx.root, jid_l, OWNER, ctx.os_)
    staged_path = stg_dir / "rep-0"
    _make_dir_link(staged_path, victim)
    order: list[str] = []
    orig_reject = ctx.os_.paths.reject_links
    orig_secure = ctx.os_.permissions.secure_file

    def _spy_reject(path: Path, entries: Any = None) -> None:
        if path == staged_path:
            order.append("reject_links")
        orig_reject(path, entries=entries)

    def _spy_secure(path: Path) -> None:
        if path == staged_path:
            order.append("secure_file")
        orig_secure(path)

    monkeypatch.setattr(ctx.os_.paths, "reject_links", _spy_reject)
    monkeypatch.setattr(ctx.os_.permissions, "secure_file", _spy_secure)
    with pytest.raises(BrainError) as lnk_exc:
        stage_apply_journal(
            ctx.proposals, ctx.os_, prop=ctx.proposals.get_proposal(prop_l.proposal_id),
            journal_id=jid_l, grant=grant_l, data_root=ctx.root, now_utc=ctx.now_str(),
        )
    assert lnk_exc.value.code is ErrorCode.UNSAFE_PATH
    assert order == ["reject_links"]
    ctx.authority.end_recovery_grant(
        grant_id=grant_l.grant_id, reason="journal_closed", final_status="recovery_required"
    )

    # 3b. reject_links MUST also run BEFORE staged.exists() / secure_file in stage_applied_rollback_journal.
    ctx.svc.apply_proposal(
        prop_l.proposal_id, approval=_sign(ctx, prop_l), signer_id=ctx.signer.signer_id, channel=ApprovalChannel.SSH_KEY
    )
    plan_l = ctx.svc.plan_rollback_targets(prop_l.proposal_id)
    rb_l_rec = ctx.authority.consume_approval(
        _sign(
            ctx, ctx.proposals.get_proposal(prop_l.proposal_id), action=ApprovalAction.ROLLBACK,
            recovery_scope=RecoveryScope.ROLLBACK, target_files=plan_l.target_files,
            resource_digests=plan_l.resource_digests,
        ),
        signer_id=ctx.signer.signer_id, channel=ApprovalChannel.SSH_KEY,
    )
    rb_l_jid = new_id()
    rb_l_grant, _ = ctx.authority.begin_journal_turn(
        approval_id=rb_l_rec.approval_id, journal_id=rb_l_jid, direction=JournalDirection.ROLLBACK
    )
    rb_stg_dir = select_staging_dir(ctx.checkout, ctx.root, rb_l_jid, OWNER, ctx.os_)
    staged_path = rb_stg_dir / "rb-rep-0"
    _make_dir_link(staged_path, victim)
    order.clear()
    with pytest.raises(BrainError) as rb_lnk_exc:
        stage_applied_rollback_journal(
            ctx.proposals, ctx.os_, prop=ctx.proposals.get_proposal(prop_l.proposal_id),
            plan=plan_l, journal_id=rb_l_jid, grant=rb_l_grant, data_root=ctx.root, now_utc=ctx.now_str(),
        )
    assert rb_lnk_exc.value.code is ErrorCode.UNSAFE_PATH
    assert order == ["reject_links"]
    ctx.authority.end_recovery_grant(
        grant_id=rb_l_grant.grant_id, reason="journal_closed", final_status="recovery_required"
    )

    # 4. Q25 check inside stage_apply_journal (seeded directly in brain.db without weakening create_proposal).
    phys = ctx.os_.physical
    assert phys is not None
    skill_root = ctx.home / ".claude" / "skills" / "bad-skill"
    skill_root.mkdir(parents=True)
    for sd in (ctx.home / ".claude", ctx.home / ".claude" / "skills", skill_root):
        ctx.os_.permissions.secure_directory(sd)
    skill_file = skill_root / "a.md"
    skill_file.write_bytes(b"u0\n")
    p_sk, f_sk = phys.stat_physical_identity(skill_root), phys.stat_physical_identity(skill_file)
    assert p_sk is not None and f_sk is not None
    d_u0, d_rep = digest_bytes(b"u0\n"), digest_bytes(b"hijack\n")
    pid_q = new_id()
    pt_q = ProposalTarget(
        "a.md", "a.md", ManagedFormat.RAW, "rq", True, d_u0, f_sk.token(), d_rep, None, str(skill_root), p_sk.token()
    )
    prop_q_seed = ChangeProposal(
        pid_q, OWNER, "bootstrap", "r01 q25", ProposalStatus.PENDING, 1, RiskLevel.HIGH,
        (RiskResource("c2"),), (ResourceDigest("resources", digest_bytes(b"[]")), ResourceDigest("target:0", d_rep)),
        (pt_q,), ctx.now_str(), ctx.now_str(),
    )
    ctx.proposals.create_proposal(prop_q_seed, {d_u0: b"u0\n", d_rep: b"hijack\n"})
    ctx.proposals.update_proposal_status(pid_q, ProposalStatus.APPROVED, subject_revision=1, updated_at=ctx.now_str())
    prop_q = ctx.proposals.get_proposal(pid_q)
    rec_q = ctx.authority.consume_approval(
        _sign(ctx, prop_q), signer_id=ctx.signer.signer_id, channel=ApprovalChannel.SSH_KEY
    )
    jid_q = new_id()
    ctx.authority.begin_journal_turn(approval_id=rec_q.approval_id, journal_id=jid_q, direction=JournalDirection.APPLY)
    rep_q = _reconcile(ctx, home_dir=ctx.home)
    assert rep_q.recovery_required_journals == 1 and rep_q.continued_journals == 0
    assert skill_file.read_bytes() == b"u0\n"
    grant_q = ctx.authority.find_recovery_grant_for_journal(jid_q)
    assert grant_q is not None and grant_q.state == "ended"


def test_r02_rollback_turn_recovery_binds_signed_approval_and_skips_ended_grant_staging(ctx: Ctx) -> None:
    claude = ctx.checkout / "CLAUDE.md"
    claude.write_text("# User v1\n", encoding="utf-8", newline="\n")
    merged = merge_markdown_block("# User v1\n", slice_id="s1", block_body="Managed body.", expected_slice_digest=None)
    prop = ctx.svc.create_proposal(
        owner_id=OWNER, kind="bootstrap", reason="r02 rb approval binding", resources=(RiskResource("c2"),),
        targets=(
            TargetWriteInput(
                ctx.checkout, "CLAUDE.md", merged.updated_text.encode("utf-8"),
                ManagedFormat.MARKDOWN, "s1", merged.slice_digest,
            ),
        ),
    )
    ctx.svc.apply_proposal(
        prop.proposal_id, approval=_sign(ctx, prop), signer_id=ctx.signer.signer_id, channel=ApprovalChannel.SSH_KEY
    )
    applied_prop = ctx.proposals.get_proposal(prop.proposal_id)
    plan = ctx.svc.plan_rollback_targets(prop.proposal_id)
    rb_msg = _sign(
        ctx, applied_prop, action=ApprovalAction.ROLLBACK, recovery_scope=RecoveryScope.ROLLBACK,
        target_files=plan.target_files, resource_digests=plan.resource_digests,
    )
    rb_rec = ctx.authority.consume_approval(rb_msg, signer_id=ctx.signer.signer_id, channel=ApprovalChannel.SSH_KEY)
    rb_jid = new_id()
    ctx.authority.begin_journal_turn(
        approval_id=rb_rec.approval_id, journal_id=rb_jid, direction=JournalDirection.ROLLBACK
    )

    # Replace CLAUDE.md with a new inode containing out-of-band edit AFTER rollback approval, before restart.
    edited = "# User v2 EDITED AFTER APPROVAL\n" + claude.read_text(encoding="utf-8")
    tmp_edit = ctx.checkout / "CLAUDE.tmp"
    tmp_edit.write_text(edited, encoding="utf-8", newline="\n")
    os.replace(tmp_edit, claude)

    rep = _reconcile(ctx)
    assert rep.recovery_required_journals == 1 and rep.rolled_back_journals == 0
    assert ctx.proposals.get_proposal(prop.proposal_id).status is ProposalStatus.RECOVERY_REQUIRED
    assert claude.read_text(encoding="utf-8") == edited
    grant = ctx.authority.find_recovery_grant_for_journal(rb_jid)
    assert grant is not None and grant.state == "ended"

    # Ended grant ("journal_closed") with missing journal in brain.db must NOT stage files on disk.
    (ctx.checkout / "ENDED.md").write_bytes(b"u0\n")
    prop_e = ctx.svc.create_proposal(
        owner_id=OWNER, kind="bootstrap", reason="r02 ended grant", resources=(RiskResource("c2"),),
        targets=(TargetWriteInput(ctx.checkout, "ENDED.md", b"u1\n", ManagedFormat.RAW, "re"),),
    )
    rec_e = ctx.authority.consume_approval(
        _sign(ctx, prop_e), signer_id=ctx.signer.signer_id, channel=ApprovalChannel.SSH_KEY
    )
    jid_e = new_id()
    g_e, _ = ctx.authority.begin_journal_turn(
        approval_id=rec_e.approval_id, journal_id=jid_e, direction=JournalDirection.APPLY
    )
    ctx.authority.end_recovery_grant(grant_id=g_e.grant_id, reason="journal_closed", final_status="applied")
    rep_e = _reconcile(ctx)
    assert rep_e.recovery_required_journals >= 1 and rep_e.continued_journals == 0
    assert not (ctx.root / "apply_staging" / jid_e).exists()
    assert (ctx.checkout / "ENDED.md").read_bytes() == b"u0\n"


def test_r03_applied_and_interrupted_rollback_recover_post_publish_before_phase_save(ctx: Ctx) -> None:
    phys = ctx.os_.physical
    assert phys is not None

    # 1. Applied rollback crashed after publish_no_replace(rb-rep-0, tgt) BEFORE saving REPLACEMENT_PUBLISHED.
    f_a = ctx.checkout / "a.txt"
    f_a.write_bytes(b"orig-a\n")
    prop_a = ctx.svc.create_proposal(
        owner_id=OWNER, kind="bootstrap", reason="r03 applied rb", resources=(RiskResource("c2"),),
        targets=(TargetWriteInput(ctx.checkout, "a.txt", b"rep-a\n", ManagedFormat.RAW, "ra"),),
    )
    ctx.svc.apply_proposal(
        prop_a.proposal_id, approval=_sign(ctx, prop_a), signer_id=ctx.signer.signer_id, channel=ApprovalChannel.SSH_KEY
    )
    plan_a = ctx.svc.plan_rollback_targets(prop_a.proposal_id)
    rb_msg_a = _sign(
        ctx, ctx.proposals.get_proposal(prop_a.proposal_id), action=ApprovalAction.ROLLBACK,
        recovery_scope=RecoveryScope.ROLLBACK, target_files=plan_a.target_files,
        resource_digests=plan_a.resource_digests,
    )
    rb_rec_a = ctx.authority.consume_approval(rb_msg_a, signer_id=ctx.signer.signer_id, channel=ApprovalChannel.SSH_KEY)
    rb_jid_a = new_id()
    rb_grant_a, _ = ctx.authority.begin_journal_turn(
        approval_id=rb_rec_a.approval_id, journal_id=rb_jid_a, direction=JournalDirection.ROLLBACK
    )
    j_a = stage_applied_rollback_journal(
        ctx.proposals, ctx.os_, prop=ctx.proposals.get_proposal(prop_a.proposal_id),
        plan=plan_a, journal_id=rb_jid_a, grant=rb_grant_a, data_root=ctx.root, now_utc=ctx.now_str(),
    )
    rb_bak_0 = Path(j_a.staging_dir) / "rb-bak-0"
    pub = cast(NoReplacePublisher, ctx.os_.publisher)
    ctx.os_.publisher.publish(f_a, rb_bak_0)
    pub.publish_no_replace(Path(j_a.files[0].replacement_staging_path), f_a)
    ctx.proposals.update_journal(ApplyJournal(
        j_a.journal_id, j_a.proposal_id, JournalDirection.ROLLBACK, ProposalStatus.ROLLING_BACK,
        j_a.grant_id, j_a.staging_dir,
        (FileJournalEntry(
            j_a.files[0].normalized_rel_path, j_a.files[0].target_root, j_a.files[0].managed_format,
            j_a.files[0].slice_id, FileOriginalState.PRESENT, FileJournalPhase.ORIGINAL_MOVED,
            j_a.files[0].original_digest, j_a.files[0].original_physical_id, j_a.files[0].replacement_digest,
            j_a.files[0].replacement_staging_path, str(rb_bak_0), j_a.files[0].replacement_physical_id,
            j_a.files[0].parent_physical_id,
        ),),
        j_a.created_at, ctx.now_str(),
    ))
    rep_a = _reconcile(ctx)
    assert rep_a.rolled_back_journals == 1 and rep_a.recovery_required_journals == 0
    assert ctx.proposals.get_proposal(prop_a.proposal_id).status is ProposalStatus.ROLLED_BACK
    assert f_a.read_bytes() == b"orig-a\n"

    # 2. Interrupted-apply rollback crashed after publish_no_replace(bak-0, tgt) BEFORE saving RESTORED.
    f_b = ctx.checkout / "b.txt"
    f_b.write_bytes(b"orig-b\n")
    orig_b_id = phys.stat_physical_identity(f_b)
    p_b_id = phys.stat_physical_identity(ctx.checkout)
    assert orig_b_id is not None and p_b_id is not None
    prop_b = ctx.svc.create_proposal(
        owner_id=OWNER, kind="bootstrap", reason="r03 int rb", resources=(RiskResource("c2"),),
        targets=(TargetWriteInput(ctx.checkout, "b.txt", b"rep-b\n", ManagedFormat.RAW, "rb"),),
    )
    rec_b = ctx.authority.consume_approval(
        _sign(ctx, prop_b), signer_id=ctx.signer.signer_id, channel=ApprovalChannel.SSH_KEY
    )
    jid_b = new_id()
    g_b, _ = ctx.authority.begin_journal_turn(
        approval_id=rec_b.approval_id, journal_id=jid_b, direction=JournalDirection.APPLY
    )
    stg_b = select_staging_dir(ctx.checkout, ctx.root, jid_b, OWNER, ctx.os_)
    bak_b = stg_b / "bak-0"
    hold_b = stg_b / "rb-hold-0"
    ctx.os_.publisher.publish(f_b, bak_b)
    ctx.os_.publisher.write_new(hold_b, b"rep-b\n")
    ctx.os_.permissions.secure_file(hold_b)
    hold_b_id = phys.stat_physical_identity(hold_b)
    assert hold_b_id is not None
    pub.publish_no_replace(bak_b, f_b)  # original restored, bak_b gone, phase not yet RESTORED
    ctx.authority.open_turn_intent(journal_id=jid_b, approval_id=rec_b.approval_id, direction=JournalDirection.ROLLBACK)
    ctx.proposals.save_journal(ApplyJournal(
        jid_b, prop_b.proposal_id, JournalDirection.ROLLBACK, ProposalStatus.ROLLING_BACK, g_b.grant_id, str(stg_b),
        (FileJournalEntry(
            "b.txt", str(ctx.checkout), ManagedFormat.RAW, "rb", FileOriginalState.PRESENT,
            FileJournalPhase.REPLACEMENT_PUBLISHED, digest_bytes(b"orig-b\n"), orig_b_id.token(),
            digest_bytes(b"rep-b\n"), str(stg_b / "rep-0"), str(bak_b), hold_b_id.token(), p_b_id.token(),
        ),),
        ctx.now_str(), ctx.now_str(),
    ))
    ctx.proposals.update_proposal_status(
        prop_b.proposal_id, ProposalStatus.ROLLING_BACK, active_journal_id=jid_b, updated_at=ctx.now_str()
    )
    rep_b = _reconcile(ctx)
    assert rep_b.rolled_back_journals == 1 and rep_b.recovery_required_journals == 0
    assert ctx.proposals.get_proposal(prop_b.proposal_id).status is ProposalStatus.ROLLED_BACK
    assert f_b.read_bytes() == b"orig-b\n"

    # 3. Negative Case 106 counterpart: identical bytes on a brand-new inode MUST fail closed to RECOVERY_REQUIRED.
    f_c = ctx.checkout / "c.txt"
    f_c.write_bytes(b"orig-c\n")
    prop_c = ctx.svc.create_proposal(
        owner_id=OWNER, kind="bootstrap", reason="r03 neg 106", resources=(RiskResource("c2"),),
        targets=(TargetWriteInput(ctx.checkout, "c.txt", b"rep-c\n", ManagedFormat.RAW, "rc"),),
    )
    rec_c = ctx.authority.consume_approval(
        _sign(ctx, prop_c), signer_id=ctx.signer.signer_id, channel=ApprovalChannel.SSH_KEY
    )
    jid_c = new_id()
    g_c, _ = ctx.authority.begin_journal_turn(
        approval_id=rec_c.approval_id, journal_id=jid_c, direction=JournalDirection.APPLY
    )
    stg_c = select_staging_dir(ctx.checkout, ctx.root, jid_c, OWNER, ctx.os_)
    ctx.authority.open_turn_intent(journal_id=jid_c, approval_id=rec_c.approval_id, direction=JournalDirection.ROLLBACK)
    ctx.proposals.save_journal(ApplyJournal(
        jid_c, prop_c.proposal_id, JournalDirection.ROLLBACK, ProposalStatus.ROLLING_BACK, g_c.grant_id, str(stg_c),
        (FileJournalEntry(
            "c.txt", str(ctx.checkout), ManagedFormat.RAW, "rc", FileOriginalState.PRESENT,
            FileJournalPhase.REPLACEMENT_PUBLISHED, digest_bytes(b"orig-c\n"), "fake:different_id",
            digest_bytes(b"rep-c\n"), str(stg_c / "rep-0"), str(stg_c / "bak-0"), "fake:rep_id", p_b_id.token(),
        ),),
        ctx.now_str(), ctx.now_str(),
    ))
    ctx.proposals.update_proposal_status(
        prop_c.proposal_id, ProposalStatus.ROLLING_BACK, active_journal_id=jid_c, updated_at=ctx.now_str()
    )
    rep_c = _reconcile(ctx)
    assert rep_c.recovery_required_journals == 1 and rep_c.rolled_back_journals == 0
    assert ctx.proposals.get_proposal(prop_c.proposal_id).status is ProposalStatus.RECOVERY_REQUIRED


def test_r04_case93_verifies_original_physical_id_and_parent_physical_id(ctx: Ctx) -> None:
    phys, now = ctx.os_.physical, ctx.now_str()
    sid, ch, up = ctx.signer.signer_id, ApprovalChannel.SSH_KEY, ctx.proposals.update_proposal_status
    assert phys is not None
    # 1. Case 93 turn.state=="rolled_back" with identical bytes on new PhysicalObjectId -> RECOVERY_REQUIRED.
    f_x = ctx.checkout / "c93rb.txt"
    f_x.write_bytes(b"orig-rb\n")
    orig_x_id, parent_id = phys.stat_physical_identity(f_x), phys.stat_physical_identity(ctx.checkout)
    assert orig_x_id is not None and parent_id is not None
    prop_x = ctx.svc.create_proposal(
        owner_id=OWNER, kind="bootstrap", reason="r04 rb phys", resources=(RiskResource("c2"),),
        targets=(TargetWriteInput(ctx.checkout, "c93rb.txt", b"rep-rb\n", ManagedFormat.RAW, "rx"),),
    )
    rec_x = ctx.authority.consume_approval(_sign(ctx, prop_x), signer_id=sid, channel=ch)
    jid_x = new_id()
    g_x, _ = ctx.authority.begin_journal_turn(
        approval_id=rec_x.approval_id, journal_id=jid_x, direction=JournalDirection.APPLY
    )
    ctx.authority.open_turn_intent(journal_id=jid_x, approval_id=rec_x.approval_id, direction=JournalDirection.ROLLBACK)
    ctx.authority.end_recovery_grant(grant_id=g_x.grant_id, reason="journal_closed", final_status="rolled_back")
    fe_x = FileJournalEntry(
        "c93rb.txt", str(ctx.checkout), ManagedFormat.RAW, "rx", FileOriginalState.PRESENT,
        FileJournalPhase.REPLACEMENT_PUBLISHED, digest_bytes(b"orig-rb\n"), orig_x_id.token(),
        digest_bytes(b"rep-rb\n"), str(ctx.root / "apply_staging" / jid_x / "rep-0"), None, None, parent_id.token(),
    )
    ctx.proposals.save_journal(ApplyJournal(
        jid_x, prop_x.proposal_id, JournalDirection.ROLLBACK, ProposalStatus.ROLLING_BACK,
        g_x.grant_id, str(ctx.root / "apply_staging" / jid_x), (fe_x,), now, now,
    ))
    up(prop_x.proposal_id, ProposalStatus.ROLLING_BACK, active_journal_id=jid_x, updated_at=now)
    f_x.unlink()
    f_x.write_bytes(b"orig-rb\n")  # identical bytes, different PhysicalObjectId
    rep_x = _reconcile(ctx)
    assert rep_x.recovery_required_journals == 1 and rep_x.rolled_back_journals == 0
    assert ctx.proposals.get_proposal(prop_x.proposal_id).status is ProposalStatus.RECOVERY_REQUIRED

    # 2. Case 93 turn.state=="applied" with file moved into swapped parent dir -> RECOVERY_REQUIRED.
    sub_y = ctx.checkout / "sub_y"
    sub_y.mkdir()
    ctx.os_.permissions.secure_directory(sub_y)
    prop_y = ctx.svc.create_proposal(
        owner_id=OWNER, kind="bootstrap", reason="r04 app parent", resources=(RiskResource("c2"),),
        targets=(TargetWriteInput(ctx.checkout, "sub_y/y.txt", b"rep-y\n", ManagedFormat.RAW, "ry"),),
    )
    j_y = ctx.svc.apply_proposal(prop_y.proposal_id, approval=_sign(ctx, prop_y), signer_id=sid, channel=ch)
    ctx.proposals.update_journal(ApplyJournal(
        j_y.journal_id, prop_y.proposal_id, JournalDirection.APPLY, ProposalStatus.APPLYING,
        j_y.grant_id, j_y.staging_dir, j_y.files, j_y.created_at, now,
    ))
    up(prop_y.proposal_id, ProposalStatus.APPLYING, active_journal_id=j_y.journal_id, updated_at=now)
    sub_y_old = ctx.checkout / "sub_y_old"
    sub_y.rename(sub_y_old)
    sub_y.mkdir()
    ctx.os_.permissions.secure_directory(sub_y)
    os.replace(sub_y_old / "y.txt", target_path(ctx.checkout, "sub_y/y.txt"))
    rep_y = _reconcile(ctx)
    assert rep_y.recovery_required_journals >= 1 and rep_y.continued_journals == 0
    assert ctx.proposals.get_proposal(prop_y.proposal_id).status is ProposalStatus.RECOVERY_REQUIRED
