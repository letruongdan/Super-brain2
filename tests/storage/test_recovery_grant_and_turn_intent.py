"""I3-3 oracle: ``apply_turn_intent``, ``recovery_grant``, startup journal recovery, carry-forwards & ``continue``.

Requirement sources: spec rev 22 §5.4, §5.8, §11.2-§11.3, §20 cases 27, 32, 33, 34, 93, 105, 106, 107;
plan I3-3 + mutants R21-01/Case 93/Case 107; ``i3-2/review.md`` §4 carry-forwards #1-#3.
"""

from __future__ import annotations

import base64
import json
import shutil
import struct
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from superbrain.adapters.harness_config.markdown_blocks import merge_markdown_block
from superbrain.adapters.harness_config.merger import SharedConfigMergerAdapter
from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.physical_fs import verify_physical_target
from superbrain.adapters.os.tls_material import create_store_tls
from superbrain.application._review_apply_ops import (
    mark_recovery_required_state,
    select_staging_dir,
    verify_target,
)
from superbrain.application.approvals import OperatorService
from superbrain.application.review_apply import ReviewApplyService, TargetWriteInput
from superbrain.cli.main import main as brain_main
from superbrain.cli_api.loopback import LoopbackClient, LoopbackTarget
from superbrain.cli_api.operator import OPERATOR_PATHS
from superbrain.composition import daemon_entry, init_entry
from superbrain.composition.review_cli_entry import run_review_cli
from superbrain.core._kernel_approval import (
    CLI_HARNESS_ID,
    RISK_POLICY_VERSION,
    ApprovalAction,
    ApprovalChannel,
    ApprovalMessage,
    RecoveryGrant,
    RecoveryScope,
    RiskResource,
    SignerEnrollment,
    SignerRecord,
)
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.kernel import DaemonConfig, Ready
from superbrain.core.proposals import (
    ApplyJournal,
    ChangeProposal,
    FileJournalEntry,
    FileJournalPhase,
    FileOriginalState,
    JournalDirection,
    ManagedFormat,
    ProposalStatus,
)
from superbrain.ports.os import NoReplacePublisher, OsAdapters
from superbrain.ports.proposals import ApplyAuthorityPort
from superbrain.storage.layout import DataRoot
from superbrain.storage.proposals import PolicyApplyAuthority, StoreProposalAdapter
from superbrain.storage.runtime import Runtime
from tests.support.clock import FakeClock
from tests.support.inc2_cli import write_client_profile_file, write_daemon_config_file, write_owner_only_bytes
from tests.support.inc2_fixture import reopen_kernel_job_runtime
from tests.support.inc2_transport import FakeMonotonicClock, clone_owner_only_tree, create_transport_template
from tests.support.kernel_auth import make_bootstrap_auth, seed_principal_and_credential
from tests.support.seed_clone import recovery_grant_ctx_clone

OWNER = "dan"


def _ssh_enrollment(tag: str = "i3-3") -> SignerEnrollment:
    raw = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", len(raw)) + raw
    return SignerEnrollment(
        owner_id=OWNER,
        channel=ApprovalChannel.SSH_KEY,
        public_key="ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + f" {tag}@devbox",
    )


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


def _open_ctx(tmp: Path, *, role: str) -> Ctx:
    clock = FakeClock(datetime(2026, 11, 19, 10, 0, tzinfo=UTC))
    os_ = os_adapters(clock=clock)
    root, checkout, home = tmp / "data", tmp / "checkout", tmp / "home"
    for d in (tmp, checkout, home):
        d.mkdir(parents=True, exist_ok=True)
        os_.permissions.secure_directory(d)
    rt, signer = recovery_grant_ctx_clone(root, os_, _ssh_enrollment)
    proposals, authority = StoreProposalAdapter(rt.store, os_), PolicyApplyAuthority(rt.policy)
    svc = ReviewApplyService(
        proposals, authority, os_, data_root=root, home_dir=home, config_merger=SharedConfigMergerAdapter()
    )
    return Ctx(rt, root, checkout, home, clock, os_, signer, proposals, authority, svc)


def _sign(
    c: Ctx,
    prop: ChangeProposal,
    *,
    action: ApprovalAction = ApprovalAction.APPLY,
    recovery_scope: RecoveryScope = RecoveryScope.CONTINUE_OR_ROLLBACK,
) -> ApprovalMessage:
    issued = c.rt.policy.issue_nonce(action=action, subject_id=prop.proposal_id, risk_level=prop.risk_level)
    return ApprovalMessage(
        c.rt.store.store_id, OWNER, issued.trust_generation, action, prop.proposal_id, prop.subject_revision,
        prop.resource_digests, prop.to_target_files(), issued.risk_level, RISK_POLICY_VERSION,
        recovery_scope, issued.nonce, issued.expires_at,
    )


def _seed_partial_apply(
    c: Ctx,
    monkeypatch: pytest.MonkeyPatch,
    *,
    f1_name: str = "CLAUDE.md",
    f2_name: str = "AGENTS.md",
    scope: RecoveryScope = RecoveryScope.CONTINUE_OR_ROLLBACK,
) -> tuple[ChangeProposal, ApplyJournal]:
    f1 = c.checkout / f1_name
    f1.write_bytes(b"# U0\n")
    prop = c.svc.create_proposal(
        owner_id=OWNER,
        kind="bootstrap",
        reason=f"partial {f1_name}",
        resources=(RiskResource("c2"), RiskResource("c5")),
        targets=(
            TargetWriteInput(c.checkout, f1_name, b"# U0\n<!-- brain -->\n", ManagedFormat.RAW, "r1"),
            TargetWriteInput(c.checkout, f2_name, b"# Created\n", ManagedFormat.RAW, "r2"),
        ),
    )
    pub = cast(NoReplacePublisher, c.os_.publisher)
    orig = pub.publish_no_replace
    hits = [0]

    def _fail_second(staging: Path, final: Path) -> None:
        hits[0] += 1
        if hits[0] == 2:
            raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "turn interrupted")
        orig(staging, final)

    monkeypatch.setattr(pub, "publish_no_replace", _fail_second)
    msg = _sign(c, prop, recovery_scope=scope)
    with pytest.raises(BrainError):
        c.svc.apply_proposal(
            prop.proposal_id, approval=msg, signer_id=c.signer.signer_id, channel=ApprovalChannel.SSH_KEY
        )
    monkeypatch.undo()
    updated_prop = c.proposals.get_proposal(prop.proposal_id)
    assert updated_prop.active_journal_id is not None
    return updated_prop, c.proposals.get_journal(updated_prop.active_journal_id)


def _create_md_proposal(c: Ctx, name: str = "CLAUDE.md", second: str = "AGENTS.md") -> ChangeProposal:
    f1 = c.checkout / name
    f1.write_bytes(b"# U0\n")
    merged = merge_markdown_block(
        "# U0\n", slice_id="s-md", block_body="Managed text.\n", expected_slice_digest=None
    )
    rep2 = b"# Agents\n"
    return c.svc.create_proposal(
        owner_id=OWNER,
        kind="bootstrap",
        reason="recover test",
        resources=(RiskResource("c2"),),
        targets=(
            TargetWriteInput(
                c.checkout, name, merged.updated_text.encode("utf-8"),
                ManagedFormat.MARKDOWN, "s-md", merged.slice_digest,
            ),
            TargetWriteInput(c.checkout, second, rep2, ManagedFormat.RAW, "s-ag", digest_bytes(rep2)),
        ),
    )


def _now_utc_fn(c: Ctx) -> Callable[[], str]:
    from superbrain.core._kernel_approval import canonical_utc

    return lambda: canonical_utc(c.clock.now())


def test_apply_turn_intent_monotonicity_authority_port_and_incomplete_listing(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from superbrain.core.proposals import ApplyTurnIntent

    c = _open_ctx(trusted_tmp, role="turn-intent")
    try:
        assert c.proposals.list_incomplete_journals() == ()
        prop_a, j_partial = _seed_partial_apply(c, monkeypatch, f1_name="A1.md", f2_name="A2.md")
        prop_b = _create_md_proposal(c, "B1.md", "B2.md")
        j_applied = c.svc.apply_proposal(
            prop_b.proposal_id,
            approval=_sign(c, prop_b),
            signer_id=c.signer.signer_id,
            channel=ApprovalChannel.SSH_KEY,
        )
        assert j_applied.status is ProposalStatus.APPLIED
        incomplete = c.proposals.list_incomplete_journals()
        assert [j.journal_id for j in incomplete] == [j_partial.journal_id]

        # Standalone journal turn lifecycle on PolicyStore & PolicyApplyAuthority.
        prop_c = _create_md_proposal(c, "C1.md", "C2.md")
        msg_c = _sign(c, prop_c, recovery_scope=RecoveryScope.CONTINUE_OR_ROLLBACK)
        rec_c = c.rt.policy.consume_approval(msg_c, signer_id=c.signer.signer_id, channel=ApprovalChannel.SSH_KEY)
        jid_c = new_id()
        grant_c, intent_c = c.authority.begin_journal_turn(
            approval_id=rec_c.approval_id, journal_id=jid_c, direction=JournalDirection.APPLY
        )
        assert isinstance(intent_c, ApplyTurnIntent)
        assert intent_c.direction is JournalDirection.APPLY and intent_c.state == "active"
        assert c.authority.turn_intent_for_journal(jid_c) == intent_c
        assert c.authority.find_recovery_grant_for_journal(jid_c) == grant_c
        assert intent_c in c.authority.list_turn_intents()
        assert grant_c in c.authority.list_recovery_grants()

        flipped = c.authority.open_turn_intent(
            journal_id=jid_c, approval_id=rec_c.approval_id, direction=JournalDirection.ROLLBACK
        )
        assert flipped.direction is JournalDirection.ROLLBACK and flipped.state == "active"
        with pytest.raises(BrainError) as rev:
            c.authority.open_turn_intent(
                journal_id=jid_c, approval_id=rec_c.approval_id, direction=JournalDirection.APPLY
            )
        assert rev.value.code is ErrorCode.REVISION_CONFLICT

        ended = c.authority.end_recovery_grant(
            grant_id=grant_c.grant_id, reason="journal_closed", final_status="rolled_back"
        )
        assert ended.state == "ended" and ended.end_reason == "journal_closed"
        after_intent = c.rt.policy.turn_intent_for_journal(jid_c)
        assert after_intent is not None and after_intent.state == "rolled_back"
        assert prop_a.status is ProposalStatus.PARTIALLY_APPLIED
    finally:
        c.rt.close()


def test_recovery_grant_expiry_vs_terminal_and_offline_trust_reset(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    c = _open_ctx(trusted_tmp, role="grant-ttl")
    try:
        prop, partial = _seed_partial_apply(c, monkeypatch, scope=RecoveryScope.CONTINUE)
        with pytest.raises(BrainError) as bad_reason:
            c.rt.policy.end_recovery_grant(grant_id=partial.grant_id, reason="recovery_required")
        assert bad_reason.value.code is ErrorCode.INVALID_INPUT

        c.clock.advance(timedelta(minutes=30))  # Case 33: past 10-min nonce expiry
        continued = c.svc.continue_interrupted_journal(partial.journal_id)
        assert continued.status is ProposalStatus.APPLIED
        assert (c.checkout / "AGENTS.md").read_bytes() == b"# Created\n"
        assert c.rt.policy.recovery_grant(partial.grant_id).end_reason == "journal_closed"
        ti = c.rt.policy.turn_intent_for_journal(partial.journal_id)
        assert ti is not None and ti.state == "applied"

        # Open a second active turn + grant, then run offline init_entry.reset_signers.
        prop2, partial2 = _seed_partial_apply(c, monkeypatch, f1_name="R1.md", f2_name="R2.md")
        assert prop2.active_journal_id == partial2.journal_id
        store_id, gen = c.rt.store.store_id, c.rt.policy.trust_generation()
        auth = make_bootstrap_auth(
            store_id=store_id, owner_id=OWNER, action="provision_tls", subject_id=store_id,
            trust_generation=gen, expires_at=c.clock.now() + timedelta(hours=2), destination=trusted_tmp / "tls",
        )
        tls = create_store_tls(store_id, trusted_tmp / "tls", auth, c.clock, c.os_)
        cfg = write_daemon_config_file(
            trusted_tmp / "daemon.json", data_root=c.root, expected_store_id=store_id,
            cert_path=tls.cert_path, key_path=tls.key_path,
        )
    finally:
        c.rt.close()

    report = init_entry.reset_signers(cfg, _ssh_enrollment("replacement"), c.os_)
    assert report.trust_generation == gen + 1
    rt2 = reopen_kernel_job_runtime(c.root, store_id, c.os_)
    try:
        grant2 = rt2.policy.recovery_grant(partial2.grant_id)
        assert grant2.state == "ended" and grant2.end_reason == "trust_reset"
        ti2 = rt2.policy.turn_intent_for_journal(partial2.journal_id)
        assert ti2 is not None and ti2.state == "recovery_required"
        assert rt2.policy.signer_reset_recorded() is True
    finally:
        rt2.close()


def test_i3_2_carry_forward_invariants(trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    c = _open_ctx(trusted_tmp, role="carry-fwd")
    try:
        # #3: verify_physical_target & verify_target explicitly reject relative roots before link/ancestor inspection.
        for fn in (verify_physical_target, verify_target):
            with pytest.raises(BrainError) as rel_exc:
                fn(Path("relative/dir"), "CLAUDE.md", c.os_)
            assert rel_exc.value.code is ErrorCode.UNSAFE_PATH

        # #1: execute_interrupted_rollback refusing RecoveryScope.CONTINUE keeps PARTIALLY_APPLIED resumable.
        prop, partial = _seed_partial_apply(c, monkeypatch, scope=RecoveryScope.CONTINUE)
        with pytest.raises(BrainError) as rb_refuse:
            c.svc.rollback_interrupted_journal(partial.journal_id)
        assert rb_refuse.value.code is ErrorCode.INVALID_INPUT
        assert c.proposals.get_proposal(prop.proposal_id).status is ProposalStatus.PARTIALLY_APPLIED
        assert c.rt.policy.recovery_grant(partial.grant_id).state == "active"
        done = c.svc.continue_interrupted_journal(partial.journal_id)
        assert done.status is ProposalStatus.APPLIED

        # #1 mirror: continue_interrupted_journal refuses direction=ROLLBACK without clobbering PARTIALLY_APPLIED.
        prop_rb, partial_rb = _seed_partial_apply(
            c, monkeypatch, f1_name="K1.md", f2_name="K2.md", scope=RecoveryScope.CONTINUE_OR_ROLLBACK
        )
        ti_rb = c.authority.turn_intent_for_journal(partial_rb.journal_id)
        assert ti_rb is not None
        c.authority.open_turn_intent(
            journal_id=partial_rb.journal_id, approval_id=ti_rb.approval_id, direction=JournalDirection.ROLLBACK
        )
        with pytest.raises(BrainError) as cont_refuse:
            c.svc.continue_interrupted_journal(partial_rb.journal_id)
        assert cont_refuse.value.code is ErrorCode.INVALID_INPUT
        assert c.proposals.get_proposal(prop_rb.proposal_id).status is ProposalStatus.PARTIALLY_APPLIED

        # #2: mark_recovery_required_state never sends invalid reason="recovery_required" to end_recovery_grant.
        calls: list[str] = []

        class _SpyAuthority:
            def __init__(self, inner: ApplyAuthorityPort) -> None:
                self._inner = inner

            def __getattr__(self, name: str) -> Any:
                return getattr(self._inner, name)

            def end_recovery_grant(
                self, *, grant_id: str, reason: str = "journal_closed", final_status: str
            ) -> RecoveryGrant:
                calls.append(reason)
                return self._inner.end_recovery_grant(grant_id=grant_id, reason=reason, final_status=final_status)

        mark_recovery_required_state(
            c.proposals,
            cast(ApplyAuthorityPort, _SpyAuthority(c.authority)),
            partial_rb,
            list(partial_rb.files),
            _now_utc_fn(c)(),
        )
        assert "recovery_required" not in calls
        assert c.proposals.get_proposal(prop_rb.proposal_id).status is ProposalStatus.RECOVERY_REQUIRED
    finally:
        c.rt.close()


def _run_reconcile(c: Ctx) -> Any:
    from superbrain.application.journal_recovery import reconcile_and_classify_journals

    return reconcile_and_classify_journals(
        c.proposals, c.authority, c.os_, data_root=c.root, home_dir=c.home,
        config_merger=SharedConfigMergerAdapter(), now_utc_fn=_now_utc_fn(c),
    )


def test_reconcile_journals_r21_case93_case107_and_trust_reset(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A + R21-01 + idempotency in fresh store.
    c = _open_ctx(trusted_tmp / "r21", role="reconcile-r21")
    try:
        p1 = _create_md_proposal(c, "CLAUDE.md", "AGENTS.md")
        m1 = _sign(c, p1, recovery_scope=RecoveryScope.CONTINUE)
        rec1 = c.authority.consume_approval(m1, signer_id=c.signer.signer_id, channel=ApprovalChannel.SSH_KEY)
        jid1 = new_id()
        c.authority.begin_journal_turn(approval_id=rec1.approval_id, journal_id=jid1, direction=JournalDirection.APPLY)
        rep = _run_reconcile(c)
        assert rep.continued_journals == 1 and rep.recovery_required_journals == 0
        assert c.proposals.get_proposal(p1.proposal_id).status is ProposalStatus.APPLIED
        assert b"Managed text." in (c.checkout / "CLAUDE.md").read_bytes()
        assert (c.checkout / "AGENTS.md").read_bytes() == b"# Agents\n"

        # R21-01 mutant: mid-rollback journal (1 file REPLACEMENT_PUBLISHED, 1 file RESTORED, direction=ROLLBACK).
        f1, f2 = c.checkout / "M1.md", c.checkout / "M2.md"
        f1.write_bytes(b"U0 m1\n")
        f2.write_bytes(b"U0 m2\n")
        p2 = c.svc.create_proposal(
            owner_id=OWNER, kind="bootstrap", reason="r21 mutant", resources=(RiskResource("c2"),),
            targets=(
                TargetWriteInput(c.checkout, "M1.md", b"Rep m1\n", ManagedFormat.RAW, "m1"),
                TargetWriteInput(c.checkout, "M2.md", b"Rep m2\n", ManagedFormat.RAW, "m2"),
            ),
        )
        m2 = _sign(c, p2, recovery_scope=RecoveryScope.CONTINUE_OR_ROLLBACK)
        rec2 = c.authority.consume_approval(m2, signer_id=c.signer.signer_id, channel=ApprovalChannel.SSH_KEY)
        jid2 = new_id()
        g2, _ = c.authority.begin_journal_turn(
            approval_id=rec2.approval_id, journal_id=jid2, direction=JournalDirection.APPLY
        )
        stg2 = select_staging_dir(c.checkout, c.root, jid2, OWNER, c.os_)
        bak1 = stg2 / "bak-0"
        c.os_.publisher.write_new(bak1, b"U0 m1\n")
        c.os_.permissions.secure_file(bak1)
        f1.write_bytes(b"Rep m1\n")
        phys = c.os_.physical
        assert phys is not None
        bak1_id = phys.stat_physical_identity(bak1)
        f1_id = phys.stat_physical_identity(f1)
        f2_id = phys.stat_physical_identity(f2)
        assert bak1_id is not None and f1_id is not None and f2_id is not None
        c.authority.open_turn_intent(journal_id=jid2, approval_id=rec2.approval_id, direction=JournalDirection.ROLLBACK)
        now = _now_utc_fn(c)()
        j2 = ApplyJournal(
            journal_id=jid2, proposal_id=p2.proposal_id, direction=JournalDirection.ROLLBACK,
            status=ProposalStatus.ROLLING_BACK, grant_id=g2.grant_id, staging_dir=str(stg2),
            files=(
                FileJournalEntry("M1.md", str(c.checkout), ManagedFormat.RAW, "m1", FileOriginalState.PRESENT,
                    FileJournalPhase.REPLACEMENT_PUBLISHED, digest_bytes(b"U0 m1\n"), bak1_id.token(),
                    digest_bytes(b"Rep m1\n"), str(stg2 / "rep-0"), str(bak1), f1_id.token(), None),
                FileJournalEntry("M2.md", str(c.checkout), ManagedFormat.RAW, "m2", FileOriginalState.PRESENT,
                    FileJournalPhase.RESTORED, digest_bytes(b"U0 m2\n"), f2_id.token(),
                    digest_bytes(b"Rep m2\n"), str(stg2 / "rep-1"), None, None, None),
            ),
            created_at=now, updated_at=now,
        )
        c.proposals.save_journal(j2)
        c.proposals.update_proposal_status(
            p2.proposal_id, ProposalStatus.ROLLING_BACK, active_journal_id=jid2, updated_at=now
        )

        rep2 = _run_reconcile(c)
        assert rep2.rolled_back_journals == 1 and rep2.continued_journals == 0
        assert c.proposals.get_proposal(p2.proposal_id).status is ProposalStatus.ROLLED_BACK
        assert f1.read_bytes() == b"U0 m1\n" and f2.read_bytes() == b"U0 m2\n"
        noop = _run_reconcile(c)
        assert noop.touched_journal_ids == ()
    finally:
        c.rt.close()

    # Case 93 + Case 107 + trust_reset fence in fresh root.
    c2 = _open_ctx(trusted_tmp / "case93", role="case93-107")
    try:
        # Case 93: policy.db already closed apply turn+grant; brain.db still APPLYING without manifests.
        p93 = _create_md_proposal(c2, "C93.md", "A93.md")
        j93 = c2.svc.apply_proposal(
            p93.proposal_id, approval=_sign(c2, p93), signer_id=c2.signer.signer_id, channel=ApprovalChannel.SSH_KEY
        )
        assert j93.status is ProposalStatus.APPLIED
        now93 = _now_utc_fn(c2)()
        c2.proposals.update_journal(ApplyJournal(
            journal_id=j93.journal_id, proposal_id=p93.proposal_id, direction=JournalDirection.APPLY,
            status=ProposalStatus.APPLYING, grant_id=j93.grant_id, staging_dir=j93.staging_dir,
            files=j93.files, created_at=j93.created_at, updated_at=now93,
        ))
        c2.proposals.update_proposal_status(
            p93.proposal_id, ProposalStatus.APPLYING, active_journal_id=j93.journal_id, updated_at=now93
        )
        grants_before = len(c2.authority.list_recovery_grants())
        rep93 = _run_reconcile(c2)
        assert j93.journal_id in rep93.touched_journal_ids
        assert c2.proposals.get_proposal(p93.proposal_id).status is ProposalStatus.APPLIED
        assert len(c2.authority.list_recovery_grants()) == grants_before

        # Case 107: corrupt backup before move during rollback -> RECOVERY_REQUIRED without deleting A107.md.
        _, j107 = _seed_partial_apply(
            c2, monkeypatch, f1_name="B107.md", f2_name="A107.md", scope=RecoveryScope.CONTINUE_OR_ROLLBACK
        )
        ti107 = c2.authority.turn_intent_for_journal(j107.journal_id)
        assert ti107 is not None
        c2.authority.open_turn_intent(
            journal_id=j107.journal_id, approval_id=ti107.approval_id, direction=JournalDirection.ROLLBACK
        )
        Path(str(j107.files[0].backup_path)).write_bytes(b"corrupted-backup")
        rep107 = _run_reconcile(c2)
        assert rep107.recovery_required_journals == 1
        assert c2.proposals.get_journal(j107.journal_id).status is ProposalStatus.RECOVERY_REQUIRED

        # trust_reset ended grant on an active journal -> RECOVERY_REQUIRED.
        _, j_tr = _seed_partial_apply(c2, monkeypatch, f1_name="T1.md", f2_name="T2.md", scope=RecoveryScope.CONTINUE)
        c2.rt.policy.reset_signers_offline()
        rep_tr = _run_reconcile(c2)
        assert rep_tr.recovery_required_journals >= 1
        assert c2.proposals.get_journal(j_tr.journal_id).status is ProposalStatus.RECOVERY_REQUIRED
    finally:
        c2.rt.close()


def test_cli_review_continue_and_operator_proposal_continue(
    trusted_tmp: Path, capfd: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    assert "/v2/operator/proposal/continue" in OPERATOR_PATHS
    missing = trusted_tmp / "no-profile.json"
    for bad in (
        ["review", "continue", "p1", "--profile", "rel/profile.json"],
        ["review", "continue", "p1", "--profile", str(missing), "--approval-file", str(missing)],
    ):
        capfd.readouterr()
        assert brain_main(bad) == 2
        assert capfd.readouterr().err.strip().splitlines()[-1] == ErrorCode.INVALID_INPUT.value
    capfd.readouterr()
    assert brain_main(["review", "continue", "p1", "--profile", str(missing)]) == 1
    assert capfd.readouterr().err.strip().splitlines()[-1] == ErrorCode.NOT_FOUND.value

    # OperatorService state transition + owner isolation on PARTIALLY_APPLIED journal.
    c = _open_ctx(trusted_tmp / "op", role="op-continue")
    try:
        cli_a = seed_principal_and_credential(c.rt.policy, owner_id=OWNER, harness_id=CLI_HARNESS_ID, machine_id="ma")
        cli_b = seed_principal_and_credential(c.rt.policy, owner_id="bob", harness_id=CLI_HARNESS_ID, machine_id="mb")
        prop, partial = _seed_partial_apply(c, monkeypatch, scope=RecoveryScope.CONTINUE_OR_ROLLBACK)
        op_svc = OperatorService(c.rt.policy, ssh_verifier=lambda: None, review_apply=c.svc)
        ep = "/v2/operator/proposal/continue"
        with pytest.raises(BrainError) as bad_body:
            op_svc.handle(ep, cli_a.principal, {}, token=cli_a.token)
        assert bad_body.value.code is ErrorCode.INVALID_INPUT
        with pytest.raises(BrainError) as idor:
            op_svc.handle(ep, cli_b.principal, {"proposal_id": prop.proposal_id}, token=cli_b.token)
        assert idor.value.code is ErrorCode.NOT_FOUND
        res = op_svc.handle(ep, cli_a.principal, {"proposal_id": prop.proposal_id}, token=cli_a.token)
        assert isinstance(res["journal"], dict) and res["journal"]["journal_id"] == partial.journal_id
        assert c.proposals.get_proposal(prop.proposal_id).status is ProposalStatus.APPLIED
    finally:
        c.rt.close()

    tpl = create_transport_template("i3-3-op-continue")
    try:
        rt = reopen_kernel_job_runtime(tpl.root, tpl.store_id, os_adapters(clock=FakeClock(tpl.base_time)))
        try:
            cli = seed_principal_and_credential(rt.policy, owner_id=OWNER, harness_id=CLI_HARNESS_ID, machine_id="mc")
        finally:
            rt.close()
        live_root = trusted_tmp / "op-live-data"
        clone_owner_only_tree(tpl.root, live_root)
        cfg = DaemonConfig(1, live_root, tpl.store_id, tpl.tls.cert_path, tpl.tls.key_path)
        d_clock, mono = FakeClock(tpl.base_time), FakeMonotonicClock(1_000_000_000)
        d_adapters = os_adapters(clock=d_clock, monotonic=mono)
        ready_evt, stop_evt = threading.Event(), threading.Event()
        ready_box: list[Ready] = []

        def _on_ready(ready: Ready, _loop: object) -> None:
            ready_box.append(ready)
            ready_evt.set()

        thr = threading.Thread(
            target=daemon_entry.serve,
            kwargs={
                "config": cfg, "os_": d_adapters, "clock": d_clock, "monotonic_clock": mono,
                "stop_event": stop_evt, "shutdown_grace_s": 1.0, "on_ready": _on_ready,
            },
            daemon=True,
        )
        thr.start()
        try:
            assert ready_evt.wait(timeout=5.0) and ready_box
            target = LoopbackTarget(
                ready_box[0].endpoint, tpl.store_id,
                tpl.tls.ca_cert_path.read_text(encoding="utf-8"), tpl.tls.leaf_cert_sha256,
            )
            client = LoopbackClient(monotonic_ns=mono.monotonic_ns)
            body = json.dumps({"proposal_id": "p-missing"}).encode("utf-8")
            for tok, expect in ((tpl.cred.token, "identity_mismatch"), ("0" * 16, "unauthenticated")):
                err = client.call_operator(target, "/v2/operator/proposal/continue", body, tok)["error"]
                assert isinstance(err, dict) and err["code"] == expect
            cred_file = write_owner_only_bytes(trusted_tmp / "cli.cred", (cli.token + "\n").encode("ascii"))
            profile, _ = write_client_profile_file(
                trusted_tmp / "cli-prof.json", endpoint_path=DataRoot.at(live_root).endpoint_path,
                expected_store_id=tpl.store_id, ca_file=tpl.tls.ca_cert_path,
                leaf_cert_sha256=tpl.tls.leaf_cert_sha256, credential_file=cred_file,
            )
            capfd.readouterr()
            assert run_review_cli(["review", "continue", "p-missing", "--profile", str(profile)], os_=d_adapters) == 1
            assert capfd.readouterr().err.strip().splitlines()[-1] == ErrorCode.NOT_FOUND.value
        finally:
            stop_evt.set()
            thr.join(timeout=5.0)
            assert not thr.is_alive()
    finally:
        shutil.rmtree(tpl.base_dir, ignore_errors=True)
