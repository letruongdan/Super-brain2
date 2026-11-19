"""I3-2 oracle: end-to-end ApplyJournal rollback (out-of-band U1 + interrupted turn).

Requirement sources: spec rev 22 §11.2 (two rollback modes, out-of-band U0/U1 preservation), §11.3,
§20 cases 12, 13, 27, 30, 33, 94, 95, 105, 106; ledger §2.2, §4; plan I3-2 Review Focus #1.
"""

from __future__ import annotations

import base64
import json
import os
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
import tomlkit
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from superbrain.adapters.harness_config.json_keys import merge_json_keys
from superbrain.adapters.harness_config.markdown_blocks import merge_markdown_block
from superbrain.adapters.harness_config.merger import SharedConfigMergerAdapter
from superbrain.adapters.harness_config.toml_tables import merge_toml_table
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
from superbrain.core.proposals import (
    ChangeProposal,
    JournalDirection,
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
    line = "ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + " e2e@devbox"
    return SignerEnrollment(owner_id=OWNER, channel=ApprovalChannel.SSH_KEY, public_key=line)


@dataclass
class E2ECtx:
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
def e2e(trusted_tmp: Path) -> Iterator[E2ECtx]:
    clock = FakeClock(datetime(2026, 11, 19, 9, 0, tzinfo=UTC))
    os_ = os_adapters(clock=clock)
    root = trusted_tmp / "data"
    checkout = trusted_tmp / "checkout"
    home = trusted_tmp / "home"
    checkout.mkdir()
    home.mkdir()
    os_.permissions.secure_directory(checkout)
    os_.permissions.secure_directory(home)
    rt = open_kernel_job_runtime(root, os_, role="i3-2-e2e")
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
        yield E2ECtx(
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
    c: E2ECtx,
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


def test_post_applied_rollback_restores_unchanged_and_guards_created_files(e2e: E2ECtx) -> None:
    claude = e2e.checkout / "CLAUDE.md"
    agents = e2e.checkout / "AGENTS.md"
    claude.write_bytes(b"# Clean U0\n")
    assert not agents.exists()

    prop = e2e.svc.create_proposal(
        owner_id=OWNER,
        kind="bootstrap",
        reason="clean rollback check",
        resources=(RiskResource("c2"),),
        targets=(
            TargetWriteInput(e2e.checkout, "CLAUDE.md", b"# Clean U0\n<!-- managed -->\n", ManagedFormat.RAW, "r1"),
            TargetWriteInput(e2e.checkout, "AGENTS.md", b"# Created by brain\n", ManagedFormat.RAW, "r2"),
        ),
    )
    apply_msg = _sign(e2e, prop, action=ApprovalAction.APPLY, recovery_scope=RecoveryScope.CONTINUE_OR_ROLLBACK)
    applied_journal = e2e.svc.apply_proposal(
        prop.proposal_id, approval=apply_msg, signer_id=e2e.signer.signer_id, channel=ApprovalChannel.SSH_KEY
    )
    assert applied_journal.status is ProposalStatus.APPLIED
    assert claude.read_bytes() == b"# Clean U0\n<!-- managed -->\n"
    assert agents.read_bytes() == b"# Created by brain\n"

    # Rollback approval with CONTINUE scope is rejected at message construction, and non-ROLLBACK action is refused.
    plan = e2e.svc.plan_rollback_targets(prop.proposal_id)
    with pytest.raises(BrainError) as msg_exc:
        _sign(
            e2e,
            prop,
            action=ApprovalAction.ROLLBACK,
            recovery_scope=RecoveryScope.CONTINUE,
            target_files=plan.target_files,
            resource_digests=plan.resource_digests,
        )
    assert msg_exc.value.code is ErrorCode.INVALID_INPUT

    wrong_action = _sign(
        e2e,
        prop,
        action=ApprovalAction.APPLY,
        recovery_scope=RecoveryScope.CONTINUE,
        target_files=plan.target_files,
        resource_digests=plan.resource_digests,
    )
    with pytest.raises(BrainError) as scope_exc:
        e2e.svc.rollback_applied_proposal(
            prop.proposal_id,
            approval=wrong_action,
            signer_id=e2e.signer.signer_id,
            channel=ApprovalChannel.SSH_KEY,
            plan=plan,
        )
    assert scope_exc.value.code in {ErrorCode.INVALID_INPUT, ErrorCode.UNAUTHENTICATED}

    rb_msg = _sign(
        e2e,
        prop,
        action=ApprovalAction.ROLLBACK,
        recovery_scope=RecoveryScope.ROLLBACK,
        target_files=plan.target_files,
        resource_digests=plan.resource_digests,
    )
    rb_journal = e2e.svc.rollback_applied_proposal(
        prop.proposal_id,
        approval=rb_msg,
        signer_id=e2e.signer.signer_id,
        channel=ApprovalChannel.SSH_KEY,
        plan=plan,
    )
    assert rb_journal.direction is JournalDirection.ROLLBACK
    assert rb_journal.status is ProposalStatus.ROLLED_BACK
    assert claude.read_bytes() == b"# Clean U0\n"
    assert not agents.exists(), "file created by Brain (original=absent) must be deleted on clean rollback"
    assert e2e.svc.get_proposal(prop.proposal_id).status is ProposalStatus.ROLLED_BACK
    assert e2e.rt.policy.recovery_grant(rb_journal.grant_id).end_reason == "journal_closed"

    # Refuse removal if user replaced an original=absent file with identical bytes (new PhysicalObjectId).
    fresh_absent = e2e.checkout / "NEW_ONLY.md"
    prop2 = e2e.svc.create_proposal(
        owner_id=OWNER,
        kind="bootstrap",
        reason="absent swap guard",
        resources=(RiskResource("c2"),),
        targets=(TargetWriteInput(e2e.checkout, "NEW_ONLY.md", b"# Same bytes\n", ManagedFormat.RAW, "r3"),),
    )
    apply2 = _sign(e2e, prop2, action=ApprovalAction.APPLY, recovery_scope=RecoveryScope.CONTINUE_OR_ROLLBACK)
    e2e.svc.apply_proposal(
        prop2.proposal_id, approval=apply2, signer_id=e2e.signer.signer_id, channel=ApprovalChannel.SSH_KEY
    )
    plan2 = e2e.svc.plan_rollback_targets(prop2.proposal_id)
    rb2 = _sign(
        e2e,
        prop2,
        action=ApprovalAction.ROLLBACK,
        recovery_scope=RecoveryScope.ROLLBACK,
        target_files=plan2.target_files,
        resource_digests=plan2.resource_digests,
    )
    tmp_swap = e2e.checkout / "swap-new-only.md"
    tmp_swap.write_bytes(b"# Same bytes\n")
    fresh_absent.unlink()
    os.replace(tmp_swap, fresh_absent)
    with pytest.raises(BrainError) as swap_exc:
        e2e.svc.rollback_applied_proposal(
            prop2.proposal_id,
            approval=rb2,
            signer_id=e2e.signer.signer_id,
            channel=ApprovalChannel.SSH_KEY,
            plan=plan2,
        )
    assert swap_exc.value.code is ErrorCode.REVISION_CONFLICT
    assert fresh_absent.read_bytes() == b"# Same bytes\n"


def test_shared_file_post_applied_rollback_preserves_out_of_band_edits_and_toml_comments(e2e: E2ECtx) -> None:
    """Review Focus #1: U0+Block -> U1+Block -> U1 across Markdown, JSON and tomlkit TOML."""
    claude = e2e.checkout / "CLAUDE.md"
    mcp = e2e.checkout / ".mcp.json"
    codex_dir = e2e.checkout / ".codex"
    codex_dir.mkdir()
    codex_toml = codex_dir / "config.toml"

    claude_u0 = "# Workspace Rules\n\nKeep code clean.\n"
    mcp_u0 = json.dumps({"theme": "dark", "mcpServers": {"userMcp": {"command": "npx"}}}, indent=2) + "\n"
    toml_u0 = (
        "# Top Codex comment\n"
        'model = "gpt-5-codex" # inline user model comment\n\n'
        "[profiles.fast]\n"
        "# Keep fast profile comment\n"
        'approval_policy = "on-request"\n'
    )
    claude.write_text(claude_u0, encoding="utf-8", newline="\n")
    mcp.write_text(mcp_u0, encoding="utf-8", newline="\n")
    codex_toml.write_text(toml_u0, encoding="utf-8", newline="\n")

    md_m = merge_markdown_block(
        claude_u0, slice_id="layer1-rule", block_body="Never self-approve.", expected_slice_digest=None
    )
    js_m = merge_json_keys(
        mcp_u0,
        key_path=("mcpServers", "super-brain"),
        value={"command": "brain-mcp", "args": ["--profile", "/abs/p.json"]},
        expected_slice_digest=None,
    )
    tm_m = merge_toml_table(
        toml_u0,
        table_path=("mcp_servers", "super-brain"),
        values={"command": "brain-mcp", "args": ["--profile", "/abs/p.json"]},
        expected_slice_digest=None,
    )

    prop = e2e.svc.create_proposal(
        owner_id=OWNER,
        kind="bootstrap",
        reason="shared harness config",
        resources=(RiskResource("c2"), RiskResource("c5")),
        targets=(
            TargetWriteInput(
                e2e.checkout,
                "CLAUDE.md",
                md_m.updated_text.encode("utf-8"),
                ManagedFormat.MARKDOWN,
                "layer1-rule",
                md_m.slice_digest,
            ),
            TargetWriteInput(
                e2e.checkout,
                ".mcp.json",
                js_m.updated_text.encode("utf-8"),
                ManagedFormat.JSON,
                "mcpServers.super-brain",
                js_m.slice_digest,
            ),
            TargetWriteInput(
                e2e.checkout,
                ".codex/config.toml",
                tm_m.updated_text.encode("utf-8"),
                ManagedFormat.TOML,
                "mcp_servers.super-brain",
                tm_m.slice_digest,
            ),
        ),
    )
    apply_msg = _sign(e2e, prop, action=ApprovalAction.APPLY, recovery_scope=RecoveryScope.CONTINUE_OR_ROLLBACK)
    e2e.svc.apply_proposal(
        prop.proposal_id, approval=apply_msg, signer_id=e2e.signer.signer_id, channel=ApprovalChannel.SSH_KEY
    )

    # Owner edits all three shared files out-of-band AFTER apply (U0+Block -> U1+Block).
    claude.write_text(
        claude.read_text(encoding="utf-8") + "\n## U1 Owner Notes\nAdded out-of-band after bootstrap.\n",
        encoding="utf-8",
        newline="\n",
    )
    mcp_obj = json.loads(mcp.read_text(encoding="utf-8"))
    mcp_obj["u1Setting"] = {"preserve": True}
    mcp_obj["mcpServers"]["u1Sibling"] = {"command": "uvx"}
    mcp.write_text(json.dumps(mcp_obj, indent=2) + "\n", encoding="utf-8", newline="\n")
    codex_toml.write_text(
        codex_toml.read_text(encoding="utf-8")
        + '\n# U1 added later by owner\n[profiles.deep]\nmode = "strict" # inline u1 comment\n',
        encoding="utf-8",
        newline="\n",
    )

    plan = e2e.svc.plan_rollback_targets(prop.proposal_id)
    rb_msg = _sign(
        e2e,
        prop,
        action=ApprovalAction.ROLLBACK,
        recovery_scope=RecoveryScope.ROLLBACK,
        target_files=plan.target_files,
        resource_digests=plan.resource_digests,
    )
    rb_journal = e2e.svc.rollback_applied_proposal(
        prop.proposal_id,
        approval=rb_msg,
        signer_id=e2e.signer.signer_id,
        channel=ApprovalChannel.SSH_KEY,
        plan=plan,
    )
    assert rb_journal.status is ProposalStatus.ROLLED_BACK

    claude_final = claude.read_text(encoding="utf-8")
    assert "ensemble-brain:begin:layer1-rule" not in claude_final
    assert "Never self-approve." not in claude_final
    assert "Keep code clean." in claude_final and "U1 Owner Notes" in claude_final

    mcp_final = json.loads(mcp.read_text(encoding="utf-8"))
    assert "super-brain" not in mcp_final["mcpServers"]
    assert mcp_final["theme"] == "dark"
    assert mcp_final["mcpServers"]["userMcp"] == {"command": "npx"}
    assert mcp_final["mcpServers"]["u1Sibling"] == {"command": "uvx"}
    assert mcp_final["u1Setting"] == {"preserve": True}

    toml_final = codex_toml.read_text(encoding="utf-8")
    assert "super-brain" not in toml_final
    assert "# Top Codex comment" in toml_final
    assert "# inline user model comment" in toml_final
    assert "# Keep fast profile comment" in toml_final
    assert "# U1 added later by owner" in toml_final
    assert "# inline u1 comment" in toml_final
    parsed_toml: dict[str, Any] = tomlkit.parse(toml_final).unwrap()
    assert parsed_toml["profiles"]["deep"]["mode"] == "strict"

    # Tampering INSIDE Brain's managed block refuses rollback planning with REVISION_CONFLICT.
    tamp = e2e.checkout / "TAMPER.md"
    tamp.write_text("# Base\n", encoding="utf-8", newline="\n")
    tamp_m = merge_markdown_block("# Base\n", slice_id="s-tamp", block_body="Brain body.", expected_slice_digest=None)
    prop_t = e2e.svc.create_proposal(
        owner_id=OWNER,
        kind="bootstrap",
        reason="slice tamper check",
        resources=(RiskResource("c2"),),
        targets=(
            TargetWriteInput(
                e2e.checkout,
                "TAMPER.md",
                tamp_m.updated_text.encode("utf-8"),
                ManagedFormat.MARKDOWN,
                "s-tamp",
                tamp_m.slice_digest,
            ),
        ),
    )
    apply_t = _sign(e2e, prop_t, action=ApprovalAction.APPLY, recovery_scope=RecoveryScope.CONTINUE_OR_ROLLBACK)
    e2e.svc.apply_proposal(
        prop_t.proposal_id, approval=apply_t, signer_id=e2e.signer.signer_id, channel=ApprovalChannel.SSH_KEY
    )
    tamp.write_text(
        tamp.read_text(encoding="utf-8").replace("Brain body.", "User edited inside!"),
        encoding="utf-8",
        newline="\n",
    )
    with pytest.raises(BrainError) as rev_exc:
        e2e.svc.plan_rollback_targets(prop_t.proposal_id)
    assert rev_exc.value.code is ErrorCode.REVISION_CONFLICT


def test_interrupted_turn_rollback_works_after_nonce_expiry_and_guards_swap(
    e2e: E2ECtx, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cases 33 & 106: interrupted-turn rollback uses active recovery_grant after 10-min nonce expiry."""
    f1 = e2e.checkout / "FILE1.md"
    f1.write_bytes(b"U0 file1\n")

    prop = e2e.svc.create_proposal(
        owner_id=OWNER,
        kind="bootstrap",
        reason="interrupted apply",
        resources=(RiskResource("c2"), RiskResource("c5")),
        targets=(
            TargetWriteInput(e2e.checkout, "FILE1.md", b"U1 brain file1\n", ManagedFormat.RAW, "r1"),
            TargetWriteInput(e2e.checkout, "FILE2.md", b"U1 brain file2\n", ManagedFormat.RAW, "r2"),
        ),
    )

    real_pub = cast(NoReplacePublisher, e2e.os_.publisher)
    orig_pub_nr = real_pub.publish_no_replace
    calls = [0]

    def _interrupt_on_second(staging: Path, final: Path) -> None:
        calls[0] += 1
        if calls[0] == 2:
            raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "simulated turn timeout")
        orig_pub_nr(staging, final)

    monkeypatch.setattr(real_pub, "publish_no_replace", _interrupt_on_second)
    msg = _sign(e2e, prop, action=ApprovalAction.APPLY, recovery_scope=RecoveryScope.CONTINUE_OR_ROLLBACK)
    with pytest.raises(BrainError):
        e2e.svc.apply_proposal(
            prop.proposal_id, approval=msg, signer_id=e2e.signer.signer_id, channel=ApprovalChannel.SSH_KEY
        )
    monkeypatch.undo()

    partial_prop = e2e.svc.get_proposal(prop.proposal_id)
    assert partial_prop.active_journal_id is not None
    partial_j = e2e.svc.get_journal(partial_prop.active_journal_id)
    assert partial_j.status in {ProposalStatus.PARTIALLY_APPLIED, ProposalStatus.APPLYING}
    assert e2e.rt.policy.recovery_grant(partial_j.grant_id).state == "active"
    assert f1.read_bytes() == b"U1 brain file1\n"

    # Advance clock past the 10-minute nonce TTL (case 33); recovery_grant must still allow interrupted rollback.
    e2e.clock.advance(timedelta(minutes=25))

    # Case 106 sub-check on a second partial apply: identical-bytes new PhysicalObjectId halts in RECOVERY_REQUIRED.
    f_swap = e2e.checkout / "SWAP1.md"
    f_swap.write_bytes(b"U0 swap\n")
    prop_s = e2e.svc.create_proposal(
        owner_id=OWNER,
        kind="bootstrap",
        reason="case 106 physical guard",
        resources=(RiskResource("c2"),),
        targets=(
            TargetWriteInput(e2e.checkout, "SWAP1.md", b"U1 swap bytes\n", ManagedFormat.RAW, "s1"),
            TargetWriteInput(e2e.checkout, "SWAP2.md", b"U1 swap2\n", ManagedFormat.RAW, "s2"),
        ),
    )
    calls[0] = 0
    monkeypatch.setattr(real_pub, "publish_no_replace", _interrupt_on_second)
    msg_s = _sign(e2e, prop_s, action=ApprovalAction.APPLY, recovery_scope=RecoveryScope.CONTINUE_OR_ROLLBACK)
    with pytest.raises(BrainError):
        e2e.svc.apply_proposal(
            prop_s.proposal_id, approval=msg_s, signer_id=e2e.signer.signer_id, channel=ApprovalChannel.SSH_KEY
        )
    monkeypatch.undo()

    swap_tmp = e2e.checkout / "swap-ident.md"
    swap_tmp.write_bytes(b"U1 swap bytes\n")
    f_swap.unlink()
    os.replace(swap_tmp, f_swap)

    j_s_id = e2e.svc.get_proposal(prop_s.proposal_id).active_journal_id
    assert j_s_id is not None
    with pytest.raises(BrainError) as case106_exc:
        e2e.svc.rollback_interrupted_journal(j_s_id)
    assert case106_exc.value.code is ErrorCode.REVISION_CONFLICT
    assert f_swap.read_bytes() == b"U1 swap bytes\n", "user file MUST be kept intact on case 106 conflict"
    j_s = e2e.svc.get_journal(j_s_id)
    assert j_s.status is ProposalStatus.RECOVERY_REQUIRED
    assert j_s.files[0].backup_path is not None and Path(j_s.files[0].backup_path).read_bytes() == b"U0 swap\n"

    # Continue-only grant refuses interrupted rollback without mutating partial_j.
    f_cont = e2e.checkout / "CONT1.md"
    f_cont.write_bytes(b"U0 cont\n")
    prop_c = e2e.svc.create_proposal(
        owner_id=OWNER,
        kind="bootstrap",
        reason="continue-only guard",
        resources=(RiskResource("c2"),),
        targets=(
            TargetWriteInput(e2e.checkout, "CONT1.md", b"U1 cont1\n", ManagedFormat.RAW, "c1"),
            TargetWriteInput(e2e.checkout, "CONT2.md", b"U1 cont2\n", ManagedFormat.RAW, "c2"),
        ),
    )
    calls[0] = 0
    monkeypatch.setattr(real_pub, "publish_no_replace", _interrupt_on_second)
    msg_c = _sign(e2e, prop_c, action=ApprovalAction.APPLY, recovery_scope=RecoveryScope.CONTINUE)
    with pytest.raises(BrainError):
        e2e.svc.apply_proposal(
            prop_c.proposal_id, approval=msg_c, signer_id=e2e.signer.signer_id, channel=ApprovalChannel.SSH_KEY
        )
    monkeypatch.undo()
    j_c_id = e2e.svc.get_proposal(prop_c.proposal_id).active_journal_id
    assert j_c_id is not None
    with pytest.raises(BrainError) as cont_exc:
        e2e.svc.rollback_interrupted_journal(j_c_id)
    assert cont_exc.value.code in {ErrorCode.INVALID_INPUT, ErrorCode.UNAUTHENTICATED}
    assert f_cont.read_bytes() == b"U1 cont1\n"

    # Clean interrupted rollback succeeds past nonce expiry and restores U0 cleanly!
    rolled = e2e.svc.rollback_interrupted_journal(partial_j.journal_id)
    assert rolled.status is ProposalStatus.ROLLED_BACK
    assert f1.read_bytes() == b"U0 file1\n"
    assert not (e2e.checkout / "FILE2.md").exists()
    assert e2e.svc.get_proposal(prop.proposal_id).status is ProposalStatus.ROLLED_BACK
    assert e2e.rt.policy.recovery_grant(rolled.grant_id).end_reason == "journal_closed"
