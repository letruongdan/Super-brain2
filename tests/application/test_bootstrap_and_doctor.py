"""I3-5 oracle: §7.4 + Layer 1-2 bootstrap templates, ``brain bootstrap`` flow, & read-only ``brain doctor``.

Requirement sources: spec rev 22 §7.4, §11.2-§11.3, §13, §14.2, §20 cases 12, 14; plan I3-5 Step 2 & Step 3.
"""

from __future__ import annotations

import base64
import json
import struct
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from superbrain.adapters.harness_config.bootstrap_templates import (
    AUTHORITY_ASK_COMMANDS,
    LAYER1_RULE_TEXT,
    plan_claude_bootstrap,
    plan_codex_bootstrap,
)
from superbrain.adapters.harness_config.markdown_blocks import merge_markdown_block
from superbrain.adapters.harness_config.merger import SharedConfigMergerAdapter
from superbrain.adapters.os import os_adapters
from superbrain.application.review_apply import ReviewApplyService, TargetWriteInput
from superbrain.cli.main import main as brain_main
from superbrain.cli_api.operator import OPERATOR_PATHS
from superbrain.composition.init_entry import InitRequest, init_store, reset_signers
from superbrain.core._kernel_approval import (
    RISK_POLICY_VERSION,
    ApprovalAction,
    ApprovalChannel,
    ApprovalMessage,
    Layer2State,
    RecoveryScope,
    RiskLevel,
    RiskResource,
    SignerEnrollment,
)
from superbrain.core.errors import ErrorCode
from superbrain.core.proposals import ManagedFormat, ProposalStatus
from superbrain.ports.os import OsAdapters
from superbrain.storage.backup import create_policy_backup
from superbrain.storage.kernel_schema import KERNEL_POLICY_MIGRATIONS
from superbrain.storage.layout import DataRoot
from superbrain.storage.proposals import PolicyApplyAuthority, StoreProposalAdapter
from superbrain.storage.restore import restore_policy
from tests.storage.conftest import maintenance_lease
from tests.support.clock import FakeClock
from tests.support.fs import digest_tree
from tests.support.inc2_fixture import reopen_kernel_job_runtime
from tests.support.inc2_transport import FakeMonotonicClock
from tests.support.kernel_auth import seed_principal_and_credential

OWNER = "dan"
MACHINE = "i3-5-box"


def _ssh_enrollment(tag: str = "doc") -> SignerEnrollment:
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


def test_bootstrap_templates_embed_section_7_4_handoff_rules_and_nonblocking_hooks(trusted_tmp: Path) -> None:
    """I3-5 §7.4 + Layer 1-2: both Claude and Codex templates cover 6 moments, takeover ACK, & non-blocking hooks."""
    from superbrain.adapters.harness_config.bootstrap_templates import HANDOFF_RULE_TEXT, HANDOFF_UPDATE_MOMENTS

    assert len(HANDOFF_UPDATE_MOMENTS) == 6
    lower_rule = HANDOFF_RULE_TEXT.lower()
    expected_tokens = (
        "handoff_status",
        "stored",
        "writer_status",
        "holder",
        "not_holder",
        "commit_outcome_unknown",
        "not_stored_policy",
        "manual_submission",
        "task_state",
        "active",
    )
    for token in expected_tokens:
        assert token in lower_rule, f"missing §7.4 token {token!r} in HANDOFF_RULE_TEXT"

    checkout = trusted_tmp / "repo"
    checkout.mkdir()
    profile = trusted_tmp / "cfg" / "profile.json"
    (checkout / "CLAUDE.md").write_text("# User Prose\n", encoding="utf-8")
    (checkout / "AGENTS.md").write_text("# Agents Prose\n", encoding="utf-8")

    plans = (
        (
            plan_claude_bootstrap(checkout_root=checkout, profile_path=profile),
            "CLAUDE.md",
            ".claude/settings.local.json",
        ),
        (plan_codex_bootstrap(checkout_root=checkout, profile_path=profile), "AGENTS.md", ".codex/hooks.json"),
    )
    for plan, md_name, hook_name in plans:
        by_rel = {t.rel_path: t for t in plan.targets}
        md_text = by_rel[md_name].preview_text
        assert LAYER1_RULE_TEXT in md_text
        assert HANDOFF_RULE_TEXT in md_text
        assert "# User Prose" in md_text or "# Agents Prose" in md_text
        hook_text = by_rel[hook_name].preview_text
        for cmd in AUTHORITY_ASK_COMMANDS:
            assert cmd in hook_text
        hook_json = json.loads(hook_text)
        assert "hooks" in hook_json
        assert "non_blocking" in hook_text or "remind" in hook_text.lower()


def test_bootstrap_service_and_cli_create_high_risk_proposal_without_writing_checkout(
    trusted_tmp: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    """I3-5: create_bootstrap_proposal & brain bootstrap emit HIGH-risk PENDING ChangeProposal with 0 file writes."""
    import superbrain.composition.bootstrap_entry as bootstrap_entry
    from superbrain.adapters.harness_config.bootstrap_templates import AdapterBootstrapPlanner
    from superbrain.application.bootstrap import create_bootstrap_proposal

    assert hasattr(bootstrap_entry, "main")
    assert "/v2/operator/proposal/bootstrap" in OPERATOR_PATHS

    clock = FakeClock(datetime(2026, 11, 19, 12, 0, tzinfo=UTC))
    os_ = os_adapters(clock=clock)
    cfg_dir, data_root, checkout, home = (
        trusted_tmp / "cfg",
        trusted_tmp / "data",
        trusted_tmp / "checkout",
        trusted_tmp / "home",
    )
    for d in (cfg_dir, checkout, home):
        d.mkdir(parents=True, exist_ok=True)
        os_.permissions.secure_directory(d)
    (checkout / "CLAUDE.md").write_text("# Keep me\n", encoding="utf-8")
    profile = cfg_dir / "cli.profile.json"
    profile.write_text("{}", encoding="utf-8")
    os_.permissions.secure_file(profile)

    rep = init_store(
        InitRequest(
            data_root=data_root, config_dir=cfg_dir, owner_id=OWNER, machine_id=MACHINE, signer=_ssh_enrollment("boot")
        ),
        os_,
    )
    rt = reopen_kernel_job_runtime(data_root, rep.store_id, os_)
    try:
        svc = ReviewApplyService(
            StoreProposalAdapter(rt.store, os_),
            PolicyApplyAuthority(rt.policy),
            os_,
            data_root=data_root,
            home_dir=home,
            config_merger=SharedConfigMergerAdapter(),
        )
        snap_before = digest_tree(checkout)
        planner = AdapterBootstrapPlanner()
        for harness in ("claude-code", "codex"):
            h_typed: Any = harness
            prop = create_bootstrap_proposal(
                svc,
                owner_id=OWNER,
                harness_id=h_typed,
                checkout_root=checkout,
                profile_path=profile,
                planner=planner,
                os_=os_,
            )
            assert prop.status is ProposalStatus.PENDING
            assert prop.risk_level is RiskLevel.HIGH
            assert prop.kind == "bootstrap"
            assert len(prop.targets) == 3
        assert digest_tree(checkout) == snap_before
    finally:
        rt.close()

    # CLI argv validation + python -I routing.
    rel_argv = ["bootstrap", "--harness", "claude-code", "--checkout", "rel/dir", "--profile", str(profile)]
    assert brain_main(rel_argv) == 2
    assert capfd.readouterr().err.strip().splitlines()[-1] == ErrorCode.INVALID_INPUT.value
    capfd.readouterr()
    assert (
        brain_main(
            [
                "bootstrap",
                "--harness",
                "claude-code",
                "--checkout",
                str(checkout),
                "--profile",
                str(trusted_tmp / "missing-profile.json"),
            ]
        )
        == 1
    )
    assert capfd.readouterr().err.strip().splitlines()[-1] == ErrorCode.NOT_FOUND.value


def _seed_diagnostic_root(
    trusted_tmp: Path, clock: FakeClock, mono: FakeMonotonicClock, os_: OsAdapters
) -> tuple[Path, Path, Path]:
    cfg_dir, data_root, checkout, home = (
        trusted_tmp / "cfg",
        trusted_tmp / "data",
        trusted_tmp / "repo",
        trusted_tmp / "home",
    )
    for d in (cfg_dir, checkout, home):
        d.mkdir(parents=True, exist_ok=True)
        os_.permissions.secure_directory(d)

    rep = init_store(
        InitRequest(
            data_root=data_root, config_dir=cfg_dir, owner_id=OWNER, machine_id=MACHINE, signer=_ssh_enrollment("d1")
        ),
        os_,
    )
    rt = reopen_kernel_job_runtime(data_root, rep.store_id, os_)
    try:
        bak_policy = create_policy_backup(rt.policy, os_, clock.now())
        seed_principal_and_credential(rt.policy, owner_id=OWNER, harness_id="claude-code", machine_id=MACHINE)
        seed_principal_and_credential(rt.policy, owner_id=OWNER, harness_id="codex", machine_id=MACHINE)
        rt.policy.set_layer2_state(
            harness_id="claude-code",
            host_version="1.0.0",
            config_digest="sha256:" + "1" * 64,
            state=Layer2State.VERIFIED,
        )
        rt.policy.set_layer2_state(
            harness_id="codex",
            host_version="1.0.0",
            config_digest="sha256:" + "2" * 64,
            state=Layer2State.UNKNOWN,
        )
        svc = ReviewApplyService(
            StoreProposalAdapter(rt.store, os_),
            PolicyApplyAuthority(rt.policy),
            os_,
            data_root=data_root,
            home_dir=home,
            config_merger=SharedConfigMergerAdapter(),
        )
        (checkout / "AGENTS.md").write_text("# A\n", encoding="utf-8")
        (checkout / "CLAUDE.md").write_text("# C\n", encoding="utf-8")
        targets = [
            TargetWriteInput(
                checkout, n, m.updated_text.encode("utf-8"), ManagedFormat.MARKDOWN, "sb-doc", m.slice_digest
            )
            for n, base, body in (("AGENTS.md", "# A\n", "## A-blk\n"), ("CLAUDE.md", "# C\n", "## C-blk\n"))
            for m in (merge_markdown_block(base, slice_id="sb-doc", block_body=body, expected_slice_digest=None),)
        ]
        prop = svc.create_proposal(
            owner_id=OWNER, kind="bootstrap", reason="doc", resources=[RiskResource(component="c2")], targets=targets
        )
        t_files = prop.to_target_files()
        n1 = rt.policy.issue_nonce(
            action=ApprovalAction.APPROVE, subject_id=prop.proposal_id, risk_level=RiskLevel.HIGH
        )
        m1 = ApprovalMessage(
            store_id=rep.store_id,
            owner_id=OWNER,
            trust_generation=1,
            action=ApprovalAction.APPROVE,
            subject_id=prop.proposal_id,
            subject_revision=prop.subject_revision,
            resource_digests=prop.resource_digests,
            target_files=t_files,
            risk_level=RiskLevel.HIGH,
            risk_policy_version=RISK_POLICY_VERSION,
            recovery_scope=RecoveryScope.NONE,
            nonce=n1.nonce,
            expires_at=n1.expires_at,
        )
        svc.approve_proposal(
            prop.proposal_id, approval=m1, signer_id=rep.signer.signer_id, channel=ApprovalChannel.SSH_KEY
        )
        n2 = rt.policy.issue_nonce(
            action=ApprovalAction.APPLY, subject_id=prop.proposal_id, risk_level=RiskLevel.HIGH
        )
        m2 = ApprovalMessage(
            store_id=rep.store_id,
            owner_id=OWNER,
            trust_generation=1,
            action=ApprovalAction.APPLY,
            subject_id=prop.proposal_id,
            subject_revision=prop.subject_revision,
            resource_digests=prop.resource_digests,
            target_files=t_files,
            risk_level=RiskLevel.HIGH,
            risk_policy_version=RISK_POLICY_VERSION,
            recovery_scope=RecoveryScope.CONTINUE_OR_ROLLBACK,
            nonce=n2.nonce,
            expires_at=n2.expires_at,
        )
        svc.apply_proposal(
            prop.proposal_id, approval=m2, signer_id=rep.signer.signer_id, channel=ApprovalChannel.SSH_KEY
        )
    finally:
        rt.close()

    # Introduce drift on CLAUDE.md + pending partial journal + unresolved lock + reset signers + pending tombstone!
    drifted = (checkout / "CLAUDE.md").read_text(encoding="utf-8").replace("## C-blk", "## UserTampered")
    (checkout / "CLAUDE.md").write_text(drifted, encoding="utf-8")

    clock.advance(timedelta(days=1))
    with maintenance_lease(data_root) as (root, lease):
        restore_policy(
            root,
            lease,
            os_,
            bak_policy,
            store_id=rep.store_id,
            now=clock.now(),
            migrations=KERNEL_POLICY_MIGRATIONS,
        )
    reset_signers(rep.daemon_config_path, _ssh_enrollment("d2"), os_)

    # Leave an un-drained pending_restore_tombstones.json matching store restore_epoch (0) and create partial journal.
    layout = DataRoot.at(data_root)
    layout.pending_restore_tombstones_path.write_bytes(
        json.dumps({"schema_version": 1, "restore_epoch": 0, "expired_holders": []}).encode("utf-8")
    )
    os_.permissions.secure_file(layout.pending_restore_tombstones_path)
    _ = mono
    return data_root, rep.daemon_config_path, checkout


def test_doctor_strictly_readonly_and_surfaces_handover_states_drift_and_locks(
    trusted_tmp: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    """I3-5 §13 / Step 3: brain doctor mutates 0 bytes and exposes schema/epoch/reset/L2/locks/drift/tombstones."""
    import superbrain.composition.doctor_entry as doctor_entry

    assert brain_main(["doctor", "--config", "relative/daemon.json"]) == 2
    assert capfd.readouterr().err.strip().splitlines()[-1] == ErrorCode.INVALID_INPUT.value
    capfd.readouterr()
    assert brain_main(["doctor", "--config", str(trusted_tmp / "missing-daemon.json")]) == 1
    assert capfd.readouterr().err.strip().splitlines()[-1] == ErrorCode.NOT_FOUND.value

    link_cfg_dir = trusted_tmp / "link-cfg"
    real_cfg_dir = trusted_tmp / "real-cfg"
    real_cfg_dir.mkdir()
    _make_dir_link(link_cfg_dir, real_cfg_dir)
    capfd.readouterr()
    assert brain_main(["doctor", "--config", str(link_cfg_dir / "daemon.json")]) == 1
    assert capfd.readouterr().err.strip().splitlines()[-1] == ErrorCode.UNSAFE_PATH.value

    clock = FakeClock(datetime(2026, 11, 19, 12, 0, tzinfo=UTC))
    mono = FakeMonotonicClock(1_000_000_000)
    os_ = os_adapters(clock=clock, monotonic=mono)
    data_root, cfg_path, checkout = _seed_diagnostic_root(trusted_tmp / "diag", clock, mono, os_)

    # Snapshot every file in data_root and checkout before running doctor.
    snap_data_before = digest_tree(data_root)
    snap_checkout_before = digest_tree(checkout)

    report = doctor_entry.run_doctor(cfg_path, checkout_root=checkout, os_=os_)
    assert report.schema.store_version == 5 and report.schema.policy_version == 4
    assert report.restore_epoch == 0
    assert report.trust_generation is not None and report.trust_generation >= 3
    assert report.signer_reset_recorded is True
    assert len(report.signers) >= 1
    assert report.terminal_channel_eligible is False
    assert report.unresolved_accounting_locks
    assert report.pending_restore_tombstones.present is True
    assert report.bootstrap_drifts
    assert report.remediations

    capfd.readouterr()
    rc_json = brain_main(["doctor", "--config", str(cfg_path), "--checkout", str(checkout), "--json"])
    assert rc_json == 0
    out_json = json.loads(capfd.readouterr().out)
    assert out_json["ok"] is True
    d = out_json["data"]
    assert d["schema"]["store_version"] == 5 and d["schema"]["policy_version"] == 4
    assert d["signer_reset_recorded"] is True
    assert d["terminal_channel_eligible"] is False
    assert len(d["unresolved_accounting_locks"]) >= 1
    assert d["pending_restore_tombstones"]["present"] is True
    assert len(d["bootstrap_drifts"]) >= 1
    assert len(d["remediations"]) >= 1

    # Human handover output also succeeds cleanly and surfaces key guidance.
    capfd.readouterr()
    rc_text = brain_main(["doctor", "--config", str(cfg_path), "--checkout", str(checkout)])
    assert rc_text == 0
    human_out = capfd.readouterr().out.lower()
    assert "accounting" in human_out and "drift" in human_out

    assert digest_tree(data_root) == snap_data_before
    assert digest_tree(checkout) == snap_checkout_before
