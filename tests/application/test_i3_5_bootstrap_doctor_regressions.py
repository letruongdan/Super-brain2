"""I3-5 Round-2 regression tests for ``brain doctor``, Case 107 intent visibility, & bootstrap security/rollback.

Requirement sources: ``i3-5/review.md`` findings ``I3-5-R02``, ``I3-5-R03``, ``I3-5-R04``, ``I3-5-N2``, ``I3-5-N3``.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import sqlite3
import stat
import struct
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import superbrain.composition.doctor_entry as doctor_entry
from superbrain.adapters.harness_config.bootstrap_templates import (
    AdapterBootstrapPlanner,
    plan_claude_bootstrap,
    plan_codex_bootstrap,
)
from superbrain.adapters.harness_config.markdown_blocks import merge_markdown_block
from superbrain.adapters.harness_config.merger import SharedConfigMergerAdapter
from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.daemon_config import read_daemon_config
from superbrain.application.approvals import OperatorService
from superbrain.application.bootstrap import create_bootstrap_proposal
from superbrain.application.review_apply import ReviewApplyService, TargetWriteInput
from superbrain.cli.main import main as brain_main
from superbrain.composition.init_entry import InitReport, InitRequest, init_store
from superbrain.composition.operator_entry import make_default_bootstrap_handler
from superbrain.core._kernel_approval import (
    RISK_POLICY_VERSION,
    ApprovalAction,
    ApprovalChannel,
    ApprovalMessage,
    RecoveryScope,
    RiskLevel,
    RiskResource,
    SignerEnrollment,
)
from superbrain.core.canonical import canonical_json
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.proposals import JournalDirection, ManagedFormat
from superbrain.ports.os import OsAdapters
from superbrain.storage.cas import blob_path
from superbrain.storage.layout import DataRoot
from superbrain.storage.proposals import PolicyApplyAuthority, StoreProposalAdapter
from tests.support.clock import FakeClock
from tests.support.fs import digest_tree
from tests.support.inc2_fixture import reopen_kernel_job_runtime
from tests.support.inc2_transport import FakeMonotonicClock, register_workspace_direct
from tests.support.kernel_auth import seed_principal_and_credential
from tests.support.rereview_1d666f5 import leaf_sha

OWNER = "dan"
MACHINE = "r2-box"


def _ssh_enrollment(tag: str) -> SignerEnrollment:
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


def _init_root(
    base: Path, os_: OsAdapters, *, tag: str = "r2"
) -> tuple[InitReport, Path, Path, Path]:
    cfg_dir, data_root, checkout = base / "cfg", base / "data", base / "checkout"
    for d in (cfg_dir, checkout):
        d.mkdir(parents=True, exist_ok=True)
        os_.permissions.secure_directory(d)
    rep = init_store(
        InitRequest(
            data_root=data_root,
            config_dir=cfg_dir,
            owner_id=OWNER,
            machine_id=MACHINE,
            signer=_ssh_enrollment(tag),
        ),
        os_,
    )
    return rep, data_root, cfg_dir, checkout


def _write_profile(
    path: Path,
    os_: OsAdapters,
    *,
    data_root: Path,
    cfg_dir: Path,
    expected_store_id: str,
    checkout_path: Path | None = None,
    credential_file: Path | None = None,
    workspace: dict[str, str] | None = None,
) -> Path:
    payload: dict[str, Any] = {
        "version": 1,
        "endpoint_path": str(data_root / "endpoint.json"),
        "expected_store_id": expected_store_id,
        "ca_file": str(cfg_dir / "tls" / "ca.pem"),
        "leaf_cert_sha256": leaf_sha(cfg_dir / "tls" / "server.pem"),
        "credential_file": str(credential_file if credential_file is not None else (cfg_dir / "cli.credential")),
    }
    if workspace is not None:
        payload["workspace"] = workspace
    elif checkout_path is not None:
        payload["workspace"] = {
            "alias": "ws-r2",
            "checkout_path": str(checkout_path),
            "expected_workspace_id": "01920000-0000-7000-8000-000000000010",
            "expected_checkout_id": "01920000-0000-7000-8000-000000000011",
        }
    path.write_text(json.dumps(payload), encoding="utf-8")
    os_.permissions.secure_file(path)
    return path


def _approve_and_apply(
    rt: Any, svc: ReviewApplyService, store_id: str, signer_id: str, proposal_id: str
) -> None:
    prop = svc.get_proposal(proposal_id)
    t_files = prop.to_target_files()
    n1 = rt.policy.issue_nonce(action=ApprovalAction.APPROVE, subject_id=prop.proposal_id, risk_level=prop.risk_level)
    m1 = ApprovalMessage(
        store_id=store_id,
        owner_id=OWNER,
        trust_generation=rt.policy.trust_generation(),
        action=ApprovalAction.APPROVE,
        subject_id=prop.proposal_id,
        subject_revision=prop.subject_revision,
        resource_digests=prop.resource_digests,
        target_files=t_files,
        risk_level=prop.risk_level,
        risk_policy_version=RISK_POLICY_VERSION,
        recovery_scope=RecoveryScope.NONE,
        nonce=n1.nonce,
        expires_at=n1.expires_at,
    )
    svc.approve_proposal(prop.proposal_id, approval=m1, signer_id=signer_id, channel=ApprovalChannel.SSH_KEY)
    n2 = rt.policy.issue_nonce(action=ApprovalAction.APPLY, subject_id=prop.proposal_id, risk_level=prop.risk_level)
    m2 = ApprovalMessage(
        store_id=store_id,
        owner_id=OWNER,
        trust_generation=rt.policy.trust_generation(),
        action=ApprovalAction.APPLY,
        subject_id=prop.proposal_id,
        subject_revision=prop.subject_revision,
        resource_digests=prop.resource_digests,
        target_files=t_files,
        risk_level=prop.risk_level,
        risk_policy_version=RISK_POLICY_VERSION,
        recovery_scope=RecoveryScope.CONTINUE_OR_ROLLBACK,
        nonce=n2.nonce,
        expires_at=n2.expires_at,
    )
    svc.apply_proposal(prop.proposal_id, approval=m2, signer_id=signer_id, channel=ApprovalChannel.SSH_KEY)


def test_r02_doctor_rejects_store_mismatch_junction_data_dirs_tampered_cas_and_junction_checkout(
    trusted_tmp: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    """I3-5-R02: read-only doctor fails on store_id mismatch, junctioned policy/, tampered CAS, & junction checkout."""
    clock = FakeClock(datetime(2026, 11, 19, 12, 0, tzinfo=UTC))
    os_ = os_adapters(clock=clock, monotonic=FakeMonotonicClock(1_000_000_000))

    rep_a, root_a, cfg_dir_a, _ = _init_root(trusted_tmp / "store-a", os_, tag="a")
    rep_b, root_b, cfg_dir_b, co_b = _init_root(trusted_tmp / "store-b", os_, tag="b")

    # (a) expected_store_id mismatch via --config and --profile -> overall_status == "fail" with 0 mutations.
    cfg_a = read_daemon_config(rep_a.daemon_config_path, os_)
    cfg_mis = cfg_dir_a / "mismatch-daemon.json"
    cfg_mis.write_text(
        json.dumps(
            {
                "version": 1,
                "data_root": str(root_b),
                "expected_store_id": rep_a.store_id,
                "cert_path": str(cfg_a.cert_path),
                "key_path": str(cfg_a.key_path),
            }
        ),
        encoding="utf-8",
    )
    os_.permissions.secure_file(cfg_mis)
    prof_mis = _write_profile(
        cfg_dir_a / "mismatch-profile.json",
        os_,
        data_root=root_b,
        cfg_dir=cfg_dir_a,
        expected_store_id=rep_a.store_id,
    )

    snap_b = digest_tree(root_b)
    rep_mis = doctor_entry.run_doctor(cfg_mis, os_=os_)
    assert rep_mis.overall_status == "fail" and rep_mis.integrity_errors
    capfd.readouterr()
    assert brain_main(["doctor", "--profile", str(prof_mis), "--json"]) == 0
    mis_json = json.loads(capfd.readouterr().out)["data"]
    assert mis_json["overall_status"] == "fail" and len(mis_json["integrity_errors"]) >= 1
    assert digest_tree(root_b) == snap_b

    # (b) Junctioned data_root/policy/ -> overall_status == "fail", 0 mutations on target.
    ext_policy = trusted_tmp / "external-policy"
    shutil.move(str(root_a / "policy"), str(ext_policy))
    _make_dir_link(root_a / "policy", ext_policy)
    snap_ext = digest_tree(ext_policy)
    rep_junc = doctor_entry.run_doctor(rep_a.daemon_config_path, os_=os_)
    assert rep_junc.overall_status == "fail" and rep_junc.integrity_errors
    assert digest_tree(ext_policy) == snap_ext

    # (c) Junctioned profile.workspace.checkout_path (omitting --checkout) -> UNSAFE_PATH!
    real_co, link_co = trusted_tmp / "real-co", trusted_tmp / "link-co"
    real_co.mkdir()
    os_.permissions.secure_directory(real_co)
    _make_dir_link(link_co, real_co)
    prof_link = _write_profile(
        cfg_dir_b / "link-co-profile.json",
        os_,
        data_root=root_b,
        cfg_dir=cfg_dir_b,
        expected_store_id=rep_b.store_id,
        checkout_path=link_co,
    )
    with pytest.raises(BrainError) as co_err:
        doctor_entry.run_doctor(prof_link, is_profile=True, os_=os_)
    assert co_err.value.code is ErrorCode.UNSAFE_PATH
    capfd.readouterr()
    assert brain_main(["doctor", "--profile", str(prof_link)]) == 1
    assert capfd.readouterr().err.strip().splitlines()[-1] == ErrorCode.UNSAFE_PATH.value

    # (d) Tampered CAS proposal payload blob hiding CLAUDE.md drift -> integrity_errors + overall_status == "fail".
    (co_b / "CLAUDE.md").write_text("# Original\n", encoding="utf-8")
    rt_b = reopen_kernel_job_runtime(root_b, rep_b.store_id, os_)
    try:
        svc_b = ReviewApplyService(
            StoreProposalAdapter(rt_b.store, os_),
            PolicyApplyAuthority(rt_b.policy),
            os_,
            data_root=root_b,
            home_dir=trusted_tmp / "home-b",
            config_merger=SharedConfigMergerAdapter(),
        )
        m_b = merge_markdown_block("# Original\n", slice_id="s1", block_body="body\n", expected_slice_digest=None)
        prop_b = svc_b.create_proposal(
            owner_id=OWNER,
            kind="bootstrap",
            reason="cas check",
            resources=[RiskResource(component="c2")],
            targets=[
                TargetWriteInput(
                    co_b, "CLAUDE.md", m_b.updated_text.encode("utf-8"), ManagedFormat.MARKDOWN, "s1", m_b.slice_digest
                )
            ],
        )
        _approve_and_apply(rt_b, svc_b, rep_b.store_id, rep_b.signer.signer_id, prop_b.proposal_id)
    finally:
        rt_b.close()

    tampered_md = b"# Drifted content on disk!\n"
    (co_b / "CLAUDE.md").write_bytes(tampered_md)
    from superbrain.core.canonical import digest_bytes

    db_ro = sqlite3.connect(f"file:{DataRoot.at(root_b).store_db}?mode=ro", uri=True)
    try:
        p_dig = str(
            db_ro.execute(
                "SELECT payload_digest FROM p_proposals_proposals WHERE proposal_id = ?", (prop_b.proposal_id,)
            ).fetchone()[0]
        )
    finally:
        db_ro.close()
    blob = blob_path(DataRoot.at(root_b).cas_dir, p_dig)
    blob_obj = json.loads(blob.read_bytes().decode("utf-8"))
    blob_obj["targets"][0]["replacement_digest"] = digest_bytes(tampered_md)
    os.chmod(blob, stat.S_IRUSR | stat.S_IWUSR)
    blob.write_bytes(canonical_json(blob_obj))
    os_.permissions.secure_file(blob)

    snap_b_after, snap_co_after = digest_tree(root_b), digest_tree(co_b)
    rep_cas = doctor_entry.run_doctor(rep_b.daemon_config_path, checkout_root=co_b, os_=os_)
    assert rep_cas.overall_status == "fail" and rep_cas.integrity_errors
    assert digest_tree(root_b) == snap_b_after and digest_tree(co_b) == snap_co_after


def test_r03_and_n3_doctor_surfaces_case107_active_turn_intent_and_latest_target_drift_only(
    trusted_tmp: Path,
) -> None:
    """I3-5-R03 & N3: active unprojected ApplyTurnIntent blocks pass & re-bootstrap only checks latest APPLIED."""
    clock = FakeClock(datetime(2026, 11, 19, 12, 0, tzinfo=UTC))
    os_ = os_adapters(clock=clock, monotonic=FakeMonotonicClock(1_000_000_000))
    rep, data_root, cfg_dir, co = _init_root(trusted_tmp / "case107", os_, tag="c107")

    (co / "CLAUDE.md").write_text("# Base\n", encoding="utf-8")
    rt = reopen_kernel_job_runtime(data_root, rep.store_id, os_)
    try:
        authority = PolicyApplyAuthority(rt.policy)
        svc = ReviewApplyService(
            StoreProposalAdapter(rt.store, os_),
            authority,
            os_,
            data_root=data_root,
            home_dir=trusted_tmp / "home",
            config_merger=SharedConfigMergerAdapter(),
        )
        m1 = merge_markdown_block("# Base\n", slice_id="s1", block_body="v1\n", expected_slice_digest=None)
        p1 = svc.create_proposal(
            owner_id=OWNER,
            kind="bootstrap",
            reason="v1",
            resources=[RiskResource(component="c2")],
            targets=[
                TargetWriteInput(
                    co, "CLAUDE.md", m1.updated_text.encode("utf-8"), ManagedFormat.MARKDOWN, "s1", m1.slice_digest
                )
            ],
        )
        _approve_and_apply(rt, svc, rep.store_id, rep.signer.signer_id, p1.proposal_id)

        # N3: re-apply p2 superseding p1 on the same target (co, "CLAUDE.md") -> 0 false drift!
        clock.advance(timedelta(seconds=5))
        m2 = merge_markdown_block(
            m1.updated_text, slice_id="s1", block_body="v2\n", expected_slice_digest=m1.slice_digest
        )
        p2 = svc.create_proposal(
            owner_id=OWNER,
            kind="bootstrap",
            reason="v2",
            resources=[RiskResource(component="c2")],
            targets=[
                TargetWriteInput(
                    co, "CLAUDE.md", m2.updated_text.encode("utf-8"), ManagedFormat.MARKDOWN, "s1", m2.slice_digest
                )
            ],
        )
        _approve_and_apply(rt, svc, rep.store_id, rep.signer.signer_id, p2.proposal_id)
    finally:
        rt.close()

    rep_n3 = doctor_entry.run_doctor(rep.daemon_config_path, checkout_root=co, os_=os_)
    assert rep_n3.bootstrap_drifts == () and rep_n3.overall_status == "pass"

    # R03 (Case 107): record active ROLLBACK ApplyTurnIntent in policy.db WITHOUT writing p_proposals_journals.
    rt2 = reopen_kernel_job_runtime(data_root, rep.store_id, os_)
    try:
        authority2 = PolicyApplyAuthority(rt2.policy)
        svc2 = ReviewApplyService(
            StoreProposalAdapter(rt2.store, os_),
            authority2,
            os_,
            data_root=data_root,
            home_dir=trusted_tmp / "home",
            config_merger=SharedConfigMergerAdapter(),
        )
        plan_rb = svc2.plan_rollback_targets(p2.proposal_id)
        n_rb = rt2.policy.issue_nonce(
            action=ApprovalAction.ROLLBACK, subject_id=p2.proposal_id, risk_level=RiskLevel.HIGH
        )
        rb_msg = ApprovalMessage(
            store_id=rep.store_id,
            owner_id=OWNER,
            trust_generation=rt2.policy.trust_generation(),
            action=ApprovalAction.ROLLBACK,
            subject_id=p2.proposal_id,
            subject_revision=p2.subject_revision,
            resource_digests=plan_rb.resource_digests,
            target_files=plan_rb.target_files,
            risk_level=RiskLevel.HIGH,
            risk_policy_version=RISK_POLICY_VERSION,
            recovery_scope=RecoveryScope.ROLLBACK,
            nonce=n_rb.nonce,
            expires_at=n_rb.expires_at,
        )
        rb_rec = authority2.consume_approval(rb_msg, signer_id=rep.signer.signer_id, channel=ApprovalChannel.SSH_KEY)
        authority2.begin_journal_turn(
            approval_id=rb_rec.approval_id, journal_id=new_id(), direction=JournalDirection.ROLLBACK
        )
    finally:
        rt2.close()

    snap_d, snap_c = digest_tree(data_root), digest_tree(co)
    rep_107 = doctor_entry.run_doctor(rep.daemon_config_path, checkout_root=co, os_=os_)
    assert len(rep_107.active_turn_intents) >= 1
    assert rep_107.overall_status != "pass"
    assert rep_107.remediations
    d107 = rep_107.to_dict()
    intents_json = d107["active_turn_intents"]
    assert isinstance(intents_json, list) and len(intents_json) >= 1
    first_intent = intents_json[0]
    assert isinstance(first_intent, dict)
    assert first_intent.get("direction") == "rollback" and first_intent.get("state") == "active"
    assert digest_tree(data_root) == snap_d and digest_tree(co) == snap_c


def test_r04_and_n2_bootstrap_junction_leak_dotdot_rejection_and_claude_rollback_with_u1(
    trusted_tmp: Path,
) -> None:
    """I3-5-R04 & N2: reject ancestor junctions/oversized reads/.. segments, & rollback removes Claude hooks."""
    clock = FakeClock(datetime(2026, 11, 19, 12, 0, tzinfo=UTC))
    os_ = os_adapters(clock=clock, monotonic=FakeMonotonicClock(1_000_000_000))
    rep, data_root, cfg_dir, co = _init_root(trusted_tmp / "boot-r04", os_, tag="r04")
    profile = _write_profile(
        cfg_dir / "cli.profile.json", os_, data_root=data_root, cfg_dir=cfg_dir, expected_store_id=rep.store_id
    )

    # (a) Junction at .claude / .codex MUST NOT leak external secrets!
    ext_secret = trusted_tmp / "ext-secret"
    ext_secret.mkdir()
    (ext_secret / "settings.local.json").write_text('{"leak": "TOP_SECRET_VALUE"}\n', encoding="utf-8")
    (ext_secret / "hooks.json").write_text('{"leak": "CODEX_SECRET_VALUE"}\n', encoding="utf-8")

    co_j_claude, co_j_codex = trusted_tmp / "j-claude", trusted_tmp / "j-codex"
    for d in (co_j_claude, co_j_codex):
        d.mkdir()
        os_.permissions.secure_directory(d)
    _make_dir_link(co_j_claude / ".claude", ext_secret)
    _make_dir_link(co_j_codex / ".codex", ext_secret)

    with pytest.raises(BrainError) as jc_err:
        plan_claude_bootstrap(checkout_root=co_j_claude, profile_path=profile)
    assert jc_err.value.code is ErrorCode.UNSAFE_PATH and "TOP_SECRET_VALUE" not in str(jc_err.value)
    with pytest.raises(BrainError) as jx_err:
        plan_codex_bootstrap(checkout_root=co_j_codex, profile_path=profile)
    assert jx_err.value.code is ErrorCode.UNSAFE_PATH and "CODEX_SECRET_VALUE" not in str(jx_err.value)

    # (b) N2: oversized pre-existing config refused cleanly before reading unbounded bytes.
    co_huge = trusted_tmp / "huge"
    co_huge.mkdir()
    os_.permissions.secure_directory(co_huge)
    (co_huge / "CLAUDE.md").write_bytes(b"a" * 2_000_000)
    with pytest.raises(BrainError) as huge_err:
        plan_claude_bootstrap(checkout_root=co_huge, profile_path=profile)
    assert huge_err.value.code is ErrorCode.INVALID_INPUT

    # (c) Reject '..' segments in OperatorService `/v2/operator/proposal/bootstrap` & `create_bootstrap_proposal`.
    from superbrain.composition._bootstrap_wiring import PolicyHarnessProfileValidator

    rt = reopen_kernel_job_runtime(data_root, rep.store_id, os_)
    try:
        cli = seed_principal_and_credential(rt.policy, owner_id=OWNER, harness_id="cli", machine_id=MACHINE)
        claude_cred = seed_principal_and_credential(
            rt.policy, owner_id=OWNER, harness_id="claude-code", machine_id=MACHINE
        )
        ws_co = register_workspace_direct(
            rt, clock, claude_cred.principal, alias="ws-r04-co", checkout_dir=co, remote="https://github.example/dan/r04-co.git"
        )
        ws_j = register_workspace_direct(
            rt,
            clock,
            claude_cred.principal,
            alias="ws-r04-j",
            checkout_dir=co_j_claude,
            remote="https://github.example/dan/r04-j.git",
        )
        claude_cred_file = cfg_dir / "claude.credential"
        claude_cred_file.write_text(f"{claude_cred.token}\n", encoding="ascii")
        os_.permissions.secure_file(claude_cred_file)
        harness_profile = _write_profile(
            cfg_dir / "harness.profile.json",
            os_,
            data_root=data_root,
            cfg_dir=cfg_dir,
            expected_store_id=rep.store_id,
            credential_file=claude_cred_file,
            workspace={
                "alias": ws_co.alias,
                "checkout_path": str(co),
                "expected_workspace_id": ws_co.repo_id,
                "expected_checkout_id": ws_co.checkout_id,
            },
        )
        j_profile = _write_profile(
            cfg_dir / "j-harness.profile.json",
            os_,
            data_root=data_root,
            cfg_dir=cfg_dir,
            expected_store_id=rep.store_id,
            credential_file=claude_cred_file,
            workspace={
                "alias": ws_j.alias,
                "checkout_path": str(co_j_claude),
                "expected_workspace_id": ws_j.repo_id,
                "expected_checkout_id": ws_j.checkout_id,
            },
        )

        svc = ReviewApplyService(
            StoreProposalAdapter(rt.store, os_),
            PolicyApplyAuthority(rt.policy),
            os_,
            data_root=data_root,
            home_dir=trusted_tmp / "home",
            config_merger=SharedConfigMergerAdapter(),
        )
        planner = AdapterBootstrapPlanner()
        validator = PolicyHarnessProfileValidator(rt.policy, os_)
        with pytest.raises(BrainError) as cp_err:
            create_bootstrap_proposal(
                svc,
                owner_id=OWNER,
                harness_id="claude-code",
                checkout_root=co_j_claude,
                harness_profile_path=j_profile,
                planner=planner,
                profile_validator=validator,
                os_=os_,
            )
        assert cp_err.value.code is ErrorCode.UNSAFE_PATH

        dotdot_co = co / "sub" / ".." / "escape"
        dotdot_prof = cfg_dir / "sub" / ".." / "harness.profile.json"
        with pytest.raises(BrainError) as dd_err1:
            create_bootstrap_proposal(
                svc,
                owner_id=OWNER,
                harness_id="claude-code",
                checkout_root=dotdot_co,
                harness_profile_path=harness_profile,
                planner=planner,
                profile_validator=validator,
                os_=os_,
            )
        assert dd_err1.value.code is ErrorCode.UNSAFE_PATH

        op = OperatorService(
            rt.policy,
            ssh_verifier=lambda: None,
            review_apply=svc,
            bootstrap_handler=make_default_bootstrap_handler(rt.policy, os_),
        )
        for body in (
            {"harness": "claude-code", "checkout_root": str(dotdot_co), "harness_profile_path": str(harness_profile)},
            {"harness": "claude-code", "checkout_root": str(co), "harness_profile_path": str(dotdot_prof)},
        ):
            with pytest.raises(BrainError) as op_dd:
                op.handle("/v2/operator/proposal/bootstrap", cli.principal, body)
            assert op_dd.value.code is ErrorCode.UNSAFE_PATH

        # (d) Claude bootstrap apply -> U1 edit -> rollback removes BOTH permissions & hooks cleanly!
        claude_dir = co / ".claude"
        claude_dir.mkdir()
        os_.permissions.secure_directory(claude_dir)
        (claude_dir / "settings.local.json").write_text('{"theme": "dark"}\n', encoding="utf-8")
        (co / "CLAUDE.md").write_text("# User Heading\n", encoding="utf-8")

        boot_prop = create_bootstrap_proposal(
            svc,
            owner_id=OWNER,
            harness_id="claude-code",
            checkout_root=co,
            harness_profile_path=harness_profile,
            planner=planner,
            profile_validator=validator,
            os_=os_,
        )
        assert len(boot_prop.targets) == 3
        _approve_and_apply(rt, svc, rep.store_id, rep.signer.signer_id, boot_prop.proposal_id)

        applied_cfg = json.loads((claude_dir / "settings.local.json").read_text(encoding="utf-8"))
        assert {"theme", "permissions", "hooks"} <= set(applied_cfg)

        # Simulate out-of-band U1 edit after apply.
        applied_cfg["u1_user_pref"] = True
        (claude_dir / "settings.local.json").write_text(json.dumps(applied_cfg, indent=2) + "\n", encoding="utf-8")

        plan_rb = svc.plan_rollback_targets(boot_prop.proposal_id)
        n_rb = rt.policy.issue_nonce(
            action=ApprovalAction.ROLLBACK, subject_id=boot_prop.proposal_id, risk_level=RiskLevel.HIGH
        )
        rb_msg = ApprovalMessage(
            store_id=rep.store_id,
            owner_id=OWNER,
            trust_generation=rt.policy.trust_generation(),
            action=ApprovalAction.ROLLBACK,
            subject_id=boot_prop.proposal_id,
            subject_revision=boot_prop.subject_revision,
            resource_digests=plan_rb.resource_digests,
            target_files=plan_rb.target_files,
            risk_level=RiskLevel.HIGH,
            risk_policy_version=RISK_POLICY_VERSION,
            recovery_scope=RecoveryScope.ROLLBACK,
            nonce=n_rb.nonce,
            expires_at=n_rb.expires_at,
        )
        svc.rollback_applied_proposal(
            boot_prop.proposal_id,
            approval=rb_msg,
            signer_id=rep.signer.signer_id,
            channel=ApprovalChannel.SSH_KEY,
            plan=plan_rb,
        )
        after_cfg = json.loads((claude_dir / "settings.local.json").read_text(encoding="utf-8"))
        assert after_cfg == {"theme": "dark", "u1_user_pref": True}, after_cfg
    finally:
        rt.close()
