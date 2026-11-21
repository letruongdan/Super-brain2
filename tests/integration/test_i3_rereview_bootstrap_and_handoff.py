"""SP1-I3 rereview oracle for F1 (bootstrap profile validation), F2 (§7.4 + SP2 gate), & F4 (manifest updates).

Requirement sources: spec rev 22 §7.4, §11.2-§11.3, D3; ``docs/reviews/2026-11-20-sp1-increment3-rereview-0b0316e.md``.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

import pytest
import tomlkit

from superbrain.adapters.harness_config import bootstrap_templates as bt
from superbrain.adapters.harness_config.bootstrap_templates import (
    HANDOFF_UPDATE_MOMENTS,
    AdapterBootstrapPlanner,
    plan_claude_bootstrap,
    plan_codex_bootstrap,
)
from superbrain.adapters.harness_config.merger import SharedConfigMergerAdapter
from superbrain.adapters.os import os_adapters
from superbrain.application.approvals import OperatorService
from superbrain.application.bootstrap import create_bootstrap_proposal
from superbrain.application.review_apply import ReviewApplyService
from superbrain.composition._bootstrap_wiring import PolicyHarnessProfileValidator
from superbrain.composition._bootstrap_wiring import make_default_bootstrap_handler as wiring_handler
from superbrain.composition.init_entry import InitReport
from superbrain.composition.operator_entry import make_default_bootstrap_handler
from superbrain.core._kernel_approval import (
    RISK_POLICY_VERSION,
    ApprovalAction,
    ApprovalChannel,
    ApprovalMessage,
    RecoveryScope,
    RiskLevel,
    RiskResource,
)
from superbrain.core._kernel_base import ResourceDigest
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import WorkspaceBinding
from superbrain.core.proposals import (
    ChangeProposal,
    ManagedFormat,
    ManagedSliceManifest,
    ProposalStatus,
    ProposalTarget,
)
from superbrain.ports.os import OsAdapters
from superbrain.storage.proposals import PolicyApplyAuthority, StoreProposalAdapter
from tests.support import rereview_1d666f5 as rr
from tests.support.clock import FakeClock
from tests.support.fs import digest_tree
from tests.support.inc2_fixture import reopen_kernel_job_runtime
from tests.support.inc2_transport import FakeMonotonicClock, register_workspace_direct
from tests.support.init_clone import init_store_cloned
from tests.support.kernel_auth import SeededCredential, make_bootstrap_auth, seed_principal_and_credential

OWNER, MACHINE = "dan", "rereview-box"
EXPECTED_MOMENTS = (
    "plan_created_or_changed", "decision_or_rejection_recorded", "user_constraint_added",
    "step_completed", "before_long_running_command", "task_ended",
)
REQUIRED_7_4_TOKENS = (
    "takeover.acknowledge_active=true", "active", "user", "handoff_status", "stored", "writer_status", "holder",
    "not_holder", "discover", "get_artifact", "handoff_live", "not_stored_policy", "manual_submission", "disabled",
    "commit_outcome_unknown", "submit_episode", "idempotency_key", "retry", "edit",
)


_ssh_enrollment, _ws_dict, _prop_id = rr.ssh_enrollment, rr.ws_dict, rr.prop_id


@dataclass
class _Ctx:
    clock: FakeClock
    os_: OsAdapters
    rep: InitReport
    data_root: Path
    cfg_dir: Path
    home: Path
    rt: Any
    adapter: StoreProposalAdapter
    svc: ReviewApplyService
    planner: AdapterBootstrapPlanner
    validator: PolicyHarnessProfileValidator

    def mk(self, *dirs: Path) -> None:
        for d in dirs:
            d.mkdir(parents=True, exist_ok=True)
            self.os_.permissions.secure_directory(d)

    def profile(
        self, name: str, cred_file: Path, ws: dict[str, str] | None = None, *, store_id: str | None = None,
        pin: str | None = None, ca_file: Path | None = None, endpoint: Path | None = None,
    ) -> Path:
        path = self.cfg_dir / name
        payload: dict[str, Any] = {
            "version": 1, "endpoint_path": str(endpoint or self.data_root / "endpoint.json"),
            "expected_store_id": store_id or self.rep.store_id,
            "ca_file": str(ca_file or self.cfg_dir / "tls" / "ca.pem"),
            "leaf_cert_sha256": pin or rr.leaf_sha(self.cfg_dir / "tls" / "server.pem"),
            "credential_file": str(cred_file),
        }
        if ws is not None:
            payload["workspace"] = ws
        path.write_bytes(canonical_json(payload))
        self.os_.permissions.secure_file(path)
        return path

    def setup(
        self, harness: Literal["claude-code", "codex"], co: Path, alias: str, tag: str
    ) -> tuple[SeededCredential, WorkspaceBinding, Path, Path]:
        cred = seed_principal_and_credential(self.rt.policy, owner_id=OWNER, harness_id=harness, machine_id=MACHINE)
        ws = register_workspace_direct(
            self.rt, self.clock, cred.principal, alias=alias, checkout_dir=co,
            remote=f"https://github.example/dan/{tag}.git",
        )
        cf = self.cfg_dir / f"{tag}.cred"
        cf.write_text(f"{cred.token}\n", encoding="ascii")
        self.os_.permissions.secure_file(cf)
        return cred, ws, cf, self.profile(f"{tag}.profile.json", cf, _ws_dict(ws))

    def propose(self, harness: Literal["claude-code", "codex"], co: Path, prof: Path) -> ChangeProposal:
        return create_bootstrap_proposal(
            self.svc, owner_id=OWNER, harness_id=harness, checkout_root=co,
            harness_profile_path=prof, planner=self.planner, profile_validator=self.validator, os_=self.os_,
        )

    def _msg(self, action: ApprovalAction, pid: str, rev: int, digests: Any, targets: Any, risk: Any,
             scope: RecoveryScope) -> ApprovalMessage:
        n = self.rt.policy.issue_nonce(action=action, subject_id=pid, risk_level=risk)
        return ApprovalMessage(
            store_id=self.rep.store_id, owner_id=OWNER, trust_generation=self.rt.policy.trust_generation(),
            action=action, subject_id=pid, subject_revision=rev, resource_digests=digests, target_files=targets,
            risk_level=risk, risk_policy_version=RISK_POLICY_VERSION, recovery_scope=scope,
            nonce=n.nonce, expires_at=n.expires_at,
        )

    def apply(self, pid: str) -> None:
        prop = self.svc.get_proposal(pid)
        t_files = prop.to_target_files()
        for action, scope, fn in (
            (ApprovalAction.APPROVE, RecoveryScope.NONE, self.svc.approve_proposal),
            (ApprovalAction.APPLY, RecoveryScope.CONTINUE_OR_ROLLBACK, self.svc.apply_proposal),
        ):
            msg = self._msg(action, pid, prop.subject_revision, prop.resource_digests, t_files, prop.risk_level, scope)
            fn(pid, approval=msg, signer_id=self.rep.signer.signer_id, channel=ApprovalChannel.SSH_KEY)

    def rollback(self, pid: str) -> None:
        prop = self.svc.get_proposal(pid)
        plan = self.svc.plan_rollback_targets(pid)
        msg = self._msg(
            ApprovalAction.ROLLBACK, pid, plan.subject_revision, plan.resource_digests,
            plan.target_files, prop.risk_level, RecoveryScope.ROLLBACK,
        )
        self.svc.rollback_applied_proposal(
            pid, approval=msg, signer_id=self.rep.signer.signer_id, channel=ApprovalChannel.SSH_KEY, plan=plan
        )


@contextmanager
def _open_ctx(base: Path, tag: str) -> Iterator[_Ctx]:
    clock = FakeClock(datetime(2026, 11, 20, 12, 0, tzinfo=UTC))
    os_ = os_adapters(clock=clock, monotonic=FakeMonotonicClock(1_000_000_000))
    cfg_dir, data_root, home = base / "cfg", base / "data", base / "home"
    for d in (cfg_dir, home):
        d.mkdir(parents=True, exist_ok=True)
        os_.permissions.secure_directory(d)
    rep = init_store_cloned(
        os_, data_root=data_root, cfg_dir=cfg_dir, owner_id=OWNER, machine_id=MACHINE, signer=_ssh_enrollment(tag)
    )
    rt = reopen_kernel_job_runtime(data_root, rep.store_id, os_)
    try:
        adapter = StoreProposalAdapter(rt.store, os_)
        svc = ReviewApplyService(
            adapter, PolicyApplyAuthority(rt.policy), os_, data_root=data_root, home_dir=home,
            config_merger=SharedConfigMergerAdapter(),
        )
        yield _Ctx(
            clock=clock, os_=os_, rep=rep, data_root=data_root, cfg_dir=cfg_dir, home=home, rt=rt,
            adapter=adapter, svc=svc, planner=AdapterBootstrapPlanner(),
            validator=PolicyHarnessProfileValidator(rt.policy, os_),
        )
    finally:
        rt.close()


def test_f1_bootstrap_profile_validation_matrix_and_isolation(trusted_tmp: Path) -> None:
    """F1: reject CLI/swapped/missing-workspace/wrong-store/unregistered/revoked profiles & embed harness only."""
    with _open_ctx(trusted_tmp / "f1", "f1") as ctx:
        co_a, co_b, co_unreg = trusted_tmp / "co-a", trusted_tmp / "co-b", trusted_tmp / "co-u"
        ctx.mk(co_a, co_b, co_unreg)
        cli_prof = ctx.profile("cli.profile.json", ctx.rep.cli_credential_path)
        cli_token = ctx.rep.cli_credential_path.read_text(encoding="ascii").strip()
        cli_p = seed_principal_and_credential(ctx.rt.policy, owner_id=OWNER, harness_id="cli", machine_id=MACHINE)
        cred_c, ws_a, c_cred, p_claude = ctx.setup("claude-code", co_a, "ws-a", "c")
        cred_x, ws_b, x_cred, p_codex = ctx.setup("codex", co_b, "ws-b", "x")
        register_workspace_direct(
            ctx.rt, ctx.clock, cred_x.principal, alias="ws-a", checkout_dir=co_a, remote="https://github.example/dan/a.git"
        )
        p_wh = ctx.profile("wh-co.profile.json", x_cred, _ws_dict(ws_a))
        p_cli_ws = ctx.profile("cw.json", ctx.rep.cli_credential_path, _ws_dict(ws_a))
        p_wrong_store = ctx.profile("ws-store.json", c_cred, _ws_dict(ws_a),
                                    store_id="01920000-0000-7000-8000-999999999999")
        p_bad_path = ctx.profile("bp.json", c_cred, _ws_dict(ws_a, co_b))
        p_bad_ids = ctx.profile("bi.json", c_cred, _ws_dict(ws_b, co_a))
        u_pref = "01920000-0000-7000-8000-000000000"
        p_unreg = ctx.profile("unreg.profile.json", c_cred, {
            "alias": "ws-unreg", "checkout_path": str(co_unreg),
            "expected_workspace_id": f"{u_pref}777", "expected_checkout_id": f"{u_pref}778",
        })

        ident = rr.daemon_identity(ctx.data_root, ctx.cfg_dir)

        # F1 (1d666f5): TLS pin / CA / endpoint identity must match the pinned daemon, not just parse.
        kw: dict[str, Any] = {"owner_id": OWNER, "harness_id": "claude-code", "checkout_root": co_a}
        f_ca = rr.foreign_ca_file(
            trusted_tmp, ctx.os_, owner_id=OWNER, machine_id=MACHINE, signer=_ssh_enrollment("f1-foreign")
        )
        ws_dict_a = _ws_dict(ws_a)
        bad_pin = rr.flip_last_hex_char(ident["expected_leaf_cert_sha256"])
        p_pin = ctx.profile("pin.json", c_cred, ws_dict_a, pin=bad_pin)
        p_fca = ctx.profile("fca.json", c_cred, ws_dict_a, ca_file=f_ca)
        p_ep_dir = ctx.profile("epd.json", c_cred, ws_dict_a, endpoint=trusted_tmp / "other-data" / "endpoint.json")
        p_ep_name = ctx.profile("epn.json", c_cred, ws_dict_a, endpoint=ctx.data_root / "other.json")

        with pytest.raises(BrainError) as default_err:  # a default-constructed validator also rejects the wrong pin
            ctx.validator.validate_harness_profile(harness_profile_path=p_pin, **kw)
        assert default_err.value.code is ErrorCode.IDENTITY_MISMATCH
        ctx.validator = PolicyHarnessProfileValidator(ctx.rt.policy, ctx.os_, **ident)
        h1 = wiring_handler(ctx.rt.policy, ctx.os_, **ident)
        h2 = make_default_bootstrap_handler(ctx.rt.policy, ctx.os_, **ident)
        op = OperatorService(ctx.rt.policy, ssh_verifier=lambda: None, review_apply=ctx.svc, bootstrap_handler=h1)
        op2 = OperatorService(ctx.rt.policy, ssh_verifier=lambda: None, review_apply=ctx.svc, bootstrap_handler=h2)

        cases: list[tuple[Literal["claude-code", "codex"], Path, Path, ErrorCode]] = [
            ("claude-code", co_a, cli_prof, ErrorCode.INVALID_INPUT),
            ("claude-code", co_a, p_cli_ws, ErrorCode.IDENTITY_MISMATCH),
            ("claude-code", co_a, p_wh, ErrorCode.IDENTITY_MISMATCH),
            ("codex", co_b, p_claude, ErrorCode.IDENTITY_MISMATCH),
            ("claude-code", co_a, p_wrong_store, ErrorCode.IDENTITY_MISMATCH),
            ("claude-code", co_a, p_bad_path, ErrorCode.IDENTITY_MISMATCH),
            ("claude-code", co_a, p_bad_ids, ErrorCode.IDENTITY_MISMATCH),
            ("claude-code", co_unreg, p_unreg, ErrorCode.IDENTITY_MISMATCH),
            ("claude-code", co_a, p_pin, ErrorCode.IDENTITY_MISMATCH),
            ("claude-code", co_a, p_fca, ErrorCode.IDENTITY_MISMATCH),
            ("claude-code", co_a, p_ep_dir, ErrorCode.IDENTITY_MISMATCH),
            ("claude-code", co_a, p_ep_name, ErrorCode.IDENTITY_MISMATCH),
        ]
        for h, co_dir, bad_prof, expected_code in cases:
            with pytest.raises(BrainError) as v_err:
                ctx.validator.validate_harness_profile(
                    owner_id=OWNER, harness_id=h, checkout_root=co_dir, harness_profile_path=bad_prof
                )
            assert v_err.value.code is expected_code
            with pytest.raises(BrainError) as svc_err:
                ctx.propose(h, co_dir, bad_prof)
            assert svc_err.value.code is expected_code
            with pytest.raises(BrainError) as op_err:
                op.handle("/v2/operator/proposal/bootstrap", cli_p.principal,
                          {"harness": h, "checkout_root": str(co_dir), "harness_profile_path": str(bad_prof)})
            assert op_err.value.code is expected_code

        # Daemon pin override: a rotated TLS bundle is accepted, the stale init pin / CA is rejected.
        r_cert, r_ca, r_sha = rr.rotated_tls(ctx.rep.store_id, trusted_tmp / "rot-tls", OWNER, ctx.clock, ctx.os_)
        rot = PolicyHarnessProfileValidator(
            ctx.rt.policy, ctx.os_, expected_endpoint_path=ident["expected_endpoint_path"],
            expected_leaf_cert_sha256=r_sha, server_cert_path=r_cert,
        )
        p_rot = ctx.profile("rot.json", c_cred, ws_dict_a, pin=r_sha, ca_file=r_ca)
        rot.validate_harness_profile(harness_profile_path=p_rot, **kw)
        for stale_v, stale_p in ((rot, p_claude), (ctx.validator, p_rot)):
            with pytest.raises(BrainError) as stale_err:
                stale_v.validate_harness_profile(harness_profile_path=stale_p, **kw)
            assert stale_err.value.code is ErrorCode.IDENTITY_MISMATCH

        ctx.rt.policy.record_authorized_revocation(
            cred_c.credential_id,
            make_bootstrap_auth(
                store_id=ctx.rep.store_id, owner_id=OWNER, action="credential_revoke",
                subject_id=cred_c.credential_id, trust_generation=ctx.rt.policy.trust_generation(),
                expires_at=ctx.clock.now() + timedelta(hours=1),
            ),
        )
        with pytest.raises(BrainError) as rev_err:
            ctx.propose("claude-code", co_a, p_claude)
        assert rev_err.value.code is ErrorCode.UNAUTHENTICATED

        snap_b = digest_tree(co_b)
        out = op2.handle("/v2/operator/proposal/bootstrap", cli_p.principal,
                         {"harness": "codex", "checkout_root": str(co_b), "harness_profile_path": str(p_codex)})
        prop = ctx.svc.get_proposal(_prop_id(out))
        joined = "\n".join(
            ctx.adapter.read_payload_bytes(str(t.replacement_digest)).decode("utf-8")
            for t in prop.targets if t.replacement_digest is not None
        )
        assert str(p_codex) in joined and str(cli_prof) not in joined and cli_token not in joined
        assert digest_tree(co_b) == snap_b


def test_f2_handoff_rule_and_sp2_takeover_edit_gate_oracle(trusted_tmp: Path) -> None:
    """F2: applied CLAUDE.md/AGENTS.md carry exact §7.4 rules & SP2 edit gate enforces every ACK invariant."""
    d_cls, evaluate_takeover_edit_gate = bt.HandoffTakeoverEditDecision, bt.evaluate_takeover_edit_gate
    assert HANDOFF_UPDATE_MOMENTS == EXPECTED_MOMENTS
    co_a, co_b = trusted_tmp / "co-a", trusted_tmp / "co-b"
    with _open_ctx(trusted_tmp / "f2", "f2") as ctx:
        ctx.mk(co_a, co_b)
        _, _, _, p_a = ctx.setup("claude-code", co_a, "ws-f2-a", "a")
        _, _, _, p_b = ctx.setup("codex", co_b, "ws-f2-b", "b")
        ctx.apply(ctx.propose("claude-code", co_a, p_a).proposal_id)
        ctx.apply(ctx.propose("codex", co_b, p_b).proposal_id)

    for md_path in (co_a / "CLAUDE.md", co_b / "AGENTS.md"):
        txt = md_path.read_text(encoding="utf-8")
        low = txt.lower()
        assert "task_state is active" not in low
        assert "not_holder, prepare manual_submission" not in low
        assert "prepare manual_submission" not in low
        for m in EXPECTED_MOMENTS:
            assert m in txt
        for tok in REQUIRED_7_4_TOKENS:
            assert tok in low, f"missing {tok!r} in {md_path.name}"
        rr.assert_f2_rule_scope(txt)

    for sess, ack, h_s, w_s, unk, expected in [
        ("ended", False, None, None, True, d_cls(False, "retry_same_idempotency_key")),
        ("in_progress_unknown", False, "stored", "holder", True, d_cls(False, "retry_same_idempotency_key")),
        ("active", False, None, None, False, d_cls(False, "require_active_takeover_ack", True, True)),
        ("active", False, "stored", "holder", False, d_cls(False, "require_active_takeover_ack", True, True)),
        ("ended", False, "not_stored_policy", None, False, d_cls(False, "policy_disabled", False, True)),
        ("active", True, "not_stored_policy", "holder", False, d_cls(False, "policy_disabled", False, True)),
        ("ended", False, "stored", "not_holder", False, d_cls(False, "reread_handoff")),
        ("active", True, "stored", "not_holder", False, d_cls(False, "reread_handoff")),
        ("ended", False, "stored", "holder", False, d_cls(True, "proceed_edit")),
        ("in_progress_unknown", False, "stored", "holder", False, d_cls(True, "proceed_edit")),
        (None, False, "stored", "holder", False, d_cls(True, "proceed_edit")),
        ("active", True, "stored", "holder", False, d_cls(True, "proceed_edit")),
    ]:
        dec = evaluate_takeover_edit_gate(
            holding_session_state=sess, acknowledge_active=ack,
            handoff_status=h_s, writer_status=w_s, commit_outcome_unknown=unk,
        )
        assert dec == expected
    # F2: explicit takeover keeps the block + notify; ordinary work (no open handoff) proceeds under repo policy.
    for h_s, unk, takeover, expected in (
        ("not_stored_policy", False, True, d_cls(False, "policy_disabled", False, True)),
        ("not_stored_policy", False, False, d_cls(True, "proceed_without_handoff_policy")),
        (None, False, False, d_cls(True, "proceed_edit")),
        (None, True, False, d_cls(False, "retry_same_idempotency_key")),
    ):
        assert evaluate_takeover_edit_gate(
            holding_session_state=None, acknowledge_active=False, handoff_status=h_s, writer_status=None,
            commit_outcome_unknown=unk, taking_over_open_handoff=takeover,
        ) == expected
    for h_s, w_s in ((None, None), ("stored", None), (None, "holder")):
        assert not evaluate_takeover_edit_gate(
            holding_session_state="ended", acknowledge_active=False,
            handoff_status=h_s, writer_status=w_s, commit_outcome_unknown=False,
        ).allow_edit
    rr.assert_not_stored_policy_not_holder_ack_pair()  # 0f3c6d6 F2: same ACK pair, both contexts, stored still re-reads


def test_f2_not_stored_policy_with_not_holder_ack_pair_decides_by_context() -> None:
    rr.assert_not_stored_policy_not_holder_ack_pair()


def test_f4_manifest_driven_rebootstrap_preserves_u1_and_blocks_in_slice_tamper(trusted_tmp: Path) -> None:
    """F4: manifest-driven re-bootstrap updates across MD/JSON/TOML preserving U1, & blocks in-slice tamper."""
    with _open_ctx(trusted_tmp / "f4", "f4") as ctx:
        co_c, co_x = trusted_tmp / "co-c", trusted_tmp / "co-x"
        ctx.mk(co_c, co_x, co_x / ".codex", co_c / ".claude")
        (co_c / "CLAUDE.md").write_text("# Claude Base\n", encoding="utf-8")
        (co_c / ".mcp.json").write_text('{"mcpServers": {"user-keep": {"command": "echo"}}}\n', encoding="utf-8")
        (co_c / ".claude" / "settings.local.json").write_text('{"theme": "dark"}\n', encoding="utf-8")
        (co_x / "AGENTS.md").write_text("# Codex Base\n", encoding="utf-8")
        (co_x / ".codex" / "config.toml").write_text("# Top user comment\n[profiles.dev]\nkeep = true\n", "utf-8")
        (co_x / ".codex" / "hooks.json").write_text('{"userTop": 1}\n', encoding="utf-8")

        cli_p = seed_principal_and_credential(ctx.rt.policy, owner_id=OWNER, harness_id="cli", machine_id=MACHINE)
        _, ws_c, c_cred, c_prof1 = ctx.setup("claude-code", co_c, "ws-f4-c", "c1")
        _, ws_x, x_cred, x_prof1 = ctx.setup("codex", co_x, "ws-f4-x", "x1")
        c_prof2 = ctx.profile("c2.profile.json", c_cred, _ws_dict(ws_c))
        x_prof2 = ctx.profile("x2.profile.json", x_cred, _ws_dict(ws_x))
        op = OperatorService(ctx.rt.policy, ssh_verifier=lambda: None, review_apply=ctx.svc,
                             bootstrap_handler=make_default_bootstrap_handler(ctx.rt.policy, ctx.os_))

        p1_c = plan_claude_bootstrap(checkout_root=co_c, profile_path=c_prof1, expected_slice_digests=None)
        assert {(t.rel_path, t.slice_id) for t in p1_c.targets} == {
            ("CLAUDE.md", "super-brain-layer1"), (".mcp.json", "mcpServers.super-brain"),
            (".claude/settings.local.json", "permissions.ask,hooks.PreToolUse"),
        }
        p1_x = plan_codex_bootstrap(checkout_root=co_x, profile_path=x_prof1, expected_slice_digests=None)
        assert {(t.rel_path, t.slice_id) for t in p1_x.targets} == {
            ("AGENTS.md", "super-brain-layer1"), (".codex/config.toml", "mcp_servers.super-brain"),
            (".codex/hooks.json", "hooks.PreToolUse"),
        }

        ctx.apply(ctx.propose("claude-code", co_c, c_prof1).proposal_id)
        ctx.apply(_prop_id(op.handle(
            "/v2/operator/proposal/bootstrap", cli_p.principal,
            {"harness": "codex", "checkout_root": str(co_x), "harness_profile_path": str(x_prof1)},
        )))

        # Out-of-band U1 edits across Markdown, JSON, dual-slice JSON, & TOML!
        def _append(path: Path, text: str) -> None:
            path.write_text(path.read_text("utf-8") + text, "utf-8")

        def _jedit(path: Path, mutate: Callable[[Any], object]) -> None:
            obj = json.loads(path.read_text("utf-8"))
            mutate(obj)
            path.write_text(json.dumps(obj, indent=2) + "\n", "utf-8")

        _append(co_c / "CLAUDE.md", "\n## User Prose After\nKeep me.\n")
        _jedit(co_c / ".mcp.json", lambda o: (
            o.update(userSibling="keep"), o["mcpServers"].update({"user-extra": {"command": "true"}})))
        _jedit(co_c / ".claude" / "settings.local.json", lambda o: (
            o["permissions"].update(allow=["Bash(git status *)"]),
            o["hooks"].update(PostToolUse=[{"type": "user-post"}])))
        _append(co_x / "AGENTS.md", "\n## Agents Prose After\nKeep me.\n")
        _append(co_x / ".codex" / "config.toml", '\n# U1 post-apply comment\n[profiles.u1]\nowner = "keep"\n')
        _jedit(co_x / ".codex" / "hooks.json", lambda o: o["hooks"].update(PostToolUse=[{"type": "codex-post"}]))
        # Rotate to c_prof2 / x_prof2 -> re-bootstrap updates cleanly and preserves 100% of U1 edits & TOML comments!
        ctx.apply(ctx.propose("claude-code", co_c, c_prof2).proposal_id)
        ctx.apply(_prop_id(op.handle(
            "/v2/operator/proposal/bootstrap", cli_p.principal,
            {"harness": "codex", "checkout_root": str(co_x), "harness_profile_path": str(x_prof2)},
        )))

        c_md2 = (co_c / "CLAUDE.md").read_text("utf-8")
        assert "# Claude Base" in c_md2 and "## User Prose After" in c_md2
        assert str(c_prof2) in c_md2 and str(c_prof1) not in c_md2
        mcp2 = json.loads((co_c / ".mcp.json").read_text("utf-8"))
        assert mcp2["userSibling"] == "keep" and mcp2["mcpServers"]["user-keep"] == {"command": "echo"}
        assert mcp2["mcpServers"]["user-extra"] == {"command": "true"}
        assert str(c_prof2) in mcp2["mcpServers"]["super-brain"]["args"]
        set2 = json.loads((co_c / ".claude" / "settings.local.json").read_text("utf-8"))
        assert set2["theme"] == "dark" and set2["permissions"]["allow"] == ["Bash(git status *)"]
        assert set2["hooks"]["PostToolUse"] == [{"type": "user-post"}]
        assert set2["hooks"]["PreToolUse"]["super_brain"]["profile"] == str(c_prof2)

        x_md2 = (co_x / "AGENTS.md").read_text("utf-8")
        assert "# Codex Base" in x_md2 and "## Agents Prose After" in x_md2
        assert str(x_prof2) in x_md2 and str(x_prof1) not in x_md2
        toml2_text = (co_x / ".codex" / "config.toml").read_text("utf-8")
        assert "# Top user comment" in toml2_text and "# U1 post-apply comment" in toml2_text
        toml2 = tomlkit.parse(toml2_text).unwrap()
        assert toml2["profiles"]["dev"]["keep"] is True and toml2["profiles"]["u1"]["owner"] == "keep"
        assert str(x_prof2) in toml2["mcp_servers"]["super-brain"]["args"]
        xhook2 = json.loads((co_x / ".codex" / "hooks.json").read_text("utf-8"))
        assert xhook2["userTop"] == 1 and xhook2["hooks"]["PostToolUse"] == [{"type": "codex-post"}]
        assert xhook2["hooks"]["PreToolUse"]["super_brain"]["profile"] == str(x_prof2)

        def _mut_json(key1: str, key2: str, val: Any) -> Callable[[str], str]:
            def _fn(txt: str) -> str:
                obj = json.loads(txt)
                if key2 == "non_blocking":
                    obj[key1]["PreToolUse"]["super_brain"][key2] = val
                else:
                    obj[key1][key2] = val
                return json.dumps(obj, indent=2) + "\n"

            return _fn

        def _check_tamper(path: Path, mut_fn: Callable[[str], str], co: Path, fn: Callable[[], object]) -> None:
            orig = path.read_text("utf-8")
            mutated = mut_fn(orig)
            assert mutated != orig, f"no-op tamper on {path}"
            try:
                path.write_text(mutated, "utf-8")
                snap = digest_tree(co)
                with pytest.raises(BrainError) as err:
                    fn()
                assert err.value.code is ErrorCode.REVISION_CONFLICT and digest_tree(co) == snap
            finally:
                path.write_text(orig, "utf-8")

        for path, mut_fn in (
            (co_c / "CLAUDE.md", lambda t: t.replace("Session Handoff Protocol", "Tampered Handoff Protocol")),
            (co_c / ".mcp.json", lambda t: t.replace(c_prof2.name, c_prof1.name)),
            (co_c / ".claude" / "settings.local.json", _mut_json("permissions", "ask", ["Bash(tampered *)"])),
            (co_c / ".claude" / "settings.local.json", _mut_json("hooks", "non_blocking", False)),
        ):
            _check_tamper(path, mut_fn, co_c, lambda: ctx.propose("claude-code", co_c, c_prof1))
        body_x = {"harness": "codex", "checkout_root": str(co_x), "harness_profile_path": str(x_prof1)}
        for path, mut_fn in (
            (co_x / "AGENTS.md", lambda t: t.replace("Session Handoff Protocol", "Tampered Agents Handoff")),
            (co_x / ".codex" / "config.toml", lambda t: t.replace(x_prof2.name, x_prof1.name)),
            (co_x / ".codex" / "hooks.json", lambda t: t.replace('"remind"', '"tampered"')),
        ):
            _check_tamper(
                path, mut_fn, co_x,
                lambda: op.handle("/v2/operator/proposal/bootstrap", cli_p.principal, body_x),
            )


def test_f4_rollback_clears_manifest_for_clean_rebootstrap_but_rejects_unmanaged_collision(trusted_tmp: Path) -> None:
    """F4: rollback clears active manifest so clean re-bootstrap works, while unmanaged slice still conflicts."""
    with _open_ctx(trusted_tmp / "f4-rb", "f4rb") as ctx:
        co = trusted_tmp / "co-rb"
        ctx.mk(co)
        (co / "CLAUDE.md").write_text("# User Header\n", encoding="utf-8")
        _, _, _, prof = ctx.setup("claude-code", co, "ws-rb", "rb")

        p1 = ctx.propose("claude-code", co, prof)
        ctx.apply(p1.proposal_id)
        ctx.rollback(p1.proposal_id)
        assert "super-brain-layer1" not in (co / "CLAUDE.md").read_text("utf-8")

        p2 = ctx.propose("claude-code", co, prof)
        ctx.apply(p2.proposal_id)
        assert str(prof) in (co / "CLAUDE.md").read_text("utf-8")

        ctx.rollback(p2.proposal_id)
        (co / "CLAUDE.md").write_text(
            "# User Header\n\n<!-- ensemble-brain:begin:super-brain-layer1 -->\nrogue\n"
            "<!-- ensemble-brain:end:super-brain-layer1 -->\n",
            encoding="utf-8",
        )
        snap_before = digest_tree(co)
        with pytest.raises(BrainError) as col_err:
            ctx.propose("claude-code", co, prof)
        assert col_err.value.code is ErrorCode.REVISION_CONFLICT and digest_tree(co) == snap_before


def test_f4_r2_f4_1_mixed_case_active_slice_digests_and_rollback(trusted_tmp: Path) -> None:
    """R2-F4-1: newer physical-match manifest wins across path spellings, & newer ROLLED_BACK masks older APPLIED."""
    co = trusted_tmp / "CoMixed"
    low_co = co.with_name(co.name.lower())
    with _open_ctx(trusted_tmp / "r2f4", "r2a") as ctx:
        ctx.mk(co)
        is_ci = str(low_co) != str(co) and low_co.exists()
        alt_root = str(low_co) if is_ci else f"{co}{os.sep}..{os.sep}{co.name}"
        d1, d2, full_d = digest_bytes(b"slice-v1"), digest_bytes(b"slice-v2"), digest_bytes(b"full")
        p1_id, p2_id = "01920000-0000-7000-8000-000000000101", "01920000-0000-7000-8000-000000000102"
        for pid, root_str, s_dig in ((p1_id, str(co), d1), (p2_id, alt_root, d2)):
            raw = f"content-{pid}".encode("ascii")
            rd = digest_bytes(raw)
            prop = ChangeProposal(
                proposal_id=pid, owner_id=OWNER, kind="harness_config_bootstrap", reason="r2-f4-1",
                status=ProposalStatus.PENDING, subject_revision=1, risk_level=RiskLevel.LOW,
                resources=(RiskResource("c1"),), resource_digests=(ResourceDigest("target:0", rd),),
                targets=(ProposalTarget(
                    rel_path="CLAUDE.md", normalized_rel_path="CLAUDE.md", managed_format=ManagedFormat.MARKDOWN,
                    slice_id="super-brain-layer1", base_present=False, base_digest=None, base_physical_id=None,
                    replacement_digest=rd, managed_slice_digest=s_dig, target_root=root_str, parent_physical_id="pid-0",
                ),),
                created_at="2026-11-20T12:00:00Z", updated_at="2026-11-20T12:00:00Z",
            )
            ctx.adapter.create_proposal(prop, {rd: raw})
            ctx.adapter.update_proposal_status(pid, ProposalStatus.APPLIED, updated_at="2026-11-20T12:01:00Z")
            ctx.adapter.save_manifests((ManagedSliceManifest(
                proposal_id=pid, normalized_rel_path="CLAUDE.md", managed_format=ManagedFormat.MARKDOWN,
                slice_id="super-brain-layer1", slice_digest=s_dig, full_file_digest=full_d,
                updated_at="2026-11-20T12:01:00Z", target_root=root_str,
            ),))
        key = ("CLAUDE.md", "super-brain-layer1")
        assert ctx.svc.active_slice_digests(co, owner_id=OWNER) == {key: d2}
        ctx.adapter.update_proposal_status(p2_id, ProposalStatus.ROLLED_BACK, updated_at="2026-11-20T12:02:00Z")
        assert ctx.svc.active_slice_digests(co, owner_id=OWNER) == {}

    if is_ci:
        co_e = trusted_tmp / "CoMixedE2E"
        low_e = co_e.with_name(co_e.name.lower())
        with _open_ctx(trusted_tmp / "r2e2e", "r2b") as ctx:
            ctx.mk(co_e)
            _, ws_e, cred_e, prof1 = ctx.setup("claude-code", co_e, "ws-mix", "m1")
            prof2 = ctx.profile("m2.profile.json", cred_e, _ws_dict(ws_e, low_e))
            p1 = ctx.propose("claude-code", co_e, prof1)
            ctx.apply(p1.proposal_id)
            d1_map = ctx.svc.active_slice_digests(co_e, owner_id=OWNER)

            p2 = ctx.propose("claude-code", low_e, prof2)
            ctx.apply(p2.proposal_id)
            d2_exp = {
                (t.normalized_rel_path, t.slice_id): str(t.managed_slice_digest)
                for t in p2.targets if t.managed_slice_digest is not None
            }
            d2_map = ctx.svc.active_slice_digests(co_e, owner_id=OWNER)
            assert d2_map == d2_exp and d2_map != d1_map

            p3 = ctx.propose("claude-code", co_e, prof1)
            assert p3.status is ProposalStatus.PENDING

            md_file = co_e / "CLAUDE.md"
            md_file.write_text(md_file.read_text("utf-8") + "\n# user post-apply note\n", "utf-8")
            ctx.rollback(p2.proposal_id)
            md_after = md_file.read_text("utf-8")
            assert "# user post-apply note" in md_after and "super-brain-layer1" not in md_after
            assert ctx.svc.active_slice_digests(co_e, owner_id=OWNER) == {}
