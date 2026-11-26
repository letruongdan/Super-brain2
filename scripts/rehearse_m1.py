"""M1 rehearsal driver (fixture mode on draft checkouts A/B, fail-closed native approval gate)."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

from superbrain.adapters.harness import (
    AdapterCaptureStatus,
    AuthorityCommandProbeResult,
    ClaudeCodeCaptureAdapter,
    CodexCaptureAdapter,
    HarnessCaptureContext,
    NativeHostReceipt,
    compute_harness_config_digest,
)
from superbrain.adapters.harness_config.bootstrap_templates import (
    AUTHORITY_ASK_COMMANDS,
    plan_claude_bootstrap,
    plan_codex_bootstrap,
)
from superbrain.adapters.os import os_adapters
from superbrain.composition._daemon_session import build_default_handoff_domain
from superbrain.composition.doctor_probes_sp2 import reconcile_harness_layer2_in_policy
from superbrain.composition.kernel_bridge import KernelBridge
from superbrain.core._kernel_approval import Layer2State
from superbrain.core.canonical import canonical_json
from superbrain.core.errors import ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    CAPABILITY_CAPTURE_PRODUCER,
    HANDLER_RESERVE_NS,
    CallContext,
    CaptureBatchCommand,
    CaptureProducerBinding,
    Identity,
    PrivateRequestAuth,
    RequestAuthView,
    Scope,
)
from superbrain.core.wire import SCHEMA_VERSION, normalize_call
from superbrain.ports.continuity import decide_session_liveness
from superbrain.storage._sessions_sql import parse_iso_utc
from superbrain.storage.handoffs import HandoffStore
from superbrain.storage.sessions import SessionStore
from tests.support.clock import FakeClock
from tests.support.inc2_fixture import open_kernel_job_runtime
from tests.support.inc2_transport import register_workspace_direct
from tests.support.kernel_auth import SeededCredential, seed_principal_and_credential, seed_repo_grant


def _write_bootstrap(checkout: Path, targets: tuple[Any, ...]) -> None:
    for tgt in targets:
        dest = checkout / Path(*tgt.rel_path.split("/"))
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(tgt.preview_text, encoding="utf-8")


def _dispatch(
    bridge: KernelBridge,
    rt: Any,
    tool: str,
    args: dict[str, JsonValue],
    *,
    cred: SeededCredential,
    scope: Scope,
) -> dict[str, Any]:
    call = normalize_call(tool, {"schema_version": SCHEMA_VERSION, **args}, cred.principal, selected_scope=scope)
    ctx = CallContext(
        principal=cred.principal,
        identity=Identity(store_id=rt.store.store_id, writer_epoch=rt.lease.epoch, instance_id="inst-m1-fixture"),
        deadline_ns=10_000_000_000 + HANDLER_RESERVE_NS + 1_500_000_000,
        selected_scope=scope,
    )
    auth = PrivateRequestAuth(credential_id=cred.credential_id, principal=cred.principal, token=cred.token)
    res: dict[str, Any] = bridge.dispatch(call, ctx, auth=auth)
    return res


def run_fixture_rehearsal(work_dir: Path, *, output_path: Path | None = None) -> dict[str, JsonValue]:
    """Run an isolated fixture M1 handoff + checkout-B isolation + Layer-2 invalidation rehearsal."""
    clock = FakeClock(dt.datetime(2026, 11, 26, 18, 0, tzinfo=dt.UTC))
    os_ = os_adapters(clock=clock)
    data_root = work_dir / "data"
    chk_a = work_dir / "checkout-a"
    chk_b = work_dir / "checkout-b"
    cfg_dir = work_dir / "cfg"
    for d in (chk_a, chk_b, cfg_dir):
        d.mkdir(parents=True, exist_ok=True)
        os_.permissions.secure_directory(d)

    prof_a = cfg_dir / "profile-a.json"
    _write_bootstrap(chk_a, plan_claude_bootstrap(checkout_root=chk_a, profile_path=prof_a).targets)
    _write_bootstrap(chk_a, plan_codex_bootstrap(checkout_root=chk_a, profile_path=prof_a).targets)

    claude_adapter = ClaudeCodeCaptureAdapter(os_)
    codex_adapter = CodexCaptureAdapter(os_)
    c_dig = compute_harness_config_digest("claude-code", chk_a, os_)
    x_dig = compute_harness_config_digest("codex", chk_a, os_)
    assert c_dig is not None and x_dig is not None

    rt = open_kernel_job_runtime(data_root, os_, role="m1-fixture")
    try:
        c_cred = seed_principal_and_credential(rt.policy, owner_id="dan", harness_id="claude-code", machine_id="m1-box")
        c_cap_cred = seed_principal_and_credential(
            rt.policy, owner_id="dan", harness_id="claude-code", machine_id="m1-box"
        )
        x_cred = seed_principal_and_credential(rt.policy, owner_id="dan", harness_id="codex", machine_id="m1-box")
        ws_a = register_workspace_direct(
            rt,
            clock,
            c_cred.principal,
            alias="ws-a",
            checkout_dir=chk_a,
            remote="https://github.example/dan/m1-draft.git",
        )
        ws_b = register_workspace_direct(
            rt,
            clock,
            c_cred.principal,
            alias="ws-b",
            checkout_dir=chk_b,
            remote="https://github.example/dan/m1-draft.git",
        )
        seed_repo_grant(rt.policy, principal_id=x_cred.principal.principal_id, repo_id=ws_a.repo_id, owner_id="dan")
        rt.store.reconcile_policy()
        domain = build_default_handoff_domain(rt=rt, clock=clock, writer_epoch=rt.lease.epoch)
        bridge = KernelBridge(
            store=rt.store, policy=rt.policy, clock=clock, writer_epoch=rt.lease.epoch, domain=domain
        )

        # Grant separate capture_producer credential for Claude Code and verify Layer-2 receipts for both hosts.
        snap = rt.policy.snapshot()
        merged = dict(snap.credentials)
        merged[c_cap_cred.credential_id] = replace(
            snap.credentials[c_cap_cred.credential_id],
            capabilities=frozenset({CAPABILITY_CAPTURE_PRODUCER}),
            capture_binding=CaptureProducerBinding("stream-claude-a", ws_a.repo_id, ws_a.checkout_id),
        )
        key_id, key_bytes = rt.policy.request_digest_key()
        bridge._auth_state.install(
            RequestAuthView(
                version=bridge._auth_state.next_version(),
                auth=replace(snap, credentials=merged),
                active_request_key_id=key_id,
                active_request_key_bytes=key_bytes,
            )
        )

        for hid, ver, dig in (("claude-code", "2.1.325", c_dig), ("codex", "26.1111.2228.0", x_dig)):
            rcpt = NativeHostReceipt.build(
                receipt_id=f"rcpt-m1-{hid}",
                harness_id=hid,
                host_version=ver,
                config_digest=dig,
                probe_mode="fixture_m1_rehearsal",
                command_probes=tuple(
                    AuthorityCommandProbeResult(cmd, prompted_user=True, blocked_without_approval=True)
                    for cmd in AUTHORITY_ASK_COMMANDS
                ),
                observed_at="2026-11-26T18:00:00Z",
            )
            st, _ = reconcile_harness_layer2_in_policy(
                rt.policy,
                harness_id=hid,
                checkout_root=chk_a,
                observed_host_version=ver,
                os_=os_,
                receipt=rcpt,
            )
            assert st is Layer2State.VERIFIED

        scope_a = Scope(ws_a.repo_id, ws_a.checkout_id)
        scope_b = Scope(ws_b.repo_id, ws_b.checkout_id)

        # Claude Code prepares task & commits rev 1 handoff on checkout A.
        prep_c = _dispatch(
            bridge,
            rt,
            "prepare_task",
            {
                "mode": "work",
                "workspace_id": ws_a.repo_id,
                "checkout_id": ws_a.checkout_id,
                "description": "M1 step 1 goal",
                "idempotency_key": "idem-m1-0000-prep-c",
            },
            cred=c_cred,
            scope=scope_a,
        )
        assert prep_c["ok"] is True
        tid = str(prep_c["data"]["task_id"])
        sub_c = _dispatch(
            bridge,
            rt,
            "submit_episode",
            {
                "task_id": tid,
                "session_id": "RAW_CLAUDE_M1_SID",
                "workspace_id": ws_a.repo_id,
                "evidence": [],
                "base_revision": 0,
                "fence": prep_c["data"]["handoff_live"]["fence"],
                "takeover": {"acknowledge_active": True, "reason": "claude start"},
                "handoff": {
                    "working_goal": "Keep constraints across handoff",
                    "task_state": "open",
                    "plan": [{"id": "s1", "summary": "Implement step 1", "status": "in_progress"}],
                    "decisions": [
                        {"id": "d1", "decision": "Use pinned SHA-256 receipts", "reason": "Integrity"}
                    ],
                    "user_constraints": [{"id": "c1", "constraint": "No secret leaks"}],
                    "rejected": [{"id": "r1", "option": "Skip Layer 2 checks", "reason": "Unsafe"}],
                    "next_action": {"summary": "Update draft file on checkout A"},
                },
                "idempotency_key": "idem-m1-0000-sub-c1",
            },
            cred=c_cred,
            scope=scope_a,
        )
        assert sub_c["ok"] is True
        hs = HandoffStore(rt.store, rt.policy)
        hdr1 = hs.read_header(tid, principal_id=c_cred.principal.principal_id, scope=scope_a)
        assert hdr1 is not None and hdr1.holder_session_ref is not None
        ss = SessionStore(rt.store, rt.policy)
        sess_c = ss.get_session(hdr1.holder_session_ref, checkout_id=ws_a.checkout_id, repo_id=ws_a.repo_id)

        adapted = claude_adapter.adapt_hook_event(
            {
                "event_id": "ev-m1-c1",
                "sequence": 1,
                "event_name": "PostToolUse",
                "recorded_at": "2026-11-26T18:00:05Z",
                "cwd": str(chk_a),
                "payload": {"command": "pytest -q", "exit_code": 0},
                "channel_kind": "local_capture",
            },
            context=HarnessCaptureContext(
                checkout_root=chk_a,
                repo_id=ws_a.repo_id,
                checkout_id=ws_a.checkout_id,
                producer_stream="stream-claude-a",
                session_ref=sess_c.session_ref,
                host_version="2.1.325",
                expected_config_digest=c_dig,
            ),
        )
        assert adapted.status is AdapterCaptureStatus.OK and adapted.record is not None
        ack_c = bridge.ingest_capture_batch(
            CaptureBatchCommand(
                token=c_cap_cred.token,
                producer_stream="stream-claude-a",
                repo_id=ws_a.repo_id,
                checkout_id=ws_a.checkout_id,
                events=(adapted.record.to_dict(),),
            )
        )
        assert ack_c.accepted_count == 1
        # Simulate abrupt kill of Claude Code (> 300s idle, no session_end event).
        clock.advance(dt.timedelta(seconds=360))
        sess_after = ss.get_session(sess_c.session_ref, checkout_id=ws_a.checkout_id, repo_id=ws_a.repo_id)
        abrupt_liveness = decide_session_liveness(
            recorded_state=sess_after.state,
            last_event_at=parse_iso_utc(sess_after.last_event_at),
            now=clock.now(),
        )
        assert abrupt_liveness.state.value != "ended"

        # Codex discovers, reads L1, resumes work, and takes over on checkout A.
        assert codex_adapter.inspect_checkout_config(chk_a).hooks_configured is True
        disc_x = _dispatch(
            bridge,
            rt,
            "prepare_task",
            {
                "mode": "discover",
                "workspace_id": ws_a.repo_id,
                "checkout_id": ws_a.checkout_id,
            },
            cred=x_cred,
            scope=scope_a,
        )
        assert disc_x["ok"] is True and len(disc_x["data"]["continuity"]) == 1
        l1_x = _dispatch(
            bridge,
            rt,
            "get_artifact",
            {
                "workspace_id": ws_a.repo_id,
                "task_id": tid,
                "artifact_id": tid,
                "revision_epoch": 0,
                "revision": 1,
                "level": "L1",
                "idempotency_key": "idem-m1-0000-l1-x",
            },
            cred=x_cred,
            scope=scope_a,
        )
        assert l1_x["ok"] is True
        res_x = _dispatch(
            bridge,
            rt,
            "prepare_task",
            {
                "mode": "work",
                "workspace_id": ws_a.repo_id,
                "checkout_id": ws_a.checkout_id,
                "task_id": tid,
                "description": "Resume M1 task",
                "idempotency_key": "idem-m1-0000-work-x",
            },
            cred=x_cred,
            scope=scope_a,
        )
        assert res_x["ok"] is True
        take_x = _dispatch(
            bridge,
            rt,
            "submit_episode",
            {
                "task_id": tid,
                "session_id": "RAW_CODEX_M1_SID",
                "workspace_id": ws_a.repo_id,
                "evidence": [],
                "base_revision": 1,
                "fence": res_x["data"]["handoff_live"]["fence"],
                "takeover": {"acknowledge_active": True, "reason": "codex takeover"},
                "idempotency_key": "idem-m1-0000-take-x",
            },
            cred=x_cred,
            scope=scope_a,
        )
        assert take_x["ok"] is True
        takeover_ack: dict[str, JsonValue] = {
            "handoff_status": str(take_x["data"]["handoff_status"]),
            "writer_status": str(take_x["data"]["writer_status"]),
        }

        # Checkout B isolation across discover (empty continuity), get_artifact, resume, submit_episode, and replay!
        b_disc = _dispatch(
            bridge,
            rt,
            "prepare_task",
            {
                "mode": "discover",
                "workspace_id": ws_b.repo_id,
                "checkout_id": ws_b.checkout_id,
                "task_id": tid,
            },
            cred=x_cred,
            scope=scope_b,
        )
        b_disc_isolated = bool(b_disc["ok"] is True and b_disc["data"]["continuity"] == [])
        b_checks = (
            _dispatch(
                bridge,
                rt,
                "get_artifact",
                {
                    "workspace_id": ws_b.repo_id,
                    "task_id": tid,
                    "artifact_id": tid,
                    "revision_epoch": 0,
                    "revision": 1,
                    "level": "L1",
                    "idempotency_key": "idem-m1-0000-b-get",
                },
                cred=x_cred,
                scope=scope_b,
            ),
            _dispatch(
                bridge,
                rt,
                "prepare_task",
                {
                    "mode": "work",
                    "workspace_id": ws_b.repo_id,
                    "checkout_id": ws_b.checkout_id,
                    "task_id": tid,
                    "description": "Cross checkout resume",
                    "idempotency_key": "idem-m1-0000-b-work",
                },
                cred=x_cred,
                scope=scope_b,
            ),
            _dispatch(
                bridge,
                rt,
                "submit_episode",
                {
                    "task_id": tid,
                    "session_id": "RAW_CODEX_B_SID",
                    "workspace_id": ws_b.repo_id,
                    "evidence": [],
                    "base_revision": 1,
                    "fence": l1_x["data"]["handoff_live"]["fence"],
                    "takeover": {"acknowledge_active": True, "reason": "cross checkout"},
                    "idempotency_key": "idem-m1-0000-b-sub",
                },
                cred=x_cred,
                scope=scope_b,
            ),
        )
        replay_b = _dispatch(
            bridge,
            rt,
            "get_artifact",
            {
                "workspace_id": ws_b.repo_id,
                "task_id": tid,
                "artifact_id": tid,
                "revision_epoch": 0,
                "revision": 1,
                "level": "L1",
                "idempotency_key": "idem-m1-0000-l1-x",
            },
            cred=x_cred,
            scope=scope_b,
        )
        all_b_not_found = (
            b_disc_isolated
            and all(res["ok"] is False and res["error"]["code"] == ErrorCode.NOT_FOUND.value for res in b_checks[:3])
            and replay_b["ok"] is False
            and replay_b["error"]["code"] in {ErrorCode.NOT_FOUND.value, ErrorCode.IDEMPOTENCY_CONFLICT.value}
        )

        # Layer-2 invalidation check on config change.
        s_path = chk_a / ".claude" / "settings.local.json"
        s_data = json.loads(s_path.read_text(encoding="utf-8"))
        s_data["permissions"]["allow"] = ["Bash(echo ok *)"]
        s_path.write_text(canonical_json(s_data).decode("utf-8"), encoding="utf-8")
        inv_st, inv_reason = reconcile_harness_layer2_in_policy(
            rt.policy,
            harness_id="claude-code",
            checkout_root=chk_a,
            observed_host_version="2.1.325",
            os_=os_,
        )
        l2_inv_ok = inv_st is Layer2State.UNKNOWN and inv_reason == "config_digest_changed"

        report: dict[str, JsonValue] = {
            "mode": "fixture",
            "passed": bool(
                abrupt_liveness.state.value != "ended"
                and takeover_ack == {"handoff_status": "stored", "writer_status": "holder"}
                and all_b_not_found
                and l2_inv_ok
            ),
            "claude_abrupt_kill_session_state": abrupt_liveness.state.value,
            "codex_takeover_ack": takeover_ack,
            "checkout_b_all_paths_rejected": all_b_not_found,
            "layer2_invalidation_verified": l2_inv_ok,
        }
        if output_path is not None:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_bytes(canonical_json(report))
        return report
    finally:
        rt.close()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SP2-5 M1 continuity & Layer-2 rehearsal driver")
    parser.add_argument("--mode", choices=("fixture", "native"), default="fixture")
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--owner-approved", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.mode == "native" and not args.owner_approved:
        print("error=native_rehearsal_requires_owner_approval", file=sys.stderr)
        return 2
    if args.mode == "native":
        print("status=not_run reason=native_driver_requires_step3_host_session", file=sys.stderr)
        return 3
    report = run_fixture_rehearsal(args.work_dir, output_path=args.output)
    print(canonical_json(report).decode("utf-8"))
    return 0 if report.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
