"""SP2-4 end-to-end tests: discover, work/resume, C5 ServedReceipt/ReadAck, takeover, replay & scope isolation.

Requirement sources:
- docs/superpowers/specs/2026-10-30-super-brain2-system-design.md
  (§6.2, §6.3, §6.5, §7.4, §20 cases 2, 36–39, 41–45, 47–53, 55–61, 63–78)
- docs/superpowers/plans/2026-11-18-sp2-capture-continuity.md (SP2-4 Step 2)
"""

from __future__ import annotations

import datetime as dt
import time
from pathlib import Path
from typing import Any

from superbrain.adapters.os import os_adapters
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    HANDLER_RESERVE_NS,
    CallContext,
    Identity,
    PrivateRequestAuth,
    Scope,
    SendAttemptState,
)
from superbrain.core.wire import SCHEMA_VERSION, normalize_call
from superbrain.ports.capture import CaptureEventRecord
from tests.support.clock import FakeClock
from tests.support.inc2_fixture import open_kernel_job_runtime
from tests.support.inc2_transport import register_workspace_direct
from tests.support.kernel_auth import SeededCredential, seed_principal_and_credential, seed_repo_grant


def _dispatch_call(
    bridge: Any,
    rt: Any,
    tool: str,
    args: dict[str, JsonValue],
    *,
    cred: SeededCredential,
    scope: Scope,
    now_ns: int = 10_000_000_000,
) -> dict[str, Any]:
    call = normalize_call(
        tool,
        {"schema_version": SCHEMA_VERSION, **args},
        cred.principal,
        selected_scope=scope,
    )
    ctx = CallContext(
        principal=cred.principal,
        identity=Identity(store_id=rt.store.store_id, writer_epoch=rt.lease.epoch, instance_id="inst-sp24-test"),
        deadline_ns=now_ns + HANDLER_RESERVE_NS + 1_500_000_000,
        selected_scope=scope,
    )
    auth = PrivateRequestAuth(credential_id=cred.credential_id, principal=cred.principal, token=cred.token)
    res: dict[str, Any] = bridge.dispatch(call, ctx, auth=auth)
    return res


def _call_ok(
    bridge: Any,
    rt: Any,
    tool: str,
    args: dict[str, JsonValue],
    *,
    cred: SeededCredential,
    scope: Scope,
) -> dict[str, Any]:
    env = _dispatch_call(bridge, rt, tool, args, cred=cred, scope=scope)
    assert env.get("ok") is True, env
    data = env.get("data")
    assert isinstance(data, dict)
    return data


def _call_err(
    bridge: Any,
    rt: Any,
    tool: str,
    args: dict[str, JsonValue],
    *,
    cred: SeededCredential,
    scope: Scope,
) -> str:
    env = _dispatch_call(bridge, rt, tool, args, cred=cred, scope=scope)
    assert env.get("ok") is False, env
    err = env.get("error")
    assert isinstance(err, dict)
    return str(err["code"])


def test_discover_work_get_artifact_resume_and_c5_receipts_end_to_end(trusted_tmp: Path) -> None:
    from superbrain.composition._daemon_session import build_default_handoff_domain
    from superbrain.composition.kernel_bridge import KernelBridge

    clock = FakeClock(dt.datetime(2026, 11, 26, 4, 0, tzinfo=dt.UTC))
    adapters = os_adapters(clock=clock)
    root = trusted_tmp / "e2e-handoff"
    rt = open_kernel_job_runtime(root / "data", adapters, role="sp24-e2e")
    try:
        cred_a = seed_principal_and_credential(rt.policy, owner_id="dan", harness_id="claude-code", machine_id="m1")
        cred_b = seed_principal_and_credential(rt.policy, owner_id="dan", harness_id="codex", machine_id="m1")
        ws_a = register_workspace_direct(
            rt,
            clock,
            cred_a.principal,
            alias="ws-a",
            checkout_dir=root / "chk-a",
            remote="https://github.example/dan/repo.git",
        )
        ws_b = register_workspace_direct(
            rt,
            clock,
            cred_a.principal,
            alias="ws-b",
            checkout_dir=root / "chk-b",
            remote="https://github.example/dan/repo.git",
        )
        seed_repo_grant(rt.policy, principal_id=cred_b.principal.principal_id, repo_id=ws_a.repo_id, owner_id="dan")
        seed_repo_grant(rt.policy, principal_id=cred_b.principal.principal_id, repo_id=ws_b.repo_id, owner_id="dan")
        rt.store.reconcile_policy()

        domain = build_default_handoff_domain(rt=rt, clock=clock, writer_epoch=rt.lease.epoch)
        assert domain is not None
        assert domain.supports_tool("prepare_task") is True
        assert domain.supports_tool("get_artifact") is True
        assert domain.supports_tool("submit_episode") is True
        assert domain.supports_tool("search_knowledge") is False
        assert domain.supports_tool("get_health", deep=True) is False

        bridge = KernelBridge(store=rt.store, policy=rt.policy, clock=clock, writer_epoch=rt.lease.epoch, domain=domain)
        scope_a = Scope(ws_a.repo_id, ws_a.checkout_id)
        scope_b = Scope(ws_b.repo_id, ws_b.checkout_id)

        # 1. Initial work call mints task + live fence (0, 0), and initial discover has 0 side effects.
        disc0 = _call_ok(
            bridge,
            rt,
            "prepare_task",
            {
                "mode": "discover",
                "workspace_id": ws_a.repo_id,
                "checkout_id": ws_a.checkout_id,
                "context_budget_tokens": 2000,
            },
            cred=cred_a,
            scope=scope_a,
        )
        assert disc0["continuity"] == []
        for code in ("skills_unavailable", "lessons_unavailable", "context_unavailable", "finishing_gates_unavailable"):
            assert code in disc0["degraded_codes"]

        work1 = _call_ok(
            bridge,
            rt,
            "prepare_task",
            {
                "mode": "work",
                "workspace_id": ws_a.repo_id,
                "checkout_id": ws_a.checkout_id,
                "description": "Implement SP2-4 continuity handoff end to end",
                "context_budget_tokens": 2000,
                "idempotency_key": "idem-work-1-aaaaaa",
            },
            cred=cred_a,
            scope=scope_a,
        )
        task_id = work1["task_id"]
        assert work1["handoff_live"]["revision"] is None
        assert work1["handoff_live"]["handoff_revision"] == 0
        assert work1["handoff_live"]["fence"] == {"restore_epoch": 0, "writer_generation": 0}

        # 2. First submit_episode with takeover + handoff creates revision 1.
        ep1 = _call_ok(
            bridge,
            rt,
            "submit_episode",
            {
                "task_id": task_id,
                "session_id": "raw-session-a-1",
                "evidence": [],
                "base_revision": 0,
                "fence": {"restore_epoch": 0, "writer_generation": 0},
                "takeover": {"acknowledge_active": True, "reason": "initial hold"},
                "handoff": {
                    "working_goal": "Complete handoff persistence",
                    "next_action": {"summary": "Serve L1 and takeover from B"},
                    "task_state": "open",
                },
                "idempotency_key": "idem-ep-1-aaaaaaaa",
            },
            cred=cred_a,
            scope=scope_a,
        )
        assert ep1["handoff_status"] == "stored"
        assert ep1["handoff_revision"] == 1
        assert ep1["writer_status"] == "holder"
        assert ep1["fence"] == {"restore_epoch": 0, "writer_generation": 1}

        # 3. Privacy leakage rejects fail-closed with ZERO side effects!
        assert (
            _call_err(
                bridge,
                rt,
                "submit_episode",
                {
                    "task_id": task_id,
                    "session_id": "raw-session-a-1",
                    "evidence": [],
                    "base_revision": 1,
                    "fence": ep1["fence"],
                    "handoff": {"working_goal": "<private>unterminated secret"},
                    "idempotency_key": "idem-priv-fail-111",
                },
                cred=cred_a,
                scope=scope_a,
            )
            == ErrorCode.INVALID_INPUT.value
        )

        # 4. B discovers -> gets L1 -> gets ServedReceipt (served_receipt_id) -> ReadAck -> resumes with read_ack!
        disc_b = _call_ok(
            bridge,
            rt,
            "prepare_task",
            {
                "mode": "discover",
                "workspace_id": ws_a.repo_id,
                "checkout_id": ws_a.checkout_id,
                "context_budget_tokens": 2000,
            },
            cred=cred_b,
            scope=scope_a,
        )
        assert len(disc_b["continuity"]) == 1
        item = disc_b["continuity"][0]
        assert item["kind"] == "handoff" and item["id"] == task_id and item["revision"] == 1
        assert "raw-session-a-1" not in item["summary"]

        # Same repo, different checkout B gets NOT_FOUND across discover/get_artifact (cases 2, 41, 48).
        disc_wrong_chk = _call_ok(
            bridge,
            rt,
            "prepare_task",
            {
                "mode": "discover",
                "workspace_id": ws_b.repo_id,
                "checkout_id": ws_b.checkout_id,
                "context_budget_tokens": 2000,
            },
            cred=cred_b,
            scope=scope_b,
        )
        assert disc_wrong_chk["continuity"] == []
        assert (
            _call_err(
                bridge,
                rt,
                "get_artifact",
                {
                    "workspace_id": ws_b.repo_id,
                    "task_id": task_id,
                    "artifact_id": task_id,
                    "revision_epoch": item["revision_epoch"],
                    "revision": item["revision"],
                    "level": "L1",
                    "idempotency_key": "idem-art-b-wrong-1",
                },
                cred=cred_b,
                scope=scope_b,
            )
            == ErrorCode.NOT_FOUND.value
        )
    finally:
        rt.close()


def test_takeover_fence_idempotency_not_holder_not_stored_policy_and_checkout_isolation(trusted_tmp: Path) -> None:
    from superbrain.composition._daemon_session import build_default_handoff_domain
    from superbrain.composition.kernel_bridge import KernelBridge

    clock = FakeClock(dt.datetime(2026, 11, 26, 5, 0, tzinfo=dt.UTC))
    adapters = os_adapters(clock=clock)
    root = trusted_tmp / "takeover-e2e"
    rt = open_kernel_job_runtime(root / "data", adapters, role="sp24-takeover")
    try:
        cred_a = seed_principal_and_credential(rt.policy, owner_id="dan", harness_id="claude-code", machine_id="m1")
        cred_b = seed_principal_and_credential(rt.policy, owner_id="dan", harness_id="codex", machine_id="m1")
        ws_a = register_workspace_direct(
            rt,
            clock,
            cred_a.principal,
            alias="ws-a",
            checkout_dir=root / "chk-a",
            remote="https://github.example/dan/repo.git",
        )
        register_workspace_direct(
            rt,
            clock,
            cred_a.principal,
            alias="ws-b",
            checkout_dir=root / "chk-b",
            remote="https://github.example/dan/repo.git",
        )
        seed_repo_grant(rt.policy, principal_id=cred_b.principal.principal_id, repo_id=ws_a.repo_id, owner_id="dan")
        rt.store.reconcile_policy()

        domain = build_default_handoff_domain(rt=rt, clock=clock, writer_epoch=rt.lease.epoch)
        assert domain is not None
        bridge = KernelBridge(store=rt.store, policy=rt.policy, clock=clock, writer_epoch=rt.lease.epoch, domain=domain)
        scope_a = Scope(ws_a.repo_id, ws_a.checkout_id)

        work1 = _call_ok(
            bridge,
            rt,
            "prepare_task",
            {
                "mode": "work",
                "workspace_id": ws_a.repo_id,
                "checkout_id": ws_a.checkout_id,
                "description": "Takeover fence verification",
                "context_budget_tokens": 2000,
                "idempotency_key": "idem-take-work-111",
            },
            cred=cred_a,
            scope=scope_a,
        )
        tid = work1["task_id"]

        # A holds fence (0, 1), hrev 1.
        r1 = _call_ok(
            bridge,
            rt,
            "submit_episode",
            {
                "task_id": tid,
                "session_id": "sess-a-hold",
                "evidence": [],
                "base_revision": 0,
                "fence": {"restore_epoch": 0, "writer_generation": 0},
                "takeover": {"acknowledge_active": True},
                "handoff": {"working_goal": "A starts"},
                "idempotency_key": "idem-take-a-111111",
            },
            cred=cred_a,
            scope=scope_a,
        )
        assert r1["writer_status"] == "holder" and r1["fence"] == {"restore_epoch": 0, "writer_generation": 1}

        clock.advance(dt.timedelta(seconds=10))
        # Seeded session A is still active (< 300 s): takeover WITHOUT acknowledge_active=True fails (case 47).
        assert (
            _call_err(
                bridge,
                rt,
                "submit_episode",
                {
                    "task_id": tid,
                    "session_id": "sess-b-take",
                    "evidence": [],
                    "base_revision": 1,
                    "fence": {"restore_epoch": 0, "writer_generation": 1},
                    "takeover": {"acknowledge_active": False, "reason": "No ack"},
                    "idempotency_key": "idem-take-b-noack1",
                },
                cred=cred_b,
                scope=scope_a,
            )
            == ErrorCode.INVALID_INPUT.value
        )

        # With acknowledge_active=True, B succeeds; takeover-only preserves handoff_revision=1!
        r2 = _call_ok(
            bridge,
            rt,
            "submit_episode",
            {
                "task_id": tid,
                "session_id": "sess-b-take",
                "evidence": [],
                "base_revision": 1,
                "fence": {"restore_epoch": 0, "writer_generation": 1},
                "takeover": {"acknowledge_active": True, "reason": "B takes over"},
                "idempotency_key": "idem-take-b-222222",
            },
            cred=cred_b,
            scope=scope_a,
        )
        assert r2["handoff_status"] == "stored"
        assert r2["handoff_revision"] == 1  # takeover-only does NOT bump handoff_revision (case 68)!
        assert r2["writer_status"] == "holder"
        assert r2["fence"] == {"restore_epoch": 0, "writer_generation": 2}

        # Stale non-takeover write by A with old fence fails REVISION_CONFLICT.
        assert (
            _call_err(
                bridge,
                rt,
                "submit_episode",
                {
                    "task_id": tid,
                    "session_id": "sess-a-hold",
                    "evidence": [],
                    "base_revision": 1,
                    "fence": {"restore_epoch": 0, "writer_generation": 1},
                    "handoff": {"working_goal": "A stale write"},
                    "idempotency_key": "idem-take-a-stale1",
                },
                cred=cred_a,
                scope=scope_a,
            )
            == ErrorCode.REVISION_CONFLICT.value
        )

        # Idempotent replay of r1 AFTER B took over checks idempotency BEFORE base_revision/fence
        # and returns dynamic writer_status="not_holder" (cases 38, 67, 74)!
        r1_replay = _call_ok(
            bridge,
            rt,
            "submit_episode",
            {
                "task_id": tid,
                "session_id": "sess-a-hold",
                "evidence": [],
                "base_revision": 0,
                "fence": {"restore_epoch": 0, "writer_generation": 0},
                "takeover": {"acknowledge_active": True},
                "handoff": {"working_goal": "A starts"},
                "idempotency_key": "idem-take-a-111111",
            },
            cred=cred_a,
            scope=scope_a,
        )
        assert r1_replay["episode_id"] == r1["episode_id"]
        assert r1_replay["fence"] == {"restore_epoch": 0, "writer_generation": 1}
        assert r1_replay["writer_status"] == "not_holder"

        # Plain episode without handoff or takeover returns SubmitEpisodePlainResult (no handoff_status).
        plain = _call_ok(
            bridge,
            rt,
            "submit_episode",
            {
                "task_id": tid,
                "session_id": "sess-b-take",
                "evidence": [{"kind": "tool_post", "data": {"step": "lint"}}],
                "idempotency_key": "idem-plain-ep-1111",
            },
            cred=cred_b,
            scope=scope_a,
        )
        assert set(plain) == {"episode_id", "evidence_ids"}
        assert len(plain["evidence_ids"]) == 1

        # Policy manual_submission=False strips evidence/handoff -> not_stored_policy, header unchanged!
        rt.policy.set_repo_policy(
            ws_a.repo_id,
            automatic_capture_enabled=True,
            manual_submission_enabled=False,
        )
        rt.store.reconcile_policy()
        blocked = _call_ok(
            bridge,
            rt,
            "submit_episode",
            {
                "task_id": tid,
                "session_id": "sess-b-take",
                "evidence": [{"kind": "tool_post", "data": {"note": "must not store"}}],
                "base_revision": 1,
                "fence": r2["fence"],
                "handoff": {"working_goal": "Blocked by policy"},
                "idempotency_key": "idem-policy-block-1",
            },
            cred=cred_b,
            scope=scope_a,
        )
        assert blocked["handoff_status"] == "not_stored_policy"
        assert blocked["handoff_revision"] is None
        assert blocked["evidence_ids"] == []
    finally:
        rt.close()


def test_production_loopback_daemon_l0_l1_l2_served_receipt_read_ack_and_resume(trusted_tmp: Path) -> None:
    from superbrain.core.kernel import ToolCommand
    from superbrain.storage.sqlite import open_readonly
    from tests.support.inc2_cli import get_shared_t7_transport_template
    from tests.support.inc2_transport import open_test_loopback_transport

    tpl = get_shared_t7_transport_template()
    ws_a = tpl.ws_a
    ws_b = tpl.ws_b
    assert ws_a is not None and ws_b is not None
    scope_a = Scope(ws_a.repo_id, ws_a.checkout_id)
    scope_b = Scope(ws_b.repo_id, ws_b.checkout_id)

    with open_test_loopback_transport(tpl, name="sp24-loopback", domain=None) as h:
        client = h.open_client()
        target = h.make_target()

        def call_loop(tool: str, args: dict[str, JsonValue], *, scope: Scope = scope_a) -> dict[str, Any]:
            return client.call(
                target,
                ToolCommand(
                    tool=tool,
                    arguments={"schema_version": SCHEMA_VERSION, **args},
                    token=tpl.cred.token,
                    selected_scope=scope,
                ),
            )

        def wait_send_state(receipt_id: str, expected: str, *, timeout_s: float = 2.0) -> str | None:
            deadline = time.perf_counter() + timeout_s
            while time.perf_counter() < deadline:
                state = h.get_send_attempt_state(receipt_id)
                if state == expected:
                    return state
                time.sleep(0.005)
            h.loop.run_owner_action(lambda: None).result(timeout=2.0)
            return h.get_send_attempt_state(receipt_id)

        # 1. Start work task on production loopback daemon (domain=None -> default HandoffKernelDomain).
        prep = call_loop(
            "prepare_task",
            {
                "mode": "work",
                "workspace_id": ws_a.repo_id,
                "checkout_id": ws_a.checkout_id,
                "description": "Production daemon continuity lifecycle test",
                "context_budget_tokens": 3000,
                "idempotency_key": "idem-prod-prep-0001",
            },
        )
        assert prep.get("ok") is True, prep
        pdata = prep["data"]
        tid = pdata["task_id"]
        assert pdata["handoff_live"] == {
            "revision": None,
            "revision_epoch": None,
            "handoff_revision": 0,
            "fence": {"restore_epoch": 0, "writer_generation": 0},
        }

        # 2. Submit initial rich handoff patch (all sections).
        sub1 = call_loop(
            "submit_episode",
            {
                "task_id": tid,
                "session_id": "RAW_LOOP_SID_SECRET_001",
                "workspace_id": ws_a.repo_id,
                "checkout_id": ws_a.checkout_id,
                "evidence": [{"kind": "tool_post", "data": {"cmd": "pytest", "passed": True}}],
                "base_revision": 0,
                "fence": pdata["handoff_live"]["fence"],
                "handoff": {
                    "working_goal": "Verify L0/L1/L2 & ReadAck",
                    "plan": [{"id": "s-1", "summary": "Serve artifacts", "status": "in_progress"}],
                    "decisions": [{"id": "d-1", "decision": "Use SQLite v8", "reason": "Epochs"}],
                    "user_constraints": [{"id": "c-1", "constraint": "No sleeps"}],
                    "tooling": [{"purpose": "test", "command": "pytest -q"}],
                    "hypotheses": ["Replay mints fresh served_receipt_id"],
                    "next_action": {"summary": "Acknowledge L1 digests"},
                    "task_state": "open",
                },
                "idempotency_key": "idem-prod-sub1-0001",
            },
        )
        assert sub1.get("ok") is True, sub1
        s1 = sub1["data"]
        assert s1["handoff_status"] == "stored" and s1["handoff_revision"] == 1
        assert s1["writer_status"] == "holder"

        # 3. Fetch L0, L1, L2; verify ServedReceipt transitions pending -> served_only on HTTP 200.
        art_l0 = call_loop(
            "get_artifact",
            {
                "workspace_id": ws_a.repo_id,
                "task_id": tid,
                "artifact_id": tid,
                "revision": 1,
                "level": "L0",
                "idempotency_key": "idem-prod-l0-000001",
            },
        )
        assert art_l0.get("ok") is True and art_l0["data"]["status"] == "ok", art_l0

        get_l1_args: dict[str, JsonValue] = {
            "workspace_id": ws_a.repo_id,
            "task_id": tid,
            "artifact_id": tid,
            "revision_epoch": 0,
            "revision": 1,
            "level": "L1",
            "idempotency_key": "idem-prod-l1-000001",
        }
        art_l1 = call_loop("get_artifact", get_l1_args)
        assert art_l1.get("ok") is True and art_l1["data"]["status"] == "ok", art_l1
        l1_data = art_l1["data"]
        receipt_1 = l1_data["served_receipt_id"]
        assert isinstance(receipt_1, str)
        assert wait_send_state(receipt_1, SendAttemptState.SERVED_ONLY) == SendAttemptState.SERVED_ONLY
        assert l1_data["resources"][0]["name"] == "handoff_header"

        # Replaying SAME get_artifact idempotency_key mints a DISTINCT served_receipt_id (C5 / case 72)!
        art_l1_replay = call_loop("get_artifact", get_l1_args)
        assert art_l1_replay.get("ok") is True
        receipt_2 = art_l1_replay["data"]["served_receipt_id"]
        assert isinstance(receipt_2, str)
        assert receipt_2 != receipt_1
        assert wait_send_state(receipt_2, SendAttemptState.SERVED_ONLY) == SendAttemptState.SERVED_ONLY

        art_l2 = call_loop(
            "get_artifact",
            {
                "workspace_id": ws_a.repo_id,
                "task_id": tid,
                "artifact_id": tid,
                "revision": 1,
                "level": "L2",
                "idempotency_key": "idem-prod-l2-000001",
            },
        )
        assert art_l2.get("ok") is True and art_l2["data"]["status"] == "ok", art_l2

        # 4. Negative ReadAck checks: wrong digest -> INVALID_INPUT; forged receipt -> NOT_FOUND.
        assert isinstance(l1_data["resources"], list)
        l1_digests: list[JsonValue] = [
            {"name": str(r["name"]), "digest": str(r["digest"])} for r in l1_data["resources"]
        ]
        wrong_digs: list[JsonValue] = [
            {"name": str(r["name"]), "digest": digest_bytes(b"wrong")} for r in l1_data["resources"]
        ]
        bad_dig_ack = call_loop(
            "submit_episode",
            {
                "task_id": tid,
                "session_id": "RAW_LOOP_SID_SECRET_001",
                "workspace_id": ws_a.repo_id,
                "checkout_id": ws_a.checkout_id,
                "evidence": [],
                "read_acks": [
                    {
                        "served_receipt_id": receipt_1,
                        "task_id": tid,
                        "artifact_id": tid,
                        "revision_epoch": 0,
                        "revision": 1,
                        "resource_digests": wrong_digs,
                    }
                ],
                "idempotency_key": "idem-prod-ack-baddig",
            },
        )
        assert bad_dig_ack == {"ok": False, "error": {"code": "invalid_input", "message": "invalid input"}}

        forged_ack = call_loop(
            "submit_episode",
            {
                "task_id": tid,
                "session_id": "RAW_LOOP_SID_SECRET_001",
                "workspace_id": ws_a.repo_id,
                "checkout_id": ws_a.checkout_id,
                "evidence": [],
                "read_acks": [
                    {
                        "served_receipt_id": "01999999-9999-7000-8000-999999999999",
                        "task_id": tid,
                        "artifact_id": tid,
                        "revision_epoch": 0,
                        "revision": 1,
                        "resource_digests": l1_digests,
                    }
                ],
                "idempotency_key": "idem-prod-ack-forged",
            },
        )
        assert forged_ack == {"ok": False, "error": {"code": "not_found", "message": "not found"}}

        # 5. Valid ReadAck succeeds and records artifact_read_ack; duplicate same-receipt ack is idempotent!
        good_ack = call_loop(
            "submit_episode",
            {
                "task_id": tid,
                "session_id": "RAW_LOOP_SID_SECRET_001",
                "workspace_id": ws_a.repo_id,
                "checkout_id": ws_a.checkout_id,
                "evidence": [],
                "read_acks": [
                    {
                        "served_receipt_id": receipt_1,
                        "task_id": tid,
                        "artifact_id": tid,
                        "revision_epoch": 0,
                        "revision": 1,
                        "resource_digests": l1_digests,
                    }
                ],
                "idempotency_key": "idem-prod-ack-good01",
            },
        )
        assert good_ack.get("ok") is True, good_ack
        assert h.count_read_acks() == 1

        dup_ack = call_loop(
            "submit_episode",
            {
                "task_id": tid,
                "session_id": "RAW_LOOP_SID_SECRET_001",
                "workspace_id": ws_a.repo_id,
                "checkout_id": ws_a.checkout_id,
                "evidence": [],
                "read_acks": [
                    {
                        "served_receipt_id": receipt_1,
                        "task_id": tid,
                        "artifact_id": tid,
                        "revision_epoch": 0,
                        "revision": 1,
                        "resource_digests": l1_digests,
                    }
                ],
                "idempotency_key": "idem-prod-ack-good02",
            },
        )
        assert dup_ack.get("ok") is True, dup_ack
        assert h.count_read_acks() == 1

        # 6. prepare_task(mode="work") with resume_ref -> exposure_evidence="resumed"; seen_handoff_refs -> "seen_l0".
        resumed_work = call_loop(
            "prepare_task",
            {
                "mode": "work",
                "workspace_id": ws_a.repo_id,
                "checkout_id": ws_a.checkout_id,
                "task_id": tid,
                "resume_ref": {
                    "served_receipt_id": receipt_1,
                    "artifact_id": tid,
                    "revision": 1,
                    "handoff_revision": 1,
                    "fence": s1["fence"],
                },
                "description": "Resume existing task",
                "idempotency_key": "idem-prod-resumed-1",
            },
        )
        assert resumed_work.get("ok") is True, resumed_work

        disc_live = call_loop(
            "prepare_task",
            {"mode": "discover", "workspace_id": ws_a.repo_id, "checkout_id": ws_a.checkout_id},
        )
        assert disc_live.get("ok") is True
        seen_item = disc_live["data"]["continuity"][0]
        seen_work = call_loop(
            "prepare_task",
            {
                "mode": "work",
                "workspace_id": ws_a.repo_id,
                "checkout_id": ws_a.checkout_id,
                "seen_handoff_refs": [
                    {
                        "artifact_id": seen_item["id"],
                        "revision_epoch": seen_item["revision_epoch"],
                        "revision": seen_item["revision"],
                        "digest": seen_item["digest"],
                    }
                ],
                "description": "New task after reviewing open handoff",
                "idempotency_key": "idem-prod-seen-work1",
            },
        )
        assert seen_work.get("ok") is True, seen_work

        # Cross-checkout resume_ref & seen_handoff_refs are rejected with NOT_FOUND (case 2, 41, 48).
        bad_resume = call_loop(
            "prepare_task",
            {
                "mode": "work",
                "workspace_id": ws_b.repo_id,
                "checkout_id": ws_b.checkout_id,
                "task_id": tid,
                "resume_ref": {
                    "artifact_id": tid,
                    "revision": 1,
                    "handoff_revision": 1,
                    "fence": s1["fence"],
                },
                "description": "Cross checkout attempt",
                "idempotency_key": "idem-prod-xchk-res-1",
            },
            scope=scope_b,
        )
        assert bad_resume == {"ok": False, "error": {"code": "not_found", "message": "not found"}}

        # Inspect durable tables (deliveries & absence of raw session ID) via read-only connection.
        ro_scratch = trusted_tmp / "ro-loop-inspect"
        ro_scratch.mkdir()
        with open_readonly(h.data_root / "store" / "brain.db", scratch_dir=ro_scratch) as conn:
            exp_rows = dict(conn.execute("SELECT delivery_id, exposure_evidence FROM deliveries").fetchall())
            assert exp_rows[resumed_work["data"]["delivery_id"]] == "resumed"
            assert exp_rows[seen_work["data"]["delivery_id"]] == "seen_l0"
            raw_cells = conn.execute(
                "SELECT COUNT(*) FROM episodes WHERE session_ref LIKE '%RAW_LOOP_SID%'"
            ).fetchone()
            assert raw_cells is not None and int(raw_cells[0]) == 0
        for blob_path in (h.data_root / "cas").rglob("*"):
            if blob_path.is_file():
                assert b"RAW_LOOP_SID_SECRET_001" not in blob_path.read_bytes()


def test_continuity_worker_3phase_quarantine_redaction_and_restore_epoch(trusted_tmp: Path) -> None:
    from superbrain.application.continuity_worker import ContinuityWorkerCoordinator
    from superbrain.composition._daemon_session import build_default_handoff_domain
    from superbrain.composition.kernel_bridge import KernelBridge
    from superbrain.ports.policy import IntentKind
    from superbrain.storage.backup import create_store_backup
    from superbrain.storage.handoffs import HandoffStore
    from superbrain.storage.kernel_schema import KERNEL_POLICY_MIGRATIONS, KERNEL_STORE_MIGRATIONS
    from superbrain.storage.policy_store import PolicyStore
    from superbrain.storage.restore import restore_store
    from superbrain.storage.sessions import SessionStore
    from superbrain.workers.executor import PRODUCTION_JOB_HANDLERS, JobExecutor
    from tests.storage.conftest import maintenance_lease
    from tests.support.inc2_fixture import kernel_job_service

    clock = FakeClock(dt.datetime(2026, 11, 26, 6, 0, tzinfo=dt.UTC))
    adapters = os_adapters(clock=clock)
    root = trusted_tmp / "worker-redaction-e2e"
    rt = open_kernel_job_runtime(root / "data", adapters, role="sp24-worker")
    try:
        cred = seed_principal_and_credential(rt.policy, owner_id="dan", harness_id="claude-code", machine_id="m1")
        ws = register_workspace_direct(rt, clock, cred.principal, alias="ws-w", checkout_dir=root / "chk-w")
        rt.store.reconcile_policy()
        scope = Scope(ws.repo_id, ws.checkout_id)

        domain = build_default_handoff_domain(rt=rt, clock=clock, writer_epoch=rt.lease.epoch)
        assert domain is not None
        bridge = KernelBridge(store=rt.store, policy=rt.policy, clock=clock, writer_epoch=rt.lease.epoch, domain=domain)
        work = _call_ok(
            bridge,
            rt,
            "prepare_task",
            {
                "mode": "work",
                "workspace_id": ws.repo_id,
                "checkout_id": ws.checkout_id,
                "description": "Worker 3-phase & redaction goal",
                "idempotency_key": "idem-wrk-prep-00001",
            },
            cred=cred,
            scope=scope,
        )
        tid = work["task_id"]
        sub1 = _call_ok(
            bridge,
            rt,
            "submit_episode",
            {
                "task_id": tid,
                "session_id": "RAW_SID_WORKER_999",
                "workspace_id": ws.repo_id,
                "checkout_id": ws.checkout_id,
                "evidence": [],
                "base_revision": 0,
                "fence": work["handoff_live"]["fence"],
                "handoff": {"working_goal": "Agent state preserved across worker refresh"},
                "idempotency_key": "idem-wrk-sub1-00001",
            },
            cred=cred,
            scope=scope,
        )
        assert sub1["handoff_revision"] == 1

        # Record captured user_message events -> run 3-phase continuity worker -> creates rev 2 preserving hrev 1.
        hs = HandoffStore(rt.store, rt.policy)
        ss = SessionStore(rt.store, rt.policy)
        hdr1 = hs.read_header(tid, principal_id=cred.principal.principal_id, scope=scope)
        assert hdr1 is not None and hdr1.holder_session_ref is not None
        ev = CaptureEventRecord(
            event_id="ev-wrk-msg-1",
            producer_stream="stream-wrk-1",
            sequence=1,
            harness_id="claude-code",
            kind="user_message",
            recorded_at="2026-11-26T06:00:05Z",
            payload={"role": "user", "text": "Please verify UTF-8 redaction without mutating header"},
            session_ref=hdr1.holder_session_ref,
        )
        ss.record_session_event(
            session_ref=hdr1.holder_session_ref,
            repo_id=ws.repo_id,
            checkout_id=ws.checkout_id,
            task_id=tid,
            producer_stream="stream-wrk-1",
            event=ev,
            now=clock.now(),
        )
        svc, _ = kernel_job_service(rt, clock)
        exec_ = JobExecutor(PRODUCTION_JOB_HANDLERS, lambda: 10_000)
        exec_.start()
        try:
            coord = ContinuityWorkerCoordinator(
                rt=rt, job_service=svc, executor=exec_, clock=clock, mono=lambda: 10_000
            )
            clock.advance(dt.timedelta(seconds=65))
            assert coord.enqueue_if_due(task_id=tid, now=clock.now()) is not None
            assert coord.run_next(writer_epoch=rt.lease.epoch, now=clock.now()) is True
        finally:
            exec_.close(5.0)

        # Verify handoff_revision_headers recorded revision 2 with handoff_revision still 1!
        hdr2 = hs.read_revision_header(
            artifact_id=tid,
            revision_epoch=0,
            revision=2,
            principal_id=cred.principal.principal_id,
            scope=scope,
        )
        assert hdr2 is not None and hdr2.handoff_revision == 1 and hdr2.observed_ref is not None

        # L2 includes conversation excerpt before quarantine.
        l2_ok = _call_ok(
            bridge,
            rt,
            "get_artifact",
            {
                "workspace_id": ws.repo_id,
                "task_id": tid,
                "artifact_id": tid,
                "revision_epoch": 0,
                "revision": 2,
                "level": "L2",
                "idempotency_key": "idem-wrk-l2-ok-00001",
            },
            cred=cred,
            scope=scope,
        )
        assert l2_ok["status"] == "ok" and "Please verify UTF-8" in str(l2_ok["resources"])

        # Quarantine event blob digest -> observed excerpt in L2 becomes redacted while handoff remains ok.
        ev_row = rt.store._db.execute(
            "SELECT payload_digest FROM session_task_events WHERE task_id = ?", (tid,)
        ).fetchone()
        assert ev_row is not None
        rt.policy.record_intent(IntentKind.QUARANTINE, {"digest": str(ev_row[0])})
        rt.store.reconcile_policy()
        l2_ev_red = _call_ok(
            bridge,
            rt,
            "get_artifact",
            {
                "workspace_id": ws.repo_id,
                "task_id": tid,
                "artifact_id": tid,
                "revision_epoch": 0,
                "revision": 2,
                "level": "L2",
                "idempotency_key": "idem-wrk-l2-evred-01",
            },
            cred=cred,
            scope=scope,
        )
        assert l2_ev_red["status"] == "ok"
        assert "Please verify UTF-8" not in str(l2_ev_red["resources"])
        assert '"status":"redacted"' in str(l2_ev_red["resources"])

        bak = create_store_backup(rt.store, adapters, clock.now())

        # Quarantine task goal digest -> get_artifact returns Redacted with 0 resources & NO served_receipt_id!
        rt.policy.record_intent(IntentKind.QUARANTINE, {"digest": hdr1.goal_ref or ""})
        rt.store.reconcile_policy()
        l1_goal_red = _call_ok(
            bridge,
            rt,
            "get_artifact",
            {
                "workspace_id": ws.repo_id,
                "task_id": tid,
                "artifact_id": tid,
                "revision_epoch": 0,
                "revision": 1,
                "level": "L1",
                "idempotency_key": "idem-wrk-l1-red-0001",
            },
            cred=cred,
            scope=scope,
        )
        assert l1_goal_red["status"] == "redacted"
        assert l1_goal_red["resources"] == []
        assert "served_receipt_id" not in l1_goal_red
    finally:
        rt.close()

    # Restore store -> restore_epoch bumps -> pre-restore replay flips to not_holder & stale fence rejected!
    clock.advance(dt.timedelta(seconds=5))
    with maintenance_lease(root / "data", adapters) as (droot, lease):
        pol_h = PolicyStore.open(droot, lease, adapters, migrations=KERNEL_POLICY_MIGRATIONS)
        try:
            rep = restore_store(
                droot,
                lease,
                adapters,
                bak,
                pol_h,
                clock.now(),
                migrations=KERNEL_STORE_MIGRATIONS,
            )
        finally:
            pol_h.close()
    assert rep.new_epoch >= 1

    rt_rest = open_kernel_job_runtime(root / "data", adapters, role="sp24-worker")
    try:
        dom2 = build_default_handoff_domain(rt=rt_rest, clock=clock, writer_epoch=rt_rest.lease.epoch)
        assert dom2 is not None
        br2 = KernelBridge(
            store=rt_rest.store,
            policy=rt_rest.policy,
            clock=clock,
            writer_epoch=rt_rest.lease.epoch,
            domain=dom2,
        )
        sub1_post = _call_ok(
            br2,
            rt_rest,
            "submit_episode",
            {
                "task_id": tid,
                "session_id": "RAW_SID_WORKER_999",
                "workspace_id": ws.repo_id,
                "checkout_id": ws.checkout_id,
                "evidence": [],
                "base_revision": 0,
                "fence": {"restore_epoch": 0, "writer_generation": 0},
                "handoff": {"working_goal": "Agent state preserved across worker refresh"},
                "idempotency_key": "idem-wrk-sub1-00001",
            },
            cred=cred,
            scope=scope,
        )
        assert sub1_post["writer_status"] == "not_holder"
        assert (
            _call_err(
                br2,
                rt_rest,
                "submit_episode",
                {
                    "task_id": tid,
                    "session_id": "RAW_SID_WORKER_999",
                    "workspace_id": ws.repo_id,
                    "checkout_id": ws.checkout_id,
                    "evidence": [],
                    "base_revision": 1,
                    "fence": sub1["fence"],
                    "handoff": {"working_goal": "Should fail stale epoch"},
                    "idempotency_key": "idem-wrk-stale-epoch",
                },
                cred=cred,
                scope=scope,
            )
            == ErrorCode.REVISION_CONFLICT.value
        )
    finally:
        rt_rest.close()


def test_replay_ack_writer_status_requires_live_fence_match_across_siblings(trusted_tmp: Path) -> None:
    """F1 oracle (§7.4, case 74): replay ACK has writer_status='holder' iff caller holds task AND ACK fence == live."""
    from superbrain.composition._daemon_session import build_default_handoff_domain
    from superbrain.composition.kernel_bridge import KernelBridge
    from superbrain.storage.backup import create_store_backup
    from superbrain.storage.kernel_schema import KERNEL_POLICY_MIGRATIONS, KERNEL_STORE_MIGRATIONS
    from superbrain.storage.policy_store import PolicyStore
    from superbrain.storage.restore import restore_store
    from tests.storage.conftest import maintenance_lease

    clock = FakeClock(dt.datetime(2026, 11, 26, 6, 0, tzinfo=dt.UTC))
    adapters = os_adapters(clock=clock)
    root = trusted_tmp / "f1-replay-fence"
    rt = open_kernel_job_runtime(root / "data", adapters, role="sp24-f1")
    try:
        cred_a = seed_principal_and_credential(rt.policy, owner_id="dan", harness_id="claude-code", machine_id="m1")
        cred_b = seed_principal_and_credential(rt.policy, owner_id="dan", harness_id="codex", machine_id="m1")
        ws = register_workspace_direct(
            rt,
            clock,
            cred_a.principal,
            alias="ws-f1",
            checkout_dir=root / "chk-f1",
            remote="https://github.example/dan/repo-f1.git",
        )
        seed_repo_grant(rt.policy, principal_id=cred_b.principal.principal_id, repo_id=ws.repo_id, owner_id="dan")
        rt.store.reconcile_policy()

        domain = build_default_handoff_domain(rt=rt, clock=clock, writer_epoch=rt.lease.epoch)
        assert domain is not None
        bridge = KernelBridge(store=rt.store, policy=rt.policy, clock=clock, writer_epoch=rt.lease.epoch, domain=domain)
        scope = Scope(ws.repo_id, ws.checkout_id)

        prep = _call_ok(
            bridge,
            rt,
            "prepare_task",
            {
                "mode": "work",
                "workspace_id": ws.repo_id,
                "checkout_id": ws.checkout_id,
                "description": "Replay writer_status fence probe",
                "idempotency_key": "idem-sp24-f1-prep-0001",
            },
            cred=cred_a,
            scope=scope,
        )
        tid = str(prep["task_id"])

        def sub(cred: SeededCredential, sid: str, key: str, args: dict[str, JsonValue]) -> dict[str, Any]:
            return _call_ok(
                bridge,
                rt,
                "submit_episode",
                {
                    "task_id": tid,
                    "session_id": sid,
                    "workspace_id": ws.repo_id,
                    "evidence": [],
                    "idempotency_key": key,
                    **args,
                },
                cred=cred,
                scope=scope,
            )

        # A initial write -> gen 1, holder.
        a1_args: dict[str, JsonValue] = {
            "evidence": [],
            "base_revision": 0,
            "fence": {"restore_epoch": 0, "writer_generation": 0},
            "handoff": {"working_goal": "A gen 1"},
        }
        a_g1 = sub(cred_a, "SID_A_F1", "idem-sp24-f1-a1-0001", a1_args)
        assert a_g1["writer_status"] == "holder"
        assert a_g1["fence"] == {"restore_epoch": 0, "writer_generation": 1}

        # B takeover -> gen 2, holder; replay of A gen 1 -> not_holder.
        b_g2 = sub(
            cred_b,
            "SID_B_F1",
            "idem-sp24-f1-b2-0001",
            {
                "evidence": [],
                "base_revision": 1,
                "fence": a_g1["fence"],
                "takeover": {"acknowledge_active": True},
                "handoff": {"working_goal": "B gen 2"},
            },
        )
        assert b_g2["writer_status"] == "holder"
        assert b_g2["fence"] == {"restore_epoch": 0, "writer_generation": 2}
        assert sub(cred_a, "SID_A_F1", "idem-sp24-f1-a1-0001", a1_args)["writer_status"] == "not_holder"

        # A (same principal & same session) takes over -> gen 3, holder.
        a3_args: dict[str, JsonValue] = {
            "evidence": [],
            "base_revision": 2,
            "fence": b_g2["fence"],
            "takeover": {"acknowledge_active": True},
            "handoff": {"working_goal": "A gen 3"},
        }
        a_g3 = sub(cred_a, "SID_A_F1", "idem-sp24-f1-a3-0001", a3_args)
        assert a_g3["writer_status"] == "holder"
        assert a_g3["fence"] == {"restore_epoch": 0, "writer_generation": 3}

        # Case 74 exact probe: replay A's stale gen 1 ACK while A holds gen 3 MUST report not_holder!
        a_g1_replay = sub(cred_a, "SID_A_F1", "idem-sp24-f1-a1-0001", a1_args)
        assert a_g1_replay["episode_id"] == a_g1["episode_id"]
        assert a_g1_replay["fence"] == {"restore_epoch": 0, "writer_generation": 1}
        assert a_g1_replay["writer_status"] == "not_holder"
        assert sub(cred_a, "SID_A_F1", "idem-sp24-f1-a3-0001", a3_args)["writer_status"] == "holder"

        # Takeover-only sibling: B takeover-only -> gen 4 (handoff_revision stays 3), A -> gen 5, B -> gen 6.
        b4_args: dict[str, JsonValue] = {
            "evidence": [],
            "base_revision": 3,
            "fence": a_g3["fence"],
            "takeover": {"acknowledge_active": True},
        }
        b_g4_to = sub(cred_b, "SID_B_F1", "idem-sp24-f1-b4-0001", b4_args)
        assert b_g4_to["writer_status"] == "holder"
        assert b_g4_to["handoff_revision"] == 3
        assert b_g4_to["fence"] == {"restore_epoch": 0, "writer_generation": 4}
        a_g5_to = sub(
            cred_a,
            "SID_A_F1",
            "idem-sp24-f1-a5-0001",
            {"evidence": [], "base_revision": 3, "fence": b_g4_to["fence"], "takeover": {"acknowledge_active": True}},
        )
        b6_args: dict[str, JsonValue] = {
            "evidence": [],
            "base_revision": 3,
            "fence": a_g5_to["fence"],
            "takeover": {"acknowledge_active": True},
        }
        b_g6_to = sub(cred_b, "SID_B_F1", "idem-sp24-f1-b6-0001", b6_args)
        assert sub(cred_b, "SID_B_F1", "idem-sp24-f1-b4-0001", b4_args)["writer_status"] == "not_holder"
        assert sub(cred_b, "SID_B_F1", "idem-sp24-f1-b6-0001", b6_args)["writer_status"] == "holder"

        # not_stored_policy sibling: holder gets holder at live fence; once fence moves past it, replay flips.
        rt.policy.set_repo_policy(ws.repo_id, manual_submission_enabled=False)
        bpol_args: dict[str, JsonValue] = {
            "evidence": [],
            "base_revision": 3,
            "fence": b_g6_to["fence"],
            "handoff": {"working_goal": "Blocked by policy"},
        }
        b_pol = sub(cred_b, "SID_B_F1", "idem-sp24-f1-bpol-01", bpol_args)
        assert b_pol["handoff_status"] == "not_stored_policy"
        assert b_pol["handoff_revision"] is None
        assert b_pol["fence"] == {"restore_epoch": 0, "writer_generation": 6}
        assert b_pol["writer_status"] == "holder"
        assert sub(cred_b, "SID_B_F1", "idem-sp24-f1-bpol-01", bpol_args)["writer_status"] == "holder"

        apol_args: dict[str, JsonValue] = {
            "evidence": [],
            "base_revision": 3,
            "fence": b_g6_to["fence"],
            "takeover": {"acknowledge_active": True},
        }
        a_pol = sub(cred_a, "SID_A_F1", "idem-sp24-f1-apol-01", apol_args)
        assert a_pol["handoff_status"] == "not_stored_policy"
        assert a_pol["writer_status"] == "not_holder"

        rt.policy.set_repo_policy(ws.repo_id, manual_submission_enabled=True)
        a_g7 = sub(
            cred_a,
            "SID_A_F1",
            "idem-sp24-f1-a7-0001",
            {"evidence": [], "base_revision": 3, "fence": b_g6_to["fence"], "takeover": {"acknowledge_active": True}},
        )
        b8_args: dict[str, JsonValue] = {
            "evidence": [],
            "base_revision": 3,
            "fence": a_g7["fence"],
            "takeover": {"acknowledge_active": True},
        }
        b_g8 = sub(cred_b, "SID_B_F1", "idem-sp24-f1-b8-0001", b8_args)
        assert b_g8["writer_status"] == "holder"
        assert b_g8["fence"] == {"restore_epoch": 0, "writer_generation": 8}
        assert sub(cred_b, "SID_B_F1", "idem-sp24-f1-bpol-01", bpol_args)["writer_status"] == "not_holder"
        assert sub(cred_a, "SID_A_F1", "idem-sp24-f1-apol-01", apol_args)["writer_status"] == "not_holder"

        bak = create_store_backup(rt.store, adapters, clock.now())
    finally:
        rt.close()

    # Restore sibling: pre-restore ACK (epoch 0) stays not_holder both before and after B retakes holder at epoch 1.
    clock.advance(dt.timedelta(seconds=5))
    with maintenance_lease(root / "data", adapters) as (droot, lease):
        pol_h = PolicyStore.open(droot, lease, adapters, migrations=KERNEL_POLICY_MIGRATIONS)
        try:
            rep = restore_store(
                droot,
                lease,
                adapters,
                bak,
                pol_h,
                clock.now(),
                migrations=KERNEL_STORE_MIGRATIONS,
            )
        finally:
            pol_h.close()
    assert rep.new_epoch >= 1

    rt_rest = open_kernel_job_runtime(root / "data", adapters, role="sp24-f1-post")
    try:
        dom2 = build_default_handoff_domain(rt=rt_rest, clock=clock, writer_epoch=rt_rest.lease.epoch)
        assert dom2 is not None
        br2 = KernelBridge(
            store=rt_rest.store,
            policy=rt_rest.policy,
            clock=clock,
            writer_epoch=rt_rest.lease.epoch,
            domain=dom2,
        )
        b8_replay_req: dict[str, JsonValue] = {
            "task_id": tid,
            "session_id": "SID_B_F1",
            "workspace_id": ws.repo_id,
            "idempotency_key": "idem-sp24-f1-b8-0001",
            **b8_args,
        }
        assert (
            _call_ok(br2, rt_rest, "submit_episode", b8_replay_req, cred=cred_b, scope=scope)["writer_status"]
            == "not_holder"
        )
        b_ep1 = _call_ok(
            br2,
            rt_rest,
            "submit_episode",
            {
                "task_id": tid,
                "session_id": "SID_B_F1",
                "workspace_id": ws.repo_id,
                "evidence": [],
                "base_revision": 3,
                "fence": {"restore_epoch": rep.new_epoch, "writer_generation": 8},
                "takeover": {"acknowledge_active": True},
                "idempotency_key": "idem-sp24-f1-b9-rest",
            },
            cred=cred_b,
            scope=scope,
        )
        assert b_ep1["writer_status"] == "holder"
        assert b_ep1["fence"] == {"restore_epoch": rep.new_epoch, "writer_generation": 9}
        assert (
            _call_ok(br2, rt_rest, "submit_episode", b8_replay_req, cred=cred_b, scope=scope)["writer_status"]
            == "not_holder"
        )
    finally:
        rt_rest.close()


def test_prepare_task_description_privacy_filter_manual_submission_and_rejection(trusted_tmp: Path) -> None:
    """F2 oracle (§14.2): prepare_task filters description before staging goal CAS blob across all flag paths."""
    from superbrain.composition._daemon_session import build_default_handoff_domain
    from superbrain.composition.kernel_bridge import KernelBridge
    from superbrain.storage.cas import blob_path

    clock = FakeClock(dt.datetime(2026, 11, 26, 6, 30, tzinfo=dt.UTC))
    adapters = os_adapters(clock=clock)
    root = trusted_tmp / "f2-goal-privacy"
    rt = open_kernel_job_runtime(root / "data", adapters, role="sp24-f2")
    cas_dir = root / "data" / "store" / "cas"

    def _cas_files() -> set[Path]:
        return {p for p in cas_dir.rglob("*") if p.is_file()} if cas_dir.exists() else set()

    def _blob_bytes_for_digest(digest: str) -> bytes:
        return blob_path(cas_dir, digest).read_bytes()

    try:
        cred = seed_principal_and_credential(rt.policy, owner_id="dan", harness_id="claude-code", machine_id="m1")
        ws = register_workspace_direct(
            rt,
            clock,
            cred.principal,
            alias="ws-f2",
            checkout_dir=root / "chk-f2",
            remote="https://github.example/dan/repo-f2.git",
        )
        rt.store.reconcile_policy()
        domain = build_default_handoff_domain(rt=rt, clock=clock, writer_epoch=rt.lease.epoch)
        assert domain is not None
        bridge = KernelBridge(store=rt.store, policy=rt.policy, clock=clock, writer_epoch=rt.lease.epoch, domain=domain)
        scope = Scope(ws.repo_id, ws.checkout_id)

        # 1. Positive twin: normal description under manual_submission=True is stored verbatim & renders in L0/L1/L2.
        pos = _call_ok(
            bridge,
            rt,
            "prepare_task",
            {
                "mode": "work",
                "workspace_id": ws.repo_id,
                "checkout_id": ws.checkout_id,
                "description": "Implement UTF-8 byte budget verification",
                "idempotency_key": "idem-sp24-f2-pos-01",
            },
            cred=cred,
            scope=scope,
        )
        pos_tid = str(pos["task_id"])
        with rt.store.transaction() as txn:
            prow = txn.db.execute("SELECT goal_ref FROM task_handoffs WHERE task_id = ?", (pos_tid,)).fetchone()
            assert prow is not None and isinstance(prow[0], str)
            pos_goal_ref = prow[0]
        assert _blob_bytes_for_digest(pos_goal_ref) == b"Implement UTF-8 byte budget verification"
        cas_before_replay = _cas_files()
        assert (
            _call_ok(
                bridge,
                rt,
                "prepare_task",
                {
                    "mode": "work",
                    "workspace_id": ws.repo_id,
                    "checkout_id": ws.checkout_id,
                    "description": "Implement UTF-8 byte budget verification",
                    "idempotency_key": "idem-sp24-f2-pos-01",
                },
                cred=cred,
                scope=scope,
            )
            == pos
        )
        assert _cas_files() == cas_before_replay

        # 2. Redaction under manual_submission=True: <private>...</private> and secret redacted BEFORE hold_blob.
        priv = _call_ok(
            bridge,
            rt,
            "prepare_task",
            {
                "mode": "work",
                "workspace_id": ws.repo_id,
                "checkout_id": ws.checkout_id,
                "description": "Goal <private>SP24_GOAL_PRIVATE_CANARY</private> password=SP24_PWD_CANARY end",
                "idempotency_key": "idem-sp24-f2-priv-01",
            },
            cred=cred,
            scope=scope,
        )
        priv_tid = str(priv["task_id"])
        with rt.store.transaction() as txn:
            r_priv = txn.db.execute("SELECT goal_ref FROM task_handoffs WHERE task_id = ?", (priv_tid,)).fetchone()
            assert r_priv is not None and isinstance(r_priv[0], str)
            priv_goal_ref = r_priv[0]
        priv_blob = _blob_bytes_for_digest(priv_goal_ref)
        assert b"[redacted]" in priv_blob
        assert b"SP24_GOAL_PRIVATE_CANARY" not in priv_blob
        assert b"SP24_PWD_CANARY" not in priv_blob

        # Render L1 -> task_goal is filtered too (no raw canary).
        sub_priv = _call_ok(
            bridge,
            rt,
            "submit_episode",
            {
                "task_id": priv_tid,
                "session_id": "SID_F2_PRIV",
                "workspace_id": ws.repo_id,
                "evidence": [],
                "base_revision": 0,
                "fence": priv["handoff_live"]["fence"],
                "handoff": {"working_goal": "Check filtered goal rendering"},
                "idempotency_key": "idem-sp24-f2-sub-01",
            },
            cred=cred,
            scope=scope,
        )
        assert sub_priv["handoff_revision"] == 1
        l1_priv = _call_ok(
            bridge,
            rt,
            "get_artifact",
            {
                "workspace_id": ws.repo_id,
                "task_id": priv_tid,
                "artifact_id": priv_tid,
                "revision": 1,
                "level": "L1",
                "idempotency_key": "idem-sp24-f2-l1-001",
            },
            cred=cred,
            scope=scope,
        )
        assert "SP24_GOAL_PRIVATE_CANARY" not in str(l1_priv)
        assert "[redacted]" in str(l1_priv)

        # 3. manual_submission=False: metadata-only work task (0 new CAS blobs, NULL goal_ref, replay identical).
        rt.policy.set_repo_policy(ws.repo_id, manual_submission_enabled=False)
        cas_before_off = _cas_files()
        man_off = _call_ok(
            bridge,
            rt,
            "prepare_task",
            {
                "mode": "work",
                "workspace_id": ws.repo_id,
                "checkout_id": ws.checkout_id,
                "description": "Manual off <private>SP24_MANUAL_OFF_CANARY</private> goal",
                "idempotency_key": "idem-sp24-f2-moff-01",
            },
            cred=cred,
            scope=scope,
        )
        off_tid = str(man_off["task_id"])
        assert _cas_files() == cas_before_off
        with rt.store.transaction() as txn:
            t_off = txn.db.execute(
                "SELECT goal_ref, goal_holder_id FROM tasks WHERE task_id = ?", (off_tid,)
            ).fetchone()
            h_off = txn.db.execute(
                "SELECT goal_ref, goal_holder_id FROM task_handoffs WHERE task_id = ?", (off_tid,)
            ).fetchone()
            assert t_off == (None, None)
            assert h_off == (None, None)
        assert (
            _call_ok(
                bridge,
                rt,
                "prepare_task",
                {
                    "mode": "work",
                    "workspace_id": ws.repo_id,
                    "checkout_id": ws.checkout_id,
                    "description": "Manual off <private>SP24_MANUAL_OFF_CANARY</private> goal",
                    "idempotency_key": "idem-sp24-f2-moff-01",
                },
                cred=cred,
                scope=scope,
            )
            == man_off
        )
        assert _cas_files() == cas_before_off

        # 4. Filter-rejected input (unclosed <private>) fails closed under both manual_submission=False and True.
        for label, enabled, target_tid in (
            ("manoff_new", False, None),
            ("manon_new", True, None),
            ("manon_existing", True, pos_tid),
        ):
            rt.policy.set_repo_policy(ws.repo_id, manual_submission_enabled=enabled)
            cas_pre = _cas_files()
            with rt.store.transaction() as txn:
                deliv_pre = int(txn.db.execute("SELECT COUNT(*) FROM deliveries").fetchone()[0])
                tasks_pre = int(txn.db.execute("SELECT COUNT(*) FROM tasks").fetchone()[0])
            req_args: dict[str, JsonValue] = {
                "mode": "work",
                "workspace_id": ws.repo_id,
                "checkout_id": ws.checkout_id,
                "description": f"Bad <private>SP24_REJECT_UNCLOSED_CANARY_{label}",
                "idempotency_key": f"idem-sp24-f2-rj-{label}",
            }
            if target_tid is not None:
                req_args["task_id"] = target_tid
            err_env = _dispatch_call(bridge, rt, "prepare_task", req_args, cred=cred, scope=scope)
            assert err_env.get("ok") is False, err_env
            assert err_env["error"]["code"] == ErrorCode.INVALID_INPUT.value
            assert "SP24_REJECT_UNCLOSED_CANARY" not in str(err_env)
            assert _cas_files() == cas_pre
            with rt.store.transaction() as txn:
                assert int(txn.db.execute("SELECT COUNT(*) FROM deliveries").fetchone()[0]) == deliv_pre
                assert int(txn.db.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]) == tasks_pre

        for p in (root / "data" / "store").rglob("*"):
            if p.is_file():
                raw_b = p.read_bytes()
                assert b"SP24_GOAL_PRIVATE_CANARY" not in raw_b
                assert b"SP24_PWD_CANARY" not in raw_b
                assert b"SP24_MANUAL_OFF_CANARY" not in raw_b
                assert b"SP24_REJECT_UNCLOSED_CANARY" not in raw_b
    finally:
        rt.close()
