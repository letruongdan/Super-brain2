"""SP2-5 live-daemon coexistence tests for capture producers, MCP tools, and operator CLI."""

from __future__ import annotations

import datetime as dt
import json
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

from superbrain.adapters.harness.layer2_probe import (
    AuthorityCommandProbeResult,
    NativeHostReceipt,
    compute_harness_config_digest,
)
from superbrain.adapters.harness_config.bootstrap_templates import (
    AUTHORITY_ASK_COMMANDS,
    plan_claude_bootstrap,
    plan_codex_bootstrap,
)
from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.workspaces import build_registration
from superbrain.cli_api.capture_client import CaptureClient
from superbrain.composition.daemon_entry import DaemonTestHooks
from superbrain.composition.doctor_probes_sp2 import reconcile_harness_layer2_in_policy
from superbrain.core._kernel_approval import Layer2State
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    CAPABILITY_CAPTURE_PRODUCER,
    CAPABILITY_MCP_TOOL,
    CAPABILITY_OPERATOR_CLI,
    AuthSnapshot,
    CaptureBatchCommand,
    CaptureProducerBinding,
    CredentialRecord,
    Scope,
    ToolCommand,
    WorkspaceBinding,
)
from superbrain.core.wire import SCHEMA_VERSION, load_catalog
from superbrain.ports.capture import CaptureEventRecord
from tests.support.inc2_cli import get_shared_t7_transport_template
from tests.support.inc2_transport import TransportHarness, open_test_loopback_transport, read_raw_http_response
from tests.support.kernel_auth import (
    SeededCredential,
    make_bootstrap_auth,
    seed_principal_and_credential,
    seed_repo_grant,
)

_WAIT_S = 20.0
_CLAUDE_VERSION = "2.1.325"
_CODEX_VERSION = "26.1111.2228.0"


def _write_plan(checkout: Path, targets: tuple[Any, ...]) -> None:
    for target in targets:
        dest = checkout / Path(*target.rel_path.split("/"))
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(target.preview_text, encoding="utf-8")


def _build_receipt(*, harness_id: str, host_version: str, config_digest: str) -> NativeHostReceipt:
    probes = tuple(
        AuthorityCommandProbeResult(
            command_pattern=cmd,
            prompted_user=True,
            blocked_without_approval=True,
        )
        for cmd in AUTHORITY_ASK_COMMANDS
    )
    return NativeHostReceipt.build(
        receipt_id=f"rcpt-{harness_id}-{host_version}",
        harness_id=harness_id,
        host_version=host_version,
        config_digest=config_digest,
        probe_mode="approved_sandbox_probe",
        command_probes=probes,
        observed_at="2026-11-26T12:00:00Z",
    )


def _publish_auth_overlay(session: Any, snap: AuthSnapshot, updates: dict[str, CredentialRecord]) -> None:
    current = session.auth_gate.current()
    merged = dict(snap.credentials)
    if current is not None:
        for cid, prev in current.auth.credentials.items():
            if cid in merged:
                merged[cid] = replace(
                    merged[cid],
                    capabilities=prev.capabilities,
                    capture_binding=prev.capture_binding,
                )
    merged.update(updates)
    session.auth_gate.publish(replace(snap, credentials=merged))


def _seed_coexistence_credentials(
    h: TransportHarness,
    ws_a: WorkspaceBinding,
    *,
    include_codex: bool = True,
    verify_layer2_dir: Path | None = None,
) -> dict[str, Any]:
    """Seed MCP, capture-producer, and operator-CLI credentials on ``ws_a`` and verify Layer-2 receipts."""
    out: dict[str, Any] = {}

    def _act() -> None:
        session = cast(Any, h.loop._session)
        assert session is not None
        rt = session._rt
        os_ = rt.os_

        mcp_c = h.cred
        cap_c = seed_principal_and_credential(
            rt.policy, owner_id="dan", harness_id="claude-code", machine_id="m-1"
        )
        seed_repo_grant(rt.policy, principal_id=cap_c.principal.principal_id, repo_id=ws_a.repo_id, owner_id="dan")

        op_cli = seed_principal_and_credential(
            rt.policy, owner_id="dan", harness_id="operator-cli", machine_id="m-1"
        )
        seed_repo_grant(rt.policy, principal_id=op_cli.principal.principal_id, repo_id=ws_a.repo_id, owner_id="dan")

        updates: dict[str, CredentialRecord] = {}
        snap = rt.policy.snapshot()
        updates[cap_c.credential_id] = replace(
            snap.credentials[cap_c.credential_id],
            capabilities=frozenset({CAPABILITY_CAPTURE_PRODUCER}),
            capture_binding=CaptureProducerBinding(
                producer_stream="stream-claude-a",
                repo_id=ws_a.repo_id,
                checkout_id=ws_a.checkout_id,
            ),
        )
        updates[op_cli.credential_id] = replace(
            snap.credentials[op_cli.credential_id],
            capabilities=frozenset({CAPABILITY_OPERATOR_CLI}),
        )

        if include_codex:
            mcp_x = seed_principal_and_credential(
                rt.policy, owner_id="dan", harness_id="codex", machine_id="m-1"
            )
            seed_repo_grant(
                rt.policy, principal_id=mcp_x.principal.principal_id, repo_id=ws_a.repo_id, owner_id="dan"
            )
            cap_x = seed_principal_and_credential(
                rt.policy, owner_id="dan", harness_id="codex", machine_id="m-1"
            )
            seed_repo_grant(
                rt.policy, principal_id=cap_x.principal.principal_id, repo_id=ws_a.repo_id, owner_id="dan"
            )
            snap = rt.policy.snapshot()
            updates[cap_x.credential_id] = replace(
                snap.credentials[cap_x.credential_id],
                capabilities=frozenset({CAPABILITY_CAPTURE_PRODUCER}),
                capture_binding=CaptureProducerBinding(
                    producer_stream="stream-codex-a",
                    repo_id=ws_a.repo_id,
                    checkout_id=ws_a.checkout_id,
                ),
            )
            out["mcp_x"] = mcp_x
            out["cap_x"] = cap_x

        rt.store.reconcile_policy()
        snap = rt.policy.snapshot()
        assert snap.credentials[mcp_c.credential_id].capabilities == frozenset({CAPABILITY_MCP_TOOL})
        if include_codex:
            mcp_x_cred = cast(SeededCredential, out["mcp_x"])
            assert snap.credentials[mcp_x_cred.credential_id].capabilities == frozenset({CAPABILITY_MCP_TOOL})
        _publish_auth_overlay(session, snap, updates)

        if verify_layer2_dir is not None:
            chk_l2 = verify_layer2_dir / "chk-l2"
            cfg_l2 = verify_layer2_dir / "cfg-l2"
            for d in (chk_l2, cfg_l2):
                d.mkdir(parents=True, exist_ok=True)
                os_.permissions.secure_directory(d)
            prof_path = cfg_l2 / "profile.json"
            _write_plan(chk_l2, plan_claude_bootstrap(checkout_root=chk_l2, profile_path=prof_path).targets)
            _write_plan(chk_l2, plan_codex_bootstrap(checkout_root=chk_l2, profile_path=prof_path).targets)

            c_dig = compute_harness_config_digest("claude-code", chk_l2, os_)
            x_dig = compute_harness_config_digest("codex", chk_l2, os_)
            assert c_dig is not None and x_dig is not None
            rcpt_c = _build_receipt(harness_id="claude-code", host_version=_CLAUDE_VERSION, config_digest=c_dig)
            rcpt_x = _build_receipt(harness_id="codex", host_version=_CODEX_VERSION, config_digest=x_dig)
            st_c, _ = reconcile_harness_layer2_in_policy(
                rt.policy,
                harness_id="claude-code",
                checkout_root=chk_l2,
                observed_host_version=_CLAUDE_VERSION,
                os_=os_,
                receipt=rcpt_c,
            )
            st_x, _ = reconcile_harness_layer2_in_policy(
                rt.policy,
                harness_id="codex",
                checkout_root=chk_l2,
                observed_host_version=_CODEX_VERSION,
                os_=os_,
                receipt=rcpt_x,
            )
            assert st_c is Layer2State.VERIFIED
            assert st_x is Layer2State.VERIFIED
            out["c_dig"] = c_dig
            out["x_dig"] = x_dig

        out["mcp_c"] = mcp_c
        out["cap_c"] = cap_c
        out["op_cli"] = op_cli

    h.loop.run_owner_action(_act).result(timeout=_WAIT_S)
    return out


def _call_tool(
    h: TransportHarness,
    *,
    tool: str,
    arguments: dict[str, JsonValue],
    token: str,
    scope: Scope | None,
) -> dict[str, Any]:
    client = h.open_client()
    target = h.make_target()
    res = client.call(
        target,
        ToolCommand(
            tool=tool,
            arguments={"schema_version": SCHEMA_VERSION, **arguments},
            token=token,
            selected_scope=scope,
        ),
    )
    return dict(res)


def _capture_event_row(h: TransportHarness, event_id: str) -> tuple[str, str]:
    def _read() -> tuple[str, str]:
        session = cast(Any, h.loop._session)
        assert session is not None
        row = session._rt.store._db.execute(
            "SELECT source, source_verification FROM capture_events WHERE event_id = ?",
            (event_id,),
        ).fetchone()
        assert row is not None
        return str(row[0]), str(row[1])

    return h.loop.run_owner_action(_read).result(timeout=_WAIT_S)


def test_capture_and_mcp_coexistence_across_claude_and_codex_live_daemon(trusted_tmp: Path) -> None:
    """Capture producers + MCP tools + operator CLI coexist on one live daemon without clearing auth_gate."""
    tpl = get_shared_t7_transport_template()
    ws_a = tpl.ws_a
    assert ws_a is not None
    scope_a = Scope(ws_a.repo_id, ws_a.checkout_id)
    expected_digest = load_catalog().schema_digest

    hooks = DaemonTestHooks(
        host_version_resolver=lambda hid: (
            _CLAUDE_VERSION if hid == "claude-code" else (_CODEX_VERSION if hid == "codex" else None)
        )
    )
    with open_test_loopback_transport(tpl, name="sp25-coexist", domain=None, hooks=hooks) as h:
        seeded = _seed_coexistence_credentials(h, ws_a, include_codex=True, verify_layer2_dir=trusted_tmp)
        mcp_c = cast(SeededCredential, seeded["mcp_c"])
        mcp_x = cast(SeededCredential, seeded["mcp_x"])
        cap_c = cast(SeededCredential, seeded["cap_c"])
        cap_x = cast(SeededCredential, seeded["cap_x"])
        c_dig = str(seeded["c_dig"])
        x_dig = str(seeded["x_dig"])

        # Verify GET /v2/identity advertises the catalog schema_digest.
        ep = h.ready.endpoint
        with h.open_raw_tls_socket() as tls_sock:
            raw_ident = h.send_raw_http(
                tls_sock,
                f"GET /v2/identity HTTP/1.1\r\nHost: {ep.host}:{ep.port}\r\n\r\n".encode("ascii"),
            )
            if not raw_ident:
                raw_ident = read_raw_http_response(tls_sock)
        _, _, ident_body = raw_ident.partition(b"\r\n\r\n")
        ident_json = json.loads(ident_body.decode("utf-8"))
        assert ident_json["schema_digest"] == expected_digest

        cap_client = CaptureClient(h.open_client())
        target = h.make_target()

        # 1. Capture batch for cap_c commits verified_host + tool_observed.
        ev_c = CaptureEventRecord(
            event_id="ev-coexist-claude-1",
            producer_stream="stream-claude-a",
            sequence=1,
            harness_id="claude-code",
            kind="tool_post",
            recorded_at="2026-11-26T12:00:01Z",
            payload={"cmd": "pytest"},
            source_metadata={"host_version": _CLAUDE_VERSION, "config_digest": c_dig},
        ).to_dict()
        ack_c = cap_client.post_batch(
            target,
            CaptureBatchCommand("stream-claude-a", ws_a.repo_id, ws_a.checkout_id, (ev_c,), cap_c.token),
        )
        assert ack_c.accepted_count == 1
        assert _capture_event_row(h, "ev-coexist-claude-1") == ("tool_observed", "verified_host")

        # 2. Immediately call prepare_task(mode="work") with mcp_c; auth_gate MUST stay populated.
        prep_c = _call_tool(
            h,
            tool="prepare_task",
            arguments={
                "mode": "work",
                "workspace_id": ws_a.repo_id,
                "checkout_id": ws_a.checkout_id,
                "description": "Coexistence primary flow",
                "context_budget_tokens": 3000,
                "idempotency_key": f"idem-coex-prep-c-{new_id()}",
            },
            token=mcp_c.token,
            scope=scope_a,
        )
        assert prep_c.get("ok") is True, prep_c
        assert h.loop.auth_gate.current() is not None
        prep_data = cast(dict[str, Any], prep_c["data"])
        task_id = str(prep_data["task_id"])
        assert isinstance(prep_data["handoff_live"], dict)

        # 3. Commit handoff rev 1 using mcp_c.
        sub_c = _call_tool(
            h,
            tool="submit_episode",
            arguments={
                "task_id": task_id,
                "session_id": "sess-claude-coexist-1",
                "workspace_id": ws_a.repo_id,
                "checkout_id": ws_a.checkout_id,
                "evidence": [{"kind": "tool_post", "data": {"step": "claude-init"}}],
                "base_revision": 0,
                "fence": prep_data["handoff_live"]["fence"],
                "handoff": {
                    "working_goal": "Keep capture and MCP coexisting",
                    "next_action": {"summary": "Hand off to codex"},
                    "task_state": "open",
                },
                "idempotency_key": f"idem-coex-sub-c-{new_id()}",
            },
            token=mcp_c.token,
            scope=scope_a,
        )
        assert sub_c.get("ok") is True, sub_c
        sub_c_data = cast(dict[str, Any], sub_c["data"])
        assert sub_c_data["handoff_status"] == "stored"
        assert sub_c_data["handoff_revision"] == 1
        assert sub_c_data["writer_status"] == "holder"

        # 4. Shallow get_health(deep=False) reports ready=True and Store v8 / PolicyStore v5.
        health = _call_tool(
            h,
            tool="get_health",
            arguments={"deep": False},
            token=mcp_c.token,
            scope=None,
        )
        assert health.get("ok") is True, health
        health_data = cast(dict[str, Any], health["data"])
        assert health_data["ready"] is True
        assert health_data["schema_version"] == 8
        assert health_data["policy_schema_version"] == 5

        # 5. Second capture batch for cap_x commits verified_host + tool_observed.
        ev_x = CaptureEventRecord(
            event_id="ev-coexist-codex-1",
            producer_stream="stream-codex-a",
            sequence=1,
            harness_id="codex",
            kind="tool_post",
            recorded_at="2026-11-26T12:00:02Z",
            payload={"cmd": "ruff"},
            source_metadata={"host_version": _CODEX_VERSION, "config_digest": x_dig},
        ).to_dict()
        ack_x = cap_client.post_batch(
            target,
            CaptureBatchCommand("stream-codex-a", ws_a.repo_id, ws_a.checkout_id, (ev_x,), cap_x.token),
        )
        assert ack_x.accepted_count == 1
        assert _capture_event_row(h, "ev-coexist-codex-1") == ("tool_observed", "verified_host")

        # 6. Codex MCP flow: discover -> get_artifact(L1) -> prepare_task(work, task_id) -> takeover submit_episode.
        disc_x = _call_tool(
            h,
            tool="prepare_task",
            arguments={
                "mode": "discover",
                "workspace_id": ws_a.repo_id,
                "checkout_id": ws_a.checkout_id,
                "context_budget_tokens": 3000,
            },
            token=mcp_x.token,
            scope=scope_a,
        )
        assert disc_x.get("ok") is True, disc_x
        continuity = cast(list[dict[str, Any]], disc_x["data"]["continuity"])
        assert len(continuity) == 1
        item = continuity[0]
        assert item["id"] == task_id and item["revision"] == 1

        art_x = _call_tool(
            h,
            tool="get_artifact",
            arguments={
                "workspace_id": ws_a.repo_id,
                "task_id": task_id,
                "artifact_id": task_id,
                "revision_epoch": item["revision_epoch"],
                "revision": 1,
                "level": "L1",
                "idempotency_key": f"idem-coex-art-x-{new_id()}",
            },
            token=mcp_x.token,
            scope=scope_a,
        )
        assert art_x.get("ok") is True, art_x
        assert art_x["data"]["status"] == "ok"
        assert isinstance(art_x["data"]["served_receipt_id"], str)

        work_x = _call_tool(
            h,
            tool="prepare_task",
            arguments={
                "mode": "work",
                "workspace_id": ws_a.repo_id,
                "checkout_id": ws_a.checkout_id,
                "task_id": task_id,
                "description": "Codex resumes task",
                "context_budget_tokens": 3000,
                "idempotency_key": f"idem-coex-work-x-{new_id()}",
            },
            token=mcp_x.token,
            scope=scope_a,
        )
        assert work_x.get("ok") is True, work_x
        assert work_x["data"]["task_id"] == task_id

        take_x = _call_tool(
            h,
            tool="submit_episode",
            arguments={
                "task_id": task_id,
                "session_id": "sess-codex-coexist-1",
                "workspace_id": ws_a.repo_id,
                "checkout_id": ws_a.checkout_id,
                "evidence": [{"kind": "tool_post", "data": {"step": "codex-takeover"}}],
                "base_revision": 1,
                "fence": sub_c_data["fence"],
                "takeover": {"acknowledge_active": True, "reason": "codex takes over"},
                "handoff": {
                    "working_goal": "Codex finishes task",
                    "next_action": {"summary": "Verify"},
                    "task_state": "open",
                },
                "idempotency_key": f"idem-coex-take-x-{new_id()}",
            },
            token=mcp_x.token,
            scope=scope_a,
        )
        assert take_x.get("ok") is True, take_x
        assert take_x["data"]["handoff_status"] == "stored"
        assert take_x["data"]["writer_status"] == "holder"
        assert take_x["data"]["fence"] == {"restore_epoch": 0, "writer_generation": 2}
        assert h.loop.auth_gate.current() is not None


def test_capability_preservation_across_register_workspace(trusted_tmp: Path) -> None:
    """Owner-thread register_workspace preserves capture_producer, operator_cli, and mcp_tool capabilities."""
    tpl = get_shared_t7_transport_template()
    ws_a = tpl.ws_a
    assert ws_a is not None
    scope_a = Scope(ws_a.repo_id, ws_a.checkout_id)

    with open_test_loopback_transport(tpl, name="sp25-regws", domain=None) as h:
        seeded = _seed_coexistence_credentials(h, ws_a, include_codex=False)
        mcp_c = cast(SeededCredential, seeded["mcp_c"])
        cap_c = cast(SeededCredential, seeded["cap_c"])
        op_cli = cast(SeededCredential, seeded["op_cli"])

        chk_b = trusted_tmp / "chk-ws-b-same-repo"
        chk_b.mkdir(parents=True, exist_ok=True)
        os_adapters().permissions.secure_directory(chk_b)

        reg = build_registration(
            owner_id=mcp_c.principal.owner_id,
            principal_id=mcp_c.principal.principal_id,
            machine_id=mcp_c.principal.machine_id,
            alias="ws-b-same-repo",
            raw_path=str(chk_b),
            raw_remote="https://github.example/dan/repo-transport-a.git",
            provider_egress_enabled=False,
        )

        def _trust_gen() -> int:
            session = cast(Any, h.loop._session)
            assert session is not None
            return int(session._rt.policy.trust_generation())

        trust_gen = h.loop.run_owner_action(_trust_gen).result(timeout=_WAIT_S)
        proof = make_bootstrap_auth(
            store_id=h.store_id,
            owner_id=mcp_c.principal.owner_id,
            action="workspace_register",
            subject_id=reg.subject_id,
            trust_generation=trust_gen,
            expires_at=h.clock.now() + dt.timedelta(hours=1),
        )
        ws_b_new = h.loop.register_workspace(reg, proof).result(timeout=_WAIT_S)
        assert ws_b_new.repo_id == ws_a.repo_id
        assert ws_b_new.checkout_id != ws_a.checkout_id

        cap_client = CaptureClient(h.open_client())
        target = h.make_target()
        ev = CaptureEventRecord(
            event_id="ev-after-reg-1",
            producer_stream="stream-claude-a",
            sequence=1,
            harness_id="claude-code",
            kind="tool_post",
            recorded_at="2026-11-26T12:05:00Z",
            payload={"after": "register_workspace"},
        ).to_dict()
        ack = cap_client.post_batch(
            target,
            CaptureBatchCommand("stream-claude-a", ws_a.repo_id, ws_a.checkout_id, (ev,), cap_c.token),
        )
        assert ack.accepted_count == 1

        # cap_c must STILL be rejected on POST /v2/tools/call.
        cap_as_mcp = _call_tool(
            h,
            tool="prepare_task",
            arguments={
                "mode": "work",
                "workspace_id": ws_a.repo_id,
                "checkout_id": ws_a.checkout_id,
                "description": "Forbidden for capture cred",
                "idempotency_key": f"idem-cap-forbid-{new_id()}",
            },
            token=cap_c.token,
            scope=scope_a,
        )
        assert cap_as_mcp["ok"] is False
        assert cap_as_mcp["error"]["code"] == ErrorCode.IDENTITY_MISMATCH.value

        # op_cli must STILL be rejected on POST /v2/tools/call.
        cli_as_mcp = _call_tool(
            h,
            tool="get_health",
            arguments={"deep": False},
            token=op_cli.token,
            scope=None,
        )
        assert cli_as_mcp["ok"] is False
        assert cli_as_mcp["error"]["code"] == ErrorCode.IDENTITY_MISMATCH.value

        # mcp_c must STILL succeed on POST /v2/tools/call.
        mcp_health = _call_tool(h, tool="get_health", arguments={"deep": False}, token=mcp_c.token, scope=None)
        assert mcp_health["ok"] is True and mcp_health["data"]["ready"] is True
        mcp_prep = _call_tool(
            h,
            tool="prepare_task",
            arguments={
                "mode": "work",
                "workspace_id": ws_a.repo_id,
                "checkout_id": ws_a.checkout_id,
                "description": "MCP works after register_workspace",
                "idempotency_key": f"idem-mcp-after-reg-{new_id()}",
            },
            token=mcp_c.token,
            scope=scope_a,
        )
        assert mcp_prep["ok"] is True, mcp_prep


def test_strict_capability_separation_on_live_loopback() -> None:
    """Capture credentials cannot call MCP tools and MCP credentials cannot post capture batches."""
    tpl = get_shared_t7_transport_template()
    ws_a = tpl.ws_a
    assert ws_a is not None
    scope_a = Scope(ws_a.repo_id, ws_a.checkout_id)

    with open_test_loopback_transport(tpl, name="sp25-capsep", domain=None) as h:
        seeded = _seed_coexistence_credentials(h, ws_a, include_codex=False)
        mcp_c = cast(SeededCredential, seeded["mcp_c"])
        cap_c = cast(SeededCredential, seeded["cap_c"])
        op_cli = cast(SeededCredential, seeded["op_cli"])

        # cap_c presented to POST /v2/tools/call (get_health & prepare_task) -> IDENTITY_MISMATCH.
        cap_health = _call_tool(h, tool="get_health", arguments={"deep": False}, token=cap_c.token, scope=None)
        assert cap_health["ok"] is False
        assert cap_health["error"]["code"] == ErrorCode.IDENTITY_MISMATCH.value

        cap_prep = _call_tool(
            h,
            tool="prepare_task",
            arguments={
                "mode": "work",
                "workspace_id": ws_a.repo_id,
                "checkout_id": ws_a.checkout_id,
                "description": "Must fail capability separation",
                "idempotency_key": f"idem-capsep-prep-{new_id()}",
            },
            token=cap_c.token,
            scope=scope_a,
        )
        assert cap_prep["ok"] is False
        assert cap_prep["error"]["code"] == ErrorCode.IDENTITY_MISMATCH.value

        # mcp_c and op_cli presented to POST /v2/capture/events -> IDENTITY_MISMATCH.
        cap_client = CaptureClient(h.open_client())
        target = h.make_target()
        ev = CaptureEventRecord(
            event_id="ev-sep-forbid-1",
            producer_stream="stream-claude-a",
            sequence=1,
            harness_id="claude-code",
            kind="tool_post",
            recorded_at="2026-11-26T12:10:00Z",
            payload={"note": "must reject"},
        ).to_dict()
        for bad_tok in (mcp_c.token, op_cli.token):
            with pytest.raises(BrainError) as exc_cap:
                cap_client.post_batch(
                    target,
                    CaptureBatchCommand("stream-claude-a", ws_a.repo_id, ws_a.checkout_id, (ev,), bad_tok),
                )
            assert exc_cap.value.code is ErrorCode.IDENTITY_MISMATCH


def test_real_policy_divergence_fails_closed_and_clears_auth_gate() -> None:
    """Direct SQLite credential revocation without auth_gate publish clears auth_gate and fails POLICY_UNAVAILABLE."""
    tpl = get_shared_t7_transport_template()
    ws_a = tpl.ws_a
    assert ws_a is not None
    scope_a = Scope(ws_a.repo_id, ws_a.checkout_id)

    with open_test_loopback_transport(tpl, name="sp25-diverge", domain=None) as h:
        seeded = _seed_coexistence_credentials(h, ws_a, include_codex=True)
        mcp_c = cast(SeededCredential, seeded["mcp_c"])
        mcp_x = cast(SeededCredential, seeded["mcp_x"])

        def _revoke_mcp_x_directly_in_sqlite() -> None:
            session = cast(Any, h.loop._session)
            assert session is not None
            rt = session._rt
            proof = make_bootstrap_auth(
                store_id=rt.policy.store_id,
                owner_id="dan",
                action="credential_revoke",
                subject_id=mcp_x.credential_id,
                trust_generation=rt.policy.trust_generation(),
                expires_at=h.clock.now() + dt.timedelta(hours=1),
            )
            rt.policy.record_authorized_revocation(mcp_x.credential_id, proof)

        h.loop.run_owner_action(_revoke_mcp_x_directly_in_sqlite).result(timeout=_WAIT_S)
        assert h.loop.auth_gate.current() is not None

        res = _call_tool(
            h,
            tool="prepare_task",
            arguments={
                "mode": "work",
                "workspace_id": ws_a.repo_id,
                "checkout_id": ws_a.checkout_id,
                "description": "Must fail closed on real policy divergence",
                "idempotency_key": f"idem-diverge-mcp-{new_id()}",
            },
            token=mcp_c.token,
            scope=scope_a,
        )
        assert res["ok"] is False
        assert res["error"]["code"] == ErrorCode.POLICY_UNAVAILABLE.value
        assert h.loop.auth_gate.current() is None
