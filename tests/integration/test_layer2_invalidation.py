"""SP2-5 Step 1 oracle: NativeHostReceipt verification, automatic invalidation, read-only doctor & M1 fixture.

Requirement sources:
- docs/superpowers/specs/2026-10-30-super-brain2-system-design.md (§8.2, §11.3, §13, §14.2, §19, §20 cases 11, 20, 42)
- docs/design/sp2-host-capture-matrix.md (§1.2, §3.1, §3.2)
- docs/superpowers/plans/2026-11-18-sp2-capture-continuity.md (SP2-5 Step 1 & Step 2)
"""

from __future__ import annotations

import base64
import datetime as dt
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from superbrain.adapters.harness.layer2_probe import (
    AuthorityCommandProbeResult,
    NativeHostReceipt,
    compute_harness_config_digest,
    verify_native_host_receipt,
)
from superbrain.adapters.harness_config.bootstrap_templates import (
    AUTHORITY_ASK_COMMANDS,
    plan_claude_bootstrap,
    plan_codex_bootstrap,
)
from superbrain.adapters.os import os_adapters
from superbrain.composition._daemon_session import build_default_handoff_domain
from superbrain.composition.doctor_probes_sp2 import (
    reconcile_harness_layer2_in_policy,
    run_sp2_doctor_probes,
)
from superbrain.composition.kernel_bridge import KernelBridge
from superbrain.core._kernel_approval import (
    RISK_POLICY_VERSION,
    ApprovalAction,
    ApprovalChannel,
    ApprovalMessage,
    Layer2State,
    RecoveryScope,
    RiskLevel,
    SignerEnrollment,
)
from superbrain.core.canonical import canonical_json
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import (
    CAPABILITY_CAPTURE_PRODUCER,
    CaptureBatchCommand,
    CaptureProducerBinding,
    RequestAuthView,
    ResourceDigest,
)
from superbrain.ports.capture import CaptureEventRecord, ProducerCaptureGap
from superbrain.ports.clock import Clock
from superbrain.storage.backup import create_policy_backup
from superbrain.storage.kernel_schema import KERNEL_POLICY_MIGRATIONS
from superbrain.storage.outbox import OutboxSpool
from superbrain.storage.restore import restore_policy
from superbrain.storage.sessions import SessionStore
from tests.storage.conftest import maintenance_lease
from tests.support.clock import FakeClock
from tests.support.fs import digest_data_root, digest_tree
from tests.support.inc2_fixture import open_kernel_job_runtime, reopen_kernel_job_runtime
from tests.support.inc2_transport import register_workspace_direct
from tests.support.kernel_auth import seed_principal_and_credential, seed_repo_grant


def _write_plan(checkout: Path, targets: tuple[Any, ...]) -> None:
    for t in targets:
        dest = checkout / Path(*t.rel_path.split("/"))
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(t.preview_text, encoding="utf-8")


def _build_receipt(
    *,
    harness_id: str,
    host_version: str,
    config_digest: str,
    commands: tuple[str, ...] = AUTHORITY_ASK_COMMANDS,
    blocked_without_approval: bool = True,
    prompted_user: bool = True,
) -> NativeHostReceipt:
    probes = tuple(
        AuthorityCommandProbeResult(
            command_pattern=cmd,
            prompted_user=prompted_user,
            blocked_without_approval=blocked_without_approval,
        )
        for cmd in commands
    )
    return NativeHostReceipt.build(
        receipt_id=f"rcpt-{harness_id}-{host_version}",
        harness_id=harness_id,
        host_version=host_version,
        config_digest=config_digest,
        probe_mode="approved_sandbox_probe",
        command_probes=probes,
        observed_at="2026-11-26T17:00:00Z",
    )


def _grant_capture_producer(bridge: KernelBridge, rt: Any, cred: Any, *, stream: str, ws: Any) -> None:
    seed_repo_grant(rt.policy, principal_id=cred.principal.principal_id, repo_id=ws.repo_id, owner_id="dan")
    snap = rt.policy.snapshot()
    cur_view = bridge._auth_state.current()
    merged = dict(snap.credentials)
    if cur_view is not None:
        for cid, prev in cur_view.auth.credentials.items():
            if cid in merged:
                merged[cid] = replace(
                    merged[cid],
                    capabilities=prev.capabilities,
                    capture_binding=prev.capture_binding,
                )
    merged[cred.credential_id] = replace(
        merged[cred.credential_id],
        capabilities=frozenset({CAPABILITY_CAPTURE_PRODUCER}),
        capture_binding=CaptureProducerBinding(
            producer_stream=stream, repo_id=ws.repo_id, checkout_id=ws.checkout_id
        ),
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


def _low_risk_terminal_approval(rt: Any, store_id: str, clock: Clock, subj: str) -> None:
    issued = rt.policy.issue_nonce(action=ApprovalAction.LESSON_CONFIRM, subject_id=subj, risk_level=RiskLevel.LOW)
    msg = ApprovalMessage(
        store_id=store_id,
        owner_id="dan",
        trust_generation=issued.trust_generation,
        action=ApprovalAction.LESSON_CONFIRM,
        subject_id=subj,
        subject_revision=1,
        resource_digests=(ResourceDigest("lesson.json", "sha256:" + "a" * 64),),
        target_files=(),
        risk_level=RiskLevel.LOW,
        risk_policy_version=RISK_POLICY_VERSION,
        recovery_scope=RecoveryScope.NONE,
        nonce=issued.nonce,
        expires_at=issued.expires_at,
    )
    rt.policy.consume_approval(msg, signer_id=None, channel=ApprovalChannel.TERMINAL)


def test_native_host_receipt_verification_and_invalidation_on_host_version_and_config_digest_change(
    trusted_tmp: Path,
) -> None:
    clock = FakeClock(dt.datetime(2026, 11, 26, 17, 0, tzinfo=dt.UTC))
    os_ = os_adapters(clock=clock)
    base = trusted_tmp / "l2-inv"
    data_root = base / "data"
    chk = base / "checkout-a"
    cfg_dir = base / "cfg"
    outbox_dir = base / "outbox"
    for d in (chk, cfg_dir):
        d.mkdir(parents=True, exist_ok=True)
        os_.permissions.secure_directory(d)

    prof_path = cfg_dir / "profile.json"
    _write_plan(chk, plan_claude_bootstrap(checkout_root=chk, profile_path=prof_path).targets)
    _write_plan(chk, plan_codex_bootstrap(checkout_root=chk, profile_path=prof_path).targets)

    c_dig1 = compute_harness_config_digest("claude-code", chk, os_)
    x_dig1 = compute_harness_config_digest("codex", chk, os_)
    assert c_dig1 is not None and x_dig1 is not None

    # 1. Receipt validation: tampered digest -> UNKNOWN; missing command -> UNKNOWN; non-blocking ask -> UNSUPPORTED.
    rcpt_c1 = _build_receipt(harness_id="claude-code", host_version="2.1.325", config_digest=c_dig1)
    assert NativeHostReceipt.from_dict(rcpt_c1.to_dict()) == rcpt_c1
    assert verify_native_host_receipt(
        rcpt_c1, current_host_version="2.1.325", current_config_digest=c_dig1, expected_harness_id="claude-code"
    ).state is Layer2State.VERIFIED
    ver_drift = verify_native_host_receipt(rcpt_c1, current_host_version="2.1.326", current_config_digest=c_dig1)
    assert ver_drift.state is Layer2State.UNKNOWN and ver_drift.reason == "host_version_changed"
    cfg_drift = verify_native_host_receipt(
        rcpt_c1, current_host_version="2.1.325", current_config_digest="sha256:" + "f" * 64
    )
    assert cfg_drift.state is Layer2State.UNKNOWN and cfg_drift.reason == "config_digest_changed"

    tampered = replace(rcpt_c1, receipt_digest="sha256:" + "0" * 64)
    assert verify_native_host_receipt(
        tampered, current_host_version="2.1.325", current_config_digest=c_dig1
    ).state is Layer2State.UNKNOWN

    missing_one = _build_receipt(
        harness_id="claude-code",
        host_version="2.1.325",
        config_digest=c_dig1,
        commands=AUTHORITY_ASK_COMMANDS[:-1],
    )
    assert verify_native_host_receipt(
        missing_one, current_host_version="2.1.325", current_config_digest=c_dig1
    ).state is Layer2State.UNKNOWN

    unblocked = _build_receipt(
        harness_id="claude-code",
        host_version="2.1.325",
        config_digest=c_dig1,
        blocked_without_approval=False,
    )
    assert verify_native_host_receipt(
        unblocked, current_host_version="2.1.325", current_config_digest=c_dig1
    ).state is Layer2State.UNSUPPORTED

    rcpt_x1 = _build_receipt(harness_id="codex", host_version="26.1111.2228.0", config_digest=x_dig1)

    rt = open_kernel_job_runtime(data_root, os_, role="sp25-l2")
    closed = False
    try:
        raw_pub = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ssh_blob = len(b"ssh-ed25519").to_bytes(4, "big") + b"ssh-ed25519" + len(raw_pub).to_bytes(4, "big") + raw_pub
        rt.policy.enroll_first_signer(
            SignerEnrollment(
                owner_id="dan",
                channel=ApprovalChannel.SSH_KEY,
                public_key="ssh-ed25519 " + base64.b64encode(ssh_blob).decode("ascii"),
            )
        )
        c_cred = seed_principal_and_credential(rt.policy, owner_id="dan", harness_id="claude-code", machine_id="m-sp25")
        x_cred = seed_principal_and_credential(rt.policy, owner_id="dan", harness_id="codex", machine_id="m-sp25")
        ws = register_workspace_direct(rt, clock, c_cred.principal, alias="ws-sp25", checkout_dir=chk)
        rt.store.reconcile_policy()
        domain = build_default_handoff_domain(rt=rt, clock=clock, writer_epoch=rt.lease.epoch)
        bridge = KernelBridge(
            store=rt.store, policy=rt.policy, clock=clock, writer_epoch=rt.lease.epoch, domain=domain
        )
        _grant_capture_producer(bridge, rt, c_cred, stream="stream-claude-1", ws=ws)
        _grant_capture_producer(bridge, rt, x_cred, stream="stream-codex-1", ws=ws)

        # Record valid Layer-2 receipts for BOTH active harnesses -> terminal eligible + verified_host capture!
        assert reconcile_harness_layer2_in_policy(
            rt.policy,
            harness_id="claude-code",
            checkout_root=chk,
            observed_host_version="2.1.325",
            os_=os_,
            receipt=rcpt_c1,
        )[0] is Layer2State.VERIFIED
        assert reconcile_harness_layer2_in_policy(
            rt.policy,
            harness_id="codex",
            checkout_root=chk,
            observed_host_version="26.1111.2228.0",
            os_=os_,
            receipt=rcpt_x1,
        )[0] is Layer2State.VERIFIED
        assert rt.policy.terminal_channel_eligible(machine_id="m-sp25") is True
        _low_risk_terminal_approval(rt, rt.store.store_id, clock, "lesson-ok-1")

        # Verified capture batch commits tool_observed + verified_host.
        cmd_ok = CaptureBatchCommand(
            token=c_cred.token,
            producer_stream="stream-claude-1",
            repo_id=ws.repo_id,
            checkout_id=ws.checkout_id,
            events=(
                CaptureEventRecord(
                    event_id="ev-l2-1",
                    producer_stream="stream-claude-1",
                    sequence=1,
                    harness_id="claude-code",
                    kind="command_result",
                    recorded_at="2026-11-26T17:00:05Z",
                    payload={"command": "pytest", "exit_code": 0},
                    source_metadata={"host_version": "2.1.325", "config_digest": c_dig1},
                ).to_dict(),
            ),
        )
        ack1 = bridge.ingest_capture_batch(cmd_ok)
        assert ack1.accepted_count == 1
        row1 = rt.store._db.execute(
            "SELECT source, source_verification FROM capture_events WHERE event_id = 'ev-l2-1'"
        ).fetchone()
        assert row1 == ("tool_observed", "verified_host")

        bak_verified = create_policy_backup(rt.policy, os_, clock.now())

        # 2. Mutate Claude permissions config on disk -> config_digest changes!
        settings_path = chk / ".claude" / "settings.local.json"
        settings_json = json.loads(settings_path.read_text(encoding="utf-8"))
        settings_json["permissions"]["allow"] = ["Bash(pytest *)"]
        settings_path.write_text(canonical_json(settings_json).decode("utf-8"), encoding="utf-8")

        # Read-only doctor probe detects invalidation with 0 bytes mutated!
        before_data = digest_data_root(data_root)
        before_chk = digest_tree(chk)
        doc = run_sp2_doctor_probes(
            data_root,
            outbox_dir=outbox_dir,
            checkout_root=chk,
            observed_host_versions={"claude-code": "2.1.325", "codex": "26.1111.2228.0"},
            os_=os_,
            now=clock.now(),
        )
        assert digest_data_root(data_root) == before_data
        assert digest_tree(chk) == before_chk
        by_h = {h.harness_id: h for h in doc.layer2_harnesses}
        assert by_h["claude-code"].effective_state is Layer2State.UNKNOWN
        assert by_h["claude-code"].invalidated_reason == "config_digest_changed"
        assert doc.terminal_channel_eligible_effective is False

        # Reconcile downgrades policy.db -> terminal channel refused & capture stops tool_observed!
        st_down, reason_down = reconcile_harness_layer2_in_policy(
            rt.policy,
            harness_id="claude-code",
            checkout_root=chk,
            observed_host_version="2.1.325",
            os_=os_,
        )
        assert st_down is Layer2State.UNKNOWN and reason_down == "config_digest_changed"
        assert rt.policy.terminal_channel_eligible(machine_id="m-sp25") is False
        with pytest.raises(BrainError) as exc_term:
            _low_risk_terminal_approval(rt, rt.store.store_id, clock, "lesson-blocked-cfg")
        assert exc_term.value.code is ErrorCode.CAPABILITY_UNAVAILABLE

        # Even if client sends stale old c_dig1 in source_metadata, capture downgrades to unverified/unknown!
        cmd_stale = CaptureBatchCommand(
            token=c_cred.token,
            producer_stream="stream-claude-1",
            repo_id=ws.repo_id,
            checkout_id=ws.checkout_id,
            events=(
                CaptureEventRecord(
                    event_id="ev-l2-2",
                    producer_stream="stream-claude-1",
                    sequence=2,
                    harness_id="claude-code",
                    kind="command_result",
                    recorded_at="2026-11-26T17:00:10Z",
                    payload={"command": "pytest", "exit_code": 0},
                    source_metadata={"host_version": "2.1.325", "config_digest": c_dig1},
                ).to_dict(),
            ),
        )
        assert bridge.ingest_capture_batch(cmd_stale).accepted_count == 1
        row2 = rt.store._db.execute(
            "SELECT source, source_verification FROM capture_events WHERE event_id = 'ev-l2-2'"
        ).fetchone()
        assert row2 == ("unknown", "unverified")

        # 3. Re-verify Claude with c_dig2, then change observed Codex host_version -> also invalidates!
        c_dig2 = compute_harness_config_digest("claude-code", chk, os_)
        assert c_dig2 is not None and c_dig2 != c_dig1
        rcpt_c2 = _build_receipt(harness_id="claude-code", host_version="2.1.325", config_digest=c_dig2)
        assert reconcile_harness_layer2_in_policy(
            rt.policy,
            harness_id="claude-code",
            checkout_root=chk,
            observed_host_version="2.1.325",
            os_=os_,
            receipt=rcpt_c2,
        )[0] is Layer2State.VERIFIED
        assert rt.policy.terminal_channel_eligible(machine_id="m-sp25") is True

        st_ver_down, reason_ver = reconcile_harness_layer2_in_policy(
            rt.policy,
            harness_id="codex",
            checkout_root=chk,
            observed_host_version="26.1112.9999.0",
            os_=os_,
        )
        assert st_ver_down is Layer2State.UNKNOWN and reason_ver == "host_version_changed"
        assert rt.policy.terminal_channel_eligible(machine_id="m-sp25") is False
        with pytest.raises(BrainError) as exc_ver:
            _low_risk_terminal_approval(rt, rt.store.store_id, clock, "lesson-blocked-ver")
        assert exc_ver.value.code is ErrorCode.CAPABILITY_UNAVAILABLE

        cmd_x_stale = CaptureBatchCommand(
            token=x_cred.token,
            producer_stream="stream-codex-1",
            repo_id=ws.repo_id,
            checkout_id=ws.checkout_id,
            events=(
                CaptureEventRecord(
                    event_id="ev-l2-3",
                    producer_stream="stream-codex-1",
                    sequence=1,
                    harness_id="codex",
                    kind="command_result",
                    recorded_at="2026-11-26T17:00:15Z",
                    payload={"command": "pytest", "exit_code": 0},
                    source_metadata={"host_version": "26.1111.2228.0", "config_digest": x_dig1},
                ).to_dict(),
            ),
        )
        assert bridge.ingest_capture_batch(cmd_x_stale).accepted_count == 1
        row3 = rt.store._db.execute(
            "SELECT source, source_verification FROM capture_events WHERE event_id = 'ev-l2-3'"
        ).fetchone()
        assert row3 == ("unknown", "unverified")

        # 4. Restoring old policy backup that recorded VERIFIED at c_dig1 invalidates against current chk (c_dig2).
        sid = rt.store.store_id
        rt.close()
        closed = True
        with maintenance_lease(data_root, os_) as (root_obj, lease):
            restore_policy(
                root_obj,
                lease,
                os_,
                bak_verified,
                store_id=sid,
                now=clock.now(),
                migrations=KERNEL_POLICY_MIGRATIONS,
            )
        rt2 = reopen_kernel_job_runtime(data_root, sid, os_)
        try:
            doc_post = run_sp2_doctor_probes(
                data_root,
                outbox_dir=outbox_dir,
                checkout_root=chk,
                observed_host_versions={"claude-code": "2.1.325", "codex": "26.1111.2228.0"},
                os_=os_,
                now=clock.now(),
            )
            post_h = {h.harness_id: h for h in doc_post.layer2_harnesses}
            assert post_h["claude-code"].effective_state is Layer2State.UNKNOWN
            assert post_h["claude-code"].invalidated_reason == "config_digest_changed"
            st_post, _ = reconcile_harness_layer2_in_policy(
                rt2.policy,
                harness_id="claude-code",
                checkout_root=chk,
                observed_host_version="2.1.325",
                os_=os_,
            )
            assert st_post is Layer2State.UNKNOWN
            assert rt2.policy.terminal_channel_eligible(machine_id="m-sp25") is False
        finally:
            rt2.close()
    finally:
        if not closed and not rt.store.closed:
            rt.close()


def test_sp2_doctor_probes_report_outbox_gaps_sessions_and_layer2_strictly_readonly(trusted_tmp: Path) -> None:
    clock = FakeClock(dt.datetime(2026, 11, 26, 17, 30, tzinfo=dt.UTC))
    os_ = os_adapters(clock=clock)
    base = trusted_tmp / "doc-ro"
    data_root = base / "data"
    outbox_dir = base / "outbox"
    chk = base / "chk"
    cfg_dir = base / "cfg"
    for d in (chk, cfg_dir):
        d.mkdir(parents=True, exist_ok=True)
        os_.permissions.secure_directory(d)
    _write_plan(chk, plan_claude_bootstrap(checkout_root=chk, profile_path=cfg_dir / "p.json").targets)
    c_dig = compute_harness_config_digest("claude-code", chk, os_)
    assert c_dig is not None

    rt = open_kernel_job_runtime(data_root, os_, role="sp25-doc")
    try:
        cred = seed_principal_and_credential(rt.policy, owner_id="dan", harness_id="claude-code", machine_id="m-doc")
        ws = register_workspace_direct(rt, clock, cred.principal, alias="ws-doc", checkout_dir=chk)
        rt.store.reconcile_policy()
        rt.policy.set_layer2_state(
            harness_id="claude-code", host_version="2.1.325", config_digest=c_dig, state=Layer2State.VERIFIED
        )

        # Populate outbox (1 event + 1 producer gap + 1 incomplete .part file)
        spool = OutboxSpool(outbox_dir, permissions=os_.permissions)
        ev1 = CaptureEventRecord(
            event_id="ev-doc-1",
            producer_stream="stream-doc-1",
            sequence=1,
            harness_id="claude-code",
            kind="user_message",
            recorded_at="2026-11-26T17:29:00Z",
            payload={"role": "user", "text": "Outbox item"},
        )
        spool.enqueue_event(ev1)
        spool.enqueue_gap(
            ProducerCaptureGap(
                gap_id="gap-doc-1",
                producer_stream="stream-doc-1",
                sequence=2,
                reason="hook_timeout",
                recorded_at="2026-11-26T17:29:05Z",
                estimated_count=1,
                duration_ms=2001,
            )
        )
        part_file = outbox_dir / "dangling.part"
        part_file.write_bytes(b"partial-unflushed")

        # Populate capture gaps and sessions in brain.db
        ss = SessionStore(rt.store, rt.policy)
        s_active = ss.bind_session(
            principal_id=cred.principal.principal_id,
            repo_id=ws.repo_id,
            checkout_id=ws.checkout_id,
            harness_id="claude-code",
            raw_session_id="RAW_DOC_ACTIVE",
            now=clock.now(),
        )
        s_idle = ss.bind_session(
            principal_id=cred.principal.principal_id,
            repo_id=ws.repo_id,
            checkout_id=ws.checkout_id,
            harness_id="claude-code",
            raw_session_id="RAW_DOC_IDLE",
            now=clock.now() - dt.timedelta(seconds=400),
        )
        with rt.store.transaction() as txn:
            txn.db.execute(
                "INSERT INTO capture_gaps "
                "(gap_id, producer_stream, sequence, gap_origin, status, reason, recorded_at) "
                "VALUES ('g-open-1', 'stream-doc-1', 5, 'daemon', 'open', 'out_of_order', '2026-11-26T17:29:10Z')"
            )
        _ = (s_active, s_idle)
    finally:
        rt.close()

    snap_data = digest_tree(data_root)
    snap_outbox = digest_tree(outbox_dir)
    snap_chk = digest_tree(chk)

    report = run_sp2_doctor_probes(
        data_root,
        outbox_dir=outbox_dir,
        checkout_root=chk,
        observed_host_versions={"claude-code": "2.1.325"},
        os_=os_,
        now=clock.now(),
    )
    # Strict read-only invariant: zero bytes created, modified, or deleted anywhere (including .part!).
    assert digest_tree(data_root) == snap_data
    assert digest_tree(outbox_dir) == snap_outbox
    assert digest_tree(chk) == snap_chk
    assert part_file.exists()

    assert report.outbox.present is True
    assert report.outbox.pending_event_count == 1
    assert report.outbox.pending_gap_count == 1
    assert report.outbox.incomplete_part_count == 1
    assert report.outbox.total_bytes > 0
    assert report.gaps.open_daemon_gaps == 1
    assert report.sessions.total_sessions == 2
    assert report.sessions.active_sessions == 1
    assert report.sessions.in_progress_unknown_sessions == 1
    assert report.terminal_channel_eligible_effective is True
    payload = report.to_dict()
    assert isinstance(payload["outbox"], dict)
    assert payload["outbox"]["pending_event_count"] == 1
    assert isinstance(payload["sessions"], dict)
    assert payload["sessions"]["in_progress_unknown_sessions"] == 1
    assert "RAW_DOC_ACTIVE" not in json.dumps(payload)


def test_m1_rehearsal_driver_fixture_mode_verifies_handoff_isolation_and_gates_native_mode(
    trusted_tmp: Path,
) -> None:
    import scripts.rehearse_m1 as rehearse_m1

    out_json = trusted_tmp / "m1-report" / "fixture-m1.json"
    report = rehearse_m1.run_fixture_rehearsal(trusted_tmp / "m1-work", output_path=out_json)
    assert out_json.exists()
    assert report["mode"] == "fixture"
    assert report["passed"] is True
    assert report["claude_abrupt_kill_session_state"] != "ended"
    assert report["codex_takeover_ack"] == {"handoff_status": "stored", "writer_status": "holder"}
    assert report["checkout_b_all_paths_rejected"] is True
    assert report["layer2_invalidation_verified"] is True

    # Native mode without --owner-approved must fail closed immediately with exit code 2.
    rc = rehearse_m1.main(["--mode", "native", "--work-dir", str(trusted_tmp / "m1-native")])
    assert rc == 2
