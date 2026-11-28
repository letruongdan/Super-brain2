"""SP2-5 Step 1 oracle: Claude Code & Codex capture adapters, workspace isolation & fail-closed rules.

Requirement sources:
- docs/superpowers/specs/2026-10-30-super-brain2-system-design.md (§5.2, §7.1, §7.2, §8.2, §8.10, §11.3, §20)
- docs/design/sp2-host-capture-matrix.md (§1, §2, §3)
- docs/superpowers/plans/2026-11-18-sp2-capture-continuity.md (SP2-5 Step 1)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

from superbrain.adapters.harness import (
    AdapterCaptureStatus,
    ClaudeCodeCaptureAdapter,
    CodexCaptureAdapter,
    HarnessCaptureContext,
)
from superbrain.adapters.harness_config.bootstrap_templates import (
    build_capture_hook_command,
    plan_claude_bootstrap,
    plan_codex_bootstrap,
)
from superbrain.adapters.os import os_adapters
from superbrain.core.canonical import digest_bytes
from superbrain.domain.capture.exposure import classify_exposure_evidence, should_open_new_segment
from superbrain.ports.capture import CaptureEventRecord, ProducerCaptureGap
from superbrain.ports.continuity import ExposureEvidence, RecipientProfile, SessionSegmentRecord
from tests.support.fs import fake_link


def _apply_plan_targets(checkout: Path, targets: tuple[Any, ...]) -> None:
    for tgt in targets:
        dest = checkout / Path(*tgt.rel_path.split("/"))
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(tgt.preview_text, encoding="utf-8")


def _make_checkouts(trusted_tmp: Path) -> tuple[Path, Path, Path]:
    os_ = os_adapters()
    root = trusted_tmp / "sp25-adapters"
    chk_a = root / "checkout-a"
    chk_b = root / "checkout-b"
    cfg_dir = root / "cfg"
    for d in (chk_a, chk_b, cfg_dir):
        d.mkdir(parents=True, exist_ok=True)
        os_.permissions.secure_directory(d)
    prof_a = cfg_dir / "profile-a.json"
    _apply_plan_targets(chk_a, plan_claude_bootstrap(checkout_root=chk_a, profile_path=prof_a).targets)
    _apply_plan_targets(chk_a, plan_codex_bootstrap(checkout_root=chk_a, profile_path=prof_a).targets)
    prof_b = cfg_dir / "profile-b.json"
    _apply_plan_targets(chk_b, plan_claude_bootstrap(checkout_root=chk_b, profile_path=prof_b).targets)
    _apply_plan_targets(chk_b, plan_codex_bootstrap(checkout_root=chk_b, profile_path=prof_b).targets)
    return chk_a, chk_b, cfg_dir


@pytest.mark.parametrize("harness_id", ["claude-code", "codex"])
def test_claude_and_codex_adapters_extract_verified_events_enforce_checkout_scope_and_fail_closed(
    trusted_tmp: Path,
    monkeypatch: pytest.MonkeyPatch,
    harness_id: str,
) -> None:
    os_ = os_adapters()
    chk_a, chk_b, _ = _make_checkouts(trusted_tmp)
    adapter = ClaudeCodeCaptureAdapter(os_) if harness_id == "claude-code" else CodexCaptureAdapter(os_)

    insp = adapter.inspect_checkout_config(chk_a)
    assert insp.harness_id == harness_id
    assert insp.hooks_configured is True
    assert insp.config_digest is not None and insp.config_digest.startswith("sha256:")
    assert insp.ask_commands_covered is (harness_id == "claude-code")

    sref = digest_bytes(b"hmac-session-sp25-adapter-1")
    stream = f"stream-{harness_id}-a"
    ctx_a = HarnessCaptureContext(
        checkout_root=chk_a,
        repo_id="repo-sp25",
        checkout_id="chk-a",
        producer_stream=stream,
        session_ref=sref,
        host_version="2.1.325" if harness_id == "claude-code" else "26.1111.2228.0",
        expected_config_digest=insp.config_digest,
    )

    # 1. Valid local capture event with complete recipient profile -> OK + LOCAL_ONLY.
    raw_ok: dict[str, Any] = {
        "event_id": "ev-sp25-1",
        "sequence": 1,
        "event_name": "PostToolUse" if harness_id == "claude-code" else "command_completed",
        "recorded_at": "2026-11-26T17:00:00Z",
        "cwd": str(chk_a / "sub"),
        "payload": {"command": "pytest -q", "exit_code": 0},
        "channel_kind": "local_capture",
        "recipient": {
            "provider_endpoint": "https://api.anthropic.com/v1" if harness_id == "claude-code" else "https://api.openai.com/v1",
            "model_config": "claude-sonnet-4-6" if harness_id == "claude-code" else "gpt-5.4",
            "account_id": "acct-dan-filtered",
        },
        # Client-supplied authority keys must never be copied into source_metadata or event payload.
        "source": "tool_observed",
        "source_verification": "verified_host",
        "session_id": "RAW_HOST_SECRET_SID",
    }
    (chk_a / "sub").mkdir(exist_ok=True)
    res1 = adapter.adapt_hook_event(raw_ok, context=ctx_a)
    assert res1.status is AdapterCaptureStatus.OK
    assert isinstance(res1.record, CaptureEventRecord)
    rec1 = res1.record
    assert rec1.harness_id == harness_id
    assert rec1.producer_stream == stream and rec1.sequence == 1
    assert rec1.session_ref == sref
    assert rec1.source_metadata["host_version"] == ctx_a.host_version
    assert rec1.source_metadata["config_digest"] == insp.config_digest
    serialized = json.dumps(rec1.to_dict(), sort_keys=True)
    assert "RAW_HOST_SECRET_SID" not in serialized
    assert "acct-dan-filtered" not in serialized
    assert res1.recipient_profile.is_complete is True
    assert res1.segment_changed is True

    seg1 = SessionSegmentRecord(
        segment_id="seg-sp25-1",
        session_ref=sref,
        segment_index=1,
        profile=res1.recipient_profile,
        opened_at="2026-11-26T17:00:00Z",
    )
    assert (
        classify_exposure_evidence(
            item_digest=digest_bytes(b"item-1"),
            active_segment=seg1,
            channel_kind=res1.channel_kind,
            model_exchange=None,
            client_claimed_exposure="sent_to_recipient",
        )
        is ExposureEvidence.LOCAL_ONLY
    )

    # 2. Same profile + completed model_io exchange -> segment_changed=False and SENT_TO_RECIPIENT.
    ctx_a_cont = HarnessCaptureContext(
        checkout_root=chk_a,
        repo_id="repo-sp25",
        checkout_id="chk-a",
        producer_stream=stream,
        session_ref=sref,
        host_version=ctx_a.host_version,
        expected_config_digest=insp.config_digest,
        active_segment=seg1,
    )
    raw_model = {
        "event_id": "ev-sp25-2",
        "sequence": 2,
        "event_name": "AssistantResponse" if harness_id == "claude-code" else "agent_turn_end",
        "recorded_at": "2026-11-26T17:00:05Z",
        "cwd": str(chk_a),
        "payload": {"role": "assistant", "text": "Filtered assistant turn"},
        "channel_kind": "model_io",
        "model_call": {"id": "call-sp25-2", "completed": True},
        "recipient": {
            "provider_endpoint": "https://api.anthropic.com/v1" if harness_id == "claude-code" else "https://api.openai.com/v1",
            "model_config": "claude-sonnet-4-6" if harness_id == "claude-code" else "gpt-5.4",
            "account_id": "acct-dan-filtered",
        },
    }
    res2 = adapter.adapt_hook_event(raw_model, context=ctx_a_cont)
    assert res2.status is AdapterCaptureStatus.OK
    assert res2.segment_changed is False
    assert should_open_new_segment(seg1, res2.recipient_profile) is False
    assert res2.model_exchange is not None and res2.model_exchange.completed is True
    assert (
        classify_exposure_evidence(
            item_digest=res2.model_exchange.item_digest,
            active_segment=seg1,
            channel_kind="model_io",
            model_exchange=res2.model_exchange,
        )
        is ExposureEvidence.SENT_TO_RECIPIENT
    )

    # 3. Switching model/account mid-session triggers new SessionSegment and fails closed if incomplete.
    raw_switch = {
        "event_id": "ev-sp25-3",
        "sequence": 3,
        "event_name": "UserPromptSubmit" if harness_id == "claude-code" else "user_prompt",
        "recorded_at": "2026-11-26T17:00:10Z",
        "cwd": str(chk_a),
        "payload": {"role": "user", "text": "Switch model"},
        "channel_kind": "model_io",
        "model_call": {"id": "call-sp25-3", "completed": False},
        "recipient": {
            "provider_endpoint": "https://api.openai.com/v2",
            "model_config": "different-model",
        },
    }
    res3 = adapter.adapt_hook_event(raw_switch, context=ctx_a_cont)
    assert res3.status is AdapterCaptureStatus.OK
    assert res3.segment_changed is True
    assert res3.recipient_profile.account_digest == "unknown"
    assert res3.recipient_profile.is_complete is False
    assert res3.model_exchange is None
    assert (
        classify_exposure_evidence(
            item_digest=digest_bytes(b"item-3"),
            active_segment=seg1,
            channel_kind="model_io",
            model_exchange=None,
        )
        is ExposureEvidence.UNKNOWN
    )

    # 4. Workspace switch to checkout B (or symlink under A) is rejected with WORKSPACE_MISMATCH.
    raw_b = dict(raw_ok, event_id="ev-sp25-4", sequence=4, cwd=str(chk_b))
    res_b = adapter.adapt_hook_event(raw_b, context=ctx_a)
    assert res_b.status is AdapterCaptureStatus.WORKSPACE_MISMATCH
    assert res_b.record is None

    link_sub = chk_a / "linked-escape"
    link_sub.mkdir(exist_ok=True)
    fake_link(monkeypatch, link_sub)
    raw_lnk = dict(raw_ok, event_id="ev-sp25-5", sequence=5, cwd=str(link_sub))
    res_lnk = adapter.adapt_hook_event(raw_lnk, context=ctx_a)
    assert res_lnk.status is AdapterCaptureStatus.WORKSPACE_MISMATCH
    assert res_lnk.record is None

    # 5. Missing cwd -> UNKNOWN; unsupported event / bare mode / hooks_enabled=False -> UNAVAILABLE.
    raw_no_cwd = {k: v for k, v in raw_ok.items() if k != "cwd"}
    assert adapter.adapt_hook_event(raw_no_cwd, context=ctx_a).status is AdapterCaptureStatus.UNKNOWN

    raw_unk_ev = dict(raw_ok, event_id="ev-sp25-6", sequence=6, event_name="UndocumentedInternalHook")
    res_unk_ev = adapter.adapt_hook_event(raw_unk_ev, context=ctx_a)
    assert res_unk_ev.status is AdapterCaptureStatus.UNAVAILABLE and res_unk_ev.record is None

    disabled_ctx = HarnessCaptureContext(
        checkout_root=chk_a,
        repo_id="repo-sp25",
        checkout_id="chk-a",
        producer_stream=stream,
        session_ref=sref,
        bare_mode=(harness_id == "claude-code"),
        hooks_enabled=(harness_id != "codex"),
    )
    res_dis = adapter.adapt_hook_event(raw_ok, context=disabled_ctx)
    assert res_dis.status is AdapterCaptureStatus.UNAVAILABLE and res_dis.record is None

    # 6. ProducerCaptureGap passthrough preserves gap semantics cleanly inside the matching checkout.
    raw_gap = {
        "record_kind": "capture_gap",
        "gap_id": "gap-sp25-7",
        "sequence": 7,
        "reason": "hook_timeout",
        "recorded_at": "2026-11-26T17:00:15Z",
        "cwd": str(chk_a),
        "estimated_count": 1,
        "duration_ms": 2001,
    }
    res_gap = adapter.adapt_hook_event(raw_gap, context=ctx_a)
    assert res_gap.status is AdapterCaptureStatus.OK
    assert isinstance(res_gap.record, ProducerCaptureGap)
    assert RecipientProfile("unknown", "unknown", "unknown", "unknown").is_complete is False


@pytest.mark.parametrize("harness_id", ["claude-code", "codex"])
def test_claude_and_codex_scoped_transcript_reader_isolates_checkout_session_and_rejects_unsafe_paths(
    trusted_tmp: Path,
    monkeypatch: pytest.MonkeyPatch,
    harness_id: str,
) -> None:
    os_ = os_adapters()
    chk_a, chk_b, cfg_dir = _make_checkouts(trusted_tmp)
    transcript_dir = cfg_dir / f"transcripts-{harness_id}"
    transcript_dir.mkdir(exist_ok=True)
    os_.permissions.secure_directory(transcript_dir)
    transcript_file = transcript_dir / "session.jsonl"

    sref_1 = digest_bytes(b"hmac-session-1")
    sref_2 = digest_bytes(b"hmac-session-2")
    raw_lines = [
        {
            "event_id": "tr-1",
            "event_name": "UserPromptSubmit" if harness_id == "claude-code" else "user_prompt",
            "recorded_at": "2026-11-26T17:10:00Z",
            "cwd": str(chk_a),
            "session_ref": sref_1,
            "raw_session_id": "RAW_SHOULD_NOT_LEAK",
            "payload": {"role": "user", "text": "Approved checkout A msg"},
            "channel_kind": "model_io",
            "model_call": {"id": "mc-1", "completed": True},
            "recipient": {
                "provider_endpoint": "https://api.example/v1",
                "model_config": "model-v1",
                "account_id": "acct-1",
            },
        },
        {
            # Different checkout B -> must be excluded from checkout A transcript read!
            "event_id": "tr-other-chk",
            "event_name": "UserPromptSubmit" if harness_id == "claude-code" else "user_prompt",
            "recorded_at": "2026-11-26T17:10:01Z",
            "cwd": str(chk_b),
            "session_ref": sref_1,
            "payload": {"role": "user", "text": "Secret checkout B msg"},
        },
        {
            # Different session_ref -> must be excluded when context pins sref_1!
            "event_id": "tr-other-sess",
            "event_name": "UserPromptSubmit" if harness_id == "claude-code" else "user_prompt",
            "recorded_at": "2026-11-26T17:10:02Z",
            "cwd": str(chk_a),
            "session_ref": sref_2,
            "payload": {"role": "user", "text": "Other session msg"},
        },
        {
            # Same checkout A + session 1, model switch -> triggers segment_changed and sequence 2!
            "event_id": "tr-2",
            "event_name": "PostToolUse" if harness_id == "claude-code" else "command_completed",
            "recorded_at": "2026-11-26T17:10:05Z",
            "cwd": str(chk_a),
            "session_ref": sref_1,
            "payload": {"command": "git status", "exit_code": 0},
            "channel_kind": "local_capture",
            "recipient": {
                "provider_endpoint": "https://api.example/v1",
                "model_config": "model-v2",
                "account_id": "acct-1",
            },
        },
    ]
    transcript_file.write_text("\n".join(json.dumps(x) for x in raw_lines) + "\n", encoding="utf-8")
    os_.permissions.secure_file(transcript_file)

    adapter = ClaudeCodeCaptureAdapter(os_) if harness_id == "claude-code" else CodexCaptureAdapter(os_)
    ctx = HarnessCaptureContext(
        checkout_root=chk_a,
        repo_id="repo-tr",
        checkout_id="chk-a",
        producer_stream=f"stream-tr-{harness_id}",
        session_ref=sref_1,
    )
    out = adapter.read_scoped_transcript(
        transcript_file,
        context=ctx,
        allowed_roots=(transcript_dir,),
        start_sequence=1,
    )
    assert out.status is AdapterCaptureStatus.OK
    assert [e.record.event_id for e in out.events if isinstance(e.record, CaptureEventRecord)] == ["tr-1", "tr-2"]
    assert [e.record.sequence for e in out.events if isinstance(e.record, CaptureEventRecord)] == [1, 2]
    assert out.skipped_out_of_scope == 2
    assert out.events[1].segment_changed is True
    assert "Secret checkout B msg" not in json.dumps([e.record.to_dict() for e in out.events if e.record])
    assert "RAW_SHOULD_NOT_LEAK" not in json.dumps([e.record.to_dict() for e in out.events if e.record])

    # Transcript outside allowed_roots (e.g. unapproved user home) -> fails closed UNAVAILABLE.
    outside = adapter.read_scoped_transcript(
        transcript_file,
        context=ctx,
        allowed_roots=(chk_a,),
        start_sequence=1,
    )
    assert outside.status is AdapterCaptureStatus.UNAVAILABLE
    assert outside.events == ()

    # Missing transcript -> UNAVAILABLE.
    missing = adapter.read_scoped_transcript(
        transcript_dir / "missing.jsonl",
        context=ctx,
        allowed_roots=(transcript_dir,),
    )
    assert missing.status is AdapterCaptureStatus.UNAVAILABLE and missing.events == ()

    # Symlink / junction transcript -> UNAVAILABLE.
    fake_link(monkeypatch, transcript_file)
    linked = adapter.read_scoped_transcript(
        transcript_file,
        context=ctx,
        allowed_roots=(transcript_dir,),
    )
    assert linked.status is AdapterCaptureStatus.UNAVAILABLE and linked.events == ()


def test_bootstrap_capture_hook_command_matches_hook_entry_cli_contract(trusted_tmp: Path) -> None:
    outbox = trusted_tmp / "outbox"
    log_file = trusted_tmp / "logs" / "hook.log"
    cmd = build_capture_hook_command(
        "claude-code",
        outbox_dir=outbox,
        log_path=log_file,
        python_executable=sys.executable,
    )
    assert cmd[0] == sys.executable
    assert cmd[1:4] == ("-I", "-m", "superbrain.composition.hook_entry")
    assert "--outbox" in cmd and str(outbox) in cmd
    assert "--harness" in cmd and "claude-code" in cmd
    assert "--log" in cmd and str(log_file) in cmd
