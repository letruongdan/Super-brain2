"""SP2-3 pure domain tests: ExposureEvidence, SessionSegment, session_ref HMAC, liveness, and worker rules.

Requirement sources:
- docs/superpowers/specs/2026-10-30-super-brain2-system-design.md (§7.1-7.4, §8.10, §20 cases 40, 54)
- docs/superpowers/plans/2026-11-18-sp2-capture-continuity.md (SP2-3, lines 55-73, 158-181)
- docs/design/sp2-host-capture-matrix.md (§2.1-2.3, §4, §4.2, lines 142-179)
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from tests.support.clock import FakeClock


def _sample_event(
    seq: int,
    *,
    kind: str = "tool_post",
    recorded_at: str = "2026-11-21T12:00:00Z",
    payload: dict[str, JsonValue] | None = None,
    session_ref: str = "sha256:" + ("a" * 64),
) -> object:
    from superbrain.ports.capture import CaptureEventRecord

    return CaptureEventRecord(
        event_id=f"evt-domain-{seq}",
        producer_stream="stream-domain-1",
        sequence=seq,
        harness_id="claude-code",
        kind=kind,
        recorded_at=recorded_at,
        payload=payload if payload is not None else {"tool": "Read", "summary": f"step {seq}"},
        session_ref=session_ref,
        source_metadata={"host_version": "2.1.325"},
    )


def test_continuity_port_constants_and_record_validation() -> None:
    from superbrain.ports.continuity import (
        CONTINUITY_REFRESH_JOB_KIND,
        SESSION_ACTIVE_IDLE_S,
        SESSION_UNKNOWN_CHECKPOINT_IDLE_S,
        WORKER_EVENT_THRESHOLD,
        WORKER_MAX_AGE_S,
        ExposureEvidence,
        LongRunningCheckpoint,
        RecipientProfile,
        SessionRecord,
        SessionSegmentRecord,
        SessionState,
    )

    assert CONTINUITY_REFRESH_JOB_KIND == "continuity.refresh"
    assert WORKER_EVENT_THRESHOLD == 20
    assert WORKER_MAX_AGE_S == 60
    assert SESSION_ACTIVE_IDLE_S == 300
    assert SESSION_UNKNOWN_CHECKPOINT_IDLE_S == 1800

    assert ExposureEvidence.SENT_TO_RECIPIENT.value == "sent_to_recipient"
    assert ExposureEvidence.LOCAL_ONLY.value == "local_only"
    assert ExposureEvidence.UNKNOWN.value == "unknown"

    assert SessionState.ACTIVE.value == "active"
    assert SessionState.IN_PROGRESS_UNKNOWN.value == "in_progress_unknown"
    assert SessionState.ENDED.value == "ended"

    complete = RecipientProfile(
        harness_id="claude-code",
        provider_endpoint_digest=digest_bytes(b"https://api.anthropic.example/v1/messages"),
        model_config_digest=digest_bytes(b'{"model":"claude-sonnet","temperature":0}'),
        account_digest=digest_bytes(b"acct-owner-1"),
    )
    assert complete.is_complete is True

    incomplete = RecipientProfile(
        harness_id="claude-code",
        provider_endpoint_digest="unknown",
        model_config_digest=complete.model_config_digest,
        account_digest=complete.account_digest,
    )
    assert incomplete.is_complete is False

    with pytest.raises(BrainError) as bad_profile:
        RecipientProfile(
            harness_id="claude-code",
            provider_endpoint_digest="not-a-digest",
            model_config_digest=complete.model_config_digest,
            account_digest=complete.account_digest,
        )
    assert bad_profile.value.code is ErrorCode.INVALID_INPUT

    seg = SessionSegmentRecord(
        segment_id="seg-1",
        session_ref="sha256:" + ("1" * 64),
        segment_index=1,
        profile=complete,
        opened_at="2026-11-21T12:00:00Z",
    )
    assert seg.segment_index == 1

    with pytest.raises(BrainError) as bad_seg_idx:
        SessionSegmentRecord(
            segment_id="seg-bad",
            session_ref="sha256:" + ("1" * 64),
            segment_index=0,
            profile=complete,
            opened_at="2026-11-21T12:00:00Z",
        )
    assert bad_seg_idx.value.code is ErrorCode.INVALID_INPUT

    sess = SessionRecord(
        session_ref="sha256:" + ("1" * 64),
        repo_id="repo-1",
        checkout_id="chk-1",
        principal_id="prin-1",
        harness_id="claude-code",
        state=SessionState.ACTIVE,
        last_event_at="2026-11-21T12:00:00Z",
        active_segment_id="seg-1",
    )
    assert sess.state is SessionState.ACTIVE

    ckpt = LongRunningCheckpoint(
        command="uv run --locked pytest -q",
        cwd="/workspace/repo-a",
        source_revision="abc1234",
        pid=4242,
        started_at="2026-11-21T12:01:00Z",
        log_or_receipt_path="artifacts/pytest.log",
        next_action="Inspect pytest failure summary on resume",
    )
    assert LongRunningCheckpoint.from_dict(ckpt.to_dict()) == ckpt

    with pytest.raises(BrainError) as bad_ckpt:
        LongRunningCheckpoint(
            command="",
            cwd="/workspace/repo-a",
            source_revision="abc1234",
            pid=4242,
            started_at="2026-11-21T12:01:00Z",
            log_or_receipt_path=None,
            next_action="Inspect",
        )
    assert bad_ckpt.value.code is ErrorCode.INVALID_INPUT


def test_classify_exposure_evidence_fail_closed_and_segment_isolation() -> None:
    from superbrain.domain.capture.exposure import classify_exposure_evidence, should_open_new_segment
    from superbrain.ports.continuity import (
        ExposureEvidence,
        ModelExchangeProof,
        RecipientProfile,
        SessionSegmentRecord,
    )

    profile_a = RecipientProfile(
        harness_id="claude-code",
        provider_endpoint_digest=digest_bytes(b"https://api.provider-a.example"),
        model_config_digest=digest_bytes(b"model-a-v1"),
        account_digest=digest_bytes(b"account-a"),
    )
    seg1 = SessionSegmentRecord(
        segment_id="seg-1",
        session_ref="sha256:" + ("2" * 64),
        segment_index=1,
        profile=profile_a,
        opened_at="2026-11-21T12:00:00Z",
    )
    item_digest = digest_bytes(b"item-payload-1")
    proof = ModelExchangeProof(
        item_digest=item_digest,
        segment_id="seg-1",
        completed_model_call_id="mcall-1",
        completed=True,
        recipient_profile=profile_a,
    )

    # 1. Exact verified match on completed model exchange -> sent_to_recipient.
    assert (
        classify_exposure_evidence(
            item_digest=item_digest,
            active_segment=seg1,
            channel_kind="model_io",
            model_exchange=proof,
        )
        is ExposureEvidence.SENT_TO_RECIPIENT
    )

    # 2. Local hook / brain-only capture stays local_only even if client claims sent_to_recipient.
    assert (
        classify_exposure_evidence(
            item_digest=item_digest,
            active_segment=seg1,
            channel_kind="local_capture",
            client_claimed_exposure="sent_to_recipient",
            model_exchange=proof,
        )
        is ExposureEvidence.LOCAL_ONLY
    )

    # 3. In-flight/failed/hung call or missing proof fails closed to unknown (ignoring client claim).
    for bad_proof in (
        None,
        ModelExchangeProof(
            item_digest=item_digest,
            segment_id="seg-1",
            completed_model_call_id="mcall-hung",
            completed=False,
            recipient_profile=profile_a,
        ),
        ModelExchangeProof(
            item_digest=digest_bytes(b"different-item"),
            segment_id="seg-1",
            completed_model_call_id="mcall-2",
            completed=True,
            recipient_profile=profile_a,
        ),
        ModelExchangeProof(
            item_digest=item_digest,
            segment_id="seg-2",
            completed_model_call_id="mcall-3",
            completed=True,
            recipient_profile=profile_a,
        ),
    ):
        assert (
            classify_exposure_evidence(
                item_digest=item_digest,
                active_segment=seg1,
                channel_kind="model_io",
                client_claimed_exposure="sent_to_recipient",
                model_exchange=bad_proof,
            )
            is ExposureEvidence.UNKNOWN
        )

    # 4. Unknown field in any of the 4 RecipientProfile slots forces UNKNOWN and opens a new segment on profile shift.
    profile_variants = (
        RecipientProfile(
            "unknown",
            profile_a.provider_endpoint_digest,
            profile_a.model_config_digest,
            profile_a.account_digest,
        ),
        RecipientProfile(
            profile_a.harness_id,
            "unknown",
            profile_a.model_config_digest,
            profile_a.account_digest,
        ),
        RecipientProfile(
            profile_a.harness_id,
            profile_a.provider_endpoint_digest,
            "unknown",
            profile_a.account_digest,
        ),
        RecipientProfile(
            profile_a.harness_id,
            profile_a.provider_endpoint_digest,
            profile_a.model_config_digest,
            "unknown",
        ),
    )
    for idx, partial_profile in enumerate(profile_variants, start=2):
        seg_partial = SessionSegmentRecord(
            segment_id=f"seg-partial-{idx}",
            session_ref=seg1.session_ref,
            segment_index=idx,
            profile=partial_profile,
            opened_at="2026-11-21T12:05:00Z",
        )
        assert should_open_new_segment(seg1, partial_profile) is True
        assert (
            classify_exposure_evidence(
                item_digest=item_digest,
                active_segment=seg_partial,
                channel_kind="model_io",
                model_exchange=ModelExchangeProof(
                    item_digest=item_digest,
                    segment_id=seg_partial.segment_id,
                    completed_model_call_id=f"mcall-p-{idx}",
                    completed=True,
                    recipient_profile=partial_profile,
                ),
            )
            is ExposureEvidence.UNKNOWN
        )

    assert should_open_new_segment(seg1, profile_a) is False
    profile_b = RecipientProfile(
        harness_id="claude-code",
        provider_endpoint_digest=profile_a.provider_endpoint_digest,
        model_config_digest=digest_bytes(b"model-b-v2"),
        account_digest=profile_a.account_digest,
    )
    assert should_open_new_segment(seg1, profile_b) is True
    assert (
        classify_exposure_evidence(
            item_digest=item_digest,
            active_segment=SessionSegmentRecord(
                segment_id="seg-2",
                session_ref=seg1.session_ref,
                segment_index=2,
                profile=profile_b,
                opened_at="2026-11-21T12:06:00Z",
            ),
            channel_kind="model_io",
            model_exchange=proof,
        )
        is ExposureEvidence.UNKNOWN
    )


def test_compute_session_ref_hmac_deterministic_and_non_leaky() -> None:
    from superbrain.domain.continuity.sessions import compute_session_ref

    key_a = b"k" * 32
    key_b = b"m" * 32
    raw_sid = "RAW_HARNESS_SESSION_SECRET_9911"

    ref1 = compute_session_ref(key_a, raw_sid)
    ref2 = compute_session_ref(key_a, raw_sid)
    ref_diff_key = compute_session_ref(key_b, raw_sid)
    ref_diff_sid = compute_session_ref(key_a, "RAW_HARNESS_SESSION_SECRET_9912")

    assert ref1.startswith("sha256:") and len(ref1) == 71
    assert ref1 == ref2
    assert ref1 != ref_diff_key
    assert ref1 != ref_diff_sid
    assert raw_sid not in ref1

    with pytest.raises(BrainError) as short_key:
        compute_session_ref(b"too-short", raw_sid)
    assert short_key.value.code is ErrorCode.INVALID_INPUT
    assert raw_sid not in str(short_key.value)

    with pytest.raises(BrainError) as empty_sid:
        compute_session_ref(key_a, "")
    assert empty_sid.value.code is ErrorCode.INVALID_INPUT


def test_evaluate_session_liveness_boundaries_with_fake_clock() -> None:
    from superbrain.domain.continuity.sessions import (
        advance_producer_watermark,
        evaluate_session_liveness,
    )
    from superbrain.ports.continuity import SessionState

    clock = FakeClock(datetime(2026, 11, 21, 12, 0, 0, tzinfo=UTC))
    t0 = clock.now()

    for delta_s in (0, 299, 300):
        clock.set(t0 + timedelta(seconds=delta_s))
        dec = evaluate_session_liveness(
            recorded_state=SessionState.ACTIVE,
            last_event_at=t0,
            now=clock.now(),
        )
        assert dec.state is SessionState.ACTIVE
        assert dec.active_takeover_warning is True
        assert dec.requires_acknowledge_active is True
        assert dec.should_create_unknown_checkpoint is False

    # Minute 6 (301 s) and 30 min exact (1800 s): already in_progress_unknown, NO 1800 s checkpoint yet.
    for delta_s in (301, 1800):
        clock.set(t0 + timedelta(seconds=delta_s))
        dec = evaluate_session_liveness(
            recorded_state=SessionState.ACTIVE,
            last_event_at=t0,
            now=clock.now(),
        )
        assert dec.state is SessionState.IN_PROGRESS_UNKNOWN
        assert dec.active_takeover_warning is False
        assert dec.requires_acknowledge_active is False
        assert dec.should_create_unknown_checkpoint is False

    # Past 1800 s (1801 s): checkpoint created once, idempotent after checkpoint_exists=True.
    clock.set(t0 + timedelta(seconds=1801))
    dec_1801 = evaluate_session_liveness(
        recorded_state=SessionState.ACTIVE,
        last_event_at=t0,
        now=clock.now(),
        checkpoint_exists=False,
    )
    assert dec_1801.state is SessionState.IN_PROGRESS_UNKNOWN
    assert dec_1801.requires_acknowledge_active is False
    assert dec_1801.should_create_unknown_checkpoint is True

    dec_existing = evaluate_session_liveness(
        recorded_state=SessionState.IN_PROGRESS_UNKNOWN,
        last_event_at=t0,
        now=clock.now(),
        checkpoint_exists=True,
    )
    assert dec_existing.state is SessionState.IN_PROGRESS_UNKNOWN
    assert dec_existing.should_create_unknown_checkpoint is False

    # Ended session stays ended across ordinary late events; only session_resumed returns to active.
    dec_ended = evaluate_session_liveness(
        recorded_state=SessionState.ENDED,
        last_event_at=t0,
        now=t0 + timedelta(seconds=10),
        has_end_event=True,
        has_resumed_after_end=False,
    )
    assert dec_ended.state is SessionState.ENDED
    assert dec_ended.requires_acknowledge_active is False
    assert dec_ended.should_create_unknown_checkpoint is False

    dec_resumed = evaluate_session_liveness(
        recorded_state=SessionState.ENDED,
        last_event_at=t0 + timedelta(seconds=5),
        now=t0 + timedelta(seconds=10),
        has_end_event=True,
        has_resumed_after_end=True,
    )
    assert dec_resumed.state is SessionState.ACTIVE
    assert dec_resumed.requires_acknowledge_active is True

    # Late out-of-order events never move producer stream high-water mark backward.
    assert advance_producer_watermark(5, 6) == 6
    assert advance_producer_watermark(5, 2) == 5
    assert advance_producer_watermark(5, 5) == 5


def test_extract_observed_summary_and_long_running_checkpoint_pure_rules() -> None:
    from superbrain.domain.continuity.sessions import extract_long_running_checkpoint
    from superbrain.domain.continuity.worker_rules import extract_observed_summary

    events: list[Any] = [
        _sample_event(
            1,
            kind="tool_post",
            recorded_at="2026-11-21T12:00:01Z",
            payload={
                "tool": "Bash",
                "command": "uv run --locked pytest tests/storage/test_dual_store_session_binding.py",
                "exit_code": 1,
                "error_signature": "IntegrityFailure: missing session row",
            },
        ),
        _sample_event(
            2,
            kind="tool_post",
            recorded_at="2026-11-21T12:00:02Z",
            payload={
                "tool": "Edit",
                "file_path": "src/superbrain/storage/sessions.py",
            },
        ),
        _sample_event(
            3,
            kind="user_prompt",
            recorded_at="2026-11-21T12:00:03Z",
            payload={
                "text": "Don't call time.sleep in tests; instead use FakeClock everywhere.",
            },
        ),
        _sample_event(
            4,
            kind="tool_post",
            recorded_at="2026-11-21T12:00:04Z",
            payload={
                "tool": "Bash",
                "command": "uv run --locked pytest tests/storage/test_dual_store_session_binding.py",
                "exit_code": 1,
                "error_signature": "IntegrityFailure: missing session row",
            },
        ),
        _sample_event(
            5,
            kind="long_running_job",
            recorded_at="2026-11-21T12:00:05Z",
            payload={
                "status": "running",
                "command": "uv run --locked pytest -q",
                "cwd": "/workspace/repo-a",
                "source_revision": "deadbeef1234",
                "pid": 8192,
                "started_at": "2026-11-21T12:00:05Z",
                "log_or_receipt_path": "logs/pytest-run.log",
                "next_action": "Await completion or inspect logs/pytest-run.log",
            },
        ),
    ]

    summary = extract_observed_summary(events)
    assert summary.latest_high_seq == 5
    assert summary.last_event_at == "2026-11-21T12:00:05Z"
    assert "src/superbrain/storage/sessions.py" in summary.modified_files
    assert len(summary.test_runs) >= 2
    assert any(tr.exit_code == 1 for tr in summary.test_runs)
    assert any(
        err.signature == "IntegrityFailure: missing session row" and err.count == 2
        for err in summary.error_signatures
    )
    assert any("FakeClock" in corr for corr in summary.user_corrections)
    assert summary.long_running is not None
    assert summary.long_running.command == "uv run --locked pytest -q"
    assert summary.long_running.cwd == "/workspace/repo-a"
    assert summary.long_running.source_revision == "deadbeef1234"
    assert summary.long_running.pid == 8192
    assert summary.long_running.started_at == "2026-11-21T12:00:05Z"
    assert summary.long_running.log_or_receipt_path == "logs/pytest-run.log"
    assert summary.long_running.next_action == "Await completion or inspect logs/pytest-run.log"

    serialized = json.dumps(summary.to_dict(), sort_keys=True)
    assert "raw_session_id" not in serialized

    # Once a completion event arrives for that running PID/job, extract_long_running_checkpoint clears.
    done_events = [
        *events,
        _sample_event(
            6,
            kind="long_running_job",
            recorded_at="2026-11-21T12:01:00Z",
            payload={"status": "completed", "pid": 8192, "exit_code": 0},
        ),
    ]
    assert extract_long_running_checkpoint(done_events) is None


def test_should_schedule_refresh_event_and_age_thresholds_with_fake_clock() -> None:
    from superbrain.domain.continuity.worker_rules import should_schedule_refresh

    clock = FakeClock(datetime(2026, 11, 21, 12, 0, 0, tzinfo=UTC))
    t0 = clock.now()

    assert should_schedule_refresh(
        pending_event_count=0, first_pending_at=None, now=t0, job_in_flight=False
    ) is False

    # Below 20 events and below 60 s -> do not fire yet.
    clock.set(t0 + timedelta(seconds=59))
    assert should_schedule_refresh(
        pending_event_count=19, first_pending_at=t0, now=clock.now(), job_in_flight=False
    ) is False

    # Event #20 triggers immediately even at +1 s.
    clock.set(t0 + timedelta(seconds=1))
    assert should_schedule_refresh(
        pending_event_count=20, first_pending_at=t0, now=clock.now(), job_in_flight=False
    ) is True

    # Case 54: quiet/dead session with < 20 events triggers at exactly 60 s.
    clock.set(t0 + timedelta(seconds=60))
    assert should_schedule_refresh(
        pending_event_count=3, first_pending_at=t0, now=clock.now(), job_in_flight=False
    ) is True

    # Never enqueue a second overlapping job while one is already queued/running.
    assert should_schedule_refresh(
        pending_event_count=25, first_pending_at=t0, now=clock.now(), job_in_flight=True
    ) is False
