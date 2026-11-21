"""Pure domain rules for HMAC session refs, session liveness, watermarks, and checkpoints."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

from superbrain.ports.capture import CaptureEventRecord
from superbrain.ports.continuity import (
    LivenessDecision,
    LongRunningCheckpoint,
    SessionState,
    compute_hmac_session_ref,
    decide_session_liveness,
    monotonic_watermark,
)


def _parse_iso_utc(timestamp: str) -> datetime:
    return datetime.fromisoformat(timestamp[:-1] + "+00:00").astimezone(UTC)


def compute_session_ref(hmac_key: bytes, raw_session_id: str) -> str:
    """Compute keyed ``sha256:<hex>`` session reference without leaking raw session IDs."""
    return compute_hmac_session_ref(hmac_key, raw_session_id)


def evaluate_session_liveness(
    *,
    recorded_state: SessionState,
    last_event_at: datetime,
    now: datetime,
    checkpoint_exists: bool = False,
    has_end_event: bool = False,
    has_resumed_after_end: bool = False,
    process_killed: bool = False,
) -> LivenessDecision:
    """Classify session liveness per spec §7.3 (`ended` stays ended without explicit resume)."""
    return decide_session_liveness(
        recorded_state=recorded_state,
        last_event_at=last_event_at,
        now=now,
        checkpoint_exists=checkpoint_exists,
        has_end_event=has_end_event,
        has_resumed_after_end=has_resumed_after_end,
        process_killed=process_killed,
    )


def advance_producer_watermark(prev_high: int, event_seq: int) -> int:
    """Return monotonic producer high watermark ``max(prev_high, event_seq)``."""
    return monotonic_watermark(prev_high, event_seq)


def extract_long_running_checkpoint(
    events: Sequence[CaptureEventRecord],
) -> LongRunningCheckpoint | None:
    """Return the newest still-running ``long_running_job`` checkpoint, or ``None`` if completed."""
    ordered = sorted(
        enumerate(events),
        key=lambda item: (_parse_iso_utc(item[1].recorded_at), item[1].sequence, item[0]),
    )
    active_by_key: dict[str, LongRunningCheckpoint] = {}
    for _, ev in ordered:
        if ev.kind != "long_running_job":
            continue
        payload = ev.payload
        status = payload.get("status")
        raw_pid = payload.get("pid")
        pid = raw_pid if isinstance(raw_pid, int) and not isinstance(raw_pid, bool) else None
        raw_cmd = payload.get("command")
        pid_key = f"pid:{pid}" if pid is not None else f"cmd:{raw_cmd if isinstance(raw_cmd, str) else '_'}"
        if status == "completed":
            if pid is not None:
                active_by_key.pop(f"pid:{pid}", None)
            elif pid_key in active_by_key:
                active_by_key.pop(pid_key, None)
            else:
                active_by_key.clear()
            continue
        if status != "running":
            continue
        command = raw_cmd if isinstance(raw_cmd, str) and raw_cmd.strip() else "unknown"
        raw_cwd = payload.get("cwd")
        cwd = raw_cwd if isinstance(raw_cwd, str) and raw_cwd.strip() else "."
        raw_rev = payload.get("source_revision")
        source_revision = raw_rev if isinstance(raw_rev, str) and raw_rev.strip() else "unknown"
        raw_started = payload.get("started_at")
        started_at = raw_started if isinstance(raw_started, str) and raw_started.strip() else ev.recorded_at
        raw_log = payload.get("log_or_receipt_path")
        log_path = raw_log if isinstance(raw_log, str) and raw_log.strip() else None
        raw_next = payload.get("next_action")
        next_action = raw_next if isinstance(raw_next, str) and raw_next.strip() else "inspect running job"
        active_by_key[pid_key] = LongRunningCheckpoint(
            command=command,
            cwd=cwd,
            source_revision=source_revision,
            pid=pid,
            started_at=started_at,
            log_or_receipt_path=log_path,
            next_action=next_action,
        )
    if not active_by_key:
        return None
    last_key = list(active_by_key)[-1]
    return active_by_key[last_key]


__all__ = [
    "advance_producer_watermark",
    "compute_session_ref",
    "evaluate_session_liveness",
    "extract_long_running_checkpoint",
]
