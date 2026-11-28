"""Pure domain rules for HMAC session refs, session liveness, watermarks, and checkpoints."""

from __future__ import annotations

from datetime import UTC, datetime

from superbrain.ports._continuity_checkpoint import (
    extract_long_running_checkpoint,
    extract_long_running_with_source,
)
from superbrain.ports.continuity import (
    LivenessDecision,
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


__all__ = [
    "advance_producer_watermark",
    "extract_long_running_with_source",
    "compute_session_ref",
    "evaluate_session_liveness",
    "extract_long_running_checkpoint",
]
