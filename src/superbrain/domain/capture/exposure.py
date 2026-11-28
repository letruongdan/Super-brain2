"""Pure domain rules for RecipientProfile segment boundaries and ExposureEvidence classification."""

from __future__ import annotations

from superbrain.core._kernel_base import require_sha256_digest
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.continuity import (
    ExposureEvidence,
    ModelExchangeProof,
    RecipientProfile,
    SessionSegmentRecord,
)


def _invalid(message: str = "invalid exposure input") -> BrainError:
    return BrainError(ErrorCode.INVALID_INPUT, message)


def should_open_new_segment(
    active_segment: SessionSegmentRecord | None,
    next_profile: RecipientProfile,
) -> bool:
    """Return True when the session needs a new SessionSegment for ``next_profile``."""
    if not isinstance(next_profile, RecipientProfile):
        raise _invalid("invalid recipient profile")
    if active_segment is None:
        return True
    if not isinstance(active_segment, SessionSegmentRecord):
        raise _invalid("invalid active segment")
    return active_segment.profile.segment_key() != next_profile.segment_key()


def classify_exposure_evidence(
    *,
    item_digest: str,
    active_segment: SessionSegmentRecord | None,
    channel_kind: str,
    model_exchange: ModelExchangeProof | None = None,
    client_claimed_exposure: str | None = None,
) -> ExposureEvidence:
    """Classify item exposure strictly from host-verified proof; ignore untrusted client claims."""
    require_sha256_digest(item_digest)
    if not isinstance(channel_kind, str) or not channel_kind.strip():
        raise _invalid("invalid channel kind")
    _ = client_claimed_exposure  # Never trust caller-asserted exposure claims.

    if channel_kind == "local_capture":
        return ExposureEvidence.LOCAL_ONLY

    if channel_kind != "model_io":
        return ExposureEvidence.UNKNOWN

    if active_segment is None or not isinstance(active_segment, SessionSegmentRecord):
        return ExposureEvidence.UNKNOWN
    if not active_segment.profile.is_complete:
        return ExposureEvidence.UNKNOWN
    if model_exchange is None or not isinstance(model_exchange, ModelExchangeProof):
        return ExposureEvidence.UNKNOWN
    if model_exchange.completed is not True:
        return ExposureEvidence.UNKNOWN
    if model_exchange.item_digest != item_digest:
        return ExposureEvidence.UNKNOWN
    if model_exchange.segment_id != active_segment.segment_id:
        return ExposureEvidence.UNKNOWN
    if not model_exchange.recipient_profile.is_complete:
        return ExposureEvidence.UNKNOWN
    if model_exchange.recipient_profile.segment_key() != active_segment.profile.segment_key():
        return ExposureEvidence.UNKNOWN
    return ExposureEvidence.SENT_TO_RECIPIENT


__all__ = [
    "classify_exposure_evidence",
    "should_open_new_segment",
]
