"""Pure domain capture continuity contracts: envelope normalization, D6 gate, outbox ACK rules."""

from __future__ import annotations

from superbrain.domain.capture.envelope import normalize_capture_record
from superbrain.domain.capture.outbox_rules import (
    compute_contiguous_event_acked_through,
    partition_pending_for_batch,
    should_evict_outbox_entry,
)
from superbrain.domain.capture.privacy_gate import CapturePrivacyGate

__all__ = [
    "CapturePrivacyGate",
    "compute_contiguous_event_acked_through",
    "normalize_capture_record",
    "partition_pending_for_batch",
    "should_evict_outbox_entry",
]
