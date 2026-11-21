"""Pure normalization of untrusted capture envelopes and gap records (no I/O, no attribution trust)."""

from __future__ import annotations

from collections.abc import Mapping

from superbrain.core._kernel_base import require_opaque_id
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.ports.capture import (
    OUTBOX_RECORD_EVENT,
    OUTBOX_RECORD_GAP,
    CaptureEventRecord,
    ProducerCaptureGap,
    assert_no_forbidden_capture_keys,
)


def normalize_capture_record(
    raw: object,
    *,
    default_harness_id: str | None = None,
) -> CaptureEventRecord | ProducerCaptureGap:
    """Normalize a client JSON capture dict into ``CaptureEventRecord`` or ``ProducerCaptureGap``.

    Rejects client-forged attribution or raw session fields anywhere in the tree.
    """
    if not isinstance(raw, Mapping):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    for key in raw:
        if not isinstance(key, str):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    assert_no_forbidden_capture_keys(raw)

    raw_mapping: Mapping[str, JsonValue] = raw  # keys verified as str above
    record_kind = raw_mapping.get("record_kind")
    if record_kind == OUTBOX_RECORD_GAP:
        return ProducerCaptureGap.from_dict(raw_mapping)
    if record_kind is None or record_kind == OUTBOX_RECORD_EVENT:
        if "harness_id" not in raw_mapping and default_harness_id is not None:
            require_opaque_id(default_harness_id, label="harness_id")
            copied = dict(raw_mapping)
            copied["harness_id"] = default_harness_id
            return CaptureEventRecord.from_dict(copied)
        return CaptureEventRecord.from_dict(raw_mapping)
    raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
