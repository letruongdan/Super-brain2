"""Capture D6 privacy gate applied before outbox enqueue and daemon ingest."""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping

from superbrain.core._kernel_workspace import FilterPolicy
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.capture import (
    CaptureEventRecord,
    CapturePrivacyFilterPort,
    ProducerCaptureGap,
    assert_no_forbidden_capture_keys,
    clone_json_mapping,
    freeze_json_mapping,
)

_PRIVACY_REJECT_MSG = "privacy filter rejected payload"
_DEADLINE_MSG = "deadline exceeded"


def _contains_substring(value: object, needle: str) -> bool:
    stack: list[object] = [value]
    while stack:
        cur = stack.pop()
        if isinstance(cur, str):
            if needle in cur:
                return True
        elif isinstance(cur, Mapping):
            for key, item in cur.items():
                if isinstance(key, str) and needle in key:
                    return True
                stack.append(item)
        elif isinstance(cur, (list, tuple)):
            stack.extend(cur)
    return False


class CapturePrivacyGate:
    """Pure capture privacy gate delegating D6 scanning to ``CapturePrivacyFilterPort``."""

    def __init__(
        self,
        privacy_filter: CapturePrivacyFilterPort,
        *,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
    ) -> None:
        self._filter = privacy_filter
        self._monotonic_ns = monotonic_ns

    def sanitize_event(
        self,
        record: CaptureEventRecord | ProducerCaptureGap,
        *,
        policy: FilterPolicy | None = None,
        raw_session_id: str | None = None,
        deadline_ns: int | None = None,
    ) -> CaptureEventRecord:
        """Validate, redact/drop secrets via D6, and refuse raw ``raw_session_id`` leaks."""
        if not isinstance(record, CaptureEventRecord):
            raise BrainError(ErrorCode.INVALID_INPUT, _PRIVACY_REJECT_MSG)
        resolved_policy = policy if policy is not None else FilterPolicy()
        if not isinstance(resolved_policy, FilterPolicy):
            raise BrainError(ErrorCode.INVALID_INPUT, _PRIVACY_REJECT_MSG)
        if deadline_ns is not None and int(self._monotonic_ns()) >= deadline_ns:
            raise BrainError(ErrorCode.DEADLINE_EXCEEDED, _DEADLINE_MSG)

        assert_no_forbidden_capture_keys(record.payload)
        assert_no_forbidden_capture_keys(record.source_metadata)

        if raw_session_id is not None:
            if not isinstance(raw_session_id, str) or not raw_session_id:
                raise BrainError(ErrorCode.INVALID_INPUT, _PRIVACY_REJECT_MSG)
            if (
                raw_session_id in record.event_id
                or raw_session_id in record.kind
                or raw_session_id in record.producer_stream
                or raw_session_id in record.harness_id
                or (record.session_ref is not None and raw_session_id in record.session_ref)
                or _contains_substring(record.payload, raw_session_id)
                or _contains_substring(record.source_metadata, raw_session_id)
            ):
                raise BrainError(ErrorCode.INVALID_INPUT, _PRIVACY_REJECT_MSG)

        try:
            safe_payload = self._filter.apply(
                clone_json_mapping(record.payload),
                resolved_policy,
                deadline_ns=deadline_ns,
            )
            safe_meta = self._filter.apply(
                clone_json_mapping(record.source_metadata),
                resolved_policy,
                deadline_ns=deadline_ns,
            )
        except BrainError as err:
            if err.code is ErrorCode.DEADLINE_EXCEEDED:
                raise BrainError(ErrorCode.DEADLINE_EXCEEDED, _DEADLINE_MSG) from err
            raise BrainError(ErrorCode.INVALID_INPUT, _PRIVACY_REJECT_MSG) from err
        except Exception as err:  # noqa: BLE001
            raise BrainError(ErrorCode.INVALID_INPUT, _PRIVACY_REJECT_MSG) from err

        safe_payload_val = safe_payload.value
        safe_meta_val = safe_meta.value
        if not isinstance(safe_payload_val, Mapping) or not isinstance(safe_meta_val, Mapping):
            raise BrainError(ErrorCode.INVALID_INPUT, _PRIVACY_REJECT_MSG)

        sanitized = CaptureEventRecord(
            event_id=record.event_id,
            producer_stream=record.producer_stream,
            sequence=record.sequence,
            harness_id=record.harness_id,
            kind=record.kind,
            recorded_at=record.recorded_at,
            payload=freeze_json_mapping(safe_payload_val),
            session_ref=record.session_ref,
            source_metadata=freeze_json_mapping(safe_meta_val),
        )
        if raw_session_id is not None and (
            _contains_substring(sanitized.payload, raw_session_id)
            or _contains_substring(sanitized.source_metadata, raw_session_id)
        ):
            raise BrainError(ErrorCode.INVALID_INPUT, _PRIVACY_REJECT_MSG)
        return sanitized
