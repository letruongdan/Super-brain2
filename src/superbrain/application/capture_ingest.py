"""Application capture ingest service: D6 re-filter, live repo flag check, server-side Layer-2 attribution."""

from __future__ import annotations

import dataclasses
import time
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from superbrain.core._kernel_auth import RepoPolicy
from superbrain.core._kernel_base import Principal
from superbrain.core._kernel_daemon import CaptureBatchCommand
from superbrain.core._kernel_workspace import FilterPolicy
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.domain.capture.envelope import normalize_capture_record
from superbrain.domain.capture.privacy_gate import CapturePrivacyGate
from superbrain.ports.capture import (
    MAX_CAPTURE_BATCH_EVENTS,
    CaptureBatchAck,
    CaptureEventRecord,
    CapturePrivacyFilterPort,
    CaptureStorePort,
    ProducerCaptureGap,
    StagedCaptureEvent,
)
from superbrain.ports.clock import Clock

__all__ = [
    "CaptureBatchAck",
    "CaptureIngestService",
    "parse_capture_batch_ack",
]


def parse_capture_batch_ack(result: Mapping[str, JsonValue]) -> CaptureBatchAck:
    """Decode a daemon loopback ``CallResult`` envelope into ``CaptureBatchAck`` or raise ``BrainError``."""
    if not isinstance(result, Mapping):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    ok = result.get("ok")
    if ok is True:
        data = result.get("data")
        if not isinstance(data, Mapping):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
        return CaptureBatchAck.from_dict(data)
    if ok is False:
        err = result.get("error")
        if not isinstance(err, Mapping):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
        raw_code = str(err.get("code", ErrorCode.INTEGRITY_FAILURE.value))
        msg = str(err.get("message", "error"))
        try:
            code = ErrorCode(raw_code)
        except ValueError:
            code = ErrorCode.INTEGRITY_FAILURE
        raise BrainError(code, msg)
    raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")


class CaptureIngestService:
    """Validates, re-filters, attributes, and commits capture batches via ``CaptureStorePort``."""

    def __init__(
        self,
        *,
        capture_store: CaptureStorePort,
        privacy_filter: CapturePrivacyFilterPort,
        clock: Clock,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
    ) -> None:
        self._store = capture_store
        self._privacy_gate = CapturePrivacyGate(privacy_filter, monotonic_ns=monotonic_ns)
        self._clock = clock
        self._monotonic_ns = monotonic_ns

    def ingest_batch(
        self,
        command: CaptureBatchCommand,
        *,
        principal: Principal,
        repo_policy: RepoPolicy,
        layer2_lookup: Callable[[str], tuple[str, str] | None],
        filter_policy: FilterPolicy | None = None,
        deadline_ns: int | None = None,
        before_commit: Callable[[Sequence[StagedCaptureEvent]], None] | None = None,
        on_event_committed_in_tx: Callable[[Any, StagedCaptureEvent], None] | None = None,
    ) -> CaptureBatchAck:
        """Ingest a capture batch after verifying live ``automatic_capture``, D6 privacy, and attribution."""
        if (
            not isinstance(command, CaptureBatchCommand)
            or not isinstance(principal, Principal)
            or not isinstance(repo_policy, RepoPolicy)
        ):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if len(command.events) > MAX_CAPTURE_BATCH_EVENTS:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if deadline_ns is not None and int(self._monotonic_ns()) >= deadline_ns:
            raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")

        if not repo_policy.automatic_capture_enabled:
            return CaptureBatchAck(
                producer_stream=command.producer_stream,
                repo_id=command.repo_id,
                checkout_id=command.checkout_id,
                committed_event_sequences=(),
                contiguous_event_acked_through=0,
                acked_producer_gap_sequences=(),
                accepted_count=0,
                deduped_count=0,
                policy_disabled=True,
            )

        if filter_policy is not None and not isinstance(filter_policy, FilterPolicy):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        effective_filter = (
            dataclasses.replace(filter_policy, manual_submission=True)
            if filter_policy is not None
            else FilterPolicy()
        )
        staged_events: list[StagedCaptureEvent] = []
        gaps: list[ProducerCaptureGap] = []
        l2_cache: dict[str, tuple[str, str] | None] = {}

        for raw in command.events:
            if deadline_ns is not None and int(self._monotonic_ns()) >= deadline_ns:
                raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")
            record = normalize_capture_record(raw)
            if record.producer_stream != command.producer_stream:
                raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
            if isinstance(record, ProducerCaptureGap):
                gaps.append(self._privacy_gate.validate_gap(record, deadline_ns=deadline_ns))
                continue
            assert isinstance(record, CaptureEventRecord)
            sanitized = self._privacy_gate.sanitize_event(
                record,
                policy=effective_filter,
                deadline_ns=deadline_ns,
            )
            payload_bytes = canonical_json(sanitized.payload)
            payload_digest = digest_bytes(payload_bytes)
            source, source_verification = self._attribute_source(
                sanitized,
                principal=principal,
                l2_cache=l2_cache,
                layer2_lookup=layer2_lookup,
            )
            staged_events.append(
                StagedCaptureEvent(
                    record=sanitized,
                    payload_bytes=payload_bytes,
                    payload_digest=payload_digest,
                    source=source,
                    source_verification=source_verification,
                )
            )

        staged_tuple = tuple(staged_events)
        if before_commit is not None and staged_tuple:
            before_commit(staged_tuple)

        return self._store.commit_staged_batch(
            producer_stream=command.producer_stream,
            repo_id=command.repo_id,
            checkout_id=command.checkout_id,
            principal_id=principal.principal_id,
            events=staged_tuple,
            gaps=tuple(gaps),
            now=self._clock.now(),
            on_event_committed_in_tx=on_event_committed_in_tx,
        )

    @staticmethod
    def _attribute_source(
        record: CaptureEventRecord,
        *,
        principal: Principal,
        l2_cache: dict[str, tuple[str, str] | None],
        layer2_lookup: Callable[[str], tuple[str, str] | None],
    ) -> tuple[str, str]:
        if record.harness_id != principal.harness_id:
            return ("unknown", "unverified")
        if record.harness_id not in l2_cache:
            l2_cache[record.harness_id] = layer2_lookup(record.harness_id)
        verified = l2_cache[record.harness_id]
        if verified is None:
            return ("unknown", "unverified")
        expected_version, expected_cfg_digest = verified
        got_version = record.source_metadata.get("host_version")
        got_cfg_digest = record.source_metadata.get("config_digest")
        if (
            isinstance(got_version, str)
            and isinstance(got_cfg_digest, str)
            and got_version == expected_version
            and got_cfg_digest == expected_cfg_digest
        ):
            return ("tool_observed", "verified_host")
        return ("unknown", "unverified")
