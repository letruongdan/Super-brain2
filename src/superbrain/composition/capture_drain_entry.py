"""Fault-free capture outbox drain entrypoint sending bounded batches and applying separated ACKs."""

from __future__ import annotations

import json

from superbrain.adapters.os import os_adapters  # noqa: F401
from superbrain.adapters.os.locks import OUTBOX_FILE_LOCK  # noqa: F401
from superbrain.cli_api.capture_client import CaptureClient
from superbrain.cli_api.loopback import LoopbackTarget
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import CaptureBatchCommand
from superbrain.domain.capture.outbox_rules import partition_pending_for_batch
from superbrain.ports.capture import MAX_CAPTURE_BATCH_EVENTS, CaptureBatchAck
from superbrain.storage.outbox import OutboxSpool


def _merge_acks(acks: list[CaptureBatchAck]) -> CaptureBatchAck:
    assert acks
    if len(acks) == 1:
        return acks[0]
    first = acks[0]
    committed_evs: set[int] = set()
    acked_gaps: set[int] = set()
    accepted = 0
    deduped = 0
    contiguous = 0
    disabled = False
    for ack in acks:
        committed_evs.update(ack.committed_event_sequences)
        acked_gaps.update(ack.acked_producer_gap_sequences)
        accepted += ack.accepted_count
        deduped += ack.deduped_count
        contiguous = max(contiguous, ack.contiguous_event_acked_through)
        disabled = disabled or ack.policy_disabled
    return CaptureBatchAck(
        producer_stream=first.producer_stream,
        repo_id=first.repo_id,
        checkout_id=first.checkout_id,
        committed_event_sequences=tuple(sorted(committed_evs)),
        contiguous_event_acked_through=contiguous,
        acked_producer_gap_sequences=tuple(sorted(acked_gaps)),
        accepted_count=accepted,
        deduped_count=deduped,
        policy_disabled=disabled,
    )


def drain_outbox(
    spool: OutboxSpool,
    *,
    client: CaptureClient,
    target: LoopbackTarget,
    producer_stream: str,
    repo_id: str,
    checkout_id: str,
    token: str,
    limit: int = MAX_CAPTURE_BATCH_EVENTS,
    correlation_id: str | None = None,
    deadline_ns: int | None = None,
) -> CaptureBatchAck | None:
    """Drain up to ``limit`` pending records for ``producer_stream`` and apply separated ACKs."""
    if not isinstance(spool, OutboxSpool) or not isinstance(client, CaptureClient):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    pending = spool.read_pending(limit=limit, producer_stream=producer_stream)
    if not pending:
        return None
    batches = partition_pending_for_batch(pending, max_events=min(limit, MAX_CAPTURE_BATCH_EVENTS))
    acks: list[CaptureBatchAck] = []
    for batch in batches:
        decoded_events: list[dict[str, JsonValue]] = []
        for entry in batch:
            parsed = json.loads(entry.payload_json)
            if not isinstance(parsed, dict):
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt outbox payload")
            decoded_events.append(parsed)
        cmd = CaptureBatchCommand(
            producer_stream=producer_stream,
            repo_id=repo_id,
            checkout_id=checkout_id,
            events=tuple(decoded_events),
            token=token,
            correlation_id=correlation_id,
        )
        ack = client.post_batch(target, cmd, deadline_ns=deadline_ns)
        if ack.policy_disabled:
            acks.append(ack)
            break
        spool.apply_ack(ack)
        acks.append(ack)
    return _merge_acks(acks)


__all__ = ["drain_outbox"]
