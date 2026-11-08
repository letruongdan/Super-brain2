"""Task 4c pure application ``ReadAck`` validation and idempotent persistence (C5:114-116)."""

from __future__ import annotations

from collections.abc import Sequence

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.kernel import (
    ArtifactReadAck,
    Principal,
    ReadAckInput,
    Scope,
    SendAttemptState,
    canonicalize_resource_digests,
    require_opaque_id,
)
from superbrain.ports.kernel import KernelPolicyPort, KernelTx

__all__ = ["record_read_acks"]


def _allocate_distinct_ack_id(served_receipt_id: str) -> str:
    candidate = new_id()
    while candidate == served_receipt_id:
        candidate = new_id()
    return candidate


def record_read_acks(
    tx: KernelTx,
    *,
    policy: KernelPolicyPort,
    principal: Principal,
    effective_scope: Scope,
    expected_task_id: str,
    acks: Sequence[ReadAckInput],
    action: str = "record_outcome",
) -> tuple[ArtifactReadAck, ...]:
    """Validate and persist client-declared ``ReadAckInput``s inside ``tx`` (C5:114-116).

    Precedence per item:
    1. Direct PK lookup ``tx.read_send_attempt(ack.served_receipt_id)`` (``None -> NOT_FOUND``).
    2. Principal, task, durable task-binding scope, and live ``policy.allows`` BEFORE state/digest checks
       (failure -> ``NOT_FOUND``, never leaking ``IN_PROGRESS`` or ``INVALID_INPUT``).
    3. State check: ``PENDING -> IN_PROGRESS``; ``UNKNOWN -> NOT_FOUND``; only ``SERVED_ONLY`` proceeds.
    4. Exact ``revision`` and complete unique ``(name, digest)`` set (mismatch -> static ``INVALID_INPUT``).
    5. Idempotent ``UNIQUE(served_receipt_id)`` persistence reusing ``existing.ack_id`` across batches/keys.
    """
    if not isinstance(principal, Principal) or not isinstance(effective_scope, Scope):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    require_opaque_id(action, label="action")
    if effective_scope.checkout_id is None:
        raise BrainError(ErrorCode.NOT_FOUND, "not found")
    require_opaque_id(expected_task_id, label="expected_task_id")
    if not isinstance(acks, Sequence) or isinstance(acks, (str, bytes)):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if not acks:
        return ()

    if not policy.allows(principal, effective_scope, action=action):
        raise BrainError(ErrorCode.NOT_FOUND, "not found")

    recorded: list[ArtifactReadAck] = []
    for ack in acks:
        if not isinstance(ack, ReadAckInput):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")

        attempt = tx.read_send_attempt(ack.served_receipt_id)
        if attempt is None:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")

        if (
            attempt.principal_id != principal.principal_id
            or attempt.task_id != expected_task_id
            or ack.task_id != expected_task_id
        ):
            raise BrainError(ErrorCode.NOT_FOUND, "not found")

        task_binding = tx.read_task_binding(attempt.task_id)
        if task_binding is None or (
            task_binding.owner_id,
            task_binding.repo_id,
            task_binding.checkout_id,
        ) != (
            principal.owner_id,
            effective_scope.repo_id,
            effective_scope.checkout_id,
        ):
            raise BrainError(ErrorCode.NOT_FOUND, "not found")

        if attempt.state is SendAttemptState.PENDING:
            raise BrainError(ErrorCode.IN_PROGRESS, "operation in progress")
        if attempt.state is not SendAttemptState.SERVED_ONLY:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")

        ordered_digests, _ = canonicalize_resource_digests(ack.resource_digests)
        if ack.revision != attempt.revision or ordered_digests != attempt.resource_digests:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")

        existing_ack = tx.read_read_ack_by_receipt(ack.served_receipt_id)
        if existing_ack is not None:
            if (
                existing_ack.principal_id,
                existing_ack.task_id,
                existing_ack.revision,
                existing_ack.resource_digests,
            ) != (
                principal.principal_id,
                attempt.task_id,
                attempt.revision,
                attempt.resource_digests,
            ):
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
            recorded.append(existing_ack)
            continue

        created = ArtifactReadAck(
            ack_id=_allocate_distinct_ack_id(ack.served_receipt_id),
            served_receipt_id=ack.served_receipt_id,
            principal_id=principal.principal_id,
            task_id=attempt.task_id,
            revision=attempt.revision,
            resource_digests=ordered_digests,
        )
        tx.save_read_ack(created)
        recorded.append(created)

    return tuple(recorded)
