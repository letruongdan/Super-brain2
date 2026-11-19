"""Task 4c pure application ``ReadAck`` validation and idempotent persistence (C5:114-116)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    OPAQUE_ID_RE,
    ArtifactReadAck,
    Principal,
    ReadAckInput,
    ResourceDigest,
    Scope,
    SendAttemptState,
    canonicalize_resource_digests,
    is_strict_int,
    require_opaque_id,
)
from superbrain.ports.kernel import KernelPolicyPort, KernelTx

__all__ = [
    "ProjectedReadAck",
    "extract_projected_read_acks",
    "record_projected_read_acks",
    "record_read_acks",
]


@dataclass(frozen=True)
class ProjectedReadAck:
    """Post-``PrivacyFilter`` ``ReadAck`` projection deferring resource-name collision checks past auth/state."""

    served_receipt_id: str
    task_id: str
    artifact_id: str
    revision_epoch: int
    revision: int
    resource_digests: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        if not isinstance(self.served_receipt_id, str) or not isinstance(self.task_id, str):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        require_opaque_id(self.artifact_id, label="artifact_id")
        if not is_strict_int(self.revision_epoch) or self.revision_epoch < 0:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if not is_strict_int(self.revision) or self.revision < 1:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if not isinstance(self.resource_digests, tuple) or not all(
            isinstance(pair, tuple) and len(pair) == 2 and isinstance(pair[0], str) and isinstance(pair[1], str)
            for pair in self.resource_digests
        ):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")


def extract_projected_read_acks(safe_payload: Mapping[str, JsonValue]) -> tuple[ProjectedReadAck, ...]:
    """Extract post-``PrivacyFilter`` ``read_acks`` (returns ``()`` when stripped by ``manual_submission=False``)."""
    if not isinstance(safe_payload, Mapping):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    raw_acks = safe_payload.get("read_acks")
    if raw_acks is None:
        return ()
    if not isinstance(raw_acks, list):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    extracted: list[ProjectedReadAck] = []
    for raw_ack in raw_acks:
        if not isinstance(raw_ack, Mapping) or set(raw_ack) != {
            "served_receipt_id",
            "task_id",
            "artifact_id",
            "revision_epoch",
            "revision",
            "resource_digests",
        }:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        receipt_id = raw_ack["served_receipt_id"]
        task_id = raw_ack["task_id"]
        artifact_id = raw_ack["artifact_id"]
        rev_epoch = raw_ack["revision_epoch"]
        rev = raw_ack["revision"]
        raw_digests = raw_ack["resource_digests"]
        if (
            not isinstance(receipt_id, str)
            or not isinstance(task_id, str)
            or not isinstance(artifact_id, str)
            or OPAQUE_ID_RE.fullmatch(artifact_id) is None
            or type(rev_epoch) is not int
            or not is_strict_int(rev_epoch)
            or rev_epoch < 0
            or type(rev) is not int
            or not is_strict_int(rev)
            or rev < 1
            or not isinstance(raw_digests, list)
        ):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        pairs: list[tuple[str, str]] = []
        for entry in raw_digests:
            if not isinstance(entry, Mapping) or set(entry) != {"name", "digest"}:
                raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
            name = entry["name"]
            digest = entry["digest"]
            if not isinstance(name, str) or not isinstance(digest, str):
                raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
            pairs.append((name, digest))
        extracted.append(
            ProjectedReadAck(
                served_receipt_id=receipt_id,
                task_id=task_id,
                artifact_id=artifact_id,
                revision_epoch=rev_epoch,
                revision=rev,
                resource_digests=tuple(pairs),
            )
        )
    return tuple(extracted)


def _allocate_distinct_ack_id(served_receipt_id: str) -> str:
    candidate = new_id()
    while candidate == served_receipt_id:
        candidate = new_id()
    return candidate


def record_projected_read_acks(
    tx: KernelTx,
    *,
    policy: KernelPolicyPort,
    principal: Principal,
    effective_scope: Scope,
    expected_task_id: str,
    acks: Sequence[ProjectedReadAck],
    action: str = "record_outcome",
) -> tuple[ArtifactReadAck, ...]:
    """Validate and persist post-projection ``ProjectedReadAck``s inside ``tx`` (C5:114-116, I2-T4C-R01)."""
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
        if not isinstance(ack, ProjectedReadAck):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if OPAQUE_ID_RE.fullmatch(ack.served_receipt_id) is None:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")

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

        try:
            typed_digests = tuple(ResourceDigest(name=n, digest=d) for n, d in ack.resource_digests)
            ordered_digests, _ = canonicalize_resource_digests(typed_digests)
        except BrainError as err:
            if err.code is ErrorCode.INVALID_INPUT:
                raise BrainError(ErrorCode.INVALID_INPUT, "invalid input") from err
            raise

        if (
            ack.artifact_id != attempt.artifact_id
            or ack.revision_epoch != attempt.revision_epoch
            or ack.revision != attempt.revision
            or ordered_digests != attempt.resource_digests
        ):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")

        existing_ack = tx.read_read_ack_by_receipt(ack.served_receipt_id)
        if existing_ack is not None:
            if (
                existing_ack.principal_id,
                existing_ack.task_id,
                existing_ack.artifact_id,
                existing_ack.revision_epoch,
                existing_ack.revision,
                existing_ack.resource_digests,
            ) != (
                principal.principal_id,
                attempt.task_id,
                attempt.artifact_id,
                attempt.revision_epoch,
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
            artifact_id=attempt.artifact_id,
            revision_epoch=attempt.revision_epoch,
            revision=attempt.revision,
            resource_digests=ordered_digests,
        )
        tx.save_read_ack(created)
        recorded.append(created)

    return tuple(recorded)


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
    """Validate and persist client-declared ``ReadAckInput``s inside ``tx`` (C5:114-116)."""
    if not isinstance(acks, Sequence) or isinstance(acks, (str, bytes)):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    projected: list[ProjectedReadAck] = []
    for ack in acks:
        if not isinstance(ack, ReadAckInput):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        projected.append(
            ProjectedReadAck(
                served_receipt_id=ack.served_receipt_id,
                task_id=ack.task_id,
                artifact_id=ack.artifact_id,
                revision_epoch=ack.revision_epoch,
                revision=ack.revision,
                resource_digests=tuple((rd.name, rd.digest) for rd in ack.resource_digests),
            )
        )
    return record_projected_read_acks(
        tx,
        policy=policy,
        principal=principal,
        effective_scope=effective_scope,
        expected_task_id=expected_task_id,
        acks=tuple(projected),
        action=action,
    )
