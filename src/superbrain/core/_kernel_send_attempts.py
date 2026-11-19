"""Task 4c pure kernel types: durable artifact send attempts vs client-declared ReadAcks (C5)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum

from superbrain.core._json_parse import parse_json
from superbrain.core._kernel_base import (
    Identity,
    ResourceDigest,
    require_non_negative_int,
    require_opaque_id,
    require_positive_int,
)
from superbrain.core._kernel_workspace import require_uuid
from superbrain.core.canonical import canonical_json
from superbrain.core.errors import BrainError, ErrorCode

ARTIFACT_LEVEL_UNKNOWN = "unknown"
_VALID_ARTIFACT_LEVELS: frozenset[str] = frozenset({"L0", "L1", "L2"})
_VALID_STORED_ARTIFACT_LEVELS: frozenset[str] = _VALID_ARTIFACT_LEVELS | {ARTIFACT_LEVEL_UNKNOWN}


def _require_artifact_level(value: object) -> str:
    if not isinstance(value, str) or value not in _VALID_ARTIFACT_LEVELS:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    return value


def _require_stored_artifact_level(value: object) -> str:
    if not isinstance(value, str) or value not in _VALID_STORED_ARTIFACT_LEVELS:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    return value


class SendAttemptState(StrEnum):
    """Durable state of an ``artifact_send_attempt`` row (C5:112)."""

    PENDING = "pending"
    UNKNOWN = "unknown"
    SERVED_ONLY = "served_only"


def canonicalize_resource_digests(digests: Sequence[ResourceDigest]) -> tuple[tuple[ResourceDigest, ...], str]:
    """Validate unique-named ``ResourceDigest`` items (`1..1024`), sort by ``name``, and encode canonically."""
    if (
        not isinstance(digests, Sequence)
        or isinstance(digests, (str, bytes))
        or not digests
        or len(digests) > 1024
        or not all(isinstance(item, ResourceDigest) for item in digests)
    ):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    names = [item.name for item in digests]
    if len(set(names)) != len(names):
        raise BrainError(ErrorCode.INVALID_INPUT, "duplicate resource digest name")
    ordered = tuple(sorted(digests, key=lambda item: item.name))
    encoded = canonical_json([item.to_dict() for item in ordered]).decode("utf-8")
    return ordered, encoded


def decode_resource_digests_json(raw_json: str) -> tuple[ResourceDigest, ...]:
    """Decode and verify canonical sorted ``ResourceDigest`` JSON stored in ``store4`` operational tables."""
    if not isinstance(raw_json, str):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
    try:
        raw_bytes = raw_json.encode("utf-8", errors="strict")
    except UnicodeEncodeError as err:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure") from err
    try:
        parsed = parse_json(raw_bytes)
    except BrainError as err:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure") from err
    if not isinstance(parsed, list) or not parsed or len(parsed) > 1024:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
    items: list[ResourceDigest] = []
    for elem in parsed:
        if not isinstance(elem, Mapping):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
        try:
            items.append(ResourceDigest.from_dict(elem))
        except BrainError as err:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure") from err
    try:
        ordered, expected_json = canonicalize_resource_digests(items)
    except BrainError as err:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure") from err
    if tuple(items) != ordered or expected_json != raw_json:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
    return ordered


@dataclass(frozen=True)
class ArtifactSendSpec:
    """Immutable subject of one permitted artifact-content send before minting ``send_attempt_id``."""

    logical_result_id: str
    principal_id: str
    task_id: str
    artifact_id: str
    revision: int
    resource_digests: tuple[ResourceDigest, ...]
    level: str = "L1"
    revision_epoch: int = 0

    def __post_init__(self) -> None:
        require_opaque_id(self.logical_result_id, label="logical_result_id")
        require_opaque_id(self.principal_id, label="principal_id")
        require_opaque_id(self.task_id, label="task_id")
        require_opaque_id(self.artifact_id, label="artifact_id")
        require_positive_int(self.revision)
        if not isinstance(self.resource_digests, tuple):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        ordered, _ = canonicalize_resource_digests(self.resource_digests)
        object.__setattr__(self, "resource_digests", ordered)
        _require_artifact_level(self.level)
        require_non_negative_int(self.revision_epoch)


@dataclass(frozen=True)
class ArtifactSendAttempt:
    """Durable ``artifact_send_attempt`` row where ``served_receipt_id == send_attempt_id`` (C5:111)."""

    send_attempt_id: str
    logical_result_id: str
    principal_id: str
    task_id: str
    artifact_id: str
    revision: int
    resource_digests: tuple[ResourceDigest, ...]
    state: SendAttemptState
    level: str = "L1"
    revision_epoch: int = 0

    def __post_init__(self) -> None:
        require_uuid(self.send_attempt_id)
        require_opaque_id(self.logical_result_id, label="logical_result_id")
        require_opaque_id(self.principal_id, label="principal_id")
        require_opaque_id(self.task_id, label="task_id")
        require_opaque_id(self.artifact_id, label="artifact_id")
        require_positive_int(self.revision)
        if not isinstance(self.resource_digests, tuple):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        ordered, _ = canonicalize_resource_digests(self.resource_digests)
        object.__setattr__(self, "resource_digests", ordered)
        if not isinstance(self.state, SendAttemptState):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        _require_stored_artifact_level(self.level)
        require_non_negative_int(self.revision_epoch)

    @property
    def served_receipt_id(self) -> str:
        """Selected identity (C5:111): ``served_receipt_id == send_attempt_id == artifact_send_attempt.id``."""
        return self.send_attempt_id


def is_verified_l1_send(attempt: ArtifactSendAttempt) -> bool:
    """Return True iff ``attempt`` is a flushed ``SERVED_ONLY`` receipt durably recorded as ``L1``."""
    return (
        isinstance(attempt, ArtifactSendAttempt)
        and attempt.state is SendAttemptState.SERVED_ONLY
        and attempt.level == "L1"
    )


@dataclass(frozen=True)
class SendAttemptCompletion:
    """Internal owner flush-completion proof fenced to exact subject and ``Identity`` (C5:113)."""

    send_attempt_id: str
    logical_result_id: str
    principal_id: str
    task_id: str
    artifact_id: str
    revision: int
    resource_digests: tuple[ResourceDigest, ...]
    identity: Identity
    level: str = "L1"
    revision_epoch: int = 0

    def __post_init__(self) -> None:
        require_uuid(self.send_attempt_id)
        require_opaque_id(self.logical_result_id, label="logical_result_id")
        require_opaque_id(self.principal_id, label="principal_id")
        require_opaque_id(self.task_id, label="task_id")
        require_opaque_id(self.artifact_id, label="artifact_id")
        require_positive_int(self.revision)
        if not isinstance(self.resource_digests, tuple):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        ordered, _ = canonicalize_resource_digests(self.resource_digests)
        object.__setattr__(self, "resource_digests", ordered)
        if not isinstance(self.identity, Identity):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        _require_stored_artifact_level(self.level)
        require_non_negative_int(self.revision_epoch)


@dataclass(frozen=True)
class ArtifactReadAck:
    """Durable client-declared ``artifact_read_ack`` row with distinct ``ack_id != served_receipt_id`` (C5:115)."""

    ack_id: str
    served_receipt_id: str
    principal_id: str
    task_id: str
    artifact_id: str
    revision: int
    resource_digests: tuple[ResourceDigest, ...]
    revision_epoch: int = 0

    def __post_init__(self) -> None:
        require_uuid(self.ack_id)
        require_uuid(self.served_receipt_id)
        if self.ack_id == self.served_receipt_id:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
        require_opaque_id(self.principal_id, label="principal_id")
        require_opaque_id(self.task_id, label="task_id")
        require_opaque_id(self.artifact_id, label="artifact_id")
        require_positive_int(self.revision)
        if not isinstance(self.resource_digests, tuple):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        ordered, _ = canonicalize_resource_digests(self.resource_digests)
        object.__setattr__(self, "resource_digests", ordered)
        require_non_negative_int(self.revision_epoch)
