"""Pure kernel contract types shared across Super-brain2 layers."""

from __future__ import annotations

import copy
from collections.abc import Mapping
from dataclasses import dataclass

from superbrain.core._json_parse import parse_json
from superbrain.core._kernel_auth import (
    AuthSnapshot,
    BootstrapAuthorization,
    CredentialRecord,
    DaemonConfig,
    DirectRefRecord,
    RepoPolicy,
    ResolvedCredential,
    TlsMaterial,
    TrustedLocator,
    VerifiedServerTls,
    WorkspaceBinding,
    WorkspaceRegistration,
    is_trusted_bootstrap_issuer,
    parse_bearer_token,
    verify_secret_digest,
)
from superbrain.core._kernel_base import (
    GLOBAL_SCOPELESS_ACTIONS,
    IDEMPOTENCY_KEY_PATTERN,
    IDEMPOTENCY_KEY_RE,
    OBJECT_KIND_PATTERN,
    OBJECT_KIND_RE,
    OPAQUE_ID_PATTERN,
    OPAQUE_ID_RE,
    SHA256_DIGEST_PATTERN,
    SHA256_DIGEST_RE,
    WORKSPACE_HINT_PATTERN,
    WORKSPACE_HINT_RE,
    Identity,
    LineagedField,
    LineageRef,
    LineageSet,
    ObjectRef,
    Principal,
    ResourceDigest,
    Scope,
    SnapshotStatus,
    is_registrable_alias,
    is_strict_int,
    require_object_kind,
    require_opaque_id,
    require_positive_int,
    require_sha256_digest,
    require_workspace_alias,
    require_workspace_hint,
)
from superbrain.core._kernel_deadlines import (
    HANDLER_RESERVE_NS,
    RESPONSE_RESERVE_NS,
    TOTAL_REQUEST_BUDGET_NS,
    QueuedKernelRequest,
    RequestDeadlines,
    ReservationPhase,
    ReservationScopeKey,
)
from superbrain.core._kernel_dispatch import (
    IDEMPOTENCY_CLOCK_HWM_META_KEY,
    IDEMPOTENCY_CLOCK_UNTRUSTED_CODE,
    IDEMPOTENCY_TTL,
    REDACTED_REASON_DEFAULT,
    CallResult,
    IdempotencyRow,
    PrivateRequestAuth,
    RequestAuthView,
    StagedBlob,
    parse_canonical_utc,
    require_aware_utc,
)
from superbrain.core._kernel_jobs import (
    DEAD_LETTER_RETENTION,
    MAX_JOB_ATTEMPTS,
    RECOVERY_BATCH,
    TERMINAL_JOB_STATES,
    AccountingStatus,
    InvocationRecord,
    InvocationState,
    JobErrorCode,
    JobLease,
    JobOutcome,
    JobRecord,
    JobRef,
    JobSpec,
    JobState,
    JobView,
    RecoveryCounts,
    UsageRecord,
    UsageReservation,
    WorkerCommand,
    WorkerCompleted,
    WorkerFailed,
    WorkerUsage,
    accounting_status_of,
    decode_result_descriptor,
    require_decimal,
    reservation_descriptor,
    result_descriptor,
    retry_backoff,
    usage_descriptor,
)
from superbrain.core._kernel_send_attempts import (
    ArtifactReadAck,
    ArtifactSendAttempt,
    ArtifactSendSpec,
    SendAttemptCompletion,
    SendAttemptState,
    canonicalize_resource_digests,
    decode_resource_digests_json,
)
from superbrain.core._kernel_workspace import (
    COMMIT_RESERVE_NS,
    DEFAULT_BLOCKED_PATH_PATTERNS,
    DEFAULT_SENSITIVE_KEYS,
    DEFAULT_STRUCTURAL_ID_FIELDS,
    LOCAL_PHASE_BUDGET_NS,
    SNAPSHOT_DEGRADED_CODES,
    DeliveryItem,
    FieldLineage,
    FilterPolicy,
    KernelRecord,
    LabeledDelivery,
    MirrorCandidate,
    RepoFlags,
    SafePayload,
    SelectorPath,
    SelectorReason,
    SnapshotDescriptor,
    SnapshotObservation,
    SourceSnapshot,
    TaskBinding,
    binding_identity_digest,
    binding_lineage_ref,
    field_path_descriptor,
    field_path_digest,
    require_canonical_timestamp,
    require_uuid,
)
from superbrain.core.canonical import canonical_json
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue


@dataclass(frozen=True)
class Call:
    tool: str
    arguments: dict[str, JsonValue]
    correlation_id: str | None
    selected_scope: Scope | None

    def __post_init__(self) -> None:
        if not isinstance(self.tool, str) or not self.tool:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if not isinstance(self.arguments, dict):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if self.correlation_id is not None:
            if not isinstance(self.correlation_id, str) or not (1 <= len(self.correlation_id.encode("utf-8")) <= 128):
                raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if self.selected_scope is not None and not isinstance(self.selected_scope, Scope):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")


@dataclass(frozen=True)
class CallContext:
    principal: Principal
    identity: Identity
    deadline_ns: int
    selected_scope: Scope | None
    local_deadline_ns: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.principal, Principal) or not isinstance(self.identity, Identity):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if isinstance(self.deadline_ns, bool) or type(self.deadline_ns) is not int:
            raise BrainError(ErrorCode.INVALID_INPUT, "boolean not allowed for integer")
        if self.selected_scope is not None and not isinstance(self.selected_scope, Scope):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if self.local_deadline_ns is not None and (
            isinstance(self.local_deadline_ns, bool) or type(self.local_deadline_ns) is not int
        ):
            raise BrainError(ErrorCode.INVALID_INPUT, "boolean not allowed for integer")


@dataclass(frozen=True)
class StoredResult:
    """Durable idempotent result descriptor: IDs and typed ObjectRefs only, never raw body."""

    result_id: str
    assignment_id: str | None
    refs: tuple[ObjectRef, ...] = ()

    def __post_init__(self) -> None:
        require_opaque_id(self.result_id, label="result_id")
        if self.assignment_id is not None:
            require_opaque_id(self.assignment_id, label="assignment_id")
        if not isinstance(self.refs, tuple) or not all(isinstance(r, ObjectRef) for r in self.refs):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")

    def encode_refs_json(self) -> str:
        return canonical_json([ref.to_dict() for ref in self.refs]).decode("utf-8")

    @staticmethod
    def decode_refs_json(raw: str) -> tuple[ObjectRef, ...]:
        if not isinstance(raw, str):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        try:
            raw_bytes = raw.encode("utf-8", errors="strict")
        except UnicodeEncodeError as err:
            raise BrainError(ErrorCode.INVALID_INPUT, "unpaired surrogate") from err
        parsed = parse_json(raw_bytes)
        if not isinstance(parsed, list):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        refs: list[ObjectRef] = []
        for item in parsed:
            if not isinstance(item, Mapping):
                raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
            refs.append(ObjectRef.from_dict(item))
        return tuple(refs)

    def encode_canonical(self) -> bytes:
        payload: dict[str, JsonValue] = {
            "result_id": self.result_id,
            "assignment_id": self.assignment_id,
            "refs": [ref.to_dict() for ref in self.refs],
        }
        return canonical_json(payload)

    @classmethod
    def from_canonical(cls, raw: bytes) -> StoredResult:
        parsed = parse_json(raw)
        if not isinstance(parsed, dict) or set(parsed) != {"result_id", "assignment_id", "refs"}:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        raw_assignment = parsed["assignment_id"]
        if raw_assignment is not None and not isinstance(raw_assignment, str):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        raw_refs = parsed["refs"]
        if not isinstance(raw_refs, list):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        refs: list[ObjectRef] = []
        for item in raw_refs:
            if not isinstance(item, Mapping):
                raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
            refs.append(ObjectRef.from_dict(item))
        return cls(
            result_id=require_opaque_id(parsed["result_id"], label="result_id"),
            assignment_id=raw_assignment,
            refs=tuple(refs),
        )


@dataclass(frozen=True)
class ReadAckInput:
    served_receipt_id: str
    task_id: str
    revision: int
    resource_digests: tuple[ResourceDigest, ...]

    def __post_init__(self) -> None:
        require_opaque_id(self.served_receipt_id, label="served_receipt_id")
        require_opaque_id(self.task_id, label="task_id")
        require_positive_int(self.revision)
        if (
            not isinstance(self.resource_digests, tuple)
            or not self.resource_digests
            or len(self.resource_digests) > 1024
            or not all(isinstance(d, ResourceDigest) for d in self.resource_digests)
        ):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        names = [d.name for d in self.resource_digests]
        if len(set(names)) != len(names):
            raise BrainError(ErrorCode.INVALID_INPUT, "duplicate resource digest name")

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "served_receipt_id": self.served_receipt_id,
            "task_id": self.task_id,
            "revision": self.revision,
            "resource_digests": [d.to_dict() for d in self.resource_digests],
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, JsonValue]) -> ReadAckInput:
        expected = {"served_receipt_id", "task_id", "revision", "resource_digests"}
        if not isinstance(raw, Mapping) or set(raw) != expected:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        raw_digests = raw["resource_digests"]
        if not isinstance(raw_digests, list):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        digests: list[ResourceDigest] = []
        for item in raw_digests:
            if not isinstance(item, Mapping):
                raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
            digests.append(ResourceDigest.from_dict(item))
        return cls(
            served_receipt_id=require_opaque_id(raw["served_receipt_id"]),
            task_id=require_opaque_id(raw["task_id"]),
            revision=require_positive_int(raw["revision"]),
            resource_digests=tuple(digests),
        )


@dataclass(frozen=True)
class WorkspaceSelector:
    """Normalized daemon workspace selector (either ``(workspace_id, checkout_id)`` or ``workspace_hint``)."""

    workspace_id: str | None = None
    checkout_id: str | None = None
    workspace_hint: str | None = None
    source_snapshot_id: str | None = None

    def __post_init__(self) -> None:
        has_hint = self.workspace_hint is not None
        has_ws = self.workspace_id is not None
        has_chk = self.checkout_id is not None
        if not ((has_hint and not has_ws and not has_chk) or (not has_hint and has_ws and has_chk)):
            raise BrainError(ErrorCode.INVALID_INPUT, "mixed or invalid workspace selector")
        if self.workspace_hint is not None:
            require_workspace_hint(self.workspace_hint)
        if self.workspace_id is not None and self.checkout_id is not None:
            require_opaque_id(self.workspace_id, label="workspace_id")
            require_opaque_id(self.checkout_id, label="checkout_id")
        if self.source_snapshot_id is not None:
            require_opaque_id(self.source_snapshot_id, label="source_snapshot_id")


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    contract: str
    tokenizer: str
    side_effects: str
    is_async: bool
    implemented_in: str
    client_input_ref: str
    daemon_input_ref: str
    result_ref: str
    input_schema: dict[str, JsonValue]
    output_schema: dict[str, JsonValue]

    def to_mcp_tool(self) -> dict[str, JsonValue]:
        """Self-contained MCP ``tools/list`` entry with transitive ``$defs`` closure."""
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": copy.deepcopy(self.input_schema),
            "outputSchema": copy.deepcopy(self.output_schema),
            "x-contract": self.contract,
            "x-tokenizer": self.tokenizer,
            "x-side-effects": self.side_effects,
            "x-async": self.is_async,
            "x-implemented-in": self.implemented_in,
        }


@dataclass(frozen=True)
class ToolCatalog:
    contract: str
    schema_id: str
    tokenizer: str
    resolution: str
    schema_sha256: str
    schema_digest: str
    raw_bytes: bytes
    schema: dict[str, JsonValue]
    tools: Mapping[str, ToolSpec]

    def mcp_tools_list(self) -> list[dict[str, JsonValue]]:
        return [spec.to_mcp_tool() for spec in self.tools.values()]


__all__ = [
    "AccountingStatus",
    "ArtifactReadAck",
    "ArtifactSendAttempt",
    "ArtifactSendSpec",
    "AuthSnapshot",
    "BootstrapAuthorization",
    "COMMIT_RESERVE_NS",
    "Call",
    "CallContext",
    "CallResult",
    "CredentialRecord",
    "DEAD_LETTER_RETENTION",
    "DEFAULT_BLOCKED_PATH_PATTERNS",
    "DEFAULT_SENSITIVE_KEYS",
    "DEFAULT_STRUCTURAL_ID_FIELDS",
    "DaemonConfig",
    "DeliveryItem",
    "DirectRefRecord",
    "FieldLineage",
    "FilterPolicy",
    "GLOBAL_SCOPELESS_ACTIONS",
    "HANDLER_RESERVE_NS",
    "IDEMPOTENCY_CLOCK_HWM_META_KEY",
    "IDEMPOTENCY_CLOCK_UNTRUSTED_CODE",
    "IDEMPOTENCY_KEY_PATTERN",
    "IDEMPOTENCY_KEY_RE",
    "IDEMPOTENCY_TTL",
    "IdempotencyRow",
    "Identity",
    "InvocationRecord",
    "InvocationState",
    "JobErrorCode",
    "JobLease",
    "JobOutcome",
    "JobRecord",
    "JobRef",
    "JobSpec",
    "JobState",
    "JobView",
    "KernelRecord",
    "LOCAL_PHASE_BUDGET_NS",
    "LabeledDelivery",
    "LineageRef",
    "LineageSet",
    "LineagedField",
    "MAX_JOB_ATTEMPTS",
    "MirrorCandidate",
    "OBJECT_KIND_PATTERN",
    "OBJECT_KIND_RE",
    "OPAQUE_ID_PATTERN",
    "OPAQUE_ID_RE",
    "ObjectRef",
    "Principal",
    "PrivateRequestAuth",
    "QueuedKernelRequest",
    "RECOVERY_BATCH",
    "REDACTED_REASON_DEFAULT",
    "RESPONSE_RESERVE_NS",
    "ReadAckInput",
    "RecoveryCounts",
    "RepoFlags",
    "RepoPolicy",
    "RequestAuthView",
    "RequestDeadlines",
    "ReservationPhase",
    "ReservationScopeKey",
    "ResolvedCredential",
    "ResourceDigest",
    "SHA256_DIGEST_PATTERN",
    "SHA256_DIGEST_RE",
    "SNAPSHOT_DEGRADED_CODES",
    "SafePayload",
    "Scope",
    "SelectorPath",
    "SelectorReason",
    "SendAttemptCompletion",
    "SendAttemptState",
    "SnapshotDescriptor",
    "SnapshotObservation",
    "SnapshotStatus",
    "SourceSnapshot",
    "StagedBlob",
    "StoredResult",
    "TERMINAL_JOB_STATES",
    "TOTAL_REQUEST_BUDGET_NS",
    "TaskBinding",
    "TlsMaterial",
    "ToolCatalog",
    "ToolSpec",
    "TrustedLocator",
    "UsageRecord",
    "UsageReservation",
    "VerifiedServerTls",
    "WORKSPACE_HINT_PATTERN",
    "WORKSPACE_HINT_RE",
    "WorkerCommand",
    "WorkerCompleted",
    "WorkerFailed",
    "WorkerUsage",
    "WorkspaceBinding",
    "WorkspaceRegistration",
    "WorkspaceSelector",
    "accounting_status_of",
    "binding_identity_digest",
    "binding_lineage_ref",
    "canonicalize_resource_digests",
    "decode_resource_digests_json",
    "decode_result_descriptor",
    "field_path_descriptor",
    "field_path_digest",
    "is_registrable_alias",
    "is_strict_int",
    "is_trusted_bootstrap_issuer",
    "parse_bearer_token",
    "parse_canonical_utc",
    "require_aware_utc",
    "require_canonical_timestamp",
    "require_decimal",
    "require_object_kind",
    "require_opaque_id",
    "require_positive_int",
    "require_sha256_digest",
    "require_uuid",
    "require_workspace_alias",
    "require_workspace_hint",
    "reservation_descriptor",
    "result_descriptor",
    "retry_backoff",
    "usage_descriptor",
    "verify_secret_digest",
]
