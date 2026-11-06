"""Pure kernel contract types shared across Super-brain2 layers."""

from __future__ import annotations

import copy
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TypeAlias

from superbrain.core._json_parse import parse_json
from superbrain.core.canonical import canonical_json, validate_json
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue

OPAQUE_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
OBJECT_KIND_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"
WORKSPACE_HINT_PATTERN = r"^[A-Za-z0-9._-]{1,128}$"
IDEMPOTENCY_KEY_PATTERN = r"^[A-Za-z0-9_-]{16,128}$"
SHA256_DIGEST_PATTERN = r"^sha256:[0-9a-f]{64}$"

OPAQUE_ID_RE = re.compile(OPAQUE_ID_PATTERN)
OBJECT_KIND_RE = re.compile(OBJECT_KIND_PATTERN)
WORKSPACE_HINT_RE = re.compile(WORKSPACE_HINT_PATTERN)
IDEMPOTENCY_KEY_RE = re.compile(IDEMPOTENCY_KEY_PATTERN)
SHA256_DIGEST_RE = re.compile(SHA256_DIGEST_PATTERN)


def is_strict_int(value: object) -> bool:
    """True for ``int`` excluding ``bool``."""
    return type(value) is int


def require_opaque_id(value: object, *, label: str = "id") -> str:
    if not isinstance(value, str) or not OPAQUE_ID_RE.fullmatch(value):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    return value


def require_object_kind(value: object) -> str:
    if not isinstance(value, str) or not OBJECT_KIND_RE.fullmatch(value):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    return value


def require_workspace_hint(value: object) -> str:
    if (
        not isinstance(value, str)
        or not WORKSPACE_HINT_RE.fullmatch(value)
        or value in {".", ".."}
        or ".." in value
    ):
        raise BrainError(ErrorCode.INVALID_INPUT, "mixed or invalid workspace selector")
    return value


def require_sha256_digest(value: object) -> str:
    if not isinstance(value, str) or not SHA256_DIGEST_RE.fullmatch(value):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    return value


def require_positive_int(value: object) -> int:
    if isinstance(value, bool):
        raise BrainError(ErrorCode.INVALID_INPUT, "boolean not allowed for integer")
    if type(value) is not int or value < 1:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    return value


class JobState(StrEnum):
    QUEUED = "queued"
    LEASED = "leased"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    DEAD_LETTER = "dead_letter"


class AccountingStatus(StrEnum):
    NONE = "none"
    RESERVED = "reserved"
    SETTLED = "settled"
    OUTCOME_UNKNOWN = "outcome_unknown"


class SnapshotStatus(StrEnum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    DEADLINE = "deadline"


@dataclass(frozen=True)
class Principal:
    principal_id: str
    owner_id: str
    harness_id: str
    machine_id: str

    def __post_init__(self) -> None:
        require_opaque_id(self.principal_id, label="principal_id")
        require_opaque_id(self.owner_id, label="owner_id")
        require_opaque_id(self.harness_id, label="harness_id")
        require_opaque_id(self.machine_id, label="machine_id")


@dataclass(frozen=True)
class Scope:
    repo_id: str
    checkout_id: str | None = None

    def __post_init__(self) -> None:
        require_opaque_id(self.repo_id, label="repo_id")
        if self.checkout_id is not None:
            require_opaque_id(self.checkout_id, label="checkout_id")

    def to_dict(self) -> dict[str, JsonValue]:
        return {"repo_id": self.repo_id, "checkout_id": self.checkout_id}


@dataclass(frozen=True)
class ObjectRef:
    kind: str
    id: str
    revision: int
    digest: str

    def __post_init__(self) -> None:
        require_object_kind(self.kind)
        require_opaque_id(self.id)
        require_positive_int(self.revision)
        require_sha256_digest(self.digest)

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "kind": self.kind,
            "id": self.id,
            "revision": self.revision,
            "digest": self.digest,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, JsonValue]) -> ObjectRef:
        if not isinstance(raw, Mapping) or set(raw) != {"kind", "id", "revision", "digest"}:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        return cls(
            kind=require_object_kind(raw["kind"]),
            id=require_opaque_id(raw["id"]),
            revision=require_positive_int(raw["revision"]),
            digest=require_sha256_digest(raw["digest"]),
        )


@dataclass(frozen=True)
class Identity:
    store_id: str
    writer_epoch: int
    instance_id: str

    def __post_init__(self) -> None:
        require_opaque_id(self.store_id, label="store_id")
        require_positive_int(self.writer_epoch)
        require_opaque_id(self.instance_id, label="instance_id")


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

    def __post_init__(self) -> None:
        if not isinstance(self.principal, Principal) or not isinstance(self.identity, Identity):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if isinstance(self.deadline_ns, bool) or type(self.deadline_ns) is not int:
            raise BrainError(ErrorCode.INVALID_INPUT, "boolean not allowed for integer")
        if self.selected_scope is not None and not isinstance(self.selected_scope, Scope):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")


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
class LineageRef:
    owner_id: str
    repo_id: str
    source: ObjectRef

    def __post_init__(self) -> None:
        require_opaque_id(self.owner_id, label="owner_id")
        require_opaque_id(self.repo_id, label="repo_id")
        if not isinstance(self.source, ObjectRef):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")


LineageSet: TypeAlias = frozenset[LineageRef]


@dataclass(frozen=True)
class LineagedField:
    value: JsonValue
    sources: frozenset[LineageRef] = field(default_factory=frozenset)
    unknown_source: bool = False

    def __post_init__(self) -> None:
        validate_json(self.value)
        if not isinstance(self.sources, frozenset) or not all(isinstance(s, LineageRef) for s in self.sources):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if not isinstance(self.unknown_source, bool):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")


@dataclass(frozen=True)
class ResourceDigest:
    name: str
    digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not (1 <= len(self.name) <= 256):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        try:
            self.name.encode("utf-8")
        except UnicodeEncodeError as err:
            raise BrainError(ErrorCode.INVALID_INPUT, "unpaired surrogate") from err
        require_sha256_digest(self.digest)

    def to_dict(self) -> dict[str, JsonValue]:
        return {"name": self.name, "digest": self.digest}

    @classmethod
    def from_dict(cls, raw: Mapping[str, JsonValue]) -> ResourceDigest:
        if not isinstance(raw, Mapping) or set(raw) != {"name", "digest"}:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        name, digest = raw["name"], raw["digest"]
        if not isinstance(name, str) or not isinstance(digest, str):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        return cls(name=name, digest=digest)


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


from superbrain.core._kernel_auth import (  # noqa: E402
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

__all__ = [
    "AccountingStatus",
    "AuthSnapshot",
    "BootstrapAuthorization",
    "Call",
    "CallContext",
    "CredentialRecord",
    "DaemonConfig",
    "DirectRefRecord",
    "IDEMPOTENCY_KEY_PATTERN",
    "IDEMPOTENCY_KEY_RE",
    "Identity",
    "JobState",
    "LineageRef",
    "LineageSet",
    "LineagedField",
    "OBJECT_KIND_PATTERN",
    "OBJECT_KIND_RE",
    "OPAQUE_ID_PATTERN",
    "OPAQUE_ID_RE",
    "ObjectRef",
    "Principal",
    "ReadAckInput",
    "RepoPolicy",
    "ResolvedCredential",
    "ResourceDigest",
    "SHA256_DIGEST_PATTERN",
    "SHA256_DIGEST_RE",
    "Scope",
    "SnapshotStatus",
    "StoredResult",
    "TlsMaterial",
    "ToolCatalog",
    "ToolSpec",
    "TrustedLocator",
    "VerifiedServerTls",
    "WORKSPACE_HINT_PATTERN",
    "WORKSPACE_HINT_RE",
    "WorkspaceBinding",
    "WorkspaceRegistration",
    "WorkspaceSelector",
    "is_strict_int",
    "is_trusted_bootstrap_issuer",
    "parse_bearer_token",
    "require_object_kind",
    "require_opaque_id",
    "require_positive_int",
    "require_sha256_digest",
    "require_workspace_hint",
    "verify_secret_digest",
]
