"""Pure Task 3 kernel types: snapshots, privacy filter policy, safe payloads, lineage records, labeled delivery.

Re-exported by ``core.kernel``; imports only ``core._kernel_base``/``core._kernel_auth`` leaves (no cycle).
"""

from __future__ import annotations

import math
import re
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Literal

from superbrain.core._kernel_auth import RepoPolicy, WorkspaceBinding
from superbrain.core._kernel_base import (
    LineageRef,
    LineageSet,
    ObjectRef,
    SnapshotStatus,
    is_strict_int,
    require_opaque_id,
    require_sha256_digest,
    require_workspace_alias,
)
from superbrain.core.canonical import canonical_json, digest_bytes, validate_json
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue

LOCAL_PHASE_BUDGET_NS = 100_000_000
"""Shared local budget for admission, privacy filtering and optional snapshot observation (D5)."""
COMMIT_RESERVE_NS = 200_000_000
"""Final window of the total deadline reserved for commit and response (D5)."""

SNAPSHOT_DEGRADED_CODES: Mapping[SnapshotStatus, str] = MappingProxyType(
    {SnapshotStatus.UNAVAILABLE: "snapshot_unavailable", SnapshotStatus.DEADLINE: "snapshot_deadline"}
)

DEFAULT_SENSITIVE_KEYS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "bearer",
        "authorization",
        "private_key",
        "client_secret",
        "credential",
        "cookie",
        "set-cookie",
        "session_token",
        "pwd",
        "token",
        "auth_token",
        "x-auth-token",
        "x-api-key",
        "passphrase",
        "passwords",
        "secrets",
        "credentials",
        "cookies",
        "signing_key",
        "encryption_key",
        "master_key",
        "ssh_key",
        "api_token",
        "apitoken",
        "github_token",
        "githubtoken",
    }
)
DEFAULT_BLOCKED_PATH_PATTERNS: tuple[str, ...] = (
    ".env",
    ".env.*",
    ".ssh/",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    ".aws/credentials",
    ".npmrc",
    ".pypirc",
    ".netrc",
    "_netrc",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
)
# ``session_id`` is deliberately absent: session tokens are classic secrets (fix round 2 ruling).
DEFAULT_STRUCTURAL_ID_FIELDS: frozenset[str] = frozenset(
    {
        "id",
        "task_id",
        "delivery_id",
        "assignment_id",
        "outcome_id",
        "episode_id",
        "workspace_id",
        "checkout_id",
        "source_snapshot_id",
        "served_receipt_id",
        "artifact_id",
        "job_id",
        "candidate_lesson_id",
        "digest",
        "revision",
    }
)

_TIMESTAMP_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z")
_KIND_NAME_RE = re.compile(r"[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+")
_ACTOR_RE = re.compile(r"(user|system|principal):[a-z0-9][a-z0-9._:-]{0,63}")
_PATH_SEGMENT_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_MAX_FIELD_PATH_DEPTH = 32


def _invalid() -> BrainError:
    return BrainError(ErrorCode.INVALID_INPUT, "invalid input")


def _require_bool(value: object) -> bool:
    if type(value) is not bool:
        raise _invalid()
    return value


def require_canonical_timestamp(value: object) -> str:
    """Require the canonical fixed-width UTC timestamp spelling ``YYYY-MM-DDTHH:MM:SS.ffffffZ``."""
    if not isinstance(value, str) or _TIMESTAMP_RE.fullmatch(value) is None:
        raise _invalid()
    return value


def require_uuid(value: object) -> str:
    if not isinstance(value, str):
        raise _invalid()
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        parsed = None
    if parsed is None or str(parsed) != value:
        raise _invalid()
    return value


def _require_lineage_set(value: object) -> LineageSet:
    if not isinstance(value, frozenset) or not all(isinstance(ref, LineageRef) for ref in value):
        raise _invalid()
    return value


@dataclass(frozen=True)
class SnapshotDescriptor:
    """Safe, content-only description of an observed checkout state; never raw paths or file bytes."""

    kind: Literal["git", "directory"]
    tree_or_head_digest: str
    dirty: bool
    dirty_digest: str | None
    observed_at: str

    def __post_init__(self) -> None:
        if self.kind not in ("git", "directory"):
            raise _invalid()
        require_sha256_digest(self.tree_or_head_digest)
        _require_bool(self.dirty)
        if self.dirty:
            require_sha256_digest(self.dirty_digest)
        elif self.dirty_digest is not None:
            raise _invalid()
        require_canonical_timestamp(self.observed_at)

    def content_bytes(self) -> bytes:
        """Canonical content descriptor (excludes ``observed_at``): the CAS blob and ``descriptor_digest`` source."""
        payload: dict[str, JsonValue] = {
            "kind": self.kind,
            "tree_or_head_digest": self.tree_or_head_digest,
            "dirty": self.dirty,
            "dirty_digest": self.dirty_digest,
        }
        return canonical_json(payload)

    @property
    def descriptor_digest(self) -> str:
        return digest_bytes(self.content_bytes())


@dataclass(frozen=True)
class SnapshotObservation:
    """``AVAILABLE`` iff a descriptor is present; ``UNAVAILABLE``/``DEADLINE`` iff it is absent."""

    status: SnapshotStatus
    descriptor: SnapshotDescriptor | None

    def __post_init__(self) -> None:
        if type(self.status) is not SnapshotStatus:
            raise _invalid()
        if self.status is SnapshotStatus.AVAILABLE:
            if not isinstance(self.descriptor, SnapshotDescriptor):
                raise _invalid()
        elif self.descriptor is not None:
            raise _invalid()


@dataclass(frozen=True)
class FilterPolicy:
    blocked_path_patterns: tuple[str, ...] = DEFAULT_BLOCKED_PATH_PATTERNS
    sensitive_keys: frozenset[str] = DEFAULT_SENSITIVE_KEYS
    entropy_min_length: int = 24
    entropy_min_bits: float = 4.0
    manual_submission: bool = True
    structural_id_fields: frozenset[str] = DEFAULT_STRUCTURAL_ID_FIELDS

    def __post_init__(self) -> None:
        for name in ("blocked_path_patterns", "sensitive_keys", "structural_id_fields"):
            values = getattr(self, name)
            expected = tuple if name == "blocked_path_patterns" else frozenset
            if not isinstance(values, expected) or not all(isinstance(v, str) and v for v in values):
                raise _invalid()
        if not is_strict_int(self.entropy_min_length) or not (8 <= self.entropy_min_length <= 4096):
            raise _invalid()
        bits = self.entropy_min_bits
        if isinstance(bits, bool) or not isinstance(bits, (int, float)) or not math.isfinite(bits):
            raise _invalid()
        if not (0.0 < float(bits) <= 8.0):
            raise _invalid()
        _require_bool(self.manual_submission)


@dataclass(frozen=True)
class SafePayload:
    """Filtered payload: canonical JSON, bounded, free of raw secrets, private blocks and blocked paths."""

    value: JsonValue
    redacted_count: int
    stripped_keys_count: int

    def __post_init__(self) -> None:
        validate_json(self.value)
        for count in (self.redacted_count, self.stripped_keys_count):
            if not is_strict_int(count) or count < 0:
                raise _invalid()


@dataclass(frozen=True)
class RepoFlags:
    """Spec 14.2 repo flags. Only ``provider_egress`` is durable in policy v3; the rest default to enabled."""

    automatic_capture: bool = True
    manual_submission: bool = True
    indexing: bool = True
    provider_egress: bool = True

    def __post_init__(self) -> None:
        for value in (self.automatic_capture, self.manual_submission, self.indexing, self.provider_egress):
            _require_bool(value)

    @classmethod
    def from_repo_policy(cls, policy: RepoPolicy) -> RepoFlags:
        if not isinstance(policy, RepoPolicy):
            raise _invalid()
        return cls(provider_egress=policy.provider_egress_enabled)


@dataclass(frozen=True)
class KernelRecord:
    """A typed ledger record for ``KernelTx.append_record``: flat typed meta and digest refs, never prose."""

    kind: str
    meta: Mapping[str, JsonValue]
    refs: tuple[str, ...] = ()
    actor: str = "system:kernel"

    def __post_init__(self) -> None:
        if not isinstance(self.kind, str) or _KIND_NAME_RE.fullmatch(self.kind) is None:
            raise _invalid()
        if not isinstance(self.meta, Mapping) or not all(isinstance(k, str) for k in self.meta):
            raise _invalid()
        if not all(v is None or type(v) in (bool, int, str) for v in self.meta.values()):
            raise _invalid()
        object.__setattr__(self, "meta", MappingProxyType(dict(self.meta)))
        if not isinstance(self.refs, tuple) or len(set(self.refs)) != len(self.refs):
            raise _invalid()
        for ref in self.refs:
            require_sha256_digest(ref)
        if not isinstance(self.actor, str) or _ACTOR_RE.fullmatch(self.actor) is None:
            raise _invalid()


class SelectorPath(StrEnum):
    """Actual selector path of a logical delivery; SP6 stratifies by it independently of ``snapshot_status``."""

    RULES = "rules"
    JEV = "jev"


class SelectorReason(StrEnum):
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    EGRESS_INELIGIBLE = "egress_ineligible"
    JEV_SELECTED = "jev_selected"
    JEV_FAILED = "jev_failed"
    JEV_DEADLINE = "jev_deadline"


@dataclass(frozen=True)
class SourceSnapshot:
    snapshot_id: str
    owner_id: str
    repo_id: str
    checkout_id: str
    kind: str
    dirty: bool
    descriptor_digest: str
    observed_at: str

    def __post_init__(self) -> None:
        require_uuid(self.snapshot_id)
        for value in (self.owner_id, self.repo_id, self.checkout_id):
            require_opaque_id(value)
        if self.kind not in ("git", "directory"):
            raise _invalid()
        _require_bool(self.dirty)
        require_sha256_digest(self.descriptor_digest)
        require_canonical_timestamp(self.observed_at)


@dataclass(frozen=True)
class TaskBinding:
    """The committed logical delivery binding of a task (``lineage.task_bound``); replays return it unchanged."""

    task_id: str
    owner_id: str
    repo_id: str
    checkout_id: str
    delivery_id: str
    assignment_id: str | None
    source_snapshot_id: str | None
    snapshot_status: SnapshotStatus
    selector_path: SelectorPath
    selector_reason: SelectorReason

    def __post_init__(self) -> None:
        for value in (self.task_id, self.owner_id, self.repo_id, self.checkout_id, self.delivery_id):
            require_opaque_id(value)
        if self.assignment_id is not None:
            require_opaque_id(self.assignment_id)
        if type(self.snapshot_status) is not SnapshotStatus:
            raise _invalid()
        if (self.snapshot_status is SnapshotStatus.AVAILABLE) != (self.source_snapshot_id is not None):
            raise _invalid()
        if self.source_snapshot_id is not None:
            require_uuid(self.source_snapshot_id)
        if type(self.selector_path) is not SelectorPath or type(self.selector_reason) is not SelectorReason:
            raise _invalid()

    @property
    def degraded_codes(self) -> tuple[str, ...]:
        code = SNAPSHOT_DEGRADED_CODES.get(self.snapshot_status)
        return () if code is None else (code,)


@dataclass(frozen=True)
class FieldLineage:
    field_path_digest: str
    sources: LineageSet = field(default_factory=frozenset)
    unknown_source: bool = False

    def __post_init__(self) -> None:
        require_sha256_digest(self.field_path_digest)
        _require_lineage_set(self.sources)
        _require_bool(self.unknown_source)


def _require_field_path(path: object) -> tuple[str | int, ...]:
    if not isinstance(path, tuple) or not (1 <= len(path) <= _MAX_FIELD_PATH_DEPTH):
        raise _invalid()
    for segment in path:
        if is_strict_int(segment):
            assert isinstance(segment, int)
            if not (0 <= segment < 2**31):
                raise _invalid()
        elif not isinstance(segment, str) or _PATH_SEGMENT_RE.fullmatch(segment) is None:
            raise _invalid()
    return path


def field_path_descriptor(path: Sequence[str | int]) -> bytes:
    """Canonical safe descriptor of a structural field path (CAS blob; the ledger keeps only its digest)."""
    checked = _require_field_path(tuple(path))
    return canonical_json({"field_path": list(checked)})


def field_path_digest(path: Sequence[str | int]) -> str:
    return digest_bytes(field_path_descriptor(path))


@dataclass(frozen=True)
class DeliveryItem:
    """One delivered item with server-resolved lineage; ``snapshot_dependent`` items need an exact snapshot."""

    path: tuple[str | int, ...]
    sources: LineageSet = field(default_factory=frozenset)
    unknown_source: bool = False
    snapshot_dependent: bool = False

    def __post_init__(self) -> None:
        _require_field_path(self.path)
        _require_lineage_set(self.sources)
        _require_bool(self.unknown_source)
        _require_bool(self.snapshot_dependent)


@dataclass(frozen=True)
class LabeledDelivery:
    binding: TaskBinding
    task_lineage: LineageSet
    task_unknown: bool
    items: tuple[FieldLineage, ...] = ()
    omitted_items: tuple[str, ...] = ()
    safe_payload: SafePayload | None = None
    replayed: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.binding, TaskBinding):
            raise _invalid()
        _require_lineage_set(self.task_lineage)
        _require_bool(self.task_unknown)
        _require_bool(self.replayed)
        if not isinstance(self.items, tuple) or not all(isinstance(i, FieldLineage) for i in self.items):
            raise _invalid()
        if not isinstance(self.omitted_items, tuple):
            raise _invalid()
        for digest in self.omitted_items:
            require_sha256_digest(digest)
        if self.safe_payload is not None and not isinstance(self.safe_payload, SafePayload):
            raise _invalid()

    @property
    def degraded_codes(self) -> tuple[str, ...]:
        return self.binding.degraded_codes


@dataclass(frozen=True)
class MirrorCandidate:
    """A non-authoritative main-store registry mirror row: preview/audit candidate only, never authority."""

    checkout_id: str
    repo_id: str
    principal_id: str
    machine_id: str
    alias: str
    locator_digest: str | None
    subject_id: str | None
    intent_id: str
    handler_version: int

    def __post_init__(self) -> None:
        for value in (self.checkout_id, self.repo_id, self.principal_id, self.machine_id):
            require_opaque_id(value)
        require_workspace_alias(self.alias)
        for digest in (self.locator_digest, self.subject_id):
            if digest is not None:
                require_sha256_digest(digest)
        require_uuid(self.intent_id)
        if not is_strict_int(self.handler_version) or self.handler_version < 1:
            raise _invalid()


def binding_identity_digest(owner_id: str, repo_id: str, checkout_id: str) -> str:
    """Digest naming a verified ``(owner, repo, checkout)`` binding: the ``workspace_binding`` lineage source."""
    identity: dict[str, JsonValue] = {
        "owner_id": require_opaque_id(owner_id),
        "repo_id": require_opaque_id(repo_id),
        "checkout_id": require_opaque_id(checkout_id),
    }
    return digest_bytes(canonical_json(identity))


def binding_lineage_ref(binding: WorkspaceBinding) -> LineageRef:
    """The lineage ref of a verified workspace binding: every task lineage starts from its repo."""
    if not isinstance(binding, WorkspaceBinding):
        raise _invalid()
    return LineageRef(
        owner_id=binding.owner_id,
        repo_id=binding.repo_id,
        source=ObjectRef(
            kind="workspace_binding",
            id=binding.checkout_id,
            revision=1,
            digest=binding_identity_digest(binding.owner_id, binding.repo_id, binding.checkout_id),
        ),
    )
