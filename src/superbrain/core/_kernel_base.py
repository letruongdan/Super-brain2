"""Leaf kernel primitives shared by ``core.kernel`` and its internal modules (no intra-kernel imports).

Keeping identifier grammars, validators, ``Principal`` and ``Scope`` here lets ``core._kernel_auth`` and
``core._kernel_workspace`` depend on them without importing ``core.kernel`` back (no import-order cycle).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TypeAlias

from superbrain.core.canonical import validate_json
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

GLOBAL_SCOPELESS_ACTIONS: frozenset[str] = frozenset({"get_health", "get_job", "global_read"})
"""Actions a principal may perform with ``scope=None``; the single source for core and storage authorization."""


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
    if not isinstance(value, str) or not WORKSPACE_HINT_RE.fullmatch(value) or value in {".", ".."} or ".." in value:
        raise BrainError(ErrorCode.INVALID_INPUT, "mixed or invalid workspace selector")
    return value


def is_registrable_alias(value: object) -> bool:
    """True iff ``value`` is a workspace hint that can also be a registered alias.

    The wire hint grammar (``WORKSPACE_HINT_RE``, pinned by the v2 schema) admits a leading ``.``/``_``/``-``,
    while a registered ``WorkspaceRegistration.alias`` must also be an opaque ID (leading alphanumeric). The
    intersection is the alias grammar; a hint outside it can never name a registration.
    """
    try:
        require_workspace_hint(value)
    except BrainError:
        return False
    return isinstance(value, str) and OPAQUE_ID_RE.fullmatch(value) is not None


def require_workspace_alias(value: object) -> str:
    if not is_registrable_alias(value):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    assert isinstance(value, str)
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


def require_non_negative_int(value: object) -> int:
    if isinstance(value, bool):
        raise BrainError(ErrorCode.INVALID_INPUT, "boolean not allowed for integer")
    if type(value) is not int or value < 0:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    return value


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


class SnapshotStatus(StrEnum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    DEADLINE = "deadline"


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
class Identity:
    store_id: str
    writer_epoch: int
    instance_id: str

    def __post_init__(self) -> None:
        require_opaque_id(self.store_id, label="store_id")
        require_positive_int(self.writer_epoch)
        require_opaque_id(self.instance_id, label="instance_id")


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
