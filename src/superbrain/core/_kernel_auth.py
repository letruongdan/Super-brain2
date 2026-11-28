"""Pure authentication, bootstrap, config, TLS, and workspace registry contract types for ``core.kernel``."""

from __future__ import annotations

import base64
import binascii
import hmac
import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from types import MappingProxyType

from superbrain.core._kernel_base import (
    GLOBAL_SCOPELESS_ACTIONS,
    Principal,
    Scope,
    is_strict_int,
    require_object_kind,
    require_opaque_id,
    require_positive_int,
    require_sha256_digest,
    require_workspace_alias,
)
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue

_LOCATOR_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]{0,31}$")
_BOOTSTRAP_ISSUER_RE = re.compile(r"^(owner|bootstrap):[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_BASE64URL_SECRET_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_DUMMY_SECRET_DIGEST = "sha256:" + ("0" * 64)

CAPABILITY_MCP_TOOL = "mcp_tool"
CAPABILITY_CAPTURE_PRODUCER = "capture_producer"
CAPABILITY_OPERATOR_CLI = "operator_cli"
_DEFAULT_MCP_CAPABILITIES: frozenset[str] = frozenset({CAPABILITY_MCP_TOOL})
CredentialCapabilityBinding = tuple[Principal, str, frozenset[str], "CaptureProducerBinding | None"]
VALID_CREDENTIAL_CAPABILITIES: frozenset[str] = frozenset(
    {
        CAPABILITY_MCP_TOOL,
        CAPABILITY_CAPTURE_PRODUCER,
        CAPABILITY_OPERATOR_CLI,
    }
)


def _require_uuid_str(value: object) -> str:
    if not isinstance(value, str):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    try:
        parsed = uuid.UUID(value)
    except ValueError as err:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input") from err
    if str(parsed) != value:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    return value


def _require_aware_datetime(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    return value


def _require_abs_path(value: object) -> Path:
    if not isinstance(value, Path) or not value.is_absolute():
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    return value


def is_trusted_bootstrap_issuer(issuer_id: str) -> bool:
    """Return True iff ``issuer_id`` names an internal owner/bootstrap authority scope (never agent/MCP)."""
    return isinstance(issuer_id, str) and _BOOTSTRAP_ISSUER_RE.fullmatch(issuer_id) is not None


def parse_bearer_token(token: str) -> tuple[str, str]:
    """Parse ``<credential_uuidv7>.<base64url-no-padding>`` into ``(credential_id, secret_digest)``.

    Raises ``BrainError(ErrorCode.UNAUTHENTICATED)`` on any syntactic or version violation.
    """
    if not isinstance(token, str) or "." not in token:
        raise BrainError(ErrorCode.UNAUTHENTICATED, "unauthenticated")
    parts = token.split(".")
    if len(parts) != 2:
        raise BrainError(ErrorCode.UNAUTHENTICATED, "unauthenticated")
    cred_id, secret_b64 = parts
    try:
        parsed_uuid = uuid.UUID(cred_id)
    except ValueError as err:
        raise BrainError(ErrorCode.UNAUTHENTICATED, "unauthenticated") from err
    if str(parsed_uuid) != cred_id or parsed_uuid.version != 7:
        raise BrainError(ErrorCode.UNAUTHENTICATED, "unauthenticated")
    if not _BASE64URL_SECRET_RE.fullmatch(secret_b64):
        raise BrainError(ErrorCode.UNAUTHENTICATED, "unauthenticated")
    try:
        raw_secret = base64.urlsafe_b64decode(secret_b64 + "=")
    except (binascii.Error, ValueError) as err:
        raise BrainError(ErrorCode.UNAUTHENTICATED, "unauthenticated") from err
    if len(raw_secret) != 32:
        raise BrainError(ErrorCode.UNAUTHENTICATED, "unauthenticated")
    # Reject non-canonical trailing bits in the 43rd base64url character.
    if base64.urlsafe_b64encode(raw_secret).rstrip(b"=").decode("ascii") != secret_b64:
        raise BrainError(ErrorCode.UNAUTHENTICATED, "unauthenticated")
    return cred_id, digest_bytes(raw_secret)


def verify_secret_digest(candidate_digest: str, expected_digest: str | None) -> bool:
    """Compare ``candidate_digest`` against ``expected_digest`` in constant time."""
    target = expected_digest if expected_digest is not None else _DUMMY_SECRET_DIGEST
    matched = hmac.compare_digest(candidate_digest.encode("ascii"), target.encode("ascii"))
    return matched and expected_digest is not None


@dataclass(frozen=True)
class DaemonConfig:
    version: int
    data_root: Path
    expected_store_id: str
    cert_path: Path
    key_path: Path

    def __post_init__(self) -> None:
        if isinstance(self.version, bool):
            raise BrainError(ErrorCode.INVALID_INPUT, "boolean not allowed for integer")
        if not is_strict_int(self.version) or self.version != 1:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        _require_abs_path(self.data_root)
        require_opaque_id(self.expected_store_id, label="expected_store_id")
        _require_abs_path(self.cert_path)
        _require_abs_path(self.key_path)


@dataclass(frozen=True)
class BootstrapAuthorization:
    intent_id: str
    store_id: str
    owner_id: str
    action: str
    subject_id: str
    trust_generation: int
    expires_at: datetime
    issuer_id: str
    destination: Path | None = None

    def __post_init__(self) -> None:
        _require_uuid_str(self.intent_id)
        require_opaque_id(self.store_id, label="store_id")
        require_opaque_id(self.owner_id, label="owner_id")
        require_opaque_id(self.action, label="action")
        if not isinstance(self.subject_id, str) or not (1 <= len(self.subject_id) <= 256):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if (
            isinstance(self.trust_generation, bool)
            or not is_strict_int(self.trust_generation)
            or self.trust_generation < 0
        ):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        _require_aware_datetime(self.expires_at)
        if not isinstance(self.issuer_id, str) or not (1 <= len(self.issuer_id) <= 256):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if self.destination is not None:
            _require_abs_path(self.destination)


@dataclass(frozen=True, repr=True)
class TlsMaterial:
    store_id: str
    ca_cert_path: Path
    ca_key_path: Path
    cert_path: Path
    key_path: Path
    leaf_cert_sha256: str
    not_before: datetime
    not_after: datetime

    def __post_init__(self) -> None:
        require_opaque_id(self.store_id, label="store_id")
        _require_abs_path(self.ca_cert_path)
        _require_abs_path(self.ca_key_path)
        _require_abs_path(self.cert_path)
        _require_abs_path(self.key_path)
        if not isinstance(self.leaf_cert_sha256, str) or not _HEX64_RE.fullmatch(self.leaf_cert_sha256):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        _require_aware_datetime(self.not_before)
        _require_aware_datetime(self.not_after)


@dataclass(frozen=True)
class VerifiedServerTls:
    store_id: str
    cert_path: Path
    key_path: Path
    leaf_cert_sha256: str
    not_before: datetime
    not_after: datetime

    def __post_init__(self) -> None:
        require_opaque_id(self.store_id, label="store_id")
        _require_abs_path(self.cert_path)
        _require_abs_path(self.key_path)
        if not isinstance(self.leaf_cert_sha256, str) or not _HEX64_RE.fullmatch(self.leaf_cert_sha256):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        _require_aware_datetime(self.not_before)
        _require_aware_datetime(self.not_after)


@dataclass(frozen=True)
class TrustedLocator:
    scheme: str
    canonical_locator: str
    locator_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.scheme, str) or not _LOCATOR_SCHEME_RE.fullmatch(self.scheme):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if not isinstance(self.canonical_locator, str) or not (1 <= len(self.canonical_locator) <= 4096):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        require_sha256_digest(self.locator_digest)


@dataclass(frozen=True)
class WorkspaceRegistration:
    owner_id: str
    principal_id: str
    machine_id: str
    alias: str
    checkout_path: str
    path_identity: str
    locator: TrustedLocator | None = None
    provider_egress_enabled: bool = False

    def __post_init__(self) -> None:
        require_opaque_id(self.owner_id, label="owner_id")
        require_opaque_id(self.principal_id, label="principal_id")
        require_opaque_id(self.machine_id, label="machine_id")
        require_workspace_alias(self.alias)
        if (
            not isinstance(self.checkout_path, str)
            or not self.checkout_path
            or not Path(self.checkout_path).is_absolute()
        ):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if not isinstance(self.path_identity, str) or not (1 <= len(self.path_identity) <= 4096):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if self.locator is not None and not isinstance(self.locator, TrustedLocator):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if not isinstance(self.provider_egress_enabled, bool):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")

    @property
    def subject_id(self) -> str:
        """Deterministic canonical subject digest binding every field of this workspace registration."""
        payload: dict[str, JsonValue] = {
            "owner_id": self.owner_id,
            "principal_id": self.principal_id,
            "machine_id": self.machine_id,
            "alias": self.alias,
            "checkout_path": self.checkout_path,
            "path_identity": self.path_identity,
            "locator_digest": self.locator.locator_digest if self.locator is not None else None,
            "canonical_locator": self.locator.canonical_locator if self.locator is not None else None,
            "locator_scheme": self.locator.scheme if self.locator is not None else None,
            "provider_egress_enabled": self.provider_egress_enabled,
        }
        return digest_bytes(canonical_json(payload))


@dataclass(frozen=True)
class WorkspaceBinding:
    owner_id: str
    repo_id: str
    checkout_id: str
    machine_id: str
    alias: str
    checkout_path: str
    locator_digest: str | None = None

    def __post_init__(self) -> None:
        require_opaque_id(self.owner_id, label="owner_id")
        require_opaque_id(self.repo_id, label="repo_id")
        require_opaque_id(self.checkout_id, label="checkout_id")
        require_opaque_id(self.machine_id, label="machine_id")
        require_workspace_alias(self.alias)
        if not isinstance(self.checkout_path, str) or not self.checkout_path:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if self.locator_digest is not None:
            require_sha256_digest(self.locator_digest)


@dataclass(frozen=True)
class CaptureProducerBinding:
    """Credential-pinned capture producer identity binding a stream to one repo/checkout."""

    producer_stream: str
    repo_id: str
    checkout_id: str

    def __post_init__(self) -> None:
        require_opaque_id(self.producer_stream, label="producer_stream")
        require_opaque_id(self.repo_id, label="repo_id")
        require_opaque_id(self.checkout_id, label="checkout_id")


@dataclass(frozen=True)
class CredentialRecord:
    credential_id: str
    principal: Principal
    secret_digest: str
    revoked: bool = False
    capabilities: frozenset[str] = frozenset({CAPABILITY_MCP_TOOL})
    capture_binding: CaptureProducerBinding | None = None

    def __post_init__(self) -> None:
        _require_uuid_str(self.credential_id)
        if not isinstance(self.principal, Principal):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        require_sha256_digest(self.secret_digest)
        if not isinstance(self.revoked, bool):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if (
            not isinstance(self.capabilities, frozenset)
            or not self.capabilities
            or any(not isinstance(cap, str) or cap not in VALID_CREDENTIAL_CAPABILITIES for cap in self.capabilities)
        ):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if self.capture_binding is not None:
            if not isinstance(self.capture_binding, CaptureProducerBinding):
                raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
            if CAPABILITY_CAPTURE_PRODUCER not in self.capabilities:
                raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")


@dataclass(frozen=True)
class ResolvedCredential:
    credential_id: str
    principal: Principal
    trust_generation: int

    def __post_init__(self) -> None:
        _require_uuid_str(self.credential_id)
        if not isinstance(self.principal, Principal):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        require_positive_int(self.trust_generation)


@dataclass(frozen=True)
class RepoPolicy:
    repo_id: str
    owner_id: str
    provider_egress_enabled: bool = False
    automatic_capture_enabled: bool = True
    manual_submission_enabled: bool = True
    indexing_enabled: bool = True
    post_session_review_enabled: bool = True

    def __post_init__(self) -> None:
        require_opaque_id(self.repo_id, label="repo_id")
        require_opaque_id(self.owner_id, label="owner_id")
        for flag in (
            self.provider_egress_enabled,
            self.automatic_capture_enabled,
            self.manual_submission_enabled,
            self.indexing_enabled,
            self.post_session_review_enabled,
        ):
            if not isinstance(flag, bool):
                raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")


@dataclass(frozen=True)
class AuthSnapshot:
    store_id: str
    trust_generation: int
    credentials: Mapping[str, CredentialRecord] = field(default_factory=dict)
    principals: Mapping[str, Principal] = field(default_factory=dict)
    repo_policies: Mapping[str, RepoPolicy] = field(default_factory=dict)
    grants: frozenset[tuple[str, str]] = field(default_factory=frozenset)
    checkouts: Mapping[str, WorkspaceBinding] = field(default_factory=dict)

    def __post_init__(self) -> None:
        require_opaque_id(self.store_id, label="store_id")
        require_positive_int(self.trust_generation)
        object.__setattr__(self, "credentials", MappingProxyType(dict(self.credentials)))
        object.__setattr__(self, "principals", MappingProxyType(dict(self.principals)))
        object.__setattr__(self, "repo_policies", MappingProxyType(dict(self.repo_policies)))
        object.__setattr__(self, "grants", frozenset(self.grants))
        object.__setattr__(self, "checkouts", MappingProxyType(dict(self.checkouts)))

    def resolve_credential_record(self, token: str) -> CredentialRecord:
        cred_id, candidate_digest = parse_bearer_token(token)
        rec = self.credentials.get(cred_id)
        expected = rec.secret_digest if (rec is not None and not rec.revoked) else None
        if not verify_secret_digest(candidate_digest, expected) or rec is None:
            raise BrainError(ErrorCode.UNAUTHENTICATED, "unauthenticated")
        return rec

    def resolve_credential(self, token: str) -> Principal:
        rec = self.resolve_credential_record(token)
        if CAPABILITY_MCP_TOOL not in rec.capabilities:
            raise BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch")
        return rec.principal

    def authorize_capture_producer(
        self,
        token: str,
        *,
        producer_stream: str,
        repo_id: str,
        checkout_id: str,
    ) -> Principal:
        require_opaque_id(producer_stream, label="producer_stream")
        require_opaque_id(repo_id, label="repo_id")
        require_opaque_id(checkout_id, label="checkout_id")
        rec = self.resolve_credential_record(token)
        if CAPABILITY_CAPTURE_PRODUCER not in rec.capabilities or rec.capture_binding is None:
            raise BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch")
        expected = CaptureProducerBinding(
            producer_stream=producer_stream,
            repo_id=repo_id,
            checkout_id=checkout_id,
        )
        if rec.capture_binding != expected:
            raise BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch")
        return rec.principal

    def allows(self, principal: Principal, scope: Scope | None, *, action: str) -> bool:
        if not isinstance(action, str) or not action:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        stored_principal = self.principals.get(principal.principal_id)
        if stored_principal != principal:
            return False
        if action == "capture_events":
            if scope is None or scope.checkout_id is None:
                return False
            has_active_cred = any(
                not cred.revoked
                and cred.principal.principal_id == principal.principal_id
                and CAPABILITY_CAPTURE_PRODUCER in cred.capabilities
                and cred.capture_binding is not None
                and cred.capture_binding.repo_id == scope.repo_id
                and cred.capture_binding.checkout_id == scope.checkout_id
                for cred in self.credentials.values()
            )
        else:
            has_active_cred = any(
                not cred.revoked
                and cred.principal.principal_id == principal.principal_id
                and CAPABILITY_MCP_TOOL in cred.capabilities
                for cred in self.credentials.values()
            )
        if not has_active_cred:
            return False
        if scope is None:
            return action in GLOBAL_SCOPELESS_ACTIONS
        if action == "get_health" and scope.checkout_id is None:
            return False
        repo_pol = self.repo_policies.get(scope.repo_id)
        if repo_pol is None or repo_pol.owner_id != principal.owner_id:
            return False
        if (principal.principal_id, scope.repo_id) not in self.grants:
            return False
        if scope.checkout_id is not None:
            binding = self.checkouts.get(scope.checkout_id)
            if (
                binding is None
                or binding.owner_id != principal.owner_id
                or binding.repo_id != scope.repo_id
                or binding.machine_id != principal.machine_id
            ):
                return False
        return True

    def is_active_mcp_credential(self, credential_id: str) -> bool:
        """Return True iff ``credential_id`` is unrevoked, bound to its principal, and holds ``mcp_tool``."""
        cred = self.credentials.get(credential_id)
        return (
            cred is not None
            and not cred.revoked
            and CAPABILITY_MCP_TOOL in cred.capabilities
            and self.principals.get(cred.principal.principal_id) == cred.principal
        )

    def matches_persisted_policy(self, policy_auth: AuthSnapshot) -> bool:
        """Return True iff all persisted policy fields match ``policy_auth`` (allowing runtime capabilities)."""
        if not isinstance(policy_auth, AuthSnapshot):
            return False
        if (
            self.store_id != policy_auth.store_id
            or self.trust_generation != policy_auth.trust_generation
            or self.principals != policy_auth.principals
            or self.repo_policies != policy_auth.repo_policies
            or self.grants != policy_auth.grants
            or self.checkouts != policy_auth.checkouts
            or self.credentials.keys() != policy_auth.credentials.keys()
        ):
            return False
        for cid, cur in self.credentials.items():
            pol = policy_auth.credentials[cid]
            if (
                cur.credential_id != pol.credential_id
                or cur.principal != pol.principal
                or cur.secret_digest != pol.secret_digest
                or cur.revoked != pol.revoked
            ):
                return False
            if (pol.capabilities != _DEFAULT_MCP_CAPABILITIES or pol.capture_binding is not None) and (
                cur.capabilities != pol.capabilities or cur.capture_binding != pol.capture_binding
            ):
                return False
        return True


def collect_credential_capability_bindings(snap: AuthSnapshot) -> dict[str, CredentialCapabilityBinding]:
    """Extract non-default credential capability/capture bindings keyed by ``credential_id``."""
    return {
        cid: (rec.principal, rec.secret_digest, rec.capabilities, rec.capture_binding)
        for cid, rec in snap.credentials.items()
        if rec.capabilities != _DEFAULT_MCP_CAPABILITIES or rec.capture_binding is not None
    }


def apply_credential_capability_bindings(
    snap: AuthSnapshot,
    bindings: Mapping[str, CredentialCapabilityBinding],
) -> AuthSnapshot:
    """Re-attach runtime credential capabilities onto matching policy-backed credentials."""
    if not bindings:
        return snap
    merged: dict[str, CredentialRecord] | None = None
    for cid, rec in snap.credentials.items():
        bound = bindings.get(cid)
        if bound is None:
            continue
        stored_principal, stored_digest, caps, cap_binding = bound
        if (
            rec.principal == stored_principal
            and rec.secret_digest == stored_digest
            and rec.capabilities == _DEFAULT_MCP_CAPABILITIES
            and rec.capture_binding is None
        ):
            if merged is None:
                merged = dict(snap.credentials)
            merged[cid] = replace(rec, capabilities=caps, capture_binding=cap_binding)
    return snap if merged is None else replace(snap, credentials=merged)


def update_credential_capability_bindings(
    existing: Mapping[str, CredentialCapabilityBinding],
    snap: AuthSnapshot,
) -> dict[str, CredentialCapabilityBinding]:
    """Update cached non-MCP bindings from ``snap`` while retaining bindings for absent credentials."""
    updated = dict(existing)
    for cid, rec in snap.credentials.items():
        if rec.capabilities != _DEFAULT_MCP_CAPABILITIES or rec.capture_binding is not None:
            updated[cid] = (rec.principal, rec.secret_digest, rec.capabilities, rec.capture_binding)
        else:
            updated.pop(cid, None)
    return updated


@dataclass(frozen=True)
class DirectRefRecord:
    kind: str
    id: str
    revision: int
    digest: str
    owner_id: str
    repo_id: str | None = None
    checkout_id: str | None = None

    def __post_init__(self) -> None:
        require_object_kind(self.kind)
        require_opaque_id(self.id, label="id")
        require_positive_int(self.revision)
        require_sha256_digest(self.digest)
        require_opaque_id(self.owner_id, label="owner_id")
        if self.repo_id is not None:
            require_opaque_id(self.repo_id, label="repo_id")
        if self.checkout_id is not None:
            if self.repo_id is None:
                raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
            require_opaque_id(self.checkout_id, label="checkout_id")
