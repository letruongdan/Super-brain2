"""Approval vocabulary, canonical ``ApprovalMessage``, server risk classification and channel rules (spec 11.3).

Pure stdlib + ``superbrain.core``: nothing here performs I/O. The signed bytes are
``ApprovalMessage.canonical_bytes()``;
risk is always classified by the server from the resources, never from a client label.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Literal

from superbrain.core._kernel_approval_parse import (
    MAX_PASSKEY_COSE_KEY_BYTES,
    MAX_PASSKEY_CREDENTIAL_ID_BYTES,
    int_field,
    invalid_input,
    mapping_field,
    parse_ssh_public_key,
    strict_b64url_decode,
    text_field,
)
from superbrain.core._kernel_base import (
    ResourceDigest,
    is_strict_int,
    require_opaque_id,
    require_positive_int,
    require_sha256_digest,
)
from superbrain.core.canonical import canonical_json
from superbrain.core.errors import BrainError
from superbrain.core.jsonvalue import JsonValue

CLI_HARNESS_ID = "cli"
"""``harness_id`` of the ``user:cli`` principal: the only caller admitted on ``/v2/operator/*``."""
APPROVAL_NAMESPACE = "ensemble-brain-approval"
APPROVAL_TTL = timedelta(minutes=10)
RISK_POLICY_VERSION = 1
"""Version of the server risk-ranking rules (spec 11.3); signed into every approval message."""

_MAX_RESOURCES = 1024
_MAX_TARGET_FILES = 1024


class ApprovalChannel(StrEnum):
    PASSKEY_UV = "passkey_uv"
    SSH_SK_VERIFIED = "ssh_sk_verified"
    SSH_SK = "ssh_sk"
    SSH_KEY = "ssh_key"
    TERMINAL = "terminal"


class AssuranceLevel(StrEnum):
    HUMAN_VERIFIED = "human_verified"
    HUMAN_PRESENT = "human_present"
    KEY_AUTHORIZATION = "key_authorization"
    CONFIRM_ONLY = "confirm_only"


class ApprovalAction(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"
    APPLY = "apply"
    ROLLBACK = "rollback"
    LESSON_CONFIRM = "lesson_confirm"
    SIGNER_ENROLL = "signer_enroll"
    SIGNER_REVOKE = "signer_revoke"
    POLICY_CHANGE = "policy_change"
    CREDENTIAL_REVOKE = "credential_revoke"
    RESTORE = "restore"
    WORKSPACE_LINK = "workspace_link"
    SKILL_PROMOTE = "skill_promote"
    SKILL_ACTIVATE = "skill_activate"
    SKILL_PUBLISH = "skill_publish"


class RecoveryScope(StrEnum):
    NONE = "none"
    CONTINUE = "continue"
    ROLLBACK = "rollback"
    CONTINUE_OR_ROLLBACK = "continue_or_rollback"


class RiskLevel(StrEnum):
    LOW = "low"
    HIGH = "high"


class Layer2State(StrEnum):
    UNKNOWN = "unknown"
    UNSUPPORTED = "unsupported"
    VERIFIED = "verified"


SIGNER_CHANNELS: frozenset[ApprovalChannel] = frozenset(
    {
        ApprovalChannel.PASSKEY_UV,
        ApprovalChannel.SSH_SK_VERIFIED,
        ApprovalChannel.SSH_SK,
        ApprovalChannel.SSH_KEY,
    }
)
ALWAYS_HIGH_ACTIONS: frozenset[ApprovalAction] = frozenset(
    {
        ApprovalAction.SIGNER_ENROLL,
        ApprovalAction.SIGNER_REVOKE,
        ApprovalAction.CREDENTIAL_REVOKE,
        ApprovalAction.RESTORE,
        ApprovalAction.SKILL_ACTIVATE,
        ApprovalAction.SKILL_PUBLISH,
    }
)
_ASSURANCE: dict[ApprovalChannel, AssuranceLevel] = {
    ApprovalChannel.PASSKEY_UV: AssuranceLevel.HUMAN_VERIFIED,
    ApprovalChannel.SSH_SK_VERIFIED: AssuranceLevel.HUMAN_VERIFIED,
    ApprovalChannel.SSH_SK: AssuranceLevel.HUMAN_PRESENT,
    ApprovalChannel.SSH_KEY: AssuranceLevel.KEY_AUTHORIZATION,
    ApprovalChannel.TERMINAL: AssuranceLevel.CONFIRM_ONLY,
}


def _invalid(message: str = "invalid input") -> BrainError:
    return invalid_input(message)


def assurance_for(channel: ApprovalChannel) -> AssuranceLevel:
    """The assurance level a verified approval over ``channel`` is recorded with (spec 11.3 channel table)."""
    if not isinstance(channel, ApprovalChannel):
        raise _invalid()
    return _ASSURANCE[channel]


def canonical_utc(value: datetime) -> str:
    """``YYYY-MM-DDTHH:MM:SS.ffffffZ`` for an aware ``datetime`` (naive is ``INVALID_INPUT``)."""
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise _invalid()
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class TargetFile:
    """One approved target file: root, normalized relative path, physical identities and the original digest."""

    root_path: str
    normalized_rel_path: str
    parent_physical_id: str
    target_physical_id: str | None
    original_digest: str | None
    original_present: bool

    def __post_init__(self) -> None:
        for text in (self.root_path, self.normalized_rel_path, self.parent_physical_id):
            if not isinstance(text, str) or not text or "\x00" in text:
                raise _invalid()
        if not isinstance(self.original_present, bool):
            raise _invalid()
        if self.original_present:
            if (
                not isinstance(self.target_physical_id, str)
                or not self.target_physical_id
                or "\x00" in self.target_physical_id
            ):
                raise _invalid()
            require_sha256_digest(self.original_digest)
        elif self.target_physical_id is not None or self.original_digest is not None:
            raise _invalid()

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "root_path": self.root_path,
            "normalized_rel_path": self.normalized_rel_path,
            "parent_physical_id": self.parent_physical_id,
            "target_physical_id": self.target_physical_id,
            "original_digest": self.original_digest,
            "original_present": self.original_present,
        }


_SCOPES_BY_ACTION: dict[ApprovalAction, frozenset[RecoveryScope]] = {
    ApprovalAction.APPLY: frozenset({RecoveryScope.CONTINUE, RecoveryScope.CONTINUE_OR_ROLLBACK}),
    ApprovalAction.ROLLBACK: frozenset({RecoveryScope.ROLLBACK}),
}


@dataclass(frozen=True)
class ApprovalMessage:
    """The message a signer signs (or a passkey uses as challenge): every spec 11.3 field, canonical and bound."""

    store_id: str
    owner_id: str
    trust_generation: int
    action: ApprovalAction
    subject_id: str
    subject_revision: int
    resource_digests: tuple[ResourceDigest, ...]
    target_files: tuple[TargetFile, ...]
    risk_level: RiskLevel
    risk_policy_version: int
    recovery_scope: RecoveryScope
    nonce: str
    expires_at: datetime

    def __post_init__(self) -> None:
        require_opaque_id(self.store_id, label="store_id")
        require_opaque_id(self.owner_id, label="owner_id")
        require_positive_int(self.trust_generation)
        if not isinstance(self.action, ApprovalAction):
            raise _invalid()
        if not isinstance(self.subject_id, str) or not self.subject_id or "\x00" in self.subject_id:
            raise _invalid()
        require_positive_int(self.subject_revision)
        if (
            not isinstance(self.resource_digests, tuple)
            or len(self.resource_digests) > _MAX_RESOURCES
            or not all(isinstance(d, ResourceDigest) for d in self.resource_digests)
        ):
            raise _invalid()
        if len({d.name for d in self.resource_digests}) != len(self.resource_digests):
            raise _invalid("duplicate resource digest name")
        if (
            not isinstance(self.target_files, tuple)
            or len(self.target_files) > _MAX_TARGET_FILES
            or not all(isinstance(f, TargetFile) for f in self.target_files)
        ):
            raise _invalid()
        if len({(f.root_path, f.normalized_rel_path) for f in self.target_files}) != len(self.target_files):
            raise _invalid()
        if not isinstance(self.risk_level, RiskLevel):
            raise _invalid()
        require_positive_int(self.risk_policy_version)
        if not isinstance(self.recovery_scope, RecoveryScope):
            raise _invalid()
        allowed = _SCOPES_BY_ACTION.get(self.action, frozenset({RecoveryScope.NONE}))
        if self.recovery_scope not in allowed:
            raise _invalid()
        if not isinstance(self.nonce, str) or not self.nonce or "\x00" in self.nonce:
            raise _invalid()
        canonical_utc(self.expires_at)

    def to_dict(self) -> dict[str, JsonValue]:
        resources = sorted(self.resource_digests, key=lambda d: d.name)
        files = sorted(self.target_files, key=lambda f: (f.root_path, f.normalized_rel_path))
        return {
            "store_id": self.store_id,
            "owner_id": self.owner_id,
            "trust_generation": self.trust_generation,
            "action": self.action.value,
            "subject_id": self.subject_id,
            "subject_revision": self.subject_revision,
            "resource_digests": [d.to_dict() for d in resources],
            "target_files": [f.to_dict() for f in files],
            "risk_level": self.risk_level.value,
            "risk_policy_version": self.risk_policy_version,
            "recovery_scope": self.recovery_scope.value,
            "nonce": self.nonce,
            "expires_at": canonical_utc(self.expires_at),
        }

    def canonical_bytes(self) -> bytes:
        """The exact UTF-8 canonical JSON that is signed; independent of input ordering."""
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, raw: Mapping[str, JsonValue]) -> ApprovalMessage:
        """Rebuild a message from its ``to_dict`` form (every field required, nothing extra); else ``INVALID_INPUT``."""
        if not isinstance(raw, Mapping) or set(raw) != _MESSAGE_FIELDS:
            raise _invalid()
        resources, files, expires = raw["resource_digests"], raw["target_files"], raw["expires_at"]
        if not isinstance(resources, list) or not isinstance(files, list):
            raise _invalid()
        if not isinstance(expires, str) or not expires.endswith("Z"):
            raise _invalid()
        try:
            expires_at = datetime.fromisoformat(expires[:-1] + "+00:00")
            return cls(
                store_id=text_field(raw["store_id"]),
                owner_id=text_field(raw["owner_id"]),
                trust_generation=int_field(raw["trust_generation"]),
                action=ApprovalAction(text_field(raw["action"])),
                subject_id=text_field(raw["subject_id"]),
                subject_revision=int_field(raw["subject_revision"]),
                resource_digests=tuple(ResourceDigest.from_dict(mapping_field(item)) for item in resources),
                target_files=tuple(_target_file(mapping_field(item)) for item in files),
                risk_level=RiskLevel(text_field(raw["risk_level"])),
                risk_policy_version=int_field(raw["risk_policy_version"]),
                recovery_scope=RecoveryScope(text_field(raw["recovery_scope"])),
                nonce=text_field(raw["nonce"]),
                expires_at=expires_at,
            )
        except ValueError as err:
            raise _invalid() from err


_MESSAGE_FIELDS = frozenset(
    {
        "store_id",
        "owner_id",
        "trust_generation",
        "action",
        "subject_id",
        "subject_revision",
        "resource_digests",
        "target_files",
        "risk_level",
        "risk_policy_version",
        "recovery_scope",
        "nonce",
        "expires_at",
    }
)
_TARGET_FILE_FIELDS = frozenset(
    {
        "root_path",
        "normalized_rel_path",
        "parent_physical_id",
        "target_physical_id",
        "original_digest",
        "original_present",
    }
)


def _target_file(raw: Mapping[str, JsonValue]) -> TargetFile:
    if set(raw) != _TARGET_FILE_FIELDS:
        raise _invalid()
    target_id, digest, present = raw["target_physical_id"], raw["original_digest"], raw["original_present"]
    if (target_id is not None and not isinstance(target_id, str)) or (
        digest is not None and not isinstance(digest, str)
    ):
        raise _invalid()
    if not isinstance(present, bool):
        raise _invalid()
    return TargetFile(
        root_path=text_field(raw["root_path"]),
        normalized_rel_path=text_field(raw["normalized_rel_path"]),
        parent_physical_id=text_field(raw["parent_physical_id"]),
        target_physical_id=target_id,
        original_digest=digest,
        original_present=present,
    )


def policy_change_subject_id(
    *,
    repo_id_or_global: str,
    base_policy_revision: int,
    base_trust_generation: int,
    base_restore_epoch: int,
    policy_diff_digest: str,
) -> str:
    """Subject of a ``policy_change`` approval: binds the diff to the policy state it was computed against."""
    if not isinstance(repo_id_or_global, str) or not repo_id_or_global or "\x00" in repo_id_or_global:
        raise _invalid()
    for number in (base_policy_revision, base_restore_epoch):
        if not is_strict_int(number) or number < 0:
            raise _invalid()
    require_positive_int(base_trust_generation)
    require_sha256_digest(policy_diff_digest)
    body = canonical_json(
        {
            "repo_id_or_global": repo_id_or_global,
            "base_policy_revision": base_policy_revision,
            "base_trust_generation": base_trust_generation,
            "base_restore_epoch": base_restore_epoch,
            "policy_diff_digest": policy_diff_digest,
        }
    )
    return "sha256:" + hashlib.sha256(body).hexdigest()


def restore_subject_id(
    *,
    target_kind: Literal["store", "policy"],
    backup_id: str,
    backup_db_digest: str,
    target_epoch_or_gen: int,
) -> str:
    """Subject of a ``restore`` approval: binds target kind, backup identity/digest, and monotonic epoch/gen."""
    if target_kind not in ("store", "policy"):
        raise _invalid()
    if not isinstance(backup_id, str) or not backup_id or "\x00" in backup_id:
        raise _invalid()
    require_sha256_digest(backup_db_digest)
    if not is_strict_int(target_epoch_or_gen) or target_epoch_or_gen < 0:
        raise _invalid()
    body = canonical_json(
        {
            "target_kind": target_kind,
            "backup_id": backup_id,
            "backup_db_digest": backup_db_digest,
            "target_epoch_or_gen": target_epoch_or_gen,
        }
    )
    return "sha256:" + hashlib.sha256(body).hexdigest()


_COMPONENTS = frozenset({"c1", "c2", "c3", "c4", "c5", "c6", "c7", "c8"})
_ALWAYS_HIGH_COMPONENTS = frozenset({"c2", "c5", "c7", "c8"})


@dataclass(frozen=True)
class RiskResource:
    """What the server knows about one resource of a proposal (never client-asserted)."""

    component: str
    executable: bool = False
    command_reference: bool = False
    outside_guidance_block: bool = False


def classify_proposal_risk(resources: Sequence[RiskResource], *, client_hint: str | None = None) -> RiskLevel:
    """Highest risk over every resource; ``client_hint`` is accepted and ignored (spec 11.3)."""
    _ = client_hint
    if not resources:
        raise _invalid()
    level = RiskLevel.LOW
    for resource in resources:
        if not isinstance(resource, RiskResource) or resource.component not in _COMPONENTS:
            raise _invalid()
        if (
            resource.component in _ALWAYS_HIGH_COMPONENTS
            or resource.executable
            or resource.command_reference
            or resource.outside_guidance_block
        ):
            level = RiskLevel.HIGH
    return level


def classify_policy_change_risk(
    *,
    widens_capture_or_egress: bool,
    sets_review_harness_or_command: bool,
    reconcile_accounting: bool,
) -> RiskLevel:
    """``HIGH`` when a policy diff widens capture/egress, steers the review harness or reconciles accounting."""
    flags = (widens_capture_or_egress, sets_review_harness_or_command, reconcile_accounting)
    if not all(isinstance(flag, bool) for flag in flags):
        raise _invalid()
    return RiskLevel.HIGH if any(flags) else RiskLevel.LOW


def required_channels(
    action: ApprovalAction, risk: RiskLevel, *, terminal_eligible: bool
) -> frozenset[ApprovalChannel]:
    """Channels that may satisfy ``action`` at ``risk``; ``terminal`` only for low risk with verified layer 2."""
    if not isinstance(action, ApprovalAction) or not isinstance(risk, RiskLevel):
        raise _invalid()
    if risk is RiskLevel.HIGH or action in ALWAYS_HIGH_ACTIONS or not terminal_eligible:
        return SIGNER_CHANNELS
    return SIGNER_CHANNELS | {ApprovalChannel.TERMINAL}


def effective_risk(action: ApprovalAction, risk: RiskLevel) -> RiskLevel:
    """``HIGH`` for an always-high action whatever risk was requested."""
    return RiskLevel.HIGH if action in ALWAYS_HIGH_ACTIONS else risk


_SSH_KEY_TYPES_SK_PREFIX = "sk-"


@dataclass(frozen=True)
class SignerEnrollment:
    """A public key offered as a signer: an SSH public key line or a WebAuthn COSE key plus credential id."""

    owner_id: str
    channel: ApprovalChannel
    public_key: str
    credential_id: str | None = None
    _normalized: str = field(init=False, repr=False, compare=False, default="")

    def __post_init__(self) -> None:
        require_opaque_id(self.owner_id, label="owner_id")
        if not isinstance(self.channel, ApprovalChannel) or self.channel not in SIGNER_CHANNELS:
            raise _invalid()
        if not isinstance(self.public_key, str) or not self.public_key:
            raise _invalid()
        if self.channel is ApprovalChannel.PASSKEY_UV:
            if not isinstance(self.credential_id, str) or not self.credential_id:
                raise _invalid()
            strict_b64url_decode(self.credential_id, max_decoded_bytes=MAX_PASSKEY_CREDENTIAL_ID_BYTES)
            strict_b64url_decode(self.public_key, max_decoded_bytes=MAX_PASSKEY_COSE_KEY_BYTES)
            normalized = f"webauthn {self.public_key}"
        else:
            if self.credential_id is not None:
                raise _invalid()
            key_type, blob = parse_ssh_public_key(self.public_key)
            is_sk = key_type.startswith(_SSH_KEY_TYPES_SK_PREFIX)
            if is_sk != (self.channel in (ApprovalChannel.SSH_SK, ApprovalChannel.SSH_SK_VERIFIED)):
                raise _invalid()
            normalized = f"{key_type} {blob}"
        object.__setattr__(self, "_normalized", normalized)

    @property
    def key_digest(self) -> str:
        cred = self.credential_id or ""
        return "sha256:" + hashlib.sha256(f"{self._normalized}\n{cred}".encode()).hexdigest()

    @property
    def subject_id(self) -> str:
        """Subject of the ``signer_enroll`` approval: the key digest itself."""
        return self.key_digest


@dataclass(frozen=True)
class SignerRecord:
    signer_id: str
    owner_id: str
    channel: ApprovalChannel
    key_digest: str
    tofu: bool
    revoked: bool
    public_key: str = ""
    credential_id: str | None = None
    sign_count: int = 0


@dataclass(frozen=True)
class IssuedNonce:
    nonce: str
    action: ApprovalAction
    subject_id: str
    risk_level: RiskLevel
    trust_generation: int
    expires_at: datetime


@dataclass(frozen=True)
class ApprovalReceipt:
    approval_id: str
    message: ApprovalMessage
    signer_id: str | None
    channel: ApprovalChannel
    assurance: AssuranceLevel


@dataclass(frozen=True)
class RecoveryGrant:
    grant_id: str
    approval_id: str
    journal_id: str
    subject_id: str
    recovery_scope: RecoveryScope
    trust_generation: int
    state: str
    end_reason: str | None


__all__ = [
    "ALWAYS_HIGH_ACTIONS",
    "APPROVAL_NAMESPACE",
    "APPROVAL_TTL",
    "CLI_HARNESS_ID",
    "RISK_POLICY_VERSION",
    "SIGNER_CHANNELS",
    "ApprovalAction",
    "ApprovalChannel",
    "ApprovalMessage",
    "ApprovalReceipt",
    "AssuranceLevel",
    "IssuedNonce",
    "Layer2State",
    "RecoveryGrant",
    "RecoveryScope",
    "RiskLevel",
    "RiskResource",
    "SignerEnrollment",
    "SignerRecord",
    "TargetFile",
    "assurance_for",
    "canonical_utc",
    "classify_policy_change_risk",
    "classify_proposal_risk",
    "effective_risk",
    "parse_ssh_public_key",
    "policy_change_subject_id",
    "required_channels",
    "strict_b64url_decode",
]
