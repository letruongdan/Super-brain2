"""Online/offline maintenance restore workflows and schema ceiling guards (spec 5.7, I3-4)."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Literal

from superbrain.application._maintenance_io import (
    challenge_from_issued,
    diff_to_json,
    parse_offline_approval,
    verify_backup_signer_record_dr,
    verify_ssh_proof,
)
from superbrain.core._kernel_approval import (
    APPROVAL_TTL,
    ApprovalAction,
    ApprovalChannel,
    ApprovalMessage,
    RiskLevel,
    SignerRecord,
    canonical_utc,
)
from superbrain.core._kernel_base import ResourceDigest
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import require_opaque_id
from superbrain.ports.approval import SshApprovalVerifierPort, WebAuthnApprovalVerifierPort
from superbrain.ports.maintenance import (
    MaintenanceStoragePort,
    RestoreOutcome,
    RestorePreview,
    VerifiedBackupInfo,
)
from superbrain.ports.os import OsAdapters

__all__ = [
    "RestoreOutcome",
    "RestorePreview",
    "diff_to_json",
    "outcome_to_json",
    "preview_online_restore",
    "preview_restore",
    "register_maintenance_backend",
    "restore_offline",
    "restore_offline_preview_payload",
    "validate_restore_approval_target",
]

_DEFAULT_BACKEND: MaintenanceStoragePort | None = None


def register_maintenance_backend(backend: MaintenanceStoragePort) -> None:
    """Register the concrete storage backend from the composition layer."""
    global _DEFAULT_BACKEND
    _DEFAULT_BACKEND = backend


def _resolve_backend(backend: MaintenanceStoragePort | None) -> MaintenanceStoragePort:
    resolved = backend if backend is not None else _DEFAULT_BACKEND
    if resolved is None:
        raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "maintenance storage backend not wired")
    return resolved


def outcome_to_json(outcome: RestoreOutcome) -> dict[str, JsonValue]:
    """Serialize a ``RestoreOutcome`` to JSON-compatible operator/CLI payload fields."""
    return {
        "target": outcome.target_kind,
        "store_id": outcome.store_id,
        "restored_from": str(outcome.restored_from),
        "replaced_dir": str(outcome.replaced_dir),
        "new_epoch": outcome.new_epoch,
        "restore_epoch": outcome.restore_epoch,
        "trust_generation": outcome.trust_generation,
    }


def _format_preview_payload(
    prev: RestorePreview, *, backup: Path, challenge: dict[str, JsonValue]
) -> dict[str, JsonValue]:
    data: dict[str, JsonValue] = {
        "target": prev.target_kind,
        "store_id": prev.store_id,
        "backup": str(backup),
        "backup_id": prev.backup_id,
        "backup_db_digest": prev.backup_db_digest,
        "target_epoch_or_gen": prev.target_epoch_or_gen,
        "subject_id": prev.subject_id,
        "challenge": challenge,
    }
    if prev.diff is not None:
        data["diff"] = diff_to_json(prev.diff)
    return data


def _check_approval_envelope(
    message: ApprovalMessage, *, store_id: str, manifest: VerifiedBackupInfo
) -> None:
    if (
        message.action is not ApprovalAction.RESTORE
        or message.risk_level is not RiskLevel.HIGH
        or message.store_id != store_id
        or tuple(message.resource_digests) != (ResourceDigest("backup", manifest.db_digest),)
    ):
        raise BrainError(ErrorCode.REVISION_CONFLICT, "approval does not match restore target")


def preview_restore(
    root_path: Path,
    os_: OsAdapters,
    *,
    target: Literal["store", "policy"],
    backup: Path,
    store_id: str,
    now: datetime | None = None,
    store_migrations: Sequence[object] | None = None,
    policy_migrations: Sequence[object] | None = None,
    backend: MaintenanceStoragePort | None = None,
) -> RestorePreview:
    """Preview an offline restore without mutating ``writer.lock`` or databases; enforces schema ceilings first."""
    require_opaque_id(store_id, label="store_id")
    now_dt = os_.clock.now() if now is None else now
    return _resolve_backend(backend).preview_restore(
        root_path,
        os_,
        target=target,
        backup=backup,
        store_id=store_id,
        now=now_dt,
        store_migrations=store_migrations,
        policy_migrations=policy_migrations,
    )


def restore_offline_preview_payload(
    root_path: Path,
    os_: OsAdapters,
    *,
    target: Literal["store", "policy"],
    backup: Path,
    store_id: str,
    now: datetime | None = None,
    store_migrations: Sequence[object] | None = None,
    policy_migrations: Sequence[object] | None = None,
    backend: MaintenanceStoragePort | None = None,
) -> dict[str, JsonValue]:
    """Build JSON preview payload + challenge for ``brain restore --offline --preview``."""
    require_opaque_id(store_id, label="store_id")
    now_dt = os_.clock.now() if now is None else now
    prev, issued = _resolve_backend(backend).offline_preview_with_challenge(
        root_path,
        os_,
        target=target,
        backup=backup,
        store_id=store_id,
        now=now_dt,
        store_migrations=store_migrations,
        policy_migrations=policy_migrations,
    )
    if issued is not None:
        challenge = challenge_from_issued(store_id, issued)
    else:
        challenge = {
            "store_id": store_id,
            "action": ApprovalAction.RESTORE.value,
            "subject_id": prev.subject_id,
            "risk_level": RiskLevel.HIGH.value,
            "trust_generation": prev.trust_generation,
            "nonce": new_id(),
            "expires_at": canonical_utc(now_dt + APPROVAL_TTL),
        }
    return _format_preview_payload(prev, backup=backup, challenge=challenge)


def preview_online_restore(
    root: object,
    lease: object,
    policy: object,
    os_: OsAdapters,
    *,
    target: Literal["store", "policy"],
    backup: Path,
    now: datetime | None = None,
    store_migrations: Sequence[object] | None = None,
    policy_migrations: Sequence[object] | None = None,
    backend: MaintenanceStoragePort | None = None,
) -> dict[str, JsonValue]:
    """Build online ``/v2/operator/restore`` preview payload and issue a live approval nonce."""
    now_dt = os_.clock.now() if now is None else now
    prev, issued = _resolve_backend(backend).online_preview_with_challenge(
        root,
        lease,
        policy,
        os_,
        target=target,
        backup=backup,
        now=now_dt,
        store_migrations=store_migrations,
        policy_migrations=policy_migrations,
    )
    return _format_preview_payload(prev, backup=backup, challenge=challenge_from_issued(prev.store_id, issued))


def validate_restore_approval_target(
    root: object,
    lease: object,
    os_: OsAdapters,
    *,
    target: Literal["store", "policy"],
    backup: Path,
    store_id: str,
    message: ApprovalMessage,
    now: datetime | None = None,
    store_migrations: Sequence[object] | None = None,
    policy_migrations: Sequence[object] | None = None,
    backend: MaintenanceStoragePort | None = None,
) -> tuple[VerifiedBackupInfo, RestorePreview, datetime]:
    """Verify backup integrity and match ``message`` against the computed restore preview under ``lease``."""
    now_dt = os_.clock.now() if now is None else now
    manifest, prev = _resolve_backend(backend).validate_online_target(
        root,
        lease,
        os_,
        target=target,
        backup=backup,
        store_id=store_id,
        now=now_dt,
        store_migrations=store_migrations,
        policy_migrations=policy_migrations,
    )
    _check_approval_envelope(message, store_id=store_id, manifest=manifest)
    if message.subject_id != prev.subject_id:
        raise BrainError(ErrorCode.REVISION_CONFLICT, "restore subject_id mismatch")
    return manifest, prev, now_dt


def restore_offline(
    root_path: Path,
    store_id: str,
    os_: OsAdapters,
    *,
    target: Literal["store", "policy"],
    backup: Path,
    approval_payload: Mapping[str, JsonValue],
    ssh_verifier: Callable[[], SshApprovalVerifierPort | None] | None = None,
    webauthn_verifier: WebAuthnApprovalVerifierPort | None = None,
    now: datetime | None = None,
    store_migrations: Sequence[object] | None = None,
    policy_migrations: Sequence[object] | None = None,
    store_hooks: Sequence[object] = (),
    policy_hooks: Sequence[object] = (),
    backend: MaintenanceStoragePort | None = None,
) -> RestoreOutcome:
    """Execute offline DR ``brain restore --offline`` under ``WriterLease`` with live or backup signer proof."""
    require_opaque_id(store_id, label="store_id")
    stor = _resolve_backend(backend)
    manifest, _ = stor.verify_offline_backup_and_ceilings(
        root_path,
        os_,
        target=target,
        backup=backup,
        store_id=store_id,
        store_migrations=store_migrations,
        policy_migrations=policy_migrations,
    )
    message, channel, signer_id = parse_offline_approval(approval_payload)
    _check_approval_envelope(message, store_id=store_id, manifest=manifest)
    now_dt = os_.clock.now() if now is None else now

    def _verify_live(signer: SignerRecord | None) -> None:
        if signer is None or signer.revoked or signer.channel is not channel or signer.owner_id != message.owner_id:
            raise BrainError(ErrorCode.UNAUTHENTICATED, "unauthenticated")
        if channel is ApprovalChannel.PASSKEY_UV:
            raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "passkey verifier unavailable offline")
        verify_ssh_proof(message, approval_payload, signer, channel, ssh_verifier)

    def _verify_dr(hwm: int, signer: SignerRecord | None) -> None:
        assert manifest.trust_generation is not None
        if message.trust_generation < max(hwm, manifest.trust_generation) or now_dt >= message.expires_at:
            raise BrainError(ErrorCode.UNAUTHENTICATED, "stale or expired restore approval")
        verify_backup_signer_record_dr(
            signer, message, channel, approval_payload, ssh_verifier, webauthn_verifier
        )

    return stor.execute_offline_restore(
        root_path,
        store_id,
        os_,
        target=target,
        backup=backup,
        manifest=manifest,
        now=now_dt,
        message=message,
        channel=channel,
        signer_id=signer_id,
        verify_live=_verify_live,
        verify_dr=_verify_dr,
        store_migrations=store_migrations,
        policy_migrations=policy_migrations,
        store_hooks=store_hooks,
        policy_hooks=policy_hooks,
    )
