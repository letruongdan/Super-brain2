"""Ports and value types for maintenance preview/restore workflows across layers."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal, Protocol

from superbrain.core._kernel_approval import ApprovalChannel, ApprovalMessage, IssuedNonce, SignerRecord
from superbrain.ports.os import OsAdapters


@dataclass(frozen=True)
class PolicyRestoreAuthorityDiff:
    """Authority delta computed between live state and a verified ``policy`` backup."""

    backup_trust_generation: int
    next_trust_generation: int
    revived_signers: tuple[SignerRecord, ...]
    revived_credential_ids: tuple[str, ...]
    removed_quarantines: tuple[str, ...]
    removed_tombstones: tuple[tuple[str, str], ...]
    affected_periods: tuple[str, ...]


@dataclass(frozen=True)
class RestorePreview:
    """Computed target restore preview including deterministic ``subject_id``."""

    target_kind: Literal["store", "policy"]
    store_id: str
    backup_id: str
    backup_db_digest: str
    trust_generation: int
    target_epoch_or_gen: int
    subject_id: str
    diff: PolicyRestoreAuthorityDiff | None


@dataclass(frozen=True)
class RestoreOutcome:
    """Completed online or offline store/policy restore outcome."""

    target_kind: Literal["store", "policy"]
    store_id: str
    restored_from: Path
    replaced_dir: Path
    new_epoch: int
    restore_epoch: int
    trust_generation: int | None


@dataclass(frozen=True)
class VerifiedBackupInfo:
    """Minimal verified backup metadata exposed across the storage/application port."""

    kind: str
    schema_version: int
    db_digest: str
    trust_generation: int | None
    logical_verified: bool


class MaintenanceStoragePort(Protocol):
    """Storage-layer operations required by ``application.maintenance``."""

    def check_live_schema_ceilings(
        self,
        root_path: Path,
        os_: OsAdapters,
        *,
        store_migrations: Sequence[object] | None,
        policy_migrations: Sequence[object] | None,
    ) -> tuple[int | None, int | None]: ...

    def preview_restore(
        self,
        root_path: Path,
        os_: OsAdapters,
        *,
        target: Literal["store", "policy"],
        backup: Path,
        store_id: str,
        now: datetime,
        store_migrations: Sequence[object] | None,
        policy_migrations: Sequence[object] | None,
    ) -> RestorePreview: ...

    def offline_preview_with_challenge(
        self,
        root_path: Path,
        os_: OsAdapters,
        *,
        target: Literal["store", "policy"],
        backup: Path,
        store_id: str,
        now: datetime,
        store_migrations: Sequence[object] | None,
        policy_migrations: Sequence[object] | None,
    ) -> tuple[RestorePreview, IssuedNonce | None]: ...

    def online_preview_with_challenge(
        self,
        root: object,
        lease: object,
        policy: object,
        os_: OsAdapters,
        *,
        target: Literal["store", "policy"],
        backup: Path,
        now: datetime,
        store_migrations: Sequence[object] | None,
        policy_migrations: Sequence[object] | None,
    ) -> tuple[RestorePreview, IssuedNonce]: ...

    def validate_online_target(
        self,
        root: object,
        lease: object,
        os_: OsAdapters,
        *,
        target: Literal["store", "policy"],
        backup: Path,
        store_id: str,
        now: datetime,
        store_migrations: Sequence[object] | None,
        policy_migrations: Sequence[object] | None,
    ) -> tuple[VerifiedBackupInfo, RestorePreview]: ...

    def verify_offline_backup_and_ceilings(
        self,
        root_path: Path,
        os_: OsAdapters,
        *,
        target: Literal["store", "policy"],
        backup: Path,
        store_id: str,
        store_migrations: Sequence[object] | None,
        policy_migrations: Sequence[object] | None,
    ) -> tuple[VerifiedBackupInfo, int | None]: ...

    def execute_offline_restore(
        self,
        root_path: Path,
        store_id: str,
        os_: OsAdapters,
        *,
        target: Literal["store", "policy"],
        backup: Path,
        manifest: VerifiedBackupInfo,
        now: datetime,
        message: ApprovalMessage,
        channel: ApprovalChannel,
        signer_id: str,
        verify_live: Callable[[SignerRecord | None], None],
        verify_dr: Callable[[int, SignerRecord | None], None],
        store_migrations: Sequence[object] | None,
        policy_migrations: Sequence[object] | None,
        store_hooks: Sequence[object],
        policy_hooks: Sequence[object],
    ) -> RestoreOutcome: ...
