"""Concrete storage-layer adapter backing ``MaintenanceStoragePort``."""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Callable, Sequence
from datetime import datetime
from pathlib import Path
from typing import Literal, cast

from superbrain.core._kernel_approval import (
    ApprovalAction,
    ApprovalChannel,
    ApprovalMessage,
    IssuedNonce,
    RiskLevel,
    SignerRecord,
    restore_subject_id,
)
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.maintenance import (
    MaintenanceStoragePort,
    PolicyRestoreAuthorityDiff,
    RestoreOutcome,
    RestorePreview,
    VerifiedBackupInfo,
)
from superbrain.ports.os import OsAdapters
from superbrain.storage import _policy_approvals as policy_approvals
from superbrain.storage.backup import BackupManifest, verify_backup
from superbrain.storage.cas import validate_path_syntax
from superbrain.storage.kernel_schema import KERNEL_POLICY_MIGRATIONS, KERNEL_STORE_MIGRATIONS
from superbrain.storage.layout import DataRoot, verify_existing_data_root
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.restore import (
    PolicyRestoreStageHook,
    RestoreStageHook,
    preview_policy_restore,
    read_restore_epoch,
    restore_policy,
    restore_store,
)
from superbrain.storage.schema import Migration, code_version, read_schema_info
from superbrain.storage.sqlite import open_immutable, open_readonly
from superbrain.storage.writer import WriterLease, acquire_writer_unbumped


def _store_migs(migrations: Sequence[object] | None) -> Sequence[Migration]:
    return KERNEL_STORE_MIGRATIONS if migrations is None else cast(Sequence[Migration], migrations)


def _policy_migs(migrations: Sequence[object] | None) -> Sequence[Migration]:
    return KERNEL_POLICY_MIGRATIONS if migrations is None else cast(Sequence[Migration], migrations)


def _to_info(manifest: BackupManifest) -> VerifiedBackupInfo:
    return VerifiedBackupInfo(
        kind=manifest.kind,
        schema_version=manifest.schema_version,
        db_digest=manifest.db_digest,
        trust_generation=manifest.trust_generation,
        logical_verified=manifest.logical_verified,
    )


def _check_ceiling(path: Path, migrations: Sequence[Migration], label: str) -> int | None:
    if not os.path.lexists(path):
        return None
    target = code_version(migrations)
    try:
        info = read_schema_info(path)
    except BrainError as err:
        if err.code is ErrorCode.INTEGRITY_FAILURE:
            return None
        raise
    if info is None:
        return None
    if info.schema_version > target or info.min_reader_version > target:
        raise BrainError(
            ErrorCode.UNSUPPORTED_VERSION,
            f"live {label} schema {info.schema_version} exceeds code version {target}",
        )
    return info.schema_version


def _check_live_schema_ceilings(
    root: DataRoot, *, store_migrations: Sequence[Migration], policy_migrations: Sequence[Migration]
) -> tuple[int | None, int | None]:
    policy_ver = _check_ceiling(root.policy_db, policy_migrations, "policy")
    store_ver = _check_ceiling(root.store_db, store_migrations, "store")
    return policy_ver, store_ver


def _verify_target_backup(
    backup: Path,
    *,
    target: Literal["store", "policy"],
    store_id: str,
    store_migrations: Sequence[Migration],
    policy_migrations: Sequence[Migration],
    os_: OsAdapters,
) -> BackupManifest:
    if target not in ("store", "policy"):
        raise BrainError(ErrorCode.INVALID_INPUT, f"unknown restore target {target!r}")
    validate_path_syntax(backup, os_)
    migs = store_migrations if target == "store" else policy_migrations
    target_ver = code_version(migs)
    if target == "store":
        manifest = verify_backup(
            backup,
            expected_kind=frozenset({"store", "store_full"}),
            expected_store_id=store_id,
            migrations=migs,
            os_=os_,
        )
    else:
        manifest = verify_backup(
            backup,
            expected_kind="policy",
            expected_store_id=store_id,
            migrations=migs,
            os_=os_,
        )
    if not manifest.logical_verified or manifest.schema_version > target_ver:
        raise BrainError(
            ErrorCode.UNSUPPORTED_VERSION,
            f"backup {backup.name} schema {manifest.schema_version} exceeds code version {target_ver}",
        )
    return manifest


def _read_live_trust_generation(root: DataRoot) -> int | None:
    if not os.path.lexists(root.policy_db):
        return None
    try:
        db = open_readonly(root.policy_db)
        try:
            row = db.execute("SELECT generation FROM trust WHERE id = 1").fetchone()
            return int(row[0]) if row is not None and type(row[0]) is int else None
        finally:
            db.close()
    except (BrainError, sqlite3.Error):
        return None


def _build_preview(
    root: DataRoot,
    lease: WriterLease,
    os_: OsAdapters,
    *,
    target: Literal["store", "policy"],
    backup: Path,
    db_digest: str,
    store_id: str,
    now_dt: datetime,
    policy_migrations: Sequence[Migration],
) -> RestorePreview:
    state = lease.state()
    hwm = state.trust_generation_hwm
    live_gen = _read_live_trust_generation(root)
    diff: PolicyRestoreAuthorityDiff | None
    if target == "policy":
        diff = preview_policy_restore(
            root,
            backup,
            store_id=store_id,
            os_=os_,
            now=now_dt,
            migrations=policy_migrations,
            hwm=hwm,
        )
        target_epoch_or_gen = diff.next_trust_generation
        eff_gen = live_gen if live_gen is not None else max(hwm, diff.backup_trust_generation)
    else:
        diff = None
        target_epoch_or_gen = state.writer_epoch + 1
        eff_gen = live_gen if live_gen is not None else hwm
    subj = restore_subject_id(
        target_kind=target,
        backup_id=backup.name,
        backup_db_digest=db_digest,
        target_epoch_or_gen=target_epoch_or_gen,
    )
    return RestorePreview(
        target_kind=target,
        store_id=store_id,
        backup_id=backup.name,
        backup_db_digest=db_digest,
        trust_generation=eff_gen,
        target_epoch_or_gen=target_epoch_or_gen,
        subject_id=subj,
        diff=diff,
    )


class StorageMaintenanceAdapter(MaintenanceStoragePort):
    """Concrete ``MaintenanceStoragePort`` backed by ``superbrain.storage``."""

    def check_live_schema_ceilings(
        self,
        root_path: Path,
        os_: OsAdapters,
        *,
        store_migrations: Sequence[object] | None,
        policy_migrations: Sequence[object] | None,
    ) -> tuple[int | None, int | None]:
        root = verify_existing_data_root(root_path, os_)
        return _check_live_schema_ceilings(
            root, store_migrations=_store_migs(store_migrations), policy_migrations=_policy_migs(policy_migrations)
        )

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
    ) -> RestorePreview:
        s_migs, p_migs = _store_migs(store_migrations), _policy_migs(policy_migrations)
        root = verify_existing_data_root(root_path, os_)
        _check_live_schema_ceilings(root, store_migrations=s_migs, policy_migrations=p_migs)
        manifest = _verify_target_backup(
            backup, target=target, store_id=store_id, store_migrations=s_migs, policy_migrations=p_migs, os_=os_
        )
        lease = acquire_writer_unbumped(root, os_)
        try:
            return _build_preview(
                root,
                lease,
                os_,
                target=target,
                backup=backup,
                db_digest=manifest.db_digest,
                store_id=store_id,
                now_dt=now,
                policy_migrations=p_migs,
            )
        finally:
            lease.release()

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
    ) -> tuple[RestorePreview, IssuedNonce | None]:
        s_migs, p_migs = _store_migs(store_migrations), _policy_migs(policy_migrations)
        root = verify_existing_data_root(root_path, os_)
        _check_live_schema_ceilings(root, store_migrations=s_migs, policy_migrations=p_migs)
        manifest = _verify_target_backup(
            backup, target=target, store_id=store_id, store_migrations=s_migs, policy_migrations=p_migs, os_=os_
        )
        lease = acquire_writer_unbumped(root, os_)
        try:
            prev = _build_preview(
                root,
                lease,
                os_,
                target=target,
                backup=backup,
                db_digest=manifest.db_digest,
                store_id=store_id,
                now_dt=now,
                policy_migrations=p_migs,
            )
            if _read_live_trust_generation(root) is None:
                return prev, None
            pol = PolicyStore.open(root, lease, os_, migrations=p_migs)
            try:
                issued = pol.issue_nonce(
                    action=ApprovalAction.RESTORE, subject_id=prev.subject_id, risk_level=RiskLevel.HIGH
                )
            finally:
                pol.close()
            return prev, issued
        finally:
            lease.release()

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
    ) -> tuple[RestorePreview, IssuedNonce]:
        s_migs, p_migs = _store_migs(store_migrations), _policy_migs(policy_migrations)
        dr = cast(DataRoot, root)
        wl = cast(WriterLease, lease)
        pol = cast(PolicyStore, policy)
        store_id = pol.store_id
        manifest = _verify_target_backup(
            backup, target=target, store_id=store_id, store_migrations=s_migs, policy_migrations=p_migs, os_=os_
        )
        prev = _build_preview(
            dr,
            wl,
            os_,
            target=target,
            backup=backup,
            db_digest=manifest.db_digest,
            store_id=store_id,
            now_dt=now,
            policy_migrations=p_migs,
        )
        issued = pol.issue_nonce(action=ApprovalAction.RESTORE, subject_id=prev.subject_id, risk_level=RiskLevel.HIGH)
        return prev, issued

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
    ) -> tuple[VerifiedBackupInfo, RestorePreview]:
        s_migs, p_migs = _store_migs(store_migrations), _policy_migs(policy_migrations)
        dr = cast(DataRoot, root)
        wl = cast(WriterLease, lease)
        manifest = _verify_target_backup(
            backup, target=target, store_id=store_id, store_migrations=s_migs, policy_migrations=p_migs, os_=os_
        )
        prev = _build_preview(
            dr,
            wl,
            os_,
            target=target,
            backup=backup,
            db_digest=manifest.db_digest,
            store_id=store_id,
            now_dt=now,
            policy_migrations=p_migs,
        )
        return _to_info(manifest), prev

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
    ) -> tuple[VerifiedBackupInfo, int | None]:
        s_migs, p_migs = _store_migs(store_migrations), _policy_migs(policy_migrations)
        root = verify_existing_data_root(root_path, os_)
        _, store_ver = _check_live_schema_ceilings(root, store_migrations=s_migs, policy_migrations=p_migs)
        manifest = _verify_target_backup(
            backup, target=target, store_id=store_id, store_migrations=s_migs, policy_migrations=p_migs, os_=os_
        )
        return _to_info(manifest), store_ver

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
    ) -> RestoreOutcome:
        s_migs, p_migs = _store_migs(store_migrations), _policy_migs(policy_migrations)
        s_hooks = cast(Sequence[RestoreStageHook], store_hooks)
        p_hooks = cast(Sequence[PolicyRestoreStageHook], policy_hooks)
        root = verify_existing_data_root(root_path, os_)
        _, store_ver = _check_live_schema_ceilings(root, store_migrations=s_migs, policy_migrations=p_migs)
        lease = acquire_writer_unbumped(root, os_)
        try:
            prev = _build_preview(
                root,
                lease,
                os_,
                target=target,
                backup=backup,
                db_digest=manifest.db_digest,
                store_id=store_id,
                now_dt=now,
                policy_migrations=p_migs,
            )
            if message.subject_id != prev.subject_id:
                raise BrainError(ErrorCode.REVISION_CONFLICT, "restore subject_id mismatch")
            if _read_live_trust_generation(root) is not None:
                pol = PolicyStore.open(root, lease, os_, migrations=p_migs)
                try:
                    verify_live(pol.signer(signer_id))
                    pol.consume_approval(message, signer_id=signer_id, channel=channel)
                    if target == "store":
                        rep = restore_store(
                            root, lease, os_, backup, pol, now, migrations=s_migs, stage_hooks=s_hooks
                        )
                        re_epoch = read_restore_epoch(root, schema_version=code_version(s_migs), os_=os_)
                        return RestoreOutcome(
                            target_kind="store",
                            store_id=store_id,
                            restored_from=backup,
                            replaced_dir=rep.replaced_dir,
                            new_epoch=rep.new_epoch,
                            restore_epoch=re_epoch,
                            trust_generation=pol.trust_generation(),
                        )
                finally:
                    pol.close()
                rep = restore_policy(
                    root, lease, os_, backup, store_id=store_id, now=now, migrations=p_migs, stage_hooks=p_hooks
                )
            else:
                if target != "policy":
                    raise BrainError(
                        ErrorCode.INTEGRITY_FAILURE,
                        "live policy store missing or corrupt; restore policy first",
                    )
                hwm = lease.state().trust_generation_hwm
                db = open_immutable(backup / "policy.db")
                try:
                    signer = policy_approvals.read_signer(db, signer_id)
                finally:
                    db.close()
                verify_dr(hwm, signer)
                rep = restore_policy(
                    root,
                    lease,
                    os_,
                    backup,
                    store_id=store_id,
                    now=now,
                    migrations=p_migs,
                    stage_hooks=p_hooks,
                    allow_corrupt_live=True,
                )
            re_epoch = (
                read_restore_epoch(root, schema_version=store_ver, os_=os_)
                if store_ver is not None and os.path.lexists(root.store_db)
                else 0
            )
            return RestoreOutcome(
                target_kind="policy",
                store_id=store_id,
                restored_from=backup,
                replaced_dir=rep.replaced_dir,
                new_epoch=rep.new_epoch,
                restore_epoch=re_epoch,
                trust_generation=rep.trust_generation,
            )
        finally:
            lease.release()
