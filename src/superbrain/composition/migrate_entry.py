"""Offline two-schema migration entry point: upgrades ``policy`` first, then ``store``, under one lease."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from superbrain.adapters.os import os_adapters
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.faults import crashpoint
from superbrain.core.kernel import DaemonConfig
from superbrain.ports.os import OsAdapters
from superbrain.storage.kernel_schema import KERNEL_POLICY_MIGRATIONS, KERNEL_STORE_MIGRATIONS
from superbrain.storage.migrate import MigrationReport, migrate_database
from superbrain.storage.runtime import admit_existing_pair
from superbrain.storage.schema import Migration, code_version, read_schema_info


@dataclass(frozen=True)
class TargetMigrationOutcome:
    target: Literal["policy", "store"]
    status: Literal["migrated", "skipped"]
    from_version: int
    to_version: int
    report: MigrationReport | None = None

    @property
    def backup(self) -> Path | None:
        return self.report.backup if self.report is not None else None

    @property
    def replaced_dir(self) -> Path | None:
        return self.report.replaced_dir if self.report is not None else None


@dataclass(frozen=True)
class OfflineMigrationReport:
    store_id: str
    writer_epoch: int
    policy_report: TargetMigrationOutcome
    store_report: TargetMigrationOutcome

    @property
    def noop(self) -> bool:
        return self.policy_report.status == "skipped" and self.store_report.status == "skipped"


def migrate_offline(
    config: DaemonConfig,
    os_: OsAdapters | None = None,
    *,
    policy_migrations: Sequence[Migration] = KERNEL_POLICY_MIGRATIONS,
    store_migrations: Sequence[Migration] = KERNEL_STORE_MIGRATIONS,
    _after_policy_step: Callable[[], None] | None = None,
) -> OfflineMigrationReport:
    """Admit ``config.data_root`` for migration and upgrade ``policy`` then ``store`` under a single writer lease.

    Note: ``config.cert_path`` and ``config.key_path`` are intentionally not opened during ``migrate_offline``;
    TLS certificate/key bytes are loaded only when starting ``serve``.
    """
    if not isinstance(config, DaemonConfig):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    adapters = os_ if os_ is not None else os_adapters()
    target_policy = code_version(policy_migrations)
    target_store = code_version(store_migrations)

    admitted = admit_existing_pair(
        config.data_root,
        config.expected_store_id,
        adapters,
        purpose="migrate",
        policy_migrations=policy_migrations,
        store_migrations=store_migrations,
    )
    try:
        p_info = read_schema_info(admitted.root.policy_db)
        if p_info is None or p_info.store_id != config.expected_store_id:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "policy database missing or mismatched before migrate")
        if p_info.schema_version < target_policy:
            p_rep = migrate_database(
                admitted.root,
                admitted.lease,
                adapters,
                target="policy",
                migrations=policy_migrations,
                now=adapters.clock.now(),
            )
            crashpoint("kernel.migrate.after_policy_swap")  # only when the policy really migrated
            policy_outcome = TargetMigrationOutcome(
                target="policy",
                status="migrated",
                from_version=p_rep.from_version,
                to_version=p_rep.to_version,
                report=p_rep,
            )
        else:
            policy_outcome = TargetMigrationOutcome(
                target="policy",
                status="skipped",
                from_version=p_info.schema_version,
                to_version=target_policy,
                report=None,
            )

        if _after_policy_step is not None:
            _after_policy_step()

        s_info = read_schema_info(admitted.root.store_db)
        if s_info is None or s_info.store_id != config.expected_store_id:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "store database missing or mismatched before migrate")
        if s_info.schema_version < target_store:
            s_rep = migrate_database(
                admitted.root,
                admitted.lease,
                adapters,
                target="store",
                migrations=store_migrations,
                now=adapters.clock.now(),
            )
            store_outcome = TargetMigrationOutcome(
                target="store",
                status="migrated",
                from_version=s_rep.from_version,
                to_version=s_rep.to_version,
                report=s_rep,
            )
        else:
            store_outcome = TargetMigrationOutcome(
                target="store",
                status="skipped",
                from_version=s_info.schema_version,
                to_version=target_store,
                report=None,
            )

        return OfflineMigrationReport(
            store_id=config.expected_store_id,
            writer_epoch=admitted.lease.epoch,
            policy_report=policy_outcome,
            store_report=store_outcome,
        )
    finally:
        admitted.release()
