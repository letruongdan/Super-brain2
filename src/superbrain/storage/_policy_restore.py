"""Policy restore authority diff preview, stage locks, carry-forward and ``PolicyRestoreStageHook`` (I3-4)."""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol

from superbrain.core._kernel_approval import SignerRecord
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import InvocationState
from superbrain.ports.maintenance import PolicyRestoreAuthorityDiff
from superbrain.ports.os import OsAdapters
from superbrain.storage import _policy_approvals as approvals
from superbrain.storage._policy_accounting import ensure_accounting_schema
from superbrain.storage._policy_layer2 import SIGNER_RESET_META_KEY
from superbrain.storage.backup import BackupManifest, verify_backup
from superbrain.storage.errors import sqlite_error
from superbrain.storage.layout import DataRoot
from superbrain.storage.ledger import utc_timestamp
from superbrain.storage.schema import POLICY_MIGRATIONS, Migration, code_version
from superbrain.storage.sqlite import apply_durability_pragmas, db_files, open_immutable, open_readonly
from superbrain.storage.writer import _read_slots

__all__ = [
    "PolicyRestoreAuthorityDiff",
    "PolicyRestoreStageHook",
    "preview_policy_restore",
    "stage_policy_restore_effects",
]


class PolicyRestoreStageHook(Protocol):
    """Extension hook invoked inside ``restore_policy``'s stage before ``READY``."""

    def on_stage_policy(
        self,
        live_policy_db: Path | None,
        staged_policy_db: sqlite3.Connection,
        *,
        manifest: BackupManifest,
        now: datetime,
        trust_generation: int,
    ) -> None: ...


def _table_exists(db: sqlite3.Connection, name: str) -> bool:
    return db.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)).fetchone() is not None


def _affected_periods(backup_created_at: str, now: datetime) -> tuple[str, ...]:
    start = datetime.fromisoformat(backup_created_at.replace("Z", "+00:00")).astimezone(UTC).date()
    end = now.astimezone(UTC).date()
    if end < start:
        return (end.strftime("%Y-%m-%d"),)
    days = (end - start).days
    return tuple((start + timedelta(days=offset)).strftime("%Y-%m-%d") for offset in range(days + 1))


def _read_lock_hwm(root: DataRoot, os_: OsAdapters) -> int:
    if not os.path.lexists(root.lock_path):
        return 0
    handle = os_.locks.acquire(root.lock_path)
    try:
        slot, _ = _read_slots(handle.read_payload())
        return slot.trust_generation_hwm
    finally:
        handle.release()


def _read_authority_sets(
    db: sqlite3.Connection,
) -> tuple[dict[str, SignerRecord], set[str], set[str], set[tuple[str, str]], int]:
    signers: dict[str, SignerRecord] = {}
    if _table_exists(db, "signer"):
        signers = {s.signer_id: s for s in approvals.active_signers(db)}
    creds: set[str] = set()
    if _table_exists(db, "credential"):
        creds = {str(r[0]) for r in db.execute("SELECT id FROM credential WHERE revoked_intent_id IS NULL").fetchall()}
    quars = {str(r[0]) for r in db.execute("SELECT digest FROM quarantine").fetchall()}
    tombs = {(str(r[0]), str(r[1])) for r in db.execute("SELECT holder_kind, holder_id FROM tombstones").fetchall()}
    row = db.execute("SELECT generation FROM trust WHERE id = 1").fetchone()
    gen = int(row[0]) if row is not None else 0
    return signers, creds, quars, tombs, gen


def preview_policy_restore(
    root: DataRoot,
    backup: Path,
    *,
    store_id: str,
    os_: OsAdapters,
    now: datetime,
    migrations: Sequence[Migration] = POLICY_MIGRATIONS,
    hwm: int | None = None,
) -> PolicyRestoreAuthorityDiff:
    """Compute exact authority diff and affected UTC accounting periods before approving ``restore_policy``."""
    target = code_version(migrations)
    manifest = verify_backup(backup, expected_kind="policy", expected_store_id=store_id, migrations=migrations, os_=os_)
    if manifest.schema_version > target:
        raise BrainError(
            ErrorCode.UNSUPPORTED_VERSION,
            f"the backup {backup.name} has schema {manifest.schema_version}, which exceeds code version {target}",
        )
    if manifest.trust_generation is None:
        raise AssertionError("verified policy backup must have trust_generation")

    bak_db = open_immutable(backup / "policy.db")
    try:
        bak_signers, bak_creds, bak_quars, bak_tombs, _ = _read_authority_sets(bak_db)
    finally:
        bak_db.close()

    live_signers: set[str] = set()
    live_creds: set[str] = set()
    live_quars: set[str] = set()
    live_tombs: set[tuple[str, str]] = set()
    live_gen = 0
    if os.path.lexists(root.policy_db):
        try:
            live_db = open_readonly(root.policy_db)
            try:
                ls, lc, lq, lt, lg = _read_authority_sets(live_db)
                live_signers = set(ls)
                live_creds = lc
                live_quars = lq
                live_tombs = lt
                live_gen = lg
            finally:
                live_db.close()
        except (BrainError, sqlite3.Error):
            pass

    resolved_hwm = _read_lock_hwm(root, os_) if hwm is None else hwm
    next_gen = max(resolved_hwm, manifest.trust_generation, live_gen) + 1
    return PolicyRestoreAuthorityDiff(
        backup_trust_generation=manifest.trust_generation,
        next_trust_generation=next_gen,
        revived_signers=tuple(bak_signers[sid] for sid in bak_signers if sid not in live_signers),
        revived_credential_ids=tuple(sorted(cid for cid in bak_creds if cid not in live_creds)),
        removed_quarantines=tuple(sorted(d for d in live_quars if d not in bak_quars)),
        removed_tombstones=tuple(sorted(t for t in live_tombs if t not in bak_tombs)),
        affected_periods=_affected_periods(manifest.created_at, now),
    )


def _carry_forward_from_live(live_path: Path, staged_db: sqlite3.Connection) -> None:
    live_db = open_readonly(live_path)
    try:
        tables = {str(r[0]) for r in live_db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        if "accounting_locks" in tables:
            cols = {str(r[1]) for r in live_db.execute("PRAGMA table_info(accounting_locks)").fetchall()}
            if "period_key" in cols:
                rows = live_db.execute(
                    "SELECT lock_key, owner_id, period_key, backup_created_at, locked_at, state, "
                    "reconciled_at, reconciled_approval_id FROM accounting_locks WHERE state = 'locked'"
                ).fetchall()
                for row in rows:
                    staged_db.execute(
                        "INSERT INTO accounting_locks "
                        "(lock_key, owner_id, period_key, backup_created_at, locked_at, state, "
                        "reconciled_at, reconciled_approval_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
                        "ON CONFLICT (lock_key) DO UPDATE SET state = 'locked', locked_at = excluded.locked_at, "
                        "reconciled_at = NULL, reconciled_approval_id = NULL",
                        tuple(row),
                    )
        if "accounting_invocations" in tables:
            inv_cols = {str(r[1]) for r in live_db.execute("PRAGMA table_info(accounting_invocations)").fetchall()}
            if "owner_id" in inv_cols:
                inv_rows = live_db.execute(
                    "SELECT invocation_id, job_id, owner_id, writer_epoch, period_key, reserved_amount, "
                    "settled_amount, state, recorded_at, updated_at FROM accounting_invocations "
                    "WHERE state IN ('reserved', 'outcome_unknown')"
                ).fetchall()
                for row in inv_rows:
                    vals = list(row)
                    if vals[7] == InvocationState.RESERVED.value:
                        vals[7] = InvocationState.OUTCOME_UNKNOWN.value
                    staged_db.execute(
                        "INSERT INTO accounting_invocations "
                        "(invocation_id, job_id, owner_id, writer_epoch, period_key, reserved_amount, "
                        "settled_amount, state, recorded_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                        "ON CONFLICT (invocation_id) DO UPDATE SET state = excluded.state, "
                        "reserved_amount = excluded.reserved_amount, updated_at = excluded.updated_at",
                        tuple(vals),
                    )
        if "meta" in tables:
            reset_row = live_db.execute(
                "SELECT value FROM meta WHERE key = ? AND value = '1'", (SIGNER_RESET_META_KEY,)
            ).fetchone()
            if reset_row is not None:
                staged_db.execute(
                    "INSERT OR REPLACE INTO meta (key, value) VALUES (?, '1')", (SIGNER_RESET_META_KEY,)
                )
    finally:
        live_db.close()


def stage_policy_restore_effects(
    root: DataRoot,
    staged_db_path: Path,
    *,
    manifest: BackupManifest,
    generation: int,
    now: datetime,
    os_: OsAdapters,
    live_carry_forward: bool,
    stage_hooks: Sequence[PolicyRestoreStageHook],
) -> None:
    """Lock affected UTC accounting periods, carry forward live holds/locks/reset flags, and run stage hooks."""
    try:
        staged_db = sqlite3.connect(staged_db_path, isolation_level=None)
    except sqlite3.Error as exc:
        raise sqlite_error("cannot open staged policy.db", exc) from exc
    live_path = root.policy_db if os.path.lexists(root.policy_db) else None
    try:
        apply_durability_pragmas(staged_db, os_.traits, foreign_keys=True)
        mode = staged_db.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
        if str(mode).lower() != "delete":
            raise BrainError(ErrorCode.IO_ERROR, f"staged policy.db journal_mode is {mode!r}")

        staged_db.execute("BEGIN IMMEDIATE")
        try:
            ensure_accounting_schema(staged_db)
            stamp = utc_timestamp(now)
            for period in _affected_periods(manifest.created_at, now):
                lock_key = f"restore:{manifest.created_at}:{period}"
                staged_db.execute(
                    "INSERT INTO accounting_locks "
                    "(lock_key, owner_id, period_key, backup_created_at, locked_at, state, "
                    "reconciled_at, reconciled_approval_id) VALUES (?, '*', ?, ?, ?, 'locked', NULL, NULL) "
                    "ON CONFLICT (lock_key) DO UPDATE SET state = 'locked', locked_at = excluded.locked_at, "
                    "reconciled_at = NULL, reconciled_approval_id = NULL",
                    (lock_key, period, manifest.created_at, stamp),
                )
            if live_carry_forward and live_path is not None:
                _carry_forward_from_live(live_path, staged_db)
            staged_db.execute("COMMIT")
        except BaseException:
            if staged_db.in_transaction:
                staged_db.execute("ROLLBACK")
            raise

        for hook in stage_hooks:
            hook.on_stage_policy(
                live_path,
                staged_db,
                manifest=manifest,
                now=now,
                trust_generation=generation,
            )
    finally:
        staged_db.close()

    companions = (*db_files(staged_db_path)[1:], staged_db_path.with_name(f"{staged_db_path.name}-journal"))
    if any(os.path.lexists(p) for p in companions):
        raise BrainError(ErrorCode.IO_ERROR, "staged policy.db kept companion files")
    os_.publisher.flush_file(staged_db_path)
