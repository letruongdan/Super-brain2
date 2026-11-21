"""``store/restore_epoch.json``, ``pending_restore_tombstones.json`` and ``RestoreStageHook`` helpers (I3-4)."""

from __future__ import annotations

import json
import os
import sqlite3
import stat
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from superbrain.core.canonical import canonical_json
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import is_strict_int
from superbrain.ports.clock import Clock
from superbrain.ports.os import OsAdapters
from superbrain.ports.policy import IntentKind
from superbrain.storage.backup import write_new_file
from superbrain.storage.cas import HOLDERS_TABLE, HolderProjection
from superbrain.storage.errors import sqlite_error
from superbrain.storage.kinds import CORE_KINDS, KindRegistry, RetentionClass
from superbrain.storage.layout import DataRoot
from superbrain.storage.ledger import Txn, utc_timestamp
from superbrain.storage.schema import Migration
from superbrain.storage.sqlite import apply_durability_pragmas, db_files
from superbrain.storage.writer import WriterLease

if TYPE_CHECKING:
    from superbrain.storage.policy_store import PolicyStore

RESTORE_EPOCH_FILE = "restore_epoch.json"
PENDING_RESTORE_TOMBSTONES_FILE = "pending_restore_tombstones.json"
_REPARSE_POINT = 0x400


class RestoreStageHook(Protocol):
    """Extension hook invoked while staging a store restore and while draining its effects after swap."""

    def on_stage_store(
        self,
        stage_dir: Path,
        staged_db: sqlite3.Connection,
        *,
        now: datetime,
        restore_epoch: int,
        expired_holders: tuple[tuple[str, str], ...],
    ) -> None: ...

    def on_drain_store(
        self,
        root: DataRoot,
        policy: PolicyStore,
        *,
        restore_epoch: int,
        expired_holders: tuple[tuple[str, str], ...],
        now: datetime,
    ) -> None: ...


class _FixedClock(Clock):
    def __init__(self, now: datetime) -> None:
        self._now = now

    def now(self) -> datetime:
        return self._now


def _reject_file_link(path: Path, os_: OsAdapters | None) -> None:
    try:
        if path.is_symlink():
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"{path.name} must not be a symlink or reparse point")
    except OSError as exc:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"cannot inspect {path.name}: {exc}") from exc
    if os.path.lexists(path):
        try:
            st = os.lstat(path)
        except OSError as exc:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"cannot stat {path.name}: {exc}") from exc
        if stat.S_ISLNK(st.st_mode) or (getattr(st, "st_file_attributes", 0) & _REPARSE_POINT) != 0:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"{path.name} must not be a symlink or reparse point")
    if os_ is not None:
        try:
            os_.paths.reject_links(path)
        except BrainError as err:
            if err.code is ErrorCode.UNSAFE_PATH:
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"{path.name} contains unsafe link") from err
            raise


def read_restore_epoch(root_or_dir: DataRoot | Path, *, schema_version: int, os_: OsAdapters | None = None) -> int:
    """Read canonical ``store/restore_epoch.json``; returns ``0`` if missing for ``< 5``, else ``INTEGRITY_FAILURE``."""
    path = root_or_dir.restore_epoch_path if isinstance(root_or_dir, DataRoot) else root_or_dir / RESTORE_EPOCH_FILE
    _reject_file_link(path, os_)
    if not os.path.lexists(path):
        if schema_version < 5:
            return 0
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"missing {RESTORE_EPOCH_FILE} for store v{schema_version}")
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"cannot stat {RESTORE_EPOCH_FILE}: {exc}") from exc
    if not stat.S_ISREG(st.st_mode):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"{RESTORE_EPOCH_FILE} is not a regular file")
    try:
        raw = path.read_bytes()
        parsed: JsonValue = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"corrupt {RESTORE_EPOCH_FILE}: {exc}") from exc
    if not isinstance(parsed, dict) or set(parsed) != {"restore_epoch"}:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"invalid keys in {RESTORE_EPOCH_FILE}")
    epoch = parsed["restore_epoch"]
    if type(epoch) is not int or epoch < 0 or raw != canonical_json({"restore_epoch": epoch}):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"invalid epoch in {RESTORE_EPOCH_FILE}")
    return epoch


def write_restore_epoch(store_dir: Path, epoch: int, os_: OsAdapters) -> Path:
    """Durably and atomically write canonical ``{"restore_epoch": epoch}`` into ``store_dir``."""
    if not is_strict_int(epoch) or epoch < 0:
        raise BrainError(ErrorCode.INVALID_INPUT, "restore_epoch must be a non-negative integer")
    dest = store_dir / RESTORE_EPOCH_FILE
    _reject_file_link(dest, os_)
    payload = canonical_json({"restore_epoch": epoch})
    tmp = store_dir / f".restore_epoch.{new_id()}.tmp"
    try:
        os_.publisher.write_new(tmp, payload)
        os_.permissions.secure_file(tmp)
        os_.publisher.flush_file(tmp)
        os_.publisher.publish(tmp, dest)
        os_.permissions.secure_file(dest)
        os_.publisher.sync_directory(store_dir)
    except BaseException:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return dest


def _table_exists(db: sqlite3.Connection, name: str) -> bool:
    return db.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)).fetchone() is not None


def _due_holders(db: sqlite3.Connection, cutoff: str) -> tuple[tuple[str, str], ...]:
    rows = db.execute(
        f"SELECT holder_kind, holder_id FROM {HOLDERS_TABLE} GROUP BY holder_kind, holder_id "
        "HAVING SUM(CASE WHEN retention_class != ? AND expires_at IS NOT NULL AND expires_at <= ? "
        "THEN 0 ELSE 1 END) = 0 ORDER BY holder_kind, holder_id",
        (RetentionClass.DURABLE.value, cutoff),
    ).fetchall()
    return tuple((str(k), str(h)) for k, h in rows)


def stage_store_restore_effects(
    stage: Path,
    staged_db_path: Path,
    *,
    policy: PolicyStore,
    restore_epoch: int,
    target_schema: int,
    now: datetime,
    os_: OsAdapters,
    stage_hooks: Sequence[RestoreStageHook] = (),
) -> tuple[tuple[str, str], ...]:
    """Evaluate & release due holds inside staged ``brain.db``, write ``pending_restore_tombstones.json``, run hooks."""
    try:
        staged_db = sqlite3.connect(staged_db_path, isolation_level=None)
    except sqlite3.Error as exc:
        raise sqlite_error("cannot open staged brain.db for restore staging", exc) from exc
    expired_holders: tuple[tuple[str, str], ...] = ()
    try:
        apply_durability_pragmas(staged_db, os_.traits, foreign_keys=True)
        mode = staged_db.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
        if str(mode).lower() != "delete":
            raise BrainError(ErrorCode.IO_ERROR, f"staged brain.db journal_mode is {mode!r}")

        if _table_exists(staged_db, HOLDERS_TABLE):
            staged_db.execute("BEGIN IMMEDIATE")
            try:
                existing_holders = staged_db.execute(
                    f"SELECT DISTINCT holder_kind, holder_id FROM {HOLDERS_TABLE}"
                ).fetchall()
                for raw_kind, raw_id in existing_holders:
                    hk, hid = str(raw_kind), str(raw_id)
                    if policy.is_tombstoned(hk, hid):
                        staged_db.execute(
                            f"DELETE FROM {HOLDERS_TABLE} WHERE holder_kind = ? AND holder_id = ?",
                            (hk, hid),
                        )
                expired_holders = _due_holders(staged_db, utc_timestamp(now))
                if expired_holders:
                    txn = Txn(
                        staged_db,
                        kinds=KindRegistry(CORE_KINDS),
                        handlers=(HolderProjection(),),
                        policy=policy,
                        writer_epoch=restore_epoch,
                        schema_version=target_schema,
                        clock=_FixedClock(now),
                        check_owner=lambda: None,
                        blob_intact=lambda _dig: True,
                        history_versions={},
                    )
                    try:
                        for hk, hid in expired_holders:
                            digs = staged_db.execute(
                                f"SELECT digest FROM {HOLDERS_TABLE} "
                                "WHERE holder_kind = ? AND holder_id = ? ORDER BY digest",
                                (hk, hid),
                            ).fetchall()
                            for (dig,) in digs:
                                txn.release(str(dig), hk, hid, "expired")
                    finally:
                        txn._end()
                staged_db.execute("COMMIT")
            except BaseException:
                if staged_db.in_transaction:
                    staged_db.execute("ROLLBACK")
                raise

        payload = canonical_json(
            {
                "schema_version": 1,
                "restore_epoch": restore_epoch,
                "expired_holders": [{"holder_kind": k, "holder_id": h} for k, h in expired_holders],
            }
        )
        write_new_file(stage / PENDING_RESTORE_TOMBSTONES_FILE, payload, os_)
        os_.publisher.sync_directory(stage)

        for hook in stage_hooks:
            hook.on_stage_store(
                stage,
                staged_db,
                now=now,
                restore_epoch=restore_epoch,
                expired_holders=expired_holders,
            )
    finally:
        staged_db.close()

    companions = (*db_files(staged_db_path)[1:], staged_db_path.with_name(f"{staged_db_path.name}-journal"))
    if any(os.path.lexists(p) for p in companions):
        raise BrainError(ErrorCode.IO_ERROR, "staged brain.db left WAL/journal companion files")
    os_.publisher.flush_file(staged_db_path)
    return expired_holders


def _parse_pending_tombstones(
    path: Path, *, expected_epoch: int, os_: OsAdapters
) -> tuple[int, tuple[tuple[str, str], ...]]:
    _reject_file_link(path, os_)
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"cannot stat {PENDING_RESTORE_TOMBSTONES_FILE}: {exc}") from exc
    if not stat.S_ISREG(st.st_mode):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"{PENDING_RESTORE_TOMBSTONES_FILE} is not a regular file")
    try:
        parsed: JsonValue = json.loads(path.read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"corrupt {PENDING_RESTORE_TOMBSTONES_FILE}: {exc}") from exc
    if not isinstance(parsed, dict) or set(parsed) != {"schema_version", "restore_epoch", "expired_holders"}:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"invalid schema in {PENDING_RESTORE_TOMBSTONES_FILE}")
    sv, epoch, raw_holders = parsed["schema_version"], parsed["restore_epoch"], parsed["expired_holders"]
    if type(sv) is not int or sv != 1 or type(epoch) is not int or epoch < 0 or not isinstance(raw_holders, list):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"invalid fields in {PENDING_RESTORE_TOMBSTONES_FILE}")
    if epoch != expected_epoch:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "pending restore tombstones epoch mismatch")
    pairs: list[tuple[str, str]] = []
    for item in raw_holders:
        if not isinstance(item, dict) or set(item) != {"holder_kind", "holder_id"}:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "invalid holder entry in pending tombstones")
        hk, hid = item["holder_kind"], item["holder_id"]
        if not isinstance(hk, str) or not hk or not isinstance(hid, str) or not hid:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "invalid holder strings in pending tombstones")
        pairs.append((hk, hid))
    return epoch, tuple(pairs)


def drain_published_restore_effects(
    root: DataRoot,
    lease: WriterLease,
    os_: OsAdapters,
    policy: PolicyStore,
    *,
    now: datetime,
    target_schema: int = 5,
    stage_hooks: Sequence[RestoreStageHook] = (),
    migrations: Sequence[Migration] = (),
) -> tuple[tuple[str, str], ...]:
    """Idempotently drain ``store/pending_restore_tombstones.json`` into ``policy.db``, run hooks, then remove."""
    _ = migrations
    if not lease.held or lease.root != root:
        raise AssertionError("drain_published_restore_effects needs a held writer lease for this data root")
    path = root.pending_restore_tombstones_path
    _reject_file_link(path, os_)
    if not os.path.lexists(path):
        return ()
    expected_epoch = read_restore_epoch(root, schema_version=target_schema, os_=os_)
    restore_epoch, pairs = _parse_pending_tombstones(path, expected_epoch=expected_epoch, os_=os_)
    for hk, hid in pairs:
        if not policy.is_tombstoned(hk, hid):
            policy.record_intent(IntentKind.TOMBSTONE, {"holder_kind": hk, "holder_id": hid})
    for hook in stage_hooks:
        hook.on_drain_store(root, policy, restore_epoch=restore_epoch, expired_holders=pairs, now=now)
    try:
        os.unlink(path)
    except OSError as exc:
        raise BrainError(ErrorCode.IO_ERROR, f"cannot remove {PENDING_RESTORE_TOMBSTONES_FILE}: {exc}") from exc
    os_.publisher.sync_directory(root.store_dir)
    return pairs
