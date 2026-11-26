"""Read-only storage, CAS, projection parity, backup, durability, and retention doctor probes."""

from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import sqlite3
import stat
from datetime import datetime, timedelta
from pathlib import Path
from typing import cast

from superbrain.core._fs_walk import stat_reparse_or_link
from superbrain.core.errors import BrainError, describe_exception
from superbrain.ports.doctor import (
    MAX_LIST_FINDINGS_PER_GROUP,
    DoctorRetentionStats,
    DoctorScanLimits,
    DoctorStorageStats,
)
from superbrain.ports.os import OsAdapters
from superbrain.ports.policy import PolicyView
from superbrain.storage._proposal_schema import ProposalProjectionHandler
from superbrain.storage.backup import verify_backup
from superbrain.storage.cas import HolderProjection, file_digest
from superbrain.storage.jobs import JobsProjection, ProviderInvocationProjection
from superbrain.storage.kernel_schema import KERNEL_POLICY_MIGRATIONS, KERNEL_STORE_MIGRATIONS
from superbrain.storage.layout import DataRoot
from superbrain.storage.ledger import ProjectionHandler, apply_to_handlers, read_entries
from superbrain.storage.schema import SchemaInfo
from superbrain.storage.sqlite import open_readonly
from superbrain.storage.workspaces import (
    FieldLineageProjection,
    SnapshotProjection,
    TaskLineageProjection,
    WorkspaceRegistryMirrorProjection,
)

__all__ = [
    "check_pair_projection_parity",
    "is_link_entry",
    "probe_storage_and_retention",
    "table_exists",
]

_REPARSE_POINT = 0x400
_SHARD_RE = re.compile(r"^[0-9a-f]{2}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_BACKUP_NAME_RE = re.compile(r"^(store|store_full|policy)-(\d{8}T\d{6}Z)-([A-Za-z0-9._-]+)$")


def is_link_entry(path: Path) -> bool:
    """Return True if ``path`` is a symlink or NTFS reparse point without resolving targets."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & _REPARSE_POINT)


def table_exists(db: sqlite3.Connection, name: str) -> bool:
    """Return True when ``name`` exists in ``sqlite_master``."""
    return db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None


class _StaticRoPolicyView(PolicyView):
    def __init__(self, tombstoned: set[tuple[str, str]], quarantined: set[str]) -> None:
        self._tombstoned = tombstoned
        self._quarantined = quarantined

    def is_quarantined(self, digest: str) -> bool:
        return digest in self._quarantined

    def is_tombstoned(self, holder_kind: str, holder_id: str) -> bool:
        return (holder_kind, holder_id) in self._tombstoned


def _check_projection_parity(
    store_db: sqlite3.Connection,
    tombstones: set[tuple[str, str]],
    quarantined: set[str],
) -> tuple[bool, str]:
    handlers: list[ProjectionHandler] = [
        HolderProjection(),
        WorkspaceRegistryMirrorProjection(),
        SnapshotProjection(),
        TaskLineageProjection(),
        FieldLineageProjection(),
        JobsProjection(),
        ProviderInvocationProjection(),
        ProposalProjectionHandler(),
    ]
    live_tables = {
        str(row[0])
        for row in store_db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'p_%'").fetchall()
    }
    active_handlers = [h for h in handlers if any(t.startswith(f"p_{h.name}_") for t in live_tables)]
    if not active_handlers:
        return True, "no projection tables initialized"

    mem = sqlite3.connect(":memory:")
    try:
        mem.execute(
            "CREATE TABLE ledger ("
            "sequence INTEGER PRIMARY KEY AUTOINCREMENT, entry_id TEXT UNIQUE NOT NULL, "
            "kind TEXT NOT NULL, schema_version INTEGER NOT NULL, handler_version INTEGER NOT NULL, "
            "writer_epoch INTEGER NOT NULL, actor TEXT NOT NULL, owner_id TEXT, "
            "recorded_at TEXT NOT NULL, meta BLOB NOT NULL, refs BLOB NOT NULL)"
        )
        rows = store_db.execute(
            "SELECT sequence, entry_id, kind, schema_version, handler_version, writer_epoch, "
            "actor, owner_id, recorded_at, meta, refs FROM ledger ORDER BY sequence"
        ).fetchall()
        mem.executemany(
            "INSERT INTO ledger (sequence, entry_id, kind, schema_version, handler_version, writer_epoch, "
            "actor, owner_id, recorded_at, meta, refs) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        for h in active_handlers:
            h.create_tables(mem, f"r_{h.name}_")
        view = _StaticRoPolicyView(tombstones, quarantined)
        after = 0
        while page := read_entries(mem, after, 256):
            for entry in page:
                apply_to_handlers(mem, active_handlers, entry, view, lambda h: f"r_{h.name}_")
            after = page[-1].sequence

        mismatches: list[str] = []
        for h in active_handlers:
            r_prefix = f"r_{h.name}_"
            p_prefix = f"p_{h.name}_"
            r_tables = sorted(
                str(r[0])
                for r in mem.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE ?", (f"{r_prefix}%",)
                ).fetchall()
            )
            for rt_name in r_tables:
                pt_name = p_prefix + rt_name[len(r_prefix) :]
                if pt_name not in live_tables:
                    mismatches.append(f"missing projection table {pt_name}")
                    continue
                expected_rows = sorted(repr(r) for r in mem.execute(f'SELECT * FROM "{rt_name}"').fetchall())
                actual_rows = sorted(repr(r) for r in store_db.execute(f'SELECT * FROM "{pt_name}"').fetchall())
                if expected_rows != actual_rows:
                    mismatches.append(
                        f"{pt_name} mismatch (expected={len(expected_rows)} rows, live={len(actual_rows)} rows)"
                    )
        if mismatches:
            return False, "; ".join(mismatches[:4])
        return True, f"ledger matches {len(active_handlers)} projections ({len(rows)} entries)"
    finally:
        mem.close()


def _wal_bytes(path: Path) -> int:
    wal = path.with_name(path.name + "-wal")
    if not os.path.lexists(wal) or is_link_entry(wal):
        return 0
    try:
        return int(os.lstat(wal).st_size)
    except OSError:
        return 0


def _collect_cas_digests(cas_dir: Path, errors: list[str]) -> list[tuple[str, Path, int]]:
    items: list[tuple[str, Path, int]] = []
    if not os.path.lexists(cas_dir) or is_link_entry(cas_dir):
        return items
    try:
        shards = sorted(os.scandir(cas_dir), key=lambda e: e.name)
    except OSError as exc:
        errors.append(f"cas directory scan error: {describe_exception(exc)}")
        return items
    for shard_ent in shards:
        shard_path = Path(shard_ent.path)
        if shard_ent.is_symlink() or is_link_entry(shard_path) or not _SHARD_RE.fullmatch(shard_ent.name):
            continue
        try:
            est = shard_ent.stat(follow_symlinks=False)
        except OSError:
            continue
        if stat_reparse_or_link(est) or not stat.S_ISDIR(est.st_mode):
            continue
        try:
            blobs = sorted(os.scandir(shard_path), key=lambda e: e.name)
        except OSError as exc:
            errors.append(f"cas shard {shard_ent.name} scan error: {describe_exception(exc)}")
            continue
        for blob_ent in blobs:
            bpath = Path(blob_ent.path)
            if blob_ent.is_symlink() or is_link_entry(bpath) or not _HEX64_RE.fullmatch(blob_ent.name):
                continue
            try:
                bst = blob_ent.stat(follow_symlinks=False)
            except OSError:
                continue
            if not stat_reparse_or_link(bst) and stat.S_ISREG(bst.st_mode):
                items.append((f"sha256:{blob_ent.name}", bpath, int(bst.st_size)))
    items.sort(key=lambda t: t[0])
    return items


def _check_sqlite_integrity(
    db_path: Path,
    label: str,
    scratch: Path,
    safe: bool,
    int_details: list[str],
    errors: list[str],
    *,
    db: sqlite3.Connection | None = None,
) -> bool:
    if not (safe and os.path.exists(db_path)):
        int_details.append(f"{label} missing or unsafe")
        return False
    opened: sqlite3.Connection | None = None
    try:
        conn = db if db is not None else open_readonly(db_path, scratch_dir=scratch)
        opened = None if db is not None else conn
        res = [str(r[0]) for r in conn.execute("PRAGMA integrity_check").fetchall()]
        ok = res == ["ok"]
        if not ok:
            int_details.append(f"{label}: {'; '.join(res[:2])}")
        return ok
    except (BrainError, sqlite3.Error, OSError) as exc:
        int_details.append(f"{label} integrity error: {describe_exception(exc)}")
        errors.append(f"{label} integrity check failed: {describe_exception(exc)}")
        return False
    finally:
        if opened is not None:
            opened.close()


def _sample_cas_blobs(
    cas_items: list[tuple[str, Path, int]],
    limits: DoctorScanLimits,
    errors: list[str],
) -> tuple[int, int, bool, list[str]]:
    sampled_blobs = 0
    sampled_bytes = 0
    cas_truncated = False
    cas_mismatches: list[str] = []
    for dig, bpath, bsize in cas_items:
        if sampled_blobs >= limits.max_cas_sample_blobs or (
            sampled_bytes + bsize > limits.max_cas_sample_bytes and (sampled_blobs > 0 or len(cas_items) > 0)
        ):
            cas_truncated = True
            break
        try:
            actual = file_digest(bpath)
            if actual != dig:
                cas_mismatches.append(f"cas digest mismatch {dig} != {actual}")
        except (BrainError, OSError) as exc:
            cas_mismatches.append(f"cas read error {dig}: {describe_exception(exc)}")
        sampled_blobs += 1
        sampled_bytes += bsize
    if cas_mismatches:
        errors.extend(cas_mismatches[:MAX_LIST_FINDINGS_PER_GROUP])
    return sampled_blobs, sampled_bytes, cas_truncated, cas_mismatches


def _probe_latest_backup(
    root: DataRoot,
    os_: OsAdapters,
    store_info: SchemaInfo | None,
    policy_info: SchemaInfo | None,
    store_safe: bool,
    errors: list[str],
) -> tuple[str | None, float | None, bool | None, str]:
    bak_id: str | None = None
    bak_age_s: float | None = None
    bak_valid: bool | None = None
    bak_detail = "no backup recorded"
    if not (store_safe and os.path.lexists(root.backups_dir) and not is_link_entry(root.backups_dir)):
        return bak_id, bak_age_s, bak_valid, bak_detail
    candidates: list[tuple[str, Path]] = []
    try:
        for ent in os.scandir(root.backups_dir):
            ep = Path(ent.path)
            if ent.is_symlink() or is_link_entry(ep):
                continue
            m = _BACKUP_NAME_RE.match(ent.name)
            sort_key = (m.group(2) if m is not None else ent.name) + ":" + ent.name
            if ent.is_dir(follow_symlinks=False):
                candidates.append((sort_key, ep))
    except OSError as exc:
        msg = f"cannot list backups: {describe_exception(exc)}"
        errors.append(msg)
        return None, None, False, msg
    if not candidates:
        return bak_id, bak_age_s, bak_valid, bak_detail
    candidates.sort(key=lambda t: t[0], reverse=True)
    _, latest_dir = candidates[0]
    bak_id = latest_dir.name
    m = _BACKUP_NAME_RE.match(bak_id)
    kind = m.group(1) if m is not None else ""
    exp_kind: str | frozenset[str] = "policy" if kind == "policy" else frozenset({"store", "store_full"})
    migs = KERNEL_POLICY_MIGRATIONS if kind == "policy" else KERNEL_STORE_MIGRATIONS
    exp_id = (
        store_info.store_id
        if store_info is not None
        else policy_info.store_id
        if policy_info is not None
        else ""
    )
    try:
        manifest = verify_backup(
            latest_dir,
            expected_kind=cast(frozenset[str], exp_kind),
            expected_store_id=exp_id,
            migrations=migs,
            os_=os_,
        )
        bak_valid = True
        created_dt = datetime.fromisoformat(manifest.created_at.replace("Z", "+00:00"))
        bak_age_s = max(0.0, (os_.clock.now() - created_dt).total_seconds())
        bak_detail = f"verified {latest_dir.name} (age={int(bak_age_s)}s)"
    except (BrainError, OSError, ValueError) as exc:
        bak_valid = False
        bak_detail = f"backup {latest_dir.name} invalid: {describe_exception(exc)}"
        errors.append(bak_detail)
    return bak_id, bak_age_s, bak_valid, bak_detail


def _read_policy_blocks(pdb: sqlite3.Connection) -> tuple[set[tuple[str, str]], set[str]]:
    tombstones: set[tuple[str, str]] = set()
    quarantined: set[str] = set()
    if table_exists(pdb, "tombstones"):
        tombstones = {
            (str(k), str(h))
            for k, h in pdb.execute("SELECT holder_kind, holder_id FROM tombstones").fetchall()
        }
    if table_exists(pdb, "quarantine"):
        quarantined = {str(d) for (d,) in pdb.execute("SELECT digest FROM quarantine").fetchall()}
    return tombstones, quarantined


def check_pair_projection_parity(
    store_db_path: Path,
    policy_db_path: Path,
    *,
    scratch_dir: Path | None = None,
) -> tuple[bool, str]:
    """Return ``(matches, detail)`` comparing live ``p_*`` projections against ledger replay."""
    if not os.path.lexists(store_db_path) or not os.path.lexists(policy_db_path):
        return False, "store or policy database missing"
    with contextlib.closing(open_readonly(policy_db_path, scratch_dir=scratch_dir)) as pdb:
        tombstones, quarantined = _read_policy_blocks(pdb)
    with contextlib.closing(open_readonly(store_db_path, scratch_dir=scratch_dir)) as sdb:
        if not table_exists(sdb, "ledger"):
            return False, "ledger table missing"
        return _check_projection_parity(sdb, tombstones, quarantined)


def probe_storage_and_retention(
    root: DataRoot,
    os_: OsAdapters,
    scratch: Path,
    store_info: SchemaInfo | None,
    policy_info: SchemaInfo | None,
    limits: DoctorScanLimits,
    errors: list[str],
    *,
    store_readable: bool,
    policy_readable: bool,
    store_safe: bool = True,
    policy_safe: bool = True,
    cas_safe: bool = True,
    store_conn: sqlite3.Connection | None = None,
    policy_conn: sqlite3.Connection | None = None,
) -> tuple[DoctorStorageStats, DoctorRetentionStats, list[tuple[str, Path, int]]]:
    """Run read-only storage, CAS, ledger-projection, backup, disk, durability, and retention probes."""
    int_details: list[str] = []
    store_int_ok = _check_sqlite_integrity(
        root.store_db, "brain.db", scratch, store_safe, int_details, errors, db=store_conn
    )
    policy_int_ok = _check_sqlite_integrity(
        root.policy_db, "policy.db", scratch, policy_safe, int_details, errors, db=policy_conn
    )

    wal_store = _wal_bytes(root.store_db) if store_safe else 0
    wal_policy = _wal_bytes(root.policy_db) if policy_safe else 0

    cas_items = _collect_cas_digests(root.cas_dir, errors) if cas_safe else []
    sampled_blobs, sampled_bytes, cas_truncated, cas_mismatches = _sample_cas_blobs(cas_items, limits, errors)

    tombstone_set: set[tuple[str, str]] = set()
    quarantine_set: set[str] = set()
    policy_intent_ids: list[str] = []
    if policy_readable and os.path.exists(root.policy_db):
        opened_pdb: sqlite3.Connection | None = None
        try:
            if policy_conn is None:
                opened_pdb = open_readonly(root.policy_db, scratch_dir=scratch)
                pdb = opened_pdb
            else:
                opened_pdb = None
                pdb = policy_conn
            tombstone_set, quarantine_set = _read_policy_blocks(pdb)
            if table_exists(pdb, "intents"):
                policy_intent_ids = [
                    str(i)
                    for i, kind in pdb.execute("SELECT intent_id, kind FROM intents").fetchall()
                    if str(kind) not in ("recovery_grant_opened", "recovery_grant_ended")
                ]
        except (BrainError, sqlite3.Error, OSError) as exc:
            errors.append(f"policy read error: {describe_exception(exc)}")
        finally:
            if opened_pdb is not None:
                opened_pdb.close()

    held_digests_set: set[str] = set()
    held_holders_set: set[tuple[str, str]] = set()
    grace_released_digests: set[str] = set()
    applied_set: set[str] = set()
    ledger_match: bool | None = None
    ledger_detail = "skipped (schema unreadable)"
    last_gc_at: str | None = None
    expired_due = 0
    if store_readable and os.path.exists(root.store_db):
        opened_sdb: sqlite3.Connection | None = None
        try:
            sdb = store_conn if store_conn is not None else open_readonly(root.store_db, scratch_dir=scratch)
            opened_sdb = None if store_conn is not None else sdb
            if table_exists(sdb, "p_cas_holders_"):
                now_iso = os_.clock.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                for dig, hk, hid, _ret, exp in sdb.execute(
                    "SELECT digest, holder_kind, holder_id, retention_class, expires_at FROM p_cas_holders_"
                ).fetchall():
                    held_digests_set.add(str(dig))
                    held_holders_set.add((str(hk), str(hid)))
                    if exp is not None and str(exp) <= now_iso:
                        expired_due += 1
            if table_exists(sdb, "applied_intents"):
                applied_set = {str(i) for (i,) in sdb.execute("SELECT intent_id FROM applied_intents").fetchall()}
            if table_exists(sdb, "ledger"):
                ledger_match, ledger_detail = _check_projection_parity(sdb, tombstone_set, quarantine_set)
                if not ledger_match:
                    errors.append(ledger_detail)
                gc_row = sdb.execute(
                    "SELECT recorded_at FROM ledger WHERE kind IN ('cas.release', 'policy.tombstone') "
                    "ORDER BY sequence DESC LIMIT 1"
                ).fetchone()
                if gc_row is not None:
                    last_gc_at = str(gc_row[0])
                grace_cutoff = (os_.clock.now() - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                for rec_at, raw_meta in sdb.execute(
                    "SELECT recorded_at, meta FROM ledger WHERE kind = 'cas.release' ORDER BY sequence"
                ).fetchall():
                    if str(rec_at) < grace_cutoff:
                        continue
                    try:
                        meta_obj = json.loads(bytes(raw_meta).decode("utf-8"))
                    except (ValueError, UnicodeDecodeError):
                        continue
                    if isinstance(meta_obj, dict) and isinstance(meta_obj.get("digest"), str):
                        grace_released_digests.add(meta_obj["digest"])
        except (BrainError, sqlite3.Error, OSError) as exc:
            ledger_match = False
            ledger_detail = f"ledger parity error: {describe_exception(exc)}"
            errors.append(ledger_detail)
        finally:
            if opened_sdb is not None:
                opened_sdb.close()

    orphans = (
        [dig for dig, _, _ in cas_items if dig not in held_digests_set and dig not in grace_released_digests]
        if store_readable
        else []
    )
    unapplied_count = (
        sum(1 for iid in policy_intent_ids if iid not in applied_set)
        if (store_readable and policy_readable)
        else None
    )

    tomb_mismatch = 0
    tomb_detail = ""
    ret_skipped: str | None = None
    if not (store_readable and policy_readable):
        ret_skipped = "schema unreadable"
    else:
        overlapping = sorted(tombstone_set & held_holders_set)
        tomb_mismatch = len(overlapping)
        if tomb_mismatch:
            tomb_detail = f"{tomb_mismatch} tombstoned holder(s) still active in CAS holders"

    disk_free: int | None = None
    disk_error: str | None = None
    try:
        disk_free = int(shutil.disk_usage(root.root).free)
    except OSError as exc:
        disk_error = f"disk usage unavailable: {describe_exception(exc)}"

    dur_tier = "power_loss_durable"
    dur_detail = "power_loss_durable"
    dur_error: str | None = None
    try:
        ro_dur_fn = getattr(os_.publisher, "durability_readonly", os_.publisher.durability)
        drep = ro_dur_fn(root.root, {})
        dur_tier = drep.tier.value
        dur_detail = dur_tier if not drep.reasons else f"{dur_tier}: {'; '.join(drep.reasons)}"
    except (BrainError, OSError, RuntimeError) as exc:
        dur_error = f"durability probe unavailable: {describe_exception(exc)}"
        dur_tier = "unavailable"
        dur_detail = dur_error

    bak_id, bak_age_s, bak_valid, bak_detail = _probe_latest_backup(
        root, os_, store_info, policy_info, store_safe, errors
    )

    st_stats = DoctorStorageStats(
        store_integrity_ok=store_int_ok,
        policy_integrity_ok=policy_int_ok,
        integrity_detail="ok" if (store_int_ok and policy_int_ok) else "; ".join(int_details) or "integrity failure",
        wal_store_bytes=wal_store,
        wal_policy_bytes=wal_policy,
        wal_warn_bytes=limits.wal_warn_bytes,
        cas_sampled_blobs=sampled_blobs,
        cas_sampled_bytes=sampled_bytes,
        cas_total_blobs=len(cas_items),
        cas_truncated=cas_truncated,
        cas_mismatches=tuple(cas_mismatches[:MAX_LIST_FINDINGS_PER_GROUP]),
        orphan_blobs_count=len(orphans),
        orphan_blobs_sample=tuple(orphans[:MAX_LIST_FINDINGS_PER_GROUP]),
        orphan_truncated=len(orphans) > MAX_LIST_FINDINGS_PER_GROUP,
        ledger_projection_match=ledger_match,
        ledger_projection_detail=ledger_detail,
        unapplied_policy_intents=unapplied_count,
        disk_free_bytes=disk_free,
        disk_warn_free_bytes=limits.disk_warn_free_bytes,
        disk_fail_free_bytes=limits.disk_fail_free_bytes,
        disk_error=disk_error,
        latest_backup_id=bak_id,
        latest_backup_age_s=bak_age_s,
        latest_backup_valid=bak_valid,
        backup_stale_age_s=limits.backup_stale_age_s,
        latest_backup_detail=bak_detail,
        durability_tier=dur_tier,
        durability_detail=dur_detail,
        durability_error=dur_error,
    )
    ret_stats = DoctorRetentionStats(
        last_gc_at=last_gc_at,
        expired_due_count=expired_due,
        tombstone_holder_mismatch_count=tomb_mismatch,
        mismatch_detail=tomb_detail,
        check_skipped_reason=ret_skipped,
    )
    return st_stats, ret_stats, cas_items
