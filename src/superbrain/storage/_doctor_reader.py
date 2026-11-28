"""Strictly read-only ``brain doctor`` snapshot reader (0 bytes mutated in data_root/checkout)."""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import stat
import tempfile
from pathlib import Path

from superbrain.core._kernel_approval import Layer2State, SignerRecord
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode, describe_exception
from superbrain.core.proposals import ChangeProposal, ProposalStatus, ProposalTarget
from superbrain.ports.doctor import (
    CaptureDoctorProbePort,
    CaptureDoctorProbeResult,
    DoctorAccountingLock,
    DoctorBootstrapDrift,
    DoctorDaemonStats,
    DoctorJournalInfo,
    DoctorLayer2HarnessStatus,
    DoctorPendingTombstones,
    DoctorProposalSummary,
    DoctorScanLimits,
    DoctorSchemaVersions,
    DoctorSnapshot,
    DoctorSnapshotReaderPort,
    DoctorTurnIntentInfo,
    PrivacyCanaryProbeResult,
    PrivacyRescanSummary,
    PrivacyScannerPort,
)
from superbrain.ports.os import OsAdapters
from superbrain.storage import _policy_approvals as policy_approvals
from superbrain.storage import _policy_layer2 as policy_layer2
from superbrain.storage._doctor_probes import (
    check_permissions_strict,
    probe_daemon_state,
    probe_identity_and_jev,
    probe_storage_and_retention,
    run_capture_probe_bounded,
    run_privacy_rescan,
)
from superbrain.storage._proposal_codec import decode_proposal
from superbrain.storage._restore_epoch import read_restore_epoch
from superbrain.storage.cas import blob_path, file_digest
from superbrain.storage.kernel_schema import KERNEL_POLICY_MIGRATIONS, KERNEL_STORE_MIGRATIONS
from superbrain.storage.layout import DataRoot
from superbrain.storage.schema import SchemaInfo, code_version, ensure_readable, read_schema_info
from superbrain.storage.sqlite import open_readonly

__all__ = ["StorageDoctorReader", "read_doctor_snapshot"]

_REPARSE_POINT = 0x400


def _table_exists(db: sqlite3.Connection, name: str) -> bool:
    row = db.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)).fetchone()
    return row is not None


def _read_pending_tombstones(root: DataRoot, os_: OsAdapters) -> DoctorPendingTombstones:
    path = root.pending_restore_tombstones_path
    if not os.path.lexists(path):
        return DoctorPendingTombstones(present=False, restore_epoch=None, expired_holders_count=0)
    try:
        os_.paths.reject_links(path)
        st = os.lstat(path)
        if stat.S_ISLNK(st.st_mode) or (getattr(st, "st_file_attributes", 0) & _REPARSE_POINT) != 0:
            return DoctorPendingTombstones(
                present=True, restore_epoch=None, expired_holders_count=0, corrupt_error="unsafe link"
            )
        data = json.loads(path.read_bytes().decode("utf-8"))
        if not isinstance(data, dict):
            return DoctorPendingTombstones(
                present=True, restore_epoch=None, expired_holders_count=0, corrupt_error="invalid JSON object"
            )
        epoch = data.get("restore_epoch")
        holders = data.get("expired_holders")
        return DoctorPendingTombstones(
            present=True,
            restore_epoch=epoch if type(epoch) is int else None,
            expired_holders_count=len(holders) if isinstance(holders, list) else 0,
        )
    except (BrainError, OSError, UnicodeDecodeError, ValueError) as exc:
        return DoctorPendingTombstones(
            present=True, restore_epoch=None, expired_holders_count=0, corrupt_error=describe_exception(exc)
        )


def _is_safe_path(path: Path, os_: OsAdapters, errors: list[str], label: str) -> bool:
    try:
        os_.paths.reject_links(path)
        if os.path.lexists(path):
            st = os.lstat(path)
            if stat.S_ISLNK(st.st_mode) or (getattr(st, "st_file_attributes", 0) & _REPARSE_POINT) != 0:
                errors.append(f"{label}: unsafe link")
                return False
        return True
    except (BrainError, OSError) as exc:
        errors.append(f"{label}: {describe_exception(exc)}")
        return False


def _try_open_shared_ro(path: Path, safe: bool, scratch: Path) -> sqlite3.Connection | None:
    if not (safe and os.path.exists(path)):
        return None
    try:
        return open_readonly(path, scratch_dir=scratch)
    except (BrainError, sqlite3.Error, OSError):
        return None


def _read_policy_state(
    policy_db_path: Path,
    scratch: Path,
    errors: list[str],
    *,
    policy_conn: sqlite3.Connection | None = None,
) -> tuple[
    int | None,
    bool,
    tuple[SignerRecord, ...],
    bool,
    tuple[DoctorLayer2HarnessStatus, ...],
    tuple[DoctorAccountingLock, ...],
    tuple[DoctorTurnIntentInfo, ...],
]:
    if not os.path.exists(policy_db_path):
        return None, False, (), False, (), (), ()
    opened: sqlite3.Connection | None = None
    try:
        db = policy_conn if policy_conn is not None else open_readonly(policy_db_path, scratch_dir=scratch)
        opened = None if policy_conn is not None else db
        trust_row = (
            db.execute("SELECT generation FROM trust WHERE id = 1").fetchone() if _table_exists(db, "trust") else None
        )
        trust_gen = int(trust_row[0]) if trust_row is not None else None
        reset_rec = policy_layer2.signer_reset_recorded(db) if _table_exists(db, "meta") else False
        signers = policy_approvals.active_signers(db) if _table_exists(db, "signer") else ()
        term_ok = policy_layer2.terminal_channel_eligible(db, None) if _table_exists(db, "principal") else False
        stale_l2_seq = policy_layer2.layer2_stale_through_seq(db) if _table_exists(db, "meta") else 0

        harnesses: list[DoctorLayer2HarnessStatus] = []
        if _table_exists(db, "harness_layer2_state"):
            seen: set[str] = set()
            if _table_exists(db, "principal"):
                p_rows = db.execute(
                    "SELECT DISTINCT p.harness_id FROM principal AS p WHERE p.harness_id != 'cli' "
                    "AND EXISTS (SELECT 1 FROM credential AS c WHERE c.principal_id = p.id "
                    "AND c.revoked_intent_id IS NULL)"
                ).fetchall()
                for (hid,) in p_rows:
                    seen.add(str(hid))
            l2_rows = db.execute("SELECT DISTINCT harness_id FROM harness_layer2_state").fetchall()
            for (hid,) in l2_rows:
                seen.add(str(hid))
            for hid in sorted(seen):
                latest = db.execute(
                    "SELECT seq, host_version, config_digest, state, created_at "
                    "FROM harness_layer2_state WHERE harness_id = ? ORDER BY seq DESC LIMIT 1",
                    (hid,),
                ).fetchone()
                if latest is None:
                    harnesses.append(
                        DoctorLayer2HarnessStatus(
                            harness_id=hid,
                            host_version=None,
                            config_digest=None,
                            state=Layer2State.UNKNOWN,
                            created_at=None,
                        )
                    )
                else:
                    l2_state = Layer2State(str(latest[3]))
                    if l2_state is Layer2State.VERIFIED and int(latest[0]) <= stale_l2_seq:
                        l2_state = Layer2State.UNKNOWN
                    harnesses.append(
                        DoctorLayer2HarnessStatus(
                            harness_id=hid,
                            host_version=str(latest[1]),
                            config_digest=str(latest[2]),
                            state=l2_state,
                            created_at=str(latest[4]),
                        )
                    )

        locks: list[DoctorAccountingLock] = []
        if _table_exists(db, "accounting_locks"):
            lock_rows = db.execute(
                "SELECT lock_key, owner_id, period_key, backup_created_at, locked_at "
                "FROM accounting_locks WHERE state = 'locked' ORDER BY locked_at, lock_key"
            ).fetchall()
            for lock_key, owner_id, period_key, bak_at, locked_at in lock_rows:
                locks.append(
                    DoctorAccountingLock(
                        lock_key=str(lock_key),
                        owner_id=str(owner_id),
                        period_key=str(period_key),
                        backup_created_at=str(bak_at),
                        locked_at=str(locked_at),
                    )
                )
        intents: list[DoctorTurnIntentInfo] = []
        if _table_exists(db, "apply_turn_intent"):
            intent_rows = db.execute(
                "SELECT turn_id, journal_id, approval_id, direction, state, created_at "
                "FROM apply_turn_intent WHERE state = 'active' ORDER BY created_at, turn_id"
            ).fetchall()
            for turn_id, journal_id, approval_id, direction, state, created_at in intent_rows:
                intents.append(
                    DoctorTurnIntentInfo(
                        turn_id=str(turn_id),
                        journal_id=str(journal_id),
                        approval_id=str(approval_id),
                        direction=str(direction),
                        state=str(state),
                        created_at=str(created_at),
                    )
                )
        return trust_gen, reset_rec, signers, term_ok, tuple(harnesses), tuple(locks), tuple(intents)
    except (BrainError, sqlite3.Error, ValueError) as exc:
        errors.append(f"policy read error: {describe_exception(exc)}")
        return None, False, (), False, (), (), ()
    finally:
        if opened is not None:
            opened.close()


def _inspect_single_target(
    prop: ChangeProposal,
    t: ProposalTarget,
    os_: OsAdapters,
    drifts: list[DoctorBootstrapDrift],
) -> None:
    tgt = Path(t.target_root) / Path(*t.normalized_rel_path.split("/"))
    if not os.path.lexists(tgt):
        drifts.append(
            DoctorBootstrapDrift(
                proposal_id=prop.proposal_id,
                target_root=t.target_root,
                rel_path=t.normalized_rel_path,
                reason="target_missing",
                current_digest=None,
                expected_digest=t.replacement_digest,
            )
        )
        return
    try:
        os_.paths.reject_links(tgt)
        st = os.lstat(tgt)
        if stat.S_ISLNK(st.st_mode) or (getattr(st, "st_file_attributes", 0) & _REPARSE_POINT) != 0:
            raise BrainError(ErrorCode.UNSAFE_PATH, "unsafe link")
        if not stat.S_ISREG(st.st_mode):
            raise BrainError(ErrorCode.INVALID_INPUT, "not a regular file")
        actual = file_digest(tgt)
    except BrainError:
        drifts.append(
            DoctorBootstrapDrift(
                proposal_id=prop.proposal_id,
                target_root=t.target_root,
                rel_path=t.normalized_rel_path,
                reason="unsafe_target",
                current_digest=None,
                expected_digest=t.replacement_digest,
            )
        )
        return
    if actual != t.replacement_digest:
        drifts.append(
            DoctorBootstrapDrift(
                proposal_id=prop.proposal_id,
                target_root=t.target_root,
                rel_path=t.normalized_rel_path,
                reason="content_drift",
                current_digest=actual,
                expected_digest=t.replacement_digest,
            )
        )


def _read_store_proposals(
    root: DataRoot,
    scratch: Path,
    checkout_root: Path | None,
    os_: OsAdapters,
    errors: list[str],
    *,
    cas_ok: bool,
    store_conn: sqlite3.Connection | None = None,
) -> tuple[tuple[DoctorProposalSummary, ...], tuple[DoctorBootstrapDrift, ...], tuple[DoctorJournalInfo, ...]]:
    if not os.path.exists(root.store_db):
        return (), (), ()
    opened: sqlite3.Connection | None = None
    pending: list[DoctorProposalSummary] = []
    drifts: list[DoctorBootstrapDrift] = []
    incomplete_journals: list[DoctorJournalInfo] = []
    latest_by_target: dict[tuple[str, str], tuple[ChangeProposal, ProposalTarget]] = {}
    resolved_checkout = os.path.normcase(str(checkout_root)) if checkout_root is not None else None
    try:
        db = store_conn if store_conn is not None else open_readonly(root.store_db, scratch_dir=scratch)
        opened = None if store_conn is not None else db
        if _table_exists(db, "p_proposals_journals"):
            j_rows = db.execute(
                "SELECT journal_id, proposal_id, direction, status, grant_id, updated_at "
                "FROM p_proposals_journals WHERE status NOT IN ('applied', 'rolled_back') "
                "ORDER BY created_at, journal_id"
            ).fetchall()
            for jid, jpid, jdir, jstat, jgrant, jupd in j_rows:
                incomplete_journals.append(
                    DoctorJournalInfo(
                        journal_id=str(jid),
                        proposal_id=str(jpid),
                        direction=str(jdir),
                        status=str(jstat),
                        grant_id=str(jgrant),
                        updated_at=str(jupd),
                    )
                )
        if not _table_exists(db, "p_proposals_proposals"):
            return (), (), tuple(incomplete_journals)
        rows = db.execute(
            "SELECT proposal_id, kind, status, subject_revision, payload_digest, active_journal_id, updated_at "
            "FROM p_proposals_proposals ORDER BY created_at, sequence, proposal_id"
        ).fetchall()
        for pid, kind, status, rev, payload_digest, active_jid, updated_at in rows:
            status_str = str(status)
            if status_str not in (
                ProposalStatus.REJECTED.value,
                ProposalStatus.APPLIED.value,
                ProposalStatus.ROLLED_BACK.value,
            ):
                pending.append(
                    DoctorProposalSummary(
                        proposal_id=str(pid),
                        status=status_str,
                        kind=str(kind),
                        active_journal_id=None if active_jid is None else str(active_jid),
                    )
                )
            if status_str == ProposalStatus.APPLIED.value:
                if not cas_ok:
                    continue
                blob = blob_path(root.cas_dir, str(payload_digest))
                if not os.path.exists(blob):
                    errors.append(f"missing CAS payload for applied proposal {pid}")
                    continue
                if not _is_safe_path(blob, os_, errors, f"cas blob {pid}"):
                    continue
                st_blob = os.lstat(blob)
                if not stat.S_ISREG(st_blob.st_mode):
                    errors.append(f"CAS payload is not a regular file for proposal {pid}")
                    continue
                raw_blob = blob.read_bytes()
                if digest_bytes(raw_blob) != str(payload_digest):
                    errors.append(f"CAS payload digest mismatch for proposal {pid}")
                    continue
                prop = decode_proposal(
                    raw_blob,
                    status=status_str,
                    subject_revision=int(rev),
                    active_journal_id=None if active_jid is None else str(active_jid),
                    updated_at=str(updated_at),
                )
                for target in prop.targets:
                    if resolved_checkout is not None and os.path.normcase(target.target_root) != resolved_checkout:
                        continue
                    key = (os.path.normcase(target.target_root), target.normalized_rel_path)
                    latest_by_target[key] = (prop, target)
        for prop, target in latest_by_target.values():
            _inspect_single_target(prop, target, os_, drifts)
        return tuple(pending), tuple(drifts), tuple(incomplete_journals)
    except (BrainError, sqlite3.Error, OSError, ValueError) as exc:
        errors.append(f"store proposal read error: {describe_exception(exc)}")
        return tuple(pending), tuple(drifts), tuple(incomplete_journals)
    finally:
        if opened is not None:
            opened.close()


def read_doctor_snapshot(
    data_root: Path,
    os_: OsAdapters,
    *,
    db_root: Path | None = None,
    checkout_root: Path | None = None,
    expected_store_id: str | None = None,
    privacy_scanner: PrivacyScannerPort | None = None,
    capture_probe: CaptureDoctorProbePort | None = None,
    limits: DoctorScanLimits | None = None,
) -> DoctorSnapshot:
    """Inspect ``data_root`` and optional ``checkout_root`` strictly read-only without leases or WAL creation."""
    scan_limits = limits if limits is not None else DoctorScanLimits()
    root = DataRoot.at(data_root)
    db_layout = DataRoot.at(db_root) if db_root is not None else root
    expected_store = code_version(KERNEL_STORE_MIGRATIONS)
    expected_policy = code_version(KERNEL_POLICY_MIGRATIONS)
    errors: list[str] = []
    perm_problems: list[str] = []
    ancestor_problems: list[str] = []
    backup_problems: list[str] = []

    data_ok = _is_safe_path(data_root, os_, errors, "data_root")
    store_ok = (
        data_ok
        and _is_safe_path(root.store_dir, os_, errors, "store_dir")
        and _is_safe_path(root.store_db, os_, errors, "store_db")
    )
    policy_ok = (
        data_ok
        and _is_safe_path(root.policy_dir, os_, errors, "policy_dir")
        and _is_safe_path(root.policy_db, os_, errors, "policy_db")
    )
    cas_ok = data_ok and _is_safe_path(root.cas_dir, os_, errors, "cas_dir")

    if data_ok and os.path.lexists(data_root):
        check_permissions_strict(
            root,
            os_,
            errors,
            perm_problems,
            ancestor_problems,
            backup_problems,
        )

    daemon_stats: DoctorDaemonStats | None
    if data_ok and os.path.lexists(data_root):
        daemon_stats = probe_daemon_state(root, os_, errors)
    else:
        daemon_stats = DoctorDaemonStats(
            writer_lock_present=False,
            writer_lock_held=False,
            lock_error="data_root missing or unsafe",
            endpoint_valid=False,
            endpoint_detail="data_root missing or unsafe",
        )

    capture_result: CaptureDoctorProbeResult | None = run_capture_probe_bounded(
        data_root, capture_probe, os_, scan_limits
    )

    raw_tmp = os_.traits.resolved_temp_dir()
    temp_base = str(raw_tmp) if raw_tmp is not None else None
    scratch = Path(tempfile.mkdtemp(prefix="sb-doctor-", dir=temp_base))
    store_conn: sqlite3.Connection | None = None
    policy_conn: sqlite3.Connection | None = None
    try:
        store_conn = _try_open_shared_ro(db_layout.store_db, store_ok, scratch)
        policy_conn = _try_open_shared_ro(db_layout.policy_db, policy_ok, scratch)
        store_info: SchemaInfo | None = None
        policy_info: SchemaInfo | None = None
        store_readable = False
        policy_readable = False
        if store_ok:
            try:
                store_info = read_schema_info(db_layout.store_db, scratch_dir=scratch, db=store_conn)
                if store_info is not None:
                    ensure_readable(store_info, KERNEL_STORE_MIGRATIONS)
                    store_readable = True
            except BrainError as exc:
                errors.append(f"store schema read error: {describe_exception(exc)}")
        if policy_ok:
            try:
                policy_info = read_schema_info(db_layout.policy_db, scratch_dir=scratch, db=policy_conn)
                if policy_info is not None:
                    ensure_readable(policy_info, KERNEL_POLICY_MIGRATIONS)
                    policy_readable = True
            except BrainError as exc:
                errors.append(f"policy schema read error: {describe_exception(exc)}")

        restore_epoch: int | None = None
        if store_ok and store_readable and store_info is not None:
            try:
                restore_epoch = read_restore_epoch(db_layout, schema_version=store_info.schema_version, os_=os_)
            except BrainError as exc:
                errors.append(f"restore_epoch error: {describe_exception(exc)}")

        if policy_ok and policy_readable:
            trust_gen, reset_rec, signers, term_ok, l2_statuses, locks, turn_intents = _read_policy_state(
                db_layout.policy_db, scratch, errors, policy_conn=policy_conn
            )
        else:
            trust_gen, reset_rec, signers, term_ok = None, False, (), False
            l2_statuses, locks, turn_intents = (), (), ()
        tombstones = (
            _read_pending_tombstones(db_layout, os_)
            if store_ok
            else DoctorPendingTombstones(present=False, restore_epoch=None, expired_holders_count=0)
        )
        if tombstones.corrupt_error is not None:
            errors.append(f"pending_restore_tombstones error: {tombstones.corrupt_error}")
        if store_ok and store_readable:
            pending_props, drifts, incomplete_journals = _read_store_proposals(
                root, scratch, checkout_root, os_, errors, cas_ok=cas_ok, store_conn=store_conn
            )
        else:
            pending_props, drifts, incomplete_journals = (), (), ()

        store_id = (
            store_info.store_id if store_info is not None else policy_info.store_id if policy_info is not None else None
        )
        if store_info is not None and policy_info is not None and store_info.store_id != policy_info.store_id:
            errors.append("store_id mismatch between store and policy databases")
        if expected_store_id is not None:
            if store_info is not None and store_info.store_id != expected_store_id:
                errors.append(f"expected_store_id mismatch in store/brain.db ({store_info.store_id})")
            if policy_info is not None and policy_info.store_id != expected_store_id:
                errors.append(f"expected_store_id mismatch in policy/policy.db ({policy_info.store_id})")

        identity_stats, jev_stats = probe_identity_and_jev(
            root.policy_db, root.store_db, scratch,
            policy_readable=policy_ok and policy_readable, store_readable=store_ok and store_readable,
            errors=errors, policy_conn=policy_conn, store_conn=store_conn,
        )
        storage_stats, retention_stats, cas_items = probe_storage_and_retention(
            root, os_, scratch, store_info, policy_info, scan_limits, errors,
            store_readable=store_ok and store_readable, policy_readable=policy_ok and policy_readable,
            store_safe=store_ok, policy_safe=policy_ok, cas_safe=cas_ok,
            store_conn=store_conn, policy_conn=policy_conn,
        )
        privacy_canaries: tuple[PrivacyCanaryProbeResult, ...] = (
            privacy_scanner.check_canary_channels() if privacy_scanner is not None else ()
        )
        privacy_rescan: PrivacyRescanSummary = (
            run_privacy_rescan(root, cas_items, scan_limits, privacy_scanner)
            if data_ok
            else PrivacyRescanSummary(error="data_root missing or unsafe")
        )
        return DoctorSnapshot(
            data_root=data_root, store_id=store_id,
            schema=DoctorSchemaVersions(
                store_version=store_info.schema_version if store_info is not None else None,
                policy_version=policy_info.schema_version if policy_info is not None else None,
                expected_store_version=expected_store, expected_policy_version=expected_policy,
                min_store_reader_version=store_info.min_reader_version if store_info is not None else None,
                min_policy_reader_version=policy_info.min_reader_version if policy_info is not None else None,
            ),
            restore_epoch=restore_epoch, trust_generation=trust_gen, signer_reset_recorded=reset_rec,
            signers=signers, terminal_channel_eligible=term_ok, layer2_harnesses=l2_statuses,
            unresolved_accounting_locks=locks, pending_restore_tombstones=tombstones,
            pending_proposals=pending_props, bootstrap_drifts=drifts, integrity_errors=tuple(errors),
            active_turn_intents=turn_intents, incomplete_journals=incomplete_journals,
            permission_problems=tuple(perm_problems), ancestor_permission_problems=tuple(ancestor_problems),
            backup_permission_problems=tuple(backup_problems), daemon_stats=daemon_stats,
            identity_stats=identity_stats, storage_stats=storage_stats, retention_stats=retention_stats,
            privacy_canaries=privacy_canaries, privacy_rescan=privacy_rescan,
            capture_probe_result=capture_result, jev_stats=jev_stats, limits=scan_limits,
        )
    finally:
        for conn in (store_conn, policy_conn):
            if conn is not None:
                conn.close()
        shutil.rmtree(scratch, ignore_errors=True)


class StorageDoctorReader(DoctorSnapshotReaderPort):
    """Storage adapter implementing ``DoctorSnapshotReaderPort``."""

    def __init__(self, os_: OsAdapters) -> None:
        self._os = os_

    def read_snapshot(
        self,
        data_root: Path,
        *,
        db_root: Path | None = None,
        checkout_root: Path | None = None,
        expected_store_id: str | None = None,
        privacy_scanner: PrivacyScannerPort | None = None,
        capture_probe: CaptureDoctorProbePort | None = None,
        limits: DoctorScanLimits | None = None,
    ) -> DoctorSnapshot:
        return read_doctor_snapshot(
            data_root,
            self._os,
            db_root=db_root,
            checkout_root=checkout_root,
            expected_store_id=expected_store_id,
            privacy_scanner=privacy_scanner,
            capture_probe=capture_probe,
            limits=limits,
        )
