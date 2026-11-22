"""Storage group check builders for read-only ``brain doctor`` diagnostics (spec 13, I4-1)."""

from __future__ import annotations

from superbrain.application._doctor_checks import CheckBuilder
from superbrain.ports.doctor import DoctorSnapshot

__all__ = [
    "check_storage_core",
    "check_storage_ops",
]


def check_storage_core(snap: DoctorSnapshot, b: CheckBuilder) -> None:
    """Emit ``storage`` checks for SQLite integrity, WAL, CAS sampling, orphans, and ledger parity."""
    st = snap.storage_stats
    if st is None:
        status = "FAIL" if snap.integrity_errors else "PASS"
        reason = "integrity_error" if snap.integrity_errors else "ok"
        detail = "; ".join(snap.integrity_errors) if snap.integrity_errors else "storage stats not attached"
        rem = (
            "Inspect reported storage integrity errors before resuming mutating operations."
            if snap.integrity_errors
            else None
        )
        b.add("storage", "storage.sqlite_integrity", status, reason=reason, detail=detail, remediation=rem)
        return

    if st.store_integrity_ok is False or st.policy_integrity_ok is False:
        b.add(
            "storage",
            "storage.sqlite_integrity",
            "FAIL",
            reason="sqlite_corrupt",
            detail=st.integrity_detail,
            remediation="Stop mutations immediately and restore from latest verified backup.",
        )
    elif snap.integrity_errors:
        b.add(
            "storage",
            "storage.sqlite_integrity",
            "FAIL",
            reason="integrity_error",
            detail="; ".join(snap.integrity_errors),
            remediation="Inspect reported storage integrity errors before resuming mutating operations.",
        )
    else:
        b.add("storage", "storage.sqlite_integrity", "PASS", reason="ok", detail=st.integrity_detail)

    wal_max = max(st.wal_store_bytes, st.wal_policy_bytes)
    wal_detail = f"store_wal={st.wal_store_bytes}B policy_wal={st.wal_policy_bytes}B"
    if wal_max > st.wal_warn_bytes:
        b.add(
            "storage",
            "storage.wal_size",
            "WARN",
            reason="wal_large",
            detail=f"{wal_detail} > warn={st.wal_warn_bytes}B",
            remediation="Checkpoint WAL cleanly when daemon runs maintenance.",
        )
    else:
        b.add("storage", "storage.wal_size", "PASS", reason="ok", detail=wal_detail)

    if st.cas_mismatches:
        b.add(
            "storage",
            "storage.cas_sample",
            "FAIL",
            reason="cas_digest_mismatch",
            detail="; ".join(st.cas_mismatches),
            remediation="Restore damaged CAS blobs from verified backup.",
        )
    elif st.cas_truncated:
        b.add(
            "storage",
            "storage.cas_sample",
            "WARN",
            reason="scan_cap_reached",
            detail=(
                f"sampled {st.cas_sampled_blobs}/{st.cas_total_blobs} blobs "
                f"({st.cas_sampled_bytes}B) due to bounded scan cap"
            ),
        )
    else:
        b.add(
            "storage",
            "storage.cas_sample",
            "PASS",
            reason="ok",
            detail=f"verified {st.cas_sampled_blobs}/{st.cas_total_blobs} CAS blobs ({st.cas_sampled_bytes}B)",
        )

    if st.orphan_blobs_count > 0:
        sample_txt = ", ".join(st.orphan_blobs_sample[:4])
        b.add(
            "storage",
            "storage.orphan_blobs",
            "WARN",
            reason="orphan_blobs",
            detail=f"{st.orphan_blobs_count} orphan CAS blob(s) without active holder: {sample_txt}",
            remediation="Run retention GC under daemon maintenance to prune unheld expired blobs.",
        )
    else:
        b.add("storage", "storage.orphan_blobs", "PASS", reason="ok", detail="0 orphan CAS blobs")

    if st.ledger_projection_match is False:
        b.add(
            "storage",
            "storage.ledger_projection_match",
            "FAIL",
            reason="ledger_projection_mismatch",
            detail=st.ledger_projection_detail,
            remediation="Run `brain doctor --fix` to rebuild storage projections from ledger.",
        )
    elif st.ledger_projection_match is None:
        b.add(
            "storage",
            "storage.ledger_projection_match",
            "WARN",
            reason="schema_unreadable",
            detail=st.ledger_projection_detail,
        )
    else:
        b.add("storage", "storage.ledger_projection_match", "PASS", reason="ok", detail=st.ledger_projection_detail)

    if st.unapplied_policy_intents is not None and st.unapplied_policy_intents > 0:
        b.add(
            "storage",
            "storage.policy_reconcile",
            "WARN",
            reason="unapplied_policy_intents",
            detail=f"{st.unapplied_policy_intents} policy intent(s) not yet applied in brain.db",
            remediation="Run `brain doctor --fix` or start daemon to reconcile pending policy intents.",
        )
    else:
        b.add("storage", "storage.policy_reconcile", "PASS", reason="ok", detail="all policy intents applied")


def check_storage_ops(snap: DoctorSnapshot, b: CheckBuilder) -> None:
    """Emit ``storage`` checks for disk, backups, durability, locks, tombstones, intents, and journals."""
    st = snap.storage_stats
    if st is not None:
        if st.disk_error is not None:
            b.add("storage", "storage.disk_space", "WARN", reason="disk_probe_unavailable", detail=st.disk_error)
        elif st.disk_free_bytes is not None and st.disk_free_bytes < st.disk_fail_free_bytes:
            b.add(
                "storage",
                "storage.disk_space",
                "FAIL",
                reason="disk_critically_low",
                detail=f"free={st.disk_free_bytes}B < fail={st.disk_fail_free_bytes}B",
                remediation="Free disk space on data_root volume immediately.",
            )
        elif st.disk_free_bytes is not None and st.disk_free_bytes < st.disk_warn_free_bytes:
            b.add(
                "storage",
                "storage.disk_space",
                "WARN",
                reason="disk_low",
                detail=f"free={st.disk_free_bytes}B < warn={st.disk_warn_free_bytes}B",
                remediation="Free disk space on data_root volume soon.",
            )
        else:
            b.add("storage", "storage.disk_space", "PASS", reason="ok", detail=f"free={st.disk_free_bytes}B")

        if st.latest_backup_id is None:
            if st.latest_backup_valid is False:
                b.add(
                    "storage",
                    "storage.latest_backup",
                    "FAIL",
                    reason="backup_list_failed",
                    detail=st.latest_backup_detail,
                )
            else:
                b.add(
                    "storage",
                    "storage.latest_backup",
                    "PASS",
                    reason="none_recorded",
                    detail=st.latest_backup_detail,
                )
        elif st.latest_backup_valid is False:
            b.add(
                "storage",
                "storage.latest_backup",
                "FAIL",
                reason="backup_invalid",
                detail=st.latest_backup_detail,
                remediation="Take a fresh verified backup via `brain backup`.",
            )
        elif st.latest_backup_age_s is not None and st.latest_backup_age_s > st.backup_stale_age_s:
            b.add(
                "storage",
                "storage.latest_backup",
                "WARN",
                reason="backup_stale",
                detail=st.latest_backup_detail,
                remediation="Create an up-to-date backup via `brain backup`.",
            )
        else:
            b.add("storage", "storage.latest_backup", "PASS", reason="ok", detail=st.latest_backup_detail)

        if st.durability_error is not None:
            b.add(
                "storage",
                "storage.durability",
                "WARN",
                reason="durability_probe_unavailable",
                detail=st.durability_detail,
            )
        elif st.durability_tier == "power_loss_durable":
            b.add("storage", "storage.durability", "PASS", reason="ok", detail=st.durability_detail)
        else:
            b.add(
                "storage",
                "storage.durability",
                "WARN",
                reason="durability_degraded",
                detail=st.durability_detail,
                remediation="Move data_root to a power-loss-durable filesystem or mount with full fsync barriers.",
            )

    if snap.unresolved_accounting_locks:
        b.add(
            "storage",
            "storage.accounting_locks",
            "WARN",
            reason="unresolved_accounting_locks",
            detail=f"{len(snap.unresolved_accounting_locks)} unresolved accounting lock(s)",
            remediation="Reconcile post-restore accounting locks before relying on affected billing periods.",
        )
    else:
        b.add("storage", "storage.accounting_locks", "PASS", reason="ok", detail="0 unresolved accounting locks")

    tomb = snap.pending_restore_tombstones
    if tomb.present and (tomb.corrupt_error is not None or tomb.expired_holders_count > 0):
        b.add(
            "storage",
            "storage.pending_restore_tombstones",
            "WARN",
            reason="pending_tombstones_drain",
            detail=f"present (restore_epoch={tomb.restore_epoch}, expired={tomb.expired_holders_count})",
            remediation=(
                "Start the daemon (`brain serve --config <daemon.json>`) to drain "
                "pending_restore_tombstones.json."
            ),
        )
    else:
        b.add(
            "storage",
            "storage.pending_restore_tombstones",
            "PASS",
            reason="ok",
            detail=f"present={tomb.present} epoch={tomb.restore_epoch}",
        )

    if snap.active_turn_intents:
        b.add(
            "storage",
            "storage.active_turn_intents",
            "WARN",
            reason="active_turn_intents",
            detail=f"{len(snap.active_turn_intents)} active unprojected apply/rollback turn intent(s)",
            remediation="Resume or recover interrupted apply/rollback journal turn before further mutations.",
        )
    else:
        b.add("storage", "storage.active_turn_intents", "PASS", reason="ok", detail="0 active turn intents")

    if snap.incomplete_journals:
        b.add(
            "storage",
            "storage.incomplete_journals",
            "WARN",
            reason="incomplete_journals",
            detail=f"{len(snap.incomplete_journals)} incomplete apply/rollback journal(s)",
            remediation=(
                "Inspect incomplete journals via `brain review continue "
                "<proposal_id> --profile <profile.json>`."
            ),
        )
    else:
        b.add("storage", "storage.incomplete_journals", "PASS", reason="ok", detail="0 incomplete journals")
