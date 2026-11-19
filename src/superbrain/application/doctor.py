"""Application diagnostic analyzer and report formatter for strictly read-only ``brain doctor`` (I3-5)."""

from __future__ import annotations

from dataclasses import dataclass

from superbrain.core._kernel_approval import SignerRecord
from superbrain.core.jsonvalue import JsonValue
from superbrain.ports.doctor import (
    DoctorAccountingLock,
    DoctorBootstrapDrift,
    DoctorJournalInfo,
    DoctorLayer2HarnessStatus,
    DoctorPendingTombstones,
    DoctorProposalSummary,
    DoctorSchemaVersions,
    DoctorSnapshot,
    DoctorTurnIntentInfo,
)

__all__ = [
    "DoctorCheckItem",
    "DoctorReport",
    "format_doctor_text",
    "inspect_doctor_snapshot",
]


@dataclass(frozen=True)
class DoctorCheckItem:
    """Single categorized health check item inside ``DoctorReport``."""

    name: str
    status: str
    detail: str
    remediation: str | None = None

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "name": self.name,
            "status": self.status,
            "detail": self.detail,
            "remediation": self.remediation,
        }


@dataclass(frozen=True)
class DoctorReport:
    """Structured diagnostic report suitable for both JSON output and human handover formatting."""

    overall_status: str
    data_root: str
    store_id: str | None
    schema: DoctorSchemaVersions
    restore_epoch: int | None
    trust_generation: int | None
    signer_reset_recorded: bool
    signers: tuple[SignerRecord, ...]
    terminal_channel_eligible: bool
    layer2_harnesses: tuple[DoctorLayer2HarnessStatus, ...]
    unresolved_accounting_locks: tuple[DoctorAccountingLock, ...]
    pending_restore_tombstones: DoctorPendingTombstones
    pending_proposals: tuple[DoctorProposalSummary, ...]
    bootstrap_drifts: tuple[DoctorBootstrapDrift, ...]
    checks: tuple[DoctorCheckItem, ...]
    remediations: tuple[str, ...]
    integrity_errors: tuple[str, ...]
    active_turn_intents: tuple[DoctorTurnIntentInfo, ...] = ()
    incomplete_journals: tuple[DoctorJournalInfo, ...] = ()
    permission_problems: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "overall_status": self.overall_status,
            "data_root": self.data_root,
            "store_id": self.store_id,
            "schema": {
                "store_version": self.schema.store_version,
                "policy_version": self.schema.policy_version,
                "expected_store_version": self.schema.expected_store_version,
                "expected_policy_version": self.schema.expected_policy_version,
            },
            "restore_epoch": self.restore_epoch,
            "trust_generation": self.trust_generation,
            "signer_reset_recorded": self.signer_reset_recorded,
            "signers": [
                {
                    "signer_id": s.signer_id,
                    "channel": s.channel.value,
                    "key_digest": s.key_digest,
                    "tofu": s.tofu,
                    "sign_count": s.sign_count,
                }
                for s in self.signers
            ],
            "terminal_channel_eligible": self.terminal_channel_eligible,
            "layer2_harnesses": [
                {
                    "harness_id": h.harness_id,
                    "host_version": h.host_version,
                    "config_digest": h.config_digest,
                    "state": h.state.value,
                    "created_at": h.created_at,
                }
                for h in self.layer2_harnesses
            ],
            "unresolved_accounting_locks": [
                {
                    "lock_key": lock.lock_key,
                    "owner_id": lock.owner_id,
                    "period_key": lock.period_key,
                    "backup_created_at": lock.backup_created_at,
                    "locked_at": lock.locked_at,
                }
                for lock in self.unresolved_accounting_locks
            ],
            "pending_restore_tombstones": {
                "present": self.pending_restore_tombstones.present,
                "restore_epoch": self.pending_restore_tombstones.restore_epoch,
                "expired_holders_count": self.pending_restore_tombstones.expired_holders_count,
                "corrupt_error": self.pending_restore_tombstones.corrupt_error,
            },
            "pending_proposals": [
                {
                    "proposal_id": p.proposal_id,
                    "status": p.status,
                    "kind": p.kind,
                    "active_journal_id": p.active_journal_id,
                }
                for p in self.pending_proposals
            ],
            "bootstrap_drifts": [
                {
                    "proposal_id": d.proposal_id,
                    "target_root": d.target_root,
                    "rel_path": d.rel_path,
                    "reason": d.reason,
                    "current_digest": d.current_digest,
                    "expected_digest": d.expected_digest,
                }
                for d in self.bootstrap_drifts
            ],
            "checks": [c.to_dict() for c in self.checks],
            "remediations": list(self.remediations),
            "integrity_errors": list(self.integrity_errors),
            "active_turn_intents": [
                {
                    "turn_id": ti.turn_id,
                    "journal_id": ti.journal_id,
                    "approval_id": ti.approval_id,
                    "direction": ti.direction,
                    "state": ti.state,
                    "created_at": ti.created_at,
                }
                for ti in self.active_turn_intents
            ],
            "incomplete_journals": [
                {
                    "journal_id": j.journal_id,
                    "proposal_id": j.proposal_id,
                    "direction": j.direction,
                    "status": j.status,
                    "grant_id": j.grant_id,
                    "updated_at": j.updated_at,
                }
                for j in self.incomplete_journals
            ],
            "permission_problems": list(self.permission_problems),
        }


def inspect_doctor_snapshot(snapshot: DoctorSnapshot) -> DoctorReport:
    """Analyze a read-only ``DoctorSnapshot`` and produce actionable checks and remediations."""
    checks: list[DoctorCheckItem] = []
    remediations: list[str] = []

    def _add(name: str, status: str, detail: str, remediation: str | None = None) -> None:
        checks.append(DoctorCheckItem(name=name, status=status, detail=detail, remediation=remediation))
        if remediation is not None and remediation not in remediations:
            remediations.append(remediation)

    sv, pv = snapshot.schema.store_version, snapshot.schema.policy_version
    esv, epv = snapshot.schema.expected_store_version, snapshot.schema.expected_policy_version
    if sv == esv and pv == epv:
        _add("schema", "ok", f"store={sv} policy={pv}")
    else:
        _add(
            "schema",
            "warn",
            f"store={sv} (expected {esv}), policy={pv} (expected {epv})",
            "Run `brain migrate --offline --config <daemon.json>` when upgrading older schemas.",
        )

    if snapshot.signer_reset_recorded:
        _add(
            "signers",
            "warn",
            f"signer_reset_recorded=true, signers={len(snapshot.signers)}, gen={snapshot.trust_generation}",
            "Confirm trust_generation with owner and enroll non-TOFU signers if needed.",
        )
    elif not snapshot.signers:
        _add(
            "signers",
            "error",
            "no active signers enrolled",
            "Re-enroll an owner signer via `brain init --reset-signers --config <daemon.json>`.",
        )
    else:
        _add(
            "signers",
            "ok",
            f"active_signers={len(snapshot.signers)}, trust_generation={snapshot.trust_generation}",
        )

    if snapshot.terminal_channel_eligible:
        _add("layer2", "ok", f"terminal_channel_eligible=true ({len(snapshot.layer2_harnesses)} harnesses)")
    elif snapshot.layer2_harnesses:
        _add(
            "layer2",
            "warn",
            f"terminal_channel_eligible=false ({len(snapshot.layer2_harnesses)} harnesses)",
            "Verify Layer-2 config or re-bootstrap checkout before relying on terminal low-risk confirmation.",
        )
    else:
        _add("layer2", "ok", "terminal_channel_eligible=false (no non-CLI harnesses registered)")

    if snapshot.unresolved_accounting_locks:
        _add(
            "accounting_locks",
            "warn",
            f"{len(snapshot.unresolved_accounting_locks)} unresolved accounting lock(s)",
            "Reconcile post-restore accounting locks before relying on affected billing periods.",
        )
    else:
        _add("accounting_locks", "ok", "0 unresolved accounting locks")

    tomb = snapshot.pending_restore_tombstones
    if tomb.present and (tomb.corrupt_error is not None or tomb.expired_holders_count > 0):
        _add(
            "pending_restore_tombstones",
            "warn",
            f"present (restore_epoch={tomb.restore_epoch}, expired={tomb.expired_holders_count})",
            "Start the daemon (`brain serve --config <daemon.json>`) to drain pending_restore_tombstones.json.",
        )
    elif tomb.present:
        _add("pending_restore_tombstones", "ok", f"present with 0 expired holders (epoch={tomb.restore_epoch})")
    else:
        _add("pending_restore_tombstones", "ok", "absent")

    if snapshot.pending_proposals:
        _add(
            "proposals",
            "warn",
            f"{len(snapshot.pending_proposals)} pending/incomplete proposal(s)",
            "Inspect pending proposals via `brain review list --profile <profile.json>`.",
        )
    else:
        _add("proposals", "ok", "0 pending proposals")

    if snapshot.bootstrap_drifts:
        _add(
            "bootstrap_drift",
            "warn",
            f"{len(snapshot.bootstrap_drifts)} drifted target file(s)",
            "Inspect bootstrap drift in checkout and re-plan or rollback via `brain review` / `brain bootstrap`.",
        )
    else:
        _add("bootstrap_drift", "ok", "0 drifted targets")

    if snapshot.active_turn_intents:
        _add(
            "active_turn_intents",
            "warn",
            f"{len(snapshot.active_turn_intents)} active unprojected apply/rollback turn intent(s)",
            "Resume or recover interrupted apply/rollback journal turn before further mutations.",
        )

    if snapshot.incomplete_journals:
        _add(
            "incomplete_journals",
            "warn",
            f"{len(snapshot.incomplete_journals)} incomplete apply/rollback journal(s)",
            "Inspect incomplete journals via `brain review continue <proposal_id> --profile <profile.json>`.",
        )

    if snapshot.permission_problems:
        _add(
            "permissions",
            "error",
            "; ".join(snapshot.permission_problems),
            "Restrict data_root and ancestor permissions to owner-only.",
        )

    if snapshot.integrity_errors:
        _add(
            "integrity",
            "error",
            "; ".join(snapshot.integrity_errors),
            "Inspect reported storage integrity errors before resuming mutating operations.",
        )

    statuses = {c.status for c in checks}
    overall = "fail" if "error" in statuses else "warn" if "warn" in statuses else "pass"

    return DoctorReport(
        overall_status=overall,
        data_root=str(snapshot.data_root),
        store_id=snapshot.store_id,
        schema=snapshot.schema,
        restore_epoch=snapshot.restore_epoch,
        trust_generation=snapshot.trust_generation,
        signer_reset_recorded=snapshot.signer_reset_recorded,
        signers=snapshot.signers,
        terminal_channel_eligible=snapshot.terminal_channel_eligible,
        layer2_harnesses=snapshot.layer2_harnesses,
        unresolved_accounting_locks=snapshot.unresolved_accounting_locks,
        pending_restore_tombstones=snapshot.pending_restore_tombstones,
        pending_proposals=snapshot.pending_proposals,
        bootstrap_drifts=snapshot.bootstrap_drifts,
        checks=tuple(checks),
        remediations=tuple(remediations),
        integrity_errors=snapshot.integrity_errors,
        active_turn_intents=snapshot.active_turn_intents,
        incomplete_journals=snapshot.incomplete_journals,
        permission_problems=snapshot.permission_problems,
    )


def format_doctor_text(report: DoctorReport) -> str:
    """Format a ``DoctorReport`` as concise human-readable handover diagnostics."""
    lines = [
        f"Overall status: {report.overall_status}",
        f"Data root: {report.data_root}",
        f"Store ID: {report.store_id or 'unknown'}",
        f"Schema: store={report.schema.store_version}/{report.schema.expected_store_version}, "
        f"policy={report.schema.policy_version}/{report.schema.expected_policy_version}",
        f"Restore epoch: {report.restore_epoch} | Trust generation: {report.trust_generation}",
        f"Signer reset recorded: {report.signer_reset_recorded} | Active signers: {len(report.signers)}",
        f"Terminal channel eligible: {report.terminal_channel_eligible}",
        f"Unresolved accounting locks: {len(report.unresolved_accounting_locks)}",
        f"Pending restore tombstones: {report.pending_restore_tombstones.present}",
        f"Pending proposals: {len(report.pending_proposals)} | Bootstrap drifts: {len(report.bootstrap_drifts)}",
        (
            f"Active turn intents: {len(report.active_turn_intents)} | "
            f"Incomplete journals: {len(report.incomplete_journals)}"
        ),
    ]
    for h in report.layer2_harnesses:
        lines.append(f"  Layer2[{h.harness_id}]: {h.state.value}")
    for lock in report.unresolved_accounting_locks:
        lines.append(f"  Accounting lock: {lock.lock_key} ({lock.period_key})")
    for ti in report.active_turn_intents:
        lines.append(f"  Active turn intent: {ti.turn_id} ({ti.direction}, {ti.state})")
    for j in report.incomplete_journals:
        lines.append(f"  Incomplete journal: {j.journal_id} ({j.direction}, {j.status})")
    for drift in report.bootstrap_drifts:
        lines.append(f"  Bootstrap drift: {drift.rel_path} ({drift.reason})")
    if report.remediations:
        lines.append("Remediations:")
        for rem in report.remediations:
            lines.append(f"  - {rem}")
    return "\n".join(lines) + "\n"
