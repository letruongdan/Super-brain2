"""Application diagnostic analyzer and report formatter for strictly read-only ``brain doctor``."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from superbrain.application._doctor_checks import (
    CheckBuilder,
    DoctorCheckItem,
    check_daemon,
    check_harness_and_subsystems,
    check_identity,
    check_permissions_privacy_retention,
    clip_report_str,
)
from superbrain.application._doctor_storage_checks import (
    check_storage_core,
    check_storage_ops,
)
from superbrain.application._privacy_canary import KernelPrivacyScanner
from superbrain.core._kernel_approval import SignerRecord
from superbrain.core.canonical import canonical_json
from superbrain.core.jsonvalue import JsonValue
from superbrain.ports.doctor import (
    MAX_DOCTOR_REPORT_BYTES,
    MAX_LIST_FINDINGS_PER_GROUP,
    MAX_REPORT_CHECKS,
    DoctorAccountingLock,
    DoctorBootstrapDrift,
    DoctorJournalInfo,
    DoctorLayer2HarnessStatus,
    DoctorPendingTombstones,
    DoctorProposalSummary,
    DoctorSchemaVersions,
    DoctorSnapshot,
    DoctorTurnIntentInfo,
    PrivacyScannerPort,
)

__all__ = [
    "DoctorCheckItem",
    "DoctorReport",
    "KernelPrivacyScanner",
    "format_doctor_dict_text",
    "format_doctor_text",
    "inspect_doctor_snapshot",
]


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
            "data_root": clip_report_str(self.data_root),
            "store_id": None if self.store_id is None else clip_report_str(self.store_id),
            "schema": {
                "store_version": self.schema.store_version,
                "policy_version": self.schema.policy_version,
                "expected_store_version": self.schema.expected_store_version,
                "expected_policy_version": self.schema.expected_policy_version,
                "min_store_reader_version": self.schema.min_store_reader_version,
                "min_policy_reader_version": self.schema.min_policy_reader_version,
            },
            "restore_epoch": self.restore_epoch,
            "trust_generation": self.trust_generation,
            "signer_reset_recorded": self.signer_reset_recorded,
            "signers": [
                {
                    "signer_id": clip_report_str(s.signer_id),
                    "channel": s.channel.value,
                    "key_digest": clip_report_str(s.key_digest),
                    "tofu": s.tofu,
                    "sign_count": s.sign_count,
                }
                for s in self.signers[:MAX_LIST_FINDINGS_PER_GROUP]
            ],
            "terminal_channel_eligible": self.terminal_channel_eligible,
            "layer2_harnesses": [
                {
                    "harness_id": clip_report_str(h.harness_id),
                    "host_version": None if h.host_version is None else clip_report_str(h.host_version),
                    "config_digest": None if h.config_digest is None else clip_report_str(h.config_digest),
                    "state": h.state.value,
                    "created_at": h.created_at,
                }
                for h in self.layer2_harnesses[:MAX_LIST_FINDINGS_PER_GROUP]
            ],
            "unresolved_accounting_locks": [
                {
                    "lock_key": clip_report_str(lock.lock_key),
                    "owner_id": clip_report_str(lock.owner_id),
                    "period_key": clip_report_str(lock.period_key),
                    "backup_created_at": lock.backup_created_at,
                    "locked_at": lock.locked_at,
                }
                for lock in self.unresolved_accounting_locks[:MAX_LIST_FINDINGS_PER_GROUP]
            ],
            "pending_restore_tombstones": {
                "present": self.pending_restore_tombstones.present,
                "restore_epoch": self.pending_restore_tombstones.restore_epoch,
                "expired_holders_count": self.pending_restore_tombstones.expired_holders_count,
                "corrupt_error": (
                    None
                    if self.pending_restore_tombstones.corrupt_error is None
                    else clip_report_str(self.pending_restore_tombstones.corrupt_error)
                ),
            },
            "pending_proposals": [
                {
                    "proposal_id": clip_report_str(p.proposal_id),
                    "status": p.status,
                    "kind": p.kind,
                    "active_journal_id": None if p.active_journal_id is None else clip_report_str(p.active_journal_id),
                }
                for p in self.pending_proposals[:MAX_LIST_FINDINGS_PER_GROUP]
            ],
            "bootstrap_drifts": [
                {
                    "proposal_id": clip_report_str(d.proposal_id),
                    "target_root": clip_report_str(d.target_root),
                    "rel_path": clip_report_str(d.rel_path),
                    "reason": clip_report_str(d.reason),
                    "current_digest": d.current_digest,
                    "expected_digest": d.expected_digest,
                }
                for d in self.bootstrap_drifts[:MAX_LIST_FINDINGS_PER_GROUP]
            ],
            "checks": [c.to_dict() for c in self.checks[:MAX_REPORT_CHECKS]],
            "remediations": [clip_report_str(r) for r in self.remediations[:MAX_LIST_FINDINGS_PER_GROUP]],
            "integrity_errors": [clip_report_str(e) for e in self.integrity_errors[:MAX_LIST_FINDINGS_PER_GROUP]],
            "active_turn_intents": [
                {
                    "turn_id": clip_report_str(ti.turn_id),
                    "journal_id": clip_report_str(ti.journal_id),
                    "approval_id": clip_report_str(ti.approval_id),
                    "direction": ti.direction,
                    "state": ti.state,
                    "created_at": ti.created_at,
                }
                for ti in self.active_turn_intents[:MAX_LIST_FINDINGS_PER_GROUP]
            ],
            "incomplete_journals": [
                {
                    "journal_id": clip_report_str(j.journal_id),
                    "proposal_id": clip_report_str(j.proposal_id),
                    "direction": j.direction,
                    "status": j.status,
                    "grant_id": clip_report_str(j.grant_id),
                    "updated_at": j.updated_at,
                }
                for j in self.incomplete_journals[:MAX_LIST_FINDINGS_PER_GROUP]
            ],
            "permission_problems": [clip_report_str(p) for p in self.permission_problems[:MAX_LIST_FINDINGS_PER_GROUP]],
        }


def _fit_report_budget(report: DoctorReport) -> DoctorReport:
    if len(canonical_json(report.to_dict())) <= MAX_DOCTOR_REPORT_BYTES:
        return report
    return DoctorReport(
        overall_status=report.overall_status,
        data_root=clip_report_str(report.data_root),
        store_id=None if report.store_id is None else clip_report_str(report.store_id),
        schema=report.schema,
        restore_epoch=report.restore_epoch,
        trust_generation=report.trust_generation,
        signer_reset_recorded=report.signer_reset_recorded,
        signers=report.signers[:8],
        terminal_channel_eligible=report.terminal_channel_eligible,
        layer2_harnesses=report.layer2_harnesses[:8],
        unresolved_accounting_locks=report.unresolved_accounting_locks[:8],
        pending_restore_tombstones=report.pending_restore_tombstones,
        pending_proposals=report.pending_proposals[:8],
        bootstrap_drifts=report.bootstrap_drifts[:8],
        checks=report.checks[:MAX_REPORT_CHECKS],
        remediations=report.remediations[:8],
        integrity_errors=report.integrity_errors[:8],
        active_turn_intents=report.active_turn_intents[:8],
        incomplete_journals=report.incomplete_journals[:8],
        permission_problems=report.permission_problems[:8],
    )


def inspect_doctor_snapshot(
    snapshot: DoctorSnapshot,
    *,
    privacy_scanner: PrivacyScannerPort | None = None,
) -> DoctorReport:
    """Analyze a read-only ``DoctorSnapshot`` across all 12 §13 groups within strict output bounds."""
    b = CheckBuilder()
    check_daemon(snapshot, b)
    check_identity(snapshot, b)
    check_storage_core(snapshot, b)
    check_storage_ops(snapshot, b)
    check_permissions_privacy_retention(snapshot, privacy_scanner, b)
    check_harness_and_subsystems(snapshot, b)

    statuses = {c.status for c in b.checks}
    overall = "fail" if "FAIL" in statuses else "warn" if "WARN" in statuses else "pass"

    report = DoctorReport(
        overall_status=overall,
        data_root=clip_report_str(str(snapshot.data_root)),
        store_id=None if snapshot.store_id is None else clip_report_str(snapshot.store_id),
        schema=snapshot.schema,
        restore_epoch=snapshot.restore_epoch,
        trust_generation=snapshot.trust_generation,
        signer_reset_recorded=snapshot.signer_reset_recorded,
        signers=snapshot.signers[:MAX_LIST_FINDINGS_PER_GROUP],
        terminal_channel_eligible=snapshot.terminal_channel_eligible,
        layer2_harnesses=snapshot.layer2_harnesses[:MAX_LIST_FINDINGS_PER_GROUP],
        unresolved_accounting_locks=snapshot.unresolved_accounting_locks[:MAX_LIST_FINDINGS_PER_GROUP],
        pending_restore_tombstones=snapshot.pending_restore_tombstones,
        pending_proposals=snapshot.pending_proposals[:MAX_LIST_FINDINGS_PER_GROUP],
        bootstrap_drifts=snapshot.bootstrap_drifts[:MAX_LIST_FINDINGS_PER_GROUP],
        checks=tuple(b.checks[:MAX_REPORT_CHECKS]),
        remediations=tuple(b.remediations[:MAX_LIST_FINDINGS_PER_GROUP]),
        integrity_errors=tuple(clip_report_str(e) for e in snapshot.integrity_errors[:MAX_LIST_FINDINGS_PER_GROUP]),
        active_turn_intents=snapshot.active_turn_intents[:MAX_LIST_FINDINGS_PER_GROUP],
        incomplete_journals=snapshot.incomplete_journals[:MAX_LIST_FINDINGS_PER_GROUP],
        permission_problems=tuple(
            clip_report_str(p) for p in snapshot.permission_problems[:MAX_LIST_FINDINGS_PER_GROUP]
        ),
    )
    return _fit_report_budget(report)


def _as_list(raw: Mapping[str, JsonValue], key: str) -> list[JsonValue]:
    val = raw.get(key)
    return val if isinstance(val, list) else []


def _format_str(val: JsonValue, *, default: str = "") -> str:
    return clip_report_str(val if isinstance(val, str) else default)


def format_doctor_dict_text(raw: Mapping[str, JsonValue]) -> str:
    """Format a doctor report JSON mapping as concise human-readable diagnostics without secrets."""
    if raw.get("status") == "running" and isinstance(raw.get("job_id"), str):
        return f"Doctor status: running\nJob ID: {clip_report_str(str(raw['job_id']))}\n"
    if raw.get("status") == "interrupted":
        fix = raw.get("fix")
        acts = fix.get("actions") if isinstance(fix, Mapping) else None
        lines = ["Doctor fix status: interrupted at the request cutoff; rerun to finish"]
        for act in acts if isinstance(acts, list) else []:
            if isinstance(act, Mapping):
                lines.append(f"  {_format_str(act.get('action'))}: {_format_str(act.get('status'))}")
        return "\n".join(lines) + "\n"
    sch = raw.get("schema")
    sch_map = sch if isinstance(sch, Mapping) else {}
    tomb = raw.get("pending_restore_tombstones")
    tomb_map = tomb if isinstance(tomb, Mapping) else {}
    store_val = raw.get("store_id")
    store_txt = clip_report_str(store_val) if isinstance(store_val, str) and store_val else "unknown"
    signers = _as_list(raw, "signers")
    locks = _as_list(raw, "unresolved_accounting_locks")
    props = _as_list(raw, "pending_proposals")
    drifts = _as_list(raw, "bootstrap_drifts")
    intents = _as_list(raw, "active_turn_intents")
    journals = _as_list(raw, "incomplete_journals")
    checks = _as_list(raw, "checks")
    harnesses = _as_list(raw, "layer2_harnesses")
    rems = _as_list(raw, "remediations")
    lines = [
        f"Overall status: {_format_str(raw.get('overall_status'), default='unknown')}",
        f"Data root: {_format_str(raw.get('data_root'))}",
        f"Store ID: {store_txt}",
        f"Schema: store={sch_map.get('store_version')}/{sch_map.get('expected_store_version')}, "
        f"policy={sch_map.get('policy_version')}/{sch_map.get('expected_policy_version')}",
        f"Restore epoch: {raw.get('restore_epoch')} | Trust generation: {raw.get('trust_generation')}",
        f"Signer reset recorded: {bool(raw.get('signer_reset_recorded'))} | Active signers: {len(signers)}",
        f"Terminal channel eligible: {bool(raw.get('terminal_channel_eligible'))}",
        f"Unresolved accounting locks: {len(locks)}",
        f"Pending restore tombstones: {bool(tomb_map.get('present'))}",
        f"Pending proposals: {len(props)} | Bootstrap drifts: {len(drifts)}",
        f"Active turn intents: {len(intents)} | Incomplete journals: {len(journals)}",
        "Checks:",
    ]
    for chk in checks[:MAX_REPORT_CHECKS]:
        if isinstance(chk, Mapping):
            lines.append(
                f"  [{_format_str(chk.get('status'))}] {_format_str(chk.get('group'))}/"
                f"{_format_str(chk.get('name'))} ({_format_str(chk.get('reason'), default='ok')}): "
                f"{_format_str(chk.get('detail'))}"
            )
    for h in harnesses[:MAX_LIST_FINDINGS_PER_GROUP]:
        if isinstance(h, Mapping):
            lines.append(f"  Layer2[{_format_str(h.get('harness_id'))}]: {_format_str(h.get('state'))}")
    for lock in locks[:MAX_LIST_FINDINGS_PER_GROUP]:
        if isinstance(lock, Mapping):
            lines.append(
                f"  Accounting lock: {_format_str(lock.get('lock_key'))} ({_format_str(lock.get('period_key'))})"
            )
    for ti in intents[:MAX_LIST_FINDINGS_PER_GROUP]:
        if isinstance(ti, Mapping):
            lines.append(
                f"  Active turn intent: {_format_str(ti.get('turn_id'))} "
                f"({_format_str(ti.get('direction'))}, {_format_str(ti.get('state'))})"
            )
    for j in journals[:MAX_LIST_FINDINGS_PER_GROUP]:
        if isinstance(j, Mapping):
            lines.append(
                f"  Incomplete journal: {_format_str(j.get('journal_id'))} "
                f"({_format_str(j.get('direction'))}, {_format_str(j.get('status'))})"
            )
    for drift in drifts[:MAX_LIST_FINDINGS_PER_GROUP]:
        if isinstance(drift, Mapping):
            lines.append(
                f"  Bootstrap drift: {_format_str(drift.get('rel_path'))} ({_format_str(drift.get('reason'))})"
            )
    if rems:
        lines.append("Remediations:")
        for rem in rems[:MAX_LIST_FINDINGS_PER_GROUP]:
            lines.append(f"  - {_format_str(rem)}")
    fix_raw = raw.get("fix")
    if isinstance(fix_raw, Mapping):
        fix_actions = fix_raw.get("actions")
        if isinstance(fix_actions, list) and fix_actions:
            lines.append("Fix actions:")
            for item in fix_actions[:MAX_LIST_FINDINGS_PER_GROUP]:
                if isinstance(item, Mapping):
                    lines.append(
                        f"  [{_format_str(item.get('status'))}] {_format_str(item.get('action'))}: "
                        f"{_format_str(item.get('detail'))}"
                    )
    return "\n".join(lines) + "\n"


def format_doctor_text(report: DoctorReport) -> str:
    """Format a ``DoctorReport`` as concise human-readable handover diagnostics without secrets."""
    return format_doctor_dict_text(report.to_dict())
