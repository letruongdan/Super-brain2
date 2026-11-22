"""Group check builders for read-only ``brain doctor`` diagnostics (spec 13, 14.2, I4-1)."""

from __future__ import annotations

from dataclasses import dataclass

from superbrain.application._privacy_canary import KernelPrivacyScanner
from superbrain.core.jsonvalue import JsonValue
from superbrain.ports.doctor import (
    MAX_LIST_FINDINGS_PER_GROUP,
    MAX_REPORT_CHECKS,
    MAX_REPORT_STRING_LEN,
    DoctorSnapshot,
    PrivacyScannerPort,
)

__all__ = [
    "CheckBuilder",
    "DoctorCheckItem",
    "check_daemon",
    "check_harness_and_subsystems",
    "check_identity",
    "check_permissions_privacy_retention",
    "clip_report_str",
]


def clip_report_str(text: str, limit: int = MAX_REPORT_STRING_LEN) -> str:
    """Truncate diagnostic strings cleanly to stay within strict output limits."""
    if len(text) <= limit:
        return text
    if limit <= 3:
        return text[:limit]
    return text[: limit - 3] + "..."


@dataclass(frozen=True)
class DoctorCheckItem:
    """Single categorized health check item inside ``DoctorReport``."""

    name: str
    status: str
    detail: str
    remediation: str | None = None
    group: str = "general"
    reason: str = "ok"

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "name": clip_report_str(self.name),
            "group": clip_report_str(self.group),
            "status": self.status,
            "reason": clip_report_str(self.reason),
            "detail": clip_report_str(self.detail),
            "remediation": None if self.remediation is None else clip_report_str(self.remediation),
        }


class CheckBuilder:
    """Bounded collector accumulating group check items and deduplicated remediations."""

    def __init__(self) -> None:
        self.checks: list[DoctorCheckItem] = []
        self.remediations: list[str] = []

    def add(
        self,
        group: str,
        name: str,
        status: str,
        *,
        reason: str,
        detail: str,
        remediation: str | None = None,
    ) -> None:
        if len(self.checks) >= MAX_REPORT_CHECKS:
            return
        clipped_rem = None if remediation is None else clip_report_str(remediation)
        self.checks.append(
            DoctorCheckItem(
                name=name,
                group=group,
                status=status,
                reason=reason,
                detail=clip_report_str(detail),
                remediation=clipped_rem,
            )
        )
        if (
            clipped_rem is not None
            and clipped_rem not in self.remediations
            and len(self.remediations) < MAX_LIST_FINDINGS_PER_GROUP
        ):
            self.remediations.append(clipped_rem)


def check_daemon(snap: DoctorSnapshot, b: CheckBuilder) -> None:
    """Emit ``daemon`` group checks covering writer lock and schema versions."""
    d = snap.daemon_stats
    if d is None:
        b.add("daemon", "daemon.writer_lock", "PASS", reason="ok", detail="daemon lock probe not attached")
    elif d.lock_error is not None:
        b.add(
            "daemon",
            "daemon.writer_lock",
            "FAIL",
            reason="writer_lock_error",
            detail=d.lock_error,
            remediation="Ensure writer.lock exists as a regular owner-only file before starting the daemon.",
        )
    elif d.endpoint_valid is False:
        b.add(
            "daemon",
            "daemon.writer_lock",
            "FAIL",
            reason="unsafe_endpoint",
            detail=d.endpoint_detail,
            remediation="Remove unsafe endpoint.json link before starting the daemon.",
        )
    elif d.writer_lock_held:
        b.add(
            "daemon",
            "daemon.writer_lock",
            "PASS",
            reason="writer_lock_held",
            detail=f"writer.lock held cleanly (epoch={d.writer_epoch}, {d.endpoint_detail})",
        )
    else:
        b.add(
            "daemon",
            "daemon.writer_lock",
            "PASS",
            reason="stopped_cleanly",
            detail=f"daemon stopped cleanly (epoch={d.writer_epoch}, {d.endpoint_detail})",
        )

    sv, pv = snap.schema.store_version, snap.schema.policy_version
    esv, epv = snap.schema.expected_store_version, snap.schema.expected_policy_version
    msv, mpv = snap.schema.min_store_reader_version, snap.schema.min_policy_reader_version
    if sv is None or pv is None:
        b.add(
            "daemon",
            "daemon.schema_version",
            "FAIL",
            reason="schema_unreadable",
            detail=f"store={sv} (expected {esv}), policy={pv} (expected {epv})",
            remediation="Inspect brain.db / policy.db readability and restore or re-initialize if missing.",
        )
    elif (msv is not None and msv > esv) or (mpv is not None and mpv > epv):
        b.add(
            "daemon",
            "daemon.schema_version",
            "FAIL",
            reason="unsupported_version",
            detail=f"min_reader store={msv}/{esv} policy={mpv}/{epv} exceeds binary version",
            remediation="Upgrade brain binary to a version supporting this database schema.",
        )
    elif sv > esv or pv > epv:
        b.add(
            "daemon",
            "daemon.schema_version",
            "WARN",
            reason="unsupported_writable_version",
            detail=f"store={sv} (code={esv}), policy={pv} (code={epv}) is newer than writable code version",
            remediation="Upgrade brain binary before performing mutating operations.",
        )
    elif sv < esv or pv < epv:
        b.add(
            "daemon",
            "daemon.schema_version",
            "WARN",
            reason="migration_required",
            detail=f"store={sv} (expected {esv}), policy={pv} (expected {epv})",
            remediation="Run `brain migrate --offline --config <daemon.json>` when upgrading older schemas.",
        )
    else:
        b.add("daemon", "daemon.schema_version", "PASS", reason="ok", detail=f"store={sv} policy={pv}")


def check_identity(snap: DoctorSnapshot, b: CheckBuilder) -> None:
    """Emit ``identity`` group checks for signers and harness credentials."""
    if snap.signer_reset_recorded:
        b.add(
            "identity",
            "identity.signers",
            "WARN",
            reason="signer_reset_recorded",
            detail=f"signer_reset_recorded=true, signers={len(snap.signers)}, gen={snap.trust_generation}",
            remediation="Confirm trust_generation with owner and enroll non-TOFU signers if needed.",
        )
    elif not snap.signers:
        b.add(
            "identity",
            "identity.signers",
            "FAIL",
            reason="no_active_signers",
            detail="no active signers enrolled",
            remediation="Re-enroll an owner signer via `brain init --reset-signers --config <daemon.json>`.",
        )
    else:
        b.add(
            "identity",
            "identity.signers",
            "PASS",
            reason="ok",
            detail=f"active_signers={len(snap.signers)}, trust_generation={snap.trust_generation}",
        )

    ident = snap.identity_stats
    if ident is None:
        b.add("identity", "identity.credentials", "PASS", reason="ok", detail="identity probe not populated")
    elif ident.error is not None:
        b.add("identity", "identity.credentials", "WARN", reason="identity_probe_unavailable", detail=ident.error)
    elif ident.missing_harness_credentials:
        missing_txt = ", ".join(ident.missing_harness_credentials)
        b.add(
            "identity",
            "identity.credentials",
            "WARN",
            reason="missing_harness_credentials",
            detail=f"registered harnesses lacking active credential: {missing_txt}",
            remediation="Provision missing harness client profile credentials via `brain enroll`.",
        )
    else:
        b.add(
            "identity",
            "identity.credentials",
            "PASS",
            reason="ok",
            detail=f"active_credentials={ident.active_credentials}, revoked={ident.revoked_credentials}",
        )


def check_permissions_privacy_retention(
    snap: DoctorSnapshot,
    privacy_scanner: PrivacyScannerPort | None,
    b: CheckBuilder,
) -> None:
    """Emit ``permissions``, ``privacy``, and ``retention`` group checks."""
    if snap.permission_problems or snap.ancestor_permission_problems or snap.backup_permission_problems:
        combined = [
            *snap.permission_problems,
            *snap.ancestor_permission_problems,
            *snap.backup_permission_problems,
        ]
        all_probs = list(dict.fromkeys(combined))
        b.add(
            "permissions",
            "permissions.tree",
            "FAIL",
            reason="insecure_permissions",
            detail="; ".join(all_probs[:MAX_LIST_FINDINGS_PER_GROUP]),
            remediation=(
                "Restrict data_root, logs, backups, and ancestor permissions via "
                "`brain doctor --fix` or owner-only ACLs."
            ),
        )
    else:
        b.add("permissions", "permissions.tree", "PASS", reason="ok", detail="owner-only tree and ancestors verified")

    canaries = snap.privacy_canaries
    if not canaries:
        scanner = privacy_scanner if privacy_scanner is not None else KernelPrivacyScanner()
        canaries = scanner.check_canary_channels()
    failed_canaries = [c for c in canaries if not c.passed]
    if failed_canaries:
        b.add(
            "privacy",
            "privacy.canaries",
            "FAIL",
            reason="canary_filter_failed",
            detail=f"failed channels: {', '.join(c.channel for c in failed_canaries)}",
            remediation="Repair PrivacyFilter rules immediately; synthetic canary secrets bypassed filtering.",
        )
    else:
        b.add(
            "privacy",
            "privacy.canaries",
            "PASS",
            reason="ok",
            detail=f"{len(canaries)} canary channel(s) verified",
        )

    rescan = snap.privacy_rescan
    if rescan is None:
        b.add("privacy", "privacy.rescan", "WARN", reason="probe_unavailable", detail="privacy rescan not executed")
    elif rescan.error is not None:
        b.add("privacy", "privacy.rescan", "WARN", reason="probe_unavailable", detail=rescan.error)
    elif rescan.findings:
        summary = "; ".join(
            f"{f.holder_kind}:{f.holder_id}:{f.rule_id}:{f.digest}"
            for f in rescan.findings[:MAX_LIST_FINDINGS_PER_GROUP]
        )
        b.add(
            "privacy",
            "privacy.rescan",
            "FAIL",
            reason="privacy_leak_detected",
            detail=f"{len(rescan.findings)} finding(s): {summary}",
            remediation="Quarantine offending CAS/log holders immediately and purge leaked secrets.",
        )
    elif rescan.truncated:
        b.add(
            "privacy",
            "privacy.rescan",
            "WARN",
            reason="scan_cap_reached",
            detail=f"privacy rescan capped at {rescan.scanned_items} item(s), {rescan.scanned_bytes} byte(s)",
        )
    else:
        b.add(
            "privacy",
            "privacy.rescan",
            "PASS",
            reason="ok",
            detail=f"scanned {rescan.scanned_items} item(s), {rescan.scanned_bytes} byte(s)",
        )

    ret = snap.retention_stats
    if ret is None:
        b.add("retention", "retention.tombstones", "PASS", reason="ok", detail="retention stats not attached")
    elif ret.tombstone_holder_mismatch_count > 0:
        b.add(
            "retention",
            "retention.tombstones",
            "FAIL",
            reason="tombstone_holder_mismatch",
            detail=ret.mismatch_detail,
            remediation="Run `brain doctor --fix` to reconcile tombstones against CAS holders.",
        )
    elif ret.check_skipped_reason is not None:
        b.add("retention", "retention.tombstones", "WARN", reason="check_skipped", detail=ret.check_skipped_reason)
    elif ret.expired_due_count > 0:
        b.add(
            "retention",
            "retention.tombstones",
            "WARN",
            reason="expired_holders_pending",
            detail=f"{ret.expired_due_count} expired CAS holder(s) due for GC (last_gc={ret.last_gc_at})",
            remediation="Run daemon retention GC to reclaim expired CAS holders.",
        )
    else:
        b.add(
            "retention",
            "retention.tombstones",
            "PASS",
            reason="ok",
            detail=f"0 tombstone/holder mismatches (last_gc={ret.last_gc_at or 'none'})",
        )


def check_harness_and_subsystems(snap: DoctorSnapshot, b: CheckBuilder) -> None:
    """Emit ``harness``, ``capture``, ``jev``, ``index``, ``lessons``, and ``skill`` checks."""
    if snap.terminal_channel_eligible:
        b.add(
            "harness",
            "harness.layer2",
            "PASS",
            reason="ok",
            detail=f"terminal_channel_eligible=true ({len(snap.layer2_harnesses)} harnesses)",
        )
    elif snap.layer2_harnesses:
        b.add(
            "harness",
            "harness.layer2",
            "WARN",
            reason="layer2_unverified",
            detail=f"terminal_channel_eligible=false ({len(snap.layer2_harnesses)} harnesses)",
            remediation=(
                "Verify Layer-2 config or re-bootstrap checkout before relying on "
                "terminal low-risk confirmation."
            ),
        )
    else:
        b.add(
            "harness",
            "harness.layer2",
            "PASS",
            reason="none_registered",
            detail="terminal_channel_eligible=false (no non-CLI harnesses registered)",
        )

    if snap.pending_proposals:
        b.add(
            "harness",
            "harness.proposals",
            "WARN",
            reason="pending_proposals",
            detail=f"{len(snap.pending_proposals)} pending/incomplete proposal(s)",
            remediation="Inspect pending proposals via `brain review list --profile <profile.json>`.",
        )
    else:
        b.add("harness", "harness.proposals", "PASS", reason="ok", detail="0 pending proposals")

    if snap.bootstrap_drifts:
        b.add(
            "harness",
            "harness.bootstrap_drift",
            "WARN",
            reason="bootstrap_drift",
            detail=f"{len(snap.bootstrap_drifts)} drifted target file(s)",
            remediation=(
                "Inspect bootstrap drift in checkout and re-plan or rollback via "
                "`brain review` / `brain bootstrap`."
            ),
        )
    else:
        b.add("harness", "harness.bootstrap_drift", "PASS", reason="ok", detail="0 drifted targets")

    cap = snap.capture_probe_result
    if cap is None:
        b.add("capture", "capture.probe", "PASS", reason="sp2_not_wired", detail="SP2 capture probe not wired")
    else:
        cap_status = cap.status
        cap_reason = cap.reason
        if cap.timed_out:
            if cap_status == "PASS":
                cap_status = "WARN"
            if cap_reason in ("", "ok"):
                cap_reason = "timeout_exceeded"
        elif not cap.available:
            if cap_status == "PASS":
                cap_status = "WARN"
            if cap_reason in ("", "ok"):
                cap_reason = "probe_unavailable"
        elif cap.dead_letters > 0 or cap.capture_gaps > 0 or cap.outbox_backlog > 0:
            if cap_status == "PASS":
                cap_status = "WARN"
            if cap_reason in ("", "ok"):
                if cap.dead_letters > 0:
                    cap_reason = "dead_letters_present"
                elif cap.capture_gaps > 0:
                    cap_reason = "capture_gaps_present"
                else:
                    cap_reason = "outbox_backlog_present"
        b.add(
            "capture",
            "capture.probe",
            cap_status,
            reason=cap_reason,
            detail=cap.detail or f"available={cap.available}",
            remediation=cap.remediation,
        )

    jev = snap.jev_stats
    if jev is None:
        b.add("jev", "jev.passive", "PASS", reason="ok", detail="network-free passive Jev check")
    elif jev.price_drift_detected:
        b.add(
            "jev",
            "jev.passive",
            "WARN",
            reason="price_drift",
            detail=f"provider_invocations={jev.provider_invocations}, key_configured={jev.key_configured}",
        )
    else:
        b.add(
            "jev",
            "jev.passive",
            "PASS",
            reason="ok",
            detail=f"provider_invocations={jev.provider_invocations}, key_configured={jev.key_configured}",
        )

    b.add("index", "index.status", "PASS", reason="deferred_sp_scope", detail="semantic index probes deferred to SP3")
    b.add("lessons", "lessons.status", "PASS", reason="deferred_sp_scope", detail="lessons probes deferred to SP4")
    b.add("skill", "skill.status", "PASS", reason="deferred_sp_scope", detail="skill probes deferred to SP4")
