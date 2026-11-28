"""Fold SP2 read-only diagnostics into a ``DoctorReport``: one merge for the offline and the daemon doctor."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from superbrain.application.doctor import DoctorReport
    from superbrain.composition.doctor_probes_sp2_store import Sp2DoctorReport

__all__ = ["merge_sp2_report"]


def merge_sp2_report(base: DoctorReport, sp2: Sp2DoctorReport) -> DoctorReport:
    """Attach read-only SP2 diagnostics and effective Layer-2 status to ``DoctorReport`` (PASS/WARN/FAIL checks)."""
    from superbrain.application.doctor import DoctorCheckItem
    from superbrain.core._kernel_approval import Layer2State
    from superbrain.ports.doctor import DoctorLayer2HarnessStatus

    eff_by_id = {h.harness_id: h for h in sp2.layer2_harnesses}
    merged_harnesses: list[DoctorLayer2HarnessStatus] = []
    for item in base.layer2_harnesses:
        probe = eff_by_id.get(item.harness_id)
        eff_state = probe.effective_state if probe is not None else item.state
        merged_harnesses.append(replace(item, state=eff_state))

    checks = list(base.checks)
    remediations = list(base.remediations)
    integrity_errors = list(base.integrity_errors)

    def _add(name: str, status: str, reason: str, detail: str, rem: str) -> None:
        checks.append(DoctorCheckItem(name=name, status=status, detail=detail, remediation=rem, group="sp2",
                                      reason=reason))
        if rem not in remediations:
            remediations.append(rem)

    for err in sp2.integrity_errors:
        if err not in integrity_errors:
            integrity_errors.append(err)
    if sp2.integrity_errors:
        _add("sp2.integrity", "FAIL", "sp2_integrity_error", "; ".join(sp2.integrity_errors),
             "Inspect SP2 storage integrity errors.")
    if sp2.gaps.open_daemon_gaps > 0 or sp2.gaps.producer_gaps > 0:
        _add("sp2.capture_gaps", "WARN", "capture_gaps_present",
             f"open_daemon_gaps={sp2.gaps.open_daemon_gaps} producer_gaps={sp2.gaps.producer_gaps}",
             "Inspect capture gaps and drain pending hook outbox streams.")
    if any(
        h.recorded_state is Layer2State.VERIFIED and h.effective_state is not Layer2State.VERIFIED
        for h in sp2.layer2_harnesses
    ):
        _add("sp2.layer2_drift", "WARN", "layer2_drift",
             "Recorded Layer-2 verification invalidated by host/config drift or policy restore.",
             "Re-verify Layer-2 native receipts before using terminal approvals or verified_host capture.")
    eff_term = base.terminal_channel_eligible and sp2.terminal_channel_eligible_effective
    if not eff_term and merged_harnesses:
        l2_rem = "Verify Layer-2 config or re-bootstrap checkout before relying on terminal low-risk confirmation."
        if l2_rem not in remediations:
            remediations.append(l2_rem)
        l2_item = DoctorCheckItem(
            name="harness.layer2", group="harness", status="WARN", reason="layer2_unverified", remediation=l2_rem,
            detail=f"terminal_channel_eligible=false ({len(merged_harnesses)} harnesses)",
        )
        checks = [l2_item if c.name == "harness.layer2" else c for c in checks]
    statuses = {c.status for c in checks}
    overall = "fail" if "FAIL" in statuses else "warn" if "WARN" in statuses else "pass"
    return replace(
        base,
        overall_status=overall,
        terminal_channel_eligible=eff_term,
        layer2_harnesses=tuple(merged_harnesses),
        checks=tuple(checks),
        remediations=tuple(remediations),
        integrity_errors=tuple(integrity_errors),
        sp2=sp2.to_dict(),
    )
