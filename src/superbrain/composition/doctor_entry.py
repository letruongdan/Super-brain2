"""Composition entrypoint for strictly read-only ``brain doctor`` (spec 13, 14.2, I3-5)."""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path

from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.daemon_config import read_client_profile, read_daemon_config
from superbrain.application.doctor import DoctorCheckItem, DoctorReport, format_doctor_text, inspect_doctor_snapshot
from superbrain.composition._operator_client import write_error_code
from superbrain.composition.doctor_probes_sp2 import Sp2DoctorReport, run_sp2_doctor_probes
from superbrain.core._kernel_approval import Layer2State
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.doctor import DoctorLayer2HarnessStatus
from superbrain.ports.os import OsAdapters
from superbrain.storage._doctor_reader import read_doctor_snapshot

__all__ = ["main", "run_doctor", "run_doctor_cli"]


@dataclass(frozen=True)
class _ParsedDoctorCli:
    source_path: Path
    is_profile: bool
    checkout_root: Path | None
    outbox_dir: Path | None
    as_json: bool


def _is_abs(raw: str) -> bool:
    return bool(raw) and "\x00" not in raw and Path(raw).is_absolute() and ".." not in Path(raw).parts


def _parse_args(args: list[str]) -> _ParsedDoctorCli | None:
    if not args or args[0] != "doctor":
        return None
    config_raw: str | None = None
    profile_raw: str | None = None
    checkout_raw: str | None = None
    outbox_raw: str | None = None
    as_json = False
    i = 1
    while i < len(args):
        tok = args[i]
        if tok == "--json":
            if as_json:
                return None
            as_json = True
            i += 1
        elif tok == "--config":
            if config_raw is not None or profile_raw is not None or i + 1 >= len(args) or not _is_abs(args[i + 1]):
                return None
            config_raw = args[i + 1]
            i += 2
        elif tok == "--profile":
            if profile_raw is not None or config_raw is not None or i + 1 >= len(args) or not _is_abs(args[i + 1]):
                return None
            profile_raw = args[i + 1]
            i += 2
        elif tok == "--checkout":
            if checkout_raw is not None or i + 1 >= len(args) or not _is_abs(args[i + 1]):
                return None
            checkout_raw = args[i + 1]
            i += 2
        elif tok == "--outbox":
            if outbox_raw is not None or i + 1 >= len(args) or not _is_abs(args[i + 1]):
                return None
            outbox_raw = args[i + 1]
            i += 2
        else:
            return None
    if config_raw is None and profile_raw is None:
        return None
    return _ParsedDoctorCli(
        source_path=Path(profile_raw if profile_raw is not None else str(config_raw)),
        is_profile=profile_raw is not None,
        checkout_root=Path(checkout_raw) if checkout_raw is not None else None,
        outbox_dir=Path(outbox_raw) if outbox_raw is not None else None,
        as_json=as_json,
    )


def _merge_sp2_report(base: DoctorReport, sp2: Sp2DoctorReport) -> DoctorReport:
    """Attach read-only SP2 diagnostics and effective Layer-2 status to ``DoctorReport``."""
    eff_by_id = {h.harness_id: h for h in sp2.layer2_harnesses}
    merged_harnesses: list[DoctorLayer2HarnessStatus] = []
    for item in base.layer2_harnesses:
        probe = eff_by_id.get(item.harness_id)
        eff_state = probe.effective_state if probe is not None else item.state
        merged_harnesses.append(replace(item, state=eff_state))

    checks = list(base.checks)
    remediations = list(base.remediations)
    integrity_errors = list(base.integrity_errors)

    def _add(name: str, status: str, detail: str, rem: str | None = None) -> None:
        checks.append(DoctorCheckItem(name=name, status=status, detail=detail, remediation=rem))
        if rem is not None and rem not in remediations:
            remediations.append(rem)

    for err in sp2.integrity_errors:
        if err not in integrity_errors:
            integrity_errors.append(err)
    if sp2.integrity_errors:
        _add("sp2_integrity", "error", "; ".join(sp2.integrity_errors), "Inspect SP2 storage integrity errors.")
    if sp2.gaps.open_daemon_gaps > 0 or sp2.gaps.producer_gaps > 0:
        _add(
            "sp2_capture_gaps",
            "warn",
            f"open_daemon_gaps={sp2.gaps.open_daemon_gaps} producer_gaps={sp2.gaps.producer_gaps}",
            "Inspect capture gaps and drain pending hook outbox streams.",
        )
    if any(
        h.recorded_state is Layer2State.VERIFIED and h.effective_state is not Layer2State.VERIFIED
        for h in sp2.layer2_harnesses
    ):
        _add(
            "sp2_layer2_drift",
            "warn",
            "Recorded Layer-2 verification invalidated by host/config drift or policy restore.",
            "Re-verify Layer-2 native receipts before using terminal approvals or verified_host capture.",
        )
    eff_term = base.terminal_channel_eligible and sp2.terminal_channel_eligible_effective
    if eff_term != base.terminal_channel_eligible or tuple(merged_harnesses) != base.layer2_harnesses:
        l2_status = "ok" if eff_term else ("warn" if merged_harnesses else "ok")
        l2_detail = (
            f"terminal_channel_eligible={'true' if eff_term else 'false'} ({len(merged_harnesses)} harnesses)"
            if merged_harnesses
            else "terminal_channel_eligible=false (no non-CLI harnesses registered)"
        )
        l2_rem = (
            None
            if eff_term or not merged_harnesses
            else "Verify Layer-2 config or re-bootstrap checkout before relying on terminal low-risk confirmation."
        )
        if l2_rem is not None and l2_rem not in remediations:
            remediations.append(l2_rem)
        checks = [
            DoctorCheckItem("layer2", l2_status, l2_detail, l2_rem) if c.name == "layer2" else c
            for c in checks
        ]
    statuses = {c.status for c in checks}
    overall = "fail" if "error" in statuses else "warn" if "warn" in statuses else "pass"
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


def run_doctor(
    config_or_profile_path: Path,
    *,
    checkout_root: Path | None = None,
    is_profile: bool = False,
    os_: OsAdapters | None = None,
    outbox_dir: Path | None = None,
    observed_host_versions: Mapping[str, str] | None = None,
    host_version_resolver: Callable[[str], str | None] | None = None,
) -> DoctorReport:
    """Inspect storage + checkout state strictly read-only and return a ``DoctorReport``."""
    adapters = os_ if os_ is not None else os_adapters()
    if is_profile:
        profile = read_client_profile(config_or_profile_path, adapters)
        data_root = profile.endpoint_path.parent
        expected_store_id = profile.expected_store_id
        resolved_checkout = checkout_root if checkout_root is not None else (
            profile.workspace.checkout_path if profile.workspace is not None else None
        )
    else:
        cfg = read_daemon_config(config_or_profile_path, adapters)
        data_root = cfg.data_root
        expected_store_id = cfg.expected_store_id
        resolved_checkout = checkout_root
    if resolved_checkout is not None:
        adapters.paths.reject_unsafe_path(str(resolved_checkout))
        if not resolved_checkout.is_absolute():
            raise BrainError(ErrorCode.INVALID_INPUT, "checkout must be absolute")
        if os.path.lexists(resolved_checkout):
            adapters.paths.reject_links(resolved_checkout)
    snapshot = read_doctor_snapshot(
        data_root,
        adapters,
        checkout_root=resolved_checkout,
        expected_store_id=expected_store_id,
    )
    report = inspect_doctor_snapshot(snapshot)
    sp2_report = run_sp2_doctor_probes(
        data_root,
        outbox_dir=outbox_dir,
        checkout_root=resolved_checkout,
        observed_host_versions=observed_host_versions,
        host_version_resolver=host_version_resolver,
        os_=adapters,
    )
    return _merge_sp2_report(report, sp2_report)


def run_doctor_cli(args: list[str], *, os_: OsAdapters | None = None) -> int:
    parsed = _parse_args(args)
    if parsed is None:
        write_error_code(ErrorCode.INVALID_INPUT)
        return 2
    try:
        report = run_doctor(
            parsed.source_path,
            checkout_root=parsed.checkout_root,
            is_profile=parsed.is_profile,
            os_=os_,
            outbox_dir=parsed.outbox_dir,
        )
    except BrainError as err:
        write_error_code(err.code)
        return 1
    if parsed.as_json:
        sys.stdout.write(json.dumps({"ok": True, "data": report.to_dict()}, sort_keys=True) + "\n")
    else:
        sys.stdout.write(format_doctor_text(report))
    sys.stdout.flush()
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    return run_doctor_cli(raw)


if __name__ == "__main__":
    raise SystemExit(main())
