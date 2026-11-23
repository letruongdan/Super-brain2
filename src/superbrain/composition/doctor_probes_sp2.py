"""SP2 capture probe adapter, M1 handover readiness evaluator, and port contract re-exports."""

from __future__ import annotations

import math
import threading
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import cast

from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.daemon_config import read_client_profile, read_daemon_config
from superbrain.adapters.os.workspaces import verify_launch_checkout
from superbrain.application.doctor import DoctorReport, KernelPrivacyScanner, inspect_doctor_snapshot
from superbrain.composition._doctor_sp2_eval import (
    DEGRADED_LAYER2,
    STATUS_RANK,
    StatusLit,
    SurfaceState,
    classify_capture_provenance,
    count_applied_bootstrap_evidence,
    norm_status,
    pick_worse,
    resolve_checkout_scope,
    sanitize_text,
    serialize_harnesses,
    surface_entry,
)
from superbrain.core._kernel_approval import CLI_HARNESS_ID, Layer2State
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.ports.doctor import (
    CaptureDoctorProbePort,
    CaptureDoctorProbeResult,
    CaptureDoctorSnapshot,
    CaptureHarnessDoctorStatus,
    DoctorLayer2HarnessStatus,
    DoctorSnapshot,
    OutboxReplayPort,
    OutboxReplayResult,
    PrivacyScannerPort,
    SupervisorControlPort,
    SupervisorRestartResult,
)
from superbrain.ports.os import OsAdapters
from superbrain.storage._doctor_reader import read_doctor_snapshot
from superbrain.storage.layout import DataRoot

M1_SURFACE_DEEP_HEALTH = "get_health(deep=true)"
M1_SURFACE_PERMISSIONS = "permissions.data_root"
M1_SURFACE_CAPTURE = "capture.sp2_probes"
M1_SURFACE_LAYER2 = "harness.layer2"
M1_SURFACE_BOOTSTRAP_DRIFT = "harness.bootstrap_drift"

M1_CHECK_SURFACES: tuple[str, ...] = (
    M1_SURFACE_DEEP_HEALTH,
    M1_SURFACE_PERMISSIONS,
    M1_SURFACE_CAPTURE,
    M1_SURFACE_LAYER2,
    M1_SURFACE_BOOTSTRAP_DRIFT,
)

__all__ = [
    "CaptureDoctorProbePort",
    "CaptureDoctorProbeResult",
    "CaptureDoctorSnapshot",
    "CaptureHarnessDoctorStatus",
    "KernelPrivacyScanner",
    "M1_CHECK_SURFACES",
    "M1_SURFACE_BOOTSTRAP_DRIFT",
    "M1_SURFACE_CAPTURE",
    "M1_SURFACE_DEEP_HEALTH",
    "M1_SURFACE_LAYER2",
    "M1_SURFACE_PERMISSIONS",
    "OutboxReplayPort",
    "OutboxReplayResult",
    "PrivacyScannerPort",
    "Sp2CaptureProbeAdapter",
    "SupervisorControlPort",
    "SupervisorRestartResult",
    "build_sp2_capture_probe",
    "evaluate_m1_surfaces",
    "run_m1_handover_probe",
]

_STATUS_RANK = STATUS_RANK
_DEGRADED_LAYER2 = DEGRADED_LAYER2
_StatusLit = StatusLit
_SurfaceState = SurfaceState
_norm_status = norm_status
_sanitize = sanitize_text
_surface_entry = surface_entry
_pick_worse = pick_worse
_serialize_harnesses = serialize_harnesses


def _classify_provenance(
    capture_snapshot: CaptureDoctorSnapshot | None,
    cap_res: CaptureDoctorProbeResult | None,
    *,
    layer2_harnesses: tuple[DoctorLayer2HarnessStatus, ...] = (),
    expected_scope: Mapping[str, JsonValue] | None = None,
) -> tuple[str, bool]:
    return classify_capture_provenance(
        capture_snapshot, cap_res, layer2_harnesses=layer2_harnesses, expected_scope=expected_scope
    )


class Sp2CaptureProbeAdapter(CaptureDoctorProbePort):
    """Wrap an SP2 ``CaptureDoctorSnapshot`` callback into ``CaptureDoctorProbePort``."""

    def __init__(
        self,
        snapshot_fn: Callable[[Path], CaptureDoctorSnapshot],
        *,
        require_native_receipts: bool = False,
        privacy_scanner: PrivacyScannerPort | None = None,
    ) -> None:
        if not callable(snapshot_fn) or not isinstance(require_native_receipts, bool):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        self._snapshot_fn = snapshot_fn
        self._require_native_receipts = require_native_receipts
        self._scanner: PrivacyScannerPort = privacy_scanner if privacy_scanner is not None else KernelPrivacyScanner()
        self._lock = threading.Lock()
        self._last_snapshot: tuple[Path, CaptureDoctorSnapshot] | None = None

    def probe_snapshot(self, data_root: Path) -> CaptureDoctorSnapshot:
        """Read and validate the raw ``CaptureDoctorSnapshot`` for ``data_root``."""
        if not isinstance(data_root, Path):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        snap = self._snapshot_fn(data_root)
        if not isinstance(snap, CaptureDoctorSnapshot):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "capture probe returned invalid snapshot")
        return snap

    def _consume_last_snapshot(self, data_root: Path) -> CaptureDoctorSnapshot | None:
        with self._lock:
            cached = self._last_snapshot
            self._last_snapshot = None
        return cached[1] if cached is not None and cached[0] == data_root else None

    def _probe_result_for_snapshot(self, snap: CaptureDoctorSnapshot) -> CaptureDoctorProbeResult:
        harnesses = snap.harnesses
        total_backlog = sum(max(0, h.outbox_backlog) for h in harnesses)
        total_gaps = sum(max(0, h.capture_gaps) for h in harnesses)
        total_dead = sum(max(0, h.dead_letters) for h in harnesses)
        last_event_at = max((h.last_event_at for h in harnesses if h.last_event_at), default=None)
        layers = {h.active_layer for h in harnesses if h.active_layer}
        active_layer = next(iter(layers)) if len(layers) == 1 else ("mixed" if layers else None)

        def _make(
            reason: str,
            detail: str,
            remediation: str,
            *,
            available: bool = True,
            status: _StatusLit = "WARN",
            with_counts: bool = True,
        ) -> CaptureDoctorProbeResult:
            return CaptureDoctorProbeResult(
                available=available, status=status, reason=reason, detail=detail, remediation=remediation,
                outbox_backlog=total_backlog if with_counts else 0,
                capture_gaps=total_gaps if with_counts else 0,
                dead_letters=total_dead if with_counts else 0,
                last_event_at=last_event_at, active_layer=active_layer,
            )

        if not snap.available:
            reason = _sanitize(snap.unavailable_reason, self._scanner) or "probe_unavailable"
            return _make(
                reason, "SP2 capture probe reported unavailable.",
                "Start or repair capture service and re-run brain doctor.", available=False,
            )
        if not harnesses:
            return _make(
                "no_harnesses_reported", "SP2 capture probe reported zero harnesses.",
                "Verify at least one native capture harness before M1 handover.", with_counts=False,
            )
        err_ids = [h.harness_id for h in harnesses if h.probe_error]
        if err_ids:
            ids = _sanitize(",".join(sorted(err_ids)), self._scanner)
            return _make(
                "harness_probe_error", f"Capture probe error reported for: {ids}.",
                "Inspect harness capture spool and run brain doctor --fix.", status="FAIL",
            )
        inv_ids = [h.harness_id for h in harnesses if h.host_invalidated]
        if inv_ids:
            ids = _sanitize(",".join(sorted(inv_ids)), self._scanner)
            return _make(
                "host_invalidated", f"Host invalidated capture integration for: {ids}.",
                "Re-verify host bootstrap and capture hooks.",
            )

        # Kind only (native vs fixture): binding receipts to platform, host, config and checkout needs the run's
        # scope and Layer-2 state, which only ``evaluate_m1_surfaces`` has.
        provenance, _bound = _classify_provenance(snap, None)
        nat_ok = provenance == "native"
        counts = (
            f"harnesses={len(harnesses)}, receipt_provenance={provenance}, "
            f"outbox_backlog={total_backlog}, capture_gaps={total_gaps}, dead_letters={total_dead}"
        )
        for cnt, reason, rem in (
            (total_dead, "dead_letters_present", "Inspect dead-lettered capture items and replay outbox."),
            (total_gaps, "capture_gaps_present", "Drain pending capture sequence gaps via `brain doctor --fix`."),
            (total_backlog, "outbox_backlog_present", "Replay pending outbox events via `brain doctor --fix`."),
        ):
            if cnt > 0:
                return _make(reason, counts, rem)

        if self._require_native_receipts and not nat_ok:
            reason = (
                "fixture_receipt_not_native" if provenance in ("fixture", "mixed") else "receipt_provenance_unverified"
            )
            return _make(
                reason, f"receipt_provenance={provenance}; native capture receipts required.",
                "Replace fixture receipts with verified native capture receipts.", with_counts=False,
            )
        return CaptureDoctorProbeResult(
            available=True, status="PASS", reason="ok",
            detail=f"harnesses={len(harnesses)}, receipt_provenance={provenance}",
            last_event_at=last_event_at, active_layer=active_layer,
        )

    def probe_capture(self, data_root: Path) -> CaptureDoctorProbeResult:
        """Execute bounded aggregation and provenance validation for ``CaptureDoctorProbePort``."""
        if not isinstance(data_root, Path):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        try:
            snap = self.probe_snapshot(data_root)
        except TimeoutError:
            with self._lock:
                self._last_snapshot = None
            return CaptureDoctorProbeResult(
                available=False,
                timed_out=True,
                status="WARN",
                reason="timeout_exceeded",
                detail="SP2 capture probe timed out.",
                remediation="Inspect capture daemon responsiveness and outbox spool.",
            )
        except Exception:  # noqa: BLE001 - fail closed without leaking provider trace text
            with self._lock:
                self._last_snapshot = None
            return CaptureDoctorProbeResult(
                available=False,
                status="WARN",
                reason="probe_error",
                detail="SP2 capture probe failed cleanly.",
                remediation="Inspect capture service logs and repair outbox state.",
            )
        with self._lock:
            self._last_snapshot = (data_root, snap)
        return self._probe_result_for_snapshot(snap)


def build_sp2_capture_probe(
    snapshot_fn: Callable[[Path], CaptureDoctorSnapshot],
    *,
    require_native_receipts: bool = False,
) -> Sp2CaptureProbeAdapter:
    """Build an ``Sp2CaptureProbeAdapter`` from an SP2 snapshot provider callable."""
    return Sp2CaptureProbeAdapter(snapshot_fn, require_native_receipts=require_native_receipts)


def _eval_deep_health(
    deep_health: Mapping[str, JsonValue] | None,
    snapshot: DoctorSnapshot,
    scanner: PrivacyScannerPort,
) -> dict[str, JsonValue]:
    surf = M1_SURFACE_DEEP_HEALTH
    if deep_health is None:
        return _surface_entry(surf, "WARN", "deep_health_missing", "get_health(deep=true) response missing", scanner)
    if deep_health.get("ready") is not True:
        return _surface_entry(surf, "WARN", "deep_health_not_ready", "get_health(deep=true) ready is false", scanner)
    run_id = deep_health.get("doctor_run_id")
    if not isinstance(run_id, str) or not run_id or deep_health.get("job_id") is not None:
        return _surface_entry(surf, "WARN", "doctor_run_pending", "get_health(deep=true) run incomplete", scanner)
    # Bind the response to the inspected store and writer generation; missing identity on either side never binds.
    store_id = deep_health.get("store_id")
    if not isinstance(store_id, str) or not store_id or not snapshot.store_id:
        return _surface_entry(surf, "WARN", "deep_health_unbound", "deep health store identity unverified", scanner)
    if store_id != snapshot.store_id:
        return _surface_entry(surf, "FAIL", "store_id_mismatch", "get_health(deep=true) store_id mismatch", scanner)
    epoch = deep_health.get("writer_epoch")
    live_epoch = snapshot.daemon_stats.writer_epoch if snapshot.daemon_stats is not None else None
    if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch <= 0 or live_epoch is None:
        return _surface_entry(surf, "WARN", "deep_health_unbound", "deep health writer epoch unverified", scanner)
    if epoch != live_epoch:
        detail = "get_health(deep=true) writer_epoch differs from writer.lock"
        return _surface_entry(surf, "WARN", "writer_epoch_mismatch", detail, scanner)
    age_s = deep_health.get("age_s")
    bad_age = isinstance(age_s, bool) or not isinstance(age_s, (int, float)) or not math.isfinite(float(age_s))
    if bad_age or float(cast(float, age_s)) < 0.0 or float(cast(float, age_s)) > 900.0:
        return _surface_entry(surf, "WARN", "deep_health_stale", "deep health snapshot stale or invalid", scanner)
    degraded = deep_health.get("degraded_codes")
    if not isinstance(degraded, (list, tuple)) or len(degraded) > 0:
        return _surface_entry(surf, "WARN", "degraded_codes_present", "deep health reports degraded_codes", scanner)
    overall = deep_health.get("overall_status")
    if isinstance(overall, str) and overall.lower() != "pass":
        st: _StatusLit = "FAIL" if overall.lower() == "fail" else "WARN"
        detail = f"get_health(deep=true) overall_status={overall.lower()}"
        return _surface_entry(surf, st, "deep_health_degraded", detail, scanner)
    return _surface_entry(surf, "PASS", "ok", "get_health(deep=true) ready and fresh", scanner)


def _eval_permissions(
    report: DoctorReport,
    snapshot: DoctorSnapshot,
    scanner: PrivacyScannerPort,
) -> dict[str, JsonValue]:
    state: _SurfaceState = ("PASS", "ok", "owner-only data root verified", None)
    for chk in report.checks:
        if chk.group == "permissions":
            state = _pick_worse(state, chk.status, chk.reason, chk.detail, chk.remediation)
    if snapshot.permission_problems or snapshot.ancestor_permission_problems or snapshot.backup_permission_problems:
        state = _pick_worse(state, "FAIL", "insecure_permissions", "unsafe permissions on data_root tree or ancestors")
    return _surface_entry(M1_SURFACE_PERMISSIONS, state[0], state[1], state[2], scanner, remediation=state[3])


def _eval_capture(
    report: DoctorReport,
    snapshot: DoctorSnapshot,
    capture_snapshot: CaptureDoctorSnapshot | None,
    *,
    provenance: str,
    native_verified: bool,
    require_native_receipts: bool,
    scanner: PrivacyScannerPort,
) -> dict[str, JsonValue]:
    state: _SurfaceState = ("PASS", "ok", f"capture verified ({provenance})", None)
    cap = snapshot.capture_probe_result
    if cap is None:
        state = _pick_worse(state, "WARN", "capture_probe_unattached", "SP2 capture probe was not attached")
    elif cap.timed_out:
        state = _pick_worse(state, "WARN", "timeout_exceeded", cap.detail or "capture timed out", cap.remediation)
    elif not cap.available:
        st = "FAIL" if cap.status == "FAIL" else "WARN"
        detail = cap.detail or "capture probe unavailable"
        state = _pick_worse(state, st, cap.reason or "probe_unavailable", detail, cap.remediation)
    elif cap.dead_letters > 0 or cap.capture_gaps > 0 or cap.outbox_backlog > 0:
        st = "FAIL" if cap.status == "FAIL" else "WARN"
        detail = cap.detail or "capture backlog/gaps/dead letters present"
        state = _pick_worse(state, st, cap.reason or "capture_degraded", detail, cap.remediation)
    elif cap.status != "PASS":
        state = _pick_worse(state, cap.status, cap.reason, cap.detail or "capture probe degraded", cap.remediation)

    for chk in report.checks:
        if chk.group == "capture" and chk.status != "PASS":
            state = _pick_worse(state, chk.status, chk.reason, chk.detail, chk.remediation)

    if capture_snapshot is not None:
        if not capture_snapshot.available:
            reason = capture_snapshot.unavailable_reason or "probe_unavailable"
            state = _pick_worse(state, "WARN", reason, "SP2 capture snapshot unavailable")
        elif not capture_snapshot.harnesses:
            state = _pick_worse(state, "WARN", "no_harnesses_reported", "zero capture harnesses reported")
        else:
            if any(h.probe_error for h in capture_snapshot.harnesses):
                state = _pick_worse(state, "FAIL", "harness_probe_error", "capture harness probe_error set")
            if any(h.host_invalidated for h in capture_snapshot.harnesses):
                state = _pick_worse(state, "WARN", "host_invalidated", "capture harness host_invalidated set")
            if sum(max(0, h.dead_letters) for h in capture_snapshot.harnesses) > 0:
                state = _pick_worse(state, "WARN", "dead_letters_present", "capture dead letters non-zero")
            if sum(max(0, h.capture_gaps) for h in capture_snapshot.harnesses) > 0:
                state = _pick_worse(state, "WARN", "capture_gaps_present", "capture gaps non-zero")
            if sum(max(0, h.outbox_backlog) for h in capture_snapshot.harnesses) > 0:
                state = _pick_worse(state, "WARN", "outbox_backlog_present", "capture backlog non-zero")

    if require_native_receipts and not native_verified:
        reason = "fixture_receipt_not_native" if provenance in ("fixture", "mixed") else "receipt_provenance_unverified"
        detail = f"native capture receipts required (observed provenance={provenance})"
        state = _pick_worse(state, "WARN", reason, detail)

    return _surface_entry(M1_SURFACE_CAPTURE, state[0], state[1], state[2], scanner, remediation=state[3])


def _eval_layer2(report: DoctorReport, snapshot: DoctorSnapshot, scanner: PrivacyScannerPort) -> dict[str, JsonValue]:
    state: _SurfaceState = ("PASS", "ok", f"{len(snapshot.layer2_harnesses)} verified Layer-2 harness(es)", None)
    for chk in report.checks:
        if chk.group == "harness" and chk.name not in ("harness.proposals", "harness.bootstrap_drift"):
            if chk.status != "PASS":
                state = _pick_worse(state, chk.status, chk.reason, chk.detail, chk.remediation)
        elif chk.name == "identity.credentials" and chk.status != "PASS":
            state = _pick_worse(state, chk.status, chk.reason, chk.detail, chk.remediation)

    ident = snapshot.identity_stats
    if ident is not None:
        if ident.error is not None:
            state = _pick_worse(state, "WARN", "identity_probe_unavailable", ident.error)
        if ident.missing_harness_credentials:
            miss = ", ".join(ident.missing_harness_credentials)
            state = _pick_worse(state, "WARN", "missing_harness_credentials", f"missing credentials: {miss}")
        verified_ids = {h.harness_id for h in snapshot.layer2_harnesses if h.state == Layer2State.VERIFIED}
        missing_l2 = sorted({h for h in ident.active_harness_ids if h != CLI_HARNESS_ID} - verified_ids)
        if missing_l2:
            miss_l2 = ", ".join(missing_l2)
            state = _pick_worse(state, "WARN", "missing_layer2_state", f"missing Layer-2 state: {miss_l2}")

    if not snapshot.layer2_harnesses:
        state = _pick_worse(state, "WARN", "no_layer2_harnesses", "no Layer-2 harness state registered")
    for h in snapshot.layer2_harnesses:
        val = h.state.value if hasattr(h.state, "value") else str(h.state)
        if val == Layer2State.UNSUPPORTED.value:
            state = _pick_worse(state, "FAIL", "layer2_unsupported", f"{h.harness_id} Layer-2 unsupported")
        elif val in _DEGRADED_LAYER2 or val != Layer2State.VERIFIED.value:
            state = _pick_worse(state, "WARN", "layer2_unverified", f"{h.harness_id} Layer-2 state={val}")

    return _surface_entry(M1_SURFACE_LAYER2, state[0], state[1], state[2], scanner, remediation=state[3])


def _eval_bootstrap_drift(
    report: DoctorReport,
    snapshot: DoctorSnapshot,
    scanner: PrivacyScannerPort,
    *,
    applied_count: int | None = None,
) -> dict[str, JsonValue]:
    state: _SurfaceState = ("PASS", "ok", "0 drifted targets, pending proposals, or incomplete journals", None)
    for chk in report.checks:
        if chk.name in ("harness.bootstrap_drift", "harness.proposals", "storage.incomplete_journals"):
            if chk.status != "PASS":
                state = _pick_worse(state, chk.status, chk.reason, chk.detail, chk.remediation)
    if snapshot.incomplete_journals:
        cnt = len(snapshot.incomplete_journals)
        state = _pick_worse(state, "WARN", "incomplete_apply_journals", f"{cnt} incomplete ApplyJournal(s)")
    if snapshot.bootstrap_drifts:
        cnt = len(snapshot.bootstrap_drifts)
        state = _pick_worse(state, "WARN", "bootstrap_drift_detected", f"{cnt} drifted target(s)")
    if snapshot.pending_proposals:
        cnt = len(snapshot.pending_proposals)
        state = _pick_worse(state, "WARN", "pending_proposals_present", f"{cnt} pending proposal(s)")
    if applied_count is None:
        state = _pick_worse(
            state,
            "WARN",
            "bootstrap_evidence_unverified",
            "no registered checkout to verify applied bootstrap against",
            "Pass the registered checkout (--checkout) to verify its applied bootstrap.",
        )
    elif applied_count == 0:
        state = _pick_worse(
            state,
            "WARN",
            "no_bootstrap_applied",
            "no applied bootstrap evidence found for checkout",
            "Run brain proposal bootstrap to apply baseline configurations.",
        )
    return _surface_entry(M1_SURFACE_BOOTSTRAP_DRIFT, state[0], state[1], state[2], scanner, remediation=state[3])


def evaluate_m1_surfaces(
    report: DoctorReport,
    snapshot: DoctorSnapshot,
    *,
    capture_snapshot: CaptureDoctorSnapshot | None = None,
    deep_health: Mapping[str, JsonValue] | None = None,
    require_native_receipts: bool = True,
    privacy_scanner: PrivacyScannerPort | None = None,
    applied_bootstrap_count: int | None = None,
    expected_scope: Mapping[str, JsonValue] | None = None,
) -> dict[str, JsonValue]:
    """Evaluate the five M1 handover verification surfaces against doctor and capture state."""
    if not isinstance(report, DoctorReport) or not isinstance(snapshot, DoctorSnapshot):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    scanner: PrivacyScannerPort = privacy_scanner if privacy_scanner is not None else KernelPrivacyScanner()
    provenance, native_verified = _classify_provenance(
        capture_snapshot,
        snapshot.capture_probe_result,
        layer2_harnesses=snapshot.layer2_harnesses,
        expected_scope=expected_scope,
    )

    surfaces: dict[str, dict[str, JsonValue]] = {
        M1_SURFACE_DEEP_HEALTH: _eval_deep_health(deep_health, snapshot, scanner),
        M1_SURFACE_PERMISSIONS: _eval_permissions(report, snapshot, scanner),
        M1_SURFACE_CAPTURE: _eval_capture(
            report,
            snapshot,
            capture_snapshot,
            provenance=provenance,
            native_verified=native_verified,
            require_native_receipts=require_native_receipts,
            scanner=scanner,
        ),
        M1_SURFACE_LAYER2: _eval_layer2(report, snapshot, scanner),
        M1_SURFACE_BOOTSTRAP_DRIFT: _eval_bootstrap_drift(
            report, snapshot, scanner, applied_count=applied_bootstrap_count
        ),
    }

    missing_surfaces: list[JsonValue] = [n for n in M1_CHECK_SURFACES if surfaces[n]["status"] != "PASS"]
    statuses = {surfaces[n]["status"] for n in M1_CHECK_SURFACES}
    if "FAIL" in statuses or report.overall_status == "fail":
        overall_status = "fail"
    elif missing_surfaces:
        overall_status = "warn"
    else:
        overall_status = "pass"

    m1_ready = (
        len(missing_surfaces) == 0
        and overall_status == "pass"
        and ((not require_native_receipts) or native_verified)
    )
    return {
        "m1_ready": m1_ready,
        "overall_status": overall_status,
        "surfaces": cast(dict[str, JsonValue], surfaces),
        "missing_surfaces": missing_surfaces,
        "native_verified": native_verified,
        "receipt_provenance": provenance,
        "harnesses": _serialize_harnesses(capture_snapshot, scanner),
        "store_id": _sanitize(snapshot.store_id, scanner) if snapshot.store_id else None,
        "require_native_receipts": require_native_receipts,
        "doctor_overall_status": report.overall_status,
    }


def run_m1_handover_probe(
    config_or_profile_path: Path,
    *,
    is_profile: bool = False,
    checkout_root: Path | None = None,
    os_: OsAdapters | None = None,
    capture_probe: Sp2CaptureProbeAdapter | CaptureDoctorProbePort | None = None,
    deep_health: Mapping[str, JsonValue] | None = None,
    require_native_receipts: bool = True,
    privacy_scanner: PrivacyScannerPort | None = None,
) -> dict[str, JsonValue]:
    """Read doctor snapshot for ``config_or_profile_path`` and evaluate M1 handover readiness."""
    if not isinstance(config_or_profile_path, Path):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    adapters = os_ if os_ is not None else os_adapters()
    scanner: PrivacyScannerPort = privacy_scanner if privacy_scanner is not None else KernelPrivacyScanner()

    if is_profile:
        prof = read_client_profile(config_or_profile_path, adapters)
        data_root = prof.endpoint_path.parent
        expected_store_id = prof.expected_store_id
        if checkout_root is not None and prof.workspace is not None:
            verify_launch_checkout(prof.workspace.checkout_path, checkout_root, adapters)
        resolved_checkout = (
            checkout_root if checkout_root is not None else (prof.workspace.checkout_path if prof.workspace else None)
        )
    else:
        cfg = read_daemon_config(config_or_profile_path, adapters)
        data_root = cfg.data_root
        expected_store_id = cfg.expected_store_id
        resolved_checkout = checkout_root

    snapshot = read_doctor_snapshot(
        data_root,
        adapters,
        checkout_root=resolved_checkout,
        expected_store_id=expected_store_id,
        privacy_scanner=scanner,
        capture_probe=capture_probe,
    )
    report = inspect_doctor_snapshot(snapshot, privacy_scanner=scanner)

    cap_snapshot: CaptureDoctorSnapshot | None = None
    cap_res = snapshot.capture_probe_result
    if isinstance(capture_probe, Sp2CaptureProbeAdapter):
        cap_snapshot = capture_probe._consume_last_snapshot(data_root)
        if cap_snapshot is None and cap_res is not None and cap_res.available and not cap_res.timed_out:
            try:
                cap_snapshot = capture_probe.probe_snapshot(data_root)
            except Exception:  # noqa: BLE001
                cap_snapshot = None
    elif capture_probe is not None and cap_res is not None and cap_res.available and not cap_res.timed_out:
        probe_fn = getattr(capture_probe, "probe_snapshot", None)
        if callable(probe_fn):
            try:
                cand = probe_fn(data_root)
                if isinstance(cand, CaptureDoctorSnapshot):
                    cap_snapshot = cand
            except Exception:  # noqa: BLE001
                cap_snapshot = None

    applied_count: int | None = None
    expected_scope: Mapping[str, JsonValue] | None = None
    if resolved_checkout is not None:
        root_data = DataRoot.at(data_root)
        expected_scope = resolve_checkout_scope(root_data.policy_db, resolved_checkout)
        if expected_scope is not None:
            applied_count = count_applied_bootstrap_evidence(root_data.store_db, root_data.cas_dir, resolved_checkout)

    return evaluate_m1_surfaces(
        report,
        snapshot,
        capture_snapshot=cap_snapshot,
        deep_health=deep_health,
        require_native_receipts=require_native_receipts,
        privacy_scanner=scanner,
        applied_bootstrap_count=applied_count,
        expected_scope=expected_scope,
    )
