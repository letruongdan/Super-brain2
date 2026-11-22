"""SP2 capture provenance validation and bootstrap evidence evaluation helpers."""

from __future__ import annotations

import contextlib
import json
import os
import sqlite3
from collections.abc import Mapping
from pathlib import Path
from typing import Literal

from superbrain.core._kernel_approval import Layer2State
from superbrain.core.jsonvalue import JsonValue
from superbrain.ports.doctor import (
    CaptureDoctorProbeResult,
    CaptureDoctorSnapshot,
    DoctorLayer2HarnessStatus,
    PrivacyScannerPort,
)
from superbrain.storage.cas import blob_path
from superbrain.storage.sqlite import open_readonly


def resolve_checkout_scope(policy_db: Path, checkout_root: Path | None) -> dict[str, JsonValue] | None:
    """Resolve authoritative ``(repo_id, checkout_id)`` registered for ``checkout_root``."""
    if checkout_root is None or not os.path.lexists(policy_db):
        return None
    norm_co = os.path.normcase(str(checkout_root.resolve()))
    with contextlib.suppress(sqlite3.Error, OSError):
        with contextlib.closing(open_readonly(policy_db)) as db:
            rows = db.execute("SELECT repo_id, checkout_id, checkout_path FROM workspace_checkout").fetchall()
            for r_id, c_id, c_path in rows:
                if os.path.normcase(str(Path(str(c_path)).resolve())) == norm_co:
                    return {"repo_id": str(r_id), "checkout_id": str(c_id)}
    return None


def count_applied_bootstrap_evidence(store_db: Path, cas_dir: Path, checkout_root: Path | None) -> int:
    """Count applied proposal targets belonging to ``checkout_root`` in ``store_db``."""
    if checkout_root is None:
        return 1
    if not os.path.lexists(store_db):
        return 0
    norm_co = os.path.normcase(str(checkout_root.resolve()))
    count = 0
    try:
        with contextlib.closing(open_readonly(store_db)) as db:
            rows = db.execute("SELECT payload_digest FROM p_proposals_proposals WHERE status = 'applied'").fetchall()
            for (p_dig,) in rows:
                if not p_dig:
                    continue
                blob = blob_path(cas_dir, str(p_dig))
                if not os.path.exists(blob):
                    continue
                try:
                    payload = json.loads(blob.read_bytes())
                    for t in payload.get("targets", ()):
                        t_root = t.get("target_root")
                        if t_root and os.path.normcase(str(Path(str(t_root)).resolve())) == norm_co:
                            count += 1
                except (OSError, json.JSONDecodeError, TypeError, KeyError):
                    continue
    except (sqlite3.Error, OSError):
        return 0
    return count


def classify_capture_provenance(
    capture_snapshot: CaptureDoctorSnapshot | None,
    cap_res: CaptureDoctorProbeResult | None,
    *,
    layer2_harnesses: tuple[DoctorLayer2HarnessStatus, ...] = (),
    expected_scope: Mapping[str, JsonValue] | None = None,
) -> tuple[str, bool]:
    """Classify capture receipt provenance and verify native receipts bind to host, config, and scope."""
    if cap_res is not None and (cap_res.timed_out or not cap_res.available):
        return "unavailable", False
    if capture_snapshot is None:
        return "unknown", False
    if not capture_snapshot.available:
        return "unavailable", False
    if not capture_snapshot.harnesses:
        return "unknown", False
    kinds = {h.receipt_kind for h in capture_snapshot.harnesses}
    healthy = all(not h.host_invalidated and not h.probe_error for h in capture_snapshot.harnesses)
    if kinds != {"native"}:
        if kinds == {"fixture"}:
            return "fixture", False
        if "native" in kinds or "fixture" in kinds:
            return "mixed", False
        return "unknown", False

    if not healthy:
        return "native", False

    l2_by_harness = {entry.harness_id: entry for entry in layer2_harnesses}
    for h in capture_snapshot.harnesses:
        if not hasattr(h, "receipt"):
            continue
        receipt = getattr(h, "receipt", None)
        if receipt is None or not isinstance(receipt, Mapping):
            return "native", False
        host = receipt.get("host")
        if host is not None and host != h.harness_id:
            return "native", False
        l2 = l2_by_harness.get(h.harness_id)
        if l2 is not None:
            if l2.host_version is not None and receipt.get("host_version") != l2.host_version:
                return "native", False
            if l2.config_digest is not None and receipt.get("config_digest") != l2.config_digest:
                return "native", False
        run_scope = receipt.get("run_scope")
        if not isinstance(run_scope, Mapping):
            return "native", False
        if expected_scope is not None:
            if run_scope.get("repo_id") != expected_scope.get("repo_id"):
                return "native", False
            if run_scope.get("checkout_id") != expected_scope.get("checkout_id"):
                return "native", False

    return "native", True


STATUS_RANK: dict[str, int] = {"PASS": 0, "WARN": 1, "FAIL": 2}
DEGRADED_LAYER2: set[str] = {Layer2State.UNKNOWN.value, Layer2State.UNSUPPORTED.value}
StatusLit = Literal["PASS", "WARN", "FAIL"]
SurfaceState = tuple[StatusLit, str, str, str | None]


def norm_status(raw: str) -> StatusLit:
    return "FAIL" if raw == "FAIL" else ("WARN" if raw == "WARN" else "PASS")


def sanitize_text(text: str | None, scanner: PrivacyScannerPort, *, fallback: str = "[REDACTED]") -> str:
    if not text:
        return ""
    return fallback if scanner.scan_bytes(text.encode("utf-8")) else text


def surface_entry(
    surface: str,
    status: StatusLit,
    reason: str,
    detail: str,
    scanner: PrivacyScannerPort,
    *,
    remediation: str | None = None,
) -> dict[str, JsonValue]:
    out: dict[str, JsonValue] = {
        "surface": surface,
        "status": status,
        "reason": sanitize_text(reason, scanner, fallback="redacted") or "unknown",
        "detail": sanitize_text(detail, scanner, fallback="detail redacted by privacy filter") or surface,
    }
    if remediation:
        out["remediation"] = sanitize_text(remediation, scanner, fallback="remediation redacted")
    return out


def pick_worse(
    cur: SurfaceState, status: str, reason: str, detail: str, remediation: str | None = None
) -> SurfaceState:
    cand_st = norm_status(status)
    if STATUS_RANK[cand_st] > STATUS_RANK[cur[0]] or (cur[0] == "PASS" and cand_st != "PASS"):
        return (cand_st, reason, detail, remediation)
    return cur


def serialize_harnesses(
    capture_snapshot: CaptureDoctorSnapshot | None,
    scanner: PrivacyScannerPort,
) -> list[JsonValue]:
    if capture_snapshot is None:
        return []
    return [
        {
            "harness_id": sanitize_text(h.harness_id, scanner),
            "last_event_at": sanitize_text(h.last_event_at, scanner) if h.last_event_at else None,
            "active_layer": sanitize_text(h.active_layer, scanner) if h.active_layer else None,
            "outbox_backlog": max(0, int(h.outbox_backlog)),
            "capture_gaps": max(0, int(h.capture_gaps)),
            "dead_letters": max(0, int(h.dead_letters)),
            "receipt_kind": sanitize_text(h.receipt_kind, scanner) if h.receipt_kind else None,
            "host_invalidated": bool(h.host_invalidated),
            "probe_error": sanitize_text(h.probe_error, scanner) if h.probe_error else None,
        }
        for h in capture_snapshot.harnesses
    ]
