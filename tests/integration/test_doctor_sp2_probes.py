"""Independent I4-5 oracle tests for ``composition.doctor_probes_sp2`` and SP2 M1 handover integration.

Requirement sources:
- Spec rev 22 §5.4, §7.1, §7.3, §7.4, §11.3, §13, §14.2, §20.1, §20.28
- ``schemas/mcp-tools-v2.json`` (``GetHealthResult``, ``ErrorEnvelope``)
- Frozen contract ``I4-5`` (``superbrain.composition.doctor_probes_sp2``, ``daemon_entry.serve`` /
  ``serve_config_path`` ``capture_probe`` wiring, non-PASS enforcement in ``application/_doctor_checks.py``,
  and M1 handover evaluation across all 5 surfaces)
"""

from __future__ import annotations

import base64
import contextlib
import importlib
import json
import os
import re
import sqlite3
import struct
import sys
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import jsonschema
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import superbrain.composition.doctor_entry as doctor_entry
from superbrain.adapters.harness_config.markdown_blocks import merge_markdown_block
from superbrain.adapters.harness_config.merger import SharedConfigMergerAdapter
from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.daemon_config import read_daemon_config
from superbrain.adapters.os.tls_material import verify_server_tls_files
from superbrain.application.doctor import (
    DoctorReport,
    KernelPrivacyScanner,
    format_doctor_dict_text,
    format_doctor_text,
    inspect_doctor_snapshot,
)
from superbrain.application.owner_loop import OwnerLoop
from superbrain.application.privacy import PrivacyFilter
from superbrain.application.review_apply import ReviewApplyService, TargetWriteInput
from superbrain.cli_api.loopback import LoopbackClient, LoopbackTarget
from superbrain.composition import daemon_entry
from superbrain.composition._daemon_session import DaemonTestHooks
from superbrain.composition.client_entry import build_tool_caller
from superbrain.composition.init_entry import InitReport, InitRequest, init_store
from superbrain.core._kernel_approval import (
    CLI_HARNESS_ID,
    RISK_POLICY_VERSION,
    ApprovalAction,
    ApprovalChannel,
    ApprovalMessage,
    Layer2State,
    RecoveryScope,
    RiskResource,
    SignerEnrollment,
)
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    TOTAL_REQUEST_BUDGET_NS,
    DaemonConfig,
    Endpoint,
    FilterPolicy,
    Ready,
    Scope,
    ToolCommand,
)
from superbrain.core.proposals import ManagedFormat
from superbrain.core.wire import load_catalog
from superbrain.ports.doctor import (
    PROBE_TIMEOUT_S,
    CaptureDoctorProbePort,
    CaptureDoctorProbeResult,
    CaptureDoctorSnapshot,
    CaptureHarnessDoctorStatus,
    DoctorBootstrapDrift,
    DoctorJournalInfo,
    DoctorProposalSummary,
    DoctorScanLimits,
    OutboxReplayPort,
    OutboxReplayResult,
    PrivacyScannerPort,
    SupervisorControlPort,
    SupervisorRestartResult,
)
from superbrain.ports.os import NoReplacePublisher, OsAdapters
from superbrain.ports.policy import IntentKind
from superbrain.storage._doctor_probes import run_capture_probe_bounded
from superbrain.storage._doctor_reader import read_doctor_snapshot
from superbrain.storage.cas import RetentionClass, blob_path
from superbrain.storage.layout import DataRoot
from superbrain.storage.proposals import PolicyApplyAuthority, StoreProposalAdapter
from superbrain.storage.runtime import Runtime
from tests.support.clock import FakeClock
from tests.support.inc2_cli import write_ca_file, write_client_profile_file, write_credential_file
from tests.support.inc2_fixture import reopen_kernel_job_runtime, validate_response_envelope
from tests.support.inc2_transport import FakeMonotonicClock, register_workspace_direct
from tests.support.kernel_auth import make_bootstrap_auth, seed_principal_and_credential

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPO_ROOT / "schemas" / "mcp-tools-v2.json"

OWNER_DAN = "dan"
OWNER_BOB = "bob"
MACHINE_ID = "i4-5-box"
BOUND_WAIT_S = 10.0

EXPECTED_M1_SURFACES: tuple[str, ...] = (
    "get_health(deep=true)",
    "permissions.data_root",
    "capture.sp2_probes",
    "harness.layer2",
    "harness.bootstrap_drift",
)


def _sp2_mod() -> Any:
    return importlib.import_module("superbrain.composition.doctor_probes_sp2")


def _base_utc_now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0) - timedelta(minutes=10)


def _ssh_signer_key(owner_id: str = OWNER_DAN) -> tuple[Ed25519PrivateKey, SignerEnrollment]:
    priv = Ed25519PrivateKey.generate()
    raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", len(raw)) + raw
    line = "ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + f" {owner_id}@i4-5"
    return priv, SignerEnrollment(owner_id=owner_id, channel=ApprovalChannel.SSH_KEY, public_key=line)


def _init_store_with_tls(
    base: Path,
    clock: FakeClock,
    *,
    owner_id: str = OWNER_DAN,
    os_: OsAdapters | None = None,
) -> tuple[InitReport, DaemonConfig, Ed25519PrivateKey, str, str, str, OsAdapters]:
    adapters = os_ if os_ is not None else os_adapters(clock=clock)
    cfg_dir, data_root = base / "cfg", base / "data"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    adapters.permissions.secure_directory(cfg_dir)
    priv, enrollment = _ssh_signer_key(owner_id)
    rep = init_store(
        InitRequest(
            data_root=data_root,
            config_dir=cfg_dir,
            owner_id=owner_id,
            machine_id=MACHINE_ID,
            signer=enrollment,
        ),
        adapters,
    )
    cfg = read_daemon_config(rep.daemon_config_path, adapters)
    verified_tls = verify_server_tls_files(cfg, adapters.clock, adapters)
    ca_pem = (cfg_dir / "tls" / "ca.pem").read_text(encoding="utf-8")
    cli_token = rep.cli_credential_path.read_text(encoding="utf-8").strip()
    return rep, cfg, priv, ca_pem, verified_tls.leaf_cert_sha256, cli_token, adapters


def _grant_wide_access(path: Path) -> None:
    if sys.platform == "win32":
        import ntsecuritycon

        from tests.support.winacl import grant

        grant(path, "S-1-1-0", ntsecuritycon.FILE_GENERIC_READ)
    else:
        os.chmod(path, 0o755 if path.is_dir() else 0o644)


def _validate_get_health_envelope(envelope: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    checked = validate_response_envelope("get_health", envelope)
    raw_schema = SCHEMA_PATH.read_bytes()
    catalog = load_catalog()
    assert raw_schema == catalog.raw_bytes
    schema_obj = json.loads(raw_schema.decode("utf-8"))
    if checked["ok"] is True:
        jsonschema.Draft202012Validator(
            {"$schema": schema_obj["$schema"], "$defs": schema_obj["$defs"], "$ref": "#/$defs/GetHealthResult"}
        ).validate(checked["data"])
    else:
        jsonschema.Draft202012Validator(
            {"$schema": schema_obj["$schema"], "$defs": schema_obj["$defs"], "$ref": "#/$defs/ErrorEnvelope"}
        ).validate(checked)
    return checked


def _call_operator_json(
    endpoint: Endpoint,
    *,
    store_id: str,
    ca_pem: str,
    leaf_sha256: str,
    token: str,
    path: str,
    body: Mapping[str, object],
    monotonic_ns: Callable[[], int],
) -> dict[str, Any]:
    target = LoopbackTarget(
        endpoint=endpoint,
        expected_store_id=store_id,
        ca_pem=ca_pem,
        leaf_cert_sha256=leaf_sha256,
    )
    res = LoopbackClient(monotonic_ns=monotonic_ns).call_operator(
        target,
        path,
        json.dumps(body).encode("utf-8"),
        token,
    )
    assert isinstance(res, dict)
    return cast(dict[str, Any], res)


_FIXTURE_HOST_VERSIONS = {"claude-code": "2.1.0", "codex": "0.55.0"}


@contextlib.contextmanager
def _running_serve_config(
    config_path: Path,
    *,
    os_: OsAdapters,
    clock: FakeClock,
    mono: Any,
    capture_probe: CaptureDoctorProbePort | None = None,
    outbox_replay: OutboxReplayPort | None = None,
    supervisor_control: SupervisorControlPort | None = None,
    hooks: DaemonTestHooks | None = None,
) -> Iterator[tuple[Ready, OwnerLoop]]:
    # SP2-5 live Layer-2 checks the installed host binaries; pin them to the versions these fixtures record
    if hooks is None or hooks.host_version_resolver is None:
        hooks = replace(hooks or DaemonTestHooks(), host_version_resolver=_FIXTURE_HOST_VERSIONS.get)
    ready_ev = threading.Event()
    stop_ev = threading.Event()
    box: dict[str, Any] = {}
    exits: list[int] = []

    def _on_ready(ready: Ready, loop: OwnerLoop) -> None:
        box["ready"] = ready
        box["loop"] = loop
        ready_ev.set()

    def _bg() -> None:
        exits.append(
            cast(Any, daemon_entry.serve_config_path)(
                config_path,
                os_=os_,
                clock=clock,
                monotonic_clock=mono,
                stop_event=stop_ev,
                shutdown_grace_s=2.0,
                on_ready=_on_ready,
                capture_probe=capture_probe,
                outbox_replay=outbox_replay,
                supervisor_control=supervisor_control,
                hooks=hooks,
            )
        )

    thr = threading.Thread(target=_bg, name="i4-5-serve-config", daemon=True)
    thr.start()
    try:
        assert ready_ev.wait(timeout=BOUND_WAIT_S), f"serve_config_path() did not become ready (exits={exits})"
        yield cast(Ready, box["ready"]), cast(OwnerLoop, box["loop"])
    finally:
        stop_ev.set()
        thr.join(timeout=BOUND_WAIT_S)
        assert not thr.is_alive(), "daemon serve_config_path thread leaked"


@contextlib.contextmanager
def _running_serve(
    cfg: DaemonConfig,
    *,
    os_: OsAdapters,
    clock: FakeClock,
    mono: Any,
    capture_probe: CaptureDoctorProbePort | None = None,
    outbox_replay: OutboxReplayPort | None = None,
    supervisor_control: SupervisorControlPort | None = None,
    config_path: Path | None = None,
) -> Iterator[tuple[Ready, OwnerLoop]]:
    ready_ev = threading.Event()
    stop_ev = threading.Event()
    box: dict[str, Any] = {}
    exits: list[int] = []

    def _on_ready(ready: Ready, loop: OwnerLoop) -> None:
        box["ready"] = ready
        box["loop"] = loop
        ready_ev.set()

    def _bg() -> None:
        exits.append(
            cast(Any, daemon_entry.serve)(
                cfg,
                os_=os_,
                clock=clock,
                monotonic_clock=mono,
                stop_event=stop_ev,
                shutdown_grace_s=2.0,
                on_ready=_on_ready,
                capture_probe=capture_probe,
                outbox_replay=outbox_replay,
                supervisor_control=supervisor_control,
                config_path=config_path,
            )
        )

    thr = threading.Thread(target=_bg, name="i4-5-serve", daemon=True)
    thr.start()
    try:
        assert ready_ev.wait(timeout=BOUND_WAIT_S), f"serve() did not become ready (exits={exits})"
        yield cast(Ready, box["ready"]), cast(OwnerLoop, box["loop"])
    finally:
        stop_ev.set()
        thr.join(timeout=BOUND_WAIT_S)
        assert not thr.is_alive(), "daemon serve thread leaked"


@contextlib.contextmanager
def _ro_db(db_path: Path) -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        yield conn
    finally:
        conn.close()


def _check_dict_by(checks: list[Mapping[str, Any]], group: str, name: str) -> Mapping[str, Any]:
    for chk in checks:
        if chk.get("group") == group and chk.get("name") in (name, f"{group}.{name}"):
            return chk
    raise AssertionError(f"missing check {group}.{name} in {checks!r}")


def _check_obj_by(report: DoctorReport, group: str, name: str) -> Any:
    for chk in report.checks:
        if chk.group == group and chk.name in (name, f"{group}.{name}"):
            return chk
    raise AssertionError(f"missing check {group}.{name} in {report.checks!r}")


def _assert_surface_shape(
    m1: Mapping[str, Any],
    surface_name: str,
    *,
    allowed_statuses: set[str],
) -> Mapping[str, Any]:
    surfaces = cast(Mapping[str, Any], m1["surfaces"])
    assert surface_name in surfaces, f"missing surface {surface_name!r} in {sorted(surfaces)}"
    item = cast(Mapping[str, Any], surfaces[surface_name])
    assert item.get("surface") == surface_name
    assert item.get("status") in allowed_statuses, item
    assert isinstance(item.get("reason"), str) and item["reason"]
    assert isinstance(item.get("detail"), str) and item["detail"]
    return item


_RESCAN_FINDING_TOKEN_RE = re.compile(r"\b(?:cas|log):[^\s\"';]+|\blast_gc=\d{4}-\d{2}-\d{2}T[^\s\"')]+")
_RAW_SECRET_SCAN_RULES = frozenset(
    {
        "private_marker",
        "pem_private_key",
        "auth_header",
        "auth_scheme",
        "key_value_secret",
        "fixed_token_prefix",
        "privacy_filter_rejected",
    }
)


def _assert_no_raw_secrets(
    payload: object,
    *,
    scanner: KernelPrivacyScanner,
    secrets: tuple[str, ...],
    label: str,
    allow_rescan_finding_tokens: bool = False,
    check_entropy: bool = True,
) -> None:
    encoded_str = payload if isinstance(payload, str) else json.dumps(payload, sort_keys=True)
    for secret in secrets:
        assert secret not in encoded_str, f"{label}: raw secret {secret!r} leaked into output!"
    hits = scanner.scan_bytes(encoded_str.encode("utf-8"))
    raw_hits = [rule for rule in hits if rule in _RAW_SECRET_SCAN_RULES]
    assert not raw_hits, f"{label}: raw secret rules matched output: {raw_hits!r}"
    det_val: JsonValue = {"content": encoded_str} if isinstance(payload, str) else cast(JsonValue, payload)
    det_out = PrivacyFilter().apply(det_val, FilterPolicy(entropy_min_length=4096))
    assert det_out.redacted_count == 0 and det_out.stripped_keys_count == 0, f"{label}: deterministic filter hit"
    if not check_entropy:
        return
    if allow_rescan_finding_tokens:
        normalized = _RESCAN_FINDING_TOKEN_RE.sub("finding_ref", encoded_str)
        norm_hits = scanner.scan_bytes(normalized.encode("utf-8"))
        assert norm_hits == (), f"{label}: KernelPrivacyScanner flagged output: {norm_hits!r} in {normalized!r}"
    else:
        assert hits == (), f"{label}: KernelPrivacyScanner flagged output: {hits!r} in {encoded_str!r}"


def _apply_clean_bootstrap(
    rt: Runtime,
    *,
    store_id: str,
    signer_id: str,
    owner_id: str,
    checkout: Path,
    home_dir: Path,
    os_: OsAdapters,
    rel_path: str = "CLAUDE.md",
    slice_id: str = "s1",
    body: str = "Managed\n",
) -> str:
    target_path = checkout / rel_path
    if not target_path.exists():
        target_path.write_text("# Original\n", encoding="utf-8")
    existing_text = target_path.read_text(encoding="utf-8")
    merged = merge_markdown_block(existing_text, slice_id=slice_id, block_body=body, expected_slice_digest=None)
    svc = ReviewApplyService(
        StoreProposalAdapter(rt.store, os_),
        PolicyApplyAuthority(rt.policy),
        os_,
        data_root=rt.root.root,
        home_dir=home_dir,
        config_merger=SharedConfigMergerAdapter(),
    )
    prop = svc.create_proposal(
        owner_id=owner_id,
        kind="bootstrap",
        reason=f"seed {rel_path}",
        resources=(RiskResource("c2"),),
        targets=(
            TargetWriteInput(
                checkout,
                rel_path,
                merged.updated_text.encode("utf-8"),
                ManagedFormat.MARKDOWN,
                slice_id,
                merged.slice_digest,
            ),
        ),
    )
    n_ap = rt.policy.issue_nonce(action=ApprovalAction.APPROVE, subject_id=prop.proposal_id, risk_level=prop.risk_level)
    svc.approve_proposal(
        prop.proposal_id,
        approval=ApprovalMessage(
            store_id=store_id,
            owner_id=owner_id,
            trust_generation=rt.policy.trust_generation(),
            action=ApprovalAction.APPROVE,
            subject_id=prop.proposal_id,
            subject_revision=prop.subject_revision,
            resource_digests=prop.resource_digests,
            target_files=prop.to_target_files(),
            risk_level=prop.risk_level,
            risk_policy_version=RISK_POLICY_VERSION,
            recovery_scope=RecoveryScope.NONE,
            nonce=n_ap.nonce,
            expires_at=n_ap.expires_at,
        ),
        signer_id=signer_id,
        channel=ApprovalChannel.SSH_KEY,
    )
    n_run = rt.policy.issue_nonce(action=ApprovalAction.APPLY, subject_id=prop.proposal_id, risk_level=prop.risk_level)
    svc.apply_proposal(
        prop.proposal_id,
        approval=ApprovalMessage(
            store_id=store_id,
            owner_id=owner_id,
            trust_generation=rt.policy.trust_generation(),
            action=ApprovalAction.APPLY,
            subject_id=prop.proposal_id,
            subject_revision=prop.subject_revision,
            resource_digests=prop.resource_digests,
            target_files=prop.to_target_files(),
            risk_level=prop.risk_level,
            risk_policy_version=RISK_POLICY_VERSION,
            recovery_scope=RecoveryScope.CONTINUE_OR_ROLLBACK,
            nonce=n_run.nonce,
            expires_at=n_run.expires_at,
        ),
        signer_id=signer_id,
        channel=ApprovalChannel.SSH_KEY,
    )
    return prop.proposal_id


def _read_latest_doctor_run_doc(root: DataRoot) -> tuple[str, dict[str, Any]]:
    with _ro_db(root.store_db) as conn:
        row = conn.execute(
            "SELECT refs FROM ledger WHERE kind = 'doctor.run' ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        assert row is not None
        refs = cast(list[str], json.loads(bytes(row[0]).decode("utf-8")))
        assert refs
        dig = refs[0]
    raw = blob_path(root.cas_dir, dig).read_bytes()
    doc = cast(dict[str, Any], json.loads(raw.decode("utf-8")))
    return dig, doc


class _StubOutboxReplay(OutboxReplayPort):
    def __init__(self, handler: Callable[[datetime], OutboxReplayResult]) -> None:
        self._handler = handler
        self.calls: list[datetime] = []

    def replay_outbox(self, *, now: datetime) -> OutboxReplayResult:
        self.calls.append(now)
        return self._handler(now)


class _StubSupervisorControl(SupervisorControlPort):
    def __init__(self, result: SupervisorRestartResult) -> None:
        self._result = result
        self.calls: list[Path] = []

    def restart_daemon(self, config_path: Path) -> SupervisorRestartResult:
        self.calls.append(config_path)
        return self._result


# ---------------------------------------------------------------------------
# 1. Module Surface, Constants, Re-Exports & Sp2CaptureProbeAdapter
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _ReceiptHarness(CaptureHarnessDoctorStatus):
    """Native capture status carrying the receipt that binds it to host, platform, Layer-2 config and checkout."""

    receipt: Mapping[str, Any] | None = None


def _bound_receipt(harness_id: str, host_version: str, config_digest: str, ws: Any) -> dict[str, Any]:
    """Native receipt bound to this run: host, ``sys.platform``, the harness's Layer-2 entry and the checkout scope."""
    return {
        "host": harness_id,
        "os": sys.platform,
        "host_version": host_version,
        "config_digest": config_digest,
        "run_scope": {"repo_id": ws.repo_id, "checkout_id": ws.checkout_id},
    }


def test_sp2_probe_module_exports_constants_and_adapter_metrics(trusted_tmp: Path) -> None:
    """Verify SP2 probe constants, re-exports, aggregation, latest timestamp, and provenance detail."""
    sp2 = _sp2_mod()

    assert sp2.M1_SURFACE_DEEP_HEALTH == "get_health(deep=true)"
    assert sp2.M1_SURFACE_PERMISSIONS == "permissions.data_root"
    assert sp2.M1_SURFACE_CAPTURE == "capture.sp2_probes"
    assert sp2.M1_SURFACE_LAYER2 == "harness.layer2"
    assert sp2.M1_SURFACE_BOOTSTRAP_DRIFT == "harness.bootstrap_drift"
    assert sp2.M1_CHECK_SURFACES == EXPECTED_M1_SURFACES

    assert sp2.CaptureDoctorProbePort is CaptureDoctorProbePort
    assert sp2.CaptureDoctorProbeResult is CaptureDoctorProbeResult
    assert sp2.CaptureDoctorSnapshot is CaptureDoctorSnapshot
    assert sp2.CaptureHarnessDoctorStatus is CaptureHarnessDoctorStatus
    assert sp2.OutboxReplayPort is OutboxReplayPort
    assert sp2.OutboxReplayResult is OutboxReplayResult
    assert sp2.PrivacyScannerPort is PrivacyScannerPort
    assert sp2.SupervisorControlPort is SupervisorControlPort
    assert sp2.SupervisorRestartResult is SupervisorRestartResult
    assert sp2.KernelPrivacyScanner is KernelPrivacyScanner

    data_root = trusted_tmp / "probe-root"
    data_root.mkdir()

    healthy_snap = CaptureDoctorSnapshot(
        harnesses=(
            CaptureHarnessDoctorStatus(
                harness_id="claude-code",
                last_event_at="2026-11-21T19:00:00Z",
                active_layer="hook",
                outbox_backlog=0,
                capture_gaps=0,
                dead_letters=0,
                receipt_kind="native",
            ),
            CaptureHarnessDoctorStatus(
                harness_id="codex",
                last_event_at="2026-11-21T19:05:30Z",
                active_layer="hook",
                outbox_backlog=0,
                capture_gaps=0,
                dead_letters=0,
                receipt_kind="native",
            ),
        ),
        available=True,
    )
    adapter = sp2.build_sp2_capture_probe(lambda _root: healthy_snap, require_native_receipts=True)
    assert isinstance(adapter, sp2.Sp2CaptureProbeAdapter)
    assert adapter.probe_snapshot(data_root) == healthy_snap
    res_ok = adapter.probe_capture(data_root)
    assert res_ok.available is True
    assert res_ok.status == "PASS"
    assert res_ok.reason == "ok"
    assert res_ok.outbox_backlog == 0
    assert res_ok.capture_gaps == 0
    assert res_ok.dead_letters == 0
    assert res_ok.last_event_at == "2026-11-21T19:05:30Z"
    assert res_ok.active_layer == "hook"
    assert res_ok.timed_out is False
    assert "native" in res_ok.detail.lower()

    agg_snap = CaptureDoctorSnapshot(
        harnesses=(
            CaptureHarnessDoctorStatus(
                harness_id="claude-code",
                last_event_at="2026-11-21T19:10:00Z",
                active_layer="hook",
                outbox_backlog=2,
                capture_gaps=1,
                dead_letters=0,
                receipt_kind="native",
            ),
            CaptureHarnessDoctorStatus(
                harness_id="codex",
                last_event_at="2026-11-21T19:08:00Z",
                active_layer="hook",
                outbox_backlog=3,
                capture_gaps=0,
                dead_letters=2,
                receipt_kind="native",
            ),
        ),
        available=True,
    )
    res_agg = sp2.Sp2CaptureProbeAdapter(lambda _root: agg_snap, require_native_receipts=True).probe_capture(data_root)
    assert res_agg.outbox_backlog == 5
    assert res_agg.capture_gaps == 1
    assert res_agg.dead_letters == 2
    assert res_agg.last_event_at == "2026-11-21T19:10:00Z"
    assert res_agg.active_layer == "hook"
    assert res_agg.status in {"WARN", "FAIL"}
    assert "native" in res_agg.detail.lower()

    backlog_snap = CaptureDoctorSnapshot(
        harnesses=(
            CaptureHarnessDoctorStatus(
                harness_id="claude-code",
                last_event_at=None,
                active_layer="hook",
                outbox_backlog=4,
                capture_gaps=0,
                dead_letters=0,
                receipt_kind="native",
            ),
            CaptureHarnessDoctorStatus(
                harness_id="codex",
                last_event_at="2026-11-21T19:12:00Z",
                active_layer="hook",
                outbox_backlog=0,
                capture_gaps=0,
                dead_letters=0,
                receipt_kind="native",
            ),
        ),
        available=True,
    )
    res_backlog = sp2.Sp2CaptureProbeAdapter(lambda _root: backlog_snap).probe_capture(data_root)
    assert res_backlog.outbox_backlog == 4
    assert res_backlog.last_event_at == "2026-11-21T19:12:00Z"
    assert "native" in res_backlog.detail.lower()


# ---------------------------------------------------------------------------
# 2. Case 1: End-to-End Wiring Across Daemon, MCP, Operator API, CLI & M1 Probe
# ---------------------------------------------------------------------------


def test_m1_all_five_surfaces_end_to_end_daemon_mcp_operator_and_cli(trusted_tmp: Path) -> None:
    """All 5 M1 surfaces wired across serve/serve_config_path, get_health(deep=True), /doctor/*, run_doctor, M1."""
    sp2 = _sp2_mod()
    clock = FakeClock(_base_utc_now())
    real_mono = os_adapters().monotonic
    base_os = os_adapters(clock=clock, monotonic=real_mono)

    rep, cfg, _priv, ca_pem, leaf_sha256, cli_token, os_ = _init_store_with_tls(
        trusted_tmp / "e2e-m1", clock, os_=base_os
    )
    root = DataRoot.at(cfg.data_root)
    checkout_a = trusted_tmp / "checkout-a"
    home_dir = trusted_tmp / "home"
    for d in (checkout_a, home_dir):
        d.mkdir(parents=True)
        os_.permissions.secure_directory(d)

    rt = reopen_kernel_job_runtime(cfg.data_root, rep.store_id, os_)
    try:
        cred_claude = seed_principal_and_credential(
            rt.policy, owner_id=OWNER_DAN, harness_id="claude-code", machine_id=MACHINE_ID
        )
        seed_principal_and_credential(
            rt.policy, owner_id=OWNER_DAN, harness_id="codex", machine_id=MACHINE_ID
        )
        ws_a = register_workspace_direct(
            rt, clock, cred_claude.principal, alias="ws-a", checkout_dir=checkout_a, remote="https://ex/repo-a.git"
        )
        rt.policy.set_layer2_state(
            harness_id="claude-code",
            host_version="2.1.0",
            config_digest=digest_bytes(b"claude-hooks-v1"),
            state=Layer2State.VERIFIED,
        )
        rt.policy.set_layer2_state(
            harness_id="codex",
            host_version="0.55.0",
            config_digest=digest_bytes(b"codex-hooks-v1"),
            state=Layer2State.VERIFIED,
        )
        assert rt.policy.terminal_channel_eligible(machine_id=MACHINE_ID) is True
        _apply_clean_bootstrap(
            rt,
            store_id=rep.store_id,
            signer_id=rep.signer.signer_id,
            owner_id=OWNER_DAN,
            checkout=checkout_a,
            home_dir=home_dir,
            os_=os_,
        )
    finally:
        rt.close()

    prof_dir = trusted_tmp / "profiles"
    ca_file = write_ca_file(prof_dir / "ca.pem", ca_pem)
    cli_cred_file = write_credential_file(prof_dir / "cli.cred", cli_token)
    cli_profile, _ = write_client_profile_file(
        prof_dir / "cli.profile.json",
        endpoint_path=root.endpoint_path,
        expected_store_id=rep.store_id,
        ca_file=ca_file,
        leaf_cert_sha256=leaf_sha256,
        credential_file=cli_cred_file,
        workspace={
            "alias": ws_a.alias,
            "checkout_path": str(checkout_a),
            "expected_workspace_id": ws_a.repo_id,
            "expected_checkout_id": ws_a.checkout_id,
        },
    )
    claude_cred_file = write_credential_file(prof_dir / "claude.cred", cred_claude.token)
    claude_profile, _ = write_client_profile_file(
        prof_dir / "claude.profile.json",
        endpoint_path=root.endpoint_path,
        expected_store_id=rep.store_id,
        ca_file=ca_file,
        leaf_cert_sha256=leaf_sha256,
        credential_file=claude_cred_file,
        workspace={
            "alias": ws_a.alias,
            "checkout_path": str(checkout_a),
            "expected_workspace_id": ws_a.repo_id,
            "expected_checkout_id": ws_a.checkout_id,
        },
    )

    live_state: dict[str, int] = {"backlog": 0, "gaps": 0, "dead": 0}

    def _dynamic_snap(_root: Path) -> CaptureDoctorSnapshot:
        return CaptureDoctorSnapshot(
            harnesses=(
                _ReceiptHarness(
                    harness_id="claude-code",
                    last_event_at="2026-11-21T19:01:00Z",
                    active_layer="hook",
                    outbox_backlog=live_state["backlog"],
                    capture_gaps=live_state["gaps"],
                    dead_letters=live_state["dead"],
                    receipt_kind="native",
                    receipt=_bound_receipt("claude-code", "2.1.0", digest_bytes(b"claude-hooks-v1"), ws_a),
                ),
                _ReceiptHarness(
                    harness_id="codex",
                    last_event_at="2026-11-21T19:02:00Z",
                    active_layer="hook",
                    outbox_backlog=0,
                    capture_gaps=0,
                    dead_letters=0,
                    receipt_kind="native",
                    receipt=_bound_receipt("codex", "0.55.0", digest_bytes(b"codex-hooks-v1"), ws_a),
                ),
            ),
            available=True,
        )

    probe = sp2.build_sp2_capture_probe(_dynamic_snap, require_native_receipts=True)

    def _replay_clears(_now: datetime) -> OutboxReplayResult:
        had = live_state["backlog"] + live_state["gaps"] + live_state["dead"]
        live_state["backlog"] = 0
        live_state["gaps"] = 0
        live_state["dead"] = 0
        if had > 0:
            return OutboxReplayResult(
                status="applied",
                replayed_events=had,
                committed_event_sequences=(1, 2),
                contiguous_event_acked_through=2,
                acked_producer_gap_sequences=(),
                pending_remaining=0,
                detail="replayed pending outbox",
            )
        return OutboxReplayResult(
            status="noop",
            replayed_events=0,
            committed_event_sequences=(),
            contiguous_event_acked_through=2,
            acked_producer_gap_sequences=(),
            pending_remaining=0,
            detail="outbox clean",
        )

    outbox_port = _StubOutboxReplay(_replay_clears)
    sup_port = _StubSupervisorControl(
        SupervisorRestartResult(status="applied", restarted=True, pid=12345, detail="restarted")
    )

    with _running_serve_config(
        rep.daemon_config_path,
        os_=os_,
        clock=clock,
        mono=real_mono,
        capture_probe=probe,
        outbox_replay=outbox_port,
        supervisor_control=sup_port,
    ) as (ready, loop):
        assert loop.wait_doctor_settled(timeout=BOUND_WAIT_S)

        # MCP get_health(deep=True) via build_tool_caller and LoopbackClient.
        caller = build_tool_caller(claude_profile, checkout_a, os_adapters(clock=clock, monotonic=real_mono))
        health_env = _validate_get_health_envelope(
            caller("get_health", {"schema_version": "2.0", "deep": True, "idempotency_key": "idem_m1_e2e_health_01"})
        )
        assert health_env["ok"] is True
        health_data = cast(dict[str, JsonValue], health_env["data"])
        assert health_data["ready"] is True
        assert isinstance(health_data["doctor_run_id"], str) and health_data["doctor_run_id"]
        assert isinstance(health_data["age_s"], (int, float)) and health_data["age_s"] >= 0.0
        assert health_data["job_id"] is None
        assert health_data["degraded_codes"] == []

        # Startup DoctorRun CAS blob must record overall_status="pass" and live capture.probe PASS (native).
        _dig, run_doc = _read_latest_doctor_run_doc(root)
        assert run_doc["overall_status"] == "pass"
        run_rep = cast(dict[str, Any], run_doc["report"])
        run_cap_chk = _check_dict_by(cast(list[Mapping[str, Any]], run_rep["checks"]), "capture", "probe")
        assert run_cap_chk["status"] == "PASS"
        assert "native" in str(run_cap_chk["detail"]).lower()

        # /v2/operator/doctor/report reflects all healthy surfaces.
        op_rep = _call_operator_json(
            ready.endpoint,
            store_id=rep.store_id,
            ca_pem=ca_pem,
            leaf_sha256=leaf_sha256,
            token=cli_token,
            path="/v2/operator/doctor/report",
            body={"wait_timeout_ms": 5000, "checkout_root": str(checkout_a)},
            monotonic_ns=real_mono.monotonic_ns,
        )
        assert op_rep.get("ok") is True, op_rep
        op_data = cast(dict[str, Any], op_rep["data"])
        assert op_data["overall_status"] == "pass"
        assert op_data["terminal_channel_eligible"] is True
        op_cap = _check_dict_by(cast(list[Mapping[str, Any]], op_data["checks"]), "capture", "probe")
        assert op_cap["status"] == "PASS" and "native" in str(op_cap["detail"]).lower()

        # doctor_entry.run_doctor (offline read-only) reflects capture.probe too.
        cli_rep = doctor_entry.run_doctor(
            rep.daemon_config_path, checkout_root=checkout_a, os_=os_, capture_probe=probe,
            host_version_resolver=_FIXTURE_HOST_VERSIONS.get,
        )
        assert cli_rep.overall_status == "pass"
        assert _check_obj_by(cli_rep, "capture", "probe").status == "PASS"

        # run_m1_handover_probe via both daemon config and client profile -> m1_ready=True, native_verified=True.
        for cfg_or_prof, is_prof in ((rep.daemon_config_path, False), (cli_profile, True)):
            m1 = sp2.run_m1_handover_probe(
                cfg_or_prof,
                is_profile=is_prof,
                checkout_root=checkout_a,
                os_=os_,
                capture_probe=probe,
                deep_health=health_data,
                require_native_receipts=True,
            )
            assert m1["m1_ready"] is True, m1
            assert m1["overall_status"] == "pass", m1
            assert m1["missing_surfaces"] == [], m1
            assert m1["native_verified"] is True, m1
            assert m1["receipt_provenance"] == "native", m1
            for sname in EXPECTED_M1_SURFACES:
                _assert_surface_shape(m1, sname, allowed_statuses={"PASS"})
            harnesses = cast(list[Mapping[str, Any]], m1["harnesses"])
            assert {h.get("harness_id") for h in harnesses} == {"claude-code", "codex"}

        # Flip live capture probe to degraded -> /v2/operator/doctor/report & get_health(deep=True) surface degradation!
        live_state["backlog"] = 3
        live_state["gaps"] = 2
        live_state["dead"] = 1
        clock.advance(timedelta(minutes=16))

        op_deg = _call_operator_json(
            ready.endpoint,
            store_id=rep.store_id,
            ca_pem=ca_pem,
            leaf_sha256=leaf_sha256,
            token=cli_token,
            path="/v2/operator/doctor/report",
            body={"wait_timeout_ms": 5000, "checkout_root": str(checkout_a)},
            monotonic_ns=real_mono.monotonic_ns,
        )
        assert op_deg.get("ok") is True, op_deg
        op_deg_data = cast(dict[str, Any], op_deg["data"])
        assert op_deg_data["overall_status"] in {"warn", "fail"}
        assert _check_dict_by(cast(list[Mapping[str, Any]], op_deg_data["checks"]), "capture", "probe")[
            "status"
        ] in {"WARN", "FAIL"}

        # I4-R4-01: store-wide get_health(deep=True) never answers with the checkout-scoped run above; the
        # degradation reaches deep health through a store-wide (no checkout) run.
        op_deg_store = _call_operator_json(
            ready.endpoint,
            store_id=rep.store_id,
            ca_pem=ca_pem,
            leaf_sha256=leaf_sha256,
            token=cli_token,
            path="/v2/operator/doctor/report",
            body={"wait_timeout_ms": 5000},
            monotonic_ns=real_mono.monotonic_ns,
        )
        assert op_deg_store.get("ok") is True, op_deg_store
        op_deg_store_data = cast(dict[str, Any], op_deg_store["data"])
        assert op_deg_store_data["overall_status"] in {"warn", "fail"}
        assert _check_dict_by(cast(list[Mapping[str, Any]], op_deg_store_data["checks"]), "capture", "probe")[
            "status"
        ] in {"WARN", "FAIL"}

        health_deg_env = _validate_get_health_envelope(
            caller("get_health", {"schema_version": "2.0", "deep": True, "idempotency_key": "idem_m1_e2e_health_02"})
        )
        assert health_deg_env["ok"] is True
        health_deg = cast(dict[str, JsonValue], health_deg_env["data"])
        assert health_deg["doctor_run_id"] != health_data["doctor_run_id"]
        assert health_deg["doctor_run_id"] == op_deg_store_data["doctor_run_id"], health_deg
        assert health_deg["doctor_run_id"] != op_deg_data["doctor_run_id"], "deep health named a checkout run"
        assert "capture.probe" in cast(list[str], health_deg["degraded_codes"])

        # /v2/operator/doctor/fix triggers outbox_replay and rechecked_checks reflects restored capture.probe PASS!
        fix_res = _call_operator_json(
            ready.endpoint,
            store_id=rep.store_id,
            ca_pem=ca_pem,
            leaf_sha256=leaf_sha256,
            token=cli_token,
            path="/v2/operator/doctor/fix",
            body={"actions": ["replay_outbox"], "checkout_root": str(checkout_a)},
            monotonic_ns=real_mono.monotonic_ns,
        )
        assert fix_res.get("ok") is True, fix_res
        fix_data = cast(dict[str, Any], fix_res["data"])
        rechecked = cast(list[Mapping[str, Any]], fix_data["fix"]["rechecked_checks"])
        assert _check_dict_by(rechecked, "capture", "probe")["status"] == "PASS"

        # Subsequent /v2/operator/doctor/report invalidates stale degraded run (fix_dirty) and reports pass!
        op_post = _call_operator_json(
            ready.endpoint,
            store_id=rep.store_id,
            ca_pem=ca_pem,
            leaf_sha256=leaf_sha256,
            token=cli_token,
            path="/v2/operator/doctor/report",
            body={"wait_timeout_ms": 5000, "checkout_root": str(checkout_a)},
            monotonic_ns=real_mono.monotonic_ns,
        )
        assert op_post.get("ok") is True and op_post["data"]["overall_status"] == "pass"

    # Also verify daemon_entry.serve(...) directly forwards capture_probe to DaemonDoctorRunner.
    live_state["gaps"] = 1
    with _running_serve(
        cfg,
        os_=os_,
        clock=clock,
        mono=real_mono,
        capture_probe=probe,
    ) as (ready2, loop2):
        assert loop2.wait_doctor_settled(timeout=BOUND_WAIT_S)
        op_srv = _call_operator_json(
            ready2.endpoint,
            store_id=rep.store_id,
            ca_pem=ca_pem,
            leaf_sha256=leaf_sha256,
            token=cli_token,
            path="/v2/operator/doctor/report",
            body={"wait_timeout_ms": 5000, "checkout_root": str(checkout_a)},
            monotonic_ns=real_mono.monotonic_ns,
        )
        assert op_srv.get("ok") is True
        assert op_srv["data"]["overall_status"] in {"warn", "fail"}
        assert _check_dict_by(cast(list[Mapping[str, Any]], op_srv["data"]["checks"]), "capture", "probe")[
            "status"
        ] in {"WARN", "FAIL"}


# ---------------------------------------------------------------------------
# 3. Case 2: Receipt Fixture vs Native Provenance
# ---------------------------------------------------------------------------


def test_m1_fixture_vs_native_receipt_provenance(trusted_tmp: Path) -> None:
    """Fixture receipt provenance is surfaced explicitly and NEVER promoted to m1_ready=True."""
    sp2 = _sp2_mod()
    clock = FakeClock(_base_utc_now())
    rep, cfg, _priv, _ca, _sha, _cli, os_ = _init_store_with_tls(trusted_tmp / "provenance", clock)
    checkout = trusted_tmp / "co"
    home_dir = trusted_tmp / "home"
    for d in (checkout, home_dir):
        d.mkdir()
        os_.permissions.secure_directory(d)

    rt = reopen_kernel_job_runtime(cfg.data_root, rep.store_id, os_)
    live_writer_epoch = rt.lease.epoch  # writer generation a live get_health(deep=true) reports
    try:
        cred = seed_principal_and_credential(
            rt.policy, owner_id=OWNER_DAN, harness_id="claude-code", machine_id=MACHINE_ID
        )
        ws = register_workspace_direct(
            rt, clock, cred.principal, alias="ws-prov", checkout_dir=checkout, remote="https://ex/prov.git"
        )
        rt.policy.set_layer2_state(
            harness_id="claude-code",
            host_version="2.1.0",
            config_digest=digest_bytes(b"cfg"),
            state=Layer2State.VERIFIED,
        )
        _apply_clean_bootstrap(
            rt,
            store_id=rep.store_id,
            signer_id=rep.signer.signer_id,
            owner_id=OWNER_DAN,
            checkout=checkout,
            home_dir=home_dir,
            os_=os_,
        )
    finally:
        rt.close()
    claude_receipt = _bound_receipt("claude-code", "2.1.0", digest_bytes(b"cfg"), ws)

    healthy_dh: dict[str, JsonValue] = {
        "ready": True,
        "store_id": rep.store_id,
        "writer_epoch": live_writer_epoch,
        "schema_version": 5,
        "policy_schema_version": 4,
        "degraded_codes": [],
        "doctor_run_id": new_id(),
        "age_s": 1.0,
        "job_id": None,
    }

    def _fixture_snap(_root: Path) -> CaptureDoctorSnapshot:
        return CaptureDoctorSnapshot(
            harnesses=(
                CaptureHarnessDoctorStatus(
                    harness_id="claude-code",
                    last_event_at="2026-11-21T19:15:00Z",
                    active_layer="hook",
                    outbox_backlog=0,
                    capture_gaps=0,
                    dead_letters=0,
                    receipt_kind="fixture",
                ),
            ),
            available=True,
        )

    probe_relaxed = sp2.build_sp2_capture_probe(_fixture_snap, require_native_receipts=False)
    res_relaxed = probe_relaxed.probe_capture(cfg.data_root)
    assert res_relaxed.status == "PASS"
    assert "fixture" in res_relaxed.detail.lower()

    probe_strict = sp2.build_sp2_capture_probe(_fixture_snap, require_native_receipts=True)
    res_strict = probe_strict.probe_capture(cfg.data_root)
    assert res_strict.status in {"WARN", "FAIL"}
    assert res_strict.reason != "ok"
    assert "fixture" in res_strict.detail.lower()

    # Even if adapter was built with require_native_receipts=False, M1 strict gate NEVER promotes fixture to m1_ready.
    for adapter in (probe_relaxed, probe_strict):
        m1_fix = sp2.run_m1_handover_probe(
            rep.daemon_config_path,
            checkout_root=checkout,
            os_=os_,
            capture_probe=adapter,
            deep_health=healthy_dh,
            require_native_receipts=True,
        )
        assert m1_fix["receipt_provenance"] == "fixture"
        assert m1_fix["native_verified"] is False
        assert m1_fix["m1_ready"] is False
        assert m1_fix["overall_status"] in {"warn", "fail"}
        _assert_surface_shape(m1_fix, sp2.M1_SURFACE_CAPTURE, allowed_statuses={"WARN", "FAIL"})
        assert sp2.M1_SURFACE_CAPTURE in cast(list[str], m1_fix["missing_surfaces"])

    # When require_native_receipts=False on evaluate_m1_surfaces, fixture still keeps native_verified=False.
    snap_fix = read_doctor_snapshot(cfg.data_root, os_, checkout_root=checkout, capture_probe=probe_relaxed)
    rep_fix = inspect_doctor_snapshot(snap_fix)
    eval_relaxed = sp2.evaluate_m1_surfaces(
        rep_fix,
        snap_fix,
        capture_snapshot=_fixture_snap(cfg.data_root),
        deep_health=healthy_dh,
        require_native_receipts=False,
    )
    assert eval_relaxed["receipt_provenance"] == "fixture"
    assert eval_relaxed["native_verified"] is False

    # Mixed native + fixture -> NEVER PASS / NEVER native_verified / NEVER m1_ready when require_native_receipts=True.
    def _mixed_snap(_root: Path) -> CaptureDoctorSnapshot:
        return CaptureDoctorSnapshot(
            harnesses=(
                _ReceiptHarness(
                    harness_id="claude-code",
                    last_event_at="2026-11-21T19:15:00Z",
                    active_layer="hook",
                    outbox_backlog=0,
                    capture_gaps=0,
                    dead_letters=0,
                    receipt_kind="native",
                    receipt=claude_receipt,
                ),
                CaptureHarnessDoctorStatus(
                    harness_id="codex",
                    last_event_at="2026-11-21T19:16:00Z",
                    active_layer="hook",
                    outbox_backlog=0,
                    capture_gaps=0,
                    dead_letters=0,
                    receipt_kind="fixture",
                ),
            ),
            available=True,
        )

    mixed_probe = sp2.build_sp2_capture_probe(_mixed_snap, require_native_receipts=True)
    assert mixed_probe.probe_capture(cfg.data_root).status in {"WARN", "FAIL"}
    m1_mixed = sp2.run_m1_handover_probe(
        rep.daemon_config_path,
        checkout_root=checkout,
        os_=os_,
        capture_probe=mixed_probe,
        deep_health=healthy_dh,
        require_native_receipts=True,
    )
    assert m1_mixed["native_verified"] is False
    assert m1_mixed["receipt_provenance"] != "native"
    assert m1_mixed["m1_ready"] is False
    _assert_surface_shape(m1_mixed, sp2.M1_SURFACE_CAPTURE, allowed_statuses={"WARN", "FAIL"})

    # Native receipt promotes cleanly.
    def _native_snap(_root: Path) -> CaptureDoctorSnapshot:
        return CaptureDoctorSnapshot(
            harnesses=(
                _ReceiptHarness(
                    harness_id="claude-code",
                    last_event_at="2026-11-21T19:17:00Z",
                    active_layer="hook",
                    outbox_backlog=0,
                    capture_gaps=0,
                    dead_letters=0,
                    receipt_kind="native",
                    receipt=claude_receipt,
                ),
            ),
            available=True,
        )

    m1_native = sp2.run_m1_handover_probe(
        rep.daemon_config_path,
        checkout_root=checkout,
        os_=os_,
        capture_probe=sp2.build_sp2_capture_probe(_native_snap, require_native_receipts=True),
        deep_health=healthy_dh,
        require_native_receipts=True,
    )
    assert m1_native["receipt_provenance"] == "native"
    assert m1_native["native_verified"] is True
    assert m1_native["m1_ready"] is True
    assert m1_native["overall_status"] == "pass"


# ---------------------------------------------------------------------------
# 4. Case 3: Missing / Unavailable / Empty / Errored / Timeout / Bogus PASS
# ---------------------------------------------------------------------------


def test_m1_missing_unhealthy_timeout_and_bogus_pass_coercion(trusted_tmp: Path) -> None:
    """Missing, unavailable, empty, errored, timed-out, and bogus PASS capture probes NEVER pass."""
    sp2 = _sp2_mod()
    assert PROBE_TIMEOUT_S == 5.0

    clock = FakeClock(_base_utc_now())
    rep, cfg, _priv, _ca, _sha, _cli, os_ = _init_store_with_tls(trusted_tmp / "fail-modes", clock)
    checkout = trusted_tmp / "co"
    checkout.mkdir()
    os_.permissions.secure_directory(checkout)

    rt = reopen_kernel_job_runtime(cfg.data_root, rep.store_id, os_)
    live_writer_epoch = rt.lease.epoch  # writer generation a live get_health(deep=true) reports
    try:
        seed_principal_and_credential(rt.policy, owner_id=OWNER_DAN, harness_id="claude-code", machine_id=MACHINE_ID)
        rt.policy.set_layer2_state(
            harness_id="claude-code",
            host_version="2.1.0",
            config_digest=digest_bytes(b"cfg"),
            state=Layer2State.VERIFIED,
        )
    finally:
        rt.close()

    healthy_dh: dict[str, JsonValue] = {
        "ready": True,
        "store_id": rep.store_id,
        "writer_epoch": live_writer_epoch,
        "schema_version": 5,
        "policy_schema_version": 4,
        "degraded_codes": [],
        "doctor_run_id": new_id(),
        "age_s": 1.0,
        "job_id": None,
    }

    # 3a) Unattached probe (capture_probe=None).
    m1_none = sp2.run_m1_handover_probe(
        rep.daemon_config_path,
        checkout_root=checkout,
        os_=os_,
        capture_probe=None,
        deep_health=healthy_dh,
        require_native_receipts=True,
    )
    assert m1_none["m1_ready"] is False
    assert m1_none["native_verified"] is False
    _assert_surface_shape(m1_none, sp2.M1_SURFACE_CAPTURE, allowed_statuses={"WARN", "FAIL"})
    assert sp2.M1_SURFACE_CAPTURE in cast(list[str], m1_none["missing_surfaces"])

    # 3b) Unavailable snapshot.
    unavail_probe = sp2.build_sp2_capture_probe(
        lambda _r: CaptureDoctorSnapshot(harnesses=(), available=False, unavailable_reason="socket down"),
        require_native_receipts=True,
    )
    unavail_res = unavail_probe.probe_capture(cfg.data_root)
    assert unavail_res.available is False and unavail_res.status in {"WARN", "FAIL"} and unavail_res.reason != "ok"
    m1_unavail = sp2.run_m1_handover_probe(
        rep.daemon_config_path,
        checkout_root=checkout,
        os_=os_,
        capture_probe=unavail_probe,
        deep_health=healthy_dh,
        require_native_receipts=True,
    )
    assert m1_unavail["m1_ready"] is False
    _assert_surface_shape(m1_unavail, sp2.M1_SURFACE_CAPTURE, allowed_statuses={"WARN", "FAIL"})

    # 3c) Empty harnesses list.
    empty_probe = sp2.build_sp2_capture_probe(
        lambda _r: CaptureDoctorSnapshot(harnesses=(), available=True),
        require_native_receipts=True,
    )
    empty_res = empty_probe.probe_capture(cfg.data_root)
    assert empty_res.status in {"WARN", "FAIL"} and empty_res.reason != "ok"
    m1_empty = sp2.run_m1_handover_probe(
        rep.daemon_config_path,
        checkout_root=checkout,
        os_=os_,
        capture_probe=empty_probe,
        deep_health=healthy_dh,
        require_native_receipts=True,
    )
    assert m1_empty["m1_ready"] is False
    _assert_surface_shape(m1_empty, sp2.M1_SURFACE_CAPTURE, allowed_statuses={"WARN", "FAIL"})

    # 3d) Per-harness probe_error.
    err_probe = sp2.build_sp2_capture_probe(
        lambda _r: CaptureDoctorSnapshot(
            harnesses=(
                CaptureHarnessDoctorStatus(
                    harness_id="claude-code",
                    last_event_at="2026-11-21T19:00:00Z",
                    active_layer="hook",
                    outbox_backlog=0,
                    capture_gaps=0,
                    dead_letters=0,
                    receipt_kind="native",
                    probe_error="corrupt outbox header",
                ),
            ),
            available=True,
        ),
        require_native_receipts=True,
    )
    err_res = err_probe.probe_capture(cfg.data_root)
    assert err_res.status in {"WARN", "FAIL"} and err_res.reason != "ok"
    m1_err = sp2.run_m1_handover_probe(
        rep.daemon_config_path,
        checkout_root=checkout,
        os_=os_,
        capture_probe=err_probe,
        deep_health=healthy_dh,
        require_native_receipts=True,
    )
    assert m1_err["m1_ready"] is False
    _assert_surface_shape(m1_err, sp2.M1_SURFACE_CAPTURE, allowed_statuses={"WARN", "FAIL"})

    # 3e) Bounded timeout (both real wait > custom limit and FakeMonotonicClock > PROBE_TIMEOUT_S).
    class _SlowAdapter(CaptureDoctorProbePort):
        def probe_capture(self, _data_root: Path) -> CaptureDoctorProbeResult:
            time.sleep(0.20)
            return CaptureDoctorProbeResult(available=True, status="PASS", reason="ok")

    res_wall_timeout = run_capture_probe_bounded(
        cfg.data_root, _SlowAdapter(), os_, DoctorScanLimits(probe_timeout_s=0.05)
    )
    assert res_wall_timeout is not None
    assert res_wall_timeout.timed_out is True
    assert res_wall_timeout.status == "WARN"
    assert res_wall_timeout.reason == "timeout_exceeded"

    fake_mono = FakeMonotonicClock(1_000_000_000)
    os_fake_mono = os_adapters(clock=clock, monotonic=fake_mono)

    def _advancing_snap(_root: Path) -> CaptureDoctorSnapshot:
        fake_mono.advance(int((PROBE_TIMEOUT_S + 0.5) * 1_000_000_000))
        return CaptureDoctorSnapshot(
            harnesses=(
                CaptureHarnessDoctorStatus(
                    harness_id="claude-code",
                    last_event_at="2026-11-21T19:00:00Z",
                    active_layer="hook",
                    outbox_backlog=0,
                    capture_gaps=0,
                    dead_letters=0,
                    receipt_kind="native",
                ),
            ),
            available=True,
        )

    timeout_probe = sp2.build_sp2_capture_probe(_advancing_snap, require_native_receipts=True)
    snap_to = read_doctor_snapshot(
        cfg.data_root, os_fake_mono, checkout_root=checkout, capture_probe=timeout_probe
    )
    assert snap_to.capture_probe_result is not None
    assert snap_to.capture_probe_result.timed_out is True
    assert snap_to.capture_probe_result.status == "WARN"
    assert snap_to.capture_probe_result.reason == "timeout_exceeded"
    rep_to = inspect_doctor_snapshot(snap_to)
    assert rep_to.overall_status == "warn"
    assert _check_obj_by(rep_to, "capture", "probe").status == "WARN"
    eval_to = sp2.evaluate_m1_surfaces(rep_to, snap_to, capture_snapshot=None, deep_health=healthy_dh)
    assert eval_to["m1_ready"] is False
    _assert_surface_shape(eval_to, sp2.M1_SURFACE_CAPTURE, allowed_statuses={"WARN", "FAIL"})

    # 3f) Bogus "PASS" results returned by a misbehaving CaptureDoctorProbePort must be coerced to non-PASS.
    base_snap = read_doctor_snapshot(cfg.data_root, os_, checkout_root=checkout)
    bogus_cases: tuple[CaptureDoctorProbeResult, ...] = (
        CaptureDoctorProbeResult(available=False, status="PASS", reason="ok", detail="bogus unavail"),
        CaptureDoctorProbeResult(available=True, timed_out=True, status="PASS", reason="ok", detail="bogus timeout"),
        CaptureDoctorProbeResult(available=True, dead_letters=2, status="PASS", reason="ok", detail="bogus dead"),
        CaptureDoctorProbeResult(available=True, capture_gaps=3, status="PASS", reason="ok", detail="bogus gap"),
    )
    for bogus in bogus_cases:
        class _BogusPort(CaptureDoctorProbePort):
            def __init__(self, payload: CaptureDoctorProbeResult) -> None:
                self._payload = payload

            def probe_capture(self, _root: Path) -> CaptureDoctorProbeResult:
                return self._payload

        coerced_snap = replace(base_snap, capture_probe_result=bogus)
        coerced_rep = inspect_doctor_snapshot(coerced_snap)
        cap_chk = _check_obj_by(coerced_rep, "capture", "probe")
        assert cap_chk.status in {"WARN", "FAIL"}, f"bogus PASS leaked through inspect_doctor_snapshot: {bogus}"
        assert coerced_rep.overall_status in {"warn", "fail"}

        cli_bogus = doctor_entry.run_doctor(
            rep.daemon_config_path, checkout_root=checkout, os_=os_, capture_probe=_BogusPort(bogus)
        )
        assert _check_obj_by(cli_bogus, "capture", "probe").status in {"WARN", "FAIL"}
        assert cli_bogus.overall_status in {"warn", "fail"}

        m1_bogus = sp2.evaluate_m1_surfaces(coerced_rep, coerced_snap, capture_snapshot=None, deep_health=healthy_dh)
        assert m1_bogus["m1_ready"] is False
        _assert_surface_shape(m1_bogus, sp2.M1_SURFACE_CAPTURE, allowed_statuses={"WARN", "FAIL"})


# ---------------------------------------------------------------------------
# 5. Case 4: Host Invalidation, Layer-2 DB States & Missing Harness Credential
# ---------------------------------------------------------------------------


def test_m1_host_invalidation_layer2_states_and_missing_harness_credential(trusted_tmp: Path) -> None:
    """host_invalidated=True, Layer-2 UNKNOWN/UNSUPPORTED, and missing harness credentials invalidate M1."""
    sp2 = _sp2_mod()
    clock = FakeClock(_base_utc_now())
    rep, cfg, _priv, _ca, _sha, _cli, os_ = _init_store_with_tls(trusted_tmp / "layer2-inv", clock)
    checkout = trusted_tmp / "co"
    home_dir = trusted_tmp / "home"
    for d in (checkout, home_dir):
        d.mkdir()
        os_.permissions.secure_directory(d)

    rt = reopen_kernel_job_runtime(cfg.data_root, rep.store_id, os_)
    live_writer_epoch = rt.lease.epoch  # writer generation a live get_health(deep=true) reports
    try:
        cred_claude = seed_principal_and_credential(
            rt.policy, owner_id=OWNER_DAN, harness_id="claude-code", machine_id=MACHINE_ID
        )
        cred_codex = seed_principal_and_credential(
            rt.policy, owner_id=OWNER_DAN, harness_id="codex", machine_id=MACHINE_ID
        )
        rt.policy.set_layer2_state(
            harness_id="claude-code",
            host_version="2.1.0",
            config_digest=digest_bytes(b"claude-v1"),
            state=Layer2State.VERIFIED,
        )
        rt.policy.set_layer2_state(
            harness_id="codex",
            host_version="0.55.0",
            config_digest=digest_bytes(b"codex-v1"),
            state=Layer2State.VERIFIED,
        )
        ws = register_workspace_direct(
            rt, clock, cred_claude.principal, alias="ws-l2", checkout_dir=checkout, remote="https://ex/l2.git"
        )
        _apply_clean_bootstrap(
            rt,
            store_id=rep.store_id,
            signer_id=rep.signer.signer_id,
            owner_id=OWNER_DAN,
            checkout=checkout,
            home_dir=home_dir,
            os_=os_,
        )
    finally:
        rt.close()
    claude_receipt = _bound_receipt("claude-code", "2.1.0", digest_bytes(b"claude-v1"), ws)
    codex_receipt = _bound_receipt("codex", "0.55.0", digest_bytes(b"codex-v1"), ws)

    healthy_dh: dict[str, JsonValue] = {
        "ready": True,
        "store_id": rep.store_id,
        "writer_epoch": live_writer_epoch,
        "schema_version": 5,
        "policy_schema_version": 4,
        "degraded_codes": [],
        "doctor_run_id": new_id(),
        "age_s": 1.0,
        "job_id": None,
    }

    def _healthy_native_snap(_r: Path) -> CaptureDoctorSnapshot:
        return CaptureDoctorSnapshot(
            harnesses=(
                _ReceiptHarness(
                    harness_id="claude-code",
                    last_event_at="2026-11-21T19:20:00Z",
                    active_layer="hook",
                    outbox_backlog=0,
                    capture_gaps=0,
                    dead_letters=0,
                    receipt_kind="native",
                    receipt=claude_receipt,
                ),
                _ReceiptHarness(
                    harness_id="codex",
                    last_event_at="2026-11-21T19:20:00Z",
                    active_layer="hook",
                    outbox_backlog=0,
                    capture_gaps=0,
                    dead_letters=0,
                    receipt_kind="native",
                    receipt=codex_receipt,
                ),
            ),
            available=True,
        )

    healthy_probe = sp2.build_sp2_capture_probe(_healthy_native_snap, require_native_receipts=True)
    m1_ok = sp2.run_m1_handover_probe(
        rep.daemon_config_path,
        checkout_root=checkout,
        os_=os_,
        capture_probe=healthy_probe,
        deep_health=healthy_dh,
        require_native_receipts=True,
    )
    assert m1_ok["m1_ready"] is True

    # 4a) host_invalidated=True on CaptureHarnessDoctorStatus invalidates capture.sp2_probes & M1.
    inv_probe = sp2.build_sp2_capture_probe(
        lambda _r: CaptureDoctorSnapshot(
            harnesses=(
                _ReceiptHarness(
                    harness_id="claude-code",
                    last_event_at="2026-11-21T19:20:00Z",
                    active_layer="hook",
                    outbox_backlog=0,
                    capture_gaps=0,
                    dead_letters=0,
                    receipt_kind="native",
                    host_invalidated=True,
                    receipt=claude_receipt,
                ),
            ),
            available=True,
        ),
        require_native_receipts=True,
    )
    assert inv_probe.probe_capture(cfg.data_root).status in {"WARN", "FAIL"}
    m1_host_inv = sp2.run_m1_handover_probe(
        rep.daemon_config_path,
        checkout_root=checkout,
        os_=os_,
        capture_probe=inv_probe,
        deep_health=healthy_dh,
        require_native_receipts=True,
    )
    assert m1_host_inv["m1_ready"] is False
    _assert_surface_shape(m1_host_inv, sp2.M1_SURFACE_CAPTURE, allowed_statuses={"WARN", "FAIL"})

    # 4b & 4c) PolicyStore Layer-2 UNKNOWN and UNSUPPORTED DB states drop terminal_channel_eligible & invalidate M1.
    for bad_state in (Layer2State.UNKNOWN, Layer2State.UNSUPPORTED):
        rt_l2 = reopen_kernel_job_runtime(cfg.data_root, rep.store_id, os_)
        try:
            rt_l2.policy.set_layer2_state(
                harness_id="claude-code",
                host_version="2.2.0",
                config_digest=digest_bytes(f"cfg-{bad_state.value}".encode()),
                state=bad_state,
            )
            assert rt_l2.policy.terminal_channel_eligible(machine_id=MACHINE_ID) is False
        finally:
            rt_l2.close()

        rep_l2 = doctor_entry.run_doctor(
            rep.daemon_config_path, checkout_root=checkout, os_=os_, capture_probe=healthy_probe
        )
        assert rep_l2.terminal_channel_eligible is False
        assert _check_obj_by(rep_l2, "harness", "layer2").status in {"WARN", "FAIL"}

        m1_l2 = sp2.run_m1_handover_probe(
            rep.daemon_config_path,
            checkout_root=checkout,
            os_=os_,
            capture_probe=healthy_probe,
            deep_health=healthy_dh,
            require_native_receipts=True,
        )
        assert m1_l2["m1_ready"] is False
        _assert_surface_shape(m1_l2, sp2.M1_SURFACE_LAYER2, allowed_statuses={"WARN", "FAIL"})

    # 4d) Missing harness credential: re-verify claude-code Layer-2, then revoke claude-code & codex creds.
    rt_rev1 = reopen_kernel_job_runtime(cfg.data_root, rep.store_id, os_)
    try:
        rt_rev1.policy.set_layer2_state(
            harness_id="claude-code",
            host_version="2.2.0",
            config_digest=digest_bytes(b"cfg-reverified"),
            state=Layer2State.VERIFIED,
        )
        rt_rev1.policy.record_authorized_revocation(
            cred_claude.credential_id,
            make_bootstrap_auth(
                store_id=rep.store_id,
                owner_id=OWNER_DAN,
                action="credential_revoke",
                subject_id=cred_claude.credential_id,
                trust_generation=rt_rev1.policy.trust_generation(),
                expires_at=clock.now() + timedelta(hours=1),
            ),
        )
        rt_rev1.store.reconcile_policy()
    finally:
        rt_rev1.close()

    snap_miss1 = read_doctor_snapshot(cfg.data_root, os_, checkout_root=checkout, capture_probe=healthy_probe)
    assert snap_miss1.identity_stats is not None
    assert "claude-code" in snap_miss1.identity_stats.missing_harness_credentials
    rep_miss1 = inspect_doctor_snapshot(snap_miss1)
    ident_chk1 = _check_obj_by(rep_miss1, "identity", "credentials")
    assert ident_chk1.status in {"WARN", "FAIL"} and ident_chk1.reason == "missing_harness_credentials"

    m1_miss1 = sp2.run_m1_handover_probe(
        rep.daemon_config_path,
        checkout_root=checkout,
        os_=os_,
        capture_probe=healthy_probe,
        deep_health=healthy_dh,
        require_native_receipts=True,
    )
    assert m1_miss1["m1_ready"] is False
    _assert_surface_shape(m1_miss1, sp2.M1_SURFACE_LAYER2, allowed_statuses={"WARN", "FAIL"})

    # Now also revoke codex credential -> zero active non-CLI credentials, terminal_channel_eligible=False.
    rt_rev2 = reopen_kernel_job_runtime(cfg.data_root, rep.store_id, os_)
    try:
        rt_rev2.policy.record_authorized_revocation(
            cred_codex.credential_id,
            make_bootstrap_auth(
                store_id=rep.store_id,
                owner_id=OWNER_DAN,
                action="credential_revoke",
                subject_id=cred_codex.credential_id,
                trust_generation=rt_rev2.policy.trust_generation(),
                expires_at=clock.now() + timedelta(hours=1),
            ),
        )
        rt_rev2.store.reconcile_policy()
        assert rt_rev2.policy.terminal_channel_eligible(machine_id=MACHINE_ID) is False
    finally:
        rt_rev2.close()

    rep_miss2 = doctor_entry.run_doctor(
        rep.daemon_config_path, checkout_root=checkout, os_=os_, capture_probe=healthy_probe
    )
    assert rep_miss2.terminal_channel_eligible is False
    assert _check_obj_by(rep_miss2, "identity", "credentials").status in {"WARN", "FAIL"}
    m1_miss2 = sp2.run_m1_handover_probe(
        rep.daemon_config_path,
        checkout_root=checkout,
        os_=os_,
        capture_probe=healthy_probe,
        deep_health=healthy_dh,
        require_native_receipts=True,
    )
    assert m1_miss2["m1_ready"] is False
    _assert_surface_shape(m1_miss2, sp2.M1_SURFACE_LAYER2, allowed_statuses={"WARN", "FAIL"})


# ---------------------------------------------------------------------------
# 6. Case 5: Incomplete Journal, Drift, Perms, Deep Health & Owner/Checkout Isolation
# ---------------------------------------------------------------------------


def test_m1_incomplete_journal_drift_permissions_deep_health_and_cross_owner_checkout_isolation(
    trusted_tmp: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    """Permissions, deep_health gates, ApplyJournal/drift/pending_proposals, and multi-owner/checkout isolation."""
    sp2 = _sp2_mod()
    clock = FakeClock(_base_utc_now())
    real_mono = os_adapters().monotonic
    base_os = os_adapters(clock=clock, monotonic=real_mono)

    rep, cfg, _priv_dan, ca_pem, leaf_sha256, cli_dan_token, os_ = _init_store_with_tls(
        trusted_tmp / "isolation", clock, owner_id=OWNER_DAN, os_=base_os
    )
    root = DataRoot.at(cfg.data_root)
    checkout_a = trusted_tmp / "checkout-a"
    checkout_b = trusted_tmp / "checkout-b"
    home_dir = trusted_tmp / "home"
    for d in (checkout_a, checkout_b, home_dir):
        d.mkdir(parents=True)
        os_.permissions.secure_directory(d)

    rt = reopen_kernel_job_runtime(cfg.data_root, rep.store_id, os_)
    live_writer_epoch = rt.lease.epoch  # writer generation a live get_health(deep=true) reports
    try:
        cred_claude_a = seed_principal_and_credential(
            rt.policy, owner_id=OWNER_DAN, harness_id="claude-code", machine_id=MACHINE_ID
        )
        cred_codex_b = seed_principal_and_credential(
            rt.policy, owner_id=OWNER_BOB, harness_id="codex", machine_id=MACHINE_ID
        )
        cli_bob = seed_principal_and_credential(
            rt.policy, owner_id=OWNER_BOB, harness_id=CLI_HARNESS_ID, machine_id=MACHINE_ID
        )
        ws_a = register_workspace_direct(
            rt, clock, cred_claude_a.principal, alias="ws-a", checkout_dir=checkout_a, remote="https://ex/a.git"
        )
        ws_b = register_workspace_direct(
            rt, clock, cred_codex_b.principal, alias="ws-b", checkout_dir=checkout_b, remote="https://ex/b.git"
        )
        rt.policy.set_layer2_state(
            harness_id="claude-code",
            host_version="2.1.0",
            config_digest=digest_bytes(b"claude-iso"),
            state=Layer2State.VERIFIED,
        )
        rt.policy.set_layer2_state(
            harness_id="codex",
            host_version="0.55.0",
            config_digest=digest_bytes(b"codex-iso"),
            state=Layer2State.VERIFIED,
        )
        # Seed clean bootstrap on checkout_a (owned by dan), and drifted bootstrap on checkout_b (owned by dan).
        _apply_clean_bootstrap(
            rt,
            store_id=rep.store_id,
            signer_id=rep.signer.signer_id,
            owner_id=OWNER_DAN,
            checkout=checkout_a,
            home_dir=home_dir,
            os_=os_,
            rel_path="CLAUDE.md",
            slice_id="s-a",
            body="Clean A\n",
        )
        _apply_clean_bootstrap(
            rt,
            store_id=rep.store_id,
            signer_id=rep.signer.signer_id,
            owner_id=OWNER_DAN,
            checkout=checkout_b,
            home_dir=home_dir,
            os_=os_,
            rel_path="CLAUDE.md",
            slice_id="s-b",
            body="Managed B\n",
        )
        # Out-of-band edit on checkout_b creates bootstrap drift strictly on checkout_b.
        (checkout_b / "CLAUDE.md").write_text("# Drifted B\n", encoding="utf-8")
    finally:
        rt.close()

    def _healthy_native_snap_for(ws: Any) -> Callable[[Path], CaptureDoctorSnapshot]:
        def _snap(_r: Path) -> CaptureDoctorSnapshot:
            return CaptureDoctorSnapshot(
                harnesses=(
                    _ReceiptHarness(
                        harness_id="claude-code",
                        last_event_at="2026-11-21T19:30:00Z",
                        active_layer="hook",
                        outbox_backlog=0,
                        capture_gaps=0,
                        dead_letters=0,
                        receipt_kind="native",
                        receipt=_bound_receipt("claude-code", "2.1.0", digest_bytes(b"claude-iso"), ws),
                    ),
                    _ReceiptHarness(
                        harness_id="codex",
                        last_event_at="2026-11-21T19:30:00Z",
                        active_layer="hook",
                        outbox_backlog=0,
                        capture_gaps=0,
                        dead_letters=0,
                        receipt_kind="native",
                        receipt=_bound_receipt("codex", "0.55.0", digest_bytes(b"codex-iso"), ws),
                    ),
                ),
                available=True,
            )

        return _snap

    healthy_probe = sp2.build_sp2_capture_probe(_healthy_native_snap_for(ws_a), require_native_receipts=True)
    # Receipts bound to checkout_b's own scope, so m1_b stays negative for checkout_b's drift, not a scope mismatch.
    probe_b = sp2.build_sp2_capture_probe(_healthy_native_snap_for(ws_b), require_native_receipts=True)
    healthy_dh: dict[str, JsonValue] = {
        "ready": True,
        "store_id": rep.store_id,
        "writer_epoch": live_writer_epoch,
        "schema_version": 5,
        "policy_schema_version": 4,
        "degraded_codes": [],
        "doctor_run_id": new_id(),
        "age_s": 2.0,
        "job_id": None,
    }

    # Checkout A is clean; Checkout B has bootstrap_drifts.
    m1_a = sp2.run_m1_handover_probe(
        rep.daemon_config_path,
        checkout_root=checkout_a,
        os_=os_,
        capture_probe=healthy_probe,
        deep_health=healthy_dh,
        require_native_receipts=True,
    )
    assert m1_a["m1_ready"] is True

    m1_b = sp2.run_m1_handover_probe(
        rep.daemon_config_path,
        checkout_root=checkout_b,
        os_=os_,
        capture_probe=probe_b,
        deep_health=healthy_dh,
        require_native_receipts=True,
    )
    assert m1_b["m1_ready"] is False
    _assert_surface_shape(m1_b, sp2.M1_SURFACE_BOOTSTRAP_DRIFT, allowed_statuses={"WARN", "FAIL"})

    # Test deep_health invalidation gates (missing, not ready, pending job, stale >15m, degraded_codes, overall_status).
    bad_dh_cases: tuple[dict[str, JsonValue] | None, ...] = (
        None,
        {**healthy_dh, "ready": False},
        {**healthy_dh, "doctor_run_id": None, "job_id": new_id()},
        {**healthy_dh, "age_s": 905.0},
        {**healthy_dh, "degraded_codes": ["capture.probe"]},
        {**healthy_dh, "overall_status": "warn"},
    )
    for bad_dh in bad_dh_cases:
        m1_bad_dh = sp2.run_m1_handover_probe(
            rep.daemon_config_path,
            checkout_root=checkout_a,
            os_=os_,
            capture_probe=healthy_probe,
            deep_health=bad_dh,
            require_native_receipts=True,
        )
        assert m1_bad_dh["m1_ready"] is False
        _assert_surface_shape(m1_bad_dh, sp2.M1_SURFACE_DEEP_HEALTH, allowed_statuses={"WARN", "FAIL"})

    # Test insecure permissions (§20.28) -> permissions.data_root FAIL, m1_ready=False, then repair cleanly.
    _grant_wide_access(root.store_dir)
    m1_perm = sp2.run_m1_handover_probe(
        rep.daemon_config_path,
        checkout_root=checkout_a,
        os_=os_,
        capture_probe=healthy_probe,
        deep_health=healthy_dh,
        require_native_receipts=True,
    )
    assert m1_perm["m1_ready"] is False
    _assert_surface_shape(m1_perm, sp2.M1_SURFACE_PERMISSIONS, allowed_statuses={"FAIL"})
    assert doctor_entry.run_doctor_cli(
        ["doctor", "--offline", "--fix", "--config", str(rep.daemon_config_path), "--json"], os_=os_
    ) == 1
    cap = capfd.readouterr()
    assert "daemon_unavailable" in cap.out or "daemon_unavailable" in cap.err
    os_.permissions.secure_directory(root.store_dir)

    # Live daemon multi-owner & cross-checkout isolation checks.
    prof_dir = trusted_tmp / "profiles"
    ca_file = write_ca_file(prof_dir / "ca.pem", ca_pem)
    cli_dan_cred = write_credential_file(prof_dir / "cli-dan.cred", cli_dan_token)
    cli_ws_a_profile, _ = write_client_profile_file(
        prof_dir / "cli-ws-a.profile.json",
        endpoint_path=root.endpoint_path,
        expected_store_id=rep.store_id,
        ca_file=ca_file,
        leaf_cert_sha256=leaf_sha256,
        credential_file=cli_dan_cred,
        workspace={
            "alias": ws_a.alias,
            "checkout_path": str(checkout_a),
            "expected_workspace_id": ws_a.repo_id,
            "expected_checkout_id": ws_a.checkout_id,
        },
    )

    with _running_serve_config(
        rep.daemon_config_path, os_=os_, clock=clock, mono=real_mono, capture_probe=healthy_probe
    ) as (ready, loop):
        assert loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        target = LoopbackTarget(
            endpoint=ready.endpoint,
            expected_store_id=rep.store_id,
            ca_pem=ca_pem,
            leaf_cert_sha256=leaf_sha256,
        )
        client = LoopbackClient(monotonic_ns=real_mono.monotonic_ns)

        # Dan's deep health vs Bob's deep health (owner isolation + wrong-checkout scope rejection).
        dan_h = _validate_get_health_envelope(
            client.call(
                target,
                ToolCommand(
                    "get_health",
                    {"schema_version": "2.0", "deep": True, "idempotency_key": "idem_iso_dan_health_01"},
                    token=cred_claude_a.token,
                    selected_scope=Scope(ws_a.repo_id, ws_a.checkout_id),
                ),
                deadline_ns=real_mono.monotonic_ns() + TOTAL_REQUEST_BUDGET_NS,
            )
        )
        assert dan_h["ok"] is True
        dan_run_id = cast(str, cast(dict[str, Any], dan_h["data"])["doctor_run_id"])
        assert isinstance(dan_run_id, str) and dan_run_id

        bob_h1 = _validate_get_health_envelope(
            client.call(
                target,
                ToolCommand(
                    "get_health",
                    {"schema_version": "2.0", "deep": True, "idempotency_key": "idem_iso_bob_health_01"},
                    token=cred_codex_b.token,
                    selected_scope=Scope(ws_b.repo_id, ws_b.checkout_id),
                ),
                deadline_ns=real_mono.monotonic_ns() + TOTAL_REQUEST_BUDGET_NS,
            )
        )
        assert bob_h1["ok"] is True
        bob_job_id = cast(str, cast(dict[str, Any], bob_h1["data"])["job_id"])
        assert isinstance(bob_job_id, str) and bob_job_id
        assert cast(dict[str, Any], bob_h1["data"]).get("doctor_run_id") is None

        # Dan cannot inspect Bob's system.doctor job via get_job.
        cross_job = client.call(
            target,
            ToolCommand("get_job", {"schema_version": "2.0", "job_id": bob_job_id}, token=cred_claude_a.token),
            deadline_ns=real_mono.monotonic_ns() + TOTAL_REQUEST_BUDGET_NS,
        )
        assert cross_job == {"ok": False, "error": {"code": "not_found", "message": "not found"}}

        # Dan's harness principal cannot use Bob's checkout scope or partial Scope(repo, None).
        for forbidden_scope in (Scope(ws_b.repo_id, ws_b.checkout_id), Scope(ws_a.repo_id, None)):
            denied = _validate_get_health_envelope(
                client.call(
                    target,
                    ToolCommand(
                        "get_health",
                        {"schema_version": "2.0", "deep": True, "idempotency_key": f"idem_forbid_{new_id()[:12]}"},
                        token=cred_claude_a.token,
                        selected_scope=forbidden_scope,
                    ),
                    deadline_ns=real_mono.monotonic_ns() + TOTAL_REQUEST_BUDGET_NS,
                )
            )
            assert denied == {"ok": False, "error": {"code": "not_found", "message": "not found"}}

        assert loop.wait_doctor_settled(timeout=BOUND_WAIT_S)

        # Operator reports partitioned by owner_id and scoped cleanly per checkout_root.
        op_dan = _call_operator_json(
            ready.endpoint,
            store_id=rep.store_id,
            ca_pem=ca_pem,
            leaf_sha256=leaf_sha256,
            token=cli_dan_token,
            path="/v2/operator/doctor/report",
            body={"wait_timeout_ms": 5000, "checkout_root": str(checkout_a)},
            monotonic_ns=real_mono.monotonic_ns,
        )
        op_bob = _call_operator_json(
            ready.endpoint,
            store_id=rep.store_id,
            ca_pem=ca_pem,
            leaf_sha256=leaf_sha256,
            token=cli_bob.token,
            path="/v2/operator/doctor/report",
            body={"wait_timeout_ms": 5000, "checkout_root": str(checkout_b)},
            monotonic_ns=real_mono.monotonic_ns,
        )
        assert op_dan["ok"] is True and op_bob["ok"] is True
        assert op_dan["data"]["doctor_run_id"] != op_bob["data"]["doctor_run_id"]
        assert op_dan["data"]["job_id"] != op_bob["data"]["job_id"]
        assert op_dan["data"]["bootstrap_drifts"] == [] and op_dan["data"]["overall_status"] == "pass"
        assert len(op_bob["data"]["bootstrap_drifts"]) == 1 and op_bob["data"]["overall_status"] == "warn"

        with _ro_db(root.store_db) as conn:
            job_owners = {
                str(jid): str(own)
                for jid, own in conn.execute(
                    "SELECT job_id, owner_id FROM p_jobs_state WHERE kind = 'system.doctor'"
                ).fetchall()
            }
            assert job_owners[str(op_dan["data"]["job_id"])] == OWNER_DAN
            assert job_owners[str(op_bob["data"]["job_id"])] == OWNER_BOB

        # Workspace-bound CLI profile for checkout_a rejects --checkout checkout_b.
        capfd.readouterr()
        rc_mismatch = doctor_entry.run_doctor_cli(
            ["doctor", "--profile", str(cli_ws_a_profile), "--checkout", str(checkout_b), "--json"], os_=os_
        )
        assert rc_mismatch == 1
        err_mismatch = json.loads(capfd.readouterr().out)
        assert err_mismatch == {"ok": False, "error": {"code": "identity_mismatch", "message": "identity mismatch"}}

        # Non-CLI harness tokens are refused on operator doctor endpoints.
        for harness_tok in (cred_claude_a.token, cred_codex_b.token):
            for op_path in ("/v2/operator/doctor/report", "/v2/operator/doctor/fix"):
                refused = _call_operator_json(
                    ready.endpoint,
                    store_id=rep.store_id,
                    ca_pem=ca_pem,
                    leaf_sha256=leaf_sha256,
                    token=harness_tok,
                    path=op_path,
                    body={},
                    monotonic_ns=real_mono.monotonic_ns,
                )
                assert refused["ok"] is False
                assert refused["error"]["code"] == ErrorCode.IDENTITY_MISMATCH.value

    # Test pending_proposals & incomplete ApplyJournal on checkout_a (and direct evaluate_m1_surfaces checks).
    rt2 = reopen_kernel_job_runtime(cfg.data_root, rep.store_id, os_)
    try:
        svc = ReviewApplyService(
            StoreProposalAdapter(rt2.store, os_),
            PolicyApplyAuthority(rt2.policy),
            os_,
            data_root=cfg.data_root,
            home_dir=home_dir,
            config_merger=SharedConfigMergerAdapter(),
        )
        cur_a = (checkout_a / "CLAUDE.md").read_text(encoding="utf-8")
        m_pend = merge_markdown_block(cur_a, slice_id="s-pend", block_body="Pending\n", expected_slice_digest=None)
        p_pend = svc.create_proposal(
            owner_id=OWNER_DAN,
            kind="bootstrap",
            reason="pending gate check",
            resources=(RiskResource("c2"),),
            targets=(
                TargetWriteInput(
                    checkout_a,
                    "CLAUDE.md",
                    m_pend.updated_text.encode("utf-8"),
                    ManagedFormat.MARKDOWN,
                    "s-pend",
                    m_pend.slice_digest,
                ),
            ),
        )
    finally:
        rt2.close()

    m1_pend = sp2.run_m1_handover_probe(
        rep.daemon_config_path,
        checkout_root=checkout_a,
        os_=os_,
        capture_probe=healthy_probe,
        deep_health=healthy_dh,
        require_native_receipts=True,
    )
    assert m1_pend["m1_ready"] is False
    _assert_surface_shape(m1_pend, sp2.M1_SURFACE_BOOTSTRAP_DRIFT, allowed_statuses={"WARN", "FAIL"})

    # Approve and interrupt multi-target apply to create an incomplete ApplyJournal on checkout_a.
    (checkout_a / "AGENTS.md").write_text("# Agents Base\n", encoding="utf-8")
    rt3 = reopen_kernel_job_runtime(cfg.data_root, rep.store_id, os_)
    try:
        svc3 = ReviewApplyService(
            StoreProposalAdapter(rt3.store, os_),
            PolicyApplyAuthority(rt3.policy),
            os_,
            data_root=cfg.data_root,
            home_dir=home_dir,
            config_merger=SharedConfigMergerAdapter(),
        )
        m_int = merge_markdown_block(
            (checkout_a / "CLAUDE.md").read_text(encoding="utf-8"),
            slice_id="s-int",
            block_body="Interrupted\n",
            expected_slice_digest=None,
        )
        agents_bytes = b"# Interrupted Agents\n"
        p_int = svc3.create_proposal(
            owner_id=OWNER_DAN,
            kind="bootstrap",
            reason="incomplete journal check",
            resources=(RiskResource("c2"),),
            targets=(
                TargetWriteInput(
                    checkout_a,
                    "CLAUDE.md",
                    m_int.updated_text.encode("utf-8"),
                    ManagedFormat.MARKDOWN,
                    "s-int",
                    m_int.slice_digest,
                ),
                TargetWriteInput(
                    checkout_a,
                    "AGENTS.md",
                    agents_bytes,
                    ManagedFormat.RAW,
                    "raw-agents",
                    digest_bytes(agents_bytes),
                ),
            ),
        )
        # Reject p_pend first so incomplete_journals alone triggers failure on next check.
        n_rej = rt3.policy.issue_nonce(
            action=ApprovalAction.REJECT, subject_id=p_pend.proposal_id, risk_level=p_pend.risk_level
        )
        svc3.reject_proposal(
            p_pend.proposal_id,
            approval=ApprovalMessage(
                store_id=rep.store_id,
                owner_id=OWNER_DAN,
                trust_generation=rt3.policy.trust_generation(),
                action=ApprovalAction.REJECT,
                subject_id=p_pend.proposal_id,
                subject_revision=p_pend.subject_revision,
                resource_digests=p_pend.resource_digests,
                target_files=p_pend.to_target_files(),
                risk_level=p_pend.risk_level,
                risk_policy_version=RISK_POLICY_VERSION,
                recovery_scope=RecoveryScope.NONE,
                nonce=n_rej.nonce,
                expires_at=n_rej.expires_at,
            ),
            signer_id=rep.signer.signer_id,
            channel=ApprovalChannel.SSH_KEY,
        )
        n_ap2 = rt3.policy.issue_nonce(
            action=ApprovalAction.APPROVE, subject_id=p_int.proposal_id, risk_level=p_int.risk_level
        )
        svc3.approve_proposal(
            p_int.proposal_id,
            approval=ApprovalMessage(
                store_id=rep.store_id,
                owner_id=OWNER_DAN,
                trust_generation=rt3.policy.trust_generation(),
                action=ApprovalAction.APPROVE,
                subject_id=p_int.proposal_id,
                subject_revision=p_int.subject_revision,
                resource_digests=p_int.resource_digests,
                target_files=p_int.to_target_files(),
                risk_level=p_int.risk_level,
                risk_policy_version=RISK_POLICY_VERSION,
                recovery_scope=RecoveryScope.NONE,
                nonce=n_ap2.nonce,
                expires_at=n_ap2.expires_at,
            ),
            signer_id=rep.signer.signer_id,
            channel=ApprovalChannel.SSH_KEY,
        )
        n_run2 = rt3.policy.issue_nonce(
            action=ApprovalAction.APPLY, subject_id=p_int.proposal_id, risk_level=p_int.risk_level
        )
        pub = cast(NoReplacePublisher, os_.publisher)
        orig_noreplace = pub.publish_no_replace
        hits = [0]

        def _interrupt_second(staging: Path, final: Path) -> None:
            hits[0] += 1
            if hits[0] == 2:
                raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "interrupted before target 2")
            orig_noreplace(staging, final)

        monkeypatch.setattr(pub, "publish_no_replace", _interrupt_second)
        with pytest.raises(BrainError):
            svc3.apply_proposal(
                p_int.proposal_id,
                approval=ApprovalMessage(
                    store_id=rep.store_id,
                    owner_id=OWNER_DAN,
                    trust_generation=rt3.policy.trust_generation(),
                    action=ApprovalAction.APPLY,
                    subject_id=p_int.proposal_id,
                    subject_revision=p_int.subject_revision,
                    resource_digests=p_int.resource_digests,
                    target_files=p_int.to_target_files(),
                    risk_level=p_int.risk_level,
                    risk_policy_version=RISK_POLICY_VERSION,
                    recovery_scope=RecoveryScope.CONTINUE,
                    nonce=n_run2.nonce,
                    expires_at=n_run2.expires_at,
                ),
                signer_id=rep.signer.signer_id,
                channel=ApprovalChannel.SSH_KEY,
            )
        monkeypatch.undo()
    finally:
        rt3.close()

    rep_j = doctor_entry.run_doctor(
        rep.daemon_config_path, checkout_root=checkout_a, os_=os_, capture_probe=healthy_probe
    )
    assert len(rep_j.incomplete_journals) >= 1
    m1_j = sp2.run_m1_handover_probe(
        rep.daemon_config_path,
        checkout_root=checkout_a,
        os_=os_,
        capture_probe=healthy_probe,
        deep_health=healthy_dh,
        require_native_receipts=True,
    )
    assert m1_j["m1_ready"] is False
    _assert_surface_shape(m1_j, sp2.M1_SURFACE_BOOTSTRAP_DRIFT, allowed_statuses={"WARN", "FAIL"})

    # Also verify evaluate_m1_surfaces directly isolates each synthetic field (journal/drift/pending_proposals).
    clean_snap = read_doctor_snapshot(cfg.data_root, os_, checkout_root=checkout_a, capture_probe=healthy_probe)
    isolated_clean_snap = replace(
        clean_snap,
        pending_proposals=(),
        incomplete_journals=(),
        bootstrap_drifts=(),
        active_turn_intents=(),
    )
    for variant in (
        replace(
            isolated_clean_snap,
            incomplete_journals=(
                DoctorJournalInfo(
                    journal_id=new_id(),
                    proposal_id=new_id(),
                    direction="apply",
                    status="partially_applied",
                    grant_id=new_id(),
                    updated_at="2026-11-21T19:30:00Z",
                ),
            ),
        ),
        replace(
            isolated_clean_snap,
            pending_proposals=(
                DoctorProposalSummary(
                    proposal_id=new_id(),
                    status="pending",
                    kind="bootstrap",
                    active_journal_id=None,
                ),
            ),
        ),
        replace(
            isolated_clean_snap,
            bootstrap_drifts=(
                DoctorBootstrapDrift(
                    proposal_id=new_id(),
                    target_root=str(checkout_a),
                    rel_path="CLAUDE.md",
                    reason="content_drift",
                    current_digest=digest_bytes(b"a"),
                    expected_digest=digest_bytes(b"b"),
                ),
            ),
        ),
    ):
        v_rep = inspect_doctor_snapshot(variant)
        v_m1 = sp2.evaluate_m1_surfaces(
            v_rep,
            variant,
            capture_snapshot=_healthy_native_snap_for(ws_a)(cfg.data_root),
            deep_health=healthy_dh,
            require_native_receipts=True,
        )
        assert v_m1["m1_ready"] is False
        _assert_surface_shape(v_m1, sp2.M1_SURFACE_BOOTSTRAP_DRIFT, allowed_statuses={"WARN", "FAIL"})


# ---------------------------------------------------------------------------
# 7. Case 6: Outbox Replay via doctor --fix, Quarantine/Tombstone & Zero Secret Leak
# ---------------------------------------------------------------------------


def test_m1_outbox_replay_gap_isolation_idempotency_quarantine_and_zero_secret_leak(
    trusted_tmp: Path,
) -> None:
    """Outbox replay preserves gap/contiguous ACK separation & dedup, enforces quarantine/tombstones, 0 leaks."""
    sp2 = _sp2_mod()
    clock = FakeClock(_base_utc_now())
    real_mono = os_adapters().monotonic
    base_os = os_adapters(clock=clock, monotonic=real_mono)

    rep, cfg, _priv, ca_pem, leaf_sha256, cli_token, os_ = _init_store_with_tls(
        trusted_tmp / "outbox-priv", clock, os_=base_os
    )
    root = DataRoot.at(cfg.data_root)
    checkout = trusted_tmp / "co"
    home_dir = trusted_tmp / "home"
    for d in (checkout, home_dir):
        d.mkdir()
        os_.permissions.secure_directory(d)

    rt = reopen_kernel_job_runtime(cfg.data_root, rep.store_id, os_)
    try:
        cred_claude = seed_principal_and_credential(
            rt.policy, owner_id=OWNER_DAN, harness_id="claude-code", machine_id=MACHINE_ID
        )
        rt.policy.set_layer2_state(
            harness_id="claude-code",
            host_version="2.1.0",
            config_digest=digest_bytes(b"claude-outbox"),
            state=Layer2State.VERIFIED,
        )
        ws = register_workspace_direct(
            rt, clock, cred_claude.principal, alias="ws-outbox", checkout_dir=checkout, remote="https://ex/outbox.git"
        )
        _apply_clean_bootstrap(
            rt,
            store_id=rep.store_id,
            signer_id=rep.signer.signer_id,
            owner_id=OWNER_DAN,
            checkout=checkout,
            home_dir=home_dir,
            os_=os_,
        )
    finally:
        rt.close()
    claude_receipt = _bound_receipt("claude-code", "2.1.0", digest_bytes(b"claude-outbox"), ws)

    # Stateful SP2 outbox simulation:
    # Phase 0: Events {1, 3} + CaptureGap(4) ready; Event 2 delayed on spool -> contiguous=1, gap_acked=(4,), pending=1.
    # Phase 1: Idempotent retry while Event 2 still pending -> noop, contiguous=1, Event 2 preserved (pending=1).
    # Phase 2: Event 2 becomes deliverable -> applied, Events {1, 3} deduped, contiguous=3, pending=0, capture healthy.
    # Phase 3: Idempotent retry after clean -> noop, contiguous=3, pending=0.
    spool_state: dict[str, Any] = {
        "committed": set(),
        "acked_gaps": set(),
        "event2_ready": False,
        "backlog": 3,
        "gaps": 1,
    }

    def _outbox_replay_handler(_now: datetime) -> OutboxReplayResult:
        committed = cast(set[int], spool_state["committed"])
        acked_gaps = cast(set[int], spool_state["acked_gaps"])
        if not committed:
            committed.update({1, 3})
            acked_gaps.add(4)
            spool_state["backlog"] = 1
            spool_state["gaps"] = 1
            return OutboxReplayResult(
                status="applied",
                replayed_events=2,
                committed_event_sequences=(1, 3),
                contiguous_event_acked_through=1,
                acked_producer_gap_sequences=(4,),
                pending_remaining=1,
                detail="committed seqs [1, 3]; producer gap [4]; event 2 pending",
            )
        if not spool_state["event2_ready"]:
            return OutboxReplayResult(
                status="noop",
                replayed_events=0,
                committed_event_sequences=tuple(sorted(committed)),
                contiguous_event_acked_through=1,
                acked_producer_gap_sequences=tuple(sorted(acked_gaps)),
                pending_remaining=1,
                detail="idempotent retry: seqs [1, 3] deduplicated; event 2 still pending",
            )
        if 2 not in committed:
            committed.add(2)
            spool_state["backlog"] = 0
            spool_state["gaps"] = 0
            return OutboxReplayResult(
                status="applied",
                replayed_events=1,
                committed_event_sequences=tuple(sorted(committed)),
                contiguous_event_acked_through=3,
                acked_producer_gap_sequences=tuple(sorted(acked_gaps)),
                pending_remaining=0,
                detail="late event 2 committed; contiguous acked through 3",
            )
        return OutboxReplayResult(
            status="noop",
            replayed_events=0,
            committed_event_sequences=tuple(sorted(committed)),
            contiguous_event_acked_through=3,
            acked_producer_gap_sequences=tuple(sorted(acked_gaps)),
            pending_remaining=0,
            detail="idempotent retry: all outbox events drained",
        )

    def _live_capture_snap(_root: Path) -> CaptureDoctorSnapshot:
        return CaptureDoctorSnapshot(
            harnesses=(
                _ReceiptHarness(
                    harness_id="claude-code",
                    last_event_at="2026-11-21T19:40:00Z",
                    active_layer="hook",
                    outbox_backlog=int(spool_state["backlog"]),
                    capture_gaps=int(spool_state["gaps"]),
                    dead_letters=0,
                    receipt_kind="native",
                    receipt=claude_receipt,
                ),
            ),
            available=True,
        )

    outbox_port = _StubOutboxReplay(_outbox_replay_handler)
    probe = sp2.build_sp2_capture_probe(_live_capture_snap, require_native_receipts=True)
    scanner = KernelPrivacyScanner()

    with _running_serve_config(
        rep.daemon_config_path,
        os_=os_,
        clock=clock,
        mono=real_mono,
        capture_probe=probe,
        outbox_replay=outbox_port,
    ) as (ready, loop):
        assert loop.wait_doctor_settled(timeout=BOUND_WAIT_S)

        target = LoopbackTarget(
            endpoint=ready.endpoint,
            expected_store_id=rep.store_id,
            ca_pem=ca_pem,
            leaf_cert_sha256=leaf_sha256,
        )
        client = LoopbackClient(monotonic_ns=real_mono.monotonic_ns)

        # Call 1: out-of-order replay {1, 3} + producer gap {4}, Event 2 still pending.
        fix1 = _call_operator_json(
            ready.endpoint,
            store_id=rep.store_id,
            ca_pem=ca_pem,
            leaf_sha256=leaf_sha256,
            token=cli_token,
            path="/v2/operator/doctor/fix",
            body={"actions": ["replay_outbox"], "checkout_root": str(checkout)},
            monotonic_ns=real_mono.monotonic_ns,
        )
        assert fix1.get("ok") is True, fix1
        act1 = cast(dict[str, Any], fix1["data"]["fix"]["actions"][0])
        assert act1["action"] == "replay_outbox"
        assert act1["status"] == "applied"
        assert act1["changed"] == 2
        assert act1["committed_event_sequences"] == [1, 3]
        assert act1["contiguous_event_acked_through"] == 1
        assert act1["acked_producer_gap_sequences"] == [4]
        assert act1["pending_remaining"] == 1
        assert _check_dict_by(
            cast(list[Mapping[str, Any]], fix1["data"]["fix"]["rechecked_checks"]), "capture", "probe"
        )["status"] in {"WARN", "FAIL"}

        # Call 2: idempotent retry while Event 2 is still undeliverable -> noop & Event 2 NOT dropped.
        fix2 = _call_operator_json(
            ready.endpoint,
            store_id=rep.store_id,
            ca_pem=ca_pem,
            leaf_sha256=leaf_sha256,
            token=cli_token,
            path="/v2/operator/doctor/fix",
            body={"actions": ["replay_outbox"], "checkout_root": str(checkout)},
            monotonic_ns=real_mono.monotonic_ns,
        )
        assert fix2.get("ok") is True, fix2
        act2 = cast(dict[str, Any], fix2["data"]["fix"]["actions"][0])
        assert act2["status"] == "noop"
        assert act2["changed"] == 0
        assert act2["contiguous_event_acked_through"] == 1
        assert act2["acked_producer_gap_sequences"] == [4]
        assert act2["pending_remaining"] == 1

        # Call 3: late Event 2 arrives -> commits Event 2, dedups {1, 3}, advances contiguous=3, clears capture!
        spool_state["event2_ready"] = True
        fix3 = _call_operator_json(
            ready.endpoint,
            store_id=rep.store_id,
            ca_pem=ca_pem,
            leaf_sha256=leaf_sha256,
            token=cli_token,
            path="/v2/operator/doctor/fix",
            body={"actions": ["replay_outbox"], "checkout_root": str(checkout)},
            monotonic_ns=real_mono.monotonic_ns,
        )
        assert fix3.get("ok") is True, fix3
        act3 = cast(dict[str, Any], fix3["data"]["fix"]["actions"][0])
        assert act3["status"] == "applied"
        assert act3["changed"] == 1
        assert act3["committed_event_sequences"] == [1, 2, 3]
        assert act3["contiguous_event_acked_through"] == 3
        assert act3["acked_producer_gap_sequences"] == [4]
        assert act3["pending_remaining"] == 0
        assert (
            _check_dict_by(
                cast(list[Mapping[str, Any]], fix3["data"]["fix"]["rechecked_checks"]), "capture", "probe"
            )["status"]
            == "PASS"
        )

        # Call 4: idempotent retry after full drain -> noop, zero duplicate commits.
        fix4 = _call_operator_json(
            ready.endpoint,
            store_id=rep.store_id,
            ca_pem=ca_pem,
            leaf_sha256=leaf_sha256,
            token=cli_token,
            path="/v2/operator/doctor/fix",
            body={"actions": ["replay_outbox"], "checkout_root": str(checkout)},
            monotonic_ns=real_mono.monotonic_ns,
        )
        assert fix4.get("ok") is True, fix4
        act4 = cast(dict[str, Any], fix4["data"]["fix"]["actions"][0])
        assert act4["status"] == "noop"
        assert act4["changed"] == 0
        assert act4["contiguous_event_acked_through"] == 3
        assert act4["pending_remaining"] == 0

        # Refresh clean DoctorRun and capture its idempotent get_health(deep=True) response.
        clock.advance(timedelta(minutes=16))
        clean_rep = _call_operator_json(
            ready.endpoint,
            store_id=rep.store_id,
            ca_pem=ca_pem,
            leaf_sha256=leaf_sha256,
            token=cli_token,
            path="/v2/operator/doctor/report",
            body={"wait_timeout_ms": 5000, "checkout_root": str(checkout)},
            monotonic_ns=real_mono.monotonic_ns,
        )
        assert clean_rep["ok"] is True and clean_rep["data"]["overall_status"] == "pass"
        _assert_no_raw_secrets(clean_rep["data"], scanner=scanner, secrets=(), label="clean_operator_report")
        _assert_no_raw_secrets(
            format_doctor_dict_text(clean_rep["data"]),
            scanner=scanner,
            secrets=(),
            label="clean_operator_report_text",
        )
        _assert_no_raw_secrets(fix3["data"], scanner=scanner, secrets=(), label="clean_operator_fix")
        # I4-R4-01: store-wide get_health(deep=True) only answers with a store-wide DoctorRun, so the clean run it
        # reports (and that is quarantined below) must also be refreshed without a checkout scope.
        clean_store_rep = _call_operator_json(
            ready.endpoint,
            store_id=rep.store_id,
            ca_pem=ca_pem,
            leaf_sha256=leaf_sha256,
            token=cli_token,
            path="/v2/operator/doctor/report",
            body={"wait_timeout_ms": 5000},
            monotonic_ns=real_mono.monotonic_ns,
        )
        assert clean_store_rep["ok"] is True and clean_store_rep["data"]["overall_status"] == "pass", clean_store_rep
        assert clean_store_rep["data"]["doctor_run_id"] != clean_rep["data"]["doctor_run_id"]
        _assert_no_raw_secrets(clean_store_rep["data"], scanner=scanner, secrets=(), label="clean_store_report")

        idem_replay_key = "idem_quar_replay_sp2_01"
        h_before = _validate_get_health_envelope(
            client.call(
                target,
                ToolCommand(
                    "get_health",
                    {"schema_version": "2.0", "deep": True, "idempotency_key": idem_replay_key},
                    token=cred_claude.token,
                ),
                deadline_ns=real_mono.monotonic_ns() + TOTAL_REQUEST_BUDGET_NS,
            )
        )
        assert h_before["ok"] is True
        h_before_data = cast(dict[str, JsonValue], h_before["data"])
        _assert_no_raw_secrets(h_before_data, scanner=scanner, secrets=(), label="clean_get_health_deep")
        m1_clean = sp2.run_m1_handover_probe(
            rep.daemon_config_path,
            checkout_root=checkout,
            os_=os_,
            capture_probe=probe,
            deep_health=h_before_data,
            require_native_receipts=True,
        )
        assert m1_clean["m1_ready"] is True
        _assert_no_raw_secrets(m1_clean, scanner=scanner, secrets=(), label="clean_run_m1_handover")
        quar_run_id = cast(str, h_before_data["doctor_run_id"])
        assert isinstance(quar_run_id, str) and quar_run_id
        assert quar_run_id == clean_store_rep["data"]["doctor_run_id"], (h_before_data, clean_store_rep["data"])

    quar_run_digest, _quar_doc = _read_latest_doctor_run_doc(root)
    assert _quar_doc.get("checkout_root") is None, "the quarantined run must be the store-wide run deep health named"

    # Seed canary secrets in CAS + log, plus QUARANTINE on DoctorRun and TOMBSTONE on secret CAS holder.
    s_ghp = "ghp_I45CanarySecretToken9988776655abcd"
    s_sk = "sk-I45CanaryOpenAISecretKey4433221100"
    s_bearer = "I45CanaryBearerTokenSecret1234567890"
    s_priv = "i45_canary_private_body_payload_88"
    secrets = (s_ghp, s_sk, s_bearer, s_priv)

    secret_holder_id = new_id()
    rt_sec = reopen_kernel_job_runtime(cfg.data_root, rep.store_id, os_)
    try:
        secret_cas_digest = rt_sec.store.store_content(
            f"Authorization: Bearer {s_bearer} token={s_ghp}".encode(),
            "event",
            secret_holder_id,
            RetentionClass.DURABLE,
            None,
        )
        rt_sec.policy.record_intent(IntentKind.QUARANTINE, {"digest": quar_run_digest})
        rt_sec.policy.record_intent(IntentKind.QUARANTINE, {"digest": secret_cas_digest})
        rt_sec.policy.record_intent(IntentKind.TOMBSTONE, {"holder_kind": "event", "holder_id": secret_holder_id})
    finally:
        rt_sec.close()

    log_file = root.logs_dir / "brain.log"
    log_file.write_bytes(
        f"2026-11-21T19:45:00Z ERROR {s_sk}\n<private>{s_priv}</private>\n".encode()
    )
    os_.permissions.secure_file(log_file)

    # Pre-boot offline inspection BEFORE Store.open reconciles pending intents at daemon startup.
    pre_boot_rep = doctor_entry.run_doctor(
        rep.daemon_config_path, checkout_root=checkout, os_=os_, capture_probe=probe
    )
    assert pre_boot_rep.overall_status == "fail"
    assert _check_obj_by(pre_boot_rep, "privacy", "rescan").status == "FAIL"
    assert _check_obj_by(pre_boot_rep, "retention", "tombstones").status == "FAIL"
    assert _check_obj_by(pre_boot_rep, "storage", "policy_reconcile").status == "WARN"
    _assert_no_raw_secrets(
        pre_boot_rep.to_dict(),
        scanner=scanner,
        secrets=secrets,
        label="pre_boot_json",
        allow_rescan_finding_tokens=True,
    )
    _assert_no_raw_secrets(
        format_doctor_text(pre_boot_rep),
        scanner=scanner,
        secrets=secrets,
        label="pre_boot_text",
        allow_rescan_finding_tokens=True,
        check_entropy=False,
    )

    live_rt_box: list[Runtime] = []
    live_hooks = DaemonTestHooks(before_job_recover=live_rt_box.append)

    with _running_serve_config(
        rep.daemon_config_path,
        os_=os_,
        clock=clock,
        mono=real_mono,
        capture_probe=probe,
        outbox_replay=outbox_port,
        hooks=live_hooks,
    ) as (ready2, loop2):
        assert loop2.wait_doctor_settled(timeout=BOUND_WAIT_S)
        target2 = LoopbackTarget(
            endpoint=ready2.endpoint,
            expected_store_id=rep.store_id,
            ca_pem=ca_pem,
            leaf_cert_sha256=leaf_sha256,
        )
        client2 = LoopbackClient(monotonic_ns=real_mono.monotonic_ns)

        # Replay of get_health(deep=True) pointing to quarantined DoctorRun MUST fail closed with QUARANTINED.
        h_quar_replay = _validate_get_health_envelope(
            client2.call(
                target2,
                ToolCommand(
                    "get_health",
                    {"schema_version": "2.0", "deep": True, "idempotency_key": idem_replay_key},
                    token=cred_claude.token,
                ),
                deadline_ns=real_mono.monotonic_ns() + TOTAL_REQUEST_BUDGET_NS,
            )
        )
        assert h_quar_replay["ok"] is False
        assert cast(dict[str, str], h_quar_replay["error"])["code"] == ErrorCode.QUARANTINED.value

        # Startup Store.open reconciled pre-boot tombstone/quarantine intents; persisted secrets still FAIL privacy/M1.
        dirty_rep = _call_operator_json(
            ready2.endpoint,
            store_id=rep.store_id,
            ca_pem=ca_pem,
            leaf_sha256=leaf_sha256,
            token=cli_token,
            path="/v2/operator/doctor/report",
            body={"wait_timeout_ms": 5000, "checkout_root": str(checkout)},
            monotonic_ns=real_mono.monotonic_ns,
        )
        assert dirty_rep["ok"] is True
        dirty_data = cast(dict[str, Any], dirty_rep["data"])
        assert dirty_data["overall_status"] == "fail"
        dirty_checks = cast(list[Mapping[str, Any]], dirty_data["checks"])
        assert _check_dict_by(dirty_checks, "privacy", "rescan")["status"] == "FAIL"
        assert _check_dict_by(dirty_checks, "retention", "tombstones")["status"] == "PASS"
        assert _check_dict_by(dirty_checks, "storage", "policy_reconcile")["status"] == "PASS"

        dirty_text = format_doctor_dict_text(dirty_data)
        h_fresh = _validate_get_health_envelope(
            client2.call(
                target2,
                ToolCommand(
                    "get_health",
                    {"schema_version": "2.0", "deep": True, "idempotency_key": "idem_fresh_after_quar_02"},
                    token=cred_claude.token,
                ),
                deadline_ns=real_mono.monotonic_ns() + TOTAL_REQUEST_BUDGET_NS,
            )
        )
        assert h_fresh["ok"] is True
        h_fresh_data = cast(dict[str, JsonValue], h_fresh["data"])
        assert h_fresh_data["doctor_run_id"] != quar_run_id

        m1_dirty = sp2.run_m1_handover_probe(
            rep.daemon_config_path,
            checkout_root=checkout,
            os_=os_,
            capture_probe=probe,
            deep_health=h_fresh_data,
            require_native_receipts=True,
        )
        assert m1_dirty["m1_ready"] is False
        assert m1_dirty["overall_status"] == "fail"

        # Online unapplied TOMBSTONE -> /v2/operator/doctor/report FAIL/WARN -> /doctor/fix reconcile_policy applied.
        assert len(live_rt_box) == 1
        live_rt = live_rt_box[0]
        holder_online = new_id()

        def _seed_online_tombstone() -> None:
            live_rt.store.store_content(
                b"online-tombstone-payload", "event", holder_online, RetentionClass.DURABLE, None
            )
            live_rt.policy.record_intent(IntentKind.TOMBSTONE, {"holder_kind": "event", "holder_id": holder_online})

        loop2.run_owner_action(_seed_online_tombstone).result(timeout=BOUND_WAIT_S)
        clock.advance(timedelta(minutes=16))

        pre_fix_rep = _call_operator_json(
            ready2.endpoint,
            store_id=rep.store_id,
            ca_pem=ca_pem,
            leaf_sha256=leaf_sha256,
            token=cli_token,
            path="/v2/operator/doctor/report",
            body={"wait_timeout_ms": 5000, "checkout_root": str(checkout)},
            monotonic_ns=real_mono.monotonic_ns,
        )
        assert pre_fix_rep["ok"] is True
        pre_fix_checks = cast(list[Mapping[str, Any]], pre_fix_rep["data"]["checks"])
        assert _check_dict_by(pre_fix_checks, "retention", "tombstones")["status"] == "FAIL"
        assert _check_dict_by(pre_fix_checks, "storage", "policy_reconcile")["status"] == "WARN"

        fix_rec = _call_operator_json(
            ready2.endpoint,
            store_id=rep.store_id,
            ca_pem=ca_pem,
            leaf_sha256=leaf_sha256,
            token=cli_token,
            path="/v2/operator/doctor/fix",
            body={"actions": ["reconcile_policy"], "checkout_root": str(checkout)},
            monotonic_ns=real_mono.monotonic_ns,
        )
        assert fix_rec["ok"] is True
        fix_rec_data = cast(dict[str, Any], fix_rec["data"])
        assert fix_rec_data["fix"]["actions"][0]["status"] == "applied"
        rec_checks = cast(list[Mapping[str, Any]], fix_rec_data["fix"]["rechecked_checks"])
        assert _check_dict_by(rec_checks, "retention", "tombstones")["status"] == "PASS"
        assert _check_dict_by(rec_checks, "storage", "policy_reconcile")["status"] == "PASS"

        # Verify ZERO raw secret leakage across report JSON, text, deep health, fix output, and M1 handover output!
        cli_snap_rep = doctor_entry.run_doctor(
            rep.daemon_config_path, checkout_root=checkout, os_=os_, capture_probe=probe
        )
        for surface_name, payload, allow_tokens, check_ent in (
            ("operator_report_json", dirty_data, True, True),
            ("operator_report_text", dirty_text, True, False),
            ("operator_fix_json", fix_rec_data, True, True),
            ("get_health_deep_json", h_fresh_data, False, True),
            ("run_m1_handover_json", m1_dirty, True, True),
            ("cli_doctor_report_json", cli_snap_rep.to_dict(), True, True),
            ("cli_doctor_report_text", format_doctor_text(cli_snap_rep), True, False),
        ):
            _assert_no_raw_secrets(
                payload,
                scanner=scanner,
                secrets=secrets,
                label=surface_name,
                allow_rescan_finding_tokens=allow_tokens,
                check_entropy=check_ent,
            )
