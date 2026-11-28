"""Independent I4-2 oracle tests for ``system.doctor`` jobs, retention, ``get_health(deep=True)``, and restore fence.

Requirement sources:
- Spec rev 22 §5.4, §5.6, §5.7, §6.4, §13, §14.2, §20.1
- ``schemas/mcp-tools-v2.json`` (``GetHealthClientArgs``, ``GetHealthDaemonArgs``,
  ``GetHealthResult``, ``GetJobResult``)
- SP1 Increment 4 I4-2 contract (RetentionClass promotion, bounded ``due_jobs_by_kinds`` / ``lease_next_for_kinds``,
  startup + 24h background ``system.doctor``, ``OwnerLoop.wait_doctor_settled()``, production ``get_health(deep=True)``,
  multi-owner isolation, ``Scope(repo_id, None)`` rejection, ``build_tool_caller`` scope forwarding,
  online restore fence)
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import sqlite3
import struct
import threading
from collections.abc import Iterator, Mapping
from concurrent.futures import Future
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import MappingProxyType
from typing import Any, cast

import jsonschema
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.daemon_config import read_client_endpoint, read_daemon_config
from superbrain.adapters.os.tls_material import verify_server_tls_files
from superbrain.application._prequeue import AtomicRequestAuthState, admit_prequeue_request
from superbrain.application.owner_loop import OwnerLoop
from superbrain.cli_api.loopback import LoopbackClient, LoopbackTarget, LoopbackTransportError
from superbrain.composition import daemon_entry
from superbrain.composition.client_entry import build_tool_caller
from superbrain.composition.daemon_entry import create_daemon_owner_loop
from superbrain.composition.init_entry import InitReport, InitRequest, init_store
from superbrain.composition.kernel_bridge import KernelBridge
from superbrain.core._kernel_approval import (
    RISK_POLICY_VERSION,
    ApprovalAction,
    ApprovalChannel,
    ApprovalMessage,
    RecoveryScope,
    RiskLevel,
    SignerEnrollment,
)
from superbrain.core._kernel_base import ResourceDigest
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.faults import crashpoint as core_crashpoint
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    TOTAL_REQUEST_BUDGET_NS,
    CallContext,
    DaemonConfig,
    Identity,
    JobErrorCode,
    JobState,
    OwnerReply,
    Principal,
    PrivateRequestAuth,
    Ready,
    RequestAuthView,
    RequestDeadlines,
    Scope,
    StoredResult,
    ToolCommand,
    WorkerFailed,
)
from superbrain.core.wire import load_catalog, normalize_call
from superbrain.ports.doctor import MAX_DOCTOR_RUN_BLOB_BYTES, DoctorSnapshot
from superbrain.ports.kernel import KernelTx
from superbrain.ports.os import LockHandle, LockProbePort, OsAdapters
from superbrain.ports.policy import IntentKind
from superbrain.storage._doctor_reader import StorageDoctorReader
from superbrain.storage.backup import create_policy_backup, create_store_backup, verify_backup
from superbrain.storage.cas import blob_path
from superbrain.storage.kernel_schema import KERNEL_POLICY_MIGRATIONS, KERNEL_STORE_MIGRATIONS
from superbrain.storage.kinds import RetentionClass
from superbrain.storage.layout import DataRoot
from superbrain.storage.ledger import utc_timestamp
from superbrain.workers.executor import PRODUCTION_JOB_HANDLERS, JobExecutor, WorkItem
from tests.support.clock import FakeClock
from tests.support.inc2_cli import write_ca_file, write_client_profile_file, write_credential_file
from tests.support.inc2_fixture import (
    FIXTURE_JOB_KIND,
    enqueue_job,
    kernel_job_service,
    open_kernel_job_runtime,
    reopen_kernel_job_runtime,
    validate_response_envelope,
)
from tests.support.inc2_transport import (
    FakeMonotonicClock,
    post_tls_http_json,
    register_workspace_direct,
)
from tests.support.kernel_auth import seed_principal_and_credential

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPO_ROOT / "schemas" / "mcp-tools-v2.json"
BOUND_WAIT_S = 10.0
OWNER_DAN = "dan"
MACHINE_ID = "i4-2-box"


def _base_utc_now() -> datetime:
    """10m prior to wall clock so TLS certs are valid immediately while >=90d advances clear 24h file mtime grace."""
    return datetime.now(UTC).replace(microsecond=0) - timedelta(minutes=10)


def _ssh_signer_key(owner_id: str = OWNER_DAN) -> tuple[Ed25519PrivateKey, SignerEnrollment]:
    priv = Ed25519PrivateKey.generate()
    raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", len(raw)) + raw
    line = "ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + f" {owner_id}@i4-2"
    return priv, SignerEnrollment(owner_id=owner_id, channel=ApprovalChannel.SSH_KEY, public_key=line)


def _ssh_sig_b64(priv: Ed25519PrivateKey, payload: bytes) -> str:
    raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", len(raw)) + raw

    def _s(data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + data

    ns = b"ensemble-brain-approval"
    signed = b"SSHSIG" + _s(ns) + _s(b"") + _s(b"sha512") + _s(hashlib.sha512(payload).digest())
    sig = _s(b"ssh-ed25519") + _s(priv.sign(signed))
    body = b"SSHSIG" + struct.pack(">I", 1) + _s(blob) + _s(ns) + _s(b"") + _s(b"sha512") + _s(sig)
    armored = base64.b64encode(body).decode("ascii")
    lines = [armored[i : i + 70] for i in range(0, len(armored), 70)]
    pem = ("-----BEGIN SSH SIGNATURE-----\n" + "\n".join(lines) + "\n-----END SSH SIGNATURE-----\n").encode("ascii")
    return base64.b64encode(pem).decode("ascii")


def _init_doctor_root(
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
    verified_tls = verify_server_tls_files(cfg, clock, adapters)
    ca_pem = (cfg_dir / "tls" / "ca.pem").read_text(encoding="utf-8")
    cli_token = rep.cli_credential_path.read_text(encoding="utf-8").strip()
    return rep, cfg, priv, ca_pem, verified_tls.leaf_cert_sha256, cli_token, adapters


def _validate_envelope(tool: str, envelope: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    """Validate envelope against both packaged catalog and checked-in ``schemas/mcp-tools-v2.json``."""
    checked = validate_response_envelope(tool, envelope)
    raw_schema = SCHEMA_PATH.read_bytes()
    catalog = load_catalog()
    assert raw_schema == catalog.raw_bytes
    schema_obj = json.loads(raw_schema.decode("utf-8"))
    if checked["ok"] is True:
        jsonschema.Draft202012Validator(
            {"$schema": schema_obj["$schema"], "$defs": schema_obj["$defs"], "$ref": "#/$defs/GetHealthResult"}
            if tool == "get_health"
            else {"$schema": schema_obj["$schema"], "$defs": schema_obj["$defs"], "$ref": "#/$defs/GetJobResult"}
        ).validate(checked["data"])
    else:
        jsonschema.Draft202012Validator(
            {"$schema": schema_obj["$schema"], "$defs": schema_obj["$defs"], "$ref": "#/$defs/ErrorEnvelope"}
        ).validate(checked)
    return checked


@contextlib.contextmanager
def _ro_db(db_path: Path) -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        yield conn
    finally:
        conn.close()


@contextlib.contextmanager
def _running_owner_loop(
    cfg: DaemonConfig,
    *,
    os_: OsAdapters,
    clock: FakeClock,
    mono: FakeMonotonicClock,
) -> Iterator[tuple[Ready, OwnerLoop]]:
    # doctor-only daemon as in SP1-I4; since the SP2 merge production also registers continuity.refresh
    loop = create_daemon_owner_loop(os_=os_, clock=clock, monotonic_clock=mono, job_handlers={})
    ready = loop.start(cfg)
    try:
        yield ready, loop
    finally:
        loop.stop(grace_s=2.0)


@contextlib.contextmanager
def _running_serve(
    cfg: DaemonConfig,
    *,
    os_: OsAdapters,
    clock: FakeClock,
    mono: FakeMonotonicClock,
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
            daemon_entry.serve(
                cfg,
                os_=os_,
                clock=clock,
                monotonic_clock=mono,
                stop_event=stop_ev,
                shutdown_grace_s=2.0,
                on_ready=_on_ready,
            )
        )

    thr = threading.Thread(target=_bg, name="i4-2-serve", daemon=True)
    thr.start()
    try:
        assert ready_ev.wait(timeout=BOUND_WAIT_S), f"serve() did not become ready (exits={exits})"
        yield cast(Ready, box["ready"]), cast(OwnerLoop, box["loop"])
    finally:
        stop_ev.set()
        thr.join(timeout=BOUND_WAIT_S)
        assert not thr.is_alive(), "daemon serve thread leaked"


def _post_tls(ready: Ready, ca_pem: str, path: str, token: str, payload: object) -> dict[str, Any]:
    return post_tls_http_json(ready, ca_pem, path, token, payload)[1]


def _restore_msg(store_id: str, owner_id: str, ch: dict[str, Any], db_digest: str) -> ApprovalMessage:
    return ApprovalMessage(
        store_id=store_id,
        owner_id=owner_id,
        trust_generation=int(cast(int | str, ch["trust_generation"])),
        action=ApprovalAction.RESTORE,
        subject_id=str(ch["subject_id"]),
        subject_revision=1,
        resource_digests=(ResourceDigest("backup", db_digest),),
        target_files=(),
        risk_level=RiskLevel.HIGH,
        risk_policy_version=RISK_POLICY_VERSION,
        recovery_scope=RecoveryScope.NONE,
        nonce=str(ch["nonce"]),
        expires_at=datetime.fromisoformat(str(ch["expires_at"]).replace("Z", "+00:00")),
    )


def _submit_tool(
    loop: OwnerLoop,
    mono: FakeMonotonicClock,
    tool: str,
    arguments: Mapping[str, JsonValue],
    *,
    token: str,
    selected_scope: Scope | None = None,
) -> dict[str, JsonValue]:
    cmd = ToolCommand(tool=tool, arguments=dict(arguments), token=token, selected_scope=selected_scope)
    res = loop.submit(cmd, mono.now + TOTAL_REQUEST_BUDGET_NS).result(timeout=BOUND_WAIT_S)
    return _validate_envelope(tool, res)


# ---------------------------------------------------------------------------
# Requirement 1: RetentionClass promotion, KernelTx.hold_blob, 90d TTL & 24h GC
# ---------------------------------------------------------------------------


def test_retention_class_promotion_and_hold_blob_optional_defaults(trusted_tmp: Path) -> None:
    """``RetentionClass`` is promoted to ``core._kernel_base`` and ``KernelTx.hold_blob`` supports retention/expiry."""
    from superbrain.core import _kernel_base, kernel
    from superbrain.storage import kinds

    assert hasattr(_kernel_base, "RetentionClass"), "RetentionClass must be promoted to superbrain.core._kernel_base"
    assert hasattr(kernel, "RetentionClass"), "RetentionClass must be re-exported from superbrain.core.kernel"
    base_cls = _kernel_base.RetentionClass
    kernel_cls = kernel.RetentionClass
    storage_cls = kinds.RetentionClass
    assert base_cls is kernel_cls is storage_cls is RetentionClass
    assert (base_cls.EVENT_PAYLOAD.value, base_cls.EVIDENCE.value, base_cls.DURABLE.value) == (
        "event_payload",
        "evidence",
        "durable",
    )

    clock = FakeClock(_base_utc_now())
    os_ = os_adapters(clock=clock)
    rt = open_kernel_job_runtime(trusted_tmp / "hold-blob", os_)
    try:
        from superbrain.storage.workspaces import StoreKernelTx

        h_default = new_id()
        h_event = new_id()
        exp_at = clock.now() + timedelta(days=90)
        b_dur = b"durable-default-hold"
        b_evt = b"event-payload-90d-hold"

        # (a) StoreKernelTx default (DURABLE, None) & explicit (EVENT_PAYLOAD, expires_at)
        with rt.store.transaction() as txn:
            stx = StoreKernelTx(txn, rt.store.cas, rt.policy)
            d_dur = stx.hold_blob(b_dur, holder_id=h_default)
            d_evt = stx.hold_blob(
                b_evt,
                holder_id=h_event,
                retention=RetentionClass.EVENT_PAYLOAD,
                expires_at=exp_at,
            )

        # (b) StagedKernelStore / StrictKernelTx default (DURABLE, None) & explicit (EVENT_PAYLOAD, expires_at)
        _, staged_store = kernel_job_service(rt, clock)
        h_strict_dur = new_id()
        h_strict_evt = new_id()
        b_s_dur = b"strict-durable-hold"
        b_s_evt = b"strict-event-90d-hold"
        staged_store.stage_blob(b_s_dur)
        staged_store.stage_blob(b_s_evt)

        def _strict_hold(tx: KernelTx) -> tuple[str, str]:
            return (
                tx.hold_blob(b_s_dur, holder_id=h_strict_dur),
                tx.hold_blob(
                    b_s_evt,
                    holder_id=h_strict_evt,
                    retention=RetentionClass.EVENT_PAYLOAD,
                    expires_at=exp_at,
                ),
            )

        d_s_dur, d_s_evt = staged_store.transact(_strict_hold)

        with _ro_db(rt.root.store_db) as conn:
            rows = conn.execute(
                "SELECT holder_id, digest, retention_class, expires_at FROM p_cas_holders_ ORDER BY holder_id"
            ).fetchall()
        by_holder = {str(h): (str(d), str(r), e) for h, d, r, e in rows}
        assert by_holder[h_default] == (d_dur, "durable", None)
        assert by_holder[h_event] == (d_evt, "event_payload", utc_timestamp(exp_at))
        assert by_holder[h_strict_dur] == (d_s_dur, "durable", None)
        assert by_holder[h_strict_evt] == (d_s_evt, "event_payload", utc_timestamp(exp_at))
    finally:
        rt.close()


def test_90d_ttl_and_24h_debounced_gc_removes_doctor_run_and_idempotency_preserving_job_descriptor(
    trusted_tmp: Path,
) -> None:
    """At day >= 91, 24h-debounced GC drops expired DoctorRun + idempotency while job result stays DURABLE."""
    clock = FakeClock(_base_utc_now())
    mono = FakeMonotonicClock(1_000_000_000)
    rep, cfg, _priv, _ca, _leaf, _cli, os_ = _init_doctor_root(trusted_tmp / "ttl-gc", clock)
    root = DataRoot.at(cfg.data_root)

    rt = reopen_kernel_job_runtime(cfg.data_root, rep.store_id, os_)
    try:
        cred_dan = seed_principal_and_credential(rt.policy, owner_id=OWNER_DAN, machine_id=MACHINE_ID)
    finally:
        rt.close()

    with _running_owner_loop(cfg, os_=os_, clock=clock, mono=mono) as (_ready, loop):
        assert loop.wait_doctor_settled(timeout=BOUND_WAIT_S)

        res0 = _submit_tool(
            loop,
            mono,
            "get_health",
            {"schema_version": "2.0", "deep": True, "idempotency_key": "idem_ttl_gc_deep_0001"},
            token=cred_dan.token,
        )
        assert res0["ok"] is True
        data0 = cast(dict[str, Any], res0["data"])
        startup_run_id = cast(str, data0["doctor_run_id"])
        assert isinstance(startup_run_id, str) and startup_run_id
        assert data0["job_id"] is None

        with _ro_db(root.store_db) as conn:
            job_rows = conn.execute(
                "SELECT job_id, owner_id, kind, state, result_digest FROM p_jobs_state"
                " WHERE kind = 'system.doctor' ORDER BY sequence"
            ).fetchall()
            assert len(job_rows) == 1
            doctor_job_id, job_owner, job_kind, job_state, job_result_digest = (
                str(job_rows[0][0]),
                str(job_rows[0][1]),
                str(job_rows[0][2]),
                str(job_rows[0][3]),
                cast(str | None, job_rows[0][4]),
            )
            assert job_owner == OWNER_DAN and job_kind == "system.doctor" and job_state == "succeeded"
            assert isinstance(job_result_digest, str) and job_result_digest

            job_hold_rows = conn.execute(
                "SELECT digest, retention_class, expires_at FROM p_cas_holders_ WHERE holder_id = ?",
                (doctor_job_id,),
            ).fetchall()
            assert len(job_hold_rows) >= 1
            assert any(
                str(dig) == job_result_digest and str(ret) == "durable" and exp is None
                for dig, ret, exp in job_hold_rows
            ), f"system.doctor result_descriptor must be held as (DURABLE, None), got {job_hold_rows}"

            doc_entries = conn.execute(
                "SELECT refs, meta FROM ledger WHERE kind = 'doctor.run' ORDER BY sequence"
            ).fetchall()
            assert len(doc_entries) == 1
            doc_refs = cast(list[str], json.loads(bytes(doc_entries[0][0]).decode("utf-8")))
            assert len(doc_refs) >= 1
            doctor_run_digest = doc_refs[0]

            run_hold_rows = conn.execute(
                "SELECT holder_id, retention_class, expires_at FROM p_cas_holders_ WHERE digest = ?",
                (doctor_run_digest,),
            ).fetchall()
            assert run_hold_rows, f"expected CAS hold for DoctorRun blob {doctor_run_digest}"
            assert all(
                str(hid) != doctor_job_id and str(ret) == "event_payload" and exp is not None
                for hid, ret, exp in run_hold_rows
            ), f"DoctorRun CAS blob must have separate holder with 90d EVENT_PAYLOAD TTL: {run_hold_rows}"

            idem_rows = conn.execute(
                "SELECT result_id, refs_json, committed_at FROM idempotency WHERE tool = 'get_health'"
            ).fetchall()
            assert len(idem_rows) == 1
            idem_result_id = str(idem_rows[0][0])
            idem_refs = StoredResult.decode_refs_json(str(idem_rows[0][1]))
            idem_hold_rows = conn.execute(
                "SELECT digest, retention_class, expires_at FROM p_cas_holders_ WHERE holder_id = ?",
                (idem_result_id,),
            ).fetchall()
            assert idem_hold_rows, "expected CAS descriptor hold for get_health idempotency result"
            assert all(str(ret) == "event_payload" and exp is not None for _d, ret, exp in idem_hold_rows)
            idem_digests = {str(d) for d, _r, _e in idem_hold_rows} | {r.digest for r in idem_refs}

        assert blob_path(root.cas_dir, doctor_run_digest).is_file()
        assert blob_path(root.cas_dir, job_result_digest).is_file()
        for dig in idem_digests:
            assert blob_path(root.cas_dir, dig).is_file()

        # Advance to day 89.5 (>=24h since startup, <90d TTL): GC runs, keeps t0 DoctorRun & descriptor intact.
        clock.set(clock.now() + timedelta(days=89, hours=12))
        assert loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        assert blob_path(root.cas_dir, doctor_run_digest).is_file()
        for dig in idem_digests:
            assert blob_path(root.cas_dir, dig).is_file()

        # Advance +13h (day 90.04 -> past 90d TTL, BUT <24h since day 89.5 GC): 24h debounce keeps t0 blobs untouched.
        clock.advance(timedelta(hours=13))
        loop.run_owner_action(lambda: None).result(timeout=BOUND_WAIT_S)
        assert loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        assert blob_path(root.cas_dir, doctor_run_digest).is_file()

        # Advance to day 91 (>=24h since day 89.5 GC AND >=90d TTL): debounced GC deletes DoctorRun & descriptor!
        clock.advance(timedelta(hours=23))
        assert loop.wait_doctor_settled(timeout=BOUND_WAIT_S)

        assert not blob_path(root.cas_dir, doctor_run_digest).exists(), "expired DoctorRun CAS blob must be GC'd"
        for dig in idem_digests - {job_result_digest}:
            assert not blob_path(root.cas_dir, dig).exists(), f"expired idempotency descriptor {dig} must be GC'd"
        with _ro_db(root.store_db) as conn:
            rem_idem = conn.execute(
                "SELECT COUNT(*) FROM idempotency WHERE result_id = ?", (idem_result_id,)
            ).fetchone()
            assert rem_idem is not None and int(rem_idem[0]) == 0

        # Meanwhile, doctor_job_id's DURABLE result_descriptor remains intact and get_job succeeds with 0 errors!
        assert blob_path(root.cas_dir, job_result_digest).is_file()
        res_job = _submit_tool(
            loop,
            mono,
            "get_job",
            {"schema_version": "2.0", "job_id": doctor_job_id},
            token=cred_dan.token,
        )
        assert res_job["ok"] is True
        job_data = cast(dict[str, Any], res_job["data"])
        assert job_data["job_id"] == doctor_job_id
        assert job_data["state"] == "succeeded"

    # Also verify directly through JobService.get_job after reopen (zero INTEGRITY_FAILURE).
    rt_after = reopen_kernel_job_runtime(cfg.data_root, rep.store_id, os_)
    try:
        svc, _ = kernel_job_service(rt_after, clock)
        view = svc.get_job(doctor_job_id, cred_dan.principal, selected_scope=None)
        assert view.job_id == doctor_job_id and view.state is JobState.SUCCEEDED
        assert any(ref.digest == doctor_run_digest for ref in view.result_refs)
    finally:
        rt_after.close()


def test_get_health_deep_quarantined_descriptor_and_blob_fail_closed_on_replay(trusted_tmp: Path) -> None:
    """Quarantining either the idempotency descriptor or the DoctorRun CAS blob fails closed on replay."""
    clock = FakeClock(_base_utc_now())
    mono = FakeMonotonicClock(1_000_000_000)
    rep, cfg, _priv, _ca, _leaf, _cli, os_ = _init_doctor_root(trusted_tmp / "quar-replay", clock)
    root = DataRoot.at(cfg.data_root)

    rt = reopen_kernel_job_runtime(cfg.data_root, rep.store_id, os_)
    try:
        cred_dan = seed_principal_and_credential(rt.policy, owner_id=OWNER_DAN, machine_id=MACHINE_ID)
    finally:
        rt.close()

    key_desc = "idem_quar_desc_replay_01"
    key_blob = "idem_quar_blob_replay_02"
    with _running_owner_loop(cfg, os_=os_, clock=clock, mono=mono) as (_ready, loop):
        assert loop.wait_doctor_settled(timeout=BOUND_WAIT_S)

        first = _submit_tool(
            loop,
            mono,
            "get_health",
            {"schema_version": "2.0", "deep": True, "idempotency_key": key_desc},
            token=cred_dan.token,
        )
        assert first["ok"] is True
        replay_ok = _submit_tool(
            loop,
            mono,
            "get_health",
            {"schema_version": "2.0", "deep": True, "idempotency_key": key_desc},
            token=cred_dan.token,
        )
        assert replay_ok == first

        # Create a 2nd DoctorRun + key_blob so we can quarantine DoctorRun CAS blob without touching key_desc's blob.
        clock.advance(timedelta(hours=25))
        assert loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        second = _submit_tool(
            loop,
            mono,
            "get_health",
            {"schema_version": "2.0", "deep": True, "idempotency_key": key_blob},
            token=cred_dan.token,
        )
        assert second["ok"] is True
        replay_second_ok = _submit_tool(
            loop,
            mono,
            "get_health",
            {"schema_version": "2.0", "deep": True, "idempotency_key": key_blob},
            token=cred_dan.token,
        )
        assert replay_second_ok == second

    with _ro_db(root.store_db) as conn:
        idem_rows = conn.execute(
            "SELECT result_id, refs_json FROM idempotency WHERE tool = 'get_health' ORDER BY committed_at"
        ).fetchall()
        assert len(idem_rows) == 2
        res_id_1 = str(idem_rows[0][0])
        refs_1 = StoredResult.decode_refs_json(str(idem_rows[0][1]))
        holds_1 = conn.execute(
            "SELECT digest FROM p_cas_holders_ WHERE holder_id = ?", (res_id_1,)
        ).fetchall()
        desc_digests_1 = {str(r[0]) for r in holds_1} | {r.digest for r in refs_1}

        doc_entries = conn.execute(
            "SELECT refs FROM ledger WHERE kind = 'doctor.run' ORDER BY sequence"
        ).fetchall()
        assert len(doc_entries) >= 2
        latest_doc_refs = cast(list[str], json.loads(bytes(doc_entries[-1][0]).decode("utf-8")))
        assert latest_doc_refs
        latest_doc_blob_digest = latest_doc_refs[0]

    # Quarantine key_desc's idempotency descriptor AND latest DoctorRun CAS blob in policy.db.
    rt_q = reopen_kernel_job_runtime(cfg.data_root, rep.store_id, os_)
    try:
        for dig in sorted(desc_digests_1 | {latest_doc_blob_digest}):
            rt_q.policy.record_intent(IntentKind.QUARANTINE, {"digest": dig})
        rt_q.store.reconcile_policy()
    finally:
        rt_q.close()

    with _running_owner_loop(cfg, os_=os_, clock=clock, mono=mono) as (_ready, loop2):
        assert loop2.wait_doctor_settled(timeout=BOUND_WAIT_S)
        for blocked_key in (key_desc, key_blob):
            err_res = _submit_tool(
                loop2,
                mono,
                "get_health",
                {"schema_version": "2.0", "deep": True, "idempotency_key": blocked_key},
                token=cred_dan.token,
            )
            assert err_res["ok"] is False, f"quarantined replay for {blocked_key} must fail closed: {err_res}"
            err_obj = cast(dict[str, str], err_res["error"])
            assert err_obj["code"] in {
                ErrorCode.QUARANTINED.value,
                ErrorCode.INTEGRITY_FAILURE.value,
                ErrorCode.NOT_FOUND.value,
            }


# ---------------------------------------------------------------------------
# Requirement 2: Bounded due_jobs_by_kinds & JobService.lease_next_for_kinds
# ---------------------------------------------------------------------------


def test_due_jobs_by_kinds_and_lease_next_for_kinds_bounds_and_isolation(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``due_jobs_by_kinds`` / ``lease_next_for_kinds`` isolate ``system.doctor``; no prod handler runs it."""
    assert isinstance(PRODUCTION_JOB_HANDLERS, MappingProxyType)
    # SP2-3 registers only continuity.refresh; system.doctor stays with the doctor runner
    assert set(PRODUCTION_JOB_HANDLERS) == {"continuity.refresh"}
    with pytest.raises(TypeError):
        PRODUCTION_JOB_HANDLERS["system.doctor"] = lambda _s, _c: ()  # type: ignore[index]

    clock = FakeClock(_base_utc_now())
    mono = FakeMonotonicClock(1_000_000_000)
    os_ = os_adapters(clock=clock)
    rt = open_kernel_job_runtime(trusted_tmp / "due-kinds", os_)
    try:
        service, store = kernel_job_service(rt, clock)

        # Production executor refuses even "system.doctor" (proving no hidden production job handler bypass).
        enqueue_job(service, store, owner_id=OWNER_DAN, kind="system.doctor", payload=b"{}")
        doctor_lease = service.lease_next(rt.lease.epoch, clock.now())
        assert doctor_lease is not None
        service.start(doctor_lease)
        prod_exec = JobExecutor(PRODUCTION_JOB_HANDLERS, mono.monotonic_ns)
        prod_exec.start()
        try:
            prod_exec.submit(
                WorkItem(
                    lease=doctor_lease,
                    spec=service.job_spec(doctor_lease),
                    invocation_ids=(),
                    deadline_ns=mono.now + 5_000_000_000,
                )
            )
            cmd = prod_exec.next_command(BOUND_WAIT_S)
            assert cmd == WorkerFailed(doctor_lease, False, JobErrorCode.HANDLER_UNAVAILABLE)
            service.apply_command(cmd)
        finally:
            prod_exec.close(BOUND_WAIT_S)

        # Enqueue earlier non-doctor jobs followed by 4 system.doctor jobs.
        j_fixture = enqueue_job(service, store, owner_id=OWNER_DAN, kind=FIXTURE_JOB_KIND, payload=b"f1").job_id
        clock.advance(timedelta(seconds=1))
        j_other = enqueue_job(service, store, owner_id=OWNER_DAN, kind="custom.work", payload=b"c1").job_id
        doc_ids: list[str] = []
        for idx in range(4):
            clock.advance(timedelta(seconds=1))
            doc_ids.append(
                enqueue_job(service, store, owner_id=OWNER_DAN, kind="system.doctor", payload=f"d{idx}".encode()).job_id
            )

        now_utc = clock.now()
        due_all = store.transact(lambda tx: tx.due_jobs(now_utc, 10))
        assert [r.job_id for r in due_all] == [j_fixture, j_other, *doc_ids]

        due_doc = store.transact(lambda tx: tx.due_jobs_by_kinds(now_utc, ("system.doctor",), 10))
        assert [r.job_id for r in due_doc] == doc_ids
        due_bounded = store.transact(lambda tx: tx.due_jobs_by_kinds(now_utc, ("system.doctor",), 2))
        assert [r.job_id for r in due_bounded] == doc_ids[:2]

        for bad_limit in (0, -1, 101, True):
            def _bad_limit_tx(tx: KernelTx, lim: int = bad_limit) -> object:
                return tx.due_jobs_by_kinds(now_utc, ("system.doctor",), lim)

            with pytest.raises(BrainError) as lim_err:
                store.transact(_bad_limit_tx)
            assert lim_err.value.code is ErrorCode.INVALID_INPUT
        for bad_kinds in ((), ("invalid kind!",)):
            def _bad_kinds_tx(tx: KernelTx, ks: tuple[str, ...] = bad_kinds) -> object:
                return tx.due_jobs_by_kinds(now_utc, ks, 10)

            with pytest.raises(BrainError) as kind_err:
                store.transact(_bad_kinds_tx)
            assert kind_err.value.code is ErrorCode.INVALID_INPUT

        # lease_next_for_kinds(..., emit_crashpoints=False) skips non-doctor jobs and does not fire jobs.after_lease!
        recorded_crashpoints: list[str] = []

        def _spy_cp(name: str) -> None:
            recorded_crashpoints.append(name)
            core_crashpoint(name)

        monkeypatch.setattr("superbrain.application.jobs.crashpoint", _spy_cp)

        leased_doc = service.lease_next_for_kinds(
            rt.lease.epoch,
            now_utc,
            ("system.doctor",),
            emit_crashpoints=False,
        )
        assert leased_doc is not None and leased_doc.job_id == doc_ids[0]
        assert "jobs.after_lease" not in recorded_crashpoints

        # Standard lease_next still sees j_fixture first and emits jobs.after_lease.
        leased_fix = service.lease_next(rt.lease.epoch, now_utc)
        assert leased_fix is not None and leased_fix.job_id == j_fixture
        assert "jobs.after_lease" in recorded_crashpoints
    finally:
        rt.close()

    # Verify arbitrary client calls on a production OwnerLoop cannot run system.doctor or execute non-doctor jobs.
    rep, cfg, _priv, _ca, _leaf, _cli, os_2 = _init_doctor_root(trusted_tmp / "client-forbid", clock)
    rt2 = reopen_kernel_job_runtime(cfg.data_root, rep.store_id, os_2)
    try:
        cred = seed_principal_and_credential(rt2.policy, owner_id=OWNER_DAN, machine_id=MACHINE_ID)
        ws = register_workspace_direct(rt2, clock, cred.principal, alias="ws-forbid", checkout_dir=trusted_tmp / "chk")
        svc2, ks2 = kernel_job_service(rt2, clock)
        queued_non_doc = enqueue_job(
            svc2, ks2, owner_id=OWNER_DAN, kind=FIXTURE_JOB_KIND, payload=b"stays-queued"
        ).job_id
    finally:
        rt2.close()

    with _running_owner_loop(cfg, os_=os_2, clock=clock, mono=mono) as (_ready, loop):
        assert loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        bad_kind_res = loop.submit(
            ToolCommand(
                "request_improvement",
                {
                    "schema_version": "2.0",
                    "workspace_id": ws.repo_id,
                    "task_id": "t-1",
                    "kind": "system.doctor",
                    "idempotency_key": "idem_client_forbid_kind_1",
                },
                token=cred.token,
                selected_scope=Scope(ws.repo_id, ws.checkout_id),
            ),
            mono.now + TOTAL_REQUEST_BUDGET_NS,
        ).result(timeout=BOUND_WAIT_S)
        assert bad_kind_res["ok"] is False
        assert cast(dict[str, str], bad_kind_res["error"])["code"] == ErrorCode.INVALID_INPUT.value

        job_res = _submit_tool(
            loop,
            mono,
            "get_job",
            {"schema_version": "2.0", "job_id": queued_non_doc},
            token=cred.token,
        )
        assert job_res["ok"] is True
        assert cast(dict[str, Any], job_res["data"])["state"] == "queued"


# ---------------------------------------------------------------------------
# Requirement 3: Startup & 24h scheduled system.doctor + wait_doctor_settled
# ---------------------------------------------------------------------------


def test_startup_and_24h_scheduled_doctor_nonblocking_ready_and_wait_doctor_settled(
    trusted_tmp: Path,
) -> None:
    """``OwnerLoop.start`` returns ``Ready`` non-blocking; ``wait_doctor_settled`` waits for ``doctor.run`` & 24h GC."""
    clock = FakeClock(_base_utc_now())
    mono = FakeMonotonicClock(1_000_000_000)
    base_os = os_adapters(clock=clock)

    probe_entered = threading.Event()
    allow_probe = threading.Event()
    gate_first = [True]

    class _GatedLockFactory(LockProbePort):
        def __init__(self, inner: Any) -> None:
            self._inner = inner

        def acquire(self, path: Path) -> LockHandle:
            return cast(LockHandle, self._inner.acquire(path))

        def probe_held(self, path: Path) -> bool:
            if gate_first[0]:
                gate_first[0] = False
                probe_entered.set()
                assert allow_probe.wait(timeout=BOUND_WAIT_S), "startup doctor probe gate timed out"
            return bool(self._inner.probe_held(path))

    gated_os = replace(base_os, locks=cast(Any, _GatedLockFactory(base_os.locks)))
    rep, cfg, _priv, _ca, _leaf, _cli, _ = _init_doctor_root(trusted_tmp / "sched", clock, os_=gated_os)
    root = DataRoot.at(cfg.data_root)

    rt = reopen_kernel_job_runtime(cfg.data_root, rep.store_id, base_os)
    try:
        cred_dan = seed_principal_and_credential(rt.policy, owner_id=OWNER_DAN, machine_id=MACHINE_ID)
    finally:
        rt.close()

    # Seed 45 orphan CAS blobs to confirm bounded DoctorRun blob <= MAX_DOCTOR_RUN_BLOB_BYTES (65536).
    for i in range(45):
        orphan_bytes = f"orphan-bound-payload-{i:03d}-".encode() + b"x" * 64
        odig = digest_bytes(orphan_bytes)
        opath = blob_path(root.cas_dir, odig)
        opath.parent.mkdir(parents=True, exist_ok=True)
        base_os.permissions.secure_directory(opath.parent)
        opath.write_bytes(orphan_bytes)
        base_os.permissions.secure_file(opath)

    loop = create_daemon_owner_loop(os_=gated_os, clock=clock, monotonic_clock=mono)
    try:
        ready = loop.start(cfg)
        assert isinstance(ready, Ready)
        # Shallow health succeeds IMMEDIATELY while startup doctor is still blocked in probe_held!
        shallow_while_busy = _submit_tool(
            loop,
            mono,
            "get_health",
            {"schema_version": "2.0", "deep": False},
            token=cred_dan.token,
        )
        assert shallow_while_busy["ok"] is True
        assert cast(dict[str, Any], shallow_while_busy["data"])["ready"] is True

        assert probe_entered.wait(timeout=BOUND_WAIT_S), "startup doctor probe was never launched"
        allow_probe.set()
        assert loop.wait_doctor_settled(timeout=BOUND_WAIT_S)

        with _ro_db(root.store_db) as conn:
            run_entries = conn.execute(
                "SELECT sequence, actor, refs FROM ledger WHERE kind = 'doctor.run' ORDER BY sequence"
            ).fetchall()
            assert len(run_entries) == 1
            assert str(run_entries[0][1]) == "system:doctor"
            run1_refs = cast(list[str], json.loads(bytes(run_entries[0][2]).decode("utf-8")))
            assert run1_refs
            run1_bytes = blob_path(root.cas_dir, run1_refs[0]).read_bytes()
            assert 0 < len(run1_bytes) <= MAX_DOCTOR_RUN_BLOB_BYTES == 65_536

        # <24h elapsed (23h 59m): waking/settling does NOT trigger a 2nd scheduled system.doctor run!
        clock.advance(timedelta(hours=23, minutes=59))
        loop.run_owner_action(lambda: None).result(timeout=BOUND_WAIT_S)
        assert loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        assert cast(dict[str, Any], _submit_tool(
            loop, mono, "get_health", {"schema_version": "2.0", "deep": False}, token=cred_dan.token
        ))["ok"] is True
        with _ro_db(root.store_db) as conn:
            assert conn.execute("SELECT COUNT(*) FROM ledger WHERE kind = 'doctor.run'").fetchone()[0] == 1

        # Pick one of the t0 orphan blobs (written before startup, so at t0 + 24h 15m its mtime clears 24h grace).
        sample_orphan_digest = digest_bytes(b"orphan-bound-payload-000-" + b"x" * 64)
        assert blob_path(root.cas_dir, sample_orphan_digest).is_file()

        clock.advance(timedelta(minutes=16))  # total elapsed from t0 = 24h 15m
        assert loop.wait_doctor_settled(timeout=BOUND_WAIT_S)

        with _ro_db(root.store_db) as conn:
            assert conn.execute("SELECT COUNT(*) FROM ledger WHERE kind = 'doctor.run'").fetchone()[0] == 2
            assert conn.execute("SELECT COUNT(*) FROM p_jobs_state WHERE kind = 'system.doctor'").fetchone()[0] == 2
        assert not blob_path(root.cas_dir, sample_orphan_digest).exists(), (
            "24h scheduled doctor + debounced collect_garbage must reclaim orphan/expired CAS blobs"
        )

        # Advancing <24h after run #2 does NOT spam a 3rd run.
        clock.advance(timedelta(hours=2))
        loop.run_owner_action(lambda: None).result(timeout=BOUND_WAIT_S)
        assert loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        with _ro_db(root.store_db) as conn:
            assert conn.execute("SELECT COUNT(*) FROM ledger WHERE kind = 'doctor.run'").fetchone()[0] == 2
    finally:
        loop.stop(grace_s=2.0)


# ---------------------------------------------------------------------------
# Requirement 4: Production get_health(deep=false/true), multi-owner & scope
# ---------------------------------------------------------------------------


def test_get_health_production_deep_replay_conflict_multi_owner_and_scope_security(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Production ``get_health``, idempotency/conflict, §20.1 multi-owner isolation, ``Scope(repo, None)``, & shim."""
    clock = FakeClock(_base_utc_now())
    mono = FakeMonotonicClock(1_000_000_000)
    rep, cfg, _priv, ca_pem, leaf_sha256, _cli, os_ = _init_doctor_root(trusted_tmp / "health-sec", clock)
    root = DataRoot.at(cfg.data_root)

    chk_a_dir = trusted_tmp / "chk-alice"
    chk_a2_dir = trusted_tmp / "chk-alice-2"
    chk_b_dir = trusted_tmp / "chk-bob"
    for d in (chk_a_dir, chk_a2_dir, chk_b_dir):
        d.mkdir(parents=True, exist_ok=True)
        os_.permissions.secure_directory(d)

    rt = reopen_kernel_job_runtime(cfg.data_root, rep.store_id, os_)
    try:
        cred_dan = seed_principal_and_credential(rt.policy, owner_id=OWNER_DAN, machine_id=MACHINE_ID)
        cred_alice = seed_principal_and_credential(rt.policy, owner_id="alice", machine_id=MACHINE_ID)
        cred_bob = seed_principal_and_credential(rt.policy, owner_id="bob", machine_id=MACHINE_ID)
        ws_a = register_workspace_direct(
            rt, clock, cred_alice.principal, alias="ws-alice", checkout_dir=chk_a_dir, remote="https://ex/alice-a.git"
        )
        ws_a2 = register_workspace_direct(
            rt, clock, cred_alice.principal, alias="ws-alice-2", checkout_dir=chk_a2_dir, remote="https://ex/alice-b.git"
        )
        ws_b = register_workspace_direct(
            rt, clock, cred_bob.principal, alias="ws-bob", checkout_dir=chk_b_dir, remote="https://ex/bob-a.git"
        )
    finally:
        rt.close()

    scope_a = Scope(ws_a.repo_id, ws_a.checkout_id)
    scope_a2 = Scope(ws_a2.repo_id, ws_a2.checkout_id)
    partial_scope_a = Scope(ws_a.repo_id, None)
    _ = ws_b

    with _running_serve(cfg, os_=os_, clock=clock, mono=mono) as (ready, loop):
        assert loop.wait_doctor_settled(timeout=BOUND_WAIT_S)

        target = LoopbackTarget(
            endpoint=ready.endpoint,
            expected_store_id=rep.store_id,
            ca_pem=ca_pem,
            leaf_cert_sha256=leaf_sha256,
        )
        client = LoopbackClient(monotonic_ns=mono.monotonic_ns)

        # 1. Shallow get_health(deep=False) succeeds fast with 0 DB mutations.
        with _ro_db(root.store_db) as conn:
            seq_0 = int(conn.execute("SELECT COALESCE(MAX(sequence), 0) FROM ledger").fetchone()[0])
            jobs_0 = int(conn.execute("SELECT COUNT(*) FROM p_jobs_state").fetchone()[0])
            idem_0 = int(conn.execute("SELECT COUNT(*) FROM idempotency").fetchone()[0])

        for tok in (cred_dan.token, cred_alice.token, cred_bob.token):
            shallow_res = _validate_envelope(
                "get_health",
                client.call(
                    target,
                    ToolCommand("get_health", {"schema_version": "2.0", "deep": False}, token=tok),
                    deadline_ns=mono.now + TOTAL_REQUEST_BUDGET_NS,
                ),
            )
            assert shallow_res["ok"] is True
            assert cast(dict[str, Any], shallow_res["data"])["ready"] is True

        with _ro_db(root.store_db) as conn:
            assert int(conn.execute("SELECT COALESCE(MAX(sequence), 0) FROM ledger").fetchone()[0]) == seq_0
            assert int(conn.execute("SELECT COUNT(*) FROM p_jobs_state").fetchone()[0]) == jobs_0
            assert int(conn.execute("SELECT COUNT(*) FROM idempotency").fetchone()[0]) == idem_0

        # 2. get_health(deep=True) requires idempotency_key.
        missing_key = _validate_envelope(
            "get_health",
            client.call(
                target,
                ToolCommand("get_health", {"schema_version": "2.0", "deep": True}, token=cred_alice.token),
                deadline_ns=mono.now + TOTAL_REQUEST_BUDGET_NS,
            ),
        )
        assert missing_key["ok"] is False
        assert cast(dict[str, str], missing_key["error"])["code"] == ErrorCode.INVALID_INPUT.value

        # 3. store_owner (dan) sees fresh startup DoctorRun; Owner A (alice) & Owner B (bob) NEVER coalesce onto it!
        dan_health = _validate_envelope(
            "get_health",
            client.call(
                target,
                ToolCommand(
                    "get_health",
                    {"schema_version": "2.0", "deep": True, "idempotency_key": "idem_dan_startup_0001"},
                    token=cred_dan.token,
                ),
                deadline_ns=mono.now + TOTAL_REQUEST_BUDGET_NS,
            ),
        )
        assert dan_health["ok"] is True
        dan_data = cast(dict[str, Any], dan_health["data"])
        assert isinstance(dan_data.get("doctor_run_id"), str) and dan_data["doctor_run_id"]
        assert dan_data.get("job_id") is None
        assert isinstance(dan_data.get("age_s"), (int, float)) and dan_data["age_s"] >= 0

        alice_health_1 = _validate_envelope(
            "get_health",
            client.call(
                target,
                ToolCommand(
                    "get_health",
                    {"schema_version": "2.0", "deep": True, "idempotency_key": "idem_alice_deep_0001"},
                    token=cred_alice.token,
                ),
                deadline_ns=mono.now + TOTAL_REQUEST_BUDGET_NS,
            ),
        )
        assert alice_health_1["ok"] is True
        alice_data_1 = cast(dict[str, Any], alice_health_1["data"])
        alice_job_id = cast(str, alice_data_1["job_id"])
        assert isinstance(alice_job_id, str) and alice_job_id
        assert alice_data_1.get("doctor_run_id") is None

        assert loop.wait_doctor_settled(timeout=BOUND_WAIT_S)

        # Even AFTER alice's DoctorRun succeeded, bob's get_health(deep=True) creates bob's OWN system.doctor job!
        bob_health_1 = _validate_envelope(
            "get_health",
            client.call(
                target,
                ToolCommand(
                    "get_health",
                    {"schema_version": "2.0", "deep": True, "idempotency_key": "idem_bob_deep_0001"},
                    token=cred_bob.token,
                ),
                deadline_ns=mono.now + TOTAL_REQUEST_BUDGET_NS,
            ),
        )
        assert bob_health_1["ok"] is True
        bob_data_1 = cast(dict[str, Any], bob_health_1["data"])
        bob_job_id = cast(str, bob_data_1["job_id"])
        assert isinstance(bob_job_id, str) and bob_job_id and bob_job_id != alice_job_id
        assert bob_data_1.get("doctor_run_id") is None

        assert loop.wait_doctor_settled(timeout=BOUND_WAIT_S)

        with _ro_db(root.store_db) as conn:
            row_a = conn.execute(
                "SELECT owner_id, kind, state FROM p_jobs_state WHERE job_id = ?", (alice_job_id,)
            ).fetchone()
            row_b = conn.execute(
                "SELECT owner_id, kind, state FROM p_jobs_state WHERE job_id = ?", (bob_job_id,)
            ).fetchone()
            assert row_a == ("alice", "system.doctor", "succeeded")
            assert row_b == ("bob", "system.doctor", "succeeded")

        # Multi-owner get_job isolation: bob & dan calling get_job(alice_job_id) -> NOT_FOUND; alice succeeds.
        for foreign_tok in (cred_bob.token, cred_dan.token):
            denied = _validate_envelope(
                "get_job",
                client.call(
                    target,
                    ToolCommand("get_job", {"schema_version": "2.0", "job_id": alice_job_id}, token=foreign_tok),
                    deadline_ns=mono.now + TOTAL_REQUEST_BUDGET_NS,
                ),
            )
            assert denied == {"ok": False, "error": {"code": "not_found", "message": "not found"}}

        alice_job_ok = _validate_envelope(
            "get_job",
            client.call(
                target,
                ToolCommand("get_job", {"schema_version": "2.0", "job_id": alice_job_id}, token=cred_alice.token),
                deadline_ns=mono.now + TOTAL_REQUEST_BUDGET_NS,
            ),
        )
        assert alice_job_ok["ok"] is True and cast(dict[str, Any], alice_job_ok["data"])["state"] == "succeeded"

        # 4. Idempotent replay & IDEMPOTENCY_CONFLICT on mismatched scope/params.
        alice_fresh = _validate_envelope(
            "get_health",
            client.call(
                target,
                ToolCommand(
                    "get_health",
                    {"schema_version": "2.0", "deep": True, "idempotency_key": "idem_alice_replay_key1"},
                    token=cred_alice.token,
                    selected_scope=scope_a,
                ),
                deadline_ns=mono.now + TOTAL_REQUEST_BUDGET_NS,
            ),
        )
        assert alice_fresh["ok"] is True
        alice_fresh_data = cast(dict[str, Any], alice_fresh["data"])
        assert isinstance(alice_fresh_data.get("doctor_run_id"), str)
        assert alice_fresh_data["doctor_run_id"] != dan_data["doctor_run_id"]
        assert alice_fresh_data.get("job_id") is None

        with _ro_db(root.store_db) as conn:
            jobs_before_replay = int(conn.execute("SELECT COUNT(*) FROM p_jobs_state").fetchone()[0])

        alice_replay = _validate_envelope(
            "get_health",
            client.call(
                target,
                ToolCommand(
                    "get_health",
                    {"schema_version": "2.0", "deep": True, "idempotency_key": "idem_alice_replay_key1"},
                    token=cred_alice.token,
                    selected_scope=scope_a,
                ),
                deadline_ns=mono.now + TOTAL_REQUEST_BUDGET_NS,
            ),
        )
        assert alice_replay == alice_fresh
        with _ro_db(root.store_db) as conn:
            assert int(conn.execute("SELECT COUNT(*) FROM p_jobs_state").fetchone()[0]) == jobs_before_replay

        # Mismatched selected_scope with same idempotency_key -> IDEMPOTENCY_CONFLICT.
        for bad_replay_scope in (None, scope_a2):
            conflict = _validate_envelope(
                "get_health",
                client.call(
                    target,
                    ToolCommand(
                        "get_health",
                        {"schema_version": "2.0", "deep": True, "idempotency_key": "idem_alice_replay_key1"},
                        token=cred_alice.token,
                        selected_scope=bad_replay_scope,
                    ),
                    deadline_ns=mono.now + TOTAL_REQUEST_BUDGET_NS,
                ),
            )
            assert conflict == {
                "ok": False,
                "error": {"code": "idempotency_conflict", "message": "idempotency conflict"},
            }

        # 5. Scope(repo_id, None) rejected pre-queue (LoopbackClient / OwnerLoop) for both deep=False and deep=True.
        partial_args_list: tuple[dict[str, JsonValue], ...] = (
            {"schema_version": "2.0", "deep": False},
            {"schema_version": "2.0", "deep": True, "idempotency_key": "idem_partial_scope_01"},
        )
        for args in partial_args_list:
            res_partial = _validate_envelope(
                "get_health",
                client.call(
                    target,
                    ToolCommand("get_health", args, token=cred_alice.token, selected_scope=partial_scope_a),
                    deadline_ns=mono.now + TOTAL_REQUEST_BUDGET_NS,
                ),
            )
            assert res_partial == {"ok": False, "error": {"code": "not_found", "message": "not found"}}

        # 6. Workspace-bound build_tool_caller forwards selected_scope on get_health(deep=True).
        prof_dir = trusted_tmp / "profiles"
        ca_file = write_ca_file(prof_dir / "ca.pem", ca_pem)
        cred_file = write_credential_file(prof_dir / "alice.cred", cred_alice.token)
        prof_path, _ = write_client_profile_file(
            prof_dir / "alice-ws-a.json",
            endpoint_path=root.endpoint_path,
            expected_store_id=rep.store_id,
            ca_file=ca_file,
            leaf_cert_sha256=leaf_sha256,
            credential_file=cred_file,
            workspace={
                "alias": ws_a.alias,
                "checkout_path": str(chk_a_dir),
                "expected_workspace_id": ws_a.repo_id,
                "expected_checkout_id": ws_a.checkout_id,
            },
        )
        forwarded_scopes: list[Scope | None] = []
        orig_submit = loop.submit_reply

        def _spy_submit(command: ToolCommand, dl_ns: int) -> Future[OwnerReply]:
            if command.tool == "get_health":
                forwarded_scopes.append(command.selected_scope)
            return orig_submit(command, dl_ns)

        monkeypatch.setattr(loop, "submit_reply", _spy_submit)
        caller = build_tool_caller(prof_path, chk_a_dir, os_adapters(clock=clock, monotonic=mono))
        shim_res = _validate_envelope(
            "get_health",
            caller("get_health", {"schema_version": "2.0", "deep": True, "idempotency_key": "idem_shim_deep_scope_1"}),
        )
        assert shim_res["ok"] is True
        assert forwarded_scopes == [scope_a], (
            "workspace-bound build_tool_caller must forward selected_scope on get_health(deep=True), "
            f"got {forwarded_scopes}"
        )

    # 7. Revoking workspace grant blocks get_health(deep=True) via build_tool_caller (fresh key AND replay).
    rt_rev = reopen_kernel_job_runtime(cfg.data_root, rep.store_id, os_)
    try:
        with rt_rev.policy._immediate() as pdb:
            cur = pdb.execute(
                "DELETE FROM repo_grant WHERE principal_id = ? AND repo_id = ?",
                (cred_alice.principal.principal_id, ws_a.repo_id),
            )
            assert cur.rowcount == 1
    finally:
        rt_rev.close()

    with _running_serve(cfg, os_=os_, clock=clock, mono=mono) as (_ready2, loop2):
        assert loop2.wait_doctor_settled(timeout=BOUND_WAIT_S)
        caller_after_revoke = build_tool_caller(prof_path, chk_a_dir, os_adapters(clock=clock, monotonic=mono))
        for key in ("idem_shim_deep_scope_1", "idem_shim_after_revoke_2"):
            blocked = _validate_envelope(
                "get_health",
                caller_after_revoke("get_health", {"schema_version": "2.0", "deep": True, "idempotency_key": key}),
            )
            assert blocked == {"ok": False, "error": {"code": "not_found", "message": "not found"}}

    # 8. Direct pre-queue admit_prequeue_request & direct KernelBridge dispatch/render_current checks.
    rt_direct = reopen_kernel_job_runtime(cfg.data_root, rep.store_id, os_)
    try:
        # Re-grant ws_a so we prove Scope(repo_id, None) is rejected even when repo_grant exists!
        with rt_direct.policy._immediate() as pdb:
            pdb.execute(
                "INSERT INTO repo_grant (principal_id, repo_id, granted_intent_id, created_at) VALUES (?, ?, ?, ?)",
                (cred_alice.principal.principal_id, ws_a.repo_id, new_id(), utc_timestamp(clock.now())),
            )
        snap = rt_direct.policy.snapshot()
        key_id, key_bytes = rt_direct.policy.request_digest_key()
        auth_state = AtomicRequestAuthState(rep.store_id)
        auth_state.install(
            RequestAuthView(
                version=1,
                auth=snap,
                active_request_key_id=key_id,
                active_request_key_bytes=key_bytes,
            )
        )
        deadlines = RequestDeadlines.from_receive_ns(mono.now)
        direct_partial_args: tuple[dict[str, JsonValue], ...] = (
            {"schema_version": "2.0", "deep": False},
            {"schema_version": "2.0", "deep": True, "idempotency_key": "idem_prequeue_partial_01"},
        )
        for deep_args in direct_partial_args:
            with pytest.raises(BrainError) as pq_err:
                admit_prequeue_request(
                    expected_store_id=rep.store_id,
                    writer_epoch=rt_direct.lease.epoch,
                    auth_state=auth_state,
                    tool="get_health",
                    raw_arguments=deep_args,
                    token=cred_alice.token,
                    deadlines=deadlines,
                    selected_scope=partial_scope_a,
                )
            assert pq_err.value.code is ErrorCode.NOT_FOUND

        # Direct owner dispatch (KernelBridge) rejects Scope(repo_id, None) with NOT_FOUND.
        recorded_actions: list[tuple[Scope | None, str]] = []
        orig_allows = rt_direct.policy.allows

        def _spy_allows(principal: Principal, scope: Scope | None, *, action: str) -> bool:
            recorded_actions.append((scope, action))
            return orig_allows(principal, scope, action=action)

        monkeypatch.setattr(rt_direct.policy, "allows", _spy_allows)
        bridge = KernelBridge(
            store=rt_direct.store,
            policy=rt_direct.policy,
            clock=clock,
            monotonic_clock=mono,
            writer_epoch=rt_direct.lease.epoch,
        )
        ident = Identity(store_id=rep.store_id, writer_epoch=rt_direct.lease.epoch, instance_id=new_id())
        auth = PrivateRequestAuth(
            credential_id=cred_alice.credential_id,
            principal=cred_alice.principal,
            token=cred_alice.token,
        )
        bridge_partial_args: tuple[dict[str, JsonValue], ...] = (
            {"schema_version": "2.0", "deep": False},
            {"schema_version": "2.0", "deep": True, "idempotency_key": "idem_direct_partial_01"},
        )
        for deep_args in bridge_partial_args:
            call_partial = normalize_call(
                "get_health", deep_args, cred_alice.principal, selected_scope=partial_scope_a
            )
            ctx_partial = CallContext(
                identity=ident,
                principal=cred_alice.principal,
                selected_scope=partial_scope_a,
                deadline_ns=mono.now + TOTAL_REQUEST_BUDGET_NS,
            )
            direct_res = _validate_envelope("get_health", bridge.dispatch(call_partial, ctx_partial, auth=auth))
            assert direct_res == {"ok": False, "error": {"code": "not_found", "message": "not found"}}

        # Verify doctor_run stored ref resolves authorization with action="get_health" (and rejects partial scope).
        with _ro_db(root.store_db) as conn:
            row_id = conn.execute(
                "SELECT result_id, assignment_id, refs_json FROM idempotency"
                " WHERE principal_id = ? AND tool = 'get_health' LIMIT 1",
                (cred_alice.principal.principal_id,),
            ).fetchone()
            assert row_id is not None
            stored_doctor_run = StoredResult(
                result_id=str(row_id[0]),
                assignment_id=None if row_id[1] is None else str(row_id[1]),
                refs=StoredResult.decode_refs_json(str(row_id[2])),
            )
        assert any(r.kind == "doctor_run" for r in stored_doctor_run.refs)

        recorded_actions.clear()
        with contextlib.suppress(BrainError):
            bridge.render_current(stored_doctor_run, cred_alice.principal, selected_scope=scope_a)
        assert (scope_a, "get_health") in recorded_actions

        with pytest.raises(BrainError) as rc_partial_err:
            bridge.render_current(stored_doctor_run, cred_alice.principal, selected_scope=partial_scope_a)
        assert rc_partial_err.value.code is ErrorCode.NOT_FOUND
    finally:
        rt_direct.close()


# ---------------------------------------------------------------------------
# Requirement 5: Online restore fence (DaemonRestoreHandler._post_restore_reconcile)
# ---------------------------------------------------------------------------


def test_online_restore_fences_inflight_and_queued_prerestore_doctor_runs(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Online store/policy restore cancels/discards in-flight and queued pre-restore ``system.doctor`` runs."""
    clock = FakeClock(_base_utc_now())
    mono = FakeMonotonicClock(1_000_000_000)
    rep, cfg, priv, ca_pem, leaf_sha256, cli_token, os_ = _init_doctor_root(trusted_tmp / "restore-fence", clock)
    root = DataRoot.at(cfg.data_root)

    # Seed dan + bob + carol + baseline policy backup & store backup (containing a pre-restore queued doctor job).
    rt = reopen_kernel_job_runtime(cfg.data_root, rep.store_id, os_)
    try:
        cred_dan = seed_principal_and_credential(rt.policy, owner_id=OWNER_DAN, machine_id=MACHINE_ID)
        cred_bob = seed_principal_and_credential(rt.policy, owner_id="bob", machine_id=MACHINE_ID)
        cred_carol = seed_principal_and_credential(rt.policy, owner_id="carol", machine_id=MACHINE_ID)
        policy_bak = create_policy_backup(rt.policy, os_, clock.now())
        # Add an extra policy quarantine so policy backup diff is non-empty.
        rt.policy.record_intent(IntentKind.QUARANTINE, {"digest": digest_bytes(b"post-bak-quarantine-i42")})
        rt.store.reconcile_policy()

        svc, ks = kernel_job_service(rt, clock)
        bak_queued_doc_id = enqueue_job(svc, ks, owner_id=OWNER_DAN, kind="system.doctor", payload=b"{}").job_id
        store_bak_queued = create_store_backup(rt.store, os_, clock.now())
        # Cancel bak_queued_doc_id in the live pre-restore DB so startup doesn't run it before Part A.
        svc.cancel(bak_queued_doc_id, cred_dan.principal, selected_scope=None)
    finally:
        rt.close()

    # Arm StorageDoctorReader.read_snapshot pause/marker for targeted in-flight pre-restore calls.
    orig_read_snapshot = StorageDoctorReader.read_snapshot
    gate_lock = threading.Lock()
    pause_next_probe = [False]
    probe_entered = threading.Event()
    allow_probe_finish = threading.Event()
    probe_finished = threading.Event()

    def _wrapped_read_snapshot(
        self: StorageDoctorReader,
        data_root: Path,
        *,
        checkout_root: Path | None = None,
        expected_store_id: str | None = None,
        privacy_scanner: Any = None,
        capture_probe: Any = None,
        limits: Any = None,
        **kwargs: Any,
    ) -> DoctorSnapshot:
        with gate_lock:
            should_pause = pause_next_probe[0]
            if should_pause:
                pause_next_probe[0] = False
        snap = orig_read_snapshot(
            self,
            data_root,
            checkout_root=checkout_root,
            expected_store_id=expected_store_id,
            privacy_scanner=privacy_scanner,
            capture_probe=capture_probe,
            limits=limits,
            **kwargs,
        )
        if should_pause:
            probe_entered.set()
            assert allow_probe_finish.wait(timeout=BOUND_WAIT_S), "restore-fence probe barrier timed out"
            tagged = replace(snap, integrity_errors=(*snap.integrity_errors, "stale_prerestore_probe_marker"))
            probe_finished.set()
            return tagged
        return snap

    monkeypatch.setattr(StorageDoctorReader, "read_snapshot", _wrapped_read_snapshot)

    def _run_online_restore(ready: Ready, target_kind: str, backup_path: Path) -> None:
        prev = _post_tls(
            ready, ca_pem, "/v2/operator/restore", cli_token, {"target": target_kind, "backup": str(backup_path)}
        )
        assert prev["ok"] is True, prev
        ch = cast(dict[str, Any], prev["data"]["challenge"])
        migs = KERNEL_POLICY_MIGRATIONS if target_kind == "policy" else KERNEL_STORE_MIGRATIONS
        manifest = verify_backup(
            backup_path,
            expected_kind=cast(Any, target_kind),
            expected_store_id=rep.store_id,
            migrations=migs,
            os_=os_,
        )
        msg = _restore_msg(str(ch["store_id"]), OWNER_DAN, ch, manifest.db_digest)
        ap = {
            "message": msg.to_dict(),
            "channel": ApprovalChannel.SSH_KEY.value,
            "signer_id": rep.signer.signer_id,
            "signature": _ssh_sig_b64(priv, msg.canonical_bytes()),
        }
        done = _post_tls(
            ready,
            ca_pem,
            "/v2/operator/restore",
            cli_token,
            {"target": target_kind, "backup": str(backup_path), "approval": ap},
        )
        assert done["ok"] is True, done

    def _assert_no_stale_marker_in_store() -> None:
        with _ro_db(root.store_db) as conn:
            entries = conn.execute("SELECT refs FROM ledger WHERE kind = 'doctor.run'").fetchall()
            for (raw_refs,) in entries:
                for dig in cast(list[str], json.loads(bytes(raw_refs).decode("utf-8"))):
                    bpath = blob_path(root.cas_dir, dig)
                    if bpath.is_file():
                        assert b"stale_prerestore_probe_marker" not in bpath.read_bytes(), (
                            f"stale pre-restore DoctorRun blob committed into post-restore store ({dig})"
                        )

    with _running_serve(cfg, os_=os_, clock=clock, mono=mono) as (ready, loop):
        assert loop.wait_doctor_settled(timeout=BOUND_WAIT_S)

        target = LoopbackTarget(
            endpoint=ready.endpoint,
            expected_store_id=rep.store_id,
            ca_pem=ca_pem,
            leaf_cert_sha256=leaf_sha256,
        )
        client = LoopbackClient(monotonic_ns=mono.monotonic_ns)

        # --- Part A: Online policy restore fences in-flight + queued pre-restore system.doctor runs ---
        with gate_lock:
            pause_next_probe[0] = True
        probe_entered.clear()
        allow_probe_finish.clear()
        probe_finished.clear()

        inflight_res = _validate_envelope(
            "get_health",
            client.call(
                target,
                ToolCommand(
                    "get_health",
                    {"schema_version": "2.0", "deep": True, "idempotency_key": "idem_restore_inflight_1"},
                    token=cred_bob.token,
                ),
                deadline_ns=mono.now + TOTAL_REQUEST_BUDGET_NS,
            ),
        )
        assert inflight_res["ok"] is True
        inflight_job_id = cast(str, cast(dict[str, Any], inflight_res["data"])["job_id"])
        assert isinstance(inflight_job_id, str)
        assert probe_entered.wait(timeout=BOUND_WAIT_S), "pre-restore system.doctor probe did not enter"

        # Queue a 2nd pre-restore system.doctor job (carol) while bob's probe is paused in-flight.
        queued_res = _validate_envelope(
            "get_health",
            client.call(
                target,
                ToolCommand(
                    "get_health",
                    {"schema_version": "2.0", "deep": True, "idempotency_key": "idem_restore_queued_2"},
                    token=cred_carol.token,
                ),
                deadline_ns=mono.now + TOTAL_REQUEST_BUDGET_NS,
            ),
        )
        assert queued_res["ok"] is True
        queued_job_id = cast(str, cast(dict[str, Any], queued_res["data"])["job_id"])
        assert isinstance(queued_job_id, str)

        # Execute online policy restore while pre-restore probe is still paused!
        _run_online_restore(ready, "policy", policy_bak)

        # Now release the paused pre-restore probe and drain owner work.
        allow_probe_finish.set()
        assert probe_finished.wait(timeout=BOUND_WAIT_S)
        loop.run_owner_action(lambda: None).result(timeout=BOUND_WAIT_S)
        assert loop.wait_doctor_settled(timeout=BOUND_WAIT_S)

        with _ro_db(root.store_db) as conn:
            st_in = conn.execute("SELECT state FROM p_jobs_state WHERE job_id = ?", (inflight_job_id,)).fetchone()
            st_q = conn.execute("SELECT state FROM p_jobs_state WHERE job_id = ?", (queued_job_id,)).fetchone()
            assert st_in is not None and str(st_in[0]) in {JobState.CANCELLED.value, JobState.FAILED.value}
            assert st_q is not None and str(st_q[0]) == JobState.CANCELLED.value
        _assert_no_stale_marker_in_store()

        # --- Part B: Online store restore fences in-flight probe AND cancels queued doctor job in restored backup ---
        ep_a = read_client_endpoint(root.endpoint_path, os_)
        assert ep_a.writer_epoch == ready.endpoint.writer_epoch + 1
        with pytest.raises(LoopbackTransportError) as stale_err:
            client.call(
                target,
                ToolCommand("get_health", {"schema_version": "2.0", "deep": False}, token=cred_bob.token),
                deadline_ns=mono.now + TOTAL_REQUEST_BUDGET_NS,
            )
        assert stale_err.value.code is ErrorCode.IDENTITY_MISMATCH
        target_a = replace(target, endpoint=ep_a)
        ready_a = replace(ready, endpoint=ep_a, identity=ep_a.identity)

        with gate_lock:
            pause_next_probe[0] = True
        probe_entered.clear()
        allow_probe_finish.clear()
        probe_finished.clear()

        inflight_store_res = _validate_envelope(
            "get_health",
            client.call(
                target_a,
                ToolCommand(
                    "get_health",
                    {"schema_version": "2.0", "deep": True, "idempotency_key": "idem_restore_store_inf_3"},
                    token=cred_bob.token,
                ),
                deadline_ns=mono.now + TOTAL_REQUEST_BUDGET_NS,
            ),
        )
        assert inflight_store_res["ok"] is True
        assert probe_entered.wait(timeout=BOUND_WAIT_S), "pre-store-restore probe did not enter"

        _run_online_restore(ready_a, "store", store_bak_queued)

        allow_probe_finish.set()
        assert probe_finished.wait(timeout=BOUND_WAIT_S)
        loop.run_owner_action(lambda: None).result(timeout=BOUND_WAIT_S)
        assert loop.wait_doctor_settled(timeout=BOUND_WAIT_S)

        with _ro_db(root.store_db) as conn:
            st_bak = conn.execute("SELECT state FROM p_jobs_state WHERE job_id = ?", (bak_queued_doc_id,)).fetchone()
            assert st_bak is not None and str(st_bak[0]) == JobState.CANCELLED.value, (
                f"queued pre-restore system.doctor job in restored backup must be cancelled, got {st_bak}"
            )
        _assert_no_stale_marker_in_store()

        # Fresh post-restore get_health(deep=True) works cleanly after restore!
        ep_b = read_client_endpoint(root.endpoint_path, os_)
        assert ep_b.writer_epoch == ep_a.writer_epoch + 1
        target_b = replace(target, endpoint=ep_b)
        post_res = _validate_envelope(
            "get_health",
            client.call(
                target_b,
                ToolCommand(
                    "get_health",
                    {"schema_version": "2.0", "deep": True, "idempotency_key": "idem_post_restore_clean_4"},
                    token=cred_bob.token,
                ),
                deadline_ns=mono.now + TOTAL_REQUEST_BUDGET_NS,
            ),
        )
        assert post_res["ok"] is True
