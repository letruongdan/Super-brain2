"""get_health(deep=True): a doctor-backed result rendered with live clock, capture-gap and Layer-2 codes."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import cast

from superbrain.application.dispatch import PreparedEffect
from superbrain.composition import _daemon_health as _m
from superbrain.composition._layer2_live import layer2_drift_detected
from superbrain.core._json_parse import parse_json
from superbrain.core._kernel_approval import CLI_HARNESS_ID
from superbrain.core.canonical import canonical_json
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    ObjectRef,
    Principal,
    RetentionClass,
    StoredResult,
    parse_canonical_utc,
    require_aware_utc,
    require_uuid,
)
from superbrain.ports.kernel import KernelTx
from superbrain.storage.capture_events import KernelCaptureStore
from superbrain.storage.cas import read_held_blob_or_none
from superbrain.storage.idempotency import StagedKernelStore
from superbrain.storage.retention import default_expiry
from superbrain.storage.runtime import Runtime


def prepare_deep_health(
    rt: Runtime,
    job_store: StagedKernelStore,
    *,
    owner_id: str,
    now: datetime,
) -> PreparedEffect:
    """Prepare idempotent ``get_health(deep=True)`` effect scoped strictly by ``owner_id``."""
    now_utc, stamp = require_aware_utc(now)
    exp_at = default_expiry(RetentionClass.EVENT_PAYLOAD, now_utc, _m.RETENTION_POLICY)
    assert exp_at is not None
    result_id = new_id()

    latest_res = _m.find_latest_valid_doctor_run(rt, owner_id, now_utc, checkout_root=None)
    latest_run = latest_res[0] if latest_res is not None else None
    is_fresh = latest_run is not None and (now_utc - latest_run.recorded_at <= _m.DOCTOR_FRESHNESS_WINDOW)
    existing_job_id = _m.find_active_doctor_job(rt, job_store, owner_id=owner_id, checkout_root=None)

    target_job_id = existing_job_id if existing_job_id is not None else new_id()
    if is_fresh and existing_job_id is None:
        assert latest_run is not None
        desc_payload: dict[str, JsonValue] = {
            "schema": 1,
            "mode": "run",
            "owner_id": owner_id,
            "doctor_run_id": latest_run.doctor_run_id,
            "doctor_run_digest": latest_run.report_digest,
            "job_id": None,
        }
        enqueue_payload: bytes | None = None
    else:
        desc_payload = {
            "schema": 1,
            "mode": "job",
            "owner_id": owner_id,
            "doctor_run_id": latest_run.doctor_run_id if latest_run is not None else None,
            "doctor_run_digest": latest_run.report_digest if latest_run is not None else None,
            "job_id": target_job_id,
        }
        enqueue_payload = (
            None if existing_job_id is not None else canonical_json({"schema": 1, "trigger": "get_health"})
        )

    desc_bytes = canonical_json(desc_payload)
    blobs = (desc_bytes,) if enqueue_payload is None else (enqueue_payload, desc_bytes)

    def apply_effect(tx: KernelTx) -> StoredResult:
        if enqueue_payload is not None:
            _m.enqueue_doctor_tx(
                tx, job_id=target_job_id, owner_id=owner_id, payload_bytes=enqueue_payload, retry_at=stamp
            )
        desc_dig = tx.hold_blob(
            desc_bytes, holder_id=result_id, retention=RetentionClass.EVENT_PAYLOAD, expires_at=exp_at
        )
        refs = (
            (
                ObjectRef(
                    kind="doctor_run",
                    id=latest_run.doctor_run_id,
                    revision=1,
                    digest=latest_run.report_digest,
                ),
                ObjectRef(kind="get_health_descriptor", id=result_id, revision=1, digest=desc_dig),
            )
            if latest_run is not None
            else (ObjectRef(kind="doctor_run", id=result_id, revision=1, digest=desc_dig),)
        )
        return StoredResult(result_id=result_id, assignment_id=None, refs=refs)

    return PreparedEffect(blobs=blobs, apply=apply_effect)




# Conditions published as live: their DoctorRun-time copies are dropped and the current state is added.
_LIVE_CODES = frozenset({"capture_gap_present", "sp2.capture_gaps", "harness.layer2", "sp2.layer2_drift"})


def historical_codes(run_doc: dict[str, JsonValue]) -> tuple[str, ...]:
    """A DoctorRun's degraded codes minus the ones deep health re-evaluates live (they may have cleared since)."""
    stored = run_doc.get("degraded_codes", [])
    return tuple(c for c in map(str, cast(list[object], stored)) if c not in _LIVE_CODES)


def _live_layer2_degraded(rt: Runtime, host_version_resolver: Callable[[str], str | None] | None) -> bool:
    """Doctor ``harness.layer2`` WARN, read live: terminal not eligible for a connected non-CLI harness, or a
    VERIFIED harness whose checkout config changed on disk since (read-only; the next live check records it)."""
    if layer2_drift_detected(rt.policy, os_=rt.os_, host_version_resolver=host_version_resolver):
        return True
    snap = rt.policy.snapshot()
    machines = {
        c.principal.machine_id
        for c in snap.credentials.values()
        if not c.revoked and c.principal.harness_id != CLI_HARNESS_ID
    }
    # every machine eligible == eligible across all machines (the doctor reads it with machine_id=None)
    return any(not rt.policy.terminal_channel_eligible(machine_id=m) for m in sorted(machines))


def render_deep_health(
    rt: Runtime,
    job_store: StagedKernelStore,
    result: StoredResult,
    principal: Principal,
    *,
    now: datetime,
    tls_not_after: datetime,
    clock_untrusted_fn: Callable[[], bool],
    host_version_resolver: Callable[[str], str | None] | None = None,
) -> dict[str, JsonValue]:
    """Render ``get_health(deep=True)`` from CAS descriptor & live policy/quarantine/clock/capture-gap checks."""
    # live like clock trust: a gap opened after the latest DoctorRun must still show (SP2-5 deep health contract)
    gaps_now = KernelCaptureStore(rt.store).has_gaps() if rt.store.schema_version >= 6 else False
    l2_now = (_m._LAYER2_CHECK_CODE,) if _live_layer2_degraded(rt, host_version_resolver) else ()
    if result.refs and result.refs[0].kind == "health_result":
        # a result stored by the SP2-5 deep-health producer (before the SP1-I4 merge): the stored object must still
        # be readable and not quarantined, as before; the answer then carries the same live codes, no run
        _require_stored_health_result(rt, result, now=now)
        return _live_only(rt, now=now, tls_not_after=tls_not_after, clock_untrusted_fn=clock_untrusted_fn,
                          gaps_now=gaps_now, l2_now=l2_now, job_id=None)
    desc_ref: ObjectRef | None = None
    run_ref: ObjectRef | None = None
    if len(result.refs) == 1 and result.refs[0].id == result.result_id:
        desc_ref = result.refs[0]
    else:
        for ref in result.refs:
            if ref.kind == "get_health_descriptor" and ref.id == result.result_id:
                desc_ref = ref
            elif ref.kind == "doctor_run":
                run_ref = ref
    if desc_ref is None:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")

    if rt.policy.is_quarantined(desc_ref.digest):
        raise BrainError(ErrorCode.QUARANTINED, "quarantined")
    if run_ref is not None and rt.policy.is_quarantined(run_ref.digest):
        raise BrainError(ErrorCode.QUARANTINED, "quarantined")

    now_utc, _ = require_aware_utc(now)
    with rt.store.transaction() as txn:
        desc_bytes = read_held_blob_or_none(
            txn.db,
            rt.store.cas,
            rt.policy,
            desc_ref.digest,
            holder_kind="event",
            holder_id=result.result_id,
            now=now_utc,
        )
        run_bytes: bytes | None = None
        if desc_bytes is not None and run_ref is not None:
            run_bytes = read_held_blob_or_none(
                txn.db,
                rt.store.cas,
                rt.policy,
                run_ref.digest,
                holder_kind="event",
                holder_id=run_ref.id,
                now=now_utc,
            )

    if desc_bytes is None:
        raise BrainError(ErrorCode.NOT_FOUND, "not found")
    desc = parse_json(desc_bytes)
    if not isinstance(desc, dict) or desc.get("owner_id") != principal.owner_id:
        raise BrainError(ErrorCode.NOT_FOUND, "not found")

    job_id = desc.get("job_id")
    if job_id is not None:
        require_uuid(job_id)
        _m._require_store_wide_doctor_job(rt, job_store, cast(str, job_id), owner_id=principal.owner_id)
    doctor_run_id = desc.get("doctor_run_id")

    if doctor_run_id is not None:
        if (
            run_ref is None
            or doctor_run_id != run_ref.id
            or desc.get("doctor_run_digest") != run_ref.digest
        ):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
        if run_bytes is None:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        run_doc = parse_json(run_bytes)
        if not isinstance(run_doc, dict):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
        if not _m.verify_doctor_run_fences(rt, run_doc, owner_id=principal.owner_id):
            raise BrainError(ErrorCode.REVISION_CONFLICT, "revision conflict")
        if not _m._doc_scope_matches(run_doc, None):
            raise BrainError(ErrorCode.REVISION_CONFLICT, "revision conflict")
        rec_raw = run_doc.get("recorded_at")
        if not isinstance(rec_raw, str):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
        age_s = max(0.0, (now_utc - parse_canonical_utc(rec_raw)).total_seconds())
        extra = historical_codes(run_doc)
        ready, degraded = _m.health_status_fields(
            now=now_utc,
            tls_not_after=tls_not_after,
            clock_untrusted=clock_untrusted_fn(),
            extra_codes=(*extra, *l2_now),
            capture_gaps_present=gaps_now,
        )
        return {
            "ready": ready,
            "store_id": rt.store.store_id,
            "writer_epoch": rt.lease.epoch,
            "schema_version": rt.store.schema_version,
            "policy_schema_version": rt.policy.schema_version,
            "degraded_codes": degraded,
            "doctor_run_id": doctor_run_id,
            "age_s": age_s,
            "job_id": job_id,
        }

    return _live_only(rt, now=now, tls_not_after=tls_not_after, clock_untrusted_fn=clock_untrusted_fn,
                      gaps_now=gaps_now, l2_now=l2_now, job_id=job_id)


def _require_stored_health_result(rt: Runtime, result: StoredResult, *, now: datetime) -> None:
    ref = result.refs[0]
    if rt.policy.is_quarantined(ref.digest):
        raise BrainError(ErrorCode.QUARANTINED, "quarantined")
    now_utc, _ = require_aware_utc(now)
    with rt.store.transaction() as txn:
        blob = read_held_blob_or_none(txn.db, rt.store.cas, rt.policy, ref.digest, holder_kind="event",
                                      holder_id=result.result_id, now=now_utc)
    if blob is None:
        raise BrainError(ErrorCode.NOT_FOUND, "not found")
    if not isinstance(parse_json(blob), dict):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")


def _live_only(
    rt: Runtime,
    *,
    now: datetime,
    tls_not_after: datetime,
    clock_untrusted_fn: Callable[[], bool],
    gaps_now: bool,
    l2_now: tuple[str, ...],
    job_id: object,
) -> dict[str, JsonValue]:
    """Deep health without a DoctorRun: only the live clock, TLS, capture-gap and Layer-2 codes."""
    now_utc, _ = require_aware_utc(now)
    ready, degraded = _m.health_status_fields(
        now=now_utc,
        tls_not_after=tls_not_after,
        clock_untrusted=clock_untrusted_fn(),
        extra_codes=l2_now,
        capture_gaps_present=gaps_now,
    )
    return {
        "ready": ready,
        "store_id": rt.store.store_id,
        "writer_epoch": rt.lease.epoch,
        "schema_version": rt.store.schema_version,
        "policy_schema_version": rt.policy.schema_version,
        "degraded_codes": degraded,
        "doctor_run_id": None,
        "age_s": None,
        "job_id": cast(JsonValue, job_id),
    }
