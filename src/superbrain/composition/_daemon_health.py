"""``DoctorRun`` bounded CAS serialization and ``get_health(deep=True)`` effect/render helpers."""

from __future__ import annotations

import contextlib
import json
import os
import sqlite3
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import cast

from superbrain.application._doctor_checks import clip_report_str
from superbrain.application.dispatch import PreparedEffect
from superbrain.application.doctor import DoctorReport
from superbrain.core._json_parse import parse_json
from superbrain.core.canonical import canonical_json
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    IDEMPOTENCY_CLOCK_UNTRUSTED_CODE,
    OPAQUE_ID_RE,
    TLS_EXPIRED_CODE,
    TLS_EXPIRING_CODE,
    TLS_EXPIRING_WINDOW,
    KernelRecord,
    ObjectRef,
    Principal,
    RetentionClass,
    StoredResult,
    parse_canonical_utc,
    require_aware_utc,
    require_uuid,
)
from superbrain.ports.doctor import MAX_DOCTOR_RUN_BLOB_BYTES
from superbrain.ports.kernel import KernelTx
from superbrain.ports.os import OsAdapters
from superbrain.storage.cas import read_held_blob_or_none
from superbrain.storage.idempotency import StagedKernelStore
from superbrain.storage.restore import read_restore_epoch
from superbrain.storage.retention import RetentionPolicy, default_expiry
from superbrain.storage.runtime import Runtime
from superbrain.storage.sqlite import open_readonly

DOCTOR_JOB_KIND = "system.doctor"
DOCTOR_FRESHNESS_WINDOW = timedelta(hours=24)
DOCTOR_OPERATOR_WINDOW = timedelta(minutes=15)
RETENTION_POLICY = RetentionPolicy()


@dataclass(frozen=True)
class RecentDoctorRun:
    """Recent non-quarantined, intact ``doctor.run`` entry belonging to one owner."""

    doctor_run_id: str
    report_digest: str
    recorded_at: datetime


def unique_opaque_codes(candidates: list[str]) -> list[JsonValue]:
    """Return deduplicated ``OpaqueId``-valid strings capped at 1024 items."""
    out: list[JsonValue] = []
    seen: set[str] = set()
    for code in candidates:
        if OPAQUE_ID_RE.fullmatch(code) and code not in seen:
            seen.add(code)
            out.append(code)
            if len(out) >= 1024:
                break
    return out


def health_status_fields(
    *,
    now: datetime,
    tls_not_after: datetime,
    clock_untrusted: bool,
    extra_codes: tuple[str, ...] = (),
) -> tuple[bool, list[JsonValue]]:
    """Compute ``(ready, degraded_codes)`` from TLS validity, clock trust, and optional check codes."""
    now_utc, _ = require_aware_utc(now)
    remaining = tls_not_after - now_utc
    codes: list[str] = []
    if clock_untrusted:
        codes.append(IDEMPOTENCY_CLOCK_UNTRUSTED_CODE)
    if remaining <= timedelta(0):
        codes.append(TLS_EXPIRED_CODE)
    elif remaining <= TLS_EXPIRING_WINDOW:
        codes.append(TLS_EXPIRING_CODE)
    codes.extend(extra_codes)
    ready = (not clock_untrusted) and (remaining > timedelta(0))
    return ready, unique_opaque_codes(codes)


def _compact_report_dict(report: DoctorReport, list_cap: int) -> dict[str, JsonValue]:
    raw = report.to_dict()
    for key in (
        "signers",
        "layer2_harnesses",
        "unresolved_accounting_locks",
        "pending_proposals",
        "bootstrap_drifts",
        "remediations",
        "integrity_errors",
        "active_turn_intents",
        "incomplete_journals",
        "permission_problems",
    ):
        val = raw.get(key)
        if isinstance(val, list):
            raw[key] = val[:list_cap]
    return raw


def build_doctor_run_bytes(
    *,
    doctor_run_id: str,
    owner_id: str,
    store_id: str,
    writer_epoch: int,
    job_id: str,
    trigger: str,
    recorded_at: str,
    report: DoctorReport,
    degraded_codes: list[JsonValue],
    checkout_root: str | None = None,
) -> bytes:
    """Serialize a privacy-filtered ``DoctorRun`` document strictly within ``MAX_DOCTOR_RUN_BLOB_BYTES``."""
    base: dict[str, JsonValue] = {
        "schema_version": 1,
        "doctor_run_id": doctor_run_id,
        "owner_id": owner_id,
        "store_id": store_id,
        "writer_epoch": writer_epoch,
        "job_id": job_id,
        "trigger": trigger,
        "recorded_at": recorded_at,
        "overall_status": report.overall_status,
        "degraded_codes": degraded_codes,
        "checkout_root": checkout_root,
    }
    for cap in (32, 8, 2, 0):
        candidate = canonical_json({**base, "report": _compact_report_dict(report, cap)})
        if len(candidate) <= MAX_DOCTOR_RUN_BLOB_BYTES:
            return candidate
    summary = [
        {"name": clip_report_str(c.name, 96), "group": clip_report_str(c.group, 32), "status": c.status}
        for c in report.checks
    ]
    compact = canonical_json({**base, "checks_summary": summary, "truncated": True})
    if len(compact) <= MAX_DOCTOR_RUN_BLOB_BYTES:
        return compact
    return canonical_json({**base, "truncated": True})


def enqueue_doctor_tx(
    tx: KernelTx,
    *,
    job_id: str,
    owner_id: str,
    payload_bytes: bytes,
    retry_at: str,
) -> None:
    """Enqueue one ``system.doctor`` job record and hold its durable payload blob."""
    payload_digest = tx.hold_blob(payload_bytes, holder_id=job_id)
    tx.append_record(
        KernelRecord(
            "job.queued",
            {
                "job_id": job_id,
                "owner_id": owner_id,
                "repo_id": None,
                "checkout_id": None,
                "kind": DOCTOR_JOB_KIND,
                "payload_digest": payload_digest,
                "attempt": 1,
                "retry_at": retry_at,
            },
        )
    )


LEDGER_PAGE_ROWS = 64
LEDGER_SCAN_CAP = 4096


def iter_owner_doctor_ledger(
    rt: Runtime,
    *,
    owner_id: str,
    current_epoch_only: bool = False,
    job_id: str | None = None,
) -> Iterator[tuple[dict[str, object], list[object]]]:
    """Yield ``owner_id``'s ``doctor.run`` ledger entries newest first, read-only, page by page.

    The owner (and optionally the job, and the current writer epoch, which every valid run must carry) is filtered in
    SQL, so other owners' entries never use up the scan. Paging stops when the caller stops iterating; past
    ``LEDGER_SCAN_CAP`` matching rows it raises ``STORE_BUSY`` instead of silently giving up.
    """
    clauses = ["kind = 'doctor.run'", "json_extract(CAST(meta AS TEXT), '$.owner_id') = ?"]
    params: list[object] = [owner_id]
    if current_epoch_only:
        clauses.append("writer_epoch = ?")
        params.append(rt.lease.epoch)
    if job_id is not None:
        clauses.append("json_extract(CAST(meta AS TEXT), '$.job_id') = ?")
        params.append(job_id)
    where = " AND ".join(clauses)
    scanned = 0
    before: int | None = None
    with contextlib.closing(open_readonly(rt.root.store_db)) as conn:
        while True:
            if before is None:
                page_where, page_params = where, (*params, LEDGER_PAGE_ROWS)
            else:
                page_where, page_params = f"{where} AND sequence < ?", (*params, before, LEDGER_PAGE_ROWS)
            rows = conn.execute(
                f"SELECT sequence, meta, refs FROM ledger WHERE {page_where} ORDER BY sequence DESC LIMIT ?",
                page_params,
            ).fetchall()
            if not rows:
                return
            for seq, raw_meta, raw_refs in rows:
                scanned += 1
                if scanned > LEDGER_SCAN_CAP:
                    raise BrainError(ErrorCode.STORE_BUSY, "doctor run scan limit reached")
                before = int(seq)
                try:
                    meta = json.loads(bytes(raw_meta).decode("utf-8"))
                    refs = json.loads(bytes(raw_refs).decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                if isinstance(meta, dict) and meta.get("owner_id") == owner_id and isinstance(refs, list):
                    yield meta, refs


def _valid_run_header(
    meta: Mapping[str, object], refs: list[object], now_utc: datetime
) -> tuple[str, str, str, datetime] | None:
    run_id = meta.get("doctor_run_id")
    rec_str = meta.get("recorded_at")
    digest = meta.get("report_digest")
    job_id = meta.get("job_id")
    if (
        not isinstance(run_id, str)
        or not isinstance(rec_str, str)
        or not isinstance(digest, str)
        or not isinstance(job_id, str)
        or not refs
        or refs[0] != digest
    ):
        return None
    try:
        rec_at = parse_canonical_utc(rec_str)
    except BrainError:
        return None
    if rec_at > now_utc:
        return None
    return run_id, digest, job_id, rec_at


def verify_doctor_run_fences(rt: Runtime, doc: Mapping[str, JsonValue], *, owner_id: str) -> bool:
    """Verify that a stored ``DoctorRun`` matches current store, writer epoch, restore epoch, and policy generation."""
    if (
        doc.get("owner_id") != owner_id
        or doc.get("store_id") != rt.store.store_id
        or doc.get("writer_epoch") != rt.lease.epoch
    ):
        return False
    rep = doc.get("report")
    if not isinstance(rep, Mapping):
        return False
    live_restore_epoch = (
        read_restore_epoch(rt.root, schema_version=rt.store.schema_version, os_=rt.os_)
        if rt.store.schema_version >= 5
        else 0
    )
    return (
        rep.get("restore_epoch") == live_restore_epoch
        and rep.get("trust_generation") == rt.policy.trust_generation()
    )


def doctor_scope_key(checkout_root: str | Path | None) -> str | None:
    """The comparison key of a doctor scope: ``None`` is store-wide, otherwise the checkout path as the OS compares it.

    Two spellings of one directory (case, separators, trailing separator on Windows) are one scope. The stored
    ``checkout_root`` keeps the caller's spelling; only comparisons go through this key.
    """
    if checkout_root is None:
        return None
    return os.path.normcase(os.path.normpath(str(checkout_root)))


def _doc_scope_matches(doc: Mapping[str, JsonValue], scope_key: str | None) -> bool:
    raw = doc.get("checkout_root")
    if raw is None:
        return scope_key is None
    return isinstance(raw, str) and bool(raw) and doctor_scope_key(raw) == scope_key


def find_latest_valid_doctor_run(
    rt: Runtime, owner_id: str, now: datetime, *, checkout_root: str | Path | None
) -> tuple[RecentDoctorRun, dict[str, JsonValue]] | None:
    """The newest fenced, intact ``doctor.run`` of scope ``(owner_id, checkout_root)``; ``None`` is store-wide."""
    now_utc, _ = require_aware_utc(now)
    scope_key = doctor_scope_key(checkout_root)
    try:
        for meta, refs in iter_owner_doctor_ledger(rt, owner_id=owner_id, current_epoch_only=True):
            hdr = _valid_run_header(meta, refs, now_utc)
            if hdr is None:
                continue
            run_id, digest, _job_id, rec_at = hdr
            if (
                rt.policy.is_quarantined(digest)
                or rt.policy.is_tombstoned("event", run_id)
                or not rt.store.cas.blob_intact(digest)
            ):
                continue
            doc = _read_doctor_run_cas_doc(rt, run_id=run_id, digest=digest, now_utc=now_utc)
            if doc is None or not verify_doctor_run_fences(rt, doc, owner_id=owner_id):
                continue
            if not _doc_scope_matches(doc, scope_key):
                continue
            return RecentDoctorRun(doctor_run_id=run_id, report_digest=digest, recorded_at=rec_at), doc
    except sqlite3.Error:
        return None
    return None


ACTIVE_DOCTOR_SCAN = 100
_NO_SCOPE = object()


def doctor_payload_scope(payload: bytes) -> str | None | object:
    """The ``checkout_root`` scope stored in a ``system.doctor`` job payload; ``_NO_SCOPE`` when unreadable."""
    try:
        parsed = parse_json(payload)
    except BrainError:
        return _NO_SCOPE
    if not isinstance(parsed, dict):
        return _NO_SCOPE
    raw = parsed.get("checkout_root")
    if raw is None:
        return None
    return raw if isinstance(raw, str) and raw else _NO_SCOPE


def find_active_doctor_job(
    rt: Runtime, job_store: StagedKernelStore, *, owner_id: str, checkout_root: str | Path | None
) -> str | None:
    """The queued/leased/running ``system.doctor`` job of scope ``(owner_id, checkout_root)``, read from durable data.

    Every path that enqueues a doctor job dedups through this one function, so one scope holds at most one slot
    whatever process, restore or trigger created it. Past ``ACTIVE_DOCTOR_SCAN`` active jobs it refuses
    (``STORE_BUSY``) rather than enqueue a duplicate it could not rule out.
    """
    scope_key = doctor_scope_key(checkout_root)
    rows = job_store.transact(lambda tx: tx.active_jobs_by_kinds((DOCTOR_JOB_KIND,), ACTIVE_DOCTOR_SCAN))
    for row in rows:
        if row.owner_id != owner_id:
            continue
        scope = doctor_payload_scope(rt.store.cas.read(row.payload_digest))
        if (scope is None or isinstance(scope, str)) and doctor_scope_key(scope) == scope_key:
            return row.job_id
    if len(rows) >= ACTIVE_DOCTOR_SCAN:
        raise BrainError(ErrorCode.STORE_BUSY, "too many active doctor jobs")
    return None


def prepare_deep_health(
    rt: Runtime,
    job_store: StagedKernelStore,
    *,
    owner_id: str,
    now: datetime,
) -> PreparedEffect:
    """Prepare idempotent ``get_health(deep=True)`` effect scoped strictly by ``owner_id``."""
    now_utc, stamp = require_aware_utc(now)
    exp_at = default_expiry(RetentionClass.EVENT_PAYLOAD, now_utc, RETENTION_POLICY)
    assert exp_at is not None
    result_id = new_id()

    latest_res = find_latest_valid_doctor_run(rt, owner_id, now_utc, checkout_root=None)
    latest_run = latest_res[0] if latest_res is not None else None
    is_fresh = latest_run is not None and (now_utc - latest_run.recorded_at <= DOCTOR_FRESHNESS_WINDOW)
    existing_job_id = find_active_doctor_job(rt, job_store, owner_id=owner_id, checkout_root=None)

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
            enqueue_doctor_tx(
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


def _require_store_wide_doctor_job(
    rt: Runtime, job_store: StagedKernelStore, job_id: str, *, owner_id: str
) -> None:
    """``job_id`` must be a durable ``system.doctor`` job of ``owner_id`` whose payload scope is store-wide.

    A stored descriptor is not trusted for this: an older binary could record a job picked by owner alone. Any state
    is accepted, since a replay returns the same answer and a job's scope never changes.
    """
    row = job_store.transact(lambda tx: tx.read_job(job_id))
    if row is None or row.owner_id != owner_id:
        raise BrainError(ErrorCode.NOT_FOUND, "not found")
    if row.kind != DOCTOR_JOB_KIND:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
    try:
        payload = rt.store.cas.read(row.payload_digest)
    except BrainError as err:
        if err.code is ErrorCode.QUARANTINED:
            raise
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure") from err
    scope = doctor_payload_scope(payload)
    if scope is not None and not isinstance(scope, str):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
    if scope is not None:
        raise BrainError(ErrorCode.REVISION_CONFLICT, "revision conflict")


def render_deep_health(
    rt: Runtime,
    job_store: StagedKernelStore,
    result: StoredResult,
    principal: Principal,
    *,
    now: datetime,
    tls_not_after: datetime,
    clock_untrusted_fn: Callable[[], bool],
) -> dict[str, JsonValue]:
    """Render ``get_health(deep=True)`` from CAS descriptor & live policy/quarantine/clock checks."""
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
        _require_store_wide_doctor_job(rt, job_store, cast(str, job_id), owner_id=principal.owner_id)
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
        if not verify_doctor_run_fences(rt, run_doc, owner_id=principal.owner_id):
            raise BrainError(ErrorCode.REVISION_CONFLICT, "revision conflict")
        if not _doc_scope_matches(run_doc, None):
            raise BrainError(ErrorCode.REVISION_CONFLICT, "revision conflict")
        rec_raw = run_doc.get("recorded_at")
        if not isinstance(rec_raw, str):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
        age_s = max(0.0, (now_utc - parse_canonical_utc(rec_raw)).total_seconds())
        extra = tuple(str(c) for c in cast(list[object], run_doc.get("degraded_codes", [])))
        ready, degraded = health_status_fields(
            now=now_utc,
            tls_not_after=tls_not_after,
            clock_untrusted=clock_untrusted_fn(),
            extra_codes=extra,
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

    ready, degraded = health_status_fields(
        now=now_utc,
        tls_not_after=tls_not_after,
        clock_untrusted=clock_untrusted_fn(),
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
        "job_id": job_id,
    }


def doctor_run_dto_from_doc(
    doc: Mapping[str, JsonValue],
    *,
    doctor_run_id: str,
    job_id: str,
) -> dict[str, JsonValue]:
    """Build the completed ``/v2/operator/doctor/report`` DTO from a stored ``DoctorRun`` CAS document."""
    report_obj = doc.get("report")
    if not isinstance(report_obj, Mapping):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
    out = dict(report_obj)
    out["doctor_run_id"] = doctor_run_id
    out["job_id"] = job_id
    out["status"] = "completed"
    return out


def _read_doctor_run_cas_doc(
    rt: Runtime,
    *,
    run_id: str,
    digest: str,
    now_utc: datetime,
) -> dict[str, JsonValue] | None:
    if rt.policy.is_quarantined(digest):
        raise BrainError(ErrorCode.QUARANTINED, "quarantined")
    if rt.policy.is_tombstoned("event", run_id):
        return None
    with rt.store.transaction() as txn:
        raw = read_held_blob_or_none(
            txn.db,
            rt.store.cas,
            rt.policy,
            digest,
            holder_kind="event",
            holder_id=run_id,
            now=now_utc,
        )
    if raw is None:
        return None
    parsed = parse_json(raw)
    return parsed if isinstance(parsed, dict) else None


def find_fresh_doctor_run_dto(
    rt: Runtime,
    adapters: OsAdapters,
    owner_id: str,
    now: datetime,
    *,
    checkout_root: Path | None,
) -> dict[str, JsonValue] | None:
    """Return fresh completed ``DoctorRun`` DTO iff writer_epoch, restore_epoch, trust_generation and checkout match."""
    now_utc, _ = require_aware_utc(now)
    scope_key = doctor_scope_key(checkout_root)
    try:
        for meta, refs in iter_owner_doctor_ledger(rt, owner_id=owner_id, current_epoch_only=True):
            hdr = _valid_run_header(meta, refs, now_utc)
            if hdr is None:
                continue
            run_id, digest, job_id, rec_at = hdr
            if now_utc - rec_at > DOCTOR_OPERATOR_WINDOW:
                continue
            try:
                doc = _read_doctor_run_cas_doc(rt, run_id=run_id, digest=digest, now_utc=now_utc)
            except BrainError:
                return None
            if doc is None or not verify_doctor_run_fences(rt, doc, owner_id=owner_id):
                continue
            if not _doc_scope_matches(doc, scope_key) or not isinstance(doc.get("report"), Mapping):
                continue
            return doctor_run_dto_from_doc(doc, doctor_run_id=run_id, job_id=job_id)
    except sqlite3.Error:
        return None
    return None


def load_committed_doctor_run_dto(
    rt: Runtime,
    *,
    owner_id: str,
    job_id: str,
    doctor_run_id: str | None,
    now: datetime,
) -> dict[str, JsonValue]:
    """Load an owner's committed ``DoctorRun`` DTO from ledger + held CAS blob."""
    now_utc, _ = require_aware_utc(now)
    for meta, refs in iter_owner_doctor_ledger(rt, owner_id=owner_id, job_id=job_id):
        if doctor_run_id is not None and meta.get("doctor_run_id") != doctor_run_id:
            continue
        if meta.get("job_id") != job_id:
            continue
        run_id = meta.get("doctor_run_id")
        digest = meta.get("report_digest")
        if not isinstance(run_id, str) or not isinstance(digest, str) or not refs or refs[0] != digest:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
        doc = _read_doctor_run_cas_doc(rt, run_id=run_id, digest=digest, now_utc=now_utc)
        if doc is None or doc.get("owner_id") != owner_id:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        return doctor_run_dto_from_doc(doc, doctor_run_id=run_id, job_id=job_id)
    raise BrainError(ErrorCode.NOT_FOUND, "not found")
