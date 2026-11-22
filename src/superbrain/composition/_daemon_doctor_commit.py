"""Transactional doctor run commit and payload parsing helpers for ``DaemonDoctorRunner``."""

from __future__ import annotations

import contextlib
import os
import shutil
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from superbrain.application._privacy_canary import KernelPrivacyScanner
from superbrain.application.doctor import inspect_doctor_snapshot
from superbrain.composition._daemon_health import (
    RETENTION_POLICY,
    build_doctor_run_bytes,
    health_status_fields,
    iter_owner_doctor_ledger,
    load_committed_doctor_run_dto,
)
from superbrain.core._json_parse import parse_json
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    JobLease,
    JobState,
    KernelRecord,
    ObjectRef,
    RetentionClass,
    parse_canonical_utc,
    require_aware_utc,
    result_descriptor,
)
from superbrain.ports.doctor import DoctorSnapshot
from superbrain.ports.kernel import KernelTx
from superbrain.ports.os import OsAdapters
from superbrain.storage.idempotency import StagedKernelStore
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.restore import read_restore_epoch
from superbrain.storage.retention import default_expiry
from superbrain.storage.runtime import Runtime

DOCTOR_ACTOR = "system:doctor"
VALID_DOCTOR_TRIGGERS = frozenset({"startup", "schedule", "get_health", "cli", "fix", "manual"})


def resolve_store_owner(policy: PolicyStore) -> str:
    """Resolve authoritative owner_id for background scheduled ``system.doctor`` jobs."""
    owner = policy.store_owner()
    if owner is not None:
        return owner
    snap = policy.snapshot()
    if snap.principals:
        return sorted(p.owner_id for p in snap.principals.values())[0]
    return "system"


@dataclass(frozen=True)
class _CompletedDoctorProbe:
    generation: int
    lease: JobLease
    owner_id: str
    trigger: str
    checkout_root: Path | None
    snapshot: DoctorSnapshot | None
    scratch_dir: Path | None = None
    fence_store_id: str | None = None
    fence_writer_epoch: int | None = None
    fence_restore_epoch: int | None = None
    fence_trust_generation: int | None = None


def find_latest_intact_doctor_run(
    rt: Runtime,
    owner_id: str,
    now: datetime,
    *,
    max_age: timedelta,
) -> tuple[str, str, datetime] | None:
    """Return ``(doctor_run_id, report_digest, recorded_at)`` of latest intact, unquarantined run within max_age."""
    now_utc, _ = require_aware_utc(now)
    try:
        entries = iter_owner_doctor_ledger(rt, owner_id=owner_id, limit=64)
    except sqlite3.Error:
        return None
    for meta, refs in entries:
        run_id = meta.get("doctor_run_id")
        rec_str = meta.get("recorded_at")
        digest = meta.get("report_digest")
        if (
            not isinstance(run_id, str)
            or not isinstance(rec_str, str)
            or not isinstance(digest, str)
            or not refs
            or refs[0] != digest
        ):
            continue
        try:
            rec_at = parse_canonical_utc(rec_str)
        except BrainError:
            continue
        if not (timedelta(0) <= now_utc - rec_at <= max_age):
            continue
        if (
            rt.policy.is_quarantined(digest)
            or rt.policy.is_tombstoned("event", run_id)
            or not rt.store.cas.blob_intact(digest)
        ):
            continue
        return run_id, digest, rec_at
    return None


def parse_doctor_payload(payload: bytes) -> tuple[str, Path | None]:
    """Extract validated ``(trigger, checkout_root)`` from a ``system.doctor`` job payload."""
    try:
        parsed = parse_json(payload)
    except BrainError:
        return "manual", None
    if not isinstance(parsed, dict):
        return "manual", None
    raw_trig = parsed.get("trigger")
    trigger = raw_trig if isinstance(raw_trig, str) and raw_trig in VALID_DOCTOR_TRIGGERS else "manual"
    raw_co = parsed.get("checkout_root")
    checkout_root: Path | None = None
    if isinstance(raw_co, str) and raw_co and "\x00" not in raw_co:
        cand = Path(raw_co)
        if cand.is_absolute() and ".." not in cand.parts:
            checkout_root = cand
    return trigger, checkout_root


def commit_doctor_run_snapshot(
    *,
    rt: Runtime,
    job_store: StagedKernelStore,
    scanner: KernelPrivacyScanner,
    lease: JobLease,
    owner_id: str,
    trigger: str,
    checkout_root: Path | None,
    snapshot: DoctorSnapshot,
    now: datetime,
    tls_not_after: datetime,
    clock_untrusted: bool,
    is_stale_fn: Callable[[], bool],
) -> str:
    """Inspect ``snapshot``, hold bounded ``DoctorRun`` + descriptor blobs, and commit ``job.terminal`` atomically."""
    report = inspect_doctor_snapshot(snapshot, privacy_scanner=scanner)
    non_pass_codes = tuple(c.name for c in report.checks if c.status != "PASS")
    now_utc, now_str = require_aware_utc(now)
    _, degraded_codes = health_status_fields(
        now=now_utc,
        tls_not_after=tls_not_after,
        clock_untrusted=clock_untrusted,
        extra_codes=non_pass_codes,
    )
    doctor_run_id = new_id()
    co_str = str(checkout_root) if checkout_root is not None else None
    report_bytes = build_doctor_run_bytes(
        doctor_run_id=doctor_run_id,
        owner_id=owner_id,
        store_id=rt.store.store_id,
        writer_epoch=lease.writer_epoch,
        job_id=lease.job_id,
        trigger=trigger,
        recorded_at=now_str,
        report=report,
        degraded_codes=degraded_codes,
        checkout_root=co_str,
    )
    report_digest = digest_bytes(report_bytes)
    desc_bytes = result_descriptor(
        lease.job_id,
        (ObjectRef(kind="doctor_run", id=doctor_run_id, revision=1, digest=report_digest),),
    )
    job_store.stage_blob(report_bytes)
    job_store.stage_blob(desc_bytes)
    expires_at = default_expiry(RetentionClass.EVENT_PAYLOAD, now_utc, RETENTION_POLICY)
    assert expires_at is not None

    def _commit(tx: KernelTx) -> None:
        if is_stale_fn():
            raise BrainError(ErrorCode.REVISION_CONFLICT, "revision conflict")
        row = tx.read_job(lease.job_id)
        if row is None or not row.matches(lease, JobState.RUNNING):
            raise BrainError(ErrorCode.REVISION_CONFLICT, "revision conflict")
        tx.hold_blob(
            report_bytes,
            holder_id=doctor_run_id,
            retention=RetentionClass.EVENT_PAYLOAD,
            expires_at=expires_at,
        )
        desc_digest = tx.hold_blob(desc_bytes, holder_id=row.job_id)
        tx.append_record(
            KernelRecord(
                "doctor.run",
                {
                    "doctor_run_id": doctor_run_id,
                    "owner_id": row.owner_id,
                    "report_digest": report_digest,
                    "overall_status": report.overall_status,
                    "recorded_at": now_str,
                    "trigger": trigger,
                    "job_id": row.job_id,
                },
                actor=DOCTOR_ACTOR,
                refs=(report_digest,),
            )
        )
        tx.append_record(
            KernelRecord(
                "job.terminal",
                {
                    "job_id": row.job_id,
                    "attempt": row.attempt,
                    "writer_epoch": row.writer_epoch,
                    "lease_id": row.lease_id,
                    "state": JobState.SUCCEEDED.value,
                    "prior_state": row.state.value,
                    "reason": None,
                    "result_digest": desc_digest,
                    "finished_at": now_str,
                },
                actor=DOCTOR_ACTOR,
            )
        )

    job_store.transact(_commit)
    return doctor_run_id


def read_doctor_job_outcome_dto(
    *,
    rt: Runtime,
    job_store: StagedKernelStore,
    owner_id: str,
    job_id: str,
    cached_outcome: tuple[str, str | None] | None,
    now: datetime,
) -> dict[str, JsonValue]:
    """Resolve Phase 3 doctor job state or committed DTO from memory cache or persistent store."""
    if cached_outcome is not None:
        status, run_id = cached_outcome
        if status == "succeeded":
            return load_committed_doctor_run_dto(
                rt,
                owner_id=owner_id,
                job_id=job_id,
                doctor_run_id=run_id,
                now=now,
            )
        if status == "cancelled":
            raise BrainError(ErrorCode.REVISION_CONFLICT, "revision conflict")
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
    row = job_store.transact(lambda tx: tx.read_job(job_id))
    if row is None or row.owner_id != owner_id:
        raise BrainError(ErrorCode.NOT_FOUND, "not found")
    if row.state in (JobState.QUEUED, JobState.LEASED, JobState.RUNNING):
        return {"status": "running", "job_id": job_id}
    if row.state is JobState.SUCCEEDED:
        return load_committed_doctor_run_dto(
            rt,
            owner_id=owner_id,
            job_id=job_id,
            doctor_run_id=None,
            now=now,
        )
    if row.state is JobState.CANCELLED:
        raise BrainError(ErrorCode.REVISION_CONFLICT, "revision conflict")
    raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")


def create_doctor_scratch_snapshot(
    rt: Runtime,
    job_id: str,
    adapters: OsAdapters,
) -> tuple[Path, str, int, int, int]:
    """Take an isolated, consistent point-in-time SQLite snapshot on the owner thread before worker execution."""
    snap_dir = rt.root.scratch_dir / f"doctor-snap-{job_id}"
    snap_dir.mkdir(parents=True, exist_ok=True)
    adapters.permissions.secure_directory(snap_dir)
    store_dir = snap_dir / "store"
    store_dir.mkdir(parents=True, exist_ok=True)
    rt.store.snapshot_db(store_dir / "brain.db")
    policy_dir = snap_dir / "policy"
    policy_dir.mkdir(parents=True, exist_ok=True)
    rt.policy.snapshot_db(policy_dir / "policy.db")
    with contextlib.suppress(OSError):
        with open(rt.root.lock_path, "rb") as fh:
            fh.seek(1)
            raw_slots = fh.read(512)
        (snap_dir / rt.root.lock_path.name).write_bytes(b"\x00" + raw_slots)
    if os.path.lexists(rt.root.endpoint_path):
        with contextlib.suppress(OSError):
            shutil.copy2(rt.root.endpoint_path, snap_dir / rt.root.endpoint_path.name)
    if os.path.lexists(rt.root.restore_epoch_path):
        with contextlib.suppress(OSError):
            shutil.copy2(rt.root.restore_epoch_path, store_dir / rt.root.restore_epoch_path.name)
    if os.path.lexists(rt.root.pending_restore_tombstones_path):
        with contextlib.suppress(OSError):
            shutil.copy2(
                rt.root.pending_restore_tombstones_path,
                store_dir / rt.root.pending_restore_tombstones_path.name,
            )
    if os.path.lexists(rt.root.cas_dir):
        shutil.copytree(rt.root.cas_dir, store_dir / "cas", dirs_exist_ok=True)
    fence_store_id = rt.store.store_id
    fence_writer_epoch = rt.lease.epoch
    fence_restore_epoch = (
        read_restore_epoch(rt.root, schema_version=rt.store.schema_version, os_=adapters)
        if rt.store.schema_version >= 5
        else 0
    )
    fence_trust_gen = rt.policy.trust_generation()
    return snap_dir, fence_store_id, fence_writer_epoch, fence_restore_epoch, fence_trust_gen


def verify_doctor_snapshot_fences(
    rt: Runtime,
    adapters: OsAdapters,
    *,
    fence_store_id: str | None,
    fence_writer_epoch: int | None,
    fence_restore_epoch: int | None,
    fence_trust_generation: int | None,
) -> bool:
    """Verify that live fences have not drifted between snapshot time and commit time."""
    if fence_store_id is not None and rt.store.store_id != fence_store_id:
        return False
    if fence_writer_epoch is not None and rt.lease.epoch != fence_writer_epoch:
        return False
    current_restore_epoch = (
        read_restore_epoch(rt.root, schema_version=rt.store.schema_version, os_=adapters)
        if rt.store.schema_version >= 5
        else 0
    )
    if fence_restore_epoch is not None and current_restore_epoch != fence_restore_epoch:
        return False
    if fence_trust_generation is not None and rt.policy.trust_generation() != fence_trust_generation:
        return False
    return True
