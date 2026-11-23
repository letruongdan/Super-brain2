"""Transactional doctor run commit and payload parsing helpers for ``DaemonDoctorRunner``."""

from __future__ import annotations

import os
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from superbrain.application._privacy_canary import KernelPrivacyScanner
from superbrain.application.doctor import inspect_doctor_snapshot
from superbrain.composition._daemon_health import (
    RETENTION_POLICY,
    build_doctor_run_bytes,
    health_status_fields,
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
    require_aware_utc,
    result_descriptor,
)
from superbrain.ports.doctor import DoctorSnapshot
from superbrain.ports.kernel import KernelTx
from superbrain.ports.os import OsAdapters
from superbrain.storage.backup import snapshot_live_db_pair
from superbrain.storage.idempotency import StagedKernelStore
from superbrain.storage.layout import DataRoot
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.restore import read_restore_epoch
from superbrain.storage.retention import default_expiry
from superbrain.storage.runtime import Runtime

DOCTOR_ACTOR = "system:doctor"
VALID_DOCTOR_TRIGGERS = frozenset({"startup", "schedule", "get_health", "cli", "fix", "manual"})


def resolve_store_owner(policy: PolicyStore) -> str | None:
    """The store's authoritative owner for background ``system.doctor`` jobs, or ``None`` when none is pinned.

    A background run is never attributed to a guessed owner: without a pinned owner nothing is scheduled.
    """
    return policy.store_owner()


@dataclass(frozen=True)
class _CompletedDoctorProbe:
    generation: int
    lease: JobLease
    owner_id: str
    trigger: str
    checkout_root: Path | None
    snapshot: DoctorSnapshot | None
    fences: DoctorFences
    transient: bool = False


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


@dataclass(frozen=True)
class DoctorFences:
    """Live identity a doctor result was measured against; a commit is refused once any of them drifts."""

    store_id: str
    writer_epoch: int
    restore_epoch: int
    trust_generation: int


def capture_doctor_fences(rt: Runtime, adapters: OsAdapters) -> DoctorFences:
    """Owner thread, bounded: read the fences a later snapshot must still match at commit time."""
    return DoctorFences(
        store_id=rt.store.store_id,
        writer_epoch=rt.lease.epoch,
        restore_epoch=(
            read_restore_epoch(rt.root, schema_version=rt.store.schema_version, os_=adapters)
            if rt.store.schema_version >= 5
            else 0
        ),
        trust_generation=rt.policy.trust_generation(),
    )


DOCTOR_SNAPSHOT_PAIR_ATTEMPTS = 3


def build_worker_db_snapshot(root: DataRoot, tag: str, adapters: OsAdapters) -> Path:
    """Worker thread: snapshot only what the reader takes from ``db_root`` (both databases and the store markers).

    CAS, logs and daemon state are read from the live root, so they are never copied. The two databases are copied
    as one consistent pair (``snapshot_live_db_pair``); after ``DOCTOR_SNAPSHOT_PAIR_ATTEMPTS`` pairs split by a
    concurrent commit this raises a retryable ``STORE_BUSY`` rather than report on two moments that never
    coexisted. On failure the partial directory is removed before the error propagates.
    """
    snap_dir = root.scratch_dir / f"doctor-snap-{tag}"
    snap = DataRoot.at(snap_dir)
    try:
        snap_dir.mkdir(parents=True, exist_ok=False)
        adapters.permissions.secure_directory(snap_dir)
        for dest_db in (snap.store_db, snap.policy_db):
            dest_db.parent.mkdir()
        for _ in range(DOCTOR_SNAPSHOT_PAIR_ATTEMPTS):
            if snapshot_live_db_pair(root.store_db, root.policy_db, snap.store_db, snap.policy_db, adapters):
                break
        else:
            raise BrainError(ErrorCode.STORE_BUSY, "store busy")
        for marker, dest in (
            (root.restore_epoch_path, snap.restore_epoch_path),
            (root.pending_restore_tombstones_path, snap.pending_restore_tombstones_path),
        ):
            if os.path.lexists(marker):
                # follow_symlinks=False: a link stays a link, so the reader rejects it as it would on the live root.
                shutil.copyfile(marker, dest, follow_symlinks=False)
    except BaseException:
        shutil.rmtree(snap_dir, ignore_errors=True)
        raise
    return snap_dir


def verify_doctor_snapshot_fences(rt: Runtime, adapters: OsAdapters, fences: DoctorFences) -> bool:
    """Verify that live fences have not drifted between fence capture and commit time."""
    return capture_doctor_fences(rt, adapters) == fences
