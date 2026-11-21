"""Three-phase continuity refresh worker and single-flight coordinator (SP2-3)."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol, cast

from superbrain.application.jobs import JobService
from superbrain.core._kernel_base import ObjectRef, require_non_negative_int, require_opaque_id, require_sha256_digest
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.faults import crashpoint
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    JobErrorCode,
    JobLease,
    JobOutcome,
    JobRecord,
    JobSpec,
    WorkerCommand,
    WorkerCompleted,
    WorkerFailed,
)
from superbrain.domain.continuity.worker_rules import execute_continuity_refresh_payload, should_schedule_refresh
from superbrain.ports.continuity import (
    CONTINUITY_REFRESH_JOB_KIND,
    ContinuityCommitOutcome,
    ContinuityStorePort,
    TaskHandoffRecord,
    default_continuity_store_factory,
    pop_worker_observed_output,
    stage_worker_observed_output,
)
from superbrain.ports.kernel import KernelBlobStagePort, KernelTx

_DEFAULT_WORKER_BUDGET_NS = 5_000_000_000
_DEFAULT_WAIT_S = 5.0


class WorkerJobContext(Protocol):
    """Minimal context protocol satisfied by ``workers.executor.JobContext``."""

    @property
    def lease(self) -> JobLease: ...


class ContinuityExecutorPort(Protocol):
    """Minimal worker executor protocol satisfied by ``workers.executor.JobExecutor``."""

    def submit_work(
        self,
        lease: JobLease,
        spec: JobSpec,
        *,
        deadline_ns: int,
        invocation_ids: tuple[str, ...] = (),
    ) -> None: ...

    def next_command(self, timeout_s: float) -> WorkerCommand | None: ...


class _RuntimeLike(Protocol):
    @property
    def store(self) -> object: ...

    @property
    def policy(self) -> object: ...


@dataclass(frozen=True)
class PreparedContinuityCommit:
    """Phase 2 worker output ready for owner-thread Phase 3 validation, staging, and commit."""

    task_id: str
    lease: JobLease
    outcome: JobOutcome
    observed_digest: str
    observed_bytes: bytes
    observed_summary: dict[str, JsonValue]
    source_events: tuple[tuple[str, int, str, str], ...]


def continuity_refresh_handler(spec: JobSpec, ctx: WorkerJobContext) -> tuple[ObjectRef, ...]:
    """Pure Phase 2 worker handler for ``continuity.refresh`` (no SQLite locks, no model calls)."""
    obs_bytes = execute_continuity_refresh_payload(spec.payload)
    obs_digest = digest_bytes(obs_bytes)
    stage_worker_observed_output(ctx.lease.job_id, ctx.lease.attempt, obs_digest, obs_bytes)
    return (
        ObjectRef(
            kind="observed_summary",
            id=ctx.lease.job_id,
            revision=ctx.lease.attempt,
            digest=obs_digest,
        ),
    )


def _parse_iso_utc(timestamp: str) -> datetime:
    return datetime.fromisoformat(timestamp[:-1] + "+00:00").astimezone(UTC)


def _task_id_from_payload(payload: bytes) -> str | None:
    try:
        raw = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if isinstance(raw, Mapping):
        val = raw.get("task_id")
        if isinstance(val, str) and val:
            return val
    return None


def _decode_summary_and_sources(
    obs_bytes: bytes,
) -> tuple[dict[str, JsonValue], tuple[tuple[str, int, str, str], ...]]:
    try:
        parsed = json.loads(obs_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt observed summary JSON") from exc
    if not isinstance(parsed, dict):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "observed summary must be a JSON object")
    sources: list[tuple[str, int, str, str]] = []
    raw_sources = parsed.get("source_events")
    if isinstance(raw_sources, Sequence) and not isinstance(raw_sources, (str, bytes)):
        for entry in raw_sources:
            if isinstance(entry, Sequence) and len(entry) == 4 and isinstance(entry[1], int):
                sources.append((str(entry[0]), entry[1], str(entry[2]), str(entry[3])))
    return parsed, tuple(sources)


class ContinuityWorkerCoordinator:
    """Owner-thread orchestrator for debounced scheduling and 3-phase continuity refresh commits."""

    def __init__(
        self,
        *,
        rt: object,
        job_service: JobService,
        executor: object | None,
        clock: object,
        mono: Callable[[], int] | None = None,
        before_commit_hook: Callable[[], None] | None = None,
        blob_stager: KernelBlobStagePort | None = None,
        store_adapter: ContinuityStorePort | None = None,
    ) -> None:
        self._rt = rt
        self._job_service = job_service
        self._executor = cast(ContinuityExecutorPort | None, executor)
        self._clock = clock
        self._mono = mono
        self._before_commit_hook = before_commit_hook
        self._blob_stager = blob_stager if blob_stager is not None else job_service._stager
        self._explicit_adapter = store_adapter
        self._cstore = self._build_store(rt, store_adapter)

    @staticmethod
    def _build_store(rt: object, explicit: ContinuityStorePort | None) -> ContinuityStorePort:
        if explicit is not None:
            return explicit
        factory = default_continuity_store_factory()
        if factory is None:
            raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "continuity store factory not registered")
        rt_like = cast(_RuntimeLike, rt)
        return factory(rt_like.store, rt_like.policy)

    def rebind(
        self,
        *,
        rt: object,
        job_service: JobService,
        blob_stager: KernelBlobStagePort | None = None,
    ) -> None:
        """Rebind after daemon hot-restore while preserving hooks and executor."""
        self._rt = rt
        self._job_service = job_service
        self._blob_stager = blob_stager if blob_stager is not None else job_service._stager
        self._cstore = self._build_store(rt, self._explicit_adapter)

    def commit_worker_completed(
        self,
        cmd: WorkerCompleted,
        *,
        now: datetime,
    ) -> ContinuityCommitOutcome | None:
        """Phase 3 commit path when ``OwnerLoop`` drains a completed ``continuity.refresh`` command."""
        spec = self._job_service.resolve_leased_spec(cmd.lease)
        task_id = _task_id_from_payload(spec.payload) if spec is not None else None
        if task_id is None:
            self._job_service.apply_command(cmd)
            return None
        prepared = self.prepare_from_completed(task_id=task_id, lease=cmd.lease, cmd=cmd)
        return self.commit_prepared(prepared, now=now)

    def handle_worker_failed(self, cmd: WorkerFailed, *, now: datetime) -> None:
        """Forward failure to ``JobService`` and clear inflight marker if ``continuity.refresh`` ended."""
        spec = self._job_service.resolve_leased_spec(cmd.lease)
        task_id = _task_id_from_payload(spec.payload) if spec is not None else None
        self._job_service.apply_command(cmd)
        if task_id is not None and not cmd.retryable:
            self._cstore.clear_inflight_job_on_skip(task_id, cmd.lease.job_id, now=now)

    def _next_deadline_ns(self) -> int:
        base = self._mono() if self._mono is not None else 0
        return base + _DEFAULT_WORKER_BUDGET_NS

    def enqueue_if_due(self, *, task_id: str, now: datetime) -> str | None:
        """Enqueue at most one ``continuity.refresh`` job when >=20 events or >=60s age."""
        require_opaque_id(task_id, label="task_id")
        wstate = self._cstore.get_continuity_worker_state(task_id)
        if wstate is None:
            return None
        in_flight = wstate.active_job_id is not None or wstate.pending_job_id is not None
        if not self._cstore.check_automatic_capture_enabled(wstate.repo_id):
            return None
        first_dt = _parse_iso_utc(wstate.first_pending_event_at) if wstate.first_pending_event_at else None
        if not should_schedule_refresh(
            pending_event_count=wstate.pending_event_count,
            first_pending_at=first_dt,
            now=now,
            job_in_flight=in_flight,
        ):
            return None
        built = self._cstore.build_refresh_job_payload(task_id)
        if built is None:
            return None
        payload_bytes, _max_order, _ev_count = built
        spec = JobSpec(
            kind=CONTINUITY_REFRESH_JOB_KIND,
            owner_id=wstate.owner_id,
            payload=payload_bytes,
            repo_id=wstate.repo_id,
            checkout_id=wstate.checkout_id,
        )
        self._blob_stager.stage_blob(payload_bytes)
        job_ref = self._job_service._store.transact(lambda tx: self._job_service.enqueue(tx, spec))
        self._cstore.reserve_pending_job(task_id, job_ref.job_id, now=now)
        return job_ref.job_id

    def prepare_from_completed(
        self,
        *,
        task_id: str,
        lease: JobLease,
        cmd: WorkerCompleted,
    ) -> PreparedContinuityCommit:
        """Consume Phase 2 RAM output emitted by ``continuity_refresh_handler``."""
        if not cmd.result_refs:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "continuity worker returned no result ref")
        ref = cmd.result_refs[0]
        obs_bytes = pop_worker_observed_output(lease.job_id, lease.attempt, ref)
        if obs_bytes is None:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "missing staged continuity worker output")
        if digest_bytes(obs_bytes) != ref.digest:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "observed output digest mismatch")
        obs_summary, sources = _decode_summary_and_sources(obs_bytes)
        return PreparedContinuityCommit(
            task_id=task_id,
            lease=lease,
            outcome=JobOutcome.success(cmd.result_refs),
            observed_digest=ref.digest,
            observed_bytes=obs_bytes,
            observed_summary=obs_summary,
            source_events=sources,
        )

    def claim_and_execute(self, *, writer_epoch: int, now: datetime) -> PreparedContinuityCommit | None:
        """Phase 1 (claim + policy check) + Phase 2 (pure worker execution without SQLite lock)."""
        if self._executor is None:
            raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "worker executor unavailable")
        self._job_service.recover(writer_epoch)
        lease = self._job_service.lease_next(writer_epoch, now)
        if lease is None:
            return None
        spec = self._job_service.resolve_leased_spec(lease)
        if spec is None or spec.kind != CONTINUITY_REFRESH_JOB_KIND:
            return None
        task_id = _task_id_from_payload(spec.payload)
        if task_id is None:
            self._job_service.start(lease)
            self._job_service.complete(lease, JobOutcome.failure(JobErrorCode.INVALID_PAYLOAD, retryable=False))
            return None
        if spec.repo_id is not None and not self._cstore.check_automatic_capture_enabled(spec.repo_id):
            self._job_service.start(lease)
            self._job_service.complete(lease, JobOutcome.failure(JobErrorCode.HANDLER_FAILED, retryable=False))
            self._cstore.clear_inflight_job_on_skip(task_id, lease.job_id, now=now)
            return None

        self._job_service.start(lease)
        self._cstore.mark_job_running(task_id, lease.job_id, now=now)
        self._executor.submit_work(lease, spec, deadline_ns=self._next_deadline_ns())

        while True:
            cmd = self._executor.next_command(_DEFAULT_WAIT_S)
            if cmd is None:
                raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "timed out waiting for continuity worker")
            if isinstance(cmd, WorkerCompleted):
                if cmd.lease != lease:
                    continue
                return self.prepare_from_completed(task_id=task_id, lease=lease, cmd=cmd)
            if isinstance(cmd, WorkerFailed):
                if cmd.lease != lease:
                    continue
                self._job_service.apply_command(cmd)
                self._cstore.clear_inflight_job_on_skip(task_id, lease.job_id, now=now)
                return None

    def commit_prepared(
        self,
        prepared: PreparedContinuityCommit,
        *,
        now: datetime,
    ) -> ContinuityCommitOutcome | None:
        """Phase 3: fire test hook/crashpoint, recheck policy & restrictions, stage blob, commit atomically."""
        if self._before_commit_hook is not None:
            self._before_commit_hook()
        crashpoint("continuity.worker.before_owner_commit")

        _, repo_id, _ = self._cstore.read_task_owner(prepared.task_id)
        if not self._cstore.check_automatic_capture_enabled(repo_id):
            self._job_service.complete(
                prepared.lease, JobOutcome.failure(JobErrorCode.HANDLER_FAILED, retryable=False)
            )
            self._cstore.clear_inflight_job_on_skip(prepared.task_id, prepared.lease.job_id, now=now)
            return None
        if self._cstore.has_restricted_blobs_for_events(prepared.source_events):
            self._job_service.complete(
                prepared.lease, JobOutcome.failure(JobErrorCode.HANDLER_FAILED, retryable=False)
            )
            self._cstore.clear_inflight_job_on_skip(prepared.task_id, prepared.lease.job_id, now=now)
            return None

        # Publish observed summary bytes into CAS strictly before starting the SQLite commit tx (C2).
        self._blob_stager.stage_blob(prepared.observed_bytes)

        outcome_box: list[ContinuityCommitOutcome] = []

        def _apply_in_tx(tx: KernelTx, row: JobRecord, outcome: JobOutcome) -> None:
            _ = outcome
            outcome_box.append(
                self._cstore.apply_worker_commit_in_tx(
                    tx,
                    task_id=prepared.task_id,
                    job_id=row.job_id,
                    observed_digest=prepared.observed_digest,
                    observed_summary=prepared.observed_summary,
                    now=now,
                    dirty_followup_fn=None,
                )
            )

        self._job_service.complete(prepared.lease, prepared.outcome, on_complete_in_tx=_apply_in_tx)
        return outcome_box[0]

    def run_next(self, *, writer_epoch: int, now: datetime) -> bool:
        """Run one full 3-phase cycle for the next due ``continuity.refresh`` job."""
        prepared = self.claim_and_execute(writer_epoch=writer_epoch, now=now)
        if prepared is None:
            return False
        return self.commit_prepared(prepared, now=now) is not None

    def submit_manual_handoff_patch(
        self,
        *,
        task_id: str,
        repo_id: str,
        checkout_id: str,
        session_ref: str | None = None,
        base_revision: int,
        agent_ref: str,
        now: datetime,
    ) -> TaskHandoffRecord:
        """Manually patch ``agent_ref`` when ``manual_submission_enabled`` is granted."""
        require_opaque_id(task_id, label="task_id")
        require_opaque_id(repo_id, label="repo_id")
        require_opaque_id(checkout_id, label="checkout_id")
        require_non_negative_int(base_revision)
        require_sha256_digest(agent_ref)
        if not self._cstore.check_manual_submission_enabled(repo_id):
            raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "manual submission disabled by repo policy")
        return self._cstore.apply_agent_handoff_patch(
            task_id=task_id,
            repo_id=repo_id,
            checkout_id=checkout_id,
            session_ref=session_ref,
            base_revision=base_revision,
            agent_ref=agent_ref,
            now=now,
        )


__all__ = [
    "ContinuityExecutorPort",
    "ContinuityWorkerCoordinator",
    "PreparedContinuityCommit",
    "WorkerJobContext",
    "continuity_refresh_handler",
]
