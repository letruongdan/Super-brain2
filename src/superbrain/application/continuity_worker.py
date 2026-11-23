"""Three-phase continuity refresh worker and single-flight coordinator (SP2-3)."""

from __future__ import annotations

import dataclasses
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
    TERMINAL_JOB_STATES,
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
# Reads that failed say nothing about the batch: the job is retried and the batch keeps its cutoff.
_UNREADABLE = frozenset({ErrorCode.IO_ERROR, ErrorCode.STORE_BUSY, ErrorCode.STORAGE_FULL})
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
    cutoff_order: int = 0
    """Last event order pinned in the job: everything up to it was considered, live or not."""


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


def _cutoff_from_payload(payload: bytes) -> int:
    try:
        raw = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return 0
    value = raw.get("cutoff_order") if isinstance(raw, Mapping) else None
    return value if type(value) is int and value > 0 else 0


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
        self._scan_cursor: tuple[str, str] | None = None

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
        spec: JobSpec | None = None,
    ) -> ContinuityCommitOutcome | None:
        """Phase 3 commit path when ``OwnerLoop`` drains a completed ``continuity.refresh`` command."""
        resolved_spec = spec if spec is not None else self._job_service.job_spec(cmd.lease)
        task_id = _task_id_from_payload(resolved_spec.payload)
        if task_id is None:
            self._job_service.apply_command(cmd)
            return None
        try:
            prepared = self.prepare_from_completed(
                task_id=task_id, lease=cmd.lease, cmd=cmd, cutoff_order=_cutoff_from_payload(resolved_spec.payload)
            )
        except BrainError as err:
            if err.code is not ErrorCode.INTEGRITY_FAILURE:
                raise
            # Unusable worker output must end the job; otherwise it stays running and blocks the task.
            self._job_service.complete(cmd.lease, JobOutcome.failure(JobErrorCode.HANDLER_FAILED, retryable=False))
            self._cstore.clear_inflight_job_on_skip(task_id, cmd.lease.job_id, now=now)
            return None
        return self.commit_prepared(prepared, now=now)

    def handle_worker_failed(
        self,
        cmd: WorkerFailed,
        *,
        now: datetime,
        spec: JobSpec | None = None,
    ) -> None:
        """Forward failure to ``JobService`` and clear inflight marker if ``continuity.refresh`` ended."""
        resolved_spec = spec if spec is not None else self._job_service.job_spec(cmd.lease)
        task_id = _task_id_from_payload(resolved_spec.payload)
        self._job_service.apply_command(cmd)
        if task_id is not None:
            after = self._job_service._store.transact(lambda tx: tx.read_job(cmd.lease.job_id))
            if after is not None and after.state in TERMINAL_JOB_STATES:
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
        in_flight = False
        for marked in {j for j in (wstate.active_job_id, wstate.pending_job_id) if j is not None}:
            if self._job_is_live(marked):
                in_flight = True
            else:
                # The job row is the truth; a crash between ending a job and clearing its marker leaves it stale.
                self._cstore.clear_inflight_job_on_skip(task_id, marked, now=now)
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
        def _enqueue_and_reserve(tx: KernelTx) -> str:
            job_id = self._job_service.enqueue(tx, spec).job_id
            self._cstore.reserve_pending_job_in_tx(tx, task_id, job_id)
            return job_id

        return self._job_service._store.transact(_enqueue_and_reserve)

    def _job_is_live(self, job_id: str) -> bool:
        row = self._job_service._store.transact(lambda tx: tx.read_job(job_id))
        return row is not None and row.state not in TERMINAL_JOB_STATES

    def prepare_from_completed(
        self,
        *,
        task_id: str,
        lease: JobLease,
        cmd: WorkerCompleted,
        cutoff_order: int = 0,
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
            cutoff_order=cutoff_order,
        )

    def claim_and_execute(self, *, writer_epoch: int, now: datetime) -> PreparedContinuityCommit | None:
        """Phase 1 (claim + policy check) + Phase 2 (pure worker execution without SQLite lock)."""
        if self._executor is None:
            raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "worker executor unavailable")
        self._job_service.recover(writer_epoch)
        lease = self._job_service.lease_next(writer_epoch, now)
        if lease is None:
            return None
        try:
            spec = self._job_service.resolve_leased_spec(lease)
        except BrainError as err:
            if err.code not in _UNREADABLE:
                raise
            self._job_service.retry_attempt(lease)  # leased, payload unreadable: queue the same attempt again
            return None
        if spec is None:
            return None
        if spec.kind != CONTINUITY_REFRESH_JOB_KIND:
            # I2 contract: a kind this coordinator cannot run fails instead of staying leased.
            self._job_service.start(lease)
            self._job_service.complete(lease, JobOutcome.failure(JobErrorCode.HANDLER_UNAVAILABLE, retryable=False))
            return None
        run_spec = self.admit_claimed(lease, spec, now=now)
        if run_spec is None:
            return None
        task_id = _task_id_from_payload(spec.payload)
        assert task_id is not None
        self._executor.submit_work(lease, run_spec, deadline_ns=self._next_deadline_ns())

        while True:
            cmd = self._executor.next_command(_DEFAULT_WAIT_S)
            if cmd is None:
                raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "timed out waiting for continuity worker")
            if isinstance(cmd, WorkerCompleted):
                if cmd.lease != lease:
                    continue
                return self.prepare_from_completed(
                    task_id=task_id, lease=lease, cmd=cmd, cutoff_order=_cutoff_from_payload(spec.payload)
                )
            if isinstance(cmd, WorkerFailed):
                if cmd.lease != lease:
                    continue
                self.handle_worker_failed(cmd, now=now, spec=spec)
                return None

    def admit_claimed(self, lease: JobLease, spec: JobSpec, *, now: datetime) -> JobSpec | None:
        """Phase 1 for a leased ``continuity.refresh`` job, shared by every claim path.

        Returns, after ``start``, the spec the worker runs: the stored refs resolved in memory to the source
        events still live at ``now``. Otherwise fails the job terminally, clears the task's inflight marker
        and returns ``None``.
        """
        task_id = _task_id_from_payload(spec.payload)
        repo_id: str | None = None
        run_payload: bytes | None = None
        enabled = False
        if task_id is not None:
            try:
                _, repo_id, _ = self._cstore.read_task_owner(task_id)
                run_payload = self._cstore.resolve_refresh_sources(spec.payload, now=now)
                enabled = self._cstore.check_automatic_capture_enabled(repo_id)
            except BrainError as err:
                if err.code in _UNREADABLE:
                    self._job_service.start(lease)
                    self._retry_later(lease, task_id, now=now)
                    return None
                if err.code not in (ErrorCode.NOT_FOUND, ErrorCode.INVALID_INPUT):
                    raise
        if task_id is None or repo_id is None or run_payload is None:
            self._job_service.start(lease)
            self._job_service.complete(lease, JobOutcome.failure(JobErrorCode.INVALID_PAYLOAD, retryable=False))
            return None
        if not enabled:
            self._job_service.start(lease)
            self._job_service.complete(lease, JobOutcome.failure(JobErrorCode.HANDLER_FAILED, retryable=False))
            self._cstore.clear_inflight_job_on_skip(task_id, lease.job_id, now=now)
            return None
        self._job_service.start(lease)
        self._cstore.mark_job_running(task_id, lease.job_id, now=now)
        return dataclasses.replace(spec, payload=run_payload)

    def _retry_later(self, lease: JobLease, task_id: str, *, now: datetime) -> None:
        """Retry the running attempt through the job lifecycle; the task keeps its batch, cutoff and marker.

        Once retries are exhausted the job ends (dead letter) and only the marker is released, so the still-pending
        events are scheduled again by a new job.
        """
        self._job_service.complete(lease, JobOutcome.failure(JobErrorCode.HANDLER_FAILED, retryable=True))
        after = self._job_service._store.transact(lambda tx: tx.read_job(lease.job_id))
        if after is not None and after.state in TERMINAL_JOB_STATES:
            self._cstore.clear_inflight_job_on_skip(task_id, lease.job_id, now=now)

    def enqueue_due(self, *, now: datetime, limit: int = 50) -> int:
        """Durable wake: schedule tasks whose committed events reached 20 or waited 60 s.

        Each call reads the next page after a rotating cursor, so a page held by tasks that cannot move (capture
        disabled, job in flight) never hides the tasks behind it; a short page wraps to the start.
        """
        page = self._cstore.refresh_candidate_tasks(limit, self._scan_cursor)
        self._scan_cursor = page[-1] if len(page) == limit else None
        scheduled = 0
        for _first_at, task_id in page:
            if self.enqueue_if_due(task_id=task_id, now=now) is not None:
                scheduled += 1
        return scheduled

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

        try:
            _, repo_id, _ = self._cstore.read_task_owner(prepared.task_id)
            enabled = self._cstore.check_automatic_capture_enabled(repo_id)
            restricted = enabled and self._cstore.has_restricted_blobs_for_events(
                prepared.task_id, prepared.source_events
            )
        except BrainError as err:
            if err.code not in _UNREADABLE:
                raise
            self._retry_later(prepared.lease, prepared.task_id, now=now)
            return None
        if not enabled:
            self._job_service.complete(
                prepared.lease, JobOutcome.failure(JobErrorCode.HANDLER_FAILED, retryable=False)
            )
            self._cstore.clear_inflight_job_on_skip(prepared.task_id, prepared.lease.job_id, now=now)
            return None
        if restricted:
            self._job_service.complete(
                prepared.lease, JobOutcome.failure(JobErrorCode.HANDLER_FAILED, retryable=False)
            )
            self._cstore.clear_inflight_job_on_skip(prepared.task_id, prepared.lease.job_id, now=now)
            return None

        if not prepared.source_events:
            # Nothing in the pinned batch is still live: close the batch at its cutoff without an empty revision.
            def _close_batch(tx: KernelTx, row: JobRecord, outcome: JobOutcome) -> None:
                _ = (row, outcome)
                self._cstore.close_refresh_batch_in_tx(tx, task_id=prepared.task_id, cutoff_order=prepared.cutoff_order)

            self._job_service.complete(prepared.lease, prepared.outcome, on_complete_in_tx=_close_batch)
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
                    cutoff_order=prepared.cutoff_order,
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



def sweep_legacy_continuity_copies(job_service: JobService, cstore: ContinuityStorePort) -> int:
    """Release content copies a ``778e451``-shaped store left behind and fail jobs that would still read them.

    Runs on store open before ``READY`` (and after an online restore); each job is one ledger transaction, so a
    crash leaves the rest of the list for the next open.
    """
    job_ids = sorted({job_id for job_id, _digest in cstore.legacy_sweep_rows()})
    for job_id in job_ids:

        def _sweep(tx: KernelTx, job_id: str = job_id) -> None:
            job_service.retire_superseded_in_tx(tx, job_id)
            cstore.clear_legacy_sweep_in_tx(tx, job_id)

        job_service._store.transact(_sweep)
    return len(job_ids)


__all__ = [
    "ContinuityExecutorPort",
    "ContinuityWorkerCoordinator",
    "PreparedContinuityCommit",
    "WorkerJobContext",
    "continuity_refresh_handler",
    "sweep_legacy_continuity_copies",
]
