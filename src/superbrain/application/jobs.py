"""Durable jobs and provider-invocation accounting (Task 5, spec 6.4, D5): fenced transitions and crash recovery.

``JobService.enqueue`` runs in the caller's transaction (a future ``request_improvement`` commits job, idempotency
row and ledger together); every other method runs its own owner-thread transaction through ``KernelStorePort``.
Each transition appends exactly one typed ledger record whose reducer re-checks the same fence, so the projection
and the ledger never diverge. CAS bytes (result refs, reservation and usage descriptors) are staged before the
transaction (C2) and held by the job or invocation ID. Errors carry only allowlisted messages: never a payload,
an exception text or a decimal amount.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.faults import crashpoint
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    DEAD_LETTER_RETENTION,
    MAX_JOB_ATTEMPTS,
    RECOVERY_BATCH,
    TERMINAL_JOB_STATES,
    InvocationState,
    JobErrorCode,
    JobLease,
    JobOutcome,
    JobRecord,
    JobRef,
    JobSpec,
    JobState,
    JobView,
    KernelRecord,
    ObjectRef,
    Principal,
    RecoveryCounts,
    Scope,
    UsageRecord,
    UsageReservation,
    WorkerCommand,
    WorkerCompleted,
    WorkerFailed,
    WorkerUsage,
    accounting_status_of,
    decode_result_descriptor,
    is_strict_int,
    require_aware_utc,
    require_opaque_id,
    require_positive_int,
    reservation_descriptor,
    result_descriptor,
    retry_backoff,
    usage_descriptor,
)
from superbrain.ports.clock import Clock
from superbrain.ports.kernel import KernelBlobStagePort, KernelPolicyPort, KernelStorePort, KernelTx

__all__ = ["RECOVERY_BATCH", "JobService"]

_ACL_ACTION = "get_job"


def _conflict() -> BrainError:
    return BrainError(ErrorCode.REVISION_CONFLICT, "revision conflict")


def _not_found() -> BrainError:
    return BrainError(ErrorCode.NOT_FOUND, "not found")


def _invalid() -> BrainError:
    return BrainError(ErrorCode.INVALID_INPUT, "invalid input")


def _lease_meta(lease: JobLease) -> dict[str, JsonValue]:
    return {
        "job_id": lease.job_id,
        "attempt": lease.attempt,
        "writer_epoch": lease.writer_epoch,
        "lease_id": lease.lease_id,
    }


def _row_fence(row: JobRecord) -> dict[str, JsonValue]:
    return {"job_id": row.job_id, "attempt": row.attempt, "writer_epoch": row.writer_epoch, "lease_id": row.lease_id}


class JobService:
    """Owner-side job state machine over one admitted store at ``writer_epoch`` (the only writer of jobs)."""

    def __init__(
        self,
        store: KernelStorePort,
        stager: KernelBlobStagePort,
        policy: KernelPolicyPort,
        clock: Clock,
        *,
        writer_epoch: int,
        cancel_signal: Callable[[str], None] | None = None,
        claim_commit_guard: Callable[[], bool] | None = None,
    ) -> None:
        self._store = store
        self._stager = stager
        self._policy = policy
        self._clock = clock
        self._writer_epoch = require_positive_int(writer_epoch)
        self._cancel_signal = cancel_signal
        self._claim_commit_guard: Callable[[], bool] | None = None
        self.set_claim_commit_guard(claim_commit_guard)

    def set_claim_commit_guard(self, guard: Callable[[], bool] | None) -> None:
        """Install or clear the zero-argument RAM predicate guarding ``job.leased`` record append."""
        if guard is not None and not callable(guard):
            raise _invalid()
        self._claim_commit_guard = guard

    # --- enqueue, lease, run ------------------------------------------------------------------------------------

    def enqueue(self, tx: KernelTx, request: JobSpec) -> JobRef:
        """Record a new queued job (attempt 1, due now) in the caller's transaction; the payload must be staged."""
        if not isinstance(request, JobSpec):
            raise _invalid()
        job_id = new_id()
        _, now = require_aware_utc(self._clock.now())
        payload_digest = tx.hold_blob(request.payload, holder_id=job_id)
        meta: dict[str, JsonValue] = {
            "job_id": job_id,
            "owner_id": request.owner_id,
            "repo_id": request.repo_id,
            "checkout_id": request.checkout_id,
            "kind": request.kind,
            "payload_digest": payload_digest,
            "attempt": 1,
            "retry_at": now,
        }
        tx.append_record(KernelRecord("job.queued", meta))
        return JobRef(job_id=job_id, state=JobState.QUEUED, attempt=1)

    def lease_next(self, epoch: int, now: datetime) -> JobLease | None:
        """Lease the first due queued job in ``(retry_at, job_id)`` order; leasing never changes ``attempt``."""
        self._require_epoch(epoch)
        now_utc, _ = require_aware_utc(now)
        guard = self._claim_commit_guard

        def lease(tx: KernelTx) -> JobLease | None:
            due = tx.due_jobs(now_utc, 1)
            if not due:
                return None
            if guard is not None and not guard():
                return None
            claimed = JobLease(job_id=due[0].job_id, attempt=due[0].attempt, writer_epoch=epoch, lease_id=new_id())
            tx.append_record(KernelRecord("job.leased", _lease_meta(claimed)))
            return claimed

        claimed = self._store.transact(lease)
        if claimed is not None:
            crashpoint("jobs.after_lease")
        return claimed

    def start(self, lease: JobLease) -> None:
        """``leased -> running`` under exactly ``lease``."""
        self._require_current(lease)

        def start(tx: KernelTx) -> None:
            self._fenced(tx, lease, JobState.LEASED)
            tx.append_record(KernelRecord("job.running", _lease_meta(lease)))

        self._store.transact(start)
        crashpoint("jobs.after_running")

    def job_spec(self, lease: JobLease) -> JobSpec:
        """The immutable ``JobSpec`` (payload read from CAS) the owner hands to the worker for ``lease``."""
        self._require_current(lease)

        def read(tx: KernelTx) -> JobSpec:
            row = tx.read_job(lease.job_id)
            if row is None or not (row.matches(lease, JobState.LEASED) or row.matches(lease, JobState.RUNNING)):
                raise _conflict()
            payload = tx.read_held_blob(row.payload_digest, holder_id=row.job_id)
            if payload is None:
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
            return JobSpec(row.kind, row.owner_id, payload, repo_id=row.repo_id, checkout_id=row.checkout_id)

        return self._store.transact(read)

    def resolve_leased_spec(self, lease: JobLease) -> JobSpec | None:
        """Read ``JobSpec`` for a ``LEASED`` job, or fail it fenced with ``INVALID_PAYLOAD`` if policy-blocked."""
        self._require_current(lease)
        _, now = require_aware_utc(self._clock.now())

        def resolve(tx: KernelTx) -> JobSpec | None:
            row = self._fenced(tx, lease, JobState.LEASED)
            if tx.holder_tombstoned(row.job_id) or tx.blob_restricted(row.payload_digest):
                self._terminal(tx, row, JobState.FAILED, now, reason=JobErrorCode.INVALID_PAYLOAD)
                return None
            payload = tx.read_held_blob(row.payload_digest, holder_id=row.job_id)
            if payload is None:
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
            return JobSpec(row.kind, row.owner_id, payload, repo_id=row.repo_id, checkout_id=row.checkout_id)

        return self._store.transact(resolve)

    def complete(self, lease: JobLease, result: JobOutcome) -> None:
        """Finish the running attempt: succeeded, failed (nonretryable), queued again with backoff, or dead letter."""
        self._require_current(lease)
        if not isinstance(result, JobOutcome):
            raise _invalid()
        descriptor = None
        if result.succeeded and result.result_refs:
            descriptor = result_descriptor(lease.job_id, result.result_refs)
            self._stager.stage_blob(descriptor)
        now_utc, now = require_aware_utc(self._clock.now())

        def complete(tx: KernelTx) -> None:
            row = self._fenced(tx, lease, JobState.RUNNING)
            if result.succeeded:
                digest = None if descriptor is None else tx.hold_blob(descriptor, holder_id=lease.job_id)
                self._terminal(tx, row, JobState.SUCCEEDED, now, result_digest=digest)
            elif not result.retryable:
                self._terminal(tx, row, JobState.FAILED, now, reason=result.error_code)
            else:
                assert result.error_code is not None
                exhausted = row.attempt >= MAX_JOB_ATTEMPTS
                retry_at = now if exhausted else require_aware_utc(now_utc + retry_backoff(row.attempt))[1]
                self._retry_or_dead_letter(tx, row, result.error_code, retry_at=retry_at, now=now)

        self._store.transact(complete)

    def apply_command(self, command: WorkerCommand) -> None:
        """Apply one typed worker command on the owner side (completion, failure or usage)."""
        if isinstance(command, WorkerCompleted):
            self.complete(command.lease, JobOutcome.success(command.result_refs))
        elif isinstance(command, WorkerFailed):
            self.complete(command.lease, JobOutcome.failure(command.code, retryable=command.retryable))
        elif isinstance(command, WorkerUsage):
            self.settle_usage(command.invocation_id, command.usage)
        else:
            raise _invalid()

    # --- provider invocations -----------------------------------------------------------------------------------

    def reserve_invocation(self, lease: JobLease, reservation: UsageReservation) -> str:
        """Durably record a new invocation and its max reservation under the running fence; its ID."""
        self._require_current(lease)
        if not isinstance(reservation, UsageReservation):
            raise _invalid()
        invocation_id = new_id()
        descriptor = reservation_descriptor(invocation_id, lease.job_id, reservation)
        self._stager.stage_blob(descriptor)

        def reserve(tx: KernelTx) -> None:
            self._fenced(tx, lease, JobState.RUNNING)
            digest = tx.hold_blob(descriptor, holder_id=invocation_id)
            meta = {"invocation_id": invocation_id, **_lease_meta(lease), "reservation_digest": digest}
            tx.append_record(KernelRecord("provider.reserved", meta))

        self._store.transact(reserve)
        crashpoint("jobs.after_invocation_reserve")
        return invocation_id

    def settle_usage(self, invocation_id: str, usage: UsageRecord) -> None:
        """Record nonfinal unknown usage or commit the first final usage of an invocation; identical retry no-op."""
        descriptor = usage_descriptor(invocation_id, usage)
        usage_digest = digest_bytes(descriptor)
        self._stager.stage_blob(descriptor)

        def settle(tx: KernelTx) -> bool:
            invocation = tx.read_invocation(invocation_id)
            if invocation is None:
                raise _not_found()
            if invocation.state is InvocationState.SETTLED:
                if usage.complete and invocation.usage_digest == usage_digest:
                    return False
                raise BrainError(ErrorCode.IDEMPOTENCY_CONFLICT, "idempotency conflict")
            if not usage.complete:
                if invocation.state is InvocationState.OUTCOME_UNKNOWN and invocation.usage_complete is False:
                    if invocation.usage_digest == usage_digest:
                        return False
                    raise BrainError(ErrorCode.IDEMPOTENCY_CONFLICT, "idempotency conflict")
                prior_usage_digest: str | None = None
            else:
                prior_usage_digest = invocation.usage_digest
            tx.hold_blob(descriptor, holder_id=invocation_id)
            meta: dict[str, JsonValue] = {
                "invocation_id": invocation_id,
                "prior_state": invocation.state.value,
                "prior_usage_digest": prior_usage_digest,
                "usage_digest": usage_digest,
                "complete": usage.complete,
            }
            tx.append_record(KernelRecord("provider.settled", meta))
            return True

        if self._store.transact(settle):
            crashpoint("jobs.after_usage_settle_commit")

    # --- authorized reads and cancellation ----------------------------------------------------------------------

    def get_job(self, job_id: str, principal: Principal, *, selected_scope: Scope | None) -> JobView:
        """The job if ``principal`` may see it in ``selected_scope``; one ``NOT_FOUND`` for every denial."""
        caller_active = self._probe(job_id, principal, selected_scope)

        def read(tx: KernelTx) -> JobView:
            row = self._authorized(tx.read_job(job_id), principal, selected_scope, caller_active)
            refs: tuple[ObjectRef, ...] = ()
            if row.result_digest is not None:
                raw = tx.read_held_blob(row.result_digest, holder_id=row.job_id)
                if raw is None:
                    raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
                refs = decode_result_descriptor(row.job_id, raw)
            accounting = accounting_status_of(tx.read_job_accounting_states(row.job_id))
            return JobView(row.job_id, row.state, row.attempt, refs, accounting)

        return self._store.transact(read)

    def cancel(self, job_id: str, principal: Principal, *, selected_scope: Scope | None) -> JobState:
        """Cancel a queued/leased/running job (same ACL as ``get_job``); a running worker is signalled to stop."""
        caller_active = self._probe(job_id, principal, selected_scope)
        _, now = require_aware_utc(self._clock.now())

        def cancel(tx: KernelTx) -> JobState:
            row = self._authorized(tx.read_job(job_id), principal, selected_scope, caller_active)
            if row.state in TERMINAL_JOB_STATES:
                raise _conflict()
            self._terminal(tx, row, JobState.CANCELLED, now, actor=f"principal:{principal.principal_id}")
            return row.state

        prior = self._store.transact(cancel)
        crashpoint("jobs.after_cancel_commit")
        if prior is not JobState.QUEUED and self._cancel_signal is not None:
            self._cancel_signal(job_id)
        return JobState.CANCELLED

    # --- recovery and retention ---------------------------------------------------------------------------------

    def recover(self, epoch: int) -> RecoveryCounts:
        """Recover jobs and invocations of epochs older than ``epoch`` in bounded batches, resumably.

        Every unsettled old-epoch invocation becomes ``outcome_unknown`` before any job is requeued; old-epoch
        ``leased|running`` jobs then go back to ``queued`` (attempt + 1, due now) or to ``dead_letter`` at attempt 3.
        A repeated recovery of the same epoch finds nothing and writes nothing.
        """
        self._require_epoch(epoch)
        unknown = requeued = dead = 0
        while True:
            marked = self._store.transact(lambda tx: self._mark_unknown_batch(tx, epoch))
            unknown += marked
            if marked < RECOVERY_BATCH:
                break
        _, now = require_aware_utc(self._clock.now())
        while True:
            batch = self._store.transact(lambda tx: self._requeue_batch(tx, epoch, now))
            requeued, dead = requeued + batch[0], dead + batch[1]
            if sum(batch) < RECOVERY_BATCH:
                break
        return RecoveryCounts(invocations_unknown=unknown, jobs_requeued=requeued, jobs_dead_lettered=dead)

    def prune_dead_letters(self, now: datetime, limit: int = 100) -> int:
        """Record ``job.retention_expired`` for at most ``limit`` dead letters finished 30 days or more ago."""
        if not is_strict_int(limit) or not 1 <= limit <= 100:
            raise _invalid()
        now_utc, stamp = require_aware_utc(now)

        def prune(tx: KernelTx) -> int:
            expired = tx.expired_dead_letters(now_utc - DEAD_LETTER_RETENTION, limit)
            for row in expired:
                tx.append_record(KernelRecord("job.retention_expired", {"job_id": row.job_id, "expired_at": stamp}))
            return len(expired)

        return self._store.transact(prune)

    # --- internals ----------------------------------------------------------------------------------------------

    def _require_epoch(self, epoch: int) -> None:
        if not is_strict_int(epoch):
            raise _invalid()
        if epoch != self._writer_epoch:
            raise _conflict()

    def _require_current(self, lease: JobLease) -> None:
        if not isinstance(lease, JobLease):
            raise _invalid()
        if lease.writer_epoch != self._writer_epoch:
            raise _conflict()

    @staticmethod
    def _fenced(tx: KernelTx, lease: JobLease, state: JobState) -> JobRecord:
        row = tx.read_job(lease.job_id)
        if row is None or not row.matches(lease, state):
            raise _conflict()
        return row

    def _probe(self, job_id: str, principal: Principal, selected_scope: Scope | None) -> bool:
        require_opaque_id(job_id, label="job_id")
        if not isinstance(principal, Principal) or (
            selected_scope is not None and not isinstance(selected_scope, Scope)
        ):
            raise _invalid()
        # Probe live policy first: a closed or corrupt policy is POLICY_UNAVAILABLE, never NOT_FOUND.
        return self._policy.allows(principal, None, action=_ACL_ACTION)

    def _authorized(
        self, row: JobRecord | None, principal: Principal, selected_scope: Scope | None, caller_active: bool
    ) -> JobRecord:
        if row is None or row.owner_id != principal.owner_id:
            raise _not_found()
        if row.repo_id is None:
            if not caller_active:
                raise _not_found()
            return row
        if selected_scope is None or selected_scope.repo_id != row.repo_id:
            raise _not_found()
        if row.checkout_id is not None and selected_scope.checkout_id != row.checkout_id:
            raise _not_found()
        checkout = row.checkout_id if row.checkout_id is not None else selected_scope.checkout_id
        if not self._policy.allows(principal, Scope(row.repo_id, checkout), action=_ACL_ACTION):
            raise _not_found()
        return row

    @staticmethod
    def _terminal(
        tx: KernelTx,
        row: JobRecord,
        state: JobState,
        now: str,
        *,
        reason: JobErrorCode | None = None,
        result_digest: str | None = None,
        actor: str = "system:kernel",
    ) -> None:
        meta: dict[str, JsonValue] = {
            **_row_fence(row),
            "state": state.value,
            "prior_state": row.state.value,
            "reason": None if reason is None else reason.value,
            "result_digest": result_digest,
            "finished_at": now,
        }
        tx.append_record(KernelRecord("job.terminal", meta, actor=actor))

    def _retry_or_dead_letter(
        self, tx: KernelTx, row: JobRecord, reason: JobErrorCode, *, retry_at: str, now: str
    ) -> bool:
        """Queue ``row`` again with ``attempt + 1`` (True), or dead-letter it and release its payload (False)."""
        if row.attempt < MAX_JOB_ATTEMPTS:
            meta: dict[str, JsonValue] = {
                **_row_fence(row),
                "attempt": row.attempt + 1,
                "prior_state": row.state.value,
                "retry_at": retry_at,
                "reason": reason.value,
            }
            tx.append_record(KernelRecord("job.retry", meta))
            return True
        self._terminal(tx, row, JobState.DEAD_LETTER, now, reason=reason)
        tx.release_blob(row.payload_digest, holder_id=row.job_id, reason="expired")
        return False

    @staticmethod
    def _mark_unknown_batch(tx: KernelTx, epoch: int) -> int:
        unsettled = tx.unsettled_invocations(epoch, RECOVERY_BATCH)
        for invocation in unsettled:
            meta: dict[str, JsonValue] = {
                "invocation_id": invocation.invocation_id,
                "writer_epoch": invocation.writer_epoch,
                "recovery_epoch": epoch,
            }
            tx.append_record(KernelRecord("provider.unknown", meta))
        return len(unsettled)

    def _requeue_batch(self, tx: KernelTx, epoch: int, now: str) -> tuple[int, int]:
        requeued = dead = 0
        for row in tx.stale_jobs(epoch, RECOVERY_BATCH):
            if self._retry_or_dead_letter(tx, row, JobErrorCode.LEASE_LOST, retry_at=now, now=now):
                requeued += 1
            else:
                dead += 1
        return requeued, dead
