"""JobService completion, provider-invocation reservation and usage settlement."""

from __future__ import annotations

from collections.abc import Callable

from superbrain.application import jobs as _m
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.faults import crashpoint
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    MAX_JOB_ATTEMPTS,
    InvocationState,
    JobErrorCode,
    JobLease,
    JobOutcome,
    JobRecord,
    JobSpec,
    JobState,
    KernelRecord,
    UsageRecord,
    UsageReservation,
    require_aware_utc,
    reservation_descriptor,
    result_descriptor,
    retry_backoff,
    usage_descriptor,
)
from superbrain.ports.kernel import (
    KernelTx,
)


def settle_usage(self: _m.JobService, invocation_id: str, usage: UsageRecord) -> None:
    descriptor = usage_descriptor(invocation_id, usage)
    usage_digest = digest_bytes(descriptor)

    def _precheck(tx: KernelTx) -> bool:
        invocation = tx.read_invocation(invocation_id)
        if invocation is None:
            raise _m._not_found()
        if invocation.state is InvocationState.SETTLED:
            if usage.complete and invocation.usage_digest == usage_digest:
                return False
            raise BrainError(ErrorCode.IDEMPOTENCY_CONFLICT, "idempotency conflict")
        if (
            not usage.complete
            and invocation.state is InvocationState.OUTCOME_UNKNOWN
            and invocation.usage_complete is False
        ):
            if invocation.usage_digest == usage_digest:
                return False
            raise BrainError(ErrorCode.IDEMPOTENCY_CONFLICT, "idempotency conflict")
        return True

    if not self._store.transact(_precheck):
        return
    acct = self._accounting_active()
    if acct is not None:
        acct.settle_accounting_invocation(
            invocation_id=invocation_id,
            amount=usage.amount,
            complete=usage.complete,
            now=self._clock.now(),
        )
    self._stager.stage_blob(descriptor)

    def settle(tx: KernelTx) -> bool:
        invocation = tx.read_invocation(invocation_id)
        if invocation is None:
            raise _m._not_found()
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


def reserve_invocation(self: _m.JobService, lease: JobLease, reservation: UsageReservation) -> str:
    self._require_current(lease)
    if not isinstance(reservation, UsageReservation):
        raise _m._invalid()
    row = self._store.transact(lambda tx: self._fenced(tx, lease, JobState.RUNNING))
    invocation_id = new_id()
    acct = self._accounting_active()
    if acct is not None:
        acct.reserve_accounting_invocation(
            invocation_id=invocation_id,
            job_id=lease.job_id,
            owner_id=row.owner_id,
            writer_epoch=lease.writer_epoch,
            max_amount=reservation.max_amount,
            now=self._clock.now(),
        )
    descriptor = reservation_descriptor(invocation_id, lease.job_id, reservation)
    self._stager.stage_blob(descriptor)

    def reserve(tx: KernelTx) -> None:
        self._fenced(tx, lease, JobState.RUNNING)
        digest = tx.hold_blob(descriptor, holder_id=invocation_id)
        meta = {"invocation_id": invocation_id, **_m._lease_meta(lease), "reservation_digest": digest}
        tx.append_record(KernelRecord("provider.reserved", meta))

    self._store.transact(reserve)
    crashpoint("jobs.after_invocation_reserve")
    return invocation_id


def complete(
    self: _m.JobService,
    lease: JobLease,
    result: JobOutcome,
    *,
    on_complete_in_tx: Callable[[KernelTx, JobRecord, JobOutcome], None] | None = None,
) -> None:
    self._require_current(lease)
    if not isinstance(result, JobOutcome):
        raise _m._invalid()
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
            if on_complete_in_tx is not None:
                on_complete_in_tx(tx, row, result)
        elif not result.retryable:
            self._terminal(tx, row, JobState.FAILED, now, reason=result.error_code)
        else:
            assert result.error_code is not None
            exhausted = row.attempt >= MAX_JOB_ATTEMPTS
            retry_at = now if exhausted else require_aware_utc(now_utc + retry_backoff(row.attempt))[1]
            self._retry_or_dead_letter(tx, row, result.error_code, retry_at=retry_at, now=now)

    self._store.transact(complete)


def _resolve_claimed_spec(
    self: _m.JobService, lease: JobLease, state: JobState, *, fail_missing_payload: bool
) -> JobSpec | None:
    self._require_current(lease)
    now_utc, now = require_aware_utc(self._clock.now())

    def resolve(tx: KernelTx) -> JobSpec | None:
        row = self._fenced(tx, lease, state)
        if tx.holder_tombstoned(row.job_id) or tx.blob_restricted(row.payload_digest):
            self._terminal(tx, row, JobState.FAILED, now, reason=JobErrorCode.INVALID_PAYLOAD)
            return None
        # Every payload-classifying read shares one transient rule, so no read failure can strand the lease.
        try:
            payload = tx.read_held_blob(row.payload_digest, holder_id=row.job_id)
            intact = payload is not None or tx.blob_present(row.payload_digest)
        except BrainError as err:
            if fail_missing_payload and err.code in _m._PERMANENT_PAYLOAD_FAULT:
                # The read itself proved the stored payload unusable (wrong entry type, link, permissions).
                payload, intact = None, False
            elif err.code not in _m._TRANSIENT_PAYLOAD_READ:
                raise
            else:
                exhausted = row.attempt >= MAX_JOB_ATTEMPTS
                retry_at = now if exhausted else require_aware_utc(now_utc + retry_backoff(row.attempt))[1]
                self._retry_or_dead_letter(
                    tx, row, JobErrorCode.HANDLER_UNAVAILABLE, retry_at=retry_at, now=now
                )
                return None
        if payload is None:
            if not intact and not fail_missing_payload:
                # Missing or corrupt bytes are an integrity alarm, kept loud: the caller sees INTEGRITY_FAILURE.
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
            # Intact bytes this job no longer holds: its payload is gone for good, so it can never run.
            self._terminal(tx, row, JobState.FAILED, now, reason=JobErrorCode.INVALID_PAYLOAD)
            return None
        return JobSpec(row.kind, row.owner_id, payload, repo_id=row.repo_id, checkout_id=row.checkout_id)

    return self._store.transact(resolve)
