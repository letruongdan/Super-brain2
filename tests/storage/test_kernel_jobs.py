"""Task 5: durable Job/ProviderInvocation transitions, fences, recovery and 30-day dead-letter retention (real SQL).

Every transition runs through ``JobService`` over a real kernel store (SQLite WAL + CAS) opened with the composition
projections; assertions read the ledger, ``p_jobs_*``/``p_provider_invocations_*`` and the CAS holder projection.
"""

from __future__ import annotations

import datetime as dt
import json
import threading
from collections.abc import Callable, Iterator, Mapping
from functools import partial
from pathlib import Path
from typing import TypeVar, cast

import pytest

from superbrain.application import jobs as jobs_mod
from superbrain.application.jobs import JobService
from superbrain.composition.kernel_projections import kernel_store_extensions
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    RECOVERY_BATCH,
    InvocationRecord,
    InvocationState,
    JobErrorCode,
    JobLease,
    JobOutcome,
    JobRecord,
    JobSpec,
    JobState,
    KernelRecord,
    ObjectRef,
    RecoveryCounts,
    StoredResult,
    UsageRecord,
    UsageReservation,
)
from superbrain.ports.kernel import KernelStorePort, KernelTx
from superbrain.ports.os import OsAdapters
from superbrain.storage.cas import held_digests
from superbrain.storage.idempotency import KernelIdempotencyStore, StagedKernelStore
from superbrain.storage.jobs import JobsProjection, ProviderInvocationProjection
from superbrain.storage.kernel_schema import KERNEL_JOB_KINDS, KERNEL_POLICY_MIGRATIONS, KERNEL_STORE_MIGRATIONS
from superbrain.storage.kinds import CORE_KINDS
from superbrain.storage.ledger import LedgerEntry, ProjectionHandler, utc_timestamp
from superbrain.storage.runtime import Runtime
from tests.support.clock import FakeClock
from tests.support.inc2_fixture import (
    enqueue_job,
    kernel_job_service,
    open_cloned_runtime,
    open_kernel_job_runtime,
    reopen_kernel_job_runtime,
)
from tests.support.kernel_auth import seed_principal_and_credential

_T = TypeVar("_T")
OWNER = "dan"
JOB_KINDS = frozenset(
    {
        "job.queued",
        "job.leased",
        "job.running",
        "job.retry",
        "job.terminal",
        "job.retention_expired",
        "provider.reserved",
        "provider.settled",
        "provider.unknown",
    }
)
RESERVE = UsageReservation(max_amount="1.5")


@pytest.fixture
def rt(trusted_tmp: Path, os_: OsAdapters) -> Iterator[Runtime]:
    handlers, kinds = kernel_store_extensions()
    runtime = open_cloned_runtime(
        trusted_tmp / "jroot",
        os_,
        role="kernel-jobs-rt",
        handlers=handlers,
        kinds=kinds,
        store_migrations=KERNEL_STORE_MIGRATIONS,
        policy_migrations=KERNEL_POLICY_MIGRATIONS,
    )
    try:
        yield runtime
    finally:
        runtime.close()


def _entries(rt: Runtime, kinds: frozenset[str] = JOB_KINDS) -> list[LedgerEntry]:
    return [entry for entry in rt.store.entries() if entry.kind in kinds]


def _ledger_len(rt: Runtime) -> int:
    return sum(1 for _ in rt.store.entries())


def _job_row(store: StagedKernelStore, job_id: str) -> JobRecord:
    row = store.transact(lambda tx: tx.read_job(job_id))
    assert row is not None, "job row is missing"
    return row


def _invocation(store: StagedKernelStore, invocation_id: str) -> InvocationRecord:
    row = store.transact(lambda tx: tx.read_invocation(invocation_id))
    assert row is not None, "invocation row is missing"
    return row


def _holds(rt: Runtime, holder_id: str) -> list[str]:
    with rt.store.transaction() as txn:
        return held_digests(txn.db, "event", holder_id)


def _tables(rt: Runtime) -> dict[str, list[tuple[object, ...]]]:
    with rt.store.transaction() as txn:
        return {
            name: sorted(txn.db.execute(f'SELECT * FROM "{name}"').fetchall(), key=repr)
            for name in ("p_jobs_state", "p_provider_invocations_state", "p_cas_holders_")
        }


def _lease(service: JobService, epoch: int, clock: FakeClock) -> JobLease:
    lease = service.lease_next(epoch, clock.now())
    assert lease is not None, "no due job was leased"
    return lease


def _running(service: JobService, epoch: int, clock: FakeClock) -> JobLease:
    lease = _lease(service, epoch, clock)
    service.start(lease)
    return lease


def _expect(code: ErrorCode, action: Callable[[], object]) -> BrainError:
    with pytest.raises(BrainError) as caught:
        action()
    assert caught.value.code is code, f"expected {code}, got {caught.value.code}"
    return caught.value


# --- registration ---------------------------------------------------------------------------------------------------


def test_job_reducers_and_kinds_are_registered_at_version_one_without_schema_change() -> None:
    handlers, kinds = kernel_store_extensions()
    by_name = {handler.name: handler for handler in handlers}
    assert {"jobs", "provider_invocations"} <= set(by_name)
    assert by_name["jobs"].handler_version == 1 and by_name["provider_invocations"].handler_version == 2
    assert by_name["jobs"].kinds | by_name["provider_invocations"].kinds == JOB_KINDS
    assert {kind.kind: kind.handler_version for kind in KERNEL_JOB_KINDS} == {
        **dict.fromkeys(JOB_KINDS, 1),
        "provider.settled": 2,
    }
    assert all(not kind.reserved for kind in KERNEL_JOB_KINDS)
    assert JOB_KINDS <= kinds.kinds()
    assert {"snapshot.observed", "lineage.task_bound"} <= kinds.kinds()  # Task 3 kinds stay registered
    hold = next(kind for kind in CORE_KINDS if kind.kind == "cas.hold")
    assert hold.enums["holder_kind"] == frozenset({"event", "evidence", "artifact", "lesson", "proposal", "receipt"})
    assert KERNEL_STORE_MIGRATIONS[-1].to_version == 6 and KERNEL_POLICY_MIGRATIONS[-1].to_version == 4
    assert RECOVERY_BATCH == 100


# --- enqueue in the caller's transaction ------------------------------------------------------------------------------


def test_enqueue_in_caller_txn_sets_attempt_one_holds_payload_and_rolls_back_together(
    rt: Runtime, clock: FakeClock
) -> None:
    service, store = kernel_job_service(rt, clock)
    payload = b"payload-canary-7f3a"
    ref = enqueue_job(service, store, owner_id=OWNER, payload=payload, repo_id="repo-a")
    assert (ref.state, ref.attempt) == (JobState.QUEUED, 1)
    row = _job_row(store, ref.job_id)
    assert (row.state, row.attempt, row.retry_at, row.owner_id, row.repo_id) == (
        JobState.QUEUED,
        1,
        utc_timestamp(clock.now()),
        OWNER,
        "repo-a",
    )
    assert row.payload_digest == digest_bytes(payload)
    assert _holds(rt, ref.job_id) == [digest_bytes(payload)]
    [queued] = _entries(rt)
    assert queued.kind == "job.queued" and queued.meta["job_id"] == ref.job_id and queued.meta["attempt"] == 1
    with rt.store.transaction() as txn:
        raw_ledger = b"".join(bytes(row[0]) for row in txn.db.execute("SELECT meta FROM ledger").fetchall())
    assert payload not in raw_ledger

    before, tables = _ledger_len(rt), _tables(rt)

    def enqueue_then_fail(tx: KernelTx) -> None:
        service.enqueue(tx, JobSpec(kind="fixture.echo", owner_id=OWNER, payload=b"rolled back"))
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")

    store.stage_blob(b"rolled back")
    _expect(ErrorCode.INVALID_INPUT, lambda: store.transact(enqueue_then_fail))
    assert (_ledger_len(rt), _tables(rt)) == (before, tables)
    unstaged = JobSpec(kind="fixture.echo", owner_id=OWNER, payload=b"never staged")
    _expect(ErrorCode.INTEGRITY_FAILURE, lambda: store.transact(lambda tx: service.enqueue(tx, unstaged)))
    assert (_ledger_len(rt), _tables(rt)) == (before, tables)


def test_enqueue_commits_with_idempotency_row_and_replay_creates_no_second_job(rt: Runtime, clock: FakeClock) -> None:
    service, _ = kernel_job_service(rt, clock)
    idem = KernelIdempotencyStore(rt.store, rt.policy, writer_epoch=rt.lease.epoch)
    key_id, _key = rt.policy.request_digest_key()
    payload = b"request_improvement payload"
    staged = StagedKernelStore(rt.store, rt.policy, writer_epoch=rt.lease.epoch).stage_blob(payload)
    spec = JobSpec(kind="fixture.echo", owner_id=OWNER, payload=payload)

    def apply(tx: KernelTx) -> StoredResult:
        ref = service.enqueue(tx, spec)
        return StoredResult(result_id=ref.job_id, assignment_id=None)

    results = [
        idem.commit_prepared_effect(
            staged_blobs=(staged,),
            principal_id="principal-1",
            tool="request_improvement",
            key_hash=digest_bytes(b"key"),
            active_key_id=key_id,
            request_digest=digest_bytes(b"request"),
            now=clock.now(),
            verify_raced_row=lambda row: True,
            apply=apply,
        )
        for _ in range(2)
    ]
    (first, replayed_first), (second, replayed_second) = results
    assert (replayed_first, replayed_second) == (False, True)
    assert first.result_id == second.result_id
    assert [entry.meta["job_id"] for entry in _entries(rt, frozenset({"job.queued"}))] == [first.result_id]
    row = idem.lookup_for_owner(
        principal_id="principal-1", tool="request_improvement", key_hash=digest_bytes(b"key"), now=clock.now()
    )
    assert row is not None and row.result_id == first.result_id


# --- fenced transitions -----------------------------------------------------------------------------------------------


def test_lease_start_complete_append_one_event_each_and_projection_matches_rebuild(
    rt: Runtime, clock: FakeClock
) -> None:
    service, store = kernel_job_service(rt, clock)
    ref = enqueue_job(service, store, owner_id=OWNER)
    epoch = rt.lease.epoch
    lease = _lease(service, epoch, clock)
    assert (lease.job_id, lease.attempt, lease.writer_epoch) == (ref.job_id, 1, epoch)
    assert _job_row(store, ref.job_id).state is JobState.LEASED
    service.start(lease)
    assert _job_row(store, ref.job_id).state is JobState.RUNNING
    result = ObjectRef(kind="fixture_result", id="r-1", revision=1, digest=digest_bytes(b"result"))
    service.complete(lease, JobOutcome.success((result,)))
    row = _job_row(store, ref.job_id)
    assert (row.state, row.attempt, row.reason) == (JobState.SUCCEEDED, 1, None)
    assert [entry.kind for entry in _entries(rt)] == ["job.queued", "job.leased", "job.running", "job.terminal"]
    terminal = _entries(rt)[-1]
    assert (terminal.meta["state"], terminal.meta["prior_state"], terminal.meta["lease_id"]) == (
        "succeeded",
        "running",
        lease.lease_id,
    )
    assert row.result_digest is not None and row.result_digest in _holds(rt, ref.job_id)
    assert service.lease_next(epoch, clock.now() + dt.timedelta(days=1)) is None  # terminal jobs are never leased
    _expect(ErrorCode.REVISION_CONFLICT, lambda: service.complete(lease, JobOutcome.success()))
    before = _tables(rt)
    rt.store.rebuild_projections()
    assert _tables(rt) == before


def test_exact_fence_mismatch_or_wrong_prior_state_is_revision_conflict_and_writes_nothing(
    rt: Runtime, clock: FakeClock
) -> None:
    service, store = kernel_job_service(rt, clock)
    epoch = rt.lease.epoch
    _expect(ErrorCode.REVISION_CONFLICT, lambda: service.lease_next(epoch + 1, clock.now()))
    enqueue_job(service, store, owner_id=OWNER)
    leased = _lease(service, epoch, clock)
    enqueue_job(service, store, owner_id=OWNER)
    running = _running(service, epoch, clock)
    queued = enqueue_job(service, store, owner_id=OWNER)

    def variants(lease: JobLease, foreign_lease_id: str) -> dict[str, JobLease]:
        return {
            "job_id": JobLease(queued.job_id, lease.attempt, lease.writer_epoch, lease.lease_id),
            "attempt": JobLease(lease.job_id, lease.attempt + 1, lease.writer_epoch, lease.lease_id),
            "writer_epoch": JobLease(lease.job_id, lease.attempt, lease.writer_epoch + 1, lease.lease_id),
            "lease_id": JobLease(lease.job_id, lease.attempt, lease.writer_epoch, foreign_lease_id),
        }

    attempts: list[tuple[str, Callable[[], object]]] = []
    for name, bad in variants(leased, running.lease_id).items():
        attempts.append((f"start/{name}", partial(service.start, bad)))
    for name, bad in variants(running, leased.lease_id).items():
        attempts.append((f"complete/{name}", partial(service.complete, bad, JobOutcome.success())))
        attempts.append((f"reserve/{name}", partial(service.reserve_invocation, bad, RESERVE)))
    attempts += [
        ("start twice", lambda: service.start(running)),
        ("complete a leased job", lambda: service.complete(leased, JobOutcome.success())),
        ("reserve on a leased job", lambda: service.reserve_invocation(leased, RESERVE)),
    ]
    before, tables = _ledger_len(rt), _tables(rt)
    for name, action in attempts:
        with pytest.raises(BrainError) as caught:
            action()
        assert caught.value.code is ErrorCode.REVISION_CONFLICT, name
        assert caught.value.message == "revision conflict", name
        assert (_ledger_len(rt), _tables(rt)) == (before, tables), name


def test_retryable_failures_back_off_one_then_two_seconds_then_dead_letter(rt: Runtime, clock: FakeClock) -> None:
    service, store = kernel_job_service(rt, clock)
    epoch = rt.lease.epoch
    ref = enqueue_job(service, store, owner_id=OWNER, payload=b"retry me")
    retryable = JobOutcome.failure(JobErrorCode.HANDLER_FAILED, retryable=True)

    first = _running(service, epoch, clock)
    assert first.attempt == 1
    service.complete(first, retryable)
    row = _job_row(store, ref.job_id)
    assert (row.state, row.attempt, row.retry_at) == (
        JobState.QUEUED,
        2,
        utc_timestamp(clock.now() + dt.timedelta(seconds=1)),
    )
    assert service.lease_next(epoch, clock.now()) is None  # not due before retry_at
    clock.advance(dt.timedelta(seconds=1))
    second = _running(service, epoch, clock)
    assert second.attempt == 2  # leasing never increments
    service.complete(second, retryable)
    assert _job_row(store, ref.job_id).retry_at == utc_timestamp(clock.now() + dt.timedelta(seconds=2))
    clock.advance(dt.timedelta(seconds=1))
    assert service.lease_next(epoch, clock.now()) is None
    clock.advance(dt.timedelta(seconds=1))
    third = _running(service, epoch, clock)
    assert third.attempt == 3
    service.complete(third, retryable)
    row = _job_row(store, ref.job_id)
    assert (row.state, row.attempt, row.reason) == (JobState.DEAD_LETTER, 3, JobErrorCode.HANDLER_FAILED)
    assert _holds(rt, ref.job_id) == []  # dead letter keeps metadata and reason only
    retries = _entries(rt, frozenset({"job.retry"}))
    assert [(e.meta["attempt"], e.meta["reason"], e.meta["prior_state"]) for e in retries] == [
        (2, "handler_failed", "running"),
        (3, "handler_failed", "running"),
    ]
    releases = _entries(rt, frozenset({"cas.release"}))
    assert [(e.meta["holder_id"], e.meta["reason"]) for e in releases] == [(ref.job_id, "expired")]
    assert service.lease_next(epoch, clock.now() + dt.timedelta(days=1)) is None

    nonretry_ref = enqueue_job(service, store, owner_id=OWNER, payload=b"fail once")
    lease = _running(service, epoch, clock)
    service.complete(lease, JobOutcome.failure(JobErrorCode.INVALID_PAYLOAD, retryable=False))
    row = _job_row(store, nonretry_ref.job_id)
    assert (row.state, row.attempt, row.reason) == (JobState.FAILED, 1, JobErrorCode.INVALID_PAYLOAD)
    assert service.lease_next(epoch, clock.now() + dt.timedelta(days=1)) is None


def test_due_queue_orders_by_retry_at_then_job_id(rt: Runtime, clock: FakeClock) -> None:
    service, store = kernel_job_service(rt, clock)
    epoch = rt.lease.epoch
    late = enqueue_job(service, store, owner_id=OWNER, payload=b"late")
    failed = _running(service, epoch, clock)
    service.complete(failed, JobOutcome.failure(JobErrorCode.HANDLER_FAILED, retryable=True))  # retry_at = t0 + 1 s
    clock.advance(dt.timedelta(milliseconds=500))
    second = enqueue_job(service, store, owner_id=OWNER, payload=b"second")
    third = enqueue_job(service, store, owner_id=OWNER, payload=b"third")
    clock.advance(dt.timedelta(seconds=1))
    order = [_lease(service, epoch, clock).job_id for _ in range(3)]
    # retry_at first (``late`` has the smallest job_id but the latest retry_at), then job_id for equal retry_at
    assert late.job_id < second.job_id < third.job_id
    assert order == [second.job_id, third.job_id, late.job_id]


# --- invocations and usage --------------------------------------------------------------------------------------------


def test_reserved_invocation_is_durable_before_return_and_usage_settles_exactly_once(
    rt: Runtime, clock: FakeClock
) -> None:
    service, store = kernel_job_service(rt, clock)
    epoch = rt.lease.epoch
    ref = enqueue_job(service, store, owner_id=OWNER)
    lease = _running(service, epoch, clock)
    invocation_id = service.reserve_invocation(lease, RESERVE)
    inv = _invocation(store, invocation_id)
    assert (inv.state, inv.job_id, inv.attempt, inv.writer_epoch, inv.lease_id) == (
        InvocationState.RESERVED,
        ref.job_id,
        1,
        epoch,
        lease.lease_id,
    )
    assert _holds(rt, invocation_id) == [inv.reservation_digest]
    reservation = json.loads(rt.store.cas.read(inv.reservation_digest))
    assert reservation["max_amount"] == "1.5" and reservation["invocation_id"] == invocation_id
    [reserved] = _entries(rt, frozenset({"provider.reserved"}))
    assert "1.5" not in json.dumps(dict(reserved.meta))  # decimal quantities stay in CAS
    second_id = service.reserve_invocation(lease, RESERVE)
    assert second_id != invocation_id

    usage = UsageRecord(amount="0.75", complete=True)
    service.settle_usage(invocation_id, usage)
    settled = _invocation(store, invocation_id)
    assert settled.state is InvocationState.SETTLED and settled.usage_complete is True
    assert settled.usage_digest is not None
    assert sorted(_holds(rt, invocation_id)) == sorted([inv.reservation_digest, settled.usage_digest])
    before = _ledger_len(rt)
    service.settle_usage(invocation_id, UsageRecord(amount="0.75", complete=True))  # identical retry: no-op
    assert _ledger_len(rt) == before
    _expect(ErrorCode.IDEMPOTENCY_CONFLICT, lambda: service.settle_usage(invocation_id, UsageRecord("0.8", True)))
    _expect(ErrorCode.IDEMPOTENCY_CONFLICT, lambda: service.settle_usage(invocation_id, UsageRecord(None, False)))
    assert _ledger_len(rt) == before
    assert _invocation(store, invocation_id).usage_digest == settled.usage_digest
    _expect(ErrorCode.NOT_FOUND, lambda: service.settle_usage("018f0000-0000-7000-8000-000000000000", usage))

    service.settle_usage(second_id, UsageRecord(amount=None, complete=False))
    unknown = _invocation(store, second_id)
    assert unknown.usage_complete is False and unknown.usage_digest is not None
    descriptor = json.loads(rt.store.cas.read(unknown.usage_digest))
    assert descriptor["amount"] is None and descriptor["complete"] is False  # unknown never becomes "0"
    for bad in (lambda: UsageRecord(None, True), lambda: UsageRecord("0", False), lambda: UsageRecord("1.50", True)):
        _expect(ErrorCode.INVALID_INPUT, bad)


# --- recovery ---------------------------------------------------------------------------------------------------------


def _fail_retry(service: JobService, lease: JobLease) -> None:
    service.complete(lease, JobOutcome.failure(JobErrorCode.HANDLER_FAILED, retryable=True))


def test_killed_epoch_recovery_marks_unknown_first_requeues_once_and_is_idempotent(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    root = trusted_tmp / "recover"
    rt1 = open_kernel_job_runtime(root, os_)
    store_id = rt1.store.store_id
    dan = seed_principal_and_credential(rt1.policy, owner_id=OWNER).principal
    service, store = kernel_job_service(rt1, clock)
    e1 = rt1.lease.epoch
    try:
        job_c = enqueue_job(service, store, owner_id=OWNER, payload=b"C")
        _fail_retry(service, _running(service, e1, clock))
        clock.advance(dt.timedelta(seconds=1))
        _fail_retry(service, _running(service, e1, clock))
        clock.advance(dt.timedelta(seconds=2))
        lease_c = _running(service, e1, clock)
        inv_c = service.reserve_invocation(lease_c, RESERVE)
        job_b = enqueue_job(service, store, owner_id=OWNER, payload=b"B")
        _fail_retry(service, _running(service, e1, clock))
        clock.advance(dt.timedelta(seconds=1))
        lease_b = _running(service, e1, clock)
        inv_b = service.reserve_invocation(lease_b, RESERVE)
        job_a = enqueue_job(service, store, owner_id=OWNER, payload=b"A")
        lease_a = _lease(service, e1, clock)
        job_d = enqueue_job(service, store, owner_id=OWNER, payload=b"D")
        inv_d = service.reserve_invocation(_running(service, e1, clock), RESERVE)
        assert service.cancel(job_d.job_id, dan, selected_scope=None) is JobState.CANCELLED
        job_e = enqueue_job(service, store, owner_id=OWNER, payload=b"E")
        lease_e = _running(service, e1, clock)
        inv_e = service.reserve_invocation(lease_e, RESERVE)
        inv_settled = service.reserve_invocation(lease_e, RESERVE)
        service.settle_usage(inv_settled, UsageRecord("0.1", True))
        service.complete(lease_e, JobOutcome.failure(JobErrorCode.INVALID_PAYLOAD, retryable=False))
        assert [lease_a.attempt, lease_b.attempt, lease_c.attempt] == [1, 2, 3]
    finally:
        rt1.close()  # the daemon is killed: leases and reservations of epoch e1 are abandoned

    clock.advance(dt.timedelta(seconds=10))
    rt2 = reopen_kernel_job_runtime(root, store_id, os_)
    try:
        e2 = rt2.lease.epoch
        assert e2 > e1
        service2, store2 = kernel_job_service(rt2, clock)
        _expect(ErrorCode.REVISION_CONFLICT, lambda: service2.recover(e1))
        mark = max(entry.sequence for entry in rt2.store.entries())
        counts = service2.recover(e2)
        assert counts == RecoveryCounts(invocations_unknown=4, jobs_requeued=2, jobs_dead_lettered=1)
        a, b, c = (_job_row(store2, job.job_id) for job in (job_a, job_b, job_c))
        now = utc_timestamp(clock.now())
        assert (a.state, a.attempt, a.retry_at, a.lease_id) == (JobState.QUEUED, 2, now, None)
        assert (b.state, b.attempt, b.retry_at) == (JobState.QUEUED, 3, now)
        assert (c.state, c.attempt, c.reason) == (JobState.DEAD_LETTER, 3, JobErrorCode.LEASE_LOST)
        assert _holds(rt2, job_c.job_id) == [] and _holds(rt2, job_a.job_id) == [digest_bytes(b"A")]
        assert _job_row(store2, job_d.job_id).state is JobState.CANCELLED
        assert _job_row(store2, job_e.job_id).state is JobState.FAILED
        for inv in (inv_c, inv_b, inv_d, inv_e):
            assert _invocation(store2, inv).state is InvocationState.OUTCOME_UNKNOWN
        assert _invocation(store2, inv_settled).state is InvocationState.SETTLED

        recovered = [entry for entry in rt2.store.entries(after=mark) if entry.kind in JOB_KINDS]
        unknown_seqs = [e.sequence for e in recovered if e.kind == "provider.unknown"]
        job_seqs = [e.sequence for e in recovered if e.kind.startswith("job.")]
        assert len(unknown_seqs) == 4 and len(job_seqs) == 3
        assert max(unknown_seqs) < min(job_seqs), "jobs were requeued before invocations became outcome_unknown"

        _expect(ErrorCode.REVISION_CONFLICT, lambda: service2.complete(lease_b, JobOutcome.success()))
        _expect(ErrorCode.REVISION_CONFLICT, lambda: service2.start(lease_a))
        before, tables = _ledger_len(rt2), _tables(rt2)
        assert service2.recover(e2) == RecoveryCounts()
        assert (_ledger_len(rt2), _tables(rt2)) == (before, tables)
        rt2.store.rebuild_projections()
        assert _tables(rt2) == tables  # replaying the recovery events never bumps attempts twice

        next_b, next_a = _lease(service2, e2, clock), _lease(service2, e2, clock)
        assert (next_b.job_id, next_b.attempt, next_b.writer_epoch) == (job_b.job_id, 3, e2)
        assert (next_a.job_id, next_a.attempt, next_a.writer_epoch) == (job_a.job_id, 2, e2)
        assert service2.lease_next(e2, clock.now() + dt.timedelta(days=1)) is None
        service2.start(next_b)
        current_inv = service2.reserve_invocation(next_b, RESERVE)
        before, tables = _ledger_len(rt2), _tables(rt2)
        assert service2.recover(e2) == RecoveryCounts()  # current-epoch leases and reservations are never recovered
        assert (_ledger_len(rt2), _tables(rt2)) == (before, tables)
        assert _invocation(store2, current_inv).state is InvocationState.RESERVED

        reservation_c = _invocation(store2, inv_c).reservation_digest
        assert _holds(rt2, inv_c) == [reservation_c]  # outcome_unknown keeps the max reservation until settle
        service2.settle_usage(inv_c, UsageRecord("0.4", True))
        assert reservation_c in _holds(rt2, inv_c)
        assert _invocation(store2, inv_c).state is InvocationState.SETTLED
    finally:
        rt2.close()


class _CountingStore:
    """``KernelStorePort`` proxy: counts transactions and job records per transaction, can fail one transaction."""

    def __init__(self, inner: StagedKernelStore, *, fail_at: int | None = None) -> None:
        self.inner = inner
        self.fail_at = fail_at
        self.calls = 0
        self.records: list[list[str]] = []
        self.limits: list[int] = []

    def transact(self, operation: Callable[[KernelTx], _T]) -> _T:
        self.calls += 1
        if self.calls == self.fail_at:
            raise BrainError(ErrorCode.IO_ERROR, "I/O error")
        kinds: list[str] = []
        self.records.append(kinds)
        outer = self

        def wrapped(tx: KernelTx) -> _T:
            class _Proxy:
                def __getattr__(self, name: str) -> object:
                    return getattr(tx, name)

                def append_record(self, record: object) -> None:
                    kinds.append(cast(KernelRecord, record).kind)
                    tx.append_record(cast(KernelRecord, record))

                def unsettled_invocations(self, epoch: int, limit: int) -> object:
                    outer.limits.append(limit)
                    return tx.unsettled_invocations(epoch, limit)

                def stale_jobs(self, epoch: int, limit: int) -> object:
                    outer.limits.append(limit)
                    return tx.stale_jobs(epoch, limit)

            return operation(cast(KernelTx, _Proxy()))

        return self.inner.transact(wrapped)


def test_recovery_runs_in_bounded_resumable_batches(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = trusted_tmp / "batches"
    rt1 = open_kernel_job_runtime(root, os_)
    store_id = rt1.store.store_id
    service, store = kernel_job_service(rt1, clock)
    jobs, invocations = [], []
    try:
        for n in range(3):
            jobs.append(enqueue_job(service, store, owner_id=OWNER, payload=f"job-{n}".encode()).job_id)
            invocations.append(service.reserve_invocation(_running(service, rt1.lease.epoch, clock), RESERVE))
    finally:
        rt1.close()
    rt2 = reopen_kernel_job_runtime(root, store_id, os_)
    try:
        monkeypatch.setattr(jobs_mod, "RECOVERY_BATCH", 2)
        _, inner = kernel_job_service(rt2, clock)
        crashing = _CountingStore(inner, fail_at=2)
        crashed = JobService(cast(KernelStorePort, crashing), inner, rt2.policy, clock, writer_epoch=rt2.lease.epoch)
        _expect(ErrorCode.IO_ERROR, lambda: crashed.recover(rt2.lease.epoch))
        states = [_invocation(inner, inv).state for inv in invocations]
        assert states.count(InvocationState.OUTCOME_UNKNOWN) == 2  # the first batch committed
        assert all(_job_row(inner, job).state is JobState.RUNNING for job in jobs)

        counting = _CountingStore(inner)
        resumed = JobService(cast(KernelStorePort, counting), inner, rt2.policy, clock, writer_epoch=rt2.lease.epoch)
        assert resumed.recover(rt2.lease.epoch) == RecoveryCounts(invocations_unknown=1, jobs_requeued=3)
        assert set(counting.limits) == {2}
        job_records = [[k for k in kinds if k in JOB_KINDS] for kinds in counting.records]
        assert all(len(kinds) <= 2 for kinds in job_records)
        flat = [k for kinds in job_records for k in kinds]
        assert flat == ["provider.unknown", "job.retry", "job.retry", "job.retry"]
        assert all(_job_row(inner, job).attempt == 2 for job in jobs)
        assert resumed.recover(rt2.lease.epoch) == RecoveryCounts()
    finally:
        rt2.close()


# --- dead-letter retention and rebuild --------------------------------------------------------------------------------


def test_dead_letter_retention_expires_after_30_days_and_rebuild_never_resurrects(
    rt: Runtime, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, store = kernel_job_service(rt, clock)
    epoch = rt.lease.epoch
    dead = enqueue_job(service, store, owner_id=OWNER, payload=b"dead letter payload")
    for delay in (1, 2, 0):
        _fail_retry(service, _running(service, epoch, clock))
        clock.advance(dt.timedelta(seconds=delay))
    kept = enqueue_job(service, store, owner_id=OWNER, payload=b"still queued")
    died_at = _job_row(store, dead.job_id).finished_at
    assert _job_row(store, dead.job_id).state is JobState.DEAD_LETTER and died_at is not None
    assert _holds(rt, dead.job_id) == []
    died = dt.datetime.strptime(died_at, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=dt.UTC)

    _expect(ErrorCode.INVALID_INPUT, lambda: service.prune_dead_letters(clock.now(), limit=0))
    _expect(ErrorCode.INVALID_INPUT, lambda: service.prune_dead_letters(clock.now(), limit=101))
    assert service.prune_dead_letters(died + dt.timedelta(days=30) - dt.timedelta(microseconds=1)) == 0
    assert service.prune_dead_letters(died + dt.timedelta(days=30)) == 1
    assert store.transact(lambda tx: tx.read_job(dead.job_id)) is None
    [expired] = _entries(rt, frozenset({"job.retention_expired"}))
    assert expired.meta["job_id"] == dead.job_id
    after = _tables(rt)
    assert dead.job_id not in repr(after["p_jobs_state"]) and kept.job_id in repr(after["p_jobs_state"])
    assert service.prune_dead_letters(died + dt.timedelta(days=31)) == 0
    kept_digest = _job_row(store, kept.job_id).payload_digest

    def release(reason: str) -> Callable[[KernelTx], None]:
        return lambda tx: tx.release_blob(kept_digest, holder_id=kept.job_id, reason=reason)

    for reason in ("tombstoned", "superseded", "deleted_by_owner"):
        _expect(ErrorCode.INVALID_INPUT, partial(store.transact, release(reason)))
    assert store.transact(lambda tx: tx.read_held_blob(kept_digest, holder_id=dead.job_id)) is None  # not its holder
    assert store.transact(lambda tx: tx.read_held_blob(kept_digest, holder_id=kept.job_id)) == b"still queued"
    rt.store.rebuild_projections()
    assert _tables(rt) == after
    assert store.transact(lambda tx: tx.read_job(dead.job_id)) is None and _holds(rt, dead.job_id) == []


def test_projection_rebuild_never_enqueues_invokes_or_creates_records(
    rt: Runtime, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, store = kernel_job_service(rt, clock)
    epoch = rt.lease.epoch
    enqueue_job(service, store, owner_id=OWNER, payload=b"one")
    lease = _running(service, epoch, clock)
    invocation_id = service.reserve_invocation(lease, RESERVE)
    enqueue_job(service, store, owner_id=OWNER, payload=b"two")
    before, ledger = _tables(rt), _ledger_len(rt)
    with rt.store.transaction() as txn:
        txn.db.execute("DROP TABLE p_jobs_state")
        txn.db.execute("DROP TABLE p_provider_invocations_state")
    import superbrain.core.ids as ids_mod

    with monkeypatch.context() as guard:
        guard.setattr(ids_mod._default, "next", lambda: (_ for _ in ()).throw(AssertionError("no new ids")))
        guard.setattr(JobService, "enqueue", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no enqueue")))
        rt.store.rebuild_projections()
    assert (_tables(rt), _ledger_len(rt)) == (before, ledger)
    assert _invocation(store, invocation_id).state is InvocationState.RESERVED
    only = _invocation(store, invocation_id)
    assert (only.invocation_id, only.job_id) == (invocation_id, lease.job_id)


def test_job_store_entry_points_require_the_admitted_pair_epoch_and_owner_thread(rt: Runtime, clock: FakeClock) -> None:
    epoch = rt.lease.epoch
    _expect(ErrorCode.INTEGRITY_FAILURE, lambda: StagedKernelStore(rt.store, rt.policy, writer_epoch=epoch + 1))
    _, store = kernel_job_service(rt, clock)
    caught: list[BrainError] = []

    def off_owner_thread() -> None:
        for action in (lambda: store.stage_blob(b"x"), lambda: store.transact(lambda tx: tx.read_job(OWNER))):
            try:
                action()
            except BrainError as err:
                caught.append(err)

    worker = threading.Thread(target=off_owner_thread)
    worker.start()
    worker.join(10)
    assert [err.code for err in caught] == [ErrorCode.INTEGRITY_FAILURE, ErrorCode.INTEGRITY_FAILURE]


class _NoPolicy:
    def is_quarantined(self, digest: str) -> bool:
        raise AssertionError("job reducers never consult policy")

    def is_tombstoned(self, holder_kind: str, holder_id: str) -> bool:
        raise AssertionError("job reducers never consult policy")


def test_reducers_are_pure_and_refuse_an_entry_that_does_not_match_its_row() -> None:
    import sqlite3

    jobs, invocations = JobsProjection(), ProviderInvocationProjection()
    db = sqlite3.connect(":memory:")
    jobs.create_tables(db, "p_jobs_")
    invocations.create_tables(db, "p_provider_invocations_")
    job_id, lease_id, inv_id = (
        "018f0000-0000-7000-8000-00000000000a",
        "018f0000-0000-7000-8000-00000000000b",
        "018f0000-0000-7000-8000-00000000000c",
    )
    sequence = iter(range(1, 100))

    def entry(kind: str, meta: Mapping[str, JsonValue]) -> LedgerEntry:
        return LedgerEntry(next(sequence), job_id, kind, 4, 1, 1, "system:kernel", None, "t", dict(meta), ())

    lease: dict[str, JsonValue] = {"job_id": job_id, "attempt": 1, "writer_epoch": 1, "lease_id": lease_id}
    queued: dict[str, JsonValue] = {
        "job_id": job_id,
        "owner_id": OWNER,
        "repo_id": None,
        "checkout_id": None,
        "kind": "k",
        "payload_digest": digest_bytes(b"p"),
        "attempt": 1,
        "retry_at": "2026-11-08T00:00:00.000000Z",
    }
    jobs.apply(db, "p_jobs_", entry("job.queued", queued), _NoPolicy())
    mismatched: list[tuple[ProjectionHandler, LedgerEntry]] = [
        (jobs, entry("job.running", lease)),  # not leased yet
        (jobs, entry("job.leased", {**lease, "attempt": 2})),
        (jobs, entry("job.retention_expired", {"job_id": job_id, "expired_at": "t"})),  # not a dead letter
        (invocations, entry("provider.unknown", {"invocation_id": inv_id, "writer_epoch": 1, "recovery_epoch": 2})),
    ]
    for handler, bad in mismatched:
        with pytest.raises(BrainError) as caught:
            handler.apply(db, f"p_{handler.name}_", bad, _NoPolicy())
        assert caught.value.code is ErrorCode.INTEGRITY_FAILURE, bad.kind
    jobs.apply(db, "p_jobs_", entry("job.leased", lease), _NoPolicy())
    assert db.execute("SELECT state, attempt, lease_id FROM p_jobs_state").fetchall() == [("leased", 1, lease_id)]
