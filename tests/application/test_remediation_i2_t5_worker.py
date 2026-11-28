"""Independent regressions for SP1-I2 Task 5 remediation: I2-T5-R03 (worker retry cancel-event race).

Requirement sources:
- ``.superpowers/sdd/2026-11-04-sp1-increment2-daemon-mcp-kernel/remediation-t5/ledger.md`` (Oracle 3)
- ``docs/superpowers/plans/2026-11-08-sp1-increment2-task5-completion-plan.md`` (Task 3)
- ``docs/reviews/2026-11-08-sp1-increment2-task5-review.md`` (I2-T5-R03)
- ``.superpowers/sdd/2026-11-04-sp1-increment2-daemon-mcp-kernel/task-5-brief.md`` (lines 60, 63, J1-J4)
"""

from __future__ import annotations

import datetime as dt
import sys
import threading
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, Protocol, cast

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.application.jobs import JobService
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import (
    AccountingStatus,
    JobErrorCode,
    JobLease,
    JobSpec,
    JobState,
    ObjectRef,
    UsageRecord,
    UsageReservation,
    WorkerCommand,
    WorkerCompleted,
    WorkerFailed,
    WorkerUsage,
)
from superbrain.ports.os import OsAdapters
from superbrain.storage.runtime import Runtime
from superbrain.workers.executor import JobContext, JobExecutor, JobHandlerError, WorkItem
from tests.support.clock import FakeClock
from tests.support.inc2_fixture import (
    FIXTURE_JOB_KIND,
    enqueue_job,
    kernel_job_service,
    open_kernel_job_runtime,
)
from tests.support.kernel_auth import seed_principal_and_credential

RESERVE = UsageReservation(max_amount="2")
BOUND_WAIT_S = 5.0


class _Mono:
    """Deterministic monotonic nanosecond clock."""

    def __init__(self) -> None:
        self.now = 1_000_000_000

    def __call__(self) -> int:
        return self.now


class _CommandQueue(Protocol):
    def put(self, item: WorkerCommand, *args: Any, **kwargs: Any) -> None: ...


class _ExecutorWithCommands(Protocol):
    _commands: _CommandQueue


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock(dt.datetime(2026, 11, 8, 9, 0, tzinfo=dt.UTC))


@pytest.fixture
def os_(clock: FakeClock) -> OsAdapters:
    return os_adapters(clock=clock)


@pytest.fixture
def rt(trusted_tmp: Path, os_: OsAdapters) -> Iterator[Runtime]:
    runtime = open_kernel_job_runtime(trusted_tmp / "r03-wroot", os_)
    try:
        yield runtime
    finally:
        runtime.close()


def _expect(code: ErrorCode, action: Callable[[], object]) -> BrainError:
    with pytest.raises(BrainError) as caught:
        action()
    assert caught.value.code is code, f"expected {code}, got {caught.value.code}"
    return caught.value


def _command(executor: JobExecutor) -> WorkerCommand:
    cmd = executor.next_command(BOUND_WAIT_S)
    assert cmd is not None, "worker reported no command within bounded wait"
    return cmd


def _running(service: JobService, rt: Runtime, clock: FakeClock) -> JobLease:
    lease = service.lease_next(rt.lease.epoch, clock.now())
    assert lease is not None, "no due job was leased"
    service.start(lease)
    return lease


def _item(service: JobService, lease: JobLease, invocation_ids: tuple[str, ...] = ()) -> WorkItem:
    return WorkItem(
        lease=lease,
        spec=service.job_spec(lease),
        invocation_ids=invocation_ids,
        deadline_ns=2_000_000_000,
    )


def test_retry_cancel_event_survives_previous_attempt_cleanup(
    rt: Runtime, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    dan = seed_principal_and_credential(rt.policy, owner_id="dan").principal
    attempt1_published = threading.Event()
    allow_attempt1_cleanup = threading.Event()
    attempt2_started = threading.Event()
    attempt2_observed_cancel = threading.Event()
    worker_threads: list[threading.Thread] = []
    seen_attempts: list[int] = []

    def retry_handler(spec: JobSpec, ctx: JobContext) -> tuple[ObjectRef, ...]:
        worker_threads.append(threading.current_thread())
        seen_attempts.append(ctx.lease.attempt)
        if ctx.lease.attempt == 1:
            raise JobHandlerError(JobErrorCode.HANDLER_FAILED, retryable=True)
        attempt2_started.set()
        if ctx.wait_cancelled(BOUND_WAIT_S) and ctx.cancelled():
            attempt2_observed_cancel.set()
        ctx.report_usage(ctx.invocation_ids[0], UsageRecord("0.4", True))
        return (ObjectRef(kind="fixture_result", id=ctx.lease.job_id, revision=1, digest=digest_bytes(spec.payload)),)

    executor = JobExecutor({FIXTURE_JOB_KIND: retry_handler}, _Mono())
    cmd_queue = cast(_ExecutorWithCommands, executor)._commands
    real_put = cmd_queue.put

    def intercept_put(cmd: WorkerCommand, *args: Any, **kwargs: Any) -> None:
        real_put(cmd, *args, **kwargs)
        if isinstance(cmd, WorkerFailed) and cmd.lease.attempt == 1:
            attempt1_published.set()
            assert allow_attempt1_cleanup.wait(BOUND_WAIT_S), "timed out waiting for cleanup release barrier"

    monkeypatch.setattr(cmd_queue, "put", intercept_put)
    executor.start()
    try:
        _, store = kernel_job_service(rt, clock)
        service = JobService(store, store, rt.policy, clock, writer_epoch=rt.lease.epoch, cancel_signal=executor.cancel)
        payload = b"r03-retry-cancel-payload"
        job_id = enqueue_job(service, store, owner_id="dan", payload=payload).job_id

        # 1. Lease/start/submit attempt 1; worker publishes retryable WorkerFailed and pauses before finally cleanup.
        lease1 = _running(service, rt, clock)
        assert lease1.attempt == 1
        executor.submit(_item(service, lease1))
        assert attempt1_published.wait(BOUND_WAIT_S), "attempt 1 did not publish WorkerFailed"

        # 2. Owner applies failure (retry_at = now + 1s), advances fake UTC 1s, leases/starts/submits attempt 2
        #    while attempt 1 is still paused before its finally cancel-event cleanup.
        failed1 = _command(executor)
        assert failed1 == WorkerFailed(lease1, True, JobErrorCode.HANDLER_FAILED)
        service.apply_command(failed1)
        clock.advance(dt.timedelta(seconds=1))
        lease2 = _running(service, rt, clock)
        assert (lease2.job_id, lease2.attempt) == (job_id, 2)
        inv2 = service.reserve_invocation(lease2, RESERVE)
        executor.submit(_item(service, lease2, (inv2,)))

        # 3. Release attempt 1 cleanup barrier; single worker thread finishes attempt 1 cleanup then starts attempt 2.
        allow_attempt1_cleanup.set()
        assert attempt2_started.wait(BOUND_WAIT_S), "attempt 2 did not enter handler"

        # 4. Owner cancels job_id cooperatively while attempt 2 is active in handler.
        assert service.cancel(job_id, dan, selected_scope=None) is JobState.CANCELLED

        cmd_usage = _command(executor)
        assert cmd_usage == WorkerUsage(inv2, UsageRecord("0.4", True))
        cmd_done = _command(executor)
        expected_ref = ObjectRef(kind="fixture_result", id=job_id, revision=1, digest=digest_bytes(payload))
        assert cmd_done == WorkerCompleted(lease2, (expected_ref,))

        # 5. Valid invocation usage settles once; stale completion callback conflicts on fence without overwriting.
        service.apply_command(cmd_usage)
        service.apply_command(cmd_usage)  # identical retry: no-op
        _expect(ErrorCode.IDEMPOTENCY_CONFLICT, lambda: service.settle_usage(inv2, UsageRecord("0.5", True)))
        _expect(ErrorCode.REVISION_CONFLICT, lambda: service.apply_command(cmd_done))

        view = service.get_job(job_id, dan, selected_scope=None)
        assert (view.state, view.attempt, view.result_refs, view.accounting_status) == (
            JobState.CANCELLED,
            2,
            (),
            AccountingStatus.SETTLED,
        )
        assert seen_attempts == [1, 2]
        assert attempt2_observed_cancel.is_set(), (
            "retry attempt lost its cooperative cancel event during previous attempt cleanup"
        )
    finally:
        allow_attempt1_cleanup.set()
        attempt1_published.set()
        attempt2_started.set()
        executor.close(BOUND_WAIT_S)
        if sys.exc_info()[0] is None:
            assert worker_threads and all(not thread.is_alive() for thread in worker_threads)


def test_normal_cancel_and_post_cleanup_retry_preserve_cancel_events(rt: Runtime, clock: FakeClock) -> None:
    dan = seed_principal_and_credential(rt.policy, owner_id="dan").principal
    single_started = threading.Event()
    single_cancelled = threading.Event()
    retry_started = threading.Event()
    retry_cancelled = threading.Event()
    worker_threads: list[threading.Thread] = []

    def normal_handler(spec: JobSpec, ctx: JobContext) -> tuple[ObjectRef, ...]:
        worker_threads.append(threading.current_thread())
        if spec.payload == b"probe":
            return ()
        if spec.payload == b"single-cancel":
            single_started.set()
            if ctx.wait_cancelled(BOUND_WAIT_S) and ctx.cancelled():
                single_cancelled.set()
            return ()
        if ctx.lease.attempt == 1:
            raise JobHandlerError(JobErrorCode.HANDLER_FAILED, retryable=True)
        retry_started.set()
        if ctx.wait_cancelled(BOUND_WAIT_S) and ctx.cancelled():
            retry_cancelled.set()
        return ()

    executor = JobExecutor({FIXTURE_JOB_KIND: normal_handler}, _Mono())
    executor.start()
    try:
        _, store = kernel_job_service(rt, clock)
        service = JobService(store, store, rt.policy, clock, writer_epoch=rt.lease.epoch, cancel_signal=executor.cancel)

        # Control A: normal single-attempt cooperative cancel.
        job_single = enqueue_job(service, store, owner_id="dan", payload=b"single-cancel").job_id
        lease_single = _running(service, rt, clock)
        executor.submit(_item(service, lease_single))
        assert single_started.wait(BOUND_WAIT_S)
        assert service.cancel(job_single, dan, selected_scope=None) is JobState.CANCELLED
        done_single = _command(executor)
        assert done_single == WorkerCompleted(lease_single)
        assert single_cancelled.is_set()
        _expect(ErrorCode.REVISION_CONFLICT, lambda: service.apply_command(done_single))
        executor.cancel(job_single)  # repeated cancel after cleanup is a clean no-op

        # Control B: retry submitted strictly AFTER attempt 1 cleanup completes receives fresh cancel event.
        job_retry = enqueue_job(service, store, owner_id="dan", payload=b"post-cleanup-retry").job_id
        lease_r1 = _running(service, rt, clock)
        executor.submit(_item(service, lease_r1))
        failed_r1 = _command(executor)
        assert failed_r1 == WorkerFailed(lease_r1, True, JobErrorCode.HANDLER_FAILED)

        # Run a probe item on the single worker thread to guarantee attempt 1's finally block finished.
        enqueue_job(service, store, owner_id="dan", payload=b"probe")
        lease_probe = _running(service, rt, clock)
        executor.submit(_item(service, lease_probe))
        assert _command(executor) == WorkerCompleted(lease_probe)

        service.apply_command(failed_r1)
        clock.advance(dt.timedelta(seconds=1))
        lease_r2 = _running(service, rt, clock)
        assert (lease_r2.job_id, lease_r2.attempt) == (job_retry, 2)
        executor.submit(_item(service, lease_r2))
        assert retry_started.wait(BOUND_WAIT_S)
        assert service.cancel(job_retry, dan, selected_scope=None) is JobState.CANCELLED
        done_r2 = _command(executor)
        assert done_r2 == WorkerCompleted(lease_r2)
        assert retry_cancelled.is_set()
        _expect(ErrorCode.REVISION_CONFLICT, lambda: service.apply_command(done_r2))
    finally:
        single_started.set()
        retry_started.set()
        executor.close(BOUND_WAIT_S)
        if sys.exc_info()[0] is None:
            assert worker_threads and all(not thread.is_alive() for thread in worker_threads)
