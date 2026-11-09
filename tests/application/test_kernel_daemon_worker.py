"""Independent regressions for SP1-I2 Task 6a worker handoff contracts (OBS-T5-W01, OBS-T5-W02).

Requirement sources:
- ``.superpowers/sdd/2026-11-04-sp1-increment2-daemon-mcp-kernel/task-6a-brief.md`` (lines 59, 70, 74)
- ``.superpowers/sdd/2026-11-04-sp1-increment2-daemon-mcp-kernel/task-6a/ledger.md`` (OBS-T5-W01, OBS-T5-W02, #17, #18)
- ``.superpowers/sdd/2026-11-04-sp1-increment2-daemon-mcp-kernel/task-6a/interface-spec.md`` (§3)
- ``docs/superpowers/specs/2026-11-04-sp1-increment2-kernel-decisions.md`` (D4-D7)
"""

from __future__ import annotations

import contextlib
import datetime as dt
import os
import sys
import threading
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, Protocol, cast

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.daemon_config import read_daemon_config
from superbrain.adapters.os.tls_material import create_store_tls
from superbrain.application.jobs import JobService
from superbrain.composition.daemon_entry import create_daemon_owner_loop
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode, is_safe_wire_message
from superbrain.core.ids import new_id
from superbrain.core.kernel import (
    AccountingStatus,
    InvocationRecord,
    InvocationState,
    JobErrorCode,
    JobLease,
    JobRecord,
    JobSpec,
    JobState,
    ObjectRef,
    RecoveryCounts,
    UsageRecord,
    UsageReservation,
    WorkerCommand,
    WorkerCompleted,
    WorkerFailed,
    WorkerUsage,
)
from superbrain.ports.os import OsAdapters
from superbrain.storage.idempotency import StagedKernelStore
from superbrain.storage.runtime import Runtime
from superbrain.workers.executor import JobContext, JobExecutor, JobHandlerError, WorkItem
from tests.support.clock import FakeClock
from tests.support.inc2_fixture import (
    FIXTURE_JOB_KIND,
    enqueue_job,
    kernel_job_service,
    open_kernel_job_runtime,
    reopen_kernel_job_runtime,
)
from tests.support.kernel_auth import make_bootstrap_auth, seed_principal_and_credential

RESERVE = UsageReservation(max_amount="2")
BOUND_WAIT_S = 5.0


class _Mono:
    """Deterministic monotonic nanosecond clock shared across owner and worker threads."""

    def __init__(self, initial_ns: int = 10) -> None:
        self.now = initial_ns

    def __call__(self) -> int:
        return self.now


class _ItemQueue(Protocol):
    def put(self, item: WorkItem | None, *args: Any, **kwargs: Any) -> None: ...
    def empty(self) -> bool: ...


class _ExecutorWithItems(Protocol):
    _items: _ItemQueue


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock(dt.datetime(2026, 11, 8, 9, 0, tzinfo=dt.UTC))


@pytest.fixture
def os_(clock: FakeClock) -> OsAdapters:
    return os_adapters(clock=clock)


@pytest.fixture
def rt(trusted_tmp: Path, os_: OsAdapters) -> Iterator[Runtime]:
    runtime = open_kernel_job_runtime(trusted_tmp / "t6a-wroot", os_)
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


def _job_row(store: StagedKernelStore, job_id: str) -> JobRecord:
    row = store.transact(lambda tx: tx.read_job(job_id))
    assert row is not None, "job row is missing"
    return row


def _invocation_row(store: StagedKernelStore, invocation_id: str) -> InvocationRecord:
    row = store.transact(lambda tx: tx.read_invocation(invocation_id))
    assert row is not None, "invocation row is missing"
    return row


def _running(service: JobService, rt: Runtime, clock: FakeClock) -> JobLease:
    lease = service.lease_next(rt.lease.epoch, clock.now())
    assert lease is not None, "no due job was leased"
    service.start(lease)
    return lease


def _make_item(
    service: JobService,
    lease: JobLease,
    *,
    deadline_ns: int,
    invocation_ids: tuple[str, ...] = (),
) -> WorkItem:
    return WorkItem(
        lease=lease,
        spec=service.job_spec(lease),
        invocation_ids=invocation_ids,
        deadline_ns=deadline_ns,
    )


def test_expired_worker_item_never_enters_handler(rt: Runtime, clock: FakeClock) -> None:
    """OBS-T5-W01: pre-expired and queue-expired items emit retryable DEADLINE_EXCEEDED without entering handler."""
    dan = seed_principal_and_credential(rt.policy, owner_id="dan").principal
    mono = _Mono(initial_ns=10)
    entered: list[tuple[bytes, int, int]] = []
    first_entered = threading.Event()
    second_submitted = threading.Event()
    retry_entered = threading.Event()
    retry_cancelled = threading.Event()
    worker_threads: list[threading.Thread] = []

    def handler(spec: JobSpec, ctx: JobContext) -> tuple[ObjectRef, ...]:
        worker_threads.append(threading.current_thread())
        entered.append((spec.payload, ctx.lease.attempt, mono.now))
        if spec.payload == b"queued-first":
            first_entered.set()
            assert second_submitted.wait(BOUND_WAIT_S), "timed out waiting for second item submission"
            assert mono.now == 10
            mono.now = 20  # exact deadline_ns of queued-second while queued-second waits in _items
            return (
                ObjectRef(
                    kind="fixture_result",
                    id=ctx.lease.job_id,
                    revision=1,
                    digest=digest_bytes(spec.payload),
                ),
            )
        if spec.payload == b"post-handler-slow":
            mono.now = ctx.deadline_ns + 1
            return (
                ObjectRef(
                    kind="fixture_result",
                    id=ctx.lease.job_id,
                    revision=1,
                    digest=digest_bytes(spec.payload),
                ),
            )
        if spec.payload == b"queued-second" and ctx.lease.attempt == 2:
            retry_entered.set()
            if ctx.wait_cancelled(BOUND_WAIT_S) and ctx.cancelled():
                retry_cancelled.set()
            return ()
        return ()

    executor = JobExecutor({FIXTURE_JOB_KIND: handler}, mono)
    executor.start()
    try:
        _, store = kernel_job_service(rt, clock)
        service = JobService(store, store, rt.policy, clock, writer_epoch=rt.lease.epoch, cancel_signal=executor.cancel)

        # (a) Exact tick boundary (now_ns == deadline_ns == 10) and past deadline (now_ns == 10 > deadline_ns == 9).
        exact_id = enqueue_job(service, store, owner_id="dan", payload=b"exact-tick").job_id
        exact_lease = _running(service, rt, clock)
        past_id = enqueue_job(service, store, owner_id="dan", payload=b"past-deadline").job_id
        past_lease = _running(service, rt, clock)

        executor.submit(_make_item(service, exact_lease, deadline_ns=10))
        executor.submit(_make_item(service, past_lease, deadline_ns=9))

        cmd_exact = _command(executor)
        cmd_past = _command(executor)
        assert entered == [], f"expired items must never enter handler, got {entered!r}"
        assert cmd_exact == WorkerFailed(exact_lease, True, JobErrorCode.DEADLINE_EXCEEDED)
        assert cmd_past == WorkerFailed(past_lease, True, JobErrorCode.DEADLINE_EXCEEDED)

        service.apply_command(cmd_exact)
        service.apply_command(cmd_past)
        assert (_job_row(store, exact_id).state, _job_row(store, exact_id).attempt) == (JobState.QUEUED, 2)
        assert (_job_row(store, past_id).state, _job_row(store, past_id).attempt) == (JobState.QUEUED, 2)

        # (b) Queued-wait expiry: second item is valid at submit time (mono.now == 10 < deadline_ns == 20),
        #     then first item advances mono.now = 20 (exact second.deadline_ns) before completing.
        first_id = enqueue_job(service, store, owner_id="dan", payload=b"queued-first").job_id
        first_lease = _running(service, rt, clock)
        second_id = enqueue_job(service, store, owner_id="dan", payload=b"queued-second").job_id
        second_lease = _running(service, rt, clock)

        first_item = _make_item(service, first_lease, deadline_ns=50)
        second_item = _make_item(service, second_lease, deadline_ns=20)

        executor.submit(first_item)
        assert first_entered.wait(BOUND_WAIT_S), "first item did not enter handler"
        assert mono.now == 10
        executor.submit(second_item)
        second_submitted.set()

        expected_first_ref = ObjectRef(
            kind="fixture_result",
            id=first_id,
            revision=1,
            digest=digest_bytes(b"queued-first"),
        )
        cmd_first = _command(executor)
        cmd_second = _command(executor)
        assert cmd_first == WorkerCompleted(first_lease, (expected_first_ref,))
        assert cmd_second == WorkerFailed(second_lease, True, JobErrorCode.DEADLINE_EXCEEDED)
        assert entered == [(b"queued-first", 1, 10)], (
            f"queue-expired second item must not enter handler; entered={entered!r}"
        )

        service.apply_command(cmd_first)
        service.apply_command(cmd_second)
        assert _job_row(store, first_id).state is JobState.SUCCEEDED
        assert (_job_row(store, second_id).state, _job_row(store, second_id).attempt) == (JobState.QUEUED, 2)

        # (c) Post-handler deadline expiry + stale lease fence + R03 retry cancel-event preservation.
        mono.now = 100
        post_id = enqueue_job(service, store, owner_id="dan", payload=b"post-handler-slow").job_id
        post_lease = _running(service, rt, clock)
        executor.submit(_make_item(service, post_lease, deadline_ns=150))
        cmd_post = _command(executor)
        assert cmd_post == WorkerFailed(post_lease, True, JobErrorCode.DEADLINE_EXCEEDED)
        assert entered[-1] == (b"post-handler-slow", 1, 100)
        service.apply_command(cmd_post)
        assert (_job_row(store, post_id).state, _job_row(store, post_id).attempt) == (JobState.QUEUED, 2)

        # Stale lease fence: pre-expired item for an already-cancelled job still conflicts on owner apply.
        stale_id = enqueue_job(service, store, owner_id="dan", payload=b"stale-cancelled").job_id
        stale_lease = _running(service, rt, clock)
        stale_item = _make_item(service, stale_lease, deadline_ns=mono.now)
        assert service.cancel(stale_id, dan, selected_scope=None) is JobState.CANCELLED
        executor.submit(stale_item)
        cmd_stale = _command(executor)
        assert cmd_stale == WorkerFailed(stale_lease, True, JobErrorCode.DEADLINE_EXCEEDED)
        assert all(payload != b"stale-cancelled" for payload, _, _ in entered)
        _expect(ErrorCode.REVISION_CONFLICT, lambda: service.apply_command(cmd_stale))
        assert _job_row(store, stale_id).state is JobState.CANCELLED

        # R03 preservation: retry attempt 2 of queue-expired second_id receives a working cooperative cancel event.
        clock.advance(dt.timedelta(seconds=1))
        second_lease_2 = service.lease_next(rt.lease.epoch, clock.now())
        while second_lease_2 is not None and second_lease_2.job_id != second_id:
            second_lease_2 = service.lease_next(rt.lease.epoch, clock.now())
        assert second_lease_2 is not None and (second_lease_2.job_id, second_lease_2.attempt) == (second_id, 2)
        service.start(second_lease_2)
        executor.submit(_make_item(service, second_lease_2, deadline_ns=mono.now + 1_000))
        assert retry_entered.wait(BOUND_WAIT_S), "attempt 2 of queue-expired job did not enter handler"
        assert service.cancel(second_id, dan, selected_scope=None) is JobState.CANCELLED
        cmd_retry_done = _command(executor)
        assert cmd_retry_done == WorkerCompleted(second_lease_2)
        assert retry_cancelled.is_set(), "retry attempt after pre-handler expiry lost its cooperative cancel signal"
        _expect(ErrorCode.REVISION_CONFLICT, lambda: service.apply_command(cmd_retry_done))
    finally:
        second_submitted.set()
        first_entered.set()
        retry_entered.set()
        executor.close(BOUND_WAIT_S)
        if sys.exc_info()[0] is None:
            assert worker_threads and all(not thread.is_alive() for thread in worker_threads)


def test_worker_submit_after_close_refuses_without_enqueue(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """OBS-T5-W02: submit() synchronized with close() refuses with DAEMON_UNAVAILABLE; slow work recovers durably."""
    # (a) Direct submit() after clean close() raises DAEMON_UNAVAILABLE without invoking handler or queuing work.
    rt_direct = open_kernel_job_runtime(trusted_tmp / "w02-direct", os_)
    direct_entered: list[str] = []
    def direct_handler(spec: JobSpec, ctx: JobContext) -> tuple[ObjectRef, ...]:
        direct_entered.append(ctx.lease.job_id)
        return ()

    executor_direct = JobExecutor({FIXTURE_JOB_KIND: direct_handler}, _Mono(initial_ns=100))
    executor_direct.start()
    try:
        service_direct, store_direct = kernel_job_service(rt_direct, clock)
        enqueue_job(service_direct, store_direct, owner_id="dan", payload=b"after-close")
        direct_lease = _running(service_direct, rt_direct, clock)
        after_close_item = _make_item(service_direct, direct_lease, deadline_ns=1_000)

        unreg_spec = JobSpec(kind="unregistered.kind", owner_id="dan", payload=b"after-close-unreg")
        store_direct.stage_blob(unreg_spec.payload)
        store_direct.transact(lambda tx: service_direct.enqueue(tx, unreg_spec))
        unreg_lease = _running(service_direct, rt_direct, clock)
        unreg_item = _make_item(service_direct, unreg_lease, deadline_ns=1_000)

        executor_direct.close(BOUND_WAIT_S)
        err = _expect(ErrorCode.DAEMON_UNAVAILABLE, lambda: executor_direct.submit(after_close_item))
        assert is_safe_wire_message(err.message)
        err_unreg = _expect(ErrorCode.DAEMON_UNAVAILABLE, lambda: executor_direct.submit(unreg_item))
        assert is_safe_wire_message(err_unreg.message)
        assert direct_entered == []
        assert executor_direct.next_command(0.01) is None
        assert cast(_ExecutorWithItems, executor_direct)._items.empty()
    finally:
        executor_direct.close(BOUND_WAIT_S)
        rt_direct.close()

    # (b) Deterministic submit/close race with in-flight slow item + durable SQLite recovery across epoch + 1 (S1=A).
    recover_root = trusted_tmp / "w02-recover"
    rt1 = open_kernel_job_runtime(recover_root, os_)
    rt1_closed = False
    store_id = rt1.store.store_id
    epoch1 = rt1.lease.epoch
    dan = seed_principal_and_credential(rt1.policy, owner_id="dan").principal

    entered_event = threading.Event()
    cancelled_event = threading.Event()
    release_event = threading.Event()
    refused_entered = threading.Event()
    slow_threads: list[threading.Thread] = []
    closer_thread: threading.Thread | None = None

    def slow_handler(spec: JobSpec, ctx: JobContext) -> tuple[ObjectRef, ...]:
        slow_threads.append(threading.current_thread())
        if spec.payload == b"refused-during-close":
            refused_entered.set()
            return ()
        entered_event.set()
        if ctx.wait_cancelled(BOUND_WAIT_S) and ctx.cancelled():
            cancelled_event.set()
        assert release_event.wait(BOUND_WAIT_S), "timed out waiting for slow worker release"
        ctx.report_usage(ctx.invocation_ids[0], UsageRecord("0.15", complete=True))
        return (
            ObjectRef(
                kind="fixture_result",
                id=ctx.lease.job_id,
                revision=1,
                digest=digest_bytes(spec.payload),
            ),
        )

    executor_slow = JobExecutor({FIXTURE_JOB_KIND: slow_handler}, _Mono(initial_ns=100))
    executor_slow.start()
    try:
        service1, store1 = kernel_job_service(rt1, clock)
        slow_job_id = enqueue_job(service1, store1, owner_id="dan", payload=b"slow-durable").job_id
        slow_lease = _running(service1, rt1, clock)
        slow_inv_id = service1.reserve_invocation(slow_lease, RESERVE)
        slow_item = _make_item(service1, slow_lease, deadline_ns=1_000, invocation_ids=(slow_inv_id,))

        refused_job_id = enqueue_job(service1, store1, owner_id="dan", payload=b"refused-during-close").job_id
        refused_lease = _running(service1, rt1, clock)
        refused_item = _make_item(service1, refused_lease, deadline_ns=1_000)

        executor_slow.submit(slow_item)
        assert entered_event.wait(BOUND_WAIT_S), "slow worker did not enter handler"

        closer_thread = threading.Thread(target=executor_slow.close, args=(0.05,))
        closer_thread.start()
        assert cancelled_event.wait(BOUND_WAIT_S), "close() did not signal cooperative cancel on active item"

        # Submit while close() is active and slow item is still running -> immediately refused without enqueue.
        err_during = _expect(ErrorCode.DAEMON_UNAVAILABLE, lambda: executor_slow.submit(refused_item))
        assert is_safe_wire_message(err_during.message)

        closer_thread.join(BOUND_WAIT_S)
        assert not closer_thread.is_alive()
        assert slow_threads and slow_threads[0].is_alive()

        # Submit after close(timeout=0.05) timed out while slow item still holds worker thread -> still refused.
        _expect(ErrorCode.DAEMON_UNAVAILABLE, lambda: executor_slow.submit(refused_item))
        assert not refused_entered.is_set()

        # Runtime closes/fences before slow worker reports back; job and invocation stay durable in SQLite.
        assert _job_row(store1, slow_job_id).state is JobState.RUNNING
        assert _invocation_row(store1, slow_inv_id).state is InvocationState.RESERVED
        rt1.close()
        rt1_closed = True

        # Release slow worker cleanly before reopening and confirm refused_item never ran or queued.
        release_event.set()
        executor_slow.close(BOUND_WAIT_S)
        assert not slow_threads[0].is_alive()
        late_usage_cmd = _command(executor_slow)
        assert late_usage_cmd == WorkerUsage(slow_inv_id, UsageRecord("0.15", complete=True))
        assert executor_slow.next_command(0.01) is None
        assert not refused_entered.is_set()
        assert cast(_ExecutorWithItems, executor_slow)._items.empty()

        # Reopen in epoch + 1: recover() marks unsettled invocation OUTCOME_UNKNOWN and requeues job to attempt=2.
        clock.advance(dt.timedelta(seconds=5))
        rt2 = reopen_kernel_job_runtime(recover_root, store_id, os_)
        try:
            assert rt2.lease.epoch == epoch1 + 1
            service2, store2 = kernel_job_service(rt2, clock)
            assert _job_row(store2, slow_job_id).state is JobState.RUNNING
            assert _invocation_row(store2, slow_inv_id).state is InvocationState.RESERVED

            counts = service2.recover(rt2.lease.epoch)
            assert counts == RecoveryCounts(invocations_unknown=1, jobs_requeued=2, jobs_dead_lettered=0)
            assert _invocation_row(store2, slow_inv_id).state is InvocationState.OUTCOME_UNKNOWN
            assert (_job_row(store2, slow_job_id).state, _job_row(store2, slow_job_id).attempt) == (
                JobState.QUEUED,
                2,
            )
            assert (_job_row(store2, refused_job_id).state, _job_row(store2, refused_job_id).attempt) == (
                JobState.QUEUED,
                2,
            )

            view_before_usage = service2.get_job(slow_job_id, dan, selected_scope=None)
            assert (view_before_usage.state, view_before_usage.attempt, view_before_usage.accounting_status) == (
                JobState.QUEUED,
                2,
                AccountingStatus.OUTCOME_UNKNOWN,
            )

            # Stale completion from epoch1 is fenced; valid late usage ("0.15", complete=True) settles once per S1=A.
            _expect(ErrorCode.REVISION_CONFLICT, lambda: service2.apply_command(WorkerCompleted(slow_lease)))
            service2.apply_command(late_usage_cmd)
            service2.apply_command(late_usage_cmd)  # identical retry: no-op
            _expect(
                ErrorCode.IDEMPOTENCY_CONFLICT,
                lambda: service2.settle_usage(slow_inv_id, UsageRecord("0.25", complete=True)),
            )

            view_after_usage = service2.get_job(slow_job_id, dan, selected_scope=None)
            assert (
                view_after_usage.state,
                view_after_usage.attempt,
                view_after_usage.result_refs,
                view_after_usage.accounting_status,
            ) == (
                JobState.QUEUED,
                2,
                (),
                AccountingStatus.SETTLED,
            )
        finally:
            rt2.close()
    finally:
        release_event.set()
        entered_event.set()
        if closer_thread is not None:
            closer_thread.join(BOUND_WAIT_S)
        executor_slow.close(BOUND_WAIT_S)
        if not rt1_closed:
            rt1.close()
        if sys.exc_info()[0] is None:
            assert slow_threads and all(not thread.is_alive() for thread in slow_threads)

    # (c) Lock-atomicity check: submit() holds the same lock across closed-check and _items.put() as close()/sentinel.
    rt_race = open_kernel_job_runtime(trusted_tmp / "w02-lock-race", os_)
    submit_reached_put = threading.Event()
    sentinel_reached_put = threading.Event()
    race_threads: list[threading.Thread] = []

    def race_handler(spec: JobSpec, ctx: JobContext) -> tuple[ObjectRef, ...]:
        race_threads.append(threading.current_thread())
        return ()

    executor_race = JobExecutor({FIXTURE_JOB_KIND: race_handler}, _Mono(initial_ns=100))
    item_queue = cast(_ExecutorWithItems, executor_race)._items
    real_put = item_queue.put
    racing_item_box: list[WorkItem] = []

    def intercept_item_put(val: WorkItem | None, *args: Any, **kwargs: Any) -> None:
        if racing_item_box and val is racing_item_box[0]:
            submit_reached_put.set()
            # If close() is NOT serialized behind the same lock held by submit(), close() will enter put(None) here.
            sentinel_reached_put.wait(0.05)
        elif val is None:
            sentinel_reached_put.set()
        real_put(val, *args, **kwargs)

    monkeypatch.setattr(item_queue, "put", intercept_item_put)
    executor_race.start()
    submit_worker: threading.Thread | None = None
    close_worker: threading.Thread | None = None
    try:
        service_race, store_race = kernel_job_service(rt_race, clock)
        enqueue_job(service_race, store_race, owner_id="dan", payload=b"lock-serialized")
        race_lease = _running(service_race, rt_race, clock)
        racing_item = _make_item(service_race, race_lease, deadline_ns=1_000)
        racing_item_box.append(racing_item)

        submit_errors: list[BaseException] = []

        def run_submit() -> None:
            try:
                executor_race.submit(racing_item)
            except BaseException as exc:  # noqa: BLE001
                submit_errors.append(exc)

        submit_worker = threading.Thread(target=run_submit)
        submit_worker.start()
        assert submit_reached_put.wait(BOUND_WAIT_S), "submit() did not reach _items.put"

        close_worker = threading.Thread(target=executor_race.close, args=(BOUND_WAIT_S,))
        close_worker.start()

        submit_worker.join(BOUND_WAIT_S)
        close_worker.join(BOUND_WAIT_S)
        assert not submit_worker.is_alive() and not close_worker.is_alive()
        assert submit_errors == []
        assert item_queue.empty(), "accepted item was stranded behind close sentinel in _items"
        assert not getattr(executor_race, "_cancel_events", {})
        assert executor_race.next_command(0.05) in (None, WorkerCompleted(race_lease))
        assert all(not thread.is_alive() for thread in race_threads)
    finally:
        sentinel_reached_put.set()
        submit_reached_put.set()
        if submit_worker is not None:
            submit_worker.join(BOUND_WAIT_S)
        if close_worker is not None:
            close_worker.join(BOUND_WAIT_S)
        executor_race.close(BOUND_WAIT_S)
        rt_race.close()
        if sys.exc_info()[0] is None:
            assert all(not thread.is_alive() for thread in race_threads)


def test_worker_hardening_guards_clock_malformed_error_and_reports_unexpected_exit(
    trusted_tmp: Path,
    clock: FakeClock,
    os_: OsAdapters,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CL-T5-A2: Strict ``JobHandlerError`` validation, clock fault isolation, and ``SystemExit`` drain reporting."""

    def _synthetic_item(payload: bytes, *, deadline_ns: int = 1_000) -> tuple[JobLease, WorkItem]:
        lease = JobLease(job_id=new_id(), attempt=1, writer_epoch=1, lease_id=new_id())
        spec = JobSpec(kind=FIXTURE_JOB_KIND, owner_id="dan", payload=payload)
        return lease, WorkItem(lease=lease, spec=spec, invocation_ids=(), deadline_ns=deadline_ns)

    # (a) JobHandlerError strict validation + worker survival on malformed error raised inside handler.
    _expect(ErrorCode.INVALID_INPUT, lambda: JobHandlerError(JobErrorCode.HANDLER_FAILED, retryable=cast(Any, "bad")))
    _expect(ErrorCode.INVALID_INPUT, lambda: JobHandlerError(JobErrorCode.HANDLER_FAILED, retryable=cast(Any, 1)))
    _expect(ErrorCode.INVALID_INPUT, lambda: JobHandlerError(cast(Any, "handler_failed"), retryable=False))

    lease_a1, item_a1 = _synthetic_item(b"a2-malformed-err")
    lease_a2, item_a2 = _synthetic_item(b"a2-after-malformed")

    entered_a: list[str] = []

    def _handler_a(spec: JobSpec, ctx: JobContext) -> tuple[ObjectRef, ...]:
        entered_a.append(ctx.lease.job_id)
        if spec.payload == b"a2-malformed-err":
            raise JobHandlerError(JobErrorCode.HANDLER_FAILED, retryable=cast(Any, "bad"))
        return ()

    executor_a = JobExecutor({FIXTURE_JOB_KIND: _handler_a}, _Mono(initial_ns=100))
    executor_a.start()
    try:
        executor_a.submit(item_a1)
        executor_a.submit(item_a2)
        assert _command(executor_a) == WorkerFailed(lease_a1, False, JobErrorCode.HANDLER_FAILED)
        assert _command(executor_a) == WorkerCompleted(lease_a2)
        assert entered_a == [lease_a1.job_id, lease_a2.job_id]
        assert executor_a.close(BOUND_WAIT_S) is True
        assert executor_a.is_drained is True
    finally:
        executor_a.close(BOUND_WAIT_S)

    # (b1) Monotonic clock RuntimeError BEFORE handler entry (clock_pre).
    lease_pre_1, item_pre_1 = _synthetic_item(b"a2-clock-pre-1")
    lease_pre_2, item_pre_2 = _synthetic_item(b"a2-clock-pre-2")

    pre_calls = 0
    pre_entered: list[str] = []

    def _clock_pre_fault() -> int:
        nonlocal pre_calls
        pre_calls += 1
        if pre_calls == 1:
            raise RuntimeError("monotonic clock pre-handler failure")
        return 100

    def _handler_pre(_spec: JobSpec, ctx: JobContext) -> tuple[ObjectRef, ...]:
        pre_entered.append(ctx.lease.job_id)
        return ()

    executor_pre = JobExecutor({FIXTURE_JOB_KIND: _handler_pre}, _clock_pre_fault)
    executor_pre.start()
    try:
        executor_pre.submit(item_pre_1)
        executor_pre.submit(item_pre_2)
        assert _command(executor_pre) == WorkerFailed(lease_pre_1, False, JobErrorCode.HANDLER_FAILED)
        assert _command(executor_pre) == WorkerCompleted(lease_pre_2)
        assert pre_entered == [lease_pre_2.job_id]
        assert executor_pre.close(BOUND_WAIT_S) is True
        assert executor_pre.is_drained is True
    finally:
        executor_pre.close(BOUND_WAIT_S)

    # (b2) Monotonic clock RuntimeError AFTER handler return (clock_post).
    lease_post_1, item_post_1 = _synthetic_item(b"a2-clock-post-1")
    lease_post_2, item_post_2 = _synthetic_item(b"a2-clock-post-2")

    post_calls = 0
    post_entered: list[str] = []

    def _clock_post_fault() -> int:
        nonlocal post_calls
        post_calls += 1
        if post_calls == 2:
            raise RuntimeError("monotonic clock post-handler failure")
        return 100

    def _handler_post(_spec: JobSpec, ctx: JobContext) -> tuple[ObjectRef, ...]:
        post_entered.append(ctx.lease.job_id)
        return ()

    executor_post = JobExecutor({FIXTURE_JOB_KIND: _handler_post}, _clock_post_fault)
    executor_post.start()
    try:
        executor_post.submit(item_post_1)
        executor_post.submit(item_post_2)
        assert _command(executor_post) == WorkerFailed(lease_post_1, False, JobErrorCode.HANDLER_FAILED)
        assert _command(executor_post) == WorkerCompleted(lease_post_2)
        assert post_entered == [lease_post_1.job_id, lease_post_2.job_id]
        assert executor_post.close(BOUND_WAIT_S) is True
        assert executor_post.is_drained is True
    finally:
        executor_post.close(BOUND_WAIT_S)

    # (c) SystemExit inside handler is NOT swallowed into WorkerCompleted and reports worker_drained=False.
    hook_types: list[type[BaseException]] = []
    monkeypatch.setattr(threading, "excepthook", lambda args: hook_types.append(args.exc_type))

    _, item_sys = _synthetic_item(b"a2-sysexit-unit")

    sysexit_entered = threading.Event()
    sysexit_threads: list[threading.Thread] = []

    def _handler_sysexit(_spec: JobSpec, _ctx: JobContext) -> tuple[ObjectRef, ...]:
        sysexit_threads.append(threading.current_thread())
        sysexit_entered.set()
        raise SystemExit(1)

    executor_sys = JobExecutor({FIXTURE_JOB_KIND: _handler_sysexit}, _Mono(initial_ns=100))
    executor_sys.start()
    try:
        executor_sys.submit(item_sys)
        assert sysexit_entered.wait(BOUND_WAIT_S)
        sysexit_threads[0].join(BOUND_WAIT_S)
        assert not sysexit_threads[0].is_alive()
        assert hook_types == [SystemExit]
        assert executor_sys.next_command(0.02) is None
        assert executor_sys.is_drained is False
        assert executor_sys.close(BOUND_WAIT_S) is False
        assert executor_sys.is_drained is False
    finally:
        executor_sys.close(BOUND_WAIT_S)

    # Real create_daemon_owner_loop check: handler raising SystemExit(1) -> ShutdownReport.worker_drained is False.
    daemon_base = trusted_tmp / "a2-daemon-sysexit"
    daemon_base.mkdir(parents=True, exist_ok=True)
    if sys.platform != "win32":
        os.chmod(daemon_base, 0o700)
    daemon_root = daemon_base / "data"
    rt_d = open_kernel_job_runtime(daemon_root, os_)
    store_id_d = rt_d.store.store_id
    try:
        seed_principal_and_credential(rt_d.policy, owner_id="dan")
        rt_d.store.reconcile_policy()
        svc_d, st_d = kernel_job_service(rt_d, clock)
        enqueue_job(svc_d, st_d, owner_id="dan", payload=b"a2-sysexit-daemon")
    finally:
        rt_d.close()

    tls_dir = daemon_base / "tls"
    tls_auth = make_bootstrap_auth(
        store_id=store_id_d,
        owner_id="dan",
        action="provision_tls",
        subject_id=store_id_d,
        trust_generation=1,
        expires_at=clock.now() + dt.timedelta(hours=1),
        destination=tls_dir,
    )
    tls_d = create_store_tls(store_id_d, tls_dir, tls_auth, clock, os_)
    cfg_path = daemon_base / "daemon-config.json"
    os_.publisher.write_new(
        cfg_path,
        canonical_json(
            {
                "version": 1,
                "data_root": str(daemon_root),
                "expected_store_id": store_id_d,
                "cert_path": str(tls_d.cert_path),
                "key_path": str(tls_d.key_path),
            }
        ),
    )
    os_.permissions.secure_file(cfg_path)
    cfg_d = read_daemon_config(cfg_path, os_)

    daemon_exit_entered = threading.Event()
    daemon_worker_threads: list[threading.Thread] = []

    def _daemon_sysexit_handler(_spec: JobSpec, _ctx: JobContext) -> tuple[ObjectRef, ...]:
        daemon_worker_threads.append(threading.current_thread())
        daemon_exit_entered.set()
        raise SystemExit(1)

    loop_d = create_daemon_owner_loop(
        os_=os_,
        clock=clock,
        job_handlers={FIXTURE_JOB_KIND: _daemon_sysexit_handler},
    )
    try:
        loop_d.start(cfg_d)
        assert daemon_exit_entered.wait(BOUND_WAIT_S)
        daemon_worker_threads[0].join(BOUND_WAIT_S)
        assert not daemon_worker_threads[0].is_alive()
        rep_d = loop_d.stop(grace_s=1.0)
        assert rep_d.worker_drained is False
    finally:
        with contextlib.suppress(BrainError):
            loop_d.stop()

