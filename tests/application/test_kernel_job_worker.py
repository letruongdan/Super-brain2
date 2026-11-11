"""Task 5: get_job/cancel ACL, cooperative cancellation and the single-thread worker executor over a real store.

The worker holds no DB handle: it receives an immutable ``JobSpec`` and reports typed commands that the owner side
(this test thread) applies through ``JobService``. The production registry is empty; the fixture handler is
registered only from ``tests/support/inc2_fixture.py``.
"""

from __future__ import annotations

import ast
import dataclasses
import datetime as dt
import json
import threading
from collections.abc import Callable, Iterator
from functools import partial
from pathlib import Path

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.workspaces import build_registration
from superbrain.application.jobs import JobService
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import (
    AccountingStatus,
    InvocationState,
    JobErrorCode,
    JobLease,
    JobRecord,
    JobSpec,
    JobState,
    ObjectRef,
    Principal,
    Scope,
    UsageRecord,
    UsageReservation,
    WorkerCommand,
    WorkerCompleted,
    WorkerFailed,
    WorkerUsage,
    accounting_status_of,
)
from superbrain.ports.os import OsAdapters
from superbrain.storage.idempotency import StagedKernelStore
from superbrain.storage.runtime import Runtime
from superbrain.workers import executor as executor_mod
from superbrain.workers.executor import PRODUCTION_JOB_HANDLERS, JobContext, JobExecutor, JobHandlerError, WorkItem
from tests.support.clock import FakeClock
from tests.support.inc2_fixture import (
    FIXTURE_JOB_KIND,
    FIXTURE_USAGE,
    enqueue_job,
    fixture_job_handler,
    fixture_job_registry,
    kernel_job_service,
    open_kernel_job_runtime,
    reopen_kernel_job_runtime,
    validate_response_envelope,
)
from tests.support.kernel_auth import make_bootstrap_auth, seed_principal_and_credential, seed_repo_grant

SRC = Path(__file__).resolve().parents[2] / "src" / "superbrain"
RESERVE = UsageReservation(max_amount="2")
WAIT_S = 10.0


class Mono:
    """Fake monotonic nanosecond clock shared by the owner and worker threads."""

    def __init__(self) -> None:
        self.now = 1_000_000_000

    def __call__(self) -> int:
        return self.now


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock(dt.datetime(2026, 11, 8, 9, 0, tzinfo=dt.UTC))


@pytest.fixture
def os_(clock: FakeClock) -> OsAdapters:
    return os_adapters(clock=clock)


@pytest.fixture
def rt(trusted_tmp: Path, os_: OsAdapters) -> Iterator[Runtime]:
    runtime = open_kernel_job_runtime(trusted_tmp / "wroot", os_)
    try:
        yield runtime
    finally:
        runtime.close()


@pytest.fixture
def executor_factory() -> Iterator[Callable[..., JobExecutor]]:
    started: list[JobExecutor] = []

    def make(handlers: object, mono: Mono | None = None) -> JobExecutor:
        executor = JobExecutor(handlers, mono or Mono())  # type: ignore[arg-type]
        executor.start()
        started.append(executor)
        return executor

    yield make
    for executor in started:
        executor.close(WAIT_S)


def _expect(code: ErrorCode, action: Callable[[], object]) -> BrainError:
    with pytest.raises(BrainError) as caught:
        action()
    assert caught.value.code is code, f"expected {code}, got {caught.value.code}"
    return caught.value


def _command(executor: JobExecutor) -> WorkerCommand:
    command = executor.next_command(WAIT_S)
    assert command is not None, "the worker reported nothing"
    return command


def _row(store: StagedKernelStore, job_id: str) -> JobRecord:
    row = store.transact(lambda tx: tx.read_job(job_id))
    assert row is not None, "job row is missing"
    return row


def _state(store: StagedKernelStore, job_id: str) -> JobState:
    return _row(store, job_id).state


def _running(service: JobService, rt: Runtime, clock: FakeClock) -> JobLease:
    lease = service.lease_next(rt.lease.epoch, clock.now())
    assert lease is not None, "no due job was leased"
    service.start(lease)
    return lease


def _item(
    service: JobService, lease: JobLease, invocation_ids: tuple[str, ...] = (), timeout_ns: int = 10**9
) -> WorkItem:
    return WorkItem(
        lease=lease, spec=service.job_spec(lease), invocation_ids=invocation_ids, deadline_ns=10**9 + timeout_ns
    )


def test_late_worker_cannot_advance_recovered_job_but_can_settle_recorded_invocation(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock, executor_factory: Callable[..., JobExecutor]
) -> None:
    root = trusted_tmp / "late-worker"
    first = open_kernel_job_runtime(root, os_)
    reservation, final_usage = UsageReservation("7.5"), UsageRecord("1.25", True)
    missing_id = "00000000-0000-4000-8000-000000000008"
    try:
        first_service, first_store = kernel_job_service(first, clock)
        job = enqueue_job(first_service, first_store, owner_id="dan")
        old = _running(first_service, first, clock)
        invocation_id = first_service.reserve_invocation(old, reservation)
        old_work = _item(first_service, old, (invocation_id,))
        assert old.job_id == job.job_id and old.attempt == 1
        original = first_store.transact(lambda tx: tx.read_invocation(invocation_id))
        assert original is not None and original.state is InvocationState.RESERVED
        assert (original.job_id, original.attempt, original.writer_epoch, original.lease_id) == (
            job.job_id, old.attempt, old.writer_epoch, old.lease_id,
        )
        prefix = tuple(first.store.entries())
        store_id = first.store.store_id
    finally:
        first.close()

    denied: list[ErrorCode] = []

    def old_handler(_spec: JobSpec, ctx: JobContext) -> tuple[ObjectRef, ...]:
        try:
            ctx.report_usage(missing_id, final_usage)
        except BrainError as err:
            denied.append(err.code)
        ctx.report_usage(invocation_id, final_usage)
        return ()

    second = reopen_kernel_job_runtime(root, store_id, os_)
    try:
        service, store = kernel_job_service(second, clock)
        service.recover(second.lease.epoch)
        assert _row(store, job.job_id).state is JobState.QUEUED and _row(store, job.job_id).attempt == 2
        unknown = store.transact(lambda tx: tx.read_invocation(invocation_id))
        assert unknown == dataclasses.replace(original, state=InvocationState.OUTCOME_UNKNOWN)
        entries = tuple(second.store.entries())
        assert entries[:len(prefix)] == prefix
        assert [e.kind for e in entries[len(prefix):]] == ["provider.unknown", "job.retry"]
        fresh = _running(service, second, clock)
        assert fresh.job_id == old.job_id and fresh.attempt == 2
        assert fresh.writer_epoch > old.writer_epoch and fresh.lease_id != old.lease_id
        running = _row(store, job.job_id)

        worker = executor_factory({FIXTURE_JOB_KIND: old_handler})
        worker.submit(old_work)
        usage, completed = _command(worker), _command(worker)
        assert denied == [ErrorCode.INVALID_INPUT]
        assert usage == WorkerUsage(invocation_id, final_usage) and completed == WorkerCompleted(old)
        before_stale = tuple(second.store.entries())
        _expect(ErrorCode.REVISION_CONFLICT, lambda: service.apply_command(completed))
        _expect(
            ErrorCode.REVISION_CONFLICT,
            lambda: service.apply_command(WorkerFailed(old, retryable=True, code=JobErrorCode.HANDLER_FAILED)),
        )
        _expect(ErrorCode.NOT_FOUND, lambda: service.apply_command(WorkerUsage(missing_id, final_usage)))
        assert _row(store, job.job_id) == running and tuple(second.store.entries()) == before_stale

        service.apply_command(WorkerUsage(invocation_id, UsageRecord(None, False)))
        partial = store.transact(lambda tx: tx.read_invocation(invocation_id))
        assert partial is not None
        assert (partial.state, partial.usage_complete) == (InvocationState.OUTCOME_UNKNOWN, False)
        service.apply_command(usage)
        recorded = store.transact(lambda tx: tx.read_invocation(invocation_id))
        assert recorded is not None and recorded.state is InvocationState.SETTLED
        assert recorded == dataclasses.replace(
            original, state=InvocationState.SETTLED, usage_digest=recorded.usage_digest, usage_complete=True,
        )
        final_digest = recorded.usage_digest
        assert final_digest is not None
        raw = store.transact(lambda tx: tx.read_held_blob(final_digest, holder_id=invocation_id))
        max_raw = store.transact(lambda tx: tx.read_held_blob(original.reservation_digest, holder_id=invocation_id))
        assert raw is not None and max_raw is not None
        assert json.loads(raw) == {
            "schema": "provider-usage-v1", "invocation_id": invocation_id, "amount": "1.25", "complete": True,
        }
        assert json.loads(max_raw) == {
            "schema": "provider-reservation-v1", "invocation_id": invocation_id, "job_id": job.job_id,
            "max_amount": "7.5",
        }
        after_usage = tuple(second.store.entries())
        assert [e.meta["complete"] for e in after_usage[len(before_stale):] if e.kind == "provider.settled"] == [
            False, True,
        ]
        service.apply_command(usage)  # the old invocation may be accounted for exactly once
        assert tuple(second.store.entries()) == after_usage and _row(store, job.job_id) == running
        service.apply_command(WorkerCompleted(fresh))
        terminal = _row(store, job.job_id)
        assert terminal.state is JobState.SUCCEEDED and terminal.attempt == 2
        ledger = tuple(second.store.entries())
    finally:
        second.close()

    third = reopen_kernel_job_runtime(root, store_id, os_)
    try:
        service, store = kernel_job_service(third, clock)
        service.recover(third.lease.epoch)
        assert tuple(third.store.entries()) == ledger
        assert _row(store, job.job_id) == terminal
        assert store.transact(lambda tx: tx.read_invocation(invocation_id)) == recorded
        third.store.rebuild_projections()
        assert tuple(third.store.entries()) == ledger
        assert _row(store, job.job_id) == terminal
        assert store.transact(lambda tx: tx.read_invocation(invocation_id)) == recorded
    finally:
        third.close()


# --- get_job / cancel ACL ---------------------------------------------------------------------------------------------


class _ClosedPolicy:
    """A policy whose authority is unavailable (closed or corrupt)."""

    def allows(self, principal: Principal, scope: Scope | None, *, action: str) -> bool:
        raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable")


def test_get_job_and_cancel_acl_never_leak_existence(rt: Runtime, clock: FakeClock, trusted_tmp: Path) -> None:
    dan_cred = seed_principal_and_credential(rt.policy, owner_id="dan", harness_id="claude-code", machine_id="box-1")
    dan = dan_cred.principal
    ungranted = seed_principal_and_credential(
        rt.policy, owner_id="dan", harness_id="codex", machine_id="box-1"
    ).principal
    eve = seed_principal_and_credential(
        rt.policy, owner_id="eve", harness_id="claude-code", machine_id="box-9"
    ).principal
    ghost = Principal(principal_id="ghost-1", owner_id="dan", harness_id="claude-code", machine_id="box-1")
    seed_repo_grant(rt.policy, principal_id=dan.principal_id, repo_id="repo-a", owner_id="dan")
    seed_repo_grant(rt.policy, principal_id=dan.principal_id, repo_id="repo-b", owner_id="dan")
    checkout_dir = trusted_tmp / "checkout-c"
    checkout_dir.mkdir()
    reg = build_registration(
        owner_id="dan",
        principal_id=dan.principal_id,
        machine_id="box-1",
        alias="wc",
        raw_path=str(checkout_dir),
        raw_remote="https://github.example/dan/repo-c.git",
        provider_egress_enabled=False,
    )
    binding = rt.policy.register_authorized_workspace(
        reg,
        make_bootstrap_auth(
            store_id=rt.policy.store_id,
            action="workspace_register",
            subject_id=reg.subject_id,
            trust_generation=rt.policy.trust_generation(),
            expires_at=clock.now() + dt.timedelta(hours=1),
        ),
    )
    rt.store.reconcile_policy()
    service, store = kernel_job_service(rt, clock)
    canary = b"payload-canary-41c9"
    global_job = enqueue_job(service, store, owner_id="dan", payload=canary).job_id
    repo_job = enqueue_job(service, store, owner_id="dan", payload=b"repo", repo_id="repo-a").job_id
    checkout_job = enqueue_job(
        service, store, owner_id="dan", payload=b"chk", repo_id=binding.repo_id, checkout_id=binding.checkout_id
    ).job_id
    eve_job = enqueue_job(service, store, owner_id="eve", payload=b"eve").job_id
    missing = "018f0000-0000-7000-8000-000000000000"
    repo_a, repo_b = Scope("repo-a"), Scope("repo-b")
    own_checkout = Scope(binding.repo_id, binding.checkout_id)
    other_checkout = Scope(binding.repo_id, "checkout-other")

    allowed = [
        ("global job, global scope", global_job, dan, None),
        ("global job, any selected scope", global_job, dan, repo_a),
        ("global job, same owner without repo grant", global_job, ungranted, None),
        ("repo job, matching repo", repo_job, dan, repo_a),
        ("checkout job, matching checkout", checkout_job, dan, own_checkout),
    ]
    for name, job_id, principal, scope in allowed:
        view = service.get_job(job_id, principal, selected_scope=scope)
        assert (view.job_id, view.state, view.attempt) == (job_id, JobState.QUEUED, 1), name
        assert view.accounting_status is AccountingStatus.NONE and view.result_refs == (), name
        envelope = validate_response_envelope("get_job", {"ok": True, "data": view.to_dict()})
        assert canary.decode() not in repr(envelope) and canary.decode() not in repr(view), name

    denied = [
        ("missing job", missing, dan, None),
        ("other owner's job", eve_job, dan, None),
        ("global job, other owner", global_job, eve, None),
        ("global job, unknown principal", global_job, ghost, None),
        ("repo job, no selected scope", repo_job, dan, None),
        ("repo job, other repo", repo_job, dan, repo_b),
        ("repo job, principal without grant", repo_job, ungranted, repo_a),
        ("checkout job, other checkout", checkout_job, dan, other_checkout),
        ("checkout job, repo-only scope", checkout_job, dan, Scope(binding.repo_id)),
    ]
    for name, job_id, principal, scope in denied:
        for action in ("get_job", "cancel"):
            with pytest.raises(BrainError) as caught:
                if action == "get_job":
                    service.get_job(job_id, principal, selected_scope=scope)
                else:
                    service.cancel(job_id, principal, selected_scope=scope)
            assert (caught.value.code, caught.value.message) == (ErrorCode.NOT_FOUND, "not found"), (name, action)
    for job_id in (global_job, repo_job, checkout_job, eve_job):
        assert _state(store, job_id) is JobState.QUEUED

    closed = JobService(store, store, _ClosedPolicy(), clock, writer_epoch=rt.lease.epoch)  # type: ignore[arg-type]
    for job_id in (missing, global_job):
        _expect(ErrorCode.POLICY_UNAVAILABLE, partial(closed.get_job, job_id, dan, selected_scope=None))
        _expect(ErrorCode.POLICY_UNAVAILABLE, partial(closed.cancel, job_id, dan, selected_scope=None))

    assert service.cancel(repo_job, dan, selected_scope=repo_a) is JobState.CANCELLED
    assert service.get_job(repo_job, dan, selected_scope=repo_a).state is JobState.CANCELLED
    _expect(ErrorCode.REVISION_CONFLICT, lambda: service.cancel(repo_job, dan, selected_scope=repo_a))


def test_accounting_status_aggregates_invocations_in_priority_order(rt: Runtime, clock: FakeClock) -> None:
    assert accounting_status_of([]) is AccountingStatus.NONE
    assert accounting_status_of([InvocationState.SETTLED]) is AccountingStatus.SETTLED
    assert accounting_status_of([InvocationState.SETTLED, InvocationState.RESERVED]) is AccountingStatus.RESERVED
    assert (
        accounting_status_of([InvocationState.RESERVED, InvocationState.OUTCOME_UNKNOWN, InvocationState.SETTLED])
        is AccountingStatus.OUTCOME_UNKNOWN
    )
    dan = seed_principal_and_credential(rt.policy, owner_id="dan").principal
    service, store = kernel_job_service(rt, clock)
    job_id = enqueue_job(service, store, owner_id="dan").job_id
    lease = _running(service, rt, clock)
    first = service.reserve_invocation(lease, RESERVE)
    assert service.get_job(job_id, dan, selected_scope=None).accounting_status is AccountingStatus.RESERVED
    service.settle_usage(first, UsageRecord("1", True))
    assert service.get_job(job_id, dan, selected_scope=None).accounting_status is AccountingStatus.SETTLED
    service.reserve_invocation(lease, RESERVE)
    assert service.get_job(job_id, dan, selected_scope=None).accounting_status is AccountingStatus.RESERVED


# --- worker executor --------------------------------------------------------------------------------------------------


def test_fixture_job_runs_on_the_worker_and_owner_applies_typed_commands(
    rt: Runtime, clock: FakeClock, executor_factory: Callable[..., JobExecutor]
) -> None:
    dan = seed_principal_and_credential(rt.policy, owner_id="dan").principal
    service, store = kernel_job_service(rt, clock)
    payload = b"fixture input"
    job_id = enqueue_job(service, store, owner_id="dan", payload=payload).job_id
    lease = _running(service, rt, clock)
    invocation_id = service.reserve_invocation(lease, RESERVE)  # durable before the hand-off below
    item = _item(service, lease, (invocation_id,))
    assert item.spec == JobSpec(kind=FIXTURE_JOB_KIND, owner_id="dan", payload=payload)
    with pytest.raises(dataclasses.FrozenInstanceError):
        item.spec.payload = b"mutated"  # type: ignore[misc]
    executor = executor_factory(fixture_job_registry())
    executor.submit(item)
    usage, done = _command(executor), _command(executor)
    assert usage == WorkerUsage(invocation_id, FIXTURE_USAGE)
    expected_ref = ObjectRef(kind="fixture_result", id=job_id, revision=1, digest=digest_bytes(payload))
    assert done == WorkerCompleted(lease, (expected_ref,))
    for command in (usage, done):
        service.apply_command(command)
    view = service.get_job(job_id, dan, selected_scope=None)
    assert (view.state, view.result_refs, view.accounting_status) == (
        JobState.SUCCEEDED,
        (expected_ref,),
        AccountingStatus.SETTLED,
    )


def test_production_registry_is_empty_and_client_kind_never_selects_the_fixture(
    rt: Runtime, clock: FakeClock, executor_factory: Callable[..., JobExecutor]
) -> None:
    assert dict(PRODUCTION_JOB_HANDLERS) == {}
    with pytest.raises(TypeError):
        PRODUCTION_JOB_HANDLERS[FIXTURE_JOB_KIND] = fixture_job_handler  # type: ignore[index]
    for path in SRC.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert FIXTURE_JOB_KIND not in text and "inc2_fixture" not in text, path
    calls: list[str] = []

    def spy(spec: JobSpec, ctx: JobContext) -> tuple[ObjectRef, ...]:
        calls.append(spec.kind)
        return ()

    service, store = kernel_job_service(rt, clock)
    enqueue_job(service, store, owner_id="dan", kind=FIXTURE_JOB_KIND)
    lease = _running(service, rt, clock)
    production = executor_factory(PRODUCTION_JOB_HANDLERS)
    production.submit(_item(service, lease))
    assert _command(production) == WorkerFailed(lease, False, JobErrorCode.HANDLER_UNAVAILABLE)
    other_kind = executor_factory({"other.kind": spy})
    other_kind.submit(_item(service, lease))
    assert _command(other_kind) == WorkerFailed(lease, False, JobErrorCode.HANDLER_UNAVAILABLE)
    assert calls == []
    service.apply_command(WorkerFailed(lease, False, JobErrorCode.HANDLER_UNAVAILABLE))
    row = store.transact(lambda tx: tx.read_job(lease.job_id))
    assert row is not None and (row.state, row.reason) == (JobState.FAILED, JobErrorCode.HANDLER_UNAVAILABLE)


def test_worker_imports_no_storage_and_runs_one_thread_serially(
    rt: Runtime, clock: FakeClock, executor_factory: Callable[..., JobExecutor]
) -> None:
    tree = ast.parse(Path(executor_mod.__file__).read_text(encoding="utf-8"))
    imported = {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)} | {
        alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names
    }
    project = {name for name in imported if name.startswith("superbrain")}
    assert project and all(name.startswith(("superbrain.core", "superbrain.application")) for name in project)
    assert "sqlite3" not in imported

    threads: list[int] = []
    active = [0, 0]  # current, peak
    lock = threading.Lock()

    def record(spec: JobSpec, ctx: JobContext) -> tuple[ObjectRef, ...]:
        with lock:
            active[0] += 1
            active[1] = max(active)
        threads.append(threading.get_ident())
        with lock:
            active[0] -= 1
        return ()

    service, store = kernel_job_service(rt, clock)
    executor = executor_factory({FIXTURE_JOB_KIND: record})
    leases = []
    for n in range(3):
        enqueue_job(service, store, owner_id="dan", payload=f"serial-{n}".encode())
        leases.append(_running(service, rt, clock))
        executor.submit(_item(service, leases[-1]))
    assert [_command(executor) for _ in leases] == [WorkerCompleted(lease) for lease in leases]
    assert len(set(threads)) == 1 and threads[0] != threading.get_ident() and active[1] == 1


def test_running_cancel_is_cooperative_old_callback_conflicts_and_late_usage_settles_once(
    rt: Runtime, clock: FakeClock, executor_factory: Callable[..., JobExecutor]
) -> None:
    dan = seed_principal_and_credential(rt.policy, owner_id="dan").principal
    started, observed = threading.Event(), threading.Event()
    late_usage = UsageRecord(amount=None, complete=False)

    def cooperative(spec: JobSpec, ctx: JobContext) -> tuple[ObjectRef, ...]:
        started.set()
        if ctx.wait_cancelled(WAIT_S):
            observed.set()
        ctx.report_usage(ctx.invocation_ids[0], late_usage)
        return ()

    executor = executor_factory({FIXTURE_JOB_KIND: cooperative})
    service, store = kernel_job_service(rt, clock)
    service = JobService(store, store, rt.policy, clock, writer_epoch=rt.lease.epoch, cancel_signal=executor.cancel)
    job_id = enqueue_job(service, store, owner_id="dan").job_id
    lease = _running(service, rt, clock)
    invocation_id = service.reserve_invocation(lease, RESERVE)
    executor.submit(_item(service, lease, (invocation_id,)))
    assert started.wait(WAIT_S)
    assert service.cancel(job_id, dan, selected_scope=None) is JobState.CANCELLED
    assert service.get_job(job_id, dan, selected_scope=None).state is JobState.CANCELLED  # immediately terminal
    usage, done = _command(executor), _command(executor)
    assert observed.is_set(), "the cancel signal never reached the worker"
    assert usage == WorkerUsage(invocation_id, late_usage) and done == WorkerCompleted(lease)
    service.apply_command(usage)  # late incomplete usage after cancel stays reconcilable outcome_unknown (S1=A)
    _expect(ErrorCode.REVISION_CONFLICT, lambda: service.apply_command(done))
    service.apply_command(usage)  # identical incomplete retry: no-op
    view = service.get_job(job_id, dan, selected_scope=None)
    assert (view.state, view.result_refs, view.accounting_status) == (
        JobState.CANCELLED,
        (),
        AccountingStatus.OUTCOME_UNKNOWN,
    )
    settled = [e for e in rt.store.entries() if e.kind == "provider.settled"]
    assert len(settled) == 1 and settled[0].meta["complete"] is False
    service.settle_usage(invocation_id, UsageRecord("3", True))  # first complete=True usage reconciles once
    service.settle_usage(invocation_id, UsageRecord("3", True))  # identical final retry: no-op
    _expect(ErrorCode.IDEMPOTENCY_CONFLICT, lambda: service.settle_usage(invocation_id, UsageRecord("4", True)))
    _expect(ErrorCode.IDEMPOTENCY_CONFLICT, lambda: service.settle_usage(invocation_id, UsageRecord(None, False)))
    reconciled = service.get_job(job_id, dan, selected_scope=None)
    assert (reconciled.state, reconciled.result_refs, reconciled.accounting_status) == (
        JobState.CANCELLED,
        (),
        AccountingStatus.SETTLED,
    )

    queued_id = enqueue_job(service, store, owner_id="dan").job_id
    assert service.cancel(queued_id, dan, selected_scope=None) is JobState.CANCELLED
    leased_id = enqueue_job(service, store, owner_id="dan").job_id
    leased = service.lease_next(rt.lease.epoch, clock.now())
    assert leased is not None and leased.job_id == leased_id
    assert service.cancel(leased_id, dan, selected_scope=None) is JobState.CANCELLED
    _expect(ErrorCode.REVISION_CONFLICT, lambda: service.start(leased))
    _expect(ErrorCode.REVISION_CONFLICT, lambda: service.job_spec(leased))  # a terminal job is never handed out
    assert service.lease_next(rt.lease.epoch, clock.now() + dt.timedelta(days=1)) is None


def test_worker_failures_are_typed_codes_without_exception_text_and_deadline_is_monotonic(
    rt: Runtime, clock: FakeClock, executor_factory: Callable[..., JobExecutor], caplog: pytest.LogCaptureFixture
) -> None:
    mono = Mono()
    canary = "secret-canary-93ab"

    def crash(spec: JobSpec, ctx: JobContext) -> tuple[ObjectRef, ...]:
        raise RuntimeError(canary)

    def refuse(spec: JobSpec, ctx: JobContext) -> tuple[ObjectRef, ...]:
        raise JobHandlerError(JobErrorCode.INVALID_PAYLOAD, retryable=False)

    def slow(spec: JobSpec, ctx: JobContext) -> tuple[ObjectRef, ...]:
        mono.now = ctx.deadline_ns + 1
        return ()

    def bad_refs(spec: JobSpec, ctx: JobContext) -> tuple[ObjectRef, ...]:
        return ("not a ref",)  # type: ignore[return-value]

    handlers = {"crash": crash, "refuse": refuse, "slow": slow, "bad": bad_refs}
    executor = executor_factory(handlers, mono)
    service, store = kernel_job_service(rt, clock)
    expected = []
    for kind, retryable, code in (
        ("crash", False, JobErrorCode.HANDLER_FAILED),
        ("refuse", False, JobErrorCode.INVALID_PAYLOAD),
        ("slow", True, JobErrorCode.DEADLINE_EXCEEDED),
        ("bad", False, JobErrorCode.HANDLER_FAILED),
    ):
        enqueue_job(service, store, owner_id="dan", kind=kind, payload=kind.encode())
        lease = _running(service, rt, clock)
        timeout_ns = 2 * 10**9 if kind == "bad" else 10**9
        executor.submit(_item(service, lease, timeout_ns=timeout_ns))
        expected.append(WorkerFailed(lease, retryable, code))
    commands = [_command(executor) for _ in expected]
    assert commands == expected
    assert canary not in repr(commands) and canary not in caplog.text
    for command in commands:
        service.apply_command(command)
    rows = [_row(store, command.lease.job_id) for command in expected]
    assert [(row.state, row.attempt) for row in rows] == [
        (JobState.FAILED, 1),
        (JobState.FAILED, 1),
        (JobState.QUEUED, 2),
        (JobState.FAILED, 1),
    ]
