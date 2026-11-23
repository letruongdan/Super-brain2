"""Read-side oracles for Task 8.3's installed-wheel job crashes."""

from __future__ import annotations

import contextlib
import datetime as dt
import json
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.daemon_config import read_daemon_config
from superbrain.application.jobs import JobService
from superbrain.composition.daemon_entry import create_daemon_owner_loop
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import JobErrorCode, JobLease, JobOutcome, Scope, UsageRecord, UsageReservation
from superbrain.storage.idempotency import StagedKernelStore
from superbrain.storage.layout import DataRoot
from superbrain.storage.sqlite import open_readonly
from tests.support.clock import FakeClock
from tests.support.inc2_cli import write_daemon_config_file
from tests.support.inc2_fixture import enqueue_job, kernel_job_service, reopen_kernel_job_runtime
from tests.support.inc2_t8_job_child import FINAL_AMOUNT, MAX_AMOUNT, T8_JOB_KIND
from tests.support.inc2_transport import clone_owner_only_tree

if TYPE_CHECKING:
    from tests.support.crash_cases import KernelCrashContext, KernelSeed, MarkedRun


class JobRow(NamedTuple):
    state: str
    attempt: int
    epoch: int | None
    lease_id: str | None
    reason: str | None


class InvocationRow(NamedTuple):
    invocation_id: str
    job_id: str
    attempt: int
    epoch: int
    lease_id: str
    reservation_digest: str
    state: str
    usage_digest: str | None
    usage_complete: int | None


@dataclass(frozen=True)
class JobEvidence:
    job: JobRow
    invocations: tuple[InvocationRow, ...]
    entries: tuple[tuple[int, str, str, bytes], ...]

    @property
    def kinds(self) -> tuple[str, ...]:
        return tuple(kind for _, _, kind, _ in self.entries)


def _capture(ctx: KernelCrashContext, seed: KernelSeed) -> JobEvidence:
    job_id = seed.notes["job_id"]
    db_path = DataRoot.at(seed.data_root).store_db
    scratch = ctx.case_dir / "jobs-read"
    scratch.mkdir(exist_ok=True)
    with contextlib.closing(open_readonly(db_path, scratch_dir=scratch)) as db:
        row = db.execute(
            "SELECT state, attempt, writer_epoch, lease_id, reason FROM p_jobs_state WHERE job_id = ?", (job_id,)
        ).fetchone()
        assert row is not None
        invocations = tuple(
            InvocationRow(*inv)
            for inv in db.execute(
                "SELECT invocation_id, job_id, attempt, writer_epoch, lease_id, reservation_digest,"
                " state, usage_digest, usage_complete FROM p_provider_invocations_state WHERE job_id = ? ORDER BY 1",
                (job_id,),
            )
        )
        ids = {inv.invocation_id for inv in invocations}
        events = []
        for sequence, entry_id, kind, meta in db.execute(
            "SELECT sequence, entry_id, kind, meta FROM ledger"
            " WHERE kind LIKE 'job.%' OR kind LIKE 'provider.%' ORDER BY sequence"
        ):
            details = json.loads(meta)
            if details.get("job_id") == job_id or details.get("invocation_id") in ids:
                events.append((sequence, entry_id, kind, meta))
        return JobEvidence(JobRow(*row), invocations, tuple(events))


@dataclass(frozen=True)
class _JobSeedTemplate:
    root: Path
    lock_epoch: int
    snapshot: dict[str, list[tuple[object, ...]]]
    notes: dict[str, object]


_JOB_SEED_TEMPLATES: dict[str, _JobSeedTemplate] = {}


def _get_job_seed_template(ctx: KernelCrashContext) -> _JobSeedTemplate:
    tpl = ctx.template
    existing = _JOB_SEED_TEMPLATES.get(tpl.store_id)
    if existing is not None and existing.root.is_dir():
        return existing
    from tests.support.crash_cases import lock_epoch, store_rows
    from tests.support.inc2_fixture import ensure_template_base

    tpl_dir = ensure_template_base() / f"job-seed-tpl-{uuid.uuid4().hex}"
    tpl_dir.mkdir(parents=True, exist_ok=True)
    tpl_root = tpl_dir / "jobs"
    clone_owner_only_tree(tpl.root, tpl_root)
    clock = FakeClock(tpl.base_time)
    rt = reopen_kernel_job_runtime(tpl_root, tpl.store_id, os_adapters(clock=clock))
    try:
        service, staged = kernel_job_service(rt, clock)
        assert tpl.global_job_id is not None and tpl.scoped_job_id is not None and tpl.ws_a is not None
        service.cancel(tpl.global_job_id, tpl.cred.principal, selected_scope=None)
        scope = Scope(tpl.ws_a.repo_id, tpl.ws_a.checkout_id)
        service.cancel(tpl.scoped_job_id, tpl.cred.principal, selected_scope=scope)
        job = enqueue_job(service, staged, owner_id=tpl.cred.principal.owner_id, kind=T8_JOB_KIND)
        notes: dict[str, object] = {
            "job_id": job.job_id,
            "attempt": 1,
            "principal_id": tpl.cred.principal.principal_id,
        }
    finally:
        rt.close()
    snapshot = store_rows(tpl_root, tpl_dir / "jobs-read")
    res = _JobSeedTemplate(
        root=tpl_root,
        lock_epoch=lock_epoch(tpl_root),
        snapshot=snapshot,
        notes=notes,
    )
    _JOB_SEED_TEMPLATES[tpl.store_id] = res
    return res


def seed_job(ctx: KernelCrashContext, *, attempt: int = 1, enqueue: bool = True) -> KernelSeed:
    """Clone the ACKed template, terminalize its jobs and optionally enqueue one new due test job."""
    from tests.support.crash_cases import KernelSeed, lock_epoch, store_rows

    tpl = ctx.template
    root = ctx.case_dir / "jobs"
    cfg = ctx.case_dir / "jobs-config.json"
    write_daemon_config_file(
        cfg, data_root=root, expected_store_id=tpl.store_id,
        cert_path=tpl.tls.cert_path, key_path=tpl.tls.key_path,
    )
    if attempt == 1 and enqueue:
        job_tpl = _get_job_seed_template(ctx)
        clone_owner_only_tree(job_tpl.root, root)
        return KernelSeed(root, cfg, tpl.store_id, job_tpl.lock_epoch, job_tpl.snapshot, notes=dict(job_tpl.notes))

    clone_owner_only_tree(tpl.root, root)
    clock = FakeClock(tpl.base_time)
    rt = reopen_kernel_job_runtime(root, tpl.store_id, os_adapters(clock=clock))
    notes: dict[str, object] = {}
    try:
        service, staged = kernel_job_service(rt, clock)
        assert tpl.global_job_id is not None and tpl.scoped_job_id is not None and tpl.ws_a is not None
        service.cancel(tpl.global_job_id, tpl.cred.principal, selected_scope=None)
        scope = Scope(tpl.ws_a.repo_id, tpl.ws_a.checkout_id)
        service.cancel(tpl.scoped_job_id, tpl.cred.principal, selected_scope=scope)
        if enqueue:
            job = enqueue_job(service, staged, owner_id=tpl.cred.principal.owner_id, kind=T8_JOB_KIND)
            notes = {"job_id": job.job_id, "attempt": attempt, "principal_id": tpl.cred.principal.principal_id}
            for previous_attempt in range(1, attempt):
                lease = service.lease_next(rt.lease.epoch, clock.now())
                assert lease is not None and (lease.job_id, lease.attempt) == (job.job_id, previous_attempt)
                service.start(lease)
                service.complete(lease, JobOutcome.failure(JobErrorCode.HANDLER_FAILED, retryable=True))
                clock.advance(dt.timedelta(seconds=3))
    finally:
        rt.close()
    snapshot = store_rows(root, ctx.case_dir / "jobs-read")
    return KernelSeed(root, cfg, tpl.store_id, lock_epoch(root), snapshot, notes=notes)


def seed_usage(ctx: KernelCrashContext, *, complete: bool = True) -> KernelSeed:
    from dataclasses import replace

    from tests.support.crash_cases import lock_epoch, store_rows

    seed = seed_job(ctx)
    clock = FakeClock(ctx.template.base_time)
    rt = reopen_kernel_job_runtime(seed.data_root, seed.store_id, os_adapters(clock=clock))
    try:
        service, _ = kernel_job_service(rt, clock)
        lease = service.lease_next(rt.lease.epoch, clock.now())
        assert lease is not None and lease.job_id == seed.notes["job_id"]
        service.start(lease)
        invocation_id = service.reserve_invocation(lease, UsageReservation(MAX_AMOUNT))
        if complete:
            service.settle_usage(invocation_id, UsageRecord(None, False))
        seed.notes.update(invocation_id=invocation_id, variant="complete" if complete else "incomplete")
    finally:
        rt.close()
    return replace(
        seed,
        epoch=lock_epoch(seed.data_root),
        snapshot=store_rows(seed.data_root, ctx.case_dir / "jobs-read"),
    )


def cancel_args(seed: KernelSeed) -> tuple[str, ...]:
    return "cancel", str(seed.notes["principal_id"])


def settle_args(seed: KernelSeed) -> tuple[str, ...]:
    return "settle", str(seed.notes["invocation_id"]), str(seed.notes["variant"])


def _require_append(before: JobEvidence, after: JobEvidence, *kinds: str) -> None:
    assert after.entries[:len(before.entries)] == before.entries, "the ACKed job ledger was rewritten"
    assert after.kinds == before.kinds + kinds, (before.kinds, after.kinds, kinds)


def _recover_twice(
    ctx: KernelCrashContext, seed: KernelSeed, *, new_state: str, attempt: int, events: tuple[str, ...]
) -> JobEvidence:
    from tests.support.crash_cases import lock_epoch

    crashed = _capture(ctx, seed)
    os_ = os_adapters()
    cfg = read_daemon_config(seed.config, os_)
    epoch = lock_epoch(seed.data_root)
    after: list[JobEvidence] = []
    for bump in (1, 2):
        loop = create_daemon_owner_loop(os_=os_, job_handlers={})
        ready = loop.start(cfg)
        try:
            assert (ready.endpoint.store_id, ready.endpoint.writer_epoch) == (seed.store_id, epoch + bump)
            after.append(_capture(ctx, seed))
        finally:
            assert loop.stop(grace_s=3.0).endpoint_removed
    first, second = after
    _require_append(crashed, first, *events)
    assert first.job[:2] == (new_state, attempt)
    if new_state == "queued":
        assert first.job == JobRow("queued", attempt, None, None, "lease_lost")
    elif new_state == "dead_letter":
        assert first.job.reason == "lease_lost"
    assert second == first, "second restart changed recovered job/accounting state or appended another event"
    return second


def _blobs(store: StagedKernelStore, inv: InvocationRow, *, usage: str | None, complete: bool | None) -> None:
    reservation = store.transact(lambda tx: tx.read_held_blob(inv.reservation_digest, holder_id=inv.invocation_id))
    assert reservation is not None
    assert json.loads(reservation) == {
        "schema": "provider-reservation-v1", "job_id": inv.job_id, "invocation_id": inv.invocation_id,
        "max_amount": MAX_AMOUNT,
    }
    digest = inv.usage_digest
    if complete is None:
        assert digest is None and inv.usage_complete is None
    else:
        assert digest is not None and inv.usage_complete == int(complete)
        raw = store.transact(lambda tx: tx.read_held_blob(digest, holder_id=inv.invocation_id))
        assert raw is not None
        assert json.loads(raw) == {
            "schema": "provider-usage-v1", "invocation_id": inv.invocation_id, "amount": usage, "complete": complete,
        }


def _rebuild(
    ctx: KernelCrashContext,
    seed: KernelSeed,
    expected: JobEvidence,
    check_blobs: Callable[[StagedKernelStore], None] | None = None,
    settle_late: Callable[[JobService, StagedKernelStore], None] | None = None,
) -> None:
    from tests.support.crash_cases import assert_acked_kept, store_rows

    os_ = os_adapters()
    rt = reopen_kernel_job_runtime(seed.data_root, seed.store_id, os_)
    try:
        service, store = kernel_job_service(rt, os_.clock)
        if check_blobs is not None:
            check_blobs(store)
        assert _capture(ctx, seed) == expected
        if settle_late is not None:
            settle_late(service, store)
            expected = _capture(ctx, seed)
        rt.store.rebuild_projections()
        assert _capture(ctx, seed) == expected, "projection rebuild changed the recovered effect"
        if check_blobs is not None and settle_late is None:
            check_blobs(store)
    finally:
        rt.close()
    assert_acked_kept(seed, store_rows(seed.data_root, ctx.case_dir / "jobs-read"))


def expect_claim(ctx: KernelCrashContext, seed: KernelSeed, run: MarkedRun, *, running: bool) -> None:
    from tests.support.crash_cases import assert_wheel_provenance

    assert_wheel_provenance(run, ctx)
    assert "JOB_HANDLER_RAN" not in run.result.stderr, "the worker ran before the lease/running hook"
    after = _capture(ctx, seed)
    attempt = int(str(seed.notes["attempt"]))
    assert after.job[:3] == ("running" if running else "leased", attempt, seed.epoch + 1)
    assert after.job.lease_id and not after.invocations
    assert after.kinds[-1] == ("job.running" if running else "job.leased")
    state = "dead_letter" if attempt == 3 else "queued"
    events = ("job.terminal",) if state == "dead_letter" else ("job.retry",)
    expected = _recover_twice(ctx, seed, new_state=state, attempt=min(attempt + 1, 3), events=events)
    _rebuild(ctx, seed, expected)


def expect_lease(ctx: KernelCrashContext, seed: KernelSeed, run: MarkedRun) -> None:
    expect_claim(ctx, seed, run, running=False)


def expect_running(ctx: KernelCrashContext, seed: KernelSeed, run: MarkedRun) -> None:
    expect_claim(ctx, seed, run, running=True)


def _crashed_invocation(ctx: KernelCrashContext, seed: KernelSeed) -> tuple[JobEvidence, InvocationRow]:
    evidence = _capture(ctx, seed)
    (invocation,) = evidence.invocations
    assert invocation.job_id == seed.notes["job_id"]
    assert invocation.attempt == 1 and invocation.lease_id == evidence.job.lease_id
    assert invocation.epoch == evidence.job.epoch
    return evidence, invocation


def expect_reserve(ctx: KernelCrashContext, seed: KernelSeed, run: MarkedRun) -> None:
    from tests.support.crash_cases import assert_wheel_provenance

    assert_wheel_provenance(run, ctx)
    assert "JOB_OPERATION reserve" in run.result.stderr and "INVOCATION_RETURNED" not in run.result.stderr
    crashed, inv = _crashed_invocation(ctx, seed)
    assert crashed.job[:3] == ("running", 1, seed.epoch + 1)
    assert crashed.kinds == ("job.queued", "job.leased", "job.running", "provider.reserved")
    assert inv.state == "reserved" and inv.usage_digest is None
    recovered = _recover_twice(
        ctx, seed, new_state="queued", attempt=2, events=("provider.unknown", "job.retry")
    )
    (unknown,) = recovered.invocations
    assert unknown == inv._replace(state="outcome_unknown")
    _rebuild(ctx, seed, recovered, lambda store: _blobs(store, unknown, usage=None, complete=None))


def expect_cancel(ctx: KernelCrashContext, seed: KernelSeed, run: MarkedRun) -> None:
    from superbrain.core.kernel import WorkerCompleted, WorkerUsage
    from tests.support.crash_cases import assert_wheel_provenance

    assert_wheel_provenance(run, ctx)
    assert "JOB_OPERATION cancel" in run.result.stderr and "JOB_CANCEL_SIGNAL" not in run.result.stderr
    crashed, inv = _crashed_invocation(ctx, seed)
    assert crashed.job[:3] == ("cancelled", 1, seed.epoch + 1)
    assert crashed.kinds == ("job.queued", "job.leased", "job.running", "provider.reserved", "job.terminal")
    assert inv.state == "reserved"
    recovered = _recover_twice(ctx, seed, new_state="cancelled", attempt=1, events=("provider.unknown",))
    (unknown,) = recovered.invocations
    assert unknown == inv._replace(state="outcome_unknown")

    def late_callback(service: JobService, store: StagedKernelStore) -> None:
        lease = JobLease(inv.job_id, inv.attempt, inv.epoch, inv.lease_id)
        with pytest.raises(BrainError) as denied:
            service.apply_command(WorkerCompleted(lease))
        assert denied.value.code is ErrorCode.REVISION_CONFLICT
        service.apply_command(WorkerUsage(inv.invocation_id, UsageRecord(FINAL_AMOUNT, True)))
        after = _capture(ctx, seed)
        _require_append(recovered, after, "provider.settled")
        assert after.job == recovered.job
        (settled,) = after.invocations
        assert settled[:6] == inv[:6] and settled.state == "settled"
        _blobs(store, settled, usage=FINAL_AMOUNT, complete=True)

    _rebuild(
        ctx, seed, recovered, lambda store: _blobs(store, unknown, usage=None, complete=None), late_callback
    )


def expect_settle(ctx: KernelCrashContext, seed: KernelSeed, run: MarkedRun) -> None:
    from tests.support.crash_cases import assert_entered, assert_wheel_provenance, run_t8_child

    assert_wheel_provenance(run, ctx)
    assert "JOB_OPERATION settle" in run.result.stderr and "JOB_RETURNED settle" not in run.result.stderr
    crashed, inv = _crashed_invocation(ctx, seed)
    assert inv.invocation_id == seed.notes["invocation_id"]
    complete = seed.notes["variant"] == "complete"
    assert crashed.kinds == (
        "job.queued", "job.leased", "job.running", "provider.reserved", "provider.settled",
    ) + (("provider.settled",) if complete else ())
    assert inv.state == ("settled" if complete else "outcome_unknown")
    assert inv.usage_complete == int(complete)
    recovered = _recover_twice(ctx, seed, new_state="queued", attempt=2, events=("job.retry",))
    assert recovered.invocations == (inv,)
    retry = run_t8_child(
        ctx.env, "job-operation", seed.config, cwd=ctx.cwd, crashpoint=run.result.hit, args=settle_args(seed),
    )
    assert_entered(retry)
    assert retry.result.returncode == 0 and retry.result.hit is None, retry.describe()
    assert "JOB_RETURNED settle" in retry.result.stderr and _capture(ctx, seed) == recovered
    if complete:
        os_ = os_adapters()
        rt = reopen_kernel_job_runtime(seed.data_root, seed.store_id, os_)
        try:
            service, _store = kernel_job_service(rt, os_.clock)
            with pytest.raises(BrainError) as conflict:
                service.settle_usage(inv.invocation_id, UsageRecord("2.75", True))
            assert conflict.value.code is ErrorCode.IDEMPOTENCY_CONFLICT
        finally:
            rt.close()
    _rebuild(
        ctx, seed, recovered,
        lambda store: _blobs(store, inv, usage=FINAL_AMOUNT if complete else None, complete=complete),
    )
