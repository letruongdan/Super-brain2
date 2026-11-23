"""SP2-3 review r10 finding 1: a leased job whose handling the owner cannot finish is retried in the same epoch.

Requirement sources: case 54 (every committed event reaches a refresh), the job lifecycle J2 (a failed attempt is
retried with backoff, then dead-lettered) and review r10: after a lease, a failed read of the payload or a failure
while handling the worker's completion or failure keeps the batch and its cutoff, queues the same job again without
a daemon restart, and a retry write that fails too is tried again on a later pass; a stop in between leaves the job
to the next start's recovery.
"""

from __future__ import annotations

import datetime as dt
import threading
from pathlib import Path
from typing import Any

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.application.continuity_worker import ContinuityWorkerCoordinator
from superbrain.application.jobs import JobService
from superbrain.composition.daemon_entry import create_daemon_owner_loop
from superbrain.composition.migrate_entry import migrate_offline
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import JobErrorCode
from superbrain.ports.capture import CaptureEventRecord
from superbrain.storage.runtime import Runtime
from superbrain.storage.sessions import SessionStore
from superbrain.workers.executor import PRODUCTION_JOB_HANDLERS, JobHandlerError
from tests.integration.test_sp2_continuity_authority_read_errors import _committed, _job, _kept
from tests.integration.test_sp2_store_v7_migration import _build_v6_store, _config, _iso, _owner, _wait
from tests.support.clock import FakeClock
from tests.support.inc2_transport import FakeMonotonicClock

_START = dt.datetime(2026, 11, 22, 18, 0, tzinfo=dt.UTC)
_TASK = "task-leased-retry"


class _Faults:
    """Counts and fails chosen calls once each while armed (thread-safe; the owner thread calls them)."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.remaining: dict[str, int] = {}
        self.hits: dict[str, int] = {}

    def arm(self, name: str, times: int = 1) -> None:
        with self.lock:
            self.remaining[name] = times

    def hit(self, name: str) -> bool:
        with self.lock:
            self.hits[name] = self.hits.get(name, 0) + 1
            left = self.remaining.get(name, 0)
            if left > 0:
                self.remaining[name] = left - 1
                return True
            return False

    def count(self, name: str) -> int:
        with self.lock:
            return self.hits.get(name, 0)


def _install(monkeypatch: pytest.MonkeyPatch, faults: _Faults) -> None:
    originals: dict[str, Any] = {
        "resolve_leased_spec": JobService.resolve_leased_spec,
        "retry_attempt": JobService.retry_attempt,
        "commit_worker_completed": ContinuityWorkerCoordinator.commit_worker_completed,
        "handle_worker_failed": ContinuityWorkerCoordinator.handle_worker_failed,
    }

    def _wrap(name: str) -> Any:
        original = originals[name]

        def _call(self: Any, *args: Any, **kwargs: Any) -> Any:
            if faults.hit(name):
                raise BrainError(ErrorCode.IO_ERROR, f"injected read failure in {name}")
            return original(self, *args, **kwargs)

        return _call

    monkeypatch.setattr(JobService, "resolve_leased_spec", _wrap("resolve_leased_spec"))
    monkeypatch.setattr(JobService, "retry_attempt", _wrap("retry_attempt"))
    monkeypatch.setattr(ContinuityWorkerCoordinator, "commit_worker_completed", _wrap("commit_worker_completed"))
    monkeypatch.setattr(ContinuityWorkerCoordinator, "handle_worker_failed", _wrap("handle_worker_failed"))


def _handlers(faults: _Faults) -> dict[str, Any]:
    production = PRODUCTION_JOB_HANDLERS["continuity.refresh"]

    def _refresh(spec: Any, ctx: Any) -> Any:
        if faults.hit("handler"):
            raise JobHandlerError(JobErrorCode.HANDLER_FAILED, retryable=True)
        return production(spec, ctx)

    return {"continuity.refresh": _refresh}


def _ingest(fx: Any, clock: FakeClock) -> Any:
    def _do(rt: Runtime) -> None:
        ss = SessionStore(rt.store, rt.policy)
        sref = ss.bind_session(
            principal_id=fx.principal_id, repo_id=fx.repo_id, checkout_id=fx.checkout_id,
            harness_id="claude-code", raw_session_id="RAW_LEASED_RETRY", now=clock.now(),
        ).session_ref
        ss.ensure_task_handoff(
            task_id=_TASK, repo_id=fx.repo_id, checkout_id=fx.checkout_id, session_ref=sref, now=clock.now()
        )
        for seq in range(1, 21):
            ss.record_session_event(
                session_ref=sref, repo_id=fx.repo_id, checkout_id=fx.checkout_id, task_id=_TASK,
                producer_stream="stream-leased-retry",
                event=CaptureEventRecord(
                    event_id=f"evt-leased-{seq}", producer_stream="stream-leased-retry", sequence=seq,
                    harness_id="claude-code", kind="tool_post", recorded_at=_iso(clock.now()),
                    payload={"tool": "Edit", "file_path": f"l{seq}.py"}, session_ref=sref,
                ),
                now=clock.now(),
            )

    return _do


def _refresh_jobs(rt: Runtime) -> list[tuple[str, str, int]]:
    rows = rt.store._db.execute(
        "SELECT job_id, state, attempt FROM p_jobs_state WHERE kind = 'continuity.refresh' ORDER BY job_id"
    ).fetchall()
    return [(str(r[0]), str(r[1]), int(r[2])) for r in rows]


def _kept20(rt: Runtime) -> bool:
    ss = SessionStore(rt.store, rt.policy)
    state, handoff = ss.get_continuity_worker_state(_TASK), ss.read_task_handoff(_TASK)
    return bool(
        state is not None and state.pending_event_count == 20 and handoff is not None and handoff.observed_ref is None
    )


def _refreshed(rt: Runtime) -> Any:
    ss = SessionStore(rt.store, rt.policy)
    state, handoff = ss.get_continuity_worker_state(_TASK), ss.read_task_handoff(_TASK)
    if state is None or handoff is None or handoff.observed_ref is None or state.pending_event_count:
        return None
    return handoff


_CASES = {
    # case -> the calls whose failure is injected (once each), in the order they are reached
    "claim_payload_read": ("resolve_leased_spec",),
    "completion_after_success": ("commit_worker_completed",),
    "completion_after_worker_failure": ("handler", "handle_worker_failed"),
    "retry_write_fails_too": ("resolve_leased_spec", "retry_attempt"),
}


@pytest.mark.parametrize("case", sorted(_CASES))
def test_owner_retries_the_same_leased_job_after_it_could_not_finish_handling_it(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    clock = FakeClock(_START)
    mono = FakeMonotonicClock()
    os_ = os_adapters(clock=clock, monotonic=mono)
    fx = _build_v6_store(trusted_tmp, os_, clock, "c57fb92")
    cfg = _config(fx, trusted_tmp, os_, clock)
    migrate_offline(cfg, os_)
    faults = _Faults()
    _install(monkeypatch, faults)
    loop = create_daemon_owner_loop(os_=os_, clock=clock, monotonic_clock=mono, job_handlers=_handlers(faults))
    loop.start(cfg)
    try:
        _owner(loop, _ingest(fx, clock))
        for name in _CASES[case]:
            faults.arm(name)
        clock.advance(dt.timedelta(seconds=2))  # the durable scan runs once per clock second
        last = _CASES[case][-1]
        _wait(loop, lambda _rt: faults.count(last) >= 1)
        if case == "retry_write_fails_too":
            # The first retry write failed; a later owner pass writes it.
            _wait(loop, lambda _rt: faults.count("retry_attempt") >= 2)

        def _requeued(rt: Runtime) -> Any:
            jobs = _refresh_jobs(rt)
            return jobs if len(jobs) == 1 and jobs[0][1] == "queued" and jobs[0][2] == 2 else None

        jobs = _wait(loop, _requeued)
        assert _owner(loop, _kept20)  # batch and cutoff kept, owner loop still serving

        clock.advance(dt.timedelta(seconds=3))
        assert _wait(loop, _refreshed).current_revision >= 1
        final = _owner(loop, _refresh_jobs)
        assert [(j, s) for j, s, _a in final] == [(jobs[0][0], "succeeded")]  # the same job, no restart
    finally:
        loop.stop()


def test_a_stop_before_the_retry_is_written_leaves_the_job_to_the_next_start(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = FakeClock(_START)
    mono = FakeMonotonicClock()
    os_ = os_adapters(clock=clock, monotonic=mono)
    fx = _build_v6_store(trusted_tmp, os_, clock, "c57fb92")
    cfg = _config(fx, trusted_tmp, os_, clock)
    migrate_offline(cfg, os_)
    faults = _Faults()
    _install(monkeypatch, faults)
    loop = create_daemon_owner_loop(os_=os_, clock=clock, monotonic_clock=mono, job_handlers=_handlers(faults))
    loop.start(cfg)
    try:
        _owner(loop, _ingest(fx, clock))
        faults.arm("commit_worker_completed")
        faults.arm("retry_attempt", times=1_000)
        clock.advance(dt.timedelta(seconds=2))
        _wait(loop, lambda _rt: faults.count("retry_attempt") >= 1)
        assert _owner(loop, _kept20)
    finally:
        loop.stop()
    faults.arm("retry_attempt", times=0)
    clock.advance(dt.timedelta(seconds=2))
    loop = create_daemon_owner_loop(os_=os_, clock=clock, monotonic_clock=mono, job_handlers=_handlers(faults))
    loop.start(cfg)
    try:
        clock.advance(dt.timedelta(seconds=2))
        assert _wait(loop, _refreshed).current_revision >= 1
        jobs = _owner(loop, _refresh_jobs)
        assert len(jobs) == 1 and jobs[0][1] == "succeeded"
    finally:
        loop.stop()


def test_coordinator_claim_retries_the_same_job_when_the_leased_payload_cannot_be_read(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from superbrain.core.kernel import JobState
    from superbrain.workers.executor import JobExecutor
    from tests.application.test_continuity_worker_scheduling import (
        BOUND_WAIT_S,
        _open_rt,
        _record_sentinel_events,
        _seed_session_and_task,
    )
    from tests.support.inc2_fixture import kernel_job_service

    clock = FakeClock(_START)
    mono = FakeMonotonicClock()
    os_ = os_adapters(clock=clock, monotonic=mono)
    rt = _open_rt(trusted_tmp / "coord-payload", os_, role="sp23-coord-payload")
    executor = JobExecutor(PRODUCTION_JOB_HANDLERS, mono.monotonic_ns)
    executor.start()
    faults = _Faults()
    _install(monkeypatch, faults)
    try:
        _cred, ws, sref, task_id = _seed_session_and_task(
            rt, clock, trusted_tmp / "chk-coord-payload", raw_sid="RAW_COORD_PAYLOAD"
        )
        _record_sentinel_events(rt, clock, ws, sref, task_id, "stream-coord-payload")
        svc, kstore = kernel_job_service(rt, clock)
        coord = ContinuityWorkerCoordinator(
            rt=rt, job_service=svc, executor=executor, clock=clock, mono=mono.monotonic_ns
        )
        clock.advance(dt.timedelta(seconds=61))
        job_id = coord.enqueue_if_due(task_id=task_id, now=clock.now())
        assert job_id is not None
        faults.arm("resolve_leased_spec")
        assert coord.claim_and_execute(writer_epoch=rt.lease.epoch, now=clock.now()) is None
        row = _job(kstore, job_id)
        assert row is not None and row.state is JobState.QUEUED and row.attempt == 2
        _kept(rt, task_id)
        clock.advance(dt.timedelta(seconds=2))
        assert coord.run_next(writer_epoch=rt.lease.epoch, now=clock.now())
        _committed(rt, task_id)
        final = _job(kstore, job_id)
        assert final is not None and final.state is JobState.SUCCEEDED
    finally:
        executor.close(BOUND_WAIT_S)
        rt.close()
