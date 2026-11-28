"""SP2-3 review r8 finding 1: a failed read of the session binding authority is not a decision about an event.

Requirement sources: spec 7.4 (only verified events feed the observed part) together with case 54 (every committed
event reaches a refresh) and review r8: the cutoff advances only when each event of the batch was used or was found
ineligible; when ``policy.db`` cannot be read the batch and its cutoff are kept and the job lifecycle retries it,
through the daemon's own loop as well; a mixed batch, the commit recheck, the checkpoint read and the stream read
follow the same rule. Review r9 finding 1: a SQLite failure on the task owner read follows the same contract (no
raw ``sqlite3.Error`` escapes the retry paths or stops the owner loop).
"""

from __future__ import annotations

import datetime as dt
import sqlite3
import threading
from pathlib import Path
from typing import Any

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.application.continuity_worker import ContinuityWorkerCoordinator
from superbrain.composition.daemon_entry import create_daemon_owner_loop
from superbrain.composition.migrate_entry import migrate_offline
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import JobState
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.runtime import Runtime
from superbrain.storage.sessions import SessionStore
from superbrain.workers.executor import PRODUCTION_JOB_HANDLERS, JobExecutor
from tests.application.test_continuity_worker_scheduling import (
    BOUND_WAIT_S,
    _open_rt,
    _record_sentinel_events,
    _seed_session_and_task,
)
from tests.integration.test_sp2_store_v7_migration import _build_v6_store, _config, _iso, _owner, _wait
from tests.support.clock import FakeClock
from tests.support.inc2_fixture import kernel_job_service
from tests.support.inc2_transport import FakeMonotonicClock

_START = dt.datetime(2026, 11, 22, 15, 0, tzinfo=dt.UTC)


class _FlakyBindingReads:
    """Makes chosen ``PolicyStore.lookup_session_binding`` calls fail as an unreadable ``policy.db`` would."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.lock = threading.Lock()
        self.fail_all = False
        self.fail_calls: set[int] = set()
        self.calls = 0
        self.failures = 0
        original = PolicyStore.lookup_session_binding

        def _lookup(store: PolicyStore, session_ref: str) -> Any:
            with self.lock:
                self.calls += 1
                fail = self.fail_all or self.calls in self.fail_calls
                if fail:
                    self.failures += 1
            if fail:
                raise BrainError(ErrorCode.IO_ERROR, "injected policy.db read failure")
            return original(store, session_ref)

        monkeypatch.setattr(PolicyStore, "lookup_session_binding", _lookup)

    def arm(self, *, fail_all: bool = False, fail_calls: set[int] | None = None) -> None:
        with self.lock:
            self.calls, self.failures = 0, 0
            self.fail_all, self.fail_calls = fail_all, set(fail_calls or ())

    def disarm(self) -> None:
        self.arm()


def _job(kstore: Any, job_id: str) -> Any:
    return kstore.transact(lambda tx: tx.read_job(job_id))


def _kept(rt: Runtime, task_id: str) -> None:
    ss = SessionStore(rt.store, rt.policy)
    state = ss.get_continuity_worker_state(task_id)
    handoff = ss.read_task_handoff(task_id)
    assert state is not None and state.pending_event_count == 4
    assert handoff is not None and handoff.observed_ref is None


def _committed(rt: Runtime, task_id: str) -> None:
    ss = SessionStore(rt.store, rt.policy)
    state = ss.get_continuity_worker_state(task_id)
    handoff = ss.read_task_handoff(task_id)
    assert state is not None and state.pending_event_count == 0
    assert state.active_job_id is None and state.pending_job_id is None
    assert handoff is not None and handoff.observed_ref is not None


@pytest.mark.parametrize("where", ["claim_whole_batch", "claim_one_event_of_the_batch", "commit_recheck"])
def test_unreadable_binding_authority_keeps_the_batch_and_the_job_retries_it(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, where: str
) -> None:
    clock = FakeClock(_START)
    mono = FakeMonotonicClock()
    os_ = os_adapters(clock=clock, monotonic=mono)
    rt = _open_rt(trusted_tmp / f"authority-{where}", os_, role=f"sp23-authority-{where}")
    executor = JobExecutor(PRODUCTION_JOB_HANDLERS, mono.monotonic_ns)
    executor.start()
    flaky = _FlakyBindingReads(monkeypatch)
    try:
        _cred, ws, sref, task_id = _seed_session_and_task(
            rt, clock, trusted_tmp / f"chk-authority-{where}", raw_sid=f"RAW_AUTH_{where.upper()}"
        )
        _record_sentinel_events(rt, clock, ws, sref, task_id, f"stream-authority-{where}")
        svc, kstore = kernel_job_service(rt, clock)
        coord = ContinuityWorkerCoordinator(
            rt=rt, job_service=svc, executor=executor, clock=clock, mono=mono.monotonic_ns
        )
        clock.advance(dt.timedelta(seconds=61))
        job_id = coord.enqueue_if_due(task_id=task_id, now=clock.now())
        assert job_id is not None

        if where == "commit_recheck":
            prepared = coord.claim_and_execute(writer_epoch=rt.lease.epoch, now=clock.now())
            assert prepared is not None and len(prepared.source_events) >= 2
            flaky.arm(fail_all=True)
            assert coord.commit_prepared(prepared, now=clock.now()) is None
        else:
            flaky.arm(fail_all=where == "claim_whole_batch", fail_calls={2})
            assert coord.claim_and_execute(writer_epoch=rt.lease.epoch, now=clock.now()) is None
        assert flaky.failures >= 1
        flaky.disarm()

        row = _job(kstore, job_id)
        # Queued again for its second attempt (retry with backoff), same job.
        assert row is not None and row.state is JobState.QUEUED and row.attempt == 2
        _kept(rt, task_id)
        # The batch is still owned by the retried job: the scan does not schedule a second one.
        assert coord.enqueue_if_due(task_id=task_id, now=clock.now()) is None

        clock.advance(dt.timedelta(seconds=2))
        prepared = coord.claim_and_execute(writer_epoch=rt.lease.epoch, now=clock.now())
        assert prepared is not None
        assert prepared.lease.job_id == job_id
        assert {seq for _s, seq, _e, _d in prepared.source_events} >= {1, 2}
        assert coord.commit_prepared(prepared, now=clock.now()) is not None
        _committed(rt, task_id)

        # The other readers of the same resolver report the read failure instead of "no source".
        ss = SessionStore(rt.store, rt.policy)
        assert ss.read_long_running_checkpoint(task_id) is not None
        flaky.arm(fail_all=True)
        with pytest.raises(BrainError) as checkpoint_err:
            ss.read_long_running_checkpoint(task_id)
        assert checkpoint_err.value.code is ErrorCode.IO_ERROR
        with pytest.raises(BrainError) as stream_err:
            ss.read_events_for_streams(task_id, {})
        assert stream_err.value.code is ErrorCode.IO_ERROR
        flaky.disarm()
    finally:
        executor.close(BOUND_WAIT_S)
        rt.close()


def test_exhausted_retries_end_the_job_but_keep_the_events_pending_for_a_new_one(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = FakeClock(_START)
    mono = FakeMonotonicClock()
    os_ = os_adapters(clock=clock, monotonic=mono)
    rt = _open_rt(trusted_tmp / "authority-exhausted", os_, role="sp23-authority-exhausted")
    executor = JobExecutor(PRODUCTION_JOB_HANDLERS, mono.monotonic_ns)
    executor.start()
    flaky = _FlakyBindingReads(monkeypatch)
    try:
        _cred, ws, sref, task_id = _seed_session_and_task(
            rt, clock, trusted_tmp / "chk-authority-exhausted", raw_sid="RAW_AUTH_EXHAUSTED"
        )
        _record_sentinel_events(rt, clock, ws, sref, task_id, "stream-authority-exhausted")
        svc, kstore = kernel_job_service(rt, clock)
        coord = ContinuityWorkerCoordinator(
            rt=rt, job_service=svc, executor=executor, clock=clock, mono=mono.monotonic_ns
        )
        clock.advance(dt.timedelta(seconds=61))
        job_id = coord.enqueue_if_due(task_id=task_id, now=clock.now())
        assert job_id is not None
        flaky.arm(fail_all=True)
        for _attempt in range(3):
            assert coord.claim_and_execute(writer_epoch=rt.lease.epoch, now=clock.now()) is None
            clock.advance(dt.timedelta(seconds=5))
        flaky.disarm()
        row = _job(kstore, job_id)
        assert row is not None and row.state is JobState.DEAD_LETTER
        state = SessionStore(rt.store, rt.policy).get_continuity_worker_state(task_id)
        assert state is not None and state.active_job_id is None and state.pending_job_id is None
        _kept(rt, task_id)

        new_job = coord.enqueue_if_due(task_id=task_id, now=clock.now())
        assert new_job is not None and new_job != job_id
        assert coord.run_next(writer_epoch=rt.lease.epoch, now=clock.now())
        _committed(rt, task_id)
    finally:
        executor.close(BOUND_WAIT_S)
        rt.close()


def test_owner_loop_retries_a_refresh_after_the_binding_authority_reads_again(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from superbrain.ports.capture import CaptureEventRecord

    clock = FakeClock(_START)
    mono = FakeMonotonicClock()
    os_ = os_adapters(clock=clock, monotonic=mono)
    fx = _build_v6_store(trusted_tmp, os_, clock, "c57fb92")
    cfg = _config(fx, trusted_tmp, os_, clock)
    migrate_offline(cfg, os_)
    flaky = _FlakyBindingReads(monkeypatch)
    task_id = "task-authority-loop"
    loop = create_daemon_owner_loop(os_=os_, clock=clock, monotonic_clock=mono, job_handlers=PRODUCTION_JOB_HANDLERS)
    loop.start(cfg)
    try:
        def _ingest(rt: Runtime) -> None:
            ss = SessionStore(rt.store, rt.policy)
            sref = ss.bind_session(
                principal_id=fx.principal_id, repo_id=fx.repo_id, checkout_id=fx.checkout_id,
                harness_id="claude-code", raw_session_id="RAW_AUTH_LOOP", now=clock.now(),
            ).session_ref
            ss.ensure_task_handoff(
                task_id=task_id, repo_id=fx.repo_id, checkout_id=fx.checkout_id, session_ref=sref, now=clock.now()
            )
            for seq in range(1, 21):
                ss.record_session_event(
                    session_ref=sref, repo_id=fx.repo_id, checkout_id=fx.checkout_id, task_id=task_id,
                    producer_stream="stream-authority-loop",
                    event=CaptureEventRecord(
                        event_id=f"evt-auth-loop-{seq}", producer_stream="stream-authority-loop", sequence=seq,
                        harness_id="claude-code", kind="tool_post", recorded_at=_iso(clock.now()),
                        payload={"tool": "Edit", "file_path": f"a{seq}.py"}, session_ref=sref,
                    ),
                    now=clock.now(),
                )
            flaky.arm(fail_all=True)

        _owner(loop, _ingest)
        clock.advance(dt.timedelta(seconds=2))  # the durable scan runs once per clock second
        _wait(loop, lambda _rt: flaky.failures >= 1)

        def _still_pending(rt: Runtime) -> Any:
            ss = SessionStore(rt.store, rt.policy)
            state, handoff = ss.get_continuity_worker_state(task_id), ss.read_task_handoff(task_id)
            return state is not None and state.pending_event_count == 20 and handoff is not None and (
                handoff.observed_ref is None
            )

        assert _owner(loop, _still_pending)
        flaky.disarm()
        clock.advance(dt.timedelta(seconds=3))

        def _refreshed(rt: Runtime) -> Any:
            ss = SessionStore(rt.store, rt.policy)
            state, handoff = ss.get_continuity_worker_state(task_id), ss.read_task_handoff(task_id)
            if state is None or handoff is None or handoff.observed_ref is None or state.pending_event_count:
                return None
            return handoff

        assert _wait(loop, _refreshed).current_revision >= 1
    finally:
        loop.stop()


class _DeniedTaskOwnerReads:
    """SQLite authorizer on one connection that fails reads of ``tasks.owner_id`` while armed."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.armed = False
        self.denied = 0

    def __call__(self, action: int, arg1: str | None, arg2: str | None, _db: str | None, _src: str | None) -> int:
        if action == sqlite3.SQLITE_READ and arg1 == "tasks" and arg2 == "owner_id":
            with self.lock:
                if self.armed:
                    self.denied += 1
                    return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    def set(self, armed: bool) -> None:
        with self.lock:
            self.armed = armed


@pytest.mark.parametrize("where", ["claim", "commit"])
def test_sqlite_failure_reading_the_task_owner_keeps_the_batch_and_the_same_job_retries(
    trusted_tmp: Path, where: str
) -> None:
    clock = FakeClock(_START)
    mono = FakeMonotonicClock()
    os_ = os_adapters(clock=clock, monotonic=mono)
    rt = _open_rt(trusted_tmp / f"owner-read-{where}", os_, role=f"sp23-owner-read-{where}")
    executor = JobExecutor(PRODUCTION_JOB_HANDLERS, mono.monotonic_ns)
    executor.start()
    deny = _DeniedTaskOwnerReads()
    try:
        _cred, ws, sref, task_id = _seed_session_and_task(
            rt, clock, trusted_tmp / f"chk-owner-read-{where}", raw_sid=f"RAW_OWNER_READ_{where.upper()}"
        )
        _record_sentinel_events(rt, clock, ws, sref, task_id, f"stream-owner-read-{where}")
        svc, kstore = kernel_job_service(rt, clock)
        coord = ContinuityWorkerCoordinator(
            rt=rt, job_service=svc, executor=executor, clock=clock, mono=mono.monotonic_ns
        )
        clock.advance(dt.timedelta(seconds=61))
        job_id = coord.enqueue_if_due(task_id=task_id, now=clock.now())
        assert job_id is not None
        if where == "commit":
            prepared = coord.claim_and_execute(writer_epoch=rt.lease.epoch, now=clock.now())
            assert prepared is not None
            rt.store._db.set_authorizer(deny)  # installing an authorizer expires cached statements
            deny.set(True)
            assert coord.commit_prepared(prepared, now=clock.now()) is None
        else:
            rt.store._db.set_authorizer(deny)
            deny.set(True)
            assert coord.claim_and_execute(writer_epoch=rt.lease.epoch, now=clock.now()) is None
        deny.set(False)
        assert deny.denied >= 1

        row = _job(kstore, job_id)
        assert row is not None and row.state is JobState.QUEUED and row.attempt == 2
        _kept(rt, task_id)
        assert coord.enqueue_if_due(task_id=task_id, now=clock.now()) is None
        clock.advance(dt.timedelta(seconds=2))
        prepared = coord.claim_and_execute(writer_epoch=rt.lease.epoch, now=clock.now())
        assert prepared is not None and prepared.lease.job_id == job_id
        assert coord.commit_prepared(prepared, now=clock.now()) is not None
        _committed(rt, task_id)
    finally:
        rt.store._db.set_authorizer(None)
        executor.close(BOUND_WAIT_S)
        rt.close()


def test_owner_loop_survives_a_sqlite_failure_reading_the_task_owner_and_refreshes_after_it(
    trusted_tmp: Path,
) -> None:
    from superbrain.ports.capture import CaptureEventRecord

    clock = FakeClock(_START)
    mono = FakeMonotonicClock()
    os_ = os_adapters(clock=clock, monotonic=mono)
    fx = _build_v6_store(trusted_tmp, os_, clock, "c57fb92")
    cfg = _config(fx, trusted_tmp, os_, clock)
    migrate_offline(cfg, os_)
    deny = _DeniedTaskOwnerReads()
    task_id = "task-owner-read-loop"
    loop = create_daemon_owner_loop(os_=os_, clock=clock, monotonic_clock=mono, job_handlers=PRODUCTION_JOB_HANDLERS)
    loop.start(cfg)
    try:
        def _ingest(rt: Runtime) -> None:
            ss = SessionStore(rt.store, rt.policy)
            sref = ss.bind_session(
                principal_id=fx.principal_id, repo_id=fx.repo_id, checkout_id=fx.checkout_id,
                harness_id="claude-code", raw_session_id="RAW_OWNER_READ_LOOP", now=clock.now(),
            ).session_ref
            ss.ensure_task_handoff(
                task_id=task_id, repo_id=fx.repo_id, checkout_id=fx.checkout_id, session_ref=sref, now=clock.now()
            )
            for seq in range(1, 21):
                ss.record_session_event(
                    session_ref=sref, repo_id=fx.repo_id, checkout_id=fx.checkout_id, task_id=task_id,
                    producer_stream="stream-owner-read-loop",
                    event=CaptureEventRecord(
                        event_id=f"evt-owner-read-{seq}", producer_stream="stream-owner-read-loop", sequence=seq,
                        harness_id="claude-code", kind="tool_post", recorded_at=_iso(clock.now()),
                        payload={"tool": "Edit", "file_path": f"o{seq}.py"}, session_ref=sref,
                    ),
                    now=clock.now(),
                )
            rt.store._db.set_authorizer(deny)
            deny.set(True)

        _owner(loop, _ingest)
        clock.advance(dt.timedelta(seconds=2))  # the durable scan runs once per clock second
        _wait(loop, lambda _rt: deny.denied >= 1)

        def _still_pending(rt: Runtime) -> Any:
            ss = SessionStore(rt.store, rt.policy)
            state, handoff = ss.get_continuity_worker_state(task_id), ss.read_task_handoff(task_id)
            return state is not None and state.pending_event_count == 20 and handoff is not None and (
                handoff.observed_ref is None
            )

        assert _owner(loop, _still_pending)  # the owner loop is still serving
        deny.set(False)
        clock.advance(dt.timedelta(seconds=3))

        def _refreshed(rt: Runtime) -> Any:
            ss = SessionStore(rt.store, rt.policy)
            state, handoff = ss.get_continuity_worker_state(task_id), ss.read_task_handoff(task_id)
            if state is None or handoff is None or handoff.observed_ref is None or state.pending_event_count:
                return None
            return handoff

        assert _wait(loop, _refreshed).current_revision >= 1
        _owner(loop, lambda rt: rt.store._db.set_authorizer(None))
    finally:
        loop.stop()


class _DeniedColumnReads:
    def __init__(self, table: str, column: str) -> None:
        self.table, self.column = table, column

    def __call__(self, action: int, arg1: str | None, arg2: str | None, _db: str | None, _src: str | None) -> int:
        if action == sqlite3.SQLITE_READ and (arg1, arg2) == (self.table, self.column):
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK


@pytest.mark.parametrize(
    ("call", "table", "column"),
    [
        ("enqueue_due", "continuity_refresh_state", "first_pending_event_at"),
        ("enqueue_if_due", "session_task_events", "payload_digest"),
        ("read_events_for_streams", "session_task_events", "payload_digest"),
    ],
)
def test_sqlite_failures_on_the_refresh_scheduling_reads_surface_as_read_errors(
    trusted_tmp: Path, call: str, table: str, column: str
) -> None:
    """The daemon's scan and scheduling catch ``BrainError`` and retry on the next pass; a raw ``sqlite3.Error``
    would stop the owner loop instead."""
    clock = FakeClock(_START)
    mono = FakeMonotonicClock()
    os_ = os_adapters(clock=clock, monotonic=mono)
    rt = _open_rt(trusted_tmp / f"sched-read-{call}", os_, role=f"sp23-sched-read-{call}")
    try:
        _cred, ws, sref, task_id = _seed_session_and_task(
            rt, clock, trusted_tmp / f"chk-sched-read-{call}", raw_sid=f"RAW_SCHED_{call.upper()}"
        )
        _record_sentinel_events(rt, clock, ws, sref, task_id, f"stream-sched-read-{call}")
        svc, _kstore = kernel_job_service(rt, clock)
        coord = ContinuityWorkerCoordinator(rt=rt, job_service=svc, executor=None, clock=clock, mono=mono.monotonic_ns)
        clock.advance(dt.timedelta(seconds=61))
        rt.store._db.set_authorizer(_DeniedColumnReads(table, column))
        with pytest.raises(BrainError) as err:
            if call == "enqueue_due":
                coord.enqueue_due(now=clock.now())
            elif call == "enqueue_if_due":
                coord.enqueue_if_due(task_id=task_id, now=clock.now())
            else:
                SessionStore(rt.store, rt.policy).read_events_for_streams(task_id, {})
        assert err.value.code is ErrorCode.IO_ERROR
        rt.store._db.set_authorizer(None)
        _kept(rt, task_id)
        assert coord.enqueue_if_due(task_id=task_id, now=clock.now()) is not None
    finally:
        rt.store._db.set_authorizer(None)
        rt.close()
