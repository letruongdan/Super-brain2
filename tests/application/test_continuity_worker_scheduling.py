"""SP2-3 application & OwnerLoop tests: 3-phase continuity.refresh worker, scheduling, races, policy matrix, liveness.

Requirement sources:
- docs/superpowers/specs/2026-10-30-super-brain2-system-design.md (§7.1-7.4, §20 cases 39, 40, 53, 54, 59)
- docs/superpowers/plans/2026-11-18-sp2-capture-continuity.md (SP2-3, lines 55-73, 158-181)
- docs/design/sp2-host-capture-matrix.md (§4, §4.2, SP2-3 crashpoints)
"""

from __future__ import annotations

import datetime as dt
import os
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.tls_material import create_store_tls
from superbrain.composition.daemon_entry import (
    PRODUCTION_JOB_HANDLERS as ENTRY_PRODUCTION_JOB_HANDLERS,
)
from superbrain.composition.daemon_entry import (
    DaemonTestHooks,
    create_daemon_owner_loop,
)
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.kernel import DaemonConfig, JobState
from superbrain.ports.capture import CaptureEventRecord
from superbrain.ports.os import OsAdapters
from superbrain.storage.idempotency import StagedKernelStore
from superbrain.storage.layout import DataRoot
from superbrain.storage.runtime import Runtime
from superbrain.workers.executor import PRODUCTION_JOB_HANDLERS, JobExecutor
from tests.support.clock import FakeClock
from tests.support.inc2_fixture import (
    FIXTURE_JOB_KIND,
    kernel_job_service,
    open_kernel_job_runtime,
    reopen_kernel_job_runtime,
)
from tests.support.inc2_transport import FakeMonotonicClock, register_workspace_direct
from tests.support.kernel_auth import make_bootstrap_auth, seed_principal_and_credential

REPO_ROOT = Path(__file__).resolve().parents[2]
_START = dt.datetime(2026, 11, 21, 14, 0, tzinfo=dt.UTC)
BOUND_WAIT_S = 5.0


def _open_rt(root: Path, os_: OsAdapters, *, role: str) -> Runtime:
    return open_kernel_job_runtime(root, os_, role=role)


def _ev(
    seq: int,
    *,
    session_ref: str,
    recorded_at: dt.datetime,
    kind: str = "tool_post",
    payload: dict[str, Any] | None = None,
    stream: str = "stream-cw-1",
) -> CaptureEventRecord:
    return CaptureEventRecord(
        event_id=f"evt-cw-{stream}-{seq}",
        producer_stream=stream,
        sequence=seq,
        harness_id="claude-code",
        kind=kind,
        recorded_at=recorded_at.astimezone(dt.UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        payload=payload if payload is not None else {"tool": "Read", "summary": f"step-{seq}"},
        session_ref=session_ref,
        source_metadata={"host_version": "2.1.325"},
    )


def _seed_session_and_task(
    rt: Runtime,
    clock: FakeClock,
    checkout_dir: Path,
    *,
    raw_sid: str = "RAW_WORKER_SESSION_1",
    alias: str = "repo-w",
) -> tuple[Any, Any, str, str]:
    from superbrain.storage.sessions import SessionStore

    cred = seed_principal_and_credential(rt.policy, owner_id="dan", harness_id="claude-code", machine_id="m-w1")
    ws = register_workspace_direct(rt, clock, cred.principal, alias=alias, checkout_dir=checkout_dir)
    rt.store.reconcile_policy()
    sessions = SessionStore(rt.store, rt.policy)
    sess = sessions.bind_session(
        principal_id=cred.principal.principal_id,
        repo_id=ws.repo_id,
        checkout_id=ws.checkout_id,
        harness_id="claude-code",
        raw_session_id=raw_sid,
        now=clock.now(),
    )
    task_id = f"task-{new_id()}"
    sessions.ensure_task_handoff(
        task_id=task_id,
        repo_id=ws.repo_id,
        checkout_id=ws.checkout_id,
        session_ref=sess.session_ref,
        now=clock.now(),
    )
    return cred, ws, sess.session_ref, task_id


def test_production_job_handlers_registers_only_deterministic_continuity_refresh() -> None:
    assert set(PRODUCTION_JOB_HANDLERS) == {"continuity.refresh"}
    assert set(ENTRY_PRODUCTION_JOB_HANDLERS) == {"continuity.refresh"}
    assert FIXTURE_JOB_KIND not in PRODUCTION_JOB_HANDLERS
    with pytest.raises(TypeError):
        PRODUCTION_JOB_HANDLERS[FIXTURE_JOB_KIND] = lambda _s, _c: ()  # type: ignore[index]


def test_scheduling_20_events_and_60s_age_and_single_inflight_dirty_flag_case_54(
    trusted_tmp: Path,
) -> None:
    from superbrain.application.continuity_worker import ContinuityWorkerCoordinator
    from superbrain.storage.sessions import SessionStore

    clock = FakeClock(_START)
    mono = FakeMonotonicClock()
    os_ = os_adapters(clock=clock, monotonic=mono)
    rt = _open_rt(trusted_tmp / "sched", os_, role="sp23-sched")
    executor = JobExecutor(PRODUCTION_JOB_HANDLERS, mono.monotonic_ns)
    executor.start()
    try:
        cred, ws, sref, task_id = _seed_session_and_task(rt, clock, trusted_tmp / "chk-sched")
        # Ensure provider_egress_enabled=False works (worker makes ZERO model calls!).
        rt.policy.set_repo_policy(
            ws.repo_id,
            provider_egress_enabled=False,
            automatic_capture_enabled=True,
            manual_submission_enabled=True,
        )
        sessions = SessionStore(rt.store, rt.policy)
        svc, kstore = kernel_job_service(rt, clock)

        # Case 54: < 20 events (3 events) on a quiet session does NOT schedule at 59 s, schedules at 60 s.
        coord = ContinuityWorkerCoordinator(
            rt=rt, job_service=svc, executor=executor, clock=clock, mono=mono.monotonic_ns
        )
        for seq in range(1, 4):
            clock.advance(dt.timedelta(seconds=1))
            sessions.record_session_event(
                session_ref=sref,
                repo_id=ws.repo_id,
                checkout_id=ws.checkout_id,
                task_id=task_id,
                producer_stream="stream-q",
                event=_ev(
                    seq,
                    session_ref=sref,
                    recorded_at=clock.now(),
                    stream="stream-q",
                    payload={"tool": "Bash", "command": "pytest -q", "exit_code": 0},
                ),
                now=clock.now(),
            )
            assert coord.enqueue_if_due(task_id=task_id, now=clock.now()) is None

        # 1st event happened at +1 s, so +59 s from first unrefreshed is still < 60 s.
        clock.set(_START + dt.timedelta(seconds=60))
        assert coord.enqueue_if_due(task_id=task_id, now=clock.now()) is None
        clock.set(_START + dt.timedelta(seconds=61))
        job1_id = coord.enqueue_if_due(task_id=task_id, now=clock.now())
        assert job1_id is not None

        # While job1 is queued/in-flight, arriving events set dirty_flag=1 and NEVER create a 2nd concurrent job!
        for seq in range(4, 24):
            clock.advance(dt.timedelta(seconds=1))
            sessions.record_session_event(
                session_ref=sref,
                repo_id=ws.repo_id,
                checkout_id=ws.checkout_id,
                task_id=task_id,
                producer_stream="stream-q",
                event=_ev(seq, session_ref=sref, recorded_at=clock.now(), stream="stream-q"),
                now=clock.now(),
            )
            assert coord.enqueue_if_due(task_id=task_id, now=clock.now()) is None

        active_jobs = rt.store._db.execute(
            "SELECT job_id FROM p_jobs_state WHERE state IN ('queued', 'leased', 'running')"
        ).fetchall()
        assert len(active_jobs) == 1
        wstate = sessions.get_continuity_worker_state(task_id)
        assert wstate is not None and wstate.dirty_flag is True

        # Execute Phase 1 (Claim) + Phase 2 (Worker) while job1 is still in-flight before Phase 3 Commit.
        prepared1 = coord.claim_and_execute(writer_epoch=rt.lease.epoch, now=clock.now())
        assert prepared1 is not None
        assert coord.enqueue_if_due(task_id=task_id, now=clock.now()) is None
        active_mid = rt.store._db.execute(
            "SELECT job_id FROM p_jobs_state WHERE state IN ('queued', 'leased', 'running')"
        ).fetchall()
        assert len(active_mid) == 1

        committed1 = coord.commit_prepared(prepared1, now=clock.now())
        assert committed1 is not None and committed1.observed_ref is not None

        job1_row = kstore.transact(lambda tx: tx.read_job(job1_id))
        assert job1_row is not None and job1_row.state is JobState.SUCCEEDED
        # After job1 commits atomically with JobService.complete, dirty follow-up schedules <= 1 new job.
        followup_id = coord.enqueue_if_due(task_id=task_id, now=clock.now())
        assert followup_id is not None and followup_id != job1_id
        assert coord.run_next(writer_epoch=rt.lease.epoch, now=clock.now()) is True
        job2_row = kstore.transact(lambda tx: tx.read_job(followup_id))
        assert job2_row is not None and job2_row.state is JobState.SUCCEEDED

        wstate_done = sessions.get_continuity_worker_state(task_id)
        assert wstate_done is not None and wstate_done.dirty_flag is False

        # Triggering strictly via 20 events at +1 s works immediately without waiting 60 s.
        t_fast = clock.now()
        for seq in range(24, 44):
            sessions.record_session_event(
                session_ref=sref,
                repo_id=ws.repo_id,
                checkout_id=ws.checkout_id,
                task_id=task_id,
                producer_stream="stream-q",
                event=_ev(seq, session_ref=sref, recorded_at=t_fast, stream="stream-q"),
                now=t_fast,
            )
        job20_id = coord.enqueue_if_due(task_id=task_id, now=t_fast + dt.timedelta(seconds=1))
        assert job20_id is not None
        assert coord.run_next(writer_epoch=rt.lease.epoch, now=t_fast + dt.timedelta(seconds=1)) is True
        handoff = sessions.read_task_handoff(task_id)
        assert handoff is not None and handoff.observed_ref is not None
        assert cred.principal.owner_id == "dan"
    finally:
        executor.close(BOUND_WAIT_S)
        rt.close()


def test_worker_before_owner_commit_race_and_base_revision_zero_cases_39_53(
    trusted_tmp: Path,
) -> None:
    from superbrain.application.continuity_worker import ContinuityWorkerCoordinator
    from superbrain.storage.sessions import SessionStore

    clock = FakeClock(_START)
    mono = FakeMonotonicClock()
    os_ = os_adapters(clock=clock, monotonic=mono)
    root_race = trusted_tmp / "ownerloop-race"

    # Seed root, session, task, and initial 20 events.
    rt_seed = _open_rt(root_race, os_, role="sp23-loop-race")
    try:
        sid = rt_seed.policy.store_id
        _cred, ws, sref, task_id = _seed_session_and_task(rt_seed, clock, trusted_tmp / "chk-loop-race")
        ss_seed = SessionStore(rt_seed.store, rt_seed.policy)
        for seq in range(1, 21):
            ss_seed.record_session_event(
                session_ref=sref,
                repo_id=ws.repo_id,
                checkout_id=ws.checkout_id,
                task_id=task_id,
                producer_stream="stream-ol",
                event=_ev(
                    seq,
                    session_ref=sref,
                    recorded_at=clock.now(),
                    stream="stream-ol",
                    payload={"tool": "Edit", "file_path": f"ol_{seq}.py"},
                ),
                now=clock.now(),
            )
    finally:
        rt_seed.close()

    # Step 1 (Case 53): worker commits first (current_revision > 0, handoff_revision == 0, source="inferred")
    # -> agent's first patch using base_revision=0 succeeds with zero revision_conflict.
    rt2 = reopen_kernel_job_runtime(root_race, sid, os_)
    exec2 = JobExecutor(PRODUCTION_JOB_HANDLERS, mono.monotonic_ns)
    exec2.start()
    try:
        ss2 = SessionStore(rt2.store, rt2.policy)
        svc2, _ = kernel_job_service(rt2, clock)
        coord_first = ContinuityWorkerCoordinator(
            rt=rt2, job_service=svc2, executor=exec2, clock=clock, mono=mono.monotonic_ns
        )
        assert coord_first.enqueue_if_due(task_id=task_id, now=clock.now()) is not None
        assert coord_first.run_next(writer_epoch=rt2.lease.epoch, now=clock.now()) is True

        h_inferred = ss2.read_task_handoff(task_id)
        assert h_inferred is not None
        assert h_inferred.observed_ref is not None
        assert h_inferred.handoff_revision == 0
        assert h_inferred.current_revision >= 1
        assert h_inferred.task_state_source == "inferred"

        agent_ref_1 = digest_bytes(b"agent-patch-v1")
        h_agent1 = ss2.apply_agent_handoff_patch(
            task_id=task_id,
            repo_id=ws.repo_id,
            checkout_id=ws.checkout_id,
            session_ref=sref,
            base_revision=0,
            agent_ref=agent_ref_1,
            now=clock.now(),
        )
        assert h_agent1.handoff_revision == 1
        assert h_agent1.agent_ref == agent_ref_1
        assert h_agent1.observed_ref == h_inferred.observed_ref
    finally:
        exec2.close(BOUND_WAIT_S)
        rt2.close()

    # Step 2 (Case 39 on real OwnerLoop + before_owner_commit hook):
    # Enqueue 20 new events, start real OwnerLoop with PRODUCTION_JOB_HANDLERS, trigger continuity refresh,
    # pause before Phase 3 owner commit to inject concurrent agent patch (agent_ref_2, handoff_revision=2),
    # then verify Phase 3 preserves live agent_ref_2 with handoff_revision unchanged == 2 and zero conflicts!
    rt_more = reopen_kernel_job_runtime(root_race, sid, os_)
    try:
        ss_more = SessionStore(rt_more.store, rt_more.policy)
        for seq in range(21, 41):
            ss_more.record_session_event(
                session_ref=sref,
                repo_id=ws.repo_id,
                checkout_id=ws.checkout_id,
                task_id=task_id,
                producer_stream="stream-ol",
                event=_ev(
                    seq,
                    session_ref=sref,
                    recorded_at=clock.now(),
                    stream="stream-ol",
                    payload={"tool": "Edit", "file_path": f"race_{seq}.py"},
                ),
                now=clock.now(),
            )
    finally:
        rt_more.close()

    tls = create_store_tls(
        sid,
        trusted_tmp / "ol-tls",
        make_bootstrap_auth(
            store_id=sid,
            owner_id="dan",
            action="provision_tls",
            subject_id=sid,
            trust_generation=1,
            expires_at=clock.now() + dt.timedelta(hours=4),
            destination=trusted_tmp / "ol-tls",
        ),
        clock,
        os_,
    )
    cfg = DaemonConfig(1, root_race, sid, tls.cert_path, tls.key_path)

    agent_ref_2 = digest_bytes(b"agent-patch-v2-concurrent")
    hook_fired = threading.Event()
    commit_done = threading.Event()
    race_box: list[Any] = []

    def _inject_concurrent_agent_patch_before_commit(session_rt: Runtime) -> None:
        # Runs strictly on owner thread right before Phase 3 commit (`continuity.worker.before_owner_commit`).
        ss_live = SessionStore(session_rt.store, session_rt.policy)
        patched = ss_live.apply_agent_handoff_patch(
            task_id=task_id,
            repo_id=ws.repo_id,
            checkout_id=ws.checkout_id,
            session_ref=sref,
            base_revision=1,
            agent_ref=agent_ref_2,
            now=clock.now() + dt.timedelta(seconds=1),
        )
        race_box.append(patched)
        hook_fired.set()

    loop = create_daemon_owner_loop(
        os_=os_,
        clock=clock,
        monotonic_clock=mono,
        job_handlers=PRODUCTION_JOB_HANDLERS,
        hooks=DaemonTestHooks(before_continuity_worker_commit=_inject_concurrent_agent_patch_before_commit),
    )
    loop.start(cfg)
    try:
        job_id_box: list[str] = []

        def _kick_worker_and_wait() -> None:
            session: Any = loop._session
            assert session is not None
            coord = session._continuity_worker
            jid = coord.enqueue_if_due(task_id=task_id, now=clock.now())
            assert jid is not None
            job_id_box.append(jid)
            coord.run_next(writer_epoch=session._rt.lease.epoch, now=clock.now())
            commit_done.set()

        loop.run_owner_action(_kick_worker_and_wait).result(timeout=BOUND_WAIT_S)
        assert hook_fired.is_set() and commit_done.is_set()
        assert race_box and race_box[0].handoff_revision == 2

        def _read_final() -> tuple[Any, Any]:
            session: Any = loop._session
            assert session is not None
            ss_end = SessionStore(session._rt.store, session._rt.policy)
            ks_end = StagedKernelStore(session._rt.store, session._rt.policy, writer_epoch=session._rt.lease.epoch)
            return ss_end.read_task_handoff(task_id), ks_end.transact(lambda tx: tx.read_job(job_id_box[0]))

        committed_handoff, done_job = loop.run_owner_action(_read_final).result(timeout=BOUND_WAIT_S)
        assert committed_handoff is not None
        assert committed_handoff.agent_ref == agent_ref_2
        assert committed_handoff.handoff_revision == 2
        assert committed_handoff.observed_ref != h_inferred.observed_ref
        assert committed_handoff.current_revision > race_box[0].current_revision
        assert done_job is not None and done_job.state is JobState.SUCCEEDED
    finally:
        loop.stop()


def test_continuity_worker_before_owner_commit_crash_recovers_cleanly(trusted_tmp: Path) -> None:
    from superbrain.application.continuity_worker import ContinuityWorkerCoordinator
    from superbrain.storage.sessions import SessionStore

    clock = FakeClock(_START)
    mono = FakeMonotonicClock()
    os_ = os_adapters(clock=clock, monotonic=mono)
    root = trusted_tmp / "crash-before-commit"
    raw_sid = "CRASH_BEFORE_WORKER_COMMIT_SID"

    rt = _open_rt(root, os_, role="sp23-wc")
    try:
        sid = rt.policy.store_id
        _cred, ws, sref, task_id = _seed_session_and_task(rt, clock, trusted_tmp / "chk-wc", raw_sid=raw_sid)
        ss = SessionStore(rt.store, rt.policy)
        agent_ref = digest_bytes(b"live-agent-ref-before-crash")
        ss.apply_agent_handoff_patch(
            task_id=task_id,
            repo_id=ws.repo_id,
            checkout_id=ws.checkout_id,
            session_ref=sref,
            base_revision=0,
            agent_ref=agent_ref,
            now=clock.now(),
        )
        for seq in range(1, 21):
            ss.record_session_event(
                session_ref=sref,
                repo_id=ws.repo_id,
                checkout_id=ws.checkout_id,
                task_id=task_id,
                producer_stream="stream-wc",
                event=_ev(seq, session_ref=sref, recorded_at=clock.now(), stream="stream-wc"),
                now=clock.now(),
            )
    finally:
        rt.close()

    child_code = """
import datetime as dt, sys
from pathlib import Path
from superbrain.adapters.os import os_adapters
from superbrain.application.continuity_worker import ContinuityWorkerCoordinator
from superbrain.application.jobs import JobService
from superbrain.composition.kernel_projections import kernel_store_extensions
from superbrain.storage.idempotency import StagedKernelStore
from superbrain.storage.runtime import admit_existing_pair, open_runtime_under_lease
from superbrain.workers.executor import PRODUCTION_JOB_HANDLERS, JobExecutor
from tests.support.clock import FakeClock

class _Mono:
    def __init__(self) -> None:
        self._now = 1_000_000_000
    def monotonic_ns(self) -> int:
        return self._now

root, sid, task_id = sys.argv[1:4]
clock = FakeClock(dt.datetime(2026, 11, 21, 14, 0, tzinfo=dt.UTC))
mono = _Mono()
os_ = os_adapters(clock=clock, monotonic=mono)
handlers, kinds = kernel_store_extensions()
rt = open_runtime_under_lease(
    admit_existing_pair(Path(root), sid, os_, purpose="serve"), handlers=handlers, kinds=kinds
)
exec_ = JobExecutor(PRODUCTION_JOB_HANDLERS, mono.monotonic_ns)
exec_.start()
try:
    kstore = StagedKernelStore(rt.store, rt.policy, writer_epoch=rt.lease.epoch)
    svc = JobService(kstore, kstore, rt.policy, clock, writer_epoch=rt.lease.epoch)
    coord = ContinuityWorkerCoordinator(rt=rt, job_service=svc, executor=exec_, clock=clock, mono=mono.monotonic_ns)
    coord.enqueue_if_due(task_id=task_id, now=clock.now())
    coord.run_next(writer_epoch=rt.lease.epoch, now=clock.now())
finally:
    exec_.close(5.0)
    rt.close()
"""
    env = dict(os.environ)
    env["SUPERBRAIN_CRASHPOINT"] = "continuity.worker.before_owner_commit"
    env.pop("SUPERBRAIN_PAUSEPOINT", None)
    env["PYTHONUTF8"] = "1"
    proc = subprocess.run(
        [sys.executable, "-c", child_code, str(root), sid, task_id],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=30.0,
    )
    assert proc.returncode == 86, f"expected crash exit 86, got {proc.returncode}: {proc.stderr}"

    # Reopen after crash: stale leased/running job recovers & completes without losing events or clobbering agent_ref.
    rt2 = reopen_kernel_job_runtime(root, sid, os_)
    exec2 = JobExecutor(PRODUCTION_JOB_HANDLERS, mono.monotonic_ns)
    exec2.start()
    try:
        ss2 = SessionStore(rt2.store, rt2.policy)
        pre = ss2.read_task_handoff(task_id)
        assert pre is not None and pre.observed_ref is None and pre.agent_ref == agent_ref

        svc2, _ = kernel_job_service(rt2, clock)
        rec_counts = svc2.recover(rt2.lease.epoch)
        assert rec_counts.jobs_requeued >= 1

        coord2 = ContinuityWorkerCoordinator(
            rt=rt2, job_service=svc2, executor=exec2, clock=clock, mono=mono.monotonic_ns
        )
        assert coord2.run_next(writer_epoch=rt2.lease.epoch, now=clock.now()) is True
        post = ss2.read_task_handoff(task_id)
        assert post is not None
        assert post.observed_ref is not None
        assert post.agent_ref == agent_ref
        assert post.handoff_revision == 1
        assert DataRoot.at(root).store_db.exists()
    finally:
        exec2.close(BOUND_WAIT_S)
        rt2.close()


def test_four_policy_combinations_and_claim_plus_commit_recheck_case_59(trusted_tmp: Path) -> None:
    from superbrain.application.continuity_worker import ContinuityWorkerCoordinator
    from superbrain.storage.sessions import SessionStore

    clock = FakeClock(_START)
    mono = FakeMonotonicClock()
    os_ = os_adapters(clock=clock, monotonic=mono)

    # 1. All 4 combinations of (automatic_capture_enabled, manual_submission_enabled).
    for auto_cap, manual_sub in (
        (True, True),
        (True, False),
        (False, True),
        (False, False),
    ):
        case_dir = trusted_tmp / f"pol-{int(auto_cap)}-{int(manual_sub)}"
        rt = _open_rt(case_dir, os_, role=f"sp23-p-{int(auto_cap)}-{int(manual_sub)}")
        exec_ = JobExecutor(PRODUCTION_JOB_HANDLERS, mono.monotonic_ns)
        exec_.start()
        try:
            _cred, ws, sref, task_id = _seed_session_and_task(
                rt, clock, trusted_tmp / f"chk-p-{int(auto_cap)}-{int(manual_sub)}"
            )
            rt.policy.set_repo_policy(
                ws.repo_id,
                automatic_capture_enabled=auto_cap,
                manual_submission_enabled=manual_sub,
            )
            ss = SessionStore(rt.store, rt.policy)
            svc, _ = kernel_job_service(rt, clock)
            coord = ContinuityWorkerCoordinator(
                rt=rt, job_service=svc, executor=exec_, clock=clock, mono=mono.monotonic_ns
            )

            # Manual handoff patch checks manual_submission_enabled when submitted via coordinator/manual path.
            agent_ref = digest_bytes(f"manual-{auto_cap}-{manual_sub}".encode())
            if manual_sub:
                h_man = coord.submit_manual_handoff_patch(
                    task_id=task_id,
                    repo_id=ws.repo_id,
                    checkout_id=ws.checkout_id,
                    session_ref=sref,
                    base_revision=0,
                    agent_ref=agent_ref,
                    now=clock.now(),
                )
                assert h_man.agent_ref == agent_ref
            else:
                with pytest.raises(BrainError) as man_denied:
                    coord.submit_manual_handoff_patch(
                        task_id=task_id,
                        repo_id=ws.repo_id,
                        checkout_id=ws.checkout_id,
                        session_ref=sref,
                        base_revision=0,
                        agent_ref=agent_ref,
                        now=clock.now(),
                    )
                assert man_denied.value.code is ErrorCode.CAPABILITY_UNAVAILABLE

            for seq in range(1, 21):
                ss.record_session_event(
                    session_ref=sref,
                    repo_id=ws.repo_id,
                    checkout_id=ws.checkout_id,
                    task_id=task_id,
                    producer_stream="stream-pol",
                    event=_ev(seq, session_ref=sref, recorded_at=clock.now(), stream="stream-pol"),
                    now=clock.now(),
                )

            enq = coord.enqueue_if_due(task_id=task_id, now=clock.now())
            if auto_cap:
                assert enq is not None
                assert coord.run_next(writer_epoch=rt.lease.epoch, now=clock.now()) is True
                h_after = ss.read_task_handoff(task_id)
                assert h_after is not None and h_after.observed_ref is not None
                if not manual_sub:
                    # Capture-only (True, False): inferred handoff exists without manual patch!
                    assert h_after.agent_ref is None
                    assert h_after.handoff_revision == 0
                    assert h_after.task_state_source == "inferred"
            else:
                assert enq is None
                h_after = ss.read_task_handoff(task_id)
                assert h_after is not None and h_after.observed_ref is None
        finally:
            exec_.close(BOUND_WAIT_S)
            rt.close()

    # 2. Case 59: runtime toggle automatic_capture_enabled True -> False BEFORE Claim AND BETWEEN Claim & Commit!
    rt_flip = _open_rt(trusted_tmp / "pol-flip", os_, role="sp23-flip")
    exec_flip = JobExecutor(PRODUCTION_JOB_HANDLERS, mono.monotonic_ns)
    exec_flip.start()
    try:
        _cred, ws, sref, task_id = _seed_session_and_task(rt_flip, clock, trusted_tmp / "chk-flip")
        rt_flip.policy.set_repo_policy(ws.repo_id, automatic_capture_enabled=True, manual_submission_enabled=True)
        ss = SessionStore(rt_flip.store, rt_flip.policy)
        svc, _ = kernel_job_service(rt_flip, clock)
        coord = ContinuityWorkerCoordinator(
            rt=rt_flip, job_service=svc, executor=exec_flip, clock=clock, mono=mono.monotonic_ns
        )

        # Enqueue while automatic_capture_enabled=True, then flip to False BEFORE Claim.
        for seq in range(1, 21):
            ss.record_session_event(
                session_ref=sref,
                repo_id=ws.repo_id,
                checkout_id=ws.checkout_id,
                task_id=task_id,
                producer_stream="stream-f1",
                event=_ev(seq, session_ref=sref, recorded_at=clock.now(), stream="stream-f1"),
                now=clock.now(),
            )
        jid_pre_claim = coord.enqueue_if_due(task_id=task_id, now=clock.now())
        assert jid_pre_claim is not None
        rt_flip.policy.set_repo_policy(ws.repo_id, automatic_capture_enabled=False, manual_submission_enabled=True)
        assert coord.run_next(writer_epoch=rt_flip.lease.epoch, now=clock.now()) is False
        h_pre = ss.read_task_handoff(task_id)
        assert h_pre is not None and h_pre.observed_ref is None

        # Re-enable, execute Claim + Phase 2 Worker, then flip automatic_capture_enabled=False BEFORE Commit!
        rt_flip.policy.set_repo_policy(ws.repo_id, automatic_capture_enabled=True, manual_submission_enabled=True)
        jid_mid = coord.enqueue_if_due(task_id=task_id, now=clock.now())
        assert jid_mid is not None
        prepared = coord.claim_and_execute(writer_epoch=rt_flip.lease.epoch, now=clock.now())
        assert prepared is not None
        rt_flip.policy.set_repo_policy(ws.repo_id, automatic_capture_enabled=False, manual_submission_enabled=True)
        committed = coord.commit_prepared(prepared, now=clock.now())
        assert committed is None
        h_final = ss.read_task_handoff(task_id)
        assert h_final is not None and h_final.observed_ref is None
    finally:
        exec_flip.close(BOUND_WAIT_S)
        rt_flip.close()


def test_liveness_300s_1800s_crash_watermarks_and_ended_session_resumed_case_40(
    trusted_tmp: Path,
) -> None:
    from superbrain.ports.continuity import SessionState
    from superbrain.storage.sessions import SessionStore

    clock = FakeClock(_START)
    os_ = os_adapters(clock=clock)
    rt = _open_rt(trusted_tmp / "liveness", os_, role="sp23-live")
    try:
        _cred, ws, sref, task_id = _seed_session_and_task(rt, clock, trusted_tmp / "chk-live")
        del task_id
        ss = SessionStore(rt.store, rt.policy)

        # Feed sequence 5 first, then late out-of-order sequence 2 -> watermark stays at 5!
        clock.advance(dt.timedelta(seconds=10))
        ss.record_session_event(
            session_ref=sref,
            repo_id=ws.repo_id,
            checkout_id=ws.checkout_id,
            producer_stream="stream-wm",
            event=_ev(5, session_ref=sref, recorded_at=clock.now(), stream="stream-wm"),
            now=clock.now(),
        )
        assert ss.read_producer_watermark("stream-wm", repo_id=ws.repo_id, checkout_id=ws.checkout_id) == 5

        ss.record_session_event(
            session_ref=sref,
            repo_id=ws.repo_id,
            checkout_id=ws.checkout_id,
            producer_stream="stream-wm",
            event=_ev(2, session_ref=sref, recorded_at=clock.now(), stream="stream-wm"),
            now=clock.now(),
        )
        assert ss.read_producer_watermark("stream-wm", repo_id=ws.repo_id, checkout_id=ws.checkout_id) == 5

        t_last = clock.now()

        # At <= 300 s -> still active, no checkpoint.
        clock.set(t_last + dt.timedelta(seconds=300))
        rec_300, ck_300 = ss.refresh_session_liveness(session_ref=sref, checkout_id=ws.checkout_id, now=clock.now())
        assert rec_300.state is SessionState.ACTIVE and ck_300 is None

        # At 301 s (minute 6) -> active -> in_progress_unknown (takeover allowed without 30m checkpoint!).
        clock.set(t_last + dt.timedelta(seconds=301))
        rec_301, ck_301 = ss.refresh_session_liveness(session_ref=sref, checkout_id=ws.checkout_id, now=clock.now())
        assert rec_301.state is SessionState.IN_PROGRESS_UNKNOWN and ck_301 is None

        # At exact 1800 s -> still NO 1800s checkpoint yet.
        clock.set(t_last + dt.timedelta(seconds=1800))
        rec_1800, ck_1800 = ss.refresh_session_liveness(session_ref=sref, checkout_id=ws.checkout_id, now=clock.now())
        assert rec_1800.state is SessionState.IN_PROGRESS_UNKNOWN and ck_1800 is None

        # At 1801 s (> 1800 s) -> in_progress_unknown checkpoint created.
        clock.set(t_last + dt.timedelta(seconds=1801))
        rec_1801, ck_1801 = ss.refresh_session_liveness(session_ref=sref, checkout_id=ws.checkout_id, now=clock.now())
        assert rec_1801.state is SessionState.IN_PROGRESS_UNKNOWN and ck_1801 is not None

        # Hard kill without session_end event (Case 40): creates checkpoint immediately and stays != ended.
        _, ws2, sref2, _t2 = _seed_session_and_task(
            rt, clock, trusted_tmp / "chk-kill", raw_sid="RAW_HARD_KILL_SID", alias="repo-kill"
        )
        rec_killed, ck_killed = ss.refresh_session_liveness(
            session_ref=sref2, checkout_id=ws2.checkout_id, now=clock.now(), process_killed=True
        )
        assert rec_killed.state is SessionState.IN_PROGRESS_UNKNOWN
        assert rec_killed.ended_at is None
        assert rec_killed.state.value != SessionState.ENDED.value
        assert ck_killed is not None

        # Ended session preserves ENDED across ordinary post-end events, reopening ONLY on session_resumed.
        clock.advance(dt.timedelta(seconds=10))
        ss.record_session_event(
            session_ref=sref,
            repo_id=ws.repo_id,
            checkout_id=ws.checkout_id,
            producer_stream="stream-wm",
            event=_ev(
                6,
                session_ref=sref,
                recorded_at=clock.now(),
                kind="session_end",
                payload={"reason": "user_exit"},
                stream="stream-wm",
            ),
            now=clock.now(),
        )
        assert ss.get_session(sref, checkout_id=ws.checkout_id).state is SessionState.ENDED

        clock.advance(dt.timedelta(seconds=5))
        ss.record_session_event(
            session_ref=sref,
            repo_id=ws.repo_id,
            checkout_id=ws.checkout_id,
            producer_stream="stream-wm",
            event=_ev(
                7,
                session_ref=sref,
                recorded_at=clock.now(),
                kind="tool_post",
                payload={"tool": "Read", "summary": "late-after-end"},
                stream="stream-wm",
            ),
            now=clock.now(),
        )
        assert ss.get_session(sref, checkout_id=ws.checkout_id).state is SessionState.ENDED

        clock.advance(dt.timedelta(seconds=5))
        ss.record_session_event(
            session_ref=sref,
            repo_id=ws.repo_id,
            checkout_id=ws.checkout_id,
            producer_stream="stream-wm",
            event=_ev(
                8,
                session_ref=sref,
                recorded_at=clock.now(),
                kind="session_resumed",
                payload={"reason": "resumed"},
                stream="stream-wm",
            ),
            now=clock.now(),
        )
        assert ss.get_session(sref, checkout_id=ws.checkout_id).state is SessionState.ACTIVE

        # Long-running job event triggers durable LongRunningCheckpoint via continuity.refresh worker.
        from superbrain.application.continuity_worker import ContinuityWorkerCoordinator

        mono = FakeMonotonicClock()
        exec_lr = JobExecutor(PRODUCTION_JOB_HANDLERS, mono.monotonic_ns)
        exec_lr.start()
        try:
            _cred_lr, ws_lr, sref_lr, task_lr = _seed_session_and_task(
                rt, clock, trusted_tmp / "chk-lr", raw_sid="RAW_LONG_RUNNING_SID", alias="repo-lr"
            )
            svc_lr, _ = kernel_job_service(rt, clock)
            coord_lr = ContinuityWorkerCoordinator(
                rt=rt, job_service=svc_lr, executor=exec_lr, clock=clock, mono=mono.monotonic_ns
            )
            started_str = clock.now().astimezone(dt.UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            ss.record_session_event(
                session_ref=sref_lr,
                repo_id=ws_lr.repo_id,
                checkout_id=ws_lr.checkout_id,
                task_id=task_lr,
                producer_stream="stream-lr",
                event=_ev(
                    1,
                    session_ref=sref_lr,
                    recorded_at=clock.now(),
                    kind="long_running_job",
                    payload={
                        "status": "running",
                        "command": "uv run --locked pytest -q",
                        "cwd": "/workspace/repo-lr",
                        "source_revision": "cafe1234",
                        "pid": 9001,
                        "started_at": started_str,
                        "log_or_receipt_path": "artifacts/full-suite.log",
                        "next_action": "Inspect artifacts/full-suite.log and summarize failures",
                    },
                    stream="stream-lr",
                ),
                now=clock.now(),
            )
            clock.advance(dt.timedelta(seconds=60))
            assert coord_lr.enqueue_if_due(task_id=task_lr, now=clock.now()) is not None
            assert coord_lr.run_next(writer_epoch=rt.lease.epoch, now=clock.now()) is True
            ckpt = ss.read_long_running_checkpoint(task_lr)
            assert ckpt is not None
            assert ckpt.command == "uv run --locked pytest -q"
            assert ckpt.cwd == "/workspace/repo-lr"
            assert ckpt.source_revision == "cafe1234"
            assert ckpt.pid == 9001
            assert ckpt.started_at == started_str
            assert ckpt.log_or_receipt_path == "artifacts/full-suite.log"
            assert ckpt.next_action == "Inspect artifacts/full-suite.log and summarize failures"
        finally:
            exec_lr.close(BOUND_WAIT_S)
    finally:
        rt.close()
