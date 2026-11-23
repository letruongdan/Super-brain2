"""SP2-3 application & OwnerLoop tests: 3-phase continuity.refresh worker, scheduling, races, policy matrix, liveness.

Requirement sources:
- docs/superpowers/specs/2026-10-30-super-brain2-system-design.md (§7.1-7.4, §20 cases 39, 40, 53, 54, 59)
- docs/superpowers/plans/2026-11-18-sp2-capture-continuity.md (SP2-3, lines 55-73, 158-181)
- docs/design/sp2-host-capture-matrix.md (§4, §4.2, SP2-3 crashpoints)
"""

from __future__ import annotations

import contextlib
import datetime as dt
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, cast

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.tls_material import create_store_tls
from superbrain.application.owner_loop import OwnerLoop
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
from superbrain.core.kernel import DaemonConfig, JobErrorCode, JobRecord, JobSpec, JobState, ObjectRef
from superbrain.ports.capture import CaptureEventRecord
from superbrain.ports.continuity import CONTINUITY_REFRESH_JOB_KIND
from superbrain.ports.os import OsAdapters
from superbrain.storage.idempotency import StagedKernelStore
from superbrain.storage.layout import DataRoot
from superbrain.storage.runtime import Runtime
from superbrain.storage.sqlite import open_readonly
from superbrain.workers.executor import PRODUCTION_JOB_HANDLERS, JobContext, JobExecutor, JobHandlerError
from tests.support.clock import FakeClock
from tests.support.inc2_fixture import (
    FIXTURE_JOB_KIND,
    ensure_template_base,
    kernel_job_service,
    open_kernel_job_runtime,
    reopen_kernel_job_runtime,
)
from tests.support.inc2_transport import FakeMonotonicClock, register_workspace_direct
from tests.support.kernel_auth import make_bootstrap_auth, seed_principal_and_credential

REPO_ROOT = Path(__file__).resolve().parents[2]
_START = dt.datetime(2026, 11, 21, 14, 0, tzinfo=dt.UTC)
BOUND_WAIT_S = 5.0


def _open_rt(root: Path, os_: OsAdapters, *, role: str = "sp23-continuity") -> Runtime:
    del role
    return open_kernel_job_runtime(root, os_, role="sp23-continuity")


_LOOP_TLS_CACHE: dict[str, tuple[Path, Path]] = {}


def _create_loop_cfg(
    root: Path,
    store_id: str,
    tls_dir: Path,
    clock: FakeClock,
    os_: OsAdapters,
) -> DaemonConfig:
    del tls_dir
    cached = _LOOP_TLS_CACHE.get(store_id)
    if cached is not None and cached[0].is_file() and cached[1].is_file():
        return DaemonConfig(1, root, store_id, cached[0], cached[1])

    target_dir = ensure_template_base() / f"loop-tls-{store_id}"
    if not (target_dir / "server.pem").is_file():
        tls = create_store_tls(
            store_id,
            target_dir,
            make_bootstrap_auth(
                store_id=store_id,
                owner_id="dan",
                action="provision_tls",
                subject_id=store_id,
                trust_generation=1,
                expires_at=clock.now() + dt.timedelta(days=365),
                destination=target_dir,
            ),
            clock,
            os_,
        )
        _LOOP_TLS_CACHE[store_id] = (tls.cert_path, tls.key_path)
        return DaemonConfig(1, root, store_id, tls.cert_path, tls.key_path)

    cert_path = target_dir / "server.pem"
    key_path = target_dir / "server.key"
    _LOOP_TLS_CACHE[store_id] = (cert_path, key_path)
    return DaemonConfig(1, root, store_id, cert_path, key_path)


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

    cfg = _create_loop_cfg(root_race, sid, trusted_tmp / "ol-tls", clock, os_)

    agent_ref_2 = digest_bytes(b"agent-patch-v2-concurrent")
    hook_fired = threading.Event()
    commit_done = threading.Event()
    race_box: list[Any] = []
    job_id_box: list[str] = []

    def _inject_concurrent_agent_patch_before_commit(session_rt: Runtime) -> None:
        # Runs strictly on owner thread right before Phase 3 commit (`continuity.worker.before_owner_commit`).
        ss_live = SessionStore(session_rt.store, session_rt.policy)
        live_state = ss_live.get_continuity_worker_state(task_id)
        assert live_state is not None and live_state.active_job_id is not None
        job_id_box.append(live_state.active_job_id)
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
        # The daemon schedules the 20 pending events itself (durable wake) and runs all three phases.
        assert hook_fired.wait(timeout=BOUND_WAIT_S)
        _wait_for_terminal_job(loop, job_id_box[0])
        commit_done.set()
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



def _wait_for_terminal_job(loop: OwnerLoop, job_id: str, *, timeout_s: float = BOUND_WAIT_S) -> JobRecord:
    deadline = time.monotonic() + timeout_s
    pause = threading.Event()
    while time.monotonic() < deadline:

        def _read() -> JobRecord | None:
            session: Any = loop._session
            assert session is not None
            ks = StagedKernelStore(session._rt.store, session._rt.policy, writer_epoch=session._rt.lease.epoch)
            return ks.transact(lambda tx: tx.read_job(job_id))

        rec = loop.run_owner_action(_read).result(timeout=timeout_s)
        if rec is not None and rec.state in (JobState.SUCCEEDED, JobState.FAILED, JobState.CANCELLED):
            return rec
        pause.wait(0.05)
    raise TimeoutError(f"timed out waiting for job {job_id} to reach terminal state")


def _seed_20_events(
    rt: Runtime,
    clock: FakeClock,
    checkout_dir: Path,
    *,
    raw_sid: str,
    alias: str,
    stream: str,
) -> tuple[Any, str, str]:
    from superbrain.storage.sessions import SessionStore

    _cred, ws, sref, task_id = _seed_session_and_task(
        rt, clock, checkout_dir, raw_sid=raw_sid, alias=alias
    )
    ss = SessionStore(rt.store, rt.policy)
    for seq in range(1, 21):
        ss.record_session_event(
            session_ref=sref,
            repo_id=ws.repo_id,
            checkout_id=ws.checkout_id,
            task_id=task_id,
            producer_stream=stream,
            event=_ev(seq, session_ref=sref, recorded_at=clock.now(), stream=stream),
            now=clock.now(),
        )
    return ws, sref, task_id


def test_owner_loop_fails_unhandled_kinds_and_completes_continuity_via_step_owner_work(
    trusted_tmp: Path,
) -> None:
    """A >100 unhandled-kind backlog fails with HANDLER_UNAVAILABLE (I2 contract) and the natural
    step_owner_work drain still runs the continuity.refresh phase-3 commit."""
    from superbrain.application.continuity_worker import ContinuityWorkerCoordinator
    from superbrain.storage.sessions import SessionStore

    clock = FakeClock(_START)
    mono = FakeMonotonicClock()
    os_ = os_adapters(clock=clock, monotonic=mono)
    root = trusted_tmp / "natural-backlog-isolation"

    rt = _open_rt(root, os_, role="sp23-ol-iso")
    try:
        sid = rt.policy.store_id
        _ws, _sref, task_id = _seed_20_events(
            rt,
            clock,
            trusted_tmp / "chk-ol-iso",
            raw_sid="RAW_OL_BACKLOG_ISOLATION",
            alias="repo-ol-iso",
            stream="stream-ol-iso",
        )
        svc, st_store = kernel_job_service(rt, clock)
        fixture_payload = b"unhandled-fixture-backlog"
        st_store.stage_blob(fixture_payload)
        fixture_spec = JobSpec(kind=FIXTURE_JOB_KIND, owner_id="dan", payload=fixture_payload)
        fixture_refs = st_store.transact(lambda tx: [svc.enqueue(tx, fixture_spec) for _ in range(105)])
        fixture_job_ids = [ref.job_id for ref in fixture_refs]
        assert len(fixture_job_ids) == 105

        # Advance past fixture retry_at so all 105 FIXTURE_JOB_KIND rows are due ahead of continuity.refresh.
        clock.advance(dt.timedelta(seconds=1))
        coord_seed = ContinuityWorkerCoordinator(rt=rt, job_service=svc, executor=None, clock=clock)
        continuity_job_id = coord_seed.enqueue_if_due(task_id=task_id, now=clock.now())
        assert continuity_job_id is not None
        pre_state = SessionStore(rt.store, rt.policy).get_continuity_worker_state(task_id)
        assert pre_state is not None and pre_state.pending_job_id == continuity_job_id
    finally:
        rt.close()

    cfg = _create_loop_cfg(root, sid, trusted_tmp / "tls-ol-iso", clock, os_)
    loop = create_daemon_owner_loop(
        os_=os_,
        clock=clock,
        monotonic_clock=mono,
        job_handlers=PRODUCTION_JOB_HANDLERS,
    )
    loop.start(cfg)
    try:
        done_job = _wait_for_terminal_job(loop, continuity_job_id)
        assert done_job.state is JobState.SUCCEEDED
        assert done_job.attempt == 1
        assert done_job.result_digest is not None

        def _inspect_owner_state() -> tuple[list[JobRecord], Any, Any]:
            session: Any = loop._session
            assert session is not None
            ks = StagedKernelStore(session._rt.store, session._rt.policy, writer_epoch=session._rt.lease.epoch)
            ss = SessionStore(session._rt.store, session._rt.policy)

            def _read_fixtures(tx: Any) -> list[JobRecord]:
                out: list[JobRecord] = []
                for jid in fixture_job_ids:
                    rec = tx.read_job(jid)
                    assert rec is not None
                    out.append(rec)
                return out

            fix_rows = ks.transact(_read_fixtures)
            return fix_rows, ss.read_task_handoff(task_id), ss.get_continuity_worker_state(task_id)

        fix_rows, handoff, wstate = loop.run_owner_action(_inspect_owner_state).result(timeout=BOUND_WAIT_S)
        assert len(fix_rows) == 105
        assert all(
            (row.state, row.reason, row.attempt) == (JobState.FAILED, JobErrorCode.HANDLER_UNAVAILABLE, 1)
            for row in fix_rows
        )
        assert handoff is not None
        assert handoff.observed_ref is not None and handoff.observed_ref.startswith("sha256:")
        assert handoff.task_state_source == "inferred"
        assert handoff.current_revision >= 1
        assert wstate is not None
        assert wstate.pending_event_count == 0
        assert wstate.pending_job_id is None
        assert wstate.active_job_id is None
        assert wstate.dirty_flag is False
        assert wstate.observed_through is not None
    finally:
        loop.stop()

    with contextlib.closing(open_readonly(DataRoot.at(root).store_db)) as conn:
        rows = conn.execute(
            "SELECT kind, meta FROM ledger WHERE kind IN ('job.leased', 'job.running', 'job.terminal')"
        ).fetchall()
    touched_by_kind: dict[str, set[str]] = {"job.leased": set(), "job.running": set(), "job.terminal": set()}
    for kind, meta_blob in rows:
        meta = json.loads(bytes(meta_blob).decode("utf-8"))
        touched_by_kind[str(kind)].add(str(meta["job_id"]))
    fixture_set = set(fixture_job_ids)
    assert fixture_set <= touched_by_kind["job.leased"]
    assert fixture_set <= touched_by_kind["job.terminal"]
    assert continuity_job_id in touched_by_kind["job.leased"]
    assert continuity_job_id in touched_by_kind["job.terminal"]


def test_owner_loop_step_owner_work_handles_worker_failed_and_midflight_policy_disable(
    trusted_tmp: Path,
) -> None:
    """Natural step_owner_work routes WorkerFailed and mid-flight policy disable without wedging in_flight state."""
    from superbrain.application.continuity_worker import ContinuityWorkerCoordinator
    from superbrain.storage.sessions import SessionStore

    clock = FakeClock(_START)
    mono = FakeMonotonicClock()
    os_ = os_adapters(clock=clock, monotonic=mono)

    # Sub-case A: WorkerFailed through natural step_owner_work calls handle_worker_failed
    # cleanly when policy disables automatic capture mid-flight.
    root_a = trusted_tmp / "ol-worker-failed"
    rt_a = _open_rt(root_a, os_, role="sp23-ol-wf")
    try:
        sid_a = rt_a.policy.store_id
        ws_a, _sref_a, task_a = _seed_20_events(
            rt_a,
            clock,
            trusted_tmp / "chk-ol-wf",
            raw_sid="RAW_OL_WORKER_FAILED",
            alias="repo-ol-wf",
            stream="stream-ol-wf",
        )
        svc_a, _ = kernel_job_service(rt_a, clock)
        fail_job_id = ContinuityWorkerCoordinator(
            rt=rt_a, job_service=svc_a, executor=None, clock=clock
        ).enqueue_if_due(task_id=task_a, now=clock.now())
        assert fail_job_id is not None
    finally:
        rt_a.close()

    handler_entered = threading.Event()
    release_handler = threading.Event()

    def _failing_continuity_handler(_spec: JobSpec, _ctx: JobContext) -> tuple[ObjectRef, ...]:
        handler_entered.set()
        release_handler.wait(timeout=BOUND_WAIT_S)
        raise JobHandlerError(JobErrorCode.HANDLER_FAILED, retryable=False)

    cfg_a = _create_loop_cfg(root_a, sid_a, trusted_tmp / "tls-ol-wf", clock, os_)
    loop_a = create_daemon_owner_loop(
        os_=os_,
        clock=clock,
        monotonic_clock=mono,
        job_handlers={CONTINUITY_REFRESH_JOB_KIND: _failing_continuity_handler},
    )
    loop_a.start(cfg_a)
    try:
        assert handler_entered.wait(timeout=BOUND_WAIT_S)

        def _disable_midflight() -> None:
            session: Any = loop_a._session
            assert session is not None
            session._rt.policy.set_repo_policy(
                ws_a.repo_id, automatic_capture_enabled=False, manual_submission_enabled=True
            )

        loop_a.run_owner_action(_disable_midflight).result(timeout=BOUND_WAIT_S)
        release_handler.set()

        failed_rec = _wait_for_terminal_job(loop_a, fail_job_id)
        assert failed_rec.state is JobState.FAILED
        assert failed_rec.reason is JobErrorCode.HANDLER_FAILED
        assert failed_rec.attempt == 1

        def _verify_cleared_and_reschedulable() -> tuple[Any, Any, str | None]:
            session: Any = loop_a._session
            assert session is not None
            ss = SessionStore(session._rt.store, session._rt.policy)
            wstate = ss.get_continuity_worker_state(task_a)
            handoff = ss.read_task_handoff(task_a)
            assert session._continuity_worker.enqueue_if_due(task_id=task_a, now=clock.now()) is None
            session._rt.policy.set_repo_policy(
                ws_a.repo_id, automatic_capture_enabled=True, manual_submission_enabled=True
            )
            re_enqueued = session._continuity_worker.enqueue_if_due(task_id=task_a, now=clock.now())
            return wstate, handoff, re_enqueued

        wstate_a, handoff_a, re_job_id = loop_a.run_owner_action(_verify_cleared_and_reschedulable).result(
            timeout=BOUND_WAIT_S
        )
        assert wstate_a is not None
        assert wstate_a.pending_job_id is None
        assert wstate_a.active_job_id is None
        assert wstate_a.pending_event_count == 20
        assert handoff_a is not None and handoff_a.observed_ref is None
        assert re_job_id is not None and re_job_id != fail_job_id
    finally:
        release_handler.set()
        loop_a.stop()

    # Sub-case B: PRODUCTION_JOB_HANDLERS completes Phase 2, then Phase 3 sees
    # automatic_capture_enabled=False mid-flight via before_continuity_worker_commit
    # inside natural step_owner_work and clears inflight state cleanly.
    root_b = trusted_tmp / "ol-midflight-disable"
    rt_b = _open_rt(root_b, os_, role="sp23-ol-md")
    try:
        sid_b = rt_b.policy.store_id
        ws_b, _sref_b, task_b = _seed_20_events(
            rt_b,
            clock,
            trusted_tmp / "chk-ol-md",
            raw_sid="RAW_OL_MIDFLIGHT_DISABLE",
            alias="repo-ol-md",
            stream="stream-ol-md",
        )
        svc_b, _ = kernel_job_service(rt_b, clock)
        mid_job_id = ContinuityWorkerCoordinator(
            rt=rt_b, job_service=svc_b, executor=None, clock=clock
        ).enqueue_if_due(task_id=task_b, now=clock.now())
        assert mid_job_id is not None
    finally:
        rt_b.close()

    disabled_once = threading.Event()

    def _disable_on_phase3_commit(session_rt: Runtime) -> None:
        if not disabled_once.is_set():
            disabled_once.set()
            session_rt.policy.set_repo_policy(
                ws_b.repo_id, automatic_capture_enabled=False, manual_submission_enabled=True
            )

    cfg_b = _create_loop_cfg(root_b, sid_b, trusted_tmp / "tls-ol-md", clock, os_)
    loop_b = create_daemon_owner_loop(
        os_=os_,
        clock=clock,
        monotonic_clock=mono,
        job_handlers=PRODUCTION_JOB_HANDLERS,
        hooks=DaemonTestHooks(before_continuity_worker_commit=_disable_on_phase3_commit),
    )
    loop_b.start(cfg_b)
    try:
        mid_rec = _wait_for_terminal_job(loop_b, mid_job_id)
        assert disabled_once.is_set()
        assert mid_rec.state is JobState.FAILED
        assert mid_rec.reason is JobErrorCode.HANDLER_FAILED

        def _verify_and_reenable() -> tuple[Any, Any, str]:
            session: Any = loop_b._session
            assert session is not None
            ss = SessionStore(session._rt.store, session._rt.policy)
            wstate = ss.get_continuity_worker_state(task_b)
            handoff = ss.read_task_handoff(task_b)
            session._rt.policy.set_repo_policy(
                ws_b.repo_id, automatic_capture_enabled=True, manual_submission_enabled=True
            )
            next_id = session._continuity_worker.enqueue_if_due(task_id=task_b, now=clock.now())
            assert next_id is not None
            return wstate, handoff, next_id

        wstate_b, handoff_b, next_job_id = loop_b.run_owner_action(_verify_and_reenable).result(
            timeout=BOUND_WAIT_S
        )
        assert wstate_b is not None
        assert wstate_b.pending_job_id is None
        assert wstate_b.active_job_id is None
        assert wstate_b.pending_event_count == 20
        assert handoff_b is not None and handoff_b.observed_ref is None
        assert next_job_id != mid_job_id

        recovered_rec = _wait_for_terminal_job(loop_b, next_job_id)
        assert recovered_rec.state is JobState.SUCCEEDED
    finally:
        loop_b.stop()



def test_owner_loop_claim_rechecks_automatic_capture_and_marks_admitted_job_running_case_59(
    trusted_tmp: Path,
) -> None:
    """The daemon claim path (not only ``claim_and_execute``) refuses a continuity job whose repo
    disabled automatic capture before the claim, and marks an admitted job as the active job."""
    from superbrain.application.continuity_worker import ContinuityWorkerCoordinator
    from superbrain.storage.sessions import SessionStore

    clock = FakeClock(_START)
    mono = FakeMonotonicClock()
    os_ = os_adapters(clock=clock, monotonic=mono)

    # Sub-case A: disabled before the claim -> the handler never runs, the job fails, inflight clears.
    root_a = trusted_tmp / "ol-claim-disabled"
    rt_a = _open_rt(root_a, os_, role="sp23-ol-cd")
    try:
        sid_a = rt_a.policy.store_id
        ws_a, _sref_a, task_a = _seed_20_events(
            rt_a,
            clock,
            trusted_tmp / "chk-ol-cd",
            raw_sid="RAW_OL_CLAIM_DISABLED",
            alias="repo-ol-cd",
            stream="stream-ol-cd",
        )
        svc_a, _ = kernel_job_service(rt_a, clock)
        job_a = ContinuityWorkerCoordinator(rt=rt_a, job_service=svc_a, executor=None, clock=clock).enqueue_if_due(
            task_id=task_a, now=clock.now()
        )
        assert job_a is not None
        rt_a.policy.set_repo_policy(ws_a.repo_id, automatic_capture_enabled=False, manual_submission_enabled=True)
    finally:
        rt_a.close()

    handler_calls: list[str] = []

    def _recording_handler(spec: JobSpec, ctx: JobContext) -> tuple[ObjectRef, ...]:
        handler_calls.append(spec.kind)
        refs: tuple[ObjectRef, ...] = PRODUCTION_JOB_HANDLERS[CONTINUITY_REFRESH_JOB_KIND](spec, ctx)
        return refs

    loop_a = create_daemon_owner_loop(
        os_=os_,
        clock=clock,
        monotonic_clock=mono,
        job_handlers={CONTINUITY_REFRESH_JOB_KIND: _recording_handler},
    )
    loop_a.start(_create_loop_cfg(root_a, sid_a, trusted_tmp / "tls-ol-cd", clock, os_))
    try:
        rec_a = _wait_for_terminal_job(loop_a, job_a)
        assert (rec_a.state, rec_a.reason, rec_a.attempt) == (JobState.FAILED, JobErrorCode.HANDLER_FAILED, 1)
        assert handler_calls == []

        def _read_a() -> tuple[Any, Any]:
            session: Any = loop_a._session
            assert session is not None
            ss = SessionStore(session._rt.store, session._rt.policy)
            return ss.get_continuity_worker_state(task_a), ss.read_task_handoff(task_a)

        wstate_a, handoff_a = loop_a.run_owner_action(_read_a).result(timeout=BOUND_WAIT_S)
        assert wstate_a is not None
        assert (wstate_a.pending_job_id, wstate_a.active_job_id) == (None, None)
        assert wstate_a.pending_event_count == 20
        assert handoff_a is not None and handoff_a.observed_ref is None
    finally:
        loop_a.stop()

    # Sub-case B (positive twin): enabled -> while the handler runs, the job is the active job.
    root_b = trusted_tmp / "ol-claim-enabled"
    rt_b = _open_rt(root_b, os_, role="sp23-ol-ce")
    try:
        sid_b = rt_b.policy.store_id
        _ws_b, _sref_b, task_b = _seed_20_events(
            rt_b,
            clock,
            trusted_tmp / "chk-ol-ce",
            raw_sid="RAW_OL_CLAIM_ENABLED",
            alias="repo-ol-ce",
            stream="stream-ol-ce",
        )
        svc_b, _ = kernel_job_service(rt_b, clock)
        job_b = ContinuityWorkerCoordinator(rt=rt_b, job_service=svc_b, executor=None, clock=clock).enqueue_if_due(
            task_id=task_b, now=clock.now()
        )
        assert job_b is not None
    finally:
        rt_b.close()

    entered = threading.Event()
    release = threading.Event()

    def _blocking_handler(spec: JobSpec, ctx: JobContext) -> tuple[ObjectRef, ...]:
        entered.set()
        release.wait(timeout=BOUND_WAIT_S)
        refs: tuple[ObjectRef, ...] = PRODUCTION_JOB_HANDLERS[CONTINUITY_REFRESH_JOB_KIND](spec, ctx)
        return refs

    loop_b = create_daemon_owner_loop(
        os_=os_,
        clock=clock,
        monotonic_clock=mono,
        job_handlers={CONTINUITY_REFRESH_JOB_KIND: _blocking_handler},
    )
    loop_b.start(_create_loop_cfg(root_b, sid_b, trusted_tmp / "tls-ol-ce", clock, os_))
    try:
        assert entered.wait(timeout=BOUND_WAIT_S)

        def _read_b() -> Any:
            session: Any = loop_b._session
            assert session is not None
            return SessionStore(session._rt.store, session._rt.policy).get_continuity_worker_state(task_b)

        mid = loop_b.run_owner_action(_read_b).result(timeout=BOUND_WAIT_S)
        assert mid is not None
        assert (mid.active_job_id, mid.pending_job_id) == (job_b, None)
        release.set()
        rec_b = _wait_for_terminal_job(loop_b, job_b)
        assert rec_b.state is JobState.SUCCEEDED
        after = loop_b.run_owner_action(_read_b).result(timeout=BOUND_WAIT_S)
        assert after is not None
        assert (after.active_job_id, after.pending_job_id, after.pending_event_count) == (None, None, 0)
    finally:
        release.set()
        loop_b.stop()


def test_unusable_worker_output_fails_job_and_clears_inflight_instead_of_leaving_it_running(
    trusted_tmp: Path,
) -> None:
    """Phase 3 with no staged worker output ends the job (HANDLER_FAILED) and frees the task."""
    from superbrain.application.continuity_worker import ContinuityWorkerCoordinator
    from superbrain.core.kernel import WorkerCompleted
    from superbrain.storage.sessions import SessionStore

    clock = FakeClock(_START)
    mono = FakeMonotonicClock()
    os_ = os_adapters(clock=clock, monotonic=mono)
    rt = _open_rt(trusted_tmp / "bad-output", os_, role="sp23-bad-out")
    try:
        _ws, _sref, task_id = _seed_20_events(
            rt,
            clock,
            trusted_tmp / "chk-bad-out",
            raw_sid="RAW_BAD_OUTPUT",
            alias="repo-bad-out",
            stream="stream-bad-out",
        )
        svc, kstore = kernel_job_service(rt, clock)
        coord = ContinuityWorkerCoordinator(rt=rt, job_service=svc, executor=None, clock=clock)
        job_id = coord.enqueue_if_due(task_id=task_id, now=clock.now())
        assert job_id is not None
        lease = svc.lease_next(rt.lease.epoch, clock.now())
        assert lease is not None and lease.job_id == job_id
        spec = svc.resolve_leased_spec(lease)
        assert spec is not None
        assert coord.admit_claimed(lease, spec, now=clock.now()) is not None

        never_staged = b"never-staged-observed-output"
        ref = ObjectRef("blob", new_id(), 1, digest_bytes(never_staged))
        assert coord.commit_worker_completed(WorkerCompleted(lease, (ref,)), now=clock.now()) is None

        row = kstore.transact(lambda tx: tx.read_job(job_id))
        assert row is not None
        assert (row.state, row.reason) == (JobState.FAILED, JobErrorCode.HANDLER_FAILED)
        ss = SessionStore(rt.store, rt.policy)
        wstate = ss.get_continuity_worker_state(task_id)
        assert wstate is not None
        assert (wstate.active_job_id, wstate.pending_job_id, wstate.pending_event_count) == (None, None, 20)
        handoff = ss.read_task_handoff(task_id)
        assert handoff is not None and handoff.observed_ref is None
        assert coord.enqueue_if_due(task_id=task_id, now=clock.now()) not in (None, job_id)
    finally:
        rt.close()


def test_claim_and_execute_fails_other_kinds_with_handler_unavailable_instead_of_leaving_them_leased(
    trusted_tmp: Path,
) -> None:
    """``claim_and_execute`` keeps the I2 contract for a kind it cannot run."""
    from superbrain.application.continuity_worker import ContinuityWorkerCoordinator

    clock = FakeClock(_START)
    mono = FakeMonotonicClock()
    os_ = os_adapters(clock=clock, monotonic=mono)
    rt = _open_rt(trusted_tmp / "other-kind", os_, role="sp23-other-kind")
    executor = JobExecutor(PRODUCTION_JOB_HANDLERS, mono.monotonic_ns)
    executor.start()
    try:
        svc, kstore = kernel_job_service(rt, clock)
        payload = b"other-kind-payload"
        kstore.stage_blob(payload)
        spec = JobSpec(kind=FIXTURE_JOB_KIND, owner_id="dan", payload=payload)
        ref = kstore.transact(lambda tx: svc.enqueue(tx, spec))
        coord = ContinuityWorkerCoordinator(
            rt=rt, job_service=svc, executor=executor, clock=clock, mono=mono.monotonic_ns
        )
        assert coord.claim_and_execute(writer_epoch=rt.lease.epoch, now=clock.now()) is None
        row = kstore.transact(lambda tx: tx.read_job(ref.job_id))
        assert row is not None
        assert (row.state, row.reason, row.attempt) == (JobState.FAILED, JobErrorCode.HANDLER_UNAVAILABLE, 1)
    finally:
        executor.close(BOUND_WAIT_S)
        rt.close()


def test_retryable_failure_keeps_inflight_until_dead_letter_then_clears(trusted_tmp: Path) -> None:
    """The task's inflight marker follows the job row: kept across retries, cleared at dead letter."""
    from superbrain.application.continuity_worker import ContinuityWorkerCoordinator
    from superbrain.core.kernel import MAX_JOB_ATTEMPTS, WorkerFailed
    from superbrain.storage.sessions import SessionStore

    clock = FakeClock(_START)
    mono = FakeMonotonicClock()
    os_ = os_adapters(clock=clock, monotonic=mono)
    rt = _open_rt(trusted_tmp / "retry-marker", os_, role="sp23-retry")
    try:
        _ws, _sref, task_id = _seed_20_events(
            rt,
            clock,
            trusted_tmp / "chk-retry",
            raw_sid="RAW_RETRY_MARKER",
            alias="repo-retry",
            stream="stream-retry",
        )
        svc, kstore = kernel_job_service(rt, clock)
        coord = ContinuityWorkerCoordinator(rt=rt, job_service=svc, executor=None, clock=clock)
        ss = SessionStore(rt.store, rt.policy)
        job_id = coord.enqueue_if_due(task_id=task_id, now=clock.now())
        assert job_id is not None
        for attempt in range(1, MAX_JOB_ATTEMPTS + 1):
            lease = svc.lease_next(rt.lease.epoch, clock.now())
            assert lease is not None and (lease.job_id, lease.attempt) == (job_id, attempt)
            spec = svc.resolve_leased_spec(lease)
            assert spec is not None
            assert coord.admit_claimed(lease, spec, now=clock.now()) is not None
            coord.handle_worker_failed(WorkerFailed(lease, True, JobErrorCode.HANDLER_FAILED), now=clock.now())
            row = kstore.transact(lambda tx: tx.read_job(job_id))
            wstate = ss.get_continuity_worker_state(task_id)
            assert row is not None and wstate is not None
            if attempt < MAX_JOB_ATTEMPTS:
                assert row.state is JobState.QUEUED
                assert job_id in (wstate.active_job_id, wstate.pending_job_id)
                assert coord.enqueue_if_due(task_id=task_id, now=clock.now()) is None
            else:
                assert (row.state, row.reason) == (JobState.DEAD_LETTER, JobErrorCode.HANDLER_FAILED)
                assert (wstate.active_job_id, wstate.pending_job_id) == (None, None)
            clock.advance(dt.timedelta(seconds=5))
        assert coord.enqueue_if_due(task_id=task_id, now=clock.now()) not in (None, job_id)
    finally:
        rt.close()


def test_admit_claimed_fails_job_whose_task_row_is_missing(trusted_tmp: Path) -> None:
    """A continuity job naming a task with no ``tasks`` row ends (INVALID_PAYLOAD) instead of staying leased."""
    from superbrain.application.continuity_worker import ContinuityWorkerCoordinator

    clock = FakeClock(_START)
    mono = FakeMonotonicClock()
    os_ = os_adapters(clock=clock, monotonic=mono)
    rt = _open_rt(trusted_tmp / "missing-task", os_, role="sp23-missing-task")
    try:
        svc, kstore = kernel_job_service(rt, clock)
        payload = json.dumps({"task_id": f"task-{new_id()}"}).encode("utf-8")
        kstore.stage_blob(payload)
        spec = JobSpec(kind=CONTINUITY_REFRESH_JOB_KIND, owner_id="dan", payload=payload)
        ref = kstore.transact(lambda tx: svc.enqueue(tx, spec))
        lease = svc.lease_next(rt.lease.epoch, clock.now())
        assert lease is not None and lease.job_id == ref.job_id
        leased_spec = svc.resolve_leased_spec(lease)
        assert leased_spec is not None
        coord = ContinuityWorkerCoordinator(rt=rt, job_service=svc, executor=None, clock=clock)
        assert coord.admit_claimed(lease, leased_spec, now=clock.now()) is None
        row = kstore.transact(lambda tx: tx.read_job(ref.job_id))
        assert row is not None
        assert (row.state, row.reason) == (JobState.FAILED, JobErrorCode.INVALID_PAYLOAD)
    finally:
        rt.close()


def test_stale_inflight_marker_of_an_ended_job_does_not_block_rescheduling(trusted_tmp: Path) -> None:
    """A marker left behind by a crash between ending a job and clearing it is reconciled against the job row."""
    from superbrain.application.continuity_worker import ContinuityWorkerCoordinator
    from superbrain.core.kernel import JobOutcome
    from superbrain.storage.sessions import SessionStore

    clock = FakeClock(_START)
    mono = FakeMonotonicClock()
    os_ = os_adapters(clock=clock, monotonic=mono)
    rt = _open_rt(trusted_tmp / "stale-marker", os_, role="sp23-stale")
    try:
        _ws, _sref, task_id = _seed_20_events(
            rt,
            clock,
            trusted_tmp / "chk-stale",
            raw_sid="RAW_STALE_MARKER",
            alias="repo-stale",
            stream="stream-stale",
        )
        svc, _ = kernel_job_service(rt, clock)
        coord = ContinuityWorkerCoordinator(rt=rt, job_service=svc, executor=None, clock=clock)
        ss = SessionStore(rt.store, rt.policy)
        first = coord.enqueue_if_due(task_id=task_id, now=clock.now())
        assert first is not None
        lease = svc.lease_next(rt.lease.epoch, clock.now())
        assert lease is not None
        spec = svc.resolve_leased_spec(lease)
        assert spec is not None
        assert coord.admit_claimed(lease, spec, now=clock.now()) is not None
        # Positive twin: while the job is live the marker blocks a second job.
        assert coord.enqueue_if_due(task_id=task_id, now=clock.now()) is None
        # Simulated crash: the job ends but its marker is never cleared.
        svc.complete(lease, JobOutcome.failure(JobErrorCode.HANDLER_FAILED, retryable=False))
        stale = ss.get_continuity_worker_state(task_id)
        assert stale is not None and stale.active_job_id == first

        second = coord.enqueue_if_due(task_id=task_id, now=clock.now())
        assert second is not None and second != first
        after = ss.get_continuity_worker_state(task_id)
        assert after is not None
        assert (after.active_job_id, after.pending_job_id) == (None, second)
    finally:
        rt.close()


def test_enqueue_and_pending_marker_commit_in_one_transaction(trusted_tmp: Path) -> None:
    """If recording the pending marker fails, the job is not enqueued either (no orphan job)."""
    from superbrain.application.continuity_worker import ContinuityWorkerCoordinator
    from superbrain.storage.sessions import SessionStore

    clock = FakeClock(_START)
    mono = FakeMonotonicClock()
    os_ = os_adapters(clock=clock, monotonic=mono)
    rt = _open_rt(trusted_tmp / "atomic-enqueue", os_, role="sp23-atomic")
    try:
        _ws, _sref, task_id = _seed_20_events(
            rt,
            clock,
            trusted_tmp / "chk-atomic",
            raw_sid="RAW_ATOMIC_ENQUEUE",
            alias="repo-atomic",
            stream="stream-atomic",
        )
        svc, _ = kernel_job_service(rt, clock)
        real = SessionStore(rt.store, rt.policy)

        class _FailingReserve:
            def __getattr__(self, name: str) -> Any:
                return getattr(real, name)

            def reserve_pending_job_in_tx(self, tx: object, task_id: str, job_id: str) -> None:
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, "injected")

        coord = ContinuityWorkerCoordinator(
            rt=rt, job_service=svc, executor=None, clock=clock, store_adapter=cast(Any, _FailingReserve())
        )
        with pytest.raises(BrainError):
            coord.enqueue_if_due(task_id=task_id, now=clock.now())
        assert rt.store._db.execute("SELECT COUNT(*) FROM p_jobs_state").fetchone()[0] == 0
        wstate = real.get_continuity_worker_state(task_id)
        assert wstate is not None and wstate.pending_job_id is None

        # Positive twin: the real store records both together.
        good = ContinuityWorkerCoordinator(rt=rt, job_service=svc, executor=None, clock=clock)
        job_id = good.enqueue_if_due(task_id=task_id, now=clock.now())
        assert job_id is not None
        assert rt.store._db.execute("SELECT COUNT(*) FROM p_jobs_state").fetchone()[0] == 1
        after = real.get_continuity_worker_state(task_id)
        assert after is not None and after.pending_job_id == job_id
    finally:
        rt.close()


_SENTINELS = ("SENTINEL_CMD_7F3A", "SENTINEL_PATH_7F3A", "SENTINEL_TEXT_7F3A", "SENTINEL_LR_7F3A")


def _record_sentinel_events(rt: Runtime, clock: FakeClock, ws: Any, sref: str, task_id: str, stream: str) -> None:
    from superbrain.storage.sessions import SessionStore

    ss = SessionStore(rt.store, rt.policy)
    payloads: list[tuple[str, dict[str, Any]]] = [
        ("tool_post", {"tool": "Bash", "command": f"pytest {_SENTINELS[0]}", "exit_code": 1}),
        ("tool_post", {"tool": "Edit", "file_path": f"src/{_SENTINELS[1]}.py"}),
        ("user_prompt", {"text": f"never use {_SENTINELS[2]} again"}),
        (
            "long_running_job",
            {"status": "running", "pid": 4242, "command": f"make {_SENTINELS[3]}", "cwd": "/w", "next_action": "wait"},
        ),
    ]
    for seq, (kind, payload) in enumerate(payloads, start=1):
        ss.record_session_event(
            session_ref=sref,
            repo_id=ws.repo_id,
            checkout_id=ws.checkout_id,
            task_id=task_id,
            producer_stream=stream,
            event=_ev(seq, session_ref=sref, recorded_at=clock.now(), kind=kind, payload=payload, stream=stream),
            now=clock.now(),
        )


def _cells_containing(rt: Runtime, needle: str) -> list[str]:
    hits: list[str] = []
    db = rt.store._db
    tables = [str(r[0]) for r in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()]
    for table in tables:
        for row in db.execute(f'SELECT * FROM "{table}"').fetchall():
            for cell in row:
                text = cell.decode("utf-8", "replace") if isinstance(cell, bytes) else str(cell)
                if needle in text:
                    hits.append(table)
    return hits


def test_observed_part_job_payload_and_checkpoint_keep_refs_only_and_follow_source_expiry(trusted_tmp: Path) -> None:
    """Spec 5.6 / 7.4: the observed part holds only (kind, source_event_id, source_digest); nothing copied from
    an event outlives it. Content is rebuilt from the live source and disappears when the source expires."""
    from superbrain.application.continuity_worker import ContinuityWorkerCoordinator
    from superbrain.storage.kinds import RetentionClass
    from superbrain.storage.retention import expire_due
    from superbrain.storage.sessions import SessionStore

    clock = FakeClock(_START)
    mono = FakeMonotonicClock()
    os_ = os_adapters(clock=clock, monotonic=mono)
    rt = _open_rt(trusted_tmp / "refs-only", os_, role="sp23-refs")
    executor = JobExecutor(PRODUCTION_JOB_HANDLERS, mono.monotonic_ns)
    executor.start()
    try:
        _cred, ws, sref, task_id = _seed_session_and_task(rt, clock, trusted_tmp / "chk-refs", raw_sid="RAW_REFS_ONLY")
        _record_sentinel_events(rt, clock, ws, sref, task_id, "stream-refs")
        svc, kstore = kernel_job_service(rt, clock)
        coord = ContinuityWorkerCoordinator(
            rt=rt, job_service=svc, executor=executor, clock=clock, mono=mono.monotonic_ns
        )
        clock.advance(dt.timedelta(seconds=61))
        job_id = coord.enqueue_if_due(task_id=task_id, now=clock.now())
        assert job_id is not None
        job_row = kstore.transact(lambda tx: tx.read_job(job_id))
        assert job_row is not None
        job_payload = rt.store.cas.read(job_row.payload_digest)
        assert all(s.encode() not in job_payload for s in _SENTINELS), "job payload copies event content"

        assert coord.run_next(writer_epoch=rt.lease.epoch, now=clock.now()) is True
        ss = SessionStore(rt.store, rt.policy)
        handoff = ss.read_task_handoff(task_id)
        assert handoff is not None and handoff.observed_ref is not None
        observed = json.loads(rt.store.cas.read(handoff.observed_ref).decode("utf-8"))
        assert all(s not in json.dumps(observed) for s in _SENTINELS), "observed part copies event content"
        kinds = {item[0] for item in observed["items"]}
        assert {"command_exit", "file_changed", "user_message", "long_running"} <= kinds
        event_ids = {f"evt-cw-stream-refs-{seq}" for seq in range(1, 5)}
        assert {item[1] for item in observed["items"]} <= event_ids
        assert all(item[2].startswith("sha256:") for item in observed["items"])
        assert all(ret is not RetentionClass.DURABLE for _k, _h, ret in rt.store.cas.holders(handoff.observed_ref))
        for sentinel in _SENTINELS:
            assert _cells_containing(rt, sentinel) == [], f"{sentinel} copied into SQLite"

        # While the source lives, the checkpoint fields are rebuilt from it.
        live_ckpt = ss.read_long_running_checkpoint(task_id)
        assert live_ckpt is not None and live_ckpt.command == f"make {_SENTINELS[3]}" and live_ckpt.pid == 4242

        # After the 90-day event retention the source is gone: no field can be served and nothing is rebuilt.
        clock.advance(dt.timedelta(days=91))
        expire_due(rt.store, rt.policy, clock.now())
        assert ss.read_long_running_checkpoint(task_id) is None
        rebuilt = json.loads(ss.resolve_refresh_sources(job_payload, now=clock.now()).decode("utf-8"))
        assert rebuilt["events"] == []
    finally:
        executor.close(BOUND_WAIT_S)
        rt.close()


@pytest.mark.parametrize("block", ["quarantine", "expiry", "tombstone", "unlinked", "forged_id", "principal"])
def test_source_blocked_between_claim_and_commit_fails_the_commit(trusted_tmp: Path, block: str) -> None:
    """Commit rechecks every source: quarantine, expiry and tombstone after the claim leave the observed part
    unchanged and end the job instead of publishing refs to blocked content. Review r6 finding 2 (spec 7.4): a
    source whose task link no longer verifies, or a pinned event ID that is not the event's, fails the same way."""
    import dataclasses

    from superbrain.application.continuity_worker import ContinuityWorkerCoordinator
    from superbrain.ports.policy import IntentKind
    from superbrain.storage.retention import expire_due
    from superbrain.storage.sessions import SessionStore

    clock = FakeClock(_START)
    mono = FakeMonotonicClock()
    os_ = os_adapters(clock=clock, monotonic=mono)
    rt = _open_rt(trusted_tmp / f"block-{block}", os_, role=f"sp23-block-{block}")
    executor = JobExecutor(PRODUCTION_JOB_HANDLERS, mono.monotonic_ns)
    executor.start()
    try:
        _cred, ws, sref, task_id = _seed_session_and_task(
            rt, clock, trusted_tmp / f"chk-block-{block}", raw_sid=f"RAW_BLOCK_{block.upper()}"
        )
        _record_sentinel_events(rt, clock, ws, sref, task_id, f"stream-block-{block}")
        svc, kstore = kernel_job_service(rt, clock)
        coord = ContinuityWorkerCoordinator(
            rt=rt, job_service=svc, executor=executor, clock=clock, mono=mono.monotonic_ns
        )
        clock.advance(dt.timedelta(seconds=61))
        job_id = coord.enqueue_if_due(task_id=task_id, now=clock.now())
        assert job_id is not None
        prepared = coord.claim_and_execute(writer_epoch=rt.lease.epoch, now=clock.now())
        assert prepared is not None and prepared.source_events

        stream, seq, _event_id, digest = prepared.source_events[0]
        if block == "quarantine":
            rt.policy.record_intent(IntentKind.QUARANTINE, {"digest": digest})
        elif block == "expiry":
            clock.advance(dt.timedelta(days=91))
            expire_due(rt.store, rt.policy, clock.now())
        elif block == "unlinked":
            with rt.store.transaction() as txn:
                txn.db.execute(
                    "UPDATE capture_events SET session_ref = ? WHERE producer_stream = ? AND sequence = ?",
                    ("sha256:" + "cd" * 32, stream, seq),
                )
        elif block == "principal":
            # Review r7 finding 2: event and session rows name another principal than the policy.db binding.
            with rt.store.transaction() as txn:
                txn.db.execute(
                    "UPDATE capture_events SET principal_id = 'principal-other' WHERE session_ref = ?", (sref,)
                )
                txn.db.execute("UPDATE sessions SET principal_id = 'principal-other' WHERE session_ref = ?", (sref,))
        elif block == "tombstone":
            holder = rt.store._db.execute(
                "SELECT cas_holder_id FROM capture_events WHERE producer_stream = ? AND sequence = ?", (stream, seq)
            ).fetchone()
            assert holder is not None
            rt.policy.record_intent(IntentKind.TOMBSTONE, {"holder_kind": "event", "holder_id": str(holder[0])})
        else:
            prepared = dataclasses.replace(
                prepared, source_events=((stream, seq, "evt-forged", digest), *prepared.source_events[1:])
            )

        assert coord.commit_prepared(prepared, now=clock.now()) is None
        row = kstore.transact(lambda tx: tx.read_job(job_id))
        assert row is not None and (row.state, row.reason) == (JobState.FAILED, JobErrorCode.HANDLER_FAILED)
        handoff = SessionStore(rt.store, rt.policy).read_task_handoff(task_id)
        assert handoff is not None and handoff.observed_ref is None
    finally:
        executor.close(BOUND_WAIT_S)
        rt.close()


def test_durable_scan_reaches_a_due_task_behind_a_full_page_of_tasks_that_cannot_move(trusted_tmp: Path) -> None:
    """Case 54 at scale: a page of pending tasks whose repo disabled capture must not hide a due task behind it,
    also when the daemon restarts in the middle of a rotation (a fresh coordinator starts from the first page)."""
    from superbrain.application.continuity_worker import ContinuityWorkerCoordinator
    from superbrain.storage.sessions import SessionStore

    clock = FakeClock(_START)
    mono = FakeMonotonicClock()
    os_ = os_adapters(clock=clock, monotonic=mono)
    rt = _open_rt(trusted_tmp / "scan-page", os_, role="sp23-scan-page")
    try:
        _cred_a, ws_a, sref_a, _first = _seed_session_and_task(
            rt, clock, trusted_tmp / "chk-scan-a", raw_sid="RAW_SCAN_A", alias="repo-scan-a"
        )
        ss = SessionStore(rt.store, rt.policy)
        blocked_tasks = [f"task-scan-blocked-{i:02d}" for i in range(50)]
        for i, tid in enumerate(blocked_tasks):
            ss.ensure_task_handoff(
                task_id=tid, repo_id=ws_a.repo_id, checkout_id=ws_a.checkout_id, session_ref=sref_a, now=clock.now()
            )
            ss.record_session_event(
                session_ref=sref_a,
                repo_id=ws_a.repo_id,
                checkout_id=ws_a.checkout_id,
                task_id=tid,
                producer_stream="stream-scan-a",
                event=_ev(i + 1, session_ref=sref_a, recorded_at=clock.now(), stream="stream-scan-a"),
                now=clock.now(),
            )
        clock.advance(dt.timedelta(seconds=1))
        cred_b = seed_principal_and_credential(rt.policy, owner_id="dan", harness_id="claude-code", machine_id="m-w1")
        ws_b = register_workspace_direct(
            rt, clock, cred_b.principal, alias="repo-scan-b", checkout_dir=trusted_tmp / "chk-scan-b",
            remote="https://github.example/dan/repo-scan-b.git",
        )
        rt.store.reconcile_policy()
        assert ws_b.repo_id != ws_a.repo_id
        sref_b = ss.bind_session(
            principal_id=cred_b.principal.principal_id, repo_id=ws_b.repo_id, checkout_id=ws_b.checkout_id,
            harness_id="claude-code", raw_session_id="RAW_SCAN_B", now=clock.now(),
        ).session_ref
        live_task = f"task-{new_id()}"
        ss.ensure_task_handoff(
            task_id=live_task, repo_id=ws_b.repo_id, checkout_id=ws_b.checkout_id, session_ref=sref_b, now=clock.now()
        )
        ss.record_session_event(
            session_ref=sref_b,
            repo_id=ws_b.repo_id,
            checkout_id=ws_b.checkout_id,
            task_id=live_task,
            producer_stream="stream-scan-b",
            event=_ev(1, session_ref=sref_b, recorded_at=clock.now(), stream="stream-scan-b"),
            now=clock.now(),
        )
        rt.policy.set_repo_policy(ws_a.repo_id, automatic_capture_enabled=False, manual_submission_enabled=True)
        rt.policy.set_repo_policy(ws_b.repo_id, automatic_capture_enabled=True, manual_submission_enabled=True)
        clock.advance(dt.timedelta(seconds=61))
        svc, _ = kernel_job_service(rt, clock)

        def _live_pending() -> str | None:
            state = ss.get_continuity_worker_state(live_task)
            assert state is not None
            return state.pending_job_id

        # One scan, then a restart: the next coordinator has no cursor and starts again from the first page.
        ContinuityWorkerCoordinator(rt=rt, job_service=svc, executor=None, clock=clock).enqueue_due(
            now=clock.now(), limit=50
        )
        assert _live_pending() is None
        restarted = ContinuityWorkerCoordinator(rt=rt, job_service=svc, executor=None, clock=clock)
        for _ in range(2):
            restarted.enqueue_due(now=clock.now(), limit=50)
        assert _live_pending() is not None, "due task behind 50 blocked tasks was never scheduled"
        assert all(
            (state := ss.get_continuity_worker_state(tid)) is not None and state.pending_job_id is None
            for tid in blocked_tasks
        )
    finally:
        rt.close()


def test_expired_batch_closes_at_its_pinned_cutoff_without_empty_revisions(trusted_tmp: Path) -> None:
    """A batch whose events expired before the claim ends at the job's pinned cutoff: one job, no new revision,
    nothing left pending, and no further job for the same events."""
    from superbrain.application.continuity_worker import ContinuityWorkerCoordinator
    from superbrain.storage.retention import expire_due
    from superbrain.storage.sessions import SessionStore

    clock = FakeClock(_START)
    mono = FakeMonotonicClock()
    os_ = os_adapters(clock=clock, monotonic=mono)
    rt = _open_rt(trusted_tmp / "cutoff-expired", os_, role="sp23-cutoff-exp")
    executor = JobExecutor(PRODUCTION_JOB_HANDLERS, mono.monotonic_ns)
    executor.start()
    try:
        _cred, ws, sref, task_id = _seed_session_and_task(
            rt, clock, trusted_tmp / "chk-cutoff-exp", raw_sid="RAW_CUT_EXP"
        )
        ss = SessionStore(rt.store, rt.policy)
        ss.record_session_event(
            session_ref=sref, repo_id=ws.repo_id, checkout_id=ws.checkout_id, task_id=task_id,
            producer_stream="stream-cut-exp",
            event=_ev(1, session_ref=sref, recorded_at=clock.now(), stream="stream-cut-exp"),
            now=clock.now(),
        )
        svc, kstore = kernel_job_service(rt, clock)
        coord = ContinuityWorkerCoordinator(
            rt=rt, job_service=svc, executor=executor, clock=clock, mono=mono.monotonic_ns
        )
        clock.advance(dt.timedelta(days=91))
        expire_due(rt.store, rt.policy, clock.now())
        job_id = coord.enqueue_if_due(task_id=task_id, now=clock.now())
        assert job_id is not None
        assert coord.run_next(writer_epoch=rt.lease.epoch, now=clock.now()) is False
        row = kstore.transact(lambda tx: tx.read_job(job_id))
        assert row is not None and row.state is JobState.SUCCEEDED
        handoff = ss.read_task_handoff(task_id)
        assert handoff is not None and handoff.current_revision == 0 and handoff.observed_ref is None
        state = ss.get_continuity_worker_state(task_id)
        assert state is not None
        assert (state.pending_event_count, state.pending_job_id, state.active_job_id) == (0, None, None)
        clock.advance(dt.timedelta(seconds=61))
        assert coord.enqueue_if_due(task_id=task_id, now=clock.now()) is None
    finally:
        executor.close(BOUND_WAIT_S)
        rt.close()


def test_mixed_batch_commits_live_events_closes_at_cutoff_and_keeps_later_events(trusted_tmp: Path) -> None:
    """Expired prefix, live middle and quarantined suffix: the commit observes only the live events, the batch
    closes at its cutoff, and an event that arrives after the cutoff stays pending for the next run."""
    from superbrain.application.continuity_worker import ContinuityWorkerCoordinator
    from superbrain.ports.policy import IntentKind
    from superbrain.storage.retention import expire_due
    from superbrain.storage.sessions import SessionStore

    clock = FakeClock(_START)
    mono = FakeMonotonicClock()
    os_ = os_adapters(clock=clock, monotonic=mono)
    rt = _open_rt(trusted_tmp / "cutoff-mixed", os_, role="sp23-cutoff-mix")
    executor = JobExecutor(PRODUCTION_JOB_HANDLERS, mono.monotonic_ns)
    executor.start()
    try:
        _cred, ws, sref, task_id = _seed_session_and_task(
            rt, clock, trusted_tmp / "chk-cutoff-mix", raw_sid="RAW_CUT_MIX"
        )
        ss = SessionStore(rt.store, rt.policy)
        stream = "stream-cut-mix"

        def _record(seq: int) -> None:
            ss.record_session_event(
                session_ref=sref, repo_id=ws.repo_id, checkout_id=ws.checkout_id, task_id=task_id,
                producer_stream=stream,
                event=_ev(seq, session_ref=sref, recorded_at=clock.now(), stream=stream,
                          payload={"tool": "Edit", "file_path": f"f{seq}.py"}),
                now=clock.now(),
            )

        _record(1)  # will expire
        clock.advance(dt.timedelta(days=10))
        _record(2)  # stays live
        _record(3)  # will be quarantined
        clock.advance(dt.timedelta(days=85))  # event 1 is past its 90 days, events 2 and 3 are not
        expire_due(rt.store, rt.policy, clock.now())
        digest3 = rt.store._db.execute(
            "SELECT payload_digest FROM capture_events WHERE producer_stream = ? AND sequence = 3", (stream,)
        ).fetchone()
        assert digest3 is not None
        rt.policy.record_intent(IntentKind.QUARANTINE, {"digest": str(digest3[0])})

        svc, _ = kernel_job_service(rt, clock)
        coord = ContinuityWorkerCoordinator(
            rt=rt, job_service=svc, executor=executor, clock=clock, mono=mono.monotonic_ns
        )
        job_id = coord.enqueue_if_due(task_id=task_id, now=clock.now())
        assert job_id is not None
        prepared = coord.claim_and_execute(writer_epoch=rt.lease.epoch, now=clock.now())
        assert prepared is not None
        assert [src[1] for src in prepared.source_events] == [2]
        _record(4)  # after the pinned cutoff
        outcome = coord.commit_prepared(prepared, now=clock.now())
        assert outcome is not None and outcome.current_revision == 1
        state = ss.get_continuity_worker_state(task_id)
        assert state is not None and state.pending_event_count == 1
        observed = json.loads(rt.store.cas.read(outcome.observed_ref).decode("utf-8"))
        assert {item[1] for item in observed["items"]} == {f"evt-cw-{stream}-2"}
    finally:
        executor.close(BOUND_WAIT_S)
        rt.close()
