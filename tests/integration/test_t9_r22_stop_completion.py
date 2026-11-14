"""Task6a.3: one shared cutoff governs owner work and shutdown classification.

Work drains inside one monotonic grace. Queued or preparing work cannot cross into execution or
commit after the cutoff. Cleanup after grace cannot become clean shutdown.
Real owner/runtime/lease are retained. Only the stop caller's return from Event.wait is delayed, after
the actual shared cutoff has elapsed. The timely-owner twin must still return STOPPED.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.application.deadlines import Reservation
from superbrain.application.jobs import JobService
from superbrain.composition.daemon_entry import DaemonTestHooks, create_daemon_owner_loop
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import (
    TOTAL_REQUEST_BUDGET_NS,
    CallResult,
    JobView,
    Principal,
    Scope,
    ShutdownReport,
    ShutdownState,
    ToolCommand,
)
from superbrain.storage.runtime import Runtime
from tests.integration.test_kernel_daemon import (
    _daemon_template as _daemon_template,
)
from tests.integration.test_kernel_daemon import (
    _DaemonTemplate,
    _DaemonTestDomain,
    _episode_args,
    _instantiate_case,
)
from tests.support.clock import FakeClock
from tests.support.inc2_fixture import enqueue_job, kernel_job_service, reopen_kernel_job_runtime


@pytest.mark.parametrize(
    ("late_owner", "work"),
    [
        pytest.param(False, "queued", id="timely-owner-queued-work"),
        pytest.param(True, "none", id="late-owner-delayed-stopper"),
        pytest.param(True, "queued", id="late-owner-queued-work"),
        pytest.param(True, "preparing", id="late-owner-preparing-work"),
        pytest.param(True, "readonly", id="late-owner-readonly-work"),
        pytest.param(True, "closing", id="late-runtime-close"),
    ],
)
def test_shutdown_result_follows_owner_completion_cutoff_not_stop_caller_scheduling(
    trusted_tmp: Path,
    _daemon_template: _DaemonTemplate,
    monkeypatch: pytest.MonkeyPatch,
    late_owner: bool,
    work: str,
) -> None:
    clock = FakeClock(_daemon_template.base_time + dt.timedelta(minutes=5))
    root, _, config = _instantiate_case(trusted_tmp, "r22-stop-completion", _daemon_template)
    adapters = os_adapters(clock=clock)
    workspace = _daemon_template.ws_a
    domain = _DaemonTestDomain(ws_a=workspace)
    entered = threading.Event()
    release_owner = threading.Event()
    stop_wait_started = threading.Event()
    stop_wait_expired = threading.Event()
    resume_stopper = threading.Event()
    stop_threads: list[threading.Thread] = []

    def hold_owner() -> bool:
        entered.set()
        return release_owner.wait(4.0)

    def hold_preparing(reservation: Reservation | None) -> None:
        assert reservation is not None
        assert hold_owner(), "test did not release preparing request"

    def hold_close(_runtime: Runtime) -> None:
        assert hold_owner(), "test did not release runtime close"

    domain_hooks = DaemonTestHooks(
        before_enter_commit=hold_preparing if work == "preparing" else None,
        before_runtime_close=hold_close if work == "closing" else None,
    )
    loop = create_daemon_owner_loop(
        os_=adapters,
        clock=clock,
        domain=domain,
        hooks=domain_hooks,
    )
    original_wait = loop._closed_done.wait
    internal_runs: list[str] = []
    idem_key = "idem-r23-stop-author-cutoff"

    def submit_episode() -> Future[CallResult]:
        return loop.submit(
            ToolCommand(
                "submit_episode", _episode_args(workspace, idem_key),
                token=_daemon_template.cred_a.token, selected_scope=Scope(workspace.repo_id, workspace.checkout_id),
            ),
            adapters.monotonic.monotonic_ns() + TOTAL_REQUEST_BUDGET_NS,
        )

    def stop_wait(timeout: float | None = None) -> bool:
        if threading.current_thread() not in stop_threads:
            return original_wait(timeout)
        stop_wait_started.set()
        result = original_wait(timeout)
        if not result:
            stop_wait_expired.set()
            assert resume_stopper.wait(4.0), "test did not release delayed stop caller"
        elif not late_owner:
            assert resume_stopper.wait(4.0), "test did not release timely-completion stop caller"
        return result

    def stop() -> ShutdownReport:
        stop_threads.append(threading.current_thread())
        return loop.stop(grace_s=0.03 if late_owner else 1.0)

    try:
        job_id = None
        if work == "readonly":
            runtime = reopen_kernel_job_runtime(root, _daemon_template.store_id, adapters)
            try:
                service, store = kernel_job_service(runtime, clock)
                job_id = enqueue_job(service, store, owner_id="dan", payload=b"r23-readonly-stop").job_id
            finally:
                runtime.close()
            original_get_job = JobService.get_job

            def get_job(
                service: JobService, job_id: str, principal: Principal, *, selected_scope: Scope | None,
            ) -> JobView:
                result = original_get_job(service, job_id, principal, selected_scope=selected_scope)
                assert hold_owner(), "test did not release read-only result"
                return result

            monkeypatch.setattr(JobService, "get_job", get_job)
        loop.start(config)
        owner_action = None
        user_work = None
        internal_work = None
        if job_id is not None:
            user_work = loop.submit(
                ToolCommand(
                    "get_job", {"schema_version": "2.0", "job_id": job_id}, token=_daemon_template.cred_a.token,
                ),
                adapters.monotonic.monotonic_ns() + TOTAL_REQUEST_BUDGET_NS,
            )
        elif work == "preparing":
            user_work = submit_episode()
        elif work != "closing":
            owner_action = loop.run_owner_action(hold_owner)
        if work != "closing":
            assert entered.wait(2.0)
        if work == "queued":
            internal_work = loop.run_owner_action(lambda: internal_runs.append("ran"))
            user_work = submit_episode()
        with monkeypatch.context() as hooks:
            hooks.setattr(loop._closed_done, "wait", stop_wait)
            with ThreadPoolExecutor(max_workers=1) as pool:
                stopping = pool.submit(stop)
                try:
                    assert stop_wait_started.wait(2.0), "stop did not install its shared cutoff"
                    if work == "closing":
                        assert entered.wait(2.0), "owner did not reach real runtime close"
                    if late_owner:
                        assert stop_wait_expired.wait(2.0), "owner was not held through the actual cutoff"
                        # Event.wait may round a short timeout slightly down on Windows.
                        # Establish actual monotonic expiry before releasing the owner.
                        while (remaining := loop._stop_wall_deadline - time.perf_counter()) > 0:
                            threading.Event().wait(remaining)
                        assert time.perf_counter() >= loop._stop_wall_deadline
                    release_owner.set()
                    if owner_action is not None:
                        assert owner_action.result(timeout=2.0) is True
                    assert original_wait(2.0), "owner did not complete real runtime cleanup"
                    if not late_owner:
                        assert time.perf_counter() < loop._stop_wall_deadline, (
                            "positive owner did not finish inside grace"
                        )
                        # Late observation by the caller must not turn timely completion into an overrun.
                        while (remaining := loop._stop_wall_deadline - time.perf_counter()) > 0:
                            threading.Event().wait(remaining)
                    assert not stopping.done(), "stop caller delay was not exercised"
                    resume_stopper.set()
                    report = stopping.result(timeout=2.0)
                finally:
                    release_owner.set()
                    resume_stopper.set()
        expected = ShutdownState.OVERRUN if late_owner else ShutdownState.STOPPED
        if user_work is not None:
            envelope = user_work.result(timeout=2.0)
            if late_owner:
                assert (internal_runs, domain.executed_keys, envelope["ok"]) == ([], [], False), (
                    "queued/preparing work crossed the owner cutoff"
                )
                error = envelope.get("error")
                assert isinstance(error, dict) and error["code"] == ErrorCode.DAEMON_UNAVAILABLE.value
                assert report.cancelled_requests == 1
                if internal_work is not None:
                    with pytest.raises(BrainError) as refused:
                        internal_work.result(timeout=2.0)
                    assert refused.value.code is ErrorCode.DAEMON_UNAVAILABLE
            else:
                assert internal_work is not None and internal_work.result(timeout=2.0) is None
                assert (internal_runs, domain.executed_keys, envelope["ok"]) == (["ran"], [idem_key], True)
                assert report.drained_requests == 1
        assert report.state is expected, "late owner cleanup was classified by stop-caller scheduling"
        assert report.error_code is (ErrorCode.DEADLINE_EXCEEDED if late_owner else None)
        assert report.endpoint_removed is True
        # A later stop cannot revise an overrun into a clean result or obtain a fresh grace.
        repeated = loop.stop(grace_s=1.0)
        assert repeated.state is expected
        assert repeated.error_code is report.error_code
        assert loop.wait_closed(timeout=0.0) == repeated
    finally:
        release_owner.set()
        resume_stopper.set()
        with contextlib.suppress(BrainError):
            loop.stop(grace_s=0.01)
        loop.wait_closed(timeout=2.0)


def test_shutdown_report_keeps_cancellations_observed_during_runtime_close(
    trusted_tmp: Path, _daemon_template: _DaemonTemplate,
) -> None:
    """Publish one cancellation in both the bounded stop and terminal reports."""
    _, _, config = _instantiate_case(trusted_tmp, "r24-stop-cancellation-count", _daemon_template)
    clock = FakeClock(_daemon_template.base_time + dt.timedelta(minutes=6))
    adapters = os_adapters(clock=clock)
    workspace = _daemon_template.ws_a
    domain = _DaemonTestDomain(ws_a=workspace)
    entered_reserve = threading.Event()
    release_reserve = threading.Event()
    entered_close = threading.Event()
    release_close = threading.Event()

    def reserve_held(_reservation: Reservation) -> None:
        entered_reserve.set()
        assert release_reserve.wait(4.0), "test did not release reserved request"

    def close_held(_runtime: Runtime) -> None:
        entered_close.set()
        assert release_close.wait(4.0), "test did not release runtime close"

    loop = create_daemon_owner_loop(
        os_=adapters,
        clock=clock,
        domain=domain,
        hooks=DaemonTestHooks(after_reserve_before_enqueue=reserve_held, before_runtime_close=close_held),
    )
    try:
        loop.start(config)
        with ThreadPoolExecutor(max_workers=2) as pool:
            try:
                submitted = pool.submit(
                    loop.submit,
                    ToolCommand(
                        "submit_episode", _episode_args(workspace, "idem-r24-cancellation-count"),
                        token=_daemon_template.cred_a.token,
                        selected_scope=Scope(workspace.repo_id, workspace.checkout_id),
                    ),
                    adapters.monotonic.monotonic_ns() + TOTAL_REQUEST_BUDGET_NS,
                )
                assert entered_reserve.wait(2.0), "request did not reach the real reservation boundary"
                stopping = pool.submit(loop.stop, grace_s=0.30)
                assert entered_close.wait(2.0), "owner did not reach real runtime close"
                first = stopping.result(timeout=2.0)
                assert first.state is ShutdownState.OVERRUN
                assert first.error_code is ErrorCode.DEADLINE_EXCEEDED
                assert first.endpoint_removed is False
                assert first.cancelled_requests == 1
                release_reserve.set()
                envelope = submitted.result(timeout=2.0).result(timeout=2.0)
                error = envelope.get("error")
                assert not envelope["ok"] and isinstance(error, dict)
                assert error["code"] == ErrorCode.DAEMON_UNAVAILABLE.value
                assert not domain.executed_keys
                release_close.set()
                final = loop.wait_closed(timeout=2.0)
                assert final is not None and final.endpoint_removed is True
                assert final.state is first.state and final.error_code is first.error_code
                repeated = loop.stop(grace_s=1.0)
                assert final.cancelled_requests == repeated.cancelled_requests == first.cancelled_requests, (
                    "terminal reports lost the cancellation accounted for during teardown"
                )
                assert repeated == final
            finally:
                release_reserve.set()
                release_close.set()
    finally:
        release_reserve.set()
        release_close.set()
        with contextlib.suppress(BrainError):
            loop.stop(grace_s=0.01)
        loop.wait_closed(timeout=2.0)
