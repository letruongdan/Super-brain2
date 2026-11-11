"""I2-T7-R05 composition: ``serve``'s signal guard spans startup through cleanup, with Task 6b's order inside it.

Requirement (docs/reviews/2026-11-11-sp1-increment2-task7-rereview-7b3a711.md): keep the signal guard covering the
Task 7 lifecycle and the Task 6b cleanup sequence in ``daemon_entry.py``. So a stop signal arriving at any point from
owner startup to the last cleanup step becomes a stop request and never reaches the handler installed before
``serve``, and cleanup still runs transport quiesce, then owner stop, then transport finish, then the overrun wait.

The real ``serve`` runs on the main thread, because the guard is a no-op elsewhere. Real signals are raised at each
seam. The wrappers only record the call and raise the signal; the real method always runs, except that the overrun
cases relabel the stop report so the final wait is reached.
"""

from __future__ import annotations

import dataclasses
import shutil
import signal
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from types import FrameType
from typing import Any

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.application.owner_loop import OwnerLoop
from superbrain.cli_api._loopback_server import LoopbackServer
from superbrain.composition._daemon_session import DaemonTestHooks
from superbrain.composition.daemon_entry import serve
from superbrain.core.kernel import DaemonConfig, Endpoint, Ready, ShutdownReport, ShutdownState
from superbrain.storage.runtime import admit_existing_pair
from tests.support.inc2_transport import (
    TransportTemplate,
    clone_owner_only_tree,
    create_transport_template,
    make_trusted_test_dir,
)

_SIGNALS: tuple[signal.Signals, ...] = (
    signal.SIGINT,
    signal.SIGTERM,
    *((signal.Signals(signal.SIGBREAK),) if hasattr(signal, "SIGBREAK") else ()),
)
_SERVE_WATCHDOG_S = 30.0
_CLEANUP_ORDER = ["quiesce", "owner_stop", "finish"]


@dataclass(frozen=True)
class _Case:
    signal_at: str
    stop_at: str = ""
    rc: int = 0
    ready_calls: int = 1
    overrun: bool = False


_CASES = {
    # A signal during startup is itself the stop request, so startup aborts as for a preset stop.
    "owner-startup": _Case(signal_at="owner_startup", rc=1, ready_calls=0),
    "transport-start": _Case(signal_at="transport_start", rc=1, ready_calls=0),
    "on-ready": _Case(signal_at="on_ready"),
    # Normal cleanup after a stop requested once ready.
    "cleanup-quiesce": _Case(signal_at="quiesce", stop_at="on_ready"),
    "cleanup-owner-stop": _Case(signal_at="owner_stop", stop_at="on_ready"),
    "cleanup-finish": _Case(signal_at="finish", stop_at="on_ready"),
    "cleanup-overrun-wait": _Case(signal_at="wait_closed", stop_at="on_ready", rc=1, overrun=True),
    # Startup-abort cleanup after a stop requested during transport start.
    "aborted-quiesce": _Case(signal_at="quiesce", stop_at="transport_start", rc=1, ready_calls=0),
    "aborted-owner-stop": _Case(signal_at="owner_stop", stop_at="transport_start", rc=1, ready_calls=0),
    "aborted-finish": _Case(signal_at="finish", stop_at="transport_start", rc=1, ready_calls=0),
    "aborted-overrun-wait": _Case(
        signal_at="wait_closed", stop_at="transport_start", rc=1, ready_calls=0, overrun=True
    ),
}


@pytest.fixture(scope="module")
def template() -> Iterator[TransportTemplate]:
    tmpl = create_transport_template("t7-signal-lifecycle")
    try:
        yield tmpl
    finally:
        shutil.rmtree(tmpl.base_dir, ignore_errors=True)


@pytest.mark.parametrize("case", [pytest.param(case, id=name) for name, case in _CASES.items()])
def test_stop_signal_is_contained_through_serve_lifecycle_and_cleanup_keeps_order(
    template: TransportTemplate,
    monkeypatch: pytest.MonkeyPatch,
    case: _Case,
) -> None:
    assert threading.current_thread() is threading.main_thread(), "the signal guard only applies on the main thread"

    case_dir = make_trusted_test_dir("t7-signal-lifecycle-case")
    data_root = case_dir / "data"
    clone_owner_only_tree(template.root, data_root)
    cfg = DaemonConfig(
        version=1,
        data_root=data_root,
        expected_store_id=template.store_id,
        cert_path=template.tls.cert_path,
        key_path=template.tls.key_path,
    )

    stop = threading.Event()
    fired: list[str] = []
    leaked: list[int] = []
    trace: list[str] = []
    ready_calls: list[Ready] = []

    def _at(seam: str) -> None:
        if seam == case.stop_at:
            stop.set()
        if seam == case.signal_at and not fired:
            fired.append(seam)
            for sig in _SIGNALS:
                signal.raise_signal(sig)

    def _prior_handler(signum: int, _frame: FrameType | None) -> None:
        leaked.append(signum)

    orig_start = LoopbackServer.start
    orig_quiesce = LoopbackServer.quiesce
    orig_finish = LoopbackServer.finish
    orig_owner_stop = OwnerLoop.stop
    orig_wait_closed = OwnerLoop.wait_closed

    def _start(self: LoopbackServer) -> None:
        _at("transport_start")
        orig_start(self)

    def _quiesce(self: LoopbackServer, *args: Any, **kwargs: Any) -> Any:
        if "finish" not in trace:  # finish() re-enters quiesce() internally; only serve's own call is a cleanup step.
            trace.append("quiesce")
            _at("quiesce")
        return orig_quiesce(self, *args, **kwargs)

    def _finish(self: LoopbackServer, *args: Any, **kwargs: Any) -> Any:
        trace.append("finish")
        _at("finish")
        return orig_finish(self, *args, **kwargs)

    def _owner_stop(self: OwnerLoop, *args: Any, **kwargs: Any) -> ShutdownReport:
        trace.append("owner_stop")
        _at("owner_stop")
        report = orig_owner_stop(self, *args, **kwargs)
        return dataclasses.replace(report, state=ShutdownState.OVERRUN) if case.overrun else report

    def _wait_closed(self: OwnerLoop, timeout: float | None = None) -> ShutdownReport | None:
        if timeout is None:  # The ready loop polls with a timeout; only the blocking wait is the cleanup step.
            trace.append("wait_closed")
            _at("wait_closed")
        return orig_wait_closed(self, timeout)

    def _on_ready(ready: Ready, _loop: OwnerLoop) -> None:
        ready_calls.append(ready)
        _at("on_ready")

    def _before_endpoint_publish(_endpoint: Endpoint) -> None:
        _at("owner_startup")

    # A guard that fails to convert the signal would otherwise leave serve waiting for a stop that never comes.
    watchdog = threading.Timer(_SERVE_WATCHDOG_S, stop.set)
    watchdog.daemon = True
    saved = {sig: signal.getsignal(sig) for sig in _SIGNALS}
    try:
        for sig in _SIGNALS:
            signal.signal(sig, _prior_handler)
        with monkeypatch.context() as mp:
            mp.setattr(LoopbackServer, "start", _start)
            mp.setattr(LoopbackServer, "quiesce", _quiesce)
            mp.setattr(LoopbackServer, "finish", _finish)
            mp.setattr(OwnerLoop, "stop", _owner_stop)
            mp.setattr(OwnerLoop, "wait_closed", _wait_closed)
            watchdog.start()
            rc = serve(
                cfg,
                stop_event=stop,
                shutdown_grace_s=5.0,
                on_ready=_on_ready,
                hooks=DaemonTestHooks(before_endpoint_publish=_before_endpoint_publish),
            )
        watchdog_expired = watchdog.finished.is_set()
        watchdog.cancel()
        handlers_after = {sig: signal.getsignal(sig) for sig in _SIGNALS}

        assert fired == [case.signal_at], f"signal seam never reached: fired={fired}, trace={trace}"
        assert leaked == [], f"signals reached the pre-serve handler: {leaked}"
        assert not watchdog_expired, "the signal did not become a stop request"
        assert stop.is_set()
        assert rc == case.rc
        assert len(ready_calls) == case.ready_calls
        assert trace == [*_CLEANUP_ORDER, *(["wait_closed"] if case.overrun else [])]
        assert all(handlers_after[sig] is _prior_handler for sig in _SIGNALS), "serve did not restore signal handlers"
        assert not (data_root / "endpoint.json").exists()
        with admit_existing_pair(data_root, template.store_id, os_adapters(), purpose="serve") as admitted:
            assert admitted is not None
    finally:
        watchdog.cancel()
        for sig, handler in saved.items():
            signal.signal(sig, handler)
        shutil.rmtree(case_dir, ignore_errors=True)
