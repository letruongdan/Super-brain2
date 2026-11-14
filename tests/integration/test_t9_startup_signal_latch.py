"""I2-T7-R05: a signal before READY aborts startup, even if background stop conversion is delayed.

The real serve/owner/TLS lifecycle runs. The test only delays background Event.set and records cleanup;
the installed signal handler still receives a real signal. The no-signal twin must publish READY once.
Existing signal-lock and conversion tests cover handler reentrancy and eventual background conversion.
"""

from __future__ import annotations

import shutil
import signal
import threading
from collections.abc import Iterator
from typing import Any

import pytest

from superbrain.application.owner_loop import OwnerLoop
from superbrain.cli_api._loopback_server import LoopbackServer
from superbrain.composition.daemon_entry import DaemonTestHooks, serve
from superbrain.core.kernel import DaemonConfig, Endpoint, Ready
from tests.support.inc2_transport import (
    TransportTemplate,
    clone_owner_only_tree,
    create_transport_template,
    make_trusted_test_dir,
)


@pytest.fixture(scope="module")
def template() -> Iterator[TransportTemplate]:
    value = create_transport_template("t9-startup-signal-latch")
    try:
        yield value
    finally:
        shutil.rmtree(value.base_dir, ignore_errors=True)


@pytest.mark.parametrize("seam", ["no-signal", "owner-startup", "transport-start"])
@pytest.mark.parametrize("signame", ["SIGTERM", "SIGINT"])
def test_stop_before_ready_does_not_depend_on_background_event_conversion(
    template: TransportTemplate, monkeypatch: pytest.MonkeyPatch, seam: str, signame: str,
) -> None:
    assert threading.current_thread() is threading.main_thread()
    base = make_trusted_test_dir("t9-startup-signal-latch-case")
    root = base / "data"
    clone_owner_only_tree(template.root, root)
    cfg = DaemonConfig(version=1, data_root=root, expected_store_id=template.store_id,
                       cert_path=template.tls.cert_path, key_path=template.tls.key_path)
    conversion_entered = threading.Event()
    release_conversion = threading.Event()
    conversion_expired = threading.Event()

    class DelayedBackgroundStop(threading.Event):
        def set(self) -> None:
            if threading.current_thread() is not threading.main_thread():
                conversion_entered.set()
                if not release_conversion.wait(5.0):
                    conversion_expired.set()
            super().set()

    stop = DelayedBackgroundStop()
    fired: list[str] = []
    ready_calls: list[Ready] = []
    trace: list[str] = []

    def fire(at: str) -> None:
        if seam == at:
            fired.append(at)
            signal.raise_signal(getattr(signal, signame))

    original_start = LoopbackServer.start
    original_quiesce = LoopbackServer.quiesce
    original_stop = OwnerLoop.stop
    original_finish = LoopbackServer.finish

    def start(server: LoopbackServer) -> None:
        fire("transport-start")
        original_start(server)

    def quiesce(server: LoopbackServer, *args: Any, **kwargs: Any) -> Any:
        if "finish" not in trace:
            trace.append("quiesce")
        return original_quiesce(server, *args, **kwargs)

    def owner_stop(owner: OwnerLoop, *args: Any, **kwargs: Any) -> Any:
        trace.append("owner_stop")
        release_conversion.set()
        return original_stop(owner, *args, **kwargs)

    def finish(server: LoopbackServer, *args: Any, **kwargs: Any) -> Any:
        trace.append("finish")
        return original_finish(server, *args, **kwargs)

    def ready(value: Ready, _owner: OwnerLoop) -> None:
        ready_calls.append(value)
        stop.set()  # real positive control and bounded escape if a regression publishes READY

    def before_publish(_endpoint: Endpoint) -> None:
        fire("owner-startup")

    try:
        with monkeypatch.context() as patch:
            patch.setattr(LoopbackServer, "start", start)
            patch.setattr(LoopbackServer, "quiesce", quiesce)
            patch.setattr(OwnerLoop, "stop", owner_stop)
            patch.setattr(LoopbackServer, "finish", finish)
            rc = serve(cfg, stop_event=stop, shutdown_grace_s=5.0, on_ready=ready,
                       hooks=DaemonTestHooks(before_endpoint_publish=before_publish))
        expected_ready = 1 if seam == "no-signal" else 0
        assert len(ready_calls) == expected_ready, "a pre-READY signal was published as successful startup"
        assert rc == (0 if seam == "no-signal" else 1)
        assert fired == ([] if seam == "no-signal" else [seam])
        assert not conversion_expired.is_set(), "background conversion did not reach cleanup release"
        assert trace == ["quiesce", "owner_stop", "finish"]
        assert stop.is_set() and not (root / "endpoint.json").exists()
        if seam != "no-signal":
            assert conversion_entered.is_set(), "the signal never requested background conversion"
    finally:
        release_conversion.set()
        shutil.rmtree(base, ignore_errors=True)
