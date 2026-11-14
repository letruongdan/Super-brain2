"""F11: one cutoff remains binding when the OS coalesces timed joins.

The real loopback server, TLS sockets and held connection workers are retained. Only the caller's
external clock and Thread.join timeout return are modeled. The leeway curve fits the recorded M1
samples (about 5.65 ms extra for a 1 ms wait and 69.25 ms extra for a 25 ms wait). No join slice size
is required: observable cutoff, graceful completion and late-wait behavior form the oracle.
"""

from __future__ import annotations

import shutil
import ssl
import threading
import time
from collections.abc import Iterator
from typing import Any

import pytest

from superbrain.cli_api import _loopback_server as server_module
from superbrain.cli_api._server_http import handle_identity_request
from tests.support.inc2_transport import TransportTemplate, create_transport_template, open_test_loopback_transport


@pytest.fixture(scope="module")
def wait_template() -> Iterator[TransportTemplate]:
    template = create_transport_template("r21-join-clock")
    try:
        yield template
    finally:
        shutil.rmtree(template.base_dir, ignore_errors=True)


class _JoinLeeway:
    def __init__(self, held: set[threading.Thread], release: threading.Event, deadline: float, graceful: bool) -> None:
        self._real_now = time.perf_counter
        self._real_join = threading.Thread.join
        self._caller = threading.get_ident()
        self._held = held
        self._release = release
        self.now = deadline - 0.03
        self._release_at = self.now + 0.005 if graceful else None
        self.waits: list[tuple[float, float]] = []

    def clock(self) -> float:
        return self.now if threading.get_ident() == self._caller else self._real_now()

    def join(self, thread: threading.Thread, timeout: float | None = None) -> None:
        if threading.get_ident() != self._caller:
            self._real_join(thread, timeout)
            return
        assert timeout is not None, "finish made an unbounded join"
        self.waits.append((self.now, timeout))
        if thread not in self._held or not thread.is_alive() or timeout <= 0:
            self._real_join(thread, timeout)
            return
        if self._release_at is not None and self._release_at <= self.now + timeout:
            self.now = max(self.now, self._release_at)
            self._release.set()
            self._real_join(thread, 1.0)
            assert not thread.is_alive(), "released connection worker did not exit"
            return
        # A timeout can return late even though its requested interval was within the budget.
        self.now += timeout + min(0.075, 0.003 + 2.65 * timeout)


@pytest.mark.parametrize("graceful", [False, True], ids=["held-workers", "released-before-cutoff"])
def test_finish_honors_cutoff_under_observed_join_leeway(
    wait_template: TransportTemplate, monkeypatch: pytest.MonkeyPatch, graceful: bool,
) -> None:
    with open_test_loopback_transport(wait_template, name="r21-join-leeway") as harness:
        entered = threading.Event()
        release = threading.Event()
        entered_lock = threading.Lock()
        count = 0
        original = handle_identity_request

        def held_identity(*args: Any, **kwargs: Any) -> Any:
            nonlocal count
            with entered_lock:
                count += 1
                if count == 5:
                    entered.set()
            assert release.wait(2.0), "test did not release connection workers"
            return original(*args, **kwargs)

        sockets: list[ssl.SSLSocket] = []
        try:
            with monkeypatch.context() as hooks:
                hooks.setattr(server_module, "handle_identity_request", held_identity)
                frame = f"GET /v2/identity HTTP/1.1\r\nHost: 127.0.0.1:{harness.ready.endpoint.port}\r\n\r\n".encode()
                for _ in range(5):
                    conn = harness.open_raw_tls_socket()
                    sockets.append(conn)
                    conn.sendall(frame)
                assert entered.wait(2.0), "five real workers did not reach the identity barrier"

                # Quiesce first and settle the accept thread, so the model isolates held-worker waits.
                # The caller clock then represents the final 30 ms of that same immutable cutoff.
                deadline = time.perf_counter() + 2.0
                harness.server.quiesce(deadline)
                accept = harness.server._accept_thread
                assert accept is not None
                accept.join(1.0)
                assert not accept.is_alive()
                with harness.server._lock:
                    held = set(harness.server._workers.values())
                assert len(held) == 5 and all(thread.is_alive() for thread in held)
                model = _JoinLeeway(held, release, deadline, graceful)
                with monkeypatch.context() as os_hooks:
                    os_hooks.setattr(time, "perf_counter", model.clock)

                    def modeled_join(thread: threading.Thread, timeout: float | None = None) -> None:
                        model.join(thread, timeout)

                    os_hooks.setattr(threading.Thread, "join", modeled_join)
                    finished = harness.server.finish(deadline)
                positive_waits = [(start, timeout) for start, timeout in model.waits if timeout > 0]
                assert all(start < deadline and timeout <= deadline - start + 1e-9 for start, timeout in positive_waits)
                if graceful:
                    assert finished is True and release.is_set()
                    assert model.now < deadline, "graceful work was not allowed to finish inside its grace"
                else:
                    assert finished is False and not release.is_set()
                    assert all(thread.is_alive() for thread in held)
                    assert model.now - deadline <= 0.06, "finish exceeded the original 60 ms post-cutoff bound"
        finally:
            release.set()
            for conn in sockets:
                conn.close()
