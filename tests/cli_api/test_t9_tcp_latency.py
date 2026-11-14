"""W1 setup regression coverage beside the independently recorded real wire-budget RED.

The wire benchmark supplies the latency oracle. These cases retain real TCP, TLS, identity pinning
and owner admission while checking successful delivery and cleanup if socket configuration fails.
"""

from __future__ import annotations

import errno
import shutil
import socket
import ssl
import threading
from collections.abc import Iterator
from typing import Any

import pytest

from superbrain.cli_api.loopback import LoopbackTransportError
from superbrain.core.kernel import ToolCommand
from tests.support.inc2_transport import TransportTemplate, create_transport_template, open_test_loopback_transport


@pytest.fixture(scope="module")
def tcp_template() -> Iterator[TransportTemplate]:
    template = create_transport_template("t9-tcp-setup")
    try:
        yield template
    finally:
        shutil.rmtree(template.base_dir, ignore_errors=True)


def test_health_delivers_through_real_tls_after_connection_setup(tcp_template: TransportTemplate) -> None:
    with open_test_loopback_transport(tcp_template, name="tcp-health") as harness:
        result = harness.open_client().call(
            harness.make_target(),
            ToolCommand("get_health", {"schema_version": "2.0", "deep": False}, token=tcp_template.cred.token),
        )
        assert result["ok"] is True
        data = result.get("data")
        assert isinstance(data, dict) and data["store_id"] == tcp_template.store_id
        assert harness.submit_count == 1


def test_socket_configuration_failure_releases_slot_before_tls_and_next_connection_succeeds(
    tcp_template: TransportTemplate, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture,
) -> None:
    with open_test_loopback_transport(tcp_template, name="tcp-option-failure") as harness:
        failed = threading.Event()
        released = threading.Event()
        server_tls_wraps: list[bool] = []
        original_option = socket.socket.setsockopt
        original_wrap = ssl.SSLContext.wrap_socket
        original_release = harness.server._release_conn
        canary = "SYNTHETIC_SOCKET_OPTION_FAILURE_R26"

        def set_option(sock: socket.socket, level: int, option: int, value: Any, *rest: Any) -> None:
            if (
                threading.current_thread().name.startswith("superbrain-loopback-conn-")
                and level == socket.IPPROTO_TCP and option == socket.TCP_NODELAY
            ):
                failed.set()
                raise OSError(errno.EIO, canary)
            original_option(sock, level, option, value, *rest)

        def wrap(context: ssl.SSLContext, *args: Any, **kwargs: Any) -> ssl.SSLSocket:
            if kwargs.get("server_side") and threading.current_thread().name.startswith("superbrain-loopback-conn-"):
                server_tls_wraps.append(True)
            return original_wrap(context, *args, **kwargs)

        def release(
            conn_id: int, raw: socket.socket | None, secured: ssl.SSLSocket | None, *, drain: bool,
        ) -> None:
            original_release(conn_id, raw, secured, drain=drain)
            released.set()

        command = ToolCommand(
            "get_health", {"schema_version": "2.0", "deep": False}, token=tcp_template.cred.token,
        )
        client = harness.open_client()
        target = harness.make_target()
        with monkeypatch.context() as hooks:
            hooks.setattr(socket.socket, "setsockopt", set_option)
            hooks.setattr(ssl.SSLContext, "wrap_socket", wrap)
            hooks.setattr(harness.server, "_release_conn", release)
            with pytest.raises(LoopbackTransportError) as refused:
                client.call(target, command)
            assert failed.is_set(), "socket configuration fault was not exercised"
            assert refused.value.request_may_have_run is False
            assert released.wait(1.0), "failed setup did not release its connection slot"
            assert server_tls_wraps == [] and harness.submit_count == 0
            with harness.server._lock:
                assert harness.server._active_slots == 0
                assert harness.server._slot_owners == set()
                assert harness.server._workers == {} and harness.server._sockets == {}
            assert canary not in caplog.text

        result = client.call(target, command)
        assert result["ok"] is True and harness.submit_count == 1
        data = result.get("data")
        assert isinstance(data, dict) and data["store_id"] == tcp_template.store_id
