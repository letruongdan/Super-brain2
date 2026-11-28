"""Contract tests for test-only pre-identity TLS socket readiness causal barrier."""

from __future__ import annotations

import os
import queue
import shutil
import socket
import threading
import time
from pathlib import Path
from typing import Any

import pytest

import tests.support._socket_readiness_hook as readiness_hook
import tests.support.inc2_native_owner as owner
from superbrain.cli_api import _loopback_server
from superbrain.cli_api.loopback import LoopbackTransportError
from superbrain.core.kernel import ToolCommand
from tests.support.inc2_cli import _STRIPPED_ENV_KEYS
from tests.support.inc2_transport import create_transport_template, open_test_loopback_transport


def _drain_owner_events(eq: queue.Queue[dict[str, Any] | None]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    while not eq.empty():
        ev = eq.get_nowait()
        if ev is not None:
            events.append(ev)
    return events


def _join_loopback_conn_threads() -> None:
    for th in threading.enumerate():
        if th.name.startswith("superbrain-loopback-conn-") and th.is_alive():
            th.join(timeout=2.0)


def test_socket_readiness_causal_barrier_waits_for_slow_lookup_and_preserves_sighting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Client holds socket open on pre-identity readiness until slow lookup resolves client PID."""
    token = "tok-causal-barrier-01"
    readiness_hook.uninstall()
    readiness_hook.install()
    tmpl = create_transport_template("t9-r40-causal")
    try:
        monkeypatch.setenv("SUPERBRAIN_TEST_SOCKET_READINESS", token)
        eq_live: queue.Queue[dict[str, Any] | None] = queue.Queue()
        os_pid = os.getpid()
        orig_handle_ident: Any = _loopback_server.handle_identity_request
        ident_seen_before_lookup: list[bool] = []
        lookup_finished_ev = threading.Event()
        lookup_observed: dict[str, Any] = {}

        def _spied_orig_ident(
            ssl_sock: Any,
            reader: Any,
            ready: Any,
            *,
            deadline_ns: int,
            monotonic_ns: Any,
        ) -> bool:
            ident_seen_before_lookup.append(not lookup_finished_ev.is_set())
            return bool(
                orig_handle_ident(
                    ssl_sock,
                    reader,
                    ready,
                    deadline_ns=deadline_ns,
                    monotonic_ns=monotonic_ns,
                )
            )

        monkeypatch.setattr(_loopback_server, "handle_identity_request", _spied_orig_ident)
        live_state = owner._install_loopback_server_hooks(
            eq=eq_live,
            daemon_pid=os_pid,
            daemon_started_at=owner.process_started_at_for_pid(os_pid),
            store_id=tmpl.store_id,
            instance_id="inst-r40-causal",
            collector_timeout_s=1.0,
            socket_readiness_token=token,
        )
        try:
            with open_test_loopback_transport(tmpl, name="r40-causal") as h:
                target = h.make_target()

                def _slow_lookup(peer: int, listen: int, **kw: Any) -> int | None:
                    c_state = kw.get("conn_state")
                    assert isinstance(c_state, dict)
                    req_ev = c_state["client_readiness_requested"]
                    requested = req_ev.wait(timeout=2.0)
                    time.sleep(0.08)
                    lookup_observed["requested_before_resolve"] = requested
                    lookup_observed["closing"] = bool(c_state.get("closing"))
                    lookup_observed["expected_tuple"] = c_state.get("expected_tuple")
                    owner._note_sighting(os_pid, owner.process_started_at_for_pid(os_pid))
                    owner._SIGHTING.tuple = c_state.get("expected_tuple")
                    lookup_finished_ev.set()
                    return os_pid

                with monkeypatch.context() as mp:
                    mp.setattr(owner, "_lookup_loopback_client_pid", _slow_lookup)
                    t_wall_start = time.monotonic_ns()
                    c_start = 10_000_000_000
                    client = h.open_client(monotonic_ns=lambda: c_start + (time.monotonic_ns() - t_wall_start))
                    res = client.call(
                        target,
                        ToolCommand(
                            tool="get_health",
                            arguments={"schema_version": "2.0"},
                            token=tmpl.cred.token,
                            selected_scope=None,
                            correlation_id="corr-r40-causal",
                        ),
                        deadline_ns=c_start + 3_000_000_000,
                    )
                    assert res.get("ok") is True
                    _join_loopback_conn_threads()
                    live_state["flush"](timeout=2.0)

                assert lookup_observed.get("requested_before_resolve") is True
                assert lookup_observed.get("closing") is False
                assert ident_seen_before_lookup == [False]
                owner_calls = [ev for ev in _drain_owner_events(eq_live) if ev.get("event") == "owner_call"]
                assert len(owner_calls) == 1
                assert owner_calls[0]["observation_status"] == "ok"
                assert owner_calls[0]["client_pid"] == os_pid
                assert owner_calls[0]["response_flushed_ok"] is True
        finally:
            live_state["uninstall"]()
    finally:
        readiness_hook.uninstall()
        shutil.rmtree(tmpl.base_dir, ignore_errors=True)


def test_socket_readiness_is_noop_when_env_unset_or_server_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unset client env bypasses readiness probe even when installed and on disabled owners."""
    readiness_hook.uninstall()
    readiness_hook.install()
    tmpl = create_transport_template("t9-r40-optout")
    try:
        monkeypatch.delenv("SUPERBRAIN_TEST_SOCKET_READINESS", raising=False)
        for srv_token in ("tok-server-enabled", None):
            eq_live: queue.Queue[dict[str, Any] | None] = queue.Queue()
            os_pid = os.getpid()
            live_state = owner._install_loopback_server_hooks(
                eq=eq_live,
                daemon_pid=os_pid,
                daemon_started_at=owner.process_started_at_for_pid(os_pid),
                store_id=tmpl.store_id,
                instance_id=f"inst-optout-{bool(srv_token)}",
                collector_timeout_s=0.5,
                socket_readiness_token=srv_token,
            )
            try:
                with open_test_loopback_transport(tmpl, name=f"r40-optout-{bool(srv_token)}") as h:
                    target = h.make_target()
                    req_seen: list[bool] = []

                    def _fast_lookup(
                        _peer: int,
                        _listen: int,
                        *,
                        _seen: list[bool] = req_seen,
                        _pid: int = os_pid,
                        **kw: Any,
                    ) -> int | None:
                        c_state = kw.get("conn_state")
                        if isinstance(c_state, dict):
                            _seen.append(c_state["client_readiness_requested"].is_set())
                            owner._SIGHTING.tuple = c_state.get("expected_tuple")
                        owner._note_sighting(_pid, owner.process_started_at_for_pid(_pid))
                        return _pid

                    with monkeypatch.context() as mp:
                        mp.setattr(owner, "_lookup_loopback_client_pid", _fast_lookup)
                        t_wall_start = time.monotonic_ns()
                        c_start = 10_000_000_000

                        def _optout_mono_ns(c0: int = c_start, w0: int = t_wall_start) -> int:
                            return c0 + (time.monotonic_ns() - w0)

                        client = h.open_client(monotonic_ns=_optout_mono_ns)
                        res = client.call(
                            target,
                            ToolCommand(
                                tool="get_health",
                                arguments={"schema_version": "2.0"},
                                token=tmpl.cred.token,
                                selected_scope=None,
                                correlation_id="corr-r40-optout",
                            ),
                            deadline_ns=c_start + 2_000_000_000,
                        )
                        assert res.get("ok") is True
                        _join_loopback_conn_threads()
                        live_state["flush"](timeout=2.0)
                    assert req_seen == [False]
            finally:
                live_state["uninstall"]()
    finally:
        readiness_hook.uninstall()
        shutil.rmtree(tmpl.base_dir, ignore_errors=True)


@pytest.mark.parametrize(
    "failure_mode",
    [
        "unknown_conn",
        "shared_holder",
        "wrong_tuple",
        "closing_socket",
    ],
)
def test_socket_readiness_rejects_unverified_or_closing_connection(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    failure_mode: str,
) -> None:
    """Server refuses 200 readiness ack for unknown, shared-holder, mismatched-tuple, or closing sockets."""
    token = f"tok-neg-{failure_mode}"
    readiness_hook.uninstall()
    readiness_hook.install()
    tmpl = create_transport_template(f"t9-r40-{failure_mode}")
    try:
        monkeypatch.setenv("SUPERBRAIN_TEST_SOCKET_READINESS", token)
        eq_live: queue.Queue[dict[str, Any] | None] = queue.Queue()
        os_pid = os.getpid()
        live_state = owner._install_loopback_server_hooks(
            eq=eq_live,
            daemon_pid=os_pid,
            daemon_started_at=owner.process_started_at_for_pid(os_pid),
            store_id=tmpl.store_id,
            instance_id=f"inst-{failure_mode}",
            collector_timeout_s=0.5,
            socket_readiness_token=token,
        )
        try:
            with open_test_loopback_transport(tmpl, name=f"r40-{failure_mode}") as h:
                target = h.make_target()

                def _bad_lookup(peer: int, listen: int, **kw: Any) -> int | None:
                    c_state = kw.get("conn_state")
                    assert isinstance(c_state, dict)
                    c_state["client_readiness_requested"].wait(timeout=1.0)
                    if failure_mode == "unknown_conn":
                        return None
                    if failure_mode == "shared_holder":
                        # Exercise the shared-holder Linux single-owner check through _single({101, 202}).
                        proc_root = tmp_path / "proc"
                        net_dir = proc_root / "net"
                        net_dir.mkdir(parents=True, exist_ok=True)
                        c_ip_hex = owner._ip_hex_proc_net_tcp("127.0.0.1", ipv6=False)
                        s_ip_hex = owner._ip_hex_proc_net_tcp("127.0.0.1", ipv6=False)
                        assert c_ip_hex is not None and s_ip_hex is not None
                        row = (
                            f"   0: {c_ip_hex}:{peer:04X} {s_ip_hex}:{listen:04X}"
                            " 01 00000000:00000000 00:00000000 00000000 1000 0 98765 1 0 0 0 0\n"
                        )
                        (net_dir / "tcp").write_text(
                            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt\n" + row,
                            encoding="ascii",
                        )
                        (net_dir / "tcp6").write_text("", encoding="ascii")
                        inode = owner._parse_proc_net_tcp_inode(
                            (net_dir / "tcp").read_text(encoding="ascii"),
                            client_port=peer,
                            listen_port=listen,
                            client_ip="127.0.0.1",
                            server_ip="127.0.0.1",
                            ipv6=False,
                        )
                        assert inode == 98765
                        assert owner._single({101, 202}) is None
                        return None
                    if failure_mode == "wrong_tuple":
                        owner._note_sighting(os_pid, owner.process_started_at_for_pid(os_pid))
                        owner._SIGHTING.tuple = ("127.0.0.1", peer + 1, "127.0.0.1", listen)
                        return os_pid
                    # closing_socket: transition connection closing before ack gate evaluates.
                    owner._note_sighting(os_pid, owner.process_started_at_for_pid(os_pid))
                    owner._SIGHTING.tuple = c_state.get("expected_tuple")
                    with c_state["lock"]:
                        c_ns, c_seq = owner._stamp_ns()
                        c_state["closing"] = True
                        c_state["closing_ns"] = c_ns
                        c_state["closing_seq"] = c_seq
                    return os_pid

                with monkeypatch.context() as mp:
                    mp.setattr(owner, "_lookup_loopback_client_pid", _bad_lookup)
                    t_wall_start = time.monotonic_ns()
                    c_start = 10_000_000_000
                    client = h.open_client(monotonic_ns=lambda: c_start + (time.monotonic_ns() - t_wall_start))
                    with pytest.raises(LoopbackTransportError):
                        client.call(
                            target,
                            ToolCommand(
                                tool="get_health",
                                arguments={"schema_version": "2.0"},
                                token=tmpl.cred.token,
                                selected_scope=None,
                                correlation_id=f"corr-{failure_mode}",
                            ),
                            deadline_ns=c_start + 1_500_000_000,
                        )
                    _join_loopback_conn_threads()
                    live_state["flush"](timeout=2.0)

                owner_calls = [ev for ev in _drain_owner_events(eq_live) if ev.get("event") == "owner_call"]
                assert owner_calls == []
        finally:
            live_state["uninstall"]()
    finally:
        readiness_hook.uninstall()
        shutil.rmtree(tmpl.base_dir, ignore_errors=True)


def test_socket_readiness_rejects_bad_token_host_auth_or_extra_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Malformed readiness requests (bad token, wrong Host, extra PID field, Auth header) get 503 close."""
    token = "tok-strict-http-01"
    tmpl = create_transport_template("t9-r40-strict-http")
    try:
        eq_live: queue.Queue[dict[str, Any] | None] = queue.Queue()
        os_pid = os.getpid()
        live_state = owner._install_loopback_server_hooks(
            eq=eq_live,
            daemon_pid=os_pid,
            daemon_started_at=owner.process_started_at_for_pid(os_pid),
            store_id=tmpl.store_id,
            instance_id="inst-strict-http",
            collector_timeout_s=0.5,
            socket_readiness_token=token,
        )
        try:
            with open_test_loopback_transport(tmpl, name="r40-strict-http") as h:
                port = h.ready.endpoint.port
                bad_requests = [
                    ("wrong token", f"127.0.0.1:{port}", "", '{"token":"wrong-token"}'),
                    ("extra pid field", f"127.0.0.1:{port}", "", f'{{"token":"{token}","pid":{os_pid}}}'),
                    ("wrong host", "127.0.0.2:1", "", f'{{"token":"{token}"}}'),
                    (
                        "auth header present",
                        f"127.0.0.1:{port}",
                        "Authorization: Bearer secret\r\n",
                        f'{{"token":"{token}"}}',
                    ),
                ]

                def _sighted_lookup(_p: int, _l: int, **_kw: Any) -> int:
                    owner._note_sighting(os_pid, owner.process_started_at_for_pid(os_pid))
                    return os_pid

                with monkeypatch.context() as mp:
                    mp.setattr(owner, "_lookup_loopback_client_pid", _sighted_lookup)
                    for label, host_hdr, extra_hdr, body_text in bad_requests:
                        body = body_text.encode("utf-8")
                        req = (
                            f"POST /__test_socket_readiness HTTP/1.1\r\n"
                            f"Host: {host_hdr}\r\n"
                            f"{extra_hdr}"
                            f"Content-Type: application/json\r\n"
                            f"Content-Length: {len(body)}\r\n"
                            f"Connection: keep-alive\r\n\r\n"
                        ).encode("ascii") + body
                        with h.open_raw_tls_socket(timeout=2.0) as tls_sock:
                            resp = h.send_raw_http(tls_sock, req, read_timeout=2.0)
                        assert resp.startswith(b"HTTP/1.1 503 "), f"{label}: {resp!r}"
                        assert b'"ready":false' in resp, f"{label}: {resp!r}"
        finally:
            live_state["uninstall"]()
    finally:
        shutil.rmtree(tmpl.base_dir, ignore_errors=True)


def test_socket_readiness_timeout_strictly_bounded_by_connect_deadline_ns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Slow unresolved lookup never hangs past client connect_deadline_ns or server deadline_ns."""
    token = "tok-timeout-bound-01"
    readiness_hook.uninstall()
    readiness_hook.install()
    tmpl = create_transport_template("t9-r40-timeout")
    try:
        monkeypatch.setenv("SUPERBRAIN_TEST_SOCKET_READINESS", token)
        eq_live: queue.Queue[dict[str, Any] | None] = queue.Queue()
        os_pid = os.getpid()
        live_state = owner._install_loopback_server_hooks(
            eq=eq_live,
            daemon_pid=os_pid,
            daemon_started_at=owner.process_started_at_for_pid(os_pid),
            store_id=tmpl.store_id,
            instance_id="inst-timeout",
            collector_timeout_s=0.3,
            socket_readiness_token=token,
        )
        try:
            with open_test_loopback_transport(tmpl, name="r40-timeout") as h:
                target = h.make_target()
                release_lookup = threading.Event()
                lookup_entered = threading.Event()

                def _blocked_lookup(_peer: int, _listen: int, **_kw: Any) -> int | None:
                    lookup_entered.set()
                    release_lookup.wait(timeout=2.0)
                    return None

                with monkeypatch.context() as mp:
                    mp.setattr(owner, "_lookup_loopback_client_pid", _blocked_lookup)
                    t_wall_start = [time.monotonic_ns()]
                    c_start = 10_000_000_000
                    tight_deadline_ns = c_start + 80_000_000
                    client = h.open_client(monotonic_ns=lambda: c_start + (time.monotonic_ns() - t_wall_start[0]))
                    t_wall_start[0] = time.monotonic_ns()
                    t0 = time.monotonic()
                    with pytest.raises(LoopbackTransportError):
                        client.call(
                            target,
                            ToolCommand(
                                tool="get_health",
                                arguments={"schema_version": "2.0"},
                                token=tmpl.cred.token,
                                selected_scope=None,
                                correlation_id="corr-r40-timeout",
                            ),
                            deadline_ns=tight_deadline_ns,
                        )
                    elapsed = time.monotonic() - t0
                    assert lookup_entered.is_set()
                    assert elapsed < 0.35, f"readiness wait exceeded 80ms budget ({elapsed:.3f}s)"

                    # Advance server monotonic clock past handshake deadline so worker exits Wait loop promptly.
                    h.mono_clock.advance(60_000_000_000)
                    release_lookup.set()
                    _join_loopback_conn_threads()
                    live_state["flush"](timeout=2.0)
        finally:
            live_state["uninstall"]()
    finally:
        readiness_hook.uninstall()
        shutil.rmtree(tmpl.base_dir, ignore_errors=True)


def test_socket_readiness_does_not_block_concurrent_rpcs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A readiness wait stalled on connection A never blocks concurrent RPCs on connection B."""
    token = "tok-concurrent-rpc-01"
    readiness_hook.uninstall()
    readiness_hook.install()
    tmpl = create_transport_template("t9-r40-concurrent")
    try:
        eq_live: queue.Queue[dict[str, Any] | None] = queue.Queue()
        os_pid = os.getpid()
        live_state = owner._install_loopback_server_hooks(
            eq=eq_live,
            daemon_pid=os_pid,
            daemon_started_at=owner.process_started_at_for_pid(os_pid),
            store_id=tmpl.store_id,
            instance_id="inst-concurrent",
            collector_timeout_s=0.5,
            socket_readiness_token=token,
        )
        try:
            with open_test_loopback_transport(tmpl, name="r40-concurrent") as h:
                target = h.make_target()
                stalled_port_lock = threading.Lock()
                stalled_port: list[int] = []
                stall_entered = threading.Event()
                release_stall = threading.Event()

                def _selective_lookup(peer: int, _listen: int, **kw: Any) -> int | None:
                    c_state = kw.get("conn_state")
                    with stalled_port_lock:
                        if not stalled_port:
                            stalled_port.append(peer)
                        is_stalled = peer == stalled_port[0]
                    if is_stalled:
                        stall_entered.set()
                        release_stall.wait(timeout=3.0)
                    owner._note_sighting(os_pid, owner.process_started_at_for_pid(os_pid))
                    if isinstance(c_state, dict):
                        owner._SIGHTING.tuple = c_state.get("expected_tuple")
                    return os_pid

                with monkeypatch.context() as mp:
                    mp.setattr(owner, "_lookup_loopback_client_pid", _selective_lookup)
                    mp.setenv("SUPERBRAIN_TEST_SOCKET_READINESS", token)

                    conn_a_errors: list[BaseException] = []
                    conn_a_res: list[dict[str, Any]] = []

                    def _run_conn_a() -> None:
                        try:
                            t_a0 = time.monotonic_ns()
                            c_a0 = 10_000_000_000
                            client_a = h.open_client(monotonic_ns=lambda: c_a0 + (time.monotonic_ns() - t_a0))
                            res_a = client_a.call(
                                target,
                                ToolCommand(
                                    tool="get_health",
                                    arguments={"schema_version": "2.0"},
                                    token=tmpl.cred.token,
                                    selected_scope=None,
                                    correlation_id="corr-conn-a",
                                ),
                                deadline_ns=c_a0 + 3_000_000_000,
                            )
                            conn_a_res.append(dict(res_a))
                        except BaseException as exc:  # noqa: BLE001
                            conn_a_errors.append(exc)

                    th_a = threading.Thread(target=_run_conn_a, daemon=True)
                    th_a.start()
                    assert stall_entered.wait(timeout=1.5)

                    # While connection A is held at readiness barrier, connection B completes RPC rapidly.
                    t_b0 = time.monotonic_ns()
                    c_b0 = 20_000_000_000
                    client_b = h.open_client(monotonic_ns=lambda: c_b0 + (time.monotonic_ns() - t_b0))
                    t0 = time.monotonic()
                    res_b = client_b.call(
                        target,
                        ToolCommand(
                            tool="get_health",
                            arguments={"schema_version": "2.0"},
                            token=tmpl.cred.token,
                            selected_scope=None,
                            correlation_id="corr-conn-b",
                        ),
                        deadline_ns=c_b0 + 1_000_000_000,
                    )
                    b_elapsed = time.monotonic() - t0
                    assert res_b.get("ok") is True
                    assert b_elapsed < 0.35, f"conn B stalled behind conn A readiness ({b_elapsed:.3f}s)"

                    release_stall.set()
                    th_a.join(timeout=3.0)
                    assert not conn_a_errors, f"conn A failed: {conn_a_errors}"
                    assert conn_a_res and conn_a_res[0].get("ok") is True

                    _join_loopback_conn_threads()
                    live_state["flush"](timeout=2.0)
        finally:
            live_state["uninstall"]()
    finally:
        readiness_hook.uninstall()
        shutil.rmtree(tmpl.base_dir, ignore_errors=True)


def test_proc_net_tcp_ip_matching_and_stripped_env_hygiene() -> None:
    """/proc/net/tcp parsing distinguishes local/remote IPs and env stripping blocks inherited readiness vars."""
    assert "SUPERBRAIN_TEST_SOCKET_READINESS" in _STRIPPED_ENV_KEYS
    assert "_SUPERBRAIN_OWNER_SOCKET_READINESS_TOKEN" in _STRIPPED_ENV_KEYS

    assert owner._format_host_header("127.0.0.1", 8443) == "127.0.0.1:8443"
    assert owner._format_host_header("::1", 8443) == "[::1]:8443"

    c_ip_v4 = owner._ip_hex_proc_net_tcp("127.0.0.1", ipv6=False)
    s_ip_v4 = owner._ip_hex_proc_net_tcp("127.0.0.1", ipv6=False)
    wrong_ip_v4 = owner._ip_hex_proc_net_tcp("127.0.0.2", ipv6=False)
    assert c_ip_v4 is not None and s_ip_v4 is not None and wrong_ip_v4 is not None

    tcp_v4 = (
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        f"   0: {wrong_ip_v4}:D431 {s_ip_v4}:20FB 01 00000000:00000000 00:00000000 00000000 1000 0 11111 1 0 0 0 0\n"
        f"   1: {c_ip_v4}:D431 {s_ip_v4}:20FB 01 00000000:00000000 00:00000000 00000000 1000 0 22222 1 0 0 0 0\n"
    )
    # Must match the row with exact client_ip=127.0.0.1 (inode 22222), never wrong IP 127.0.0.2 (inode 11111).
    assert (
        owner._parse_proc_net_tcp_inode(
            tcp_v4,
            client_port=0xD431,
            listen_port=0x20FB,
            client_ip="127.0.0.1",
            server_ip="127.0.0.1",
            ipv6=False,
        )
        == 22222
    )
    assert (
        owner._parse_proc_net_tcp_inode(
            tcp_v4,
            client_port=0xD431,
            listen_port=0x20FB,
            client_ip="127.0.0.3",
            server_ip="127.0.0.1",
            ipv6=False,
        )
        is None
    )

    v6_loopback = owner._ip_hex_proc_net_tcp("::1", ipv6=True)
    v4_mapped_v6 = owner._ip_hex_proc_net_tcp("127.0.0.1", ipv6=True)
    assert v6_loopback is not None and v4_mapped_v6 is not None
    v6_tail = "01 00000000:00000000 00:00000000 00000000 1000 0"
    tcp_v6 = (
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        f"   0: {v6_loopback}:C001 {v6_loopback}:20FC {v6_tail} 33333 1 0 0 0 0\n"
        f"   1: {v4_mapped_v6}:C002 {v4_mapped_v6}:20FD {v6_tail} 44444 1 0 0 0 0\n"
    )
    assert (
        owner._parse_proc_net_tcp_inode(
            tcp_v6,
            client_port=0xC001,
            listen_port=0x20FC,
            client_ip="::1",
            server_ip="::1",
            ipv6=True,
        )
        == 33333
    )
    assert (
        owner._parse_proc_net_tcp_inode(
            tcp_v6,
            client_port=0xC002,
            listen_port=0x20FD,
            client_ip="127.0.0.1",
            server_ip="127.0.0.1",
            ipv6=True,
        )
        == 44444
    )
    assert socket.inet_pton(socket.AF_INET6, "::1")
