"""Task 9 (T9-R02 R6, T9-PORT-F3): bind a loopback client only from a holder seen while the connection was live.

Seam: ``_safe_client_identity`` is a closure of ``_install_loopback_server_hooks``. After installing the hooks, the
test takes it (and the hooks' own ``_mark_conn_closing``) from the closure cells of the installed
``LoopbackServer._conn_worker`` tap, and calls it with a connection-state dict of the shape that tap creates. The
lookup runs the real darwin path (``owner.sys`` faked as darwin) against a fake libproc (``ctypes.CDLL`` patched),
whose callbacks mark the connection closing at chosen points of the scan. ``process_started_at_for_pid`` is stubbed:
start times are not under test here.
"""

from __future__ import annotations

import ctypes
import os
import queue
import threading
import time
from collections.abc import Callable, Iterator
from typing import Any

import pytest

from superbrain.cli_api import _loopback_server
from tests.integration.test_t9_libproc_client_pid import CLIENT_PORT, LISTEN_PORT, TCP, _FakeLibproc
from tests.support import inc2_native_owner as owner

HOLDER = os.getpid()
OTHER = 1  # listed after the holder (the scan goes newest pid first) and holds no matching socket


def _closure_fn(fn: Any, name: str) -> Any:
    for cell in fn.__closure__ or ():
        value = cell.cell_contents
        if callable(value) and getattr(value, "__name__", "") == name:
            return value
    raise LookupError(name)


class _ScanLibproc(_FakeLibproc):
    """Fake libproc that records listing calls and runs ``on_listing`` / ``on_pid`` at those points of the scan."""

    def __init__(self, table: dict[int, list[tuple[int, bytes]]]) -> None:
        super().__init__(table)
        self.listings: list[tuple[int, int]] = []
        self.on_listing: Callable[[], None] = lambda: None
        self.on_pid: dict[int, Callable[[], None]] = {}

    def proc_listpids(self, type_: int, info: int, buf: Any, size: int) -> int:
        self.listings.append((type_, info))
        if buf is not None:
            self.on_listing()
        return super().proc_listpids(type_, info, buf, size)

    def proc_pidinfo(self, pid: int, flavor: int, arg: int, buf: Any, size: int) -> int:
        if buf is None and pid in self.on_pid:
            self.on_pid[pid]()
        return super().proc_pidinfo(pid, flavor, arg, buf, size)


def _next_tick() -> None:
    """Return only once the monotonic clock has moved past the call instant (coarse clocks would tie stamps)."""
    start = time.monotonic_ns()
    while time.monotonic_ns() == start:
        pass


def _conn_state() -> dict[str, Any]:
    return {
        "lock": threading.Lock(),
        "conn_started_ns": time.monotonic_ns(),
        "closed_event": threading.Event(),
        "worker_entered_event": threading.Event(),
        "closing": False,
        "closing_ns": None,
        "closing_at": None,
        "closed_at": None,
        "closed_ns": None,
        "raw_sock": None,
        "ssl_sock": None,
    }


@pytest.fixture
def hooks(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[Any, Any, _ScanLibproc]]:
    monkeypatch.setattr(owner, "sys", type("FakeSys", (), {"platform": "darwin"})())
    monkeypatch.setattr(owner, "process_started_at_for_pid", lambda pid: "2026-11-14T00:00:00.000000Z")
    fake = _ScanLibproc({HOLDER: [(5, TCP)], OTHER: []})
    monkeypatch.setattr(ctypes, "CDLL", lambda *_a, **_k: fake)
    state = owner._install_loopback_server_hooks(
        eq=queue.Queue(), daemon_pid=os.getpid(), daemon_started_at="2026-11-14T00:00:00.000000Z"
    )
    try:
        tap = _loopback_server.LoopbackServer._conn_worker
        safe = _closure_fn(_closure_fn(tap, "_submit_lookup"), "_safe_client_identity")
        mark_closing = _closure_fn(tap, "_mark_conn_closing")
        yield safe, mark_closing, fake
    finally:
        state["uninstall"]()


def test_holder_sighted_before_closing_stays_bound_when_the_scan_ends_after(hooks: tuple[Any, Any, Any]) -> None:
    safe, mark_closing, fake = hooks
    conn = _conn_state()

    def close_mid_scan() -> None:  # the close begins strictly after the holder was seen, while the scan goes on
        _next_tick()
        mark_closing(conn)

    fake.on_pid[OTHER] = close_mid_scan
    pid, _started, observed_at, observed_ns = safe(CLIENT_PORT, LISTEN_PORT, conn)
    assert conn["closing"] and conn["closing_ns"] is not None
    assert pid == HOLDER, "a holder seen while the connection was live must stay bound"
    assert observed_ns is not None and observed_ns < conn["closing_ns"], "observed_ns must be the sighting"
    assert observed_at is not None and observed_at <= conn["closing_at"]


def test_holder_sighted_after_closing_began_is_rejected(hooks: tuple[Any, Any, Any]) -> None:
    safe, mark_closing, fake = hooks
    conn = _conn_state()

    def close_before_sighting() -> None:  # the lookup started live; the close begins strictly before the sighting
        mark_closing(conn)
        _next_tick()

    fake.on_listing = close_before_sighting
    assert safe(CLIENT_PORT, LISTEN_PORT, conn) == (None, None, None, None)
    assert conn["closing"]


def test_lookup_started_after_closing_is_rejected_up_front(hooks: tuple[Any, Any, Any]) -> None:
    safe, mark_closing, fake = hooks
    conn = _conn_state()
    mark_closing(conn)
    assert safe(CLIENT_PORT, LISTEN_PORT, conn) == (None, None, None, None)
    assert fake.listings == [], "no lookup may run for a connection that is already closing"


def test_lookup_without_a_sighting_keeps_the_closing_rule(
    hooks: tuple[Any, Any, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    # A lookup that records no sighting (Windows/Linux paths, monkeypatched lookups): a connection closing when the
    # lookup returns is rejected, as before.
    safe, mark_closing, _fake = hooks
    conn = _conn_state()

    def lookup(_client: int, _listen: int, **_kw: Any) -> int:
        mark_closing(conn)
        return HOLDER

    monkeypatch.setattr(owner, "_lookup_loopback_client_pid", lookup)
    assert safe(CLIENT_PORT, LISTEN_PORT, conn) == (None, None, None, None)


def test_libproc_lists_only_this_users_processes(hooks: tuple[Any, Any, Any]) -> None:
    safe, _mark_closing, fake = hooks
    assert safe(CLIENT_PORT, LISTEN_PORT, _conn_state())[0] == HOLDER
    uid = int(getattr(os, "getuid", lambda: 0)())
    assert fake.listings and all(listing == (4, uid) for listing in fake.listings), fake.listings  # PROC_UID_ONLY
