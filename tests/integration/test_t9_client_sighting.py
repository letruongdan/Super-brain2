"""Task 9 (T9-R02 R6, T9-PORT-F3): bind a loopback client only from a holder seen while the connection was live.

Seam: ``_safe_client_identity`` is a closure of ``_install_loopback_server_hooks``. After installing the hooks, the
test takes it (and the hooks' own ``_mark_conn_closing``) from the closure cells of the installed
``LoopbackServer._conn_worker`` tap, and calls it with a connection-state dict of the shape that tap creates. The
lookup runs the real darwin path (``owner.sys`` faked as darwin) against a fake libproc (``ctypes.CDLL`` patched),
whose callbacks mark the connection closing at chosen points of the scan. ``process_started_at_for_pid`` is stubbed:
start times are not under test here.
"""

from __future__ import annotations

import contextlib
import ctypes
import os
import queue
import socket
import struct
import subprocess
import threading
import time
from collections.abc import Callable, Iterator
from concurrent.futures import Future
from pathlib import Path
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
    seq_src = getattr(owner, "_ORDER_SEQ", None)
    return {
        "lock": threading.Lock(),
        "conn_started_ns": time.monotonic_ns(),
        "conn_started_seq": next(seq_src) if seq_src is not None else None,
        "closed_event": threading.Event(),
        "worker_entered_event": threading.Event(),
        "closing": False,
        "closing_ns": None,
        "closing_seq": None,
        "closing_at": None,
        "closed_at": None,
        "closed_ns": None,
        "closed_seq": None,
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
    # A lookup that records no sighting (e.g., lsof fallback or monkeypatched lookups): a connection closing when the
    # lookup returns is rejected, as before.
    safe, mark_closing, _fake = hooks
    conn = _conn_state()

    def lookup(_client: int, _listen: int, **_kw: Any) -> int:
        mark_closing(conn)
        return HOLDER

    monkeypatch.setattr(owner, "_lookup_loopback_client_pid", lookup)
    assert safe(CLIENT_PORT, LISTEN_PORT, conn) == (None, None, None, None)


@pytest.mark.parametrize(("euid", "listing"), [(501, (4, 501)), (0, (1, 0))], ids=["user", "root"])
def test_libproc_lists_by_effective_uid_and_everything_as_root(
    hooks: tuple[Any, Any, Any], monkeypatch: pytest.MonkeyPatch, euid: int, listing: tuple[int, int]
) -> None:
    # The fd tables a lookup can read are those of the effective uid: PROC_UID_ONLY (4) for it, or every process
    # (PROC_ALL_PIDS = 1) when root, which reads all fd tables -- a uid-only listing would then hide holders from
    # the uniqueness check. The real uid is never what decides it.
    safe, _mark_closing, fake = hooks
    monkeypatch.setattr(os, "geteuid", lambda: euid, raising=False)
    monkeypatch.setattr(os, "getuid", lambda: 777, raising=False)
    assert safe(CLIENT_PORT, LISTEN_PORT, _conn_state())[0] == HOLDER
    assert fake.listings and all(seen == listing for seen in fake.listings), fake.listings


def test_a_sighting_from_an_earlier_lookup_never_carries_over(
    hooks: tuple[Any, Any, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    safe, mark_closing, fake = hooks
    later_conn = _conn_state()  # started before the first sighting, so a stale sighting would pass its start check
    _next_tick()
    first = safe(CLIENT_PORT, LISTEN_PORT, _conn_state())
    assert first[0] == HOLDER and first[3] is not None
    _next_tick()

    # Second lookup on the same thread: libproc sees no holder at all.
    fake.table[HOLDER] = []
    lsof_out: list[str] = [""]

    def run(cmd: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(cmd, 0, stdout=lsof_out[0], stderr="")

    monkeypatch.setattr(subprocess, "run", run)
    assert safe(CLIENT_PORT, LISTEN_PORT, later_conn) == (None, None, None, None), "no holder, no binding"

    # lsof (which records no sighting) names the holder, but the connection began closing during that lookup:
    # only a sighting made by this lookup could keep the binding, so it is rejected under the closing rule.
    lsof_out[0] = f"p{HOLDER}\nf3\nn127.0.0.1:{CLIENT_PORT}->127.0.0.1:{LISTEN_PORT}\n"

    def closing_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        mark_closing(later_conn)
        return run(cmd, **kwargs)

    monkeypatch.setattr(subprocess, "run", closing_run)
    assert safe(CLIENT_PORT, LISTEN_PORT, later_conn) == (None, None, None, None), "a stale sighting leaked"


@contextlib.contextmanager
def _safe_identity_hooks(
    monkeypatch: pytest.MonkeyPatch, *, platform: str, on_started_at: Callable[[int], None] | None = None
) -> Iterator[tuple[Any, Any]]:
    monkeypatch.setattr(owner, "sys", type("FakeSys", (), {"platform": platform})())

    def fake_started_at(pid: int) -> str:
        if on_started_at is not None:
            on_started_at(pid)
        return "2026-11-14T00:00:00.000000Z"

    monkeypatch.setattr(owner, "process_started_at_for_pid", fake_started_at)
    state = owner._install_loopback_server_hooks(
        eq=queue.Queue(), daemon_pid=os.getpid(), daemon_started_at="2026-11-14T00:00:00.000000Z"
    )
    try:
        tap = _loopback_server.LoopbackServer._conn_worker
        safe = _closure_fn(_closure_fn(tap, "_submit_lookup"), "_safe_client_identity")
        mark_closing = _closure_fn(tap, "_mark_conn_closing")
        yield safe, mark_closing
    finally:
        state["uninstall"]()


def _make_fake_proc(tmp_path: Path, pid_fds: dict[int, tuple[str, ...]]) -> Path:
    proc_root = tmp_path / "proc"
    (proc_root / "net").mkdir(parents=True)
    ip_hex = "0100007F"
    (proc_root / "net" / "tcp").write_text(
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        f"   0: {ip_hex}:{CLIENT_PORT:04X} {ip_hex}:{LISTEN_PORT:04X} "
        "01 00000000:00000000 00:00000000 00000000  1000        0 998877 1 0 0 0 0\n",
        encoding="ascii",
    )
    for pid, fds in pid_fds.items():
        fd_dir = proc_root / str(pid) / "fd"
        fd_dir.mkdir(parents=True)
        for fd_name in fds:
            (fd_dir / fd_name).write_text("", encoding="ascii")
    return proc_root


def test_linux_proc_checks_own_pid_before_newer_pids_and_keeps_early_sighting(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    newer_pids = [HOLDER + 1, HOLDER + 50, HOLDER + 300]
    proc_root = _make_fake_proc(tmp_path, {HOLDER: ("3",), **{pid: ("3",) for pid in newer_pids}})
    monkeypatch.setattr(owner, "_LINUX_PROC_ROOT", proc_root, raising=False)
    seen_pids: list[int] = []
    close_triggered = False

    with _safe_identity_hooks(monkeypatch, platform="linux") as (safe, mark_closing):
        conn = _conn_state()

        def fake_readlink(path: Any) -> str:
            nonlocal close_triggered
            p = Path(path)
            pid = int(p.parent.parent.name)
            seen_pids.append(pid)
            if pid != HOLDER and not close_triggered:
                close_triggered = True
                _next_tick()
                mark_closing(conn)
            return "socket:[998877]" if pid == HOLDER else "pipe:[11]"

        monkeypatch.setattr(os, "readlink", fake_readlink)
        pid, _started, observed_at, observed_ns = safe(CLIENT_PORT, LISTEN_PORT, conn)

    assert close_triggered, "newer PIDs were never scanned after checking self PID"
    assert pid == HOLDER, "self PID sighted before close during newer-PID scan must stay bound"
    assert seen_pids[0] == HOLDER, f"os.getpid() must be checked first when proc_root is None; order={seen_pids}"
    assert seen_pids[1:] == sorted(newer_pids, reverse=True), f"remaining PIDs must scan descending; order={seen_pids}"
    assert conn["closing"] and conn["closing_ns"] is not None
    assert observed_ns is not None and observed_ns < conn["closing_ns"]
    assert observed_at is not None and observed_at <= conn["closing_at"]


def test_linux_proc_multi_holder_still_rejects_after_checking_own_pid(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    newer_pids = [HOLDER + 50, HOLDER + 300]
    proc_root = _make_fake_proc(tmp_path, {HOLDER: ("3",), **{pid: ("4",) for pid in newer_pids}})
    monkeypatch.setattr(owner, "_LINUX_PROC_ROOT", proc_root, raising=False)
    seen_pids: list[int] = []

    with _safe_identity_hooks(monkeypatch, platform="linux") as (safe, _mark_closing):
        def fake_readlink(path: Any) -> str:
            pid = int(Path(path).parent.parent.name)
            seen_pids.append(pid)
            return "socket:[998877]" if pid in (HOLDER, HOLDER + 300) else "pipe:[11]"

        monkeypatch.setattr(os, "readlink", fake_readlink)
        result = safe(CLIENT_PORT, LISTEN_PORT, _conn_state())

    assert result == (None, None, None, None), "multi-holder fd sharing must still be rejected by _single(holders)"
    assert seen_pids == [HOLDER, HOLDER + 300, HOLDER + 50]


def test_linux_proc_closes_before_sighting_is_rejected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    proc_root = _make_fake_proc(tmp_path, {HOLDER: ("3",)})
    monkeypatch.setattr(owner, "_LINUX_PROC_ROOT", proc_root, raising=False)

    with _safe_identity_hooks(monkeypatch, platform="linux") as (safe, mark_closing):
        conn = _conn_state()

        def fake_readlink(_path: Any) -> str:
            mark_closing(conn)
            _next_tick()
            return "socket:[998877]"

        monkeypatch.setattr(os, "readlink", fake_readlink)
        assert safe(CLIENT_PORT, LISTEN_PORT, conn) == (None, None, None, None)


def test_linux_proc_explicit_proc_root_scans_descending_without_self_shortcut(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    proc_root = _make_fake_proc(tmp_path, {HOLDER: ("3",), HOLDER + 10: ("3",), HOLDER + 50: ("4",)})
    seen_pids: list[int] = []

    def fake_readlink(path: Any) -> str:
        pid = int(Path(path).parent.parent.name)
        seen_pids.append(pid)
        return "socket:[998877]" if pid in (HOLDER, HOLDER + 50) else "pipe:[11]"

    monkeypatch.setattr(os, "readlink", fake_readlink)
    holders = owner._socket_inode_holders(998877, proc_root=proc_root)
    assert holders == {HOLDER, HOLDER + 50}
    assert seen_pids == [HOLDER + 50, HOLDER + 10, HOLDER], (
        f"explicit proc_root must not jump to os.getpid(); {seen_pids}"
    )


def _make_fake_iphlpapi(
    rows: list[tuple[int, str, int, str, int, int]], on_table: Callable[[], None] | None = None
) -> Any:
    raw_rows = []
    for state, laddr_s, lport, raddr_s, rport, pid in rows:
        laddr = struct.unpack("<I", socket.inet_aton(laddr_s))[0]
        raddr = struct.unpack("<I", socket.inet_aton(raddr_s))[0]
        raw_rows.append(struct.pack("=6I", state, laddr, socket.htons(lport), raddr, socket.htons(rport), pid))
    payload = struct.pack("=I", len(raw_rows)) + b"".join(raw_rows)

    class _FakeIphlpapi:
        def GetExtendedTcpTable(
            self, buf: Any, size_ref: Any, _order: bool, _family: int, _table_class: int, _reserved: int
        ) -> int:
            if buf is None:
                if hasattr(size_ref, "_obj"):
                    size_ref._obj.value = len(payload)
                return 122
            if on_table is not None:
                on_table()
            ctypes.memmove(buf, payload, len(payload))
            return 0

    return lambda *_args, **_kwargs: _FakeIphlpapi()


def test_windows_tcp_table_sighting_keeps_binding_when_close_begins_after_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        ctypes,
        "WinDLL",
        _make_fake_iphlpapi([(5, "127.0.0.1", CLIENT_PORT, "127.0.0.1", LISTEN_PORT, HOLDER)]),
        raising=False,
    )
    conn = _conn_state()
    holder_holder: dict[str, Any] = {}

    def close_after_sighting(_pid: int) -> None:
        _next_tick()
        holder_holder["mark"](conn)

    with _safe_identity_hooks(
        monkeypatch,
        platform="win32",
        on_started_at=close_after_sighting,
    ) as (safe, mark_closing):
        holder_holder["mark"] = mark_closing
        pid, _started, observed_at, observed_ns = safe(CLIENT_PORT, LISTEN_PORT, conn)

    assert pid == HOLDER, "Windows PID sighted while live must remain bound if close begins afterwards"
    assert conn["closing"] and conn["closing_ns"] is not None
    assert observed_ns is not None and observed_ns < conn["closing_ns"]
    assert observed_at is not None and observed_at <= conn["closing_at"]


@pytest.mark.parametrize("row_pid", [HOLDER, 0], ids=["close-before-table-match", "zero-pid-ignored"])
def test_windows_tcp_table_close_before_lookup_or_zero_pid_is_rejected(
    monkeypatch: pytest.MonkeyPatch, row_pid: int
) -> None:
    holder_holder: dict[str, Any] = {}
    conn = _conn_state()

    def close_before_match() -> None:
        if row_pid > 0:
            holder_holder["mark"](conn)
            _next_tick()

    monkeypatch.setattr(
        ctypes,
        "WinDLL",
        _make_fake_iphlpapi(
            [(5, "127.0.0.1", CLIENT_PORT, "127.0.0.1", LISTEN_PORT, row_pid)],
            on_table=close_before_match,
        ),
        raising=False,
    )
    with _safe_identity_hooks(monkeypatch, platform="win32") as (safe, mark_closing):
        holder_holder["mark"] = mark_closing
        assert safe(CLIENT_PORT, LISTEN_PORT, conn) == (None, None, None, None)


def test_equal_monotonic_tick_sighting_before_closing_stays_bound(
    hooks: tuple[Any, Any, _ScanLibproc], monkeypatch: pytest.MonkeyPatch
) -> None:
    safe, mark_closing, fake = hooks
    frozen_ns = 9_876_543_210
    monkeypatch.setattr(time, "monotonic_ns", lambda: frozen_ns)
    conn = _conn_state()

    fake.on_pid[OTHER] = lambda: mark_closing(conn)
    pid, _started, observed_at, observed_ns = safe(CLIENT_PORT, LISTEN_PORT, conn)

    assert pid == HOLDER, "live sighting before closing on the same monotonic tick must remain bound"
    assert conn["closing"] and conn["closing_ns"] == frozen_ns
    assert observed_ns == frozen_ns
    assert observed_at is not None and observed_at <= conn["closing_at"]


def test_equal_monotonic_tick_closing_before_sighting_is_rejected(
    hooks: tuple[Any, Any, _ScanLibproc], monkeypatch: pytest.MonkeyPatch
) -> None:
    safe, mark_closing, fake = hooks
    frozen_ns = 9_876_543_210
    monkeypatch.setattr(time, "monotonic_ns", lambda: frozen_ns)
    conn = _conn_state()

    fake.on_listing = lambda: mark_closing(conn)
    assert safe(CLIENT_PORT, LISTEN_PORT, conn) == (None, None, None, None)
    assert conn["closing"] and conn["closing_ns"] == frozen_ns


def test_equal_monotonic_tick_sighting_before_conn_started_is_rejected(
    hooks: tuple[Any, Any, _ScanLibproc], monkeypatch: pytest.MonkeyPatch
) -> None:
    safe, _mark_closing, fake = hooks
    frozen_ns = 9_876_543_210
    monkeypatch.setattr(time, "monotonic_ns", lambda: frozen_ns)
    conn = _conn_state()

    def advance_conn_start_after_sighting() -> None:
        seq_src = getattr(owner, "_ORDER_SEQ", None)
        with conn["lock"]:
            conn["conn_started_ns"] = frozen_ns
            conn["conn_started_seq"] = next(seq_src) if seq_src is not None else 999_999_999

    fake.on_pid[OTHER] = advance_conn_start_after_sighting
    assert safe(CLIENT_PORT, LISTEN_PORT, conn) == (None, None, None, None)


def test_legacy_conn_state_without_seq_keys_works_without_keyerror(
    hooks: tuple[Any, Any, _ScanLibproc], monkeypatch: pytest.MonkeyPatch
) -> None:
    safe, mark_closing, fake = hooks
    conn_live = _conn_state()
    for key in ("conn_started_seq", "closing_seq", "closed_seq"):
        conn_live.pop(key, None)
    assert safe(CLIENT_PORT, LISTEN_PORT, conn_live)[0] == HOLDER

    conn_closing = _conn_state()
    for key in ("conn_started_seq", "closing_seq", "closed_seq"):
        conn_closing.pop(key, None)

    def close_before_sighting() -> None:
        mark_closing(conn_closing)
        _next_tick()

    monkeypatch.setattr(fake, "on_listing", close_before_sighting)
    assert safe(CLIENT_PORT, LISTEN_PORT, conn_closing) == (None, None, None, None)


def test_finalize_resolves_equal_monotonic_tick_by_sequence(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(owner, "sys", type("FakeSys", (), {"platform": "darwin"})())
    monkeypatch.setattr(owner, "process_started_at_for_pid", lambda pid: "2026-11-14T00:00:00.000000Z")
    fake = _ScanLibproc({HOLDER: [(5, TCP)], OTHER: []})
    monkeypatch.setattr(ctypes, "CDLL", lambda *_a, **_k: fake)
    frozen_ns = 9_876_543_210
    monkeypatch.setattr(time, "monotonic_ns", lambda: frozen_ns)

    eq: queue.Queue[dict[str, Any]] = queue.Queue()
    state = owner._install_loopback_server_hooks(
        eq=eq, daemon_pid=os.getpid(), daemon_started_at="2026-11-14T00:00:00.000000Z"
    )
    try:
        tap = _loopback_server.LoopbackServer._conn_worker
        safe = _closure_fn(_closure_fn(tap, "_submit_lookup"), "_safe_client_identity")
        mark_closing = _closure_fn(tap, "_mark_conn_closing")
        schedule_emit = _closure_fn(tap, "_schedule_emit")
        gate = type("DummyGate", (), {"identity": None})()
        seq_src = getattr(owner, "_ORDER_SEQ", None)

        def emit_case(
            conn: dict[str, Any], res: tuple[int | None, str | None, str | None, int | None]
        ) -> dict[str, Any]:
            fut: Future[tuple[int | None, str | None, str | None, int | None]] = Future()
            fut.set_result(res)
            conn["closed_event"].set()
            schedule_emit(
                gate=gate,
                connection_id="conn-seq",
                conn_started_at="2026-11-14T00:00:00.000000Z",
                lookup_fut=fut,
                conn_state=conn,
                principal_id="p1",
                credential_id="c1",
                tool_name="read",
                ready_val=True,
                auth_matched=True,
                response_flushed_ok=True,
                resp_digest="sha256:0",
                listen_host="127.0.0.1",
                listen_port=LISTEN_PORT,
                peer_host="127.0.0.1",
                peer_port=CLIENT_PORT,
                req_started_at="2026-11-14T00:00:00.000000Z",
                ended_at="2026-11-14T23:59:59.000000Z",
                selected_scope=None,
            )
            return eq.get_nowait()

        # In-order equal-tick lifecycle passes finalize.
        conn_ok = _conn_state()
        res_ok = safe(CLIENT_PORT, LISTEN_PORT, conn_ok)
        assert res_ok[0] == HOLDER
        mark_closing(conn_ok)
        conn_ok["closed_ns"] = frozen_ns
        conn_ok["closed_seq"] = next(seq_src) if seq_src is not None else None
        conn_ok["closed_at"] = "2026-11-14T23:59:59.000000Z"
        assert emit_case(conn_ok, res_ok)["observation_status"] == "ok"

        # Equal-tick closed_seq before closing_seq fails finalize.
        conn_oob = _conn_state()
        res_oob = safe(CLIENT_PORT, LISTEN_PORT, conn_oob)
        assert res_oob[0] == HOLDER
        early_closed_seq = next(seq_src) if seq_src is not None else 1
        mark_closing(conn_oob)
        conn_oob["closed_ns"] = frozen_ns
        conn_oob["closed_seq"] = early_closed_seq
        conn_oob["closed_at"] = "2026-11-14T23:59:59.000000Z"
        ev_oob = emit_case(conn_oob, res_oob)
        assert ev_oob["observation_status"] == "observation_incomplete"
        assert ev_oob["client_pid"] is None

        # Legacy conn_state without *_seq keys still passes finalize cleanly.
        conn_legacy = _conn_state()
        res_legacy = safe(CLIENT_PORT, LISTEN_PORT, conn_legacy)
        mark_closing(conn_legacy)
        conn_legacy["closed_ns"] = frozen_ns
        conn_legacy["closed_at"] = "2026-11-14T23:59:59.000000Z"
        for key in ("conn_started_seq", "observed_seq", "closing_seq", "closed_seq"):
            conn_legacy.pop(key, None)
        assert emit_case(conn_legacy, res_legacy)["observation_status"] == "ok"
    finally:
        state["uninstall"]()
