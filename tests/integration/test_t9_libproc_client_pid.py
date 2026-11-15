"""Task 9 (macOS libproc lookup, run on any OS): a loopback client PID is bound only from the TCP socket carrying
that exact client->listen connection, never from another protocol's socket on the same 4-tuple, never ambiguously.

Seam: ``_libproc_client_pid`` does ``import ctypes`` and calls ``ctypes.CDLL(...)`` at call time, so patching the
``ctypes.CDLL`` attribute hands it a fake libproc. The fake implements socket lookup and process creation metadata
through ``proc_listpids``, ``proc_pidinfo(PROC_PIDLISTFDS/PROC_PIDTBSDINFO)`` and
``proc_pidfdinfo(PROC_PIDFDSOCKETINFO)`` over an in-memory process table. Its buffers follow the Darwin ABI.
"""

from __future__ import annotations

import ctypes
import os
import socket
import struct
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from tests.support import inc2_native_owner as owner

IPPROTO_TCP, IPPROTO_UDP = 6, 17
SOCKINFO_IN, SOCKINFO_TCP = 1, 2
SOI_PROTOCOL_OFF = 24 + 156  # xnu socket_info.soi_protocol
CLIENT_PORT, LISTEN_PORT = 52001, 45123


def _fdinfo(
    *,
    local: tuple[str, int],
    remote: tuple[str, int],
    kind: int = SOCKINFO_TCP,
    protocol: int = IPPROTO_TCP,
    family: int = socket.AF_INET,
) -> bytes:
    buf = bytearray(owner._SOCKET_FDINFO_SIZE)
    struct.pack_into("<i", buf, owner._SOI_FAMILY_OFF, family)
    struct.pack_into("<i", buf, owner._SOI_KIND_OFF, kind)
    struct.pack_into("<i", buf, SOI_PROTOCOL_OFF, protocol)
    struct.pack_into("<ii", buf, owner._INSI_OFF, socket.htons(remote[1]), socket.htons(local[1]))
    buf[owner._INSI_OFF + 32 + 12 : owner._INSI_OFF + 32 + 16] = socket.inet_aton(remote[0])
    buf[owner._INSI_OFF + 48 + 12 : owner._INSI_OFF + 48 + 16] = socket.inet_aton(local[0])
    return bytes(buf)


def _client(**fields: int) -> bytes:
    return _fdinfo(local=("127.0.0.1", CLIENT_PORT), remote=("127.0.0.1", LISTEN_PORT), **fields)


def _server(**fields: int) -> bytes:
    return _fdinfo(local=("127.0.0.1", LISTEN_PORT), remote=("127.0.0.1", CLIENT_PORT), **fields)


def test_parse_socket_fdinfo_decodes_an_ipv4_tcp_socket() -> None:
    assert owner._parse_socket_fdinfo(_client()) == ("127.0.0.1", CLIENT_PORT, "127.0.0.1", LISTEN_PORT)


@pytest.mark.parametrize(
    ("fields", "why"),
    [
        ({"kind": SOCKINFO_IN, "protocol": IPPROTO_UDP}, "UDP reports SOCKINFO_IN and can share the 4-tuple"),
        ({"protocol": IPPROTO_UDP}, "the TCP layout with a non-TCP protocol is not a TCP connection"),
        ({"family": socket.AF_INET6}, "IPv6 is not decoded here; the caller falls back to lsof"),
    ],
    ids=["udp-kind-in", "kind-tcp-proto-udp", "ipv6"],
)
def test_parse_socket_fdinfo_rejects_non_tcp_or_non_ipv4(fields: dict[str, int], why: str) -> None:
    assert owner._parse_socket_fdinfo(_client(**fields)) is None, why


class _FakeLibproc:
    """``{pid: [(fd, fdinfo bytes)]}``; every listed fd is a socket."""

    def __init__(self, table: dict[int, list[tuple[int, bytes]]]) -> None:
        self.table = table

    def proc_listpids(self, _type: int, _info: int, buf: Any, size: int) -> int:
        pids = list(self.table)
        if buf is None:
            return 4 * len(pids)
        for i, pid in enumerate(pids[: size // 4]):
            buf[i] = pid
        return 4 * min(len(pids), size // 4)

    def proc_pidinfo(self, pid: int, flavor: int, _arg: int, buf: Any, size: int) -> int:
        if flavor == owner._PROC_PIDTBSDINFO:
            if pid not in self.table:
                return 0
            # Darwin proc_bsdinfo ABI: pid at 12, creation seconds/useconds at 120/128.
            info = bytearray(136)
            struct.pack_into("<I", info, 12, pid)
            struct.pack_into("<QQ", info, 120, 1_700_000_000, 123_456)
            ctypes.memmove(buf, bytes(info), min(len(info), size))
            return min(len(info), size)
        assert flavor == owner._PROC_PIDLISTFDS
        fds = self.table.get(pid, [])
        if buf is None:
            return 8 * len(fds)
        for i, (fd, _info) in enumerate(fds[: size // 8]):
            buf[2 * i], buf[2 * i + 1] = fd, owner._PROX_FDTYPE_SOCKET
        return 8 * min(len(fds), size // 8)

    def proc_pidfdinfo(self, pid: int, fd: int, flavor: int, buf: Any, size: int) -> int:
        assert flavor == owner._PROC_PIDFDSOCKETINFO
        info = dict(self.table.get(pid, []))[fd]
        ctypes.memmove(buf, info, min(len(info), size))
        return min(len(info), size)


def _patch_libproc_cdll(monkeypatch: pytest.MonkeyPatch, libproc_provider: Any) -> None:
    real_cdll: Any = ctypes.CDLL

    def _cdll(name: Any, *args: Any, **kwargs: Any) -> Any:
        if name is not None and "libproc" in str(name).lower():
            return libproc_provider() if callable(libproc_provider) else libproc_provider
        return real_cdll(name, *args, **kwargs)

    monkeypatch.setattr(ctypes, "CDLL", _cdll)


def _lookup(monkeypatch: pytest.MonkeyPatch, table: dict[int, list[tuple[int, bytes]]]) -> int | None:
    _on(monkeypatch, "darwin")
    fake = _FakeLibproc(table)
    _patch_libproc_cdll(monkeypatch, fake)
    return owner._libproc_client_pid(CLIENT_PORT, LISTEN_PORT)


TCP = _client()
UDP = _client(kind=SOCKINFO_IN, protocol=IPPROTO_UDP)


def test_libproc_lookup_binds_the_lone_tcp_client_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    # Twin: the client's TCP socket alone names its pid.
    assert _lookup(monkeypatch, {101: [(5, TCP)]}) == 101


def test_libproc_lookup_skips_a_udp_socket_on_the_same_tuple(monkeypatch: pytest.MonkeyPatch) -> None:
    # A UDP socket of another pid on the same 4-tuple, listed first, never names the client: the TCP holder does.
    assert _lookup(monkeypatch, {201: [(3, UDP)], 202: [(7, TCP)]}) == 202


def test_libproc_lookup_refuses_two_pids_holding_the_tcp_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    # Two distinct pids hold the matching TCP socket (an inherited fd): ambiguous, nothing is bound.
    assert _lookup(monkeypatch, {301: [(4, TCP)], 302: [(4, TCP)]}) is None


def test_libproc_lookup_ignores_the_server_side_tuple(monkeypatch: pytest.MonkeyPatch) -> None:
    # Only the server side of the connection (reversed tuple) exists: no client pid.
    assert _lookup(monkeypatch, {401: [(6, _server())]}) is None


# --- No later path may resolve an ambiguity (T9-PORT-F3-R2) ----------------------------------------------------------
# Seams: the platform branch reads the module's ``sys.platform`` (patched as ``owner.sys``), the lsof fallback calls
# ``subprocess.run`` (patched), the Linux path reads ``_LINUX_PROC_ROOT`` (patched to a fake tree) and resolves fd
# links with the fake holder callback, without requiring Linux directory-fd syscalls on other hosts.

LSOF_NAME = f"n127.0.0.1:{CLIENT_PORT}->127.0.0.1:{LISTEN_PORT}"


def test_lsof_output_with_two_holders_is_ambiguous() -> None:
    out = f"p100\nf3\n{LSOF_NAME}\np200\nf4\n{LSOF_NAME}\n"
    assert owner._parse_lsof_client_pid(out, client_port=CLIENT_PORT, listen_port=LISTEN_PORT) is None


def test_lsof_output_with_one_holder_on_two_fds_names_it() -> None:
    out = f"p100\nf3\n{LSOF_NAME}\nf4\n{LSOF_NAME}\n"
    assert owner._parse_lsof_client_pid(out, client_port=CLIENT_PORT, listen_port=LISTEN_PORT) == 100


def _on(monkeypatch: pytest.MonkeyPatch, platform: str) -> None:
    monkeypatch.setattr(owner, "sys", type("FakeSys", (), {"platform": platform})())


def _lsof(monkeypatch: pytest.MonkeyPatch, stdout: str | None) -> list[list[str]]:
    """Patch ``subprocess.run``; ``stdout=None`` makes any call fail the test."""
    calls: list[list[str]] = []

    def run(cmd: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        assert stdout is not None, "lsof must not run once libproc found the connection"
        return subprocess.CompletedProcess(cmd, 0, stdout=stdout, stderr="")

    monkeypatch.setattr(subprocess, "run", run)
    return calls


def test_darwin_ambiguous_libproc_result_is_final(monkeypatch: pytest.MonkeyPatch) -> None:
    _on(monkeypatch, "darwin")
    calls = _lsof(monkeypatch, None)
    fake = _FakeLibproc({301: [(4, TCP)], 302: [(4, TCP)]})
    _patch_libproc_cdll(monkeypatch, fake)

    def unknown_creation(_pid: int) -> str:
        raise OSError("creation_time_unavailable")

    # Unknown process identity must not remove a socket holder from ambiguity.
    monkeypatch.setattr(owner, "process_started_at_for_pid", unknown_creation)
    assert owner._lookup_loopback_client_pid(CLIENT_PORT, LISTEN_PORT) is None
    assert calls == []


@pytest.mark.parametrize("libproc", ["unavailable", "no-pids"])
def test_darwin_falls_back_to_lsof_only_without_libproc_data(monkeypatch: pytest.MonkeyPatch, libproc: str) -> None:
    _on(monkeypatch, "darwin")
    calls = _lsof(monkeypatch, f"p100\nf3\n{LSOF_NAME}\n")
    if libproc == "unavailable":

        def no_lib(*_a: Any, **_k: Any) -> Any:
            raise OSError("libproc.dylib not found")

        _patch_libproc_cdll(monkeypatch, no_lib)
    else:
        empty = _FakeLibproc({})
        _patch_libproc_cdll(monkeypatch, empty)
    assert owner._lookup_loopback_client_pid(CLIENT_PORT, LISTEN_PORT) == 100
    assert len(calls) == 1 and calls[0][0] == "lsof"


def _tcp_row(local_hex: str, remote_hex: str, inode: int) -> str:
    return f"   0: {local_hex}:{CLIENT_PORT:04X} {remote_hex}:{LISTEN_PORT:04X} 01 00000000:00000000 00:00000000 " \
        f"00000000  1000        0 {inode} 1 0000000000000000 20 4 30 10 -1"


V4 = "0100007F"
V6 = "0000000000000000FFFF00000100007F"
HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"


def _patch_fake_linux_holders(
    monkeypatch: pytest.MonkeyPatch, root: Path, readlink: Callable[[Path], str]
) -> None:
    """Supply only the fake per-process kernel query to the portable scan tests."""
    def holder(pid: int, pid_dir: Path, target: str) -> bool:
        assert pid_dir == root / str(pid)
        if not (pid_dir / "fd").is_dir():
            return False
        with os.scandir(pid_dir / "fd") as entries:
            for entry in entries:
                try:
                    matched = readlink(Path(entry.path)) == target
                except OSError:
                    continue
                if matched:
                    if getattr(owner._SIGHTING, "ns", None) is None:
                        owner._store_sighting(
                            pid, "2020-01-01T00:00:00.000000Z", owner._stamp_ns(), owner._utc_now_z()
                        )
                    return True
        return False

    monkeypatch.setattr(owner, "_linux_socket_holder", holder)


def _fake_proc(
    monkeypatch: pytest.MonkeyPatch, root: Path, *, tcp: list[str], tcp6: list[str], fds: dict[int, list[int]]
) -> None:
    """``fds``: pid -> socket inodes its fds link to (one fd per entry)."""
    (root / "net").mkdir(parents=True)
    (root / "net" / "tcp").write_text("\n".join([HEADER, *tcp]) + "\n", encoding="ascii")
    (root / "net" / "tcp6").write_text("\n".join([HEADER, *tcp6]) + "\n", encoding="ascii")
    links: dict[str, str] = {}
    for pid, inodes in fds.items():
        (root / str(pid) / "fd").mkdir(parents=True)
        for fd, inode in enumerate(inodes, start=3):
            path = root / str(pid) / "fd" / str(fd)
            path.write_bytes(b"")
            links[str(path)] = f"socket:[{inode}]"
    (root / "self").mkdir()  # non-numeric entries are skipped

    def readlink(path: Any, *_a: Any, **_k: Any) -> str:
        try:
            return links[str(path)]
        except KeyError:
            raise OSError(f"not a link: {path}") from None

    _patch_fake_linux_holders(monkeypatch, root, readlink)
    monkeypatch.setattr(owner, "_LINUX_PROC_ROOT", root)
    _on(monkeypatch, "linux")


@pytest.mark.parametrize(
    ("table", "fds", "expected"),
    [
        ("tcp", {501: [111]}, 501),
        ("tcp", {501: [111], 502: [111]}, None),
        ("tcp", {501: [111, 111]}, 501),
        ("tcp6", {601: [222], 602: [222]}, None),
        ("tcp6", {601: [222, 222]}, 601),
    ],
    ids=["tcp-one-holder", "tcp-two-holders", "tcp-one-holder-two-fds", "tcp6-two-holders", "tcp6-one-holder-two-fds"],
)
def test_linux_socket_inode_binds_only_a_single_holder(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, table: str, fds: dict[int, list[int]], expected: int | None
) -> None:
    rows = {"tcp": [_tcp_row(V4, V4, 111)], "tcp6": [_tcp_row(V6, V6, 222)]}
    _fake_proc(
        monkeypatch,
        tmp_path / "proc",
        tcp=rows["tcp"] if table == "tcp" else [],
        tcp6=rows["tcp6"] if table == "tcp6" else [],
        fds=fds,
    )
    assert owner._lookup_loopback_client_pid(CLIENT_PORT, LISTEN_PORT) == expected


def test_linux_ambiguous_tcp_holder_is_not_resolved_by_the_tcp6_table(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # The tcp table names the connection but two processes hold it; a single holder found later through tcp6
    # must not turn that ambiguity into a binding.
    _fake_proc(
        monkeypatch,
        tmp_path / "proc",
        tcp=[_tcp_row(V4, V4, 111)],
        tcp6=[_tcp_row(V6, V6, 222)],
        fds={501: [111], 502: [111], 601: [222]},
    )
    assert owner._lookup_loopback_client_pid(CLIENT_PORT, LISTEN_PORT) is None
