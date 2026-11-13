"""Task 9 (macOS libproc lookup, run on any OS): a loopback client PID is bound only from the TCP socket carrying
that exact client->listen connection, never from another protocol's socket on the same 4-tuple, never ambiguously.

Seam: ``_libproc_client_pid`` does ``import ctypes`` and calls ``ctypes.CDLL(...)`` at call time, so patching the
``ctypes.CDLL`` attribute hands it a fake libproc. The fake implements only the three calls the lookup makes
(``proc_listpids``, ``proc_pidinfo(PROC_PIDLISTFDS)``, ``proc_pidfdinfo(PROC_PIDFDSOCKETINFO)``) over an in-memory
process table, with ``socket_fdinfo`` buffers built at the module's own offsets.
"""

from __future__ import annotations

import ctypes
import socket
import struct
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


def _lookup(monkeypatch: pytest.MonkeyPatch, table: dict[int, list[tuple[int, bytes]]]) -> int | None:
    fake = _FakeLibproc(table)
    monkeypatch.setattr(ctypes, "CDLL", lambda *_a, **_k: fake)
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
