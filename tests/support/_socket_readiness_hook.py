"""Test-only client TLS pre-identity socket readiness probe for controlled Linux fixtures.

Installed only into temporary test wheel virtual environments by ``inc2_fixture.py`` and
activated only when ``SUPERBRAIN_TEST_SOCKET_READINESS`` is explicitly set by controlled
positive integration fixtures. Production ``src/superbrain`` contains no fixture flags.
"""

from __future__ import annotations

import json
import os
import socket
from collections.abc import Callable
from typing import Any

_READINESS_ENV_VAR = "SUPERBRAIN_TEST_SOCKET_READINESS"
_READINESS_PATH = "/__test_socket_readiness"
_IDENTITY_PREFIX = b"GET /v2/identity HTTP/1.1\r\n"
_MAX_READINESS_BODY_BYTES = 4096

_HOOK_LOCK_STATE: dict[str, Any] = {
    "installed": False,
    "orig_write_all": None,
}


def _extract_host_header(probe_frame: bytes, sock: socket.socket) -> str:
    """Extract Host header value from ``GET /v2/identity`` frame or derive from connected peer."""
    for line in probe_frame.split(b"\r\n")[1:]:
        if not line:
            break
        if line.lower().startswith(b"host:"):
            value = line.split(b":", 1)[1].strip().decode("ascii")
            if value:
                return value
    peer_ip, peer_port = sock.getpeername()[:2]
    ip_text = str(peer_ip)
    if ":" in ip_text:
        return f"[{ip_text}]:{int(peer_port)}"
    return f"{ip_text}:{int(peer_port)}"


def perform_socket_readiness_probe(
    sock: socket.socket,
    probe_frame: bytes,
    deadline_ns: int,
    monotonic_ns: Callable[[], int],
    write_fn: Callable[[socket.socket, bytes, int, Callable[[], int]], None],
    token: str,
) -> None:
    """Perform causal pre-identity socket readiness handshake strictly within ``deadline_ns``."""
    from superbrain.cli_api._http_frames import FramedReader, HttpFramingError
    from superbrain.core.errors import ErrorCode

    if not token:
        raise HttpFramingError(ErrorCode.IO_ERROR, "missing socket readiness token")

    host_header = _extract_host_header(probe_frame, sock)
    body = json.dumps({"token": token}, separators=(",", ":"), sort_keys=True).encode("utf-8")
    req = (
        f"POST {_READINESS_PATH} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: keep-alive\r\n\r\n"
    ).encode("ascii") + body

    write_fn(sock, req, deadline_ns, monotonic_ns)
    reader = FramedReader(sock, monotonic_ns)
    head = reader.read_response_head(deadline_ns)
    for conn_val in head.get_all("Connection"):
        if "close" in conn_val.lower():
            raise HttpFramingError(ErrorCode.IO_ERROR, "socket readiness closed connection")
    if (
        head.status != 200
        or head.content_length is None
        or head.content_length <= 0
        or head.content_length > _MAX_READINESS_BODY_BYTES
    ):
        raise HttpFramingError(ErrorCode.IO_ERROR, "socket readiness not acknowledged")

    raw_body = reader.read_exact(head.content_length, deadline_ns)
    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as err:
        raise HttpFramingError(ErrorCode.IO_ERROR, "invalid socket readiness response") from err
    if (
        not isinstance(payload, dict)
        or set(payload.keys()) != {"ok", "ready"}
        or payload.get("ok") is not True
        or payload.get("ready") is not True
    ):
        raise HttpFramingError(ErrorCode.IO_ERROR, "socket readiness rejected")


def install() -> None:
    """Wrap ``superbrain.cli_api.loopback.write_all`` lazily when readiness env is set."""
    if _HOOK_LOCK_STATE["installed"]:
        return

    import superbrain.cli_api.loopback as loopback_mod

    loopback_any: Any = loopback_mod
    orig_write_all: Callable[[socket.socket, bytes, int, Callable[[], int]], None] = loopback_any.write_all

    def _wrapped_write_all(
        sock: socket.socket,
        data: bytes,
        deadline_ns: int,
        monotonic_ns: Callable[[], int],
    ) -> None:
        token = os.environ.get(_READINESS_ENV_VAR, "")
        if token and isinstance(data, (bytes, bytearray, memoryview)) and bytes(data).startswith(_IDENTITY_PREFIX):
            perform_socket_readiness_probe(
                sock,
                bytes(data),
                deadline_ns,
                monotonic_ns,
                orig_write_all,
                token,
            )
        orig_write_all(sock, data, deadline_ns, monotonic_ns)

    _HOOK_LOCK_STATE["orig_write_all"] = orig_write_all
    _HOOK_LOCK_STATE["installed"] = True
    loopback_any.write_all = _wrapped_write_all


def uninstall() -> None:
    """Restore ``superbrain.cli_api.loopback.write_all`` if currently installed."""
    orig_write_all = _HOOK_LOCK_STATE.get("orig_write_all")
    if not _HOOK_LOCK_STATE["installed"] or orig_write_all is None:
        return
    import superbrain.cli_api.loopback as loopback_mod

    loopback_any: Any = loopback_mod
    loopback_any.write_all = orig_write_all
    _HOOK_LOCK_STATE["orig_write_all"] = None
    _HOOK_LOCK_STATE["installed"] = False
