"""Loopback TLS listener binding and lease-fenced ``endpoint.json`` publication (Task 6a)."""

from __future__ import annotations

import contextlib
import os
import socket
import ssl
from dataclasses import dataclass

from superbrain.adapters.os.durable import map_os_error
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.kernel import (
    DAEMON_LISTEN_BACKLOG,
    ENDPOINT_HOST,
    DaemonConfig,
    Endpoint,
)
from superbrain.ports.os import OsAdapters
from superbrain.storage.errors import os_error
from superbrain.storage.layout import (
    ENDPOINT_STAGE_PREFIX,
    DataRoot,
    check_endpoint_entries_under_lease,
)
from superbrain.storage.writer import WriterLease


@dataclass(frozen=True)
class BoundLoopbackListener:
    """Bound ``127.0.0.1`` loopback socket and verified server ``SSLContext`` (handed to Task 6b)."""

    sock: socket.socket
    ssl_context: ssl.SSLContext
    port: int

    def close(self) -> None:
        with contextlib.suppress(OSError):
            self.sock.close()


def build_server_ssl_context(config: DaemonConfig) -> ssl.SSLContext:
    """Construct a TLS >= 1.2 server context from already-verified ``(cert_path, key_path)``."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=config.cert_path, keyfile=config.key_path)
    except ssl.SSLError as err:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input") from err
    except FileNotFoundError as err:
        raise BrainError(ErrorCode.NOT_FOUND, "not found") from err
    except OSError as err:
        raise map_os_error(err, "loading server TLS certificate") from err
    return ctx


def bind_loopback_listener(ssl_context: ssl.SSLContext) -> BoundLoopbackListener:
    """Bind ``127.0.0.1:0`` with backlog ``32`` without enabling unsafe port sharing."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        excl_opt = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
        if isinstance(excl_opt, int):
            sock.setsockopt(socket.SOL_SOCKET, excl_opt, 1)
        sock.bind((ENDPOINT_HOST, 0))
        sock.listen(DAEMON_LISTEN_BACKLOG)
        addr = sock.getsockname()
        port = int(addr[1])
    except OSError as err:
        with contextlib.suppress(OSError):
            sock.close()
        raise BrainError(ErrorCode.IO_ERROR, "I/O error") from err
    return BoundLoopbackListener(sock=sock, ssl_context=ssl_context, port=port)


def publish_endpoint(
    root: DataRoot,
    lease: WriterLease,
    endpoint: Endpoint,
    os_: OsAdapters,
) -> None:
    """Stage, secure, fsync, and atomically publish ``endpoint.json`` under a held ``WriterLease``."""
    if not isinstance(root, DataRoot) or not isinstance(endpoint, Endpoint):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if not lease.held or lease.root != root or lease.epoch != endpoint.writer_epoch:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
    check_endpoint_entries_under_lease(root, lease, os_)
    stage_path = root.root / f"{ENDPOINT_STAGE_PREFIX}{new_id()}"
    payload = endpoint.encode_canonical()
    try:
        os_.publisher.write_new(stage_path, payload)
        os_.permissions.secure_file(stage_path)
        os_.publisher.flush_file(stage_path)
        os_.publisher.publish(stage_path, root.endpoint_path)
    except BaseException:
        if os.path.lexists(stage_path):
            with contextlib.suppress(OSError):
                stage_path.unlink()
        raise


def remove_own_endpoint(
    root: DataRoot,
    lease: WriterLease,
    endpoint: Endpoint,
    os_: OsAdapters,
) -> bool:
    """Remove ``endpoint.json`` under ``lease`` iff its ``(store_id, writer_epoch, instance_id)`` matches."""
    if not isinstance(root, DataRoot) or not isinstance(endpoint, Endpoint):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if not lease.held or lease.root != root or lease.epoch != endpoint.writer_epoch:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
    check_endpoint_entries_under_lease(root, lease, os_)
    ep_path = root.endpoint_path
    if not os.path.lexists(ep_path):
        return False
    try:
        raw = ep_path.read_bytes()
    except FileNotFoundError:
        return False
    except OSError as err:
        raise os_error("reading endpoint descriptor", err) from err
    parsed = Endpoint.from_canonical(raw)
    if parsed.identity != endpoint.identity:
        return False
    try:
        ep_path.unlink()
    except FileNotFoundError:
        return False
    except OSError as err:
        raise os_error("removing endpoint descriptor", err) from err
    os_.publisher.sync_directory(root.root)
    return True
