"""Composition entry point for the Increment 2 kernel daemon lifecycle (Task 6a)."""

from __future__ import annotations

import contextlib
import socket
import ssl
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from superbrain.application.deadlines import Reservation
from superbrain.application.dispatch import KernelToolDomain
from superbrain.application.owner_loop import OwnerLoop
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import (
    DEFAULT_SHUTDOWN_GRACE_S,
    DaemonConfig,
    Endpoint,
    Ready,
    RequestAuthView,
)
from superbrain.ports.clock import Clock, MonotonicClock
from superbrain.ports.os import OsAdapters
from superbrain.storage.layout import DataRoot
from superbrain.storage.runtime import Runtime
from superbrain.storage.writer import WriterLease
from superbrain.workers.executor import PRODUCTION_JOB_HANDLERS, JobHandler

__all__ = [
    "BoundLoopbackListener",
    "DaemonTestHooks",
    "PRODUCTION_JOB_HANDLERS",
    "create_daemon_owner_loop",
    "publish_endpoint",
    "remove_own_endpoint",
    "serve",
    "serve_config_path",
]


@dataclass(frozen=True)
class BoundLoopbackListener:
    """Bound ``127.0.0.1`` loopback socket and verified server ``SSLContext`` (handed to Task 6b)."""

    sock: socket.socket
    ssl_context: ssl.SSLContext
    port: int

    def close(self) -> None:
        with contextlib.suppress(OSError):
            self.sock.close()


@dataclass(frozen=True)
class DaemonTestHooks:
    """Optional deterministic barriers/fault seams for daemon lifecycle integration tests."""

    after_tls_verify: Callable[[], None] | None = None
    after_open_before_rebuild: Callable[[Runtime], None] | None = None
    before_job_recover: Callable[[Runtime], None] | None = None
    before_bind: Callable[[Runtime], None] | None = None
    before_endpoint_publish: Callable[[Endpoint], None] | None = None
    after_endpoint_publish_before_final_tls_check: Callable[[Endpoint], None] | None = None
    before_auth_gate_publish: Callable[[RequestAuthView], None] | None = None
    before_enter_commit: Callable[[Reservation | None], None] | None = None
    after_reserve_before_enqueue: Callable[[Reservation], None] | None = None
    before_runtime_close: Callable[[Runtime], None] | None = None


def publish_endpoint(
    root: DataRoot,
    lease: WriterLease,
    endpoint: Endpoint,
    os_: OsAdapters,
) -> None:
    """Stage, secure, fsync, and atomically publish ``endpoint.json`` under a held ``WriterLease``."""
    del root, lease, endpoint, os_
    raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")


def remove_own_endpoint(
    root: DataRoot,
    lease: WriterLease,
    endpoint: Endpoint,
    os_: OsAdapters,
) -> bool:
    """Remove ``endpoint.json`` under ``lease`` iff its ``(store_id, writer_epoch, instance_id)`` matches."""
    del root, lease, endpoint, os_
    raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")


def create_daemon_owner_loop(
    *,
    os_: OsAdapters | None = None,
    clock: Clock | None = None,
    monotonic_clock: MonotonicClock | None = None,
    domain: KernelToolDomain | None = None,
    job_handlers: Mapping[str, JobHandler] | None = None,
    hooks: DaemonTestHooks | None = None,
    on_listener_bound: Callable[[BoundLoopbackListener], None] | None = None,
) -> OwnerLoop:
    """Construct an ``OwnerLoop`` wired to real admission, recovery, bridge, worker, and listener ports."""
    del os_, clock, monotonic_clock, domain, job_handlers, hooks, on_listener_bound
    return OwnerLoop()


def serve(
    config: DaemonConfig,
    *,
    os_: OsAdapters | None = None,
    clock: Clock | None = None,
    monotonic_clock: MonotonicClock | None = None,
    stop_event: threading.Event | None = None,
    shutdown_grace_s: float = DEFAULT_SHUTDOWN_GRACE_S,
    on_ready: Callable[[Ready, OwnerLoop], None] | None = None,
    domain: KernelToolDomain | None = None,
    job_handlers: Mapping[str, JobHandler] | None = None,
    hooks: DaemonTestHooks | None = None,
) -> int:
    """Run the foreground kernel daemon lifecycle for ``config`` and return process exit status."""
    del (
        config,
        os_,
        clock,
        monotonic_clock,
        stop_event,
        shutdown_grace_s,
        on_ready,
        domain,
        job_handlers,
        hooks,
    )
    raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")


def serve_config_path(
    config_path: Path,
    *,
    os_: OsAdapters | None = None,
    clock: Clock | None = None,
    monotonic_clock: MonotonicClock | None = None,
    stop_event: threading.Event | None = None,
    shutdown_grace_s: float = DEFAULT_SHUTDOWN_GRACE_S,
    on_ready: Callable[[Ready, OwnerLoop], None] | None = None,
    domain: KernelToolDomain | None = None,
    job_handlers: Mapping[str, JobHandler] | None = None,
    hooks: DaemonTestHooks | None = None,
) -> int:
    """Read and validate ``DaemonConfig`` from ``config_path`` and execute ``serve(...)``."""
    del (
        config_path,
        os_,
        clock,
        monotonic_clock,
        stop_event,
        shutdown_grace_s,
        on_ready,
        domain,
        job_handlers,
        hooks,
    )
    raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")
