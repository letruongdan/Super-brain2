"""Signal-driven stop guard and the config-path entry point of the kernel daemon."""

from __future__ import annotations

import contextlib
import queue
import signal
import threading
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from types import FrameType
from typing import TYPE_CHECKING

from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.daemon_config import read_daemon_config
from superbrain.application.dispatch import KernelToolDomain
from superbrain.application.owner_loop import OwnerLoop
from superbrain.composition._daemon_session import (
    DaemonTestHooks,
)
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import (
    DEFAULT_SHUTDOWN_GRACE_S,
    Ready,
)
from superbrain.ports.clock import Clock, MonotonicClock
from superbrain.ports.doctor import CaptureDoctorProbePort, OutboxReplayPort, SupervisorControlPort
from superbrain.ports.os import OsAdapters
from superbrain.workers.executor import JobHandler

if TYPE_CHECKING:
    pass
from superbrain.composition import daemon_entry as _m


@contextlib.contextmanager
def _signal_stop_guard(target: threading.Event) -> Iterator[Callable[[], bool]]:
    """Latch stop signals and request ``target`` asynchronously in every phase; yields ``signalled()``.

    The handler never touches ``target``: CPython runs it on the main thread, which may be inside ``target.wait()``
    holding its condition lock. It only records the signal and wakes a watcher thread that calls ``target.set()``.
    """
    flag = [False]
    if threading.current_thread() is not threading.main_thread():
        yield lambda: flag[0]
        return
    saved: list[tuple[signal.Signals, Callable[[int, FrameType | None], object] | int | None]] = []
    wake: queue.SimpleQueue[int | None] = queue.SimpleQueue()

    def _watch() -> None:
        while wake.get() is not None:
            target.set()

    watcher = threading.Thread(target=_watch, name="superbrain-stop-signal", daemon=True)
    watcher.start()

    def _handler(signum: int, _frame: FrameType | None) -> None:
        flag[0] = True
        wake.put_nowait(signum)  # SimpleQueue.put is reentrant: documented safe from a signal handler

    candidates: list[signal.Signals] = [signal.SIGINT, signal.SIGTERM]
    sigbreak = getattr(signal, "SIGBREAK", None)
    if isinstance(sigbreak, signal.Signals):
        candidates.append(sigbreak)

    for sig in candidates:
        with contextlib.suppress(OSError, ValueError):
            prev = signal.getsignal(sig)
            signal.signal(sig, _handler)
            saved.append((sig, prev))
    try:
        yield lambda: flag[0]
    finally:
        for sig, prev in saved:
            with contextlib.suppress(OSError, ValueError, TypeError):
                signal.signal(sig, prev)
        wake.put_nowait(None)  # after restore: every signal the handler queued is applied before the watcher exits
        watcher.join(timeout=1.0)


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
    outbox_replay: OutboxReplayPort | None = None,
    supervisor_control: SupervisorControlPort | None = None,
    log_quiesce_hook: Callable[[], contextlib.AbstractContextManager[None]] | None = None,
    capture_probe: CaptureDoctorProbePort | None = None,
) -> int:
    """Read and validate ``DaemonConfig`` from ``config_path`` and execute ``serve(...)``."""
    if not isinstance(config_path, Path):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    adapters = os_ if os_ is not None else os_adapters(clock=clock, monotonic=monotonic_clock)
    cfg = read_daemon_config(config_path, adapters)
    return _m.serve(
        cfg, os_=adapters, clock=clock, monotonic_clock=monotonic_clock, stop_event=stop_event,
        shutdown_grace_s=shutdown_grace_s, on_ready=on_ready, domain=domain, job_handlers=job_handlers,
        hooks=hooks, outbox_replay=outbox_replay, supervisor_control=supervisor_control,
        log_quiesce_hook=log_quiesce_hook, capture_probe=capture_probe, config_path=config_path,
    )
