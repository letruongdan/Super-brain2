"""T9-F12: a stop signal always stops the daemon; its handler never takes a lock the interrupted main thread may hold.

Seam: ``daemon_entry._signal_stop_guard``, the context manager ``serve()`` wraps its whole lifecycle in. ``serve()``
itself needs a started owner loop on a real data root and listener, so the guard is the honest unit: the test drives
the exact state that hung the daemon -- the main thread inside the stop Event's internal condition lock, as
``Event.wait()`` holds it while entering and leaving its ``with self._cond`` -- and delivers the signal right there.

Deterministic: ``signal.raise_signal`` queues the signal and its Python handler runs at the next bytecode boundary,
still inside the lock. A handler that calls ``Event.set()`` then blocks forever; faulthandler dumps the child's stack
and exits it, and the parent fails with that stack. The lock and signal step runs before ``signalled()`` is touched, so
a guard without the callable still fails by hanging, not by an attribute error.
"""

from __future__ import annotations

import signal
import subprocess
import sys

import pytest

CHILD = r"""
import faulthandler, signal, sys, threading
from superbrain.composition.daemon_entry import _signal_stop_guard

sig = getattr(signal, sys.argv[1])
faulthandler.dump_traceback_later(4.0, exit=True)  # a blocked handler: dump every stack and exit non-zero
stop = threading.Event()
with _signal_stop_guard(stop) as signalled:
    with stop._cond:  # the main thread holds what Event.wait() holds while entering/leaving its wait
        signal.raise_signal(sig)  # the Python handler runs here, inside the lock
        sys.stdout.write("handler-returned\n")
    faulthandler.cancel_dump_traceback_later()
    assert callable(signalled) and signalled() is True, signalled
sys.stdout.write("ok\n")
"""

SIGNALS = [name for name in ("SIGTERM", "SIGINT", "SIGBREAK") if hasattr(signal, name)]


@pytest.mark.parametrize("signame", SIGNALS)
def test_stop_signal_handler_never_blocks_on_the_stop_event_lock(signame: str) -> None:
    try:
        proc = subprocess.run(
            [sys.executable, "-c", CHILD, signame], capture_output=True, text=True, timeout=10.0
        )
    except subprocess.TimeoutExpired as exc:  # backstop: faulthandler should have ended the child at 4 s
        pytest.fail(f"{signame}: child still running after 10 s (killed): {exc.stderr!r}")
    assert proc.returncode == 0 and proc.stdout == "handler-returned\nok\n", (
        f"{signame}: the stop-signal handler blocked or did not record the signal\n"
        f"rc={proc.returncode}\nstdout={proc.stdout!r}\nstderr:\n{proc.stderr}"
    )
