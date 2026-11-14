"""T9-PORT-F12-R1: a stop signal sets the daemon's stop event in every phase (sealed I2-T7-R05), without the handler
ever taking the event's lock.

Seam: ``daemon_entry._signal_stop_guard`` (``serve()`` needs a started owner loop, data root and listener, so the guard
plus a serve-style poll is the honest unit). Each case runs in a child with ``faulthandler.dump_traceback_later`` and a
parent timeout, so a blocked handler or a loop that never stops fails with the child's stacks instead of hanging.
The poll loop deliberately does not consult ``signalled()``: during owner/transport startup no poll loop runs, so the
guard itself must turn the signal into ``target.set()``.
"""

from __future__ import annotations

import signal
import subprocess
import sys

import pytest

CHILD = r"""
import faulthandler, signal, sys, threading, time
from superbrain.composition.daemon_entry import _signal_stop_guard

mode, signame = sys.argv[1], sys.argv[2]
sig = getattr(signal, signame)
faulthandler.dump_traceback_later(6.0, exit=True)
WATCHER = "superbrain-stop-signal"
seen = []
stop_names = [n for n in ("SIGINT", "SIGTERM", "SIGBREAK") if hasattr(signal, n)]
for n in stop_names:  # previous handlers: record instead of dying if a signal outlives the guard
    signal.signal(getattr(signal, n), lambda s, f: seen.append(s))
previous = {n: signal.getsignal(getattr(signal, n)) for n in stop_names}


def watchers():
    return [t for t in threading.enumerate() if t.name == WATCHER and t.is_alive()]


def poll_until_set(stop, bound=2.0):
    end = time.monotonic() + bound
    while not stop.wait(timeout=0.02):  # serve()'s poll, without consulting signalled()
        assert time.monotonic() < end, "stop event not set within the bound"


def signal_inside_wait_lock(stop, *sigs):
    with stop._cond:  # what Event.wait() holds while entering/leaving its wait
        for s in sigs:
            signal.raise_signal(s)  # the handler runs here, inside the lock


if mode == "converts":
    stop = threading.Event()
    with _signal_stop_guard(stop) as signalled:
        signal_inside_wait_lock(stop, sig)
        poll_until_set(stop)
        assert signalled() is True

elif mode == "repeated":
    stop = threading.Event()
    others = [getattr(signal, n) for n in stop_names]
    with _signal_stop_guard(stop) as signalled:
        signal_inside_wait_lock(stop, sig, *others, sig)
        poll_until_set(stop)
        stop.clear()
        signal_inside_wait_lock(stop, sig)  # a later signal is converted too
        poll_until_set(stop)
        assert signalled() is True

elif mode == "during_exit":
    stop = threading.Event()
    real_signal = signal.signal
    fired = []

    def restoring(s, handler):
        if not fired and handler is previous.get(signal.Signals(s).name):  # first restore call: the guard is exiting
            fired.append(s)
            other = next(getattr(signal, n) for n in stop_names if getattr(signal, n) != s)
            signal.raise_signal(other)  # its guard handler is still installed
        return real_signal(s, handler)

    with _signal_stop_guard(stop):
        signal.signal = restoring
    signal.signal = real_signal
    assert fired, "the guard restored no handler"
    assert stop.is_set(), "a signal that landed while the guard was exiting was dropped"
    assert not seen, seen

elif mode == "no_leak":
    stop = threading.Event()
    with _signal_stop_guard(stop):
        pass
    assert not watchers(), watchers()
    assert {n: signal.getsignal(getattr(signal, n)) for n in stop_names} == previous

elif mode == "worker_thread":
    stop = threading.Event()
    box = {}

    def body():
        with _signal_stop_guard(stop) as signalled:
            box["installed"] = {n: signal.getsignal(getattr(signal, n)) for n in stop_names} != previous
            box["watchers"] = len(watchers())
            box["signalled"] = signalled()

    t = threading.Thread(target=body)
    t.start()
    t.join()
    assert box == {"installed": False, "watchers": 0, "signalled": False}, box
    assert not watchers() and not stop.is_set()

faulthandler.cancel_dump_traceback_later()
sys.stdout.write("ok\n")
"""

SIGNALS = [name for name in ("SIGTERM", "SIGINT", "SIGBREAK") if hasattr(signal, name)]
MODES = ["converts", "repeated", "during_exit", "no_leak", "worker_thread"]


@pytest.mark.parametrize("signame", SIGNALS)
@pytest.mark.parametrize("mode", MODES)
def test_stop_signal_conversion(mode: str, signame: str) -> None:
    try:
        proc = subprocess.run(
            [sys.executable, "-c", CHILD, mode, signame], capture_output=True, text=True, timeout=15.0
        )
    except subprocess.TimeoutExpired as exc:  # backstop: faulthandler should have ended the child at 6 s
        pytest.fail(f"{mode}/{signame}: child still running after 15 s (killed): {exc.stderr!r}")
    assert proc.returncode == 0 and proc.stdout == "ok\n", (
        f"{mode}/{signame}: rc={proc.returncode}\nstdout={proc.stdout!r}\nstderr:\n{proc.stderr[-4000:]}"
    )
