"""pytest plugin (CI diagnostic only): time where LoopbackServer.finish() spends time after its cutoff."""

import sys
import time

from superbrain.cli_api import _loopback_server as srv

_finish = srv.LoopbackServer.finish
_abort_all = srv.LoopbackServer._abort_all_active_sockets
_safe_join = srv._safe_join


def _trace_abort_all(self):  # type: ignore[no-untyped-def]
    t0 = time.perf_counter()
    try:
        return _abort_all(self)
    finally:
        print(f"[trace] _abort_all_active_sockets {time.perf_counter() - t0:.4f}s", file=sys.stderr)


def _trace_join(thread, timeout):  # type: ignore[no-untyped-def]
    t0 = time.perf_counter()
    try:
        return _safe_join(thread, timeout)
    finally:
        took = time.perf_counter() - t0
        if took > 0.005:
            print(f"[trace] join {getattr(thread, 'name', thread)} timeout={timeout:.4f} took {took:.4f}s", file=sys.stderr)


def _trace_finish(self, stop_deadline):  # type: ignore[no-untyped-def]
    t0 = time.perf_counter()
    try:
        return _finish(self, stop_deadline)
    finally:
        end = time.perf_counter()
        print(f"[trace] finish total {end - t0:.4f}s past_deadline {end - stop_deadline:.4f}s", file=sys.stderr)


srv.LoopbackServer.finish = _trace_finish
srv.LoopbackServer._abort_all_active_sockets = _trace_abort_all
srv._safe_join = _trace_join
