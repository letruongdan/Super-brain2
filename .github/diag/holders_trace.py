"""pytest plugin (CI diagnostic only): log every macOS client-PID lookup the observer makes, with timing and holders."""

import sys
import time

from tests.support import inc2_native_owner as own

_holders = own._libproc_client_holders
_lookup = own._lookup_loopback_client_pid
_started = own.process_started_at_for_pid


def _trace_holders(client_port: int, listen_port: int):  # type: ignore[no-untyped-def]
    t0 = time.monotonic()
    result = _holders(client_port, listen_port)
    print(f"[trace] holders {client_port}->{listen_port} = {result} in {time.monotonic() - t0:.4f}s", file=sys.stderr)
    return result


def _trace_lookup(client_port: int, listen_port: int, **kwargs):  # type: ignore[no-untyped-def]
    t0 = time.monotonic()
    state = kwargs.get("conn_state")
    closing_before = None if state is None else (state.get("closing"), state["closed_event"].is_set())
    result = _lookup(client_port, listen_port, **kwargs)
    closing_after = None if state is None else (state.get("closing"), state["closed_event"].is_set())
    print(
        f"[trace] lookup {client_port}->{listen_port} = {result} in {time.monotonic() - t0:.4f}s "
        f"closing/closed before={closing_before} after={closing_after}",
        file=sys.stderr,
    )
    return result


def _trace_started(pid: int) -> str:
    t0 = time.monotonic()
    result = _started(pid)
    print(f"[trace] started_at {pid} = {result} in {time.monotonic() - t0:.4f}s", file=sys.stderr)
    return result


own._libproc_client_holders = _trace_holders
own._lookup_loopback_client_pid = _trace_lookup
own.process_started_at_for_pid = _trace_started
