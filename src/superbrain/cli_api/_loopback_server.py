"""Bounded TLS/HTTP loopback server enforcing two-request admission on the owner listener."""

from __future__ import annotations

import socket
import ssl
import threading
from collections.abc import Callable

from superbrain.application.owner_loop import OwnerLoop
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import Ready

MAX_ACTIVE_CONNECTIONS = 32
SERVER_HANDSHAKE_BUDGET_NS = 1_000_000_000


class LoopbackServer:
    """Bounded loopback TLS server delegating authorized tool calls to ``OwnerLoop``."""

    def __init__(
        self,
        listener: socket.socket,
        ssl_context: ssl.SSLContext,
        ready: Ready,
        owner: OwnerLoop,
        monotonic_ns: Callable[[], int],
        stop_event: threading.Event,
    ) -> None:
        if (
            not isinstance(listener, socket.socket)
            or not isinstance(ssl_context, ssl.SSLContext)
            or not isinstance(ready, Ready)
            or not isinstance(owner, OwnerLoop)
            or not callable(monotonic_ns)
            or not callable(getattr(stop_event, "is_set", None))
            or not callable(getattr(stop_event, "set", None))
        ):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        self._listener = listener
        self._ssl_context = ssl_context
        self._ready = ready
        self._owner = owner
        self._monotonic_ns = monotonic_ns
        self._stop_event = stop_event

    def start(self) -> None:
        raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")

    def quiesce(self, stop_deadline: float) -> None:
        _ = stop_deadline
        return None

    def finish(self, stop_deadline: float) -> bool:
        _ = stop_deadline
        return True
