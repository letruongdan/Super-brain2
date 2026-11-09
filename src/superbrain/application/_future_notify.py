"""Safe concurrent ``Future`` settlement and off-cutoff-path callback dispatch helpers."""

from __future__ import annotations

import contextlib
import threading
from collections import deque
from collections.abc import Callable, Sequence
from concurrent.futures import Future, InvalidStateError
from typing import TypeVar

_T = TypeVar("_T")

_MAX_NOTIFY_WORKERS = 128


def safe_set_result(fut: Future[_T], value: _T) -> bool:
    """Set ``fut`` result iff still pending; swallow concurrent ``InvalidStateError`` on caller cancel."""
    if fut.done():
        return False
    try:
        fut.set_result(value)
    except InvalidStateError:
        return False
    return True


def safe_set_exception(fut: Future[_T], exc: BaseException) -> bool:
    """Set ``fut`` exception iff still pending; swallow concurrent ``InvalidStateError`` on caller cancel."""
    if fut.done():
        return False
    try:
        fut.set_exception(exc)
    except InvalidStateError:
        return False
    return True


def safe_cancel(fut: Future[_T]) -> bool:
    """Cancel ``fut`` safely without raising if already completed."""
    with contextlib.suppress(InvalidStateError):
        return fut.cancel()
    return False


def dispatch_async_thunks(thunks: Sequence[Callable[[], None]]) -> None:
    """Execute notification thunks on bounded daemon worker threads outside caller locks & cutoff path."""
    if not thunks:
        return
    queue: deque[Callable[[], None]] = deque(thunks)
    q_lock = threading.Lock()
    worker_count = min(len(queue), _MAX_NOTIFY_WORKERS)

    def _drain() -> None:
        while True:
            with q_lock:
                if not queue:
                    return
                fn = queue.popleft()
            with contextlib.suppress(Exception):
                fn()

    for idx in range(worker_count):
        threading.Thread(
            target=_drain,
            name=f"superbrain-cancel-notify-{idx}",
            daemon=True,
        ).start()
