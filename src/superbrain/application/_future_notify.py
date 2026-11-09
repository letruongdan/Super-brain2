"""Safe concurrent ``Future`` settlement and fault-tolerant off-cutoff callback notifier."""

from __future__ import annotations

import contextlib
import threading
from collections import deque
from collections.abc import Callable, Sequence
from concurrent.futures import Future, InvalidStateError
from typing import TypeVar

from superbrain.core.errors import BrainError, ErrorCode

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


class AsyncThunkNotifier:
    """Retained-queue async callback notifier with pre-started standby worker and ``Thread.start`` fallback."""

    def __init__(self, *, max_workers: int = _MAX_NOTIFY_WORKERS) -> None:
        self._max_workers = max(1, max_workers)
        self._cond = threading.Condition()
        self._queue: deque[Callable[[], None]] = deque()
        self._active_workers = 0
        self._idle_workers = 0
        self._started = False
        self._closed = False

    def start(self, *, strict: bool = False) -> None:
        """Pre-start one standby daemon worker so shutdown cancellation never depends on late thread creation."""
        with self._cond:
            if self._closed:
                if strict:
                    raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")
                return
            if self._started:
                return
            self._started = True
            self._active_workers += 1
        worker = threading.Thread(
            target=self._standby_worker,
            name="superbrain-cancel-notifier",
            daemon=True,
        )
        try:
            worker.start()
        except RuntimeError as err:
            with self._cond:
                self._active_workers -= 1
                self._started = False
            self._drain_if_workerless()
            if strict:
                raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable") from err

    def submit(self, thunks: Sequence[Callable[[], None]]) -> None:
        """Enqueue ``thunks`` before spawning burst helpers; survive ``Thread.start`` ``RuntimeError`` without loss."""
        if not thunks:
            return
        with self._cond:
            self._queue.extend(thunks)
            needed = len(self._queue) - self._idle_workers
            avail = self._max_workers - self._active_workers
            to_spawn = min(needed, avail) if needed > 0 and avail > 0 else 0
            self._active_workers += to_spawn
            self._cond.notify_all()

        unstarted = to_spawn
        for idx in range(to_spawn):
            helper = threading.Thread(
                target=self._burst_worker,
                name=f"superbrain-cancel-notify-{idx}",
                daemon=True,
            )
            try:
                helper.start()
                unstarted -= 1
            except RuntimeError:
                break
        if unstarted:
            with self._cond:
                self._active_workers -= unstarted
        self._drain_if_workerless()

    def _drain_if_workerless(self) -> None:
        while True:
            with self._cond:
                if not self._queue or self._active_workers > 0:
                    return
                fn = self._queue.popleft()
            with contextlib.suppress(Exception):
                fn()

    def close(self) -> None:
        """Allow the standby worker to exit once all queued thunks have drained."""
        with self._cond:
            self._closed = True
            self._cond.notify_all()

    def _standby_worker(self) -> None:
        while True:
            with self._cond:
                while not self._queue and not self._closed:
                    self._idle_workers += 1
                    try:
                        self._cond.wait()
                    finally:
                        self._idle_workers -= 1
                if not self._queue and self._closed:
                    self._active_workers -= 1
                    return
                fn = self._queue.popleft()
            with contextlib.suppress(Exception):
                fn()

    def _burst_worker(self) -> None:
        while True:
            with self._cond:
                if not self._queue:
                    self._active_workers -= 1
                    return
                fn = self._queue.popleft()
            with contextlib.suppress(Exception):
                fn()


def dispatch_async_thunks(thunks: Sequence[Callable[[], None]]) -> None:
    """Execute notification thunks asynchronously with retained-queue ``Thread.start`` fallback."""
    if not thunks:
        return
    AsyncThunkNotifier().submit(thunks)
