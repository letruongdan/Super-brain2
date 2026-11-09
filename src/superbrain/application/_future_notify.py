"""Safe concurrent ``Future`` settlement and fault-tolerant off-cutoff callback notifier."""

from __future__ import annotations

import contextlib
import threading
from collections import deque
from collections.abc import Callable, Iterator, Sequence
from concurrent.futures import Future, InvalidStateError
from typing import TypeVar

from superbrain.core.errors import BrainError, ErrorCode

_T = TypeVar("_T")

_MAX_NOTIFY_WORKERS = 128
_SCALER_ACK_WAIT_S = 0.01
_SCALER_SETTLE_WAIT_S = 0.002
_DEFER_LOCAL = threading.local()


def noop_thunk() -> None:
    """Placeholder thunk used to preserve batch cardinality for callback-less settlements."""
    return None


def _invoke_user_cb(fut: Future[_T], fn: Callable[[Future[_T]], object]) -> None:
    with contextlib.suppress(Exception):
        fn(fut)


def _make_user_cb_thunk(fut: Future[_T], fn: Callable[[Future[_T]], object]) -> Callable[[], None]:
    def _run() -> None:
        _invoke_user_cb(fut, fn)

    return _run


def is_collecting_deferred_callbacks() -> bool:
    """Return ``True`` when the current thread is inside ``collect_deferred_callbacks()``."""
    return getattr(_DEFER_LOCAL, "collector", None) is not None


@contextlib.contextmanager
def collect_deferred_callbacks() -> Iterator[list[Callable[[], None]]]:
    """Publish ``DeferredCallbackFuture`` outcomes immediately while deferring user callbacks."""
    prev: list[Callable[[], None]] | None = getattr(_DEFER_LOCAL, "collector", None)
    collected: list[Callable[[], None]] = []
    _DEFER_LOCAL.collector = collected
    try:
        yield collected
    finally:
        if prev is None:
            with contextlib.suppress(AttributeError):
                delattr(_DEFER_LOCAL, "collector")
        else:
            _DEFER_LOCAL.collector = prev


class DeferredCallbackFuture(Future[_T]):
    """``Future`` subclass that separates outcome publication from deferred user callbacks."""

    def __init__(self) -> None:
        super().__init__()
        self._cb_lock = threading.Lock()
        self._settled_dispatch_done = False
        self._projections: list[Callable[[Future[_T]], None]] = []
        self._user_callbacks: list[Callable[[Future[_T]], object]] = []
        super().add_done_callback(self._on_raw_done)

    def add_projection(self, fn: Callable[[Future[_T]], None]) -> None:
        """Register an internal immediate outcome projection before user ``done_callback``s."""
        with self._cb_lock:
            if not self._settled_dispatch_done:
                self._projections.append(fn)
                return
        fn(self)

    def add_done_callback(self, fn: Callable[[Future[_T]], object]) -> None:
        with self._cb_lock:
            if not self._settled_dispatch_done:
                self._user_callbacks.append(fn)
                return
        _invoke_user_cb(self, fn)

    def _on_raw_done(self, _done_fut: Future[_T]) -> None:
        with self._cb_lock:
            projs = tuple(self._projections)
            self._projections.clear()
            cbs = tuple(self._user_callbacks)
            self._user_callbacks.clear()
            self._settled_dispatch_done = True
        for proj in projs:
            proj(self)
        collector: list[Callable[[], None]] | None = getattr(_DEFER_LOCAL, "collector", None)
        if collector is not None and not self.cancelled():
            for cb in cbs:
                collector.append(_make_user_cb_thunk(self, cb))
            return
        for cb in cbs:
            _invoke_user_cb(self, cb)


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
    """Retained-queue async callback notifier with pre-started standby + background burst-scaler workers."""

    def __init__(self, *, max_workers: int = _MAX_NOTIFY_WORKERS) -> None:
        self._max_workers = max(1, max_workers)
        self._cond = threading.Condition()
        self._queue: deque[Callable[[], None]] = deque()
        self._active_workers = 0
        self._idle_workers = 0
        self._pending_spawns = 0
        self._burst_seq = 0
        self._scaler_alive = False
        self._scaler_busy = False
        self._spawn_waiters: list[tuple[threading.Event, threading.Event]] = []
        self._started = False
        self._closed = False

    def start(self, *, strict: bool = False) -> None:
        """Pre-start standby callback and burst-scaler daemon workers so ``stop()`` never calls ``Thread.start``."""
        with self._cond:
            if self._closed:
                if strict:
                    raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")
                return
            if self._started:
                return
            self._started = True
            self._active_workers += 1
            self._scaler_alive = True

        standby = threading.Thread(
            target=self._standby_worker,
            name="superbrain-cancel-notifier",
            daemon=True,
        )
        scaler = threading.Thread(
            target=self._scaler_worker,
            name="superbrain-cancel-scaler",
            daemon=True,
        )
        try:
            standby.start()
        except RuntimeError as err:
            with self._cond:
                self._active_workers -= 1
                self._scaler_alive = False
                self._started = False
            self._drain_if_workerless()
            if strict:
                raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable") from err
            return

        try:
            scaler.start()
        except RuntimeError as err:
            with self._cond:
                self._scaler_alive = False
                if strict:
                    self._closed = True
                    self._cond.notify_all()
            if strict:
                standby.join(timeout=1.0)
                if not standby.is_alive():
                    with self._cond:
                        self._started = False
                        self._closed = False
                raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable") from err

    def submit(self, thunks: Sequence[Callable[[], None]]) -> None:
        """Enqueue ``thunks`` in RAM and signal background scaling without calling ``Thread.start`` on caller."""
        if not thunks:
            return
        if not self._started and not self._closed:
            self.start(strict=False)
        wait_pair: tuple[threading.Event, threading.Event] | None = None
        with self._cond:
            self._queue.extend(thunks)
            can_scale = self._scaler_alive and not self._closed
            needed = len(self._queue) - (self._idle_workers + self._pending_spawns)
            avail = self._max_workers - self._active_workers
            to_spawn = min(needed, avail) if (can_scale and needed > 0 and avail > 0) else 0
            if to_spawn > 0:
                self._active_workers += to_spawn
                self._pending_spawns += to_spawn
                if not self._scaler_busy:
                    wait_pair = (threading.Event(), threading.Event())
                    self._spawn_waiters.append(wait_pair)
            self._cond.notify_all()

        if wait_pair is not None:
            ack_ev, settled_ev = wait_pair
            if ack_ev.wait(timeout=_SCALER_ACK_WAIT_S):
                settled_ev.wait(timeout=_SCALER_SETTLE_WAIT_S)
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
        """Allow standby and scaler workers to exit once queued work and pending spawns finish."""
        with self._cond:
            self._closed = True
            self._cond.notify_all()

    def _scaler_worker(self) -> None:
        while True:
            with self._cond:
                while self._pending_spawns == 0 and not self._closed:
                    self._cond.wait()
                if self._pending_spawns == 0 and self._closed:
                    self._scaler_alive = False
                    return
                batch = self._pending_spawns
                self._pending_spawns = 0
                self._scaler_busy = True
                waiters = tuple(self._spawn_waiters)
                self._spawn_waiters.clear()
                base_seq = self._burst_seq
                self._burst_seq += batch

            for ack_ev, _settled_ev in waiters:
                ack_ev.set()

            unstarted = batch
            for offset in range(batch):
                helper = threading.Thread(
                    target=self._burst_worker,
                    name=f"superbrain-cancel-notify-{base_seq + offset}",
                    daemon=True,
                )
                try:
                    helper.start()
                    unstarted -= 1
                except RuntimeError:
                    break

            with self._cond:
                if unstarted:
                    self._active_workers -= unstarted
                self._scaler_busy = False

            for _ack_ev, settled_ev in waiters:
                settled_ev.set()
            self._drain_if_workerless()

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
    notifier = AsyncThunkNotifier()
    notifier.start(strict=False)
    notifier.submit(thunks)
    notifier.close()
