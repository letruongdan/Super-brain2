"""Single-thread job worker for Increment 2 (D5): runs registered handlers on immutable ``JobSpec``s, outside any DB.

The worker holds no SQLite handle, ``Store`` or ``Runtime``: the owner side reads the payload, reserves invocations
and hands over a ``WorkItem``; the worker reports typed commands (``WorkerCompleted``, ``WorkerFailed``,
``WorkerUsage``) that the owner applies through ``JobService``. Cancellation is cooperative through a per-job event.
Only a handler registered for the job's ``kind`` ever runs; the production registry is empty, so a client-chosen
``kind`` can never select a test fixture. Failures become typed codes; exception text is never kept or logged.
"""

from __future__ import annotations

import contextlib
import queue
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import (
    JobErrorCode,
    JobLease,
    JobSpec,
    ObjectRef,
    UsageRecord,
    WorkerCommand,
    WorkerCompleted,
    WorkerFailed,
    WorkerUsage,
    is_strict_int,
    require_uuid,
)


@dataclass(frozen=True)
class WorkItem:
    """One running attempt handed to the worker after its invocations were durably reserved."""

    lease: JobLease
    spec: JobSpec
    invocation_ids: tuple[str, ...]
    deadline_ns: int

    def __post_init__(self) -> None:
        if not isinstance(self.lease, JobLease) or not isinstance(self.spec, JobSpec):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if not isinstance(self.invocation_ids, tuple) or not is_strict_int(self.deadline_ns):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        for invocation_id in self.invocation_ids:
            require_uuid(invocation_id)


class JobContext:
    """What a handler may do: observe cancellation and the monotonic deadline, report usage of its invocations."""

    def __init__(self, item: WorkItem, cancelled: threading.Event, report: Callable[[WorkerCommand], None]) -> None:
        self._item = item
        self._cancelled = cancelled
        self._report = report

    @property
    def lease(self) -> JobLease:
        return self._item.lease

    @property
    def invocation_ids(self) -> tuple[str, ...]:
        return self._item.invocation_ids

    @property
    def deadline_ns(self) -> int:
        return self._item.deadline_ns

    def cancelled(self) -> bool:
        return self._cancelled.is_set()

    def wait_cancelled(self, timeout_s: float) -> bool:
        """Block up to ``timeout_s`` for a cooperative cancel; True iff the job was cancelled."""
        return self._cancelled.wait(timeout_s)

    def report_usage(self, invocation_id: str, usage: UsageRecord) -> None:
        if invocation_id not in self._item.invocation_ids:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        self._report(WorkerUsage(invocation_id, usage))


JobHandler = Callable[[JobSpec, JobContext], tuple[ObjectRef, ...]]
"""A capability: computes safe result refs from an immutable spec; never touches the store."""


class JobHandlerError(Exception):
    """Typed handler failure: only ``code`` and ``retryable`` reach the owner side."""

    def __init__(self, code: JobErrorCode, *, retryable: bool) -> None:
        if not isinstance(code, JobErrorCode) or type(retryable) is not bool:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        super().__init__(code.value)
        self.code = code
        self.retryable = retryable


PRODUCTION_JOB_HANDLERS: Mapping[str, JobHandler] = MappingProxyType({})
"""Production capability registry: empty in Increment 2 (every domain is unavailable)."""


class JobExecutor:
    """One worker thread draining submitted ``WorkItem``s in order and queueing typed commands for the owner."""

    def __init__(
        self,
        handlers: Mapping[str, JobHandler],
        monotonic_ns: Callable[[], int],
        *,
        on_command: Callable[[], None] | None = None,
    ) -> None:
        self._handlers = MappingProxyType(dict(handlers))
        self._monotonic_ns = monotonic_ns
        self._on_command = on_command
        self._items: queue.Queue[WorkItem | None] = queue.Queue()
        self._commands: queue.Queue[WorkerCommand] = queue.Queue()
        self._cancel_events: dict[str, threading.Event] = {}
        self._submit_lock = threading.Lock()
        self._lock = threading.Lock()
        self._cancel_lock = threading.Lock()
        self._closed = False
        self._clean_stop = False
        self._unexpected_exit = False
        self._in_flight = 0
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        with self._submit_lock, self._lock:
            if self._closed:
                raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")
            if self._thread is not None:
                raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
            thread = threading.Thread(target=self._run, name="superbrain-job-worker", daemon=True)
            self._thread = thread
        thread.start()

    @property
    def is_closed(self) -> bool:
        with self._lock:
            return self._closed

    @property
    def in_flight(self) -> int:
        with self._cancel_lock:
            return self._in_flight

    def can_claim(self) -> bool:
        """True iff the worker is open and has zero in-flight items under one atomic critical section."""
        with self._lock, self._cancel_lock:
            return not self._closed and self._in_flight == 0

    @property
    def is_drained(self) -> bool:
        with self._lock:
            thread = self._thread
            unexpected = self._unexpected_exit
        if unexpected:
            return False
        return thread is None or not thread.is_alive()

    def close(self, timeout_s: float = 5.0) -> bool:
        """Stop after the current item; items still queued are dropped (the owner recovers them by epoch)."""
        with self._submit_lock, self._lock:
            thread = self._thread
            if not self._closed:
                self._closed = True
                with self._cancel_lock:
                    events = tuple(self._cancel_events.values())
                for event in events:
                    event.set()
                if thread is not None:
                    self._items.put(None)
        if thread is None:
            return True
        thread.join(timeout_s)
        with self._lock:
            clean = self._clean_stop and not self._unexpected_exit
        return not thread.is_alive() and clean

    def submit(self, item: WorkItem) -> None:
        """Queue ``item``; an unregistered ``kind`` never runs and is reported as a nonretryable failure."""
        if not isinstance(item, WorkItem):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        unregistered = False
        with self._submit_lock:
            if self._closed:
                raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")
            if item.spec.kind not in self._handlers:
                with self._lock:
                    if self._closed:
                        raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")
                    self._commands.put(WorkerFailed(item.lease, False, JobErrorCode.HANDLER_UNAVAILABLE))
                unregistered = True
            else:
                event = threading.Event()
                with self._cancel_lock:
                    self._cancel_events[item.lease.job_id] = event
                    self._in_flight += 1
                try:
                    self._items.put(item)
                except BaseException:
                    with self._cancel_lock:
                        self._in_flight -= 1
                        if self._cancel_events.get(item.lease.job_id) is event:
                            self._cancel_events.pop(item.lease.job_id, None)
                    raise
        if unregistered:
            self._notify_command()

    def cancel(self, job_id: str) -> None:
        """Signal the cooperative cancel of ``job_id`` (no-op when the worker does not hold it)."""
        with self._cancel_lock:
            event = self._cancel_events.get(job_id)
        if event is not None:
            event.set()

    def next_command(self, timeout_s: float) -> WorkerCommand | None:
        try:
            return self._commands.get(timeout=timeout_s)
        except queue.Empty:
            return None

    def _notify_command(self) -> None:
        if self._on_command is not None:
            with contextlib.suppress(Exception):
                self._on_command()

    def _emit_usage_command(self, cmd: WorkerCommand) -> None:
        self._commands.put(cmd)
        self._notify_command()

    def _emit_terminal_command(
        self,
        cmd: WorkerCompleted | WorkerFailed,
        *,
        decrement_in_flight: bool = False,
    ) -> None:
        with self._lock:
            if decrement_in_flight:
                with self._cancel_lock:
                    self._in_flight -= 1
            if self._closed:
                return
            self._commands.put(cmd)
        self._notify_command()

    def _run(self) -> None:
        try:
            while True:
                item = self._items.get()
                if item is None:
                    with self._lock:
                        self._clean_stop = True
                    return
                with self._lock:
                    is_closed = self._closed
                with self._cancel_lock:
                    registered = self._cancel_events.get(item.lease.job_id)
                    cancelled = registered if registered is not None else threading.Event()
                decremented = False
                try:
                    if not is_closed and not cancelled.is_set():
                        result_cmd = self._execute(item, cancelled)
                        decremented = True
                        self._emit_terminal_command(result_cmd, decrement_in_flight=True)
                finally:
                    with self._cancel_lock:
                        if not decremented:
                            self._in_flight -= 1
                        if registered is not None and self._cancel_events.get(item.lease.job_id) is registered:
                            self._cancel_events.pop(item.lease.job_id, None)
        finally:
            notify = False
            with self._lock:
                if not self._clean_stop:
                    self._unexpected_exit = True
                    notify = True
            if notify:
                self._notify_command()

    def _execute(self, item: WorkItem, cancelled: threading.Event) -> WorkerCompleted | WorkerFailed:
        try:
            start_ns = self._monotonic_ns()
        except Exception:  # noqa: BLE001
            return WorkerFailed(item.lease, False, JobErrorCode.HANDLER_FAILED)
        if not is_strict_int(start_ns):
            return WorkerFailed(item.lease, False, JobErrorCode.HANDLER_FAILED)
        if start_ns >= item.deadline_ns:
            return WorkerFailed(item.lease, True, JobErrorCode.DEADLINE_EXCEEDED)
        handler = self._handlers[item.spec.kind]
        try:
            refs = handler(item.spec, JobContext(item, cancelled, self._emit_usage_command))
            completed = WorkerCompleted(item.lease, refs)
        except JobHandlerError as err:
            try:
                return WorkerFailed(item.lease, err.retryable, err.code)
            except Exception:  # noqa: BLE001
                return WorkerFailed(item.lease, False, JobErrorCode.HANDLER_FAILED)
        except Exception:  # noqa: BLE001 - any other failure is a typed code; its text is never kept or logged
            return WorkerFailed(item.lease, False, JobErrorCode.HANDLER_FAILED)
        try:
            end_ns = self._monotonic_ns()
        except Exception:  # noqa: BLE001
            return WorkerFailed(item.lease, False, JobErrorCode.HANDLER_FAILED)
        if not is_strict_int(end_ns):
            return WorkerFailed(item.lease, False, JobErrorCode.HANDLER_FAILED)
        if end_ns > item.deadline_ns:
            return WorkerFailed(item.lease, True, JobErrorCode.DEADLINE_EXCEEDED)
        return completed
