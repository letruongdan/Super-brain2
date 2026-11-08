"""Single-thread job worker for Increment 2 (D5): runs registered handlers on immutable ``JobSpec``s, outside any DB.

The worker holds no SQLite handle, ``Store`` or ``Runtime``: the owner side reads the payload, reserves invocations
and hands over a ``WorkItem``; the worker reports typed commands (``WorkerCompleted``, ``WorkerFailed``,
``WorkerUsage``) that the owner applies through ``JobService``. Cancellation is cooperative through a per-job event.
Only a handler registered for the job's ``kind`` ever runs; the production registry is empty, so a client-chosen
``kind`` can never select a test fixture. Failures become typed codes; exception text is never kept or logged.
"""

from __future__ import annotations

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
        self._lock = threading.Lock()
        self._closed = False
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        with self._lock:
            if self._closed:
                raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")
            if self._thread is not None:
                raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
            thread = threading.Thread(target=self._run, name="superbrain-job-worker", daemon=True)
            self._thread = thread
        thread.start()

    def close(self, timeout_s: float = 5.0) -> bool:
        """Stop after the current item; items still queued are dropped (the owner recovers them by epoch)."""
        with self._lock:
            thread = self._thread
            if not self._closed:
                self._closed = True
                for event in self._cancel_events.values():
                    event.set()
                if thread is not None:
                    self._items.put(None)
        if thread is None:
            return True
        thread.join(timeout_s)
        return not thread.is_alive()

    def submit(self, item: WorkItem) -> None:
        """Queue ``item``; an unregistered ``kind`` never runs and is reported as a nonretryable failure."""
        if not isinstance(item, WorkItem):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        with self._lock:
            if self._closed:
                raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")
            if item.spec.kind not in self._handlers:
                self._emit_command(WorkerFailed(item.lease, False, JobErrorCode.HANDLER_UNAVAILABLE))
                return
            self._cancel_events[item.lease.job_id] = threading.Event()
            self._items.put(item)

    def cancel(self, job_id: str) -> None:
        """Signal the cooperative cancel of ``job_id`` (no-op when the worker does not hold it)."""
        with self._lock:
            event = self._cancel_events.get(job_id)
        if event is not None:
            event.set()

    def next_command(self, timeout_s: float) -> WorkerCommand | None:
        try:
            return self._commands.get(timeout=timeout_s)
        except queue.Empty:
            return None

    def _emit_command(self, cmd: WorkerCommand) -> None:
        self._commands.put(cmd)
        if self._on_command is not None:
            self._on_command()

    def _run(self) -> None:
        while (item := self._items.get()) is not None:
            with self._lock:
                registered = self._cancel_events.get(item.lease.job_id)
                cancelled = registered if registered is not None else threading.Event()
            try:
                if not cancelled.is_set():
                    self._emit_command(self._execute(item, cancelled))
            finally:
                with self._lock:
                    if registered is not None and self._cancel_events.get(item.lease.job_id) is registered:
                        self._cancel_events.pop(item.lease.job_id, None)

    def _execute(self, item: WorkItem, cancelled: threading.Event) -> WorkerCommand:
        if self._monotonic_ns() >= item.deadline_ns:
            return WorkerFailed(item.lease, True, JobErrorCode.DEADLINE_EXCEEDED)
        handler = self._handlers[item.spec.kind]
        try:
            refs = handler(item.spec, JobContext(item, cancelled, self._emit_command))
            completed = WorkerCompleted(item.lease, refs)
        except JobHandlerError as err:
            return WorkerFailed(item.lease, err.retryable, err.code)
        except Exception:  # noqa: BLE001 - any other failure is a typed code; its text is never kept or logged
            return WorkerFailed(item.lease, False, JobErrorCode.HANDLER_FAILED)
        if self._monotonic_ns() > item.deadline_ns:
            return WorkerFailed(item.lease, True, JobErrorCode.DEADLINE_EXCEEDED)
        return completed
