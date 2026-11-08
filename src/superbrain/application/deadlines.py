"""Task 4b bounded owner queue, non-owner deadline coordinator, and reservation surface."""

from __future__ import annotations

import threading
from collections import deque
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import replace

from superbrain.application._prequeue import (
    AtomicRequestAuthState,
    admit_prequeue_request,
    authorize_call_against_snapshot,
    begin_local_phase,
    reconstruct_queued_call,
)
from superbrain.application._reservation import (
    Reservation,
    ReservationTable,
    enter_commit,
    invoke_response_callback,
    make_checked_error,
    reserve,
)
from superbrain.application.idempotency import compute_canonical_payload_hmac
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    LOCAL_PHASE_BUDGET_NS,
    Call,
    CallContext,
    CallResult,
    Identity,
    Principal,
    PrivateRequestAuth,
    QueuedKernelRequest,
    RequestDeadlines,
    Scope,
    require_opaque_id,
    require_positive_int,
)
from superbrain.ports.clock import MonotonicClock
from superbrain.ports.kernel import RequestAuthStatePort

DEFAULT_MAX_QUEUE_DEPTH = 64

OwnerDispatchRunner = Callable[[Call, CallContext, PrivateRequestAuth, Reservation], CallResult]

__all__ = [
    "AtomicRequestAuthState",
    "DEFAULT_MAX_QUEUE_DEPTH",
    "KernelDeadlineCoordinator",
    "OwnerDispatchRunner",
    "Reservation",
    "ReservationTable",
    "SubmittedKernelRequest",
    "admit_prequeue_request",
    "authorize_call_against_snapshot",
    "begin_local_phase",
    "compute_canonical_payload_hmac",
    "enter_commit",
    "reconstruct_queued_call",
    "reserve",
]


class SubmittedKernelRequest:
    """Caller handle for a pre-queue refused or bounded-queue admitted kernel request."""

    def __init__(
        self,
        *,
        queued: QueuedKernelRequest | None = None,
        reservation: Reservation | None = None,
        immediate_response: CallResult | None = None,
    ) -> None:
        self.queued = queued
        self.reservation = reservation
        self._immediate_response = immediate_response

    def done(self) -> bool:
        if self._immediate_response is not None:
            return True
        return self.reservation is not None and self.reservation.response_settled

    def wait(self, timeout: float | None = None) -> CallResult:
        if self._immediate_response is not None:
            return self._immediate_response
        if self.reservation is None:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
        settled = self.reservation.wait_response(timeout=timeout)
        if settled is None:
            raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")
        return settled


class KernelDeadlineCoordinator:
    """Pre-queue RAM admission + in-memory reservation + bounded FIFO queue + non-owner arbiter + owner executor."""

    def __init__(
        self,
        *,
        store_id: str,
        writer_epoch: int,
        instance_id: str,
        auth_state: RequestAuthStatePort,
        monotonic_clock: MonotonicClock,
        owner_runner: OwnerDispatchRunner,
        max_queue_size: int = DEFAULT_MAX_QUEUE_DEPTH,
        reservations: ReservationTable | None = None,
        on_unsent_owner_response: Callable[[CallResult], None] | None = None,
        after_reserve_before_enqueue: Callable[[Reservation], None] | None = None,
        on_queue_wake: Callable[[], None] | None = None,
        on_owner_finished: Callable[[Reservation, bool], None] | None = None,
    ) -> None:
        require_opaque_id(store_id, label="store_id")
        require_positive_int(writer_epoch)
        require_opaque_id(instance_id, label="instance_id")
        require_positive_int(max_queue_size)
        self._store_id = store_id
        self._writer_epoch = writer_epoch
        self._instance_id = instance_id
        self._auth_state = auth_state
        self._monotonic_clock = monotonic_clock
        self._owner_runner = owner_runner
        self._max_queue_size = max_queue_size
        self._reservations = reservations if reservations is not None else ReservationTable()
        self._on_unsent_owner_response = on_unsent_owner_response
        self._after_reserve_before_enqueue = after_reserve_before_enqueue
        self._on_queue_wake = on_queue_wake
        self._on_owner_finished = on_owner_finished
        self._queue_cv = threading.Condition()
        self._queue: deque[tuple[QueuedKernelRequest, Reservation]] = deque()
        self._closed = False

    @property
    def reservations(self) -> ReservationTable:
        return self._reservations

    def queue_depth(self) -> int:
        with self._queue_cv:
            return len(self._queue)

    def close_admissions(self) -> None:
        with self._queue_cv:
            self._closed = True
            self._queue_cv.notify_all()
        if self._on_queue_wake is not None:
            with suppress(Exception):
                self._on_queue_wake()

    def cancel_uncommitted_for_shutdown(self) -> int:
        with self._queue_cv:
            self._closed = True
            self._queue.clear()
            self._queue_cv.notify_all()
        err_env = make_checked_error(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")
        return self._reservations.cancel_all_uncommitted(err_env)

    def submit(
        self,
        tool: str,
        arguments: JsonValue | Mapping[str, JsonValue],
        *,
        token: str,
        selected_scope: Scope | None = None,
        expected_principal: Principal | None = None,
        correlation_id: str | None = None,
        receive_ns: int | None = None,
        on_response: Callable[[CallResult], None] | None = None,
        on_reserved: Callable[[Reservation], None] | None = None,
    ) -> SubmittedKernelRequest:
        reservation: Reservation | None = None
        try:
            with self._queue_cv:
                if self._closed:
                    raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")
            adm_start_ns = self._monotonic_clock.monotonic_ns()
            t0_ns = adm_start_ns if receive_ns is None else receive_ns
            deadlines = RequestDeadlines.from_receive_ns(t0_ns)
            queued = admit_prequeue_request(
                expected_store_id=self._store_id,
                writer_epoch=self._writer_epoch,
                auth_state=self._auth_state,
                tool=tool,
                raw_arguments=arguments,
                token=token,
                deadlines=deadlines,
                selected_scope=selected_scope,
                expected_principal=expected_principal,
                correlation_id=correlation_id,
            )
            adm_end_ns = self._monotonic_clock.monotonic_ns()
            prequeue_local_elapsed_ns = max(0, adm_end_ns - min(t0_ns, adm_start_ns))
            if adm_end_ns >= deadlines.handler_deadline_ns or prequeue_local_elapsed_ns >= LOCAL_PHASE_BUDGET_NS:
                raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")
            remaining_local_budget_ns = LOCAL_PHASE_BUDGET_NS - prequeue_local_elapsed_ns
            queued = replace(queued, remaining_local_budget_ns=remaining_local_budget_ns)
            if queued.scope_key is not None:
                assert queued.request_digest is not None
                reservation = self._reservations.reserve(
                    queued.scope_key,
                    queued.request_digest,
                    deadlines=deadlines,
                    request_digest_key_id=queued.request_digest_key_id,
                    on_response=on_response,
                )
            else:
                reservation = self._reservations.create_unscoped_ticket(
                    deadlines=deadlines,
                    on_response=on_response,
                )

            if on_reserved is not None:
                on_reserved(reservation)
            if self._after_reserve_before_enqueue is not None:
                self._after_reserve_before_enqueue(reservation)

            with self._queue_cv:
                if self._closed:
                    raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")
                if reservation.cancelled:
                    raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")
                if len(self._queue) >= self._max_queue_size:
                    raise BrainError(ErrorCode.STORE_BUSY, "store busy")
                self._queue.append((queued, reservation))
                self._queue_cv.notify_all()
            if self._on_queue_wake is not None:
                with suppress(Exception):
                    self._on_queue_wake()

            return SubmittedKernelRequest(queued=queued, reservation=reservation)
        except BrainError as err:
            err_env = make_checked_error(err.code, err.message)
            if reservation is not None:
                settled_env = self._reservations.abort_before_enqueue(reservation, err_env)
                return SubmittedKernelRequest(immediate_response=settled_env)
            invoke_response_callback(on_response, err_env)
            return SubmittedKernelRequest(immediate_response=err_env)

    def call_tool(
        self,
        tool: str,
        arguments: JsonValue | Mapping[str, JsonValue],
        *,
        token: str,
        selected_scope: Scope | None = None,
        expected_principal: Principal | None = None,
        correlation_id: str | None = None,
        receive_ns: int | None = None,
        timeout: float | None = None,
    ) -> CallResult:
        return self.submit(
            tool,
            arguments,
            token=token,
            selected_scope=selected_scope,
            expected_principal=expected_principal,
            correlation_id=correlation_id,
            receive_ns=receive_ns,
        ).wait(timeout=timeout)

    def arbitrate(self, now_ns: int | None = None) -> tuple[tuple[Reservation, CallResult], ...]:
        ts = self._monotonic_clock.monotonic_ns() if now_ns is None else now_ns
        return self._reservations.arbitrate_at(ts)

    def process_next(self, *, block: bool = False, timeout: float | None = None) -> bool:
        item: tuple[QueuedKernelRequest, Reservation] | None = None
        with self._queue_cv:
            if not self._queue and block:
                self._queue_cv.wait(timeout=timeout)
            if self._queue:
                item = self._queue.popleft()
        if item is None:
            return False

        queued, reservation = item
        now_ns = self._monotonic_clock.monotonic_ns()
        if not self._reservations.try_claim_for_owner(reservation, now_ns):
            return True
        owner_local_deadline_ns = min(
            now_ns + queued.remaining_local_budget_ns,
            queued.deadlines.handler_deadline_ns,
        )

        response: CallResult = make_checked_error(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
        try:
            call = reconstruct_queued_call(queued)
            ctx = CallContext(
                principal=queued.auth.principal,
                identity=Identity(
                    store_id=queued.store_id,
                    writer_epoch=queued.writer_epoch,
                    instance_id=self._instance_id,
                ),
                deadline_ns=queued.deadlines.total_deadline_ns,
                selected_scope=queued.selected_scope,
                local_deadline_ns=owner_local_deadline_ns,
            )
            response = self._owner_runner(call, ctx, queued.auth, reservation)
        except BrainError as err:
            response = make_checked_error(err.code, err.message)
        except Exception:  # noqa: BLE001 — guarantee finish_owner_execution settles static error on unexpected bug
            response = make_checked_error(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
        finally:
            won = self._reservations.finish_owner_execution(
                reservation,
                response,
                now_ns=self._monotonic_clock.monotonic_ns(),
            )
            if self._on_owner_finished is not None:
                with suppress(Exception):
                    self._on_owner_finished(reservation, won)
            if not won and self._on_unsent_owner_response is not None:
                with suppress(Exception):
                    self._on_unsent_owner_response(response)
        return True
