"""Task 4b in-memory reservation registry and single-lock response/commit arbiter."""

from __future__ import annotations

import contextlib
import hmac
import threading
import time
from collections.abc import Callable

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.kernel import (
    CallResult,
    RequestDeadlines,
    ReservationPhase,
    ReservationScopeKey,
    is_strict_int,
    require_opaque_id,
    require_sha256_digest,
)
from superbrain.core.wire import encode_envelope, make_error_envelope


def _coerce_scope_key(scope_key: ReservationScopeKey | tuple[str, str, str]) -> ReservationScopeKey:
    if isinstance(scope_key, ReservationScopeKey):
        return scope_key
    if isinstance(scope_key, tuple) and len(scope_key) == 3:
        principal_id, tool, key_hash = scope_key
        return ReservationScopeKey(principal_id=principal_id, tool=tool, key_hash=key_hash)
    raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")


def make_checked_error(code: ErrorCode, message: str) -> CallResult:
    envelope = make_error_envelope(BrainError(code, message))
    encode_envelope(envelope)
    return envelope


def invoke_response_callback(cb: Callable[[CallResult], None] | None, response: CallResult) -> None:
    """Invoke transport response callback outside the state lock, isolating socket/client errors."""
    if cb is None:
        return
    with contextlib.suppress(Exception):
        cb(response)


def _deliver_settled(
    reservation: Reservation,
    response: CallResult,
    cb: Callable[[CallResult], None] | None,
) -> None:
    reservation._response_event.set()
    invoke_response_callback(cb, response)


def _make_response_thunk(cb: Callable[[CallResult], None], response: CallResult) -> Callable[[], None]:
    def _run() -> None:
        invoke_response_callback(cb, response)

    return _run


class Reservation:
    """In-flight execution & idempotency reservation synchronized under ``ReservationTable``'s single state lock."""

    def __init__(
        self,
        *,
        table: ReservationTable,
        deadlines: RequestDeadlines,
        scope_key: ReservationScopeKey | None = None,
        request_digest_key_id: str | None = None,
        request_digest: str | None = None,
        on_response: Callable[[CallResult], None] | None = None,
    ) -> None:
        self._table = table
        self._state_lock = table._lock
        self._reservation_id = new_id()
        self._scope_key = scope_key
        self._request_digest_key_id = request_digest_key_id
        self._request_digest = request_digest
        self._deadlines = deadlines
        self._on_response = on_response
        self._phase = ReservationPhase.QUEUED
        self._cancelled = False
        self._response_settled = False
        self._response: CallResult | None = None
        self._response_event = threading.Event()

    @property
    def reservation_id(self) -> str:
        return self._reservation_id

    @property
    def scope_key(self) -> ReservationScopeKey | None:
        return self._scope_key

    @property
    def request_digest_key_id(self) -> str | None:
        return self._request_digest_key_id

    @property
    def request_digest(self) -> str | None:
        return self._request_digest

    @property
    def deadlines(self) -> RequestDeadlines:
        return self._deadlines

    @property
    def phase(self) -> ReservationPhase:
        with self._state_lock:
            return self._phase

    @property
    def cancelled(self) -> bool:
        with self._state_lock:
            return self._cancelled

    @property
    def response_settled(self) -> bool:
        with self._state_lock:
            return self._response_settled

    @property
    def response(self) -> CallResult | None:
        with self._state_lock:
            return self._response

    def wait_response(self, timeout: float | None = None) -> CallResult | None:
        if not self._response_event.wait(timeout=timeout):
            return None
        with self._state_lock:
            return self._response

    def _enter_commit_locked(self, now_ns: int) -> bool:
        with self._state_lock:
            if self._cancelled or self._phase not in (ReservationPhase.QUEUED, ReservationPhase.PREPARING):
                return False
            expire = self._table._shutdown_expiry_locked()
            if expire is None:
                if now_ns >= min(self._deadlines.handler_deadline_ns, self._deadlines.commit_waiter_cutoff_ns):
                    self._cancelled = True
                    self._phase = ReservationPhase.CANCELLED
                    return False
                self._phase = ReservationPhase.COMMITTING
                return True
        # The existing cancellation path acquires the table lock and settles callbacks.
        expire()
        return False


class ReservationTable:
    """In-memory reservation registry and single-lock response arbiter (Task 4b)."""

    def __init__(self, *, on_change: Callable[[], None] | None = None) -> None:
        self._lock = threading.Lock()
        self._active: dict[ReservationScopeKey, Reservation] = {}
        self._tracked: dict[str, Reservation] = {}
        self._on_change = on_change
        self._stop_cutoff: tuple[float, Callable[[], None]] | None = None

    def pin_stop_cutoff(self, deadline: float, expire: Callable[[], None]) -> None:
        with self._lock:
            if self._stop_cutoff is None:
                self._stop_cutoff = (deadline, expire)

    def _shutdown_expiry_locked(self) -> Callable[[], None] | None:
        cutoff = self._stop_cutoff
        if cutoff is None or time.perf_counter() < cutoff[0]:
            return None
        return cutoff[1]

    def expire_shutdown_if_due(self) -> bool:
        with self._lock:
            expire = self._shutdown_expiry_locked()
        if expire is None:
            return False
        expire()
        return True

    def has_tracked(self) -> bool:
        with self._lock:
            return bool(self._tracked)

    def next_deadline_ns(self) -> int | None:
        """Return earliest unsettled arbiter deadline or commit cutoff across tracked reservations."""
        earliest: int | None = None
        with self._lock:
            for res in self._tracked.values():
                if res._cancelled or res._response_settled:
                    continue
                if res._phase in (ReservationPhase.QUEUED, ReservationPhase.PREPARING):
                    dl = res._deadlines.handler_deadline_ns
                elif res._phase is ReservationPhase.COMMITTING:
                    dl = res._deadlines.commit_waiter_cutoff_ns
                else:
                    continue
                if earliest is None or dl < earliest:
                    earliest = dl
        return earliest

    def state_lock_locked(self) -> bool:
        """True iff the shared reservation/arbiter state lock is currently held."""
        return self._lock.locked()

    def active_count(self) -> int:
        with self._lock:
            return len(self._active)

    def has_active(self, scope_key: ReservationScopeKey | tuple[str, str, str]) -> bool:
        key = _coerce_scope_key(scope_key)
        with self._lock:
            return key in self._active

    def reserve(
        self,
        scope_key: ReservationScopeKey | tuple[str, str, str],
        request_digest: str,
        *,
        deadlines: RequestDeadlines | None = None,
        request_digest_key_id: str | None = None,
        on_response: Callable[[CallResult], None] | None = None,
    ) -> Reservation:
        key = _coerce_scope_key(scope_key)
        require_sha256_digest(request_digest)
        if request_digest_key_id is not None:
            require_opaque_id(request_digest_key_id, label="request_digest_key_id")
        resolved_deadlines = deadlines if deadlines is not None else RequestDeadlines.from_receive_ns(0)
        if not isinstance(resolved_deadlines, RequestDeadlines):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")

        with self._lock:
            existing = self._active.get(key)
            if existing is not None:
                assert existing.request_digest is not None
                same_digest = hmac.compare_digest(
                    existing.request_digest.encode("ascii"),
                    request_digest.encode("ascii"),
                )
                same_key_id = (
                    existing.request_digest_key_id is None
                    or request_digest_key_id is None
                    or existing.request_digest_key_id == request_digest_key_id
                )
                if same_digest and same_key_id:
                    raise BrainError(ErrorCode.IN_PROGRESS, "operation in progress")
                raise BrainError(ErrorCode.IDEMPOTENCY_CONFLICT, "idempotency conflict")

            reservation = Reservation(
                table=self,
                deadlines=resolved_deadlines,
                scope_key=key,
                request_digest_key_id=request_digest_key_id,
                request_digest=request_digest,
                on_response=on_response,
            )
            self._active[key] = reservation
            self._tracked[reservation.reservation_id] = reservation
        if self._on_change is not None:
            with contextlib.suppress(Exception):
                self._on_change()
        return reservation

    def create_unscoped_ticket(
        self,
        *,
        deadlines: RequestDeadlines,
        on_response: Callable[[CallResult], None] | None = None,
    ) -> Reservation:
        if not isinstance(deadlines, RequestDeadlines):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        with self._lock:
            ticket = Reservation(
                table=self,
                deadlines=deadlines,
                on_response=on_response,
            )
            self._tracked[ticket.reservation_id] = ticket
        if self._on_change is not None:
            with contextlib.suppress(Exception):
                self._on_change()
        return ticket

    def rollback_unstarted(self, reservation: Reservation) -> None:
        """Roll back an unstarted reservation immediately on ``STORE_BUSY`` queue-full refusal (4b:205)."""
        if not isinstance(reservation, Reservation):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        with self._lock:
            reservation._cancelled = True
            reservation._phase = ReservationPhase.CANCELLED
            self._tracked.pop(reservation.reservation_id, None)
            if reservation._scope_key is not None and self._active.get(reservation._scope_key) is reservation:
                del self._active[reservation._scope_key]

    def abort_before_enqueue(self, reservation: Reservation, fallback_error: CallResult) -> CallResult:
        """Cancel an unqueued reservation atomically and return its single settled envelope."""
        if not isinstance(reservation, Reservation):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if reservation._state_lock is not self._lock:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
        encode_envelope(fallback_error)
        deliver_cb: Callable[[CallResult], None] | None = None
        settled_here = False

        with self._lock:
            reservation._cancelled = True
            reservation._phase = ReservationPhase.CANCELLED
            self._tracked.pop(reservation.reservation_id, None)
            if reservation._scope_key is not None and self._active.get(reservation._scope_key) is reservation:
                del self._active[reservation._scope_key]
            if not reservation._response_settled:
                reservation._response_settled = True
                reservation._response = fallback_error
                settled_here = True
                deliver_cb = reservation._on_response
                result_env = fallback_error
            else:
                assert reservation._response is not None
                result_env = reservation._response

        if settled_here:
            _deliver_settled(reservation, result_env, deliver_cb)
        return result_env

    def prepare_cancel_all_uncommitted(
        self,
        error_envelope: CallResult,
    ) -> tuple[int, tuple[Callable[[], None], ...]]:
        """Cancel ``QUEUED``/``PREPARING`` reservations under ``_lock`` and return deferred callback thunks."""
        encode_envelope(error_envelope)
        settled_events: list[threading.Event] = []
        thunks: list[Callable[[], None]] = []
        cancelled_count = 0

        with self._lock:
            for res in list(self._tracked.values()):
                if res._phase in (ReservationPhase.QUEUED, ReservationPhase.PREPARING):
                    was_queued = res._phase is ReservationPhase.QUEUED
                    res._cancelled = True
                    res._phase = ReservationPhase.CANCELLED
                    cancelled_count += 1
                    if was_queued:
                        self._tracked.pop(res.reservation_id, None)
                        if res._scope_key is not None and self._active.get(res._scope_key) is res:
                            del self._active[res._scope_key]
                    if not res._response_settled:
                        res._response_settled = True
                        res._response = error_envelope
                        settled_events.append(res._response_event)
                        if res._on_response is not None:
                            thunks.append(_make_response_thunk(res._on_response, error_envelope))

        for ev in settled_events:
            ev.set()
        return cancelled_count, tuple(thunks)

    def cancel_all_uncommitted(self, error_envelope: CallResult) -> int:
        """Cancel every ``QUEUED`` or ``PREPARING`` reservation once; ``COMMITTING`` stays active."""
        cancelled_count, thunks = self.prepare_cancel_all_uncommitted(error_envelope)
        for thunk in thunks:
            thunk()
        return cancelled_count

    def try_claim_for_owner(self, reservation: Reservation, now_ns: int) -> bool:
        """Claim ``reservation`` on the owner thread if still queued and before ``handler_deadline_ns``."""
        if not isinstance(reservation, Reservation) or not is_strict_int(now_ns):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        expired_env = make_checked_error(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")
        deliver_cb: Callable[[CallResult], None] | None = None
        settled_here = False

        with self._lock:
            if reservation._cancelled or reservation._phase is not ReservationPhase.QUEUED:
                return False
            expire = self._shutdown_expiry_locked()
            if expire is not None:
                claimed = False
            elif (
                now_ns >= reservation._deadlines.handler_deadline_ns
                or now_ns >= reservation._deadlines.commit_waiter_cutoff_ns
            ):
                reservation._cancelled = True
                reservation._phase = ReservationPhase.CANCELLED
                self._tracked.pop(reservation.reservation_id, None)
                if reservation._scope_key is not None and self._active.get(reservation._scope_key) is reservation:
                    del self._active[reservation._scope_key]
                if not reservation._response_settled:
                    reservation._response_settled = True
                    reservation._response = expired_env
                    settled_here = True
                    deliver_cb = reservation._on_response
                claimed = False
            else:
                reservation._phase = ReservationPhase.PREPARING
                claimed = True

        if expire is not None:
            expire()
        elif settled_here:
            _deliver_settled(reservation, expired_env, deliver_cb)
        return claimed

    def enter_commit(self, reservation: Reservation, now_ns: int) -> bool:
        if not isinstance(reservation, Reservation):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if not is_strict_int(now_ns):
            raise BrainError(ErrorCode.INVALID_INPUT, "boolean not allowed for integer")
        if reservation._state_lock is not self._lock:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
        return reservation._enter_commit_locked(now_ns)

    def cancel_before_commit(self, reservation: Reservation, now_ns: int) -> bool:
        """Cancel ``reservation`` under the single state lock if it has not entered ``COMMITTING``."""
        if not isinstance(reservation, Reservation) or not is_strict_int(now_ns):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if reservation._state_lock is not self._lock:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
        expired_env = make_checked_error(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")
        deliver_cb: Callable[[CallResult], None] | None = None
        settled_here = False

        with self._lock:
            if reservation._cancelled or reservation._phase not in (
                ReservationPhase.QUEUED,
                ReservationPhase.PREPARING,
            ):
                return False
            was_queued = reservation._phase is ReservationPhase.QUEUED
            reservation._cancelled = True
            reservation._phase = ReservationPhase.CANCELLED
            if was_queued:
                self._tracked.pop(reservation.reservation_id, None)
                if reservation._scope_key is not None and self._active.get(reservation._scope_key) is reservation:
                    del self._active[reservation._scope_key]
            if not reservation._response_settled:
                reservation._response_settled = True
                reservation._response = expired_env
                settled_here = True
                deliver_cb = reservation._on_response

        if settled_here:
            _deliver_settled(reservation, expired_env, deliver_cb)
        return True

    def arbitrate_at(self, now_ns: int) -> tuple[tuple[Reservation, CallResult], ...]:
        """Sweep tracked executions outside the owner thread and settle expired/cutoff responses once."""
        if not is_strict_int(now_ns):
            raise BrainError(ErrorCode.INVALID_INPUT, "boolean not allowed for integer")
        deadline_env = make_checked_error(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")
        unknown_env = make_checked_error(ErrorCode.COMMIT_OUTCOME_UNKNOWN, "commit outcome unknown")
        to_deliver: list[tuple[Reservation, CallResult, Callable[[CallResult], None] | None]] = []

        with self._lock:
            for res in list(self._tracked.values()):
                if res._phase is ReservationPhase.QUEUED and now_ns >= res._deadlines.handler_deadline_ns:
                    res._cancelled = True
                    res._phase = ReservationPhase.CANCELLED
                    self._tracked.pop(res.reservation_id, None)
                    if res._scope_key is not None and self._active.get(res._scope_key) is res:
                        del self._active[res._scope_key]
                    if not res._response_settled:
                        res._response_settled = True
                        res._response = deadline_env
                        to_deliver.append((res, deadline_env, res._on_response))
                elif res._phase is ReservationPhase.PREPARING and now_ns >= res._deadlines.handler_deadline_ns:
                    res._cancelled = True
                    res._phase = ReservationPhase.CANCELLED
                    if not res._response_settled:
                        res._response_settled = True
                        res._response = deadline_env
                        to_deliver.append((res, deadline_env, res._on_response))
                elif res._phase is ReservationPhase.COMMITTING and now_ns >= res._deadlines.commit_waiter_cutoff_ns:
                    # Reservation stays active until the owner's commit or rollback finishes definitively (4b:215, 217).
                    if not res._response_settled:
                        res._response_settled = True
                        res._response = unknown_env
                        to_deliver.append((res, unknown_env, res._on_response))

        for res, _env, _cb in to_deliver:
            res._response_event.set()
        for _res, env, cb in to_deliver:
            invoke_response_callback(cb, env)
        return tuple((res, env) for res, env, _ in to_deliver)

    def finish_owner_execution(
        self,
        reservation: Reservation,
        response: CallResult,
        *,
        now_ns: int | None = None,
    ) -> bool:
        """Clear ``reservation`` after definitive owner finish and settle ``response`` iff within budget."""
        if not isinstance(reservation, Reservation):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if now_ns is not None and not is_strict_int(now_ns):
            raise BrainError(ErrorCode.INVALID_INPUT, "boolean not allowed for integer")
        if reservation._state_lock is not self._lock:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
        encode_envelope(response)

        with self._lock:
            expire = (
                self._shutdown_expiry_locked()
                if reservation._phase in (ReservationPhase.QUEUED, ReservationPhase.PREPARING)
                else None
            )
            if expire is None:
                result = self._finish_owner_locked(reservation, response, now_ns)
        if expire is not None:
            # Keep the request tracked until shutdown counts and settles it.
            expire()
            with self._lock:
                result = self._finish_owner_locked(reservation, response, now_ns)
        won, settled_here, deliver_env, deliver_cb = result
        if settled_here:
            _deliver_settled(reservation, deliver_env, deliver_cb)
        return won

    def _finish_owner_locked(
        self, reservation: Reservation, response: CallResult, now_ns: int | None,
    ) -> tuple[bool, bool, CallResult, Callable[[CallResult], None] | None]:
        deliver_cb: Callable[[CallResult], None] | None = None
        deliver_env = response
        settled_here = False
        won = False

        prior_phase = reservation._phase
        self._tracked.pop(reservation.reservation_id, None)
        if reservation._scope_key is not None and self._active.get(reservation._scope_key) is reservation:
            del self._active[reservation._scope_key]
        if not reservation._response_settled:
            if (
                now_ns is not None
                and prior_phase is ReservationPhase.COMMITTING
                and now_ns >= reservation._deadlines.commit_waiter_cutoff_ns
            ):
                reservation._phase = ReservationPhase.COMPLETED
                deliver_env = make_checked_error(ErrorCode.COMMIT_OUTCOME_UNKNOWN, "commit outcome unknown")
                reservation._response_settled = True
                reservation._response = deliver_env
                settled_here = True
                deliver_cb = reservation._on_response
            elif (
                now_ns is not None
                and prior_phase in (ReservationPhase.QUEUED, ReservationPhase.PREPARING)
                and now_ns >= reservation._deadlines.handler_deadline_ns
            ):
                reservation._cancelled = True
                reservation._phase = ReservationPhase.CANCELLED
                deliver_env = make_checked_error(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")
                reservation._response_settled = True
                reservation._response = deliver_env
                settled_here = True
                deliver_cb = reservation._on_response
            else:
                if prior_phase is not ReservationPhase.CANCELLED:
                    reservation._phase = ReservationPhase.COMPLETED
                reservation._response_settled = True
                reservation._response = response
                settled_here = True
                won = True
                deliver_cb = reservation._on_response
        elif prior_phase is not ReservationPhase.CANCELLED:
            reservation._phase = ReservationPhase.COMPLETED

        return won, settled_here, deliver_env, deliver_cb


def reserve(
    scope_key: ReservationScopeKey | tuple[str, str, str],
    request_digest: str,
    *,
    table: ReservationTable,
    deadlines: RequestDeadlines | None = None,
    request_digest_key_id: str | None = None,
    on_response: Callable[[CallResult], None] | None = None,
) -> Reservation:
    """Reserve ``scope_key`` in ``table`` before queueing on the request thread (4b:200)."""
    if not isinstance(table, ReservationTable):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    return table.reserve(
        scope_key,
        request_digest,
        deadlines=deadlines,
        request_digest_key_id=request_digest_key_id,
        on_response=on_response,
    )


def enter_commit(reservation: Reservation, now_ns: int) -> bool:
    """Transition ``reservation`` into ``COMMITTING`` under its shared state lock iff uncancelled and within budget."""
    if not isinstance(reservation, Reservation):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if not is_strict_int(now_ns):
        raise BrainError(ErrorCode.INVALID_INPUT, "boolean not allowed for integer")
    return reservation._enter_commit_locked(now_ns)
