"""Task 4b in-memory reservation registry and single-lock response/commit arbiter."""

from __future__ import annotations

import hmac
import threading
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


class Reservation:
    """In-flight execution & idempotency reservation synchronized under ``ReservationTable``'s single state lock."""

    def __init__(
        self,
        *,
        state_lock: threading.Lock,
        deadlines: RequestDeadlines,
        scope_key: ReservationScopeKey | None = None,
        request_digest_key_id: str | None = None,
        request_digest: str | None = None,
        on_response: Callable[[CallResult], None] | None = None,
    ) -> None:
        self._state_lock = state_lock
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
            if now_ns >= self._deadlines.handler_deadline_ns or now_ns >= self._deadlines.commit_waiter_cutoff_ns:
                self._cancelled = True
                self._phase = ReservationPhase.CANCELLED
                return False
            self._phase = ReservationPhase.COMMITTING
            return True


class ReservationTable:
    """In-memory reservation registry and single-lock response arbiter (Task 4b)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._active: dict[ReservationScopeKey, Reservation] = {}
        self._tracked: dict[str, Reservation] = {}

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
                state_lock=self._lock,
                deadlines=resolved_deadlines,
                scope_key=key,
                request_digest_key_id=request_digest_key_id,
                request_digest=request_digest,
                on_response=on_response,
            )
            self._active[key] = reservation
            self._tracked[reservation.reservation_id] = reservation
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
                state_lock=self._lock,
                deadlines=deadlines,
                on_response=on_response,
            )
            self._tracked[ticket.reservation_id] = ticket
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
            if (
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

        if settled_here:
            reservation._response_event.set()
            if deliver_cb is not None:
                deliver_cb(expired_env)
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
            reservation._response_event.set()
            if deliver_cb is not None:
                deliver_cb(expired_env)
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

        for res, env, cb in to_deliver:
            res._response_event.set()
            if cb is not None:
                cb(env)
        return tuple((res, env) for res, env, _ in to_deliver)

    def finish_owner_execution(self, reservation: Reservation, response: CallResult) -> bool:
        """Clear ``reservation`` after definitive owner finish and settle ``response`` iff still unsettled."""
        if not isinstance(reservation, Reservation):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if reservation._state_lock is not self._lock:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
        encode_envelope(response)
        deliver_cb: Callable[[CallResult], None] | None = None
        won = False

        with self._lock:
            self._tracked.pop(reservation.reservation_id, None)
            if reservation._scope_key is not None and self._active.get(reservation._scope_key) is reservation:
                del self._active[reservation._scope_key]
            if reservation._phase is not ReservationPhase.CANCELLED:
                reservation._phase = ReservationPhase.COMPLETED
            if not reservation._response_settled:
                reservation._response_settled = True
                reservation._response = response
                won = True
                deliver_cb = reservation._on_response

        if won:
            reservation._response_event.set()
            if deliver_cb is not None:
                deliver_cb(response)
        return won


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
