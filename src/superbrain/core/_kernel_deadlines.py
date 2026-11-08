"""Pure Task 4b kernel deadline budgets, reservation scope keys, phases, and immutable queued requests."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from superbrain.core._kernel_base import (
    Scope,
    is_strict_int,
    require_opaque_id,
    require_positive_int,
    require_sha256_digest,
)
from superbrain.core._kernel_dispatch import PrivateRequestAuth
from superbrain.core._kernel_workspace import COMMIT_RESERVE_NS, LOCAL_PHASE_BUDGET_NS
from superbrain.core.errors import BrainError, ErrorCode

TOTAL_REQUEST_BUDGET_NS = 1_500_000_000
"""Total daemon request budget (1,500 ms) from receive timestamp ``t0_ns`` (D5)."""

HANDLER_RESERVE_NS = COMMIT_RESERVE_NS
"""Final 200 ms reserved after handler preparation (handler deadline = total - 200 ms = 1,300 ms)."""

RESPONSE_RESERVE_NS = 25_000_000
"""Final 25 ms response budget after commit-waiter cutoff (cutoff = total - 25 ms = 1,475 ms)."""


@dataclass(frozen=True)
class RequestDeadlines:
    """Monotonic nanosecond deadlines derived from ``receive_ns`` (D5, Task 4b)."""

    receive_ns: int
    total_deadline_ns: int
    handler_deadline_ns: int
    commit_waiter_cutoff_ns: int

    def __post_init__(self) -> None:
        for val in (
            self.receive_ns,
            self.total_deadline_ns,
            self.handler_deadline_ns,
            self.commit_waiter_cutoff_ns,
        ):
            if not is_strict_int(val):
                raise BrainError(ErrorCode.INVALID_INPUT, "boolean not allowed for integer")
        if not (self.receive_ns < self.handler_deadline_ns < self.commit_waiter_cutoff_ns < self.total_deadline_ns):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")

    @classmethod
    def from_receive_ns(
        cls,
        receive_ns: int,
        *,
        total_budget_ns: int = TOTAL_REQUEST_BUDGET_NS,
    ) -> RequestDeadlines:
        if not is_strict_int(receive_ns) or not is_strict_int(total_budget_ns):
            raise BrainError(ErrorCode.INVALID_INPUT, "boolean not allowed for integer")
        if total_budget_ns <= HANDLER_RESERVE_NS:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        total_deadline_ns = receive_ns + total_budget_ns
        return cls(
            receive_ns=receive_ns,
            total_deadline_ns=total_deadline_ns,
            handler_deadline_ns=total_deadline_ns - HANDLER_RESERVE_NS,
            commit_waiter_cutoff_ns=total_deadline_ns - RESPONSE_RESERVE_NS,
        )

    @property
    def response_budget_ns(self) -> int:
        return self.total_deadline_ns - self.commit_waiter_cutoff_ns

    def local_deadline_ns(self, local_phase_start_ns: int) -> int:
        if not is_strict_int(local_phase_start_ns):
            raise BrainError(ErrorCode.INVALID_INPUT, "boolean not allowed for integer")
        return min(local_phase_start_ns + LOCAL_PHASE_BUDGET_NS, self.handler_deadline_ns)


@dataclass(frozen=True)
class ReservationScopeKey:
    """In-memory reservation identity ``(principal_id, tool, key_hash)`` matching durable ``store4`` scope."""

    principal_id: str
    tool: str
    key_hash: str

    def __post_init__(self) -> None:
        require_opaque_id(self.principal_id, label="principal_id")
        if not isinstance(self.tool, str) or not self.tool:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        require_sha256_digest(self.key_hash)


class ReservationPhase(StrEnum):
    """Lifecycle phase of a queued/executing kernel request under the shared arbiter lock."""

    QUEUED = "queued"
    PREPARING = "preparing"
    COMMITTING = "committing"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class QueuedKernelRequest:
    """Immutable pre-validated request handoff owning canonical payload bytes (C3:92).

    ``auth`` and ``canonical_payload`` are excluded from ``repr`` so tokens and raw argument text never leak.
    """

    store_id: str
    writer_epoch: int
    tool: str
    correlation_id: str | None
    selected_scope: Scope | None
    deadlines: RequestDeadlines
    auth_view_version: int
    auth: PrivateRequestAuth = field(repr=False)
    canonical_payload: bytes = field(repr=False)
    scope_key: ReservationScopeKey | None = None
    request_digest_key_id: str | None = None
    request_digest: str | None = None
    remaining_local_budget_ns: int = LOCAL_PHASE_BUDGET_NS

    def __post_init__(self) -> None:
        require_opaque_id(self.store_id, label="store_id")
        require_positive_int(self.writer_epoch)
        if not isinstance(self.tool, str) or not self.tool:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if self.correlation_id is not None and (
            not isinstance(self.correlation_id, str) or not (1 <= len(self.correlation_id.encode("utf-8")) <= 128)
        ):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if self.selected_scope is not None and not isinstance(self.selected_scope, Scope):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if not isinstance(self.deadlines, RequestDeadlines):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        require_positive_int(self.auth_view_version)
        if not isinstance(self.auth, PrivateRequestAuth):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if type(self.canonical_payload) is not bytes or not self.canonical_payload:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if self.scope_key is not None:
            if not isinstance(self.scope_key, ReservationScopeKey):
                raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
            require_opaque_id(self.request_digest_key_id, label="request_digest_key_id")
            require_sha256_digest(self.request_digest)
        elif self.request_digest_key_id is not None or self.request_digest is not None:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if not is_strict_int(self.remaining_local_budget_ns):
            raise BrainError(ErrorCode.INVALID_INPUT, "boolean not allowed for integer")
        if not (0 < self.remaining_local_budget_ns <= LOCAL_PHASE_BUDGET_NS):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
