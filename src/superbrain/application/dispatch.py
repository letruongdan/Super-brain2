"""Task 4a/4b owner dispatch, live credential/scope recheck, C1/C2/C3/C4 orchestration, and commit gating."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from superbrain.application.deadlines import Reservation, authorize_call_against_snapshot, enter_commit
from superbrain.application.idempotency import (
    compute_idempotency_key_hash,
    compute_request_hmac,
    is_idempotency_expired,
    tool_uses_idempotency,
    verify_request_hmac,
)
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.faults import crashpoint
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    HANDLER_RESERVE_NS,
    IDEMPOTENCY_CLOCK_UNTRUSTED_CODE,
    ArtifactSendSpec,
    Call,
    CallContext,
    CallResult,
    IdempotencyRow,
    Principal,
    PrivateRequestAuth,
    Scope,
    StoredResult,
    parse_bearer_token,
    require_opaque_id,
)
from superbrain.core.wire import encode_envelope, make_error_envelope, make_success_envelope
from superbrain.ports.clock import Clock, MonotonicClock
from superbrain.ports.kernel import (
    KernelBlobStagePort,
    KernelIdempotencyPort,
    KernelPolicyPort,
    KernelSendAttemptPort,
    KernelTx,
)

_PLACEHOLDER_RECEIPT_ID = "00000000-0000-7000-8000-000000000000"

_STORED_KIND_ACTIONS: dict[str, str] = {
    "delivery_result": "prepare_task",
    "artifact_result": "get_artifact",
    "outcome_result": "record_outcome",
}


def _scope_action_for_stored(result: StoredResult) -> str:
    return _STORED_KIND_ACTIONS.get(result.refs[0].kind, "prepare_task") if result.refs else "prepare_task"


@dataclass(frozen=True)
class PreparedEffect:
    """Bounded safe blobs to pre-stage outside SQLite plus the single-transaction business ``apply`` callback (C2)."""

    blobs: tuple[bytes, ...]
    apply: Callable[[KernelTx], StoredResult]

    def __post_init__(self) -> None:
        if not isinstance(self.blobs, tuple) or not all(type(b) is bytes for b in self.blobs):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if not callable(self.apply):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")


class KernelToolDomain(Protocol):
    """Pluggable business tool handler contract (injected in tests; production tools unlock per increment)."""

    def supports_tool(self, tool: str, *, deep: bool = False) -> bool: ...

    def prepare_mutation(self, call: Call, ctx: CallContext, *, now: datetime) -> PreparedEffect: ...

    def execute_readonly(self, call: Call, ctx: CallContext) -> dict[str, JsonValue]: ...

    def render_stored(
        self, result: StoredResult, principal: Principal, *, selected_scope: Scope | None
    ) -> dict[str, JsonValue]: ...

    def describe_artifact_send(
        self,
        result: StoredResult,
        rendered: Mapping[str, JsonValue],
        principal: Principal,
        *,
        selected_scope: Scope | None,
    ) -> ArtifactSendSpec | None:
        return None


class KernelDispatcher:
    """Pure application owner dispatcher over port interfaces (zero ``storage`` or ``adapters`` imports)."""

    def __init__(
        self,
        *,
        store_id: str,
        policy: KernelPolicyPort,
        idempotency: KernelIdempotencyPort,
        blob_stager: KernelBlobStagePort,
        clock: Clock,
        store_schema_version: Callable[[], int],
        policy_schema_version: Callable[[], int],
        monotonic_clock: MonotonicClock | None = None,
        enforce_unreserved_deadline: bool = True,
        domain: KernelToolDomain | None = None,
        send_attempts: KernelSendAttemptPort | None = None,
        before_enter_commit: Callable[[Reservation | None], None] | None = None,
        on_commit_completed: Callable[[StoredResult], None] | None = None,
    ) -> None:
        require_opaque_id(store_id, label="store_id")
        self._store_id = store_id
        self._policy = policy
        self._idempotency = idempotency
        self._blob_stager = blob_stager
        self._clock = clock
        self._monotonic_clock = monotonic_clock
        self._enforce_unreserved_deadline = enforce_unreserved_deadline
        self._store_schema_version = store_schema_version
        self._policy_schema_version = policy_schema_version
        self._domain = domain
        self._send_attempts = send_attempts
        self._before_enter_commit = before_enter_commit
        self._on_commit_completed = on_commit_completed

    def dispatch(self, call: Call, ctx: CallContext, *, auth: PrivateRequestAuth) -> CallResult:
        """Execute ``call`` on the owner thread and return a validated v2 ``CallResult`` envelope."""
        return self.dispatch_reserved(call, ctx, auth=auth, reservation=None)

    def dispatch_reserved(
        self,
        call: Call,
        ctx: CallContext,
        *,
        auth: PrivateRequestAuth,
        reservation: Reservation | None = None,
    ) -> CallResult:
        """Execute ``call`` on the owner thread gated by ``reservation`` and ``enter_commit`` (Task 4b)."""
        try:
            data = self._dispatch_data(call, ctx, auth=auth, reservation=reservation)
            envelope = make_success_envelope(data)
            encode_envelope(envelope)
            return envelope
        except BrainError as err:
            err_envelope = make_error_envelope(err)
            encode_envelope(err_envelope)
            return err_envelope

    def render_current(self, result: StoredResult, principal: Principal, *, selected_scope: Scope | None) -> JsonValue:
        """Resolve and render ``result``'s recorded refs against live policy and ``selected_scope``."""
        if not isinstance(result, StoredResult) or not isinstance(principal, Principal):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if selected_scope is not None and not isinstance(selected_scope, Scope):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if not self._policy.allows(principal, None, action="get_health"):
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        if selected_scope is not None and not self._policy.allows(
            principal, selected_scope, action=_scope_action_for_stored(result)
        ):
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        if self._domain is None:
            raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")
        rendered = self._domain.render_stored(result, principal, selected_scope=selected_scope)
        make_success_envelope(rendered)
        return rendered

    def _render_dict(
        self, result: StoredResult, principal: Principal, *, selected_scope: Scope | None
    ) -> dict[str, JsonValue]:
        rendered = self.render_current(result, principal, selected_scope=selected_scope)
        if not isinstance(rendered, dict):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
        return rendered

    def _attach_pending_send_attempt(
        self,
        result: StoredResult,
        rendered: dict[str, JsonValue],
        principal: Principal,
        *,
        selected_scope: Scope | None,
        reservation: Reservation | None,
    ) -> dict[str, JsonValue]:
        if self._send_attempts is None or self._domain is None:
            return rendered
        if reservation is not None and reservation.response_settled:
            return rendered
        spec = self._domain.describe_artifact_send(
            result,
            rendered,
            principal,
            selected_scope=selected_scope,
        )
        if spec is None:
            return rendered
        encode_envelope(make_success_envelope({**rendered, "served_receipt_id": _PLACEHOLDER_RECEIPT_ID}))
        attempt = self._send_attempts.record_pending_attempt(spec)
        return {**rendered, "served_receipt_id": attempt.served_receipt_id}

    def _verify_owner_auth_and_scope(self, call: Call, ctx: CallContext, auth: PrivateRequestAuth) -> Principal:
        if not isinstance(call, Call) or not isinstance(ctx, CallContext) or not isinstance(auth, PrivateRequestAuth):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if ctx.identity.store_id != self._store_id or ctx.selected_scope != call.selected_scope:
            raise BrainError(ErrorCode.IDENTITY_MISMATCH, "principal identity mismatch")
        parsed_cred_id, _ = parse_bearer_token(auth.token)
        if parsed_cred_id != auth.credential_id:
            raise BrainError(ErrorCode.UNAUTHENTICATED, "unauthenticated")
        live_principal = self._policy.resolve_credential(auth.token)
        if live_principal != auth.principal or live_principal != ctx.principal:
            raise BrainError(ErrorCode.IDENTITY_MISMATCH, "principal identity mismatch")
        authorize_call_against_snapshot(self._policy.snapshot(), live_principal, call)
        return live_principal

    def _check_handler_budget(self, ctx: CallContext, reservation: Reservation | None) -> None:
        if reservation is not None and reservation.cancelled:
            raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")
        cutoff_ns = ctx.deadline_ns - HANDLER_RESERVE_NS
        if ctx.local_deadline_ns is not None:
            cutoff_ns = min(cutoff_ns, ctx.local_deadline_ns)
        if reservation is not None:
            if self._monotonic_clock is None:
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
            now_ns = self._monotonic_clock.monotonic_ns()
            if now_ns >= cutoff_ns:
                raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")
        elif self._monotonic_clock is not None and (
            self._enforce_unreserved_deadline or ctx.local_deadline_ns is not None
        ):
            now_ns = self._monotonic_clock.monotonic_ns()
            if now_ns >= cutoff_ns:
                raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")

    def _gate_enter_commit(self, ctx: CallContext, reservation: Reservation | None) -> None:
        if self._before_enter_commit is not None:
            self._before_enter_commit(reservation)
        if reservation is not None:
            if self._monotonic_clock is None:
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
            now_ns = self._monotonic_clock.monotonic_ns()
            if not enter_commit(reservation, now_ns):
                raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")
        elif self._monotonic_clock is not None and self._enforce_unreserved_deadline:
            now_ns = self._monotonic_clock.monotonic_ns()
            if now_ns >= ctx.deadline_ns - HANDLER_RESERVE_NS:
                raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")

    def _verify_retained_row(
        self, row: IdempotencyRow, call: Call, *, now: datetime, canonical_payload: bytes | None = None
    ) -> bool:
        """Validate ``row.request_digest_key_id`` (even when expired); return True iff ``row`` is live and matches."""
        stored_key = self._policy.request_digest_key_by_id(row.request_digest_key_id)
        if stored_key is None:
            raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable")
        if not is_idempotency_expired(row.committed_at, now):
            resolver = self._send_attempts.read_attempt if self._send_attempts is not None else None
            if not verify_request_hmac(
                stored_key,
                call,
                row.request_digest,
                canonical_payload,
                principal_id=row.principal_id,
                resolve_send_attempt=resolver,
            ):
                raise BrainError(ErrorCode.IDEMPOTENCY_CONFLICT, "idempotency conflict")
            return True
        return False

    def _dispatch_data(
        self,
        call: Call,
        ctx: CallContext,
        *,
        auth: PrivateRequestAuth,
        reservation: Reservation | None = None,
    ) -> dict[str, JsonValue]:
        live_principal = self._verify_owner_auth_and_scope(call, ctx, auth)
        self._check_handler_budget(ctx, reservation)

        uses_idem = tool_uses_idempotency(call)
        is_shallow_health = call.tool == "get_health" and not uses_idem

        if not is_shallow_health:
            deep_flag = call.tool == "get_health" and uses_idem
            if self._domain is None or not self._domain.supports_tool(call.tool, deep=deep_flag):
                raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")

        if not uses_idem:
            if is_shallow_health:
                untrusted = self._idempotency.clock_untrusted()
                degraded: list[JsonValue] = [IDEMPOTENCY_CLOCK_UNTRUSTED_CODE] if untrusted else []
                return {
                    "ready": not untrusted,
                    "store_id": self._store_id,
                    "writer_epoch": ctx.identity.writer_epoch,
                    "schema_version": self._store_schema_version(),
                    "policy_schema_version": self._policy_schema_version(),
                    "degraded_codes": degraded,
                }
            assert self._domain is not None
            return self._domain.execute_readonly(call, ctx)

        assert self._domain is not None
        raw_idem_key = call.arguments.get("idempotency_key")
        if not isinstance(raw_idem_key, str):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        key_hash = compute_idempotency_key_hash(live_principal.principal_id, call.tool, raw_idem_key)

        now = self._clock.now()
        existing = self._idempotency.lookup_for_owner(
            principal_id=live_principal.principal_id,
            tool=call.tool,
            key_hash=key_hash,
            now=now,
        )
        if existing is not None and self._verify_retained_row(
            existing, call, now=now, canonical_payload=ctx.canonical_payload
        ):
            replay_result = StoredResult(
                result_id=existing.result_id,
                assignment_id=existing.assignment_id,
                refs=existing.refs,
            )
            rendered_replay = self._render_dict(replay_result, live_principal, selected_scope=call.selected_scope)
            self._gate_enter_commit(ctx, reservation)
            self._idempotency.record_replay(row=existing, now=now)
            return self._attach_pending_send_attempt(
                replay_result,
                rendered_replay,
                live_principal,
                selected_scope=call.selected_scope,
                reservation=reservation,
            )

        active_key_id, active_key_bytes = self._policy.request_digest_key()
        request_digest = compute_request_hmac(active_key_bytes, call, ctx.canonical_payload)
        prepared = self._domain.prepare_mutation(call, ctx, now=now)

        if reservation is not None and reservation.cancelled:
            raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")
        staged_blobs = tuple(self._blob_stager.stage_blob(blob) for blob in prepared.blobs)

        self._gate_enter_commit(ctx, reservation)
        commit_now = self._clock.now()
        stored, was_raced_replay = self._idempotency.commit_prepared_effect(
            staged_blobs=staged_blobs,
            principal_id=live_principal.principal_id,
            tool=call.tool,
            key_hash=key_hash,
            active_key_id=active_key_id,
            request_digest=request_digest,
            now=commit_now,
            verify_raced_row=lambda r: self._check_raced_row(r, call, now=commit_now),
            apply=prepared.apply,
        )
        if not was_raced_replay:
            crashpoint("kernel.after_commit_before_response")
            if self._on_commit_completed is not None:
                try:
                    self._on_commit_completed(stored)
                except BrainError as err:
                    if err.code is ErrorCode.COMMIT_OUTCOME_UNKNOWN:
                        raise
                    raise BrainError(ErrorCode.COMMIT_OUTCOME_UNKNOWN, "commit outcome unknown") from err
                except Exception as exc:  # noqa: BLE001 — lost completion callback after durable commit (4a line 160)
                    raise BrainError(ErrorCode.COMMIT_OUTCOME_UNKNOWN, "commit outcome unknown") from exc

        rendered_fresh = self._render_dict(stored, live_principal, selected_scope=call.selected_scope)
        return self._attach_pending_send_attempt(
            stored,
            rendered_fresh,
            live_principal,
            selected_scope=call.selected_scope,
            reservation=reservation,
        )

    def _check_raced_row(self, row: IdempotencyRow, call: Call, *, now: datetime) -> bool:
        return self._verify_retained_row(row, call, now=now)


def dispatch(
    call: Call,
    ctx: CallContext,
    *,
    auth: PrivateRequestAuth,
    dispatcher: KernelDispatcher,
) -> CallResult:
    """Module-level owner dispatch helper delegating to ``dispatcher``."""
    return dispatcher.dispatch(call, ctx, auth=auth)


def render_current(
    result: StoredResult,
    principal: Principal,
    *,
    selected_scope: Scope | None,
    dispatcher: KernelDispatcher,
) -> JsonValue:
    """Module-level current-policy renderer delegating to ``dispatcher``."""
    return dispatcher.render_current(result, principal, selected_scope=selected_scope)
