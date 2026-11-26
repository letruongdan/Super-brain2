"""Task 4b pre-queue RAM RequestAuthView admission and immutable canonical Call copy/reconstruction (C3)."""

from __future__ import annotations

import threading
from collections.abc import Callable, Mapping

from superbrain.application.idempotency import (
    compute_canonical_payload_hmac,
    compute_idempotency_key_hash,
    tool_uses_idempotency,
)
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    HANDLER_RESERVE_NS,
    LOCAL_PHASE_BUDGET_NS,
    AuthSnapshot,
    Call,
    CredentialCapabilityBinding,
    Principal,
    PrivateRequestAuth,
    QueuedKernelRequest,
    RequestAuthView,
    RequestDeadlines,
    ReservationScopeKey,
    Scope,
    apply_credential_capability_bindings,
    collect_credential_capability_bindings,
    is_strict_int,
    parse_bearer_token,
    require_opaque_id,
    require_positive_int,
)
from superbrain.core.wire import canonical_request_payload, normalize_call, parse_json
from superbrain.ports.kernel import RequestAuthStatePort


class AtomicRequestAuthState(RequestAuthStatePort):
    """Store-bound atomic RAM holder for ``RequestAuthView`` (short pointer swap only, zero I/O under lock)."""

    def __init__(self, expected_store_id: str) -> None:
        require_opaque_id(expected_store_id, label="expected_store_id")
        self._expected_store_id = expected_store_id
        self._lock = threading.Lock()
        self._view: RequestAuthView | None = None
        self._installed_version = 0
        self._issued_version = 0
        self._credential_bindings: dict[str, CredentialCapabilityBinding] = {}

    @property
    def store_id(self) -> str:
        return self._expected_store_id

    def current(self) -> RequestAuthView | None:
        with self._lock:
            view = self._view
        if view is not None and view.auth.store_id != self._expected_store_id:
            raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable")
        return view

    def install(self, view: RequestAuthView) -> RequestAuthView:
        if not isinstance(view, RequestAuthView):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if view.auth.store_id != self._expected_store_id:
            with self._lock:
                self._view = None
                self._credential_bindings.clear()
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
        with self._lock:
            if view.version <= self._installed_version:
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
            self._view = view
            self._installed_version = view.version
            if view.version > self._issued_version:
                self._issued_version = view.version
            self._credential_bindings = collect_credential_capability_bindings(view.auth)
            return view

    def merge_runtime_capabilities(self, snap: AuthSnapshot) -> AuthSnapshot:
        """Overlay cached runtime credential capabilities onto a freshly loaded policy snapshot."""
        with self._lock:
            if not self._credential_bindings:
                return snap
            bindings = dict(self._credential_bindings)
        return apply_credential_capability_bindings(snap, bindings)

    def next_version(self) -> int:
        with self._lock:
            self._issued_version = max(self._issued_version, self._installed_version) + 1
            return self._issued_version

    def clear(self) -> None:
        with self._lock:
            self._view = None


def begin_local_phase(
    monotonic_ns: Callable[[], int],
    total_deadline_ns: int,
    *,
    local_deadline_ns: int | None = None,
    local_budget_ns: int = LOCAL_PHASE_BUDGET_NS,
) -> int:
    """Start or continue the shared <=100 ms local admission/filter/observer phase or fail closed."""
    if not is_strict_int(total_deadline_ns) or not is_strict_int(local_budget_ns):
        raise BrainError(ErrorCode.INVALID_INPUT, "boolean not allowed for integer")
    if local_budget_ns <= 0 or local_budget_ns > LOCAL_PHASE_BUDGET_NS:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    handler_deadline_ns = total_deadline_ns - HANDLER_RESERVE_NS
    if local_deadline_ns is not None:
        if not is_strict_int(local_deadline_ns):
            raise BrainError(ErrorCode.INVALID_INPUT, "boolean not allowed for integer")
        return min(local_deadline_ns, handler_deadline_ns)
    start_ns = monotonic_ns()
    if not is_strict_int(start_ns):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
    if start_ns >= handler_deadline_ns:
        raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")
    return min(start_ns + local_budget_ns, handler_deadline_ns)


def _decode_scope(raw_scope: JsonValue) -> Scope | None:
    if raw_scope is None:
        return None
    if not isinstance(raw_scope, dict) or set(raw_scope) != {"repo_id", "checkout_id"}:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
    repo_id = raw_scope["repo_id"]
    checkout_id = raw_scope["checkout_id"]
    if not isinstance(repo_id, str) or (checkout_id is not None and not isinstance(checkout_id, str)):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
    return Scope(repo_id=repo_id, checkout_id=checkout_id)


def reconstruct_queued_call(queued: QueuedKernelRequest) -> Call:
    """Reconstruct a fresh private ``Call`` on the owner thread from immutable ``queued.canonical_payload`` (C3:92)."""
    if not isinstance(queued, QueuedKernelRequest):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    parsed = parse_json(queued.canonical_payload)
    if not isinstance(parsed, dict) or set(parsed) != {"tool", "selected_scope", "arguments"}:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
    tool = parsed["tool"]
    arguments = parsed["arguments"]
    decoded_scope = _decode_scope(parsed["selected_scope"])
    if tool != queued.tool or decoded_scope != queued.selected_scope or not isinstance(arguments, dict):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
    call = Call(
        tool=queued.tool,
        arguments=arguments,
        correlation_id=queued.correlation_id,
        selected_scope=queued.selected_scope,
    )
    if canonical_request_payload(call) != queued.canonical_payload:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
    return call


def authorize_call_against_snapshot(snap: AuthSnapshot, principal: Principal, call: Call) -> None:
    """Enforce principal, ``selected_scope``, and tool selector/scope rules symmetrically against ``snap``."""
    if not isinstance(snap, AuthSnapshot) or not isinstance(principal, Principal) or not isinstance(call, Call):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if not snap.allows(principal, None, action="get_health"):
        raise BrainError(ErrorCode.NOT_FOUND, "not found")
    if call.selected_scope is not None and not snap.allows(principal, call.selected_scope, action=call.tool):
        raise BrainError(ErrorCode.NOT_FOUND, "not found")

    if call.tool == "prepare_task":
        has_hint = "workspace_hint" in call.arguments
        has_ws = "workspace_id" in call.arguments
        has_chk = "checkout_id" in call.arguments
        if has_hint and not has_ws and not has_chk:
            # Mutable human alias: binding resolution is deferred until owner cache miss (4a:162-164, 170; 4b:202-203).
            return
        if not has_hint and has_ws and has_chk:
            arg_ws = str(call.arguments["workspace_id"])
            arg_chk = str(call.arguments["checkout_id"])
            found = snap.checkouts.get(arg_chk)
            if found is None or found.owner_id != principal.owner_id or found.repo_id != arg_ws:
                raise BrainError(ErrorCode.NOT_FOUND, "not found")
            if found.machine_id != principal.machine_id:
                raise BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch")
            if call.selected_scope is not None and (
                call.selected_scope.repo_id != found.repo_id
                or (
                    call.selected_scope.checkout_id is not None and call.selected_scope.checkout_id != found.checkout_id
                )
            ):
                raise BrainError(ErrorCode.NOT_FOUND, "not found")
            if not snap.allows(principal, Scope(found.repo_id, found.checkout_id), action="prepare_task"):
                raise BrainError(ErrorCode.NOT_FOUND, "not found")
            return
        raise BrainError(ErrorCode.INVALID_INPUT, "mixed or invalid workspace selector")
    elif "workspace_id" in call.arguments:
        arg_ws = str(call.arguments["workspace_id"])
        arg_chk_opt = str(call.arguments["checkout_id"]) if "checkout_id" in call.arguments else None
        if call.selected_scope is not None and (
            call.selected_scope.repo_id != arg_ws
            or (
                arg_chk_opt is not None
                and call.selected_scope.checkout_id is not None
                and call.selected_scope.checkout_id != arg_chk_opt
            )
        ):
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        if not snap.allows(principal, Scope(arg_ws, arg_chk_opt), action=call.tool):
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
    elif "checkout_id" in call.arguments:
        arg_chk = str(call.arguments["checkout_id"])
        chk_b = snap.checkouts.get(arg_chk)
        if chk_b is None:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        if call.selected_scope is not None and (
            call.selected_scope.repo_id != chk_b.repo_id
            or (call.selected_scope.checkout_id is not None and call.selected_scope.checkout_id != arg_chk)
        ):
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        if not snap.allows(principal, Scope(chk_b.repo_id, arg_chk), action=call.tool):
            raise BrainError(ErrorCode.NOT_FOUND, "not found")


def admit_prequeue_request(
    *,
    expected_store_id: str,
    writer_epoch: int,
    auth_state: RequestAuthStatePort,
    tool: str,
    raw_arguments: JsonValue | Mapping[str, JsonValue],
    token: str,
    deadlines: RequestDeadlines,
    selected_scope: Scope | None = None,
    expected_principal: Principal | None = None,
    correlation_id: str | None = None,
    remaining_local_budget_ns: int = LOCAL_PHASE_BUDGET_NS,
) -> QueuedKernelRequest:
    """Authenticate, normalize, authorize scope, and freeze canonical bytes using ONLY ``RequestAuthView`` (C3)."""
    require_opaque_id(expected_store_id, label="expected_store_id")
    require_positive_int(writer_epoch)
    if not isinstance(deadlines, RequestDeadlines):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")

    view = auth_state.current()
    if view is None or not isinstance(view, RequestAuthView) or view.auth.store_id != expected_store_id:
        raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable")

    credential_id, _ = parse_bearer_token(token)
    principal = view.auth.resolve_credential(token)
    if expected_principal is not None:
        if not isinstance(expected_principal, Principal):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if principal != expected_principal:
            raise BrainError(ErrorCode.IDENTITY_MISMATCH, "principal identity mismatch")

    auth = PrivateRequestAuth(credential_id=credential_id, principal=principal, token=token)
    call = normalize_call(
        tool,
        raw_arguments,
        principal,
        selected_scope=selected_scope,
        correlation_id=correlation_id,
    )

    authorize_call_against_snapshot(view.auth, principal, call)

    canonical_bytes = canonical_request_payload(call)
    scope_key: ReservationScopeKey | None = None
    request_digest_key_id: str | None = None
    request_digest: str | None = None

    if tool_uses_idempotency(call):
        idem_key = call.arguments.get("idempotency_key")
        if not isinstance(idem_key, str):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        key_hash = compute_idempotency_key_hash(principal.principal_id, call.tool, idem_key)
        scope_key = ReservationScopeKey(
            principal_id=principal.principal_id,
            tool=call.tool,
            key_hash=key_hash,
        )
        request_digest_key_id = view.active_request_key_id
        request_digest = compute_canonical_payload_hmac(view.active_request_key_bytes, canonical_bytes)

    return QueuedKernelRequest(
        store_id=expected_store_id,
        writer_epoch=writer_epoch,
        tool=call.tool,
        correlation_id=call.correlation_id,
        selected_scope=call.selected_scope,
        deadlines=deadlines,
        auth_view_version=view.version,
        auth=auth,
        canonical_payload=canonical_bytes,
        scope_key=scope_key,
        request_digest_key_id=request_digest_key_id,
        request_digest=request_digest,
        remaining_local_budget_ns=remaining_local_budget_ns,
    )
