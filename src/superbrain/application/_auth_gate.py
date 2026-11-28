"""RAM ``AuthGate`` and zero-I/O shallow ``get_health`` evaluator for Task 6a."""

from __future__ import annotations

import threading
from dataclasses import replace
from datetime import timedelta

from superbrain.application._prequeue import authorize_call_against_snapshot
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    CAPTURE_GAPS_PRESENT_CODE,
    HANDLER_RESERVE_NS,
    IDEMPOTENCY_CLOCK_UNTRUSTED_CODE,
    TLS_EXPIRED_CODE,
    TLS_EXPIRING_CODE,
    TLS_EXPIRING_WINDOW,
    AuthGrantStamp,
    AuthSnapshot,
    CredentialCapabilityBinding,
    Identity,
    OwnerReply,
    RequestAuthView,
    ShallowHealthMeta,
    ToolCommand,
    apply_credential_capability_bindings,
    is_strict_int,
    parse_bearer_token,
    require_aware_utc,
    update_credential_capability_bindings,
)
from superbrain.core.wire import encode_envelope, make_success_envelope, normalize_call
from superbrain.ports.clock import Clock, MonotonicClock
from superbrain.ports.kernel import RequestAuthStatePort


class AuthGate(RequestAuthStatePort):
    """Single short-mutex RAM gate for ``RequestAuthView``, shallow health metadata, and release grants."""

    def __init__(self, store_id: str, writer_epoch: int, instance_id: str) -> None:
        self._identity = Identity(
            store_id=store_id,
            writer_epoch=writer_epoch,
            instance_id=instance_id,
        )
        self._lock = threading.Lock()
        self._view: RequestAuthView | None = None
        self._health_meta: ShallowHealthMeta | None = None
        self._installed_version = 0
        self._issued_version = 0
        self._closed = False
        self._cached_key_id: str | None = None
        self._cached_key_bytes: bytes | None = None
        self._credential_bindings: dict[str, CredentialCapabilityBinding] = {}

    @property
    def identity(self) -> Identity:
        return self._identity

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._closed

    def current(self) -> RequestAuthView | None:
        with self._lock:
            if self._closed or self._view is None:
                return None
            view = self._view
        if view.auth.store_id != self._identity.store_id:
            raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable")
        return view

    def current_with_health(self) -> tuple[RequestAuthView | None, ShallowHealthMeta | None, bool]:
        with self._lock:
            if self._closed:
                return (None, None, True)
            return (self._view, self._health_meta, False)

    def next_version(self) -> int:
        with self._lock:
            self._issued_version = max(self._issued_version, self._installed_version) + 1
            return self._issued_version

    def invalidate(self) -> None:
        with self._lock:
            self._view = None

    def clear(self) -> None:
        self.invalidate()

    def publish(
        self,
        snapshot: AuthSnapshot,
        *,
        active_request_key_id: str | None = None,
        active_request_key_bytes: bytes | None = None,
        health_meta: ShallowHealthMeta | None = None,
        version: int | None = None,
    ) -> RequestAuthView | None:
        if not isinstance(snapshot, AuthSnapshot):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        with self._lock:
            if self._closed:
                raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")
            key_id = active_request_key_id if active_request_key_id is not None else self._cached_key_id
            key_bytes = active_request_key_bytes if active_request_key_bytes is not None else self._cached_key_bytes
            if key_id is None or key_bytes is None:
                raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
            if version is None:
                self._issued_version = max(self._issued_version, self._installed_version) + 1
                ver = self._issued_version
            else:
                ver = version
        view = RequestAuthView(
            version=ver,
            auth=snapshot,
            active_request_key_id=key_id,
            active_request_key_bytes=key_bytes,
        )
        return self.publish_view(view, health_meta=health_meta)

    def publish_view(
        self,
        view: RequestAuthView,
        *,
        health_meta: ShallowHealthMeta | None = None,
    ) -> RequestAuthView:
        if not isinstance(view, RequestAuthView):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if view.auth.store_id != self._identity.store_id:
            with self._lock:
                self._view = None
                self._credential_bindings.clear()
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
        if health_meta is not None:
            if not isinstance(health_meta, ShallowHealthMeta):
                raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
            if health_meta.store_id != self._identity.store_id:
                with self._lock:
                    self._view = None
                    self._credential_bindings.clear()
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
            if (
                health_meta.writer_epoch != self._identity.writer_epoch
                or health_meta.instance_id != self._identity.instance_id
            ):
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
        with self._lock:
            if self._closed:
                raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")
            if view.version <= self._installed_version:
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
            self._view = view
            self._installed_version = view.version
            if view.version > self._issued_version:
                self._issued_version = view.version
            self._cached_key_id = view.active_request_key_id
            self._cached_key_bytes = view.active_request_key_bytes
            self._credential_bindings = update_credential_capability_bindings(
                self._credential_bindings, view.auth
            )
            if health_meta is not None:
                self._health_meta = health_meta
            return view

    def merge_runtime_capabilities(self, snap: AuthSnapshot) -> AuthSnapshot:
        """Overlay cached runtime credential capabilities onto a freshly loaded policy snapshot."""
        with self._lock:
            if self._closed or not self._credential_bindings:
                return snap
            bindings = dict(self._credential_bindings)
        return apply_credential_capability_bindings(snap, bindings)

    def install(self, view: RequestAuthView) -> RequestAuthView:
        return self.publish_view(view)

    def install_view(
        self,
        view: RequestAuthView,
        *,
        health_meta: ShallowHealthMeta | None = None,
    ) -> RequestAuthView | None:
        return self.publish_view(view, health_meta=health_meta)

    def rebind_writer_epoch(
        self,
        new_epoch: int,
        view: RequestAuthView,
        *,
        health_meta: ShallowHealthMeta,
    ) -> RequestAuthView:
        """Atomically advance the admitted writer epoch and publish the refreshed auth view."""
        if not isinstance(view, RequestAuthView) or not isinstance(health_meta, ShallowHealthMeta):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if view.auth.store_id != self._identity.store_id or health_meta.store_id != self._identity.store_id:
            with self._lock:
                self._view = None
                self._credential_bindings.clear()
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
        if health_meta.writer_epoch != new_epoch or health_meta.instance_id != self._identity.instance_id:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
        with self._lock:
            if self._closed:
                raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")
            if view.version <= self._installed_version:
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
            self._identity = replace(self._identity, writer_epoch=new_epoch)
            self._view = view
            self._installed_version = view.version
            if view.version > self._issued_version:
                self._issued_version = view.version
            self._cached_key_id = view.active_request_key_id
            self._cached_key_bytes = view.active_request_key_bytes
            self._credential_bindings = update_credential_capability_bindings(
                self._credential_bindings, view.auth
            )
            self._health_meta = health_meta
            return view

    def update_clock_untrusted(self, untrusted: bool) -> None:
        if not isinstance(untrusted, bool):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        with self._lock:
            if not self._closed and self._health_meta is not None:
                if self._health_meta.idempotency_clock_untrusted != untrusted:
                    self._health_meta = replace(self._health_meta, idempotency_clock_untrusted=untrusted)

    def update_capture_gaps_present(self, present: bool) -> None:
        if not isinstance(present, bool):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        with self._lock:
            if not self._closed and self._health_meta is not None:
                if self._health_meta.capture_gaps_present != present:
                    self._health_meta = replace(self._health_meta, capture_gaps_present=present)

    def authorize_release(self, credential_id: str, generation: int) -> bool:
        if not isinstance(credential_id, str) or not is_strict_int(generation):
            return False
        with self._lock:
            if self._closed or self._view is None or self._view.version != generation:
                return False
            return self._view.auth.is_active_mcp_credential(credential_id)

    def authorize_stamp(self, stamp: AuthGrantStamp) -> bool:
        if not isinstance(stamp, AuthGrantStamp) or stamp.identity != self._identity:
            return False
        with self._lock:
            if self._closed or self._view is None:
                return False
            if self._view.version != stamp.generation or self._view.auth.trust_generation != stamp.trust_generation:
                return False
            return self._view.auth.is_active_mcp_credential(stamp.credential_id)

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._view = None
            self._health_meta = None
            self._credential_bindings.clear()


def evaluate_shallow_health(
    command: ToolCommand,
    deadline_ns: int,
    *,
    auth_gate: AuthGate,
    clock: Clock,
    monotonic_clock: MonotonicClock,
    loop_ready: bool,
) -> OwnerReply:
    """Evaluate shallow ``get_health`` completely in RAM without touching the owner queue or disk."""
    view, health_meta, closed = auth_gate.current_with_health()
    if closed:
        raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")
    if view is None or health_meta is None:
        raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable")

    credential_id, _ = parse_bearer_token(command.token)
    principal = view.auth.resolve_credential(command.token)
    call = normalize_call(
        "get_health",
        command.arguments,
        principal,
        selected_scope=command.selected_scope,
        correlation_id=command.correlation_id,
    )
    authorize_call_against_snapshot(view.auth, principal, call)
    if call.selected_scope is not None:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")

    if monotonic_clock.monotonic_ns() >= deadline_ns - HANDLER_RESERVE_NS:
        raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")

    now_utc, _ = require_aware_utc(clock.now())
    remaining = health_meta.tls_not_after - now_utc
    degraded_codes: list[JsonValue] = []
    if health_meta.idempotency_clock_untrusted:
        degraded_codes.append(IDEMPOTENCY_CLOCK_UNTRUSTED_CODE)
    if health_meta.capture_gaps_present:
        degraded_codes.append(CAPTURE_GAPS_PRESENT_CODE)
    if remaining <= timedelta(0):
        degraded_codes.append(TLS_EXPIRED_CODE)
    elif remaining <= TLS_EXPIRING_WINDOW:
        degraded_codes.append(TLS_EXPIRING_CODE)

    is_ready = loop_ready and (not health_meta.idempotency_clock_untrusted) and (remaining > timedelta(0))
    envelope = make_success_envelope(
        {
            "ready": is_ready,
            "store_id": health_meta.store_id,
            "writer_epoch": health_meta.writer_epoch,
            "schema_version": health_meta.schema_version,
            "policy_schema_version": health_meta.policy_schema_version,
            "degraded_codes": degraded_codes,
        }
    )
    encode_envelope(envelope)
    stamp = AuthGrantStamp(
        credential_id=credential_id,
        generation=view.version,
        trust_generation=view.auth.trust_generation,
        identity=auth_gate.identity,
    )
    return OwnerReply(envelope=envelope, grant_stamp=stamp, send_completion=None)
