"""Composition bridge binding admitted ``Store`` + ``PolicyStore`` to Task 4 typed dispatch & staging ports."""

from __future__ import annotations

import threading
from collections.abc import Callable
from datetime import datetime

from superbrain.application.dispatch import KernelDispatcher, KernelToolDomain
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    Call,
    CallContext,
    CallResult,
    Principal,
    PrivateRequestAuth,
    RequestAuthView,
    Scope,
    StagedBlob,
    StoredResult,
    require_positive_int,
)
from superbrain.ports.clock import Clock
from superbrain.ports.kernel import KernelBlobStagePort, RequestAuthStatePort
from superbrain.storage.idempotency import KernelBlobStager, KernelIdempotencyStore
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.store import Store


class AtomicRequestAuthState(RequestAuthStatePort):
    """In-process atomic RAM holder for ``RequestAuthView`` (short pointer swap only, zero I/O under lock)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._view: RequestAuthView | None = None
        self._version = 0

    def current(self) -> RequestAuthView | None:
        with self._lock:
            return self._view

    def install(self, view: RequestAuthView) -> RequestAuthView:
        with self._lock:
            self._view = view
            if view.version > self._version:
                self._version = view.version
            return view

    def next_version(self) -> int:
        with self._lock:
            self._version += 1
            return self._version

    def clear(self) -> None:
        with self._lock:
            self._view = None


class KernelBridge(KernelBlobStagePort):
    """Composition root wiring an admitted ``(Store, PolicyStore)`` pair to ``KernelDispatcher``."""

    def __init__(
        self,
        *,
        store: Store,
        policy: PolicyStore,
        clock: Clock,
        writer_epoch: int = 1,
        domain: KernelToolDomain | None = None,
        on_commit_completed: Callable[[StoredResult], None] | None = None,
    ) -> None:
        require_positive_int(writer_epoch)
        if store.store_id != policy.store_id:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
        self._store = store
        self._policy = policy
        self._clock = clock
        self._writer_epoch = writer_epoch
        self._blob_stager = KernelBlobStager(store)
        self._idempotency = KernelIdempotencyStore(store, policy, policy_view=policy)
        self._auth_state = AtomicRequestAuthState()
        self._dispatcher = KernelDispatcher(
            store_id=store.store_id,
            policy=policy,
            idempotency=self._idempotency,
            blob_stager=self._blob_stager,
            clock=clock,
            store_schema_version=lambda: self._store.schema_version,
            policy_schema_version=lambda: self._policy.schema_version,
            domain=domain,
            on_commit_completed=on_commit_completed,
        )

    @property
    def auth_state(self) -> RequestAuthStatePort:
        return self._auth_state

    def publish_auth_view(self) -> RequestAuthView:
        """Load snapshot + active request HMAC key on the owner thread and publish atomically into RAM (C3)."""
        try:
            snap = self._policy.snapshot()
            key_id, key_bytes = self._policy.request_digest_key()
            version = self._auth_state.next_version()
            view = RequestAuthView(
                version=version,
                auth=snap,
                active_request_key_id=key_id,
                active_request_key_bytes=key_bytes,
            )
        except BrainError:
            self._auth_state.clear()
            raise
        return self._auth_state.install(view)

    def clear_auth_view(self) -> None:
        self._auth_state.clear()

    def stage_blob(self, data: bytes) -> StagedBlob:
        return self._blob_stager.stage_blob(data)

    def dispatch(self, call: Call, ctx: CallContext, *, auth: PrivateRequestAuth) -> CallResult:
        return self._dispatcher.dispatch(call, ctx, auth=auth)

    def render_current(self, result: StoredResult, principal: Principal, *, selected_scope: Scope | None) -> JsonValue:
        return self._dispatcher.render_current(result, principal, selected_scope=selected_scope)

    def prune_expired(self, now: datetime, limit: int = 100) -> int:
        return self._idempotency.prune_expired(now, limit=limit)

    def clock_untrusted(self) -> bool:
        return self._idempotency.clock_untrusted()
