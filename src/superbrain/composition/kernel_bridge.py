"""Composition bridge binding admitted ``Store`` + ``PolicyStore`` to Task 4 typed dispatch & staging ports."""

from __future__ import annotations

import threading
from collections.abc import Callable, Sequence
from datetime import datetime

from superbrain.application.dispatch import KernelDispatcher, KernelToolDomain
from superbrain.application.idempotency import is_idempotency_expired
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
from superbrain.core.wire import encode_envelope, make_error_envelope
from superbrain.ports.clock import Clock
from superbrain.ports.kernel import KernelBlobStagePort, KernelStorePort, RequestAuthStatePort
from superbrain.storage._pair_admission import verify_admitted_store_pair
from superbrain.storage.idempotency import KernelBlobStager, KernelIdempotencyStore, StrictKernelStore
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.store import Store


def _verify_domain_pair(domain: KernelToolDomain | None, *, store: Store, policy: PolicyStore) -> None:
    if domain is None:
        return
    dom_store = getattr(domain, "store", None)
    if isinstance(dom_store, Store) and dom_store is not store:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
    dom_policy = getattr(domain, "policy", None)
    if isinstance(dom_policy, PolicyStore) and dom_policy is not policy:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")


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
        verify_admitted_store_pair(store, policy, writer_epoch=writer_epoch)
        _verify_domain_pair(domain, store=store, policy=policy)
        self._store = store
        self._policy = policy
        self._clock = clock
        self._writer_epoch = writer_epoch
        self._domain = domain
        self._blob_stager = KernelBlobStager(store)
        self._idempotency = KernelIdempotencyStore(
            store,
            policy,
            policy_view=policy,
            writer_epoch=writer_epoch,
            is_expired=is_idempotency_expired,
        )
        self._auth_state = AtomicRequestAuthState()
        self._dispatcher = KernelDispatcher(
            store_id=store.store_id,
            policy=policy,
            idempotency=self._idempotency,
            blob_stager=self._blob_stager,
            clock=clock,
            store_schema_version=self._read_store_schema_version,
            policy_schema_version=self._read_policy_schema_version,
            domain=domain,
            on_commit_completed=on_commit_completed,
        )

    def _check_live_pair(self) -> None:
        verify_admitted_store_pair(self._store, self._policy, writer_epoch=self._writer_epoch)
        _verify_domain_pair(self._domain, store=self._store, policy=self._policy)

    def _read_store_schema_version(self) -> int:
        self._check_live_pair()
        return self._store.schema_version

    def _read_policy_schema_version(self) -> int:
        self._check_live_pair()
        return self._policy.schema_version

    @property
    def auth_state(self) -> RequestAuthStatePort:
        return self._auth_state

    def publish_auth_view(self) -> RequestAuthView:
        """Load snapshot + active request HMAC key on the owner thread and publish atomically into RAM (C3)."""
        try:
            self._check_live_pair()
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

    def strict_store(self, staged_blobs: Sequence[StagedBlob] = ()) -> KernelStorePort:
        """Return an admitted ``KernelStorePort`` bound to pre-staged ``staged_blobs`` (C2:81)."""
        self._check_live_pair()
        return StrictKernelStore(
            self._store,
            self._policy,
            staged_blobs=staged_blobs,
            policy_store=self._policy,
            writer_epoch=self._writer_epoch,
        )

    def stage_blob(self, data: bytes) -> StagedBlob:
        self._check_live_pair()
        return self._blob_stager.stage_blob(data)

    def dispatch(self, call: Call, ctx: CallContext, *, auth: PrivateRequestAuth) -> CallResult:
        try:
            self._check_live_pair()
        except BrainError as err:
            err_envelope = make_error_envelope(err)
            encode_envelope(err_envelope)
            return err_envelope
        return self._dispatcher.dispatch(call, ctx, auth=auth)

    def render_current(self, result: StoredResult, principal: Principal, *, selected_scope: Scope | None) -> JsonValue:
        self._check_live_pair()
        return self._dispatcher.render_current(result, principal, selected_scope=selected_scope)

    def prune_expired(self, now: datetime, limit: int = 100) -> int:
        self._check_live_pair()
        return self._idempotency.prune_expired(now, limit=limit)

    def clock_untrusted(self) -> bool:
        return self._idempotency.clock_untrusted()
