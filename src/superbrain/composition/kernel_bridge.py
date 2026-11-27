"""Composition bridge binding admitted ``Store`` + ``PolicyStore`` to Task 4a/4b dispatch, staging & deadlines."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from typing import Protocol, TypeVar, cast

from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.clock import SystemMonotonicClock
from superbrain.application.capture_ingest import CaptureBatchAck, CaptureIngestService
from superbrain.application.deadlines import (
    DEFAULT_MAX_QUEUE_DEPTH,
    AtomicRequestAuthState,
    KernelDeadlineCoordinator,
    Reservation,
    ReservationTable,
    SubmittedKernelRequest,
)
from superbrain.application.dispatch import KernelDispatcher, KernelToolDomain
from superbrain.application.idempotency import is_idempotency_expired
from superbrain.application.privacy import PrivacyFilter
from superbrain.composition._layer2_live import make_live_layer2_lookup
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    ArtifactSendAttempt,
    AuthGrantStamp,
    AuthSnapshot,
    BootstrapAuthorization,
    Call,
    CallContext,
    CallResult,
    CaptureBatchCommand,
    Identity,
    Principal,
    PrivateRequestAuth,
    RequestAuthView,
    Scope,
    SendAttemptCompletion,
    StagedBlob,
    StoredResult,
    WorkspaceBinding,
    WorkspaceRegistration,
    require_opaque_id,
    require_positive_int,
)
from superbrain.core.wire import encode_envelope, make_error_envelope
from superbrain.ports.clock import Clock, MonotonicClock
from superbrain.ports.kernel import KernelBlobStagePort, KernelStorePort, RequestAuthStatePort
from superbrain.ports.os import OsAdapters
from superbrain.ports.policy import Intent, IntentKind
from superbrain.storage._pair_admission import verify_admitted_store_pair
from superbrain.storage.capture_events import KernelCaptureStore
from superbrain.storage.idempotency import KernelBlobStager, KernelIdempotencyStore, StrictKernelStore
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.send_attempts import KernelSendAttemptStore
from superbrain.storage.sessions import capture_continuity_hooks
from superbrain.storage.store import Store

_T = TypeVar("_T")

__all__ = ["AtomicRequestAuthState", "KernelBridge"]


class _CallableMonotonicClock:
    def __init__(self, fn: Callable[[], int]) -> None:
        self._fn = fn

    def monotonic_ns(self) -> int:
        return self._fn()


class _MutableRequestAuthState(RequestAuthStatePort, Protocol):
    def install(self, view: RequestAuthView) -> RequestAuthView: ...

    def next_version(self) -> int: ...

    def clear(self) -> None: ...

    def merge_runtime_capabilities(self, snap: AuthSnapshot) -> AuthSnapshot: ...


def _encoded_error(err: BrainError) -> CallResult:
    envelope = make_error_envelope(err)
    encode_envelope(envelope)
    return envelope


def _verify_domain_pair(domain: KernelToolDomain | None, *, store: Store, policy: PolicyStore) -> None:
    if domain is None:
        return
    dom_store = getattr(domain, "store", None)
    if isinstance(dom_store, Store) and dom_store is not store:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
    dom_policy = getattr(domain, "policy", None)
    if isinstance(dom_policy, PolicyStore) and dom_policy is not policy:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")


class KernelBridge(KernelBlobStagePort):
    """Composition root wiring an admitted ``(Store, PolicyStore)`` pair to ``KernelDispatcher`` and ``4b`` arbiter."""

    def __init__(
        self,
        *,
        store: Store,
        policy: PolicyStore,
        clock: Clock,
        monotonic_clock: MonotonicClock | None = None,
        writer_epoch: int = 1,
        instance_id: str | None = None,
        max_queue_size: int = DEFAULT_MAX_QUEUE_DEPTH,
        domain: KernelToolDomain | None = None,
        before_enter_commit: Callable[[Reservation | None], None] | None = None,
        on_commit_completed: Callable[[StoredResult], None] | None = None,
        recover_pending_on_init: bool = True,
        auth_state: _MutableRequestAuthState | None = None,
        before_auth_gate_publish: Callable[[RequestAuthView], None] | None = None,
        after_reserve_before_enqueue: Callable[[Reservation], None] | None = None,
        on_reservation_change: Callable[[], None] | None = None,
        on_queue_wake: Callable[[], None] | None = None,
        on_owner_reply_ready: Callable[[Reservation, AuthGrantStamp | None, SendAttemptCompletion | None], None]
        | None = None,
        on_owner_finished: Callable[[Reservation, bool], None] | None = None,
        on_clock_untrusted_changed: Callable[[bool], None] | None = None,
        on_capture_gaps_changed: Callable[[bool], None] | None = None,
        os_: OsAdapters | None = None,
        host_version_resolver: Callable[[str], str | None] | None = None,
        seen_configured_layer2: set[tuple[str, str]] | None = None,
    ) -> None:
        if not isinstance(recover_pending_on_init, bool):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        require_positive_int(writer_epoch)
        require_positive_int(max_queue_size)
        resolved_instance_id = new_id() if instance_id is None else instance_id
        require_opaque_id(resolved_instance_id, label="instance_id")
        verify_admitted_store_pair(store, policy, writer_epoch=writer_epoch)
        _verify_domain_pair(domain, store=store, policy=policy)

        dom_mono = getattr(domain, "monotonic_ns", None) if domain is not None else None
        if monotonic_clock is not None:
            resolved_mono: MonotonicClock = monotonic_clock
            enforce_unreserved = True
        elif callable(dom_mono):
            resolved_mono = _CallableMonotonicClock(cast(Callable[[], int], dom_mono))
            enforce_unreserved = True
        else:
            resolved_mono = SystemMonotonicClock()
            enforce_unreserved = False

        self._clock = clock
        self._monotonic_clock = resolved_mono
        self._instance_id = resolved_instance_id
        self._enforce_unreserved = enforce_unreserved
        self._domain = domain
        self._before_enter_commit = before_enter_commit
        self._on_commit_completed = on_commit_completed
        self._auth_state: _MutableRequestAuthState = (
            auth_state if auth_state is not None else AtomicRequestAuthState(store.store_id)
        )
        self._before_auth_gate_publish = before_auth_gate_publish
        self._on_owner_reply_ready = on_owner_reply_ready
        self._on_clock_untrusted_changed = on_clock_untrusted_changed
        self._on_capture_gaps_changed = on_capture_gaps_changed
        self._os = os_ if os_ is not None else os_adapters(clock=clock, monotonic=resolved_mono)
        if host_version_resolver is None:
            from superbrain.adapters.harness.host_version import probe_installed_host_version

            self._host_version_resolver: Callable[[str], str | None] = probe_installed_host_version
        else:
            self._host_version_resolver = host_version_resolver
        self._seen_l2: set[tuple[str, str]] = set() if seen_configured_layer2 is None else seen_configured_layer2
        self.on_continuity_tasks: Callable[[tuple[str, ...]], None] | None = None  # owner thread
        self._wire_stores(store, policy, writer_epoch)
        if recover_pending_on_init:
            self._send_attempts.recover_pending_attempts()
        reservations_table = ReservationTable(on_change=on_reservation_change)
        self._coordinator = KernelDeadlineCoordinator(
            store_id=store.store_id,
            writer_epoch=writer_epoch,
            instance_id=resolved_instance_id,
            auth_state=self._auth_state,
            monotonic_clock=resolved_mono,
            owner_runner=self._run_reserved_on_owner,
            max_queue_size=max_queue_size,
            reservations=reservations_table,
            on_unsent_owner_response=self._interrupt_unsent_response,
            after_reserve_before_enqueue=after_reserve_before_enqueue,
            on_queue_wake=on_queue_wake,
            on_owner_finished=on_owner_finished,
        )

    def _wire_stores(self, store: Store, policy: PolicyStore, writer_epoch: int) -> None:
        self._store = store
        self._policy = policy
        self._writer_epoch = writer_epoch
        self._owner_identity = Identity(
            store_id=store.store_id, writer_epoch=writer_epoch, instance_id=self._instance_id
        )
        self._blob_stager = KernelBlobStager(store)
        self._idempotency = KernelIdempotencyStore(
            store, policy, policy_view=policy, writer_epoch=writer_epoch, is_expired=is_idempotency_expired
        )
        self._send_attempts = KernelSendAttemptStore(store, policy, writer_epoch=writer_epoch)
        self._capture_store = KernelCaptureStore(store)
        self._capture_ingest = CaptureIngestService(
            capture_store=self._capture_store,
            privacy_filter=PrivacyFilter(monotonic_ns=self._monotonic_clock.monotonic_ns),
            clock=self._clock,
            monotonic_ns=self._monotonic_clock.monotonic_ns,
        )
        self._dispatcher = KernelDispatcher(
            store_id=store.store_id,
            policy=policy,
            idempotency=self._idempotency,
            blob_stager=self._blob_stager,
            clock=self._clock,
            monotonic_clock=self._monotonic_clock,
            enforce_unreserved_deadline=self._enforce_unreserved,
            store_schema_version=self._read_store_schema_version,
            policy_schema_version=self._read_policy_schema_version,
            domain=self._domain,
            send_attempts=self._send_attempts,
            before_enter_commit=self._before_enter_commit,
            on_commit_completed=self._on_commit_completed,
            has_capture_gaps=self.capture_gaps_present,
            effective_snapshot=self._effective_policy_snapshot,
        )

    def _effective_policy_snapshot(self) -> AuthSnapshot:
        return self._auth_state.merge_runtime_capabilities(self._policy.snapshot())

    def rebind_stores(self, *, store: Store, policy: PolicyStore, writer_epoch: int) -> None:
        """Rebind the bridge to reopened ``Store`` / ``PolicyStore`` handles after an online restore."""
        require_positive_int(writer_epoch)
        verify_admitted_store_pair(store, policy, writer_epoch=writer_epoch)
        _verify_domain_pair(self._domain, store=store, policy=policy)
        self._seen_l2.clear()
        self._wire_stores(store, policy, writer_epoch)
        self._coordinator.rebind_writer_epoch(writer_epoch)

    def _check_live_pair(self) -> None:
        verify_admitted_store_pair(self._store, self._policy, writer_epoch=self._writer_epoch)
        _verify_domain_pair(self._domain, store=self._store, policy=self._policy)

    def _read_store_schema_version(self) -> int:
        self._check_live_pair()
        return self._store.schema_version

    def _read_policy_schema_version(self) -> int:
        self._check_live_pair()
        return self._policy.schema_version

    def _run_reserved_on_owner(
        self, call: Call, ctx: CallContext, auth: PrivateRequestAuth, reservation: Reservation
    ) -> CallResult:
        try:
            self._check_live_pair()
        except BrainError as err:
            if err.code in (ErrorCode.IDENTITY_MISMATCH, ErrorCode.POLICY_UNAVAILABLE, ErrorCode.INTEGRITY_FAILURE):
                self._auth_state.clear()
            return _encoded_error(err)
        result = self._dispatcher.dispatch_reserved(
            call, ctx, auth=auth, reservation=reservation, enforce_effective=True
        )
        if self._on_clock_untrusted_changed is not None:
            self._on_clock_untrusted_changed(self._idempotency.clock_untrusted())
        if result.get("ok") is False:
            err_obj = result.get("error")
            err_code = err_obj.get("code") if isinstance(err_obj, Mapping) else None
            if err_code in (ErrorCode.IDENTITY_MISMATCH.value, ErrorCode.POLICY_UNAVAILABLE.value):
                self._auth_state.clear()
            elif err_code == ErrorCode.UNAUTHENTICATED.value:
                self._clear_auth_if_diverged(auth.credential_id)
            return result
        if self._on_owner_reply_ready is not None:
            stamp = self._mint_owner_grant_stamp(auth.credential_id)
            completion: SendAttemptCompletion | None = None
            data = result.get("data")
            if isinstance(data, Mapping):
                receipt_id = data.get("served_receipt_id")
                if isinstance(receipt_id, str):
                    completion = self.build_send_completion(receipt_id)
            self._on_owner_reply_ready(reservation, stamp, completion)
        return result

    def _verified_auth_view(self) -> RequestAuthView | None:
        try:
            view = self._auth_state.current()
            if view is None:
                return None
            live_snap = self._policy.snapshot()
        except BrainError:
            self._auth_state.clear()
            return None
        if not view.auth.matches_persisted_policy(live_snap):
            self._auth_state.clear()
            return None
        return view

    def _clear_auth_if_diverged(self, credential_id: str) -> None:
        try:
            view = self._auth_state.current()
        except BrainError:
            self._auth_state.clear()
            return
        if view is None:
            return
        if view.auth.is_active_mcp_credential(credential_id):
            self._auth_state.clear()
            return
        self._verified_auth_view()

    def _mint_owner_grant_stamp(self, credential_id: str) -> AuthGrantStamp | None:
        view = self._verified_auth_view()
        if view is None or not view.auth.is_active_mcp_credential(credential_id):
            return None
        return AuthGrantStamp(
            credential_id=credential_id,
            generation=view.version,
            trust_generation=view.auth.trust_generation,
            identity=self._owner_identity,
        )

    @property
    def auth_state(self) -> RequestAuthStatePort:
        return self._auth_state

    @property
    def reservations(self) -> ReservationTable:
        return self._coordinator.reservations

    def queue_depth(self) -> int:
        return self._coordinator.queue_depth()

    def publish_auth_view(self) -> RequestAuthView:
        """Load snapshot + active request HMAC key on the owner thread and publish atomically into RAM (C3)."""
        try:
            self._check_live_pair()
            snap = self._auth_state.merge_runtime_capabilities(self._policy.snapshot())
            key_id, key_bytes = self._policy.request_digest_key()
            version = self._auth_state.next_version()
            view = RequestAuthView(
                version=version,
                auth=snap,
                active_request_key_id=key_id,
                active_request_key_bytes=key_bytes,
            )
            if self._before_auth_gate_publish is not None:
                self._before_auth_gate_publish(view)
            return self._auth_state.install(view)
        except BrainError:
            self._auth_state.clear()
            raise

    def clear_auth_view(self) -> None:
        self._auth_state.clear()

    def apply_policy_mutation(self, mutation: Callable[[PolicyStore], _T]) -> _T:
        """Run an owner ``PolicyStore`` mutation and install the updated ``RequestAuthView`` before return."""
        self._check_live_pair()
        self._auth_state.clear()
        result = mutation(self._policy)
        self.publish_auth_view()
        return result

    def revoke_credential(self, credential_id: str, authorization: BootstrapAuthorization) -> Intent:
        """Revoke ``credential_id`` on the owner thread and publish the updated ``RequestAuthView`` before return."""
        return self.apply_policy_mutation(lambda pol: pol.record_authorized_revocation(credential_id, authorization))

    def register_workspace(
        self, registration: WorkspaceRegistration, authorization: BootstrapAuthorization
    ) -> WorkspaceBinding:
        """Register ``registration`` on the owner thread, reconcile policy, and publish ``RequestAuthView``."""
        self._check_live_pair()
        self._auth_state.clear()
        binding = self._policy.register_authorized_workspace(registration, authorization)
        self._store.reconcile_policy()
        self.publish_auth_view()
        return binding

    def record_policy_intent(self, kind: IntentKind, payload: Mapping[str, JsonValue]) -> Intent:
        """Record a policy intent on the owner thread and publish ``RequestAuthView`` before return."""
        return self.apply_policy_mutation(lambda pol: pol.record_intent(kind, payload))

    def submit_request(
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
        return self._coordinator.submit(
            tool,
            arguments,
            token=token,
            selected_scope=selected_scope,
            expected_principal=expected_principal,
            correlation_id=correlation_id,
            receive_ns=receive_ns,
            on_response=on_response,
            on_reserved=on_reserved,
        )

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
        return self._coordinator.call_tool(
            tool,
            arguments,
            token=token,
            selected_scope=selected_scope,
            expected_principal=expected_principal,
            correlation_id=correlation_id,
            receive_ns=receive_ns,
            timeout=timeout,
        )

    def arbitrate_deadlines(self, now_ns: int | None = None) -> tuple[tuple[Reservation, CallResult], ...]:
        return self._coordinator.arbitrate(now_ns)

    def next_deadline_ns(self) -> int | None:
        return self._coordinator.next_deadline_ns()

    def process_next_queued(self, *, block: bool = False, timeout: float | None = None) -> bool:
        return self._coordinator.process_next(block=block, timeout=timeout)

    def close_admissions(self) -> None:
        self._coordinator.close_admissions()

    def prepare_cancel_uncommitted_for_shutdown(self) -> tuple[int, tuple[Callable[[], None], ...]]:
        return self._coordinator.prepare_cancel_uncommitted_for_shutdown()

    def cancel_uncommitted_for_shutdown(self) -> int:
        return self._coordinator.cancel_uncommitted_for_shutdown()

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
            return _encoded_error(err)
        result = self._dispatcher.dispatch(call, ctx, auth=auth, enforce_effective=True)
        if result.get("ok") is False:
            err_obj = result.get("error")
            err_code = err_obj.get("code") if isinstance(err_obj, Mapping) else None
            if err_code == ErrorCode.UNAUTHENTICATED.value:
                self._clear_auth_if_diverged(auth.credential_id)
        return result

    def render_current(self, result: StoredResult, principal: Principal, *, selected_scope: Scope | None) -> JsonValue:
        self._check_live_pair()
        return self._dispatcher.render_current(result, principal, selected_scope=selected_scope)

    def prune_expired(self, now: datetime, limit: int = 100) -> int:
        self._check_live_pair()
        return self._idempotency.prune_expired(now, limit=limit)

    def clock_untrusted(self) -> bool:
        return self._idempotency.clock_untrusted()

    def _interrupt_unsent_response(self, response: CallResult) -> None:
        if response.get("ok") is not True:
            return
        data = response.get("data")
        if not isinstance(data, Mapping):
            return
        receipt_id = data.get("served_receipt_id")
        if not isinstance(receipt_id, str):
            return
        try:
            self._send_attempts.interrupt_attempt(receipt_id)
        except BrainError:
            return

    @property
    def owner_identity(self) -> Identity:
        return self._owner_identity

    def read_send_attempt(self, send_attempt_id: str) -> ArtifactSendAttempt | None:
        self._check_live_pair()
        return self._send_attempts.read_attempt(send_attempt_id)

    def build_send_completion(self, send_attempt_id: str) -> SendAttemptCompletion:
        self._check_live_pair()
        attempt = self._send_attempts.read_attempt(send_attempt_id)
        if attempt is None:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        return SendAttemptCompletion(
            send_attempt_id=attempt.send_attempt_id, logical_result_id=attempt.logical_result_id,
            principal_id=attempt.principal_id, task_id=attempt.task_id, artifact_id=attempt.artifact_id,
            revision=attempt.revision, resource_digests=attempt.resource_digests,
            identity=self._owner_identity, level=attempt.level, revision_epoch=attempt.revision_epoch,
        )

    def finalize_send_attempt(self, completion: SendAttemptCompletion) -> ArtifactSendAttempt:
        self._check_live_pair()
        return self._send_attempts.finalize_attempt(completion, expected_identity=self._owner_identity)

    def interrupt_send_attempt(self, send_attempt_id: str) -> ArtifactSendAttempt:
        self._check_live_pair()
        return self._send_attempts.interrupt_attempt(send_attempt_id)

    def recover_pending_send_attempts(self) -> int:
        self._check_live_pair()
        return self._send_attempts.recover_pending_attempts()

    def capture_gaps_present(self) -> bool:
        self._check_live_pair()
        return self._capture_store.has_gaps()

    def ingest_capture_batch(self, command: CaptureBatchCommand, *, deadline_ns: int | None = None) -> CaptureBatchAck:
        """Authorize, privacy-filter, attribute, and commit one ``POST /v2/capture/events`` batch."""
        self._check_live_pair()
        if deadline_ns is not None and self._monotonic_clock.monotonic_ns() >= deadline_ns:
            raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")
        view = self._auth_state.current()
        if view is None:
            raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable")
        ram_p = view.auth.authorize_capture_producer(
            command.token,
            producer_stream=command.producer_stream,
            repo_id=command.repo_id,
            checkout_id=command.checkout_id,
        )
        try:
            live_p = self._policy.resolve_credential(command.token)
        except BrainError as err:
            if err.code is ErrorCode.UNAUTHENTICATED:
                self._verified_auth_view()
            raise
        if live_p != ram_p:
            raise BrainError(ErrorCode.IDENTITY_MISMATCH, "principal identity mismatch")
        snap = self._policy.snapshot()
        repo_pol = snap.repo_policies.get(command.repo_id)
        chk = snap.checkouts.get(command.checkout_id)
        if (
            repo_pol is None or chk is None or snap.principals.get(live_p.principal_id) != live_p
            or (live_p.principal_id, command.repo_id) not in snap.grants
            or repo_pol.owner_id != live_p.owner_id or chk.owner_id != live_p.owner_id
            or chk.repo_id != command.repo_id or chk.machine_id != live_p.machine_id
        ):
            raise BrainError(ErrorCode.IDENTITY_MISMATCH, "principal identity mismatch")
        try:
            bind_fn, link_fn, touched = capture_continuity_hooks(
                self._store, self._policy, principal_id=live_p.principal_id, repo_id=command.repo_id,
                checkout_id=command.checkout_id, now=self._clock.now(),
            ) if repo_pol.automatic_capture_enabled else (None, None, [])
            layer2_lookup = make_live_layer2_lookup(
                self._policy,
                events=command.events,
                harness_id=live_p.harness_id,
                repo_id=command.repo_id,
                checkout_id=command.checkout_id,
                os_=self._os,
                host_version_resolver=self._host_version_resolver,
                seen_configured=self._seen_l2,
            )
            ack = self._capture_ingest.ingest_batch(
                command, principal=live_p, repo_policy=repo_pol, layer2_lookup=layer2_lookup,
                deadline_ns=deadline_ns, before_commit=bind_fn, on_event_committed_in_tx=link_fn,
            )
            if touched and self.on_continuity_tasks is not None:
                self.on_continuity_tasks(tuple(touched))
            return ack
        finally:
            if self._on_capture_gaps_changed is not None:
                self._on_capture_gaps_changed(self._capture_store.has_gaps())
