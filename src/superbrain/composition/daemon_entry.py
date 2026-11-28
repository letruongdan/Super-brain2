"""Composition entry point for the Increment 2 kernel daemon lifecycle (Task 6a)."""

from __future__ import annotations

import contextlib
import logging
import math
import threading
import time
from collections.abc import Callable, Mapping
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from superbrain.adapters.os import os_adapters
from superbrain.application.approvals import OperatorHandle
from superbrain.application.deadlines import Reservation
from superbrain.application.dispatch import KernelToolDomain
from superbrain.application.owner_loop import AuthGate, OwnerLoop, OwnerSession
from superbrain.application.review_apply import ReviewApplyService
from superbrain.composition._daemon_doctor import DaemonDoctorRunner
from superbrain.composition._daemon_session import (
    DaemonTestHooks,
    _AdmittedOwnerSession,
    _DaemonCompositeDomain,
    make_default_handoff_domain_factory,
)
from superbrain.composition._doctor_fix_wiring import DoctorFixHooks
from superbrain.composition._endpoint import (
    BoundLoopbackListener,
    bind_loopback_listener,
    build_server_ssl_context,
    publish_endpoint,
    remove_own_endpoint,
)
from superbrain.composition.kernel_projections import kernel_store_extensions
from superbrain.core._kernel_approval import canonical_utc
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.faults import crashpoint
from superbrain.core.ids import new_id
from superbrain.core.kernel import (
    DAEMON_QUEUE_DEPTH,
    DEFAULT_SHUTDOWN_GRACE_S,
    ENDPOINT_HOST,
    ENDPOINT_VERSION,
    AuthGrantStamp,
    DaemonConfig,
    Endpoint,
    Ready,
    RequestAuthView,
    SendAttemptCompletion,
    ShallowHealthMeta,
    ShutdownState,
    require_aware_utc,
)
from superbrain.ports.clock import Clock, MonotonicClock
from superbrain.ports.doctor import CaptureDoctorProbePort, OutboxReplayPort, SupervisorControlPort
from superbrain.ports.os import OsAdapters
from superbrain.workers.executor import PRODUCTION_JOB_HANDLERS, JobExecutor, JobHandler

if TYPE_CHECKING:
    from superbrain.cli_api._loopback_server import LoopbackServer
from superbrain.composition._daemon_serve_config import _signal_stop_guard as _signal_stop_guard
from superbrain.composition._daemon_serve_config import serve_config_path as serve_config_path

__all__ = [
    "BoundLoopbackListener",
    "DaemonTestHooks",
    "PRODUCTION_JOB_HANDLERS",
    "create_daemon_owner_loop",
    "publish_endpoint",
    "remove_own_endpoint",
    "serve",
    "serve_config_path",
]

_LOGGER = logging.getLogger(__name__)


def _check_tls_utc_window(clock: Clock, not_before: datetime, not_after: datetime) -> None:
    try:
        now_utc, _ = require_aware_utc(clock.now())
    except BrainError as err:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input") from err
    if not (not_before <= now_utc < not_after):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")


def _open_owner_session(
    config: DaemonConfig,
    owner_wake: Callable[[], None],
    arbiter_wake: Callable[[], None],
    *,
    os_: OsAdapters | None,
    clock: Clock | None,
    monotonic_clock: MonotonicClock | None,
    domain: KernelToolDomain | None,
    job_handlers: Mapping[str, JobHandler] | None,
    hooks: DaemonTestHooks,
    on_listener_bound: Callable[[BoundLoopbackListener], None] | None,
    operator: OperatorHandle | None = None,
    doctor_fix_hooks: DoctorFixHooks | None = None,
) -> _AdmittedOwnerSession:
    from superbrain.adapters.os.tls_material import verify_server_tls_files
    from superbrain.application.continuity_worker import sweep_legacy_continuity_copies
    from superbrain.application.jobs import JobService
    from superbrain.application.journal_recovery import reconcile_and_classify_journals
    from superbrain.composition._daemon_restore import (
        DaemonRestoreHandler,
        LazyConfigMerger,
        build_review_apply_service,
    )
    from superbrain.composition.kernel_bridge import KernelBridge
    from superbrain.composition.operator_entry import build_operator_service
    from superbrain.storage.capture_events import KernelCaptureStore
    from superbrain.storage.idempotency import StagedKernelStore
    from superbrain.storage.jobs import has_legacy_incomplete_settled_projections
    from superbrain.storage.proposals import PolicyApplyAuthority, StoreProposalAdapter
    from superbrain.storage.runtime import admit_existing_pair, open_runtime_under_lease
    from superbrain.storage.sessions import SessionStore

    adapters = os_ if os_ is not None else os_adapters(clock=clock, monotonic=monotonic_clock)
    resolved_clock = clock if clock is not None else adapters.clock
    resolved_mono = monotonic_clock if monotonic_clock is not None else adapters.monotonic
    resolved_handlers = PRODUCTION_JOB_HANDLERS if job_handlers is None else job_handlers

    try:
        require_aware_utc(resolved_clock.now())
    except BrainError as err:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input") from err
    verified_tls = verify_server_tls_files(config, resolved_clock, adapters)
    ssl_ctx = build_server_ssl_context(config)
    if hooks.after_tls_verify is not None:
        hooks.after_tls_verify()

    admitted = admit_existing_pair(config.data_root, config.expected_store_id, adapters, purpose="serve")
    proj_handlers, proj_kinds = kernel_store_extensions()
    rt = open_runtime_under_lease(admitted, handlers=proj_handlers, kinds=proj_kinds)

    listener: BoundLoopbackListener | None = None
    endpoint: Endpoint | None = None
    executor: JobExecutor | None = None
    auth_gate: AuthGate | None = None
    doctor_runner: DaemonDoctorRunner | None = None
    try:
        if hooks.after_open_before_rebuild is not None:
            hooks.after_open_before_rebuild(rt)
        if has_legacy_incomplete_settled_projections(rt.store, rt.lease):
            rt.store.rebuild_projections()
            if has_legacy_incomplete_settled_projections(rt.store, rt.lease):
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")

        if resolved_handlers:
            executor = JobExecutor(resolved_handlers, resolved_mono.monotonic_ns, on_command=owner_wake)
        job_store = StagedKernelStore(rt.store, rt.policy, writer_epoch=rt.lease.epoch)
        job_service = JobService(
            job_store,
            job_store,
            rt.policy,
            resolved_clock,
            writer_epoch=rt.lease.epoch,
            accounting=rt.policy if rt.policy.schema_version >= 4 else None,
            cancel_signal=executor.cancel if executor is not None else None,
        )

        if hooks.before_job_recover is not None:
            hooks.before_job_recover(rt)
        if rt.store.schema_version >= 7 and rt.policy.schema_version >= 5:
            sweep_legacy_continuity_copies(job_service, SessionStore(rt.store, rt.policy))
        job_service.recover(rt.lease.epoch)
        if rt.store.schema_version >= 5 and rt.policy.schema_version >= 4:
            reconcile_and_classify_journals(
                StoreProposalAdapter(rt.store, adapters),
                PolicyApplyAuthority(rt.policy),
                adapters,
                data_root=rt.root.root,
                home_dir=Path.home(),
                config_merger=LazyConfigMerger(),
                now_utc_fn=lambda: canonical_utc(resolved_clock.now()),
            )

        instance_id = new_id()
        auth_gate = AuthGate(rt.store.store_id, rt.lease.epoch, instance_id)
        reply_meta_lock = threading.Lock()
        reply_meta: dict[str, tuple[AuthGrantStamp | None, SendAttemptCompletion | None]] = {}

        session_box: list[_AdmittedOwnerSession] = []

        def _on_reply_ready(
            res: Reservation,
            stamp: AuthGrantStamp | None,
            completion: SendAttemptCompletion | None,
        ) -> None:
            with reply_meta_lock:
                reply_meta[res.reservation_id] = (stamp, completion)

        def _on_owner_finished(res: Reservation, won: bool) -> None:
            if not won:
                with reply_meta_lock:
                    reply_meta.pop(res.reservation_id, None)
            elif session_box:
                session_box[0].record_request_drained()

        from superbrain.adapters.harness.host_version import probe_installed_host_version
        from superbrain.composition._layer2_live import Layer2ApplyTracker, reconcile_live_layer2_all

        seen_configured_layer2: set[tuple[str, str]] = set()
        l2_apply = Layer2ApplyTracker()  # one per daemon: capture, approval checks and restore share it
        resolved_hv_resolver = (
            hooks.host_version_resolver if hooks.host_version_resolver is not None else probe_installed_host_version
        )
        composite_domain = _DaemonCompositeDomain(
            job_service, domain,
            fallback_factory=(
                make_default_handoff_domain_factory(
                    rt=rt, clock=resolved_clock, writer_epoch=rt.lease.epoch,
                ) if domain is None else None
            ),
        )
        bridge = KernelBridge(
            store=rt.store, policy=rt.policy, clock=resolved_clock, monotonic_clock=resolved_mono,
            writer_epoch=rt.lease.epoch, instance_id=instance_id, max_queue_size=DAEMON_QUEUE_DEPTH,
            domain=composite_domain, before_enter_commit=hooks.before_enter_commit, recover_pending_on_init=False,
            auth_state=auth_gate, before_auth_gate_publish=hooks.before_auth_gate_publish,
            after_reserve_before_enqueue=hooks.after_reserve_before_enqueue, on_reservation_change=arbiter_wake,
            on_queue_wake=owner_wake, on_owner_reply_ready=_on_reply_ready, on_owner_finished=_on_owner_finished,
            on_clock_untrusted_changed=auth_gate.update_clock_untrusted,
            on_capture_gaps_changed=auth_gate.update_capture_gaps_present, os_=adapters,
            host_version_resolver=resolved_hv_resolver, seen_configured_layer2=seen_configured_layer2,
            layer2_apply=l2_apply,
        )
        reconcile_live_layer2_all(
            rt.policy, store=rt.store, os_=adapters, host_version_resolver=resolved_hv_resolver,
            seen_configured=seen_configured_layer2, apply_tracker=l2_apply,
        )
        bridge.recover_pending_send_attempts()

        snap = rt.policy.snapshot()
        has_active_cred = any(
            not cred.revoked and snap.principals.get(cred.principal.principal_id) == cred.principal
            for cred in snap.credentials.values()
        )
        if not has_active_cred:
            raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable")
        key_id, key_bytes = rt.policy.request_digest_key()
        health_meta = ShallowHealthMeta(
            store_id=rt.store.store_id,
            writer_epoch=rt.lease.epoch,
            instance_id=instance_id,
            schema_version=rt.store.schema_version,
            policy_schema_version=rt.policy.schema_version,
            tls_not_after=verified_tls.not_after,
            idempotency_clock_untrusted=bridge.clock_untrusted(),
            capture_gaps_present=KernelCaptureStore(rt.store).has_gaps() if rt.store.schema_version >= 6 else False,
        )
        initial_view = RequestAuthView(
            version=auth_gate.next_version(),
            auth=snap,
            active_request_key_id=key_id,
            active_request_key_bytes=key_bytes,
        )
        if hooks.before_auth_gate_publish is not None:
            hooks.before_auth_gate_publish(initial_view)
        auth_gate.publish_view(initial_view, health_meta=health_meta)

        if hooks.before_bind is not None:
            hooks.before_bind(rt)
        _check_tls_utc_window(resolved_clock, verified_tls.not_before, verified_tls.not_after)

        listener = bind_loopback_listener(ssl_ctx)
        if on_listener_bound is not None:
            on_listener_bound(listener)
        crashpoint("daemon.after_bind_before_endpoint")

        candidate_endpoint = Endpoint(
            version=ENDPOINT_VERSION,
            host=ENDPOINT_HOST,
            port=listener.port,
            store_id=rt.store.store_id,
            writer_epoch=rt.lease.epoch,
            instance_id=instance_id,
        )
        if hooks.before_endpoint_publish is not None:
            hooks.before_endpoint_publish(candidate_endpoint)
        _check_tls_utc_window(resolved_clock, verified_tls.not_before, verified_tls.not_after)
        endpoint = candidate_endpoint
        publish_endpoint(rt.root, rt.lease, endpoint, adapters)
        crashpoint("daemon.after_endpoint_publish")

        if hooks.after_endpoint_publish_before_final_tls_check is not None:
            hooks.after_endpoint_publish_before_final_tls_check(endpoint)
        _check_tls_utc_window(resolved_clock, verified_tls.not_before, verified_tls.not_after)

        if executor is not None:
            executor.start()

        from superbrain.composition.doctor_probes_sp2_store import run_sp2_doctor_probes

        doctor_runner = DaemonDoctorRunner(
            rt=rt,
            job_store=job_store,
            job_service=job_service,
            adapters=adapters,
            clock=resolved_clock,
            tls_not_after=verified_tls.not_after,
            clock_untrusted_fn=bridge.clock_untrusted,
            prune_idempotency_fn=bridge.prune_expired,
            wake_owner=owner_wake,
            claim_guard=lambda: not session_box or session_box[0].doctor_claim_guard(),
            fix_hooks=doctor_fix_hooks,
            host_version_resolver=resolved_hv_resolver,
            sp2_probe=lambda data_root, checkout: run_sp2_doctor_probes(
                data_root, checkout_root=checkout, host_version_resolver=resolved_hv_resolver, os_=adapters
            ),
        )
        composite_domain.bind_doctor_runner(doctor_runner)

        ready = Ready(
            endpoint=endpoint,
            identity=endpoint.identity,
            tls_not_after=verified_tls.not_after,
            leaf_cert_sha256=verified_tls.leaf_cert_sha256,
        )
        session = _AdmittedOwnerSession(
            rt=rt,
            ready=ready,
            auth_gate=auth_gate,
            bridge=bridge,
            job_store=job_store,
            job_service=job_service,
            executor=executor,
            listener=listener,
            clock=resolved_clock,
            monotonic_clock=resolved_mono,
            hooks=hooks,
            reply_meta_lock=reply_meta_lock,
            reply_meta=reply_meta,
            operator=operator,
            doctor_runner=doctor_runner,
        )
        session_box.append(session)
        owner_wake()
        if operator is not None:
            review_apply = build_review_apply_service(
                rt.store,
                rt.policy,
                rt.root.root,
                adapters,
                service_cls=ReviewApplyService,
            )
            restore_handler = DaemonRestoreHandler(
                session=session, adapters=adapters, clock=resolved_clock, executor=executor,
                composite_domain=composite_domain, instance_id=instance_id, operator=operator,
                review_apply_cls=ReviewApplyService, seen_configured_layer2=seen_configured_layer2,
                layer2_apply=l2_apply,
                host_version_resolver=resolved_hv_resolver,
            )
            operator.bind(
                build_operator_service(
                    rt.policy,
                    os_=adapters,
                    review_apply=review_apply,
                    restore_handler=restore_handler,
                    doctor_handler=doctor_runner,
                    expected_endpoint_path=rt.root.endpoint_path,
                    expected_leaf_cert_sha256=verified_tls.leaf_cert_sha256,
                    server_cert_path=verified_tls.cert_path,
                    live_layer2_check=lambda: reconcile_live_layer2_all(
                        session.rt.policy, store=session.rt.store, os_=adapters,
                        host_version_resolver=resolved_hv_resolver, seen_configured=seen_configured_layer2,
                        apply_tracker=l2_apply,
                    ),
                )
            )
        return session
    except BaseException:
        if doctor_runner is not None:
            doctor_runner.close()
        if operator is not None:
            operator.unbind()
        if auth_gate is not None:
            auth_gate.close()
        if endpoint is not None:
            with contextlib.suppress(BrainError):
                remove_own_endpoint(rt.root, rt.lease, endpoint, adapters)
        if listener is not None:
            listener.close()
        if executor is not None:
            with contextlib.suppress(BrainError):
                executor.close(0.5)
        with contextlib.suppress(BrainError):
            rt.close()
        raise


def create_daemon_owner_loop(
    *,
    os_: OsAdapters | None = None,
    clock: Clock | None = None,
    monotonic_clock: MonotonicClock | None = None,
    domain: KernelToolDomain | None = None,
    job_handlers: Mapping[str, JobHandler] | None = None,
    hooks: DaemonTestHooks | None = None,
    on_listener_bound: Callable[[BoundLoopbackListener], None] | None = None,
    operator: OperatorHandle | None = None,
    doctor_fix_hooks: DoctorFixHooks | None = None,
) -> OwnerLoop:
    """Construct an ``OwnerLoop`` wired to real admission, recovery, bridge, worker, and listener ports."""
    resolved_hooks = hooks if hooks is not None else DaemonTestHooks()
    if not isinstance(resolved_hooks, DaemonTestHooks):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")

    def _factory(
        cfg: DaemonConfig,
        owner_wake: Callable[[], None],
        arbiter_wake: Callable[[], None],
    ) -> OwnerSession:
        return _open_owner_session(
            cfg,
            owner_wake,
            arbiter_wake,
            os_=os_,
            clock=clock,
            monotonic_clock=monotonic_clock,
            domain=domain,
            job_handlers=job_handlers,
            hooks=resolved_hooks,
            on_listener_bound=on_listener_bound,
            operator=operator,
            doctor_fix_hooks=doctor_fix_hooks,
        )

    return OwnerLoop(_factory)


def serve(
    config: DaemonConfig,
    *,
    os_: OsAdapters | None = None,
    clock: Clock | None = None,
    monotonic_clock: MonotonicClock | None = None,
    stop_event: threading.Event | None = None,
    shutdown_grace_s: float = DEFAULT_SHUTDOWN_GRACE_S,
    on_ready: Callable[[Ready, OwnerLoop], None] | None = None,
    domain: KernelToolDomain | None = None,
    job_handlers: Mapping[str, JobHandler] | None = None,
    hooks: DaemonTestHooks | None = None,
    outbox_replay: OutboxReplayPort | None = None,
    supervisor_control: SupervisorControlPort | None = None,
    log_quiesce_hook: Callable[[], contextlib.AbstractContextManager[None]] | None = None,
    capture_probe: CaptureDoctorProbePort | None = None,
    config_path: Path | None = None,
) -> int:
    """Run the foreground kernel daemon lifecycle for ``config`` and return process exit status."""
    if not isinstance(config, DaemonConfig):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    bad_grace = isinstance(shutdown_grace_s, bool) or not isinstance(shutdown_grace_s, (int, float))
    if bad_grace or not math.isfinite(shutdown_grace_s) or shutdown_grace_s <= 0:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")

    from superbrain.cli_api._loopback_server import LoopbackServer
    from superbrain.composition.operator_entry import make_operator_executor

    adapters = os_ if os_ is not None else os_adapters(clock=clock, monotonic=monotonic_clock)
    resolved_clock = clock if clock is not None else adapters.clock
    resolved_mono = monotonic_clock if monotonic_clock is not None else adapters.monotonic
    bound_listeners: list[BoundLoopbackListener] = []
    operator_handle = OperatorHandle()
    fix_deps = (config_path, outbox_replay, supervisor_control, log_quiesce_hook, capture_probe)
    fix_hooks = (
        DoctorFixHooks(
            config_path=config_path,
            outbox_replay=outbox_replay,
            supervisor_control=supervisor_control,
            log_quiesce_hook=log_quiesce_hook,
            capture_probe=capture_probe,
        )
        if any(x is not None for x in fix_deps)
        else None
    )
    loop = create_daemon_owner_loop(
        os_=adapters, clock=resolved_clock, monotonic_clock=resolved_mono,
        domain=domain, job_handlers=job_handlers, hooks=hooks,
        on_listener_bound=bound_listeners.append, operator=operator_handle,
        doctor_fix_hooks=fix_hooks,
    )
    effective_stop = stop_event if stop_event is not None else threading.Event()
    with _signal_stop_guard(effective_stop) as signalled:
        ready = loop.start(config)
        server: LoopbackServer | None = None
        try:
            if len(bound_listeners) != 1:
                raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")
            bound = bound_listeners[0]
            server = LoopbackServer(
                listener=bound.sock,
                ssl_context=bound.ssl_context,
                ready=ready,
                owner=loop,
                monotonic_ns=resolved_mono.monotonic_ns,
                stop_event=effective_stop,
                operator=make_operator_executor(loop, operator_handle, resolved_mono.monotonic_ns),
            )
            # The synchronous signal latch is authoritative during startup;
            # the background Event conversion may not have run yet.
            if signalled() or effective_stop.is_set():
                raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")
            server.start()
            if signalled() or effective_stop.is_set():
                raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")
        except BaseException as err:  # noqa: BLE001
            code = err.code if isinstance(err, BrainError) else ErrorCode.INTEGRITY_FAILURE
            _LOGGER.error("loopback server startup failed (phase=loopback_startup, code=%s)", code.value)
            stop_deadline = time.perf_counter() + float(shutdown_grace_s)
            if server is not None:
                with contextlib.suppress(Exception):
                    server.quiesce(stop_deadline)
            rep = None
            with contextlib.suppress(BrainError):
                rep = loop.stop(grace_s=max(0.0, stop_deadline - time.perf_counter()))
            if server is not None:
                with contextlib.suppress(Exception):
                    server.finish(stop_deadline)
            if rep is not None and rep.state is ShutdownState.OVERRUN:
                with contextlib.suppress(BrainError):
                    loop.wait_closed()
            if isinstance(err, (KeyboardInterrupt, SystemExit)):
                raise
            return 1

        try:
            if on_ready is not None:
                on_ready(ready, loop)
            try:
                while not effective_stop.wait(timeout=0.02):
                    if loop.is_stopping or loop.wait_closed(timeout=0.0) is not None:
                        break
            except KeyboardInterrupt:
                effective_stop.set()
        finally:
            stop_deadline = time.perf_counter() + float(shutdown_grace_s)
            quiesce_ok = True
            try:
                server.quiesce(stop_deadline)
            except Exception:  # noqa: BLE001
                quiesce_ok = False
            report = loop.stop(grace_s=max(0.0, stop_deadline - time.perf_counter()))
            try:
                transport_ok = server.finish(stop_deadline) and quiesce_ok
            except Exception:  # noqa: BLE001
                transport_ok = False
            if report.state is ShutdownState.OVERRUN:
                loop.wait_closed()
        return 0 if (report.state is ShutdownState.STOPPED and report.endpoint_removed and transport_ok) else 1


