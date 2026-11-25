"""Composition entry point for the Increment 2 kernel daemon lifecycle (Task 6a)."""

from __future__ import annotations

import contextlib
import logging
import math
import queue
import signal
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from datetime import datetime
from pathlib import Path
from types import FrameType
from typing import TYPE_CHECKING

from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.daemon_config import read_daemon_config
from superbrain.application.approvals import OperatorHandle
from superbrain.application.deadlines import Reservation
from superbrain.application.dispatch import KernelToolDomain
from superbrain.application.owner_loop import AuthGate, OwnerLoop, OwnerSession
from superbrain.application.review_apply import ReviewApplyService
from superbrain.composition._daemon_session import (
    DaemonTestHooks,
    _AdmittedOwnerSession,
    _DaemonCompositeDomain,
)
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
from superbrain.ports.os import OsAdapters
from superbrain.workers.executor import PRODUCTION_JOB_HANDLERS, JobExecutor, JobHandler

if TYPE_CHECKING:
    from superbrain.cli_api._loopback_server import LoopbackServer

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

        composite_domain = _DaemonCompositeDomain(job_service, domain)
        bridge = KernelBridge(
            store=rt.store,
            policy=rt.policy,
            clock=resolved_clock,
            monotonic_clock=resolved_mono,
            writer_epoch=rt.lease.epoch,
            instance_id=instance_id,
            max_queue_size=DAEMON_QUEUE_DEPTH,
            domain=composite_domain,
            before_enter_commit=hooks.before_enter_commit,
            recover_pending_on_init=False,
            auth_state=auth_gate,
            before_auth_gate_publish=hooks.before_auth_gate_publish,
            after_reserve_before_enqueue=hooks.after_reserve_before_enqueue,
            on_reservation_change=arbiter_wake,
            on_queue_wake=owner_wake,
            on_owner_reply_ready=_on_reply_ready,
            on_owner_finished=_on_owner_finished,
            on_clock_untrusted_changed=auth_gate.update_clock_untrusted,
            on_capture_gaps_changed=auth_gate.update_capture_gaps_present,
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
            owner_wake()

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
        )
        session_box.append(session)
        if operator is not None:
            review_apply = build_review_apply_service(
                rt.store,
                rt.policy,
                rt.root.root,
                adapters,
                service_cls=ReviewApplyService,
            )
            restore_handler = DaemonRestoreHandler(
                session=session,
                adapters=adapters,
                clock=resolved_clock,
                executor=executor,
                composite_domain=composite_domain,
                instance_id=instance_id,
                operator=operator,
                review_apply_cls=ReviewApplyService,
            )
            operator.bind(
                build_operator_service(
                    rt.policy,
                    os_=adapters,
                    review_apply=review_apply,
                    restore_handler=restore_handler,
                    expected_endpoint_path=rt.root.endpoint_path,
                    expected_leaf_cert_sha256=verified_tls.leaf_cert_sha256,
                    server_cert_path=verified_tls.cert_path,
                )
            )
        return session
    except BaseException:
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
        )

    return OwnerLoop(_factory)


@contextlib.contextmanager
def _signal_stop_guard(target: threading.Event) -> Iterator[Callable[[], bool]]:
    """Latch stop signals and request ``target`` asynchronously in every phase; yields ``signalled()``.

    The handler never touches ``target``: CPython runs it on the main thread, which may be inside ``target.wait()``
    holding its condition lock. It only records the signal and wakes a watcher thread that calls ``target.set()``.
    """
    flag = [False]
    if threading.current_thread() is not threading.main_thread():
        yield lambda: flag[0]
        return
    saved: list[tuple[signal.Signals, Callable[[int, FrameType | None], object] | int | None]] = []
    wake: queue.SimpleQueue[int | None] = queue.SimpleQueue()

    def _watch() -> None:
        while wake.get() is not None:
            target.set()

    watcher = threading.Thread(target=_watch, name="superbrain-stop-signal", daemon=True)
    watcher.start()

    def _handler(signum: int, _frame: FrameType | None) -> None:
        flag[0] = True
        wake.put_nowait(signum)  # SimpleQueue.put is reentrant: documented safe from a signal handler

    candidates: list[signal.Signals] = [signal.SIGINT, signal.SIGTERM]
    sigbreak = getattr(signal, "SIGBREAK", None)
    if isinstance(sigbreak, signal.Signals):
        candidates.append(sigbreak)

    for sig in candidates:
        with contextlib.suppress(OSError, ValueError):
            prev = signal.getsignal(sig)
            signal.signal(sig, _handler)
            saved.append((sig, prev))
    try:
        yield lambda: flag[0]
    finally:
        for sig, prev in saved:
            with contextlib.suppress(OSError, ValueError, TypeError):
                signal.signal(sig, prev)
        wake.put_nowait(None)  # after restore: every signal the handler queued is applied before the watcher exits
        watcher.join(timeout=1.0)


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
) -> int:
    """Run the foreground kernel daemon lifecycle for ``config`` and return process exit status."""
    if not isinstance(config, DaemonConfig):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if (
        isinstance(shutdown_grace_s, bool)
        or not isinstance(shutdown_grace_s, (int, float))
        or not math.isfinite(shutdown_grace_s)
        or shutdown_grace_s <= 0
    ):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")

    from superbrain.cli_api._loopback_server import LoopbackServer
    from superbrain.composition.operator_entry import make_operator_executor

    adapters = os_ if os_ is not None else os_adapters(clock=clock, monotonic=monotonic_clock)
    resolved_clock = clock if clock is not None else adapters.clock
    resolved_mono = monotonic_clock if monotonic_clock is not None else adapters.monotonic
    bound_listeners: list[BoundLoopbackListener] = []
    operator_handle = OperatorHandle()

    loop = create_daemon_owner_loop(
        os_=adapters,
        clock=resolved_clock,
        monotonic_clock=resolved_mono,
        domain=domain,
        job_handlers=job_handlers,
        hooks=hooks,
        on_listener_bound=bound_listeners.append,
        operator=operator_handle,
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


def serve_config_path(
    config_path: Path,
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
) -> int:
    """Read and validate ``DaemonConfig`` from ``config_path`` and execute ``serve(...)``."""
    if not isinstance(config_path, Path):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    adapters = os_ if os_ is not None else os_adapters(clock=clock, monotonic=monotonic_clock)
    cfg = read_daemon_config(config_path, adapters)
    return serve(
        cfg,
        os_=adapters,
        clock=clock,
        monotonic_clock=monotonic_clock,
        stop_event=stop_event,
        shutdown_grace_s=shutdown_grace_s,
        on_ready=on_ready,
        domain=domain,
        job_handlers=job_handlers,
        hooks=hooks,
    )
