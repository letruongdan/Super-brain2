"""Default handoff domain construction for the daemon session; ``_daemon_session`` re-exports these."""

from __future__ import annotations

from collections.abc import Callable

from superbrain.application.dispatch import KernelToolDomain
from superbrain.ports.clock import Clock
from superbrain.storage.runtime import Runtime


def build_default_handoff_domain(
    *,
    rt: Runtime,
    clock: Clock,
    writer_epoch: int,
    deep_health: bool = False,
    host_version_resolver: Callable[[str], str | None] | None = None,
) -> KernelToolDomain | None:
    """Build the production SP2-4/5 ``HandoffKernelDomain`` when store v8 and policy v5 are admitted."""
    if rt.store.schema_version < 8 or rt.policy.schema_version < 5:
        return None
    from superbrain.application._deep_health import DeepHealthProbeResult
    from superbrain.application.handoff_service import HandoffKernelDomain
    from superbrain.application.idempotency import is_idempotency_expired
    from superbrain.composition.doctor_probes_sp2_store import run_sp2_doctor_probes
    from superbrain.core._kernel_approval import Layer2State
    from superbrain.storage.handoffs import HandoffStore
    from superbrain.storage.idempotency import KernelIdempotencyStore
    from superbrain.storage.send_attempts import KernelSendAttemptStore

    idem_store = (
        KernelIdempotencyStore(
            rt.store,
            rt.policy,
            policy_view=rt.policy,
            writer_epoch=writer_epoch,
            is_expired=is_idempotency_expired,
        )
        if deep_health
        else None
    )

    def _probe_deep() -> DeepHealthProbeResult:
        sp2 = run_sp2_doctor_probes(
            rt.root.root,
            checkout_root=None,
            host_version_resolver=host_version_resolver,
            os_=rt.os_,
            now=clock.now(),
        )
        drifted = any(
            h.recorded_state is Layer2State.VERIFIED and h.effective_state is not Layer2State.VERIFIED
            for h in sp2.layer2_harnesses
        )
        untrusted = idem_store.clock_untrusted() if idem_store is not None else False
        return DeepHealthProbeResult(
            store_id=rt.store.store_id,
            writer_epoch=writer_epoch,
            store_schema_version=rt.store.schema_version,
            policy_schema_version=rt.policy.schema_version,
            clock_untrusted=untrusted,
            has_open_gaps=sp2.gaps.open_daemon_gaps > 0 or sp2.gaps.producer_gaps > 0,
            outbox_pending=sp2.outbox.pending_event_count + sp2.outbox.pending_gap_count,
            active_sessions=sp2.sessions.active_sessions,
            layer2_degraded=not sp2.terminal_channel_eligible_effective,
            layer2_drifted=drifted,
            probe_errors=sp2.integrity_errors,
        )

    return HandoffKernelDomain(
        handoffs=HandoffStore(rt.store, rt.policy),
        policy=rt.policy,
        clock=clock,
        send_attempts=KernelSendAttemptStore(rt.store, rt.policy, writer_epoch=writer_epoch),
        deep_health_probe=_probe_deep if deep_health else None,
        read_blob=rt.store.cas.read if deep_health else None,
    )


def make_default_handoff_domain_factory(
    *,
    rt: Runtime,
    clock: Clock,
    writer_epoch: int,
    host_version_resolver: Callable[[str], str | None] | None = None,
) -> Callable[[], KernelToolDomain | None] | None:
    """Return a lazy builder for ``HandoffKernelDomain`` when store v8 and policy v5 are admitted."""
    if rt.store.schema_version < 8 or rt.policy.schema_version < 5:
        return None

    def _build() -> KernelToolDomain | None:
        return build_default_handoff_domain(
            rt=rt,
            clock=clock,
            writer_epoch=writer_epoch,
            deep_health=True,
            host_version_resolver=host_version_resolver,
        )

    return _build
