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
) -> KernelToolDomain | None:
    """Build the production SP2-4/5 ``HandoffKernelDomain`` when store v8 and policy v5 are admitted."""
    if rt.store.schema_version < 8 or rt.policy.schema_version < 5:
        return None
    from superbrain.application.handoff_service import HandoffKernelDomain
    from superbrain.storage.handoffs import HandoffStore
    from superbrain.storage.send_attempts import KernelSendAttemptStore

    return HandoffKernelDomain(
        handoffs=HandoffStore(rt.store, rt.policy),
        policy=rt.policy,
        clock=clock,
        send_attempts=KernelSendAttemptStore(rt.store, rt.policy, writer_epoch=writer_epoch),
    )


def make_default_handoff_domain_factory(
    *,
    rt: Runtime,
    clock: Clock,
    writer_epoch: int,
) -> Callable[[], KernelToolDomain | None] | None:
    """Return a lazy builder for ``HandoffKernelDomain`` when store v8 and policy v5 are admitted."""
    if rt.store.schema_version < 8 or rt.policy.schema_version < 5:
        return None

    def _build() -> KernelToolDomain | None:
        return build_default_handoff_domain(rt=rt, clock=clock, writer_epoch=writer_epoch)

    return _build
