"""Installed-wheel actions for the Task 8.3 process-crash tests."""

from __future__ import annotations

import threading
from collections.abc import Callable, Sequence
from datetime import datetime
from pathlib import Path

from superbrain.application.jobs import JobService
from superbrain.application.owner_loop import OwnerLoop
from superbrain.composition.daemon_entry import serve_config_path
from superbrain.composition.kernel_projections import kernel_store_extensions
from superbrain.core.kernel import DaemonConfig, JobSpec, JobState, ObjectRef, Ready, UsageRecord, UsageReservation
from superbrain.ports.os import OsAdapters
from superbrain.storage.idempotency import StagedKernelStore
from superbrain.storage.runtime import admit_existing_pair, open_runtime_under_lease
from superbrain.workers.executor import JobContext
from tests.support.kernel_auth import make_bootstrap_auth

T8_JOB_KIND = "fixture.t8.echo"
MAX_AMOUNT = "7.5"
FINAL_AMOUNT = "1.25"


def serve_claim(config_path: Path, os_: OsAdapters, mark: Callable[[str, str], None]) -> int:
    """Run the real daemon's claim/start path with a handler as the no-hook positive control."""
    handler_ran = threading.Event()
    stopped = threading.Event()

    def handler(_spec: JobSpec, ctx: JobContext) -> tuple[ObjectRef, ...]:
        mark("JOB_HANDLER_RAN", ctx.lease.job_id)
        handler_ran.set()
        return ()

    def after_ready(_ready: Ready, _loop: OwnerLoop) -> None:
        assert handler_ran.wait(10.0), "the real daemon never dispatched the seeded job"
        stopped.set()

    return serve_config_path(
        config_path,
        os_=os_,
        job_handlers={T8_JOB_KIND: handler},
        on_ready=after_ready,
        stop_event=stopped,
    )


def operate_job(cfg: DaemonConfig, os_: OsAdapters, args: Sequence[str], mark: Callable[[str, str], None]) -> int:
    """Call the real owner JobService under a fresh admitted writer lease."""
    operation, *params = args
    handlers, kinds = kernel_store_extensions()
    admitted = admit_existing_pair(cfg.data_root, cfg.expected_store_id, os_, purpose="serve")
    rt = open_runtime_under_lease(admitted, handlers=handlers, kinds=kinds)
    try:
        store = StagedKernelStore(rt.store, rt.policy, writer_epoch=rt.lease.epoch)
        service = JobService(
            store, store, rt.policy, os_.clock, writer_epoch=rt.lease.epoch,
            cancel_signal=lambda job_id: mark("JOB_CANCEL_SIGNAL", job_id),
        )
        mark("JOB_OPERATION", operation)
        if operation in {"reserve", "cancel"}:
            lease = service.lease_next(rt.lease.epoch, os_.clock.now())
            assert lease is not None, "the test's seeded job must be due"
            service.start(lease)
            invocation_id = service.reserve_invocation(lease, UsageReservation(MAX_AMOUNT))
            if operation == "cancel":
                (principal_id,) = params
                principal = rt.policy.snapshot().principals[principal_id]
                assert service.cancel(lease.job_id, principal, selected_scope=None) is JobState.CANCELLED
            else:
                assert not params
                mark("INVOCATION_RETURNED", invocation_id)
        elif operation == "settle":
            invocation_id, variant = params
            assert variant in {"incomplete", "complete"}
            usage = UsageRecord(FINAL_AMOUNT, True) if variant == "complete" else UsageRecord(None, False)
            service.settle_usage(invocation_id, usage)
        else:
            assert operation in {"empty-poll", "guarded-poll"} and not params
            if operation == "guarded-poll":
                service.set_claim_commit_guard(lambda: False)
            assert service.lease_next(rt.lease.epoch, os_.clock.now()) is None
        mark("JOB_RETURNED", operation)
        return 0
    finally:
        rt.close()


def revoke_on_owner(
    loop: OwnerLoop, cfg: DaemonConfig, args: Sequence[str], mark: Callable[[str, str], None]
) -> None:
    credential_id, owner_id, generation, intent_id, expires = args
    proof = make_bootstrap_auth(
        store_id=cfg.expected_store_id, owner_id=owner_id, action="credential_revoke",
        subject_id=credential_id, trust_generation=int(generation), intent_id=intent_id,
        expires_at=datetime.fromisoformat(expires),
    )
    mark("REVOKE_CALL", intent_id)
    intent = loop.revoke_credential(credential_id, proof).result(timeout=10.0)
    mark("REVOKE_RETURNED", intent.intent_id)
