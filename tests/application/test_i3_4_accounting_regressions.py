"""I3-4 Round-2 RED regression for Case 102 ``settle_usage`` ordering invariant (R02)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.application.jobs import JobService
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import InvocationState, UsageRecord, UsageReservation
from superbrain.storage.backup import create_store_backup
from superbrain.storage.kernel_schema import KERNEL_POLICY_MIGRATIONS, KERNEL_STORE_MIGRATIONS
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.restore import restore_store
from tests.storage.conftest import maintenance_lease
from tests.support.clock import FakeClock
from tests.support.inc2_fixture import (
    enqueue_job,
    kernel_job_service,
    open_kernel_job_runtime,
    reopen_kernel_job_runtime,
)

OWNER = "dan"


def _start_job(service: JobService, store: Any, epoch: int, now: datetime) -> Any:
    enqueue_job(service, store, owner_id=OWNER)
    lease = service.lease_next(epoch, now)
    assert lease is not None
    service.start(lease)
    return lease


def test_r02_case102_settle_usage_not_found_and_conflict_never_clear_policy_outcome_unknown_hold(
    trusted_tmp: Path,
) -> None:
    """I3-4-R02: failed settle_usage (NOT_FOUND or IDEMPOTENCY_CONFLICT) must NOT mutate policy.db."""
    clock = FakeClock(datetime(2026, 10, 30, 12, 0, tzinfo=UTC))
    os_ = os_adapters(clock=clock)
    root_path = trusted_tmp / "r02-cap"
    period = clock.now().strftime("%Y-%m-%d")
    rt = open_kernel_job_runtime(root_path, os_, role="r02-seed")
    try:
        store_id = rt.store.store_id
        rt.policy.set_period_cap(OWNER, "5")
        bak_empty = create_store_backup(rt.store, os_, clock.now())
        svc, kstore = kernel_job_service(rt, clock)
        lease1 = _start_job(svc, kstore, rt.lease.epoch, clock.now())
        inv1 = svc.reserve_invocation(lease1, UsageReservation(max_amount="5"))
        assert rt.policy.period_committed_total(OWNER, period) == "5"
    finally:
        rt.close()

    # Rewind store so inv1 leaves brain.db while policy.db retains it; recover moves it to outcome_unknown.
    clock.advance(timedelta(seconds=10))
    with maintenance_lease(root_path) as (root, lease):
        pol = PolicyStore.open(root, lease, os_, migrations=KERNEL_POLICY_MIGRATIONS)
        try:
            restore_store(root, lease, os_, bak_empty, pol, clock.now(), migrations=KERNEL_STORE_MIGRATIONS)
        finally:
            pol.close()

    rt2 = reopen_kernel_job_runtime(root_path, store_id, os_)
    try:
        svc2, ks2 = kernel_job_service(rt2, clock)
        svc2.recover(rt2.lease.epoch)
        held = rt2.policy.accounting_invocation(inv1)
        assert held is not None and held.state is InvocationState.OUTCOME_UNKNOWN and held.reserved_amount == "5"

        with pytest.raises(BrainError) as err_nf:
            svc2.settle_usage(inv1, UsageRecord(amount="0", complete=True))
        assert err_nf.value.code is ErrorCode.NOT_FOUND

        still_held = rt2.policy.accounting_invocation(inv1)
        assert still_held is not None and still_held.state is InvocationState.OUTCOME_UNKNOWN
        assert still_held.reserved_amount == "5" and still_held.settled_amount is None
        assert rt2.policy.period_committed_total(OWNER, period) == "5"

        lease2 = _start_job(svc2, ks2, rt2.lease.epoch, clock.now())
        with pytest.raises(BrainError) as err_cap:
            svc2.reserve_invocation(lease2, UsageReservation(max_amount="5"))
        assert err_cap.value.code is ErrorCode.CAPABILITY_UNAVAILABLE
    finally:
        rt2.close()

    # Conflicting retry (IDEMPOTENCY_CONFLICT) on live settled invocation must also leave policy.db intact.
    rt3 = open_kernel_job_runtime(trusted_tmp / "r02-conflict", os_, role="r02-conflict")
    try:
        svc3, ks3 = kernel_job_service(rt3, clock)
        l_c = _start_job(svc3, ks3, rt3.lease.epoch, clock.now())
        inv_c = svc3.reserve_invocation(l_c, UsageReservation(max_amount="4"))
        svc3.settle_usage(inv_c, UsageRecord(amount="1", complete=True))
        with pytest.raises(BrainError) as err_conf:
            svc3.settle_usage(inv_c, UsageRecord(amount="2", complete=True))
        assert err_conf.value.code is ErrorCode.IDEMPOTENCY_CONFLICT
        settled_c = rt3.policy.accounting_invocation(inv_c)
        assert settled_c is not None and settled_c.state is InvocationState.SETTLED
        assert settled_c.settled_amount == "1"
    finally:
        rt3.close()
