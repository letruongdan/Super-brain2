"""Independent regressions for SP1-I2 Task 5 remediation: I2-T5-R01, I2-T5-R02, and S1=A.

Requirement sources:
- ``.superpowers/sdd/2026-11-04-sp1-increment2-daemon-mcp-kernel/remediation-t5/ledger.md`` (Oracles 1, 2, 4)
- ``.superpowers/sdd/2026-11-04-sp1-increment2-daemon-mcp-kernel/remediation-t5/s1-compatibility-spec.md``
- ``docs/superpowers/plans/2026-11-08-sp1-increment2-task5-completion-plan.md`` (Tasks 1, 2, 4)
- ``docs/reviews/2026-11-08-sp1-increment2-task5-review.md``
- ``.superpowers/sdd/2026-11-04-sp1-increment2-daemon-mcp-kernel/task-5-owner-decisions-20261108.json``
"""

from __future__ import annotations

import datetime as dt
import json
import os
import shutil
import sqlite3
import sys
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Protocol, cast

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.application.jobs import JobService
from superbrain.composition.kernel_projections import kernel_store_extensions
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    AccountingStatus,
    InvocationRecord,
    InvocationState,
    JobErrorCode,
    JobLease,
    JobOutcome,
    JobRecord,
    JobSpec,
    JobState,
    KernelRecord,
    ObjectRef,
    Principal,
    RecoveryCounts,
    UsageRecord,
    UsageReservation,
    reservation_descriptor,
    usage_descriptor,
)
from superbrain.ports.kernel import KernelTx
from superbrain.ports.os import OsAdapters
from superbrain.ports.policy import IntentKind, PolicyView
from superbrain.storage.cas import held_digests
from superbrain.storage.idempotency import StagedKernelStore
from superbrain.storage.jobs import ProviderInvocationProjection
from superbrain.storage.kernel_schema import (
    KERNEL_JOB_KINDS,
    KERNEL_POLICY_MIGRATIONS,
    KERNEL_STORE_MIGRATIONS,
)
from superbrain.storage.kinds import EntryKind, FieldType, KindRegistry
from superbrain.storage.ledger import LedgerEntry, ProjectionHandler
from superbrain.storage.runtime import Runtime, open_runtime
from tests.storage.conftest import CLOCK_START
from tests.support.clock import FakeClock
from tests.support.inc2_fixture import (
    FIXTURE_JOB_KIND,
    _cleanup_dir,
    _make_trusted_session_dir,
    enqueue_job,
    kernel_job_service,
    open_cloned_runtime,
    open_kernel_job_runtime,
    reopen_kernel_job_runtime,
)
from tests.support.kernel_auth import seed_principal_and_credential

OWNER = "dan"
RESERVE = UsageReservation(max_amount="1.5")


class _AccountingStatesTx(Protocol):
    def read_job_accounting_states(self, job_id: str) -> frozenset[InvocationState]: ...


@dataclass(frozen=True)
class _Seeded1024Template:
    root: Path
    store_id: str
    principal: Principal
    empty_job_id: str
    job_id: str


@pytest.fixture
def rt(trusted_tmp: Path, os_: OsAdapters) -> Iterator[Runtime]:
    handlers, kinds = kernel_store_extensions()
    runtime = open_cloned_runtime(
        trusted_tmp / "r5-root",
        os_,
        role="t5-rt",
        handlers=handlers,
        kinds=kinds,
        store_migrations=KERNEL_STORE_MIGRATIONS,
        policy_migrations=KERNEL_POLICY_MIGRATIONS,
    )
    try:
        yield runtime
    finally:
        runtime.close()


def _clone_closed_data_root(src: Path, dst: Path, os_: OsAdapters) -> None:
    """Copy a closed data root inside ``trusted_tmp`` keeping owner-only permissions on every entry."""
    shutil.copytree(src, dst)
    if sys.platform != "win32":
        os_.permissions.secure_directory(dst)
        for cur_dir, dirnames, filenames in os.walk(dst):
            cur_path = Path(cur_dir)
            for dirname in dirnames:
                os_.permissions.secure_directory(cur_path / dirname)
            for filename in filenames:
                os_.permissions.secure_file(cur_path / filename)


def _ledger_len(rt: Runtime) -> int:
    return sum(1 for _ in rt.store.entries())


def _holds(rt: Runtime, holder_id: str) -> list[str]:
    with rt.store.transaction() as txn:
        return held_digests(txn.db, "event", holder_id)


def _job_row(store: StagedKernelStore, job_id: str) -> JobRecord:
    row = store.transact(lambda tx: tx.read_job(job_id))
    assert row is not None, "job row is missing"
    return row


def _invocation(store: StagedKernelStore, invocation_id: str) -> InvocationRecord:
    row = store.transact(lambda tx: tx.read_invocation(invocation_id))
    assert row is not None, "invocation row is missing"
    return row


def _accounting_states(store: StagedKernelStore, job_id: str) -> frozenset[InvocationState]:
    return store.transact(lambda tx: cast(_AccountingStatesTx, tx).read_job_accounting_states(job_id))


def _running(service: JobService, epoch: int, clock: FakeClock) -> JobLease:
    lease = service.lease_next(epoch, clock.now())
    assert lease is not None, "no due job was leased"
    service.start(lease)
    return lease


def _expect(code: ErrorCode, action: Callable[[], object]) -> BrainError:
    with pytest.raises(BrainError) as caught:
        action()
    assert caught.value.code is code, f"expected {code}, got {caught.value.code}"
    return caught.value


def _seed_settled_invocations_batch(
    store: StagedKernelStore,
    lease: JobLease,
    count: int,
) -> None:
    """Batch-insert ``count`` valid settled invocations in one ``Store.transaction()`` for fast >1024 tests."""
    seed_inv_id = "018f0000-0000-7000-8000-ffffffffffff"
    res_blob = reservation_descriptor(seed_inv_id, lease.job_id, RESERVE)
    use_blob = usage_descriptor(seed_inv_id, UsageRecord(amount="0.01", complete=True))
    store.stage_blob(res_blob)
    store.stage_blob(use_blob)

    settled_kind = next(k for k in KERNEL_JOB_KINDS if k.kind == "provider.settled")
    has_prior_usage = "prior_usage_digest" in settled_kind.fields

    def _batch(tx: KernelTx) -> None:
        for idx in range(1, count + 1):
            inv_id = f"018f0000-0000-7000-8000-{idx:012x}"
            res_digest = tx.hold_blob(res_blob, holder_id=inv_id)
            tx.append_record(
                KernelRecord(
                    "provider.reserved",
                    {
                        "invocation_id": inv_id,
                        "job_id": lease.job_id,
                        "attempt": lease.attempt,
                        "writer_epoch": lease.writer_epoch,
                        "lease_id": lease.lease_id,
                        "reservation_digest": res_digest,
                    },
                )
            )
            use_digest = tx.hold_blob(use_blob, holder_id=inv_id)
            settled_meta: dict[str, JsonValue] = {
                "invocation_id": inv_id,
                "prior_state": "reserved",
                "usage_digest": use_digest,
                "complete": True,
            }
            if has_prior_usage:
                settled_meta["prior_usage_digest"] = None
            tx.append_record(KernelRecord("provider.settled", settled_meta))

    store.transact(_batch)


@pytest.fixture(scope="module")
def _seeded_1024_template(tmp_path_factory: pytest.TempPathFactory) -> Iterator[_Seeded1024Template]:
    """Shared closed data root containing 1,024 real settled invocations on a due job (F4 budget friendly)."""
    scratch = _make_trusted_session_dir("r02-1024-seed", tmp_path_factory)
    try:
        seed_clock = FakeClock(CLOCK_START)
        seed_os = os_adapters(clock=seed_clock)
        root = scratch / "template"
        rt = open_kernel_job_runtime(root, seed_os, role="t5-1024-tpl")
        store_id = rt.store.store_id
        try:
            dan = seed_principal_and_credential(rt.policy, owner_id=OWNER).principal
            service, store = kernel_job_service(rt, seed_clock)
            job_id = enqueue_job(service, store, owner_id=OWNER, payload=b"acct-1025").job_id
            lease1 = _running(service, rt.lease.epoch, seed_clock)
            _seed_settled_invocations_batch(store, lease1, 1024)
            service.complete(lease1, JobOutcome.failure(JobErrorCode.HANDLER_FAILED, retryable=True))
            empty_job_id = enqueue_job(service, store, owner_id=OWNER, payload=b"acct-empty").job_id
            service.cancel(empty_job_id, dan, selected_scope=None)
        finally:
            rt.close()
        yield _Seeded1024Template(
            root=root,
            store_id=store_id,
            principal=dan,
            empty_job_id=empty_job_id,
            job_id=job_id,
        )
    finally:
        _cleanup_dir(scratch)


# --- Oracle 1: I2-T5-R01 (live policy tombstone blocks CAS reads before reconcile) -----------------------------------


def test_job_tombstone_blocks_payload_before_reconcile(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = trusted_tmp / "r01-payload"
    rt1 = open_kernel_job_runtime(root, os_)
    store_id = rt1.store.store_id
    try:
        service, store = kernel_job_service(rt1, clock)
        payload = b"payload-canary-r01-before-reconcile"
        payload_digest = digest_bytes(payload)
        ref = enqueue_job(service, store, owner_id=OWNER, payload=payload)
        lease = _running(service, rt1.lease.epoch, clock)

        # Control: before tombstone, both job_spec and read_held_blob return the staged payload bytes.
        assert service.job_spec(lease) == JobSpec(kind=FIXTURE_JOB_KIND, owner_id=OWNER, payload=payload)
        assert store.transact(lambda tx: tx.read_held_blob(payload_digest, holder_id=ref.job_id)) == payload

        # Commit TOMBSTONE(event, job_id) in PolicyStore WITHOUT running main-store reconcile_policy().
        intent = rt1.policy.record_intent(IntentKind.TOMBSTONE, {"holder_kind": "event", "holder_id": ref.job_id})
        assert rt1.policy.is_tombstoned("event", ref.job_id) is True
        assert intent in rt1.policy.intents() and len(rt1.policy.intents()) >= 1
        assert [
            e for e in rt1.store.entries() if e.kind == "cas.release" and e.meta.get("holder_id") == ref.job_id
        ] == []
        assert _holds(rt1, ref.job_id) == [payload_digest]

        # Behavioral oracle BEFORE reconcile: live tombstone immediately blocks payload handoff.
        assert store.transact(lambda tx: tx.read_held_blob(payload_digest, holder_id=ref.job_id)) is None
        _expect(ErrorCode.INTEGRITY_FAILURE, lambda: service.job_spec(lease))

        # Denial persists AFTER reconcile_policy() and AFTER rebuild_projections().
        assert rt1.store.reconcile_policy() >= 1
        assert _holds(rt1, ref.job_id) == []
        assert store.transact(lambda tx: tx.read_held_blob(payload_digest, holder_id=ref.job_id)) is None
        _expect(ErrorCode.INTEGRITY_FAILURE, lambda: service.job_spec(lease))

        rt1.store.rebuild_projections()
        assert store.transact(lambda tx: tx.read_held_blob(payload_digest, holder_id=ref.job_id)) is None
        _expect(ErrorCode.INTEGRITY_FAILURE, lambda: service.job_spec(lease))

        # Enqueue a second job and commit its tombstone in PolicyStore without reconciling before daemon restart.
        reopen_payload = b"payload-canary-r01-reopen"
        reopen_digest = digest_bytes(reopen_payload)
        reopen_ref = enqueue_job(service, store, owner_id=OWNER, payload=reopen_payload)
        rt1.policy.record_intent(IntentKind.TOMBSTONE, {"holder_kind": "event", "holder_id": reopen_ref.job_id})
    finally:
        rt1.close()

    rt2 = reopen_kernel_job_runtime(root, store_id, os_)
    try:
        e2 = rt2.lease.epoch
        service2, store2 = kernel_job_service(rt2, clock)
        assert service2.recover(e2) == RecoveryCounts(invocations_unknown=0, jobs_requeued=1, jobs_dead_lettered=0)

        leased = {
            leased_job.job_id: leased_job
            for leased_job in (_running(service2, e2, clock), _running(service2, e2, clock))
        }
        assert set(leased) == {ref.job_id, reopen_ref.job_id}
        for target_id, target_digest in ((ref.job_id, payload_digest), (reopen_ref.job_id, reopen_digest)):
            assert (
                store2.transact(partial(lambda d, h, tx: tx.read_held_blob(d, holder_id=h), target_digest, target_id))
                is None
            )
            _expect(ErrorCode.INTEGRITY_FAILURE, partial(service2.job_spec, leased[target_id]))

        # Unavailable PolicyView / closed PolicyStore fails closed with POLICY_UNAVAILABLE, never returning bytes.
        live_payload = b"live-untombstoned-payload"
        live_digest = digest_bytes(live_payload)
        live_ref = enqueue_job(service2, store2, owner_id=OWNER, payload=live_payload)
        live_lease = _running(service2, e2, clock)
        assert service2.job_spec(live_lease).payload == live_payload

        def _policy_down(_holder_kind: str, _holder_id: str) -> bool:
            raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable")

        with monkeypatch.context() as mp:
            mp.setattr(rt2.policy, "is_tombstoned", _policy_down)
            _expect(
                ErrorCode.POLICY_UNAVAILABLE,
                lambda: store2.transact(lambda tx: tx.read_held_blob(live_digest, holder_id=live_ref.job_id)),
            )
            _expect(ErrorCode.POLICY_UNAVAILABLE, lambda: service2.job_spec(live_lease))

        rt2.policy.close()
        with pytest.raises(BrainError) as closed_err:
            store2.transact(lambda tx: tx.read_held_blob(live_digest, holder_id=live_ref.job_id))
        assert closed_err.value.code in {ErrorCode.POLICY_UNAVAILABLE, ErrorCode.INTEGRITY_FAILURE}
        with pytest.raises(BrainError) as closed_spec_err:
            service2.job_spec(live_lease)
        assert closed_spec_err.value.code in {ErrorCode.POLICY_UNAVAILABLE, ErrorCode.INTEGRITY_FAILURE}
    finally:
        rt2.close()


def test_job_result_tombstone_blocks_descriptor_before_reconcile(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    root = trusted_tmp / "r01-result"
    rt1 = open_kernel_job_runtime(root, os_)
    store_id = rt1.store.store_id
    try:
        dan = seed_principal_and_credential(rt1.policy, owner_id=OWNER).principal
        service, store = kernel_job_service(rt1, clock)
        ref = enqueue_job(service, store, owner_id=OWNER, payload=b"job-with-result")
        lease = _running(service, rt1.lease.epoch, clock)
        out_ref = ObjectRef(kind="fixture_result", id="res-r01-1", revision=1, digest=digest_bytes(b"res-r01-body"))
        service.complete(lease, JobOutcome.success((out_ref,)))

        res_digest = _job_row(store, ref.job_id).result_digest
        assert res_digest is not None

        # Control: before tombstone, get_job returns the exact ObjectRef.
        control = service.get_job(ref.job_id, dan, selected_scope=None)
        assert (control.state, control.result_refs) == (JobState.SUCCEEDED, (out_ref,))
        assert store.transact(lambda tx: tx.read_held_blob(res_digest, holder_id=ref.job_id)) is not None

        # Commit TOMBSTONE(event, job_id) without running reconcile_policy().
        intent = rt1.policy.record_intent(IntentKind.TOMBSTONE, {"holder_kind": "event", "holder_id": ref.job_id})
        assert rt1.policy.is_tombstoned("event", ref.job_id) is True
        assert intent in rt1.policy.intents()
        assert res_digest in _holds(rt1, ref.job_id)

        # Behavioral oracle BEFORE reconcile: get_job refuses to read/expose the tombstoned result descriptor.
        _expect(ErrorCode.INTEGRITY_FAILURE, lambda: service.get_job(ref.job_id, dan, selected_scope=None))
        assert store.transact(lambda tx: tx.read_held_blob(res_digest, holder_id=ref.job_id)) is None

        # Same denial AFTER reconcile_policy() and AFTER rebuild_projections().
        assert rt1.store.reconcile_policy() >= 1
        assert _holds(rt1, ref.job_id) == []
        _expect(ErrorCode.INTEGRITY_FAILURE, lambda: service.get_job(ref.job_id, dan, selected_scope=None))

        rt1.store.rebuild_projections()
        _expect(ErrorCode.INTEGRITY_FAILURE, lambda: service.get_job(ref.job_id, dan, selected_scope=None))
    finally:
        rt1.close()

    rt2 = reopen_kernel_job_runtime(root, store_id, os_)
    try:
        service2, _ = kernel_job_service(rt2, clock)
        _expect(ErrorCode.INTEGRITY_FAILURE, lambda: service2.get_job(ref.job_id, dan, selected_scope=None))
        rt2.store.rebuild_projections()
        _expect(ErrorCode.INTEGRITY_FAILURE, lambda: service2.get_job(ref.job_id, dan, selected_scope=None))
    finally:
        rt2.close()


# --- Oracle 2: I2-T5-R02 (accounting aggregates all invocations past 1,024) ------------------------------------------


def test_job_accounting_includes_invocation_after_1024(
    _seeded_1024_template: _Seeded1024Template,
    trusted_tmp: Path,
    os_: OsAdapters,
    clock: FakeClock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = trusted_tmp / "r02-after-1024"
    _clone_closed_data_root(_seeded_1024_template.root, root, os_)
    dan = _seeded_1024_template.principal
    job_id = _seeded_1024_template.job_id
    clock.advance(dt.timedelta(seconds=2))

    rt1 = reopen_kernel_job_runtime(root, _seeded_1024_template.store_id, os_)
    try:
        service, store = kernel_job_service(rt1, clock)
        lease1 = _running(service, rt1.lease.epoch, clock)
        assert lease1.job_id == job_id

        # Controls: 0 invocations -> NONE; 1,024 settled invocations -> SETTLED.
        assert (
            service.get_job(_seeded_1024_template.empty_job_id, dan, selected_scope=None).accounting_status
            is AccountingStatus.NONE
        )
        assert service.get_job(job_id, dan, selected_scope=None).accounting_status is AccountingStatus.SETTLED

        # Invocation 1,025 is RESERVED: must not be truncated by a 1,024-row cap.
        inv_1025 = service.reserve_invocation(lease1, RESERVE)
        assert service.get_job(job_id, dan, selected_scope=None).accounting_status is AccountingStatus.RESERVED
        assert _accounting_states(store, job_id) == frozenset({InvocationState.SETTLED, InvocationState.RESERVED})

        rt1.store.rebuild_projections()
        assert service.get_job(job_id, dan, selected_scope=None).accounting_status is AccountingStatus.RESERVED

        # Settle 1,025 -> SETTLED; then reserve 1,026 and abandon this epoch so recovery marks 1,026 OUTCOME_UNKNOWN.
        service.settle_usage(inv_1025, UsageRecord("0.25", True))
        assert service.get_job(job_id, dan, selected_scope=None).accounting_status is AccountingStatus.SETTLED
        inv_1026 = service.reserve_invocation(lease1, RESERVE)
        assert _invocation(store, inv_1026).state is InvocationState.RESERVED
    finally:
        rt1.close()

    rt2 = reopen_kernel_job_runtime(root, _seeded_1024_template.store_id, os_)
    try:
        e2 = rt2.lease.epoch
        service2, store2 = kernel_job_service(rt2, clock)
        assert service2.recover(e2) == RecoveryCounts(invocations_unknown=1, jobs_requeued=1, jobs_dead_lettered=0)
        lease2 = _running(service2, e2, clock)
        inv_1027 = service2.reserve_invocation(lease2, RESERVE)

        # With 1..1025 SETTLED + 1026 OUTCOME_UNKNOWN + 1027 RESERVED: OUTCOME_UNKNOWN takes priority over RESERVED.
        assert service2.get_job(job_id, dan, selected_scope=None).accounting_status is AccountingStatus.OUTCOME_UNKNOWN
        assert _accounting_states(store2, job_id) == frozenset(
            {InvocationState.SETTLED, InvocationState.OUTCOME_UNKNOWN, InvocationState.RESERVED}
        )

        # get_job must not read raw reservation/usage CAS descriptors when result_digest is None.
        with monkeypatch.context() as mp:
            mp.setattr(
                rt2.store.cas,
                "read",
                lambda _digest: (_ for _ in ()).throw(AssertionError("get_job read CAS blobs for accounting")),
            )
            assert (
                service2.get_job(job_id, dan, selected_scope=None).accounting_status is AccountingStatus.OUTCOME_UNKNOWN
            )

        # Malformed state string in p_provider_invocations_state must fail closed with INTEGRITY_FAILURE.
        with rt2.store.transaction() as txn:
            txn.db.execute(
                "UPDATE p_provider_invocations_state SET state = 'bogus' WHERE invocation_id = ?",
                (inv_1027,),
            )
        _expect(ErrorCode.INTEGRITY_FAILURE, lambda: _accounting_states(store2, job_id))
        _expect(ErrorCode.INTEGRITY_FAILURE, lambda: service2.get_job(job_id, dan, selected_scope=None))

        rt2.store.rebuild_projections()
        assert service2.get_job(job_id, dan, selected_scope=None).accounting_status is AccountingStatus.OUTCOME_UNKNOWN
    finally:
        rt2.close()


def test_job_accounting_includes_late_unknown_after_recovery(
    _seeded_1024_template: _Seeded1024Template,
    trusted_tmp: Path,
    os_: OsAdapters,
    clock: FakeClock,
) -> None:
    root = trusted_tmp / "r02-late-unknown"
    _clone_closed_data_root(_seeded_1024_template.root, root, os_)
    dan = _seeded_1024_template.principal
    job_id = _seeded_1024_template.job_id
    clock.advance(dt.timedelta(seconds=2))

    rt1 = reopen_kernel_job_runtime(root, _seeded_1024_template.store_id, os_)
    try:
        service1, _ = kernel_job_service(rt1, clock)
        lease1 = _running(service1, rt1.lease.epoch, clock)
        assert lease1.job_id == job_id
        inv_1025 = service1.reserve_invocation(lease1, RESERVE)
    finally:
        rt1.close()

    rt2 = reopen_kernel_job_runtime(root, _seeded_1024_template.store_id, os_)
    try:
        e2 = rt2.lease.epoch
        service2, store2 = kernel_job_service(rt2, clock)
        counts = service2.recover(e2)
        assert counts == RecoveryCounts(invocations_unknown=1, jobs_requeued=1, jobs_dead_lettered=0)
        assert _invocation(store2, inv_1025).state is InvocationState.OUTCOME_UNKNOWN
        assert service2.get_job(job_id, dan, selected_scope=None).accounting_status is AccountingStatus.OUTCOME_UNKNOWN

        rt2.store.rebuild_projections()
        assert service2.get_job(job_id, dan, selected_scope=None).accounting_status is AccountingStatus.OUTCOME_UNKNOWN
    finally:
        rt2.close()


# --- Oracle 4: S1=A (incomplete usage remains reconcilable unknown until first complete=True usage) ------------------


def test_incomplete_usage_remains_unknown_until_first_complete_usage(rt: Runtime, clock: FakeClock) -> None:
    dan = seed_principal_and_credential(rt.policy, owner_id=OWNER).principal
    service, store = kernel_job_service(rt, clock)
    job_id = enqueue_job(service, store, owner_id=OWNER).job_id
    lease = _running(service, rt.lease.epoch, clock)
    invocation_id = service.reserve_invocation(lease, RESERVE)
    reservation_digest = _invocation(store, invocation_id).reservation_digest

    service.settle_usage(invocation_id, UsageRecord(None, False))
    assert service.get_job(job_id, dan, selected_scope=None).accounting_status is AccountingStatus.OUTCOME_UNKNOWN
    inv_unknown = _invocation(store, invocation_id)
    assert inv_unknown.state is InvocationState.OUTCOME_UNKNOWN
    assert inv_unknown.usage_complete is False and inv_unknown.usage_digest is not None
    assert reservation_digest in _holds(rt, invocation_id)
    assert inv_unknown.usage_digest in _holds(rt, invocation_id)
    raw_unknown = json.loads(rt.store.cas.read(inv_unknown.usage_digest))
    assert raw_unknown["amount"] is None and raw_unknown["complete"] is False

    before = (_ledger_len(rt), _invocation(store, invocation_id))
    service.settle_usage(invocation_id, UsageRecord(None, False))
    assert (_ledger_len(rt), _invocation(store, invocation_id)) == before

    service.settle_usage(invocation_id, UsageRecord("0.25", True))
    assert service.get_job(job_id, dan, selected_scope=None).accounting_status is AccountingStatus.SETTLED
    inv_settled = _invocation(store, invocation_id)
    assert inv_settled.state is InvocationState.SETTLED and inv_settled.usage_complete is True
    assert reservation_digest in _holds(rt, invocation_id)

    settled = (_ledger_len(rt), _invocation(store, invocation_id))
    service.settle_usage(invocation_id, UsageRecord("0.25", True))
    assert (_ledger_len(rt), _invocation(store, invocation_id)) == settled

    _expect(ErrorCode.IDEMPOTENCY_CONFLICT, lambda: service.settle_usage(invocation_id, UsageRecord("0.5", True)))
    _expect(ErrorCode.IDEMPOTENCY_CONFLICT, lambda: service.settle_usage(invocation_id, UsageRecord(None, False)))
    assert (_ledger_len(rt), _invocation(store, invocation_id)) == settled


def test_incomplete_usage_survives_cancel_restart_recovery_and_rebuild(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    root = trusted_tmp / "s1-cancel-recover"
    rt1 = open_kernel_job_runtime(root, os_)
    store_id = rt1.store.store_id
    try:
        dan = seed_principal_and_credential(rt1.policy, owner_id=OWNER).principal
        service1, store1 = kernel_job_service(rt1, clock)
        e1 = rt1.lease.epoch

        # Job 1: incomplete usage reported before cancel & restart recovery.
        job1 = enqueue_job(service1, store1, owner_id=OWNER, payload=b"s1-job-1").job_id
        lease1 = _running(service1, e1, clock)
        inv1 = service1.reserve_invocation(lease1, RESERVE)
        res1_digest = _invocation(store1, inv1).reservation_digest
        service1.settle_usage(inv1, UsageRecord(None, False))
        assert service1.cancel(job1, dan, selected_scope=None) is JobState.CANCELLED
        assert service1.get_job(job1, dan, selected_scope=None).accounting_status is AccountingStatus.OUTCOME_UNKNOWN

        # Job 2: cancelled while invocation is still RESERVED, so recover(e2) marks provider.unknown first.
        job2 = enqueue_job(service1, store1, owner_id=OWNER, payload=b"s1-job-2").job_id
        lease2 = _running(service1, e1, clock)
        inv2 = service1.reserve_invocation(lease2, RESERVE)
        res2_digest = _invocation(store1, inv2).reservation_digest
        assert service1.cancel(job2, dan, selected_scope=None) is JobState.CANCELLED
    finally:
        rt1.close()

    rt2 = reopen_kernel_job_runtime(root, store_id, os_)
    try:
        e2 = rt2.lease.epoch
        service2, store2 = kernel_job_service(rt2, clock)

        # recover(e2) marks ONLY inv2 unknown (inv1 is already outcome_unknown) and requeues 0 cancelled jobs.
        assert service2.recover(e2) == RecoveryCounts(invocations_unknown=1, jobs_requeued=0, jobs_dead_lettered=0)
        assert service2.recover(e2) == RecoveryCounts()
        assert [
            e for e in rt2.store.entries() if e.kind == "provider.unknown" and e.meta.get("invocation_id") == inv1
        ] == []
        assert _job_row(store2, job1).attempt == 1 and _job_row(store2, job2).attempt == 1

        rt2.store.rebuild_projections()
        assert service2.get_job(job1, dan, selected_scope=None).accounting_status is AccountingStatus.OUTCOME_UNKNOWN
        inv1_row = _invocation(store2, inv1)
        assert inv1_row.state is InvocationState.OUTCOME_UNKNOWN
        assert inv1_row.usage_complete is False and inv1_row.usage_digest is not None
        assert res1_digest in _holds(rt2, inv1)
        desc1 = json.loads(rt2.store.cas.read(inv1_row.usage_digest))
        assert desc1["amount"] is None and desc1["complete"] is False

        # Reverse order on inv2: provider.unknown (usage_digest=None) -> UsageRecord(None, False) once -> retry no-op.
        inv2_recovered = _invocation(store2, inv2)
        assert (inv2_recovered.state, inv2_recovered.usage_digest, inv2_recovered.usage_complete) == (
            InvocationState.OUTCOME_UNKNOWN,
            None,
            None,
        )
        service2.settle_usage(inv2, UsageRecord(None, False))
        inv2_inc = _invocation(store2, inv2)
        assert inv2_inc.state is InvocationState.OUTCOME_UNKNOWN
        assert inv2_inc.usage_digest is not None and inv2_inc.usage_complete is False
        assert res2_digest in _holds(rt2, inv2)
        before_inv2 = (_ledger_len(rt2), inv2_inc)
        service2.settle_usage(inv2, UsageRecord(None, False))
        assert (_ledger_len(rt2), _invocation(store2, inv2)) == before_inv2

        # First complete=True usage reconciles both to SETTLED, survives rebuild, and locks against changes.
        service2.settle_usage(inv1, UsageRecord("0.25", True))
        service2.settle_usage(inv2, UsageRecord("0.25", True))
        assert service2.get_job(job1, dan, selected_scope=None).accounting_status is AccountingStatus.SETTLED
        assert service2.get_job(job2, dan, selected_scope=None).accounting_status is AccountingStatus.SETTLED
        assert _job_row(store2, job1).attempt == 1 and _job_row(store2, job2).attempt == 1

        rt2.store.rebuild_projections()
        assert service2.get_job(job1, dan, selected_scope=None).accounting_status is AccountingStatus.SETTLED
        assert service2.get_job(job2, dan, selected_scope=None).accounting_status is AccountingStatus.SETTLED
        for inv_id in (inv1, inv2):
            _expect(
                ErrorCode.IDEMPOTENCY_CONFLICT,
                partial(service2.settle_usage, inv_id, UsageRecord("0.4", True)),
            )
            _expect(
                ErrorCode.IDEMPOTENCY_CONFLICT,
                partial(service2.settle_usage, inv_id, UsageRecord(None, False)),
            )
    finally:
        rt2.close()


class _LegacyV1ProviderInvocationProjection:
    """Candidate ``f82b5a3`` v1 ``provider_invocations`` reducer for historical compatibility verification."""

    name = "provider_invocations"
    handler_version = 1
    kinds = frozenset({"provider.reserved", "provider.settled", "provider.unknown"})

    def __init__(self) -> None:
        self._delegate = ProviderInvocationProjection()

    def create_tables(self, db: sqlite3.Connection, prefix: str) -> None:
        self._delegate.create_tables(db, prefix)

    def apply(self, db: sqlite3.Connection, prefix: str, entry: LedgerEntry, policy: PolicyView) -> None:
        if entry.kind == "provider.settled":
            complete = entry.meta["complete"]
            assert type(complete) is bool
            cursor = db.execute(
                f"UPDATE {prefix}state SET state = 'settled', usage_digest = ?, usage_complete = ?, sequence = ? "
                "WHERE invocation_id = ? AND state = ?",
                (
                    str(entry.meta["usage_digest"]),
                    1 if complete else 0,
                    entry.sequence,
                    str(entry.meta["invocation_id"]),
                    str(entry.meta["prior_state"]),
                ),
            )
            assert cursor.rowcount == 1
            return
        self._delegate.apply(db, prefix, entry, policy)


def _legacy_v1_extensions() -> tuple[tuple[ProjectionHandler, ...], KindRegistry]:
    prod_handlers, prod_kinds = kernel_store_extensions()
    legacy_settled_kind = EntryKind(
        "provider.settled",
        1,
        {
            "invocation_id": FieldType.UUID,
            "prior_state": FieldType.ENUM,
            "usage_digest": FieldType.DIGEST,
            "complete": FieldType.BOOL,
        },
        {"prior_state": frozenset({"reserved", "outcome_unknown"})},
    )
    v1_kinds = KindRegistry(
        [
            legacy_settled_kind if name == "provider.settled" else prod_kinds.get(name)
            for name in sorted(prod_kinds.kinds())
        ]
    )
    v1_handlers = tuple(
        _LegacyV1ProviderInvocationProjection() if handler.name == "provider_invocations" else handler
        for handler in prod_handlers
    )
    return v1_handlers, v1_kinds


def test_legacy_f82b5a3_incomplete_settled_history_rebuilds_as_reconcilable_unknown_and_locks_known_final(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    root = trusted_tmp / "s1-legacy-f82b5a3"
    v1_handlers, v1_kinds = _legacy_v1_extensions()

    rt1 = open_runtime(
        root,
        os_,
        handlers=v1_handlers,
        kinds=v1_kinds,
        store_migrations=KERNEL_STORE_MIGRATIONS,
        policy_migrations=KERNEL_POLICY_MIGRATIONS,
    )
    store_id = rt1.store.store_id
    try:
        dan = seed_principal_and_credential(rt1.policy, owner_id=OWNER).principal
        service1, store1 = kernel_job_service(rt1, clock)
        job_id = enqueue_job(service1, store1, owner_id=OWNER, payload=b"legacy-v1-history").job_id
        lease1 = _running(service1, rt1.lease.epoch, clock)
        inv_incomplete = service1.reserve_invocation(lease1, RESERVE)
        inv_complete = service1.reserve_invocation(lease1, RESERVE)
        res_inc_digest = _invocation(store1, inv_incomplete).reservation_digest

        inc_blob = usage_descriptor(inv_incomplete, UsageRecord(None, False))
        cmp_blob = usage_descriptor(inv_complete, UsageRecord("0.1", True))
        store1.stage_blob(inc_blob)
        store1.stage_blob(cmp_blob)

        def _append_v1_settled(tx: KernelTx) -> None:
            inc_dig = tx.hold_blob(inc_blob, holder_id=inv_incomplete)
            tx.append_record(
                KernelRecord(
                    "provider.settled",
                    {
                        "invocation_id": inv_incomplete,
                        "prior_state": "reserved",
                        "usage_digest": inc_dig,
                        "complete": False,
                    },
                )
            )
            cmp_dig = tx.hold_blob(cmp_blob, holder_id=inv_complete)
            tx.append_record(
                KernelRecord(
                    "provider.settled",
                    {
                        "invocation_id": inv_complete,
                        "prior_state": "reserved",
                        "usage_digest": cmp_dig,
                        "complete": True,
                    },
                )
            )

        store1.transact(_append_v1_settled)
        service1.complete(lease1, JobOutcome.success())
        v1_settled_entries = [e for e in rt1.store.entries() if e.kind == "provider.settled"]
        assert [e.handler_version for e in v1_settled_entries] == [1, 1]
    finally:
        rt1.close()

    rt2 = reopen_kernel_job_runtime(root, store_id, os_)
    try:
        service2, store2 = kernel_job_service(rt2, clock)

        # Rebuild projections first so v2 reducer replays the preserved v1 ledger entries.
        rt2.store.rebuild_projections()

        # Legacy v1 complete=False rebuilds as reconcilable OUTCOME_UNKNOWN with reservation hold intact.
        inc_rebuilt = _invocation(store2, inv_incomplete)
        assert inc_rebuilt.state is InvocationState.OUTCOME_UNKNOWN
        assert inc_rebuilt.usage_complete is False and inc_rebuilt.usage_digest is not None
        assert res_inc_digest in _holds(rt2, inv_incomplete)
        assert service2.get_job(job_id, dan, selected_scope=None).accounting_status is AccountingStatus.OUTCOME_UNKNOWN

        # Legacy v1 complete=True ("0.1") stays locked as immutable SETTLED and is never unlocked.
        cmp_rebuilt = _invocation(store2, inv_complete)
        assert cmp_rebuilt.state is InvocationState.SETTLED and cmp_rebuilt.usage_complete is True
        locked_before = (_ledger_len(rt2), cmp_rebuilt)
        service2.settle_usage(inv_complete, UsageRecord("0.1", True))
        assert (_ledger_len(rt2), _invocation(store2, inv_complete)) == locked_before
        _expect(ErrorCode.IDEMPOTENCY_CONFLICT, lambda: service2.settle_usage(inv_complete, UsageRecord("0.2", True)))
        _expect(ErrorCode.IDEMPOTENCY_CONFLICT, lambda: service2.settle_usage(inv_complete, UsageRecord(None, False)))

        # Unrebuilt stale (state='settled', usage_complete=0) row fails closed with INTEGRITY_FAILURE.
        with rt2.store.transaction() as txn:
            txn.db.execute(
                "UPDATE p_provider_invocations_state SET state = 'settled', usage_complete = 0 WHERE invocation_id = ?",
                (inv_incomplete,),
            )
        _expect(ErrorCode.INTEGRITY_FAILURE, lambda: _invocation(store2, inv_incomplete))
        _expect(ErrorCode.INTEGRITY_FAILURE, lambda: service2.get_job(job_id, dan, selected_scope=None))
        rt2.store.rebuild_projections()

        # Reconcile legacy incomplete invocation once with first complete=True usage ("0.3").
        service2.settle_usage(inv_incomplete, UsageRecord("0.3", True))
        assert _invocation(store2, inv_incomplete).state is InvocationState.SETTLED
        assert _invocation(store2, inv_incomplete).usage_complete is True
        assert service2.get_job(job_id, dan, selected_scope=None).accounting_status is AccountingStatus.SETTLED
        rt2.store.rebuild_projections()
        assert service2.get_job(job_id, dan, selected_scope=None).accounting_status is AccountingStatus.SETTLED
        _expect(ErrorCode.IDEMPOTENCY_CONFLICT, lambda: service2.settle_usage(inv_incomplete, UsageRecord("0.4", True)))
        _expect(ErrorCode.IDEMPOTENCY_CONFLICT, lambda: service2.settle_usage(inv_incomplete, UsageRecord(None, False)))
    finally:
        rt2.close()

    # Spec §5.8 fail-closed downgrade guard: v1 reader seeing v2 provider.settled raises UNSUPPORTED_VERSION.
    _expect(
        ErrorCode.UNSUPPORTED_VERSION,
        lambda: open_runtime(
            root,
            os_,
            handlers=v1_handlers,
            kinds=v1_kinds,
            store_migrations=KERNEL_STORE_MIGRATIONS,
            policy_migrations=KERNEL_POLICY_MIGRATIONS,
        ),
    )

    rt3 = reopen_kernel_job_runtime(root, store_id, os_)
    try:
        service3, _ = kernel_job_service(rt3, clock)
        assert service3.get_job(job_id, dan, selected_scope=None).accounting_status is AccountingStatus.SETTLED
    finally:
        rt3.close()
