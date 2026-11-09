"""Task 5 residual remediation regressions (CL-T5-A3, CL-T5-B4, CL-T5-B5).

Covers:
- CL-T5-A3: ``JobService.cancel`` records ``actor=f"principal:{principal.principal_id}"`` while all
  worker/recovery/retention/accounting system transitions retain ``actor="system:kernel"``.
- CL-T5-B4: Pure ``JobsProjection`` / ``ProviderInvocationProjection`` reducers fail closed with
  ``INTEGRITY_FAILURE`` on fenced mismatches in ``job.retry``, ``job.terminal``, and ``provider.settled``
  (v1 & v2) without mutating SQLite projection rows.
- CL-T5-B5: Pre-recovery stale-epoch leases are rejected by ``JobService``'s ``writer_epoch`` guard
  with ``REVISION_CONFLICT`` and zero writes even while SQLite rows still match the abandoned epoch's fence.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import os
import sqlite3
import sys
from collections.abc import Callable, Mapping
from functools import partial
from pathlib import Path

import pytest

from superbrain.adapters.os.workspaces import build_registration
from superbrain.application.jobs import JobService
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    JobErrorCode,
    JobLease,
    JobOutcome,
    JobRecord,
    JobState,
    KernelRecord,
    Principal,
    RecoveryCounts,
    Scope,
    UsageRecord,
    UsageReservation,
    WorkspaceBinding,
)
from superbrain.ports.os import OsAdapters
from superbrain.storage.idempotency import StagedKernelStore
from superbrain.storage.jobs import JobsProjection, ProviderInvocationProjection
from superbrain.storage.kinds import validate_envelope
from superbrain.storage.ledger import LedgerEntry, ProjectionHandler
from superbrain.storage.runtime import Runtime
from tests.support.clock import FakeClock
from tests.support.inc2_fixture import (
    enqueue_job,
    kernel_job_service,
    open_kernel_job_runtime,
    reopen_kernel_job_runtime,
)
from tests.support.kernel_auth import make_bootstrap_auth, seed_principal_and_credential

OWNER = "dan"
REMOTE_WS = "https://github.com/dan/residual-repo.git"
RESERVE = UsageReservation(max_amount="1.5")
JOB_KINDS = frozenset(
    {
        "job.queued",
        "job.leased",
        "job.running",
        "job.retry",
        "job.terminal",
        "job.retention_expired",
        "provider.reserved",
        "provider.settled",
        "provider.unknown",
    }
)


def _entries(rt: Runtime, kinds: frozenset[str] = JOB_KINDS) -> list[LedgerEntry]:
    return [entry for entry in rt.store.entries() if entry.kind in kinds]


def _ledger_len(rt: Runtime) -> int:
    return sum(1 for _ in rt.store.entries())


def _job_row(store: StagedKernelStore, job_id: str) -> JobRecord:
    row = store.transact(lambda tx: tx.read_job(job_id))
    assert row is not None, "job row is missing"
    return row


def _tables(rt: Runtime) -> dict[str, list[tuple[object, ...]]]:
    with rt.store.transaction() as txn:
        return {
            name: sorted(txn.db.execute(f'SELECT * FROM "{name}"').fetchall(), key=repr)
            for name in ("p_jobs_state", "p_provider_invocations_state", "p_cas_holders_")
        }


def _lease(service: JobService, epoch: int, clock: FakeClock) -> JobLease:
    lease = service.lease_next(epoch, clock.now())
    assert lease is not None, "no due job was leased"
    return lease


def _running(service: JobService, epoch: int, clock: FakeClock) -> JobLease:
    lease = _lease(service, epoch, clock)
    service.start(lease)
    return lease


def _register_workspace(
    rt: Runtime,
    clock: FakeClock,
    principal: Principal,
    checkout_dir: Path,
) -> WorkspaceBinding:
    checkout_dir.mkdir(parents=True, exist_ok=True)
    if sys.platform != "win32":
        os.chmod(checkout_dir, 0o700)
    reg = build_registration(
        owner_id=principal.owner_id,
        principal_id=principal.principal_id,
        machine_id=principal.machine_id,
        alias="ws-residual",
        raw_path=str(checkout_dir),
        raw_remote=REMOTE_WS,
        provider_egress_enabled=False,
    )
    proof = make_bootstrap_auth(
        store_id=rt.policy.store_id,
        owner_id=principal.owner_id,
        action="workspace_register",
        subject_id=reg.subject_id,
        trust_generation=rt.policy.trust_generation(),
        expires_at=clock.now() + dt.timedelta(hours=1),
    )
    binding = rt.policy.register_authorized_workspace(reg, proof)
    rt.store.reconcile_policy()
    return binding


class _NoPolicy:
    def is_quarantined(self, digest: str) -> bool:
        raise AssertionError("job reducers never consult policy")

    def is_tombstoned(self, holder_kind: str, holder_id: str) -> bool:
        raise AssertionError("job reducers never consult policy")


def test_cancel_records_authenticated_principal_actor_while_system_transitions_keep_kernel_actor(
    trusted_tmp: Path,
    os_: OsAdapters,
    clock: FakeClock,
) -> None:
    """CL-T5-A3: ``cancel`` records ``principal:<principal_id>`` while system transitions keep ``system:kernel``."""
    root = trusted_tmp / "cl-t5-a3"
    rt1 = open_kernel_job_runtime(root, os_)
    store_id = rt1.store.store_id
    try:
        dan_global = seed_principal_and_credential(
            rt1.policy, owner_id=OWNER, harness_id="claude-code", machine_id="m-global"
        ).principal
        dan_ws = seed_principal_and_credential(
            rt1.policy, owner_id=OWNER, harness_id="codex", machine_id="m-scoped"
        ).principal
        assert dan_global.principal_id != dan_ws.principal_id
        ws = _register_workspace(rt1, clock, dan_ws, trusted_tmp / "cl-t5-a3-chk")
        scope_ws = Scope(ws.repo_id, ws.checkout_id)

        service1, store1 = kernel_job_service(rt1, clock)
        e1 = rt1.lease.epoch

        # 1. Cancel 3 jobs from queued, leased, and running states.
        job_q = enqueue_job(service1, store1, owner_id=OWNER, payload=b"a3-cancel-queued").job_id
        assert service1.cancel(job_q, dan_global, selected_scope=None) is JobState.CANCELLED

        job_l = enqueue_job(service1, store1, owner_id=OWNER, payload=b"a3-cancel-leased").job_id
        _ = _lease(service1, e1, clock)
        assert service1.cancel(job_l, dan_global, selected_scope=None) is JobState.CANCELLED

        job_r = enqueue_job(
            service1,
            store1,
            owner_id=OWNER,
            payload=b"a3-cancel-running",
            repo_id=ws.repo_id,
            checkout_id=ws.checkout_id,
        ).job_id
        _ = _running(service1, e1, clock)
        assert service1.cancel(job_r, dan_ws, selected_scope=scope_ws) is JobState.CANCELLED

        cancelled_entries = {
            str(e.meta["job_id"]): e
            for e in _entries(rt1, frozenset({"job.terminal"}))
            if e.meta.get("state") == "cancelled"
        }
        assert set(cancelled_entries) == {job_q, job_l, job_r}
        assert cancelled_entries[job_q].actor == f"principal:{dan_global.principal_id}"
        assert cancelled_entries[job_l].actor == f"principal:{dan_global.principal_id}"
        assert cancelled_entries[job_r].actor == f"principal:{dan_ws.principal_id}"
        assert all(entry.actor != "system:kernel" for entry in cancelled_entries.values())

        # 1b. Opaque Principal ID domain parity (mixed-case, 65-char, 128-char) + negative actor boundaries.
        max_opaque_id = "Agent_Max.01-" + "Z" * 115
        assert len(max_opaque_id) == 128
        for label, opaque_pid in (
            ("mixed-case", "Harness-A"),
            ("len-65", "a" * 65),
            ("len-128", max_opaque_id),
        ):
            seeded = seed_principal_and_credential(
                rt1.policy,
                owner_id=OWNER,
                harness_id=f"opaque-{label}",
                machine_id=f"m-{label}",
                principal_id=opaque_pid,
            )
            resolved = rt1.policy.resolve_credential(seeded.token)
            assert resolved == seeded.principal
            assert resolved.principal_id == opaque_pid
            opaque_job_id = enqueue_job(
                service1,
                store1,
                owner_id=OWNER,
                payload=f"a3-opaque-{label}".encode(),
            ).job_id
            assert service1.get_job(opaque_job_id, resolved, selected_scope=None).state is JobState.QUEUED
            assert service1.cancel(opaque_job_id, resolved, selected_scope=None) is JobState.CANCELLED
            expected_actor = f"principal:{opaque_pid}"
            opaque_terminals = [
                e
                for e in _entries(rt1, frozenset({"job.terminal"}))
                if e.meta.get("job_id") == opaque_job_id
            ]
            assert len(opaque_terminals) == 1
            assert opaque_terminals[0].meta["state"] == "cancelled"
            assert opaque_terminals[0].actor == expected_actor
            assert KernelRecord(kind="test.item", meta={"k": 1}, refs=(), actor=expected_actor).actor == expected_actor
            assert validate_envelope(expected_actor, OWNER, ()) == ()

        before_opaque_rebuild = _tables(rt1)
        rt1.store.rebuild_projections()
        assert _tables(rt1) == before_opaque_rebuild

        for bad_actor in (
            "user:CLI",
            "user:" + "a" * 65,
            "system:UPPER",
            "system:" + "a" * 65,
            "principal:",
            "principal:-bad",
            "principal:a:b",
            "principal:" + "a" * 129,
        ):
            with pytest.raises(BrainError) as kr_err:
                KernelRecord(kind="test.item", meta={"k": 1}, refs=(), actor=bad_actor)
            assert kr_err.value.code is ErrorCode.INVALID_INPUT
            with pytest.raises(BrainError) as ve_err:
                validate_envelope(bad_actor, OWNER, ())
            assert ve_err.value.code is ErrorCode.INVALID_INPUT

        # 2. Control system transitions: enqueue, lease, start, reserve, settle, succeed, fail, dead-letter, prune.
        job_ok = enqueue_job(service1, store1, owner_id=OWNER, payload=b"a3-sys-ok").job_id
        lease_ok = _running(service1, e1, clock)
        inv_ok = service1.reserve_invocation(lease_ok, RESERVE)
        service1.settle_usage(inv_ok, UsageRecord("0.25", complete=True))
        service1.complete(lease_ok, JobOutcome.success())

        job_fail = enqueue_job(service1, store1, owner_id=OWNER, payload=b"a3-sys-fail").job_id
        lease_fail = _running(service1, e1, clock)
        service1.complete(lease_fail, JobOutcome.failure(JobErrorCode.INVALID_PAYLOAD, retryable=False))

        job_dead = enqueue_job(service1, store1, owner_id=OWNER, payload=b"a3-sys-dead").job_id
        for delay in (1, 2, 0):
            service1.complete(
                _running(service1, e1, clock),
                JobOutcome.failure(JobErrorCode.HANDLER_FAILED, retryable=True),
            )
            clock.advance(dt.timedelta(seconds=delay))
        assert _job_row(store1, job_dead).state is JobState.DEAD_LETTER
        clock.advance(dt.timedelta(days=31))
        assert service1.prune_dead_letters(clock.now()) == 1

        # Leave one abandoned running job + unsettled invocation for next-epoch recover() actor check.
        job_rec = enqueue_job(service1, store1, owner_id=OWNER, payload=b"a3-sys-recover").job_id
        lease_rec = _running(service1, e1, clock)
        inv_rec = service1.reserve_invocation(lease_rec, RESERVE)
    finally:
        rt1.close()

    rt2 = reopen_kernel_job_runtime(root, store_id, os_)
    try:
        service2, store2 = kernel_job_service(rt2, clock)
        assert service2.recover(rt2.lease.epoch) == RecoveryCounts(
            invocations_unknown=1, jobs_requeued=1, jobs_dead_lettered=0
        )
        assert _job_row(store2, job_rec).state is JobState.QUEUED
        assert _job_row(store2, job_ok).state is JobState.SUCCEEDED
        assert _job_row(store2, job_fail).state is JobState.FAILED

        all_job_entries = _entries(rt2)
        non_cancel_entries = [
            e
            for e in all_job_entries
            if not (e.kind == "job.terminal" and e.meta.get("state") == "cancelled")
        ]
        seen_system_kinds = {e.kind for e in non_cancel_entries}
        assert seen_system_kinds == JOB_KINDS
        assert any(e.meta.get("invocation_id") == inv_rec and e.kind == "provider.unknown" for e in non_cancel_entries)
        assert all(e.actor == "system:kernel" for e in non_cancel_entries)

        before_rebuild = _tables(rt2)
        rt2.store.rebuild_projections()
        assert _tables(rt2) == before_rebuild
    finally:
        rt2.close()


def test_reducers_reject_fenced_mismatches_on_retry_terminal_and_settled_without_mutating_rows() -> None:
    """CL-T5-B4: Pure reducers reject fenced mismatches on ``job.retry``, ``job.terminal`` & ``provider.settled``."""
    jobs = JobsProjection()
    invocations = ProviderInvocationProjection()
    with contextlib.closing(sqlite3.connect(":memory:")) as db:
        jobs.create_tables(db, "p_jobs_")
        invocations.create_tables(db, "p_provider_invocations_")

        job_run = "018f0000-0000-7000-8000-000000000101"
        job_queued = "018f0000-0000-7000-8000-000000000102"
        lease_1 = "018f0000-0000-7000-8000-000000000201"
        lease_2 = "018f0000-0000-7000-8000-000000000202"
        inv_1 = "018f0000-0000-7000-8000-000000000301"
        inv_2 = "018f0000-0000-7000-8000-000000000302"
        inv_3 = "018f0000-0000-7000-8000-000000000303"
        ts = "2026-11-09T00:00:00.000000Z"
        d_payload = digest_bytes(b"b4-payload")
        d_res = digest_bytes(b"b4-res")
        d_inc = digest_bytes(b"b4-inc")
        d_cmp = digest_bytes(b"b4-cmp")
        d_other = digest_bytes(b"b4-other")

        seq = iter(range(1, 500))

        def _entry(
            entry_id: str,
            kind: str,
            meta: Mapping[str, JsonValue],
            *,
            hv: int = 1,
        ) -> LedgerEntry:
            return LedgerEntry(next(seq), entry_id, kind, 4, hv, 1, "system:kernel", None, ts, dict(meta), ())

        def _snap() -> dict[str, list[tuple[object, ...]]]:
            return {
                "jobs": db.execute("SELECT * FROM p_jobs_state ORDER BY job_id").fetchall(),
                "inv": db.execute("SELECT * FROM p_provider_invocations_state ORDER BY invocation_id").fetchall(),
            }

        def _assert_rejected(handler: ProjectionHandler, prefix: str, bad: LedgerEntry, label: str) -> None:
            before = _snap()
            with pytest.raises(BrainError) as caught:
                handler.apply(db, prefix, bad, _NoPolicy())
            assert caught.value.code is ErrorCode.INTEGRITY_FAILURE, label
            assert _snap() == before, f"projection mutated on rejected {label}"

        # Seed running job_run (attempt=1, writer_epoch=1, lease_id=lease_1) and queued job_queued (null lease/epoch).
        for jid in (job_run, job_queued):
            jobs.apply(
                db,
                "p_jobs_",
                _entry(
                    jid,
                    "job.queued",
                    {
                        "job_id": jid,
                        "owner_id": OWNER,
                        "repo_id": None,
                        "checkout_id": None,
                        "kind": "fixture.echo",
                        "payload_digest": d_payload,
                        "attempt": 1,
                        "retry_at": ts,
                    },
                ),
                _NoPolicy(),
            )
        lease_meta: dict[str, JsonValue] = {
            "job_id": job_run,
            "attempt": 1,
            "writer_epoch": 1,
            "lease_id": lease_1,
        }
        jobs.apply(db, "p_jobs_", _entry(job_run, "job.leased", lease_meta), _NoPolicy())
        jobs.apply(db, "p_jobs_", _entry(job_run, "job.running", lease_meta), _NoPolicy())

        # Seed inv_1 (reserved), inv_2 (outcome_unknown with usage_digest=d_inc, usage_complete=0), inv_3 (settled).
        for iid in (inv_1, inv_2, inv_3):
            invocations.apply(
                db,
                "p_provider_invocations_",
                _entry(
                    iid,
                    "provider.reserved",
                    {
                        "invocation_id": iid,
                        "job_id": job_run,
                        "attempt": 1,
                        "writer_epoch": 1,
                        "lease_id": lease_1,
                        "reservation_digest": d_res,
                    },
                ),
                _NoPolicy(),
            )
        invocations.apply(
            db,
            "p_provider_invocations_",
            _entry(
                inv_2,
                "provider.settled",
                {
                    "invocation_id": inv_2,
                    "prior_state": "reserved",
                    "prior_usage_digest": None,
                    "usage_digest": d_inc,
                    "complete": False,
                },
                hv=2,
            ),
            _NoPolicy(),
        )
        invocations.apply(
            db,
            "p_provider_invocations_",
            _entry(
                inv_3,
                "provider.settled",
                {
                    "invocation_id": inv_3,
                    "prior_state": "reserved",
                    "prior_usage_digest": None,
                    "usage_digest": d_cmp,
                    "complete": True,
                },
                hv=2,
            ),
            _NoPolicy(),
        )

        # Confirm seeded baseline before negative fence probes.
        assert db.execute(
            "SELECT state, attempt, writer_epoch, lease_id FROM p_jobs_state WHERE job_id = ?", (job_run,)
        ).fetchone() == ("running", 1, 1, lease_1)
        assert db.execute(
            "SELECT state, attempt, writer_epoch, lease_id FROM p_jobs_state WHERE job_id = ?", (job_queued,)
        ).fetchone() == ("queued", 1, None, None)
        assert db.execute(
            "SELECT invocation_id, state, usage_digest, usage_complete FROM p_provider_invocations_state "
            "ORDER BY invocation_id"
        ).fetchall() == [
            (inv_1, "reserved", None, None),
            (inv_2, "outcome_unknown", d_inc, 0),
            (inv_3, "settled", d_cmp, 1),
        ]

        valid_retry: dict[str, JsonValue] = {
            "job_id": job_run,
            "attempt": 2,
            "writer_epoch": 1,
            "lease_id": lease_1,
            "prior_state": "running",
            "retry_at": ts,
            "reason": "handler_failed",
        }
        job_bad_cases: list[tuple[str, LedgerEntry]] = [
            ("retry/wrong_prior_state", _entry(job_run, "job.retry", {**valid_retry, "prior_state": "leased"})),
            ("retry/attempt_3", _entry(job_run, "job.retry", {**valid_retry, "attempt": 3})),
            ("retry/attempt_1", _entry(job_run, "job.retry", {**valid_retry, "attempt": 1})),
            ("retry/wrong_epoch", _entry(job_run, "job.retry", {**valid_retry, "writer_epoch": 2})),
            ("retry/wrong_lease_id", _entry(job_run, "job.retry", {**valid_retry, "lease_id": lease_2})),
        ]

        valid_terminal_run: dict[str, JsonValue] = {
            "job_id": job_run,
            "attempt": 1,
            "writer_epoch": 1,
            "lease_id": lease_1,
            "state": "cancelled",
            "prior_state": "running",
            "reason": None,
            "result_digest": None,
            "finished_at": ts,
        }
        job_bad_cases += [
            (
                "terminal_run/prior_leased",
                _entry(job_run, "job.terminal", {**valid_terminal_run, "prior_state": "leased"}),
            ),
            (
                "terminal_run/prior_queued_fenced",
                _entry(job_run, "job.terminal", {**valid_terminal_run, "prior_state": "queued"}),
            ),
            (
                "terminal_run/prior_queued_nulls",
                _entry(
                    job_run,
                    "job.terminal",
                    {**valid_terminal_run, "prior_state": "queued", "writer_epoch": None, "lease_id": None},
                ),
            ),
            ("terminal_run/attempt_2", _entry(job_run, "job.terminal", {**valid_terminal_run, "attempt": 2})),
            ("terminal_run/epoch_2", _entry(job_run, "job.terminal", {**valid_terminal_run, "writer_epoch": 2})),
            ("terminal_run/epoch_none", _entry(job_run, "job.terminal", {**valid_terminal_run, "writer_epoch": None})),
            ("terminal_run/lease_2", _entry(job_run, "job.terminal", {**valid_terminal_run, "lease_id": lease_2})),
            ("terminal_run/lease_none", _entry(job_run, "job.terminal", {**valid_terminal_run, "lease_id": None})),
        ]

        valid_terminal_queued: dict[str, JsonValue] = {
            "job_id": job_queued,
            "attempt": 1,
            "writer_epoch": None,
            "lease_id": None,
            "state": "cancelled",
            "prior_state": "queued",
            "reason": None,
            "result_digest": None,
            "finished_at": ts,
        }
        job_bad_cases += [
            (
                "terminal_queued/non_null_epoch",
                _entry(job_queued, "job.terminal", {**valid_terminal_queued, "writer_epoch": 1}),
            ),
            (
                "terminal_queued/non_null_lease",
                _entry(job_queued, "job.terminal", {**valid_terminal_queued, "lease_id": lease_1}),
            ),
            (
                "terminal_queued/non_null_both",
                _entry(
                    job_queued,
                    "job.terminal",
                    {**valid_terminal_queued, "writer_epoch": 1, "lease_id": lease_1},
                ),
            ),
        ]
        for label, bad_job_entry in job_bad_cases:
            _assert_rejected(jobs, "p_jobs_", bad_job_entry, label)

        inv_bad_cases: list[tuple[str, LedgerEntry]] = [
            # v1 provider.settled mismatches
            (
                "settled_v1/inv1_wrong_prior",
                _entry(
                    inv_1,
                    "provider.settled",
                    {
                        "invocation_id": inv_1,
                        "prior_state": "outcome_unknown",
                        "usage_digest": d_cmp,
                        "complete": True,
                    },
                    hv=1,
                ),
            ),
            (
                "settled_v1/inv2_wrong_prior",
                _entry(
                    inv_2,
                    "provider.settled",
                    {"invocation_id": inv_2, "prior_state": "reserved", "usage_digest": d_cmp, "complete": True},
                    hv=1,
                ),
            ),
            (
                "settled_v1/inv3_already_settled",
                _entry(
                    inv_3,
                    "provider.settled",
                    {"invocation_id": inv_3, "prior_state": "reserved", "usage_digest": d_cmp, "complete": True},
                    hv=1,
                ),
            ),
            # v2 provider.settled mismatches
            (
                "settled_v2/inv1_wrong_prior",
                _entry(
                    inv_1,
                    "provider.settled",
                    {
                        "invocation_id": inv_1,
                        "prior_state": "outcome_unknown",
                        "prior_usage_digest": None,
                        "usage_digest": d_cmp,
                        "complete": True,
                    },
                    hv=2,
                ),
            ),
            (
                "settled_v2/inv1_wrong_prior_digest",
                _entry(
                    inv_1,
                    "provider.settled",
                    {
                        "invocation_id": inv_1,
                        "prior_state": "reserved",
                        "prior_usage_digest": d_inc,
                        "usage_digest": d_cmp,
                        "complete": True,
                    },
                    hv=2,
                ),
            ),
            (
                "settled_v2/inv2_wrong_prior",
                _entry(
                    inv_2,
                    "provider.settled",
                    {
                        "invocation_id": inv_2,
                        "prior_state": "reserved",
                        "prior_usage_digest": d_inc,
                        "usage_digest": d_cmp,
                        "complete": True,
                    },
                    hv=2,
                ),
            ),
            (
                "settled_v2/inv2_null_prior_digest",
                _entry(
                    inv_2,
                    "provider.settled",
                    {
                        "invocation_id": inv_2,
                        "prior_state": "outcome_unknown",
                        "prior_usage_digest": None,
                        "usage_digest": d_cmp,
                        "complete": True,
                    },
                    hv=2,
                ),
            ),
            (
                "settled_v2/inv2_other_prior_digest",
                _entry(
                    inv_2,
                    "provider.settled",
                    {
                        "invocation_id": inv_2,
                        "prior_state": "outcome_unknown",
                        "prior_usage_digest": d_other,
                        "usage_digest": d_cmp,
                        "complete": True,
                    },
                    hv=2,
                ),
            ),
            (
                "settled_v2/inv3_already_settled_cmp",
                _entry(
                    inv_3,
                    "provider.settled",
                    {
                        "invocation_id": inv_3,
                        "prior_state": "outcome_unknown",
                        "prior_usage_digest": d_cmp,
                        "usage_digest": d_other,
                        "complete": True,
                    },
                    hv=2,
                ),
            ),
            (
                "settled_v2/inv3_already_settled_inc",
                _entry(
                    inv_3,
                    "provider.settled",
                    {
                        "invocation_id": inv_3,
                        "prior_state": "reserved",
                        "prior_usage_digest": None,
                        "usage_digest": d_inc,
                        "complete": False,
                    },
                    hv=2,
                ),
            ),
        ]
        for label, bad_inv_entry in inv_bad_cases:
            _assert_rejected(invocations, "p_provider_invocations_", bad_inv_entry, label)


def test_pre_recovery_stale_epoch_leases_are_rejected_by_epoch_guard_with_zero_writes(
    trusted_tmp: Path,
    os_: OsAdapters,
    clock: FakeClock,
) -> None:
    """CL-T5-B5: Before ``recover(e2)``, epoch-1 leases matching SQLite rows are rejected by ``e2`` epoch guard."""
    root = trusted_tmp / "cl-t5-b5"
    rt1 = open_kernel_job_runtime(root, os_)
    store_id = rt1.store.store_id
    e1 = rt1.lease.epoch
    try:
        service1, store1 = kernel_job_service(rt1, clock)
        job_run_id = enqueue_job(service1, store1, owner_id=OWNER, payload=b"b5-running").job_id
        lease_run_e1 = _running(service1, e1, clock)
        job_leased_id = enqueue_job(service1, store1, owner_id=OWNER, payload=b"b5-leased").job_id
        lease_leased_e1 = _lease(service1, e1, clock)
        assert (lease_run_e1.job_id, lease_run_e1.attempt, lease_run_e1.writer_epoch) == (job_run_id, 1, e1)
        assert (lease_leased_e1.job_id, lease_leased_e1.attempt, lease_leased_e1.writer_epoch) == (
            job_leased_id,
            1,
            e1,
        )
    finally:
        rt1.close()

    rt2 = reopen_kernel_job_runtime(root, store_id, os_)
    try:
        e2 = rt2.lease.epoch
        assert e2 > e1
        service2, store2 = kernel_job_service(rt2, clock)

        # Do NOT call recover(e2): SQLite rows still match epoch e1's exact (attempt=1, writer_epoch=e1, lease_id).
        run_row = _job_row(store2, job_run_id)
        leased_row = _job_row(store2, job_leased_id)
        assert (run_row.state, run_row.attempt, run_row.writer_epoch, run_row.lease_id) == (
            JobState.RUNNING,
            1,
            e1,
            lease_run_e1.lease_id,
        )
        assert (leased_row.state, leased_row.attempt, leased_row.writer_epoch, leased_row.lease_id) == (
            JobState.LEASED,
            1,
            e1,
            lease_leased_e1.lease_id,
        )

        before_len = _ledger_len(rt2)
        before_tables = _tables(rt2)
        stale_calls: tuple[tuple[str, Callable[[], object]], ...] = (
            ("complete_success", partial(service2.complete, lease_run_e1, JobOutcome.success())),
            (
                "complete_retry",
                partial(
                    service2.complete,
                    lease_run_e1,
                    JobOutcome.failure(JobErrorCode.HANDLER_FAILED, retryable=True),
                ),
            ),
            ("reserve_invocation", partial(service2.reserve_invocation, lease_run_e1, RESERVE)),
            ("start_leased", partial(service2.start, lease_leased_e1)),
            ("job_spec", partial(service2.job_spec, lease_run_e1)),
        )
        for name, action in stale_calls:
            with pytest.raises(BrainError) as caught:
                action()
            assert caught.value.code is ErrorCode.REVISION_CONFLICT, name
            assert caught.value.message == "revision conflict", name
            assert (_ledger_len(rt2), _tables(rt2)) == (before_len, before_tables), name
    finally:
        rt2.close()
