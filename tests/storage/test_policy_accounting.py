"""I3-4 oracle: self-contained ``policy.db`` accounting, ``restore_policy`` diff/locks/carry-forward & hooks.

Requirement sources: spec rev 22 §5.7, §11.3, §20 case 102; plan I3-4 Step 2-4 & ``I3-1-N2``.
"""

from __future__ import annotations

import base64
import shutil
import sqlite3
import struct
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from superbrain.adapters.os import os_adapters
from superbrain.application.jobs import JobService
from superbrain.composition.kernel_projections import kernel_store_extensions
from superbrain.composition.migrate_entry import migrate_offline
from superbrain.core._kernel_approval import (
    RISK_POLICY_VERSION,
    ApprovalAction,
    ApprovalChannel,
    ApprovalMessage,
    Layer2State,
    RecoveryScope,
    RiskLevel,
    SignerEnrollment,
    classify_policy_change_risk,
    policy_change_subject_id,
)
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.kernel import (
    DaemonConfig,
    InvocationState,
    JobErrorCode,
    JobOutcome,
    ResourceDigest,
    UsageRecord,
    UsageReservation,
)
from superbrain.ports.policy import IntentKind
from superbrain.storage.backup import BackupManifest, create_policy_backup, create_store_backup
from superbrain.storage.kernel_schema import KERNEL_POLICY_MIGRATIONS, KERNEL_STORE_MIGRATIONS
from superbrain.storage.layout import DataRoot
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.restore import restore_policy, restore_store
from superbrain.storage.runtime import open_runtime
from superbrain.storage.schema import SchemaInfo, read_schema_info
from tests.storage.conftest import maintenance_lease
from tests.support.clock import FakeClock
from tests.support.inc2_fixture import (
    enqueue_job,
    kernel_job_service,
    open_kernel_job_runtime,
    reopen_kernel_job_runtime,
)
from tests.support.kernel_auth import make_bootstrap_auth, seed_principal_and_credential

OWNER = "dan"
D_DIFF = digest_bytes(b'{"reconcile_accounting":true}')


def _ssh_enrollment(tag: str = "acct") -> SignerEnrollment:
    raw = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", len(raw)) + raw
    return SignerEnrollment(
        owner_id=OWNER,
        channel=ApprovalChannel.SSH_KEY,
        public_key="ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + f" {tag}@devbox",
    )


def _start_job(service: JobService, store: Any, epoch: int, now: datetime) -> Any:
    enqueue_job(service, store, owner_id=OWNER)
    lease = service.lease_next(epoch, now)
    assert lease is not None
    service.start(lease)
    return lease


def test_job_service_persists_accounting_in_policy_db_before_brain_db_and_recovers_mid_crash(
    trusted_tmp: Path, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    os_ = os_adapters(clock=clock)
    root_path = trusted_tmp / "acct-order"
    rt = open_kernel_job_runtime(root_path, os_, role="i3-4-acct")
    try:
        store_id = rt.store.store_id
        period = clock.now().strftime("%Y-%m-%d")
        service, kernel_store = kernel_job_service(rt, clock)
        lease1 = _start_job(service, kernel_store, rt.lease.epoch, clock.now())

        # Normal lifecycle: reserve -> incomplete settle (outcome_unknown) -> final settle ("1.25").
        inv1 = service.reserve_invocation(lease1, UsageReservation(max_amount="3.5"))
        rec = rt.policy.accounting_invocation(inv1)
        assert rec is not None
        assert (rec.job_id, rec.owner_id, rec.reserved_amount, rec.settled_amount, rec.state) == (
            lease1.job_id,
            OWNER,
            "3.5",
            None,
            InvocationState.RESERVED,
        )
        assert rec.period_key == period
        assert rt.policy.period_committed_total(OWNER, period) == "3.5"

        service.settle_usage(inv1, UsageRecord(amount=None, complete=False))
        rec_u = rt.policy.accounting_invocation(inv1)
        assert rec_u is not None and rec_u.state is InvocationState.OUTCOME_UNKNOWN and rec_u.reserved_amount == "3.5"
        assert rt.policy.period_committed_total(OWNER, period) == "3.5"

        service.settle_usage(inv1, UsageRecord(amount="1.25", complete=True))
        rec_s = rt.policy.accounting_invocation(inv1)
        assert rec_s is not None and rec_s.state is InvocationState.SETTLED and rec_s.settled_amount == "1.25"
        assert rt.policy.period_committed_total(OWNER, period) == "1.25"

        # Simulated crash AFTER policy.db reserves and BEFORE brain.db commits provider.reserved!
        lease2 = _start_job(service, kernel_store, rt.lease.epoch, clock.now())

        class _CrashBeforeBrainCommit(RuntimeError):
            pass

        orig_transact = kernel_store.transact

        def _fail_on_reserve_tx(op: Any) -> Any:
            if len(rt.policy.list_accounting_invocations(owner_id=OWNER, period_key=period)) == 2:
                raise _CrashBeforeBrainCommit("killed between policy.db and brain.db")
            return orig_transact(op)

        with monkeypatch.context() as mp:
            mp.setattr(kernel_store, "transact", _fail_on_reserve_tx)
            with pytest.raises(_CrashBeforeBrainCommit):
                service.reserve_invocation(lease2, UsageReservation(max_amount="2.75"))

        # Even before recovery AND with store/cas untouched for inv2, policy.db holds the 2.75 reservation!
        rows = rt.policy.list_accounting_invocations(owner_id=OWNER, period_key=period)
        assert len(rows) == 2
        orphaned = [r for r in rows if r.invocation_id != inv1][0]
        assert orphaned.state is InvocationState.RESERVED and orphaned.reserved_amount == "2.75"
        assert rt.policy.period_committed_total(OWNER, period) == "4"
    finally:
        if not rt.store.closed:
            rt.close()

    # Delete store/cas files cleanly on disk only to prove policy.db accounting never reads store/cas/!
    shutil.rmtree(DataRoot.at(root_path).cas_dir)
    DataRoot.at(root_path).cas_dir.mkdir()
    os_.permissions.secure_directory(DataRoot.at(root_path).cas_dir)

    # Reopen at new epoch & recover -> orphaned reservation becomes outcome_unknown keeping "2.75"!
    rt2 = reopen_kernel_job_runtime(root_path, store_id, os_)
    try:
        svc2, _ = kernel_job_service(rt2, clock)
        svc2.recover(rt2.lease.epoch)
        recovered = rt2.policy.accounting_invocation(orphaned.invocation_id)
        assert recovered is not None
        assert recovered.state is InvocationState.OUTCOME_UNKNOWN
        assert recovered.reserved_amount == "2.75"
        assert rt2.policy.period_committed_total(OWNER, period) == "4"
    finally:
        rt2.close()


def test_migrate_from_4_3_to_5_4_preserves_existing_provider_invocation_rows(
    trusted_tmp: Path, clock: FakeClock
) -> None:
    os_ = os_adapters(clock=clock)
    root_path = trusted_tmp / "mig-43-to-54"
    handlers, kinds = kernel_store_extensions()
    rt = open_runtime(
        root_path,
        os_,
        handlers=handlers,
        kinds=kinds,
        store_migrations=KERNEL_STORE_MIGRATIONS[:4],
        policy_migrations=KERNEL_POLICY_MIGRATIONS[:3],
    )
    try:
        store_id = rt.store.store_id
        svc, kstore = kernel_job_service(rt, clock)
        l_settled = _start_job(svc, kstore, rt.lease.epoch, clock.now())
        inv_settled = svc.reserve_invocation(l_settled, UsageReservation(max_amount="4"))
        svc.settle_usage(inv_settled, UsageRecord(amount="1.5", complete=True))

        l_unknown = _start_job(svc, kstore, rt.lease.epoch, clock.now())
        inv_unknown = svc.reserve_invocation(l_unknown, UsageReservation(max_amount="6.5"))
    finally:
        rt.close()

    # Reopen at (4, 3) and recover epoch so inv_unknown transitions to outcome_unknown in brain.db.
    rt_mid = open_runtime(
        root_path,
        os_,
        handlers=handlers,
        kinds=kinds,
        store_migrations=KERNEL_STORE_MIGRATIONS[:4],
        policy_migrations=KERNEL_POLICY_MIGRATIONS[:3],
    )
    try:
        svc_mid, kstore_mid = kernel_job_service(rt_mid, clock)
        svc_mid.recover(rt_mid.lease.epoch)
        l_reserved = _start_job(svc_mid, kstore_mid, rt_mid.lease.epoch, clock.now())
        inv_reserved = svc_mid.reserve_invocation(l_reserved, UsageReservation(max_amount="2.25"))
    finally:
        rt_mid.close()

    assert read_schema_info(DataRoot.at(root_path).store_db) == SchemaInfo(4, 4, store_id)
    assert read_schema_info(DataRoot.at(root_path).policy_db) == SchemaInfo(3, 3, store_id)

    cfg = DaemonConfig(
        version=1,
        data_root=root_path,
        expected_store_id=store_id,
        cert_path=trusted_tmp / "unused.pem",
        key_path=trusted_tmp / "unused.key",
    )
    rep = migrate_offline(cfg, os_)
    assert (rep.policy_report.to_version, rep.store_report.to_version) == (4, 5)

    rt_after = reopen_kernel_job_runtime(root_path, store_id, os_)
    try:
        # Both brain.db p_provider_invocations_state AND policy.db accounting_invocations keep all 3 rows!
        _, kstore_after = kernel_job_service(rt_after, clock)
        b_settled = kstore_after.transact(lambda tx: tx.read_invocation(inv_settled))
        b_unknown = kstore_after.transact(lambda tx: tx.read_invocation(inv_unknown))
        b_reserved = kstore_after.transact(lambda tx: tx.read_invocation(inv_reserved))
        assert b_settled is not None and b_settled.state is InvocationState.SETTLED
        assert b_unknown is not None and b_unknown.state is InvocationState.OUTCOME_UNKNOWN
        assert b_reserved is not None and b_reserved.state is InvocationState.RESERVED

        p_settled = rt_after.policy.accounting_invocation(inv_settled)
        p_unknown = rt_after.policy.accounting_invocation(inv_unknown)
        p_reserved = rt_after.policy.accounting_invocation(inv_reserved)
        assert (
            p_settled is not None and p_settled.state is InvocationState.SETTLED and p_settled.settled_amount == "1.5"
        )
        assert p_unknown is not None and p_unknown.state is InvocationState.OUTCOME_UNKNOWN
        assert p_unknown.reserved_amount == "6.5"
        assert p_reserved is not None and p_reserved.state is InvocationState.RESERVED
        assert p_reserved.reserved_amount == "2.25"
    finally:
        rt_after.close()


def test_case_102_cap_hit_and_outcome_unknown_hold_survive_store_restore(trusted_tmp: Path, clock: FakeClock) -> None:
    os_ = os_adapters(clock=clock)
    root_path = trusted_tmp / "case102-store"
    rt = open_kernel_job_runtime(root_path, os_, role="c102-store")
    try:
        store_id = rt.store.store_id
        rt.policy.set_period_cap(OWNER, "5")
        backup_empty = create_store_backup(rt.store, os_, clock.now())

        svc, kstore = kernel_job_service(rt, clock)
        # 1) Invocation with outcome_unknown ("3") + settled invocation ("2") = 5 cap hit, 0 running jobs!
        l1 = _start_job(svc, kstore, rt.lease.epoch, clock.now())
        inv_u = svc.reserve_invocation(l1, UsageReservation(max_amount="3"))
        svc.settle_usage(inv_u, UsageRecord(amount=None, complete=False))
        svc.complete(l1, JobOutcome.failure(JobErrorCode.HANDLER_FAILED, retryable=False))

        l2 = _start_job(svc, kstore, rt.lease.epoch, clock.now())
        inv_s = svc.reserve_invocation(l2, UsageReservation(max_amount="2"))
        svc.settle_usage(inv_s, UsageRecord(amount="2", complete=True))
        svc.complete(l2, JobOutcome.success())

        # Cap is hit (3 + 2 = 5); extra 0.5 MUST fail BEFORE restore.
        l3 = _start_job(svc, kstore, rt.lease.epoch, clock.now())
        with pytest.raises(BrainError) as err_before:
            svc.reserve_invocation(l3, UsageReservation(max_amount="0.5"))
        assert err_before.value.code is ErrorCode.CAPABILITY_UNAVAILABLE
    finally:
        rt.close()

    # Restore store/ back to empty snapshot taken BEFORE any invocations.
    clock.advance(timedelta(minutes=5))
    with maintenance_lease(root_path) as (root, lease):
        pol = PolicyStore.open(root, lease, os_, migrations=KERNEL_POLICY_MIGRATIONS)
        try:
            restore_store(root, lease, os_, backup_empty, pol, clock.now(), migrations=KERNEL_STORE_MIGRATIONS)
        finally:
            pol.close()

    rt_after = reopen_kernel_job_runtime(root_path, store_id, os_)
    try:
        svc_after, kstore_after = kernel_job_service(rt_after, clock)
        unknown_rec = rt_after.policy.accounting_invocation(inv_u)
        assert unknown_rec is not None and unknown_rec.state is InvocationState.OUTCOME_UNKNOWN
        assert unknown_rec.reserved_amount == "3"

        # Fresh job in restored store MUST STILL hit the 5 cap and reject 0.5!
        l_new = _start_job(svc_after, kstore_after, rt_after.lease.epoch, clock.now())
        with pytest.raises(BrainError) as err_after:
            svc_after.reserve_invocation(l_new, UsageReservation(max_amount="0.5"))
        assert err_after.value.code is ErrorCode.CAPABILITY_UNAVAILABLE

        # If cap is raised to 6, remaining capacity is 6 - (3 + 2) = 1 (not 3!): 1.5 rejected, 1 ok.
        rt_after.policy.set_period_cap(OWNER, "6")
        with pytest.raises(BrainError) as err_hold:
            svc_after.reserve_invocation(l_new, UsageReservation(max_amount="1.5"))
        assert err_hold.value.code is ErrorCode.CAPABILITY_UNAVAILABLE
        inv_ok = svc_after.reserve_invocation(l_new, UsageReservation(max_amount="1"))
        assert inv_ok
    finally:
        rt_after.close()


def test_restore_policy_preview_immediate_locks_carry_forward_and_reconcile_unlock(
    trusted_tmp: Path, clock: FakeClock
) -> None:
    from superbrain.storage.restore import PolicyRestoreStageHook, preview_policy_restore, read_restore_epoch

    t0 = clock.now()
    day0 = t0.strftime("%Y-%m-%d")
    os_ = os_adapters(clock=clock)
    root_path = trusted_tmp / "case102-policy"
    rt = open_kernel_job_runtime(root_path, os_, role="c102-pol")
    store_id = rt.store.store_id
    layout = DataRoot.at(root_path)

    # Seed signer1 (will stay), signer_rev (revoked later), harness cred (revoked later), quarantine1, tombstone1.
    s1 = rt.policy.enroll_first_signer(_ssh_enrollment("s1"))
    seeded_harness = seed_principal_and_credential(rt.policy, owner_id=OWNER, harness_id="claude-code", machine_id="m1")
    rev_cred_id = seeded_harness.credential_id
    rt.policy.set_layer2_state(
        harness_id="claude-code",
        host_version="1.0.0",
        config_digest="sha256:" + "1" * 64,
        state=Layer2State.VERIFIED,
    )
    # Enroll signer2 via s1 high-risk approval, then take policy backup bak_t0.
    s2_enr = _ssh_enrollment("s2")
    n_s2 = rt.policy.issue_nonce(
        action=ApprovalAction.SIGNER_ENROLL, subject_id=s2_enr.subject_id, risk_level=RiskLevel.HIGH
    )
    m_s2 = ApprovalMessage(
        store_id=store_id,
        owner_id=OWNER,
        trust_generation=rt.policy.trust_generation(),
        action=ApprovalAction.SIGNER_ENROLL,
        subject_id=s2_enr.subject_id,
        subject_revision=1,
        resource_digests=(ResourceDigest("signer", s2_enr.key_digest),),
        target_files=(),
        risk_level=RiskLevel.HIGH,
        risk_policy_version=RISK_POLICY_VERSION,
        recovery_scope=RecoveryScope.NONE,
        nonce=n_s2.nonce,
        expires_at=n_s2.expires_at,
    )
    s2 = rt.policy.enroll_signer(
        s2_enr, approval=m_s2, approver_signer_id=s1.signer_id, channel=ApprovalChannel.SSH_KEY
    )
    d_q_extra = digest_bytes(b"quarantine-added-after-backup")
    tomb_extra_id = new_id()
    bak_t0 = create_policy_backup(rt.policy, os_, t0)

    # Mutate live authority AFTER backup: revoke signer s2, revoke harness credential, add quarantine & tombstone.
    clock.advance(timedelta(days=1))
    day1 = clock.now().strftime("%Y-%m-%d")
    n_rev = rt.policy.issue_nonce(
        action=ApprovalAction.SIGNER_REVOKE, subject_id=s2.signer_id, risk_level=RiskLevel.HIGH
    )
    m_rev = ApprovalMessage(
        store_id=store_id,
        owner_id=OWNER,
        trust_generation=rt.policy.trust_generation(),
        action=ApprovalAction.SIGNER_REVOKE,
        subject_id=s2.signer_id,
        subject_revision=1,
        resource_digests=(ResourceDigest("signer", s2.key_digest),),
        target_files=(),
        risk_level=RiskLevel.HIGH,
        risk_policy_version=RISK_POLICY_VERSION,
        recovery_scope=RecoveryScope.NONE,
        nonce=n_rev.nonce,
        expires_at=n_rev.expires_at,
    )
    rt.policy.revoke_signer(
        s2.signer_id, approval=m_rev, approver_signer_id=s1.signer_id, channel=ApprovalChannel.SSH_KEY
    )
    rt.policy.record_authorized_revocation(
        rev_cred_id,
        make_bootstrap_auth(
            store_id=store_id,
            owner_id=OWNER,
            action="credential_revoke",
            subject_id=rev_cred_id,
            trust_generation=rt.policy.trust_generation(),
            expires_at=clock.now() + timedelta(hours=1),
        ),
    )
    rt.policy.record_intent(IntentKind.QUARANTINE, {"digest": d_q_extra})
    rt.policy.record_intent(IntentKind.TOMBSTONE, {"holder_kind": "event", "holder_id": tomb_extra_id})

    # Record an outcome_unknown invocation AND set signer_reset_recorded='1' (carry-forward across 2nd restore!).
    svc, kstore = kernel_job_service(rt, clock)
    l_unk = _start_job(svc, kstore, rt.lease.epoch, clock.now())
    inv_unk = svc.reserve_invocation(l_unk, UsageReservation(max_amount="2.25"))
    svc.settle_usage(inv_unk, UsageRecord(amount=None, complete=False))
    with rt.policy._immediate() as db:
        db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('signer_reset_recorded', '1')")
    assert rt.policy.signer_reset_recorded() is True
    rt.close()

    # Day 2: preview_policy_restore MUST show exact revived signers/credentials, removed quarantine/tombstone & periods.
    clock.advance(timedelta(days=1))
    day2 = clock.now().strftime("%Y-%m-%d")
    diff = preview_policy_restore(
        layout, bak_t0, store_id=store_id, os_=os_, now=clock.now(), migrations=KERNEL_POLICY_MIGRATIONS
    )
    assert [s.signer_id for s in diff.revived_signers] == [s2.signer_id]
    assert rev_cred_id in diff.revived_credential_ids
    assert d_q_extra in diff.removed_quarantines
    assert ("event", tomb_extra_id) in diff.removed_tombstones
    assert diff.affected_periods == ("2026-10", "2026-11", day0, day1, day2)
    assert diff.next_trust_generation > diff.backup_trust_generation

    # First restore_policy with PolicyRestoreStageHook proves stage locks + hook run BEFORE swap/READY.
    staged_locks: list[int] = []

    class _PolicyHook(PolicyRestoreStageHook):
        def on_stage_policy(
            self,
            live_policy_db: Path | None,
            staged_policy_db: sqlite3.Connection,
            *,
            manifest: BackupManifest,
            now: datetime,
            trust_generation: int,
        ) -> None:
            _ = live_policy_db, manifest, now, trust_generation
            cnt = staged_policy_db.execute("SELECT COUNT(*) FROM accounting_locks WHERE state = 'locked'").fetchone()[0]
            staged_locks.append(int(cnt))

    hook = _PolicyHook()
    with maintenance_lease(root_path) as (root, lease):
        restore_policy(
            root,
            lease,
            os_,
            bak_t0,
            store_id=store_id,
            now=clock.now(),
            migrations=KERNEL_POLICY_MIGRATIONS,
            stage_hooks=(hook,),
        )
    assert staged_locks == [5]

    # Very first request after restore_policy MUST be blocked immediately by accounting_locks!
    rt_locked = reopen_kernel_job_runtime(root_path, store_id, os_)
    try:
        svc_locked, kstore_locked = kernel_job_service(rt_locked, clock)
        l_blocked = _start_job(svc_locked, kstore_locked, rt_locked.lease.epoch, clock.now())
        with pytest.raises(BrainError) as lock_err:
            svc_locked.reserve_invocation(l_blocked, UsageReservation(max_amount="0.5"))
        assert lock_err.value.code is ErrorCode.CAPABILITY_UNAVAILABLE
        assert rt_locked.policy.signer_reset_recorded() is True
        kept_unk = rt_locked.policy.accounting_invocation(inv_unk)
        assert (
            kept_unk is not None
            and kept_unk.state is InvocationState.OUTCOME_UNKNOWN
            and kept_unk.reserved_amount == "2.25"
        )
    finally:
        rt_locked.close()

    # Second restore_policy on Day 4 BEFORE reconciling MUST carry forward Day 0..2 locks, outcome_unknown & flag!
    clock.advance(timedelta(days=2))
    day3 = (t0 + timedelta(days=3)).strftime("%Y-%m-%d")
    day4 = clock.now().strftime("%Y-%m-%d")
    with maintenance_lease(root_path) as (root, lease):
        restore_policy(
            root, lease, os_, bak_t0, store_id=store_id, now=clock.now(), migrations=KERNEL_POLICY_MIGRATIONS
        )

    rt_carried = reopen_kernel_job_runtime(root_path, store_id, os_)
    try:
        locks = rt_carried.policy.list_accounting_locks(state="locked")
        assert {lk.period_key for lk in locks} == {"2026-10", "2026-11", day0, day1, day2, day3, day4}
        assert rt_carried.policy.signer_reset_recorded() is True
        carried_unk = rt_carried.policy.accounting_invocation(inv_unk)
        assert carried_unk is not None and carried_unk.reserved_amount == "2.25"

        svc_c, kstore_c = kernel_job_service(rt_carried, clock)
        l_blocked2 = _start_job(svc_c, kstore_c, rt_carried.lease.epoch, clock.now())
        with pytest.raises(BrainError) as lock_err2:
            svc_c.reserve_invocation(l_blocked2, UsageReservation(max_amount="0.25"))
        assert lock_err2.value.code is ErrorCode.CAPABILITY_UNAVAILABLE

        # Policy_change with reconcile_accounting is HIGH: terminal MUST be refused even with verified layer 2!
        assert (
            classify_policy_change_risk(
                widens_capture_or_egress=False, sets_review_harness_or_command=False, reconcile_accounting=True
            )
            is RiskLevel.HIGH
        )
        rev = rt_carried.policy.policy_revision()
        cur_epoch = read_restore_epoch(layout, schema_version=5, os_=os_)
        subj = policy_change_subject_id(
            repo_id_or_global="global",
            base_policy_revision=rev,
            base_trust_generation=rt_carried.policy.trust_generation(),
            base_restore_epoch=cur_epoch,
            policy_diff_digest=D_DIFF,
        )
        n_unlock = rt_carried.policy.issue_nonce(
            action=ApprovalAction.POLICY_CHANGE, subject_id=subj, risk_level=RiskLevel.HIGH
        )
        m_unlock = ApprovalMessage(
            store_id=store_id,
            owner_id=OWNER,
            trust_generation=rt_carried.policy.trust_generation(),
            action=ApprovalAction.POLICY_CHANGE,
            subject_id=subj,
            subject_revision=1,
            resource_digests=(ResourceDigest("policy_diff", D_DIFF),),
            target_files=(),
            risk_level=RiskLevel.HIGH,
            risk_policy_version=RISK_POLICY_VERSION,
            recovery_scope=RecoveryScope.NONE,
            nonce=n_unlock.nonce,
            expires_at=n_unlock.expires_at,
        )
        with pytest.raises(BrainError) as term_err:
            rt_carried.policy.reconcile_accounting_locks(
                repo_id_or_global="global",
                base_policy_revision=rev,
                base_restore_epoch=cur_epoch,
                policy_diff_digest=D_DIFF,
                approval=m_unlock,
                signer_id=None,
                channel=ApprovalChannel.TERMINAL,
                expected_restore_epoch=cur_epoch,
            )
        assert term_err.value.code is ErrorCode.CAPABILITY_UNAVAILABLE

        # Signer approval unlocks -> next reserve_invocation immediately succeeds!
        reconciled = rt_carried.policy.reconcile_accounting_locks(
            repo_id_or_global="global",
            base_policy_revision=rev,
            base_restore_epoch=cur_epoch,
            policy_diff_digest=D_DIFF,
            approval=m_unlock,
            signer_id=s1.signer_id,
            channel=ApprovalChannel.SSH_KEY,
            expected_restore_epoch=cur_epoch,
        )
        assert len(reconciled) == 7
        assert rt_carried.policy.list_accounting_locks(state="locked") == ()
        assert svc_c.reserve_invocation(l_blocked2, UsageReservation(max_amount="0.25"))
    finally:
        rt_carried.close()
