"""I3-4 Round-2 RED regressions for storage/migration invariants (R01, R03, R05, N1, N2).

Covers uncheckpointed ``brain.db-wal`` accounting preservation and closed failure on missing/corrupt CAS
descriptors during ``(4,3)->(5,4)`` migration (R01), policy-restore ``accounting_locks`` carry-forward +
``risk_policy_version``/``resource_digests``/``policy_revision`` enforcement (R03), intact live store
admission with abandoned ``READY`` ``store.restoring/`` stages (R05), strict integer ``schema_version``
in ``pending_restore_tombstones.json`` (N1), and durable ``restore_epoch.json`` staging before ``brain.db``
publication in ``Store.create`` (N2).
"""

from __future__ import annotations

import base64
import json
import shutil
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
    RecoveryScope,
    RiskLevel,
    SignerEnrollment,
    policy_change_subject_id,
)
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.kernel import DaemonConfig, InvocationState, ResourceDigest, UsageReservation
from superbrain.ports.os import OsAdapters
from superbrain.storage.backup import create_policy_backup
from superbrain.storage.cas import RetentionClass, blob_path, held_digests
from superbrain.storage.kernel_schema import KERNEL_POLICY_MIGRATIONS, KERNEL_STORE_MIGRATIONS
from superbrain.storage.kinds import KindRegistry
from superbrain.storage.layout import DataRoot, secure_subdirectories
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.restore import drain_published_restore_effects, read_restore_epoch, restore_policy
from superbrain.storage.runtime import admit_existing_pair, open_runtime, open_runtime_under_lease
from superbrain.storage.sqlite import open_immutable, open_readonly
from superbrain.storage.store import Store
from superbrain.storage.swap import READY
from tests.storage.conftest import DEMO_KINDS, maintenance_lease
from tests.support.clock import FakeClock
from tests.support.inc2_fixture import (
    enqueue_job,
    kernel_job_service,
    open_kernel_job_runtime,
    reopen_kernel_job_runtime,
)

OWNER = "dan"
D_DIFF = digest_bytes(b'{"reconcile_accounting":true}')


def _ssh_enrollment(tag: str = "r2") -> SignerEnrollment:
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


def test_r01_migrate_4_3_to_5_4_preserves_uncheckpointed_wal_and_rejects_corrupt_cas_descriptor(
    trusted_tmp: Path, clock: FakeClock
) -> None:
    """I3-4-R01: (4,3)->(5,4) reads brain.db-wal frames via open_readonly and fails closed on corrupt/missing CAS."""
    os_ = os_adapters(clock=clock)
    handlers, kinds = kernel_store_extensions()
    period = clock.now().strftime("%Y-%m-%d")

    # Part A: invocation row exists ONLY in uncheckpointed store/brain.db-wal at migration time.
    wal_root = trusted_tmp / "r01-wal-only"
    rt = open_runtime(
        wal_root,
        os_,
        handlers=handlers,
        kinds=kinds,
        store_migrations=KERNEL_STORE_MIGRATIONS[:4],
        policy_migrations=KERNEL_POLICY_MIGRATIONS[:3],
    )
    layout = DataRoot.at(wal_root)
    try:
        store_id = rt.store.store_id
        rt.store._db.execute("PRAGMA wal_autocheckpoint = 0")
        svc, kstore = kernel_job_service(rt, clock)
        lease = _start_job(svc, kstore, rt.lease.epoch, clock.now())
        inv_wal = svc.reserve_invocation(lease, UsageReservation(max_amount="2.5"))
        snap_dir = trusted_tmp / "wal-snap"
        snap_dir.mkdir()
        assert (layout.store_dir / "brain.db-wal").exists()
        shutil.copy2(layout.store_db, snap_dir / "brain.db")
        shutil.copy2(layout.store_dir / "brain.db-wal", snap_dir / "brain.db-wal")
    finally:
        rt.close()

    for suffix in ("brain.db", "brain.db-wal", "brain.db-shm"):
        p = layout.store_dir / suffix
        if p.exists():
            p.unlink()
    shutil.copy2(snap_dir / "brain.db", layout.store_db)
    shutil.copy2(snap_dir / "brain.db-wal", layout.store_dir / "brain.db-wal")
    os_.permissions.secure_file(layout.store_db)
    os_.permissions.secure_file(layout.store_dir / "brain.db-wal")

    # Confirm the simulated post-crash state: main DB file has 0 rows, while WAL-aware readonly sees 1 row.
    imm = open_immutable(layout.store_db)
    try:
        imm_cnt = imm.execute(
            "SELECT COUNT(*) FROM p_provider_invocations_state WHERE invocation_id = ?", (inv_wal,)
        ).fetchone()[0]
    finally:
        imm.close()
    assert imm_cnt == 0

    ro = open_readonly(layout.store_db)
    try:
        ro_cnt = ro.execute(
            "SELECT COUNT(*) FROM p_provider_invocations_state WHERE invocation_id = ?", (inv_wal,)
        ).fetchone()[0]
    finally:
        ro.close()
    assert ro_cnt == 1

    cfg = DaemonConfig(
        version=1,
        data_root=wal_root,
        expected_store_id=store_id,
        cert_path=trusted_tmp / "u.pem",
        key_path=trusted_tmp / "u.key",
    )
    rep = migrate_offline(
        cfg, os_, policy_migrations=KERNEL_POLICY_MIGRATIONS, store_migrations=KERNEL_STORE_MIGRATIONS
    )
    assert (rep.policy_report.to_version, rep.store_report.to_version) == (5, 7)

    rt_up = reopen_kernel_job_runtime(wal_root, store_id, os_)
    try:
        migrated = rt_up.policy.accounting_invocation(inv_wal)
        assert migrated is not None
        assert migrated.state is InvocationState.RESERVED
        assert migrated.reserved_amount == "2.5"
        assert rt_up.policy.period_committed_total(OWNER, period) == "2.5"
    finally:
        rt_up.close()

    # Part B: missing/corrupt CAS reservation descriptor MUST fail closed with INTEGRITY_FAILURE (never "0").
    bad_cas_root = trusted_tmp / "r01-bad-cas"
    rt_b = open_runtime(
        bad_cas_root,
        os_,
        handlers=handlers,
        kinds=kinds,
        store_migrations=KERNEL_STORE_MIGRATIONS[:4],
        policy_migrations=KERNEL_POLICY_MIGRATIONS[:3],
    )
    bad_layout = DataRoot.at(bad_cas_root)
    try:
        bad_sid = rt_b.store.store_id
        svc_b, ks_b = kernel_job_service(rt_b, clock)
        lease_b = _start_job(svc_b, ks_b, rt_b.lease.epoch, clock.now())
        inv_b = svc_b.reserve_invocation(lease_b, UsageReservation(max_amount="3.25"))
        inv_row = ks_b.transact(lambda tx: tx.read_invocation(inv_b))
        assert inv_row is not None
        res_digest = inv_row.reservation_digest
    finally:
        rt_b.close()

    blob_path(bad_layout.cas_dir, res_digest).unlink()
    bad_cfg = DaemonConfig(
        version=1,
        data_root=bad_cas_root,
        expected_store_id=bad_sid,
        cert_path=trusted_tmp / "u.pem",
        key_path=trusted_tmp / "u.key",
    )
    with pytest.raises(BrainError) as cas_err:
        migrate_offline(
            bad_cfg, os_, policy_migrations=KERNEL_POLICY_MIGRATIONS, store_migrations=KERNEL_STORE_MIGRATIONS
        )
    assert cas_err.value.code is ErrorCode.INTEGRITY_FAILURE


def test_r03_policy_restore_carry_forward_wins_over_reconciled_and_reconcile_checks_version_digest_and_revision(
    trusted_tmp: Path, clock: FakeClock
) -> None:
    """I3-4-R03: active live locks survive carry-forward over backup 'reconciled' rows & reconcile checks fields."""
    t_oct28 = clock.now() - timedelta(days=2)
    clock_b1 = FakeClock(t_oct28)
    os_b1 = os_adapters(clock=clock_b1)
    root_path = trusted_tmp / "r03-locks"
    rt = open_kernel_job_runtime(root_path, os_b1, role="r03-seed")
    layout = DataRoot.at(root_path)
    try:
        store_id = rt.store.store_id
        s1 = rt.policy.enroll_first_signer(_ssh_enrollment("r03"))
        bak_oct28 = create_policy_backup(rt.policy, os_b1, t_oct28)
    finally:
        rt.close()

    # On Day 2 (2026-10-30), restore bak_oct28 (locks 28,29,30), reconcile, then take bak_oct30 (has reconciled rows!).
    day28 = t_oct28.strftime("%Y-%m-%d")
    day29 = (t_oct28 + timedelta(days=1)).strftime("%Y-%m-%d")
    day30 = clock.now().strftime("%Y-%m-%d")
    os_now = os_adapters(clock=clock)

    with maintenance_lease(root_path) as (root, lease):
        restore_policy(
            root,
            lease,
            os_now,
            bak_oct28,
            store_id=store_id,
            now=clock.now(),
            migrations=KERNEL_POLICY_MIGRATIONS,
        )

    rt_rec = reopen_kernel_job_runtime(root_path, store_id, os_now)
    try:
        rev0 = rt_rec.policy.policy_revision()
        epoch0 = read_restore_epoch(layout, schema_version=6, os_=os_now)
        subj0 = policy_change_subject_id(
            repo_id_or_global="global",
            base_policy_revision=rev0,
            base_trust_generation=rt_rec.policy.trust_generation(),
            base_restore_epoch=epoch0,
            policy_diff_digest=D_DIFF,
        )
        n0 = rt_rec.policy.issue_nonce(action=ApprovalAction.POLICY_CHANGE, subject_id=subj0, risk_level=RiskLevel.HIGH)
        m0 = ApprovalMessage(
            store_id=store_id,
            owner_id=OWNER,
            trust_generation=rt_rec.policy.trust_generation(),
            action=ApprovalAction.POLICY_CHANGE,
            subject_id=subj0,
            subject_revision=1,
            resource_digests=(ResourceDigest("policy_diff", D_DIFF),),
            target_files=(),
            risk_level=RiskLevel.HIGH,
            risk_policy_version=RISK_POLICY_VERSION,
            recovery_scope=RecoveryScope.NONE,
            nonce=n0.nonce,
            expires_at=n0.expires_at,
        )
        rt_rec.policy.reconcile_accounting_locks(
            repo_id_or_global="global",
            base_policy_revision=rev0,
            base_restore_epoch=epoch0,
            policy_diff_digest=D_DIFF,
            approval=m0,
            signer_id=s1.signer_id,
            channel=ApprovalChannel.SSH_KEY,
            expected_restore_epoch=epoch0,
        )
        assert rt_rec.policy.policy_revision() > rev0
        bak_oct30 = create_policy_backup(rt_rec.policy, os_now, clock.now())
    finally:
        rt_rec.close()

    # Re-restore bak_oct28 so live policy.db holds active 'locked' rows for {28, 29, 30}, then restore bak_oct30.
    with maintenance_lease(root_path) as (root, lease):
        restore_policy(
            root,
            lease,
            os_now,
            bak_oct28,
            store_id=store_id,
            now=clock.now(),
            migrations=KERNEL_POLICY_MIGRATIONS,
        )
        restore_policy(
            root,
            lease,
            os_now,
            bak_oct30,
            store_id=store_id,
            now=clock.now(),
            live_carry_forward=True,
            migrations=KERNEL_POLICY_MIGRATIONS,
        )

    rt_chk = reopen_kernel_job_runtime(root_path, store_id, os_now)
    try:
        locked_periods = {lk.period_key for lk in rt_chk.policy.list_accounting_locks(state="locked")}
        assert {day28, day29, day30} <= locked_periods

        # Also test reconcile_accounting_locks rejects wrong risk_policy_version and wrong resource_digests.
        rev_cur = rt_chk.policy.policy_revision()
        gen_cur = rt_chk.policy.trust_generation()
        epoch_cur = read_restore_epoch(layout, schema_version=6, os_=os_now)
        subj_cur = policy_change_subject_id(
            repo_id_or_global="global",
            base_policy_revision=rev_cur,
            base_trust_generation=gen_cur,
            base_restore_epoch=epoch_cur,
            policy_diff_digest=D_DIFF,
        )
        for bad_rpv, bad_res in (
            (RISK_POLICY_VERSION + 1, (ResourceDigest("policy_diff", D_DIFF),)),
            (RISK_POLICY_VERSION, (ResourceDigest("policy_diff", digest_bytes(b"wrong-diff")),)),
        ):
            n_bad = rt_chk.policy.issue_nonce(
                action=ApprovalAction.POLICY_CHANGE, subject_id=subj_cur, risk_level=RiskLevel.HIGH
            )
            m_bad = ApprovalMessage(
                store_id=store_id,
                owner_id=OWNER,
                trust_generation=gen_cur,
                action=ApprovalAction.POLICY_CHANGE,
                subject_id=subj_cur,
                subject_revision=1,
                resource_digests=bad_res,
                target_files=(),
                risk_level=RiskLevel.HIGH,
                risk_policy_version=bad_rpv,
                recovery_scope=RecoveryScope.NONE,
                nonce=n_bad.nonce,
                expires_at=n_bad.expires_at,
            )
            with pytest.raises(BrainError) as bad_err:
                rt_chk.policy.reconcile_accounting_locks(
                    repo_id_or_global="global",
                    base_policy_revision=rev_cur,
                    base_restore_epoch=epoch_cur,
                    policy_diff_digest=D_DIFF,
                    approval=m_bad,
                    signer_id=s1.signer_id,
                    channel=ApprovalChannel.SSH_KEY,
                    expected_restore_epoch=epoch_cur,
                )
            assert bad_err.value.code in {ErrorCode.REVISION_CONFLICT, ErrorCode.UNAUTHENTICATED}
            locked_now = {lk.period_key for lk in rt_chk.policy.list_accounting_locks(state="locked")}
            assert locked_now >= {day28, day29, day30}
    finally:
        rt_chk.close()


def test_r05_admit_existing_pair_allows_intact_live_store_with_broken_abandoned_stage(
    trusted_tmp: Path, os_: OsAdapters
) -> None:
    """I3-4-R05: intact live store/ boots cleanly and abandons a READY store.restoring/ missing restore_epoch.json."""
    root_path = trusted_tmp / "r05-intact"
    rt = open_kernel_job_runtime(root_path, os_, role="r05-seed")
    layout = DataRoot.at(root_path)
    try:
        store_id = rt.store.store_id
        ev_id = new_id()
        d_live = rt.store.store_content(b"intact-live-payload", "event", ev_id, RetentionClass.DURABLE, None)
    finally:
        rt.close()

    abandoned = root_path / "store.restoring"
    abandoned.mkdir()
    os_.permissions.secure_directory(abandoned)
    shutil.copy2(layout.store_db, abandoned / "brain.db")
    os_.permissions.secure_file(abandoned / "brain.db")
    (abandoned / READY).write_bytes(b"")
    os_.permissions.secure_file(abandoned / READY)
    assert not (abandoned / "restore_epoch.json").exists()

    admitted = admit_existing_pair(
        root_path,
        store_id,
        os_,
        purpose="serve",
        store_migrations=KERNEL_STORE_MIGRATIONS,
        policy_migrations=KERNEL_POLICY_MIGRATIONS,
    )
    handlers, kinds = kernel_store_extensions()
    rt2 = open_runtime_under_lease(admitted, handlers=handlers, kinds=kinds)
    try:
        assert not abandoned.exists()
        assert list(root_path.glob("store.restoring.abandoned-*"))
        with rt2.store.transaction() as txn:
            assert d_live in held_digests(txn.db, "event", ev_id)
    finally:
        rt2.close()


def test_n1_pending_tombstones_rejects_boolean_schema_version(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    """I3-4-N1: bool schema_version=true in pending_restore_tombstones.json raises INTEGRITY_FAILURE."""
    root_path = trusted_tmp / "n1-bool-tomb"
    rt = open_kernel_job_runtime(root_path, os_, role="n1-seed")
    layout = DataRoot.at(root_path)
    rt.close()

    layout.pending_restore_tombstones_path.write_bytes(
        json.dumps({"schema_version": True, "restore_epoch": 0, "expired_holders": []}).encode("utf-8")
    )
    os_.permissions.secure_file(layout.pending_restore_tombstones_path)

    with maintenance_lease(root_path) as (root, lease):
        pol = PolicyStore.open(root, lease, os_, migrations=KERNEL_POLICY_MIGRATIONS)
        try:
            with pytest.raises(BrainError) as err:
                drain_published_restore_effects(root, lease, os_, pol, now=clock.now())
            assert err.value.code is ErrorCode.INTEGRITY_FAILURE
        finally:
            pol.close()


def test_n2_store_create_stages_restore_epoch_before_publishing_brain_db(
    trusted_tmp: Path, os_: OsAdapters, monkeypatch: pytest.MonkeyPatch
) -> None:
    """I3-4-N2: Store.create writes store/restore_epoch.json before brain.db is published."""
    root_path = trusted_tmp / "n2-create"
    layout = DataRoot.at(root_path)
    seen_epoch_ready: list[bool] = []
    orig_publish = os_.publisher.publish

    class _CrashAfterBrainPublish(RuntimeError):
        pass

    def _spy_publish(staging: Path, final: Path) -> None:
        if final == layout.store_db:
            seen_epoch_ready.append(layout.restore_epoch_path.is_file())
            orig_publish(staging, final)
            raise _CrashAfterBrainPublish("simulated crash right after brain.db publish")
        orig_publish(staging, final)

    monkeypatch.setattr(os_.publisher, "publish", _spy_publish)
    with maintenance_lease(root_path) as (root, lease):
        secure_subdirectories(root, lease, os_)
        pol = PolicyStore.create(root, lease, os_, store_id=new_id(), migrations=KERNEL_POLICY_MIGRATIONS)
        try:
            with pytest.raises(_CrashAfterBrainPublish):
                Store.create(
                    root,
                    lease,
                    os_,
                    pol,
                    (),
                    KindRegistry(DEMO_KINDS),
                    migrations=KERNEL_STORE_MIGRATIONS,
                )
        finally:
            pol.close()

    assert seen_epoch_ready == [True]
    monkeypatch.undo()
    rt = open_runtime(
        root_path,
        os_,
        kinds=KindRegistry(DEMO_KINDS),
        store_migrations=KERNEL_STORE_MIGRATIONS,
        policy_migrations=KERNEL_POLICY_MIGRATIONS,
    )
    rt.close()
