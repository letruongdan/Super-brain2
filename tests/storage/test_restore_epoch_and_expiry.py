"""I3-4 oracle: ``store/restore_epoch.json``, per-holder read-time expiry, and restore step 4/7 boundaries.

Requirement sources: spec rev 22 §5.6-§5.8, §20 cases 25, 35, 75-77, 101; plan I3-4 Step 1 & Step 3.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

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
from superbrain.core.kernel import ResourceDigest
from superbrain.ports.os import OsAdapters
from superbrain.storage.backup import create_store_backup
from superbrain.storage.cas import RetentionClass, held_digests
from superbrain.storage.kernel_schema import KERNEL_POLICY_MIGRATIONS, KERNEL_STORE_MIGRATIONS
from superbrain.storage.kinds import KindRegistry
from superbrain.storage.layout import RESERVED_ENTRIES, DataRoot
from superbrain.storage.migrate import migrate_database
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.restore import restore_policy, restore_store
from superbrain.storage.retention import expire_due
from superbrain.storage.runtime import admit_existing_pair, open_runtime
from superbrain.storage.schema import Migration, SchemaInfo, code_version, read_schema_info
from superbrain.storage.swap import recover_interrupted_swaps
from superbrain.storage.writer import acquire_writer
from tests.storage.conftest import DEMO_KINDS, maintenance_lease
from tests.support.clock import FakeClock
from tests.support.fs import db_files, fake_link, read_all_bytes
from tests.support.inc2_fixture import open_kernel_job_runtime, reopen_kernel_job_runtime
from tests.support.seed_clone import case101_seeded_clone, v5_live_clone, v5_ready_stage_clone

if TYPE_CHECKING:
    pass

OWNER = "dan"
D_DIFF = digest_bytes(b'{"reconcile_accounting":true}')


def _open_v5(root: Path, os_: OsAdapters) -> tuple[Path, str]:
    rt = open_kernel_job_runtime(root, os_, role="i3-4-v5")
    try:
        sid = rt.store.store_id
    finally:
        rt.close()
    return root, sid


def _ssh_enrollment() -> SignerEnrollment:
    import base64
    import struct

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    raw = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", len(raw)) + raw
    return SignerEnrollment(
        owner_id=OWNER,
        channel=ApprovalChannel.SSH_KEY,
        public_key="ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + " owner@devbox",
    )


def _tamper_restore_epoch(
    path: Path, mode: str, trusted_tmp: Path, os_: OsAdapters, monkeypatch: pytest.MonkeyPatch
) -> None:
    if mode == "missing":
        path.unlink()
    elif mode == "malformed_json":
        path.write_bytes(b"{not-json")
    elif mode == "wrong_keys":
        path.write_bytes(b'{"epoch":0}')
    elif mode == "negative":
        path.write_bytes(b'{"restore_epoch":-1}')
    elif mode == "bool_epoch":
        path.write_bytes(b'{"restore_epoch":false}')
    elif mode == "symlink_or_junction":
        target = trusted_tmp / f"link-target-{new_id()}.json"
        target.write_bytes(b'{"restore_epoch":0}')
        os_.permissions.secure_file(target)
        path.unlink()
        try:
            path.symlink_to(target)
        except OSError:
            path.write_bytes(b'{"restore_epoch":0}')
            fake_link(monkeypatch, path)
    else:
        raise AssertionError(mode)


def test_store_v5_create_and_lt5_upgrade_seed_zero_and_preserve_data_root_layout(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    from superbrain.storage.restore import read_restore_epoch

    assert len(RESERVED_ENTRIES) == 14
    assert len(DataRoot.__dataclass_fields__) == 7
    root_v5 = trusted_tmp / "v5-create"
    _, sid_v5 = _open_v5(root_v5, os_)
    layout_v5 = DataRoot.at(root_v5)
    assert hasattr(layout_v5, "restore_epoch_path") and hasattr(layout_v5, "pending_restore_tombstones_path")
    assert layout_v5.restore_epoch_path.is_file()
    assert json.loads(layout_v5.restore_epoch_path.read_text(encoding="utf-8")) == {"restore_epoch": 0}
    assert read_restore_epoch(layout_v5, schema_version=6, os_=os_) == 0
    assert read_schema_info(layout_v5.store_db) == SchemaInfo(8, 8, sid_v5)

    # Pre-v5 store without restore_epoch.json reads as 0; migrating <5 -> latest writes 0.
    root_v4 = trusted_tmp / "v4-upgrade"
    rt_v4 = open_runtime(
        root_v4,
        os_,
        kinds=KindRegistry(DEMO_KINDS),
        store_migrations=KERNEL_STORE_MIGRATIONS[:4],
        policy_migrations=KERNEL_POLICY_MIGRATIONS[:3],
    )
    rt_v4.close()
    layout_v4 = DataRoot.at(root_v4)
    if os.path.lexists(layout_v4.restore_epoch_path):
        layout_v4.restore_epoch_path.unlink()
    assert read_restore_epoch(layout_v4, schema_version=4, os_=os_) == 0

    with maintenance_lease(root_v4) as (root, lease):
        migrate_database(
            root,
            lease,
            os_,
            target="policy",
            migrations=KERNEL_POLICY_MIGRATIONS,
            now=clock.now(),
        )
        rep = migrate_database(
            root,
            lease,
            os_,
            target="store",
            migrations=KERNEL_STORE_MIGRATIONS,
            now=clock.now(),
        )
        assert rep.to_version == 8
    assert layout_v4.restore_epoch_path.is_file()
    assert read_restore_epoch(layout_v4, schema_version=6, os_=os_) == 0


@pytest.mark.parametrize(
    "mode",
    ["missing", "malformed_json", "wrong_keys", "negative", "bool_epoch", "symlink_or_junction"],
)
def test_store_v5_invalid_restore_epoch_rejected_on_open_and_ready_swap(
    trusted_tmp: Path, os_: OsAdapters, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    root_path, store_id = v5_live_clone(trusted_tmp / f"live-{mode}", os_)
    layout = DataRoot.at(root_path)
    _tamper_restore_epoch(layout.restore_epoch_path, mode, trusted_tmp, os_, monkeypatch)

    with pytest.raises(BrainError) as err_open:
        reopen_kernel_job_runtime(root_path, store_id, os_)
    assert err_open.value.code is ErrorCode.INTEGRITY_FAILURE

    with pytest.raises(BrainError) as err_admit:
        admit_existing_pair(root_path, store_id, os_, purpose="serve")
    assert err_admit.value.code is ErrorCode.INTEGRITY_FAILURE

    # Also test interrupted READY stage during recover_interrupted_swaps (Cases 75, 77).
    stage_root, stage_dir, stage_layout = v5_ready_stage_clone(trusted_tmp / f"ready-{mode}", os_, maintenance_lease)
    _tamper_restore_epoch(stage_dir / "restore_epoch.json", mode, trusted_tmp, os_, monkeypatch)

    lease = acquire_writer(stage_layout, os_)
    try:
        with pytest.raises(BrainError) as err_swap:
            recover_interrupted_swaps(stage_layout, lease, os_)
        assert err_swap.value.code is ErrorCode.INTEGRITY_FAILURE
        assert not stage_layout.store_dir.exists()
        assert stage_dir.exists()
    finally:
        lease.release()

    with pytest.raises(BrainError) as err_rt:
        open_runtime(
            stage_root,
            os_,
            store_migrations=KERNEL_STORE_MIGRATIONS,
            policy_migrations=KERNEL_POLICY_MIGRATIONS,
        )
    assert err_rt.value.code is ErrorCode.INTEGRITY_FAILURE
    assert not stage_layout.store_dir.exists()



def test_consecutive_restores_bump_epoch_migrate_preserves_it_and_policy_change_fences_it(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    from superbrain.storage.restore import read_restore_epoch

    root_path, store_id = _open_v5(trusted_tmp / "seq-restore", os_)
    layout = DataRoot.at(root_path)
    rt = reopen_kernel_job_runtime(root_path, store_id, os_)
    try:
        signer = rt.policy.enroll_first_signer(_ssh_enrollment())
        gen0 = rt.policy.trust_generation()
        rev0 = rt.policy.policy_revision()
        rt.policy.set_period_cap(OWNER, "5")
        subj_before = policy_change_subject_id(
            repo_id_or_global="global",
            base_policy_revision=rev0,
            base_trust_generation=gen0,
            base_restore_epoch=0,
            policy_diff_digest=D_DIFF,
        )
        nonce = rt.policy.issue_nonce(
            action=ApprovalAction.POLICY_CHANGE, subject_id=subj_before, risk_level=RiskLevel.HIGH
        )
        stale_msg = ApprovalMessage(
            store_id=store_id,
            owner_id=OWNER,
            trust_generation=gen0,
            action=ApprovalAction.POLICY_CHANGE,
            subject_id=subj_before,
            subject_revision=1,
            resource_digests=(ResourceDigest("policy_diff", D_DIFF),),
            target_files=(),
            risk_level=RiskLevel.HIGH,
            risk_policy_version=RISK_POLICY_VERSION,
            recovery_scope=RecoveryScope.NONE,
            nonce=nonce.nonce,
            expires_at=nonce.expires_at,
        )
        backup = create_store_backup(rt.store, os_, clock.now())
    finally:
        rt.close()

    clock.advance(timedelta(minutes=5))
    with maintenance_lease(root_path) as (root, lease):
        pol = PolicyStore.open(root, lease, os_, migrations=KERNEL_POLICY_MIGRATIONS)
        try:
            rep1 = restore_store(root, lease, os_, backup, pol, clock.now(), migrations=KERNEL_STORE_MIGRATIONS)
        finally:
            pol.close()
    e1 = read_restore_epoch(layout, schema_version=6, os_=os_)
    assert e1 == rep1.new_epoch >= 1

    clock.advance(timedelta(minutes=5))
    with maintenance_lease(root_path) as (root, lease):
        pol = PolicyStore.open(root, lease, os_, migrations=KERNEL_POLICY_MIGRATIONS)
        try:
            rep2 = restore_store(root, lease, os_, backup, pol, clock.now(), migrations=KERNEL_STORE_MIGRATIONS)
        finally:
            pol.close()
    e2 = read_restore_epoch(layout, schema_version=6, os_=os_)
    assert e2 == rep2.new_epoch > e1

    # Stale policy_change signed for base_restore_epoch=0 MUST be rejected even though trust_generation == gen0.
    rt2 = reopen_kernel_job_runtime(root_path, store_id, os_)
    try:
        assert rt2.policy.trust_generation() == gen0
        with pytest.raises(BrainError) as stale_err:
            rt2.policy.reconcile_accounting_locks(
                repo_id_or_global="global",
                base_policy_revision=rev0,
                base_restore_epoch=0,
                policy_diff_digest=D_DIFF,
                approval=stale_msg,
                signer_id=signer.signer_id,
                channel=ApprovalChannel.SSH_KEY,
                expected_restore_epoch=e2,
            )
        assert stale_err.value.code in {ErrorCode.REVISION_CONFLICT, ErrorCode.UNAUTHENTICATED}
    finally:
        rt2.close()

    # Restore -> Migrate before any takeover preserves restore_epoch == e2 (Case 76).
    next_store_ver = code_version(KERNEL_STORE_MIGRATIONS) + 1
    store_next = (
        *KERNEL_STORE_MIGRATIONS,
        Migration(to_version=next_store_ver, min_reader_version=next_store_ver, apply=lambda db: None),
    )
    clock.advance(timedelta(minutes=5))
    with maintenance_lease(root_path) as (root, lease):
        mig = migrate_database(root, lease, os_, target="store", migrations=store_next, now=clock.now())
        assert mig.to_version == next_store_ver
    assert read_restore_epoch(layout, schema_version=next_store_ver, os_=os_) == e2


def test_shared_blob_per_holder_expiry_and_small_evidence_expiry_before_gc(
    trusted_tmp: Path, os_: OsAdapters, clock: FakeClock
) -> None:
    from superbrain.storage.cas import active_held_digests

    root_path, store_id = _open_v5(trusted_tmp / "expiry-read", os_)
    rt = reopen_kernel_job_runtime(root_path, store_id, os_)
    try:
        shared = b"shared-blob-event-and-evidence-case25"
        ev_id = new_id()
        evid_keep_id = new_id()
        d_shared = rt.store.store_content(
            shared, "event", ev_id, RetentionClass.EVENT_PAYLOAD, clock.now() + timedelta(days=10)
        )
        assert rt.store.store_content(shared, "evidence", evid_keep_id, RetentionClass.DURABLE, None) == d_shared
        small_secret = b"tiny-secret-evidence-case35"
        evid_exp_id = new_id()
        d_small = rt.store.store_content(
            small_secret, "evidence", evid_exp_id, RetentionClass.EVIDENCE, clock.now() + timedelta(days=5)
        )

        # Advance past both expiries WITHOUT running expire_due or GC yet.
        future = clock.now() + timedelta(days=11)
        clock.advance(timedelta(days=11))

        with rt.store.transaction() as txn:
            assert active_held_digests(txn.db, "event", ev_id, now=future) == []
            assert active_held_digests(txn.db, "evidence", evid_keep_id, now=future) == [d_shared]
            assert active_held_digests(txn.db, "evidence", evid_exp_id, now=future) == []
            assert txn.read_held_blob(d_shared, holder_id=ev_id, holder_kind="event", now=future) is None
            assert txn.read_held_blob(d_shared, holder_id=evid_keep_id, holder_kind="evidence", now=future) == shared
            assert txn.read_held_blob(d_small, holder_id=evid_exp_id, holder_kind="evidence", now=future) is None

        with pytest.raises(BrainError) as err_ev:
            rt.store.cas.read_held(d_shared, holder_kind="event", holder_id=ev_id, now=future)
        assert err_ev.value.code is ErrorCode.NOT_FOUND

        with pytest.raises(BrainError) as err_small:
            rt.store.cas.read_held(d_small, holder_kind="evidence", holder_id=evid_exp_id, now=future)
        assert err_small.value.code is ErrorCode.NOT_FOUND

        assert rt.store.cas.read_held(d_shared, holder_kind="evidence", holder_id=evid_keep_id, now=future) == shared

        # expire_due + GC deletes small Evidence blob and leaves 0 secret bytes in any DB file (Case 35).
        expire_due(rt.store, rt.policy, future)
        gc_now = max(future + timedelta(days=1), datetime.now(UTC) + timedelta(days=1))
        rt.store.cas.collect_garbage(now=gc_now, grace=timedelta(0))
        assert not rt.store.cas.exists(d_small)
        assert rt.store.cas.exists(d_shared)
        rt.store.rebuild_projections()
        with rt.store.transaction() as txn:
            assert held_digests(txn.db, "evidence", evid_exp_id) == []
            assert held_digests(txn.db, "event", ev_id) == []
    finally:
        rt.close()
    layout = DataRoot.at(root_path)
    assert small_secret not in read_all_bytes(db_files(layout.store_db) + db_files(layout.policy_db))


@pytest.mark.parametrize("mode", ["store_then_policy", "policy_then_store", "policy_only"])
def test_case_101_restore_orders_and_policy_only_block_expired_on_first_read(
    trusted_tmp: Path, clock: FakeClock, mode: str
) -> None:
    from superbrain.adapters.os import os_adapters
    from superbrain.storage.cas import active_held_digests

    os_ = os_adapters(clock=clock)
    root_path, store_bak, policy_bak, tpl = case101_seeded_clone(trusted_tmp, mode, clock)

    # Wait past expiry and run expire_due once before restoring backups from t0.
    clock.advance(timedelta(days=95))
    t_late = clock.now()
    rt = reopen_kernel_job_runtime(root_path, tpl.store_id, os_)
    expire_due(rt.store, rt.policy, t_late)
    rt.close()

    with maintenance_lease(root_path) as (root, lease):
        if mode == "store_then_policy":
            pol = PolicyStore.open(root, lease, os_, migrations=KERNEL_POLICY_MIGRATIONS)
            try:
                restore_store(root, lease, os_, store_bak, pol, t_late, migrations=KERNEL_STORE_MIGRATIONS)
            finally:
                pol.close()
            restore_policy(
                root, lease, os_, policy_bak, store_id=tpl.store_id, now=t_late, migrations=KERNEL_POLICY_MIGRATIONS
            )
        elif mode == "policy_then_store":
            restore_policy(
                root, lease, os_, policy_bak, store_id=tpl.store_id, now=t_late, migrations=KERNEL_POLICY_MIGRATIONS
            )
            pol = PolicyStore.open(root, lease, os_, migrations=KERNEL_POLICY_MIGRATIONS)
            try:
                restore_store(root, lease, os_, store_bak, pol, t_late, migrations=KERNEL_STORE_MIGRATIONS)
            finally:
                pol.close()
        else:
            restore_policy(
                root, lease, os_, policy_bak, store_id=tpl.store_id, now=t_late, migrations=KERNEL_POLICY_MIGRATIONS
            )

    # First read after reopen BEFORE expire_due or GC runs MUST refuse expired holders while keeping DURABLE.
    rt_after = reopen_kernel_job_runtime(root_path, tpl.store_id, os_)
    try:
        for kind, hid, digest in (
            ("event", tpl.ev_id, tpl.d_ev),
            ("evidence", tpl.evid_exp_id, tpl.d_evid_exp),
            ("event", tpl.ev_id, tpl.d_shared),
        ):
            with pytest.raises(BrainError) as err:
                rt_after.store.cas.read_held(digest, holder_kind=kind, holder_id=hid, now=t_late)
            assert err.value.code is ErrorCode.NOT_FOUND
            with rt_after.store.transaction() as txn:
                assert txn.read_held_blob(digest, holder_id=hid, holder_kind=kind, now=t_late) is None
                assert digest not in active_held_digests(txn.db, kind, hid, now=t_late)
        assert (
            rt_after.store.cas.read_held(tpl.d_shared, holder_kind="evidence", holder_id=tpl.evid_keep_id, now=t_late)
            == tpl.shared_bytes
        )
    finally:
        rt_after.close()


def test_case_101_pre_swap_crash_keeps_live_evidence_and_invokes_restore_stage_hook(
    trusted_tmp: Path, clock: FakeClock
) -> None:
    from superbrain.adapters.os import os_adapters
    from superbrain.storage.restore import RestoreStageHook, drain_published_restore_effects

    root_path = trusted_tmp / "case101-preswap"
    os_ = os_adapters(clock=clock)
    t0 = clock.now()
    rt = open_kernel_job_runtime(root_path, os_, role="c101-preswap")
    store_id = rt.store.store_id
    evid_id = new_id()
    evid_bytes = b"lesson-kept-evidence-E"
    d_evid = rt.store.store_content(evid_bytes, "evidence", evid_id, RetentionClass.EVIDENCE, t0 + timedelta(days=5))
    bak = create_store_backup(rt.store, os_, t0)
    # In the live store after backup, a Lesson promotes Evidence E to DURABLE.
    rt.store.store_content(evid_bytes, "evidence", evid_id, RetentionClass.DURABLE, None)
    rt.close()

    # Build a child-crashed restoring.store.after_stage AFTER pending_restore_tombstones.json was staged BEFORE swap.
    class _RecordingHook(RestoreStageHook):
        def __init__(self) -> None:
            self.staged: list[tuple[int, tuple[tuple[str, str], ...]]] = []
            self.drained: list[tuple[int, tuple[tuple[str, str], ...]]] = []

        def on_stage_store(
            self,
            stage_dir: Path,
            staged_db: sqlite3.Connection,
            *,
            now: datetime,
            restore_epoch: int,
            expired_holders: tuple[tuple[str, str], ...],
        ) -> None:
            _ = staged_db, now
            assert (stage_dir / "pending_restore_tombstones.json").is_file()
            self.staged.append((restore_epoch, expired_holders))

        def on_drain_store(
            self,
            root: DataRoot,
            policy: PolicyStore,
            *,
            restore_epoch: int,
            expired_holders: tuple[tuple[str, str], ...],
            now: datetime,
        ) -> None:
            _ = root, policy, now
            self.drained.append((restore_epoch, expired_holders))

    # Simulate crash at restoring.store.after_stage on a copy using subprocess crash driver OR explicit check:
    clock.advance(timedelta(days=10))
    t_late = clock.now()
    crash_root = trusted_tmp / "c101-crash-stage"
    shutil.copytree(root_path, crash_root)
    with maintenance_lease(crash_root) as (root, lease):
        pol = PolicyStore.open(root, lease, os_, migrations=KERNEL_POLICY_MIGRATIONS)

        # Verify stage hook runs inside stage before READY, and live policy.db is NOT written if swap aborts.
        class _AbortBeforeSwap(RestoreStageHook):
            def on_stage_store(
                self,
                stage_dir: Path,
                staged_db: sqlite3.Connection,
                *,
                now: datetime,
                restore_epoch: int,
                expired_holders: tuple[tuple[str, str], ...],
            ) -> None:
                _ = staged_db, now, restore_epoch
                assert ("evidence", evid_id) in expired_holders
                assert (stage_dir / "pending_restore_tombstones.json").is_file()
                raise RuntimeError("simulated abort before swap")

            def on_drain_store(
                self,
                root: DataRoot,
                policy: PolicyStore,
                *,
                restore_epoch: int,
                expired_holders: tuple[tuple[str, str], ...],
                now: datetime,
            ) -> None:
                raise AssertionError("drain must not run on aborted stage")

        try:
            with pytest.raises(RuntimeError, match="simulated abort before swap"):
                restore_store(
                    root,
                    lease,
                    os_,
                    bak,
                    pol,
                    t_late,
                    migrations=KERNEL_STORE_MIGRATIONS,
                    stage_hooks=(_AbortBeforeSwap(),),
                )
            assert not pol.is_tombstoned("evidence", evid_id)
        finally:
            pol.close()

    # Reopening live crash_root MUST still read Evidence E kept DURABLE by the live Lesson.
    rt_live = reopen_kernel_job_runtime(crash_root, store_id, os_)
    try:
        assert not rt_live.policy.is_tombstoned("evidence", evid_id)
        assert rt_live.store.cas.read_held(d_evid, holder_kind="evidence", holder_id=evid_id, now=t_late) == evid_bytes
    finally:
        rt_live.close()

    # Completing the restore on root_path invokes RestoreStageHook stage+drain and tombstones E cleanly.
    recorder = _RecordingHook()
    with maintenance_lease(root_path) as (root, lease):
        pol = PolicyStore.open(root, lease, os_, migrations=KERNEL_POLICY_MIGRATIONS)
        try:
            rep = restore_store(
                root,
                lease,
                os_,
                bak,
                pol,
                t_late,
                migrations=KERNEL_STORE_MIGRATIONS,
                stage_hooks=(recorder,),
            )
            assert pol.is_tombstoned("evidence", evid_id)
        finally:
            pol.close()
    assert len(recorder.staged) == 1 and len(recorder.drained) == 1
    assert recorder.staged[0] == recorder.drained[0] == (rep.new_epoch, (("evidence", evid_id),))
    # Idempotent drain_published_restore_effects returns () once drained.
    with maintenance_lease(root_path) as (root, lease):
        pol = PolicyStore.open(root, lease, os_, migrations=KERNEL_POLICY_MIGRATIONS)
        try:
            assert (
                drain_published_restore_effects(root, lease, os_, pol, now=t_late, migrations=KERNEL_STORE_MIGRATIONS)
                == ()
            )
        finally:
            pol.close()
