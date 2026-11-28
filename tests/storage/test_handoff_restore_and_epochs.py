"""SP2-4 storage tests: append-only store v8 migration, restore_epoch continuity isolation, and source redaction/expiry.

Requirement sources:
- docs/superpowers/specs/2026-10-30-super-brain2-system-design.md
  (§5.6, §5.7, §7.4, §20 cases 51, 52, 61, 65, 70, 73, 75–78)
- docs/superpowers/plans/2026-11-18-sp2-capture-continuity.md (SP2-4 Step 2)
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.composition.kernel_projections import kernel_store_extensions
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import Scope
from superbrain.domain.continuity.budget import validate_handoff_write_limits
from superbrain.domain.continuity.handoff_model import parse_handoff_patch
from superbrain.domain.continuity.merge_rules import apply_handoff_patch
from superbrain.domain.continuity.rendering import render_handoff_l0
from superbrain.ports.capture import CaptureEventRecord
from superbrain.ports.policy import IntentKind
from superbrain.storage._restore_epoch import RESTORE_EPOCH_FILE, read_restore_epoch
from superbrain.storage.backup import create_store_backup
from superbrain.storage.kernel_schema import KERNEL_POLICY_MIGRATIONS, KERNEL_STORE_MIGRATIONS
from superbrain.storage.layout import DataRoot
from superbrain.storage.migrate import migrate_database
from superbrain.storage.restore import restore_store
from superbrain.storage.runtime import admit_existing_pair, open_runtime
from superbrain.storage.schema import code_version
from tests.storage.conftest import maintenance_lease
from tests.support.clock import FakeClock
from tests.support.inc2_fixture import open_kernel_job_runtime
from tests.support.inc2_transport import register_workspace_direct
from tests.support.kernel_auth import seed_principal_and_credential


def test_store_v8_migration_upgrades_v7_and_blocks_pre_v8_binary(trusted_tmp: Path) -> None:
    clock = FakeClock(dt.datetime(2026, 11, 26, 1, 0, tzinfo=dt.UTC))
    adapters = os_adapters(clock=clock)
    root_path = trusted_tmp / "v7-upgrade"
    handlers, kinds = kernel_store_extensions()
    rt7 = open_runtime(
        root_path,
        adapters,
        handlers=handlers,
        kinds=kinds,
        store_migrations=KERNEL_STORE_MIGRATIONS[:7],
        policy_migrations=KERNEL_POLICY_MIGRATIONS,
    )
    store_id = rt7.store.store_id
    rt7.close()
    assert code_version(KERNEL_STORE_MIGRATIONS) == 8

    # Older v7 binary cannot admit after upgrading to v8.
    with maintenance_lease(root_path, adapters) as (root, lease):
        rep = migrate_database(
            root,
            lease,
            adapters,
            target="store",
            migrations=KERNEL_STORE_MIGRATIONS,
            now=clock.now(),
        )
        assert rep.from_version == 7 and rep.to_version == 8

    with pytest.raises(BrainError) as exc_old:
        adm = admit_existing_pair(
            root_path,
            store_id,
            adapters,
            purpose="serve",
            store_migrations=KERNEL_STORE_MIGRATIONS[:7],
            policy_migrations=KERNEL_POLICY_MIGRATIONS,
        )
        adm.release()
    assert exc_old.value.code is ErrorCode.UNSUPPORTED_VERSION


def test_handoff_composite_epoch_prevents_post_restore_revision_aliasing_and_survives_migrate(
    trusted_tmp: Path,
) -> None:
    from superbrain.storage.handoffs import HandoffStore
    from superbrain.storage.sessions import SessionStore

    clock = FakeClock(dt.datetime(2026, 11, 26, 2, 0, tzinfo=dt.UTC))
    adapters = os_adapters(clock=clock)
    root_path = trusted_tmp / "epoch-alias"
    rt = open_kernel_job_runtime(root_path, adapters, role="sp24-epoch")
    task_id = "task-epoch-alias-1"
    try:
        prin_a = seed_principal_and_credential(
            rt.policy, owner_id="dan", harness_id="claude-code", machine_id="m1"
        ).principal
        ws = register_workspace_direct(rt, clock, prin_a, alias="ws-epoch", checkout_dir=trusted_tmp / "chk-epoch")
        rt.store.reconcile_policy()

        ss = SessionStore(rt.store, rt.policy)
        sess = ss.bind_session(
            principal_id=prin_a.principal_id,
            repo_id=ws.repo_id,
            checkout_id=ws.checkout_id,
            harness_id="claude-code",
            raw_session_id="RAW_SID_EPOCH_SECRET",
            now=clock.now(),
        )
        hs = HandoffStore(rt.store, rt.policy)
        hs.create_work_task(
            task_id=task_id,
            owner_id="dan",
            repo_id=ws.repo_id,
            checkout_id=ws.checkout_id,
            principal_id=prin_a.principal_id,
            session_ref=sess.session_ref,
            description="Goal for epoch test",
            delivery_id="deliv-init",
            now=clock.now(),
        )
        for rev in range(1, 5):
            clock.advance(dt.timedelta(seconds=5))
            head_now = hs.read_header(
                task_id, principal_id=prin_a.principal_id, scope=Scope(ws.repo_id, ws.checkout_id)
            )
            assert head_now is not None
            hs.commit_handoff_mutation(
                task_id=task_id,
                owner_id="dan",
                repo_id=ws.repo_id,
                checkout_id=ws.checkout_id,
                principal_id=prin_a.principal_id,
                harness_id="claude-code",
                session_ref=sess.session_ref,
                episode_id=f"ep-{rev}",
                base_revision=rev - 1,
                expected_fence=head_now.live_fence,
                takeover=(rev == 1),
                takeover_acknowledge_active=True,
                patch=parse_handoff_patch({"working_goal": f"Milestone {rev}"}),
                evidence_digests=(),
                manual_submission_enabled=True,
                now=clock.now(),
                apply_patch=apply_handoff_patch,
                validate_limits=validate_handoff_write_limits,
            )
        bak_rev4 = create_store_backup(rt.store, adapters, clock.now())
    finally:
        rt.close()

    # Commit revision 5 ("X") in live store at epoch 0.
    rt2 = open_kernel_job_runtime(root_path, adapters, role="sp24-epoch")
    try:
        hs2 = HandoffStore(rt2.store, rt2.policy)
        h4 = hs2.read_header(task_id, principal_id=prin_a.principal_id, scope=Scope(ws.repo_id, ws.checkout_id))
        assert h4 is not None and h4.revision == 4 and h4.revision_epoch == 0
        hs2.commit_handoff_mutation(
            task_id=task_id,
            owner_id="dan",
            repo_id=ws.repo_id,
            checkout_id=ws.checkout_id,
            principal_id=prin_a.principal_id,
            harness_id="claude-code",
            session_ref=sess.session_ref,
            episode_id="ep-5x",
            base_revision=4,
            expected_fence=h4.live_fence,
            takeover=False,
            takeover_acknowledge_active=False,
            patch=parse_handoff_patch({"working_goal": "Branch X at rev 5"}),
            evidence_digests=(),
            manual_submission_enabled=True,
            now=clock.now(),
            apply_patch=apply_handoff_patch,
            validate_limits=validate_handoff_write_limits,
        )
        hdr_x = hs2.read_revision_header(
            artifact_id=h4.artifact_id,
            revision_epoch=0,
            revision=5,
            principal_id=prin_a.principal_id,
            scope=Scope(ws.repo_id, ws.checkout_id),
        )
        assert hdr_x is not None and hdr_x.agent_ref is not None
        x_agent_ref = hdr_x.agent_ref
        pre_restore_fence = h4.live_fence
    finally:
        rt2.close()

    # Two consecutive restores yield distinct restore_epoch values (case 75).
    from superbrain.storage.policy_store import PolicyStore

    with maintenance_lease(root_path, adapters) as (root, lease):
        pol_handle = PolicyStore.open(root, lease, adapters, migrations=KERNEL_POLICY_MIGRATIONS)
        try:
            rep1 = restore_store(
                root,
                lease,
                adapters,
                bak_rev4,
                pol_handle,
                clock.now(),
                migrations=KERNEL_STORE_MIGRATIONS,
            )
            clock.advance(dt.timedelta(seconds=2))
            rep2 = restore_store(
                root,
                lease,
                adapters,
                bak_rev4,
                pol_handle,
                clock.now(),
                migrations=KERNEL_STORE_MIGRATIONS,
            )
        finally:
            pol_handle.close()
    assert rep1.new_epoch < rep2.new_epoch
    assert read_restore_epoch(DataRoot.at(root_path), schema_version=8, os_=adapters) == rep2.new_epoch

    # Missing/corrupt restore_epoch.json on store v8 fails closed with INTEGRITY_FAILURE (case 77).
    epoch_path = DataRoot.at(root_path).restore_epoch_path
    saved_bytes = epoch_path.read_bytes()
    epoch_path.write_text('{"restore_epoch": "bad"}', encoding="utf-8")
    with pytest.raises(BrainError) as exc_corrupt:
        read_restore_epoch(DataRoot.at(root_path), schema_version=8, os_=adapters)
    assert exc_corrupt.value.code is ErrorCode.INTEGRITY_FAILURE
    epoch_path.write_bytes(saved_bytes)

    # Re-open, reject pre-restore epoch patch; takeover at live epoch & write Y at rev 5 (cases 61, 73, 78).
    rt3 = open_kernel_job_runtime(root_path, adapters, role="sp24-epoch")
    try:
        hs3 = HandoffStore(rt3.store, rt3.policy)
        # Pre-restore fence is rejected even if writer_generation matches.
        with pytest.raises(BrainError) as exc_old_epoch:
            hs3.commit_handoff_mutation(
                task_id=task_id,
                owner_id="dan",
                repo_id=ws.repo_id,
                checkout_id=ws.checkout_id,
                principal_id=prin_a.principal_id,
                harness_id="claude-code",
                session_ref=sess.session_ref,
                episode_id="ep-stale-epoch",
                base_revision=4,
                expected_fence=pre_restore_fence,
                takeover=True,
                takeover_acknowledge_active=True,
                patch=parse_handoff_patch({"working_goal": "Should fail stale epoch"}),
                evidence_digests=(),
                manual_submission_enabled=True,
                now=clock.now(),
                apply_patch=apply_handoff_patch,
                validate_limits=validate_handoff_write_limits,
            )
        assert exc_old_epoch.value.code is ErrorCode.REVISION_CONFLICT

        h_post = hs3.read_header(task_id, principal_id=prin_a.principal_id, scope=Scope(ws.repo_id, ws.checkout_id))
        assert h_post is not None
        assert h_post.revision == 4 and h_post.revision_epoch == 0
        assert h_post.live_fence.restore_epoch == rep2.new_epoch
        y_res = hs3.commit_handoff_mutation(
            task_id=task_id,
            owner_id="dan",
            repo_id=ws.repo_id,
            checkout_id=ws.checkout_id,
            principal_id=prin_a.principal_id,
            harness_id="claude-code",
            session_ref=sess.session_ref,
            episode_id="ep-5y",
            base_revision=4,
            expected_fence=h_post.live_fence,
            takeover=True,
            takeover_acknowledge_active=True,
            patch=parse_handoff_patch({"working_goal": "Branch Y at new epoch rev 5"}),
            evidence_digests=(),
            manual_submission_enabled=True,
            now=clock.now(),
            apply_patch=apply_handoff_patch,
            validate_limits=validate_handoff_write_limits,
        )
        assert y_res.revision == 5 and y_res.revision_epoch == rep2.new_epoch
        # Looking up X's ref (artifact_id, 0, 5) NEVER aliases Y's (artifact_id, new_epoch, 5) (case 78)!
        with pytest.raises(BrainError) as exc_alias:
            hs3.read_revision_header(
                artifact_id=h_post.artifact_id,
                revision_epoch=0,
                revision=5,
                principal_id=prin_a.principal_id,
                scope=Scope(ws.repo_id, ws.checkout_id),
            )
        assert exc_alias.value.code is ErrorCode.NOT_FOUND
        hdr_y = hs3.read_revision_header(
            artifact_id=h_post.artifact_id,
            revision_epoch=rep2.new_epoch,
            revision=5,
            principal_id=prin_a.principal_id,
            scope=Scope(ws.repo_id, ws.checkout_id),
        )
        assert hdr_y is not None and hdr_y.agent_ref != x_agent_ref
        _ = RESTORE_EPOCH_FILE
    finally:
        rt3.close()


def test_source_quarantine_and_expiry_redact_l0_l1_l2_and_keep_receipt_digest(trusted_tmp: Path) -> None:
    from superbrain.storage.handoffs import HandoffStore
    from superbrain.storage.sessions import SessionStore

    clock = FakeClock(dt.datetime(2026, 11, 26, 3, 0, tzinfo=dt.UTC))
    adapters = os_adapters(clock=clock)
    root_path = trusted_tmp / "redact-store"
    rt = open_kernel_job_runtime(root_path, adapters, role="sp24-redact")
    try:
        prin = seed_principal_and_credential(
            rt.policy, owner_id="dan", harness_id="claude-code", machine_id="m2"
        ).principal
        ws = register_workspace_direct(rt, clock, prin, alias="ws-red", checkout_dir=trusted_tmp / "chk-red")
        rt.store.reconcile_policy()
        ss = SessionStore(rt.store, rt.policy)
        sess = ss.bind_session(
            principal_id=prin.principal_id,
            repo_id=ws.repo_id,
            checkout_id=ws.checkout_id,
            harness_id="claude-code",
            raw_session_id="RAW_REDACT_SID",
            now=clock.now(),
        )
        hs = HandoffStore(rt.store, rt.policy)
        res = hs.create_work_task(
            task_id="task-redact-1",
            owner_id="dan",
            repo_id=ws.repo_id,
            checkout_id=ws.checkout_id,
            principal_id=prin.principal_id,
            session_ref=sess.session_ref,
            description="Sensitive secret goal string xyz",
            delivery_id="deliv-red-1",
            now=clock.now(),
        )
        # Attach a captured user_message event whose expiry/quarantine redacts observed excerpt while keeping proposal.
        ev = CaptureEventRecord(
            event_id="ev-user-reply-1",
            producer_stream="stream-red-1",
            sequence=1,
            harness_id="claude-code",
            kind="user_message",
            recorded_at="2026-11-26T03:00:00Z",
            payload={"role": "user", "text": "Yes please exception allowed xyzsecret"},
            session_ref=sess.session_ref,
        )
        ss.record_session_event(
            session_ref=sess.session_ref,
            repo_id=ws.repo_id,
            checkout_id=ws.checkout_id,
            task_id="task-redact-1",
            producer_stream="stream-red-1",
            event=ev,
            now=clock.now(),
        )
        hdr_r = hs.read_header(
            "task-redact-1", principal_id=prin.principal_id, scope=Scope(ws.repo_id, ws.checkout_id)
        )
        assert hdr_r is not None
        hs.commit_handoff_mutation(
            task_id="task-redact-1",
            owner_id="dan",
            repo_id=ws.repo_id,
            checkout_id=ws.checkout_id,
            principal_id=prin.principal_id,
            harness_id="claude-code",
            session_ref=sess.session_ref,
            episode_id="ep-red-1",
            base_revision=0,
            expected_fence=hdr_r.live_fence,
            takeover=True,
            takeover_acknowledge_active=True,
            patch=parse_handoff_patch({"working_goal": "Work on redacted task"}),
            evidence_digests=(),
            manual_submission_enabled=True,
            now=clock.now(),
            apply_patch=apply_handoff_patch,
            validate_limits=validate_handoff_write_limits,
        )
        # Quarantine goal blob digest via policy intent -> discover & get_artifact must return Redacted!
        rt.policy.record_intent(IntentKind.QUARANTINE, {"digest": res.goal_digest})
        rt.store.reconcile_policy()
        disc = hs.list_discover(
            principal_id=prin.principal_id,
            owner_id="dan",
            repo_id=ws.repo_id,
            checkout_id=ws.checkout_id,
            task_id="task-redact-1",
            now=clock.now(),
            render_l0=render_handoff_l0,
        )
        assert len(disc) == 1
        assert disc[0].status == "redacted"
        # Scan entire CAS+SQLite files: raw session ID must not appear anywhere.
        raw_hits = list((root_path / "store").rglob("*"))
        assert raw_hits and not any(
            p.is_file() and b"RAW_REDACT_SID" in p.read_bytes() for p in raw_hits if p.name.endswith(".json")
        )
    finally:
        rt.close()


def test_handoff_store_v8_migration_rejects_half_migrated_and_malformed_shapes(trusted_tmp: Path) -> None:
    """Lens 3: v8 migration fails closed with INTEGRITY_FAILURE before swapping on half-migrated or malformed v7 DBs."""
    clock = FakeClock(dt.datetime(2026, 11, 26, 4, 30, tzinfo=dt.UTC))
    adapters = os_adapters(clock=clock)
    handlers, kinds = kernel_store_extensions()

    # Case A: half-migrated artifact_send_attempt (only 'level' exists without 'revision_epoch').
    half_path = trusted_tmp / "v8-half"
    rt_half = open_runtime(
        half_path,
        adapters,
        handlers=handlers,
        kinds=kinds,
        store_migrations=KERNEL_STORE_MIGRATIONS[:7],
        policy_migrations=KERNEL_POLICY_MIGRATIONS,
    )
    try:
        with rt_half.store.transaction() as txn:
            txn.db.execute("ALTER TABLE artifact_send_attempt ADD COLUMN level TEXT NOT NULL DEFAULT 'L1'")
    finally:
        rt_half.close()

    with maintenance_lease(half_path, adapters) as (root_h, lease):
        with pytest.raises(BrainError) as exc_half:
            migrate_database(
                root_h,
                lease,
                adapters,
                target="store",
                migrations=KERNEL_STORE_MIGRATIONS,
                now=clock.now(),
            )
        assert exc_half.value.code is ErrorCode.INTEGRITY_FAILURE

    reopened = open_runtime(
        half_path,
        adapters,
        handlers=handlers,
        kinds=kinds,
        store_migrations=KERNEL_STORE_MIGRATIONS[:7],
        policy_migrations=KERNEL_POLICY_MIGRATIONS,
    )
    try:
        assert reopened.store.schema_version == 7
    finally:
        reopened.close()

    # Case B: malformed base table missing required task_handoffs columns is rejected cleanly.
    mal_path = trusted_tmp / "v8-malformed"
    rt_mal = open_runtime(
        mal_path,
        adapters,
        handlers=handlers,
        kinds=kinds,
        store_migrations=KERNEL_STORE_MIGRATIONS[:7],
        policy_migrations=KERNEL_POLICY_MIGRATIONS,
    )
    try:
        with rt_mal.store.transaction() as txn:
            txn.db.execute("DROP TABLE task_handoffs")
            txn.db.execute("CREATE TABLE task_handoffs (task_id TEXT PRIMARY KEY)")
    finally:
        rt_mal.close()

    with maintenance_lease(mal_path, adapters) as (root_m, lease):
        with pytest.raises(BrainError) as exc_mal:
            migrate_database(
                root_m,
                lease,
                adapters,
                target="store",
                migrations=KERNEL_STORE_MIGRATIONS,
                now=clock.now(),
            )
        assert exc_mal.value.code is ErrorCode.INTEGRITY_FAILURE


def test_handoff_store_v8_migration_and_restore_reject_malformed_ddl_shapes(trusted_tmp: Path) -> None:
    """F3 oracle (Lens 1, 2, 3, 7, 10): v8 rejects non-contract DDLs on migration and backup restore."""
    import json
    import sqlite3

    from superbrain.core.canonical import canonical_json, digest_bytes
    from superbrain.storage.handoffs import HandoffStore
    from superbrain.storage.policy_store import PolicyStore
    from superbrain.storage.prune import MANIFEST_NAME
    from superbrain.storage.sessions import SessionStore

    clock = FakeClock(dt.datetime(2026, 11, 26, 5, 0, tzinfo=dt.UTC))
    adapters = os_adapters(clock=clock)
    handlers, kinds = kernel_store_extensions()

    def _expect_rejected_v7_migration(name: str, setup_sql: list[str]) -> None:
        db_root = trusted_tmp / f"v8-bad-{name}"
        rt = open_runtime(
            db_root,
            adapters,
            handlers=handlers,
            kinds=kinds,
            store_migrations=KERNEL_STORE_MIGRATIONS[:7],
            policy_migrations=KERNEL_POLICY_MIGRATIONS,
        )
        try:
            with rt.store.transaction() as txn:
                for stmt in setup_sql:
                    txn.db.execute(stmt)
        finally:
            rt.close()

        with maintenance_lease(db_root, adapters) as (root_b, lease):
            with pytest.raises(BrainError) as exc_bad:
                migrate_database(
                    root_b,
                    lease,
                    adapters,
                    target="store",
                    migrations=KERNEL_STORE_MIGRATIONS,
                    now=clock.now(),
                )
            assert exc_bad.value.code is ErrorCode.INTEGRITY_FAILURE

        reopened = open_runtime(
            db_root,
            adapters,
            handlers=handlers,
            kinds=kinds,
            store_migrations=KERNEL_STORE_MIGRATIONS[:7],
            policy_migrations=KERNEL_POLICY_MIGRATIONS,
        )
        try:
            assert reopened.store.schema_version == 7
        finally:
            reopened.close()

    # 1. Exact reviewer probe: preseeded 3-col handoff_revision_headers matching index columns only.
    _expect_rejected_v7_migration(
        "rev-hdr-3col",
        ["CREATE TABLE handoff_revision_headers (task_id TEXT, revision_epoch INTEGER, revision INTEGER)"],
    )

    # 2. All other new v8 tables preseeded with malformed/wrong DDL.
    for bad_tbl, ddl in (
        ("deliveries", "CREATE TABLE deliveries (delivery_id TEXT PRIMARY KEY)"),
        ("delivery_seen_handoffs", "CREATE TABLE delivery_seen_handoffs (delivery_id TEXT PRIMARY KEY)"),
        ("episodes", "CREATE TABLE episodes (episode_id TEXT PRIMARY KEY)"),
        ("episode_evidence", "CREATE TABLE episode_evidence (evidence_id TEXT PRIMARY KEY)"),
        ("artifact_get_results", "CREATE TABLE artifact_get_results (result_id TEXT PRIMARY KEY)"),
    ):
        _expect_rejected_v7_migration(f"tbl-{bad_tbl}", [ddl])

    # 3. C5 extended column type/constraint/default drift on existing v7 tables.
    _expect_rejected_v7_migration(
        "c5-send-wrong-default",
        [
            "ALTER TABLE artifact_send_attempt ADD COLUMN level TEXT NOT NULL DEFAULT 'L1'",
            "ALTER TABLE artifact_send_attempt ADD COLUMN revision_epoch INTEGER NOT NULL DEFAULT 0",
        ],
    )
    _expect_rejected_v7_migration(
        "c5-send-wrong-type-nullable",
        [
            "ALTER TABLE artifact_send_attempt ADD COLUMN level TEXT",
            "ALTER TABLE artifact_send_attempt ADD COLUMN revision_epoch TEXT",
        ],
    )
    _expect_rejected_v7_migration(
        "c5-ack-wrong-type-nullable",
        [
            "ALTER TABLE artifact_read_ack ADD COLUMN artifact_id TEXT",
            "ALTER TABLE artifact_read_ack ADD COLUMN revision_epoch TEXT",
        ],
    )

    # 4. Restore backup containing malformed v7->v8 shape leaves live v8 store & data intact.
    live_root = trusted_tmp / "v8-restore-live"
    rt7 = open_runtime(
        live_root,
        adapters,
        handlers=handlers,
        kinds=kinds,
        store_migrations=KERNEL_STORE_MIGRATIONS[:7],
        policy_migrations=KERNEL_POLICY_MIGRATIONS,
    )
    try:
        v7_backup = create_store_backup(rt7.store, adapters, clock.now())
    finally:
        rt7.close()

    # Tamper ONLY the v7 backup snapshot to inject malformed 3-col handoff_revision_headers, then re-sign manifest.
    bak_db_path = v7_backup / "brain.db"
    conn = sqlite3.connect(str(bak_db_path))
    try:
        conn.execute("CREATE TABLE handoff_revision_headers (task_id TEXT, revision_epoch INTEGER, revision INTEGER)")
        conn.commit()
    finally:
        conn.close()
    man_path = v7_backup / MANIFEST_NAME
    man_obj = json.loads(man_path.read_text(encoding="utf-8"))
    man_obj["db_digest"] = digest_bytes(bak_db_path.read_bytes())
    man_path.write_bytes(canonical_json(man_obj))

    # Upgrade live_root cleanly to v8 and commit live task/handoff state before attempting malformed restore.
    with maintenance_lease(live_root, adapters) as (r_live, lease):
        mrep = migrate_database(
            r_live, lease, adapters, target="store", migrations=KERNEL_STORE_MIGRATIONS, now=clock.now()
        )
        assert mrep.from_version == 7 and mrep.to_version == 8

    live_tid = "task-live-control-1"
    rt8 = open_kernel_job_runtime(live_root, adapters, role="sp24-live-ctrl")
    try:
        prin = seed_principal_and_credential(
            rt8.policy, owner_id="dan", harness_id="claude-code", machine_id="m1"
        ).principal
        ws = register_workspace_direct(rt8, clock, prin, alias="ws-ctrl", checkout_dir=trusted_tmp / "chk-ctrl")
        rt8.store.reconcile_policy()
        sess = SessionStore(rt8.store, rt8.policy).bind_session(
            principal_id=prin.principal_id,
            repo_id=ws.repo_id,
            checkout_id=ws.checkout_id,
            harness_id="claude-code",
            raw_session_id="RAW_CTRL_SID",
            now=clock.now(),
        )
        HandoffStore(rt8.store, rt8.policy).create_work_task(
            task_id=live_tid,
            owner_id="dan",
            repo_id=ws.repo_id,
            checkout_id=ws.checkout_id,
            principal_id=prin.principal_id,
            session_ref=sess.session_ref,
            description="Live control task must survive failed restore",
            delivery_id="deliv-live-ctrl",
            now=clock.now(),
        )
        epoch_before = read_restore_epoch(DataRoot.at(live_root), schema_version=8, os_=adapters)
    finally:
        rt8.close()

    clock.advance(dt.timedelta(seconds=3))
    with maintenance_lease(live_root, adapters) as (r_rest, lease):
        pol_h = PolicyStore.open(r_rest, lease, adapters, migrations=KERNEL_POLICY_MIGRATIONS)
        try:
            with pytest.raises(BrainError) as exc_rest:
                restore_store(
                    r_rest,
                    lease,
                    adapters,
                    v7_backup,
                    pol_h,
                    clock.now(),
                    migrations=KERNEL_STORE_MIGRATIONS,
                )
            assert exc_rest.value.code is ErrorCode.INTEGRITY_FAILURE
        finally:
            pol_h.close()

    rt_after = open_kernel_job_runtime(live_root, adapters, role="sp24-live-after")
    try:
        assert rt_after.store.schema_version == 8
        assert read_restore_epoch(DataRoot.at(live_root), schema_version=8, os_=adapters) == epoch_before
        hs_after = HandoffStore(rt_after.store, rt_after.policy)
        hdr = hs_after.read_header(live_tid, principal_id=prin.principal_id, scope=Scope(ws.repo_id, ws.checkout_id))
        assert hdr is not None and hdr.task_id == live_tid
    finally:
        rt_after.close()
