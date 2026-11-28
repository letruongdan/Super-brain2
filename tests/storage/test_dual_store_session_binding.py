"""SP2-3 storage & security tests: dual-store session_ref binding, restore hooks, crash recovery, and leak scan.

Requirement sources:
- docs/superpowers/specs/2026-10-30-super-brain2-system-design.md (§7.1-7.2, §20 cases 2, 46)
- docs/superpowers/plans/2026-11-18-sp2-capture-continuity.md (SP2-3, lines 55-73, 158-181)
- docs/design/sp2-host-capture-matrix.md (§2.1-2.3, §4.2)
"""

from __future__ import annotations

import contextlib
import datetime as dt
import json
import logging
import os
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.composition.migrate_entry import migrate_offline
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    CAPABILITY_CAPTURE_PRODUCER,
    CaptureBatchCommand,
    CaptureProducerBinding,
    DaemonConfig,
)
from superbrain.ports.capture import CaptureEventRecord
from superbrain.ports.os import OsAdapters
from superbrain.storage.backup import create_policy_backup, create_store_backup
from superbrain.storage.kernel_schema import KERNEL_POLICY_MIGRATIONS, KERNEL_STORE_MIGRATIONS
from superbrain.storage.layout import DataRoot
from superbrain.storage.outbox import OutboxSpool
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.restore import restore_policy, restore_store
from superbrain.storage.runtime import Runtime
from superbrain.storage.schema import SchemaInfo, code_version, read_schema_info
from superbrain.storage.sqlite import open_readonly
from tests.storage.conftest import maintenance_lease
from tests.support.clock import FakeClock
from tests.support.fs import db_files, read_all_bytes
from tests.support.inc2_fixture import (
    open_cloned_runtime,
    open_kernel_job_runtime,
    reopen_kernel_job_runtime,
)
from tests.support.inc2_transport import (
    TransportTestDomain,
    clone_owner_only_tree,
    open_test_loopback_transport,
    register_workspace_direct,
)
from tests.support.kernel_auth import seed_principal_and_credential, seed_repo_grant

REPO_ROOT = Path(__file__).resolve().parents[2]
_START = dt.datetime(2026, 11, 21, 12, 0, tzinfo=dt.UTC)


def _open_v5_runtime(root: Path, os_: OsAdapters, *, role: str, use_template: bool = True) -> Runtime:
    return open_kernel_job_runtime(root, os_, role=role, use_template=use_template)


def _reopen_v5_runtime(root: Path, store_id: str, os_: OsAdapters) -> Runtime:
    return reopen_kernel_job_runtime(root, store_id, os_)


def _child_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(os.environ)
    env.pop("SUPERBRAIN_CRASHPOINT", None)
    env.pop("SUPERBRAIN_PAUSEPOINT", None)
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    if extra:
        env.update(extra)
    return env


def test_policy_v5_migration_tables_and_hmac_key_uniqueness(trusted_tmp: Path) -> None:
    from superbrain.storage.kernel_schema import POLICY_V5_MIGRATION, POLICY_V5_TABLES

    assert (POLICY_V5_MIGRATION.to_version, POLICY_V5_MIGRATION.min_reader_version) == (5, 5)
    assert code_version(KERNEL_POLICY_MIGRATIONS) == 5
    assert "session_ref_bindings" in POLICY_V5_TABLES

    clock = FakeClock(_START)
    os_ = os_adapters(clock=clock)

    rt_a = _open_v5_runtime(trusted_tmp / "store-a", os_, role="sp23-v5-a", use_template=False)
    try:
        sid_a = rt_a.policy.store_id
        assert rt_a.policy.schema_version == 5
        assert read_schema_info(DataRoot.at(trusted_tmp / "store-a").policy_db) == SchemaInfo(5, 5, sid_a)
        with rt_a.policy._immediate() as db:
            tables = {str(r[0]) for r in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()}
        for tbl in POLICY_V5_TABLES:
            assert tbl in tables
        key_a1 = rt_a.policy.session_hmac_key()
        assert len(key_a1) == 32
    finally:
        rt_a.close()

    rt_a_reopened = _reopen_v5_runtime(trusted_tmp / "store-a", sid_a, os_)
    try:
        assert rt_a_reopened.policy.session_hmac_key() == key_a1
    finally:
        rt_a_reopened.close()

    rt_b = _open_v5_runtime(trusted_tmp / "store-b", os_, role="sp23-v5-b", use_template=False)
    try:
        key_b = rt_b.policy.session_hmac_key()
        assert len(key_b) == 32
        assert key_b != key_a1
    finally:
        rt_b.close()

    # Upgrading from an existing policy v4 store creates v5 tables cleanly while preserving policy v4 data.
    v4_root = trusted_tmp / "upgrade-v4"
    rt_v4 = open_cloned_runtime(
        v4_root,
        os_,
        role="sp23-v4-src",
        store_migrations=KERNEL_STORE_MIGRATIONS,
        policy_migrations=KERNEL_POLICY_MIGRATIONS[:4],
    )
    try:
        v4_sid = rt_v4.policy.store_id
        cred = seed_principal_and_credential(rt_v4.policy, owner_id="dan", harness_id="claude-code", machine_id="m-1")
    finally:
        rt_v4.close()

    clock.advance(dt.timedelta(seconds=5))
    mig = migrate_offline(
        DaemonConfig(1, v4_root, v4_sid, trusted_tmp / "c.pem", trusted_tmp / "c.key"),
        os_,
    )
    assert mig.policy_report.status == "migrated"
    assert (mig.policy_report.from_version, mig.policy_report.to_version) == (4, 5)
    rt_v5 = _reopen_v5_runtime(v4_root, v4_sid, os_)
    try:
        assert rt_v5.policy.resolve_credential(cred.token).principal_id == cred.principal.principal_id
        assert len(rt_v5.policy.session_hmac_key()) == 32
    finally:
        rt_v5.close()


def test_two_principals_same_session_id_sequential_and_concurrent_refused_case_46(
    trusted_tmp: Path,
) -> None:
    from superbrain.cli_api.capture_client import CaptureClient
    from tests.support.inc2_cli import get_shared_t7_transport_template

    clock = FakeClock(_START)

    from superbrain.domain.continuity.sessions import compute_session_ref
    from superbrain.ports.continuity import SessionState
    from superbrain.storage.sessions import SessionStore

    os_ = os_adapters(clock=clock)
    root = trusted_tmp / "case46-seq"

    rt = _open_v5_runtime(root, os_, role="sp23-c46")
    raw_sid = "RAW_SHARED_SESSION_ID_CASE46_CANARY"
    try:
        prin_a = seed_principal_and_credential(
            rt.policy, owner_id="dan", harness_id="claude-code", machine_id="m-a"
        ).principal
        prin_b = seed_principal_and_credential(
            rt.policy, owner_id="bob", harness_id="codex", machine_id="m-b"
        ).principal
        ws_a = register_workspace_direct(rt, clock, prin_a, alias="repo-a", checkout_dir=trusted_tmp / "chk-seq-a")
        seed_repo_grant(rt.policy, principal_id=prin_b.principal_id, repo_id=ws_a.repo_id, owner_id="dan")
        rt.store.reconcile_policy()

        sessions = SessionStore(rt.store, rt.policy)
        bound = sessions.bind_session(
            principal_id=prin_a.principal_id,
            repo_id=ws_a.repo_id,
            checkout_id=ws_a.checkout_id,
            harness_id="claude-code",
            raw_session_id=raw_sid,
            now=clock.now(),
        )
        expected_ref = compute_session_ref(rt.policy.session_hmac_key(), raw_sid)
        assert bound.session_ref == expected_ref
        assert bound.principal_id == prin_a.principal_id
        assert bound.state is SessionState.ACTIVE

        # Re-binding by the same owner principal & checkout is idempotent.
        again = sessions.bind_session(
            principal_id=prin_a.principal_id,
            repo_id=ws_a.repo_id,
            checkout_id=ws_a.checkout_id,
            harness_id="claude-code",
            raw_session_id=raw_sid,
            now=clock.now(),
        )
        assert again.session_ref == expected_ref

        # Second principal using raw_session_id OR precomputed session_ref MUST be rejected with IDENTITY_MISMATCH.
        with pytest.raises(BrainError) as mismatch_raw:
            sessions.bind_session(
                principal_id=prin_b.principal_id,
                repo_id=ws_a.repo_id,
                checkout_id=ws_a.checkout_id,
                harness_id="codex",
                raw_session_id=raw_sid,
                now=clock.now(),
            )
        assert mismatch_raw.value.code is ErrorCode.IDENTITY_MISMATCH
        assert raw_sid not in str(mismatch_raw.value)

        with pytest.raises(BrainError) as mismatch_ref:
            sessions.bind_session(
                principal_id=prin_b.principal_id,
                repo_id=ws_a.repo_id,
                checkout_id=ws_a.checkout_id,
                harness_id="codex",
                session_ref=expected_ref,
                now=clock.now(),
            )
        assert mismatch_ref.value.code is ErrorCode.IDENTITY_MISMATCH
        assert raw_sid not in str(mismatch_ref.value)

        # Direct PolicyStore verification also preserves first owner and refuses second principal on retries.
        for _ in range(2):
            with pytest.raises(BrainError) as pol_mismatch:
                rt.policy.bind_or_verify_session_ref(
                    expected_ref,
                    principal_id=prin_b.principal_id,
                    repo_id=ws_a.repo_id,
                    checkout_id=ws_a.checkout_id,
                    harness_id="codex",
                    now=clock.now(),
                )
            assert pol_mismatch.value.code is ErrorCode.IDENTITY_MISMATCH
        row = rt.policy.lookup_session_binding(expected_ref)
        assert row is not None and row.principal_id == prin_a.principal_id
    finally:
        rt.close()

    # Concurrent 2-principal contention over loopback POST /v2/capture/events using the same session_ref.
    tpl = get_shared_t7_transport_template()
    assert tpl.ws_a is not None and tpl.ws_b is not None
    ws_a = tpl.ws_a
    ws_b = tpl.ws_b
    stream_a = "c46-stream-a"
    stream_b = "c46-stream-b"
    domain = TransportTestDomain(ws_a=ws_a)

    with open_test_loopback_transport(tpl, name="sp23-c46-race", domain=domain) as h:
        creds_box: list[tuple[Any, Any, str]] = []

        def _seed_two_producers() -> None:
            session: Any = h.loop._session
            assert session is not None
            r = session._rt
            p_a = seed_principal_and_credential(
                r.policy, owner_id=ws_a.owner_id, harness_id="claude-code", machine_id=ws_a.machine_id
            )
            p_b = seed_principal_and_credential(
                r.policy, owner_id=ws_b.owner_id, harness_id="codex", machine_id=ws_b.machine_id
            )
            seed_repo_grant(
                r.policy, principal_id=p_a.principal.principal_id, repo_id=ws_a.repo_id, owner_id=ws_a.owner_id
            )
            seed_repo_grant(
                r.policy, principal_id=p_b.principal.principal_id, repo_id=ws_b.repo_id, owner_id=ws_b.owner_id
            )
            snap = r.policy.snapshot()
            overlay = dict(snap.credentials)
            overlay[p_a.credential_id] = replace(
                overlay[p_a.credential_id],
                capabilities=frozenset({CAPABILITY_CAPTURE_PRODUCER}),
                capture_binding=CaptureProducerBinding(
                    producer_stream=stream_a, repo_id=ws_a.repo_id, checkout_id=ws_a.checkout_id
                ),
            )
            overlay[p_b.credential_id] = replace(
                overlay[p_b.credential_id],
                capabilities=frozenset({CAPABILITY_CAPTURE_PRODUCER}),
                capture_binding=CaptureProducerBinding(
                    producer_stream=stream_b, repo_id=ws_b.repo_id, checkout_id=ws_b.checkout_id
                ),
            )
            session.auth_gate.publish(replace(snap, credentials=overlay))
            s_ref = compute_session_ref(r.policy.session_hmac_key(), "CONCURRENT_CASE46_SID")
            creds_box.append((p_a, p_b, s_ref))

        h.loop.run_owner_action(_seed_two_producers).result(timeout=5.0)
        cap_a, cap_b, raced_ref = creds_box[0]

        barrier = threading.Barrier(2)
        target = h.make_target()

        def _post(cap_cred: Any, stream: str, ws: Any, harness: str) -> str:
            client = CaptureClient(h.open_client())
            ev: dict[str, JsonValue] = {
                "event_id": f"evt-race-{stream}",
                "producer_stream": stream,
                "sequence": 1,
                "harness_id": harness,
                "kind": "tool_post",
                "recorded_at": "2026-11-21T12:00:01Z",
                "payload": {"step": "race"},
                "session_ref": raced_ref,
            }
            barrier.wait(timeout=5.0)
            try:
                ack = client.post_batch(
                    target,
                    CaptureBatchCommand(stream, ws.repo_id, ws.checkout_id, (ev,), cap_cred.token),
                )
                assert ack.accepted_count == 1
                return "ok"
            except BrainError as err:
                assert err.code is ErrorCode.IDENTITY_MISMATCH
                return "mismatch"

        with ThreadPoolExecutor(max_workers=2) as pool:
            f1 = pool.submit(_post, cap_a, stream_a, ws_a, "claude-code")
            f2 = pool.submit(_post, cap_b, stream_b, ws_b, "codex")
            outcomes = sorted((f1.result(timeout=10.0), f2.result(timeout=10.0)))
        assert outcomes == ["mismatch", "ok"]


def test_session_after_policy_bind_before_store_project_crash_reconciles_once_in_subprocess(
    trusted_tmp: Path,
) -> None:
    from superbrain.domain.continuity.sessions import compute_session_ref
    from superbrain.storage.sessions import SessionStore

    clock = FakeClock(_START)
    os_ = os_adapters(clock=clock)
    root = trusted_tmp / "crash-bind"
    raw_sid = "CRASH_BEFORE_STORE_PROJECT_SID"

    rt = _open_v5_runtime(root, os_, role="sp23-crash")
    try:
        sid = rt.policy.store_id
        prin_a = seed_principal_and_credential(
            rt.policy, owner_id="dan", harness_id="claude-code", machine_id="m-1"
        ).principal
        prin_b = seed_principal_and_credential(
            rt.policy, owner_id="bob", harness_id="codex", machine_id="m-2"
        ).principal
        ws_a = register_workspace_direct(rt, clock, prin_a, alias="repo-a", checkout_dir=trusted_tmp / "chk-crash")
        seed_repo_grant(rt.policy, principal_id=prin_b.principal_id, repo_id=ws_a.repo_id, owner_id="dan")
        rt.store.reconcile_policy()
        expected_ref = compute_session_ref(rt.policy.session_hmac_key(), raw_sid)
    finally:
        rt.close()

    child_script = """
import datetime as dt, sys
from pathlib import Path
from superbrain.adapters.os import os_adapters
from superbrain.composition.kernel_projections import kernel_store_extensions
from superbrain.storage.runtime import admit_existing_pair, open_runtime_under_lease
from superbrain.storage.sessions import SessionStore
from tests.support.clock import FakeClock

root, sid, prin_id, repo_id, chk_id, raw_sid = sys.argv[1:7]
clock = FakeClock(dt.datetime(2026, 11, 21, 12, 0, tzinfo=dt.UTC))
os_ = os_adapters(clock=clock)
handlers, kinds = kernel_store_extensions()
rt = open_runtime_under_lease(
    admit_existing_pair(Path(root), sid, os_, purpose="serve"), handlers=handlers, kinds=kinds
)
try:
    SessionStore(rt.store, rt.policy).bind_session(
        principal_id=prin_id,
        repo_id=repo_id,
        checkout_id=chk_id,
        harness_id="claude-code",
        raw_session_id=raw_sid,
        now=clock.now(),
    )
finally:
    rt.close()
"""
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            child_script,
            str(root),
            sid,
            prin_a.principal_id,
            ws_a.repo_id,
            ws_a.checkout_id,
            raw_sid,
        ],
        cwd=str(REPO_ROOT),
        env=_child_env({"SUPERBRAIN_CRASHPOINT": "session.after_policy_bind_before_store_project"}),
        capture_output=True,
        text=True,
        check=False,
        timeout=30.0,
    )
    assert proc.returncode == 86, f"expected crash exit 86, got {proc.returncode}: {proc.stderr}"

    # Before reopen: policy.db has the binding while brain.db.sessions has 0 rows for expected_ref.
    ro_dir = trusted_tmp / "ro-crash"
    ro_dir.mkdir(exist_ok=True)
    with contextlib.closing(open_readonly(DataRoot.at(root).policy_db, scratch_dir=ro_dir)) as pol_ro:
        pol_row = pol_ro.execute(
            "SELECT session_ref, principal_id FROM session_ref_bindings WHERE session_ref = ?",
            (expected_ref,),
        ).fetchone()
        assert pol_row is not None and tuple(pol_row) == (expected_ref, prin_a.principal_id)
    with contextlib.closing(open_readonly(DataRoot.at(root).store_db, scratch_dir=ro_dir)) as str_ro:
        str_rows = str_ro.execute(
            "SELECT session_ref FROM sessions WHERE session_ref = ?",
            (expected_ref,),
        ).fetchall()
        assert str_rows == []

    # Reopen reconciles into brain.db.sessions exactly once and still rejects second principal.
    rt2 = _reopen_v5_runtime(root, sid, os_)
    try:
        sessions2 = SessionStore(rt2.store, rt2.policy)
        rec = sessions2.get_session(expected_ref, repo_id=ws_a.repo_id, checkout_id=ws_a.checkout_id)
        assert rec.session_ref == expected_ref
        assert rec.principal_id == prin_a.principal_id
        assert sessions2.reconcile_missing_sessions() == 0

        retried = sessions2.bind_session(
            principal_id=prin_a.principal_id,
            repo_id=ws_a.repo_id,
            checkout_id=ws_a.checkout_id,
            harness_id="claude-code",
            raw_session_id=raw_sid,
            now=clock.now(),
        )
        assert retried.session_ref == expected_ref

        cnt_row = rt2.store._db.execute(
            "SELECT count(*) FROM sessions WHERE session_ref = ?",
            (expected_ref,),
        ).fetchone()
        assert cnt_row is not None and int(cnt_row[0]) == 1

        with pytest.raises(BrainError) as mismatch:
            sessions2.bind_session(
                principal_id=prin_b.principal_id,
                repo_id=ws_a.repo_id,
                checkout_id=ws_a.checkout_id,
                harness_id="codex",
                raw_session_id=raw_sid,
                now=clock.now(),
            )
        assert mismatch.value.code is ErrorCode.IDENTITY_MISMATCH
    finally:
        rt2.close()


def test_all_four_independent_restore_combinations_preserve_hmac_key_and_bindings(
    trusted_tmp: Path,
) -> None:
    from superbrain.domain.continuity.sessions import compute_session_ref
    from superbrain.storage._policy_sessions import SessionPolicyRestoreStageHook
    from superbrain.storage.sessions import SessionStore

    clock = FakeClock(_START)
    os_ = os_adapters(clock=clock)
    base_root = trusted_tmp / "restore-base"

    # Seed at (store=6, policy=4) first so we have a real I3 policy v4 backup for Combo 3.
    rt_v4 = open_cloned_runtime(
        base_root,
        os_,
        role="sp23-r-v4",
        store_migrations=KERNEL_STORE_MIGRATIONS,
        policy_migrations=KERNEL_POLICY_MIGRATIONS[:4],
    )
    try:
        store_id = rt_v4.policy.store_id
        prin_a = seed_principal_and_credential(
            rt_v4.policy, owner_id="dan", harness_id="claude-code", machine_id="m-1"
        ).principal
        prin_b = seed_principal_and_credential(
            rt_v4.policy, owner_id="bob", harness_id="codex", machine_id="m-2"
        ).principal
        ws_a = register_workspace_direct(rt_v4, clock, prin_a, alias="repo-r", checkout_dir=trusted_tmp / "chk-rest")
        seed_repo_grant(rt_v4.policy, principal_id=prin_b.principal_id, repo_id=ws_a.repo_id, owner_id="dan")
        rt_v4.store.reconcile_policy()
        clock.advance(dt.timedelta(seconds=5))
        bak_pol_v4 = create_policy_backup(rt_v4.policy, os_, clock.now())
    finally:
        rt_v4.close()

    # Upgrade base_root to (store=6, policy=5), bind session 1, snapshot both DBs, then bind session 2.
    clock.advance(dt.timedelta(seconds=5))
    mig = migrate_offline(
        DaemonConfig(1, base_root, store_id, trusted_tmp / "rc.pem", trusted_tmp / "rc.key"),
        os_,
    )
    assert mig.policy_report.to_version == 5

    raw_s1 = "RESTORE_CANARY_SESSION_ONE"
    raw_s2 = "RESTORE_CANARY_SESSION_TWO"

    rt_v5 = _reopen_v5_runtime(base_root, store_id, os_)
    try:
        key0 = rt_v5.policy.session_hmac_key()
        sstore = SessionStore(rt_v5.store, rt_v5.policy)
        rec1 = sstore.bind_session(
            principal_id=prin_a.principal_id,
            repo_id=ws_a.repo_id,
            checkout_id=ws_a.checkout_id,
            harness_id="claude-code",
            raw_session_id=raw_s1,
            now=clock.now(),
        )
        ref1 = rec1.session_ref
        assert ref1 == compute_session_ref(key0, raw_s1)

        clock.advance(dt.timedelta(seconds=5))
        bak_store_before_s2 = create_store_backup(rt_v5.store, os_, clock.now())
        clock.advance(dt.timedelta(seconds=5))
        bak_pol_v5_before_s2 = create_policy_backup(rt_v5.policy, os_, clock.now())

        clock.advance(dt.timedelta(seconds=5))
        rec2 = sstore.bind_session(
            principal_id=prin_a.principal_id,
            repo_id=ws_a.repo_id,
            checkout_id=ws_a.checkout_id,
            harness_id="claude-code",
            raw_session_id=raw_s2,
            now=clock.now(),
        )
        ref2 = rec2.session_ref
        assert ref2 == compute_session_ref(key0, raw_s2)
    finally:
        rt_v5.close()

    assert isinstance(SessionPolicyRestoreStageHook(), SessionPolicyRestoreStageHook)

    def _assert_post_restore(target_root: Path) -> None:
        reopened = _reopen_v5_runtime(target_root, store_id, os_)
        try:
            assert reopened.policy.session_hmac_key() == key0
            assert compute_session_ref(reopened.policy.session_hmac_key(), raw_s1) == ref1
            assert compute_session_ref(reopened.policy.session_hmac_key(), raw_s2) == ref2
            ss = SessionStore(reopened.store, reopened.policy)
            for raw_sid, expected_ref in ((raw_s1, ref1), (raw_s2, ref2)):
                loaded = ss.get_session(expected_ref, repo_id=ws_a.repo_id, checkout_id=ws_a.checkout_id)
                assert loaded.session_ref == expected_ref
                assert loaded.principal_id == prin_a.principal_id
                with pytest.raises(BrainError) as mismatch:
                    ss.bind_session(
                        principal_id=prin_b.principal_id,
                        repo_id=ws_a.repo_id,
                        checkout_id=ws_a.checkout_id,
                        harness_id="codex",
                        raw_session_id=raw_sid,
                        now=clock.now(),
                    )
                assert mismatch.value.code is ErrorCode.IDENTITY_MISMATCH
        finally:
            reopened.close()

    # 1. restore_store only (older store backup missing ref2 in brain.db).
    c1 = trusted_tmp / "combo-1-store-only"
    clone_owner_only_tree(base_root, c1)
    clock.advance(dt.timedelta(seconds=10))
    with maintenance_lease(c1, os_) as (mroot, mlease):
        p1 = PolicyStore.open(mroot, mlease, os_, migrations=KERNEL_POLICY_MIGRATIONS)
        try:
            restore_store(mroot, mlease, os_, bak_store_before_s2, p1, clock.now(), migrations=KERNEL_STORE_MIGRATIONS)
        finally:
            p1.close()
    _assert_post_restore(c1)

    # 2. restore_policy only from policy v5 backup (missing ref2 in backup).
    c2 = trusted_tmp / "combo-2-policy-v5-only"
    clone_owner_only_tree(base_root, c2)
    clock.advance(dt.timedelta(seconds=10))
    with maintenance_lease(c2, os_) as (mroot, mlease):
        restore_policy(
            mroot,
            mlease,
            os_,
            bak_pol_v5_before_s2,
            store_id=store_id,
            now=clock.now(),
            migrations=KERNEL_POLICY_MIGRATIONS,
        )
    _assert_post_restore(c2)

    # 3. restore_policy only from I3 policy v4 backup upgrading v4 -> v5 on stage (key0 + bindings MUST survive!).
    c3 = trusted_tmp / "combo-3-policy-v4-upgrade"
    clone_owner_only_tree(base_root, c3)
    clock.advance(dt.timedelta(seconds=10))
    with maintenance_lease(c3, os_) as (mroot, mlease):
        restore_policy(
            mroot,
            mlease,
            os_,
            bak_pol_v4,
            store_id=store_id,
            now=clock.now(),
            migrations=KERNEL_POLICY_MIGRATIONS,
        )
    assert read_schema_info(DataRoot.at(c3).policy_db) == SchemaInfo(5, 5, store_id)
    _assert_post_restore(c3)

    # 4a. Both orders: store -> policy.
    c4a = trusted_tmp / "combo-4a-store-then-policy"
    clone_owner_only_tree(base_root, c4a)
    clock.advance(dt.timedelta(seconds=10))
    with maintenance_lease(c4a, os_) as (mroot, mlease):
        pa = PolicyStore.open(mroot, mlease, os_, migrations=KERNEL_POLICY_MIGRATIONS)
        try:
            restore_store(mroot, mlease, os_, bak_store_before_s2, pa, clock.now(), migrations=KERNEL_STORE_MIGRATIONS)
        finally:
            pa.close()
        clock.advance(dt.timedelta(seconds=5))
        restore_policy(
            mroot,
            mlease,
            os_,
            bak_pol_v5_before_s2,
            store_id=store_id,
            now=clock.now(),
            migrations=KERNEL_POLICY_MIGRATIONS,
        )
    _assert_post_restore(c4a)

    # 4b. Both orders: policy -> store.
    c4b = trusted_tmp / "combo-4b-policy-then-store"
    clone_owner_only_tree(base_root, c4b)
    clock.advance(dt.timedelta(seconds=10))
    with maintenance_lease(c4b, os_) as (mroot, mlease):
        restore_policy(
            mroot,
            mlease,
            os_,
            bak_pol_v5_before_s2,
            store_id=store_id,
            now=clock.now(),
            migrations=KERNEL_POLICY_MIGRATIONS,
        )
        clock.advance(dt.timedelta(seconds=5))
        pb = PolicyStore.open(mroot, mlease, os_, migrations=KERNEL_POLICY_MIGRATIONS)
        try:
            restore_store(mroot, mlease, os_, bak_store_before_s2, pb, clock.now(), migrations=KERNEL_STORE_MIGRATIONS)
        finally:
            pb.close()
    _assert_post_restore(c4b)


def test_session_segments_exposure_and_two_checkout_isolation_case_2(trusted_tmp: Path) -> None:
    from superbrain.ports.continuity import ExposureEvidence, RecipientProfile
    from superbrain.storage.sessions import SessionStore

    clock = FakeClock(_START)
    os_ = os_adapters(clock=clock)
    root = trusted_tmp / "case2-checkouts"

    rt = _open_v5_runtime(root, os_, role="sp23-c2")
    try:
        prin = seed_principal_and_credential(
            rt.policy, owner_id="dan", harness_id="claude-code", machine_id="m-1"
        ).principal
        same_remote = "https://github.example/dan/shared-repo.git"
        ws_a = register_workspace_direct(
            rt, clock, prin, alias="chk-alpha", checkout_dir=trusted_tmp / "ws-alpha", remote=same_remote
        )
        ws_b = register_workspace_direct(
            rt, clock, prin, alias="chk-beta", checkout_dir=trusted_tmp / "ws-beta", remote=same_remote
        )
        assert ws_a.repo_id == ws_b.repo_id
        assert ws_a.checkout_id != ws_b.checkout_id

        # Create identical relative file paths inside both checkouts.
        for d in (trusted_tmp / "ws-alpha", trusted_tmp / "ws-beta"):
            (d / "src").mkdir(exist_ok=True)
            (d / "src" / "app.py").write_text("print('same relative path')\n", encoding="utf-8")

        prof1 = RecipientProfile(
            harness_id="claude-code",
            provider_endpoint_digest=digest_bytes(b"https://api.provider.example/v1"),
            model_config_digest=digest_bytes(b"claude-sonnet-4"),
            account_digest=digest_bytes(b"acct-1"),
        )
        prof2 = RecipientProfile(
            harness_id="claude-code",
            provider_endpoint_digest=digest_bytes(b"https://api.provider.example/v1"),
            model_config_digest=digest_bytes(b"claude-opus-4"),
            account_digest=digest_bytes(b"acct-1"),
        )

        ss = SessionStore(rt.store, rt.policy)
        rec = ss.bind_session(
            principal_id=prin.principal_id,
            repo_id=ws_a.repo_id,
            checkout_id=ws_a.checkout_id,
            harness_id="claude-code",
            raw_session_id="CASE2_TWO_CHECKOUT_SID",
            profile=prof1,
            now=clock.now(),
        )
        seg1 = ss.open_or_switch_segment(
            session_ref=rec.session_ref, checkout_id=ws_a.checkout_id, profile=prof1, now=clock.now()
        )
        assert seg1.segment_index == 1

        clock.advance(dt.timedelta(seconds=10))
        seg2 = ss.open_or_switch_segment(
            session_ref=rec.session_ref, checkout_id=ws_a.checkout_id, profile=prof2, now=clock.now()
        )
        assert seg2.segment_index == 2
        assert seg2.segment_id != seg1.segment_id

        item_digest = digest_bytes(b"shared-item-content")
        ss.record_capture_exposure(
            event_id="evt-exp-1",
            item_ref="item-1",
            item_digest=item_digest,
            segment_id=seg1.segment_id,
            exposure_evidence=ExposureEvidence.SENT_TO_RECIPIENT,
            completed_model_call_id="mcall-1",
            recorded_at=clock.now(),
        )
        ss.record_capture_exposure(
            event_id="evt-exp-2",
            item_ref="item-1",
            item_digest=item_digest,
            segment_id=seg2.segment_id,
            exposure_evidence=ExposureEvidence.LOCAL_ONLY,
            completed_model_call_id=None,
            recorded_at=clock.now(),
        )
        assert (
            ss.read_capture_exposure(item_ref="item-1", segment_id=seg1.segment_id)
            is ExposureEvidence.SENT_TO_RECIPIENT
        )
        assert ss.read_capture_exposure(item_ref="item-1", segment_id=seg2.segment_id) is ExposureEvidence.LOCAL_ONLY
        assert ss.read_capture_exposure(item_ref="item-other", segment_id=seg1.segment_id) is ExposureEvidence.UNKNOWN

        # Case 2: lookup scoped by checkout_id rejects second checkout on same remote/repo with NOT_FOUND.
        loaded_a = ss.get_session(rec.session_ref, repo_id=ws_a.repo_id, checkout_id=ws_a.checkout_id)
        assert loaded_a.session_ref == rec.session_ref
        with pytest.raises(BrainError) as cross_checkout:
            ss.get_session(rec.session_ref, repo_id=ws_b.repo_id, checkout_id=ws_b.checkout_id)
        assert cross_checkout.value.code is ErrorCode.NOT_FOUND
    finally:
        rt.close()


def test_raw_session_id_zero_leak_across_db_cas_outbox_logs_and_outputs(
    trusted_tmp: Path, caplog: pytest.LogCaptureFixture
) -> None:
    from superbrain.ports.capture import StagedCaptureEvent
    from superbrain.storage.capture_events import KernelCaptureStore

    canary_raw = "CANARY_RAW_SESSION_ID_DO_NOT_LEAK_7741"

    from superbrain.domain.continuity.sessions import compute_session_ref
    from superbrain.domain.continuity.worker_rules import extract_observed_summary
    from superbrain.ports.continuity import RecipientProfile
    from superbrain.storage.sessions import SessionStore

    clock = FakeClock(_START)
    os_ = os_adapters(clock=clock)
    root = trusted_tmp / "leak-scan"
    outbox_dir = trusted_tmp / "leak-outbox"

    rt = _open_v5_runtime(root, os_, role="sp23-leak")
    with caplog.at_level(logging.DEBUG):
        try:
            prin = seed_principal_and_credential(
                rt.policy, owner_id="dan", harness_id="claude-code", machine_id="m-1"
            ).principal
            ws_a = register_workspace_direct(rt, clock, prin, alias="repo-leak", checkout_dir=trusted_tmp / "chk-leak")
            sref = compute_session_ref(rt.policy.session_hmac_key(), canary_raw)

            ss = SessionStore(rt.store, rt.policy)
            prof = RecipientProfile(
                harness_id="claude-code",
                provider_endpoint_digest=digest_bytes(b"https://api.example"),
                model_config_digest=digest_bytes(b"model-1"),
                account_digest=digest_bytes(b"acct-1"),
            )
            bound = ss.bind_session(
                principal_id=prin.principal_id,
                repo_id=ws_a.repo_id,
                checkout_id=ws_a.checkout_id,
                harness_id="claude-code",
                raw_session_id=canary_raw,
                profile=prof,
                now=clock.now(),
            )
            assert bound.session_ref == sref

            spool = OutboxSpool(outbox_dir, permissions=os_.permissions)
            ev = CaptureEventRecord(
                event_id="evt-leak-1",
                producer_stream="stream-leak",
                sequence=1,
                harness_id="claude-code",
                kind="tool_post",
                recorded_at="2026-11-21T12:00:01Z",
                payload={"tool": "Edit", "file_path": "README.md", "summary": "safe update"},
                session_ref=sref,
                source_metadata={"host_version": "2.1.325"},
            )
            spool.enqueue_event(ev)

            payload_bytes = json.dumps(ev.payload, sort_keys=True).encode("utf-8")
            staged = StagedCaptureEvent(
                record=ev,
                payload_bytes=payload_bytes,
                payload_digest=digest_bytes(payload_bytes),
                source="tool_observed",
                source_verification="verified_host",
            )
            cstore = KernelCaptureStore(rt.store)
            ack = cstore.commit_staged_batch(
                producer_stream="stream-leak",
                repo_id=ws_a.repo_id,
                checkout_id=ws_a.checkout_id,
                principal_id=prin.principal_id,
                events=(staged,),
                gaps=(),
                now=clock.now(),
            )
            assert ack.accepted_count == 1

            summary = extract_observed_summary((ev,))
            l0_l1_l2_repr = json.dumps(
                {
                    "session_ref": bound.session_ref,
                    "summary": summary.to_dict(),
                    "ack": ack.to_dict(),
                },
                sort_keys=True,
            )
            assert canary_raw not in l0_l1_l2_repr
            assert sref in l0_l1_l2_repr
        finally:
            rt.close()

    needle = canary_raw.encode("utf-8")
    layout = DataRoot.at(root)
    assert needle not in read_all_bytes(db_files(layout.policy_db) + db_files(layout.store_db))

    for p in list(layout.cas_dir.rglob("*")) + list(outbox_dir.rglob("*")):
        if p.is_file():
            assert needle not in p.read_bytes(), f"raw session_id leaked in {p}"

    for rec in caplog.records:
        assert canary_raw not in rec.getMessage()
