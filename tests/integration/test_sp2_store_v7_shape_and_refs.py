"""SP2-3 store v7, review r6 findings 1 and 2.

Requirement sources: owner condition 1 (only the three known store v6 shapes upgrade; any other or partial schema
fails before the swap and before READY), spec 7.4 (only content of the exact pinned and verified event is used),
owner condition 2 (an event without a trusted task link is kept and the link is not used) and review r6 (a mismatch
that keeps stream, sequence and digest, and the same check when the migration runs behind a store restore).
"""

from __future__ import annotations

import datetime as dt
import json
import shutil
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.application.continuity_worker import sweep_legacy_continuity_copies
from superbrain.composition.kernel_projections import kernel_store_extensions
from superbrain.composition.migrate_entry import migrate_offline
from superbrain.core.canonical import canonical_json
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.capture import CaptureEventRecord
from superbrain.storage.backup import create_store_backup
from superbrain.storage.kernel_schema import KERNEL_STORE_MIGRATIONS
from superbrain.storage.layout import DataRoot
from superbrain.storage.restore import restore_store
from superbrain.storage.runtime import Runtime, admit_existing_pair, open_runtime_under_lease
from superbrain.storage.schema import SchemaInfo, read_schema_info
from superbrain.storage.sessions import SessionStore
from tests.integration.test_sp2_store_v7_migration import (
    _START,
    _STREAM,
    _build_v6_store,
    _config,
    _file_digest,
    _iso,
    v6_policy_migrations,
)
from tests.support.clock import FakeClock
from tests.support.inc2_fixture import kernel_job_service, reopen_kernel_job_runtime
from tests.support.inc2_transport import FakeMonotonicClock

_DIVERGENT_SCHEMAS = [
    ("r5", "ALTER TABLE tasks DROP COLUMN updated_at"),
    ("r5", "DROP INDEX idx_sessions_scope"),
    ("r5", "ALTER TABLE sessions ADD COLUMN extra TEXT"),
    ("778e451", "ALTER TABLE continuity_refresh_state DROP COLUMN last_summarized_rowid"),
    ("778e451", "CREATE INDEX idx_extra ON session_task_events (event_id)"),
    # Review r7 finding 1: the store v6 capture tables the v7 code reads are part of every shape.
    ("c57fb92", "ALTER TABLE capture_events DROP COLUMN cas_holder_id"),
    ("r5", "ALTER TABLE capture_events DROP COLUMN cas_holder_id"),
    ("778e451", "DROP INDEX idx_capture_gaps_status"),
]


@pytest.mark.parametrize(("shape", "change"), _DIVERGENT_SCHEMAS)
def test_store_v6_with_every_continuity_table_but_a_divergent_definition_fails_before_ready(
    trusted_tmp: Path, shape: str, change: str
) -> None:
    clock = FakeClock(_START)
    os_ = os_adapters(clock=clock, monotonic=FakeMonotonicClock())
    fx = _build_v6_store(trusted_tmp, os_, clock, shape)
    db = sqlite3.connect(DataRoot.at(fx.root).store_db)
    try:
        with db:
            db.execute(change)
    finally:
        db.close()
    cfg = _config(fx, trusted_tmp, os_, clock)
    store_before = _file_digest(DataRoot.at(fx.root).store_db)
    with pytest.raises(BrainError) as failed:
        migrate_offline(cfg, os_)
    assert failed.value.code is ErrorCode.INTEGRITY_FAILURE
    assert read_schema_info(DataRoot.at(fx.root).store_db) == SchemaInfo(6, 6, fx.store_id)
    assert _file_digest(DataRoot.at(fx.root).store_db) == store_before
    with pytest.raises(BrainError) as not_ready:
        admit_existing_pair(fx.root, fx.store_id, os_, purpose="serve").release()
    assert not_ready.value.code is ErrorCode.MIGRATION_REQUIRED


def _resolved_ids(ss: SessionStore, task_id: str, refs: list[dict[str, Any]], now: dt.datetime) -> list[str]:
    payload = canonical_json({"cutoff_order": 0, "events": refs, "task_id": task_id})
    return [str(e["event_id"]) for e in json.loads(ss.resolve_refresh_sources(payload, now=now))["events"]]


def _open_v6(root: Path, store_id: str, os_: Any, shape: str) -> Runtime:
    handlers, kinds = kernel_store_extensions()
    lease = admit_existing_pair(
        root, store_id, os_, purpose="serve",
        store_migrations=KERNEL_STORE_MIGRATIONS[:6], policy_migrations=v6_policy_migrations(shape),
    )
    return open_runtime_under_lease(
        lease, handlers=handlers, kinds=kinds,
        store_migrations=KERNEL_STORE_MIGRATIONS[:6], policy_migrations=v6_policy_migrations(shape),
    )


@pytest.mark.parametrize("path", ["offline_migrate", "store_restore"])
def test_continuity_refs_resolve_only_the_pinned_event_of_a_verified_link(trusted_tmp: Path, path: str) -> None:
    clock = FakeClock(_START)
    os_ = os_adapters(clock=clock, monotonic=FakeMonotonicClock())
    fx = _build_v6_store(trusted_tmp, os_, clock, "778e451")
    backup = None
    if path == "store_restore":
        rt6 = _open_v6(fx.root, fx.store_id, os_, "778e451")
        try:
            backup = create_store_backup(rt6.store, os_, clock.now())
        finally:
            rt6.close()
    migrate_offline(_config(fx, trusted_tmp, os_, clock), os_)
    if backup is not None:
        # The daemon's online restore: close the store, restore the v6 backup (migrated to v7 on the way), reopen.
        rt = reopen_kernel_job_runtime(fx.root, fx.store_id, os_)
        try:
            rt.store.close()
            restore_store(rt.root, rt.lease, os_, backup, rt.policy, clock.now(), migrations=KERNEL_STORE_MIGRATIONS)
        finally:
            rt.policy.close()
            rt.lease.release()
    assert read_schema_info(DataRoot.at(fx.root).store_db) == SchemaInfo(7, 7, fx.store_id)

    rt = reopen_kernel_job_runtime(fx.root, fx.store_id, os_)
    try:
        ss = SessionStore(rt.store, rt.policy)
        if path == "store_restore":
            job_service, _kstore = kernel_job_service(rt, clock)
            assert ss.legacy_sweep_rows()
            sweep_legacy_continuity_copies(job_service, ss)
            assert ss.legacy_sweep_rows() == ()
            assert all(rt.store.cas.holders(d) == [] for d in fx.copy_digests)
        now = clock.now()
        refs = [
            {"event_id": f"evt-v7-778e451-{s}", "payload_digest": d, "producer_stream": _STREAM, "sequence": s}
            for s, d in enumerate(fx.event_digests, start=1)
        ]
        ids = [f"evt-v7-778e451-{s}" for s in (1, 2, 3)]
        assert _resolved_ids(ss, fx.legacy_task, refs, now) == ids
        # Same stream, sequence and digest, another pinned event ID: not resolved.
        forged = [dict(r) for r in refs]
        forged[1]["event_id"] = "evt-forged"
        assert _resolved_ids(ss, fx.legacy_task, forged, now) == [ids[0], ids[2]]
        # A task the events are not linked to: nothing resolved.
        assert _resolved_ids(ss, "task-unlinked", refs, now) == []
        # A link whose event records another session is not trusted; the event itself is kept.
        with rt.store.transaction() as txn:
            txn.db.execute(
                "UPDATE capture_events SET session_ref = ? WHERE producer_stream = ? AND sequence = 3",
                ("sha256:" + "cd" * 32, _STREAM),
            )
        assert _resolved_ids(ss, fx.legacy_task, refs, now) == ids[:2]
        kept = rt.store._db.execute(
            "SELECT event_id FROM capture_events WHERE producer_stream = ? AND sequence = 3", (_STREAM,)
        ).fetchone()
        assert kept is not None and str(kept[0]) == ids[2]
        # A task or session recorded under another checkout than the event: not trusted.
        for table, key, value in (
            ("tasks", "task_id", fx.legacy_task),
            ("sessions", "session_ref", "sha256:" + "ab" * 32),
        ):
            with rt.store.transaction() as txn:
                txn.db.execute(f"UPDATE {table} SET checkout_id = 'chk-other' WHERE {key} = ?", (value,))
            assert _resolved_ids(ss, fx.legacy_task, refs, now) == []
            with rt.store.transaction() as txn:
                txn.db.execute(f"UPDATE {table} SET checkout_id = ? WHERE {key} = ?", (fx.checkout_id, value))
            assert _resolved_ids(ss, fx.legacy_task, refs, now) == ids[:2]
        # Review r7 finding 2: only the identity changes (event ID, session ref, repo, checkout, digest kept).
        # An event recorded under another principal than the session's binding is not resolved.
        def _set_principal(table: str, where: str, args: tuple[Any, ...], principal: str) -> None:
            with rt.store.transaction() as txn:
                txn.db.execute(f"UPDATE {table} SET principal_id = ? WHERE {where}", (principal, *args))

        one = ("producer_stream = ? AND sequence = 1", (_STREAM,))
        _set_principal("capture_events", *one, "principal-other")
        assert _resolved_ids(ss, fx.legacy_task, refs, now) == [ids[1]]
        _set_principal("capture_events", *one, fx.principal_id)
        # Event and session rows agreeing with each other but not with the binding in policy.db: not resolved.
        every = ("producer_stream = ?", (_STREAM,))
        session = ("session_ref = ?", ("sha256:" + "ab" * 32,))
        _set_principal("capture_events", *every, "principal-other")
        _set_principal("sessions", *session, "principal-other")
        assert _resolved_ids(ss, fx.legacy_task, refs, now) == []
        _set_principal("capture_events", *every, fx.principal_id)
        _set_principal("sessions", *session, fx.principal_id)
        assert _resolved_ids(ss, fx.legacy_task, refs, now) == ids[:2]
        # A session row naming another principal than its events: not resolved either.
        _set_principal("sessions", *session, "principal-other")
        assert _resolved_ids(ss, fx.legacy_task, refs, now) == []
        _set_principal("sessions", *session, fx.principal_id)
        # The binding in policy.db scoped to another checkout than the event: not resolved.
        with rt.policy._db:
            rt.policy._db.execute(
                "UPDATE session_ref_bindings SET checkout_id = 'chk-other' WHERE session_ref = ?", session[1]
            )
        assert _resolved_ids(ss, fx.legacy_task, refs, now) == []
        with rt.policy._db:
            rt.policy._db.execute(
                "UPDATE session_ref_bindings SET checkout_id = ? WHERE session_ref = ?", (fx.checkout_id, *session[1])
            )
        assert _resolved_ids(ss, fx.legacy_task, refs, now) == ids[:2]

        # The long-running checkpoint source is resolved under the same rule.
        sref = ss.bind_session(
            principal_id=fx.principal_id, repo_id=fx.repo_id, checkout_id=fx.checkout_id,
            harness_id="claude-code", raw_session_id=f"RAW_R6_{path}", now=now,
        ).session_ref
        task = f"task-lr-{path}"
        ss.ensure_task_handoff(task_id=task, repo_id=fx.repo_id, checkout_id=fx.checkout_id, session_ref=sref, now=now)
        ss.record_session_event(
            session_ref=sref, repo_id=fx.repo_id, checkout_id=fx.checkout_id, task_id=task,
            producer_stream="stream-r6-lr",
            event=CaptureEventRecord(
                event_id="evt-r6-lr-1", producer_stream="stream-r6-lr", sequence=1, harness_id="claude-code",
                kind="long_running_job", recorded_at=_iso(now),
                payload={"status": "running", "pid": 4242, "command": "sleep 600"}, session_ref=sref,
            ),
            now=now,
        )
        digest_row = rt.store._db.execute(
            "SELECT payload_digest FROM session_task_events WHERE task_id = ?", (task,)
        ).fetchone()
        assert digest_row is not None

        def _checkpoint(event_id: str) -> object:
            with rt.store.transaction() as txn:
                txn.db.execute("DELETE FROM session_checkpoints WHERE task_id = ?", (task,))
                txn.db.execute(
                    "INSERT INTO session_checkpoints VALUES (?, ?, ?, 'long_running', ?, ?)",
                    (f"ck-{event_id}", sref, task,
                     json.dumps({"source": ["stream-r6-lr", 1, event_id, str(digest_row[0])]}), _iso(now)),
                )
            return ss.read_long_running_checkpoint(task)

        assert _checkpoint("evt-r6-lr-1") is not None
        assert _checkpoint("evt-forged") is None
        _set_principal("capture_events", "producer_stream = ?", ("stream-r6-lr",), "principal-other")
        assert _checkpoint("evt-r6-lr-1") is None
    finally:
        rt.close()


def test_store_restore_of_a_v6_backup_with_a_divergent_capture_table_fails_and_keeps_the_live_store(
    trusted_tmp: Path,
) -> None:
    """Review r7 finding 1 on the restore path: the backup is migrated by the same v7 migration and refused."""
    clock = FakeClock(_START)
    os_ = os_adapters(clock=clock, monotonic=FakeMonotonicClock())
    fx = _build_v6_store(trusted_tmp, os_, clock, "r5")
    store_dir = DataRoot.at(fx.root).store_db.parent
    healthy = trusted_tmp / "healthy-store"
    shutil.copytree(store_dir, healthy)
    db = sqlite3.connect(DataRoot.at(fx.root).store_db)
    try:
        with db:
            db.execute("ALTER TABLE capture_events DROP COLUMN cas_holder_id")
    finally:
        db.close()
    rt6 = _open_v6(fx.root, fx.store_id, os_, "r5")
    try:
        backup = create_store_backup(rt6.store, os_, clock.now())
    finally:
        rt6.close()
    shutil.rmtree(store_dir)
    shutil.copytree(healthy, store_dir)
    migrate_offline(_config(fx, trusted_tmp, os_, clock), os_)
    assert read_schema_info(DataRoot.at(fx.root).store_db) == SchemaInfo(7, 7, fx.store_id)

    rt = reopen_kernel_job_runtime(fx.root, fx.store_id, os_)
    try:
        rt.store.close()
        with pytest.raises(BrainError) as refused:
            restore_store(rt.root, rt.lease, os_, backup, rt.policy, clock.now(), migrations=KERNEL_STORE_MIGRATIONS)
        assert refused.value.code is ErrorCode.INTEGRITY_FAILURE
    finally:
        rt.policy.close()
        rt.lease.release()
    assert read_schema_info(DataRoot.at(fx.root).store_db) == SchemaInfo(7, 7, fx.store_id)
    rt = reopen_kernel_job_runtime(fx.root, fx.store_id, os_)
    try:
        rows = rt.store._db.execute("SELECT COUNT(*), MIN(cas_holder_id) FROM capture_events").fetchone()
        assert rows is not None and int(rows[0]) == 3 and rows[1] is not None
    finally:
        rt.close()
