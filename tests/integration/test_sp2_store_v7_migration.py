"""SP2-3 store v7 (owner decision 2026-11-22, review r5 finding 1).

Requirement sources: spec 5.8 (an upgrade keeps existing data and declares its schema before serving), 5.6 and 7.4
(nothing derived from an event outlives it; the observed part is refs only), and the owner's acceptance conditions:
every known store v6 shape (``c57fb92`` without continuity tables, ``778e451`` with ``event_json`` copies, r5 refs
only) upgrades through ``migrate --offline -> serve -> ingest/refresh``, also after an interruption between the
policy and store upgrade; an unknown shape fails before READY; the previous binary refuses a v7 store before any
write.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.tls_material import create_store_tls
from superbrain.composition.daemon_entry import create_daemon_owner_loop
from superbrain.composition.kernel_projections import kernel_store_extensions
from superbrain.composition.migrate_entry import migrate_offline
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import DaemonConfig, JobErrorCode, JobSpec, JobState
from superbrain.ports.capture import CaptureEventRecord, StagedCaptureEvent
from superbrain.ports.os import OsAdapters
from superbrain.storage._continuity_schema import _create_continuity_tables
from superbrain.storage.capture_events import KernelCaptureStore
from superbrain.storage.idempotency import StagedKernelStore
from superbrain.storage.kernel_schema import KERNEL_POLICY_MIGRATIONS, KERNEL_STORE_MIGRATIONS
from superbrain.storage.kinds import RetentionClass
from superbrain.storage.layout import DataRoot
from superbrain.storage.runtime import Runtime, admit_existing_pair
from superbrain.storage.schema import SchemaInfo, read_schema_info
from superbrain.storage.sqlite import open_readonly
from superbrain.workers.executor import PRODUCTION_JOB_HANDLERS
from tests.support.clock import FakeClock
from tests.support.inc2_fixture import kernel_job_service, open_cloned_runtime
from tests.support.inc2_transport import FakeMonotonicClock, register_workspace_direct
from tests.support.kernel_auth import make_bootstrap_auth, seed_principal_and_credential

_START = dt.datetime(2026, 11, 22, 9, 0, tzinfo=dt.UTC)
_SENTINEL = "SENTINEL_V7_COPY_5C1D"
_STREAM = "stream-v7"
_SESSION_REF = "sha256:" + "ab" * 32
_WAIT_S = 20.0
# The link table exactly as commit 778e451 created it (git show 778e451:src/superbrain/storage/_capture_schema.py).
_LINK_TABLE_778E451 = (
    "CREATE TABLE session_task_events ("
    "event_order INTEGER PRIMARY KEY AUTOINCREMENT, "
    "task_id TEXT NOT NULL REFERENCES tasks(task_id), "
    "session_ref TEXT NOT NULL REFERENCES sessions(session_ref), "
    "producer_stream TEXT NOT NULL, "
    "sequence INTEGER NOT NULL, "
    "event_id TEXT NOT NULL, "
    "harness_id TEXT NOT NULL, "
    "kind TEXT NOT NULL, "
    "recorded_at TEXT NOT NULL, "
    "payload_digest TEXT NOT NULL, "
    "event_json TEXT NOT NULL, "
    "UNIQUE(task_id, producer_stream, sequence))"
)


def _iso(value: dt.datetime) -> str:
    return value.astimezone(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sqlite_cells_with(root: Path, needle: str, scratch: Path) -> list[str]:
    hits: list[str] = []
    with contextlib.closing(open_readonly(DataRoot.at(root).store_db, scratch_dir=scratch)) as conn:
        tables = [str(r[0]) for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")]
        for table in tables:
            for row in conn.execute(f'SELECT * FROM "{table}"').fetchall():
                for cell in row:
                    text = cell.decode("utf-8", "replace") if isinstance(cell, bytes) else str(cell)
                    if needle in text:
                        hits.append(table)
    return hits


def _query(root: Path, scratch: Path, sql: str, args: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    with contextlib.closing(open_readonly(DataRoot.at(root).store_db, scratch_dir=scratch)) as conn:
        return [tuple(r) for r in conn.execute(sql, args).fetchall()]


class _Fixture:
    def __init__(self, root: Path, store_id: str, repo_id: str, checkout_id: str, principal_id: str) -> None:
        self.root = root
        self.store_id = store_id
        self.repo_id = repo_id
        self.checkout_id = checkout_id
        self.principal_id = principal_id
        self.event_digests: list[str] = []
        self.legacy_task = f"task-{new_id()}"
        self.legacy_job_id: str | None = None
        self.copy_digests: list[str] = []


def v6_policy_migrations(shape: str) -> Any:
    return KERNEL_POLICY_MIGRATIONS[: 4 if shape == "c57fb92" else 5]


def _build_v6_store(tmp: Path, os_: OsAdapters, clock: FakeClock, shape: str) -> _Fixture:
    """A store v6 data root with captured events, plus the continuity rows of ``shape``.

    ``c57fb92`` predates the policy v5 session bindings (policy v4). The ``778e451`` and r5 builds bound sessions in
    ``policy.db`` (policy v5) before writing continuity rows, so their roots carry that binding.
    """
    root = tmp / f"v6-{shape}"
    handlers, kinds = kernel_store_extensions()
    rt = open_cloned_runtime(
        root,
        os_,
        role=f"sp23-v7-{shape}",
        handlers=handlers,
        kinds=kinds,
        store_migrations=KERNEL_STORE_MIGRATIONS[:6],
        policy_migrations=v6_policy_migrations(shape),
    )
    try:
        assert read_schema_info(rt.root.store_db) == SchemaInfo(6, 6, rt.store.store_id)
        cred = seed_principal_and_credential(rt.policy, owner_id="dan", harness_id="claude-code", machine_id="m-v7")
        ws = register_workspace_direct(
            rt, clock, cred.principal, alias=f"repo-v7-{shape}", checkout_dir=tmp / f"chk-{shape}"
        )
        rt.store.reconcile_policy()
        fx = _Fixture(root, rt.store.store_id, ws.repo_id, ws.checkout_id, cred.principal.principal_id)
        if shape != "c57fb92":
            rt.policy.bind_or_verify_session_ref(
                _SESSION_REF, principal_id=fx.principal_id, repo_id=ws.repo_id, checkout_id=ws.checkout_id,
                harness_id="claude-code", now=clock.now(),
            )
        staged = []
        for seq in (1, 2, 3):
            payload: dict[str, JsonValue] = {"tool": "Bash", "command": f"pytest -q {seq}", "exit_code": seq % 2}
            body = canonical_json(payload)
            staged.append(
                StagedCaptureEvent(
                    record=CaptureEventRecord(
                        event_id=f"evt-v7-{shape}-{seq}", producer_stream=_STREAM, sequence=seq,
                        harness_id="claude-code", kind="tool_post", recorded_at=_iso(clock.now()), payload=payload,
                        session_ref=_SESSION_REF,
                    ),
                    payload_bytes=body,
                    payload_digest=digest_bytes(body),
                    source="unknown",
                    source_verification="unverified",
                )
            )
            fx.event_digests.append(digest_bytes(body))
        KernelCaptureStore(rt.store).commit_staged_batch(
            producer_stream=_STREAM, repo_id=ws.repo_id, checkout_id=ws.checkout_id,
            principal_id=fx.principal_id, events=tuple(staged), gaps=(), now=clock.now(),
        )
        if shape == "778e451":
            svc, kstore = kernel_job_service(rt, clock)
            job_payload = canonical_json({"events": [{"note": _SENTINEL}], "task_id": fx.legacy_task})
            kstore.stage_blob(job_payload)
            spec = JobSpec(kind="continuity.refresh", owner_id="dan", payload=job_payload)
            fx.legacy_job_id = kstore.transact(lambda tx: svc.enqueue(tx, spec)).job_id
            observed = canonical_json({"modified_files": [f"src/{_SENTINEL}.py"]})
            rt.store.cas.put(observed)
            with rt.store.transaction() as txn:
                txn.hold(
                    digest_bytes(observed), "event", fx.legacy_job_id, RetentionClass.DURABLE,
                    clock.now() + dt.timedelta(days=365),
                )
            fx.copy_digests = [digest_bytes(job_payload), digest_bytes(observed)]
    finally:
        rt.close()
    if shape in ("778e451", "r5"):
        _write_continuity_rows(fx, clock, legacy=shape == "778e451")
    return fx


def _write_continuity_rows(fx: _Fixture, clock: FakeClock, *, legacy: bool) -> None:
    """Continuity tables and rows as the development build of that shape left them (written while closed)."""
    stamp = _iso(clock.now())
    shape = "778e451" if legacy else "r5"
    db = sqlite3.connect(DataRoot.at(fx.root).store_db)
    try:
        with db:
            _create_continuity_tables(db)
            if legacy:
                db.execute("DROP TABLE session_task_events")
                db.execute(_LINK_TABLE_778E451)
            db.execute(
                "INSERT INTO sessions VALUES (?, ?, ?, ?, 'claude-code', 'active', ?, NULL, NULL)",
                (_SESSION_REF, fx.repo_id, fx.checkout_id, fx.principal_id, stamp),
            )
            db.execute(
                "INSERT INTO tasks VALUES (?, 'dan', ?, ?, 0, 0, 'in_progress', 'inferred', ?, ?, ?, ?)",
                (fx.legacy_task, fx.repo_id, fx.checkout_id, fx.principal_id, _SESSION_REF, stamp, stamp),
            )
            observed_ref = fx.copy_digests[1] if legacy else None
            db.execute(
                "INSERT INTO task_handoffs VALUES (?, ?, ?, ?, 1, 0, 0, 0, NULL, ?, 'in_progress', 'inferred', "
                "?, ?, NULL, ?)",
                (fx.legacy_task, new_id(), fx.repo_id, fx.checkout_id, observed_ref, fx.principal_id, _SESSION_REF,
                 stamp),
            )
            db.execute(
                "INSERT INTO continuity_refresh_state VALUES (?, ?, 'dan', ?, ?, 0, NULL, ?, 0, NULL, NULL, 0, 3)",
                (fx.legacy_task, _SESSION_REF, fx.repo_id, fx.checkout_id, stamp),
            )
            cols = "task_id, session_ref, producer_stream, sequence, event_id, harness_id, kind, recorded_at, "
            cols += "payload_digest" + (", event_json" if legacy else "")
            for seq, digest in enumerate(fx.event_digests, start=1):
                values: list[Any] = [
                    fx.legacy_task, _SESSION_REF, _STREAM, seq, f"evt-v7-{shape}-{seq}", "claude-code", "tool_post",
                    stamp, digest,
                ]
                if legacy:
                    values.append(json.dumps({"payload": {"command": f"pytest {_SENTINEL}"}}))
                marks = ", ".join("?" for _ in values)
                db.execute(f"INSERT INTO session_task_events ({cols}) VALUES ({marks})", values)
            ckpt: dict[str, Any] = (
                {"command": f"make {_SENTINEL}", "cwd": "/w"}
                if legacy
                else {"source": [_STREAM, 3, f"evt-v7-{shape}-3", fx.event_digests[2]]}
            )
            db.execute(
                "INSERT INTO session_checkpoints VALUES (?, ?, ?, 'long_running', ?, ?)",
                (new_id(), _SESSION_REF, fx.legacy_task, json.dumps(ckpt), stamp),
            )
    finally:
        db.close()


def _config(fx: _Fixture, tmp: Path, os_: OsAdapters, clock: FakeClock) -> DaemonConfig:
    tls_dir = tmp / f"tls-{fx.store_id[:8]}"
    tls = create_store_tls(
        fx.store_id,
        tls_dir,
        make_bootstrap_auth(
            store_id=fx.store_id, owner_id="dan", action="provision_tls", subject_id=fx.store_id,
            trust_generation=1, expires_at=clock.now() + dt.timedelta(hours=4), destination=tls_dir,
        ),
        clock,
        os_,
    )
    return DaemonConfig(1, fx.root, fx.store_id, tls.cert_path, tls.key_path)


def _owner(loop: Any, fn: Any) -> Any:
    def _act() -> Any:
        session: Any = loop._session
        assert session is not None
        return fn(session._rt)

    return loop.run_owner_action(_act).result(timeout=_WAIT_S)  # owner actions also run under full-gate load


def _wait(loop: Any, fn: Any) -> Any:
    deadline = time.monotonic() + _WAIT_S
    pause = threading.Event()
    while time.monotonic() < deadline:
        value = _owner(loop, fn)
        if value:
            return value
        pause.wait(0.05)
    raise AssertionError("condition not reached through the daemon's own loop")


@pytest.mark.parametrize("shape", ["c57fb92", "778e451", "r5"])
def test_every_known_store_v6_shape_upgrades_to_v7_and_serves_refs_only(trusted_tmp: Path, shape: str) -> None:
    from superbrain.storage.sessions import SessionStore

    clock = FakeClock(_START)
    mono = FakeMonotonicClock()
    os_ = os_adapters(clock=clock, monotonic=mono)
    fx = _build_v6_store(trusted_tmp, os_, clock, shape)
    cfg = _config(fx, trusted_tmp, os_, clock)
    scratch = trusted_tmp / f"ro-{shape}"
    scratch.mkdir()
    events_before = _query(fx.root, scratch, "SELECT producer_stream, sequence, payload_digest FROM capture_events")

    # Interrupted between the policy and the store upgrade, then the same command again.
    def _boom() -> None:
        raise RuntimeError("interrupted after the policy step")

    with pytest.raises(RuntimeError):
        migrate_offline(cfg, os_, _after_policy_step=_boom)
    assert read_schema_info(DataRoot.at(fx.root).policy_db) == SchemaInfo(5, 5, fx.store_id)
    assert read_schema_info(DataRoot.at(fx.root).store_db) == SchemaInfo(6, 6, fx.store_id)
    report = migrate_offline(cfg, os_)
    assert (report.policy_report.status, report.store_report.status) == ("skipped", "migrated")
    assert read_schema_info(DataRoot.at(fx.root).store_db) == SchemaInfo(7, 7, fx.store_id)

    # Events kept; links kept by ID/digest; no event content copied into SQLite.
    events_after = _query(fx.root, scratch, "SELECT producer_stream, sequence, payload_digest FROM capture_events")
    assert events_after == events_before
    link_cols = [str(r[1]) for r in _query(fx.root, scratch, "PRAGMA table_info(session_task_events)")]
    assert "event_json" not in link_cols
    links = _query(fx.root, scratch, "SELECT sequence, payload_digest FROM session_task_events ORDER BY sequence")
    expected_links = [] if shape == "c57fb92" else list(enumerate(fx.event_digests, start=1))
    assert [(int(s), str(d)) for s, d in links] == expected_links
    assert _sqlite_cells_with(fx.root, _SENTINEL, scratch) == []
    sweep = _query(fx.root, scratch, "SELECT job_id, digest FROM continuity_legacy_sweep ORDER BY digest")
    if shape == "778e451":
        assert sorted(d for _j, d in sweep) == sorted(fx.copy_digests)
        assert {j for j, _d in sweep} == {fx.legacy_job_id}
    else:
        assert sweep == []

    # The previous binary (store code version 6) refuses the v7 store before writing anything.
    store_db, policy_db = DataRoot.at(fx.root).store_db, DataRoot.at(fx.root).policy_db
    before = (_file_digest(store_db), _file_digest(policy_db))
    old_store, old_policy = KERNEL_STORE_MIGRATIONS[:6], KERNEL_POLICY_MIGRATIONS
    for purpose in ("serve", "migrate"):
        with pytest.raises(BrainError) as refused:
            admit_existing_pair(
                fx.root, fx.store_id, os_, purpose=purpose, store_migrations=old_store, policy_migrations=old_policy
            ).release()
        assert refused.value.code is ErrorCode.UNSUPPORTED_VERSION
    with pytest.raises(BrainError) as refused_migrate:
        migrate_offline(cfg, os_, store_migrations=old_store, policy_migrations=old_policy)
    assert refused_migrate.value.code is ErrorCode.UNSUPPORTED_VERSION
    assert (_file_digest(store_db), _file_digest(policy_db)) == before

    loop = create_daemon_owner_loop(os_=os_, clock=clock, monotonic_clock=mono, job_handlers=PRODUCTION_JOB_HANDLERS)
    loop.start(cfg)
    try:
        # Before READY the sweep released every legacy copy and failed the job that would have read one.
        def _swept(rt: Runtime) -> Any:
            rows = rt.store._db.execute("SELECT COUNT(*) FROM continuity_legacy_sweep").fetchone()
            holders = [rt.store.cas.holders(d) for d in fx.copy_digests]
            job = None
            legacy_id = fx.legacy_job_id
            if legacy_id is not None:
                ks = StagedKernelStore(rt.store, rt.policy, writer_epoch=rt.lease.epoch)
                job = ks.transact(lambda tx: tx.read_job(legacy_id))
            return int(rows[0]), holders, job

        remaining, holders, job = _owner(loop, _swept)
        assert remaining == 0 and all(h == [] for h in holders)
        if shape == "778e451":
            assert job is not None and (job.state, job.reason) == (JobState.FAILED, JobErrorCode.INVALID_PAYLOAD)

        if shape == "r5":
            # Already refs only: the upgrade is a no-op for the task (its batch stays summarized).
            def _kept(rt: Runtime) -> Any:
                ss = SessionStore(rt.store, rt.policy)
                return ss.get_continuity_worker_state(fx.legacy_task), ss.read_task_handoff(fx.legacy_task)

            kept_state, kept_handoff = _owner(loop, _kept)
            assert kept_state is not None and kept_state.pending_event_count == 0
            assert kept_handoff is not None and kept_handoff.current_revision == 1

        if shape == "778e451":
            # The migrated task is refreshed from its linked events into a refs-only observed part.
            clock.advance(dt.timedelta(seconds=61))

            def _legacy_refreshed(rt: Runtime) -> Any:
                ss = SessionStore(rt.store, rt.policy)
                handoff = ss.read_task_handoff(fx.legacy_task)
                if handoff is None or handoff.observed_ref is None or handoff.observed_ref in fx.copy_digests:
                    return None
                state = ss.get_continuity_worker_state(fx.legacy_task)
                if state is None or state.pending_event_count or state.active_job_id or state.pending_job_id:
                    return None
                return rt.store.cas.read(handoff.observed_ref)

            observed = json.loads(_wait(loop, _legacy_refreshed).decode("utf-8"))
            assert {item[1] for item in observed["items"]} <= {f"evt-v7-{shape}-{s}" for s in (1, 2, 3)}
            assert _SENTINEL not in json.dumps(observed)

        # New ingest on the upgraded store schedules and commits a refresh through the daemon's own loop.
        new_task = f"task-{new_id()}"

        def _ingest(rt: Runtime) -> None:
            ss = SessionStore(rt.store, rt.policy)
            sref = ss.bind_session(
                principal_id=fx.principal_id, repo_id=fx.repo_id, checkout_id=fx.checkout_id,
                harness_id="claude-code", raw_session_id=f"RAW_V7_{shape}", now=clock.now(),
            ).session_ref
            ss.ensure_task_handoff(
                task_id=new_task, repo_id=fx.repo_id, checkout_id=fx.checkout_id, session_ref=sref, now=clock.now()
            )
            for seq in range(1, 21):
                ss.record_session_event(
                    session_ref=sref, repo_id=fx.repo_id, checkout_id=fx.checkout_id, task_id=new_task,
                    producer_stream="stream-v7-new",
                    event=CaptureEventRecord(
                        event_id=f"evt-v7-new-{shape}-{seq}", producer_stream="stream-v7-new", sequence=seq,
                        harness_id="claude-code", kind="tool_post", recorded_at=_iso(clock.now()),
                        payload={"tool": "Edit", "file_path": f"n{seq}.py"}, session_ref=sref,
                    ),
                    now=clock.now(),
                )

        _owner(loop, _ingest)
        clock.advance(dt.timedelta(seconds=2))

        def _new_refreshed(rt: Runtime) -> Any:
            handoff = SessionStore(rt.store, rt.policy).read_task_handoff(new_task)
            return handoff if handoff is not None and handoff.observed_ref is not None else None

        assert _wait(loop, _new_refreshed).current_revision >= 1
    finally:
        loop.stop()
    assert _sqlite_cells_with(fx.root, _SENTINEL, scratch) == []


def test_unknown_store_v6_continuity_shape_fails_before_ready_and_leaves_the_store_untouched(trusted_tmp: Path) -> None:
    clock = FakeClock(_START)
    os_ = os_adapters(clock=clock, monotonic=FakeMonotonicClock())
    fx = _build_v6_store(trusted_tmp, os_, clock, "c57fb92")
    db = sqlite3.connect(DataRoot.at(fx.root).store_db)
    try:
        with db:  # a partial continuity schema: one table of the set, nothing else
            db.execute("CREATE TABLE sessions (session_ref TEXT PRIMARY KEY)")
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
