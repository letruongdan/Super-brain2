"""Independent RED oracle (R6): the daemon's own periodic maintenance must not starve its own doctor run.

Requirement (coordinator, from hosted Windows CI run 45738996874 and the p2-hosted-repro diagnostic): while a doctor
worker is running, periodic GC maintenance (``expire_due`` / ``collect_garbage`` / idempotency prune, each of which
commits to store.db) is deferred, not interleaved with the worker's live DB snapshot; it runs after the worker
finishes (stays due, is not skipped for a whole interval) without a client poke; and the deferral never makes the idle
owner loop hot-spin. External request writes are out of scope.

Mechanism under test: ``snapshot_live_db_pair`` discards a store/policy pair when store.db committed between the two
copies; after ``DOCTOR_SNAPSHOT_PAIR_ATTEMPTS`` split pairs the job is retried (``job.retry``). Here the snapshot is
made deterministically slow: after the worker's store.db copy of the startup job, ``backup._snapshot_db`` holds for
``HOLD_S`` (several maintenance intervals) before the policy copy.

Observed on durable state / real calls, never logs: maintenance calls and store.db ``data_version`` during each hold,
the job row and ``job.retry`` ledger records, the DoctorRun ledger rows, an aged orphan blob, owner pokes and owner
steps during the hold.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import Any, cast

import pytest

import superbrain.storage.backup as backup_mod
from superbrain.adapters.os import os_adapters
from superbrain.composition import _daemon_doctor
from superbrain.composition._daemon_doctor import DaemonDoctorRunner
from superbrain.storage.cas import ContentStore, blob_path
from superbrain.storage.layout import DataRoot
from tests.integration.test_doctor_jobs import _init_doctor_root, _ro_db
from tests.integration.test_i4_a1_a2_job_lifecycle import _job_tuple, _spy_owner_pokes
from tests.integration.test_i4_f4_f8_remediation import _doctor_runs, _wait_until
from tests.integration.test_i4_r3_remediation import _serve
from tests.support.inc2_fixture import reopen_kernel_job_runtime

INTERVAL_S = 0.5  # DOCTOR_SCHEDULE_INTERVAL for these cases (schedule and GC share it)
HOLD_S = 2.0  # each held snapshot spans several maintenance due points
MAX_HOLDS = 3  # == DOCTOR_SNAPSHOT_PAIR_ATTEMPTS: enough to exhaust one job attempt on the unfixed daemon
MAX_STEPS_PER_HOLD = 15  # a hot-spinning owner loop makes thousands of steps in HOLD_S
SETTLE_BOUND_S = MAX_HOLDS * HOLD_S + 10.0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _SnapshotHold:
    """Holds the worker's live snapshot of the first doctor job after its store.db copy, before the policy copy."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, root: DataRoot) -> None:
        self.root = root
        self.lock = threading.Lock()
        self.tag: str | None = None
        self.holds = 0
        self.holding = threading.Event()
        self.first_hold = threading.Event()
        self.release = threading.Event()
        self.version_changed: list[bool] = []
        orig = backup_mod._snapshot_db

        def _gated(source: sqlite3.Connection, dest: Path, os_: Any) -> None:
            orig(source, dest, os_)
            tag = next((part for part in Path(dest).parts if part.startswith("doctor-snap-")), None)
            if tag is None or Path(dest).name != root.store_db.name:
                return
            with self.lock:
                if self.tag is None:
                    self.tag = tag
                if tag != self.tag or self.holds >= MAX_HOLDS:
                    return
                self.holds += 1
            with _ro_db(root.store_db) as conn:
                before = conn.execute("PRAGMA data_version").fetchone()[0]
                self.holding.set()
                self.first_hold.set()
                try:
                    self.release.wait(HOLD_S)
                finally:
                    after = conn.execute("PRAGMA data_version").fetchone()[0]
                    self.holding.clear()
            self.version_changed.append(after != before)

        monkeypatch.setattr(backup_mod, "_snapshot_db", _gated)

    @property
    def job_id(self) -> str:
        assert self.tag is not None
        return self.tag.removeprefix("doctor-snap-")


class _Maintenance:
    """Counts the daemon's periodic maintenance calls (``expire_due`` / ``collect_garbage``), total and while held."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, hold: _SnapshotHold | None) -> None:
        self.calls = 0
        self.during_hold: list[str] = []
        self.gc_calls = 0
        orig_expire = cast(Callable[..., Any], vars(_daemon_doctor)["expire_due"])
        orig_gc = ContentStore.collect_garbage

        def _note(name: str) -> None:
            self.calls += 1
            if hold is not None and hold.holding.is_set():
                self.during_hold.append(name)

        def _expire(*args: Any, **kwargs: Any) -> Any:
            _note("expire_due")
            return orig_expire(*args, **kwargs)

        def _gc(self_cas: ContentStore, *args: Any, **kwargs: Any) -> Any:
            self.gc_calls += 1
            _note("collect_garbage")
            return orig_gc(self_cas, *args, **kwargs)

        monkeypatch.setattr(_daemon_doctor, "expire_due", _expire)
        monkeypatch.setattr(ContentStore, "collect_garbage", _gc)


def _aged_orphan(cfg: Any, store_id: str, real_os: Any, root: DataRoot, data: bytes) -> Path:
    """An unheld CAS blob older than the GC grace (daemon stopped), as P2.11 seeds it."""
    rt = reopen_kernel_job_runtime(cfg.data_root, store_id, real_os)
    try:
        digest = rt.store.cas.put(data)
    finally:
        rt.close()
    path = blob_path(root.cas_dir, digest)
    old = (real_os.clock.now() - timedelta(hours=25)).timestamp()
    os.utime(path, (old, old))
    assert path.is_file()
    return path


def _retry_records(root: DataRoot, job_id: str) -> int:
    with _ro_db(root.store_db) as conn:
        rows = conn.execute("SELECT meta FROM ledger WHERE kind = 'job.retry'").fetchall()
    return sum(1 for (meta,) in rows if json.loads(bytes(meta).decode("utf-8")).get("job_id") == job_id)


def _spy_steps_while(monkeypatch: pytest.MonkeyPatch, d: Any, flag: threading.Event) -> list[int]:
    steps = [0]
    session = cast(Any, d.loop)._session
    assert session is not None
    orig: Callable[..., bool] = session.step_owner_work

    def _spied(*, allow_new_jobs: bool) -> bool:
        if flag.is_set():
            steps[0] += 1
        return orig(allow_new_jobs=allow_new_jobs)

    monkeypatch.setattr(session, "step_owner_work", _spied)
    return steps


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------


def test_r6_doctor_snapshot_is_not_starved_by_periodic_maintenance(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_os = os_adapters()
    rep, cfg, _priv, _ca, _leaf, _tok, _ad = _init_doctor_root(
        trusted_tmp / "r6-hold", cast(Any, real_os.clock), os_=real_os
    )
    root = DataRoot.at(cfg.data_root)
    orphan = _aged_orphan(cfg, rep.store_id, real_os, root, b"r6-deferred-gc-orphan")
    monkeypatch.setattr(_daemon_doctor, "DOCTOR_SCHEDULE_INTERVAL", timedelta(seconds=INTERVAL_S))
    hold = _SnapshotHold(monkeypatch, root)
    maint = _Maintenance(monkeypatch, hold)
    pokes = _spy_owner_pokes(monkeypatch)

    with _serve(cfg, os_=real_os, clock=cast(Any, real_os.clock), mono=cast(Any, real_os.monotonic)) as d:
        steps = _spy_steps_while(monkeypatch, d, hold.holding)
        try:
            assert hold.first_hold.wait(timeout=10.0), "precondition: the startup doctor worker reached the snapshot"
            job_id = hold.job_id

            def _ended_or_retried() -> bool:
                state, attempt, _ = _job_tuple(root, job_id)
                return state in ("succeeded", "failed", "dead_letter") or attempt > 1

            ended = _wait_until(_ended_or_retried, SETTLE_BOUND_S)
            job = _job_tuple(root, job_id)
            runs = [r for r in _doctor_runs(root) if r.get("job_id") == job_id]
            retries = _retry_records(root, job_id)
            reclaimed = _wait_until(lambda: not orphan.exists(), 5.0)
            holds = hold.holds
        finally:
            hold.release.set()

    # (1) no maintenance commit interleaves with the held snapshot
    assert not maint.during_hold, (
        f"periodic maintenance ran while the doctor worker held its live snapshot: {maint.during_hold} "
        f"(holds={holds}, job={job})"
    )
    assert not any(hold.version_changed), f"store.db committed during a held snapshot: {hold.version_changed}"
    # (2) the doctor run is not starved: first attempt succeeds, one DoctorRun, no job.retry
    assert ended, f"the startup doctor job neither ended nor retried within {SETTLE_BOUND_S}s: {job}"
    assert job == ("succeeded", 1, None), f"doctor job must succeed at attempt 1, is {job} (holds={holds})"
    assert len(runs) == 1 and retries == 0, f"runs={len(runs)} job.retry={retries}"
    # (3) the deferred GC runs after the worker finished, without a client poke
    assert reclaimed and maint.gc_calls >= 1, f"deferred GC never ran (gc_calls={maint.gc_calls})"
    assert pokes[0] == 0, f"GC needed {pokes[0]} client pokes"
    # (4) deferral does not hot-spin the owner loop
    assert steps[0] <= MAX_STEPS_PER_HOLD * holds, f"owner loop made {steps[0]} steps during {holds} held snapshots"


def test_r6_control_periodic_gc_runs_on_interval_without_a_worker(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Control: with no doctor worker running (the periodic schedule enqueues nothing), GC runs on its interval."""
    real_os = os_adapters()
    rep, cfg, _priv, _ca, _leaf, _tok, _ad = _init_doctor_root(
        trusted_tmp / "r6-ctl", cast(Any, real_os.clock), os_=real_os
    )
    root = DataRoot.at(cfg.data_root)
    orphan = _aged_orphan(cfg, rep.store_id, real_os, root, b"r6-control-gc-orphan")
    monkeypatch.setattr(_daemon_doctor, "DOCTOR_SCHEDULE_INTERVAL", timedelta(seconds=INTERVAL_S))
    orig_schedule = DaemonDoctorRunner._schedule_store_run

    def _no_periodic_run(self_runner: DaemonDoctorRunner, trigger: str) -> bool | None:
        return False if trigger == "schedule" else orig_schedule(self_runner, trigger)

    monkeypatch.setattr(DaemonDoctorRunner, "_schedule_store_run", _no_periodic_run)
    maint = _Maintenance(monkeypatch, None)

    with _serve(cfg, os_=real_os, clock=cast(Any, real_os.clock), mono=cast(Any, real_os.monotonic)):
        assert _wait_until(lambda: len(_doctor_runs(root)) >= 1, 10.0), "precondition: startup DoctorRun"
        base = maint.gc_calls
        time.sleep(5 * INTERVAL_S)
        window = maint.gc_calls - base
        reclaimed = _wait_until(lambda: not orphan.exists(), 5.0)
    assert window >= 3, f"periodic GC must run on its {INTERVAL_S}s interval: {window} runs in {5 * INTERVAL_S}s"
    assert reclaimed, "periodic GC never reclaimed the aged orphan"
