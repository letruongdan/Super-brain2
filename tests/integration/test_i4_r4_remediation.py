"""Independent RED oracle for SP1 increment 4 re-review R4 findings I4-R4-01 and I4-R4-02.

Requirement source: ``docs/reviews/2026-11-23-sp1-increment4-rereview-r4.md``.

Invariants under test:
- I4-R4-01: the scope key ``(owner, checkout_root)`` applies to the active slot AND to committed DoctorRuns. A
  store-wide request (deep health, startup self-check, CLI report without checkout) only ever gets a store-wide
  (``checkout_root`` null) result; a checkout-scoped request only gets its own checkout's result. Two spellings of
  one Windows directory are one scope.
- I4-R4-02: background schedule work is due at ``elapsed >= 24h``; deep health freshness still treats a run aged
  exactly 24 h as fresh (``<=``). A failed due enqueue stays due and is retried on a later tick.

Every test drives the real daemon (``daemon_entry.serve``) with a ``FakeClock``; only storage-level faults
(a gated doctor read, an injected ``STORE_BUSY`` on the doctor enqueue append) are injected.
"""

from __future__ import annotations

import importlib
import inspect
import json
import sys
import threading
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import Any, cast

import pytest

from superbrain.core._kernel_approval import CLI_HARNESS_ID
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import KernelRecord
from superbrain.storage.idempotency import StagedKernelStore
from tests.integration.test_doctor_jobs import BOUND_WAIT_S, MACHINE_ID, OWNER_DAN, _submit_tool
from tests.integration.test_i4_f4_f8_remediation import (
    NON_TERMINAL,
    OTHER_OWNER,
    _checkout,
    _doctor_jobs,
    _doctor_runs,
    _Env,
    _job_payload,
    _ReadGate,
    _report,
    _wait_until,
)
from tests.integration.test_i4_rereview_remediation import _Daemon
from tests.support.kernel_auth import seed_principal_and_credential

DAY = timedelta(hours=24)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _health_res(d: _Daemon, env: _Env, token: str, key: str) -> dict[str, Any]:
    """Full ``get_health(deep=True)`` envelope (ok or error) for idempotency key ``key``."""
    return _submit_tool(
        d.loop, env.mono, "get_health", {"schema_version": "2.0", "deep": True, "idempotency_key": key}, token=token
    )


def _data(env_: dict[str, Any]) -> dict[str, Any]:
    return cast(dict[str, Any], env_.get("data") or {})


def _brief(env_: dict[str, Any]) -> dict[str, Any]:
    """The scope-relevant part of a report/health envelope (keeps failure messages readable)."""
    d = _data(env_)
    keys = ("status", "job_id", "doctor_run_id")
    return {"ok": env_.get("ok"), "error": env_.get("error"), **{k: d.get(k) for k in keys}}


def _tick(d: _Daemon) -> None:
    d.loop.run_owner_action(lambda: None).result(timeout=BOUND_WAIT_S)


def _ticked(d: _Daemon, ev: threading.Event) -> bool:
    _tick(d)
    return ev.is_set()


def _run_count(env: _Env) -> int:
    return len(_doctor_runs(env.root))


def _run_of_job(env: _Env, job_id: str) -> dict[str, Any] | None:
    return next((r for r in _doctor_runs(env.root) if r.get("job_id") == job_id), None)


def _store_wide_dan_runs(env: _Env) -> list[dict[str, Any]]:
    return [
        r
        for r in _doctor_runs(env.root)
        if r["owner_id"] == OWNER_DAN and _job_payload(env.root, r["job_id"]).get("checkout_root") is None
    ]


def _complete_checkout_run(
    env: _Env, d: _Daemon, gate: _ReadGate, co: Path, running_key: str
) -> tuple[str, str, str, dict[str, Any]]:
    """Settle the startup run S1, run a CLI doctor for ``co`` to completion; deep health ``running_key`` while running.

    Returns ``(s1_run_id, cli_job_id, checkout_run_id, health_while_running)``.
    """
    assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
    runs = _doctor_runs(env.root)
    assert len(runs) == 1, runs
    s1 = str(runs[0]["doctor_run_id"])
    env.clock.advance(timedelta(minutes=16))  # past the operator reuse window, inside the 24 h freshness window
    gate.armed.set()
    rep = _report(d, env, env.cli_token, wait_ms=0, checkout=co)
    cli_job = _data(rep).get("job_id")
    assert isinstance(cli_job, str) and cli_job, rep
    assert gate.entered.wait(timeout=BOUND_WAIT_S), "the CLI job never reached the worker"
    running = _health_res(d, env, env.cli_token, running_key)
    gate.release.set()
    assert _wait_until(lambda: _run_of_job(env, cli_job) is not None, BOUND_WAIT_S), "CLI DoctorRun never committed"
    assert _wait_until(
        lambda: not any(j["state"] in NON_TERMINAL for j in _doctor_jobs(env.root) if j["job_id"] == cli_job),
        BOUND_WAIT_S,
    )
    run_a = _run_of_job(env, cli_job)
    assert run_a is not None
    assert _job_payload(env.root, cli_job).get("checkout_root") is not None, "precondition: checkout-scoped job"
    return s1, cli_job, str(run_a["doctor_run_id"]), running


# ---------------------------------------------------------------------------
# I4-R4-01: scope applies to completed runs too
# ---------------------------------------------------------------------------


def test_r4_01a_deep_health_never_returns_completed_checkout_scoped_run(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """After a (dan, X) CLI run completes, store-wide deep health still answers with the store-wide run S1."""
    env = _Env(trusted_tmp, "r4-01a")
    co = _checkout(env, "repo-x")
    gate = _ReadGate(monkeypatch)
    try:
        with env.serve() as d:
            s1, cli_job, run_a, running = _complete_checkout_run(env, d, gate, co, "idem_i4_r4_01a_running")
            after = _health_res(d, env, env.cli_token, "idem_i4_r4_01a_after")
    finally:
        gate.release.set()

    # Control (already held before R4): while the CLI job is running, deep health does not answer with it.
    assert running.get("ok") is True and _data(running).get("job_id") != cli_job, running
    assert _data(running).get("doctor_run_id") == s1, running

    violations: list[str] = []
    data = _data(after)
    if after.get("ok") is not True:
        violations.append(f"deep health failed instead of answering with the store-wide run: {after.get('error')}")
    if data.get("doctor_run_id") == run_a:
        violations.append(f"deep health returned the checkout-scoped DoctorRun {run_a}")
    if data.get("job_id") == cli_job:
        violations.append(f"deep health returned the checkout-scoped job {cli_job}")
    # Positive control of the same rule: the fresh store-wide run S1 is still the answer, even though a newer
    # checkout-scoped run exists after it.
    if data.get("doctor_run_id") != s1 or data.get("job_id") is not None:
        violations.append(f"deep health did not answer with the fresh store-wide run {s1}: {_brief(after)}")
    assert not violations, "I4-R4-01 (completed run):\n" + "\n".join(violations)


def test_r4_01b_deep_health_replay_never_returns_checkout_scoped_run(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A replayed deep-health key returns its first answer, and no answer ever names a checkout-scoped run."""
    env = _Env(trusted_tmp, "r4-01b")
    co = _checkout(env, "repo-x")
    gate = _ReadGate(monkeypatch)
    try:
        with env.serve() as d:
            _s1, cli_job, run_a, running = _complete_checkout_run(env, d, gate, co, "idem_i4_r4_01b_k1")
            k2_first = _health_res(d, env, env.cli_token, "idem_i4_r4_01b_k2")
            k2_replay = _health_res(d, env, env.cli_token, "idem_i4_r4_01b_k2")
            k1_replay = _health_res(d, env, env.cli_token, "idem_i4_r4_01b_k1")
    finally:
        gate.release.set()

    def _ans(e: dict[str, Any]) -> tuple[Any, Any, Any]:
        return e.get("ok"), _data(e).get("doctor_run_id"), _data(e).get("job_id")

    violations: list[str] = []
    for label, e in (("K1 first", running), ("K1 replay", k1_replay), ("K2 first", k2_first), ("K2 replay", k2_replay)):
        ok, run_id, job_id = _ans(e)
        if ok is not True:
            violations.append(f"{label} failed: {e.get('error')}")
        if run_id == run_a or job_id == cli_job:
            violations.append(f"{label} names the checkout-scoped run {run_a} / job {cli_job}: {_brief(e)}")
    if _ans(k1_replay) != _ans(running):
        violations.append(f"K1 replay changed its answer: first {_ans(running)}, replay {_ans(k1_replay)}")
    if _ans(k2_replay) != _ans(k2_first):
        violations.append(f"K2 replay changed its answer: first {_ans(k2_first)}, replay {_ans(k2_replay)}")
    assert not violations, "I4-R4-01 (replay):\n" + "\n".join(violations)


def test_r4_01c_control_restart_startup_not_suppressed_by_previous_epoch_checkout_run(trusted_tmp: Path) -> None:
    """A fresh (dan, X) run with a stale store-wide run must not suppress the store-wide startup self-check.

    Control: across a restart the previous writer epoch's checkout run is already excluded by the epoch fence; the
    same-epoch case (startup retried after a failed enqueue) is ``test_r4_01c_retried_startup_...``.
    """
    env = _Env(trusted_tmp, "r4-01c")
    co = _checkout(env, "repo-x")
    with env.serve() as d1:
        assert d1.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        assert _run_count(env) == 1
        env.clock.advance(timedelta(hours=23))  # S1 is 23 h old: not yet due
        _tick(d1)
        assert d1.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        assert _run_count(env) == 1, "precondition: no scheduled run before 24 h"
        rep = _report(d1, env, env.cli_token, wait_ms=10_000, checkout=co)
        assert rep.get("ok") is True and _data(rep).get("status") == "completed", rep
        run_a = str(_data(rep)["doctor_run_id"])
    env.clock.advance(timedelta(hours=2))  # S1 is 25 h old (stale); the checkout run is 2 h old
    base = _run_count(env)
    with env.serve() as d2:
        d2.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        _wait_until(lambda: _run_count(env) > base, 3.0)
        new_runs = _doctor_runs(env.root)[base:]
        health = _health_res(d2, env, env.cli_token, "idem_i4_r4_01c_health")

    store_wide = [
        r
        for r in new_runs
        if r["owner_id"] == OWNER_DAN and _job_payload(env.root, r["job_id"]).get("checkout_root") is None
    ]
    violations: list[str] = []
    if not store_wide:
        violations.append(
            f"no store-wide startup self-check committed after restart; new runs={[r['trigger'] for r in new_runs]}"
        )
    elif store_wide[0]["trigger"] != "startup":
        violations.append(f"first store-wide run after restart has trigger {store_wide[0]['trigger']!r}")
    if _data(health).get("doctor_run_id") == run_a:
        violations.append(f"deep health after restart returned the checkout-scoped run {run_a}: {_data(health)}")
    assert not violations, "I4-R4-01 (startup):\n" + "\n".join(violations)


def test_r4_01d_cli_report_scope_for_completed_runs(trusted_tmp: Path) -> None:
    """CLI report reuse of a completed run is per (owner, checkout): B never gets A's or the store-wide run; another
    owner never gets dan's runs. A and store-wide reuse are the positive controls."""
    env = _Env(trusted_tmp, "r4-01d")
    co_a = _checkout(env, "repo-a")
    co_b = _checkout(env, "repo-b")
    with env.offline_rt() as rt:
        eve = seed_principal_and_credential(
            rt.policy, owner_id=OTHER_OWNER, harness_id=CLI_HARNESS_ID, machine_id=MACHINE_ID
        )
    with env.serve() as d:
        assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        s1 = str(_doctor_runs(env.root)[0]["doctor_run_id"])
        rep_a = _report(d, env, env.cli_token, wait_ms=10_000, checkout=co_a)
        assert rep_a.get("ok") is True and _data(rep_a).get("status") == "completed", rep_a
        run_a, job_a = _data(rep_a)["doctor_run_id"], _data(rep_a)["job_id"]
        rep_b = _report(d, env, env.cli_token, wait_ms=0, checkout=co_b)
        rep_a2 = _report(d, env, env.cli_token, wait_ms=0, checkout=co_a)
        rep_none = _report(d, env, env.cli_token, wait_ms=0)
        rep_eve = _report(d, env, eve.token, wait_ms=0, checkout=co_a)
        health_eve = _health_res(d, env, eve.token, "idem_i4_r4_01d_eve")
        _wait_until(lambda: not any(j["state"] in NON_TERMINAL for j in _doctor_jobs(env.root)), BOUND_WAIT_S)
    dan_runs = {s1, run_a}
    violations: list[str] = []
    if _data(rep_b).get("doctor_run_id") in dan_runs or _data(rep_b).get("job_id") == job_a:
        violations.append(f"report for checkout B reused another scope's result: {_brief(rep_b)}")
    if _data(rep_eve).get("doctor_run_id") in dan_runs or _data(rep_eve).get("job_id") == job_a:
        violations.append(f"{OTHER_OWNER}'s report for checkout A got dan's result: {_brief(rep_eve)}")
    if _data(health_eve).get("doctor_run_id") in dan_runs:
        violations.append(f"{OTHER_OWNER}'s deep health got dan's run: {_brief(health_eve)}")
    if _data(rep_a2).get("doctor_run_id") != run_a:
        violations.append(f"control: report for checkout A must reuse A's completed run {run_a}: {_brief(rep_a2)}")
    if _data(rep_none).get("doctor_run_id") != s1:
        violations.append(f"control: store-wide report must reuse the store-wide run {s1}: {_brief(rep_none)}")
    assert not violations, "I4-R4-01 (CLI report scope):\n" + "\n".join(violations)


def _spell(co: Path, variant: str) -> str:
    s = str(co)
    if variant in ("case", "combined"):
        s = s.upper()
    if variant in ("forward_slashes", "combined"):
        s = s.replace("\\", "/")
    if variant in ("trailing_sep", "combined"):
        s = s + ("/" if variant == "combined" else "\\")
    return s


@pytest.mark.skipif(sys.platform != "win32", reason="Windows path equivalence (case, separators) is Windows-only")
@pytest.mark.parametrize("variant", ["case", "forward_slashes", "trailing_sep", "combined"])
def test_r4_01e_windows_equivalent_checkout_spellings_are_one_scope(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, variant: str
) -> None:
    """A second spelling of the same checkout joins the first spelling's active job and reuses its completed run."""
    env = _Env(trusted_tmp, f"r4-01e-{variant}")
    co = _checkout(env, "repo-x")
    alt = _spell(co, variant)
    assert alt != str(co) and Path(alt).is_dir(), f"precondition: {alt!r} is another spelling of {co}"
    gate = _ReadGate(monkeypatch)
    try:
        with env.serve() as d:
            assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
            gate.armed.set()
            first = _report(d, env, env.cli_token, wait_ms=0, checkout=co)
            job = _data(first).get("job_id")
            assert isinstance(job, str) and job, first
            jobs_before = {j["job_id"] for j in _doctor_jobs(env.root)}
            joined = _report(d, env, env.cli_token, wait_ms=0, checkout=Path(alt))
            jobs_after_join = {j["job_id"] for j in _doctor_jobs(env.root)}
            gate.release.set()
            _wait_until(lambda: not any(j["state"] in NON_TERMINAL for j in _doctor_jobs(env.root)), BOUND_WAIT_S)
            run = _run_of_job(env, job)
            assert run is not None, "the first spelling's DoctorRun never committed"
            jobs_before_reuse = {j["job_id"] for j in _doctor_jobs(env.root)}
            reused = _report(d, env, env.cli_token, wait_ms=0, checkout=Path(alt))
            jobs_after_reuse = {j["job_id"] for j in _doctor_jobs(env.root)}
    finally:
        gate.release.set()
    violations: list[str] = []
    if _data(joined).get("job_id") != job or jobs_after_join - jobs_before:
        violations.append(
            f"spelling {alt!r} did not join the active job {job}: got {_brief(joined)}, "
            f"new jobs {sorted(jobs_after_join - jobs_before)}"
        )
    if _data(reused).get("doctor_run_id") != run["doctor_run_id"] or jobs_after_reuse - jobs_before_reuse:
        violations.append(
            f"spelling {alt!r} did not reuse the completed run {run['doctor_run_id']}: got {_brief(reused)}, "
            f"new jobs {sorted(jobs_after_reuse - jobs_before_reuse)}"
        )
    assert not violations, f"I4-R4-01 (Windows spelling {variant}):\n" + "\n".join(violations)


def test_r4_01e_control_different_directories_are_different_scopes(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = _Env(trusted_tmp, "r4-01e-ctrl")
    co_a = _checkout(env, "repo-a")
    co_b = _checkout(env, "repo-ab")
    gate = _ReadGate(monkeypatch)
    try:
        with env.serve() as d:
            assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
            gate.armed.set()
            job_a = _data(_report(d, env, env.cli_token, wait_ms=0, checkout=co_a)).get("job_id")
            job_b = _data(_report(d, env, env.cli_token, wait_ms=0, checkout=co_b)).get("job_id")
            gate.release.set()
            _wait_until(lambda: not any(j["state"] in NON_TERMINAL for j in _doctor_jobs(env.root)), BOUND_WAIT_S)
    finally:
        gate.release.set()
    assert job_a and job_b and job_a != job_b, f"different checkouts must have different slots: {job_a} {job_b}"


# ---------------------------------------------------------------------------
# I4-R4-02: schedule due at elapsed >= 24 h; freshness keeps <= 24 h; failed due enqueue is retried
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("past_boundary", [timedelta(0), timedelta(seconds=1)], ids=["exact_24h", "24h_plus_1s"])
def test_r4_02a_schedule_is_due_at_elapsed_24h(trusted_tmp: Path, past_boundary: timedelta) -> None:
    env = _Env(trusted_tmp, f"r4-02a-{past_boundary.seconds}")
    with env.serve() as d:
        assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        assert _run_count(env) == 1
        env.clock.advance(DAY - timedelta(seconds=1))  # 23:59:59 after the first run
        _tick(d)
        assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        assert _run_count(env) == 1, "control: 23:59:59 is not due"
        env.clock.advance(timedelta(seconds=1) + past_boundary)
        _tick(d)
        settled = d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        at_boundary = _doctor_runs(env.root)
        for _ in range(3):  # repeated ticks at the same instant must not schedule again
            _tick(d)
        settled_again = d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        after_ticks = _doctor_runs(env.root)
        jobs = _doctor_jobs(env.root)
    assert settled, "owner never reported settled at the 24 h boundary"
    assert len(at_boundary) == 2 and at_boundary[1]["trigger"] == "schedule", (
        f"I4-R4-02: at elapsed 24h{'+' + str(past_boundary) if past_boundary else ''} the owner reported settled "
        f"with {len(at_boundary)} doctor.run row(s); the scheduled run is due at elapsed >= 24 h"
    )
    assert settled_again and len(after_ticks) == 2 and len(jobs) == 2, (
        f"repeated ticks at the boundary created extra runs/jobs: runs={len(after_ticks)} jobs={len(jobs)}"
    )


def test_r4_02b_deep_health_treats_run_aged_exactly_24h_as_fresh(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """API contract (``<=``), independent of the scheduler: a run aged exactly 24 h is still reported."""
    env = _Env(trusted_tmp, "r4-02b")
    gate = _ReadGate(monkeypatch)
    try:
        with env.serve() as d:
            assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
            s1 = str(_doctor_runs(env.root)[0]["doctor_run_id"])
            jobs_before = len(_doctor_jobs(env.root))
            gate.armed.set()  # a scheduled run due at 24 h stays running and cannot replace S1
            env.clock.advance(DAY)
            _tick(d)
            res = _health_res(d, env, env.cli_token, "idem_i4_r4_02b_health")
            jobs_after = len(_doctor_jobs(env.root))
            gate.release.set()
    finally:
        gate.release.set()
    data = _data(res)
    assert res.get("ok") is True and data.get("doctor_run_id") == s1 and data.get("age_s") == DAY.total_seconds(), (
        f"I4-R4-02: deep health must still report the store-wide run {s1} aged exactly 24 h: {res}"
    )
    assert jobs_after - jobs_before <= 1, f"deep health and schedule enqueued {jobs_after - jobs_before} jobs"


class _EnqueueTx:
    """Kernel tx proxy remembering held payload bytes per holder so a ``job.queued`` append can see its scope."""

    def __init__(self, inner: Any, on_queued: Callable[[KernelRecord, bytes | None], None]) -> None:
        self._inner = inner
        self._on_queued = on_queued
        self._held: dict[Any, bytes] = {}

    def hold_blob(self, data: bytes, *a: Any, **kw: Any) -> Any:
        self._held[kw.get("holder_id")] = data
        return self._inner.hold_blob(data, *a, **kw)

    def append_record(self, record: KernelRecord) -> Any:
        if record.kind == "job.queued" and record.meta.get("kind") == "system.doctor":
            self._on_queued(record, self._held.get(record.meta.get("job_id")))
        return self._inner.append_record(record)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def _patch_doctor_enqueue_busy(
    monkeypatch: pytest.MonkeyPatch, *, once: bool = True, store_wide_only: bool = False
) -> tuple[threading.Event, threading.Event]:
    """While armed, a ``system.doctor`` enqueue (store-wide only if asked) raises ``STORE_BUSY`` (once if asked)."""
    armed, fired = threading.Event(), threading.Event()
    orig = StagedKernelStore.transact

    def _on_queued(record: KernelRecord, payload: bytes | None) -> None:
        if not armed.is_set() or (once and fired.is_set()):
            return
        scope = json.loads(payload.decode("utf-8")).get("checkout_root") if payload is not None else "unknown"
        if store_wide_only and scope is not None:
            return
        fired.set()
        raise BrainError(ErrorCode.STORE_BUSY, "injected busy enqueue")

    def _transact(self: StagedKernelStore, operation: Callable[[Any], Any]) -> Any:
        return orig(self, lambda tx: operation(_EnqueueTx(tx, _on_queued)))

    monkeypatch.setattr(StagedKernelStore, "transact", _transact)
    return armed, fired


@pytest.mark.parametrize("which", ["periodic", "startup"])
def test_r4_02c_transient_store_busy_on_due_enqueue_is_retried(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, which: str
) -> None:
    """A STORE_BUSY on the due enqueue keeps the work due; a later tick (minutes, not 24 h) commits the run."""
    env = _Env(trusted_tmp, f"r4-02c-{which}")
    armed, fired = _patch_doctor_enqueue_busy(monkeypatch)
    if which == "startup":
        armed.set()
    with env.serve() as d:
        if which == "periodic":
            assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
            assert len(_store_wide_dan_runs(env)) == 1
            armed.set()
            env.clock.advance(DAY + timedelta(minutes=1))
        assert _wait_until(lambda: _ticked(d, fired), BOUND_WAIT_S), "the due enqueue was never attempted"
        want = 2 if which == "periodic" else 1
        for _ in range(5):
            env.clock.advance(timedelta(minutes=1))
            _tick(d)
            d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
            if len(_store_wide_dan_runs(env)) >= want:
                break
        runs = _store_wide_dan_runs(env)
    assert len(runs) == want, (
        f"I4-R4-02 ({which}): after a transient STORE_BUSY on the due enqueue, {len(runs)} store-wide run(s) "
        f"exist 5 minutes later (want {want}); the failed attempt was deferred instead of retried"
    )


def test_r4_01c_retried_startup_self_check_not_suppressed_by_same_epoch_checkout_run(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The startup self-check enqueue fails (STORE_BUSY) until a (dan, X) CLI run of this writer epoch has completed;
    the retried store-wide self-check must still run: a checkout-scoped run never counts as a recent self-check."""
    env = _Env(trusted_tmp, "r4-01c-retry")
    co = _checkout(env, "repo-x")
    armed, fired = _patch_doctor_enqueue_busy(monkeypatch, once=False, store_wide_only=True)
    armed.set()
    with env.serve() as d:
        assert _wait_until(lambda: _ticked(d, fired), BOUND_WAIT_S), "startup enqueue never attempted"
        rep = _report(d, env, env.cli_token, wait_ms=10_000, checkout=co)
        assert rep.get("ok") is True and _data(rep).get("status") == "completed", _brief(rep)
        run_a = str(_data(rep)["doctor_run_id"])
        assert not _store_wide_dan_runs(env), "precondition: no store-wide run while its enqueue fails"
        armed.clear()
        for _ in range(5):
            env.clock.advance(timedelta(minutes=1))
            _tick(d)
            d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
            if _store_wide_dan_runs(env):
                break
        store_wide = _store_wide_dan_runs(env)
        health = _health_res(d, env, env.cli_token, "idem_i4_r4_01c_retry_health")
    violations: list[str] = []
    if len(store_wide) != 1 or store_wide[0]["trigger"] != "startup":
        violations.append(
            f"retried startup self-check missing after a same-epoch checkout run {run_a}: "
            f"store-wide runs={[r['trigger'] for r in store_wide]}"
        )
    if _data(health).get("doctor_run_id") == run_a:
        violations.append(f"deep health returned the checkout-scoped run {run_a}: {_brief(health)}")
    assert not violations, "I4-R4-01 (retried startup):\n" + "\n".join(violations)


def test_r4_01f_replay_of_pre_fix_stored_checkout_descriptor_never_returns_checkout_run(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Old data (lens 3): a store-wide deep-health result stored by a pre-fix binary that names a checkout-scoped
    run, replayed with the same key after upgrade, must not return that run (fail closed instead).

    The pre-fix binary is simulated for the first call only: the run lookup of ``prepare_deep_health`` ignores scope
    (selects the completed checkout run, as the R4 baseline did) and the render accepts any scope. Both patches are
    undone before the replay, which then runs the code under test unmodified. The exact error code is not pinned:
    requirement 5 and plan line 37 require only that replay never returns a checkout-scoped run; a replay that
    silently answered with a different run would break replay identity, so the replay must be an error envelope.
    """
    env = _Env(trusted_tmp, "r4-01f")
    co = _checkout(env, "repo-x")
    gate = _ReadGate(monkeypatch)
    health_mod = importlib.import_module("superbrain.composition._daemon_health")
    orig_lookup = health_mod.find_latest_valid_doctor_run
    scoped = "checkout_root" in inspect.signature(orig_lookup).parameters

    def _pre_fix_lookup(rt: Any, owner_id: str, now: Any, **_kw: Any) -> Any:
        return orig_lookup(rt, owner_id, now, **({"checkout_root": str(co)} if scoped else {}))

    try:
        with env.serve() as d:
            s1, cli_job, run_a, stored_wide = _complete_checkout_run(env, d, gate, co, "idem_i4_r4_01f_wide")
            with monkeypatch.context() as m:
                m.setattr(health_mod, "find_latest_valid_doctor_run", _pre_fix_lookup)
                m.setattr(health_mod, "_doc_scope_matches", lambda *_a, **_k: True, raising=False)
                old_first = _health_res(d, env, env.cli_token, "idem_i4_r4_01f_old")
            old_replay = _health_res(d, env, env.cli_token, "idem_i4_r4_01f_old")
            wide_replay = _health_res(d, env, env.cli_token, "idem_i4_r4_01f_wide")
    finally:
        gate.release.set()

    assert old_first.get("ok") is True and _data(old_first).get("doctor_run_id") == run_a, (
        f"precondition: the simulated pre-fix call stored a descriptor naming the checkout run: {_brief(old_first)}"
    )
    violations: list[str] = []
    if _data(old_replay).get("doctor_run_id") == run_a or _data(old_replay).get("job_id") == cli_job:
        violations.append(f"pre-fix result replay returned the checkout run {run_a}: {_brief(old_replay)}")
    if old_replay.get("ok") is not False or not (old_replay.get("error") or {}).get("code"):
        violations.append(f"replay of the pre-fix result did not fail closed: {_brief(old_replay)}")
    # Positive control: a replayed store-wide descriptor still returns its store-wide run.
    if not (wide_replay.get("ok") is True and _data(wide_replay).get("doctor_run_id") == s1):
        violations.append(f"control: replay of the store-wide result must still return {s1}: {_brief(wide_replay)}")
    if _brief(stored_wide)["doctor_run_id"] != s1:
        violations.append(f"control: the store-wide result was stored with run {s1}: {_brief(stored_wide)}")
    assert not violations, "I4-R4-01 (replay of pre-fix stored result):\n" + "\n".join(violations)
