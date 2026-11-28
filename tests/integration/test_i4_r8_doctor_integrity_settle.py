"""Independent RED oracle: the doctor runner settles a job whose payload it confirms is gone (I4-R8 user decision).

Requirement (user decision relayed by the coordinator): the ``system.doctor`` runner moves the job to FAILED as soon
as it confirms the payload blob is really missing or has the wrong digest, keeping INTEGRITY_FAILURE as the
diagnostic. The job has a definite outcome, so it must not keep its lease until a restart nor retry the same payload.

- D1 blob missing / wrong digest at claim: durable ``failed``/``invalid_payload`` under the current lease, no
  DoctorRun for that job, a report caller already blocked on that job is woken well before its timeout and gets
  INTEGRITY_FAILURE; in the SAME writer epoch (one daemon session) the next report runs a new job to a report.
- D2 a job settled inside ``resolve_leased_spec`` (released holder) is the same "settled at claim" invariant: the
  blocked report caller is woken promptly and gets INTEGRITY_FAILURE.
- D3 the transaction writing the terminal state fails once (``STORE_BUSY``): the job is not reported finished,
  stays with the doctor runner in the same epoch, and a later runner step settles it ``failed`` and answers the
  waiter.
- D4 ``JobService.start`` fails once after a successful resolve: the runner retries that lease in the same epoch
  and the job runs to ``succeeded`` instead of being abandoned ``leased``.
- D5 smoke: a transient read failure of the payload at the doctor runner re-queues the job (attempt 2) and the
  retry then succeeds in the same epoch.
- Control: at service level a missing blob still raises INTEGRITY_FAILURE and leaves the job ``leased`` (I2
  subcase 3a contract, unchanged for the generic runner and for ``resolve_leased_spec`` itself).

Durable state is read from ``p_jobs_state`` / the ledger, never from logs. The only instrumentation of product code
is observation (a wrapper that signals when a report caller enters ``wait_report``) and one-shot fault injection.
"""

from __future__ import annotations

import builtins
import contextlib
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

import superbrain.storage.cas as cas_mod
from superbrain.application.jobs import JobService
from superbrain.composition._daemon_doctor import DaemonDoctorRunner
from superbrain.core._kernel_jobs import JobState, retry_backoff
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.kernel import KernelRecord, require_aware_utc
from superbrain.storage.cas import blob_path
from superbrain.storage.idempotency import StagedKernelStore
from tests.integration.test_doctor_jobs import BOUND_WAIT_S, OWNER_DAN, _ro_db
from tests.integration.test_i4_f4_f8_remediation import _doctor_runs, _Env, _report
from tests.support.inc2_fixture import FIXTURE_JOB_KIND, enqueue_job, kernel_job_service

DOCTOR_KIND = "system.doctor"
WAIT_MS = 8_000  # report wait budget; a prompt wake must come well before it
PROMPT_S = 4.0  # max seconds from the claim poke to the waiter's answer
DELAY = timedelta(minutes=5)  # seeded job is not due until the clock moves past this


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _seed_doctor_job(env: _Env, tag: str, *, delay: timedelta = DELAY) -> tuple[str, bytes]:
    """Durably queue a store-wide ``system.doctor`` job of the store owner, due only after ``delay`` (daemon
    stopped), exactly as the daemon's enqueue records it."""
    job_id = new_id()
    payload = canonical_json({"schema": 1, "trigger": "manual", "checkout_root": None, "i4_r8b": tag})
    now_utc, _ = require_aware_utc(env.clock.now())
    retry_at = require_aware_utc(now_utc + delay)[1]
    with env.offline_rt() as rt:
        _svc, js = kernel_job_service(rt, env.clock)
        js.stage_blob(payload)

        def _op(tx: Any) -> None:
            digest = tx.hold_blob(payload, holder_id=job_id)
            tx.append_record(
                KernelRecord(
                    "job.queued",
                    {
                        "job_id": job_id,
                        "owner_id": OWNER_DAN,
                        "repo_id": None,
                        "checkout_id": None,
                        "kind": DOCTOR_KIND,
                        "payload_digest": digest,
                        "attempt": 1,
                        "retry_at": retry_at,
                    },
                )
            )

        js.transact(_op)
    return job_id, payload


def _durable(env: _Env, job_id: str) -> tuple[str, int, str | None]:
    with _ro_db(env.root.store_db) as conn:
        r = conn.execute("SELECT state, attempt, reason FROM p_jobs_state WHERE job_id = ?", (job_id,)).fetchone()
    assert r is not None, f"job {job_id} has no durable row"
    return str(r[0]), int(r[1]), None if r[2] is None else str(r[2])


def _runs_for(env: _Env, job_id: str) -> list[dict[str, Any]]:
    return [r for r in _doctor_runs(env.root) if r.get("job_id") == job_id]


@dataclass
class _Waiter:
    thread: threading.Thread
    entered: threading.Event
    res: dict[str, Any] = field(default_factory=dict)
    done_at: float | None = None


@contextlib.contextmanager
def _blocked_report(d: Any, env: _Env, monkeypatch: pytest.MonkeyPatch) -> Iterator[_Waiter]:
    """A CLI doctor report running in a thread; yields once its caller is blocked in ``wait_report``."""
    entered = threading.Event()
    orig = DaemonDoctorRunner.wait_report

    def _wait_report(self: Any, job_id: str, *, generation: int, timeout_s: float) -> None:
        entered.set()
        orig(self, job_id, generation=generation, timeout_s=timeout_s)

    monkeypatch.setattr(DaemonDoctorRunner, "wait_report", _wait_report)
    waiter = _Waiter(thread=threading.Thread(target=lambda: None), entered=entered)

    def _run() -> None:
        waiter.res = _report(d, env, env.cli_token, wait_ms=WAIT_MS)
        waiter.done_at = time.monotonic()

    waiter.thread = threading.Thread(target=_run, name="i4-r8b-report", daemon=True)
    waiter.thread.start()
    assert entered.wait(BOUND_WAIT_S), "precondition: the report caller never reached wait_report"
    try:
        yield waiter
    finally:
        waiter.thread.join(WAIT_MS / 1000.0 + BOUND_WAIT_S)


def _poke_until(d: Any, pred: Callable[[], bool], *, tries: int = 3, each_s: float = 1.5) -> bool:
    """Drive the owner loop's doctor step (``wait_doctor_settled``) until ``pred`` holds or ``tries`` run out."""
    for _ in range(tries):
        d.loop.wait_doctor_settled(timeout=each_s)
        if pred():
            return True
    return pred()


def _break_blob(d: Any, env: _Env, job_id: str, payload: bytes, how: str) -> None:
    digest = digest_bytes(payload)
    path = blob_path(env.root.cas_dir, digest)
    if how == "missing":
        path.unlink()
    elif how == "corrupt":
        path.write_bytes(b"i4-r8b corrupted blob bytes")
    else:  # released: the job's own hold goes away, the bytes stay intact

        def _release() -> None:
            with d.rt.store.transaction() as txn:
                txn.release(digest, "event", job_id, "expired")

        d.loop.run_owner_action(_release).result(timeout=BOUND_WAIT_S)
        assert path.is_file()


def _err_code(res: dict[str, Any]) -> str | None:
    err = res.get("error")
    return str(err.get("code")) if isinstance(err, dict) else None


def _fail_terminal_once(monkeypatch: pytest.MonkeyPatch, job_id: str, code: ErrorCode) -> threading.Event:
    """The first ``job.terminal`` append for ``job_id`` raises ``BrainError(code)`` (the transaction rolls back)."""
    fired = threading.Event()
    orig = StagedKernelStore.transact

    class _Tx:
        def __init__(self, inner: Any) -> None:
            self._inner = inner

        def append_record(self, record: KernelRecord) -> Any:
            if record.kind == "job.terminal" and record.meta.get("job_id") == job_id and not fired.is_set():
                fired.set()
                raise BrainError(code, "injected terminal-write failure")
            return self._inner.append_record(record)

        def __getattr__(self, name: str) -> Any:
            return getattr(self._inner, name)

    def _transact(self: StagedKernelStore, operation: Callable[[Any], Any]) -> Any:
        return orig(self, lambda tx: operation(_Tx(tx)))

    monkeypatch.setattr(StagedKernelStore, "transact", _transact)
    return fired


# ---------------------------------------------------------------------------
# D1 / D2: settled at claim -> failed, waiter woken with INTEGRITY_FAILURE, next run reports (same epoch)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("how", ["missing", "corrupt", "released"])
def test_r8b_doctor_settles_job_without_payload_at_claim_and_wakes_waiter(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, how: str
) -> None:
    env = _Env(trusted_tmp, f"r8b-{how}")
    job_id, payload = _seed_doctor_job(env, how)
    with env.serve() as d:
        with _blocked_report(d, env, monkeypatch) as waiter:
            assert _durable(env, job_id) == ("queued", 1, None), "precondition: the waiter joined the queued job"
            _break_blob(d, env, job_id, payload, how)
            env.clock.advance(DELAY + timedelta(milliseconds=1))
            poked_at = time.monotonic()
            _poke_until(d, lambda: waiter.done_at is not None, tries=1, each_s=2.0)
        state = _durable(env, job_id)
        woke_after = None if waiter.done_at is None else waiter.done_at - poked_at
        old_runs = _runs_for(env, job_id)
        second = _report(d, env, env.cli_token, wait_ms=WAIT_MS)
        second_data: dict[str, Any] = second.get("data") or {}
        second_job = str(second_data.get("job_id") or "")
        second_state = _durable(env, second_job) if second_job else None

    assert state == ("failed", 1, "invalid_payload"), f"{how}: job must be failed/invalid_payload, is {state}"
    assert _err_code(waiter.res) == ErrorCode.INTEGRITY_FAILURE.value, (
        f"{how}: the blocked report must get INTEGRITY_FAILURE: {waiter.res}"
    )
    assert woke_after is not None and woke_after < PROMPT_S, (
        f"{how}: waiter must be woken promptly after settlement, answered after {woke_after}s (budget {WAIT_MS}ms)"
    )
    assert not old_runs, f"{how}: no DoctorRun may be created for the failed job: {old_runs}"
    assert second.get("ok") is True and second_data.get("status") == "completed", f"next report: {second}"
    assert second_job != job_id and second_state is not None and second_state[0] == "succeeded", (
        f"next report must run a new job to success in the same epoch: job={second_job} state={second_state}"
    )


# ---------------------------------------------------------------------------
# D3: the terminal write fails once -> stays on the retry path, later settled and answered
# ---------------------------------------------------------------------------


def test_r8b_terminal_write_failure_is_retried_before_reporting_finished(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = _Env(trusted_tmp, "r8b-commitfail")
    job_id, payload = _seed_doctor_job(env, "commitfail")
    with env.serve() as d:
        with _blocked_report(d, env, monkeypatch) as waiter:
            fired = _fail_terminal_once(monkeypatch, job_id, ErrorCode.STORE_BUSY)
            _break_blob(d, env, job_id, payload, "missing")
            env.clock.advance(DELAY + timedelta(milliseconds=1))
            poked_at = time.monotonic()
            _poke_until(d, lambda: waiter.done_at is not None, tries=3, each_s=1.5)
        state = _durable(env, job_id)
        woke_after = None if waiter.done_at is None else waiter.done_at - poked_at

    assert state == ("failed", 1, "invalid_payload"), f"job must end failed/invalid_payload in this epoch: {state}"
    assert fired.is_set(), "precondition: the injected terminal-write failure fired"
    assert _err_code(waiter.res) == ErrorCode.INTEGRITY_FAILURE.value, f"waiter answer: {waiter.res}"
    assert woke_after is not None and woke_after < 3 * 1.5 + 1.0, f"waiter answered after {woke_after}s"


# ---------------------------------------------------------------------------
# D4: JobService.start fails once after resolve -> the lease is retried in the same epoch
# ---------------------------------------------------------------------------


def test_r8b_start_failure_after_resolve_is_retried_not_abandoned_leased(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = _Env(trusted_tmp, "r8b-startfail")
    job_id, _payload = _seed_doctor_job(env, "startfail")
    calls = [0]
    orig = JobService.start

    def _start(self: JobService, lease: Any) -> Any:
        if lease.job_id == job_id:
            calls[0] += 1
            if calls[0] == 1:
                raise BrainError(ErrorCode.STORE_BUSY, "injected start failure")
        return orig(self, lease)

    with env.serve() as d:
        monkeypatch.setattr(JobService, "start", _start)
        env.clock.advance(DELAY + timedelta(milliseconds=1))
        _poke_until(d, lambda: _durable(env, job_id)[0] in ("succeeded", "failed", "dead_letter"), tries=3)
        state = _durable(env, job_id)
        runs = _runs_for(env, job_id)

    assert calls[0] >= 1, "precondition: the doctor runner called start for the job"
    assert state[0] == "succeeded", f"job must be retried to success in the same epoch, is {state}"
    assert runs, "the retried job must commit its DoctorRun"


# ---------------------------------------------------------------------------
# D5: smoke -- transient payload read failure at the doctor runner is retried
# ---------------------------------------------------------------------------


def test_r8b_smoke_transient_payload_read_failure_retried_by_doctor_runner(trusted_tmp: Path) -> None:
    env = _Env(trusted_tmp, "r8b-transient")
    job_id, payload = _seed_doctor_job(env, "transient")
    target = str(blob_path(env.root.cas_dir, digest_bytes(payload))).lower()
    hits = [0]

    def _open(file: Any, *args: Any, **kwargs: Any) -> Any:
        if str(file).lower() == target and hits[0] < 1:
            hits[0] += 1
            raise PermissionError(13, "Access is denied (i4-r8b transient)", str(file))
        return builtins.open(file, *args, **kwargs)

    with env.serve() as d:
        # One owner step first: the startup self-check reads the payload through the scope lookup, not the claim.
        d.loop.wait_doctor_settled(timeout=0.5)
        with pytest.MonkeyPatch.context() as m:
            m.setattr(cas_mod, "open", _open, raising=False)
            env.clock.advance(DELAY + timedelta(milliseconds=1))
            _poke_until(d, lambda: _durable(env, job_id)[1] > 1, tries=1, each_s=1.0)
            first = _durable(env, job_id)
        env.clock.advance(retry_backoff(1) + timedelta(milliseconds=1))
        _poke_until(d, lambda: _durable(env, job_id)[0] == "succeeded", tries=3)
        final = _durable(env, job_id)

    assert hits[0] == 1, "precondition: the injected read failure fired"
    assert first[:2] == ("queued", 2), f"transient failure must re-queue at attempt 2: {first}"
    assert final[0] == "succeeded", f"the retry must succeed in the same epoch: {final}"


# ---------------------------------------------------------------------------
# Control: service-level I2 contract unchanged (generic and doctor kinds)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", [FIXTURE_JOB_KIND, DOCTOR_KIND])
def test_r8b_control_service_level_missing_blob_keeps_integrity_failure_and_lease(
    trusted_tmp: Path, kind: str
) -> None:
    env = _Env(trusted_tmp, f"r8b-ctl-{kind.split('.')[0]}")
    payload = (
        canonical_json({"schema": 1, "trigger": "manual", "checkout_root": None, "i4_r8b": "ctl"})
        if kind == DOCTOR_KIND
        else b"i4-r8b fixture missing"
    )
    with env.offline_rt() as rt:
        svc, st = kernel_job_service(rt, env.clock)
        job_id = enqueue_job(svc, st, owner_id=OWNER_DAN, payload=payload, kind=kind).job_id
        blob_path(env.root.cas_dir, digest_bytes(payload)).unlink()
        lease = svc.lease_next(rt.lease.epoch, env.clock.now())
        assert lease is not None and lease.job_id == job_id
        with pytest.raises(BrainError) as exc:
            svc.resolve_leased_spec(lease)
        row = st.transact(lambda tx: tx.read_job(job_id))
    assert exc.value.code is ErrorCode.INTEGRITY_FAILURE, exc.value
    assert row is not None and row.state is JobState.LEASED, row


# ---------------------------------------------------------------------------
# D6: a transient read failure at claim is NOT a finish -- the blocked waiter keeps waiting for the same job
# ---------------------------------------------------------------------------


def test_r8b_transient_read_failure_at_claim_does_not_answer_waiter_failed(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = _Env(trusted_tmp, "r8b-transient-waiter")
    job_id, payload = _seed_doctor_job(env, "transient-waiter")
    target = str(blob_path(env.root.cas_dir, digest_bytes(payload))).lower()
    hits = [0]

    def _open(file: Any, *args: Any, **kwargs: Any) -> Any:
        if str(file).lower() == target and hits[0] < 1:
            hits[0] += 1
            raise PermissionError(13, "Access is denied (i4-r8b transient)", str(file))
        return builtins.open(file, *args, **kwargs)

    with env.serve() as d:
        d.loop.wait_doctor_settled(timeout=0.5)  # startup self-check done before the seam is armed
        with _blocked_report(d, env, monkeypatch) as waiter:
            with pytest.MonkeyPatch.context() as m:
                m.setattr(cas_mod, "open", _open, raising=False)
                env.clock.advance(DELAY + timedelta(milliseconds=1))
                _poke_until(d, lambda: _durable(env, job_id)[1] > 1, tries=1, each_s=1.0)
                requeued = _durable(env, job_id)
                answered_early = dict(waiter.res) if waiter.done_at is not None else None
            env.clock.advance(retry_backoff(1) + timedelta(milliseconds=1))
            _poke_until(d, lambda: waiter.done_at is not None, tries=3, each_s=1.5)
        final = _durable(env, job_id)
        runs = _runs_for(env, job_id)

    assert hits[0] == 1, "precondition: the injected read failure fired"
    assert requeued[:2] == ("queued", 2), f"transient failure must re-queue at attempt 2: {requeued}"
    assert answered_early is None, f"the waiter was answered while its job was only re-queued: {answered_early}"
    data: dict[str, Any] = waiter.res.get("data") or {}
    assert _err_code(waiter.res) != ErrorCode.INTEGRITY_FAILURE.value, f"re-queued job reported failed: {waiter.res}"
    assert waiter.res.get("ok") is True and data.get("status") == "completed" and data.get("job_id") == job_id, (
        f"the waiter must get the completed DoctorRun of the same job: {waiter.res}"
    )
    assert final[0] == "succeeded" and runs, f"job must succeed after the retry: {final}, runs={len(runs)}"
