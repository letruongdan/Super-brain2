"""Independent RED oracle for SP1 increment 4 re-review finding I4-R9-01 (doctor payload fault classification).

Requirement source: ``docs/reviews/2026-11-24-sp1-increment4-rereview-9edc6dc.md`` (I4-R9-01) and the coordinator's
classification. Invariant: the doctor ends the job with a fence when its payload is confirmed permanently broken;
only recoverable read errors or settlement-write errors take the retry path; a failed job never blocks the next valid
doctor run in the same writer epoch.

- P1 permanent payload fault raised from inside the payload read/verify (CAS entry is a directory, a link/reparse
  point, or not owner-only): job ``failed``/``invalid_payload``, the blocked report caller is woken promptly with
  INTEGRITY_FAILURE, no DoctorRun for that job (the CAS guard never reads through the link), and the next report runs
  a new job to ``succeeded`` in the same daemon session. Missing blob stays a passing control (``None`` path).
- P2 lost acknowledgement: the terminal write (or the ``job.running`` write of ``start``) commits, then the runner
  sees ``STORE_BUSY`` once. Committed terminal -> the waiter is still answered promptly and the next job runs;
  committed start -> the job is still executed and ends ``succeeded`` in the same epoch.
- Controls: a transient payload read failure re-queues (attempt 2) and the retry succeeds; ``STORE_BUSY`` on the
  terminal append (rolled back) is retried to ``failed``; at service level with default arguments a generic
  ``fixture.echo`` job whose payload entry is a directory raises INTEGRITY_FAILURE and stays ``leased`` (I2).

Durable state is read from ``p_jobs_state`` / the ledger, never from logs. Product code is only observed (a wrapper
signalling that a report caller entered ``wait_report``) and fault-injected (one-shot errors).
"""

from __future__ import annotations

import builtins
import contextlib
import os
import sys
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

import superbrain.storage.cas as cas_mod
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
# Helpers (copied from the I4-R8b oracle, not imported from it)
# ---------------------------------------------------------------------------


def _seed_doctor_job(env: _Env, tag: str, *, delay: timedelta = DELAY) -> tuple[str, bytes]:
    """Durably queue a store-wide ``system.doctor`` job of the store owner, due only after ``delay`` (daemon
    stopped), exactly as the daemon's enqueue records it."""
    job_id = new_id()
    payload = canonical_json({"schema": 1, "trigger": "manual", "checkout_root": None, "i4_r9": tag})
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

    waiter.thread = threading.Thread(target=_run, name="i4-r9-report", daemon=True)
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



def _err_code(res: dict[str, Any]) -> str | None:
    err = res.get("error")
    return str(err.get("code")) if isinstance(err, dict) else None


def _grant_wide_access(path: Path) -> None:
    """Make ``path`` readable by everyone (not owner-only); same mechanism as ``test_doctor_fix``."""
    if sys.platform == "win32":
        import ntsecuritycon

        from tests.support.winacl import grant

        grant(path, "S-1-1-0", ntsecuritycon.FILE_GENERIC_READ)
    else:
        os.chmod(path, 0o644)


def _make_link(path: Path, payload: bytes, outside: Path) -> str:
    """Replace the blob file with a link to a file outside CAS holding the very same (valid) bytes.

    Symlink first; on Windows without the symlink privilege fall back to a directory junction (a reparse point too).
    """
    outside.mkdir(parents=True, exist_ok=True)
    target = outside / "link-target.bin"
    target.write_bytes(payload)
    path.unlink()
    try:
        os.symlink(target, path)
        return "symlink"
    except OSError as err:
        if sys.platform != "win32":
            pytest.skip(f"cannot create a symlink without privilege on this platform: {err}")
    import _winapi

    _winapi.CreateJunction(str(outside), str(path))
    return "junction"


def _break_payload(env: _Env, payload: bytes, how: str, outside: Path) -> None:
    path = blob_path(env.root.cas_dir, digest_bytes(payload))
    if how == "missing":
        path.unlink()
    elif how == "directory":
        path.unlink()
        path.mkdir()
    elif how == "link":
        _make_link(path, payload, outside)
    else:  # insecure: still a regular file with the right bytes, but readable by everyone
        _grant_wide_access(path)


def _inject_after_commit_once(
    monkeypatch: pytest.MonkeyPatch, job_id: str, record_kind: str, *, commit: bool
) -> threading.Event:
    """For the first transaction appending ``record_kind`` for ``job_id``: raise ``STORE_BUSY`` after the commit
    (``commit=True``: lost acknowledgement) or inside the transaction (``commit=False``: rolled back)."""
    fired = threading.Event()
    orig = StagedKernelStore.transact

    def _transact(self: StagedKernelStore, operation: Callable[[Any], Any]) -> Any:
        seen = [False]

        class _Tx:
            def __init__(self, inner: Any) -> None:
                self._inner = inner

            def append_record(self, record: KernelRecord) -> Any:
                if record.kind == record_kind and record.meta.get("job_id") == job_id and not fired.is_set():
                    seen[0] = True
                    if not commit:
                        fired.set()
                        raise BrainError(ErrorCode.STORE_BUSY, "injected settlement-write failure")
                return self._inner.append_record(record)

            def __getattr__(self, name: str) -> Any:
                return getattr(self._inner, name)

        result = orig(self, lambda tx: operation(_Tx(tx)))
        if commit and seen[0] and not fired.is_set():
            fired.set()
            raise BrainError(ErrorCode.STORE_BUSY, "injected lost acknowledgement")
        return result

    monkeypatch.setattr(StagedKernelStore, "transact", _transact)
    return fired


def _settle_scenario(
    trusted_tmp: Path,
    monkeypatch: pytest.MonkeyPatch,
    label: str,
    how: str,
    *,
    arm: Callable[[str], threading.Event] | None = None,
) -> dict[str, Any]:
    """One daemon session: a report blocks on a not-yet-due doctor job, its payload is broken ``how``, the job comes
    due and the doctor step runs; then a second report runs. Returns the observations."""
    env = _Env(trusted_tmp, label)
    job_id, payload = _seed_doctor_job(env, label)
    out: dict[str, Any] = {"job_id": job_id}
    with env.serve() as d:
        with _blocked_report(d, env, monkeypatch) as waiter:
            assert _durable(env, job_id) == ("queued", 1, None), "precondition: the waiter joined the queued job"
            fired = arm(job_id) if arm is not None else None
            _break_payload(env, payload, how, trusted_tmp / f"{label}-outside")
            env.clock.advance(DELAY + timedelta(milliseconds=1))
            poked_at = time.monotonic()
            _poke_until(d, lambda: waiter.done_at is not None, tries=3, each_s=1.5)
        out["fired"] = None if fired is None else fired.is_set()
        out["state"] = _durable(env, job_id)
        out["waiter"] = waiter.res
        out["woke_after"] = None if waiter.done_at is None else waiter.done_at - poked_at
        out["old_runs"] = _runs_for(env, job_id)
        second = _report(d, env, env.cli_token, wait_ms=WAIT_MS)
        data: dict[str, Any] = second.get("data") or {}
        out["second"] = second
        out["second_job"] = str(data.get("job_id") or "")
        out["second_state"] = _durable(env, out["second_job"]) if out["second_job"] else None
    return out


def _assert_settled_failed_and_next_runs(o: dict[str, Any], what: str) -> None:
    assert o["state"] == ("failed", 1, "invalid_payload"), f"{what}: job must be failed/invalid_payload: {o['state']}"
    assert _err_code(o["waiter"]) == ErrorCode.INTEGRITY_FAILURE.value, f"{what}: waiter answer {o['waiter']}"
    assert o["woke_after"] is not None and o["woke_after"] < PROMPT_S, (
        f"{what}: waiter must be woken promptly, answered after {o['woke_after']}s (budget {WAIT_MS}ms)"
    )
    assert not o["old_runs"], f"{what}: no DoctorRun may be created for the failed job: {o['old_runs']}"
    second, data = o["second"], o["second"].get("data") or {}
    assert second.get("ok") is True and data.get("status") == "completed", f"{what}: next report {second}"
    assert o["second_job"] != o["job_id"] and o["second_state"] is not None and o["second_state"][0] == "succeeded", (
        f"{what}: the next job must run to success in the same epoch: {o['second_job']} {o['second_state']}"
    )


# ---------------------------------------------------------------------------
# P1: permanent payload fault raised from inside the read -> settled, waiter answered, next job runs
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("how", ["directory", "link", "insecure", "missing"])
def test_r9_permanent_payload_fault_settles_doctor_job_and_next_job_runs(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, how: str
) -> None:
    """``directory``/``link``/``insecure`` raise from the CAS guard (INTEGRITY_FAILURE / UNSAFE_PATH /
    INSECURE_PERMISSIONS); ``missing`` is the passing control that reaches the same end through a ``None`` read."""
    o = _settle_scenario(trusted_tmp, monkeypatch, f"r9-{how}", how)
    _assert_settled_failed_and_next_runs(o, how)


# ---------------------------------------------------------------------------
# P2: lost acknowledgement of a committed settlement / start
# ---------------------------------------------------------------------------


def test_r9_lost_ack_of_committed_terminal_still_answers_waiter_and_next_job_runs(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    o = _settle_scenario(
        trusted_tmp,
        monkeypatch,
        "r9-lostack-terminal",
        "missing",
        arm=lambda job_id: _inject_after_commit_once(monkeypatch, job_id, "job.terminal", commit=True),
    )
    assert o["fired"], "precondition: the terminal write committed and its acknowledgement was lost"
    _assert_settled_failed_and_next_runs(o, "lost-ack terminal")


def test_r9_lost_ack_of_committed_start_still_runs_the_job(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = _Env(trusted_tmp, "r9-lostack-start")
    job_id, _payload = _seed_doctor_job(env, "lostack-start")
    with env.serve() as d:
        fired = _inject_after_commit_once(monkeypatch, job_id, "job.running", commit=True)
        env.clock.advance(DELAY + timedelta(milliseconds=1))
        _poke_until(d, lambda: _durable(env, job_id)[0] in ("succeeded", "failed", "dead_letter"), tries=3)
        state = _durable(env, job_id)
        runs = _runs_for(env, job_id)
    assert state[0] == "succeeded", f"a committed start must still be executed in the same epoch, job is {state}"
    assert fired.is_set(), "precondition: the job.running write committed and its acknowledgement was lost"
    assert runs, "the started job must commit its DoctorRun"


# ---------------------------------------------------------------------------
# Controls
# ---------------------------------------------------------------------------


def test_r9_control_terminal_write_rolled_back_is_retried_to_failed(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    o = _settle_scenario(
        trusted_tmp,
        monkeypatch,
        "r9-terminal-busy",
        "missing",
        arm=lambda job_id: _inject_after_commit_once(monkeypatch, job_id, "job.terminal", commit=False),
    )
    assert o["fired"], "precondition: the injected terminal-write failure fired"
    assert o["state"] == ("failed", 1, "invalid_payload"), o["state"]
    assert _err_code(o["waiter"]) == ErrorCode.INTEGRITY_FAILURE.value, o["waiter"]


def test_r9_control_transient_payload_read_failure_is_retried(trusted_tmp: Path) -> None:
    env = _Env(trusted_tmp, "r9-transient")
    job_id, payload = _seed_doctor_job(env, "transient")
    target = str(blob_path(env.root.cas_dir, digest_bytes(payload))).lower()
    hits = [0]

    def _open(file: Any, *args: Any, **kwargs: Any) -> Any:
        if str(file).lower() == target and hits[0] < 1:
            hits[0] += 1
            raise PermissionError(13, "Access is denied (i4-r9 transient)", str(file))
        return builtins.open(file, *args, **kwargs)

    with env.serve() as d:
        d.loop.wait_doctor_settled(timeout=0.5)  # startup self-check done before the seam is armed
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


def test_r9_control_generic_job_with_directory_payload_keeps_i2_contract(trusted_tmp: Path) -> None:
    env = _Env(trusted_tmp, "r9-generic-dir")
    payload = b"i4-r9 fixture directory payload"
    with env.offline_rt() as rt:
        svc, st = kernel_job_service(rt, env.clock)
        job_id = enqueue_job(svc, st, owner_id=OWNER_DAN, payload=payload, kind=FIXTURE_JOB_KIND).job_id
        path = blob_path(env.root.cas_dir, digest_bytes(payload))
        path.unlink()
        path.mkdir()
        lease = svc.lease_next(rt.lease.epoch, env.clock.now())
        assert lease is not None and lease.job_id == job_id
        with pytest.raises(BrainError) as exc:
            svc.resolve_leased_spec(lease)
        row = st.transact(lambda tx: tx.read_job(job_id))
    assert exc.value.code is ErrorCode.INTEGRITY_FAILURE, exc.value
    assert row is not None and row.state is JobState.LEASED, row


@pytest.mark.parametrize(
    ("how", "code"), [("insecure", ErrorCode.INSECURE_PERMISSIONS), ("link", ErrorCode.UNSAFE_PATH)]
)
def test_r9_control_generic_job_with_guarded_payload_keeps_original_code_and_lease(
    trusted_tmp: Path, how: str, code: ErrorCode
) -> None:
    """Generic runner, default arguments: a CAS guard refusal surfaces with its own code (not remapped to
    INTEGRITY_FAILURE) and the job stays leased -- the I2 behaviour as on HEAD 9edc6dc."""
    env = _Env(trusted_tmp, f"r9-generic-{how}")
    payload = f"i4-r9 fixture {how} payload".encode()
    with env.offline_rt() as rt:
        svc, st = kernel_job_service(rt, env.clock)
        job_id = enqueue_job(svc, st, owner_id=OWNER_DAN, payload=payload, kind=FIXTURE_JOB_KIND).job_id
        _break_payload(env, payload, how, trusted_tmp / f"r9-generic-{how}-outside")
        lease = svc.lease_next(rt.lease.epoch, env.clock.now())
        assert lease is not None and lease.job_id == job_id
        with pytest.raises(BrainError) as exc:
            svc.resolve_leased_spec(lease)
        row = st.transact(lambda tx: tx.read_job(job_id))
    assert exc.value.code is code, exc.value
    assert row is not None and row.state is JobState.LEASED, row

