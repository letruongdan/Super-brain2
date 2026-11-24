"""Independent RED oracle for SP1 increment 4 re-review finding I4-R7-01 (leased job left unsettled).

Requirement source: ``docs/reviews/2026-11-24-sp1-increment4-rereview-50f63ac.md`` (I4-R7-01) and the coordinator's
brief. Invariant under test: once a runner holds a lease, ``JobService.resolve_leased_spec`` settles the job durably
before returning and never leaves it ``leased``:

- R1 the job's own payload hold was released (blob still on disk and intact, holder not tombstoned) -> the job
  is ``failed`` with reason ``invalid_payload`` in the same call; no exception reaches the runner; nothing runs.
  Tombstoned holder / quarantined payload already end the same way (controls).
- Out of scope (coordinator correction, sealed contract of ``test_kernel_daemon.py`` subcase 3a): a MISSING or
  CORRUPT blob without policy restriction keeps today's contract -- ``INTEGRITY_FAILURE`` and the job left leased;
  a control pins that it is unchanged.
- R2 transient read failure of the payload (an OSError while reading the blob) -> bounded retry through the existing
  retry rules: ``queued`` with ``attempt + 1`` and a backoff ``retry_at``; after ``MAX_JOB_ATTEMPTS`` ->
  ``dead_letter``; never ``leased``.
- R3 through the real daemon (released-hold case): a due store-wide doctor job whose hold was released ends
  ``failed``/``invalid_payload``, the daemon settles, another valid DoctorRun commits and a store-wide enqueue still
  works; the same end state for a job left leased by a previous writer epoch. The generic daemon runner (non-doctor
  kind) obeys the same rule.
- Controls (before and after): tombstoned holder -> ``failed``/``invalid_payload``; a valid job runs to
  ``succeeded``; a valid non-doctor job runs unchanged.

Durable job state is read from the job store (``read_job`` / ``p_jobs_state``), never from logs. The transient read
failure is injected by shadowing ``open`` in ``superbrain.storage.cas`` for that one blob path.
"""

from __future__ import annotations

import builtins
import contextlib
import threading
from collections.abc import Callable, Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

import superbrain.storage.cas as cas_mod
from superbrain.composition.daemon_entry import create_daemon_owner_loop
from superbrain.core._kernel_jobs import MAX_JOB_ATTEMPTS, JobErrorCode, JobRecord, JobState, retry_backoff
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import ObjectRef, require_aware_utc
from superbrain.ports.policy import IntentKind
from superbrain.storage.cas import blob_path
from superbrain.workers.executor import JobContext
from tests.integration.test_doctor_jobs import BOUND_WAIT_S, OWNER_DAN, _ro_db
from tests.integration.test_i4_f4_f8_remediation import _doctor_runs, _Env, _report, _wait_until
from tests.support.inc2_fixture import FIXTURE_JOB_KIND, enqueue_job, kernel_job_service

DOCTOR_KIND = "system.doctor"
POLICY_OR_RELEASED = ("released", "tombstoned", "quarantined")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _doctor_payload(tag: str) -> bytes:
    return canonical_json({"schema": 1, "trigger": "manual", "checkout_root": None, "i4_r7": tag})


def _seed(env: _Env, payload: bytes, kind: str) -> str:
    """Enqueue one job (daemon stopped) through ``JobService.enqueue``; returns its id."""
    with env.offline_rt() as rt:
        svc, st = kernel_job_service(rt, env.clock)
        return enqueue_job(svc, st, owner_id=OWNER_DAN, payload=payload, kind=kind).job_id


def _break_payload(rt: Any, env: _Env, job_id: str, digest: str, how: str) -> None:
    """Permanently remove the payload evidence of ``job_id`` the way ``how`` names (daemon stopped)."""
    path = blob_path(env.root.cas_dir, digest)
    if how == "released":
        with rt.store.transaction() as txn:
            txn.release(digest, "event", job_id, "expired")
        assert path.is_file(), "precondition: blob still on disk after the release"
    elif how == "tombstoned":
        rt.policy.record_intent(IntentKind.TOMBSTONE, {"holder_kind": "event", "holder_id": job_id})
    elif how == "quarantined":
        rt.policy.record_intent(IntentKind.QUARANTINE, {"digest": digest})
    elif how == "missing":
        path.unlink()
    else:
        path.write_bytes(b"i4-r7 corrupted blob bytes")
        assert digest_bytes(path.read_bytes()) != digest


def _row(st: Any, job_id: str) -> JobRecord:
    row = st.transact(lambda tx: tx.read_job(job_id))
    assert row is not None, f"job {job_id} vanished"
    return row  # type: ignore[no-any-return]


def _durable(env: _Env, job_id: str) -> tuple[str, int, str | None]:
    """``(state, attempt, reason)`` of ``job_id`` read from the durable jobs projection (daemon may be running)."""
    with _ro_db(env.root.store_db) as conn:
        r = conn.execute("SELECT state, attempt, reason FROM p_jobs_state WHERE job_id = ?", (job_id,)).fetchone()
    assert r is not None, f"job {job_id} has no durable row"
    return str(r[0]), int(r[1]), None if r[2] is None else str(r[2])


@contextlib.contextmanager
def _failing_blob_open(path: Path, times: int) -> Iterator[list[int]]:
    """``open`` inside ``superbrain.storage.cas`` raises PermissionError for ``path`` the next ``times`` calls."""
    target = str(path).lower()
    hits = [0]

    def _open(file: Any, *args: Any, **kwargs: Any) -> Any:
        if str(file).lower() == target and hits[0] < times:
            hits[0] += 1
            raise PermissionError(13, "Access is denied (i4-r7 transient)", str(file))
        return builtins.open(file, *args, **kwargs)

    with pytest.MonkeyPatch.context() as m:
        m.setattr(cas_mod, "open", _open, raising=False)
        yield hits


def _lease_and_resolve(svc: Any, rt: Any, env: _Env, job_id: str) -> tuple[Any, BrainError | None]:
    lease = svc.lease_next(rt.lease.epoch, env.clock.now())
    assert lease is not None and lease.job_id == job_id, f"precondition: leased {job_id}: {lease}"
    try:
        return svc.resolve_leased_spec(lease), None
    except BrainError as exc:
        return None, exc


# ---------------------------------------------------------------------------
# R1 / controls: service level, both a doctor kind and a non-doctor kind (one shared JobService rule)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", [DOCTOR_KIND, FIXTURE_JOB_KIND])
@pytest.mark.parametrize("how", POLICY_OR_RELEASED)
def test_r7_01_resolve_fails_leased_job_whose_payload_evidence_is_gone(trusted_tmp: Path, kind: str, how: str) -> None:
    """A leased job whose own payload hold was released (blob intact on disk) is settled ``failed``/
    ``invalid_payload`` at attempt 1 by ``resolve_leased_spec`` itself; no exception escapes and no spec is returned.
    Tombstoned and quarantined are the existing behaviour (controls)."""
    env = _Env(trusted_tmp, f"r7-{how}-{kind.split('.')[0]}")
    payload = _doctor_payload(how) if kind == DOCTOR_KIND else f"i4-r7 fixture {how}".encode()
    job_id = _seed(env, payload, kind)
    with env.offline_rt() as rt:
        svc, st = kernel_job_service(rt, env.clock)
        _break_payload(rt, env, job_id, digest_bytes(payload), how)
        spec, exc = _lease_and_resolve(svc, rt, env, job_id)
        row = _row(st, job_id)
    assert exc is None, f"{how}: resolve_leased_spec raised {exc!r}; job left {row.state.value}"
    assert spec is None, f"{how}: a spec was returned for a job without payload evidence"
    assert (row.state, row.reason, row.attempt) == (JobState.FAILED, JobErrorCode.INVALID_PAYLOAD, 1), (
        f"{how}: job must be failed/invalid_payload at attempt 1, is {row.state.value}/{row.reason}/{row.attempt}"
    )


@pytest.mark.parametrize("kind", [DOCTOR_KIND, FIXTURE_JOB_KIND])
@pytest.mark.parametrize("how", ["missing", "corrupt"])
def test_r7_01_control_missing_or_corrupt_blob_keeps_integrity_failure_contract(
    trusted_tmp: Path, kind: str, how: str
) -> None:
    """Control (existing sealed contract, out of scope for I4-R7-01): a missing or corrupt blob without policy
    restriction makes ``resolve_leased_spec`` raise ``INTEGRITY_FAILURE`` and leaves the job leased."""
    env = _Env(trusted_tmp, f"r7-{how}-{kind.split('.')[0]}")
    payload = _doctor_payload(how) if kind == DOCTOR_KIND else f"i4-r7 fixture {how}".encode()
    job_id = _seed(env, payload, kind)
    with env.offline_rt() as rt:
        svc, st = kernel_job_service(rt, env.clock)
        _break_payload(rt, env, job_id, digest_bytes(payload), how)
        spec, exc = _lease_and_resolve(svc, rt, env, job_id)
        row = _row(st, job_id)
    assert spec is None
    assert exc is not None and exc.code is ErrorCode.INTEGRITY_FAILURE, f"{how}: expected INTEGRITY_FAILURE: {exc!r}"
    assert row.state is JobState.LEASED, f"{how}: existing contract leaves the job leased, is {row.state.value}"


@pytest.mark.parametrize("kind", [DOCTOR_KIND, FIXTURE_JOB_KIND])
def test_r7_01_control_valid_payload_resolves_to_its_spec(trusted_tmp: Path, kind: str) -> None:
    """Control: an intact payload resolves to the job's spec and the job stays leased for the runner to start."""
    env = _Env(trusted_tmp, f"r7-valid-{kind.split('.')[0]}")
    payload = _doctor_payload("valid") if kind == DOCTOR_KIND else b"i4-r7 fixture valid"
    job_id = _seed(env, payload, kind)
    with env.offline_rt() as rt:
        svc, st = kernel_job_service(rt, env.clock)
        spec, exc = _lease_and_resolve(svc, rt, env, job_id)
        row = _row(st, job_id)
    assert exc is None and spec is not None, exc
    assert (spec.kind, spec.payload) == (kind, payload)
    assert row.state is JobState.LEASED


# ---------------------------------------------------------------------------
# R2: transient read failure -> bounded retry, then dead letter; never leased
# ---------------------------------------------------------------------------


def test_r7_02_transient_payload_read_failure_requeues_with_backoff(trusted_tmp: Path) -> None:
    """An OSError while reading an intact, held payload re-queues the job at ``attempt + 1`` with the backoff
    ``retry_at`` (not ``failed``, not ``leased``); once the read works again the next lease resolves the spec."""
    env = _Env(trusted_tmp, "r7-transient")
    payload = _doctor_payload("transient")
    job_id = _seed(env, payload, DOCTOR_KIND)
    path = blob_path(env.root.cas_dir, digest_bytes(payload))
    with env.offline_rt() as rt:
        svc, st = kernel_job_service(rt, env.clock)
        now_utc, _ = require_aware_utc(env.clock.now())
        with _failing_blob_open(path, times=1) as hits:
            _spec, exc = _lease_and_resolve(svc, rt, env, job_id)
        row = _row(st, job_id)
        assert hits[0] == 1, "precondition: the injected read failure fired"
        assert row.state is JobState.QUEUED, f"transient read failure left the job {row.state.value} ({exc!r})"
        assert row.attempt == 2 and row.writer_epoch is None and row.lease_id is None, row
        assert row.retry_at == require_aware_utc(now_utc + retry_backoff(1))[1], row.retry_at
        env.clock.advance(retry_backoff(1))
        spec2, exc2 = _lease_and_resolve(svc, rt, env, job_id)
    assert exc2 is None and spec2 is not None and spec2.payload == payload, exc2


def test_r7_02_transient_payload_read_failure_dead_letters_after_max_attempts(trusted_tmp: Path) -> None:
    """A payload read that keeps failing transiently is retried up to ``MAX_JOB_ATTEMPTS`` and then dead-lettered;
    after every attempt the job is queued or terminal, never leased."""
    env = _Env(trusted_tmp, "r7-deadletter")
    payload = _doctor_payload("deadletter")
    job_id = _seed(env, payload, DOCTOR_KIND)
    path = blob_path(env.root.cas_dir, digest_bytes(payload))
    states: list[tuple[str, int]] = []
    with env.offline_rt() as rt:
        svc, st = kernel_job_service(rt, env.clock)
        with _failing_blob_open(path, times=10_000):
            for attempt in range(1, MAX_JOB_ATTEMPTS + 1):
                _lease_and_resolve(svc, rt, env, job_id)
                row = _row(st, job_id)
                states.append((row.state.value, row.attempt))
                if attempt < MAX_JOB_ATTEMPTS:
                    env.clock.advance(retry_backoff(attempt) + timedelta(milliseconds=1))
        final = _row(st, job_id)
    expected = [("queued", a + 1) for a in range(1, MAX_JOB_ATTEMPTS)] + [("dead_letter", MAX_JOB_ATTEMPTS)]
    assert states == expected, f"retry sequence {states}, expected {expected}"
    assert final.state is JobState.DEAD_LETTER


# ---------------------------------------------------------------------------
# R3: real daemon, doctor runner
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("how", ["released", "tombstoned", "valid"])
def test_r7_03_daemon_settles_due_doctor_job_without_payload_hold(trusted_tmp: Path, how: str) -> None:
    """A due store-wide doctor job whose own hold was released ends ``failed``/``invalid_payload`` (not ``leased``);
    the daemon settles, a valid DoctorRun commits and a store-wide report still works. Controls: a tombstoned holder
    ends the same way; a valid job ends ``succeeded``."""
    env = _Env(trusted_tmp, f"r7-daemon-{how}")
    payload = _doctor_payload(f"daemon-{how}")
    job_id = _seed(env, payload, DOCTOR_KIND)
    if how != "valid":
        with env.offline_rt() as rt:
            _break_payload(rt, env, job_id, digest_bytes(payload), how)
    with env.serve() as d:
        settled = d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        state = _durable(env, job_id)
        runs = _doctor_runs(env.root)
        env.clock.advance(timedelta(minutes=16))
        rep = _report(d, env, env.cli_token, wait_ms=0)

    if how == "valid":
        assert state[0] == "succeeded", f"control: valid doctor job must succeed: {state}"
    else:
        assert state == ("failed", 1, "invalid_payload"), f"{how}: job must be failed/invalid_payload, is {state}"
    assert settled, f"{how}: daemon never settled (job {state})"
    assert any(r["job_id"] != job_id for r in runs) or how == "valid", f"{how}: no other DoctorRun committed"
    assert rep.get("ok") is True, f"{how}: store-wide report failed afterwards: {rep}"


@pytest.mark.parametrize("how", ["released", "tombstoned"])
def test_r7_03_daemon_settles_doctor_job_left_leased_by_previous_epoch(trusted_tmp: Path, how: str) -> None:
    """A doctor job leased by an earlier writer epoch whose payload evidence is gone is recovered and then settled
    ``failed``/``invalid_payload`` by the new daemon, which settles."""
    env = _Env(trusted_tmp, f"r7-epoch-{how}")
    payload = _doctor_payload(f"epoch-{how}")
    job_id = _seed(env, payload, DOCTOR_KIND)
    with env.offline_rt() as rt:
        svc, st = kernel_job_service(rt, env.clock)
        lease = svc.lease_next(rt.lease.epoch, env.clock.now())
        assert lease is not None and lease.job_id == job_id
        _break_payload(rt, env, job_id, digest_bytes(payload), how)
        assert _row(st, job_id).state is JobState.LEASED, "precondition: left leased in the old epoch"
    with env.serve() as d:
        settled = d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        state = _durable(env, job_id)
    assert state[0] == "failed" and state[2] == "invalid_payload", (
        f"{how}: job must end failed/invalid_payload: {state}"
    )
    assert settled, f"{how}: daemon never settled (job {state})"


# ---------------------------------------------------------------------------
# R3: real daemon, generic runner (non-doctor kind)
# ---------------------------------------------------------------------------


def test_r7_03_generic_daemon_runner_settles_released_job_and_runs_valid_one(trusted_tmp: Path) -> None:
    """Generic daemon runner (released-hold case): a non-doctor job whose hold was released ends
    ``failed``/``invalid_payload`` without its handler running; a valid non-doctor job queued after it runs to
    ``succeeded`` (control)."""
    env = _Env(trusted_tmp, "r7-generic")
    bad_payload, good_payload = b"i4-r7 generic released", b"i4-r7 generic valid"
    bad = _seed(env, bad_payload, FIXTURE_JOB_KIND)
    env.clock.advance(timedelta(milliseconds=1))
    good = _seed(env, good_payload, FIXTURE_JOB_KIND)
    with env.offline_rt() as rt:
        _break_payload(rt, env, bad, digest_bytes(bad_payload), "released")
    ran: list[bytes] = []
    ran_lock = threading.Lock()

    def _handler(spec: Any, _ctx: JobContext) -> tuple[ObjectRef, ...]:
        with ran_lock:
            ran.append(bytes(spec.payload))
        return ()

    handlers: dict[str, Callable[[Any, JobContext], tuple[ObjectRef, ...]]] = {FIXTURE_JOB_KIND: _handler}
    loop = create_daemon_owner_loop(os_=env.os_, clock=env.clock, monotonic_clock=env.mono, job_handlers=handlers)
    try:
        loop.start(env.cfg)
        done = _wait_until(
            lambda: _durable(env, good)[0] == "succeeded" and _durable(env, bad)[0] not in ("queued",), BOUND_WAIT_S
        )
        good_state, bad_state = _durable(env, good), _durable(env, bad)
    finally:
        with contextlib.suppress(BrainError):
            loop.stop()
        loop.wait_closed(timeout=BOUND_WAIT_S)

    assert done, f"jobs never progressed: good={good_state} bad={bad_state}"
    assert good_state[0] == "succeeded" and good_payload in ran, f"control: valid job must run: {good_state}"
    assert bad_payload not in ran, "the handler ran a job without payload evidence"
    assert bad_state == ("failed", 1, "invalid_payload"), f"released job must be failed/invalid_payload: {bad_state}"
