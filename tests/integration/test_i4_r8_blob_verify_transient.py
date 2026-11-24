"""Independent RED oracle for SP1 increment 4 re-review finding I4-R8-01 (transient blob-verify error leaves job leased)

Requirement source: ``docs/reviews/2026-11-24-sp1-increment4-rereview-adec0c7.md`` (I4-R8-01). Invariant under test:
after a lease is acquired, a transient I/O error in ANY step ``JobService.resolve_leased_spec`` uses to classify the
payload goes through the bounded retry settlement (``queued`` at ``attempt + 1`` with the backoff ``retry_at``, then
``dead_letter`` at ``MAX_JOB_ATTEMPTS``); the job is never left ``leased`` and no transient error reaches the caller.

The covered step: the job's own hold was released, so the held read yields nothing without touching the file, and the
"are the bytes still intact?" check (``blob_present`` -> ``blob_intact`` -> ``file_digest``) reads the blob. The
transient failure is injected with the same seam as the I4-R7 oracle: ``open`` shadowed in ``superbrain.storage.cas``
for that one blob path, raising ``PermissionError``.

- B1 one transient failure -> ``None``, ``queued``/attempt 2, ``retry_at == now + retry_backoff(1)``; once the failure
  stops the next lease settles ``failed``/``invalid_payload`` (holder gone, bytes intact).
- B2 the failure persists -> ``queued``/2 ... ``queued``/MAX then ``dead_letter``; never ``leased``.
- B3 generic daemon runner (non-doctor kind): one transient failure re-queues, then the job ends
  ``failed``/``invalid_payload`` without its handler running.
- Controls: missing / corrupt blob (no policy restriction) still raise ``INTEGRITY_FAILURE`` and leave the job
  ``leased`` (I2 subcase 3a contract); a valid payload still resolves to its ``JobSpec``.

Durable job state is read from the job store (``read_job`` / ``p_jobs_state``), never from logs.
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
from superbrain.storage.cas import blob_path
from superbrain.workers.executor import JobContext
from tests.integration.test_doctor_jobs import BOUND_WAIT_S, OWNER_DAN, _ro_db
from tests.integration.test_i4_f4_f8_remediation import _Env, _wait_until
from tests.support.inc2_fixture import FIXTURE_JOB_KIND, enqueue_job, kernel_job_service

DOCTOR_KIND = "system.doctor"
KINDS = [DOCTOR_KIND, FIXTURE_JOB_KIND]


# ---------------------------------------------------------------------------
# Helpers (copied from the I4-R7 oracle, not imported from it)
# ---------------------------------------------------------------------------


def _payload(kind: str, tag: str) -> bytes:
    if kind == DOCTOR_KIND:
        return canonical_json({"schema": 1, "trigger": "manual", "checkout_root": None, "i4_r8": tag})
    return f"i4-r8 fixture {tag}".encode()


def _seed(env: _Env, payload: bytes, kind: str) -> str:
    with env.offline_rt() as rt:
        svc, st = kernel_job_service(rt, env.clock)
        return enqueue_job(svc, st, owner_id=OWNER_DAN, payload=payload, kind=kind).job_id


def _release(rt: Any, env: _Env, job_id: str, digest: str) -> Path:
    """Release the job's own payload hold; the blob stays on disk and intact."""
    path = blob_path(env.root.cas_dir, digest)
    with rt.store.transaction() as txn:
        txn.release(digest, "event", job_id, "expired")
    assert path.is_file() and digest_bytes(path.read_bytes()) == digest, "precondition: blob intact after release"
    return path


def _row(st: Any, job_id: str) -> JobRecord:
    row = st.transact(lambda tx: tx.read_job(job_id))
    assert row is not None, f"job {job_id} vanished"
    return row  # type: ignore[no-any-return]


def _durable(env: _Env, job_id: str) -> tuple[str, int, str | None]:
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
            raise PermissionError(13, "Access is denied (i4-r8 transient)", str(file))
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
# B1: one transient failure in the intact check -> requeue with backoff, then failed/invalid_payload
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", KINDS)
def test_r8_01_transient_intact_check_failure_requeues_then_fails_invalid_payload(
    trusted_tmp: Path, kind: str
) -> None:
    env = _Env(trusted_tmp, f"r8-once-{kind.split('.')[0]}")
    payload = _payload(kind, "once")
    job_id = _seed(env, payload, kind)
    with env.offline_rt() as rt:
        svc, st = kernel_job_service(rt, env.clock)
        path = _release(rt, env, job_id, digest_bytes(payload))
        now_utc, _ = require_aware_utc(env.clock.now())
        with _failing_blob_open(path, times=1) as hits:
            spec, exc = _lease_and_resolve(svc, rt, env, job_id)
        row = _row(st, job_id)
        assert hits[0] == 1, "precondition: the injected read failure fired during the intact check"
        assert exc is None, f"transient intact-check failure escaped: {exc!r}; job left {row.state.value}"
        assert spec is None
        assert row.state is JobState.QUEUED, f"job must be re-queued, is {row.state.value}"
        assert row.attempt == 2 and row.writer_epoch is None and row.lease_id is None, row
        assert row.retry_at == require_aware_utc(now_utc + retry_backoff(1))[1], row.retry_at

        env.clock.advance(retry_backoff(1))
        spec2, exc2 = _lease_and_resolve(svc, rt, env, job_id)
        row2 = _row(st, job_id)
    assert exc2 is None and spec2 is None, (spec2, exc2)
    assert (row2.state, row2.reason) == (JobState.FAILED, JobErrorCode.INVALID_PAYLOAD), (
        f"after recovery the released job must be failed/invalid_payload, is {row2.state.value}/{row2.reason}"
    )


# ---------------------------------------------------------------------------
# B2: persistent transient failure -> bounded retry then dead letter
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", KINDS)
def test_r8_02_persistent_intact_check_failure_dead_letters_after_max_attempts(trusted_tmp: Path, kind: str) -> None:
    env = _Env(trusted_tmp, f"r8-dead-{kind.split('.')[0]}")
    payload = _payload(kind, "dead")
    job_id = _seed(env, payload, kind)
    states: list[tuple[str, int]] = []
    with env.offline_rt() as rt:
        svc, st = kernel_job_service(rt, env.clock)
        path = _release(rt, env, job_id, digest_bytes(payload))
        with _failing_blob_open(path, times=10_000):
            for attempt in range(1, MAX_JOB_ATTEMPTS + 1):
                _lease_and_resolve(svc, rt, env, job_id)
                row = _row(st, job_id)
                states.append((row.state.value, row.attempt))
                if row.state is not JobState.QUEUED:
                    break
                env.clock.advance(retry_backoff(attempt) + timedelta(milliseconds=1))
    expected = [("queued", a + 1) for a in range(1, MAX_JOB_ATTEMPTS)] + [("dead_letter", MAX_JOB_ATTEMPTS)]
    assert states == expected, f"retry sequence {states}, expected {expected}"


# ---------------------------------------------------------------------------
# B3: generic daemon runner
# ---------------------------------------------------------------------------


def test_r8_03_generic_daemon_runner_requeues_transient_then_fails_released_job(trusted_tmp: Path) -> None:
    env = _Env(trusted_tmp, "r8-generic")
    payload = b"i4-r8 generic released"
    job_id = _seed(env, payload, FIXTURE_JOB_KIND)
    with env.offline_rt() as rt:
        path = _release(rt, env, job_id, digest_bytes(payload))
    ran: list[bytes] = []
    ran_lock = threading.Lock()

    def _handler(spec: Any, _ctx: JobContext) -> tuple[ObjectRef, ...]:
        with ran_lock:
            ran.append(bytes(spec.payload))
        return ()

    handlers: dict[str, Callable[[Any, JobContext], tuple[ObjectRef, ...]]] = {FIXTURE_JOB_KIND: _handler}
    loop = create_daemon_owner_loop(os_=env.os_, clock=env.clock, monotonic_clock=env.mono, job_handlers=handlers)
    first: tuple[str, int, str | None] | None = None
    final: tuple[str, int, str | None] | None = None
    try:
        with _failing_blob_open(path, times=1) as hits:
            loop.start(env.cfg)
            _wait_until(lambda: _durable(env, job_id)[0] != "queued" or _durable(env, job_id)[1] > 1, BOUND_WAIT_S)
            first = _durable(env, job_id)
            env.clock.advance(retry_backoff(1) + timedelta(milliseconds=1))
            _wait_until(lambda: _durable(env, job_id)[0] not in ("queued", "leased"), BOUND_WAIT_S)
            final = _durable(env, job_id)
    finally:
        with contextlib.suppress(BrainError):
            loop.stop()
        loop.wait_closed(timeout=BOUND_WAIT_S)

    assert hits[0] == 1, "precondition: the injected read failure fired"
    assert first is not None and first[:2] == ("queued", 2), f"transient failure must re-queue at attempt 2: {first}"
    assert final is not None and (final[0], final[2]) == ("failed", "invalid_payload"), (
        f"released job must end failed/invalid_payload: {final}"
    )
    assert payload not in ran, "the handler ran a job without payload evidence"


# ---------------------------------------------------------------------------
# Controls
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("how", ["missing", "corrupt"])
def test_r8_control_missing_or_corrupt_blob_keeps_integrity_failure_contract(
    trusted_tmp: Path, kind: str, how: str
) -> None:
    env = _Env(trusted_tmp, f"r8-{how}-{kind.split('.')[0]}")
    payload = _payload(kind, how)
    job_id = _seed(env, payload, kind)
    digest = digest_bytes(payload)
    with env.offline_rt() as rt:
        svc, st = kernel_job_service(rt, env.clock)
        path = blob_path(env.root.cas_dir, digest)
        if how == "missing":
            path.unlink()
        else:
            path.write_bytes(b"i4-r8 corrupted blob bytes")
        spec, exc = _lease_and_resolve(svc, rt, env, job_id)
        row = _row(st, job_id)
    assert spec is None
    assert exc is not None and exc.code is ErrorCode.INTEGRITY_FAILURE, f"{how}: expected INTEGRITY_FAILURE: {exc!r}"
    assert row.state is JobState.LEASED, f"{how}: existing contract leaves the job leased, is {row.state.value}"


@pytest.mark.parametrize("kind", KINDS)
def test_r8_control_valid_payload_resolves_to_its_spec(trusted_tmp: Path, kind: str) -> None:
    env = _Env(trusted_tmp, f"r8-valid-{kind.split('.')[0]}")
    payload = _payload(kind, "valid")
    job_id = _seed(env, payload, kind)
    with env.offline_rt() as rt:
        svc, st = kernel_job_service(rt, env.clock)
        spec, exc = _lease_and_resolve(svc, rt, env, job_id)
        row = _row(st, job_id)
    assert exc is None and spec is not None, exc
    assert (spec.kind, spec.payload) == (kind, payload)
    assert row.state is JobState.LEASED
