"""A doctor must settle its claimed job despite a lost write ACK and a second read failure."""

from __future__ import annotations

import threading
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from superbrain.core._kernel_jobs import JobRecord, retry_backoff
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.storage.cas import blob_path
from superbrain.storage.idempotency import StagedKernelStore
from tests.integration.test_i4_f4_f8_remediation import _Env, _report
from tests.integration.test_i4_r9_doctor_payload_fault_classification import (
    DELAY,
    WAIT_MS,
    _assert_settled_failed_and_next_runs,
    _durable,
    _inject_after_commit_once,
    _poke_until,
    _runs_for,
    _seed_doctor_job,
    _settle_scenario,
)


def _fault_claim_read(
    monkeypatch: pytest.MonkeyPatch,
    job_id: str,
    armed: threading.Event,
    *,
    method: str,
    times: int = 1,
) -> list[int]:
    """Inject bounded STORE_BUSY only for the intended job, strictly after the lost ACK."""
    transact = StagedKernelStore.transact
    failed = [0]

    def guarded(self: StagedKernelStore, operation: Callable[[Any], Any]) -> Any:
        if method == "read_job":
            # Fail the lookup receipt, without perturbing a fenced mutation that reads a row internally.
            row = transact(self, operation)
            if armed.is_set() and isinstance(row, JobRecord) and row.job_id == job_id and failed[0] < times:
                failed[0] += 1
                raise BrainError(ErrorCode.STORE_BUSY, "injected job-row read failure after commit")
            return row

        class GuardedTx:
            def __init__(self, inner: Any) -> None:
                self.inner = inner

            def __getattr__(self, name: str) -> Any:
                fn = getattr(self.inner, name)
                if name != method:
                    return fn

                def read(*args: Any, **kwargs: Any) -> Any:
                    if armed.is_set() and kwargs.get("holder_id") == job_id and failed[0] < times:
                        failed[0] += 1
                        raise BrainError(ErrorCode.STORE_BUSY, "injected payload read failure after commit")
                    return fn(*args, **kwargs)

                return read

        return transact(self, lambda tx: operation(GuardedTx(tx)))

    monkeypatch.setattr(StagedKernelStore, "transact", guarded)
    return failed


@pytest.mark.parametrize("method", ["read_job", "read_held_blob"])
def test_r10_lost_start_ack_with_one_transient_reconciliation_read(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, method: str
) -> None:
    env = _Env(trusted_tmp, f"r10-{method}")
    job_id, _ = _seed_doctor_job(env, method)
    with env.serve() as daemon:
        lost_ack = _inject_after_commit_once(monkeypatch, job_id, "job.running", commit=True)
        failed_read = _fault_claim_read(monkeypatch, job_id, lost_ack, method=method)
        env.clock.advance(DELAY + timedelta(milliseconds=1))
        assert _poke_until(daemon, lambda: failed_read[0] == 1), "the reconciliation fault must be exercised"
        env.clock.advance(retry_backoff(1) + timedelta(milliseconds=1))
        _poke_until(daemon, lambda: _durable(env, job_id)[0] == "succeeded")
        state = _durable(env, job_id)
        runs = _runs_for(env, job_id)
    assert lost_ack.is_set() and failed_read == [1]
    assert state[0] == "succeeded", f"one transient reconciliation failure stranded the job: {state}"
    assert len(runs) == 1, f"expected exactly one DoctorRun in the same daemon epoch, got {len(runs)}"


def test_r10_lost_terminal_ack_with_unavailable_reconciliation_wakes_waiter(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    failure_counters: list[list[int]] = []

    def arm(job_id: str) -> threading.Event:
        lost_ack = _inject_after_commit_once(monkeypatch, job_id, "job.terminal", commit=True)
        # Two targeted lookups fail during the transient outage, then the store becomes readable.
        failure_counters.append(_fault_claim_read(monkeypatch, job_id, lost_ack, method="read_job", times=2))
        return lost_ack

    out = _settle_scenario(trusted_tmp, monkeypatch, "r10-terminal-read", "missing", arm=arm)
    assert out["fired"], "the committed terminal acknowledgement must be lost"
    assert failure_counters and failure_counters[0][0] > 0, "a read after the commit must fail"
    _assert_settled_failed_and_next_runs(out, "terminal reconciliation read unavailable")


def test_r10_lost_start_ack_with_permanent_payload_loss_settles_in_same_epoch(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = _Env(trusted_tmp, "r10-adopt-missing")
    job_id, payload = _seed_doctor_job(env, "adopt-missing")
    path = blob_path(env.root.cas_dir, digest_bytes(payload))
    removed = threading.Event()
    with env.serve() as daemon:
        lost_ack = _inject_after_commit_once(monkeypatch, job_id, "job.running", commit=True)
        transact = StagedKernelStore.transact

        def after_start(self: StagedKernelStore, operation: Callable[[Any], Any]) -> Any:
            try:
                return transact(self, operation)
            except BrainError:
                if lost_ack.is_set() and not removed.is_set():
                    path.unlink()
                    removed.set()
                raise

        monkeypatch.setattr(StagedKernelStore, "transact", after_start)
        env.clock.advance(DELAY + timedelta(milliseconds=1))
        _poke_until(daemon, lambda: _durable(env, job_id)[0] == "failed")
        state = _durable(env, job_id)
        assert lost_ack.is_set() and removed.is_set(), "payload must disappear after the committed start"
        assert state[0] == "failed", f"a permanent payload loss stranded the already running job: {state}"
        assert not _runs_for(env, job_id), "the lost payload must never produce a DoctorRun"
        report = _report(daemon, env, env.cli_token, wait_ms=WAIT_MS)
        result = report.get("data") or {}
        assert report.get("ok") is True and result.get("status") == "completed", report
        assert result.get("job_id") != job_id, report
