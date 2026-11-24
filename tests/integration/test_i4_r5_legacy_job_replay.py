"""Independent RED oracle for SP1 increment 4 re-review finding I4-R5-01 (replay of a legacy job-ID descriptor).

Requirement source: ``docs/reviews/2026-11-24-sp1-increment4-rereview-dd24770.md`` (I4-R5-01) and the coordinator's
brief. A pre-fix ``prepare_deep_health`` could pick an active doctor job by owner only, so a stored store-wide
deep-health descriptor may carry the ``job_id`` of a checkout-scoped (or otherwise invalid) job.

Invariant under test: every ``job_id`` returned by a store-wide deep-health render -- first call or replay, with a
job-only descriptor or a run+job descriptor -- is a durable ``system.doctor`` job of the caller's owner whose payload
scope is store-wide (``checkout_root`` null). On replay the job is read by ID from the durable job store:

- job row absent -> ``not_found``; job owner differs from the principal's owner -> ``not_found``
- job kind is not ``system.doctor`` -> ``integrity_failure``
- payload blob missing / not JSON / not an object / ``checkout_root`` malformed -> ``integrity_failure``
- payload scope is a checkout (any spelling) -> ``revision_conflict`` (as the run-ref path does)
- a valid store-wide doctor job of this owner is returned unchanged in any state, terminal included (control).

How the legacy descriptor is produced: the real daemon stores it through the real idempotent ``get_health`` path.
For the first call only, the two lookups of ``prepare_deep_health`` are patched to the old behaviour
(``find_latest_valid_doctor_run`` -> no run for the job-only shape; ``find_active_doctor_job`` -> a job chosen by
owner only, or the seeded job of the case) and the post-fix render fence is made a no-op, so the first answer is
the old binary's. Patches are undone before the replay with the same idempotency key,
which then runs the code under test unmodified. "Job row gone after restore" is simulated by a job ID that never
existed: a store restore also rewinds the idempotency record, so the harness cannot keep the descriptor while losing
the job row through a real restore.
"""

from __future__ import annotations

import contextlib
import importlib
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any, cast

import pytest

from superbrain.core.canonical import canonical_json
from superbrain.core.errors import ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.kernel import KernelRecord, require_aware_utc
from superbrain.storage.cas import blob_path
from tests.integration.test_doctor_jobs import BOUND_WAIT_S, OWNER_DAN, _ro_db
from tests.integration.test_i4_f4_f8_remediation import (
    NON_TERMINAL,
    OTHER_OWNER,
    _checkout,
    _doctor_jobs,
    _doctor_runs,
    _Env,
    _ReadGate,
    _report,
    _wait_until,
)
from tests.integration.test_i4_r4_remediation import _brief, _data, _health_res
from tests.integration.test_i4_rereview_remediation import _Daemon
from tests.support.inc2_fixture import kernel_job_service

health_mod = importlib.import_module("superbrain.composition._daemon_health")

STORE_WIDE_PAYLOAD = canonical_json({"schema": 1, "trigger": "get_health"})
SHAPES = ("job_only", "run_and_job")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _seed_job(env: _Env, *, owner_id: str, kind: str, payload: bytes) -> str:
    """Durably enqueue a job (daemon stopped) the way the daemon's enqueue path records it; returns its id."""
    job_id = new_id()
    _, now_str = require_aware_utc(env.clock.now())
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
                        "owner_id": owner_id,
                        "repo_id": None,
                        "checkout_id": None,
                        "kind": kind,
                        "payload_digest": digest,
                        "attempt": 1,
                        "retry_at": now_str,
                    },
                )
            )

        js.transact(_op)
    return job_id


def _payload_digest(env: _Env, job_id: str) -> str:
    with _ro_db(env.root.store_db) as conn:
        row = conn.execute("SELECT payload_digest FROM p_jobs_state WHERE job_id = ?", (job_id,)).fetchone()
    assert row is not None and row[0], f"job {job_id} has no durable payload"
    return str(row[0])


def _job_state(env: _Env, job_id: str) -> str | None:
    return next((j["state"] for j in _doctor_jobs(env.root) if j["job_id"] == job_id), None)


@contextlib.contextmanager
def _legacy_lookups(shape: str, job_id: str) -> Iterator[None]:
    """The pre-fix binary for one call: ``prepare_deep_health`` finds ``job_id`` as the active job (picked by owner
    only), and for the job-only shape no DoctorRun; the render accepts the job unchecked, as the pre-fix render did
    (the post-fix render fence ``_require_store_wide_doctor_job`` is made a no-op; absent before the fix)."""
    with pytest.MonkeyPatch.context() as m:
        m.setattr(health_mod, "find_active_doctor_job", lambda *_a, **_k: job_id)
        m.setattr(health_mod, "_require_store_wide_doctor_job", lambda *_a, **_k: None, raising=False)
        if shape == "job_only":
            m.setattr(health_mod, "find_latest_valid_doctor_run", lambda *_a, **_k: None)
        yield


def _store_legacy(d: _Daemon, env: _Env, shape: str, job_id: str, key: str) -> dict[str, Any]:
    """First call under the legacy lookups; asserts the stored descriptor carries ``job_id`` in the wanted shape."""
    with _legacy_lookups(shape, job_id):
        first = _health_res(d, env, env.cli_token, key)
    assert first.get("ok") is True and _data(first).get("job_id") == job_id, (
        f"precondition: the simulated pre-fix call stored a descriptor naming job {job_id}: {_brief(first)}"
    )
    has_run = _data(first).get("doctor_run_id") is not None
    assert has_run is (shape == "run_and_job"), f"precondition: descriptor shape {shape}: {_brief(first)}"
    return first


def _ans(e: dict[str, Any]) -> tuple[Any, Any, Any]:
    """The replay-identity part of a deep-health answer (live fields such as ``age_s`` may differ)."""
    return e.get("ok"), _data(e).get("doctor_run_id"), _data(e).get("job_id")


def _assert_refused(replay: dict[str, Any], job_id: str, code: ErrorCode, label: str) -> None:
    assert _data(replay).get("job_id") != job_id, f"{label}: replay returned the legacy job {job_id}: {_brief(replay)}"
    err = cast(dict[str, Any], replay.get("error") or {})
    assert replay.get("ok") is False and err.get("code") == code.value, (
        f"{label}: replay must fail with {code.value}: {_brief(replay)}"
    )


# ---------------------------------------------------------------------------
# End to end: the reviewer's reproduction (active CLI checkout job picked by owner only)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("shape", SHAPES)
def test_r5_01_replay_of_legacy_descriptor_naming_active_checkout_cli_job_is_refused(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, shape: str
) -> None:
    """A store-wide deep-health key whose pre-fix descriptor names the running CLI job of a checkout is refused on
    replay with ``revision_conflict``; with the run+job shape the store-wide run does not make the job acceptable.
    A store-wide key stored by the current code still replays unchanged (control)."""
    env = _Env(trusted_tmp, f"r5-01-{shape}")
    co = _checkout(env, "repo-x")
    gate = _ReadGate(monkeypatch)
    try:
        with env.serve() as d:
            assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
            env.clock.advance(timedelta(minutes=16))  # past the operator reuse window, inside the 24 h window
            wide_first = _health_res(d, env, env.cli_token, f"idem_i4_r5_01_wide_{shape}")
            gate.armed.set()
            rep = _report(d, env, env.cli_token, wait_ms=0, checkout=co)
            cli_job = _data(rep).get("job_id")
            assert isinstance(cli_job, str) and cli_job, rep
            assert gate.entered.wait(timeout=BOUND_WAIT_S), "the CLI job never reached the worker"
            assert _job_state(env, cli_job) in NON_TERMINAL, "precondition: CLI job is active"
            _store_legacy(d, env, shape, cli_job, f"idem_i4_r5_01_old_{shape}")
            old_replay = _health_res(d, env, env.cli_token, f"idem_i4_r5_01_old_{shape}")
            wide_replay = _health_res(d, env, env.cli_token, f"idem_i4_r5_01_wide_{shape}")
            gate.release.set()
    finally:
        gate.release.set()

    assert wide_first.get("ok") is True, wide_first
    assert _ans(wide_replay) == _ans(wide_first), f"control: store-wide key changed on replay: {wide_replay}"
    _assert_refused(old_replay, cli_job, ErrorCode.REVISION_CONFLICT, "replay returned the checkout-scoped legacy job")


# ---------------------------------------------------------------------------
# Seeded legacy / corrupt jobs, both descriptor shapes
# ---------------------------------------------------------------------------

_CASES: dict[str, tuple[str, str, Any, ErrorCode]] = {
    # name: (owner, kind, payload (bytes, or "CHECKOUT" for the env's real checkout), expected replay error)
    "checkout_scope": (OWNER_DAN, "system.doctor", "CHECKOUT", ErrorCode.REVISION_CONFLICT),
    "checkout_scope_other_spelling": (
        OWNER_DAN,
        "system.doctor",
        canonical_json({"schema": 1, "trigger": "cli", "checkout_root": "c:/I4-R5-Elsewhere/Repo/"}),
        ErrorCode.REVISION_CONFLICT,
    ),
    "never_existed": (OWNER_DAN, "", b"", ErrorCode.NOT_FOUND),
    "other_owner": (OTHER_OWNER, "system.doctor", STORE_WIDE_PAYLOAD, ErrorCode.NOT_FOUND),
    "other_kind": (OWNER_DAN, "test.i4r5.other", STORE_WIDE_PAYLOAD, ErrorCode.INTEGRITY_FAILURE),
    "payload_not_json": (OWNER_DAN, "system.doctor", b"\xffi4-r5 not json", ErrorCode.INTEGRITY_FAILURE),
    "payload_not_object": (OWNER_DAN, "system.doctor", canonical_json([1, 2]), ErrorCode.INTEGRITY_FAILURE),
    "checkout_root_not_string": (
        OWNER_DAN,
        "system.doctor",
        canonical_json({"schema": 1, "trigger": "cli", "checkout_root": 42}),
        ErrorCode.INTEGRITY_FAILURE,
    ),
    "checkout_root_empty": (
        OWNER_DAN,
        "system.doctor",
        canonical_json({"schema": 1, "trigger": "cli", "checkout_root": ""}),
        ErrorCode.INTEGRITY_FAILURE,
    ),
    "payload_blob_missing": (
        OWNER_DAN,
        "system.doctor",
        canonical_json({"schema": 1, "trigger": "get_health", "checkout_root": None, "i4_r5": "unique"}),
        ErrorCode.INTEGRITY_FAILURE,
    ),
}


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("case", sorted(_CASES))
def test_r5_01_replay_of_legacy_descriptor_naming_invalid_job_fails_closed(
    trusted_tmp: Path, shape: str, case: str
) -> None:
    """A replayed store-wide deep-health descriptor whose job is absent, of another owner or kind, has a missing or
    malformed payload, or is checkout-scoped, never returns that job: it fails with the case's error code."""
    owner, kind, payload, expected = _CASES[case]
    env = _Env(trusted_tmp, f"r5-{case}-{shape}"[:40])
    if payload == "CHECKOUT":
        payload = canonical_json({"schema": 1, "trigger": "cli", "checkout_root": str(_checkout(env, "repo-x"))})
    job_id = new_id() if case == "never_existed" else _seed_job(env, owner_id=owner, kind=kind, payload=payload)
    key = f"idem_i4_r5_{case}_{shape}"
    with env.serve() as d:
        assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        env.clock.advance(timedelta(minutes=16))
        _store_legacy(d, env, shape, job_id, key)
        if case == "payload_blob_missing":
            blob_path(env.root.cas_dir, _payload_digest(env, job_id)).unlink()
        replay = _health_res(d, env, env.cli_token, key)

    _assert_refused(replay, job_id, expected, f"{case}/{shape}")


# ---------------------------------------------------------------------------
# Positive control: a valid store-wide doctor job of this owner replays unchanged, terminal included
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("shape", SHAPES)
def test_r5_01_control_replay_of_valid_store_wide_job_is_unchanged_after_it_terminates(
    trusted_tmp: Path, shape: str
) -> None:
    """A replayed descriptor naming a store-wide ``system.doctor`` job of the caller's owner returns the same answer
    after the job reached a terminal state."""
    env = _Env(trusted_tmp, f"r5-ctrl-{shape}")
    job_id = _seed_job(env, owner_id=OWNER_DAN, kind="system.doctor", payload=STORE_WIDE_PAYLOAD)
    key = f"idem_i4_r5_ctrl_{shape}"
    with env.serve() as d:
        assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        assert _wait_until(lambda: _job_state(env, job_id) not in (*NON_TERMINAL, None), BOUND_WAIT_S), (
            f"precondition: seeded store-wide job never terminated: {_job_state(env, job_id)}"
        )
        if shape == "run_and_job":
            assert _doctor_runs(env.root), "precondition: a store-wide DoctorRun exists"
        env.clock.advance(timedelta(minutes=16))
        first = _store_legacy(d, env, shape, job_id, key)
        replay = _health_res(d, env, env.cli_token, key)
        state = _job_state(env, job_id)

    assert state is not None and state not in NON_TERMINAL, f"precondition: job is terminal at replay: {state}"
    assert _ans(replay) == _ans(first), f"control: replay changed: {_brief(first)} -> {_brief(replay)}"
