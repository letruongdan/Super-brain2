"""Independent RED oracle for SP1 increment 4 re-review finding I4-R6-01 (job payload read without its holder).

Requirement source: ``docs/reviews/2026-11-24-sp1-increment4-rereview-a4be356.md`` (I4-R6-01) and the coordinator's
brief. Invariant under test: a ``system.doctor`` job's payload is evidence of its scope only through a live hold of
THAT job (holder kind ``event``, holder id = job id, the job runner's rule: held, holder not tombstoned, digest not
quarantined, blob intact). Bytes still on disk, or held by another job, do not count.

- R1 render (first call and replay; job-only and run+job descriptors): a job whose hold was released or whose holder
  is tombstoned is refused with ``integrity_failure``; a quarantined payload is refused with ``quarantined``.
- R2 active-job lookup: an active doctor job whose payload hold is released/tombstoned is never the slot owner --
  deep health does not return it, a store-wide enqueue (startup schedule, CLI/operator report) is not deduplicated
  onto it -- and the lookup does not raise for it.
- Controls (green before and after): an intact hold keeps working across a restart and replay; an intact active job
  is still the deduplicated slot; with a shared payload digest, releasing one job's hold leaves the other job intact.

Mutations are applied with the daemon stopped, through the store/policy APIs the product itself uses:
``cas.release`` via a store transaction (``txn.release``), a tombstone/quarantine via ``policy.record_intent``. The
reviewer's reproduction (release, confirm ``CAS.read`` still returns the bytes, restart, replay the same key over
TLS) is the ``released`` render case; every final replay goes over TLS ``/v2/tools/call``.
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
from superbrain.core.wire import load_catalog
from superbrain.ports.policy import IntentKind
from superbrain.storage.cas import blob_path
from tests.integration.test_doctor_jobs import BOUND_WAIT_S, OWNER_DAN, _ro_db
from tests.integration.test_i4_f4_f8_remediation import NON_TERMINAL, _doctor_jobs, _doctor_runs, _Env, _report
from tests.integration.test_i4_owner_thread_remediation import _post_operator
from tests.integration.test_i4_r4_remediation import _brief, _data, _health_res
from tests.integration.test_i4_rereview_remediation import _Daemon
from tests.support.inc2_fixture import kernel_job_service

health_mod = importlib.import_module("superbrain.composition._daemon_health")

SHAPES = ("job_only", "run_and_job")
_EXPECTED = {
    "released": ErrorCode.INTEGRITY_FAILURE,
    "tombstoned": ErrorCode.INTEGRITY_FAILURE,
    "quarantined": ErrorCode.QUARANTINED,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _payload(tag: str) -> bytes:
    """A store-wide doctor payload whose bytes (digest) are unique to ``tag``."""
    return canonical_json({"schema": 1, "trigger": "manual", "checkout_root": None, "i4_r6": tag})


def _seed_job(env: _Env, payload: bytes, *, retry_in: timedelta = timedelta(0)) -> str:
    """Durably enqueue a store-wide ``system.doctor`` job of dan (daemon stopped), held by its own job id."""
    job_id = new_id()
    _, retry_str = require_aware_utc(env.clock.now() + retry_in)
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
                        "kind": "system.doctor",
                        "payload_digest": digest,
                        "attempt": 1,
                        "retry_at": retry_str,
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


def _job_holds(env: _Env, job_id: str) -> set[str]:
    with _ro_db(env.root.store_db) as conn:
        rows = conn.execute("SELECT digest FROM p_cas_holders_ WHERE holder_id = ?", (job_id,)).fetchall()
    return {str(r[0]) for r in rows}


def _job_state(env: _Env, job_id: str) -> str | None:
    return next((j["state"] for j in _doctor_jobs(env.root) if j["job_id"] == job_id), None)


def _apply_mutation(rt: Any, job_id: str, digest: str, how: str) -> None:
    expected = rt.store.cas.read(digest)
    if how == "released":
        with rt.store.transaction() as txn:
            txn.release(digest, "event", job_id, "expired")
        assert rt.store.cas.read(digest) == expected, "precondition: CAS.read still returns the payload bytes"
    elif how == "tombstoned":
        rt.policy.record_intent(IntentKind.TOMBSTONE, {"holder_kind": "event", "holder_id": job_id})
        assert rt.policy.is_tombstoned("event", job_id)
    else:
        rt.policy.record_intent(IntentKind.QUARANTINE, {"digest": digest})
        assert rt.policy.is_quarantined(digest)


def _mutate(env: _Env, job_id: str, how: str, d: _Daemon | None = None) -> None:
    """Release the job's own payload hold, tombstone the job holder, or quarantine the payload: offline (daemon
    stopped) when ``d`` is None, else on the running daemon's owner thread."""
    digest = _payload_digest(env, job_id)
    if d is None:
        with env.offline_rt() as rt:
            _apply_mutation(rt, job_id, digest, how)
    else:
        d.loop.run_owner_action(lambda: _apply_mutation(d.rt, job_id, digest, how)).result(timeout=BOUND_WAIT_S)
    if how == "released":
        assert digest not in _job_holds(env, job_id), "precondition: the job no longer holds its payload"
    assert blob_path(env.root.cas_dir, digest).is_file(), "precondition: the payload blob is still on disk"


@contextlib.contextmanager
def _lookup_names(shape: str, job_id: str) -> Iterator[None]:
    """For one first call: ``prepare_deep_health`` finds ``job_id`` as the active slot (and no run when job-only).
    The render is not patched."""
    with pytest.MonkeyPatch.context() as m:
        m.setattr(health_mod, "find_active_doctor_job", lambda *_a, **_k: job_id)
        if shape == "job_only":
            m.setattr(health_mod, "find_latest_valid_doctor_run", lambda *_a, **_k: None)
        yield


def _store_descriptor(d: _Daemon, env: _Env, shape: str, job_id: str, key: str) -> dict[str, Any]:
    with _lookup_names(shape, job_id):
        first = _health_res(d, env, env.cli_token, key)
    assert first.get("ok") is True and _data(first).get("job_id") == job_id, (
        f"precondition: first call stored a descriptor naming job {job_id}: {_brief(first)}"
    )
    assert (_data(first).get("doctor_run_id") is not None) is (shape == "run_and_job"), _brief(first)
    return first


def _health_tls(d: _Daemon, env: _Env, key: str) -> dict[str, Any]:
    """``get_health(deep=True)`` over the daemon's TLS ``/v2/tools/call`` route."""
    probe = {
        "schema_digest": load_catalog().schema_digest,
        "tool": "get_health",
        "correlation_id": None,
        "selected_scope": None,
        "arguments": {"schema_version": "2.0", "deep": True, "idempotency_key": key},
    }
    return _post_operator(d.ready, env.ca_pem, "/v2/tools/call", env.cli_token, probe, 8.0)


def _ans(e: dict[str, Any]) -> tuple[Any, Any, Any]:
    return e.get("ok"), _data(e).get("doctor_run_id"), _data(e).get("job_id")


def _assert_refused(res: dict[str, Any], job_id: str, code: ErrorCode, label: str) -> None:
    assert _data(res).get("job_id") != job_id, f"{label}: returned job {job_id} without its payload hold: {_brief(res)}"
    err = cast(dict[str, Any], res.get("error") or {})
    assert res.get("ok") is False and err.get("code") == code.value, f"{label}: must fail with {code.value}: {res}"


def _settle_terminal(d: _Daemon, env: _Env, shape: str, *job_ids: str) -> None:
    assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
    for job_id in job_ids:
        state = _job_state(env, job_id)
        assert state is not None and state not in NON_TERMINAL, f"precondition: seeded job {job_id} is {state}"
    if shape == "run_and_job":
        assert _doctor_runs(env.root), "precondition: a store-wide DoctorRun exists"
    env.clock.advance(timedelta(minutes=16))


# ---------------------------------------------------------------------------
# R1: render refuses a job without a live payload hold (first call and replay, both shapes)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("how", sorted(_EXPECTED))
def test_r6_01_render_refuses_job_without_live_payload_hold(trusted_tmp: Path, shape: str, how: str) -> None:
    """A deep-health descriptor naming a job whose own payload hold was released, whose holder is tombstoned, or
    whose payload is quarantined is refused on replay over TLS and on a first call naming it, although the blob is
    still on disk; before the mutation the same key replayed with that job (control in the same test)."""
    env = _Env(trusted_tmp, f"r6-{how}-{shape}")
    job_id = _seed_job(env, _payload(f"{how}-{shape}"))
    key = f"idem_i4_r6_{how}_{shape}"
    with env.serve() as d:
        _settle_terminal(d, env, shape, job_id)
        first = _store_descriptor(d, env, shape, job_id, key)
        before = _health_tls(d, env, key)
        _mutate(env, job_id, how, d)
        replay = _health_tls(d, env, key)
        with _lookup_names(shape, job_id):
            fresh_first = _health_res(d, env, env.cli_token, f"{key}_new")

    assert _ans(before) == _ans(first), f"control: replay with the hold intact must be unchanged: {_brief(before)}"
    _assert_refused(replay, job_id, _EXPECTED[how], f"replay/{how}/{shape}")
    _assert_refused(fresh_first, job_id, _EXPECTED[how], f"first call/{how}/{shape}")


def test_r6_01_reviewer_repro_released_hold_refused_after_restart(trusted_tmp: Path) -> None:
    """The reviewer reproduction: a terminal store-wide job's job-only descriptor replays with the job while its
    hold is intact; with the daemon stopped its own ``cas.release`` is appended (``CAS.read`` still returns the
    bytes); after a restart the same key replayed over TLS is refused with ``integrity_failure``."""
    env = _Env(trusted_tmp, "r6-repro")
    job_id = _seed_job(env, _payload("repro"))
    key = "idem_i4_r6_repro"
    with env.serve() as d:
        _settle_terminal(d, env, "job_only", job_id)
        first = _store_descriptor(d, env, "job_only", job_id, key)
        before = _health_tls(d, env, key)
    assert _ans(before) == _ans(first), f"control: replay with the hold intact must be unchanged: {_brief(before)}"

    _mutate(env, job_id, "released")

    with env.serve() as d:
        assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        replay = _health_tls(d, env, key)

    _assert_refused(replay, job_id, ErrorCode.INTEGRITY_FAILURE, "replay after restart")


@pytest.mark.parametrize("shape", SHAPES)
def test_r6_01_render_refuses_released_job_even_when_digest_is_held_by_another_job(
    trusted_tmp: Path, shape: str
) -> None:
    """Two jobs share one payload digest; after job A's own hold is released, A's descriptor is refused with
    ``integrity_failure`` although job B still holds the same blob, and B's descriptor still replays unchanged."""
    env = _Env(trusted_tmp, f"r6-shared-{shape}")
    shared = _payload(f"shared-{shape}")
    job_a = _seed_job(env, shared)
    job_b = _seed_job(env, shared)
    assert _payload_digest(env, job_a) == _payload_digest(env, job_b), "precondition: shared payload digest"
    key_a, key_b = f"idem_i4_r6_shared_a_{shape}", f"idem_i4_r6_shared_b_{shape}"
    with env.serve() as d:
        _settle_terminal(d, env, shape, job_a, job_b)
        _store_descriptor(d, env, shape, job_a, key_a)
        first_b = _store_descriptor(d, env, shape, job_b, key_b)
        _mutate(env, job_a, "released", d)
        assert _payload_digest(env, job_b) in _job_holds(env, job_b), "precondition: job B still holds the blob"
        replay_b = _health_tls(d, env, key_b)
        replay_a = _health_tls(d, env, key_a)

    assert _ans(replay_b) == _ans(first_b), f"control: job B (hold intact) must replay unchanged: {_brief(replay_b)}"
    _assert_refused(replay_a, job_a, ErrorCode.INTEGRITY_FAILURE, f"shared/{shape}")


def test_r6_01_control_terminal_job_with_intact_hold_replays_unchanged_after_restart(trusted_tmp: Path) -> None:
    """Control: a terminal store-wide job whose own hold is intact replays with the same job id after a restart.

    Job-only descriptor: a restart bumps the writer epoch, which fences a run+job descriptor's run by design."""
    shape = "job_only"
    env = _Env(trusted_tmp, "r6-ctrl")
    job_id = _seed_job(env, _payload("ctrl"))
    key = "idem_i4_r6_ctrl_restart"
    with env.serve() as d:
        _settle_terminal(d, env, shape, job_id)
        first = _store_descriptor(d, env, shape, job_id, key)
    with env.serve() as d:
        assert d.loop.wait_doctor_settled(timeout=BOUND_WAIT_S)
        replay = _health_tls(d, env, key)
    assert _ans(replay) == _ans(first), f"control: replay changed: {_brief(first)} -> {_brief(replay)}"
    assert _data(replay).get("job_id") == job_id


# ---------------------------------------------------------------------------
# R2: the active-job lookup never treats a job without a live payload hold as the slot
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("how", ["released", "tombstoned", "intact"])
def test_r6_02_lookup_ignores_active_job_without_live_payload_hold(trusted_tmp: Path, how: str) -> None:
    """``find_active_doctor_job`` does not return (and does not raise for) an active store-wide job whose payload
    hold is released or tombstoned; with the hold intact it returns that job (control)."""
    env = _Env(trusted_tmp, f"r6-lookup-{how}")
    job_id = _seed_job(env, _payload(f"lookup-{how}"), retry_in=timedelta(days=2))
    if how != "intact":
        _mutate(env, job_id, how)
    with env.offline_rt() as rt:
        _svc, js = kernel_job_service(rt, env.clock)
        found = health_mod.find_active_doctor_job(rt, js, owner_id=OWNER_DAN, checkout_root=None)
    if how == "intact":
        assert found == job_id, f"control: the intact active job is the slot: {found}"
    else:
        assert found != job_id, f"lookup returned active job {job_id} whose payload hold is {how}"
        assert found is None, found


@pytest.mark.parametrize("how", ["released", "tombstoned", "intact"])
def test_r6_02_store_wide_enqueue_not_deduplicated_onto_job_without_live_payload_hold(
    trusted_tmp: Path, how: str
) -> None:
    """Real daemon: an active (not yet due) store-wide doctor job whose payload hold is released or tombstoned is
    neither returned by deep health nor joined by a store-wide operator report; with the hold intact both return
    that job and no duplicate store-wide job is enqueued (control)."""
    env = _Env(trusted_tmp, f"r6-dedup-{how}")
    job_id = _seed_job(env, _payload(f"dedup-{how}"), retry_in=timedelta(days=2))
    if how != "intact":
        _mutate(env, job_id, how)
    with env.serve() as d:
        health = _health_res(d, env, env.cli_token, f"idem_i4_r6_dedup_{how}")
        rep = _report(d, env, env.cli_token, wait_ms=0)
        jobs = _doctor_jobs(env.root)

    assert health.get("ok") is True, health
    assert rep.get("ok") is True, rep
    others = [j for j in jobs if j["job_id"] != job_id and j["owner_id"] == OWNER_DAN]
    if how == "intact":
        assert _data(health).get("job_id") == job_id, f"control: deep health joins the intact slot: {_brief(health)}"
        assert _data(rep).get("job_id") == job_id, f"control: report joins the intact slot: {_brief(rep)}"
        assert others == [], f"control: no duplicate store-wide job: {others}"
    else:
        assert _data(health).get("job_id") != job_id, f"deep health returned job {job_id} ({how}): {_brief(health)}"
        assert _data(rep).get("job_id") != job_id, f"report joined job {job_id} ({how}): {_brief(rep)}"
        assert others, f"no store-wide job was enqueued past job {job_id} ({how}): {jobs}"
