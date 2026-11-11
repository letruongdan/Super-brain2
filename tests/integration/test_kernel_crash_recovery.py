"""Kernel crash recovery through the installed wheel (SP1 increment 2, Task 8.1; spec rev22 sections 5.4-5.5).

Each ``KernelCrashCase`` (``tests/support/crash_cases.py``) seeds a data root, runs ``inc2_t8_child.py`` from the
wheel venv with ``SUPERBRAIN_CRASHPOINT`` set, requires ``CRASHPOINT_HIT <name>`` and exit 86 from that invocation,
then checks what the dead process left and recovers with the installed ``brain serve``, ``brain migrate --offline``
and ``brain-mcp``. Rows: ``docs/design/sp1-crash-table.md``, section "Kernel daemon và offline migrate".

- ``daemon.after_bind_before_endpoint`` / ``daemon.after_endpoint_publish``: both sides of endpoint publication. The
  ACKed store survives, every old endpoint tuple fails closed (also on a reused port), the next writer gets a new
  epoch and instance, and shallow ``get_health`` goes through the installed shim.
- ``kernel.migrate.after_policy_swap``: a (store 2, policy 3) mixed pair is refused by ``brain serve`` until an
  explicit ``brain migrate --offline`` resumes the store part; a repeat is a no-op and fires no hook.

The driver positive control shows the same driver serving normally without the fault env, and a second writer
fenced while the first is alive, so a missing hit is attributable to the product and not to the harness.
"""

from __future__ import annotations

import datetime as dt
import json
from dataclasses import replace
from functools import partial
from pathlib import Path

import pytest

from superbrain.core.errors import ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import Endpoint
from superbrain.ports.policy import IntentKind
from superbrain.storage.layout import DataRoot
from tests.support.crash_cases import (
    KERNEL_CRASH_CASES,
    T8_TASK_ID,
    KernelCrashCase,
    KernelCrashContext,
    MarkedRun,
    assert_entered,
    assert_t8_crashed,
    assert_wheel_provenance,
    error_code,
    ok_data,
    pair_rows,
    run_kernel_case,
    run_t8_child,
    seed_daemon_root,
    seed_fixture_root,
    shim_calls,
    store_rows,
    t8_prepare_args,
)
from tests.support.inc2_cli import get_shared_t7_transport_template, is_writer_lock_held
from tests.support.inc2_fixture import InstalledEnv
from tests.support.inc2_t8_domain import ART_ALLOWED
from tests.support.inc2_t8_job_cases import seed_job, seed_usage

_DAEMON_CASES = [c for c in KERNEL_CRASH_CASES if c.operation == "serve"]  # startup crashpoints (8.1)
_MIGRATE_CASES = [c for c in KERNEL_CRASH_CASES if c.operation == "migrate"]
_BEFORE_COMMIT_CASES = [c for c in KERNEL_CRASH_CASES if c.crashpoint == "kernel.before_commit"]
_AFTER_COMMIT_CASES = [c for c in KERNEL_CRASH_CASES if c.crashpoint == "kernel.after_commit_before_response"]
_JOB_CASES = [c for c in KERNEL_CRASH_CASES if c.crashpoint.startswith("jobs.")]
_CLAIM_CASES = [c for c in _JOB_CASES if c.operation == "serve-jobs"]


def _context(env: InstalledEnv, trusted_tmp: Path) -> KernelCrashContext:
    cwd = trusted_tmp / "outside-cwd"
    cwd.mkdir()
    return KernelCrashContext(env=env, template=get_shared_t7_transport_template(), case_dir=trusted_tmp, cwd=cwd)


@pytest.mark.parametrize("case", _DAEMON_CASES, ids=lambda c: c.node_id)
def test_daemon_crash_preserves_store_and_fences_old_endpoint(
    inc2_installed_env: InstalledEnv, trusted_tmp: Path, case: KernelCrashCase
) -> None:
    run_kernel_case(case, _context(inc2_installed_env, trusted_tmp))


@pytest.mark.parametrize("case", _MIGRATE_CASES, ids=lambda c: c.node_id)
def test_policy_swap_crash_requires_explicit_migration_resume(
    inc2_installed_env: InstalledEnv, trusted_tmp: Path, case: KernelCrashCase
) -> None:
    run_kernel_case(case, _context(inc2_installed_env, trusted_tmp))


@pytest.mark.parametrize("case", _BEFORE_COMMIT_CASES, ids=lambda c: c.node_id)
def test_crash_before_commit_leaves_no_effect_and_one_retry_applies(
    inc2_installed_env: InstalledEnv, trusted_tmp: Path, case: KernelCrashCase
) -> None:
    run_kernel_case(case, _context(inc2_installed_env, trusted_tmp))


@pytest.mark.parametrize("case", _AFTER_COMMIT_CASES, ids=lambda c: c.node_id)
def test_replay_after_response_loss_through_real_shim(
    inc2_installed_env: InstalledEnv, trusted_tmp: Path, case: KernelCrashCase
) -> None:
    run_kernel_case(case, _context(inc2_installed_env, trusted_tmp))


def test_t8_driver_serves_without_fault_env_and_fences_a_second_writer(
    inc2_installed_env: InstalledEnv, trusted_tmp: Path
) -> None:
    ctx = _context(inc2_installed_env, trusted_tmp)
    seed = seed_daemon_root(ctx)
    endpoint_path = DataRoot.at(seed.data_root).endpoint_path
    second: list[MarkedRun] = []

    def while_ready(ready: Endpoint) -> None:
        assert (ready.store_id, ready.writer_epoch) == (seed.store_id, seed.epoch + 1)
        assert endpoint_path.read_bytes() == ready.encode_canonical()
        assert is_writer_lock_held(seed.data_root) is True
        second.append(run_t8_child(ctx.env, "serve", seed.config, cwd=ctx.cwd))

    first = run_t8_child(ctx.env, "serve", seed.config, cwd=ctx.cwd, while_ready=while_ready)
    assert first.ready is not None and first.result.hit is None and not first.timed_out, first.describe()
    assert first.result.returncode == 0 and first.result.stdout == "" and first.owner_stderr == (), first.describe()
    assert_entered(first)

    (fenced,) = second
    assert (fenced.result.returncode, fenced.result.error_code) == (1, ErrorCode.WRITER_HELD.value), fenced.describe()
    assert fenced.ready is None and fenced.result.hit is None and fenced.result.stdout == "", fenced.describe()
    assert_entered(fenced)
    assert not endpoint_path.exists() and is_writer_lock_held(seed.data_root) is False


@pytest.mark.parametrize("case", _JOB_CASES, ids=lambda c: c.node_id)
def test_job_crash_recovers_the_exact_durable_state(
    inc2_installed_env: InstalledEnv, trusted_tmp: Path, case: KernelCrashCase
) -> None:
    run_kernel_case(case, _context(inc2_installed_env, trusted_tmp))


@pytest.mark.parametrize("case", _CLAIM_CASES, ids=lambda c: c.node_id)
def test_attempt_three_dead_letters_after_claim_crash(
    inc2_installed_env: InstalledEnv, trusted_tmp: Path, case: KernelCrashCase
) -> None:
    run_kernel_case(replace(case, seed=partial(seed_job, attempt=3)), _context(inc2_installed_env, trusted_tmp))


def test_incomplete_usage_crash_preserves_unknown_and_identical_retry_is_noop(
    inc2_installed_env: InstalledEnv, trusted_tmp: Path
) -> None:
    (case,) = (c for c in _JOB_CASES if c.crashpoint == "jobs.after_usage_settle_commit")
    run_kernel_case(replace(case, seed=partial(seed_usage, complete=False)), _context(inc2_installed_env, trusted_tmp))


def test_lease_crash_hook_ignores_empty_and_guarded_polls(
    inc2_installed_env: InstalledEnv, trusted_tmp: Path
) -> None:
    ctx = _context(inc2_installed_env, trusted_tmp)
    for mode, due in (("empty-poll", False), ("guarded-poll", True)):
        subdir = ctx.case_dir / mode
        subdir.mkdir()
        case = replace(ctx, case_dir=subdir)
        seed = seed_job(case, enqueue=due)
        run = run_t8_child(
            ctx.env, "job-operation", seed.config, cwd=ctx.cwd, crashpoint="jobs.after_lease", args=(mode,),
        )
        assert_entered(run)
        assert_wheel_provenance(run, ctx)
        assert run.result.returncode == 0 and run.result.hit is None, run.describe()
        assert f"JOB_RETURNED {mode}" in run.result.stderr, run.describe()
        assert store_rows(seed.data_root, subdir / "jobs-read") == seed.snapshot


def test_revoke_intent_crash_reconciles_once_and_refuses_before_replay_or_ref_read(
    inc2_installed_env: InstalledEnv, trusted_tmp: Path
) -> None:
    """Exercise the existing policy crashpoint on the OwnerLoop credential-revoke path."""
    ctx = _context(inc2_installed_env, trusted_tmp)
    seed = seed_fixture_root(ctx)
    active, revoked = ctx.template.cred, ctx.template.cred_b
    assert revoked is not None and revoked.principal == active.principal and ctx.template.ws_a is not None
    prep = t8_prepare_args()
    artifact: dict[str, JsonValue] = {
        "schema_version": "2.0", "workspace_id": ctx.template.ws_a.repo_id, "task_id": T8_TASK_ID,
        "artifact_id": ART_ALLOWED, "revision": 1, "level": "L1", "idempotency_key": "idem-t8-revoke-artifact-01",
    }
    original: list[dict[str, JsonValue]] = []

    def write_acked(_ready: Endpoint) -> None:
        original.extend(
            shim_calls(ctx, seed, "acked", revoked.token, [("prepare_task", prep), ("get_artifact", artifact)])
        )

    serving = run_t8_child(ctx.env, "serve-fixture", seed.config, cwd=ctx.cwd, while_ready=write_acked)
    assert serving.ready is not None and serving.result.returncode == 0, serving.describe()
    delivery, served_artifact = (ok_data(result) for result in original)
    assert served_artifact["resources"] and delivery["assignment_id"] is not None
    scratch = ctx.case_dir / "revoke-read"
    acked = pair_rows(seed.data_root, scratch)
    ((generation,),) = acked["trust"]
    intent_id = new_id()
    expires = (dt.datetime.now(dt.UTC) + dt.timedelta(hours=2)).isoformat()
    args = (revoked.credential_id, revoked.principal.owner_id, str(generation), intent_id, expires)

    def revoke() -> MarkedRun:
        return run_t8_child(
            ctx.env, "revoke-fixture", seed.config, cwd=ctx.cwd, crashpoint="policy.after_intent_commit", args=args,
        )

    crash = revoke()
    assert_t8_crashed(crash, "policy.after_intent_commit")
    assert_wheel_provenance(crash, ctx)
    assert crash.result.stderr.index(f"REVOKE_CALL {intent_id}") < crash.result.stderr.index("CRASHPOINT_HIT ")
    after_crash = pair_rows(seed.data_root, scratch)
    assert after_crash["ledger"] == acked["ledger"] and after_crash["applied_intents"] == acked["applied_intents"]
    (intent,) = [row for row in after_crash["intents"] if row not in acked["intents"]]
    assert intent[:2] == (intent_id, IntentKind.CREDENTIAL_REVOKE.value)
    assert isinstance(intent[2], bytes | str)
    assert json.loads(intent[2]) == {
        "credential_id": revoked.credential_id, "principal_id": revoked.principal.principal_id,
        "owner_id": revoked.principal.owner_id,
    }
    assert [row[-1] for row in after_crash["credential"] if row[0] == revoked.credential_id] == [intent_id]

    def check_auth(_ready: Endpoint) -> None:
        direct = artifact | {"idempotency_key": "idem-t8-revoke-fresh-artifact-02"}
        refusals = shim_calls(ctx, seed, "revoked", revoked.token, [("prepare_task", prep), ("get_artifact", direct)])
        assert [error_code(result) for result in refusals] == [ErrorCode.UNAUTHENTICATED.value] * 2
        replay, allowed = (
            ok_data(result) for result in
            shim_calls(ctx, seed, "active", active.token, [("prepare_task", prep), ("get_artifact", artifact)])
        )
        assert (replay["delivery_id"], replay["assignment_id"]) == (delivery["delivery_id"], delivery["assignment_id"])
        assert allowed["resources"] == served_artifact["resources"]

    recovered = run_t8_child(ctx.env, "serve-fixture", seed.config, cwd=ctx.cwd, while_ready=check_auth)
    assert recovered.ready is not None and recovered.result.returncode == 0, recovered.describe()
    projected = pair_rows(seed.data_root, scratch)
    assert projected["intents"] == after_crash["intents"]
    assert projected["ledger"][:len(acked["ledger"])] == acked["ledger"]
    ((seq, _, kind),) = projected["ledger"][len(acked["ledger"]):]
    assert kind == "policy.credential_revoke"
    # The marker binds the ledger high-water before the one reconciliation event is appended.
    high_water = max(int(str(row[0])) for row in acked["ledger"])
    assert seq == high_water + 1
    assert set(projected["applied_intents"]) - set(acked["applied_intents"]) == {(intent_id, high_water)}

    # A second daemon startup reconciles the same root, then retries the same owner authorization with the hook on.
    retry = revoke()
    assert_entered(retry)
    assert retry.result.returncode == 0 and retry.result.hit is None, retry.describe()
    assert f"REVOKE_RETURNED {intent_id}" in retry.result.stderr, retry.describe()
    assert pair_rows(seed.data_root, scratch) == projected
