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

from pathlib import Path

import pytest

from superbrain.core.errors import ErrorCode
from superbrain.core.kernel import Endpoint
from superbrain.storage.layout import DataRoot
from tests.support.crash_cases import (
    KERNEL_CRASH_CASES,
    KernelCrashCase,
    KernelCrashContext,
    MarkedRun,
    assert_entered,
    run_kernel_case,
    run_t8_child,
    seed_daemon_root,
)
from tests.support.inc2_cli import get_shared_t7_transport_template, is_writer_lock_held
from tests.support.inc2_fixture import InstalledEnv

_DAEMON_CASES = [c for c in KERNEL_CRASH_CASES if c.operation == "serve"]  # startup crashpoints (8.1)
_MIGRATE_CASES = [c for c in KERNEL_CRASH_CASES if c.operation == "migrate"]
_BEFORE_COMMIT_CASES = [c for c in KERNEL_CRASH_CASES if c.crashpoint == "kernel.before_commit"]
_AFTER_COMMIT_CASES = [c for c in KERNEL_CRASH_CASES if c.crashpoint == "kernel.after_commit_before_response"]


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
