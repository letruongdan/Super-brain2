"""The default gate: one script for local runs and CI.

The gate checks out HEAD into a sealed git worktree, runs every required phase there with the interpreter
chosen by ``--python`` and writes a receipt that binds the source snapshot, the exact test inventory, a
terminal outcome for every test ID and the interpreter that actually ran. Nothing is "done" or "verified"
without an accepted receipt.

``build_receipt`` reuses ``superbrain.core.canonical`` (the package is installed editable), so the receipt
digests follow the same canonical-JSON rules as the rest of the code base.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import platform as host_platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid
import xml.etree.ElementTree as ET
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from contextvars import ContextVar
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock

from superbrain.adapters.os import environment as environment_facts
from superbrain.adapters.os.environment import EnvironmentFacts as EnvironmentFacts
from superbrain.adapters.os.environment import EnvironmentProbe as EnvironmentProbe
from superbrain.adapters.os.environment import OsEnvironmentProbe as OsEnvironmentProbe
from superbrain.adapters.os.environment import PathFacts as PathFacts
from superbrain.adapters.os.paths import default_data_root
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.jsonvalue import JsonValue

REQUIRED_PHASES = ("ruff", "mypy", "lint-imports", "pytest")
TERMINAL_OUTCOMES = {"passed", "failed", "error", "skipped", "xfailed", "xpassed"}
NON_FAILING = {"passed", "skipped", "xfailed"}
TEST_JOB_BUDGET_S = 300.0  # spec 17: interpreter preflight through the end of pytest
PREFLIGHT_TIMEOUT_S = 120.0
PHASE_TIMEOUTS_S = {"ruff": 120.0, "mypy": 300.0, "lint-imports": 120.0, "pytest": 300.0}
GIT_TIMEOUT_S = 120.0
SYNC_TIMEOUT_S = 600.0
COLLECT_TIMEOUT_S = 300.0
# An explicit local budget is a plan-recorded temporary threshold (acceptance policy); hosted workers keep the default.
MAX_TEST_JOB_BUDGET_S = 600.0
def default_pytest_shards(platform_name: str = sys.platform, cpu_count: int | None = None) -> int:
    """Return the platform default pytest shard count."""
    del platform_name
    cpus = max(1, (os.cpu_count() if cpu_count is None else cpu_count) or 1)
    return min(4, cpus)


PYTEST_SHARDS = default_pytest_shards()
KILL_GRACE_S = 30.0
KILL_HANG_MARKER = "<process did not exit after being killed; output lost>"

PREFLIGHT_CODE = (
    "import json, sys, superbrain; "
    "print(json.dumps({'executable': sys.executable, 'version': sys.version, "
    "'implementation': sys.implementation.name, 'package_file': superbrain.__file__}))"
)


@dataclass(frozen=True)
class SourceIdentity:
    commit: str
    tree_clean: bool
    tracked_digest: str
    lock_digest: str
    config_digest: str


@dataclass(frozen=True)
class PhaseResult:
    name: str
    exit_code: int | None  # None: timed out
    duration_s: float


@dataclass(frozen=True)
class InterpreterInfo:
    executable: str
    version: str
    implementation: str
    package_file: str


# --- acceptance environment (spec 4.3 owner policy of 2026-10-31, spec 5.9) ----------------------------

TRUSTED_TEST_ROOT = "trusted_test_root"
DEFAULT_DATA_ROOT = environment_facts.DATA_ROOT_ROLE


def acceptance_paths(env: Mapping[str, str], platform: str) -> dict[str, Path]:
    """The test trusted root (where ``tests/conftest.py::trusted_tmp`` and pytest's ``tmp_path`` live) and the data
    root the code defaults to (``SUPERBRAIN_HOME`` honoured)."""
    if platform == "win32":
        trusted = Path(env["LOCALAPPDATA"]) / "superbrain-tests"
    else:
        trusted = Path(next((env[name] for name in ("TMPDIR", "TEMP", "TMP") if env.get(name)), "/tmp"))
    return {TRUSTED_TEST_ROOT: trusted, DEFAULT_DATA_ROOT: Path(default_data_root(env, platform))}


def collect_environment(probe: EnvironmentProbe, *, env: Mapping[str, str], platform: str) -> EnvironmentFacts:
    """The token facts and, for each ``acceptance_paths`` role, the physical path and its ancestor check."""
    return environment_facts.collect(probe, acceptance_paths(env, platform), platform)


def assess_environment(facts: EnvironmentFacts) -> dict[str, JsonValue]:
    """The receipt's ``environment`` section: the facts, every problem found, and ``accepted`` (no problem)."""
    return environment_facts.assess(facts, required=(TRUSTED_TEST_ROOT, DEFAULT_DATA_ROOT))


# --- receipt ------------------------------------------------------------------------------------------


def _under(path: str, parent: Path) -> bool:
    try:
        return Path(path).resolve().is_relative_to(parent.resolve())
    except (OSError, ValueError):
        return False


def build_receipt(
    *,
    start: SourceIdentity | None,
    end: SourceIdentity | None,
    phases: Sequence[PhaseResult],
    collected_ids: Sequence[str],
    junit_ids: Sequence[str],
    junit_outcomes: Mapping[str, str],
    python: str,
    implementation: str,
    platform: str,
    interpreter: InterpreterInfo | None,
    worktree: str,
    requested_python: str,
    test_job_seconds: float | None,
    time_budget_s: float = TEST_JOB_BUDGET_S,
    cleanup_error: str | None = None,
    extra_reasons: Sequence[str] = (),
    environment: Mapping[str, JsonValue] | None = None,
) -> dict[str, JsonValue]:
    """Judge a run. The interpreter binding is mandatory: ``interpreter=None`` means the preflight failed.

    ``environment`` is the ``assess_environment`` section; each of its problems is a reason.
    ``test_job_seconds`` is the aggregate from just before the interpreter preflight to the end of pytest; ``None``
    (not measured), a non-finite or negative value, or one at or above ``time_budget_s`` is refused.
    ``start``/``end`` are ``None`` when the source identity could not be read: the source is unverified.
    """
    reasons: list[str] = list(extra_reasons)
    if environment is not None:
        problems = environment.get("problems")
        if not isinstance(problems, list):
            reasons.append("environment: the section has no problem list")
        else:
            reasons.extend(f"environment: {problem}" for problem in problems)
    if start is None:
        reasons.append("source identity could not be read at start: the source is unverified")
    if end is None:
        reasons.append("source identity could not be read at end: the source is unverified")
    if start is not None and end is not None and start != end:
        reasons.append("source identity changed between start and end of the run")
    if start is not None and not start.tree_clean:
        reasons.append("working tree was not clean at start")
    if end is not None and not end.tree_clean:
        reasons.append("working tree was not clean at end")
    is_number = isinstance(test_job_seconds, (int, float)) and not isinstance(test_job_seconds, bool)
    job_s = test_job_seconds if is_number else None
    if job_s is None or not math.isfinite(job_s) or job_s < 0:
        reasons.append(f"the test-job time {test_job_seconds!r} is not a measured, finite, non-negative value")
        job_s = None
    elif job_s >= time_budget_s:
        reasons.append(f"the test job took {job_s:.3f}s, at or over the {time_budget_s:.1f}s aggregate budget")

    names = [p.name for p in phases]
    if sorted(names) != sorted(REQUIRED_PHASES):
        reasons.append(f"phases {sorted(names)} are not exactly the required {sorted(REQUIRED_PHASES)}")
    for phase in phases:
        if phase.exit_code is None:
            reasons.append(f"phase {phase.name} timed out")
        elif phase.exit_code != 0:
            reasons.append(f"phase {phase.name} exited with {phase.exit_code}")
        if phase.name == "pytest" and phase.duration_s > time_budget_s:
            reasons.append(f"pytest took {phase.duration_s:.1f}s, over the {time_budget_s:.1f}s budget")

    if not collected_ids:
        reasons.append("the test inventory is empty")
    if len(set(collected_ids)) != len(collected_ids):
        reasons.append("collected test IDs contain duplicates")
    if sorted(collected_ids) != sorted(junit_ids):
        reasons.append("JUnit test IDs do not match the collected inventory")
    if set(junit_outcomes) != set(collected_ids):
        missing = sorted(set(collected_ids) - set(junit_outcomes))
        extra = sorted(set(junit_outcomes) - set(collected_ids))
        reasons.append(f"outcome keys differ from the inventory (missing {missing[:5]}, unexpected {extra[:5]})")
    unknown = sorted({v for v in junit_outcomes.values() if v not in TERMINAL_OUTCOMES})
    if unknown:
        reasons.append(f"non-terminal outcome values: {unknown}")
    bad = sorted(i for i, v in junit_outcomes.items() if v in TERMINAL_OUTCOMES and v not in NON_FAILING)
    if bad:
        reasons.append(f"{len(bad)} tests did not pass, first: {bad[:5]}")

    counted = Counter(v for v in junit_outcomes.values() if v in TERMINAL_OUTCOMES)
    counts: dict[str, JsonValue] = {name: counted.get(name, 0) for name in sorted(TERMINAL_OUTCOMES)}
    if sum(counted.values()) != len(collected_ids):
        reasons.append(f"outcome counts sum to {sum(counted.values())}, inventory has {len(collected_ids)}")

    if interpreter is None:
        reasons.append("the interpreter preflight did not produce a result")
    else:
        if not _under(interpreter.package_file, Path(worktree) / "src"):
            reasons.append(f"superbrain was imported from {interpreter.package_file}, outside the sealed worktree")
        if not re.match(re.escape(requested_python) + r"(?![0-9])", interpreter.version):
            reasons.append(f"interpreter {interpreter.version!r} does not match --python {requested_python}")
    if cleanup_error is not None:
        reasons.append(f"sealed worktree was not removed: {cleanup_error}")

    return {
        "start": asdict(start) if start is not None else None,
        "end": asdict(end) if end is not None else None,
        "test_job_seconds": job_s,
        "time_budget_s": time_budget_s,
        "test_inventory_digest": digest_bytes(canonical_json(sorted(collected_ids))),
        "junit_inventory_digest": digest_bytes(canonical_json(sorted(junit_ids))),
        "test_count": len(collected_ids),
        "counts": counts,
        "outcomes": {node: str(value) for node, value in sorted(junit_outcomes.items())},
        "phases": [asdict(p) for p in phases],
        "python": python,
        "implementation": implementation,
        "platform": platform,
        "interpreter": asdict(interpreter) if interpreter is not None else None,
        "requested_python": requested_python,
        "environment": dict(environment) if environment is not None else None,
        "accepted": not reasons,
        "reasons": list(reasons),
    }


# --- pytest output ------------------------------------------------------------------------------------

_COLLECTED_SUMMARY = re.compile(r"^(\d+) tests? collected\b")
_NODE_ID = re.compile(r"^[^\s:][^:]*::\S.*$")


def parse_collected(text: str) -> list[str]:
    """Node-ID lines of ``pytest --collect-only -q``; the count in the summary line must agree."""
    ids: list[str] = []
    expected: int | None = None
    for line in text.splitlines():
        line = line.rstrip()
        match = _COLLECTED_SUMMARY.match(line)
        if match:
            expected = int(match.group(1))
        elif _NODE_ID.match(line):
            ids.append(line)
    if len(set(ids)) != len(ids):
        raise ValueError("pytest collected duplicate node IDs")
    if expected is not None and expected != len(ids):
        raise ValueError(f"pytest reports {expected} collected tests but {len(ids)} node IDs were parsed")
    return ids


# Tests asserting wall-clock product deadlines (hook 2 s cap, request budgets, short doctor periods). Parallel
# shards deselect them and one serial pytest runs them after the shards, inside the same test-job deadline, so a
# loaded machine cannot fail them by contention. Deadlines and assertions in the tests stay unchanged.
SERIAL_NODE_PREFIXES: tuple[str, ...] = (
    "tests/integration/test_hook_deadline_gap.py",
    "tests/integration/test_sp2_5_production_wiring.py::test_p1_finding2_bootstrap_and_installed_hook_adapters_end_to_end",
    "tests/integration/test_sp2_5_production_wiring.py::test_r5_finding1_observed_host_payloads_consecutive_retry_and_ws_switch",
    "tests/integration/test_sp2_5_production_wiring.py::test_r6_finding1_hook_binding_survives_pre_and_post_publish_crashes_and_post_ack_retry",
    "tests/integration/test_i4_a1_a2_job_lifecycle.py::test_p2_12_",
    "tests/integration/test_kernel_crash_recovery.py::test_crash_before_commit_leaves_no_effect_and_one_retry_applies",
    "tests/integration/test_doctor_sp2_probes.py::test_m1_incomplete_journal_drift_permissions_deep_health_and_cross_owner_checkout_isolation",
)


def split_serial(collected_ids: Sequence[str]) -> tuple[list[str], list[str]]:
    """``(parallel_ids, serial_ids)``: node IDs under ``SERIAL_NODE_PREFIXES`` run in the serial phase."""
    serial = [nid for nid in collected_ids if nid.startswith(SERIAL_NODE_PREFIXES)]
    chosen = set(serial)
    return [nid for nid in collected_ids if nid not in chosen], serial


_WHEEL_SETUP_COST_MS = 3_000
_DEFAULT_CASE_COST_MS = 20
_WHEEL_FIXTURE_FILES: frozenset[str] = frozenset(
    {
        "tests/contract/test_mcp_v2_schema.py",
        "tests/integration/test_apply_journal_crash_matrix.py",
        "tests/integration/test_capture_ack_and_crash_matrix.py",
        "tests/integration/test_doctor_cli.py",
        "tests/integration/test_doctor_fix.py",
        "tests/integration/test_i3_wheel_e2e.py",
        "tests/integration/test_kernel_cli.py",
        "tests/integration/test_kernel_crash_recovery.py",
        "tests/integration/test_kernel_native_receipt_contract.py",
        "tests/integration/test_kernel_privacy_persistence.py",
        "tests/integration/test_kernel_receipts.py",
        "tests/integration/test_kernel_shim.py",
        "tests/integration/test_sp2_i2_wheel_compat.py",
        "tests/integration/test_restore_and_migration_i3.py",
        "tests/integration/test_t9_benchmark_scratch.py",
    }
)
# Calibrated across all 181 collected test files using hosted windows-2022 CI measurements
# (run 44705523078 shard-0, baseline 035a4cd, and Azure 2.43x storage scaling for new/updated storage modules)
# plus session wheel setup overhead across the two wheel shards. _WHEEL_SETUP_COST_MS=3000 and 300s budget intact.
# Recalibrated on 2026-11-25 from Python 3.14 and 3.11 Windows 6-shard diagnostic runs
# (diag-remediate-v11/py3.14 and py3.11 on commit 4ce42af) across all 194 collected test files.
# Integration with main (SP1-I4): its doctor/I4 files keep main's measured weights.
_HEAVY_FILE_COST_MS: dict[str, int] = {
    "tests/integration/test_kernel_crash_recovery.py": 70022,
    "tests/integration/test_apply_journal_crash_matrix.py": 63762,
    "tests/integration/test_kernel_daemon.py": 48682,
    "tests/integration/test_kernel_native_receipt_contract.py": 44594,
    "tests/integration/test_i3_rereview_init_and_accounting.py": 39926,
    "tests/integration/test_sp2_i2_wheel_compat.py": 38145,
    "tests/integration/test_i3_wheel_e2e.py": 36243,
    "tests/application/test_continuity_worker_scheduling.py": 34942,
    "tests/storage/test_kernel_revocation.py": 30970,
    "tests/integration/test_capture_ack_and_crash_matrix.py": 24254,
    "tests/architecture/test_gate_receipt.py": 23730,
    "tests/storage/test_restore.py": 20921,
    "tests/integration/test_kernel_cli.py": 20442,
    "tests/integration/test_restore_and_migration_i3.py": 19335,
    "tests/domain/test_capture_envelope_and_privacy.py": 18810,
    "tests/storage/test_kernel_migration.py": 18305,
    "tests/storage/test_crash_matrix.py": 18197,
    "tests/integration/test_i3_rereview_bootstrap_and_handoff.py": 16662,
    "tests/integration/test_kernel_shim.py": 16085,
    "tests/storage/test_backup.py": 15496,
    "tests/storage/test_runtime.py": 15372,
    "tests/storage/test_remediation_i2_t5.py": 14356,
    "tests/integration/test_kernel_receipts.py": 13584,
    "tests/application/test_t8_review_p01_r2_edge_globs.py": 13448,
    "tests/integration/test_t9_signal_stop_conversion.py": 13198,
    "tests/storage/test_ledger.py": 12102,
    "tests/application/test_t8_review_p01_wrapped_paths.py": 11747,
    "tests/storage/test_remediation_i2_t3_lineage.py": 11725,
    "tests/integration/test_kernel_transport.py": 11442,
    "tests/integration/test_sp2_daemon_leased_attempt_retry.py": 11260,
    "tests/integration/test_sp2_store_v7_shape_and_refs.py": 11182,
    "tests/storage/test_kernel_idempotency.py": 10279,
    "tests/storage/test_cas.py": 10172,
    "tests/integration/test_sp2_continuity_authority_read_errors.py": 9790,
    "tests/contract/test_mcp_v2_schema.py": 9698,
    "tests/application/test_kernel_send_attempts.py": 9316,
    "tests/integration/test_kernel_privacy_persistence.py": 9274,
    "tests/storage/test_outbox_durability_and_limits.py": 9017,
    "tests/storage/test_recovery_grant_and_turn_intent.py": 8496,
    "tests/integration/test_sp2_store_v7_migration.py": 8225,
    "tests/storage/test_restore_epoch_and_expiry.py": 8163,
    "tests/application/test_i3_5_bootstrap_doctor_regressions.py": 7741,
    "tests/application/test_bootstrap_and_doctor.py": 7604,
    "tests/storage/test_kernel_workspaces.py": 7508,
    "tests/integration/test_t9_socket_readiness.py": 7497,
    "tests/storage/test_remediation_i2_os01.py": 7436,
    "tests/integration/test_kernel_performance.py": 7086,
    "tests/integration/test_cli_init_and_authority.py": 7053,
    "tests/storage/test_remediation_c02_r6_restore_marker.py": 6933,
    "tests/support/test_bounded_worker.py": 6764,
    "tests/integration/test_i2_close_01_canonical_compat.py": 6452,
    "tests/architecture/test_t9_ci_checkout_bytes.py": 6404,
    "tests/storage/test_migrate.py": 6054,
    "tests/integration/test_i3_1_review_regressions.py": 5984,
    "tests/storage/test_dual_store_session_binding.py": 5932,
    "tests/storage/test_writer.py": 5766,
    "tests/application/test_t8_review_p01_r3_spellings.py": 5317,
    "tests/integration/test_apply_journal_e2e.py": 5046,
    "tests/adapters/test_durable.py": 4994,
    "tests/storage/test_kernel_identity.py": 4919,
    "tests/storage/test_policy_accounting.py": 4770,
    "tests/storage/test_remediation_i2_t3_mirror_history.py": 4754,
    "tests/architecture/test_remediation_c06_gate_xpass.py": 4656,
    "tests/storage/test_kernel_jobs.py": 4583,
    "tests/integration/test_i2_close_01_transport_stdio.py": 4581,
    "tests/application/test_i3_3_review_regressions.py": 4437,
    "tests/integration/test_i2_close_01_wire_replay.py": 4232,
    "tests/cli_api/test_schema_digest_handshake.py": 4197,
    "tests/storage/test_policy_store.py": 4027,
    "tests/application/test_kernel_job_worker.py": 3966,
    "tests/architecture/test_imports.py": 3915,
    "tests/storage/test_remediation_i2_t4a.py": 3839,
    "tests/storage/test_remediation_c01_wal_admission.py": 3684,
    "tests/application/test_kernel_deadlines.py": 3666,
    "tests/integration/test_review_apply_cli_and_operator.py": 3617,
    "tests/support/test_crash_harness.py": 3600,
    "tests/application/test_i3_2_journal_regressions.py": 3540,
    "tests/application/test_i3_2_rollback_and_schema_regressions.py": 3513,
    "tests/integration/test_kernel_serve_signal_lifecycle.py": 3217,
    "tests/integration/test_i3_4_restore_regressions.py": 3193,
    "tests/storage/test_reconcile.py": 3111,
    "tests/application/test_t8_review_p01_n04_short_spellings.py": 3033,
    "tests/storage/test_i3_4_storage_regressions.py": 2978,
    "tests/architecture/test_t8_review_w02_canonical_payload_source.py": 2919,
    "tests/application/test_t8_review_p01_n01_linear.py": 2873,
    "tests/storage/test_remediation_c04_r8_backup_files.py": 2808,
    "tests/storage/test_remediation_c02_lost_main_db.py": 2751,
    "tests/adapters/test_client_profile.py": 2708,
    "tests/storage/test_swap.py": 2654,
    "tests/integration/test_t9_signal_stop_guard.py": 2589,
    "tests/integration/test_t9_r22_stop_completion.py": 2570,
    "tests/application/test_remediation_i2_t4bc.py": 2535,
    "tests/cli_api/test_review_web.py": 2488,
    "tests/application/test_change_proposal_and_journal.py": 2465,
    "tests/storage/test_signer_and_layer2_authority.py": 2424,
    "tests/application/test_t8_review_p01_r4_oracle_fixes.py": 2390,
    "tests/integration/test_t9_benchmark_scratch.py": 2375,
    "tests/architecture/test_remediation_c08_r13_unavailable_drive.py": 2282,
    "tests/storage/test_remediation_c04_cas_shard_boundary.py": 2131,
    "tests/application/test_kernel_daemon_worker.py": 2094,
    "tests/application/test_t8_review_p01_n03_r2_inner_literals.py": 2071,
    "tests/application/test_t8_closure_privacy_r2.py": 2067,
    "tests/storage/test_schema.py": 1903,
    "tests/architecture/test_remediation_i2_os01.py": 1829,
    "tests/application/test_t8_review_p01_n03_edge_cost.py": 1809,
    "tests/application/test_t8_review_p01_n01_r2_edges.py": 1775,
    "tests/integration/test_t9_startup_signal_latch.py": 1736,
    "tests/storage/test_remediation_c04_r9_imported_backup_ancestors.py": 1734,
    "tests/cli_api/test_t9_tcp_latency.py": 1732,
    "tests/storage/test_remediation_c04_r6_backup_container_perms.py": 1648,
    "tests/storage/test_remediation_c01_r4_reading_leftovers.py": 1647,
    "tests/application/test_t8_review_w02_private_large_blocks.py": 1626,
    "tests/support/test_inc2_process_cleanup.py": 1586,
    "tests/architecture/test_remediation_c08_r11_raw_path_admission.py": 1552,
    "tests/storage/test_remediation_c02_r8_restore_carryover.py": 1533,
    "tests/application/test_t8_closure_privacy.py": 1523,
    "tests/storage/test_t9_endpoint_casefold.py": 1458,
    "tests/storage/test_errors.py": 1457,
    "tests/storage/test_retention.py": 1445,
    "tests/application/test_t8_review_w01_private_equivalence.py": 1405,
    "tests/adapters/test_approval_verifiers.py": 1385,
    "tests/storage/test_remediation_i2_t5_residual.py": 1330,
    "tests/support/test_init_clone.py": 1314,
    "tests/integration/test_i3_2_operator_cli_regressions.py": 1308,
    "tests/storage/test_remediation_c04_r2_cas_siblings.py": 1283,
    "tests/integration/test_t9_client_sighting.py": 1252,
    "tests/storage/test_remediation_c01_r5_policy_wal_reader.py": 1252,
    "tests/storage/test_remediation_c05_r2_resync.py": 1252,
    "tests/application/test_t8_review_w01_canonical_reuse.py": 1251,
    "tests/cli_api/test_i3_5_review_web_regressions.py": 1206,
    "tests/application/test_remediation_i2_t5_worker.py": 1167,
    "tests/cli_api/test_loopback_client.py": 1148,
    "tests/storage/test_cas_gc.py": 1085,
    "tests/integration/test_t9_r21_shutdown_wait.py": 1014,
    "tests/application/test_i3_4_accounting_regressions.py": 938,
    "tests/storage/test_remediation_c05_shard_parent_sync.py": 934,
    "tests/core/test_faults.py": 859,
    "tests/application/test_i3_3_r3_regressions.py": 852,
    "tests/application/test_t8_privacy_performance_equivalence.py": 808,
    "tests/architecture/test_t9_ci_seal.py": 807,
    "tests/application/test_kernel_privacy.py": 753,
    "tests/application/test_operator_service_and_verifiers_r2.py": 750,
    "tests/adapters/test_physical_fs_and_no_replace.py": 705,
    "tests/storage/test_flush_routing.py": 676,
    "tests/mcp/test_stdio.py": 647,
    "tests/core/test_ids.py": 638,
    "tests/storage/test_remediation_c03_handler_downgrade.py": 616,
    "tests/cli_api/test_loopback_frames.py": 576,
    "tests/storage/test_remediation_c02_r4_intents_signal.py": 553,
    "tests/cli_api/test_t8_closure_wire.py": 538,
    "tests/storage/test_layout.py": 484,
    "tests/storage/test_i3_3_authority_regressions.py": 428,
    "tests/architecture/test_t9_gate_job_drain.py": 404,
    "tests/application/test_t8_closure_privacy_r2_gates.py": 403,
    "tests/architecture/test_remediation_c08_r8_root_links.py": 388,
    "tests/storage/test_remediation_c02_r7_live_marker.py": 378,
    "tests/architecture/test_t9_gate_environment_isolation.py": 339,
    "tests/architecture/test_remediation_c08_r4_preflight_failures.py": 323,
    "tests/storage/test_remediation_c04_r5_backup_cas_link.py": 304,
    "tests/architecture/test_remediation_c08_r6_root_itself.py": 294,
    "tests/storage/test_t9_reserved_sibling_casefold.py": 238,
    "tests/architecture/test_remediation_c08_r9_missing_root_linked_parent.py": 184,
    "tests/application/test_t9_privacy_non_retention.py": 151,
    "tests/integration/test_t9_libproc_client_pid.py": 138,
    "tests/adapters/test_permissions.py": 130,
    "tests/adapters/test_paths.py": 129,
    "tests/composition/test_client_scope.py": 126,
    "tests/architecture/test_remediation_c08_r2_real_probe.py": 119,
    "tests/application/test_t8_closure_privacy_r5_shapes.py": 108,
    "tests/architecture/test_remediation_c08_gate_environment.py": 107,
    "tests/adapters/test_i3_2_hygiene_regressions.py": 102,
    "tests/application/test_t8_review_r01_path_enforcement.py": 101,
    "tests/application/test_t8_closure_privacy_r5_paths.py": 98,
    "tests/integration/test_t8_closure_perf_probe_r5.py": 91,
    "tests/application/test_remediation_i2_t3_privacy.py": 83,
    "tests/storage/test_kinds.py": 80,
    "tests/integration/test_t9_process_sighting.py": 54,
    "tests/adapters/test_shared_config_mergers.py": 39,
    "tests/application/test_t8_closure_privacy_r4_literals.py": 35,
    "tests/core/test_canonical.py": 33,
    "tests/integration/test_t8_review_20261112_perf_replay.py": 28,
    "tests/application/test_t8_review_p02_rule_gates.py": 26,
    "tests/support/test_fs.py": 24,
    "tests/application/test_t8_closure_prequeue.py": 21,
    "tests/core/test_approval_message.py": 20,
    "tests/domain/test_exposure_and_worker_rules.py": 20,
    "tests/integration/test_t8_review_20261112_perf_attribution.py": 20,
    "tests/core/test_t8_closure_normalize.py": 18,
    "tests/application/test_t8_closure_privacy_r3_casefold.py": 16,
    "tests/application/test_kernel_lineage.py": 15,
    "tests/integration/test_t8_closure_perf_probe.py": 11,
    "tests/storage/test_t9_checkout_spelling.py": 11,
    "tests/application/test_t8_review_p02_r2_rule_discovery.py": 2,
    "tests/integration/test_t9_linux_scan_budget.py": 0,
    "tests/integration/test_handoff_lifecycle_and_takeover.py": 3560,
    "tests/storage/test_handoff_restore_and_epochs.py": 1860,
    "tests/domain/test_handoff_limits_and_budget.py": 100,
    "tests/integration/test_sp2_5_production_wiring.py": 120000,
    "tests/integration/test_capture_mcp_coexistence_r2.py": 2000,
    "tests/integration/test_capture_mcp_coexistence.py": 1800,
    "tests/storage/test_outbox_r9_ack_cursor_bounds.py": 1100,
    "tests/integration/test_layer2_invalidation.py": 900,
    "tests/storage/test_outbox_r8_migration_and_limits.py": 850,
    "tests/adapters/test_claude_and_codex_capture_adapters.py": 350,
    "tests/storage/test_outbox_r10_ack_durability.py": 1600,
    # SP1-I4 files merged from main (main's calibration, 2026-11-28 integration)
    "tests/integration/test_doctor_fix.py": 78365,
    "tests/integration/test_doctor_cli.py": 65325,
    "tests/integration/test_i4_r3_remediation.py": 43434,
    "tests/integration/test_i4_f4_f8_remediation.py": 39295,
    "tests/integration/test_i4_r5_legacy_job_replay.py": 25171,
    "tests/integration/test_i4_rereview_remediation.py": 20242,
    "tests/integration/test_i4_a1_a2_job_lifecycle.py": 62300,
    "tests/integration/test_i4_r6_maintenance_snapshot.py": 12000,
    "tests/integration/test_i4_r4_remediation.py": 20018,
    "tests/integration/test_doctor_sp2_probes.py": 18137,
    "tests/integration/test_i4_r6_job_payload_holder.py": 15548,
    "tests/integration/test_i4_r7_leased_payload_settlement.py": 13293,
    "tests/storage/test_doctor_snapshot.py": 12530,
    "tests/integration/test_doctor_jobs.py": 12410,
    "tests/integration/test_i4_r9_doctor_payload_fault_classification.py": 10786,
    "tests/integration/test_i4_r8_doctor_integrity_settle.py": 10567,
    "tests/integration/test_i4_review_remediation.py": 9195,
    "tests/integration/test_i4_owner_thread_remediation.py": 8307,
    "tests/integration/test_i4_r8_blob_verify_transient.py": 6942,
    "tests/integration/test_i4_r10_claim_reconciliation.py": 3512,
    "tests/integration/test_i4_vanished_entry_walk.py": 1350,
    "tests/integration/test_i4_r7_remediation.py": 1500,
    "tests/architecture/test_gate_time_budget.py": 142,
}


def _estimated_file_cost_ms(file: str, count: int) -> int:
    normalized = file.replace("\\", "/")
    if normalized in _HEAVY_FILE_COST_MS:
        return _HEAVY_FILE_COST_MS[normalized]
    return count * _DEFAULT_CASE_COST_MS


def _is_storage_file(path: str) -> bool:
    return path.replace("\\", "/").startswith("tests/storage/")


def _wheel_shard_count(wheel_total: int, non_wheel_total: int, size: int, wheel_file_count: int) -> int:
    """Minimum shard prefix needed so wheel suites do not exceed a single shard's fair share."""
    if size <= 1 or wheel_file_count <= 1:
        return 1
    single_shard_target = (wheel_total + non_wheel_total + _WHEEL_SETUP_COST_MS) // size
    if wheel_total + _WHEEL_SETUP_COST_MS <= single_shard_target:
        return 1
    needed = math.ceil((wheel_total + _WHEEL_SETUP_COST_MS) / max(1, single_shard_target))
    return min(size, wheel_file_count, max(1, needed))


def _order_bucket_for_io_stagger(shard_idx: int, group: list[str]) -> list[str]:
    """Order files within a shard to stagger heavy SQLite/fsync storage suites and wheel installs across shards."""
    wheel = sorted(f for f in group if f.replace("\\", "/") in _WHEEL_FIXTURE_FILES)
    non_wheel = [f for f in group if f.replace("\\", "/") not in _WHEEL_FIXTURE_FILES]
    non_storage = [f for f in non_wheel if not _is_storage_file(f)]
    storage = [f for f in non_wheel if _is_storage_file(f)]
    if shard_idx == 0:
        return [*wheel, *non_storage, *storage]
    if shard_idx == 1:
        return [*storage, *non_storage, *wheel]
    if shard_idx >= 3 and shard_idx % 2 == 1:
        if len(non_storage) >= 2:
            staggered_ns = [non_storage[1], non_storage[0], *reversed(non_storage[2:])]
        else:
            staggered_ns = list(non_storage)
        return [*staggered_ns, *storage, *wheel]
    return [*non_storage, *storage, *wheel]


TIMING_CONTRACT_PARALLEL_MAX = "parallel_max_per_worker_bounded_300s"
_PARTITION_SPEC = re.compile(r"^([0-9]+)/([0-9]+)$")


def parse_partition(spec: str) -> tuple[int, int]:
    """Parse ``'<index>/<count>'`` into ``(index, count)`` with ``0 <= index < count`` and ``count >= 1``."""
    match = _PARTITION_SPEC.fullmatch(spec.strip())
    if match is None:
        raise ValueError(f"partition must be '<index>/<count>', got {spec!r}")
    index, count = int(match.group(1)), int(match.group(2))
    if count < 1 or index < 0 or index >= count:
        raise ValueError(f"partition index {index} out of range for count {count}")
    return index, count


def partition_files(collected_ids: Sequence[str], partition: tuple[int, int]) -> list[str]:
    """Deterministically partition whole test files across ``count`` balanced buckets and return bucket ``index``."""
    index, count = partition
    if count < 1 or index < 0 or index >= count:
        raise ValueError(f"invalid partition {partition!r}")
    counts = Counter(node.split("::", 1)[0] for node in collected_ids)
    if not counts:
        return []
    if count == 1:
        return sorted(counts)
    buckets: list[list[str]] = [[] for _ in range(count)]
    loads = [0] * count
    wheel_items: list[tuple[int, str]] = []
    remaining: list[tuple[int, str]] = []
    for file, case_count in counts.items():
        cost = _estimated_file_cost_ms(file, case_count)
        if file.replace("\\", "/") in _WHEEL_FIXTURE_FILES:
            wheel_items.append((cost, file))
        else:
            remaining.append((cost, file))
    for cost, file in sorted(wheel_items, key=lambda item: (-item[0], item[1])):
        bucket_idx = min(range(count), key=lambda idx: (loads[idx], idx))
        buckets[bucket_idx].append(file)
        loads[bucket_idx] += cost
    for idx in range(count):
        if buckets[idx]:
            loads[idx] += _WHEEL_SETUP_COST_MS
    for cost, file in sorted(remaining, key=lambda item: (-item[0], item[1])):
        bucket_idx = min(range(count), key=lambda idx: (loads[idx], idx))
        buckets[bucket_idx].append(file)
        loads[bucket_idx] += cost
    return sorted(buckets[index])


def shard_files(collected_ids: Sequence[str], shards: int) -> list[list[str]]:
    """Group whole test files by estimated millisecond cost, placing wheel suites across the minimal shard prefix."""
    counts = Counter(node.split("::", 1)[0] for node in collected_ids)
    size = min(max(1, shards), len(counts))
    if size == 0:
        return []
    groups: list[list[str]] = [[] for _ in range(size)]
    loads = [0] * size
    wheel_items: list[tuple[int, str]] = []
    remaining: list[tuple[int, str]] = []
    for file, count in counts.items():
        cost = _estimated_file_cost_ms(file, count)
        if size > 1 and file.replace("\\", "/") in _WHEEL_FIXTURE_FILES:
            wheel_items.append((cost, file))
        else:
            remaining.append((cost, file))
    if wheel_items:
        wheel_shards = _wheel_shard_count(
            sum(cost for cost, _ in wheel_items),
            sum(cost for cost, _ in remaining),
            size,
            len(wheel_items),
        )
        for cost, file in sorted(wheel_items, key=lambda item: (-item[0], item[1])):
            index = min(range(wheel_shards), key=lambda idx: (loads[idx], idx))
            groups[index].append(file)
            loads[index] += cost
        for idx in range(wheel_shards):
            if groups[idx]:
                groups[idx].sort()
                loads[idx] += _WHEEL_SETUP_COST_MS
    # Balance non-wheel tests across all shards so wheel setup overhead stays evenly offset.
    for cost, file in sorted(remaining, key=lambda item: (-item[0], item[1])):
        index = min(range(size), key=lambda idx: (loads[idx], idx))
        groups[index].append(file)
        loads[index] += cost
    if size > 1:
        return [_order_bucket_for_io_stagger(idx, group) for idx, group in enumerate(groups) if group]
    return [group for group in groups if group]


def _split_classname(classname: str, root: Path | None) -> tuple[str, list[str]]:
    """Split a dotted JUnit ``classname`` into a module file path and its enclosing classes."""
    parts = classname.split(".")
    if root is not None:
        for i in range(len(parts), 0, -1):
            relative = "/".join(parts[:i]) + ".py"
            if (root / relative).is_file():
                return relative, parts[i:]
        raise ValueError(f"no module file under {root} matches JUnit classname {classname!r}")
    for i, part in enumerate(parts):
        if part.startswith("test_") or part.endswith("_test"):
            return "/".join(parts[: i + 1]) + ".py", parts[i + 1 :]
    return "/".join(parts) + ".py", []


def _outcome(case: ET.Element) -> str:
    kinds = {child.tag for child in case if child.tag in ("failure", "error", "skipped")}
    if "failure" in kinds:
        return "failed"
    if "error" in kinds:
        return "error"
    if "skipped" in kinds:
        skipped = case.find("skipped")
        kind = (skipped.get("type") if skipped is not None else None) or ""
        # pytest writes <skipped type="pytest.xfail"> for an expected failure and <skipped type="pytest.skip">
        # for a skip; anything else is reported as a (counted, visible) skip.
        return "xfailed" if kind == "pytest.xfail" else "skipped"
    return "passed"


_XPASS_PREFIX = "XPASS "
_FINAL_SUMMARY = re.compile(r"^=*\s*\d+ [a-z]+(, \d+ [a-z]+)* in [0-9.]+s\b")
_XPASSED = re.compile(r"\b(\d+) xpassed\b")


def parse_xpassed(text: str, ids: Iterable[str]) -> tuple[list[str], list[str]]:
    """The tests the ``-rX`` short summary of pytest's terminal output reports as XPASS, and any problem.

    A non-strict XPASS looks like a pass in JUnit (no child element), so the terminal summary is the evidence.
    Each ``XPASS <node id>[ - <reason>]`` line must name one of ``ids``, and their number must equal the
    ``N xpassed`` of pytest's final summary line.
    """
    known = sorted(set(ids), key=len, reverse=True)
    found: list[str] = []
    problems: list[str] = []
    final: str | None = None
    for line in text.splitlines():
        line = line.rstrip()
        if _FINAL_SUMMARY.match(line):
            final = line
        if not line.startswith(_XPASS_PREFIX):
            continue
        rest = line[len(_XPASS_PREFIX) :]
        match = next((i for i in known if rest == i or rest.startswith(f"{i} - ")), None)
        if match is None:
            problems.append(f"an XPASS line names no collected test: {rest[:200]}")
        else:
            found.append(match)
    counted = _XPASSED.search(final) if final is not None else None
    reported = int(counted.group(1)) if counted else 0
    lines = len(found) + len(problems)
    if reported != lines:
        problems.append(f"pytest reports {reported} xpassed but {lines} XPASS lines were found")
    return found, problems


def parse_junit(path: Path, *, root: Path | None = None) -> tuple[list[str], dict[str, str]]:
    """Map every JUnit testcase to its ``--collect-only -q`` node ID and terminal outcome.

    pytest writes ``classname`` as the dotted module path plus enclosing classes and ``name`` as the test
    function with its parametrization. ``root`` (the pytest rootdir) resolves the dotted path exactly, by
    finding the module file.
    """
    return _parse_junit(path.read_bytes(), root=root)


def _junit_nodeid(case: ET.Element, *, root: Path | None) -> str:
    classname = case.get("classname") or ""
    name = case.get("name") or ""
    file_attr = (case.get("file") or "").replace("\\", "/")
    if file_attr and classname:
        mod_dotted = file_attr.replace("/", ".")
        if classname == mod_dotted:
            return f"{file_attr}::{name}"
        if classname.startswith(mod_dotted + "."):
            classes = classname[len(mod_dotted) + 1 :].split(".")
            return "::".join([file_attr, *classes, name])
    if classname:
        module, classes = _split_classname(classname, root)
        return "::".join([module, *classes, name])
    return name


def _parse_junit(report: bytes, *, root: Path | None) -> tuple[list[str], dict[str, str]]:
    ids: list[str] = []
    outcomes: dict[str, str] = {}
    for case in ET.fromstring(report).iter("testcase"):
        node_id = _junit_nodeid(case, root=root)
        if node_id in outcomes:
            raise ValueError(f"duplicate testcase in JUnit report: {node_id}")
        ids.append(node_id)
        outcomes[node_id] = _outcome(case)
    return ids, outcomes


# --- running ------------------------------------------------------------------------------------------


def _clean_env() -> dict[str, str]:
    env = dict(os.environ)
    for name in ("VIRTUAL_ENV", "UV_PROJECT_ENVIRONMENT", "PYTHONPATH", "PYTHONHOME"):
        env.pop(name, None)
    if sys.platform == "win32":
        env["UV_LINK_MODE"] = "copy"  # Mapped DLL hardlinks prevent ephemeral checkout removal on Windows Server.
    return env


def _win32_assign_job(proc: subprocess.Popen[str]) -> int | None:
    """Assign a real Win32 Popen process to a kill-on-close Job Object; return handle or None."""
    if sys.platform != "win32":
        return None
    raw_handle = getattr(proc, "_handle", None)
    if isinstance(raw_handle, bool) or not isinstance(raw_handle, int) or raw_handle <= 0:
        return None
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    class _IoCounters(ctypes.Structure):
        _fields_ = [(n, ctypes.c_uint64) for n in ("r", "w", "o", "rb", "wb", "ob")]

    class _BasicLimit(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _ExtendedLimit(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _BasicLimit),
            ("IoInfo", _IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        return None
    info = _ExtendedLimit()
    info.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    if not kernel32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info)):
        kernel32.CloseHandle(job)
        return None
    if not kernel32.AssignProcessToJobObject(job, raw_handle):
        kernel32.CloseHandle(job)
        return None
    return int(job)


_WIN32_JOB_DRAIN_TIMEOUT_S = 1.0
_WIN32_MAX_JOB_PIDS = 16_384


def _win32_close_job(job: int | None, *, terminate: bool) -> None:
    """Reap owned job processes before releasing their mapped worktree images."""
    if job is None or sys.platform != "win32":
        return
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateJobObject.restype = wintypes.BOOL
    kernel32.QueryInformationJobObject.argtypes = [
        wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD, wintypes.LPVOID,
    ]
    kernel32.QueryInformationJobObject.restype = wintypes.BOOL
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    deadline = time.monotonic() + _WIN32_JOB_DRAIN_TIMEOUT_S
    handles: list[int] = []

    def process_ids() -> list[int]:
        capacity = 64
        while True:
            class ProcessList(ctypes.Structure):
                _fields_ = [
                    ("assigned", wintypes.DWORD),
                    ("count", wintypes.DWORD),
                    ("ids", ctypes.c_size_t * capacity),
                ]

            info = ProcessList()
            ctypes.set_last_error(0)
            ok = kernel32.QueryInformationJobObject(job, 3, ctypes.byref(info), ctypes.sizeof(info), None)
            error = ctypes.get_last_error()
            if not ok and error != 234:  # ERROR_MORE_DATA: retry the whole list, never truncate it.
                raise RuntimeError(f"Win32 job process query failed ({error})")
            if not ok or info.count < info.assigned:
                needed = max(capacity * 2, int(info.assigned))
                if needed > _WIN32_MAX_JOB_PIDS or time.monotonic() >= deadline:
                    raise RuntimeError("Win32 job process list exceeds the drain limit")
                capacity = needed
                continue
            if info.count > capacity or info.count != info.assigned:
                raise RuntimeError("Win32 job process list is incomplete")
            pids = [int(info.ids[index]) for index in range(info.count)]
            if any(pid <= 0 or pid > 0xFFFFFFFF for pid in pids) or len(pids) != len(set(pids)):
                raise RuntimeError("Win32 job process list is invalid")
            return pids

    terminated = False
    try:
        while True:
            pids = process_ids()
            if not pids:
                if terminate and not terminated and not kernel32.TerminateJobObject(job, 1):
                    raise RuntimeError("Win32 empty job termination failed")
                return
            batch: list[int] = []
            for pid in pids:
                if time.monotonic() >= deadline:
                    raise RuntimeError("Win32 job process drain timed out")
                ctypes.set_last_error(0)
                handle = kernel32.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE, no PID-based termination.
                if not handle:
                    error = ctypes.get_last_error()
                    if error == 87:  # ERROR_INVALID_PARAMETER: the listed process has already exited.
                        continue
                    raise RuntimeError(f"Win32 job process handle could not be opened ({error})")
                batch.append(int(handle))
                handles.append(int(handle))
            if not terminated:
                # Normal close already has KILL_ON_JOB_CLOSE semantics. Keep the handle open until drained.
                if not kernel32.TerminateJobObject(job, 1):
                    raise RuntimeError("Win32 job termination failed")
                terminated = True
            for handle in batch:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError("Win32 job process drain timed out")
                result = kernel32.WaitForSingleObject(handle, max(1, math.ceil(remaining * 1000)))
                if result != 0:  # WAIT_OBJECT_0 alone proves that image teardown completed.
                    raise RuntimeError(f"Win32 job process did not finish before teardown ({result})")
            if time.monotonic() >= deadline:
                raise RuntimeError("Win32 job process drain timed out")
    finally:
        close_failed = False
        for handle in handles:
            if not kernel32.CloseHandle(handle):
                close_failed = True
        if not kernel32.CloseHandle(job):
            close_failed = True
        if close_failed:
            raise RuntimeError("Win32 job drain handle cleanup failed")


def _kill_tree(proc: subprocess.Popen[str]) -> None:
    if sys.platform == "win32":
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True, check=False, timeout=60
        )
    else:
        import signal

        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    proc.kill()


_STEP_PID: ContextVar[int | None] = ContextVar("_STEP_PID", default=None)


class _ProcessCleanupError(RuntimeError):
    def __init__(self, message: str, *, output: str, seconds: float) -> None:
        super().__init__(message)
        self.output = output
        self.seconds = seconds


def run(cmd: Sequence[str], *, cwd: Path, timeout_s: float) -> tuple[int | None, str, float]:
    """Run ``cmd``; return ``(exit_code or None on timeout, combined output, seconds)``."""
    began = time.monotonic()
    proc = subprocess.Popen(
        list(cmd),
        cwd=cwd,
        env=_clean_env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        start_new_session=sys.platform != "win32",
    )
    job = _win32_assign_job(proc)
    _STEP_PID.set(proc.pid)
    timed_out = False
    output = ""
    try:
        output, _ = proc.communicate(timeout=timeout_s)
        return proc.returncode, output, time.monotonic() - began
    except subprocess.TimeoutExpired:
        timed_out = True
        kill_note = ""
        try:
            _kill_tree(proc)
        except (OSError, subprocess.SubprocessError) as err:  # still a timeout; never "could not start"
            kill_note = f"\n<killing the timed-out process tree failed: {type(err).__name__}: {err}>"
            try:
                proc.kill()
            except OSError:
                pass
        closing_job, job = job, None
        try:
            _win32_close_job(closing_job, terminate=True)
        except RuntimeError as err:  # retain the original timeout and captured subprocess output
            kill_note += f"\n<draining the timed-out process tree failed: {err}>"
        try:
            output, _ = proc.communicate(timeout=KILL_GRACE_S)
        except subprocess.TimeoutExpired:
            output = KILL_HANG_MARKER
        return None, (output or "") + kill_note, time.monotonic() - began
    finally:
        if job is not None:
            try:
                _win32_close_job(job, terminate=timed_out)
            except RuntimeError as err:
                raise _ProcessCleanupError(
                    str(err), output=output or "", seconds=time.monotonic() - began,
                ) from err


_TRANSIENT_CLEANUP_SLEEP_S: tuple[float, ...] = (0.02, 0.04, 0.06, 0.06)
_TRANSIENT_WINERRORS: frozenset[int] = frozenset({5, 32})


def _git(repo: Path, *args: str) -> str:
    code, output, _ = run(["git", "-C", str(repo), *args], cwd=repo, timeout_s=GIT_TIMEOUT_S)
    if code != 0:
        raise RuntimeError(f"git {' '.join(args)} failed ({code}): {output.strip()}")
    return output


def _worktree_identity(worktree: Path, allocator: Path) -> tuple[int, int]:
    """Return ``(st_dev, st_ino)`` if ``worktree`` is a physical non-reparse child of ``allocator``."""
    info = worktree.lstat()
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    if getattr(info, "st_file_attributes", 0) & reparse_flag:
        raise OSError(f"worktree is a Windows reparse point: {worktree}")
    if not stat.S_ISDIR(info.st_mode):
        raise OSError(f"worktree is not a directory: {worktree}")
    if worktree.parent != allocator or worktree.resolve(strict=True) != worktree:
        raise OSError(f"worktree escaped allocator {allocator}: {worktree}")
    return (info.st_dev, info.st_ino)


def _is_worktree_registered(repo: Path, worktree: Path) -> bool:
    """Return ``True`` if ``worktree`` is still registered (or listing cannot prove otherwise)."""
    output = _git(repo, "worktree", "list", "--porcelain", "-z")
    raw_paths = [field.removeprefix("worktree ") for field in output.split("\x00") if field.startswith("worktree ")]
    if not raw_paths:  # fail closed on empty/non-porcelain output (e.g. mocked runners)
        return True
    target_keys = {os.path.normcase(os.path.normpath(os.fspath(worktree)))}
    try:
        target_keys.add(os.path.normcase(os.path.normpath(os.fspath(worktree.resolve(strict=True)))))
    except OSError:
        pass
    for raw in raw_paths:
        entry = Path(raw)
        candidates = [entry]
        try:
            candidates.append(entry.resolve(strict=True))
        except OSError:
            pass
        for candidate in candidates:
            if os.path.normcase(os.path.normpath(os.fspath(candidate))) in target_keys:
                return True
    return False


def _is_transient_cleanup_error(err: OSError) -> bool:
    return isinstance(err, PermissionError) or getattr(err, "winerror", None) in _TRANSIENT_WINERRORS


def _remove_gate_worktree(
    repo: Path, worktree: Path, allocator: Path, worktree_id: tuple[int, int] | None
) -> None:
    """Remove only the original physical worktree directory owned by this gate attempt."""
    if not os.path.lexists(worktree):
        _git(repo, "worktree", "prune")
        return
    if worktree_id is None or _worktree_identity(worktree, allocator) != worktree_id:
        raise RuntimeError(f"refused to remove replaced or unverified worktree {worktree}")
    try:
        _git(repo, "worktree", "remove", "--force", str(worktree))
        return
    except RuntimeError as err:
        if not os.path.lexists(worktree):
            _git(repo, "worktree", "prune")
            return
        if _worktree_identity(worktree, allocator) != worktree_id:
            raise RuntimeError(f"refused fallback removal of replaced worktree {worktree}: {err}") from err
        if sys.platform != "win32" or _is_worktree_registered(repo, worktree):
            raise
        deadline = time.monotonic() + 0.18
        delays = iter(_TRANSIENT_CLEANUP_SLEEP_S)
        while True:
            if not os.path.lexists(worktree):
                _git(repo, "worktree", "prune")
                return
            if _worktree_identity(worktree, allocator) != worktree_id:
                raise RuntimeError(f"refused fallback removal of replaced worktree {worktree}: {err}") from err
            try:
                shutil.rmtree(worktree)
                return
            except OSError as rm_err:
                if not _is_transient_cleanup_error(rm_err):
                    raise RuntimeError(f"{err}; fallback rmtree failed: {rm_err}") from rm_err
                delay = next(delays, None)
                remaining = deadline - time.monotonic()
                if delay is None or remaining <= 0:
                    raise RuntimeError(f"{err}; fallback rmtree failed: {rm_err}") from rm_err
                time.sleep(min(delay, remaining))


def tree_is_clean(repo: Path) -> bool:
    return _git(repo, "status", "--porcelain", "--untracked-files=no").strip() == ""


def source_identity(repo: Path) -> SourceIdentity:
    return SourceIdentity(
        commit=_git(repo, "rev-parse", "HEAD").strip(),
        tree_clean=tree_is_clean(repo),
        tracked_digest=digest_bytes(_git(repo, "ls-files", "-s").encode("utf-8")),
        lock_digest=digest_bytes((repo / "uv.lock").read_bytes()),
        config_digest=digest_bytes((repo / "pyproject.toml").read_bytes()),
    )


def _uv(worktree: Path, python: str, *tool: str) -> list[str]:
    return ["uv", "run", "--locked", "--no-sync", "--project", str(worktree), "--python", python, *tool]


def receipt_name(receipt: Mapping[str, JsonValue]) -> str:
    start = receipt["start"]
    impl, version, platform = receipt["implementation"], receipt["python"], receipt["platform"]
    if not isinstance(start, dict):  # the source could not be read: never named after a commit
        return f"receipt-unverified-{impl}{version}-{platform}-{uuid.uuid4().hex[:12]}.json"
    commit = str(start["commit"])
    raw_lock = start.get("lock_digest") or start.get("tracked") or start.get("tree") or ("sha256:" + "0" * 64)
    lock = str(raw_lock)
    return f"receipt-{commit[:12]}-{impl}{version}-{platform}-{lock[7:19]}.json"


class _Evidence:
    """The artifacts of one attempt. Each file is written once and its digest enters the manifest; a write that
    fails becomes an error (a refusal reason), never a silent gap. Without an attempt dir nothing is written."""

    def __init__(self, root: Path | None) -> None:
        self.root = root
        self.manifest: dict[str, JsonValue] = {}
        self.errors: list[str] = []

    def write(self, rel: str, data: bytes) -> str | None:
        if self.root is None:
            return None
        try:
            path = self.root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        except OSError as err:
            self.errors.append(f"evidence: could not write {rel}: {type(err).__name__}: {err}")
            return None
        self.manifest[rel] = digest_bytes(data)
        return rel

    def write_receipt(self, receipt: dict[str, JsonValue]) -> str | None:
        """Write the terminal receipt last and atomically; returns an error or ``None``."""
        if self.root is None:
            return None
        try:
            tmp = self.root / f".receipt-{uuid.uuid4().hex[:8]}.tmp"
            tmp.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            os.replace(tmp, self.root / "receipt.json")
        except OSError as err:
            return f"evidence: could not write the terminal receipt: {type(err).__name__}: {err}"
        return None


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _host() -> dict[str, JsonValue]:
    return {
        "node": host_platform.node(),
        "system": host_platform.system(),
        "release": host_platform.release(),
        "version": host_platform.version(),
        "machine": host_platform.machine(),
        "platform": sys.platform,
    }


class EvidenceDirError(OSError):
    """The attempt dir under ``--evidence-dir`` could not be created: nothing has run yet."""


def run_gate(
    repo: Path,
    python: str,
    *,
    evidence_dir: Path | None = None,
    shards: int = PYTEST_SHARDS,
    partition: tuple[int, int] | None = None,
    time_budget_s: float = TEST_JOB_BUDGET_S,
) -> tuple[dict[str, JsonValue], str]:
    """Run the gate in a detached worktree of the resolved HEAD. Returns the receipt and a printable log.

    One monotonic deadline of ``time_budget_s`` (default ``TEST_JOB_BUDGET_S``) starts just before the interpreter
    preflight; collect and every phase get ``min(cap, remaining)`` and no step starts once it is spent. Collect and
    pytest are capped by the budget itself when it exceeds their default caps. Pytest shards partition the collected
    files under that same deadline. With ``evidence_dir`` every step's
    command, cwd, PID, start, exit, time and output, the raw JUnit report and the terminal receipt (written last)
    go into a new attempt dir under it, outside the worktree; only failing to create that dir raises
    (``EvidenceDirError``). Every other failure becomes a reason in a refused receipt.
    """
    began = time.monotonic()
    attempt_dir: Path | None = None
    if evidence_dir is not None:
        try:
            evidence_dir.mkdir(parents=True, exist_ok=True)
            attempt_dir = evidence_dir / f"attempt-{datetime.now(UTC):%Y%m%dT%H%M%S%fZ}-{uuid.uuid4().hex[:8]}"
            attempt_dir.mkdir()
        except OSError as err:
            raise EvidenceDirError(f"{type(err).__name__}: {err}") from err
    ev = _Evidence(attempt_dir)
    steps: list[JsonValue] = []
    record_lock = Lock()

    def step(name: str, cmd: list[str], cwd: Path, timeout_s: float) -> tuple[int | None, str, float, str | None]:
        """Run one command and record it; ``(exit or None, output, seconds, error)``. ``error`` says the step did not
        reach an exit code: "could not start: …" (no process) or "failed while running: …" (a process had started)."""
        _STEP_PID.set(None)
        started_at, error = _now(), None
        try:
            code, output, seconds = run(cmd, cwd=cwd, timeout_s=timeout_s)
        except Exception as err:  # noqa: BLE001 - recorded as a refusal reason, the attempt still ends in a receipt
            never_started = _STEP_PID.get() is None
            stage = "could not start" if never_started and isinstance(err, OSError) else "failed while running"
            code, output, seconds, error = None, "", 0.0, f"{stage}: {type(err).__name__}: {err}"
            if isinstance(err, _ProcessCleanupError):
                output, seconds = err.output, err.seconds
        with record_lock:
            rel = ev.write(f"steps/{len(steps):02d}-{name}.log", output.encode("utf-8", "replace"))
            steps.append({
                "name": name,
                "command": list(cmd),
                "cwd": str(cwd),
                "pid": _STEP_PID.get(),
                "started_at": started_at,
                "timeout_s": timeout_s,
                "exit_code": code,
                "duration_s": seconds,
                "output": rel,
                "error": error,
            })
        return code, output, seconds, error

    allocator = Path(tempfile.gettempdir()).resolve()
    worktree = allocator / f"superbrain-gate-{uuid.uuid4().hex[:12]}"
    extra: list[str] = []
    log: list[str] = []
    phases: list[PhaseResult] = []
    interpreter: InterpreterInfo | None = None
    collected: list[str] = []
    selected_files: list[str] = []
    target_ids: list[str] = []
    junit_ids: list[str] = []
    outcomes: dict[str, str] = {}
    start: SourceIdentity | None = None
    end: SourceIdentity | None = None
    resolved: str | None = None
    created = False
    worktree_id: tuple[int, int] | None = None
    cleanup_error: str | None = None
    junit = worktree.parent / f"{worktree.name}-junit.xml"
    junit_paths = [junit]
    pytest_output = ""
    environment: dict[str, JsonValue] | None = None
    job_began: float | None = None
    job_ended: float | None = None

    def read_report(
        path: Path, artifact: str, output: str, *, shard: str | None = None
    ) -> tuple[list[str], dict[str, str]]:
        label = "junit" if shard is None else f"junit {shard}"
        if not path.is_file():
            extra.append(f"{label}: pytest wrote no JUnit report")
            return [], {}
        report = path.read_bytes()
        ev.write(artifact, report)
        try:
            ids, observed = _parse_junit(report, root=worktree)
        except (ValueError, LookupError, ET.ParseError) as err:
            extra.append(f"{label}: the report could not be parsed: {err}")
            ids, observed = [], {}
        xpassed, problems = parse_xpassed(output, observed)
        prefix = "xpass" if shard is None else f"xpass {shard}"
        extra.extend(f"{prefix}: {problem}" for problem in problems)
        for node in xpassed:  # JUnit shows a non-strict XPASS as a pass; the terminal summary does not
            if observed[node] == "passed":
                observed[node] = "xpassed"
            else:
                extra.append(f"{prefix}: {node} is XPASS in the terminal but {observed[node]} in JUnit")
        return ids, observed

    def run_sharded_pytest(
        groups: list[list[str]], deadline: float, serial_ids: Sequence[str] = ()
    ) -> tuple[PhaseResult, float]:
        started = time.monotonic()
        parallel = len(groups)
        serial_args = sorted({p for p in SERIAL_NODE_PREFIXES if any(n.startswith(p) for n in serial_ids)})
        # shards deselect by prefix; the serial run names each node (pytest takes no partial node ID as a path)
        all_groups = [*groups, sorted(serial_ids)] if serial_args else list(groups)
        names = [f"pytest-shard-{i}" for i in range(parallel)] + (["pytest-serial"] if serial_args else [])
        paths = [junit.with_name(f"{junit.stem}-{name.removeprefix('pytest-')}.xml") for name in names]
        junit_paths.extend(paths)
        results: list[tuple[int | None, str, float, str | None] | None] = [None] * len(all_groups)
        serial_set = set(serial_ids)
        expected: list[set[str]] = [set() for _ in all_groups]
        for node in target_ids:
            if node in serial_set:
                expected[-1].add(node)
                continue
            file = node.split("::", 1)[0]
            expected[next(i for i in range(parallel) if file in groups[i])].add(node)

        def run_shard(index: int) -> None:
            timeout = min(max(PHASE_TIMEOUTS_S["pytest"], time_budget_s), deadline - time.monotonic())
            if timeout <= 0:
                return
            deselect = [] if index >= parallel else [
                f"--deselect={p}" for p in serial_args if p.split("::", 1)[0] in groups[index]
            ]
            cmd = _uv(worktree, python, "pytest", f"--junitxml={paths[index]}", "-q", "-rfEX", *deselect,
                      *all_groups[index])
            result = step(names[index], cmd, worktree, timeout)
            with record_lock:
                results[index] = result

        execution_failed = False
        try:
            with ThreadPoolExecutor(max_workers=parallel) as pool:
                for _ in pool.map(run_shard, range(parallel)):
                    pass
            if serial_args:  # alone, after every shard: no contention for the wall-clock deadline tests
                run_shard(parallel)
        except Exception as err:  # noqa: BLE001 - drained workers still have evidence to collect
            execution_failed = True
            extra.append(f"phase pytest shard launch or execution failed: {type(err).__name__}: {err}")
        ended = time.monotonic()
        codes: list[int | None] = []
        runner_error = execution_failed
        for index, result in enumerate(results):
            name = names[index]
            if result is None:
                reason = (
                    "shard execution failed"
                    if execution_failed
                    else f"the {time_budget_s:.0f}s test-job budget was spent"
                )
                extra.append(f"phase {name} not started: {reason}")
                codes.append(None)
                continue
            code, output, _, error = result
            codes.append(code)
            if error is not None:
                runner_error = True
                extra.append(f"phase {name} {error}")
            elif code is None:
                extra.append(f"phase {name} timed out")
            elif code != 0:
                extra.append(f"phase {name} exited with {code}")
            if KILL_HANG_MARKER in output:
                extra.append(f"phase {name} did not exit after being killed")
            if code != 0:
                log.append(f"--- {name} (exit {code}) ---\n{output[-4000:]}")
            try:
                evidence_name = f"junit-{name.removeprefix('pytest-')}.xml"
                ids, observed = read_report(paths[index], evidence_name, output, shard=name)
            except OSError as err:
                extra.append(f"junit {name}: the report could not be read: {err}")
                continue
            if set(ids) != expected[index]:
                extra.append(f"inventory {name}: JUnit node IDs differ from this shard's collected IDs")
            duplicates = outcomes.keys() & observed.keys()
            if duplicates:
                extra.append(f"junit {name}: node IDs duplicated across shards: {sorted(duplicates)}")
            junit_ids.extend(ids)
            outcomes.update({node: value for node, value in observed.items() if node not in outcomes})
        code = next((status for status in codes if status), 0)
        if runner_error:
            code = code or 1
        elif None in codes:
            code = None
        return PhaseResult("pytest", code, ended - started), ended

    try:
        facts = collect_environment(OsEnvironmentProbe(), env=os.environ, platform=sys.platform)
        environment = assess_environment(facts)
    except Exception as err:  # noqa: BLE001 - never swallowed: any failure is a reason, the receipt is not accepted
        extra.append(f"environment preflight failed: {type(err).__name__}: {err}")
    try:
        try:
            resolved = _git(repo, "rev-parse", "HEAD").strip()
            _git(repo, "worktree", "add", "--detach", str(worktree), resolved)
            created = True
            worktree_id = _worktree_identity(worktree, allocator)
            start = source_identity(worktree)
        except (RuntimeError, OSError) as err:
            extra.append(f"source identity could not be read at start: {type(err).__name__}: {err}")
        if start is not None:
            code, output, _, error = step(
                "uv-sync",
                ["uv", "sync", "--locked", "--project", str(worktree), "--python", python],
                worktree,
                SYNC_TIMEOUT_S,
            )
            if code != 0:
                extra.append(f"uv sync failed ({error or ('timed out' if code is None else code)})")
                log.append(output)
            else:
                job_began = time.monotonic()
                deadline = job_began + time_budget_s
                halted: str | None = None  # why no further step of the test job may start

                def bounded(name: str, cap: float) -> float | None:
                    """The timeout for the next step, or ``None`` (with a reason) when it must not start."""
                    left = deadline - time.monotonic()
                    if halted is not None:
                        extra.append(f"{name} not started: {halted}")
                        return None
                    if left <= 0:
                        extra.append(f"{name} not started: the {time_budget_s:.0f}s test-job budget was spent")
                        return None
                    return min(cap, left)

                def failed_to_run(label: str, code: int | None, error: str | None, output: str) -> bool:
                    nonlocal halted
                    if error is not None:
                        extra.append(f"{label} {error}")
                        halted = "an earlier step did not complete"
                    elif code is None:
                        extra.append(f"{label} timed out")
                    elif code != 0:
                        extra.append(f"{label} exited with {code}")
                    else:
                        return False
                    log.append(f"--- {label} (exit {code}) ---\n{output[-4000:]}")
                    return True

                timeout = bounded("interpreter preflight", PREFLIGHT_TIMEOUT_S)
                if timeout is not None:
                    code, output, _, error = step(
                        "preflight", _uv(worktree, python, "python", "-I", "-c", PREFLIGHT_CODE), worktree, timeout
                    )
                    if not failed_to_run("interpreter preflight", code, error, output):
                        try:
                            interpreter = InterpreterInfo(**json.loads(output.strip().splitlines()[-1]))
                        except (ValueError, TypeError, IndexError):
                            extra.append("interpreter preflight output was not understood")
                            log.append(output)

                timeout = bounded("pytest --collect-only", max(COLLECT_TIMEOUT_S, time_budget_s))
                if timeout is not None:
                    code, output, _, error = step(
                        "collect", _uv(worktree, python, "pytest", "--collect-only", "-q"), worktree, timeout
                    )
                    if not failed_to_run("pytest --collect-only", code, error, output):
                        try:
                            collected = parse_collected(output)
                        except ValueError as err:
                            extra.append(f"inventory: {err}")

                commands: dict[str, list[str]] = {
                    "ruff": _uv(worktree, python, "ruff", "check", "src", "tests", "scripts"),
                    "mypy": _uv(worktree, python, "mypy"),
                    "lint-imports": _uv(worktree, python, "lint-imports"),
                    "pytest": _uv(worktree, python, "pytest", f"--junitxml={junit}", "-q", "-rfEX"),
                }
                selected_files = []
                target_ids = list(collected)
                if partition is not None:
                    selected_files = partition_files(collected, partition)
                    selected_set = set(selected_files)
                    target_ids = [nid for nid in collected if nid.split("::", 1)[0] in selected_set]
                    ev.write("collected-full.json", canonical_json(sorted(collected)))
                    ev.write("collected-partition.json", canonical_json(sorted(target_ids)))
                parallel_ids, serial_ids = split_serial(target_ids) if shards > 1 else (target_ids, [])
                groups = shard_files(parallel_ids, shards)
                for name in REQUIRED_PHASES:
                    cap = PHASE_TIMEOUTS_S[name]
                    timeout = bounded(f"phase {name}", max(cap, time_budget_s) if name == "pytest" else cap)
                    if timeout is None:
                        continue
                    if name == "pytest" and len(groups) > 1:
                        phase, job_ended = run_sharded_pytest(groups, deadline, serial_ids)
                        phases.append(phase)
                        continue
                    if name == "pytest" and partition is not None and not groups:
                        extra.append("partition has empty test inventory")
                        phases.append(PhaseResult("pytest", 1, 0.0))
                        continue
                    cmd = (
                        [*commands[name], *groups[0]]
                        if name == "pytest" and partition is not None and len(groups) == 1
                        else commands[name]
                    )
                    code, output, seconds, error = step(name, cmd, worktree, timeout)
                    if error is not None:
                        extra.append(f"phase {name} {error}")
                        halted = "an earlier step did not complete"
                        continue
                    phases.append(PhaseResult(name, code, seconds))
                    if name == "pytest":
                        pytest_output = output
                    if KILL_HANG_MARKER in output:
                        extra.append(f"phase {name} did not exit after being killed")
                    if code != 0:
                        log.append(f"--- {name} (exit {code}) ---\n{output[-4000:]}")
                if job_ended is None:
                    job_ended = time.monotonic()
                    if len(groups) <= 1 and not (partition is not None and not groups):
                        junit_ids, outcomes = read_report(junit, "junit.xml", pytest_output)
        if created:
            try:
                end = source_identity(worktree)
            except (RuntimeError, OSError) as err:
                extra.append(f"source identity could not be read at end: {type(err).__name__}: {err}")
    except Exception as err:  # noqa: BLE001 - never lost: a refusal reason, and the evidence is still written
        extra.append(f"gate run aborted: {type(err).__name__}: {err}")
    finally:
        for path in junit_paths:
            try:
                path.unlink(missing_ok=True)
            except OSError as err:
                extra.append(f"junit temp file was not removed: {err}")
        if created:
            try:
                _remove_gate_worktree(repo, worktree, allocator, worktree_id)
            except (RuntimeError, OSError) as err:
                cleanup_error = str(err)

    finished = time.monotonic()
    ev.write(  # the source probes as observed, also when they failed (the receipt then says unverified)
        "source.json",
        canonical_json({
            "resolved_commit": resolved,
            "start": asdict(start) if start is not None else None,
            "end": asdict(end) if end is not None else None,
            "host": _host(),
        }),
    )
    test_job_s = None if job_began is None else (job_ended if job_ended is not None else finished) - job_began
    receipt = build_receipt(
        start=start,
        end=end,
        phases=phases,
        collected_ids=target_ids,
        junit_ids=junit_ids,
        junit_outcomes=outcomes,
        python=(interpreter.version.split()[0] if interpreter else python),
        implementation=(interpreter.implementation if interpreter else "unknown"),
        platform=sys.platform,
        interpreter=interpreter,
        worktree=str(worktree),
        requested_python=python,
        test_job_seconds=test_job_s,
        cleanup_error=cleanup_error,
        extra_reasons=[*extra, *ev.errors],
        environment=environment,
        time_budget_s=time_budget_s,
    )
    receipt["resolved_commit"] = resolved
    receipt["timing"] = {
        "setup_s": None if job_began is None else job_began - began,
        "test_job_s": test_job_s,
        "teardown_s": None if job_ended is None else finished - job_ended,
        "total_s": finished - began,
    }
    receipt["steps"] = steps
    receipt["host"] = _host()
    if partition is not None:
        part_files: list[JsonValue] = list(sorted(selected_files))
        receipt["partition"] = {
            "index": partition[0],
            "count": partition[1],
            "files": part_files,
            "full_collected_count": len(collected),
            "full_collected_digest": digest_bytes(canonical_json(sorted(collected))),
        }
    receipt["evidence"] = {
        "attempt_dir": str(attempt_dir) if attempt_dir is not None else None,
        "manifest": dict(ev.manifest),
    }
    receipt["receipt_digest"] = digest_bytes(canonical_json(receipt))
    failure = ev.write_receipt(receipt)
    if failure is not None:  # the evidence is incomplete: never an accepted run; re-digest the changed payload
        del receipt["receipt_digest"]
        receipt["accepted"] = False
        reasons = receipt["reasons"]
        assert isinstance(reasons, list)
        reasons.append(failure)
        receipt["receipt_digest"] = digest_bytes(canonical_json(receipt))
    log.extend(ev.errors)
    if failure is not None:
        log.append(failure)
    return receipt, "\n".join(log)


def _is_finite_non_neg_number(val: object) -> bool:
    return (
        isinstance(val, (int, float))
        and not isinstance(val, bool)
        and math.isfinite(float(val))
        and float(val) >= 0.0
    )


def _worker_source_clean(identity: object) -> bool:
    if not isinstance(identity, Mapping):
        return False
    flag = identity.get("tree_clean") if "tree_clean" in identity else identity.get("clean")
    return flag is True


def _parse_junit_items(report: bytes) -> tuple[list[tuple[str, str]], float]:
    items: list[tuple[str, str]] = []
    total_time = 0.0
    for case in ET.fromstring(report).iter("testcase"):
        node_id = _junit_nodeid(case, root=None)
        items.append((node_id, _outcome(case)))
        raw_t = case.get("time")
        if raw_t is not None:
            try:
                total_time += float(raw_t)
            except ValueError:
                pass
    return items, total_time


def aggregate_partition_receipts(
    workers_dir: Path,
    *,
    python: str,
    partition_count: int,
    evidence_dir: Path | None = None,
    expected_commit: str | None = None,
) -> tuple[dict[str, JsonValue], str]:
    """Verify and combine all ``partition_count`` worker attempts into one F4 aggregate receipt."""
    attempt_dir: Path | None = None
    if evidence_dir is not None:
        try:
            evidence_dir.mkdir(parents=True, exist_ok=True)
            attempt_dir = evidence_dir / f"attempt-{datetime.now(UTC):%Y%m%dT%H%M%S%fZ}-{uuid.uuid4().hex[:8]}"
            attempt_dir.mkdir()
        except OSError as err:
            raise EvidenceDirError(f"{type(err).__name__}: {err}") from err
    ev = _Evidence(attempt_dir)
    reasons: list[str] = []
    if partition_count < 1:
        reasons.append(f"invalid partition_count {partition_count}")

    receipt_paths = sorted(workers_dir.rglob("receipt.json")) if workers_dir.is_dir() else []
    by_index: dict[int, tuple[Path, dict[str, object]]] = {}
    for r_path in receipt_paths:
        try:
            raw_obj = json.loads(r_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as err:
            reasons.append(f"unreadable worker receipt {r_path}: {type(err).__name__}: {err}")
            continue
        if not isinstance(raw_obj, dict):
            reasons.append(f"worker receipt {r_path} is not a JSON object")
            continue
        stored_digest = raw_obj.get("receipt_digest")
        computed_digest = digest_bytes(canonical_json({k: v for k, v in raw_obj.items() if k != "receipt_digest"}))
        if not isinstance(stored_digest, str) or stored_digest != computed_digest:
            reasons.append(f"worker receipt {r_path} has tampered or invalid receipt_digest")
            continue
        part = raw_obj.get("partition")
        if not isinstance(part, dict):
            reasons.append(f"worker receipt {r_path} missing partition metadata")
            continue
        idx = part.get("index")
        cnt = part.get("count")
        if type(idx) is not int or type(cnt) is not int or cnt != partition_count or idx < 0 or idx >= partition_count:
            reasons.append(
                f"worker receipt {r_path} has invalid partition ({idx}/{cnt}, expected count {partition_count})"
            )
            continue
        if idx in by_index:
            reasons.append(f"duplicate partition index {idx} among worker receipts")
            continue
        by_index[idx] = (r_path, raw_obj)

    missing_parts = [i for i in range(partition_count) if i not in by_index]
    if missing_parts:
        reasons.append(f"missing partition(s): {missing_parts}")

    all_outcomes: dict[str, str] = {}
    dup_nodeids: list[str] = []
    worker_times: list[float] = []
    worker_summaries: list[JsonValue] = []
    total_junit_s = 0.0
    base_full: list[str] | None = None
    ref_start: object = None
    ref_end: object = None
    ref_commit: object = None
    ref_platform: object = None
    ref_python: object = None
    ref_impl: object = None
    ref_env: object = None

    for idx in sorted(by_index):
        r_path, w = by_index[idx]
        w_dir = r_path.parent
        w_prefix = f"partition {idx}"

        ev_sec = w.get("evidence")
        manifest = ev_sec.get("manifest") if isinstance(ev_sec, dict) else None
        if not isinstance(manifest, dict) or not manifest:
            reasons.append(f"{w_prefix}: missing evidence manifest")
        else:
            w_root_resolved = w_dir.resolve()
            for rel, exp_sha in manifest.items():
                artifact = w_dir / str(rel)
                if not artifact.resolve().is_relative_to(w_root_resolved) or not artifact.is_file():
                    reasons.append(f"{w_prefix}: missing manifest artifact {rel}")
                    continue
                if digest_bytes(artifact.read_bytes()) != exp_sha:
                    reasons.append(f"{w_prefix}: tampered artifact {rel}: manifest SHA-256 mismatch")
            on_disk = {p.relative_to(w_dir).as_posix() for p in w_dir.rglob("*") if p.is_file()}
            if on_disk - {r_path.name} != set(manifest):
                reasons.append(f"{w_prefix}: unlisted or missing files relative to manifest")

        if w.get("accepted") is not True:
            w_rs = w.get("reasons")
            reasons.append(f"{w_prefix}: worker did not pass (accepted={w.get('accepted')!r}, reasons={w_rs!r})")

        phases_raw = w.get("phases")
        phase_names = (
            {p.get("name") for p in phases_raw if isinstance(p, dict)} if isinstance(phases_raw, list) else set()
        )
        if not isinstance(phases_raw, list) or phase_names != set(REQUIRED_PHASES):
            reasons.append(f"{w_prefix}: missing required gate phases")
        else:
            for p_entry in phases_raw:
                if not isinstance(p_entry, dict) or p_entry.get("exit_code") != 0:
                    pname = p_entry.get("name") if isinstance(p_entry, dict) else "?"
                    reasons.append(f"{w_prefix}: phase {pname} failed")

        w_time = w.get("test_job_seconds")
        if not isinstance(w_time, (int, float)) or isinstance(w_time, bool) or not math.isfinite(float(w_time)):
            reasons.append(f"{w_prefix}: non-numeric or non-finite test_job_seconds {w_time!r}")
            w_time_val: JsonValue = None
        elif float(w_time) < 0.0:
            reasons.append(f"{w_prefix}: negative test_job_seconds {w_time!r}")
            w_time_val = None
        else:
            w_float = float(w_time)
            w_time_val = w_float
            worker_times.append(w_float)
            if w_float >= TEST_JOB_BUDGET_S:
                reasons.append(
                    f"{w_prefix}: test_job_seconds {w_float:.3f}s exceeds {TEST_JOB_BUDGET_S:.1f}s budget"
                )

        w_req_py = w.get("requested_python")
        if w_req_py != python:
            reasons.append(f"{w_prefix}: requested_python {w_req_py!r} != {python!r}")
        w_env = w.get("environment")
        if not isinstance(w_env, dict) or w_env.get("accepted") is not True:
            reasons.append(f"{w_prefix}: environment was not accepted")

        w_start, w_end, w_commit = w.get("start"), w.get("end"), w.get("resolved_commit")
        if not _worker_source_clean(w_start) or not _worker_source_clean(w_end) or w_start != w_end:
            reasons.append(f"{w_prefix}: source identity unverified, dirty, or changed during run")
        if ref_start is None:
            ref_start, ref_end, ref_commit = w_start, w_end, w_commit
            ref_platform = w.get("platform")
            ref_python = w.get("python")
            ref_impl = w.get("implementation")
            ref_env = w_env
        else:
            if w_start != ref_start or w_end != ref_end or w_commit != ref_commit:
                reasons.append(f"{w_prefix}: commit/source identity mismatch across partitions")
            if (
                w.get("platform") != ref_platform
                or w.get("python") != ref_python
                or w.get("implementation") != ref_impl
            ):
                reasons.append(f"{w_prefix}: interpreter/platform mismatch across partitions")
        if expected_commit is not None and w_commit != expected_commit:
            reasons.append(f"{w_prefix}: commit {w_commit!r} != expected {expected_commit!r}")

        part_meta = w["partition"]
        assert isinstance(part_meta, dict)
        full_p = w_dir / "collected-full.json"
        part_p = w_dir / "collected-partition.json"
        if not isinstance(manifest, dict) or "collected-full.json" not in manifest or not full_p.is_file():
            reasons.append(f"{w_prefix}: missing collected-full.json")
        else:
            try:
                w_full = json.loads(full_p.read_text(encoding="utf-8"))
            except (OSError, ValueError) as err:
                reasons.append(f"{w_prefix}: invalid collected-full.json: {err}")
                w_full = None
            if not isinstance(w_full, list) or not all(isinstance(x, str) for x in w_full):
                reasons.append(f"{w_prefix}: malformed collected-full.json")
            else:
                sorted_full = sorted(w_full)
                exp_full_dig = part_meta.get("full_collected_digest")
                exp_full_cnt = part_meta.get("full_collected_count")
                if len(set(sorted_full)) != len(sorted_full):
                    reasons.append(f"{w_prefix}: full collected inventory contains duplicates")
                elif digest_bytes(canonical_json(sorted_full)) != exp_full_dig or len(sorted_full) != exp_full_cnt:
                    reasons.append(f"{w_prefix}: full_collected_digest or count mismatch")
                elif base_full is None:
                    base_full = sorted_full
                elif sorted_full != base_full:
                    reasons.append(f"{w_prefix}: full test inventory mismatch across partitions")

        w_part_ids: list[str] | None = None
        if not isinstance(manifest, dict) or "collected-partition.json" not in manifest or not part_p.is_file():
            reasons.append(f"{w_prefix}: missing collected-partition.json")
        else:
            try:
                raw_part_ids = json.loads(part_p.read_text(encoding="utf-8"))
            except (OSError, ValueError) as err:
                reasons.append(f"{w_prefix}: invalid collected-partition.json: {err}")
                raw_part_ids = None
            if isinstance(raw_part_ids, list) and all(isinstance(x, str) for x in raw_part_ids):
                w_part_ids = sorted(raw_part_ids)
            else:
                reasons.append(f"{w_prefix}: malformed collected-partition.json")

        w_junit_rels = sorted(
            str(rel) for rel in (manifest or {}) if str(rel).startswith("junit") and str(rel).endswith(".xml")
        )
        if not w_junit_rels:
            reasons.append(f"{w_prefix}: missing JUnit XML report in manifest")
        worker_junit_ids: list[str] = []
        raw_outcomes_obj = w.get("outcomes")
        raw_w_outcomes: dict[object, object] = raw_outcomes_obj if isinstance(raw_outcomes_obj, dict) else {}
        for jrel in w_junit_rels:
            try:
                items, jtime = _parse_junit_items((w_dir / jrel).read_bytes())
            except (OSError, ET.ParseError, ValueError) as err:
                reasons.append(f"{w_prefix}: invalid JUnit {jrel}: {err}")
                continue
            total_junit_s += jtime
            for nid, outc in items:
                worker_junit_ids.append(nid)
                if outc == "passed" and raw_w_outcomes.get(nid) == "xpassed":
                    outc = "xpassed"
                if nid in all_outcomes:
                    dup_nodeids.append(nid)
                else:
                    all_outcomes[nid] = outc
        if w_part_ids is not None and sorted(worker_junit_ids) != w_part_ids:
            reasons.append(f"{w_prefix}: JUnit nodeids do not match partition collected inventory")

        raw_digest = w.get("receipt_digest")
        w_counts = w.get("counts")
        worker_summaries.append({
            "index": idx,
            "accepted": bool(w.get("accepted")),
            "test_job_seconds": w_time_val,
            "receipt_digest": str(raw_digest) if isinstance(raw_digest, str) else None,
            "counts": dict(w_counts) if isinstance(w_counts, dict) else None,
            "attempt_dir": str(w_dir),
        })

    if dup_nodeids:
        sample = sorted(set(dup_nodeids))[:5]
        reasons.append(f"duplicate testcase nodeid(s) across partitions ({len(dup_nodeids)}): {sample}")
    if base_full is not None:
        missing_tests = sorted(set(base_full) - set(all_outcomes))
        if missing_tests:
            reasons.append(f"missing testcase(s) from aggregate JUnit ({len(missing_tests)}): {missing_tests[:5]}")
        extra_tests = sorted(set(all_outcomes) - set(base_full))
        if extra_tests:
            reasons.append(f"unexpected testcase(s) in aggregate JUnit ({len(extra_tests)}): {extra_tests[:5]}")
    bad = sorted(nid for nid, v in all_outcomes.items() if v not in NON_FAILING)
    if bad:
        reasons.append(f"{len(bad)} test(s) did not pass across partitions, first: {bad[:5]}")

    counted = Counter(v for v in all_outcomes.values() if v in TERMINAL_OUTCOMES)
    counts: dict[str, JsonValue] = {name: counted.get(name, 0) for name in sorted(TERMINAL_OUTCOMES)}
    agg_test_job_s = max(worker_times) if worker_times else None
    worker_sum_s = sum(worker_times) if worker_times else None
    if agg_test_job_s is not None and agg_test_job_s >= TEST_JOB_BUDGET_S:
        if not any("budget" in r for r in reasons):
            reasons.append(
                f"aggregate test_job_seconds {agg_test_job_s:.3f}s meets/exceeds {TEST_JOB_BUDGET_S:.1f}s budget"
            )

    ev.write(
        "source.json",
        canonical_json({
            "resolved_commit": ref_commit if isinstance(ref_commit, str) else None,
            "start": ref_start if isinstance(ref_start, dict) else None,
            "end": ref_end if isinstance(ref_end, dict) else None,
            "host": _host(),
        }),
    )
    reasons.extend(ev.errors)
    reason_items: list[JsonValue] = list(reasons)
    time_items: list[JsonValue] = list(worker_times)
    agg_receipt: dict[str, JsonValue] = {
        "accepted": not reasons,
        "reasons": reason_items,
        "timing_contract": TIMING_CONTRACT_PARALLEL_MAX,
        "test_job_seconds": agg_test_job_s,
        "time_budget_s": TEST_JOB_BUDGET_S,
        "worker_test_job_seconds": time_items,
        "worker_sum_seconds": worker_sum_s,
        "total_junit_seconds": total_junit_s,
        "full_collected_count": len(base_full) if base_full is not None else 0,
        "test_count": len(base_full) if base_full is not None else len(all_outcomes),
        "test_inventory_digest": digest_bytes(canonical_json(base_full)) if base_full is not None else None,
        "junit_inventory_digest": digest_bytes(canonical_json(sorted(all_outcomes))),
        "counts": counts,
        "workers": worker_summaries,
        "start": dict(ref_start) if isinstance(ref_start, dict) else None,
        "end": dict(ref_end) if isinstance(ref_end, dict) else None,
        "resolved_commit": ref_commit if isinstance(ref_commit, str) else None,
        "requested_python": python,
        "python": ref_python if isinstance(ref_python, str) else python,
        "implementation": ref_impl if isinstance(ref_impl, str) else "unknown",
        "platform": ref_platform if isinstance(ref_platform, str) else sys.platform,
        "environment": dict(ref_env) if isinstance(ref_env, dict) else None,
        "host": _host(),
        "evidence": {
            "attempt_dir": str(attempt_dir) if attempt_dir is not None else None,
            "manifest": dict(ev.manifest),
        },
    }
    agg_digest = digest_bytes(canonical_json(agg_receipt))
    agg_receipt["receipt_digest"] = agg_digest
    failure = ev.write_receipt(agg_receipt)
    if failure is not None:
        del agg_receipt["receipt_digest"]
        agg_receipt["accepted"] = False
        r_list = agg_receipt["reasons"]
        assert isinstance(r_list, list)
        r_list.append(failure)
        agg_digest = digest_bytes(canonical_json(agg_receipt))
        agg_receipt["receipt_digest"] = agg_digest
    return agg_receipt, agg_digest


def _aggregate_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description="Aggregate partitioned worker receipts into one F4 cell receipt.")
    parser.add_argument("--python", required=True, help="Expected Python version")
    parser.add_argument("--partition-count", type=int, required=True, help="Expected number of worker partitions")
    parser.add_argument("--workers-dir", required=True, help="Directory holding worker attempt directories")
    parser.add_argument("--evidence-dir", help="Absolute directory for the aggregate attempt dir")
    parser.add_argument("--expected-commit", help="Optional resolved commit SHA all workers must match")
    args = parser.parse_args(list(argv))
    evidence: Path | None = None
    if args.evidence_dir is not None:
        evidence = Path(args.evidence_dir)
        if not evidence.is_absolute():
            print(
                f"gate aggregate refused: --evidence-dir must be absolute, got {args.evidence_dir!r}",
                file=sys.stderr,
            )
            return 2
        if evidence.exists() and not evidence.is_dir():
            print(f"gate aggregate refused: the evidence dir {evidence} is not a directory", file=sys.stderr)
            return 2
    repo = Path(__file__).resolve().parent.parent
    try:
        receipt, _ = aggregate_partition_receipts(
            Path(args.workers_dir),
            python=args.python,
            partition_count=args.partition_count,
            evidence_dir=evidence,
            expected_commit=args.expected_commit,
        )
    except EvidenceDirError as err:
        print(f"gate aggregate refused: the evidence dir could not be prepared: {err}", file=sys.stderr)
        return 2
    out_dir = repo / ".gate"
    path = out_dir / receipt_name(receipt)
    try:
        out_dir.mkdir(exist_ok=True)
        path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError as err:
        print(f"gate aggregate: the legacy receipt could not be written: {err}", file=sys.stderr)
        return 1
    counts = receipt["counts"]
    assert isinstance(counts, dict)
    summary = ", ".join(f"{k}={v}" for k, v in counts.items() if v)
    print(f"gate aggregate {'ACCEPTED' if receipt['accepted'] else 'NOT ACCEPTED'}: {summary or 'no tests'} -> {path}")
    reasons = receipt["reasons"]
    if isinstance(reasons, list):
        for reason in reasons:
            print(f"  reason: {reason}", file=sys.stderr)
    return 0 if receipt["accepted"] else 1


def main(argv: Sequence[str] | None = None) -> int:
    argv_list = list(sys.argv[1:] if argv is None else argv)
    if argv_list and argv_list[0] == "aggregate":
        return _aggregate_main(argv_list[1:])
    parser = argparse.ArgumentParser(description="Run the default gate and write a receipt.")
    parser.add_argument("--python", required=True, help="Python version to run the gate with, e.g. 3.14")
    parser.add_argument("--evidence-dir", help="absolute directory; each run writes a new attempt dir under it")
    parser.add_argument("--shards", type=int, default=PYTEST_SHARDS, help="maximum parallel pytest processes")
    parser.add_argument("--partition", help="optional worker partition '<index>/<count>'")
    parser.add_argument(
        "--time-budget-s",
        type=float,
        default=None,
        help=f"test-job budget in seconds (default {TEST_JOB_BUDGET_S:.0f}); only a plan-recorded local threshold",
    )
    args = parser.parse_args(argv_list)
    if args.shards < 1:
        print("gate refused: --shards must be at least 1", file=sys.stderr)
        return 2
    time_budget_s = TEST_JOB_BUDGET_S
    if args.time_budget_s is not None:
        if args.partition is not None:
            print("gate refused: --time-budget-s cannot be combined with --partition", file=sys.stderr)
            return 2
        if not math.isfinite(args.time_budget_s) or not 0 < args.time_budget_s <= MAX_TEST_JOB_BUDGET_S:
            print(
                f"gate refused: --time-budget-s must be finite and in (0, {MAX_TEST_JOB_BUDGET_S:.0f}]",
                file=sys.stderr,
            )
            return 2
        time_budget_s = args.time_budget_s
    partition: tuple[int, int] | None = None
    if args.partition is not None:
        try:
            partition = parse_partition(args.partition)
        except ValueError as err:
            print(f"gate refused: invalid partition {args.partition!r}: {err}", file=sys.stderr)
            return 2
    evidence: Path | None = None
    if args.evidence_dir is not None:
        evidence = Path(args.evidence_dir)
        if not evidence.is_absolute():
            print(f"gate refused: --evidence-dir must be an absolute path, got {args.evidence_dir!r}", file=sys.stderr)
            return 2
        if evidence.exists() and not evidence.is_dir():
            print(f"gate refused: the evidence dir {evidence} is not a directory", file=sys.stderr)
            return 2
    repo = Path(__file__).resolve().parent.parent
    if not tree_is_clean(repo):
        print("gate refused: the working tree has uncommitted changes to tracked files", file=sys.stderr)
        return 2
    try:
        receipt, log = run_gate(
            repo, args.python, evidence_dir=evidence, shards=args.shards, partition=partition,
            time_budget_s=time_budget_s,
        )
    except EvidenceDirError as err:  # the attempt dir could not be created; nothing ran
        print(f"gate refused: the evidence dir could not be prepared: {err}", file=sys.stderr)
        return 2
    out_dir = repo / ".gate"
    path = out_dir / receipt_name(receipt)
    try:
        out_dir.mkdir(exist_ok=True)
        path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError as err:
        print(f"gate: evidence: the legacy receipt could not be written: {err}", file=sys.stderr)
        return 1
    if log:
        print(log, file=sys.stderr)
    counts = receipt["counts"]
    assert isinstance(counts, dict)
    summary = ", ".join(f"{k}={v}" for k, v in counts.items() if v)
    print(f"gate {'ACCEPTED' if receipt['accepted'] else 'NOT ACCEPTED'}: {summary or 'no tests'} -> {path}")
    reasons = receipt["reasons"]
    if isinstance(reasons, list):
        for reason in reasons:
            print(f"  reason: {reason}", file=sys.stderr)
    return 0 if receipt["accepted"] else 1


if __name__ == "__main__":
    sys.exit(main())
