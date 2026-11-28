"""T9-CI-F1: CI checks reviewed oracle bytes around acceptance, including failed runs."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

from tests.architecture.test_gate_receipt import ci_jobs, ci_steps

REPOSITORY = Path(__file__).resolve().parents[2]
HELPER = REPOSITORY / ".verification" / "test_lock.py"
MANIFEST = ".verification/task9-seal.json"
ANCHOR = "T9_TEST_SEAL_R19_SHA256"


def test_ci_checks_externally_anchored_seal_before_and_after_acceptance() -> None:
    """A reviewer-owned anchor must guard all cells across all 3 CI jobs and still check a failed acceptance run."""
    jobs = ci_jobs()
    expected_jobs = {
        "gate", "gate-windows-worker", "gate-windows-aggregate", "gate-macos-worker", "gate-macos-aggregate"
    }
    assert set(jobs.keys()) == expected_jobs, (
        f"CI workflow must define exactly jobs {expected_jobs}, found {set(jobs.keys())}"
    )

    workflow = (REPOSITORY / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert re.search(rf"{ANCHOR}:\s*\$\{{\{{\s*vars\.{ANCHOR}\s*\}}\}}", workflow), (
        f"{ANCHOR} must be anchored from vars"
    )
    assert ".verification/test_lock.py seal" not in workflow, "CI must not approve its own input bytes"

    for job_name in (
        "gate", "gate-windows-worker", "gate-windows-aggregate", "gate-macos-worker", "gate-macos-aggregate"
    ):
        steps = ci_steps(job_name)
        checks = [(i, step) for i, step in enumerate(steps) if ".verification/test_lock.py check" in step]
        assert len(checks) == 2, (
            f"Job {job_name!r} needs real seal checks both before and after execution, found {len(checks)}"
        )
        (before_at, before), (after_at, after) = checks
        assert before_at < after_at, f"Job {job_name!r}: before-check must precede after-check"
        assert not re.search(r"^\s*if:", before, re.M), (
            f"Job {job_name!r}: all cells must run the before-check unconditionally"
        )
        assert re.search(r"^\s*if:\s*always\(\)\s*$", after, re.M), (
            f"Job {job_name!r}: failed acceptance must run after-check"
        )

        for step in (before, after):
            assert "continue-on-error:" not in step, f"Job {job_name!r}: seal refusal must fail the job"
            assert "shell: bash" in step, f"Job {job_name!r}: seal check step must specify shell: bash"
            assert re.search(r"--root\s+\.(?:\s|$)", step), f"Job {job_name!r}: seal check must target --root ."
            assert re.search(rf"--manifest\s+{re.escape(MANIFEST)}(?:\s|$)", step), (
                f"Job {job_name!r}: missing manifest arg"
            )
            assert f'--expected-digest "${ANCHOR}"' in step, (
                f'Job {job_name!r}: must verify against --expected-digest "${ANCHOR}"'
            )
            assert "|| true" not in step and "|| :" not in step, (
                f"Job {job_name!r}: seal check must never mask exit code"
            )
            assert re.search(r">[^\n]*seal-evidence[^\n]*\.json", step), f"Job {job_name!r}: retain checker receipt"
            assert "2>&1" in step or re.search(r"2>\s*\S*seal-evidence/\S+", step), (
                f"Job {job_name!r}: retain refused checker JSON from stderr in uploaded seal evidence"
            )

        normalize = next((i for i, step in enumerate(steps) if "git config core.autocrlf false" in step), None)
        assert normalize is not None and normalize < before_at, (
            f"Job {job_name!r}: checkout normalization must precede seal check"
        )
        assert re.search(r"git checkout-index\s+(?:--all\s+--force|--force\s+--all)", steps[normalize])

        uploads = [step for step in steps if "upload-artifact" in step and "seal-evidence" in step]
        assert len(uploads) == 1, f"Job {job_name!r} must upload seal evidence artifact"
        assert re.search(r"^\s*if:\s*always\(\)\s*$", uploads[0], re.M), (
            f"Job {job_name!r}: seal evidence upload must be if: always()"
        )
        assert "if-no-files-found: error" in uploads[0], f"Job {job_name!r}: seal evidence must error if no files found"

    # Specific sequencing per job
    gate_steps = ci_steps("gate")
    gate_at = next(i for i, s in enumerate(gate_steps) if "scripts/gate.py" in s)
    bench_at = next(i for i, s in enumerate(gate_steps) if "tests.integration.test_kernel_performance" in s)
    gate_before = next(
        i
        for i, s in enumerate(gate_steps)
        if ".verification/test_lock.py check" in s and not re.search(r"^\s*if:", s, re.M)
    )
    gate_after = next(
        i
        for i, s in enumerate(gate_steps)
        if ".verification/test_lock.py check" in s and re.search(r"^\s*if:\s*always\(\)", s, re.M)
    )
    assert gate_before < gate_at < bench_at < gate_after, "gate job must sequence: before < gate < benchmark < after"

    worker_steps = ci_steps("gate-windows-worker")
    worker_gate_at = next(i for i, s in enumerate(worker_steps) if "scripts/gate.py" in s)
    worker_before = next(
        i
        for i, s in enumerate(worker_steps)
        if ".verification/test_lock.py check" in s and not re.search(r"^\s*if:", s, re.M)
    )
    worker_after = next(
        i
        for i, s in enumerate(worker_steps)
        if ".verification/test_lock.py check" in s and re.search(r"^\s*if:\s*always\(\)", s, re.M)
    )
    assert worker_before < worker_gate_at < worker_after, "gate-windows-worker job must sequence: before < gate < after"

    agg_steps = ci_steps("gate-windows-aggregate")
    agg_at = next(i for i, s in enumerate(agg_steps) if "scripts/gate.py aggregate" in s)
    agg_bench_at = next(i for i, s in enumerate(agg_steps) if "tests.integration.test_kernel_performance" in s)
    agg_before = next(
        i
        for i, s in enumerate(agg_steps)
        if ".verification/test_lock.py check" in s and not re.search(r"^\s*if:", s, re.M)
    )
    agg_after = next(
        i
        for i, s in enumerate(agg_steps)
        if ".verification/test_lock.py check" in s and re.search(r"^\s*if:\s*always\(\)", s, re.M)
    )
    assert agg_before < agg_at < agg_bench_at < agg_after, (
        "gate-windows-aggregate job must sequence: before < aggregate < benchmark < after"
    )


def test_ci_seal_helper_rejects_changed_input_and_changed_manifest(tmp_path: Path) -> None:
    """Real CLI positive control and two attacks, using a digest computed independently."""
    root = tmp_path / "oracle"
    root.mkdir()
    source = root / "tests" / "case.py"
    source.parent.mkdir()
    original = b"assert 2 + 2 == 4\n"
    source.write_bytes(original)
    manifest = tmp_path / "reviewed.json"
    expected = {
        "schema_version": "1.0",
        "selectors": ["tests"],
        "files": {"tests/case.py": "sha256:" + hashlib.sha256(original).hexdigest()},
    }
    manifest.write_text(json.dumps(expected, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    retained = "sha256:" + hashlib.sha256(manifest.read_bytes()).hexdigest()

    def check() -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(HELPER),
                "check",
                "--root",
                str(root),
                "--manifest",
                str(manifest),
                "--expected-digest",
                retained,
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    positive = check()
    assert positive.returncode == 0, positive.stdout + positive.stderr
    assert json.loads(positive.stdout)["ok"] is True
    source.write_bytes(b"assert True\n")
    input_change = check()
    assert input_change.returncode != 0
    input_refusal = json.loads(input_change.stderr)
    assert input_refusal["ok"] is False
    assert input_refusal["error"] == "Test input set/content differs from the frozen manifest"
    source.write_bytes(original)
    manifest.write_text(json.dumps({**expected, "selectors": ["tests/case.py"]}), encoding="utf-8")
    manifest_change = check()
    assert manifest_change.returncode != 0
    manifest_refusal = json.loads(manifest_change.stderr)
    assert manifest_refusal["ok"] is False
    assert manifest_refusal["error"] == "Manifest digest differs from independently retained digest"
