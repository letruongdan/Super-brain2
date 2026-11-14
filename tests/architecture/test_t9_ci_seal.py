"""T9-CI-F1: CI checks reviewed oracle bytes around acceptance, including failed runs."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

from tests.architecture.test_gate_receipt import ci_matrix_list, ci_steps

REPOSITORY = Path(__file__).resolve().parents[2]
HELPER = REPOSITORY / ".verification" / "test_lock.py"
MANIFEST = ".verification/task9-seal.json"
ANCHOR = "T9_TEST_SEAL_R19_SHA256"


def test_ci_checks_externally_anchored_seal_before_and_after_acceptance() -> None:
    """A reviewer-owned anchor must guard all cells and still check a failed acceptance run."""
    steps = ci_steps()
    gate_at = next(i for i, step in enumerate(steps) if "scripts/gate.py" in step)
    bench_at = next(i for i, step in enumerate(steps) if "tests.integration.test_kernel_performance" in step)
    checks = [(i, step) for i, step in enumerate(steps) if ".verification/test_lock.py check" in step]
    assert len(checks) == 2, "CI needs real seal checks both before and after gate/benchmark"
    (before_at, before), (after_at, after) = checks
    assert before_at < gate_at < bench_at < after_at
    assert not re.search(r"^\s*if:", before, re.M), "all cells must run the before-check"
    assert re.search(r"^\s*if:\s*always\(\)\s*$", after, re.M), "failed acceptance must run after-check"
    for step in (before, after):
        assert "continue-on-error:" not in step, "seal refusal must fail the job"
        assert "shell: bash" in step
        assert re.search(r"--root\s+\.(?:\s|$)", step), step
        assert re.search(rf"--manifest\s+{re.escape(MANIFEST)}(?:\s|$)", step), step
        assert f'--expected-digest "${ANCHOR}"' in step, "do not derive acceptance from the supplied manifest"
        assert "|| true" not in step and "|| :" not in step
        assert re.search(r">[^\n]*seal-evidence[^\n]*\.json", step), "retain the actual checker receipt"
        assert "2>&1" in step or re.search(r"2>\s*\S*seal-evidence/\S+", step), (
            "retain refused checker JSON from stderr in the uploaded seal evidence"
        )

    workflow = (REPOSITORY / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert re.search(rf"{ANCHOR}:\s*\$\{{\{{\s*vars\.{ANCHOR}\s*\}}\}}", workflow)
    assert ".verification/test_lock.py seal" not in workflow, "CI must not approve its own input bytes"
    normalize = next(
        (i for i, step in enumerate(steps) if "git config core.autocrlf false" in step), None
    )
    assert normalize is not None and normalize < before_at
    assert re.search(r"git checkout-index\s+(?:--all\s+--force|--force\s+--all)", steps[normalize])
    assert set(ci_matrix_list("os")) == {"windows-latest", "macos-latest", "ubuntu-latest"}
    assert ci_matrix_list("python") == ["3.11", "3.14"]
    uploads = [step for step in steps if "upload-artifact" in step and "seal-evidence" in step]
    assert len(uploads) == 1
    assert re.search(r"^\s*if:\s*always\(\)\s*$", uploads[0], re.M)
    assert "if-no-files-found: error" in uploads[0]


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
            [sys.executable, str(HELPER), "check", "--root", str(root), "--manifest", str(manifest),
             "--expected-digest", retained],
            capture_output=True, text=True, timeout=10, check=False,
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
