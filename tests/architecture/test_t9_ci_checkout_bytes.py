"""CI-F1-R2: review bytes survive the initial checkout and the detached gate checkout across all CI jobs."""

from __future__ import annotations

import os
import re
import shlex
import subprocess
from pathlib import Path

import pytest

from tests.architecture.test_gate_receipt import CI_FILE, ci_jobs, ci_steps


def _job_git_environment(job_name: str = "gate") -> dict[str, str]:
    """Read Git's scalar job environment, which applies before actions/checkout starts."""
    text = CI_FILE.read_text(encoding="utf-8")
    lines = text.splitlines()
    job_starts: list[tuple[str, int]] = []
    in_jobs = False
    for i, line in enumerate(lines):
        if line.strip() == "jobs:":
            in_jobs = True
            continue
        if in_jobs:
            m = re.match(r"^  ([a-zA-Z0-9_-]+):\s*$", line)
            if m:
                job_starts.append((m.group(1), i))
            elif line and not line.startswith(" "):
                in_jobs = False

    idx = next((i for i, (name, _) in enumerate(job_starts) if name == job_name), None)
    if idx is None:
        return {}
    s_line = job_starts[idx][1]
    e_line = job_starts[idx + 1][1] if idx + 1 < len(job_starts) else len(lines)
    job_text = "\n".join(lines[s_line:e_line]).split("    steps:", 1)[0]
    values = {}
    for name, raw in re.findall(r"^\s+(GIT_CONFIG_[A-Z0-9_]+):\s*([^\n]+)$", job_text, re.M):
        values[name] = raw.strip().strip("\"'")
    return values


@pytest.mark.parametrize("job_name", ["gate", "gate-windows-worker", "gate-windows-aggregate"])
def test_ci_initial_and_gate_checkouts_use_reviewed_bytes_with_hostile_git_defaults(
    tmp_path: Path, job_name: str
) -> None:
    """Use real Git and the workflow's preparation, starting with Windows-like CRLF defaults across all jobs."""
    jobs = ci_jobs()
    assert job_name in jobs, f"Job {job_name!r} must exist in {CI_FILE}"

    global_config = tmp_path / f"host_{job_name}.gitconfig"
    global_config.write_text(
        "[core]\n\tautocrlf = true\n[user]\n\tname = Oracle\n\temail = oracle@example.invalid\n",
        encoding="utf-8",
    )
    host_env = {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}
    host_env.update(GIT_CONFIG_GLOBAL=str(global_config), GIT_CONFIG_NOSYSTEM="1")
    job_env = {**host_env, **_job_git_environment(job_name)}

    def git(root: Path, *args: str, env: dict[str, str]) -> bytes:
        result = subprocess.run(
            ["git", "-C", str(root), *args],
            env=env,
            capture_output=True,
            timeout=15,
            check=False,
        )
        assert result.returncode == 0, result.stderr.decode(errors="replace")
        return result.stdout

    seed = tmp_path / f"source_{job_name}"
    seed.mkdir()
    git(seed, "init", env=host_env)
    git(seed, "config", "core.autocrlf", "false", env=host_env)
    expected = {
        ".gitattributes": b"tests/fixtures/** -text\n",
        ".verification/task9-seal.json": b'{"reviewer":"independent","files":2}\n',
        "tests/case.py": b"assert 2 + 2 == 4\n",
        "tests/fixtures/intentional.bin": b"header\r\nbody\x00\r\n",
    }
    for relative, contents in expected.items():
        path = seed / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents)
    git(seed, "add", ".", env=host_env)
    git(seed, "commit", "-m", "independent reviewed fixture", env=host_env)

    checkout = tmp_path / f"checkout_{job_name}"
    checkout.mkdir()
    git(checkout, "init", env=job_env)
    git(checkout, "fetch", "--depth=1", str(seed), "HEAD", env=job_env)
    git(checkout, "checkout", "--force", "--detach", "FETCH_HEAD", env=job_env)
    steps = ci_steps(job_name)
    check_at = next((i for i, step in enumerate(steps) if ".verification/test_lock.py check" in step), None)
    assert check_at is not None, f"Job {job_name} missing seal check"
    for step in steps[:check_at]:
        for line in step.splitlines():
            command = line.strip()
            if command.startswith("git "):
                git(checkout, *shlex.split(command)[1:], env=job_env)

    for relative, contents in expected.items():
        assert (checkout / relative).read_bytes() == contents, (
            f"CI checkout in {job_name} must retain the independently reviewed raw bytes: {relative}"
        )
    status = git(checkout, "status", "--porcelain", env=job_env)
    assert not status, f"CI primary checkout in {job_name} must be clean"

    if job_name in ("gate", "gate-windows-worker"):
        gate_checkout = tmp_path / f"gate-checkout_{job_name}"
        git(checkout, "worktree", "add", "--detach", str(gate_checkout), "HEAD", env=job_env)
        for relative, contents in expected.items():
            assert (gate_checkout / relative).read_bytes() == contents, (
                f"Detached gate checkout in {job_name} must retain the independently reviewed raw bytes: {relative}"
            )
        gate_status = git(gate_checkout, "status", "--porcelain", env=job_env)
        assert not gate_status, f"Detached gate checkout in {job_name} must be clean"
