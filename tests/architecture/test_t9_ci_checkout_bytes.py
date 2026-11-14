"""CI-F1-R2: review bytes survive the initial checkout and the detached gate checkout."""

from __future__ import annotations

import os
import re
import shlex
import subprocess
from pathlib import Path

from tests.architecture.test_gate_receipt import CI_FILE, ci_steps


def _job_git_environment() -> dict[str, str]:
    """Read Git's scalar job environment, which applies before actions/checkout starts."""
    job = CI_FILE.read_text(encoding="utf-8").split("    steps:", 1)[0]
    values = {}
    for name, raw in re.findall(r"^      (GIT_CONFIG_[A-Z0-9_]+):\s*([^\n]+)$", job, re.M):
        values[name] = raw.strip().strip("\"'")
    return values


def test_ci_initial_and_gate_checkouts_use_reviewed_bytes_with_hostile_git_defaults(tmp_path: Path) -> None:
    """Use real Git and the workflow's preparation, starting with Windows-like CRLF defaults."""
    global_config = tmp_path / "host.gitconfig"
    global_config.write_text(
        "[core]\n\tautocrlf = true\n[user]\n\tname = Oracle\n\temail = oracle@example.invalid\n", encoding="utf-8",
    )
    host_env = {
        name: value for name, value in os.environ.items()
        if not name.startswith("GIT_")
    }
    host_env.update(GIT_CONFIG_GLOBAL=str(global_config), GIT_CONFIG_NOSYSTEM="1")
    job_env = {**host_env, **_job_git_environment()}

    def git(root: Path, *args: str, env: dict[str, str]) -> bytes:
        result = subprocess.run(
            ["git", "-C", str(root), *args], env=env, capture_output=True, timeout=15, check=False,
        )
        assert result.returncode == 0, result.stderr.decode(errors="replace")
        return result.stdout

    seed = tmp_path / "source"
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

    checkout = tmp_path / "checkout"
    checkout.mkdir()
    git(checkout, "init", env=job_env)
    git(checkout, "fetch", "--depth=1", str(seed), "HEAD", env=job_env)
    git(checkout, "checkout", "--force", "--detach", "FETCH_HEAD", env=job_env)
    steps = ci_steps()
    check_at = next(i for i, step in enumerate(steps) if ".verification/test_lock.py check" in step)
    for step in steps[:check_at]:
        for line in step.splitlines():
            command = line.strip()
            if command.startswith("git "):
                git(checkout, *shlex.split(command)[1:], env=job_env)

    for relative, contents in expected.items():
        assert (checkout / relative).read_bytes() == contents, (
            f"CI checkout must retain the independently reviewed raw bytes: {relative}"
        )
    status = git(checkout, "status", "--porcelain", env=job_env)
    assert not status, "CI primary checkout must be clean"

    gate_checkout = tmp_path / "gate-checkout"
    git(checkout, "worktree", "add", "--detach", str(gate_checkout), "HEAD", env=job_env)
    for relative, contents in expected.items():
        assert (gate_checkout / relative).read_bytes() == contents, (
            f"Detached gate checkout must retain the independently reviewed raw bytes: {relative}"
        )
    gate_status = git(gate_checkout, "status", "--porcelain", env=job_env)
    assert not gate_status, "Detached gate checkout must be clean"
