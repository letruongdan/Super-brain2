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
import os
import re
import subprocess
import sys
import tempfile
import time
import uuid
import xml.etree.ElementTree as ET
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path

from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.jsonvalue import JsonValue

REQUIRED_PHASES = ("ruff", "mypy", "lint-imports", "pytest")
TERMINAL_OUTCOMES = {"passed", "failed", "error", "skipped", "xfailed", "xpassed"}
NON_FAILING = {"passed", "skipped", "xfailed"}
PHASE_TIMEOUTS_S = {"ruff": 120.0, "mypy": 300.0, "lint-imports": 120.0, "pytest": 300.0}
GIT_TIMEOUT_S = 120.0
SYNC_TIMEOUT_S = 600.0
COLLECT_TIMEOUT_S = 300.0

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


# --- receipt ------------------------------------------------------------------------------------------


def _under(path: str, parent: Path) -> bool:
    try:
        return Path(path).resolve().is_relative_to(parent.resolve())
    except (OSError, ValueError):
        return False


def build_receipt(
    *,
    start: SourceIdentity,
    end: SourceIdentity,
    phases: Sequence[PhaseResult],
    collected_ids: Sequence[str],
    junit_ids: Sequence[str],
    junit_outcomes: Mapping[str, str],
    python: str,
    implementation: str,
    platform: str,
    time_budget_s: float = 300.0,
    interpreter: InterpreterInfo | None = None,
    worktree: str | None = None,
    requested_python: str | None = None,
    cleanup_error: str | None = None,
    extra_reasons: Sequence[str] = (),
) -> dict[str, JsonValue]:
    """Judge a run. ``interpreter``/``worktree``/``requested_python`` are given together by the real gate."""
    reasons: list[str] = list(extra_reasons)
    if start != end:
        reasons.append("source identity changed between start and end of the run")
    if not start.tree_clean:
        reasons.append("working tree was not clean at start")
    if not end.tree_clean:
        reasons.append("working tree was not clean at end")

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

    if worktree is not None:
        if interpreter is None:
            reasons.append("the interpreter preflight did not produce a result")
        else:
            if not _under(interpreter.package_file, Path(worktree) / "src"):
                reasons.append(f"superbrain was imported from {interpreter.package_file}, outside the sealed worktree")
            if requested_python is not None and not re.match(
                re.escape(requested_python) + r"(?![0-9])", interpreter.version
            ):
                reasons.append(f"interpreter {interpreter.version!r} does not match --python {requested_python}")
    if cleanup_error is not None:
        reasons.append(f"sealed worktree was not removed: {cleanup_error}")

    return {
        "start": asdict(start),
        "end": asdict(end),
        "test_inventory_digest": digest_bytes(canonical_json(sorted(collected_ids))),
        "test_count": len(collected_ids),
        "counts": counts,
        "phases": [asdict(p) for p in phases],
        "python": python,
        "implementation": implementation,
        "platform": platform,
        "interpreter": asdict(interpreter) if interpreter is not None else None,
        "requested_python": requested_python,
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
        return "xfailed" if kind == "pytest.xfail" else "skipped"
    return "passed"


def parse_junit(path: Path, *, root: Path | None = None) -> tuple[list[str], dict[str, str]]:
    """Map every JUnit testcase to its ``--collect-only -q`` node ID and terminal outcome.

    pytest writes ``classname`` as the dotted module path plus enclosing classes and ``name`` as the test
    function with its parametrization. ``root`` (the pytest rootdir) resolves the dotted path exactly, by
    finding the module file.
    """
    ids: list[str] = []
    outcomes: dict[str, str] = {}
    for case in ET.parse(path).getroot().iter("testcase"):
        classname = case.get("classname") or ""
        name = case.get("name") or ""
        if classname:
            module, classes = _split_classname(classname, root)
            node_id = "::".join([module, *classes, name])
        else:
            node_id = name
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
    return env


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
    try:
        output, _ = proc.communicate(timeout=timeout_s)
        return proc.returncode, output, time.monotonic() - began
    except subprocess.TimeoutExpired:
        _kill_tree(proc)
        output, _ = proc.communicate()
        return None, output or "", time.monotonic() - began


def _git(repo: Path, *args: str) -> str:
    code, output, _ = run(["git", "-C", str(repo), *args], cwd=repo, timeout_s=GIT_TIMEOUT_S)
    if code != 0:
        raise RuntimeError(f"git {' '.join(args)} failed ({code}): {output.strip()}")
    return output


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
    return ["uv", "run", "--project", str(worktree), "--python", python, *tool]


def receipt_name(receipt: Mapping[str, JsonValue]) -> str:
    start = receipt["start"]
    assert isinstance(start, dict)
    commit, lock = str(start["commit"]), str(start["lock_digest"])
    impl, version, platform = receipt["implementation"], receipt["python"], receipt["platform"]
    return f"receipt-{commit[:12]}-{impl}{version}-{platform}-{lock[7:19]}.json"


def run_gate(repo: Path, python: str) -> tuple[dict[str, JsonValue], str]:
    """Run the gate in a sealed worktree of HEAD. Returns the receipt and a printable log of failures."""
    worktree = Path(tempfile.gettempdir()) / f"superbrain-gate-{uuid.uuid4().hex[:12]}"
    _git(repo, "worktree", "add", "--detach", str(worktree), "HEAD")
    extra: list[str] = []
    log: list[str] = []
    phases: list[PhaseResult] = []
    interpreter: InterpreterInfo | None = None
    collected: list[str] = []
    junit_ids: list[str] = []
    outcomes: dict[str, str] = {}
    start = end = None
    cleanup_error: str | None = None
    try:
        start = source_identity(worktree)
        code, output, _ = run(
            ["uv", "sync", "--project", str(worktree), "--python", python], cwd=worktree, timeout_s=SYNC_TIMEOUT_S
        )
        if code != 0:
            extra.append(f"uv sync failed ({code})")
            log.append(output)
        else:
            code, output, _ = run(
                _uv(worktree, python, "python", "-I", "-c", PREFLIGHT_CODE), cwd=worktree, timeout_s=120.0
            )
            try:
                interpreter = InterpreterInfo(**json.loads(output.strip().splitlines()[-1]))
            except (ValueError, TypeError, IndexError):
                extra.append("interpreter preflight output was not understood")
                log.append(output)

            junit = worktree.parent / f"{worktree.name}-junit.xml"
            commands: dict[str, list[str]] = {
                "ruff": _uv(worktree, python, "ruff", "check", "src", "tests", "scripts"),
                "mypy": _uv(worktree, python, "mypy"),
                "lint-imports": _uv(worktree, python, "lint-imports"),
                "pytest": _uv(worktree, python, "pytest", f"--junitxml={junit}", "-q"),
            }
            code, output, _ = run(
                _uv(worktree, python, "pytest", "--collect-only", "-q"), cwd=worktree, timeout_s=COLLECT_TIMEOUT_S
            )
            if code != 0:
                extra.append(f"pytest --collect-only exited with {code}")
                log.append(output)
            else:
                try:
                    collected = parse_collected(output)
                except ValueError as err:
                    extra.append(f"inventory: {err}")
            for name in REQUIRED_PHASES:
                code, output, seconds = run(commands[name], cwd=worktree, timeout_s=PHASE_TIMEOUTS_S[name])
                phases.append(PhaseResult(name, code, seconds))
                if code != 0:
                    log.append(f"--- {name} (exit {code}) ---\n{output[-4000:]}")
            if junit.is_file():
                try:
                    junit_ids, outcomes = parse_junit(junit, root=worktree)
                except (ValueError, ET.ParseError) as err:
                    extra.append(f"junit: {err}")
                junit.unlink()
            else:
                extra.append("pytest wrote no JUnit report")
        end = source_identity(worktree)
    finally:
        try:
            _git(repo, "worktree", "remove", "--force", str(worktree))
        except RuntimeError as err:
            cleanup_error = str(err)

    if start is None or end is None:
        raise RuntimeError("could not take the source identity of the sealed worktree")
    receipt = build_receipt(
        start=start,
        end=end,
        phases=phases,
        collected_ids=collected,
        junit_ids=junit_ids,
        junit_outcomes=outcomes,
        python=(interpreter.version.split()[0] if interpreter else python),
        implementation=(interpreter.implementation if interpreter else "unknown"),
        platform=sys.platform,
        interpreter=interpreter,
        worktree=str(worktree),
        requested_python=python,
        cleanup_error=cleanup_error,
        extra_reasons=extra,
    )
    return receipt, "\n".join(log)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the default gate and write a receipt.")
    parser.add_argument("--python", required=True, help="Python version to run the gate with, e.g. 3.14")
    args = parser.parse_args(argv)
    repo = Path(__file__).resolve().parent.parent
    if not tree_is_clean(repo):
        print("gate refused: the working tree has uncommitted changes to tracked files", file=sys.stderr)
        return 2
    receipt, log = run_gate(repo, args.python)
    out_dir = repo / ".gate"
    out_dir.mkdir(exist_ok=True)
    path = out_dir / receipt_name(receipt)
    path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
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
