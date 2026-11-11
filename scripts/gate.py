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
import subprocess
import sys
import tempfile
import time
import uuid
import xml.etree.ElementTree as ET
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

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


LAST_PID: int | None = None
"""The PID of the process ``run`` started last; the step recorder reads it (``None`` when a stand-in ran)."""


def run(cmd: Sequence[str], *, cwd: Path, timeout_s: float) -> tuple[int | None, str, float]:
    """Run ``cmd``; return ``(exit_code or None on timeout, combined output, seconds)``."""
    global LAST_PID
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
    LAST_PID = proc.pid
    try:
        output, _ = proc.communicate(timeout=timeout_s)
        return proc.returncode, output, time.monotonic() - began
    except subprocess.TimeoutExpired:
        kill_note = ""
        try:
            _kill_tree(proc)
        except (OSError, subprocess.SubprocessError) as err:  # still a timeout; never "could not start"
            kill_note = f"\n<killing the timed-out process tree failed: {type(err).__name__}: {err}>"
            try:
                proc.kill()
            except OSError:
                pass
        try:
            output, _ = proc.communicate(timeout=KILL_GRACE_S)
        except subprocess.TimeoutExpired:
            output = KILL_HANG_MARKER
        return None, (output or "") + kill_note, time.monotonic() - began


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
    return ["uv", "run", "--locked", "--project", str(worktree), "--python", python, *tool]


def receipt_name(receipt: Mapping[str, JsonValue]) -> str:
    start = receipt["start"]
    impl, version, platform = receipt["implementation"], receipt["python"], receipt["platform"]
    if not isinstance(start, dict):  # the source could not be read: never named after a commit
        return f"receipt-unverified-{impl}{version}-{platform}-{uuid.uuid4().hex[:12]}.json"
    commit, lock = str(start["commit"]), str(start["lock_digest"])
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
    repo: Path, python: str, *, evidence_dir: Path | None = None
) -> tuple[dict[str, JsonValue], str]:
    """Run the gate in a detached worktree of the resolved HEAD. Returns the receipt and a printable log.

    One monotonic deadline of ``TEST_JOB_BUDGET_S`` starts just before the interpreter preflight; collect and every
    phase get ``min(cap, remaining)`` and no step starts once it is spent. With ``evidence_dir`` every step's
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

    def step(name: str, cmd: list[str], cwd: Path, timeout_s: float) -> tuple[int | None, str, float, str | None]:
        """Run one command and record it; ``(exit or None, output, seconds, error)``. ``error`` says the step did not
        reach an exit code: "could not start: …" (no process) or "failed while running: …" (a process had started)."""
        global LAST_PID
        LAST_PID = None
        started_at, error = _now(), None
        try:
            code, output, seconds = run(cmd, cwd=cwd, timeout_s=timeout_s)
        except Exception as err:  # noqa: BLE001 - recorded as a refusal reason, the attempt still ends in a receipt
            stage = "could not start" if LAST_PID is None and isinstance(err, OSError) else "failed while running"
            code, output, seconds, error = None, "", 0.0, f"{stage}: {type(err).__name__}: {err}"
        rel = ev.write(f"steps/{len(steps):02d}-{name}.log", output.encode("utf-8", "replace"))
        steps.append({
            "name": name,
            "command": list(cmd),
            "cwd": str(cwd),
            "pid": LAST_PID,
            "started_at": started_at,
            "timeout_s": timeout_s,
            "exit_code": code,
            "duration_s": seconds,
            "output": rel,
            "error": error,
        })
        return code, output, seconds, error

    worktree = Path(tempfile.gettempdir()) / f"superbrain-gate-{uuid.uuid4().hex[:12]}"
    extra: list[str] = []
    log: list[str] = []
    phases: list[PhaseResult] = []
    interpreter: InterpreterInfo | None = None
    collected: list[str] = []
    junit_ids: list[str] = []
    outcomes: dict[str, str] = {}
    start: SourceIdentity | None = None
    end: SourceIdentity | None = None
    resolved: str | None = None
    created = False
    cleanup_error: str | None = None
    junit = worktree.parent / f"{worktree.name}-junit.xml"
    pytest_output = ""
    environment: dict[str, JsonValue] | None = None
    job_began: float | None = None
    job_ended: float | None = None
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
            start = source_identity(worktree)
        except (RuntimeError, OSError) as err:
            extra.append(f"source identity could not be read at start: {type(err).__name__}: {err}")
        if start is not None:
            code, output, _, error = step(
                "uv-sync", ["uv", "sync", "--locked", "--project", str(worktree), "--python", python], worktree,
                SYNC_TIMEOUT_S,
            )
            if code != 0:
                extra.append(f"uv sync failed ({error or ('timed out' if code is None else code)})")
                log.append(output)
            else:
                job_began = time.monotonic()
                deadline = job_began + TEST_JOB_BUDGET_S
                halted: str | None = None  # why no further step of the test job may start

                def bounded(name: str, cap: float) -> float | None:
                    """The timeout for the next step, or ``None`` (with a reason) when it must not start."""
                    left = deadline - time.monotonic()
                    if halted is not None:
                        extra.append(f"{name} not started: {halted}")
                        return None
                    if left <= 0:
                        extra.append(f"{name} not started: the {TEST_JOB_BUDGET_S:.0f}s test-job budget was spent")
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

                timeout = bounded("pytest --collect-only", COLLECT_TIMEOUT_S)
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
                for name in REQUIRED_PHASES:
                    timeout = bounded(f"phase {name}", PHASE_TIMEOUTS_S[name])
                    if timeout is None:
                        continue
                    code, output, seconds, error = step(name, commands[name], worktree, timeout)
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
                job_ended = time.monotonic()
                raw: bytes | None = None
                try:
                    if junit.is_file():
                        raw = junit.read_bytes()
                except OSError as err:
                    extra.append(f"junit: the report could not be read: {type(err).__name__}: {err}")
                if raw is not None:
                    ev.write("junit.xml", raw)  # raw bytes kept before parsing and before cleanup
                    try:
                        junit_ids, outcomes = parse_junit(junit, root=worktree)
                    except (ValueError, OSError, ET.ParseError) as err:
                        extra.append(f"junit: the report could not be parsed: {err}")
                    xpassed, problems = parse_xpassed(pytest_output, outcomes)
                    extra.extend(f"xpass: {problem}" for problem in problems)
                    for node in xpassed:  # JUnit shows a non-strict XPASS as a pass; the terminal summary does not
                        if outcomes[node] == "passed":
                            outcomes[node] = "xpassed"
                        else:
                            extra.append(f"xpass: {node} is XPASS in the terminal but {outcomes[node]} in JUnit")
                elif not any(r.startswith("junit: the report could not be read") for r in extra):
                    extra.append("junit: pytest wrote no JUnit report")
        if created:
            try:
                end = source_identity(worktree)
            except (RuntimeError, OSError) as err:
                extra.append(f"source identity could not be read at end: {type(err).__name__}: {err}")
    except Exception as err:  # noqa: BLE001 - never lost: a refusal reason, and the evidence is still written
        extra.append(f"gate run aborted: {type(err).__name__}: {err}")
    finally:
        try:
            junit.unlink(missing_ok=True)
        except OSError as err:
            extra.append(f"junit temp file was not removed: {err}")
        if created:
            try:
                if worktree.exists():
                    _git(repo, "worktree", "remove", "--force", str(worktree))
                else:  # the worktree disappeared during the run: drop git's record of it
                    _git(repo, "worktree", "prune")
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
    test_job_s =None if job_began is None else (job_ended if job_ended is not None else finished) - job_began
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
        test_job_seconds=test_job_s,
        cleanup_error=cleanup_error,
        extra_reasons=[*extra, *ev.errors],
        environment=environment,
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


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the default gate and write a receipt.")
    parser.add_argument("--python", required=True, help="Python version to run the gate with, e.g. 3.14")
    parser.add_argument("--evidence-dir", help="absolute directory; each run writes a new attempt dir under it")
    args = parser.parse_args(argv)
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
        receipt, log = run_gate(repo, args.python, evidence_dir=evidence)
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
