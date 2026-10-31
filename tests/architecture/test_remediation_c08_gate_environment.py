"""SP1-C08: the gate checks its acceptance environment and records what it found.

Requirement (spec 4.3 owner policy of 2026-10-31: "Môi trường nghiệm thu phải được kiểm tra trên thực tế: token của
tiến trình, đường dẫn vật lý và ACL thật của data root cùng các thư mục cha"; spec 5.9 trusted SID set unchanged;
spec 17.2 receipts; ledger C08): a gate run records the process token facts, the resolved physical paths of the test
trusted root and of the default data root, and the ancestor/ACL check of those paths. A failing environment makes
the receipt NOT accepted with explicit reasons, instead of hundreds of opaque test errors.

C08 RECEIPT CONTRACT (exact target for ``scripts/gate.py``)
-----------------------------------------------------------
Roles: ``TRUSTED_TEST_ROOT = "trusted_test_root"`` and ``DEFAULT_DATA_ROOT = "default_data_root"``.

``acceptance_paths(env: Mapping[str, str], platform: str) -> dict[str, Path]`` -- the configured paths:
  * trusted_test_root: win32 ``Path(env["LOCALAPPDATA"]) / "superbrain-tests"`` (what ``trusted_tmp`` uses);
    POSIX the first set of ``TMPDIR``, ``TEMP``, ``TMP``, else ``/tmp`` (where pytest's ``tmp_path`` lives).
  * default_data_root: ``Path(superbrain.adapters.os.paths.default_data_root(env, platform))``.

``class EnvironmentProbe(Protocol)``: ``app_container() -> bool | None`` (Windows ``TokenIsAppContainer``; ``None``
where not applicable or unknown), ``integrity_level() -> str | None`` (``"untrusted"``, ``"low"``, ``"medium"``,
``"high"``, ``"system"``, or ``None`` if unavailable), ``resolve(path: Path) -> Path`` (the physical path; may raise
``OSError``), ``check_ancestors(path: Path) -> list[str]`` (``PermissionGuard.check_ancestors`` problems as text).
``class OsEnvironmentProbe`` implements it for the running OS.

``@dataclass(frozen=True) class PathFacts``: ``role: str``, ``configured: str``, ``resolved: str | None``,
``ancestor_problems: tuple[str, ...]``, ``error: str | None = None``.
``@dataclass(frozen=True) class EnvironmentFacts``: ``platform: str``, ``app_container: bool | None``,
``integrity_level: str | None``, ``paths: tuple[PathFacts, ...]``, ``probe_error: str | None = None``.

``collect_environment(probe, *, env, platform) -> EnvironmentFacts``: for each role of ``acceptance_paths`` (in
that order) resolves the configured path with ``probe.resolve`` and runs ``probe.check_ancestors`` on the RESOLVED
path; an ``OSError`` from ``resolve`` gives ``resolved=None`` and ``error`` set (never an exception).

``assess_environment(facts) -> dict[str, JsonValue]``, the receipt section ``receipt["environment"]``::

    {"platform": str, "app_container": bool | None, "integrity_level": str | None,
     "paths": {role: {"configured": str, "resolved": str | None, "ancestor_problems": [str], "error": str | None}},
     "problems": [str], "accepted": bool}          # accepted == (problems == [])

Problems (stable substrings): app_container True -> contains "AppContainer"; app_container None on win32 -> contains
"AppContainer" and "unknown"; integrity level "low"/"untrusted" -> contains "integrity level" and the level; a
required role absent -> contains the role and "missing"; a path not resolved -> contains the role and
"not resolved"; each ancestor problem -> contains the role and the problem text; ``probe_error`` -> contains
"preflight".

``build_receipt(..., environment: Mapping[str, JsonValue] | None = None)``: stores ``receipt["environment"]``
(``None`` when not given) and adds the reason ``f"environment: {problem}"`` for every problem.
``run_gate`` always calls ``collect_environment(OsEnvironmentProbe(), env=os.environ, platform=sys.platform)``
(looked up on the module at call time) and passes ``assess_environment(...)`` to ``build_receipt``; if
``collect_environment`` raises, ``receipt["environment"]`` is ``None`` and a reason contains "environment preflight".
"""

import json
import os
import shutil
import sys
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest

from scripts import gate
from superbrain.adapters.os.paths import default_data_root

ROLES = ("trusted_test_root", "default_data_root")


def require(*names: str) -> None:
    missing = [name for name in names if not hasattr(gate, name)]
    assert not missing, f"C08 contract not implemented in scripts/gate.py: missing {missing}"


def path_facts(role: str, *, problems: Sequence[str] = (), resolved: str | None = "R", error: str | None = None) -> Any:
    return gate.PathFacts(
        role=role,
        configured=f"C:\\cfg\\{role}",
        resolved=None if resolved is None else f"C:\\phys\\{role}",
        ancestor_problems=tuple(problems),
        error=error,
    )


def facts(**changes: Any) -> Any:
    values: dict[str, Any] = {
        "platform": "win32",
        "app_container": False,
        "integrity_level": "medium",
        "paths": tuple(path_facts(role) for role in ROLES),
    }
    values.update(changes)
    return gate.EnvironmentFacts(**values)


def problem_list(section: Mapping[str, object]) -> list[str]:
    problems = section["problems"]
    assert isinstance(problems, list)
    assert section["accepted"] is (problems == [])
    return [str(p) for p in problems]


def problems_of(**changes: Any) -> list[str]:
    return problem_list(gate.assess_environment(facts(**changes)))


def receipt_args(**overrides: Any) -> dict[str, Any]:
    """A complete, clean ``build_receipt`` call (as in ``test_gate_receipt.ok``), plus ``overrides``."""
    worktree = Path(tempfile.gettempdir()) / "superbrain-gate-fixture"
    identity = gate.SourceIdentity("c" * 40, True, "sha256:" + "1" * 64, "sha256:" + "2" * 64, "sha256:" + "3" * 64)
    args: dict[str, Any] = {
        "start": identity,
        "end": identity,
        "phases": tuple(gate.PhaseResult(name, 0, 1.0) for name in gate.REQUIRED_PHASES),
        "collected_ids": ["a"],
        "junit_ids": ["a"],
        "junit_outcomes": {"a": "passed"},
        "python": "3.14.3",
        "implementation": "cpython",
        "platform": "win32",
        "interpreter": gate.InterpreterInfo(
            executable=str(worktree / ".venv" / "python"),
            version="3.14.3 (main)",
            implementation="cpython",
            package_file=str(worktree / "src" / "superbrain" / "__init__.py"),
        ),
        "worktree": str(worktree),
        "requested_python": "3.14",
    }
    args.update(overrides)
    return args


# --- the pure assessment ------------------------------------------------------------------------------------------


def test_a_clean_environment_has_no_problems_and_records_every_fact() -> None:
    require("PathFacts", "EnvironmentFacts", "assess_environment")
    section = gate.assess_environment(facts())

    assert section["problems"] == [] and section["accepted"] is True
    assert section["platform"] == "win32"
    assert section["app_container"] is False and section["integrity_level"] == "medium"
    paths = section["paths"]
    assert isinstance(paths, dict) and set(paths) == set(ROLES)
    assert paths["trusted_test_root"] == {
        "configured": "C:\\cfg\\trusted_test_root",
        "resolved": "C:\\phys\\trusted_test_root",
        "ancestor_problems": [],
        "error": None,
    }
    json.dumps(section)


def test_an_app_container_token_is_a_problem() -> None:
    require("PathFacts", "EnvironmentFacts", "assess_environment")
    assert any("AppContainer" in p for p in problems_of(app_container=True))


def test_an_unknown_app_container_flag_on_windows_is_a_problem() -> None:
    require("PathFacts", "EnvironmentFacts", "assess_environment")
    assert any("AppContainer" in p and "unknown" in p for p in problems_of(app_container=None))
    assert problems_of(platform="linux", app_container=None) == []


@pytest.mark.parametrize("level", ["low", "untrusted"])
def test_a_low_integrity_level_is_a_problem(level: str) -> None:
    require("PathFacts", "EnvironmentFacts", "assess_environment")
    assert any("integrity level" in p and level in p for p in problems_of(integrity_level=level))


@pytest.mark.parametrize("level", ["medium", "high", None])
def test_an_ordinary_or_unavailable_integrity_level_is_not_a_problem(level: str | None) -> None:
    require("PathFacts", "EnvironmentFacts", "assess_environment")
    assert problems_of(integrity_level=level) == []


@pytest.mark.parametrize("role", ROLES)
def test_every_ancestor_problem_of_a_path_is_reported_with_its_role(role: str) -> None:
    require("PathFacts", "EnvironmentFacts", "assess_environment")
    found = ["C:\\Users\\u\\AppData\\Local: S-1-15-3-1024-1 may delete or replace entries", "C:\\Users: owner is X"]
    paths = tuple(path_facts(r, problems=found if r == role else ()) for r in ROLES)

    problems = problems_of(paths=paths)

    for text in found:
        assert any(role in p and text in p for p in problems), (text, problems)


@pytest.mark.parametrize("role", ROLES)
def test_an_unresolved_or_missing_path_is_a_problem(role: str) -> None:
    require("PathFacts", "EnvironmentFacts", "assess_environment")
    unresolved = tuple(
        path_facts(r, resolved=None if r == role else "R", error="boom" if r == role else None) for r in ROLES
    )
    missing = tuple(path_facts(r) for r in ROLES if r != role)

    assert any(role in p and "not resolved" in p for p in problems_of(paths=unresolved))
    assert any(role in p and "missing" in p for p in problems_of(paths=missing))


def test_a_probe_error_is_a_problem() -> None:
    require("PathFacts", "EnvironmentFacts", "assess_environment")
    assert any("preflight" in p for p in problems_of(probe_error="OpenProcessToken failed"))


def test_environment_problems_make_the_receipt_not_accepted() -> None:
    require("PathFacts", "EnvironmentFacts", "assess_environment")
    bad = gate.assess_environment(facts(app_container=True))
    good = gate.assess_environment(facts())

    refused = gate.build_receipt(**receipt_args(environment=bad))
    accepted = gate.build_receipt(**receipt_args(environment=good))

    assert refused["accepted"] is False and refused["environment"] == bad
    reasons = [str(r) for r in refused["reasons"]] if isinstance(refused["reasons"], list) else []
    assert any(r.startswith("environment: ") and "AppContainer" in r for r in reasons), reasons
    assert accepted["accepted"] is True and accepted["environment"] == good


# --- the preflight's reporting, with a fake probe ----------------------------------------------------------------


class FakeProbe:
    """Environment facts on demand; records what it was asked."""

    def __init__(self, *, physical: Mapping[Path, Path] | None = None, unresolvable: Sequence[Path] = ()) -> None:
        self.physical = dict(physical or {})
        self.unresolvable = set(unresolvable)
        self.checked: list[Path] = []

    def app_container(self) -> bool | None:
        return False

    def integrity_level(self) -> str | None:
        return "medium"

    def resolve(self, path: Path) -> Path:
        if path in self.unresolvable:
            raise OSError(2, "injected: cannot resolve", str(path))
        return self.physical.get(path, path)

    def check_ancestors(self, path: Path) -> list[str]:
        self.checked.append(path)
        return [f"{path.parent}: writable by another account"] if path.name == "physical-data-root" else []


def host_env(tmp_path: Path) -> dict[str, str]:
    if sys.platform == "win32":
        return {"LOCALAPPDATA": str(tmp_path / "Local")}
    return {"TMPDIR": str(tmp_path / "tmp"), "HOME": str(tmp_path / "home"), "XDG_DATA_HOME": str(tmp_path / "xdg")}


def test_acceptance_paths_are_the_trusted_test_root_and_the_default_data_root(tmp_path: Path) -> None:
    require("acceptance_paths")
    env = host_env(tmp_path)
    expected_trusted = (
        Path(env["LOCALAPPDATA"]) / "superbrain-tests" if sys.platform == "win32" else Path(env["TMPDIR"])
    )

    paths = gate.acceptance_paths(env, sys.platform)

    assert list(paths) == list(ROLES)
    assert paths["trusted_test_root"] == expected_trusted
    assert paths["default_data_root"] == Path(default_data_root(env, sys.platform))
    overridden = gate.acceptance_paths({**env, "SUPERBRAIN_HOME": str(tmp_path / "home-override")}, sys.platform)
    assert overridden["default_data_root"] == tmp_path / "home-override"


def test_collect_environment_checks_the_ancestors_of_the_resolved_physical_paths(tmp_path: Path) -> None:
    require("acceptance_paths", "collect_environment", "assess_environment")
    env = host_env(tmp_path)
    configured = gate.acceptance_paths(env, sys.platform)
    physical = tmp_path / "elsewhere" / "physical-data-root"
    probe = FakeProbe(physical={configured["default_data_root"]: physical})

    found = gate.collect_environment(probe, env=env, platform=sys.platform)

    by_role = {p.role: p for p in found.paths}
    assert [p.role for p in found.paths] == list(ROLES)
    assert found.app_container is False and found.integrity_level == "medium"
    assert by_role["default_data_root"].configured == str(configured["default_data_root"])
    assert by_role["default_data_root"].resolved == str(physical)
    assert probe.checked == [configured["trusted_test_root"], physical]  # the resolved path, not the configured one
    assert by_role["default_data_root"].ancestor_problems == (f"{physical.parent}: writable by another account",)
    problems = problem_list(gate.assess_environment(found))
    assert any("default_data_root" in p and "writable by another account" in p for p in problems), problems


def test_collect_environment_reports_an_unresolvable_path_instead_of_raising(tmp_path: Path) -> None:
    require("acceptance_paths", "collect_environment", "assess_environment")
    env = host_env(tmp_path)
    configured = gate.acceptance_paths(env, sys.platform)

    found = gate.collect_environment(
        FakeProbe(unresolvable=[configured["trusted_test_root"]]), env=env, platform=sys.platform
    )

    trusted = next(p for p in found.paths if p.role == "trusted_test_root")
    assert trusted.resolved is None and trusted.error
    problems = problem_list(gate.assess_environment(found))
    assert any("trusted_test_root" in p and "not resolved" in p for p in problems), problems


def test_the_real_probe_reports_this_machine() -> None:
    require("OsEnvironmentProbe", "collect_environment", "assess_environment")

    found = gate.collect_environment(gate.OsEnvironmentProbe(), env=os.environ, platform=sys.platform)

    assert [p.role for p in found.paths] == list(ROLES)
    if sys.platform == "win32":
        assert isinstance(found.app_container, bool), "the AppContainer flag of this token must be determinable"
    assert all(p.resolved is not None or p.error for p in found.paths)
    json.dumps(gate.assess_environment(found))


# --- run_gate records the environment and refuses on a failing one ----------------------------------------------


JUNIT_ONE_PASS = '<testsuites><testsuite><testcase classname="t.test_a" name="test_a"/></testsuite></testsuites>'


class GreenRunner:
    """Stands in for ``gate.run``: every tool answers green; one passing test; creates and removes the worktree."""

    def __init__(self) -> None:
        self.worktree: Path | None = None

    def __call__(self, cmd: Sequence[str], *, cwd: Path, timeout_s: float) -> tuple[int | None, str, float]:
        argv = list(cmd)
        if argv[0] == "git":
            sub = argv[3:]
            if sub[:2] == ["worktree", "add"]:
                self.worktree = Path(sub[3])
                (self.worktree / "src" / "superbrain").mkdir(parents=True)
                (self.worktree / "t").mkdir()
                (self.worktree / "t" / "test_a.py").write_text("")
                (self.worktree / "uv.lock").write_text("lock")
                (self.worktree / "pyproject.toml").write_text("cfg")
            elif sub[:2] == ["worktree", "remove"]:
                shutil.rmtree(sub[3])
            elif sub[:1] == ["rev-parse"]:
                return 0, "a" * 40 + "\n", 0.0
            return 0, "", 0.0
        if argv[:2] == ["uv", "sync"]:
            return 0, "", 0.0
        tool = argv[argv.index("--python") + 2 :]
        if gate.PREFLIGHT_CODE in tool:
            assert self.worktree is not None
            info = {
                "executable": str(self.worktree / ".venv" / "python"),
                "version": "3.14.3 (main)",
                "implementation": "cpython",
                "package_file": str(self.worktree / "src" / "superbrain" / "__init__.py"),
            }
            return 0, json.dumps(info) + "\n", 0.0
        if tool[:1] == ["pytest"] and "--collect-only" in tool:
            return 0, "t/test_a.py::test_a\n\n1 test collected in 0.01s\n", 0.0
        if tool[:1] == ["pytest"]:
            junit = next(a for a in tool if a.startswith("--junitxml=")).split("=", 1)[1]
            Path(junit).write_text(JUNIT_ONE_PASS)
        return 0, "", 0.0


def gate_with_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, collect: Any) -> dict[str, Any]:
    monkeypatch.setattr(gate, "run", GreenRunner())
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(gate, "collect_environment", collect, raising=False)
    receipt, _ = gate.run_gate(tmp_path / "repo", "3.14")
    return dict(receipt)


def test_run_gate_refuses_and_records_an_app_container_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    receipt = gate_with_environment(tmp_path, monkeypatch, lambda *a, **k: facts(app_container=True))

    assert receipt["accepted"] is False, "a run inside an AppContainer token was accepted"
    assert any(str(r).startswith("environment: ") and "AppContainer" in str(r) for r in receipt["reasons"])
    environment = receipt.get("environment")
    assert isinstance(environment, dict) and environment["app_container"] is True and environment["problems"]


def test_run_gate_refuses_when_the_environment_preflight_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*args: object, **kwargs: object) -> Any:
        raise RuntimeError("injected: the token could not be queried")

    receipt = gate_with_environment(tmp_path, monkeypatch, broken)

    assert receipt["accepted"] is False, "a run whose environment preflight failed was accepted"
    assert any("environment preflight" in str(r) for r in receipt["reasons"]), receipt["reasons"]
    assert receipt.get("environment", "absent") is None


def test_run_gate_records_a_clean_environment_and_accepts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    receipt = gate_with_environment(tmp_path, monkeypatch, lambda *a, **k: facts())

    environment = receipt.get("environment")
    assert isinstance(environment, dict), "the receipt does not record the acceptance environment"
    assert environment["problems"] == [] and set(environment["paths"]) == set(ROLES)
    assert receipt["accepted"] is True, receipt["reasons"]
