"""Architecture guardrails: layer rules (spec 4.2), checked on every import at any depth."""

from __future__ import annotations

import ast
import warnings
from collections.abc import Iterator, Mapping
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src"
ROOT = "superbrain"

_RULES: dict[str, frozenset[str]] = {
    "core": frozenset(),
    "ports": frozenset({"core"}),
    "storage": frozenset({"ports", "core"}),
    "adapters": frozenset({"ports", "core"}),
    "domain": frozenset({"ports", "core", "domain"}),
    "application": frozenset({"domain", "ports", "core"}),
    "mcp": frozenset({"application", "core"}),
    "cli_api": frozenset({"application", "core"}),
    "review_web": frozenset({"application", "core"}),
    "workers": frozenset({"application", "core"}),
    "cli": frozenset({"core"}),
}
ALL_LAYERS = frozenset(_RULES) | {"composition"}
LAYER_RULES: dict[str, frozenset[str]] = {**_RULES, "composition": ALL_LAYERS - {"composition"}}


def make_package(base: Path, files: Mapping[str, str]) -> Path:
    """Write ``files`` (relative path -> source) under ``base`` and return ``base``."""
    for rel, source in files.items():
        target = base / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source, encoding="utf-8")
    return base


def _module_name(root: Path, path: Path) -> str:
    parts = list(path.relative_to(root.parent).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _imports(root: Path, path: Path) -> Iterator[str]:
    """Yield every absolute imported name that starts with ``superbrain.`` (any depth, relative resolved)."""
    module = _module_name(root, path)
    package = module if path.name == "__init__.py" else module.rpartition(".")[0]
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base_parts = package.split(".")
                base_parts = base_parts[: len(base_parts) - (node.level - 1)]
                base = ".".join(base_parts)
                target = f"{base}.{node.module}" if node.module else base
            else:
                target = node.module or ""
            for alias in node.names:
                yield f"{target}.{alias.name}"
            yield target


def _layer(name: str) -> str | None:
    parts = name.split(".")
    if len(parts) < 2 or parts[0] != ROOT:
        return None
    return parts[1]


def _edges(root: Path) -> set[tuple[str, str]]:
    edges: set[tuple[str, str]] = set()
    for path in sorted(root.rglob("*.py")):
        module = _module_name(root, path)
        for imported in _imports(root, path):
            if imported.startswith(f"{ROOT}."):
                edges.add((module, imported))
    return edges


def find_violations(root: Path, rules: Mapping[str, frozenset[str]]) -> list[tuple[str, str]]:
    """Return (importer, imported) pairs where the importer's layer may not import the imported layer."""
    violations: list[tuple[str, str]] = []
    for module, imported in sorted(_edges(root)):
        source, target = _layer(module), _layer(imported)
        if source is None or target is None or source == target:
            continue
        if target not in rules.get(source, frozenset()):
            violations.append((module, imported))
    # `from pkg import name` yields both pkg.name and pkg; keep only the most specific per importer/layer.
    best: dict[tuple[str, str | None], tuple[str, str]] = {}
    for module, imported in violations:
        key = (module, _layer(imported))
        if key not in best or len(imported) > len(best[key][1]):
            best[key] = (module, imported)
    return sorted(best.values())


def find_package_cycles(root: Path) -> list[list[str]]:
    """Return import cycles between Python packages (directories with ``__init__.py``).

    Each module maps to the package containing it; edges inside one package are ignored.
    """
    modules = {_module_name(root, p): p.name == "__init__.py" for p in root.rglob("*.py")}

    def package_of(name: str) -> str | None:
        parts = name.split(".")
        for end in range(len(parts), 0, -1):
            candidate = ".".join(parts[:end])
            if candidate in modules:
                return candidate if modules[candidate] else candidate.rpartition(".")[0]
        return None

    graph: dict[str, set[str]] = {}
    for module, imported in _edges(root):
        source, target = package_of(module), package_of(imported)
        if source is None or target is None or source == target:
            continue
        graph.setdefault(source, set()).add(target)
    cycles: list[list[str]] = []
    done: set[str] = set()

    def visit(node: str, stack: list[str]) -> None:
        if node in stack:
            cycles.append([*stack[stack.index(node) :], node])
            return
        if node in done:
            return
        for nxt in sorted(graph.get(node, ())):
            visit(nxt, [*stack, node])
        done.add(node)

    for start in sorted(graph):
        visit(start, [])
    return cycles


def files_over(root: Path, limit: int) -> list[tuple[Path, int]]:
    result: list[tuple[Path, int]] = []
    for path in sorted(root.rglob("*.py")):
        count = len(path.read_text(encoding="utf-8").splitlines())
        if count > limit:
            result.append((path, count))
    return result


def test_every_import_including_function_level_respects_layers() -> None:
    assert find_violations(SRC / "superbrain", LAYER_RULES) == []


def test_checker_detects_function_level_upward_import(tmp_path: Path) -> None:
    pkg = make_package(
        tmp_path,
        {"superbrain/core/a.py": "def f():\n    import superbrain.storage.x\n", "superbrain/storage/x.py": ""},
    )
    assert find_violations(pkg / "superbrain", LAYER_RULES) == [("superbrain.core.a", "superbrain.storage.x")]


def test_checker_detects_relative_and_type_checking_imports(tmp_path: Path) -> None:
    pkg = make_package(
        tmp_path,
        {
            "superbrain/storage/a.py": (
                "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from ..adapters import b\n"
            ),
            "superbrain/adapters/b.py": "",
        },
    )
    assert find_violations(pkg / "superbrain", LAYER_RULES) == [("superbrain.storage.a", "superbrain.adapters.b")]


def test_package_graph_is_acyclic() -> None:
    assert find_package_cycles(SRC / "superbrain") == []


def test_report_files_over_600_lines() -> None:
    for path, count in files_over(SRC, 600):
        warnings.warn(f"{path} has {count} lines (>600)", stacklevel=1)


def test_checker_detects_cycle_between_packages_in_one_layer(tmp_path: Path) -> None:
    pkg = make_package(
        tmp_path,
        {
            "superbrain/__init__.py": "",
            "superbrain/domain/__init__.py": "",
            "superbrain/domain/a/__init__.py": "",
            "superbrain/domain/a/x.py": "from superbrain.domain.b import y\n",
            "superbrain/domain/b/__init__.py": "",
            "superbrain/domain/b/y.py": "def f():\n    import superbrain.domain.a.x\n",
        },
    )
    assert find_package_cycles(pkg / "superbrain") == [
        ["superbrain.domain.a", "superbrain.domain.b", "superbrain.domain.a"]
    ]


def test_checker_reports_no_cycle_for_one_way_package_import(tmp_path: Path) -> None:
    pkg = make_package(
        tmp_path,
        {
            "superbrain/__init__.py": "",
            "superbrain/domain/__init__.py": "",
            "superbrain/domain/a/__init__.py": "",
            "superbrain/domain/a/x.py": "from superbrain.domain.b import y\n",
            "superbrain/domain/b/__init__.py": "",
            "superbrain/domain/b/y.py": "from superbrain.domain.b import z\n",
            "superbrain/domain/b/z.py": "",
        },
    )
    assert find_package_cycles(pkg / "superbrain") == []


FAULT_FREE_ENTRIES = ("mcp", "cli", "composition/shim_entry.py", "composition/client_entry.py")
"""Client-side code: no crash or pause hook may be reachable from these files, however it is spelled."""
FAULT_MODULE = f"{ROOT}.core.faults"
FAULT_STRINGS = (FAULT_MODULE, "SUPERBRAIN_CRASHPOINT", "SUPERBRAIN_PAUSEPOINT")


def find_fault_hooks(root: Path, entries: tuple[str, ...] = FAULT_FREE_ENTRIES) -> list[tuple[str, str]]:
    """``(file, evidence)`` for every import of ``superbrain.core.faults`` (any depth, relative or aliased) and every
    string literal naming that module or a fault-injection variable, in the files under ``entries``."""
    found: set[tuple[str, str]] = set()
    for entry in entries:
        target = root / entry
        assert target.exists(), f"fault-free entry {entry} does not exist under {root}"
        for path in sorted(target.rglob("*.py")) if target.is_dir() else [target]:
            rel = path.relative_to(root).as_posix()
            for imported in _imports(root, path):
                if imported == FAULT_MODULE or imported.startswith(f"{FAULT_MODULE}."):
                    found.add((rel, imported))
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"), filename=str(path))):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    if any(marker in node.value for marker in FAULT_STRINGS):
                        found.add((rel, node.value))
    return sorted(found)


def test_crash_hooks_stay_out_of_client_entrypoints() -> None:
    assert find_fault_hooks(SRC / ROOT) == []
    assert find_fault_hooks(SRC / ROOT, ("storage",)), "the scanner must see the hooks the storage layer does call"


def test_fault_hook_scanner_catches_aliases_relative_and_dynamic_imports(tmp_path: Path) -> None:
    pkg = make_package(
        tmp_path,
        {
            "superbrain/mcp/a.py": "from superbrain.core import faults as hooks\n",
            "superbrain/mcp/deep/b.py": "def f():\n    import os\n    return os.environ.get('SUPERBRAIN_PAUSEPOINT')\n",
            "superbrain/cli/c.py": "from ..core.faults import crashpoint as cp\n",
            "superbrain/composition/shim_entry.py": "import superbrain.core.faults as x\n",
            "superbrain/composition/client_entry.py": (
                "import importlib\nm = importlib.import_module('superbrain.core.faults')\n"
            ),
            "superbrain/composition/daemon_entry.py": "from superbrain.core.faults import crashpoint\n",
            "superbrain/storage/x.py": "from superbrain.core.faults import crashpoint\n",
            "superbrain/core/faults.py": "def crashpoint(name):\n    pass\n",
        },
    )
    assert find_fault_hooks(pkg / ROOT) == [
        ("cli/c.py", "superbrain.core.faults"),
        ("cli/c.py", "superbrain.core.faults.crashpoint"),
        ("composition/client_entry.py", "superbrain.core.faults"),
        ("composition/shim_entry.py", "superbrain.core.faults"),
        ("mcp/a.py", "superbrain.core.faults"),
        ("mcp/deep/b.py", "SUPERBRAIN_PAUSEPOINT"),
    ]
