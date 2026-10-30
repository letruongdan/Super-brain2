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
    """Return cycles in the top-level package (layer) import graph."""
    graph: dict[str, set[str]] = {}
    for module, imported in _edges(root):
        source, target = _layer(module), _layer(imported)
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
