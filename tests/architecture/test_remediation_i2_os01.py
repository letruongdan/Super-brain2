"""AST architecture guard for I2-OS-01: no OS-dependent branching outside ``superbrain.adapters.os``."""

from __future__ import annotations

import ast
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from tests.architecture.test_imports import make_package

SRC = Path(__file__).resolve().parents[2] / "src"

FORBIDDEN_MODULES: frozenset[str] = frozenset(
    {
        "platform",
        "msvcrt",
        "fcntl",
        "winreg",
        "ctypes",
        "pywintypes",
        "ntsecuritycon",
    }
)

FORBIDDEN_MODULE_ATTRS: Mapping[str, frozenset[str]] = {
    "sys": frozenset({"platform", "getwindowsversion"}),
    "os": frozenset({"name"}),
    "tempfile": frozenset({"gettempdir", "gettempdirb"}),
}


@dataclass(frozen=True, order=True)
class OsBoundaryViolation:
    rel_path: str
    lineno: int
    symbol: str


def _is_forbidden_module(top_level_name: str) -> bool:
    return top_level_name in FORBIDDEN_MODULES or top_level_name.startswith("win32")


def _is_os_adapter_path(root: Path, path: Path) -> bool:
    parts = path.relative_to(root).parts
    return len(parts) >= 2 and parts[0] == "adapters" and parts[1] == "os"


def _scan_file(root: Path, path: Path) -> list[OsBoundaryViolation]:
    rel = path.relative_to(root).as_posix()
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[OsBoundaryViolation] = set()
    module_aliases: dict[str, set[str]] = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if _is_forbidden_module(top):
                    found.add(OsBoundaryViolation(rel, node.lineno, f"import {alias.name}"))
                if alias.name in FORBIDDEN_MODULE_ATTRS:
                    local = alias.asname or alias.name
                    module_aliases.setdefault(local, set()).add(alias.name)
                elif alias.asname is None and top in FORBIDDEN_MODULE_ATTRS:
                    module_aliases.setdefault(top, set()).add(top)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            top = node.module.split(".")[0]
            if _is_forbidden_module(top):
                found.add(OsBoundaryViolation(rel, node.lineno, f"from {node.module} import ..."))
            if node.module in FORBIDDEN_MODULE_ATTRS:
                forbidden_attrs = FORBIDDEN_MODULE_ATTRS[node.module]
                for alias in node.names:
                    if alias.name in forbidden_attrs or alias.name == "*":
                        found.add(OsBoundaryViolation(rel, node.lineno, f"from {node.module} import {alias.name}"))

    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            for target_mod in module_aliases.get(node.value.id, ()):
                if node.attr in FORBIDDEN_MODULE_ATTRS[target_mod]:
                    found.add(OsBoundaryViolation(rel, node.lineno, f"{target_mod}.{node.attr}"))
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and len(node.args) >= 2
            and isinstance(node.args[0], ast.Name)
            and isinstance(node.args[1], ast.Constant)
            and isinstance(node.args[1].value, str)
        ):
            attr_name = node.args[1].value
            for target_mod in module_aliases.get(node.args[0].id, ()):
                if attr_name in FORBIDDEN_MODULE_ATTRS[target_mod]:
                    found.add(OsBoundaryViolation(rel, node.lineno, f"{target_mod}.{attr_name}"))

    return sorted(found)


def find_os_boundary_violations(root: Path) -> list[OsBoundaryViolation]:
    """Scan every ``.py`` file under ``root`` except ``adapters/os/**`` for OS-branching imports/reads."""
    violations: list[OsBoundaryViolation] = []
    for path in sorted(root.rglob("*.py")):
        if _is_os_adapter_path(root, path):
            continue
        violations.extend(_scan_file(root, path))
    return sorted(violations)


def test_no_os_branching_outside_os_adapters() -> None:
    violations = find_os_boundary_violations(SRC / "superbrain")
    formatted = "\n".join(f"  {v.rel_path}:{v.lineno}: {v.symbol}" for v in violations)
    assert violations == [], f"OS-dependent symbols outside superbrain.adapters.os:\n{formatted}"


def test_scanner_catches_top_level_and_nested_platform_attributes(tmp_path: Path) -> None:
    pkg = make_package(
        tmp_path,
        {
            "superbrain/storage/top_sys.py": "import sys\nIS_MAC = sys.platform == 'darwin'\n",
            "superbrain/storage/nested_alias.py": (
                "def f() -> tuple[str, object]:\n"
                "    import sys as _s\n"
                "    import os as _o\n"
                "    return _o.name, _s.getwindowsversion()\n"
            ),
            "superbrain/storage/from_imports.py": (
                "from os import name as os_name\n"
                "def g() -> str:\n"
                "    from sys import platform\n"
                "    from tempfile import gettempdir, gettempdirb\n"
                "    _ = (os_name, gettempdirb)\n"
                "    return platform + gettempdir()\n"
            ),
            "superbrain/storage/temp_attr.py": (
                "import tempfile\n"
                "import sys\n"
                "P = tempfile.gettempdir()\n"
                "B = tempfile.gettempdirb()\n"
                "D = getattr(sys, 'platform')\n"
            ),
        },
    )
    violations = find_os_boundary_violations(pkg / "superbrain")
    by_file_and_symbol = {(v.rel_path, v.symbol) for v in violations}
    assert by_file_and_symbol == {
        ("storage/top_sys.py", "sys.platform"),
        ("storage/nested_alias.py", "os.name"),
        ("storage/nested_alias.py", "sys.getwindowsversion"),
        ("storage/from_imports.py", "from os import name"),
        ("storage/from_imports.py", "from sys import platform"),
        ("storage/from_imports.py", "from tempfile import gettempdir"),
        ("storage/from_imports.py", "from tempfile import gettempdirb"),
        ("storage/temp_attr.py", "tempfile.gettempdir"),
        ("storage/temp_attr.py", "tempfile.gettempdirb"),
        ("storage/temp_attr.py", "sys.platform"),
    }


def test_scanner_catches_forbidden_os_modules_at_any_depth(tmp_path: Path) -> None:
    pkg = make_package(
        tmp_path,
        {
            "superbrain/domain/mods.py": (
                "from typing import TYPE_CHECKING\n"
                "import platform\n"
                "if TYPE_CHECKING:\n"
                "    import winreg\n"
                "    import pywintypes\n"
                "    import ntsecuritycon\n"
                "def lock_it() -> None:\n"
                "    import msvcrt\n"
                "    import fcntl\n"
                "    import ctypes.wintypes\n"
                "    import win32security\n"
                "    from win32api import GetLastError\n"
                "    _ = (platform, msvcrt, fcntl, ctypes, win32security, GetLastError)\n"
            ),
        },
    )
    symbols = {v.symbol for v in find_os_boundary_violations(pkg / "superbrain")}
    assert symbols == {
        "import platform",
        "import winreg",
        "import pywintypes",
        "import ntsecuritycon",
        "import msvcrt",
        "import fcntl",
        "import ctypes.wintypes",
        "import win32security",
        "from win32api import ...",
    }


def test_scanner_allows_os_adapters_and_non_platform_stdlib_uses(tmp_path: Path) -> None:
    pkg = make_package(
        tmp_path,
        {
            "superbrain/adapters/os/__init__.py": (
                "import os\n"
                "import sys\n"
                "import tempfile\n"
                "X = (sys.platform, os.name, tempfile.gettempdir())\n"
            ),
            "superbrain/adapters/os/win.py": (
                "import ctypes\n"
                "import msvcrt\n"
                "import win32security\n"
                "import ntsecuritycon\n"
                "import pywintypes\n"
            ),
            "superbrain/core/faults.py": (
                "import os\n"
                "import sys\n"
                "import tempfile\n"
                "from pathlib import Path\n"
                "def info(p: Path) -> tuple[object, str, str]:\n"
                "    _ = tempfile.SpooledTemporaryFile\n"
                "    return sys.exc_info(), os.fspath(p), p.name\n"
            ),
        },
    )
    assert find_os_boundary_violations(pkg / "superbrain") == []
