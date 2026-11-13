"""T8-W01-F2: only the owner path sets ``CallContext.canonical_payload``, from the bytes it has just verified.

Requirement (C3:92, review ruling W01 lens 6): the request digest covers exactly the bytes verified against the
dispatched call. Dispatch trusts ``ctx.canonical_payload`` without comparing again, so the invariant rests on the code
structure, pinned here over the AST of ``src``:

* exactly one ``CallContext(...)`` call in ``src`` passes ``canonical_payload`` (by keyword; no call passes six or
  more positional arguments), in ``superbrain/application/deadlines.py``;
* its value is ``X.canonical_payload`` where ``X`` is the same name passed to ``reconstruct_queued_call(X)`` earlier in
  the same function;
* no ``replace(...)`` / ``dataclasses.replace(...)`` call passes ``canonical_payload`` or takes a ``CallContext``
  (a name assigned from ``CallContext(...)`` or a parameter annotated ``CallContext``) as its first argument.
"""

from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src"
OWNER_FILE = "superbrain/application/deadlines.py"


def _name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _ctx_names(func: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    names = {a.arg for a in (*func.args.posonlyargs, *func.args.args, *func.args.kwonlyargs)
             if a.annotation is not None and "CallContext" in ast.unparse(a.annotation)}  # fmt: skip
    for node in ast.walk(func):
        if (
            isinstance(node, ast.Assign)
            and isinstance(node.value, ast.Call)
            and _name(node.value.func) == "CallContext"
        ):
            names |= {t.id for t in node.targets if isinstance(t, ast.Name)}
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if "CallContext" in ast.unparse(node.annotation):
                names.add(node.target.id)
    return names


def violations(root: Path) -> list[str]:
    """Every breach of the invariant under ``root`` (a ``src`` directory); empty when it holds."""
    found: list[str] = []
    sites: list[tuple[str, int]] = []
    for path in sorted(root.rglob("*.py")):
        rel = path.relative_to(root).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=rel)
        funcs = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)]
        for func in funcs:
            ctx_names = _ctx_names(func)
            reconstructed = [
                (n.lineno, n.args[0].id)
                for n in ast.walk(func)
                if isinstance(n, ast.Call) and _name(n.func) == "reconstruct_queued_call"
                and n.args and isinstance(n.args[0], ast.Name)
            ]  # fmt: skip
            for node in ast.walk(func):
                if not isinstance(node, ast.Call):
                    continue
                callee = _name(node.func)
                keyword = next((k for k in node.keywords if k.arg == "canonical_payload"), None)
                if callee == "CallContext":
                    if len(node.args) >= 6:
                        found.append(f"{rel}:{node.lineno}: CallContext with positional canonical_payload")
                    if keyword is None:
                        continue
                    sites.append((rel, node.lineno))
                    value = keyword.value
                    if rel != OWNER_FILE:
                        found.append(f"{rel}:{node.lineno}: CallContext(canonical_payload=...) outside {OWNER_FILE}")
                    elif not (
                        isinstance(value, ast.Attribute)
                        and value.attr == "canonical_payload"
                        and isinstance(value.value, ast.Name)
                        and any(line < node.lineno and name == value.value.id for line, name in reconstructed)
                    ):
                        found.append(f"{rel}:{node.lineno}: canonical_payload is not the reconstructed bytes")
                if callee == "replace":
                    if keyword is not None:
                        found.append(f"{rel}:{node.lineno}: replace(..., canonical_payload=...)")
                    if node.args and isinstance(node.args[0], ast.Name) and node.args[0].id in ctx_names:
                        found.append(f"{rel}:{node.lineno}: replace() on a CallContext")
    if len(sites) != 1:
        found.append(f"expected exactly one CallContext(canonical_payload=...) site, found {sites}")
    return found


def test_w02_only_the_owner_path_sets_canonical_payload_from_verified_bytes() -> None:
    assert SRC.is_dir()
    assert violations(SRC) == []


def _tree(tmp: Path, files: dict[str, str]) -> Path:
    for rel, body in files.items():
        target = tmp / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
    return tmp


_OWNER_OK = """
def process(queued):
    call = reconstruct_queued_call(queued)
    ctx = CallContext(
        principal=p, identity=i, deadline_ns=1, selected_scope=None, canonical_payload=queued.canonical_payload
    )
"""


def test_w02_checker_accepts_the_owner_shape(tmp_path: Path) -> None:
    assert violations(_tree(tmp_path, {OWNER_FILE: _OWNER_OK})) == []


def test_w02_checker_refuses_breaches(tmp_path: Path) -> None:
    # Positive twins of the test above: each breach alone must be reported.
    cases = {
        "second-site": {OWNER_FILE: _OWNER_OK, "superbrain/application/dispatch.py":
                        "def f(c):\n    return CallContext(canonical_payload=b'x')\n"},
        "other-bytes": {OWNER_FILE: _OWNER_OK.replace("queued.canonical_payload", "other.canonical_payload")},
        "not-reconstructed": {OWNER_FILE: _OWNER_OK.replace("reconstruct_queued_call(queued)", "parse(queued)")},
        "positional": {OWNER_FILE: _OWNER_OK + "\ndef g():\n    CallContext(1, 2, 3, 4, 5, b'x')\n"},
        "replace-ctx": {OWNER_FILE: _OWNER_OK + "\ndef h(ctx: CallContext):\n    return replace(ctx, deadline_ns=2)\n"},
        "replace-kw": {OWNER_FILE: _OWNER_OK + "\ndef k(x):\n    return dataclasses.replace(x, canonical_payload=b)\n"},
        "no-site": {OWNER_FILE: "def process(queued):\n    return reconstruct_queued_call(queued)\n"},
    }  # fmt: skip
    for name, files in cases.items():
        root = tmp_path / name
        assert violations(_tree(root, files)), f"breach {name!r} not reported"
