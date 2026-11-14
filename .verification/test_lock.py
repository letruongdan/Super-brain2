"""Seal/check test inputs against an independently retained manifest digest.

This is tamper evidence, not an OS permission boundary or a concurrent writer lock.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys


CACHE_DIRS = {"__pycache__", ".pytest_cache", ".git"}


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def checked(path: Path) -> Path:
    """Keep lexical paths until every existing component has passed lstat."""
    path = Path(os.path.abspath(path))
    for part in (*reversed(path.parents), path):
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & getattr(
            stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400
        ):
            raise ValueError(f"Linked/reparse path refused: {part}")
        if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            raise ValueError(f"Regular file/directory required: {part}")
    return path


def selected_paths(root: Path, selectors: list[str]) -> list[Path]:
    if not isinstance(selectors, list) or not selectors:
        raise ValueError("Select at least one test input")
    paths = []
    for selector in selectors:
        if not isinstance(selector, str) or not selector:
            raise ValueError("Nonempty relative selectors required")
        relative = Path(selector)
        if relative.is_absolute() or relative.drive or ".." in relative.parts:
            raise ValueError(f"Relative selector within root required: {selector}")
        path = checked(root / relative)
        if not path.is_relative_to(root) or not path.exists():
            raise ValueError(f"Existing input within root required: {selector}")
        paths.append(path)
    return paths


def snapshot(root: Path, selectors: list[str]) -> dict:
    paths = selected_paths(root, selectors)
    files = {}

    def visit(path: Path):
        checked(path)
        if path.is_dir():
            if path.name in CACHE_DIRS:
                return
            for child in sorted(path.iterdir()):
                visit(child)
        elif path.suffix != ".pyc":
            files[path.relative_to(root).as_posix()] = digest(path.read_bytes())

    for path in paths:
        visit(path)
    if not files:
        raise ValueError("No non-cache input files selected")
    return {
        "schema_version": "1.0",
        "selectors": sorted({path.relative_to(root).as_posix() for path in paths}),
        "files": dict(sorted(files.items())),
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    seal = commands.add_parser("seal", help="Independent test author freezes the oracle inputs")
    seal.add_argument("--root", type=Path, required=True)
    seal.add_argument("--path", dest="selectors", action="append", required=True)
    seal.add_argument("--output", type=Path, required=True)
    check = commands.add_parser("check", help="Verify against the reviewer's retained digest")
    check.add_argument("--root", type=Path, required=True)
    check.add_argument("--manifest", type=Path, required=True)
    check.add_argument("--expected-digest", required=True)
    args = parser.parse_args(argv)
    try:
        root = checked(args.root)
        if not root.is_dir():
            raise ValueError("Existing project root required")
        if args.command == "seal":
            output = checked(args.output)
            for path in selected_paths(root, args.selectors):
                if output == path or (path.is_dir() and output.is_relative_to(path)):
                    raise ValueError("Manifest output must be outside selected inputs")
            data = snapshot(root, args.selectors)
            raw = (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8")
            output.parent.mkdir(parents=True, exist_ok=True)
            with output.open("xb") as stream:
                stream.write(raw)
        else:
            raw = checked(args.manifest).read_bytes()
            if digest(raw) != args.expected_digest:
                raise ValueError("Manifest digest differs from independently retained digest")
            data = json.loads(raw)
            if not isinstance(data, dict) or snapshot(root, data.get("selectors")) != data:
                raise ValueError("Test input set/content differs from the frozen manifest")
        print(json.dumps({"ok": True, "manifest_digest": digest(raw), "files": len(data["files"])}))
        return 0
    except (OSError, ValueError, TypeError) as error:
        print(json.dumps({"ok": False, "error": str(error)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
