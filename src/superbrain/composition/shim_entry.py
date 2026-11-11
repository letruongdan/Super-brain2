"""Bound MCP stdio shim entrypoint (`T7b.2`)."""

from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import Path

from superbrain.adapters.os import os_adapters
from superbrain.composition.client_entry import build_tool_caller
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.mcp.stdio import run_stdio

__all__ = ["main"]


def _write_stderr(code: str) -> None:
    try:
        sys.stderr.write(f"{code}\n")
        sys.stderr.flush()
    except OSError:
        pass


def _parse_shim_profile_arg(args: list[str]) -> Path | None:
    if len(args) == 2 and args[0] == "--profile":
        raw = args[1]
    elif len(args) == 3 and args[0] == "mcp" and args[1] == "--profile":
        raw = args[2]
    else:
        return None
    if not raw or "\x00" in raw:
        return None
    path = Path(raw)
    return path if path.is_absolute() else None


def main(argv: Sequence[str] | None = None) -> int:
    """Run ``brain-mcp --profile <abs>`` or ``brain mcp --profile <abs>`` over stdio."""
    raw_args = list(sys.argv[1:] if argv is None else argv)
    profile_path = _parse_shim_profile_arg(raw_args)
    if profile_path is None:
        _write_stderr(ErrorCode.INVALID_INPUT.value)
        return 2

    try:
        launch_cwd = Path.cwd()
        caller = build_tool_caller(profile_path, launch_cwd, os_adapters())
    except BrainError as err:
        _write_stderr(err.code.value)
        return 1
    except OSError:
        _write_stderr(ErrorCode.IO_ERROR.value)
        return 1

    return run_stdio(sys.stdin.buffer, sys.stdout.buffer, caller)


if __name__ == "__main__":
    raise SystemExit(main())
