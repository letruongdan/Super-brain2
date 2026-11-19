"""Installed ``brain`` CLI wrapper enforcing isolated ``-I`` execution (`T7b.2`)."""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from superbrain.core.errors import ErrorCode

__all__ = ["main"]


def _write_stderr(code: str) -> None:
    try:
        sys.stderr.write(f"{code}\n")
        sys.stderr.flush()
    except OSError:
        pass


def _is_valid_abs_path(raw: str) -> bool:
    if not raw or "\x00" in raw:
        return False
    return Path(raw).is_absolute()


def _parse_review_args(args: list[str]) -> tuple[str, list[str]] | None:
    if args[0] == "review":
        if len(args) < 2:
            return None
        sub = args[1]
        if sub == "list":
            rest = args[2:]
            needs_id = False
        elif sub in ("show", "approve", "reject"):
            rest = args[2:]
            needs_id = True
        else:
            return None
    elif args[0] in ("apply", "rollback"):
        rest = args[1:]
        needs_id = True
    else:
        return None

    has_profile = False
    has_approval = False
    has_json = False
    pos: list[str] = []
    i = 0
    while i < len(rest):
        tok = rest[i]
        if tok == "--json":
            if has_json:
                return None
            has_json = True
            i += 1
        elif tok == "--profile":
            if has_profile or i + 1 >= len(rest) or not _is_valid_abs_path(rest[i + 1]):
                return None
            has_profile = True
            i += 2
        elif tok == "--approval-file":
            if has_approval or i + 1 >= len(rest) or not _is_valid_abs_path(rest[i + 1]):
                return None
            has_approval = True
            i += 2
        elif tok.startswith("-"):
            return None
        else:
            pos.append(tok)
            i += 1

    if not has_profile:
        return None
    if has_approval and args[0] == "review" and args[1] in ("list", "show"):
        return None
    if needs_id and (len(pos) != 1 or not pos[0] or "\x00" in pos[0]):
        return None
    if not needs_id and pos:
        return None
    return ("superbrain.composition.review_cli_entry", args)


def _parse_cli_args(args: list[str]) -> tuple[str, list[str]] | None:
    if not args:
        return None
    if len(args) == 3 and args[0] == "serve" and args[1] == "--config":
        if _is_valid_abs_path(args[2]):
            return ("superbrain.composition.owner_entry", ["serve", "--config", args[2]])
        return None
    if len(args) == 4 and args[0] == "migrate":
        if args[1] == "--offline" and args[2] == "--config" and _is_valid_abs_path(args[3]):
            return ("superbrain.composition.owner_entry", ["migrate", "--offline", "--config", args[3]])
        if args[1] == "--config" and args[3] == "--offline" and _is_valid_abs_path(args[2]):
            return ("superbrain.composition.owner_entry", ["migrate", "--offline", "--config", args[2]])
        return None
    if len(args) == 3 and args[0] == "status" and args[1] == "--profile":
        if _is_valid_abs_path(args[2]):
            return ("superbrain.composition.client_entry", ["status", "--profile", args[2]])
        return None
    if len(args) == 3 and args[0] == "mcp" and args[1] == "--profile":
        if _is_valid_abs_path(args[2]):
            return ("superbrain.composition.shim_entry", ["--profile", args[2]])
        return None
    if len(args) >= 3 and args[0] == "init":
        rest = args[1:]
        reset = "--reset-signers" in rest
        remaining = [a for a in rest if a != "--reset-signers"]
        if len(rest) - len(remaining) > 1 or len(remaining) != 2 or remaining[0] != "--config":
            return None
        if not _is_valid_abs_path(remaining[1]):
            return None
        forwarded = ["init", *(["--reset-signers"] if reset else []), "--config", remaining[1]]
        return ("superbrain.composition.init_entry", forwarded)
    if args[0] in ("review", "apply", "rollback"):
        return _parse_review_args(args)
    return None


def main(argv: Sequence[str] | None = None) -> int:
    """Validate CLI arguments and launch the target composition module under ``python -I``."""
    raw_args = list(sys.argv[1:] if argv is None else argv)
    parsed = _parse_cli_args(raw_args)
    if parsed is None:
        _write_stderr(ErrorCode.INVALID_INPUT.value)
        return 2

    target_module, target_args = parsed
    cmd = [sys.executable, "-I", "-m", target_module, *target_args]
    with contextlib.suppress(OSError):
        sys.stdout.flush()
        sys.stderr.flush()

    if os.sep != "\\":
        try:
            os.execv(sys.executable, cmd)
        except OSError:
            _write_stderr(ErrorCode.IO_ERROR.value)
            return 1

    saved_handlers: list[tuple[signal.Signals, Any]] = []
    for sig_name in ("SIGINT", "SIGBREAK"):
        sig = getattr(signal, sig_name, None)
        if isinstance(sig, signal.Signals):
            try:
                prev = signal.signal(sig, signal.SIG_IGN)
                saved_handlers.append((sig, prev))
            except (OSError, ValueError):
                pass
    try:
        try:
            proc = subprocess.Popen(cmd, shell=False)
        except OSError:
            _write_stderr(ErrorCode.IO_ERROR.value)
            return 1
        while True:
            try:
                return int(proc.wait())
            except KeyboardInterrupt:
                continue
    finally:
        for sig, prev in saved_handlers:
            with contextlib.suppress(OSError, ValueError):
                signal.signal(sig, prev)


if __name__ == "__main__":
    raise SystemExit(main())
