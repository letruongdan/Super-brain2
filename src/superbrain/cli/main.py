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


def _parse_cli_args(args: list[str]) -> tuple[str, list[str]] | None:
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
