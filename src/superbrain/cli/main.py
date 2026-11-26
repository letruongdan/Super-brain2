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
    if not raw or "\x00" in raw or ".." in Path(raw).parts:
        return False
    return Path(raw).is_absolute()


def _parse_bootstrap_args(args: list[str]) -> tuple[str, list[str]] | None:
    harness: str | None = None
    checkout: str | None = None
    profile: str | None = None
    harness_profile: str | None = None
    as_json = False
    i = 1
    while i < len(args):
        tok = args[i]
        if tok == "--json":
            if as_json:
                return None
            as_json = True
            i += 1
        elif tok == "--harness":
            if harness is not None or i + 1 >= len(args) or args[i + 1] not in ("claude-code", "codex"):
                return None
            harness = args[i + 1]
            i += 2
        elif tok == "--checkout":
            if checkout is not None or i + 1 >= len(args) or not _is_valid_abs_path(args[i + 1]):
                return None
            checkout = args[i + 1]
            i += 2
        elif tok == "--profile":
            if profile is not None or i + 1 >= len(args) or not _is_valid_abs_path(args[i + 1]):
                return None
            profile = args[i + 1]
            i += 2
        elif tok == "--harness-profile":
            if harness_profile is not None or i + 1 >= len(args) or not _is_valid_abs_path(args[i + 1]):
                return None
            harness_profile = args[i + 1]
            i += 2
        else:
            return None
    if harness is None or checkout is None or profile is None or harness_profile is None:
        return None
    return ("superbrain.composition.bootstrap_entry", args)


def _parse_doctor_args(args: list[str]) -> tuple[str, list[str]] | None:
    has_config = False
    has_profile = False
    has_checkout = False
    has_outbox = False
    has_json = False
    i = 1
    while i < len(args):
        tok = args[i]
        if tok == "--json":
            if has_json:
                return None
            has_json = True
            i += 1
        elif tok == "--config":
            if has_config or has_profile or i + 1 >= len(args) or not _is_valid_abs_path(args[i + 1]):
                return None
            has_config = True
            i += 2
        elif tok == "--profile":
            if has_profile or has_config or i + 1 >= len(args) or not _is_valid_abs_path(args[i + 1]):
                return None
            has_profile = True
            i += 2
        elif tok == "--checkout":
            if has_checkout or i + 1 >= len(args) or not _is_valid_abs_path(args[i + 1]):
                return None
            has_checkout = True
            i += 2
        elif tok == "--outbox":
            if has_outbox or i + 1 >= len(args) or not _is_valid_abs_path(args[i + 1]):
                return None
            has_outbox = True
            i += 2
        else:
            return None
    if not has_config and not has_profile:
        return None
    return ("superbrain.composition.doctor_entry", args)


def _parse_review_web_args(args: list[str]) -> tuple[str, list[str]] | None:
    has_profile = False
    has_web = False
    has_action = False
    has_print_url = False
    pos: list[str] = []
    i = 1
    while i < len(args):
        tok = args[i]
        if tok == "--web":
            if has_web:
                return None
            has_web = True
            i += 1
        elif tok == "--print-url-only":
            if has_print_url:
                return None
            has_print_url = True
            i += 1
        elif tok == "--profile":
            if has_profile or i + 1 >= len(args) or not _is_valid_abs_path(args[i + 1]):
                return None
            has_profile = True
            i += 2
        elif tok == "--action":
            if has_action or i + 1 >= len(args) or args[i + 1] not in ("approve", "reject", "apply", "rollback"):
                return None
            has_action = True
            i += 2
        elif tok.startswith("-"):
            return None
        else:
            pos.append(tok)
            i += 1
    if not has_web or not has_profile or len(pos) != 1 or not pos[0] or "\x00" in pos[0]:
        return None
    return ("superbrain.composition.review_web_entry", args)


def _parse_review_args(args: list[str]) -> tuple[str, list[str]] | None:
    if args[0] == "review":
        if "--web" in args[1:]:
            return _parse_review_web_args(args)
        if len(args) < 2:
            return None
        sub = args[1]
        if sub == "list":
            rest = args[2:]
            needs_id = False
        elif sub in ("show", "approve", "reject", "continue"):
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
    if has_approval and args[0] == "review" and args[1] in ("list", "show", "continue"):
        return None
    if needs_id and (len(pos) != 1 or not pos[0] or "\x00" in pos[0]):
        return None
    if not needs_id and pos:
        return None
    return ("superbrain.composition.review_cli_entry", args)


def _parse_restore_args(args: list[str]) -> tuple[str, list[str]] | None:
    rest = args[1:]
    offline = False
    preview = False
    kind: str | None = None
    backup: str | None = None
    approval_file: str | None = None
    config: str | None = None
    i = 0
    while i < len(rest):
        tok = rest[i]
        if tok == "--offline":
            if offline:
                return None
            offline = True
            i += 1
        elif tok == "--preview":
            if preview:
                return None
            preview = True
            i += 1
        elif tok == "--kind":
            if kind is not None or i + 1 >= len(rest) or rest[i + 1] not in ("store", "policy"):
                return None
            kind = rest[i + 1]
            i += 2
        elif tok == "--backup":
            if backup is not None or i + 1 >= len(rest) or not _is_valid_abs_path(rest[i + 1]):
                return None
            backup = rest[i + 1]
            i += 2
        elif tok == "--approval-file":
            if approval_file is not None or i + 1 >= len(rest) or not _is_valid_abs_path(rest[i + 1]):
                return None
            approval_file = rest[i + 1]
            i += 2
        elif tok == "--config":
            if config is not None or i + 1 >= len(rest) or not _is_valid_abs_path(rest[i + 1]):
                return None
            config = rest[i + 1]
            i += 2
        else:
            return None
    if not offline or kind is None or backup is None or config is None:
        return None
    if preview == (approval_file is not None):
        return None
    return ("superbrain.composition.owner_entry", args)


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
    if args and args[0] == "restore":
        return _parse_restore_args(args)
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
    if args[0] == "bootstrap":
        return _parse_bootstrap_args(args)
    if args[0] == "doctor":
        return _parse_doctor_args(args)
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

    if os.sep != "\\" and argv is None:
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
