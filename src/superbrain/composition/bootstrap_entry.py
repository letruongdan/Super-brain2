"""Composition entrypoint for ``brain bootstrap`` (spec 11.3, D3, I3-5)."""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from superbrain.composition._operator_client import call_operator_from_profile, write_error_code
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.os import OsAdapters

__all__ = ["main", "run_bootstrap_cli"]


@dataclass(frozen=True)
class _ParsedBootstrapCli:
    harness: str
    checkout_root: Path
    profile_path: Path
    as_json: bool


def _is_abs(raw: str) -> bool:
    return bool(raw) and "\x00" not in raw and Path(raw).is_absolute() and ".." not in Path(raw).parts


def _parse_args(args: list[str]) -> _ParsedBootstrapCli | None:
    if not args or args[0] != "bootstrap":
        return None
    harness: str | None = None
    checkout_raw: str | None = None
    profile_raw: str | None = None
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
            if checkout_raw is not None or i + 1 >= len(args) or not _is_abs(args[i + 1]):
                return None
            checkout_raw = args[i + 1]
            i += 2
        elif tok == "--profile":
            if profile_raw is not None or i + 1 >= len(args) or not _is_abs(args[i + 1]):
                return None
            profile_raw = args[i + 1]
            i += 2
        else:
            return None
    if harness is None or checkout_raw is None or profile_raw is None:
        return None
    return _ParsedBootstrapCli(
        harness=harness,
        checkout_root=Path(checkout_raw),
        profile_path=Path(profile_raw),
        as_json=as_json,
    )


def run_bootstrap_cli(args: list[str], *, os_: OsAdapters | None = None) -> int:
    parsed = _parse_args(args)
    if parsed is None:
        write_error_code(ErrorCode.INVALID_INPUT)
        return 2
    try:
        result = call_operator_from_profile(
            parsed.profile_path,
            "/v2/operator/proposal/bootstrap",
            {
                "harness": parsed.harness,
                "checkout_root": str(parsed.checkout_root),
                "profile_path": str(parsed.profile_path),
            },
            os_=os_,
        )
    except BrainError as err:
        write_error_code(err.code)
        return 1

    if result.get("ok") is not True:
        err_obj = result.get("error")
        code_str = err_obj.get("code") if isinstance(err_obj, dict) else ErrorCode.IO_ERROR.value
        write_error_code(str(code_str))
        return 1
    payload = result if parsed.as_json else result.get("data", {})
    sys.stdout.write(json.dumps(payload, sort_keys=True) + "\n")
    sys.stdout.flush()
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    return run_bootstrap_cli(raw)


if __name__ == "__main__":
    raise SystemExit(main())
