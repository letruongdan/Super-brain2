"""Composition entrypoint for strictly read-only ``brain doctor`` (spec 13, 14.2, I3-5)."""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.daemon_config import read_client_profile, read_daemon_config
from superbrain.application.doctor import DoctorReport, format_doctor_text, inspect_doctor_snapshot
from superbrain.composition._operator_client import write_error_code
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.os import OsAdapters
from superbrain.storage._doctor_reader import read_doctor_snapshot

__all__ = ["main", "run_doctor", "run_doctor_cli"]


@dataclass(frozen=True)
class _ParsedDoctorCli:
    source_path: Path
    is_profile: bool
    checkout_root: Path | None
    as_json: bool


def _is_abs(raw: str) -> bool:
    return bool(raw) and "\x00" not in raw and Path(raw).is_absolute() and ".." not in Path(raw).parts


def _parse_args(args: list[str]) -> _ParsedDoctorCli | None:
    if not args or args[0] != "doctor":
        return None
    config_raw: str | None = None
    profile_raw: str | None = None
    checkout_raw: str | None = None
    as_json = False
    i = 1
    while i < len(args):
        tok = args[i]
        if tok == "--json":
            if as_json:
                return None
            as_json = True
            i += 1
        elif tok == "--config":
            if config_raw is not None or profile_raw is not None or i + 1 >= len(args) or not _is_abs(args[i + 1]):
                return None
            config_raw = args[i + 1]
            i += 2
        elif tok == "--profile":
            if profile_raw is not None or config_raw is not None or i + 1 >= len(args) or not _is_abs(args[i + 1]):
                return None
            profile_raw = args[i + 1]
            i += 2
        elif tok == "--checkout":
            if checkout_raw is not None or i + 1 >= len(args) or not _is_abs(args[i + 1]):
                return None
            checkout_raw = args[i + 1]
            i += 2
        else:
            return None
    if config_raw is None and profile_raw is None:
        return None
    return _ParsedDoctorCli(
        source_path=Path(profile_raw if profile_raw is not None else str(config_raw)),
        is_profile=profile_raw is not None,
        checkout_root=Path(checkout_raw) if checkout_raw is not None else None,
        as_json=as_json,
    )


def run_doctor(
    config_or_profile_path: Path,
    *,
    checkout_root: Path | None = None,
    is_profile: bool = False,
    os_: OsAdapters | None = None,
) -> DoctorReport:
    """Inspect storage + checkout state strictly read-only and return a ``DoctorReport``."""
    adapters = os_ if os_ is not None else os_adapters()
    if is_profile:
        profile = read_client_profile(config_or_profile_path, adapters)
        data_root = profile.endpoint_path.parent
        expected_store_id = profile.expected_store_id
        resolved_checkout = checkout_root if checkout_root is not None else (
            profile.workspace.checkout_path if profile.workspace is not None else None
        )
    else:
        cfg = read_daemon_config(config_or_profile_path, adapters)
        data_root = cfg.data_root
        expected_store_id = cfg.expected_store_id
        resolved_checkout = checkout_root
    if resolved_checkout is not None:
        adapters.paths.reject_unsafe_path(str(resolved_checkout))
        if not resolved_checkout.is_absolute():
            raise BrainError(ErrorCode.INVALID_INPUT, "checkout must be absolute")
        if os.path.lexists(resolved_checkout):
            adapters.paths.reject_links(resolved_checkout)
    snapshot = read_doctor_snapshot(
        data_root,
        adapters,
        checkout_root=resolved_checkout,
        expected_store_id=expected_store_id,
    )
    return inspect_doctor_snapshot(snapshot)


def run_doctor_cli(args: list[str], *, os_: OsAdapters | None = None) -> int:
    parsed = _parse_args(args)
    if parsed is None:
        write_error_code(ErrorCode.INVALID_INPUT)
        return 2
    try:
        report = run_doctor(
            parsed.source_path,
            checkout_root=parsed.checkout_root,
            is_profile=parsed.is_profile,
            os_=os_,
        )
    except BrainError as err:
        write_error_code(err.code)
        return 1
    if parsed.as_json:
        sys.stdout.write(json.dumps({"ok": True, "data": report.to_dict()}, sort_keys=True) + "\n")
    else:
        sys.stdout.write(format_doctor_text(report))
    sys.stdout.flush()
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    return run_doctor_cli(raw)


if __name__ == "__main__":
    raise SystemExit(main())
