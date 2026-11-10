"""Isolated owner CLI entrypoint for ``serve`` and ``migrate --offline`` (`T7b.2`)."""

from __future__ import annotations

import dataclasses
import shutil
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Literal

from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.daemon_config import read_daemon_config
from superbrain.composition.daemon_entry import serve
from superbrain.composition.migrate_entry import migrate_offline
from superbrain.core.canonical import canonical_json
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import DaemonConfig
from superbrain.ports.os import OsAdapters

__all__ = ["main"]


def _write_stderr(code: str) -> None:
    try:
        sys.stderr.write(f"{code}\n")
        sys.stderr.flush()
    except OSError:
        pass


def _parse_owner_args(args: list[str]) -> tuple[Literal["serve", "migrate"], Path] | None:
    if len(args) == 3 and args[0] == "serve" and args[1] == "--config":
        mode: Literal["serve", "migrate"] = "serve"
        raw = args[2]
    elif len(args) == 4 and args[0] == "migrate" and args[1] == "--offline" and args[2] == "--config":
        mode = "migrate"
        raw = args[3]
    elif len(args) == 4 and args[0] == "migrate" and args[1] == "--config" and args[3] == "--offline":
        mode = "migrate"
        raw = args[2]
    else:
        return None
    if not raw or "\x00" in raw:
        return None
    path = Path(raw)
    if not path.is_absolute():
        return None
    return mode, path


def _explicit_owner_adapters(config_path: Path) -> tuple[DaemonConfig, OsAdapters, Path]:
    base_adapters = os_adapters()
    cfg = read_daemon_config(config_path, base_adapters)
    scratch_base = cfg.data_root.parent / f".{cfg.data_root.name}.admit-{new_id()}"
    adapters = dataclasses.replace(
        base_adapters,
        traits=dataclasses.replace(base_adapters.traits, default_scratch_base=scratch_base),
    )
    return cfg, adapters, scratch_base


def _run_serve(config_path: Path) -> int:
    cfg, adapters, scratch_base = _explicit_owner_adapters(config_path)
    try:
        return serve(
            cfg,
            os_=adapters,
            on_ready=lambda _ready, _loop: shutil.rmtree(scratch_base, ignore_errors=True),
        )
    finally:
        shutil.rmtree(scratch_base, ignore_errors=True)


def _run_migrate(config_path: Path) -> int:
    cfg, adapters, scratch_base = _explicit_owner_adapters(config_path)
    try:
        report = migrate_offline(cfg, os_=adapters)
    finally:
        shutil.rmtree(scratch_base, ignore_errors=True)
    envelope: dict[str, JsonValue] = {
        "ok": True,
        "data": {
            "store_id": report.store_id,
            "writer_epoch": report.writer_epoch,
            "noop": report.noop,
            "migrated": not report.noop,
            "store_schema_version": report.store_report.to_version,
            "policy_schema_version": report.policy_report.to_version,
            "policy": {
                "status": report.policy_report.status,
                "from_version": report.policy_report.from_version,
                "to_version": report.policy_report.to_version,
            },
            "store": {
                "status": report.store_report.status,
                "from_version": report.store_report.from_version,
                "to_version": report.store_report.to_version,
            },
        },
    }
    try:
        sys.stdout.buffer.write(canonical_json(envelope) + b"\n")
        sys.stdout.buffer.flush()
    except OSError:
        return 1
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Dispatch ``serve --config <abs>`` or ``migrate --offline --config <abs>``."""
    raw_args = list(sys.argv[1:] if argv is None else argv)
    parsed = _parse_owner_args(raw_args)
    if parsed is None:
        _write_stderr(ErrorCode.INVALID_INPUT.value)
        return 2

    mode, config_path = parsed
    try:
        if mode == "serve":
            return _run_serve(config_path)
        return _run_migrate(config_path)
    except BrainError as err:
        _write_stderr(err.code.value)
        return 1
    except OSError:
        _write_stderr(ErrorCode.IO_ERROR.value)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
