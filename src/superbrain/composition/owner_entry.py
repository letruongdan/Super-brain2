"""Isolated owner CLI entrypoint for ``serve``, ``migrate --offline``, and ``restore --offline``."""

from __future__ import annotations

import dataclasses
import shutil
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Literal

from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.daemon_config import read_daemon_config
from superbrain.core.canonical import canonical_json
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import DaemonConfig
from superbrain.ports.os import OsAdapters

__all__ = ["main"]


@dataclasses.dataclass(frozen=True)
class _OfflineRestoreArgs:
    kind: Literal["store", "policy"]
    backup: Path
    preview: bool
    approval_file: Path | None
    config: Path


def _is_abs_path(raw: str) -> Path | None:
    if not raw or "\x00" in raw:
        return None
    path = Path(raw)
    return path if path.is_absolute() else None


def _write_stderr(code: str) -> None:
    try:
        sys.stderr.write(f"{code}\n")
        sys.stderr.flush()
    except OSError:
        pass


def _write_stdout_json(envelope: dict[str, JsonValue]) -> int:
    try:
        sys.stdout.buffer.write(canonical_json(envelope) + b"\n")
        sys.stdout.buffer.flush()
    except OSError:
        return 1
    return 0


def _parse_restore_owner_args(rest: list[str]) -> tuple[Literal["restore"], _OfflineRestoreArgs] | None:
    offline = False
    preview = False
    kind: Literal["store", "policy"] | None = None
    backup: Path | None = None
    approval_file: Path | None = None
    config: Path | None = None
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
            kind = "store" if rest[i + 1] == "store" else "policy"
            i += 2
        elif tok == "--backup":
            p = _is_abs_path(rest[i + 1]) if i + 1 < len(rest) else None
            if backup is not None or p is None:
                return None
            backup = p
            i += 2
        elif tok == "--approval-file":
            p = _is_abs_path(rest[i + 1]) if i + 1 < len(rest) else None
            if approval_file is not None or p is None:
                return None
            approval_file = p
            i += 2
        elif tok == "--config":
            p = _is_abs_path(rest[i + 1]) if i + 1 < len(rest) else None
            if config is not None or p is None:
                return None
            config = p
            i += 2
        else:
            return None
    if not offline or kind is None or backup is None or config is None or preview == (approval_file is not None):
        return None
    return "restore", _OfflineRestoreArgs(
        kind=kind, backup=backup, preview=preview, approval_file=approval_file, config=config
    )


def _parse_owner_args(
    args: list[str],
) -> tuple[Literal["serve", "migrate"], Path] | tuple[Literal["restore"], _OfflineRestoreArgs] | None:
    if args and args[0] == "restore":
        return _parse_restore_owner_args(args[1:])
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
    path = _is_abs_path(raw)
    if path is None:
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
    from superbrain.composition.daemon_entry import serve

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
    from superbrain.composition.migrate_entry import migrate_offline

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
    return _write_stdout_json(envelope)


def _run_restore(opts: _OfflineRestoreArgs) -> int:
    from superbrain.adapters.os.daemon_config import read_owner_json_object
    from superbrain.application.maintenance import (
        outcome_to_json,
        restore_offline,
        restore_offline_preview_payload,
    )
    from superbrain.composition._maintenance_wiring import ensure_maintenance_backend
    from superbrain.composition.operator_entry import make_lazy_ssh_verifier

    backend = ensure_maintenance_backend()
    cfg, adapters, scratch_base = _explicit_owner_adapters(opts.config)
    try:
        if opts.preview:
            data = restore_offline_preview_payload(
                cfg.data_root,
                adapters,
                target=opts.kind,
                backup=opts.backup,
                store_id=cfg.expected_store_id,
                backend=backend,
            )
        else:
            assert opts.approval_file is not None
            raw_approval = read_owner_json_object(opts.approval_file, adapters)
            outcome = restore_offline(
                cfg.data_root,
                cfg.expected_store_id,
                adapters,
                target=opts.kind,
                backup=opts.backup,
                approval_payload=raw_approval,
                ssh_verifier=make_lazy_ssh_verifier(adapters),
                backend=backend,
            )
            data = outcome_to_json(outcome)
    finally:
        shutil.rmtree(scratch_base, ignore_errors=True)
    return _write_stdout_json({"ok": True, "data": data})


def main(argv: Sequence[str] | None = None) -> int:
    """Dispatch ``serve``, ``migrate --offline``, or ``restore --offline``."""
    raw_args = list(sys.argv[1:] if argv is None else argv)
    parsed = _parse_owner_args(raw_args)
    if parsed is None:
        _write_stderr(ErrorCode.INVALID_INPUT.value)
        return 2

    try:
        if parsed[0] == "serve":
            return _run_serve(parsed[1])
        if parsed[0] == "migrate":
            return _run_migrate(parsed[1])
        return _run_restore(parsed[1])
    except BrainError as err:
        _write_stderr(err.code.value)
        return 1
    except OSError:
        _write_stderr(ErrorCode.IO_ERROR.value)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
