"""Composition entrypoint for online and strictly read-only offline ``brain doctor`` (spec 13, 14.2, I3-5, I4-3)."""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from superbrain.core.errors import BrainError, ErrorCode, brain_error_wire_message
from superbrain.core.jsonvalue import JsonValue

if TYPE_CHECKING:
    from superbrain.application.doctor import DoctorReport
    from superbrain.ports.doctor import CaptureDoctorProbePort, DoctorScanLimits, PrivacyScannerPort
    from superbrain.ports.os import OsAdapters

__all__ = ["main", "run_doctor", "run_doctor_cli"]

_DEFAULT_WAIT_TIMEOUT_MS = 10_000


@dataclass(frozen=True)
class _ParsedDoctorCli:
    source_path: Path
    is_profile: bool
    checkout_root: Path | None
    offline: bool
    fix: bool
    wait_timeout_ms: int
    as_json: bool


def _is_abs(raw: str) -> bool:
    return bool(raw) and "\x00" not in raw and Path(raw).is_absolute() and ".." not in Path(raw).parts


def _parse_wait_ms(raw: str) -> int | None:
    if not raw or not raw.isascii() or not raw.isdigit():
        return None
    val = int(raw, 10)
    if 0 <= val <= 10_000:
        return val
    return None


def _parse_args(args: list[str]) -> _ParsedDoctorCli | None:
    if not args or args[0] != "doctor":
        return None
    config_raw: str | None = None
    profile_raw: str | None = None
    checkout_raw: str | None = None
    offline = False
    fix = False
    wait_ms: int | None = None
    as_json = False
    i = 1
    while i < len(args):
        tok = args[i]
        if tok == "--json":
            if as_json:
                return None
            as_json = True
            i += 1
        elif tok == "--offline":
            if offline:
                return None
            offline = True
            i += 1
        elif tok == "--fix":
            if fix:
                return None
            fix = True
            i += 1
        elif tok == "--wait-ms":
            if wait_ms is not None or i + 1 >= len(args):
                return None
            parsed_wait = _parse_wait_ms(args[i + 1])
            if parsed_wait is None:
                return None
            wait_ms = parsed_wait
            i += 2
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
        offline=offline,
        fix=fix,
        wait_timeout_ms=wait_ms if wait_ms is not None else _DEFAULT_WAIT_TIMEOUT_MS,
        as_json=as_json,
    )


def _validate_checkout(checkout_root: Path | None, adapters: OsAdapters) -> None:
    if checkout_root is None:
        return
    adapters.paths.reject_unsafe_path(str(checkout_root))
    if not checkout_root.is_absolute():
        raise BrainError(ErrorCode.INVALID_INPUT, "checkout must be absolute")
    if os.path.lexists(checkout_root):
        adapters.paths.reject_links(checkout_root)


def run_doctor(
    config_or_profile_path: Path,
    *,
    checkout_root: Path | None = None,
    is_profile: bool = False,
    os_: OsAdapters | None = None,
    privacy_scanner: PrivacyScannerPort | None = None,
    capture_probe: CaptureDoctorProbePort | None = None,
    limits: DoctorScanLimits | None = None,
) -> DoctorReport:
    """Inspect storage + checkout state strictly read-only and return a ``DoctorReport``."""
    from superbrain.adapters.os import os_adapters
    from superbrain.adapters.os.daemon_config import read_client_profile, read_daemon_config
    from superbrain.application.doctor import KernelPrivacyScanner, inspect_doctor_snapshot
    from superbrain.storage._doctor_reader import read_doctor_snapshot

    adapters = os_ if os_ is not None else os_adapters()
    scanner: PrivacyScannerPort = privacy_scanner if privacy_scanner is not None else KernelPrivacyScanner()
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
    _validate_checkout(resolved_checkout, adapters)
    snapshot = read_doctor_snapshot(
        data_root,
        adapters,
        checkout_root=resolved_checkout,
        expected_store_id=expected_store_id,
        privacy_scanner=scanner,
        capture_probe=capture_probe,
        limits=limits,
    )
    return inspect_doctor_snapshot(snapshot, privacy_scanner=scanner)


def _raise_error_from_envelope(env: Mapping[str, JsonValue]) -> None:
    err_obj = env.get("error")
    code = ErrorCode.INTEGRITY_FAILURE
    msg = "integrity failure"
    if isinstance(err_obj, Mapping):
        raw_code = err_obj.get("code")
        raw_msg = err_obj.get("message")
        if isinstance(raw_code, str):
            try:
                code = ErrorCode(raw_code)
            except ValueError:
                code = ErrorCode.INTEGRITY_FAILURE
        if isinstance(raw_msg, str) and raw_msg:
            msg = raw_msg
    raise BrainError(code, msg)


def _call_online_doctor(
    parsed: _ParsedDoctorCli,
    *,
    adapters: OsAdapters,
    endpoint_path: Path,
    expected_store_id: str,
    resolved_checkout: Path | None,
    ca_path: Path,
    cred_path: Path,
    leaf_sha256: str,
) -> dict[str, JsonValue]:
    from superbrain.adapters.os.daemon_config import read_client_ca, read_client_credential, read_client_endpoint
    from superbrain.cli_api.loopback import LoopbackTarget
    from superbrain.composition._operator_client import call_operator_target

    ca_pem = read_client_ca(ca_path, adapters)
    token = read_client_credential(cred_path, adapters)
    endpoint = read_client_endpoint(endpoint_path, adapters)
    target = LoopbackTarget(
        endpoint=endpoint,
        expected_store_id=expected_store_id,
        ca_pem=ca_pem,
        leaf_cert_sha256=leaf_sha256,
    )
    body: dict[str, object] = {} if parsed.fix else {"wait_timeout_ms": parsed.wait_timeout_ms}
    if resolved_checkout is not None:
        body["checkout_root"] = str(resolved_checkout)
    path = "/v2/operator/doctor/fix" if parsed.fix else "/v2/operator/doctor/report"
    env = call_operator_target(target, token, path, body, os_=adapters)
    if env.get("ok") is not True:
        _raise_error_from_envelope(env)
    data = env.get("data")
    if not isinstance(data, Mapping):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
    return dict(data)


def _verify_profile_checkout(
    checkout_path: Path,
    override_checkout: Path,
    adapters: OsAdapters,
) -> None:
    from superbrain.adapters.os.workspaces import verify_launch_checkout

    verify_launch_checkout(checkout_path, override_checkout, adapters)


def _execute_cli_doctor(parsed: _ParsedDoctorCli, adapters: OsAdapters) -> dict[str, JsonValue]:
    from superbrain.adapters.os.daemon_config import (
        CLI_CREDENTIAL_NAME,
        read_client_endpoint,
        read_client_profile,
        read_daemon_config,
    )
    from superbrain.storage.layout import DataRoot

    if parsed.is_profile:
        profile = read_client_profile(parsed.source_path, adapters)
        data_root = profile.endpoint_path.parent
        expected_store_id = profile.expected_store_id
        endpoint_path = profile.endpoint_path
        resolved_checkout = parsed.checkout_root if parsed.checkout_root is not None else (
            profile.workspace.checkout_path if profile.workspace is not None else None
        )
        cfg_cert_path: Path | None = None
        ca_path = profile.ca_file
        cred_path = profile.credential_file
        profile_pin: str | None = profile.leaf_cert_sha256
    else:
        cfg = read_daemon_config(parsed.source_path, adapters)
        data_root = cfg.data_root
        expected_store_id = cfg.expected_store_id
        endpoint_path = DataRoot.at(cfg.data_root).endpoint_path
        resolved_checkout = parsed.checkout_root
        cfg_cert_path = cfg.cert_path
        ca_path = cfg.cert_path.parent / "ca.pem"
        cred_path = parsed.source_path.parent / CLI_CREDENTIAL_NAME
        profile_pin = None

    root = DataRoot.at(data_root)
    endpoint_exists = os.path.lexists(endpoint_path)
    probe_fn = getattr(adapters.locks, "probe_held", None)
    if not callable(probe_fn):
        # Without a lock probe nobody can tell whether a daemon owns the store; never assume it does not.
        raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")
    writer_held = bool(probe_fn(root.lock_path))

    if parsed.offline:
        if parsed.fix:
            raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")
        # writer.lock is the source of truth: an endpoint.json left by a crashed daemon does not block the
        # explicitly requested offline read, and the report flags it as stale.
        if writer_held:
            raise BrainError(ErrorCode.STORE_BUSY, "store busy")
        if parsed.is_profile and profile.workspace is not None and parsed.checkout_root is not None:
            _verify_profile_checkout(profile.workspace.checkout_path, parsed.checkout_root, adapters)
        _validate_checkout(resolved_checkout, adapters)
        return run_doctor(
            parsed.source_path,
            checkout_root=resolved_checkout,
            is_profile=parsed.is_profile,
            os_=adapters,
        ).to_dict()

    if not endpoint_exists:
        if writer_held or parsed.fix:
            raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")
        if parsed.is_profile and profile.workspace is not None and parsed.checkout_root is not None:
            _verify_profile_checkout(profile.workspace.checkout_path, parsed.checkout_root, adapters)
        _validate_checkout(resolved_checkout, adapters)
        return run_doctor(
            parsed.source_path,
            checkout_root=resolved_checkout,
            is_profile=parsed.is_profile,
            os_=adapters,
        ).to_dict()

    if parsed.is_profile and profile.workspace is not None and parsed.checkout_root is not None:
        _verify_profile_checkout(profile.workspace.checkout_path, parsed.checkout_root, adapters)
    _validate_checkout(resolved_checkout, adapters)

    if profile_pin is not None:
        leaf_sha256 = profile_pin
    else:
        from superbrain.adapters.os.tls_material import read_server_cert_leaf_sha256

        assert cfg_cert_path is not None
        leaf_sha256 = read_server_cert_leaf_sha256(cfg_cert_path, adapters)
    endpoint = read_client_endpoint(endpoint_path, adapters)
    if endpoint.store_id != expected_store_id:
        raise BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch")
    if not writer_held:
        raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")
    return _call_online_doctor(
        parsed,
        adapters=adapters,
        endpoint_path=endpoint_path,
        expected_store_id=expected_store_id,
        resolved_checkout=resolved_checkout,
        ca_path=ca_path,
        cred_path=cred_path,
        leaf_sha256=leaf_sha256,
    )


def run_doctor_cli(args: list[str], *, os_: OsAdapters | None = None) -> int:
    """Parse ``brain doctor`` CLI flags, route online or offline fail-closed, and emit JSON or text."""
    from superbrain.composition._operator_client import write_error_code, write_json_error

    parsed = _parse_args(args)
    if parsed is None:
        if "--json" in args[1:]:
            write_json_error(ErrorCode.INVALID_INPUT)
        write_error_code(ErrorCode.INVALID_INPUT)
        return 2
    from superbrain.adapters.os import os_adapters

    adapters = os_ if os_ is not None else os_adapters()
    try:
        result_data = _execute_cli_doctor(parsed, adapters)
    except BrainError as err:
        if parsed.as_json:
            write_json_error(err.code, brain_error_wire_message(err))
        write_error_code(err.code)
        return 1
    if parsed.as_json:
        import json

        sys.stdout.write(json.dumps({"ok": True, "data": result_data}, sort_keys=True) + "\n")
    else:
        from superbrain.application.doctor import format_doctor_dict_text

        sys.stdout.write(format_doctor_dict_text(result_data))
    sys.stdout.flush()
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    return run_doctor_cli(raw)


if __name__ == "__main__":
    raise SystemExit(main())
