"""Client workspace scope selection and composition entrypoints (`T7b`)."""

from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.daemon_config import (
    read_client_ca,
    read_client_credential,
    read_client_endpoint,
    read_client_profile,
)
from superbrain.adapters.os.workspaces import verify_launch_checkout
from superbrain.cli_api.loopback import (
    LoopbackClient,
    LoopbackTarget,
    LoopbackTransportError,
)
from superbrain.core.canonical import canonical_json
from superbrain.core.client_profile import ClientProfile, SelectedWorkspace
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import CallResult, Scope, ToolCommand
from superbrain.core.wire import make_error_envelope, normalize_shim_args
from superbrain.mcp.stdio import ToolCaller, ToolCallUncertain
from superbrain.ports.os import OsAdapters

__all__ = ["build_tool_caller", "main", "read_status", "select_workspace"]


def select_workspace(
    profile: ClientProfile,
    launch_cwd: Path | None,
    os_: OsAdapters,
) -> SelectedWorkspace | None:
    """Verify ``launch_cwd`` against ``profile.workspace`` at shim startup and return bound scope."""
    if not isinstance(profile, ClientProfile):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if profile.workspace is None:
        return None
    if launch_cwd is None:
        raise BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch")
    verify_launch_checkout(profile.workspace.checkout_path, launch_cwd, os_)
    return SelectedWorkspace(
        alias=profile.workspace.alias,
        scope=Scope(
            repo_id=profile.workspace.expected_workspace_id,
            checkout_id=profile.workspace.expected_checkout_id,
        ),
    )


def build_tool_caller(
    profile_path: Path,
    launch_cwd: Path | None,
    os_: OsAdapters,
) -> ToolCaller:
    """Load profile, verify launch checkout before reading secrets, and return a bound ``ToolCaller``."""
    if not isinstance(profile_path, Path):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if launch_cwd is not None and not isinstance(launch_cwd, Path):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")

    profile: ClientProfile = read_client_profile(profile_path, os_)
    selected = select_workspace(profile, launch_cwd, os_)
    ca_pem = read_client_ca(profile.ca_file, os_)
    token = read_client_credential(profile.credential_file, os_)

    def _call(tool: str, arguments: dict[str, JsonValue]) -> CallResult:
        try:
            norm_args = normalize_shim_args(tool, arguments, selected)
        except BrainError as err:
            return make_error_envelope(err)

        try:
            endpoint = read_client_endpoint(profile.endpoint_path, os_)
            target = LoopbackTarget(
                endpoint=endpoint,
                expected_store_id=profile.expected_store_id,
                ca_pem=ca_pem,
                leaf_cert_sha256=profile.leaf_cert_sha256,
            )
            scope_for_call = None if tool == "get_health" else (selected.scope if selected is not None else None)
            command = ToolCommand(
                tool=tool,
                arguments=norm_args,
                token=token,
                selected_scope=scope_for_call,
            )
            result = LoopbackClient(monotonic_ns=os_.monotonic.monotonic_ns).call(target, command)
        except LoopbackTransportError as err:
            if err.request_may_have_run:
                raise ToolCallUncertain() from err
            return make_error_envelope(BrainError(err.code, err.message))
        except BrainError as err:
            return make_error_envelope(err)

        if tool == "prepare_task" and result.get("ok") is True:
            data = result.get("data")
            if (
                selected is None
                or not isinstance(data, dict)
                or data.get("workspace_id") != selected.scope.repo_id
                or data.get("checkout_id") != selected.scope.checkout_id
            ):
                return make_error_envelope(BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch"))
        return result

    return _call


def read_status(profile_path: Path, os_: OsAdapters) -> dict[str, Any]:
    """Execute a global shallow ``get_health`` probe using ``profile_path`` without workspace CWD binding."""
    try:
        if not isinstance(profile_path, Path):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        profile: ClientProfile = read_client_profile(profile_path, os_)
        ca_pem = read_client_ca(profile.ca_file, os_)
        token = read_client_credential(profile.credential_file, os_)
        endpoint = read_client_endpoint(profile.endpoint_path, os_)
        target = LoopbackTarget(
            endpoint=endpoint,
            expected_store_id=profile.expected_store_id,
            ca_pem=ca_pem,
            leaf_cert_sha256=profile.leaf_cert_sha256,
        )
        command = ToolCommand(
            tool="get_health",
            arguments={"schema_version": "2.0", "deep": False},
            token=token,
            selected_scope=None,
        )
        return LoopbackClient(monotonic_ns=os_.monotonic.monotonic_ns).call(target, command)
    except LoopbackTransportError as err:
        return make_error_envelope(BrainError(err.code, err.message))
    except BrainError as err:
        return make_error_envelope(BrainError(err.code, err.message))


def _parse_status_profile_arg(args: list[str]) -> Path | None:
    if len(args) == 3 and args[0] == "status" and args[1] == "--profile":
        raw = args[2]
    elif len(args) == 2 and args[0] == "--profile":
        raw = args[1]
    else:
        return None
    if not raw or "\x00" in raw:
        return None
    path = Path(raw)
    return path if path.is_absolute() else None


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint for ``brain status --profile <abs>``."""
    raw_args = list(sys.argv[1:] if argv is None else argv)
    profile_path = _parse_status_profile_arg(raw_args)
    if profile_path is None:
        try:
            sys.stderr.write(f"{ErrorCode.INVALID_INPUT.value}\n")
            sys.stderr.flush()
        except OSError:
            pass
        return 2

    envelope = read_status(profile_path, os_adapters())
    try:
        sys.stdout.buffer.write(canonical_json(envelope) + b"\n")
        sys.stdout.buffer.flush()
    except OSError:
        return 1

    data = envelope.get("data")
    if envelope.get("ok") is True and isinstance(data, dict) and data.get("ready") is True:
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
