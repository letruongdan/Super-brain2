"""Client profile and bound workspace scope value types (`T7b.1`, Decision D3)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from superbrain.core._kernel_base import (
    Scope,
    is_strict_int,
    require_opaque_id,
    require_workspace_alias,
)
from superbrain.core.errors import BrainError, ErrorCode

__all__ = [
    "CLIENT_PROFILE_VERSION",
    "ClientProfile",
    "SelectedWorkspace",
    "WorkspaceProfile",
]

CLIENT_PROFILE_VERSION = 1
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


def _require_profile_id(value: object, *, label: str) -> str:
    checked = require_opaque_id(value, label=label)
    if ".." in checked:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    return checked


def _require_safe_abs_path(value: object) -> Path:
    if not isinstance(value, Path):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    raw = str(value)
    if not raw or "\x00" in raw:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if ".." in value.parts:
        raise BrainError(ErrorCode.UNSAFE_PATH, "unsafe path")
    if not value.is_absolute():
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    return value


@dataclass(frozen=True)
class WorkspaceProfile:
    """Single-checkout binding declared in an owner-only ``ClientProfile``."""

    alias: str
    checkout_path: Path
    expected_workspace_id: str
    expected_checkout_id: str

    def __post_init__(self) -> None:
        require_workspace_alias(self.alias)
        _require_safe_abs_path(self.checkout_path)
        _require_profile_id(self.expected_workspace_id, label="expected_workspace_id")
        _require_profile_id(self.expected_checkout_id, label="expected_checkout_id")


@dataclass(frozen=True)
class ClientProfile:
    """Owner-only client profile configuring trust roots and optional workspace binding."""

    version: int
    endpoint_path: Path
    expected_store_id: str
    ca_file: Path
    leaf_cert_sha256: str
    credential_file: Path
    workspace: WorkspaceProfile | None = None

    def __post_init__(self) -> None:
        if isinstance(self.version, bool):
            raise BrainError(ErrorCode.INVALID_INPUT, "boolean not allowed for integer")
        if not is_strict_int(self.version) or self.version != CLIENT_PROFILE_VERSION:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        _require_safe_abs_path(self.endpoint_path)
        _require_profile_id(self.expected_store_id, label="expected_store_id")
        _require_safe_abs_path(self.ca_file)
        if not isinstance(self.leaf_cert_sha256, str) or not _HEX64_RE.fullmatch(self.leaf_cert_sha256):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        _require_safe_abs_path(self.credential_file)
        if self.workspace is not None and not isinstance(self.workspace, WorkspaceProfile):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")


@dataclass(frozen=True)
class SelectedWorkspace:
    """Verified launch-time checkout scope bound for the lifetime of an MCP shim process."""

    alias: str
    scope: Scope

    def __post_init__(self) -> None:
        require_workspace_alias(self.alias)
        if not isinstance(self.scope, Scope) or self.scope.checkout_id is None:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
