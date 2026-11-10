"""Client workspace scope selection and composition entrypoints (`T7b`)."""

from __future__ import annotations

from pathlib import Path

from superbrain.adapters.os.workspaces import verify_launch_checkout
from superbrain.core.client_profile import ClientProfile, SelectedWorkspace
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import Scope
from superbrain.ports.os import OsAdapters

__all__ = ["select_workspace"]


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
