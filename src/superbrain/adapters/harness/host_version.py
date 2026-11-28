"""Fail-closed live host version probing for Claude Code and Codex (SP2-5)."""

from __future__ import annotations

import re
from collections.abc import Iterable

from superbrain.adapters.os.host_probe import (
    find_host_executable,
    probe_windows_codex_appx_version,
    run_host_version_command,
)
from superbrain.core._kernel_base import OPAQUE_ID_RE

__all__ = [
    "find_host_executable",
    "probe_installed_host_version",
    "probe_observed_host_versions",
]

_VERSION_TOKEN_RE = re.compile(
    r"^\s*(?:codex-cli\s+|codex\s+)?v?([0-9]+(?:\.[0-9A-Za-z._-]+)+)(?:\s|\(|$)",
    re.IGNORECASE,
)


def _parse_version_line(output: str) -> str | None:
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        match = _VERSION_TOKEN_RE.match(stripped)
        if match is None:
            return None
        token = match.group(1)
        if OPAQUE_ID_RE.fullmatch(token):
            return token
        return None
    return None


def probe_installed_host_version(harness_id: str, *, timeout_s: float = 2.0) -> str | None:
    """Inspect the active local ``harness_id`` version fail-closed; return ``None`` if unverifiable."""
    if harness_id not in ("claude-code", "codex"):
        return None
    exe_name = "claude" if harness_id == "claude-code" else "codex"
    exe = find_host_executable(exe_name)
    if exe is None:
        if harness_id == "codex":
            return probe_windows_codex_appx_version()
        return None
    stdout = run_host_version_command(exe, timeout_s=timeout_s)
    if stdout is None:
        return None
    return _parse_version_line(stdout)


def probe_observed_host_versions(
    harness_ids: Iterable[str],
    *,
    timeout_s: float = 2.0,
) -> dict[str, str | None]:
    """Probe each distinct harness once and return ``{harness_id: verified_version_or_none}``."""
    out: dict[str, str | None] = {}
    for hid in harness_ids:
        if hid not in out:
            out[hid] = probe_installed_host_version(hid, timeout_s=timeout_s)
    return out
