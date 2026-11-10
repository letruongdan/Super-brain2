"""Native host shim lifecycle observation & workspace transition classifier (`T7b.2` / `T9`).

Implements ``ShimLaunchObservation`` and ``workspace_transition_matches`` per Decision D3:
each MCP stdio shim process is bound to at most one workspace checkout for its entire process
lifetime; switching workspaces or checkouts requires launching a new shim process with a
profile bound to the target checkout.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from superbrain.core.kernel import SHA256_DIGEST_RE, Scope


def _is_valid_digest(value: object) -> bool:
    return isinstance(value, str) and SHA256_DIGEST_RE.fullmatch(value) is not None


def _is_concrete_scope(scope: object) -> bool:
    return isinstance(scope, Scope) and scope.checkout_id is not None


@dataclass(frozen=True)
class ShimLaunchObservation:
    """Observed identity and scope of a single MCP stdio shim launch."""

    pid: int
    started_at: str
    profile_digest: str
    observed_scope: Scope
    profile_path: Path | None = None
    launch_cwd: Path | None = None
    reported_alias: str | None = None

    @property
    def shim_id(self) -> tuple[int, str]:
        """Composite process identity ``(pid, started_at)`` protecting against PID reuse."""
        return (self.pid, self.started_at)


def workspace_transition_matches(
    before: ShimLaunchObservation,
    after: ShimLaunchObservation,
    *,
    expected_scope: Scope,
    expected_profile_digest: str,
    expected_first_scope: Scope | None = None,
    expected_alias: str | None = None,
) -> bool:
    """Verify whether a workspace transition launched a distinct shim bound to ``expected_scope``.

    Returns ``False`` when:
    - Either observation has an invalid PID, empty start timestamp, non-SHA256 profile digest,
      or scopeless/incomplete ``Scope`` (``checkout_id is None``).
    - ``after.observed_scope != expected_scope`` or ``after.profile_digest != expected_profile_digest``.
    - ``expected_first_scope`` is supplied and ``before.observed_scope != expected_first_scope``.
    - ``expected_alias`` is supplied and ``after.reported_alias != expected_alias``.
    - The target scope or profile changed across the transition, yet the same shim process
      ``(pid, started_at)`` or the same ``profile_digest`` was reused instead of relaunching.
    """
    if not isinstance(before, ShimLaunchObservation) or not isinstance(after, ShimLaunchObservation):
        return False
    if not _is_concrete_scope(expected_scope) or not _is_valid_digest(expected_profile_digest):
        return False
    for obs in (before, after):
        if type(obs.pid) is not int or obs.pid <= 0:
            return False
        if not isinstance(obs.started_at, str) or not obs.started_at.strip():
            return False
        if not _is_valid_digest(obs.profile_digest):
            return False
        if not _is_concrete_scope(obs.observed_scope):
            return False

    if expected_first_scope is not None and before.observed_scope != expected_first_scope:
        return False
    if after.observed_scope != expected_scope:
        return False
    if after.profile_digest != expected_profile_digest:
        return False
    if expected_alias is not None and after.reported_alias != expected_alias:
        return False

    scope_changed = expected_scope != before.observed_scope
    profile_changed = expected_profile_digest != before.profile_digest
    if scope_changed or profile_changed:
        if (after.pid, after.started_at) == (before.pid, before.started_at):
            return False
        if after.profile_digest == before.profile_digest:
            return False
        if (
            scope_changed
            and before.launch_cwd is not None
            and after.launch_cwd is not None
            and after.launch_cwd == before.launch_cwd
        ):
            return False

    return True
