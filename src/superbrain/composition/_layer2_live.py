"""Live production Layer-2 verification for daemon capture ingest and operator terminal approvals."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

from superbrain.adapters.harness.layer2_probe import compute_harness_config_digest
from superbrain.core._kernel_approval import CLI_HARNESS_ID, Layer2State
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import WorkspaceBinding
from superbrain.ports.os import OsAdapters
from superbrain.storage.policy_store import PolicyStore


def _has_harness_config_presence(checkout_root: Path, harness_id: str) -> bool:
    """Return True when ``checkout_root`` carries harness files suggesting config was initialized."""
    if harness_id == "claude-code":
        return (checkout_root / ".claude").exists() or (checkout_root / "CLAUDE.md").exists()
    if harness_id == "codex":
        return (checkout_root / ".codex").exists() or (checkout_root / "AGENTS.md").exists()
    return False


def _matching_checkouts(
    checkouts: Mapping[str, WorkspaceBinding],
    *,
    repo_id: str | None,
    checkout_id: str | None,
) -> tuple[WorkspaceBinding, ...]:
    if checkout_id is not None:
        binding = checkouts.get(checkout_id)
        if binding is None or (repo_id is not None and binding.repo_id != repo_id):
            return ()
        return (binding,)
    return tuple(checkouts.values())


def verify_live_layer2_harness(
    policy: PolicyStore,
    *,
    harness_id: str,
    os_: OsAdapters,
    repo_id: str | None = None,
    checkout_id: str | None = None,
    reported_host_version: str | None = None,
    host_version_resolver: Callable[[str], str | None] | None = None,
    seen_configured: set[tuple[str, str]] | None = None,
) -> tuple[str, str] | None:
    """Verify live ``(host_version, config_digest)`` for ``harness_id``, downgrading to ``UNKNOWN`` on drift."""
    latest = policy.layer2_state(harness_id)
    if latest is None or latest[3] is not Layer2State.VERIFIED:
        return None
    _, recorded_ver, recorded_dig, _ = latest

    obs_ver = host_version_resolver(harness_id) if host_version_resolver is not None else None
    if obs_ver is not None and obs_ver != recorded_ver:
        policy.set_layer2_state(
            harness_id=harness_id,
            host_version=obs_ver,
            config_digest=recorded_dig,
            state=Layer2State.UNKNOWN,
        )
        return None

    if reported_host_version is not None and reported_host_version != recorded_ver:
        policy.set_layer2_state(
            harness_id=harness_id,
            host_version=reported_host_version,
            config_digest=recorded_dig,
            state=Layer2State.UNKNOWN,
        )
        return None

    snap = policy.snapshot()
    targets = _matching_checkouts(snap.checkouts, repo_id=repo_id, checkout_id=checkout_id)
    for binding in targets:
        chk_path = Path(binding.checkout_path)
        actual_dig = compute_harness_config_digest(harness_id, chk_path, os_)
        track_key = (harness_id, binding.checkout_id)
        if actual_dig is not None:
            if actual_dig != recorded_dig:
                policy.set_layer2_state(
                    harness_id=harness_id,
                    host_version=recorded_ver,
                    config_digest=actual_dig,
                    state=Layer2State.UNKNOWN,
                )
                return None
            if seen_configured is not None:
                seen_configured.add(track_key)
        elif _has_harness_config_presence(chk_path, harness_id) or (
            seen_configured is not None and track_key in seen_configured
        ):
            policy.set_layer2_state(
                harness_id=harness_id,
                host_version=recorded_ver,
                config_digest=recorded_dig,
                state=Layer2State.UNKNOWN,
            )
            return None

    return (recorded_ver, recorded_dig)


def reconcile_live_layer2_all(
    policy: PolicyStore,
    *,
    os_: OsAdapters,
    host_version_resolver: Callable[[str], str | None] | None = None,
    seen_configured: set[tuple[str, str]] | None = None,
) -> None:
    """Re-verify every active non-CLI harness against live host version and checkout configs."""
    snap = policy.snapshot()
    harnesses = sorted(
        {
            cred.principal.harness_id
            for cred in snap.credentials.values()
            if not cred.revoked and cred.principal.harness_id != CLI_HARNESS_ID
        }
    )
    for harness_id in harnesses:
        verify_live_layer2_harness(
            policy,
            harness_id=harness_id,
            os_=os_,
            host_version_resolver=host_version_resolver,
            seen_configured=seen_configured,
        )


def batch_reported_host_version(
    policy: PolicyStore,
    events: Sequence[Mapping[str, JsonValue]],
    harness_id: str,
) -> str | None:
    """Return a drifted ``host_version`` reported by an authenticated batch event, if any."""
    latest = policy.layer2_state(harness_id)
    recorded_ver = latest[1] if latest is not None and latest[3] is Layer2State.VERIFIED else None
    if recorded_ver is None:
        return None
    for ev in events:
        if ev.get("harness_id", harness_id) != harness_id:
            continue
        meta = ev.get("source_metadata")
        if isinstance(meta, Mapping):
            hv = meta.get("host_version")
            if isinstance(hv, str) and hv != recorded_ver:
                return hv
    return None


def make_live_layer2_lookup(
    policy: PolicyStore,
    *,
    events: Sequence[Mapping[str, JsonValue]],
    harness_id: str,
    repo_id: str,
    checkout_id: str,
    os_: OsAdapters,
    host_version_resolver: Callable[[str], str | None] | None = None,
    seen_configured: set[tuple[str, str]] | None = None,
) -> Callable[[str], tuple[str, str] | None]:
    """Return a batch-scoped Layer-2 lookup closure and eagerly downgrade any reported drift."""
    reported_hv = batch_reported_host_version(policy, events, harness_id)
    if reported_hv is not None:
        verify_live_layer2_harness(
            policy,
            harness_id=harness_id,
            os_=os_,
            repo_id=repo_id,
            checkout_id=checkout_id,
            reported_host_version=reported_hv,
            host_version_resolver=host_version_resolver,
            seen_configured=seen_configured,
        )

    def _lookup(req_harness_id: str) -> tuple[str, str] | None:
        return verify_live_layer2_harness(
            policy,
            harness_id=req_harness_id,
            os_=os_,
            repo_id=repo_id,
            checkout_id=checkout_id,
            reported_host_version=reported_hv if req_harness_id == harness_id else None,
            host_version_resolver=host_version_resolver,
            seen_configured=seen_configured,
        )

    return _lookup


__all__ = [
    "batch_reported_host_version",
    "make_live_layer2_lookup",
    "reconcile_live_layer2_all",
    "verify_live_layer2_harness",
]
