"""Live production Layer-2 verification for daemon capture ingest and operator terminal approvals."""

from __future__ import annotations

import logging
import os
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

from superbrain.adapters.harness.layer2_probe import compute_harness_config_digest
from superbrain.core._kernel_approval import CLI_HARNESS_ID, Layer2State
from superbrain.core._kernel_base import OPAQUE_ID_RE
from superbrain.core.errors import BrainError
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import WorkspaceBinding
from superbrain.ports.os import OsAdapters
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.store import Store

_HOST_VERSION_DRIFT_UNSET = object()
_LOGGER = logging.getLogger(__name__)


def has_harness_config_presence(checkout_root: Path, harness_id: str) -> bool:
    """Return True when ``checkout_root`` has the host config directory (even a dangling link) for ``harness_id``.

    Only the directories whose files feed ``config_digest`` count: ``CLAUDE.md``/``AGENTS.md`` are often committed to
    a repo that was never bootstrapped and are not part of the digest, so they prove nothing about host config.
    """
    if harness_id == "claude-code":
        return os.path.lexists(checkout_root / ".claude")
    if harness_id == "codex":
        return os.path.lexists(checkout_root / ".codex")
    return False


def _safe_opaque_version(candidate: object, fallback: str) -> str:
    if isinstance(candidate, str) and OPAQUE_ID_RE.fullmatch(candidate):
        return candidate
    return fallback


def _norm_path(path: str | Path) -> str:
    return os.path.normcase(os.path.abspath(str(path)))


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
    reported_host_version: object = _HOST_VERSION_DRIFT_UNSET,
    host_version_resolver: Callable[[str], str | None] | None = None,
    seen_configured: set[tuple[str, str]] | None = None,
    on_recorded: Callable[[], None] | None = None,
    dry_run: bool = False,
) -> tuple[str, str] | None:
    """Verify live ``(host_version, config_digest)`` for ``harness_id``, downgrading to ``UNKNOWN`` on drift.

    ``on_recorded`` runs after a downgrade intent is recorded so the caller can apply it to ``brain.db``.
    ``dry_run`` only reports drift (``None``): it writes nothing to the policy store.
    """

    def _downgrade(host_version: str, config_digest: str) -> None:
        if dry_run:
            return
        policy.set_layer2_state(
            harness_id=harness_id, host_version=host_version, config_digest=config_digest, state=Layer2State.UNKNOWN
        )
        if on_recorded is not None:
            on_recorded()

    latest = policy.layer2_state(harness_id)
    if latest is None or latest[3] is not Layer2State.VERIFIED:
        return None
    _, recorded_ver, recorded_dig, _ = latest

    if host_version_resolver is not None:
        try:
            obs_ver: object = host_version_resolver(harness_id)
        except Exception:  # noqa: BLE001
            obs_ver = _HOST_VERSION_DRIFT_UNSET
        if not isinstance(obs_ver, str) or not OPAQUE_ID_RE.fullmatch(obs_ver) or obs_ver != recorded_ver:
            _downgrade(_safe_opaque_version(obs_ver, recorded_ver), recorded_dig)
            return None

    if reported_host_version is not _HOST_VERSION_DRIFT_UNSET and reported_host_version != recorded_ver:
        _downgrade(_safe_opaque_version(reported_host_version, recorded_ver), recorded_dig)
        return None

    snap = policy.snapshot()
    configured_map = policy.configured_layer2_checkouts()
    configured_paths = set(configured_map.get(harness_id, ()))
    targets = _matching_checkouts(snap.checkouts, repo_id=repo_id, checkout_id=checkout_id)
    for binding in targets:
        chk_path = Path(binding.checkout_path)
        norm = _norm_path(chk_path)
        actual_dig = compute_harness_config_digest(harness_id, chk_path, os_)
        track_key = (harness_id, binding.checkout_id)
        if actual_dig is not None:
            if actual_dig != recorded_dig:
                _downgrade(recorded_ver, actual_dig)
                return None
            if norm not in configured_paths and not dry_run:
                policy.record_configured_layer2_checkout(harness_id=harness_id, checkout_path=str(chk_path))
                configured_paths.add(norm)
            if seen_configured is not None:
                seen_configured.add(track_key)
        elif (
            has_harness_config_presence(chk_path, harness_id)
            or norm in configured_paths
            or (seen_configured is not None and track_key in seen_configured)
        ):
            _downgrade(recorded_ver, recorded_dig)
            return None

    return (recorded_ver, recorded_dig)


def layer2_drift_detected(
    policy: PolicyStore, *, os_: OsAdapters, host_version_resolver: Callable[[str], str | None] | None = None,
) -> bool:
    """Read-only: does any VERIFIED connected harness no longer match its host version or checkout config?

    Nothing is recorded; the next live check records the downgrade.
    """
    snap = policy.snapshot()
    harnesses = sorted(
        {c.principal.harness_id for c in snap.credentials.values() if not c.revoked}
        - {CLI_HARNESS_ID}
    )
    for harness_id in harnesses:
        latest = policy.layer2_state(harness_id)
        if latest is not None and latest[3] is Layer2State.VERIFIED and (
            verify_live_layer2_harness(policy, harness_id=harness_id, os_=os_, dry_run=True,
                                       host_version_resolver=host_version_resolver) is None
        ):
            return True
    return False


def reconcile_live_layer2_all(
    policy: PolicyStore,
    *,
    store: Store,
    os_: OsAdapters,
    host_version_resolver: Callable[[str], str | None] | None = None,
    seen_configured: set[tuple[str, str]] | None = None,
    apply_tracker: Layer2ApplyTracker | None = None,
) -> None:
    """Re-verify every active non-CLI harness against live host version and checkout configs.

    Downgrades are applied to ``brain.db`` before return; the caller must not hold a ``store`` transaction.
    """
    recorded: list[bool] = []
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
            on_recorded=lambda: recorded.append(True),
        )
    (apply_tracker if apply_tracker is not None else Layer2ApplyTracker()).apply(store, bool(recorded), quiet=False)


class Layer2ApplyTracker:
    """One per daemon, shared by every path that records Layer-2 downgrades (capture, approval checks, restore): a
    downgrade whose apply to ``brain.db`` failed stays pending until the next check on any path applies it."""

    def __init__(self) -> None:
        self._pending = False

    def apply(self, store: Store, needed: bool, *, quiet: bool) -> None:
        """Apply when something was recorded now or is still pending; ``quiet`` logs a failure instead of raising."""
        if not (needed or self._pending):
            return
        try:
            store.reconcile_policy()
        except BrainError as err:
            self._pending = True  # durable in policy.db: retried by the next check on any path, or at startup
            if not quiet:
                raise
            _LOGGER.warning("layer2 downgrade apply deferred (code=%s)", err.code.value)
            return
        self._pending = False


def batch_reported_host_version(
    policy: PolicyStore,
    events: Sequence[Mapping[str, JsonValue]],
    harness_id: str,
) -> object:
    """Return a drifted/malformed ``host_version`` reported by an authenticated batch event, or unset sentinel."""
    latest = policy.layer2_state(harness_id)
    recorded_ver = latest[1] if latest is not None and latest[3] is Layer2State.VERIFIED else None
    if recorded_ver is None:
        return _HOST_VERSION_DRIFT_UNSET
    for ev in events:
        if ev.get("harness_id", harness_id) != harness_id:
            continue
        meta = ev.get("source_metadata")
        if isinstance(meta, Mapping) and "host_version" in meta and meta["host_version"] is not None:
            hv = meta["host_version"]
            if hv != recorded_ver:
                return hv
    return _HOST_VERSION_DRIFT_UNSET


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
    on_recorded: Callable[[], None] | None = None,
) -> Callable[[str], tuple[str, str] | None]:
    """Return a batch-scoped Layer-2 lookup closure and eagerly downgrade any reported drift."""
    reported_hv = batch_reported_host_version(policy, events, harness_id)
    if reported_hv is not _HOST_VERSION_DRIFT_UNSET:
        verify_live_layer2_harness(
            policy,
            harness_id=harness_id,
            os_=os_,
            repo_id=repo_id,
            checkout_id=checkout_id,
            reported_host_version=reported_hv,
            host_version_resolver=host_version_resolver,
            seen_configured=seen_configured,
            on_recorded=on_recorded,
        )

    def _lookup(req_harness_id: str) -> tuple[str, str] | None:
        return verify_live_layer2_harness(
            policy,
            harness_id=req_harness_id,
            os_=os_,
            repo_id=repo_id,
            checkout_id=checkout_id,
            reported_host_version=reported_hv if req_harness_id == harness_id else _HOST_VERSION_DRIFT_UNSET,
            host_version_resolver=host_version_resolver,
            seen_configured=seen_configured,
            on_recorded=on_recorded,
        )

    return _lookup


__all__ = [
    "batch_reported_host_version",
    "Layer2ApplyTracker",
    "has_harness_config_presence",
    "layer2_drift_detected",
    "make_live_layer2_lookup",
    "reconcile_live_layer2_all",
    "verify_live_layer2_harness",
]
