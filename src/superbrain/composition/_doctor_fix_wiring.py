"""Composition wiring for online and offline ``brain doctor --fix`` safe repairs (spec 13, §20.28)."""

from __future__ import annotations

import os
import shutil
from collections.abc import Callable, Mapping
from contextlib import AbstractContextManager
from dataclasses import dataclass
from pathlib import Path

from superbrain.application._doctor_fix import (
    SAFE_FIX_ACTIONS,
    FixInterrupted,
    build_fix_response,
    build_interrupted_fix_response,
    execute_post_open_fixes,
    make_action_outcome,
    run_external_fix_ports,
    tighten_data_root_permissions,
)
from superbrain.application._log_rotate import RotationStopped, rotate_logs
from superbrain.application.doctor import (
    KernelPrivacyScanner,
    inspect_doctor_snapshot,
)
from superbrain.composition._daemon_doctor_commit import build_worker_db_snapshot
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.ports.doctor import (
    MAX_LOG_BYTES,
    CaptureDoctorProbePort,
    OutboxReplayPort,
    PrivacyScannerPort,
    SupervisorControlPort,
)
from superbrain.ports.os import OsAdapters
from superbrain.storage._doctor_reader import read_doctor_snapshot
from superbrain.storage._doctor_storage_probes import check_pair_projection_parity
from superbrain.storage.layout import (
    DataRoot,
)
from superbrain.storage.runtime import Runtime, _preadmission_scratch

__all__ = [
    "DoctorFixHooks",
    "fresh_report_matches_live_state",
    "run_fix_store_action",
    "run_online_doctor_fix",
    "validate_fix_checkout",
]


@dataclass(frozen=True)
class DoctorFixHooks:
    """Optional composition hooks wired into daemon/CLI ``doctor --fix`` orchestration."""

    config_path: Path | None = None
    outbox_replay: OutboxReplayPort | None = None
    supervisor_control: SupervisorControlPort | None = None
    log_quiesce_hook: Callable[[], AbstractContextManager[None]] | None = None
    capture_probe: CaptureDoctorProbePort | None = None
    max_log_bytes: int = MAX_LOG_BYTES


def validate_fix_checkout(checkout_root: Path | None, os_: OsAdapters) -> None:
    """Reject an unsafe, relative or linked ``checkout_root`` before any repair starts."""
    if checkout_root is None:
        return
    os_.paths.reject_unsafe_path(str(checkout_root))
    if not checkout_root.is_absolute():
        raise BrainError(ErrorCode.INVALID_INPUT, "checkout must be absolute")
    if os.path.lexists(checkout_root):
        os_.paths.reject_links(checkout_root)


def fresh_report_matches_live_state(
    rt: Runtime,
    adapters: OsAdapters,
    fresh: Mapping[str, JsonValue],
    *,
    fix_dirty: bool = False,
) -> bool:
    """Return False when live permissions drifted or ``--fix`` mutated state since the cached ``DoctorRun``."""
    if fix_dirty:
        return False
    try:
        live_bad = bool(
            adapters.permissions.problems(rt.root.root)
            or adapters.permissions.check_ancestors(rt.root.root)
        )
    except BrainError:
        return False
    cached_checks = fresh.get("checks")
    if isinstance(cached_checks, list):
        for chk in cached_checks:
            if isinstance(chk, Mapping) and chk.get("name") == "permissions.tree":
                return (chk.get("status") != "PASS") == live_bad
    return bool(fresh.get("permission_problems")) == live_bad


_STORE_ACTIONS = frozenset({"reconcile_policy", "rebuild_projections", "replay_outbox"})


def run_fix_store_action(
    rt: Runtime,
    name: str,
    *,
    explicit_actions: bool,
    adapters: OsAdapters,
    hooks: DoctorFixHooks,
) -> dict[str, JsonValue]:
    """Owner thread: one store-writing repair, a single atomic store operation (or the SP2 outbox port)."""
    if name == "replay_outbox":
        return run_external_fix_ports(
            actions=("replay_outbox",),
            os_=adapters,
            outbox_replay=hooks.outbox_replay,
            supervisor_control=hooks.supervisor_control,
            config_path=hooks.config_path,
        )["replay_outbox"]
    needs_rebuild = False
    if name == "rebuild_projections":
        with _preadmission_scratch(rt.root.root, adapters, None) as scratch_dir:
            matches, _detail = check_pair_projection_parity(
                rt.root.store_db, rt.root.policy_db, scratch_dir=scratch_dir
            )
        needs_rebuild = not matches
    return execute_post_open_fixes(
        actions=(name,),
        explicit_actions=explicit_actions,
        needs_rebuild=needs_rebuild,
        reconcile_policy_fn=rt.store.reconcile_policy,
        rebuild_projections_fn=rt.store.rebuild_projections,
        logs_dir=rt.root.logs_dir,
        os_=adapters,
    )[name]


def _authorized(authorize: Callable[[], None]) -> bool:
    """False when the runtime changed generation or passed the cutoff; a revoked credential raises."""
    try:
        authorize()
    except BrainError as err:
        if err.code is not ErrorCode.REVISION_CONFLICT:
            raise
        return False
    return True


def _not_started(name: str) -> dict[str, JsonValue]:
    return make_action_outcome(name, "not_started", "stopped at the request cutoff before this action")


def run_online_doctor_fix(
    root: DataRoot,
    *,
    store_id: str,
    actions: tuple[str, ...],
    checkout_root: Path | None,
    adapters: OsAdapters,
    hooks: DoctorFixHooks | None = None,
    privacy_scanner: PrivacyScannerPort | None = None,
    should_stop: Callable[[], bool],
    run_store_action: Callable[[str], dict[str, JsonValue]],
    authorize: Callable[[], None],
) -> dict[str, JsonValue]:
    """Off the owner thread: run the requested repairs in canonical order, then recheck from a fresh snapshot.

    Store repairs are delegated to ``run_store_action`` (the owner), which re-checks authority and the cutoff when
    it starts; ``authorize`` does the same before each filesystem repair, again immediately before each of its
    writes (every ACL change, every log-rotation journal), and once more after the recheck scan, so a report is only
    returned while its runtime is still current. The recheck reads a consistent pair of database snapshots.
    ``should_stop`` is checked before every step and inside the
    permission walk; once it fires, or the runtime changes generation (``REVISION_CONFLICT``), no further step
    starts and the response is ``build_interrupted_fix_response`` with each action's definite state.
    """
    cfg_hooks = hooks if hooks is not None else DoctorFixHooks()
    scanner: PrivacyScannerPort = privacy_scanner if privacy_scanner is not None else KernelPrivacyScanner()
    outcomes: dict[str, dict[str, JsonValue]] = {}
    interrupted = False

    def _still_current() -> bool:
        # Asked at each filesystem write boundary, after that step's own reads, and once more after the recheck
        # scan: the cutoff, the generation and the caller's credential (re-checked on the owner) must all hold.
        return not should_stop() and _authorized(authorize)

    for name in SAFE_FIX_ACTIONS:
        if name not in actions or name == "restart_daemon":
            continue
        if interrupted or should_stop():
            interrupted = True
            outcomes[name] = _not_started(name)
            continue
        if name not in _STORE_ACTIONS and not _authorized(authorize):
            interrupted = True
            outcomes[name] = _not_started(name)
            continue
        if name == "tighten_permissions":
            try:
                changed, detail = tighten_data_root_permissions(
                    (root.root, root.backups_dir), adapters, should_stop=should_stop, may_write=_still_current
                )
            except FixInterrupted as stop:
                interrupted = True
                outcomes[name] = make_action_outcome(
                    name, "interrupted", "stopped at the request cutoff; rerun to finish", changed=stop.changed
                )
                continue
            outcomes[name] = make_action_outcome(name, "applied" if changed > 0 else "noop", detail, changed=changed)
        elif name in _STORE_ACTIONS:
            try:
                outcomes[name] = run_store_action(name)
            except BrainError as err:
                if err.code is not ErrorCode.REVISION_CONFLICT:
                    raise
                interrupted = True  # the runtime changed generation (restore or shutdown) before the owner ran it
                outcomes[name] = _not_started(name)
        elif name == "rotate_logs":
            try:
                rotated, detail = rotate_logs(
                    root.logs_dir,
                    adapters,
                    max_bytes=cfg_hooks.max_log_bytes,
                    quiesce_hook=cfg_hooks.log_quiesce_hook,
                    may_write=_still_current,
                )
            except RotationStopped as stop:
                interrupted = True
                outcomes[name] = (
                    make_action_outcome(
                        name, "interrupted", "stopped at the request cutoff; rerun to finish", changed=stop.recovered
                    )
                    if stop.recovered > 0
                    else _not_started(name)
                )
                continue
            outcomes[name] = make_action_outcome(name, "applied" if rotated else "noop", detail, changed=int(rotated))
    if interrupted or should_stop():
        if "restart_daemon" in actions:
            outcomes["restart_daemon"] = _not_started("restart_daemon")
        return build_interrupted_fix_response(actions, outcomes)

    snap_dir = build_worker_db_snapshot(root, f"fix-{new_id()}", adapters)
    try:
        post_snap = read_doctor_snapshot(
            root.root,
            adapters,
            db_root=snap_dir,
            checkout_root=checkout_root,
            expected_store_id=store_id,
            privacy_scanner=scanner,
            capture_probe=cfg_hooks.capture_probe,
        )
    finally:
        shutil.rmtree(snap_dir, ignore_errors=True)
    post_report = inspect_doctor_snapshot(post_snap, privacy_scanner=scanner)
    # The recheck is current only if the cutoff, the generation and the credential still hold after the scan; a
    # restore or revocation during the scan makes it a report of a runtime that no longer exists.
    if not _still_current():
        if "restart_daemon" in actions:
            outcomes["restart_daemon"] = _not_started("restart_daemon")
        return build_interrupted_fix_response(actions, outcomes)
    if "restart_daemon" in actions:
        outcomes.update(
            run_external_fix_ports(
                actions=("restart_daemon",),
                os_=adapters,
                outbox_replay=cfg_hooks.outbox_replay,
                supervisor_control=cfg_hooks.supervisor_control,
                config_path=cfg_hooks.config_path,
            )
        )
    return build_fix_response(post_report, actions, outcomes)
