"""Composition wiring for online and offline ``brain doctor --fix`` safe repairs (spec 13, §20.28)."""

from __future__ import annotations

import contextlib
import os
from collections.abc import Callable, Mapping, Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass
from pathlib import Path

from superbrain.adapters.os.daemon_config import (
    read_client_credential,
)
from superbrain.application._doctor_fix import (
    build_fix_response,
    execute_post_open_fixes,
    make_action_outcome,
    parse_fix_request_body,
    run_external_fix_ports,
    tighten_data_root_permissions,
)
from superbrain.application.doctor import (
    KernelPrivacyScanner,
    inspect_doctor_snapshot,
)
from superbrain.core._kernel_approval import CLI_HARNESS_ID
from superbrain.core.client_profile import ClientProfile
from superbrain.core.errors import BrainError, ErrorCode
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
from superbrain.storage._policy_authority import resolve_policy_credential
from superbrain.storage.kernel_schema import KERNEL_POLICY_MIGRATIONS
from superbrain.storage.layout import (
    DataRoot,
)
from superbrain.storage.runtime import Runtime, _preadmission_scratch
from superbrain.storage.schema import Migration, ensure_writable, read_schema_info
from superbrain.storage.sqlite import db_files, open_readonly
from superbrain.storage.swap import PURPOSES, READY, Target

__all__ = [
    "DoctorFixHooks",
    "fresh_report_matches_live_state",
    "run_offline_doctor_fix",
    "run_online_doctor_fix",
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


def _validate_checkout_safe(checkout_root: Path | None, os_: OsAdapters) -> None:
    if checkout_root is None:
        return
    os_.paths.reject_unsafe_path(str(checkout_root))
    if not checkout_root.is_absolute():
        raise BrainError(ErrorCode.INVALID_INPUT, "checkout must be absolute")
    if os.path.lexists(checkout_root):
        os_.paths.reject_links(checkout_root)


def _count_applied_intents(store_db: Path, *, scratch_dir: Path | None = None) -> int:
    if not os.path.lexists(store_db):
        return 0
    with contextlib.closing(open_readonly(store_db, scratch_dir=scratch_dir)) as sdb:
        has_tbl = sdb.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='applied_intents'").fetchone()
        if has_tbl is None:
            return 0
        row = sdb.execute("SELECT COUNT(*) FROM applied_intents").fetchone()
        return int(row[0]) if row is not None else 0


def _locate_effective_db_links_checked(root: DataRoot, target: Target, os_: OsAdapters) -> Path | None:
    live = root.store_dir if target == "store" else root.policy_dir
    db_name = "brain.db" if target == "store" else "policy.db"
    stages = [root.root / f"{target}.{p}" for p in PURPOSES if os.path.lexists(root.root / f"{target}.{p}")]
    if len(stages) > 1:
        names = ", ".join(s.name for s in stages)
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"two swaps of {target} were interrupted at once: {names}")
    if stages:
        (stage,) = stages
        os_.paths.reject_links(stage)
        if not stage.is_dir():
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"{stage.name} is not a directory")
        marker = stage / READY
        if os.path.lexists(live):
            if not live.is_dir():
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"{live.name} is not a directory")
            effective_dir = live
        else:
            os_.paths.reject_links(marker)
            if not os.path.isfile(marker):
                raise BrainError(
                    ErrorCode.INTEGRITY_FAILURE,
                    f"{target}/ is missing and {stage.name} was never marked {READY}",
                )
            effective_dir = stage
    else:
        if not os.path.lexists(live):
            return None
        if not live.is_dir():
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, f"{live.name} is not a directory")
        effective_dir = live
    db_path = effective_dir / db_name
    companions = [p for p in db_files(db_path) if os.path.lexists(p)]
    if companions:
        os_.paths.reject_links(effective_dir, entries=companions)
    return db_path if os.path.lexists(db_path) else None


def _verify_offline_profile_credential(
    root: DataRoot,
    profile: ClientProfile,
    *,
    os_: OsAdapters,
    policy_migrations: Sequence[Migration] = KERNEL_POLICY_MIGRATIONS,
) -> None:
    token = read_client_credential(profile.credential_file, os_)
    os_.paths.reject_links(root.root)
    if os_.permissions.check_ancestors(root.root):
        raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")
    os_.paths.reject_links(root.policy_dir)
    os_.paths.reject_links(root.policy_db)
    if not os.path.lexists(root.policy_db):
        raise BrainError(ErrorCode.NOT_FOUND, f"policy store {root.policy_db} does not exist")
    with _preadmission_scratch(root.root, os_, None) as scratch_dir:
        info = read_schema_info(root.policy_db, scratch_dir=scratch_dir)
        if info is None:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "policy store schema metadata missing")
        if info.store_id != profile.expected_store_id:
            raise BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch")
        ensure_writable(info, policy_migrations)
        with contextlib.closing(open_readonly(root.policy_db, scratch_dir=scratch_dir)) as pdb:
            principal = resolve_policy_credential(
                pdb,
                token,
                expected_store_id=profile.expected_store_id,
                expected_schema_version=info.schema_version,
            )
    if principal.harness_id != CLI_HARNESS_ID:
        raise BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch")


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


def run_online_doctor_fix(
    rt: Runtime,
    body: Mapping[str, JsonValue],
    *,
    adapters: OsAdapters,
    hooks: DoctorFixHooks | None = None,
    privacy_scanner: PrivacyScannerPort | None = None,
) -> dict[str, JsonValue]:
    """Execute safe ``doctor --fix`` repairs on the owner thread against the running daemon ``Runtime``."""
    cfg_hooks = hooks if hooks is not None else DoctorFixHooks()
    actions, checkout_root = parse_fix_request_body(body)
    explicit_actions = "actions" in body
    _validate_checkout_safe(checkout_root, adapters)
    scanner: PrivacyScannerPort = privacy_scanner if privacy_scanner is not None else KernelPrivacyScanner()

    outcomes: dict[str, dict[str, JsonValue]] = {}
    if "tighten_permissions" in actions:
        changed, detail = tighten_data_root_permissions((rt.root.root, rt.root.backups_dir), adapters)
        outcomes["tighten_permissions"] = make_action_outcome(
            "tighten_permissions",
            "applied" if changed > 0 else "noop",
            detail,
            changed=changed,
        )

    needs_rebuild = False
    if "rebuild_projections" in actions:
        with _preadmission_scratch(rt.root.root, adapters, None) as scratch_dir:
            matches, _detail = check_pair_projection_parity(
                rt.root.store_db, rt.root.policy_db, scratch_dir=scratch_dir
            )
        needs_rebuild = not matches

    outcomes.update(
        execute_post_open_fixes(
            actions=actions,
            explicit_actions=explicit_actions,
            needs_rebuild=needs_rebuild,
            reconcile_policy_fn=rt.store.reconcile_policy,
            rebuild_projections_fn=rt.store.rebuild_projections,
            logs_dir=rt.root.logs_dir,
            os_=adapters,
            max_log_bytes=cfg_hooks.max_log_bytes,
            quiesce_hook=cfg_hooks.log_quiesce_hook,
        )
    )

    if "replay_outbox" in actions:
        outcomes.update(
            run_external_fix_ports(
                actions=("replay_outbox",),
                os_=adapters,
                outbox_replay=cfg_hooks.outbox_replay,
                supervisor_control=cfg_hooks.supervisor_control,
                config_path=cfg_hooks.config_path,
            )
        )

    post_snap = read_doctor_snapshot(
        rt.root.root,
        adapters,
        checkout_root=checkout_root,
        expected_store_id=rt.store.store_id,
        privacy_scanner=scanner,
        capture_probe=cfg_hooks.capture_probe,
    )
    post_report = inspect_doctor_snapshot(post_snap, privacy_scanner=scanner)
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


def run_offline_doctor_fix(
    source_path: Path,
    *,
    is_profile: bool,
    checkout_root: Path | None,
    os_: OsAdapters,
    hooks: DoctorFixHooks | None = None,
    privacy_scanner: PrivacyScannerPort | None = None,
) -> dict[str, JsonValue]:
    """Execute fail-closed offline ``brain doctor --offline --fix`` (strictly read-only per §13)."""
    raise BrainError(ErrorCode.DAEMON_UNAVAILABLE, "daemon unavailable")
