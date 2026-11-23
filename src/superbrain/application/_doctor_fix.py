"""Application safe-repair planner, allowlist validation, and permission tightening (spec 13, §20.28)."""

from __future__ import annotations

import os
import stat
from collections.abc import Callable, Mapping, Sequence
from contextlib import AbstractContextManager
from pathlib import Path

from superbrain.application._doctor_checks import clip_report_str
from superbrain.application._log_rotate import rotate_logs
from superbrain.application.doctor import DoctorReport
from superbrain.core.errors import BrainError, ErrorCode, describe_exception
from superbrain.core.jsonvalue import JsonValue
from superbrain.ports.doctor import (
    MAX_LOG_BYTES,
    OutboxReplayPort,
    SupervisorControlPort,
)
from superbrain.ports.os import OsAdapters, PhysicalObjectId

__all__ = [
    "SAFE_FIX_ACTIONS",
    "SAFE_FIX_ACTION_SET",
    "FixInterrupted",
    "build_interrupted_fix_response",
    "build_fix_response",
    "ensure_no_links_in_tree",
    "execute_post_open_fixes",
    "make_action_outcome",
    "parse_fix_request_body",
    "run_external_fix_ports",
    "tighten_data_root_permissions",
]

SAFE_FIX_ACTIONS: tuple[str, ...] = (
    "tighten_permissions",
    "reconcile_policy",
    "rebuild_projections",
    "rotate_logs",
    "replay_outbox",
    "restart_daemon",
)
SAFE_FIX_ACTION_SET: frozenset[str] = frozenset(SAFE_FIX_ACTIONS)
_REPARSE_POINT = 0x400


def _is_link(path: Path, os_: OsAdapters) -> bool:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError as exc:
        detail = f"cannot inspect {path.name}: {describe_exception(exc)}"
        raise BrainError(ErrorCode.INSECURE_PERMISSIONS, detail) from exc
    if stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & _REPARSE_POINT):
        return True
    if os_.physical is not None:
        ident = os_.physical.stat_physical_identity(path)
        return ident is not None and ident.is_link
    return False


def ensure_no_links_in_tree(root: Path, os_: OsAdapters) -> tuple[list[Path], list[Path]]:
    """Reject any symlink/reparse point under ``root`` and return ``(dirs_top_down, files)``."""
    os_.paths.reject_links(root)
    if not os.path.lexists(root):
        return [], []
    if _is_link(root, os_):
        raise BrainError(ErrorCode.UNSAFE_PATH, f"unsafe link at {root}")
    if not root.is_dir():
        return [], [root]
    dirs: list[Path] = [root]
    files: list[Path] = []
    stack: list[Path] = [root]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError as exc:
            detail = f"cannot list {current.name}: {describe_exception(exc)}"
            raise BrainError(ErrorCode.INSECURE_PERMISSIONS, detail) from exc
        for entry in entries:
            epath = Path(entry.path)
            if entry.is_symlink() or _is_link(epath, os_):
                raise BrainError(ErrorCode.UNSAFE_PATH, f"unsafe link inside data root: {epath}")
            try:
                est = entry.stat(follow_symlinks=False)
            except OSError as exc:
                detail = f"cannot stat {epath.name}: {describe_exception(exc)}"
                raise BrainError(ErrorCode.INSECURE_PERMISSIONS, detail) from exc
            if stat.S_ISDIR(est.st_mode):
                dirs.append(epath)
                stack.append(epath)
            else:
                files.append(epath)
    return dirs, files


def _verify_and_secure(
    path: Path,
    *,
    is_dir: bool,
    pre_id: PhysicalObjectId | None,
    os_: OsAdapters,
    may_write: Callable[[], bool] | None = None,
) -> int | None:
    """Repair one entry; ``None`` when ``may_write`` refused the write this entry needed (nothing was changed)."""
    if not os_.permissions.object_problems(path):
        return 0
    if may_write is not None and not may_write():
        return None
    if os_.physical is not None:
        cur_id = os_.physical.stat_physical_identity(path)
        if cur_id is None or cur_id.is_link or cur_id != pre_id:
            raise BrainError(ErrorCode.UNSAFE_PATH, f"target identity changed before ACL repair: {path}")
    elif _is_link(path, os_):
        raise BrainError(ErrorCode.UNSAFE_PATH, f"target replaced by link: {path}")
    if is_dir:
        os_.permissions.secure_directory(path)
    else:
        os_.permissions.secure_file(path)
    return 1


class FixInterrupted(Exception):  # noqa: N818 - a stop signal, not an error
    """A repair stopped at a step boundary because its caller's cutoff fired; ``changed`` steps were applied."""

    def __init__(self, changed: int) -> None:
        super().__init__("fix interrupted")
        self.changed = changed


def tighten_data_root_permissions(
    roots: Sequence[Path],
    os_: OsAdapters,
    *,
    should_stop: Callable[[], bool] | None = None,
    may_write: Callable[[], bool] | None = None,
) -> tuple[int, str]:
    """Verify non-symlink identity on every node strictly inside ``roots`` and repair owner-only permissions.

    ``should_stop`` is checked before every node and ``may_write`` immediately before every entry that needs a
    change; once either refuses, the walk raises ``FixInterrupted`` without touching another node, so the caller can
    report exactly how far the repair went.
    """
    seen: set[str] = set()
    unique_roots: list[Path] = []
    for item in roots:
        norm = os.path.abspath(item)
        if norm not in seen:
            seen.add(norm)
            unique_roots.append(Path(norm))

    all_dirs: list[tuple[Path, PhysicalObjectId | None]] = []
    all_files: list[tuple[Path, PhysicalObjectId | None]] = []
    for base in unique_roots:
        dirs, files = ensure_no_links_in_tree(base, os_)
        for d in dirs:
            ident = os_.physical.stat_physical_identity(d) if os_.physical is not None else None
            if ident is not None and ident.is_link:
                raise BrainError(ErrorCode.UNSAFE_PATH, f"unsafe link: {d}")
            all_dirs.append((d, ident))
        for f in files:
            ident = os_.physical.stat_physical_identity(f) if os_.physical is not None else None
            if ident is not None and ident.is_link:
                raise BrainError(ErrorCode.UNSAFE_PATH, f"unsafe link: {f}")
            all_files.append((f, ident))

    # Second file pass catches any child whose ACL reset during parent directory DACL update on Windows.
    steps = [(d, True, i) for d, i in all_dirs] + [(f, False, i) for f, i in all_files] * 2
    changed = 0
    for path, is_dir, pre_id in steps:
        if should_stop is not None and should_stop():
            raise FixInterrupted(changed)
        step = _verify_and_secure(path, is_dir=is_dir, pre_id=pre_id, os_=os_, may_write=may_write)
        if step is None:
            raise FixInterrupted(changed)
        changed += step

    if changed > 0:
        return changed, f"restricted {changed} insecure entry/entries to owner-only"
    return 0, "all data_root and backup entries already owner-only"


def parse_fix_request_body(raw: Mapping[str, JsonValue]) -> tuple[tuple[str, ...], Path | None]:
    """Validate `/v2/operator/doctor/fix` payload against ``SAFE_FIX_ACTIONS`` and optional ``checkout_root``."""
    unknown_keys = set(raw) - {"actions", "checkout_root"}
    if unknown_keys:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    checkout_root: Path | None = None
    if "checkout_root" in raw:
        raw_co = raw["checkout_root"]
        if not isinstance(raw_co, str) or not raw_co or "\x00" in raw_co:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        co_path = Path(raw_co)
        if not co_path.is_absolute():
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        if ".." in co_path.parts:
            raise BrainError(ErrorCode.UNSAFE_PATH, "unsafe path")
        checkout_root = co_path
    if "actions" not in raw:
        return SAFE_FIX_ACTIONS, checkout_root
    raw_actions = raw["actions"]
    if not isinstance(raw_actions, list) or not raw_actions:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    selected: list[str] = []
    seen: set[str] = set()
    for item in raw_actions:
        if not isinstance(item, str) or item not in SAFE_FIX_ACTION_SET or item in seen:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        seen.add(item)
        selected.append(item)
    return tuple(selected), checkout_root


def make_action_outcome(
    action: str,
    status: str,
    detail: str,
    *,
    changed: int | None = None,
) -> dict[str, JsonValue]:
    out: dict[str, JsonValue] = {
        "action": action,
        "status": status,
        "detail": clip_report_str(detail),
    }
    if changed is not None:
        out["changed"] = changed
    return out


def execute_post_open_fixes(
    *,
    actions: tuple[str, ...],
    explicit_actions: bool,
    needs_rebuild: bool,
    reconcile_policy_fn: Callable[[], int],
    rebuild_projections_fn: Callable[[], int],
    logs_dir: Path,
    os_: OsAdapters,
    max_log_bytes: int = MAX_LOG_BYTES,
    quiesce_hook: Callable[[], AbstractContextManager[None]] | None = None,
) -> dict[str, dict[str, JsonValue]]:
    """Run safe storage/log repairs under an open admitted store lease."""
    outcomes: dict[str, dict[str, JsonValue]] = {}
    if "reconcile_policy" in actions:
        applied = reconcile_policy_fn()
        outcomes["reconcile_policy"] = make_action_outcome(
            "reconcile_policy",
            "applied" if applied > 0 else "noop",
            f"applied {applied} pending policy intent(s)" if applied > 0 else "all policy intents already applied",
            changed=applied,
        )
    if "rebuild_projections" in actions:
        if needs_rebuild or explicit_actions:
            replayed = rebuild_projections_fn()
            outcomes["rebuild_projections"] = make_action_outcome(
                "rebuild_projections",
                "applied",
                f"rebuilt projections cleanly from {replayed} ledger entry/entries",
                changed=replayed,
            )
        else:
            outcomes["rebuild_projections"] = make_action_outcome(
                "rebuild_projections",
                "noop",
                "projections already match ledger",
                changed=0,
            )
    if "rotate_logs" in actions:
        rotated, detail = rotate_logs(
            logs_dir,
            os_,
            max_bytes=max_log_bytes,
            quiesce_hook=quiesce_hook,
        )
        outcomes["rotate_logs"] = make_action_outcome(
            "rotate_logs",
            "applied" if rotated else "noop",
            detail,
            changed=1 if rotated else 0,
        )
    return outcomes


def run_external_fix_ports(
    *,
    actions: tuple[str, ...],
    os_: OsAdapters,
    outbox_replay: OutboxReplayPort | None,
    supervisor_control: SupervisorControlPort | None,
    config_path: Path | None,
) -> dict[str, dict[str, JsonValue]]:
    """Run ``replay_outbox`` and ``restart_daemon`` port delegations, or report ``capability_unavailable``."""
    outcomes: dict[str, dict[str, JsonValue]] = {}
    if "replay_outbox" in actions:
        if outbox_replay is None:
            outcomes["replay_outbox"] = make_action_outcome(
                "replay_outbox",
                "capability_unavailable",
                "OutboxReplayPort not attached",
            )
        else:
            res = outbox_replay.replay_outbox(now=os_.clock.now())
            outcome = make_action_outcome(
                "replay_outbox",
                res.status,
                res.detail or f"replayed={res.replayed_events}, pending={res.pending_remaining}",
                changed=res.replayed_events,
            )
            outcome["replayed_events"] = res.replayed_events
            outcome["committed_event_sequences"] = list(res.committed_event_sequences)
            outcome["contiguous_event_acked_through"] = res.contiguous_event_acked_through
            outcome["acked_producer_gap_sequences"] = list(res.acked_producer_gap_sequences)
            outcome["pending_remaining"] = res.pending_remaining
            outcomes["replay_outbox"] = outcome
    if "restart_daemon" in actions:
        if supervisor_control is None or config_path is None:
            reason = (
                "SupervisorControlPort not attached"
                if supervisor_control is None
                else "daemon config path unavailable"
            )
            outcomes["restart_daemon"] = make_action_outcome(
                "restart_daemon",
                "capability_unavailable",
                reason,
            )
        else:
            sres = supervisor_control.restart_daemon(config_path)
            outcomes["restart_daemon"] = make_action_outcome(
                "restart_daemon",
                sres.status,
                sres.detail or ("daemon restarted" if sres.restarted else "daemon restart not performed"),
                changed=1 if sres.restarted else 0,
            )
    return outcomes


def build_interrupted_fix_response(
    ordered_actions: tuple[str, ...],
    outcomes_by_name: Mapping[str, dict[str, JsonValue]],
) -> dict[str, JsonValue]:
    """The fix stopped at its cutoff: every requested action with its definite state, and no recheck."""
    return {
        "status": "interrupted",
        "fix": {
            "actions": [outcomes_by_name[name] for name in ordered_actions if name in outcomes_by_name],
            "rechecked_checks": [],
        },
    }


def build_fix_response(
    report: DoctorReport,
    ordered_actions: tuple[str, ...],
    outcomes_by_name: Mapping[str, dict[str, JsonValue]],
) -> dict[str, JsonValue]:
    """Assemble ``{**post_report.to_dict(), 'fix': ...}`` keeping report keys exact."""
    action_list: list[JsonValue] = [
        outcomes_by_name[name] for name in ordered_actions if name in outcomes_by_name
    ]
    rechecked: list[JsonValue] = [chk.to_dict() for chk in report.checks]
    out = report.to_dict()
    out["fix"] = {
        "actions": action_list,
        "rechecked_checks": rechecked,
    }
    return out
