"""Pure long-running checkpoint extraction shared by domain rules and the store's read-time rebuild."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

from superbrain.ports.capture import CaptureEventRecord
from superbrain.ports.continuity import LongRunningCheckpoint


def _lr_parse_iso_utc(timestamp: str) -> datetime:
    return datetime.fromisoformat(timestamp[:-1] + "+00:00").astimezone(UTC)


def extract_long_running_checkpoint(
    events: Sequence[CaptureEventRecord],
) -> LongRunningCheckpoint | None:
    """Return the newest still-running ``long_running_job`` checkpoint, or ``None`` if completed."""
    found = extract_long_running_with_source(events)
    return None if found is None else found[0]


def extract_long_running_with_source(
    events: Sequence[CaptureEventRecord],
) -> tuple[LongRunningCheckpoint, CaptureEventRecord] | None:
    """The newest still-running checkpoint together with the event it was read from."""
    ordered = sorted(
        enumerate(events),
        key=lambda item: (_lr_parse_iso_utc(item[1].recorded_at), item[1].sequence, item[0]),
    )
    active_by_key: dict[str, tuple[LongRunningCheckpoint, CaptureEventRecord]] = {}
    for _, ev in ordered:
        if ev.kind != "long_running_job":
            continue
        payload = ev.payload
        status = payload.get("status")
        raw_pid = payload.get("pid")
        pid = raw_pid if isinstance(raw_pid, int) and not isinstance(raw_pid, bool) else None
        raw_cmd = payload.get("command")
        pid_key = f"pid:{pid}" if pid is not None else f"cmd:{raw_cmd if isinstance(raw_cmd, str) else '_'}"
        if status == "completed":
            if pid is not None:
                active_by_key.pop(f"pid:{pid}", None)
            elif pid_key in active_by_key:
                active_by_key.pop(pid_key, None)
            else:
                active_by_key.clear()
            continue
        if status != "running":
            continue
        command = raw_cmd if isinstance(raw_cmd, str) and raw_cmd.strip() else "unknown"
        raw_cwd = payload.get("cwd")
        cwd = raw_cwd if isinstance(raw_cwd, str) and raw_cwd.strip() else "."
        raw_rev = payload.get("source_revision")
        source_revision = raw_rev if isinstance(raw_rev, str) and raw_rev.strip() else "unknown"
        raw_started = payload.get("started_at")
        started_at = raw_started if isinstance(raw_started, str) and raw_started.strip() else ev.recorded_at
        raw_log = payload.get("log_or_receipt_path")
        log_path = raw_log if isinstance(raw_log, str) and raw_log.strip() else None
        raw_next = payload.get("next_action")
        next_action = raw_next if isinstance(raw_next, str) and raw_next.strip() else "inspect running job"
        active_by_key[pid_key] = (
            LongRunningCheckpoint(
                command=command,
                cwd=cwd,
                source_revision=source_revision,
                pid=pid,
                started_at=started_at,
                log_or_receipt_path=log_path,
                next_action=next_action,
            ),
            ev,
        )
    if not active_by_key:
        return None
    last_key = list(active_by_key)[-1]
    return active_by_key[last_key]


__all__ = ["extract_long_running_checkpoint", "extract_long_running_with_source"]
