"""Pure deterministic rules for Continuity Worker scheduling and signal extraction."""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta

from superbrain.core._kernel_base import is_strict_int, require_non_negative_int
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.domain.continuity.sessions import extract_long_running_with_source
from superbrain.ports.capture import CaptureEventRecord
from superbrain.ports.continuity import (
    WORKER_EVENT_THRESHOLD,
    WORKER_MAX_AGE_S,
    ErrorSignatureSignal,
    ObservedSummary,
    TestRunSignal,
)

_EDIT_TOOLS: frozenset[str] = frozenset(
    {"edit", "multiedit", "write", "notebookedit", "file_edit", "file_write"}
)
_USER_PROMPT_KINDS: frozenset[str] = frozenset({"user_prompt", "user_message"})
_CORRECTION_RE = re.compile(
    r"(?i)(?:\b(?:don['’]?t|do\s+not|never|stop|avoid|instead|wrong)\b|^(?:please\s+)?(?:use|switch\s+to|always|prefer)\b)"
)


def _invalid(message: str = "invalid continuity worker input") -> BrainError:
    return BrainError(ErrorCode.INVALID_INPUT, message)


def _parse_iso_utc(timestamp: str) -> datetime:
    return datetime.fromisoformat(timestamp[:-1] + "+00:00").astimezone(UTC)


def _require_aware_utc(value: object, *, label: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise _invalid(f"timezone-aware datetime required for {label}")
    return value.astimezone(UTC)


def should_schedule_refresh(
    *,
    pending_event_count: int,
    first_pending_at: datetime | None,
    now: datetime,
    job_in_flight: bool = False,
) -> bool:
    """Return True when continuity refresh hits 20 pending events or 60s age with no job running."""
    if type(job_in_flight) is not bool:
        raise _invalid("invalid job_in_flight flag")
    count = require_non_negative_int(pending_event_count)
    now_dt = _require_aware_utc(now, label="now")
    first_dt = (
        _require_aware_utc(first_pending_at, label="first_pending_at")
        if first_pending_at is not None
        else None
    )
    if job_in_flight or count <= 0:
        return False
    if count >= WORKER_EVENT_THRESHOLD:
        return True
    if first_dt is not None and (now_dt - first_dt) >= timedelta(seconds=WORKER_MAX_AGE_S):
        return True
    return False


def _extract_command_text(payload: Mapping[str, JsonValue]) -> str | None:
    cmd = payload.get("command")
    if isinstance(cmd, str) and cmd.strip():
        return cmd.strip()
    tool_input = payload.get("tool_input")
    if isinstance(tool_input, Mapping):
        nested = tool_input.get("command")
        if isinstance(nested, str) and nested.strip():
            return nested.strip()
    return None


def _extract_edited_file_paths(ev: CaptureEventRecord) -> list[str]:
    payload = ev.payload
    raw_tool = payload.get("tool_name")
    if not isinstance(raw_tool, str):
        raw_tool = payload.get("tool")
    tool_lower = raw_tool.lower() if isinstance(raw_tool, str) else ""
    is_edit_event = (
        tool_lower in _EDIT_TOOLS
        or ev.kind in {"file_edit", "file_write"}
        or payload.get("modified") is True
    )
    if not is_edit_event:
        return []
    paths: list[str] = []
    for key in ("file_path", "path"):
        val = payload.get(key)
        if isinstance(val, str) and val.strip():
            paths.append(val.strip())
    tool_input = payload.get("tool_input")
    if isinstance(tool_input, Mapping):
        for key in ("file_path", "path"):
            val = tool_input.get(key)
            if isinstance(val, str) and val.strip():
                paths.append(val.strip())
    return paths


def extract_observed_summary(events: Sequence[CaptureEventRecord]) -> ObservedSummary:
    """Deterministically summarize capture events without model calls or raw session IDs."""
    for ev in events:
        if not isinstance(ev, CaptureEventRecord):
            raise _invalid("expected CaptureEventRecord sequence")

    if not events:
        return ObservedSummary(
            latest_high_seq=0,
            last_event_at=None,
            test_runs=(),
            error_signatures=(),
            modified_files=(),
            user_corrections=(),
            long_running=None,
            item_count=0,
            source_events=(),
            items=(),
            long_running_source=None,
        )

    latest_high_seq = max(ev.sequence for ev in events)
    latest_event = max(events, key=lambda ev: (_parse_iso_utc(ev.recorded_at), ev.sequence))
    test_runs: list[TestRunSignal] = []
    err_counts: Counter[str] = Counter()
    modified_files: list[str] = []
    seen_files: set[str] = set()
    user_corrections: list[str] = []
    seen_corrections: set[str] = set()
    source_events: list[tuple[str, int, str, str]] = []
    items: list[tuple[str, str, str]] = []

    for ev in events:
        payload = ev.payload
        payload_digest = digest_bytes(canonical_json(payload))
        source_events.append((ev.producer_stream, ev.sequence, ev.event_id, payload_digest))

        def _item(kind: str, ev: CaptureEventRecord = ev, digest: str = payload_digest) -> None:
            ref = (kind, ev.event_id, digest)
            if ref not in items:
                items.append(ref)

        command = _extract_command_text(payload)
        exit_code = payload.get("exit_code")
        if command is not None and is_strict_int(exit_code):
            assert isinstance(exit_code, int)
            test_runs.append(TestRunSignal(command=command, exit_code=exit_code, recorded_at=ev.recorded_at))
            _item("command_exit")

        raw_sig = payload.get("error_signature")
        if not isinstance(raw_sig, str) and ev.kind == "error":
            raw_sig = payload.get("signature")
        if isinstance(raw_sig, str) and raw_sig.strip():
            err_counts[raw_sig.strip()] += 1
            _item("error")

        for fpath in _extract_edited_file_paths(ev):
            if fpath not in seen_files:
                seen_files.add(fpath)
                modified_files.append(fpath)
            _item("file_changed")

        if ev.kind in _USER_PROMPT_KINDS or payload.get("role") == "user":
            raw_text = payload.get("text")
            if not isinstance(raw_text, str):
                raw_text = payload.get("prompt")
            if isinstance(raw_text, str):
                text = raw_text.strip()
                if text and _CORRECTION_RE.search(text) is not None and text not in seen_corrections:
                    seen_corrections.add(text)
                    user_corrections.append(text)
                if text:
                    _item("user_message")

    error_signatures = tuple(
        ErrorSignatureSignal(signature=sig, count=cnt) for sig, cnt in err_counts.items()
    )
    found_lr = extract_long_running_with_source(events)
    long_running = None if found_lr is None else found_lr[0]
    long_running_source: tuple[str, int, str, str] | None = None
    if found_lr is not None:
        lr_ev = found_lr[1]
        lr_digest = digest_bytes(canonical_json(lr_ev.payload))
        long_running_source = (lr_ev.producer_stream, lr_ev.sequence, lr_ev.event_id, lr_digest)
        if ("long_running", lr_ev.event_id, lr_digest) not in items:
            items.append(("long_running", lr_ev.event_id, lr_digest))

    return ObservedSummary(
        latest_high_seq=latest_high_seq,
        last_event_at=latest_event.recorded_at,
        test_runs=tuple(test_runs),
        error_signatures=error_signatures,
        modified_files=tuple(modified_files),
        user_corrections=tuple(user_corrections),
        long_running=long_running,
        item_count=len(events),
        source_events=tuple(source_events),
        items=tuple(items),
        long_running_source=long_running_source,
    )


def execute_continuity_refresh_payload(payload_bytes: bytes) -> bytes:
    """Decode worker refresh job payload bytes and emit canonical ``ObservedSummary`` JSON bytes."""
    if type(payload_bytes) is not bytes:
        raise _invalid("payload_bytes must be bytes")
    try:
        decoded: object = json.loads(payload_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as err:
        raise _invalid("invalid continuity refresh JSON payload") from err

    if isinstance(decoded, list):
        raw_events = decoded
    elif isinstance(decoded, Mapping) and isinstance(decoded.get("events"), list):
        raw_events = decoded["events"]
    else:
        raise _invalid("continuity refresh payload must contain an events list")

    records: list[CaptureEventRecord] = []
    for item in raw_events:
        if not isinstance(item, Mapping):
            raise _invalid("each refresh event entry must be a JSON object")
        records.append(CaptureEventRecord.from_dict(item))

    summary = extract_observed_summary(records)
    # Only refs leave the worker: content stays with its source event and is rebuilt when served (spec 7.4).
    return canonical_json(summary.to_refs_dict())


__all__ = [
    "execute_continuity_refresh_payload",
    "extract_observed_summary",
    "should_schedule_refresh",
]
