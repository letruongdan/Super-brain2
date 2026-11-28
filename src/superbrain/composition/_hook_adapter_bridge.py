"""Fault-free adapter translation bridge for ``superbrain.composition.hook_entry`` (SP2-5)."""

from __future__ import annotations

import math
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from superbrain.adapters.harness.claude_code import ClaudeCodeCaptureAdapter
    from superbrain.adapters.harness.codex import CodexCaptureAdapter

from superbrain.adapters.harness._common import (
    AdapterCaptureStatus,
    HarnessCaptureContext,
    strip_forbidden_client_keys,
)
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.ports.capture import CaptureEventRecord, ProducerCaptureGap, require_iso_utc_timestamp
from superbrain.ports.os import OsAdapters

_RAW_SESSION_KEYS: tuple[str, ...] = (
    "raw_session_id",
    "session_id",
    "sessionId",
    "conversation_id",
    "thread_id",
    "thread-id",
)
_STRIPPED_HOOK_KEYS: frozenset[str] = frozenset({*_RAW_SESSION_KEYS, "session_ref"})
_NATIVE_ID_KEYS: tuple[str, ...] = (
    "tool_use_id",
    "prompt_id",
    "call_id",
    "turn_id",
    "turn-id",
    "item_id",
    "message_id",
    "id",
)
_ENVELOPE_OR_ROUTING_KEYS: frozenset[str] = frozenset(
    {
        "record_kind",
        "event_id",
        "sequence",
        "recorded_at",
        "observed_at",
        "timestamp",
        "created_at",
        "producer_stream",
        "harness_id",
        "event_name",
        "hook_event_name",
        "event_type",
        "type",
        "event",
        "kind",
        "cwd",
        "transcript_path",
        "channel_kind",
        "recipient",
        "model_call",
        "payload",
        *_STRIPPED_HOOK_KEYS,
    }
)


@dataclass(frozen=True)
class PreparedNativeHook:
    """Validated host hook plan ready to materialize inside ``OutboxSpool.enqueue_hook_event`` or direct return."""

    producer_stream: str
    raw_session_id: str | None
    explicit_sequence: int | None
    explicit_event_id: str | None
    dedup_key: str | None
    fallback_recorded_at: str
    skip_code: str | None
    build_record: Callable[[int, str, str], CaptureEventRecord | ProducerCaptureGap] | None


def _extract_raw_session_id(parsed: Mapping[str, Any], kwarg_raw_sid: str | None) -> str | None:
    candidates: list[str] = []
    if isinstance(kwarg_raw_sid, str) and kwarg_raw_sid:
        candidates.append(kwarg_raw_sid)
    for key in _RAW_SESSION_KEYS:
        val = parsed.get(key)
        if val is not None:
            if not isinstance(val, str):
                raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
            if val:
                candidates.append(val)
    if not candidates:
        return None
    if len(set(candidates)) > 1:
        raise BrainError(ErrorCode.INVALID_INPUT, "ambiguous raw session identifier")
    return candidates[0]


def _strip_recursive(value: object) -> object:
    cleaned = strip_forbidden_client_keys(value)
    if isinstance(cleaned, dict):
        return {k: _strip_recursive(v) for k, v in cleaned.items() if k not in _STRIPPED_HOOK_KEYS}
    if isinstance(cleaned, list):
        return [_strip_recursive(item) for item in cleaned]
    return cleaned


def _resolve_event_name(parsed: Mapping[str, Any]) -> str | None:
    for key in ("event_name", "hook_event_name", "event_type", "type", "event", "kind"):
        val = parsed.get(key)
        if isinstance(val, str) and val:
            return val
    return None


def _resolve_recorded_at(parsed: Mapping[str, Any], os_: OsAdapters) -> str:
    for key in ("recorded_at", "observed_at", "timestamp", "created_at"):
        val = parsed.get(key)
        if val is None:
            continue
        if isinstance(val, str):
            try:
                return require_iso_utc_timestamp(val)
            except BrainError:
                try:
                    dt_val = datetime.fromisoformat(val.replace("Z", "+00:00"))
                    if dt_val.tzinfo is None:
                        dt_val = dt_val.replace(tzinfo=UTC)
                    return dt_val.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
                except ValueError as err:
                    raise BrainError(ErrorCode.INVALID_INPUT, "invalid input") from err
        if isinstance(val, (int, float)) and not isinstance(val, bool):
            epoch_val = float(val)
            if not math.isfinite(epoch_val):
                raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
            try:
                dt_epoch = datetime.fromtimestamp(epoch_val, tz=UTC)
                return dt_epoch.isoformat(timespec="microseconds").replace("+00:00", "Z")
            except (ValueError, OverflowError, OSError) as err:
                raise BrainError(ErrorCode.INVALID_INPUT, "invalid input") from err
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    return os_.clock.now().astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _extract_native_payload(parsed: Mapping[str, Any], event_name: str | None) -> object:
    if "payload" in parsed:
        return _strip_recursive(parsed["payload"])
    body: dict[str, object] = {}
    for k, v in parsed.items():
        if not isinstance(k, str) or k in _ENVELOPE_OR_ROUTING_KEYS:
            continue
        body[k] = _strip_recursive(v)
    if not body and event_name is not None:
        body["hook_event"] = event_name
    return _strip_recursive(body)


def _compute_dedup_key(
    parsed: Mapping[str, Any],
    *,
    harness_id: str,
    producer_stream: str,
    event_name: str | None,
    session_ref: str,
    explicit_event_id: str | None,
) -> str | None:
    if explicit_event_id is not None:
        return digest_bytes(canonical_json({"k": "event_id", "s": producer_stream, "v": explicit_event_id}))
    for id_key in _NATIVE_ID_KEYS:
        val = parsed.get(id_key)
        if isinstance(val, (str, int)) and not isinstance(val, bool) and str(val):
            return digest_bytes(
                canonical_json(
                    {
                        "k": "native_id",
                        "f": id_key,
                        "h": harness_id,
                        "s": producer_stream,
                        "e": event_name or "",
                        "sr": session_ref,
                        "v": str(val),
                    }
                )
            )
    return None


def prepare_native_hook(
    parsed: Mapping[str, Any],
    *,
    os_: OsAdapters,
    default_harness_id: str | None = None,
    checkout_root: Path | None = None,
    profile_path: Path | None = None,
    producer_stream: str | None = None,
    sequence: int | None = None,
    raw_session_id: str | None = None,
) -> PreparedNativeHook:
    """Validate host context/scope and prepare an adapter builder for native Claude Code or Codex hook payloads."""
    raw_hid = default_harness_id or parsed.get("harness_id")
    if raw_hid not in ("claude-code", "codex"):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    harness_id = str(raw_hid)

    repo_id = "unknown"
    checkout_id = "unknown"
    resolved_checkout = checkout_root
    if profile_path is not None:
        from superbrain.adapters.os.daemon_config import read_client_profile

        profile = read_client_profile(profile_path, os_)
        if profile.workspace is None:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        repo_id = profile.workspace.expected_workspace_id
        checkout_id = profile.workspace.expected_checkout_id
        if resolved_checkout is None:
            resolved_checkout = profile.workspace.checkout_path
        else:
            from superbrain.adapters.os.workspaces import physical_checkout

            p_chk = physical_checkout(str(resolved_checkout)).checkout_path
            p_prof = physical_checkout(str(profile.workspace.checkout_path)).checkout_path
            if p_chk != p_prof:
                raise BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch")

    if resolved_checkout is None:
        raw_cwd = parsed.get("cwd")
        if not isinstance(raw_cwd, str) or not raw_cwd:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        resolved_checkout = Path(raw_cwd)

    os_.paths.reject_unsafe_path(str(resolved_checkout))
    os_.paths.reject_links(resolved_checkout)

    eff_raw_sid = _extract_raw_session_id(parsed, raw_session_id)
    sid_token = eff_raw_sid if eff_raw_sid is not None else "anonymous"
    session_ref = digest_bytes(f"hook-session:{harness_id}:{resolved_checkout}:{sid_token}".encode())

    raw_stream = parsed.get("producer_stream")
    if isinstance(producer_stream, str) and producer_stream:
        eff_stream = producer_stream
    elif isinstance(raw_stream, str) and raw_stream:
        eff_stream = raw_stream
    else:
        if repo_id != "unknown" and checkout_id != "unknown":
            scope_seed = f"{harness_id}:{repo_id}:{checkout_id}"
        else:
            from superbrain.adapters.os.workspaces import physical_checkout

            phys = physical_checkout(str(resolved_checkout)).checkout_path
            scope_seed = f"{harness_id}:{os.path.normcase(os.fspath(phys))}"
        eff_stream = f"hook-{harness_id}-{digest_bytes(scope_seed.encode('utf-8')).removeprefix('sha256:')[:16]}"

    raw_ev_name = _resolve_event_name(parsed)
    recorded_at_default = _resolve_recorded_at(parsed, os_)
    raw_seq_val = parsed.get("sequence")
    explicit_seq: int | None = sequence if sequence is not None else (
        raw_seq_val if type(raw_seq_val) is int else None
    )
    raw_ev_id = parsed.get("event_id")
    if raw_ev_id is not None and not (isinstance(raw_ev_id, str) and raw_ev_id):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    explicit_ev_id = str(raw_ev_id) if isinstance(raw_ev_id, str) else None

    hook_base: dict[str, Any] = {str(k): v for k, v in parsed.items() if k not in _STRIPPED_HOOK_KEYS}
    if "event_name" not in hook_base and raw_ev_name is not None:
        hook_base["event_name"] = raw_ev_name
    if parsed.get("record_kind") != "capture_gap":
        hook_base["payload"] = _extract_native_payload(parsed, raw_ev_name)
    if "channel_kind" not in hook_base:
        hook_base["channel_kind"] = "local_capture"

    adapter: ClaudeCodeCaptureAdapter | CodexCaptureAdapter
    if harness_id == "claude-code":
        from superbrain.adapters.harness.claude_code import ClaudeCodeCaptureAdapter

        adapter = ClaudeCodeCaptureAdapter(os_)
    else:
        from superbrain.adapters.harness.codex import CodexCaptureAdapter

        adapter = CodexCaptureAdapter(os_)
    ctx = HarnessCaptureContext(
        checkout_root=resolved_checkout,
        repo_id=repo_id,
        checkout_id=checkout_id,
        producer_stream=eff_stream,
        session_ref=session_ref,
    )

    # Hosts pass ``transcript_path`` under their own data directory, outside the checkout. The hook event on stdin is
    # the observation; the transcript file is never read here.

    dedup_key = _compute_dedup_key(
        parsed,
        harness_id=harness_id,
        producer_stream=eff_stream,
        event_name=raw_ev_name,
        session_ref=session_ref,
        explicit_event_id=explicit_ev_id,
    )

    def _build(seq_val: int, ev_id_val: str, rec_at_val: str) -> CaptureEventRecord | ProducerCaptureGap:
        candidate = dict(hook_base)
        candidate["sequence"] = seq_val
        candidate["event_id"] = ev_id_val
        candidate["recorded_at"] = rec_at_val
        adapted = adapter.adapt_hook_event(candidate, context=ctx)
        if adapted.status is AdapterCaptureStatus.WORKSPACE_MISMATCH:
            raise BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch")
        if adapted.status is not AdapterCaptureStatus.OK or adapted.record is None:
            raise BrainError(ErrorCode.INVALID_INPUT, adapted.reason or adapted.status.value)
        return adapted.record

    # Probe once synchronously for status errors (WORKSPACE_MISMATCH, unsupported_event, etc.) when seq unknown
    probe_seq = explicit_seq if explicit_seq is not None else 1
    probe_id = explicit_ev_id if explicit_ev_id is not None else f"ev-probe-{new_id()}"
    candidate_probe = dict(hook_base)
    candidate_probe["sequence"] = probe_seq
    candidate_probe["event_id"] = probe_id
    candidate_probe["recorded_at"] = recorded_at_default
    probe_res = adapter.adapt_hook_event(candidate_probe, context=ctx)
    if probe_res.status is AdapterCaptureStatus.WORKSPACE_MISMATCH:
        raise BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch")
    if probe_res.status is not AdapterCaptureStatus.OK or probe_res.record is None:
        return PreparedNativeHook(
            eff_stream,
            eff_raw_sid,
            explicit_seq,
            explicit_ev_id,
            dedup_key,
            recorded_at_default,
            probe_res.reason or probe_res.status.value,
            None,
        )

    return PreparedNativeHook(
        producer_stream=eff_stream,
        raw_session_id=eff_raw_sid,
        explicit_sequence=explicit_seq,
        explicit_event_id=explicit_ev_id,
        dedup_key=dedup_key,
        fallback_recorded_at=recorded_at_default,
        skip_code=None,
        build_record=_build,
    )


def adapt_native_hook_payload(
    parsed: Mapping[str, Any],
    *,
    os_: OsAdapters,
    default_harness_id: str | None = None,
    checkout_root: Path | None = None,
    profile_path: Path | None = None,
    producer_stream: str | None = None,
    sequence: int | None = None,
    raw_session_id: str | None = None,
) -> tuple[CaptureEventRecord | ProducerCaptureGap | None, str | None, str | None]:
    """Translate native Claude Code / Codex hook JSON via host adapter; fail closed on mismatch."""
    prep = prepare_native_hook(
        parsed,
        os_=os_,
        default_harness_id=default_harness_id,
        checkout_root=checkout_root,
        profile_path=profile_path,
        producer_stream=producer_stream,
        sequence=sequence,
        raw_session_id=raw_session_id,
    )
    if prep.build_record is None:
        return None, prep.raw_session_id, prep.skip_code or "unavailable"
    seq = prep.explicit_sequence if prep.explicit_sequence is not None else 1
    ev_id = prep.explicit_event_id if prep.explicit_event_id is not None else f"ev-{new_id()}"
    rec = prep.build_record(seq, ev_id, prep.fallback_recorded_at)
    return rec, prep.raw_session_id, None


__all__ = ["PreparedNativeHook", "adapt_native_hook_payload", "prepare_native_hook"]
