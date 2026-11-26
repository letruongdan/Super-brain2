"""Fault-free adapter translation bridge for ``superbrain.composition.hook_entry`` (SP2-5)."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from superbrain.adapters.harness._common import AdapterCaptureStatus, HarnessCaptureContext
from superbrain.adapters.harness.claude_code import ClaudeCodeCaptureAdapter
from superbrain.adapters.harness.codex import CodexCaptureAdapter
from superbrain.adapters.os.daemon_config import read_client_profile
from superbrain.adapters.os.workspaces import physical_checkout
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.capture import CaptureEventRecord, ProducerCaptureGap
from superbrain.ports.os import OsAdapters

_RAW_SESSION_KEYS: tuple[str, ...] = ("raw_session_id", "session_id", "sessionId", "conversation_id")
_STRIPPED_HOOK_KEYS: frozenset[str] = frozenset({*_RAW_SESSION_KEYS, "session_ref"})


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
    """Translate native Claude Code / Codex hook JSON via host adapter; fail closed on mismatch.

    Any raw session key (`session_id`, `raw_session_id`, `sessionId`, `conversation_id`) and any client-supplied
    `session_ref` are stripped; `session_ref` is always derived server-side and raw IDs go to `PrivacyGate`.
    If `transcript_path` is provided, containment under the pinned checkout is verified before emitting the event.
    """
    raw_hid = default_harness_id or parsed.get("harness_id")
    if raw_hid not in ("claude-code", "codex"):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    harness_id = str(raw_hid)

    repo_id = "unknown"
    checkout_id = "unknown"
    resolved_checkout = checkout_root
    if profile_path is not None:
        profile = read_client_profile(profile_path, os_)
        if profile.workspace is None:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        repo_id = profile.workspace.expected_workspace_id
        checkout_id = profile.workspace.expected_checkout_id
        if resolved_checkout is None:
            resolved_checkout = profile.workspace.checkout_path
        else:
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
    eff_stream = (
        producer_stream
        if isinstance(producer_stream, str) and producer_stream
        else (raw_stream if isinstance(raw_stream, str) and raw_stream else f"hook-{harness_id}")
    )

    hook_input: dict[str, Any] = {
        str(k): v for k, v in parsed.items() if k not in _STRIPPED_HOOK_KEYS
    }
    if "event_name" not in hook_input:
        alt_name = parsed.get("hook_event_name") or parsed.get("event_type")
        if isinstance(alt_name, str) and alt_name:
            hook_input["event_name"] = alt_name
    if sequence is not None and "sequence" not in hook_input:
        hook_input["sequence"] = sequence

    adapter = ClaudeCodeCaptureAdapter(os_) if harness_id == "claude-code" else CodexCaptureAdapter(os_)
    ctx = HarnessCaptureContext(
        checkout_root=resolved_checkout,
        repo_id=repo_id,
        checkout_id=checkout_id,
        producer_stream=eff_stream,
        session_ref=session_ref,
    )

    raw_tr = parsed.get("transcript_path")
    if raw_tr is not None:
        if not isinstance(raw_tr, str) or not raw_tr:
            return None, eff_raw_sid, "unavailable"
        tr_res = adapter.read_scoped_transcript(
            Path(raw_tr),
            context=ctx,
            allowed_roots=(resolved_checkout,),
        )
        if tr_res.status is not AdapterCaptureStatus.OK:
            return None, eff_raw_sid, tr_res.status.value

    adapted = adapter.adapt_hook_event(hook_input, context=ctx)
    if adapted.status is AdapterCaptureStatus.WORKSPACE_MISMATCH:
        raise BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch")
    if adapted.status is not AdapterCaptureStatus.OK or adapted.record is None:
        return None, eff_raw_sid, adapted.reason or adapted.status.value
    return adapted.record, eff_raw_sid, None


__all__ = ["adapt_native_hook_payload"]
