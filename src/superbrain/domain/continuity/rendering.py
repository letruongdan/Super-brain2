"""Deterministic L0/L1/L2 rendering with strict UTF-8 bounds and live source excerpt resolution (§7.4)."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence

from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.jsonvalue import JsonValue
from superbrain.domain.continuity.budget import (
    HANDOFF_L0_GOAL_MAX_BYTES,
    HANDOFF_L0_SUMMARY_MAX_BYTES,
    HANDOFF_L1_GOAL_MAX_BYTES,
    HANDOFF_L1_RESOURCE_MAX_BYTES,
    HANDOFF_L2_MAX_BYTES,
    HANDOFF_REPLY_EXCERPT_MAX_BYTES,
    truncate_utf8_boundary,
    utf8_byte_v1_tokens,
    utf8_len,
)
from superbrain.domain.continuity.handoff_model import HandoffAgentState
from superbrain.domain.continuity.merge_rules import derive_active_sets
from superbrain.ports._handoff_types import ResolvedSourceContent


def _render_source_content(item: ResolvedSourceContent) -> dict[str, JsonValue]:
    """Render one resolved observed or history item cleanly within UTF-8 excerpt limits."""
    out: dict[str, JsonValue] = {
        "kind": item.kind,
        "source_event_id": item.source_event_id,
        "source_digest": item.source_digest,
        "status": item.status,
    }
    if item.status != "ok":
        out["reason"] = item.reason or item.status
        return out
    payload = item.payload or {}
    if item.kind in {"user_message", "constraint_reply"}:
        raw_text = payload.get("text")
        if not isinstance(raw_text, str):
            raw_text = payload.get("prompt")
        if isinstance(raw_text, str):
            excerpt, _ = truncate_utf8_boundary(raw_text, HANDOFF_REPLY_EXCERPT_MAX_BYTES)
            out["excerpt"] = excerpt
    else:
        rendered = dict(payload)
        raw_str = json.dumps(rendered, ensure_ascii=False, sort_keys=True)
        if utf8_len(raw_str) > HANDOFF_REPLY_EXCERPT_MAX_BYTES:
            clipped, _ = truncate_utf8_boundary(raw_str, HANDOFF_REPLY_EXCERPT_MAX_BYTES)
            out["excerpt"] = clipped
        else:
            out["content"] = rendered
    if item.recorded_at is not None:
        out["recorded_at"] = item.recorded_at
    return out


def _make_resource(name: str, content: str) -> dict[str, JsonValue]:
    raw = content.encode("utf-8")
    return {
        "name": name,
        "digest": digest_bytes(raw),
        "encoding": "utf-8",
        "content": content,
    }


def _chunk_json_entries(prefix: str, entries: Sequence[JsonValue], max_bytes: int) -> list[dict[str, JsonValue]]:
    if not entries:
        return []
    resources: list[dict[str, JsonValue]] = []
    bucket: list[JsonValue] = []
    part = 0
    for entry in entries:
        candidate = [*bucket, entry]
        encoded = canonical_json(candidate).decode("utf-8")
        if utf8_len(encoded) <= max_bytes:
            bucket = candidate
            continue
        if bucket:
            resources.append(_make_resource(f"{prefix}_{part}", canonical_json(bucket).decode("utf-8")))
            part += 1
        single_encoded = canonical_json([entry]).decode("utf-8")
        if utf8_len(single_encoded) <= max_bytes:
            bucket = [entry]
        else:
            clipped, _ = truncate_utf8_boundary(single_encoded, max_bytes)
            resources.append(_make_resource(f"{prefix}_{part}", clipped))
            part += 1
            bucket = []
    if bucket:
        resources.append(_make_resource(f"{prefix}_{part}", canonical_json(bucket).decode("utf-8")))
    return resources


def render_handoff_l0(
    *,
    task_goal: str,
    state: HandoffAgentState | None,
    handoff_revision: int,
    session_state: str | None,
    agent_updated_at: str | None,
    observed_through: str | None,
    other_active_warning: bool = False,
) -> str:
    """Render L0 continuity summary strictly within 600 UTF-8 bytes without source excerpts or raw session IDs."""
    goal_cut, _ = truncate_utf8_boundary(task_goal, HANDOFF_L0_GOAL_MAX_BYTES)
    active = derive_active_sets(state)
    parts: list[str] = [f"goal={goal_cut}"]
    if handoff_revision == 0 or state is None:
        parts.append("agent_handoff=none")
    else:
        if state.working_goal and state.working_goal != task_goal:
            wg_cut, _ = truncate_utf8_boundary(state.working_goal, 120)
            parts.append(f"working={wg_cut}")
        in_prog = next((s for s in state.plan if s.status == "in_progress"), None)
        if in_prog is not None:
            step_cut, _ = truncate_utf8_boundary(in_prog.summary, 80)
            parts.append(f"step={step_cut}")
        if state.next_action is not None:
            na_cut, _ = truncate_utf8_boundary(state.next_action.summary, 80)
            parts.append(f"next={na_cut}")
        parts.append(f"decisions={len(active.decisions)}")
        parts.append(f"pending_changes={len(active.pending_changes)}")
    if session_state:
        parts.append(f"session={session_state}")
    if agent_updated_at:
        parts.append(f"agent_at={agent_updated_at}")
    if observed_through:
        parts.append(f"obs_at={observed_through}")
    if other_active_warning:
        parts.append("warn=other_session_active")

    text = "; ".join(parts)
    bounded, _ = truncate_utf8_boundary(text, HANDOFF_L0_SUMMARY_MAX_BYTES)
    return bounded


def select_discover_items(
    candidates: Sequence[Mapping[str, JsonValue]],
    *,
    budget_tokens: int,
) -> tuple[list[dict[str, JsonValue]], bool]:
    """Select whole L0 items fitting a single ``utf8_byte_v1_tokens`` ceiling (§6.2, §7.4)."""
    selected: list[dict[str, JsonValue]] = []
    acc_bytes = 0
    truncated = False
    for raw in candidates:
        item = dict(raw)
        summary = item.get("summary")
        if isinstance(summary, str) and utf8_len(summary) > HANDOFF_L0_SUMMARY_MAX_BYTES:
            item["summary"] = truncate_utf8_boundary(summary, HANDOFF_L0_SUMMARY_MAX_BYTES)[0]
        item_bytes = utf8_len(canonical_json(item).decode("utf-8"))
        candidate_bytes = acc_bytes + item_bytes
        if utf8_byte_v1_tokens(candidate_bytes) > budget_tokens:
            truncated = True
            break
        selected.append(item)
        acc_bytes = candidate_bytes
    return selected, truncated


def render_handoff_l1(
    *,
    task_id: str,
    artifact_id: str,
    revision: int,
    revision_epoch: int,
    handoff_revision: int,
    writer_generation: int,
    holder_harness_id: str | None,
    session_state: str | None,
    agent_updated_at: str | None,
    observed_through: str | None,
    task_goal: str,
    state: HandoffAgentState | None,
    observed_sources: Sequence[ResolvedSourceContent],
    agent_ref: str | None = None,
    observed_ref: str | None = None,
    task_state_source: str = "agent",
    restore_epoch_for_header: int | None = None,
    events_since_agent: int = 0,
    max_optional_resources: int = 16,
) -> tuple[list[dict[str, JsonValue]], bool]:
    """Render L1 resources (header + <=8KB required chunks + observed + optional), never dropping item #31+."""
    effective_epoch = revision_epoch if restore_epoch_for_header is None else restore_epoch_for_header
    active = derive_active_sets(state)
    l1_goal, goal_clipped = truncate_utf8_boundary(task_goal, HANDOFF_L1_GOAL_MAX_BYTES)
    header: dict[str, JsonValue] = {
        "artifact_id": artifact_id,
        "revision_epoch": revision_epoch,
        "revision": revision,
        "handoff_revision": handoff_revision,
        "agent_ref": agent_ref,
        "observed_ref": observed_ref,
        "task_id": task_id,
        "task_state": "open" if state is None else state.task_state,
        "task_state_source": task_state_source if handoff_revision > 0 else "inferred",
        "fence": {"restore_epoch": effective_epoch, "writer_generation": writer_generation},
        "holder_harness_id": holder_harness_id,
        "session_state": session_state,
        "agent_updated_at": agent_updated_at,
        "observed_through": observed_through,
        "task_goal": l1_goal,
        "task_goal_truncated": goal_clipped,
    }
    if state is not None and state.working_goal and state.working_goal != task_goal:
        header["working_goal"] = state.working_goal

    resources: list[dict[str, JsonValue]] = [_make_resource("handoff_header", canonical_json(header).decode("utf-8"))]

    # Required section: constraints, pending changes, decisions, rejected, plan, next_action, tooling, long_running.
    required_entries: list[JsonValue] = []
    if state is not None:
        for c in active.user_constraints:
            required_entries.append({"section": "user_constraint", **c.to_dict()})
        for ch in active.pending_changes:
            required_entries.append({"section": "constraint_change", **ch.to_dict()})
        for d in active.decisions:
            required_entries.append({"section": "decision", **d.to_dict()})
        for r in active.rejected:
            required_entries.append({"section": "rejected", **r.to_dict()})
        for step in state.plan:
            required_entries.append({"section": "plan", **step.to_dict()})
        if state.next_action is not None:
            required_entries.append({"section": "next_action", **state.next_action.to_dict()})
        for tool in state.tooling:
            required_entries.append({"section": "tooling", **tool.to_dict()})
        if state.long_running is not None:
            required_entries.append({"section": "long_running", **state.long_running.to_dict()})
    if not required_entries:
        required_entries.append({"section": "required_empty", "note": "no agent handoff items yet"})
    resources.extend(_chunk_json_entries("required", required_entries, HANDOFF_L1_RESOURCE_MAX_BYTES))

    # Observed section (resolved live at read time).
    obs_entries: list[JsonValue] = [
        {"events_since_agent": events_since_agent, "observed_through": observed_through},
        *(_render_source_content(src) for src in observed_sources),
    ]
    resources.extend(_chunk_json_entries("observed", obs_entries, HANDOFF_L1_RESOURCE_MAX_BYTES))

    # Optional section (hypotheses): emit if within optional resource count, else mark incomplete_optional=True.
    incomplete_optional = False
    if state is not None and state.hypotheses:
        opt_entries: list[JsonValue] = [{"section": "hypothesis", "text": h} for h in state.hypotheses]
        opt_resources = _chunk_json_entries("optional", opt_entries, HANDOFF_L1_RESOURCE_MAX_BYTES)
        if len(opt_resources) > max_optional_resources:
            incomplete_optional = True
        else:
            resources.extend(opt_resources)

    return resources, incomplete_optional


def render_handoff_l2(
    *,
    l1_resources: Sequence[Mapping[str, JsonValue]],
    full_task_goal: str,
    state: HandoffAgentState | None,
    revision_history: Sequence[Mapping[str, JsonValue]],
    conversation_excerpts: Sequence[ResolvedSourceContent],
) -> list[dict[str, JsonValue]]:
    """Render L2 full detail + revision/closed history bounded to 256 KB UTF-8 newest-first (§7.4)."""
    resources: list[dict[str, JsonValue]] = [dict(r) for r in l1_resources]
    used_bytes = sum(utf8_len(str(r.get("content", ""))) for r in resources)

    history_payload: dict[str, JsonValue] = {
        "full_task_goal": full_task_goal,
        "all_decisions": [] if state is None else [d.to_dict() for d in state.decisions],
        "all_rejected": [] if state is None else [r.to_dict() for r in state.rejected],
        "closed_changes": [] if state is None else [c.to_dict() for c in state.closed_changes],
        "revision_history": [dict(h) for h in revision_history],
        "conversation_excerpts": [_render_source_content(c) for c in conversation_excerpts],
    }
    hist_resources = _chunk_json_entries("l2_history", [history_payload], HANDOFF_L1_RESOURCE_MAX_BYTES)
    if len(hist_resources) == 1 and used_bytes + utf8_len(str(hist_resources[0]["content"])) <= HANDOFF_L2_MAX_BYTES:
        resources.extend(hist_resources)
        return resources

    # Pack piecewise within 256 KB newest-first so oversized goals/history never violate the 256 KB ceiling.
    pieces: list[tuple[str, JsonValue]] = [
        ("l2_goal", {"full_task_goal": full_task_goal}),
        ("l2_closed", {"closed_changes": history_payload["closed_changes"]}),
        ("l2_decisions", {"all_decisions": history_payload["all_decisions"]}),
        ("l2_rejected", {"all_rejected": history_payload["all_rejected"]}),
        ("l2_revisions", {"revision_history": history_payload["revision_history"]}),
        ("l2_conversation", {"conversation_excerpts": history_payload["conversation_excerpts"]}),
    ]
    for name, piece in pieces:
        for chunk in _chunk_json_entries(name, [piece], HANDOFF_L1_RESOURCE_MAX_BYTES):
            cbytes = utf8_len(str(chunk["content"]))
            if used_bytes + cbytes > HANDOFF_L2_MAX_BYTES:
                return resources
            resources.append(chunk)
            used_bytes += cbytes
    return resources


__all__ = [
    "ResolvedSourceContent",
    "render_handoff_l0",
    "render_handoff_l1",
    "render_handoff_l2",
    "select_discover_items",
]
