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


def _render_l1_header_only_task_state(
    task_state: str | None, state: HandoffAgentState | None
) -> str:
    if task_state is not None:
        return task_state
    return "open" if state is None else state.task_state


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
    task_state: str | None = None,
    task_state_source: str = "agent",
    restore_epoch_for_header: int | None = None,
    events_since_agent: int = 0,
    max_optional_resources: int = 16,
) -> tuple[list[dict[str, JsonValue]], bool]:
    """Render L1 resources (header + <=8KB required chunks + observed + optional), never dropping item #31+."""
    effective_epoch = revision_epoch if restore_epoch_for_header is None else restore_epoch_for_header
    active = derive_active_sets(state)
    l1_goal, goal_clipped = truncate_utf8_boundary(task_goal, HANDOFF_L1_GOAL_MAX_BYTES)
    eff_task_state = _render_l1_header_only_task_state(task_state, state)
    eff_task_state_source = task_state_source if (handoff_revision > 0 or agent_ref is not None) else (
        task_state_source if task_state is not None else "inferred"
    )
    header: dict[str, JsonValue] = {
        "artifact_id": artifact_id,
        "revision_epoch": revision_epoch,
        "revision": revision,
        "handoff_revision": handoff_revision,
        "agent_ref": agent_ref,
        "observed_ref": observed_ref,
        "task_id": task_id,
        "task_state": eff_task_state,
        "task_state_source": eff_task_state_source,
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


def _pack_goal_chunks(
    full_task_goal: str, *, used_bytes: int, max_total_bytes: int
) -> tuple[list[dict[str, JsonValue]], int, bool]:
    encoded_full = canonical_json({"full_task_goal": full_task_goal}).decode("utf-8")
    full_len = utf8_len(encoded_full)
    if full_len <= HANDOFF_L1_RESOURCE_MAX_BYTES and used_bytes + full_len <= max_total_bytes:
        return [_make_resource("l2_goal_0", encoded_full)], used_bytes + full_len, False
    chunks: list[dict[str, JsonValue]] = []
    rest = full_task_goal
    part = 0
    # Leave room for {"full_task_goal":"..."} wrapper + JSON escaping overhead.
    max_text_bytes = HANDOFF_L1_RESOURCE_MAX_BYTES - 1024
    while rest:
        seg, _ = truncate_utf8_boundary(rest, max_text_bytes)
        if not seg:
            return chunks, used_bytes, True
        # Remove trailing "..." if truncated purely for chunking.
        if seg.endswith("...") and len(seg) < len(rest):
            seg = seg[:-3]
        if not seg:
            return chunks, used_bytes, True
        enc = canonical_json({"full_task_goal": seg}).decode("utf-8")
        clen = utf8_len(enc)
        while clen > HANDOFF_L1_RESOURCE_MAX_BYTES and len(seg) > 1:
            seg = seg[: max(1, len(seg) // 2)]
            enc = canonical_json({"full_task_goal": seg}).decode("utf-8")
            clen = utf8_len(enc)
        if clen > HANDOFF_L1_RESOURCE_MAX_BYTES or used_bytes + clen > max_total_bytes:
            return chunks, used_bytes, True
        chunks.append(_make_resource(f"l2_goal_{part}", enc))
        used_bytes += clen
        part += 1
        rest = rest[len(seg) :]
    return chunks, used_bytes, False


def _pack_list_section(
    prefix: str,
    field_key: str,
    entries: Sequence[JsonValue],
    *,
    used_bytes: int,
    max_total_bytes: int,
) -> tuple[list[dict[str, JsonValue]], int, bool]:
    """Pack whole list items sequentially into valid <=8 KB JSON chunks within ``max_total_bytes``."""
    if not entries:
        enc_empty = canonical_json({field_key: []}).decode("utf-8")
        elen = utf8_len(enc_empty)
        if elen <= HANDOFF_L1_RESOURCE_MAX_BYTES and used_bytes + elen <= max_total_bytes:
            return [_make_resource(f"{prefix}_0", enc_empty)], used_bytes + elen, False
        return [], used_bytes, True

    out: list[dict[str, JsonValue]] = []
    bucket: list[JsonValue] = []
    part = 0
    for entry in entries:
        cand_enc = canonical_json({field_key: [*bucket, entry]}).decode("utf-8")
        cand_len = utf8_len(cand_enc)
        if cand_len <= HANDOFF_L1_RESOURCE_MAX_BYTES and used_bytes + cand_len <= max_total_bytes:
            bucket.append(entry)
            continue
        if bucket:
            flush_enc = canonical_json({field_key: bucket}).decode("utf-8")
            flush_len = utf8_len(flush_enc)
            out.append(_make_resource(f"{prefix}_{part}", flush_enc))
            used_bytes += flush_len
            part += 1
            bucket = []
        single_enc = canonical_json({field_key: [entry]}).decode("utf-8")
        single_len = utf8_len(single_enc)
        if single_len <= HANDOFF_L1_RESOURCE_MAX_BYTES and used_bytes + single_len <= max_total_bytes:
            bucket = [entry]
        else:
            return out, used_bytes, True
    if bucket:
        flush_enc = canonical_json({field_key: bucket}).decode("utf-8")
        out.append(_make_resource(f"{prefix}_{part}", flush_enc))
        used_bytes += utf8_len(flush_enc)
    return out, used_bytes, False


def render_handoff_l2(
    *,
    l1_resources: Sequence[Mapping[str, JsonValue]],
    full_task_goal: str,
    state: HandoffAgentState | None,
    revision_history: Sequence[Mapping[str, JsonValue]],
    conversation_excerpts: Sequence[ResolvedSourceContent],
    max_total_bytes: int = HANDOFF_L2_MAX_BYTES,
) -> list[dict[str, JsonValue]]:
    """Render L2 full detail + revision/closed history bounded to 256 KB UTF-8 newest-first (§7.4)."""
    resources: list[dict[str, JsonValue]] = [dict(r) for r in l1_resources]
    used_bytes = sum(utf8_len(str(r.get("content", ""))) for r in resources)

    rev_list: list[JsonValue] = [dict(h) for h in revision_history]
    all_dec: list[JsonValue] = [] if state is None else [d.to_dict() for d in state.decisions]
    all_rej: list[JsonValue] = [] if state is None else [r.to_dict() for r in state.rejected]
    closed_chg: list[JsonValue] = [] if state is None else [c.to_dict() for c in state.closed_changes]
    conv_list: list[JsonValue] = [_render_source_content(c) for c in conversation_excerpts]

    history_payload: dict[str, JsonValue] = {
        "full_task_goal": full_task_goal,
        "all_decisions": all_dec,
        "all_rejected": all_rej,
        "closed_changes": closed_chg,
        "revision_history": rev_list,
        "conversation_excerpts": conv_list,
    }
    encoded_all = canonical_json([history_payload]).decode("utf-8")
    all_bytes = utf8_len(encoded_all)
    if all_bytes <= HANDOFF_L1_RESOURCE_MAX_BYTES and used_bytes + all_bytes <= max_total_bytes:
        resources.append(_make_resource("l2_history_0", encoded_all))
        return resources

    # Pack piecewise within max_total_bytes keeping every resource valid JSON <= 8 KB.
    goal_chunks, used_bytes, exhausted = _pack_goal_chunks(
        full_task_goal, used_bytes=used_bytes, max_total_bytes=max_total_bytes
    )
    resources.extend(goal_chunks)
    if exhausted:
        return resources

    sections: tuple[tuple[str, str, Sequence[JsonValue]], ...] = (
        ("l2_closed", "closed_changes", closed_chg),
        ("l2_decisions", "all_decisions", all_dec),
        ("l2_rejected", "all_rejected", all_rej),
        ("l2_revisions", "revision_history", rev_list),
        ("l2_conversation", "conversation_excerpts", conv_list),
    )
    for prefix, field_key, entries in sections:
        sec_chunks, used_bytes, exhausted = _pack_list_section(
            prefix, field_key, entries, used_bytes=used_bytes, max_total_bytes=max_total_bytes
        )
        resources.extend(sec_chunks)
        if exhausted:
            return resources
    return resources


__all__ = [
    "ResolvedSourceContent",
    "render_handoff_l0",
    "render_handoff_l1",
    "render_handoff_l2",
    "select_discover_items",
]
