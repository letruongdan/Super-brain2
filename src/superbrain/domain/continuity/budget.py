"""UTF-8 byte limits, token estimation (``utf8-byte-v1``), and 32 KB non-growing exemption (§6.2, §7.4)."""

from __future__ import annotations

from collections.abc import Mapping

from superbrain.core._kernel_base import require_non_negative_int
from superbrain.core.canonical import canonical_json
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.domain.continuity.handoff_model import HandoffAgentState
from superbrain.domain.continuity.merge_rules import derive_active_sets

HANDOFF_ITEM_MAX_BYTES = 2 * 1024
HANDOFF_PATCH_MAX_BYTES = 16 * 1024
HANDOFF_REQUIRED_TOTAL_MAX_BYTES = 32 * 1024
HANDOFF_CONSTRAINTS_MAX_BYTES = 16 * 1024
HANDOFF_PENDING_CHANGES_MAX_BYTES = 4 * 1024
HANDOFF_REPLY_EXCERPT_MAX_BYTES = 512
HANDOFF_L0_GOAL_MAX_BYTES = 200
HANDOFF_L1_GOAL_MAX_BYTES = 2 * 1024
HANDOFF_L0_SUMMARY_MAX_BYTES = 600
HANDOFF_L1_RESOURCE_MAX_BYTES = 8 * 1024
HANDOFF_L2_MAX_BYTES = 256 * 1024


def utf8_len(text: str) -> int:
    """Exact UTF-8 byte length of ``text``."""
    return len(text.encode("utf-8"))


def canonical_utf8_len(value: JsonValue) -> int:
    """Exact UTF-8 byte length of canonical JSON encoding."""
    return len(canonical_json(value))


def truncate_utf8_boundary(text: str, max_bytes: int, *, marker: str = "...") -> tuple[str, bool]:
    """Truncate ``text`` strictly on a UTF-8 character boundary within ``max_bytes``."""
    require_non_negative_int(max_bytes)
    raw = text.encode("utf-8")
    if len(raw) <= max_bytes:
        return text, False
    marker_bytes = marker.encode("utf-8")
    if max_bytes <= len(marker_bytes):
        prefix = raw[:max_bytes].decode("utf-8", errors="ignore")
        return prefix, True
    keep = max_bytes - len(marker_bytes)
    head = raw[:keep].decode("utf-8", errors="ignore")
    return head + marker, True


def utf8_byte_v1_tokens(total_bytes: int) -> int:
    """Deterministic ``ceil(total_bytes / 4)`` token estimator (§6.2)."""
    require_non_negative_int(total_bytes)
    return (total_bytes + 3) // 4


def active_constraints_bytes(state: HandoffAgentState | None) -> int:
    """Exact UTF-8 bytes of active ``user_constraints``."""
    if state is None:
        return 0
    return canonical_utf8_len([c.to_dict() for c in state.user_constraints])


def pending_changes_bytes(state: HandoffAgentState | None) -> int:
    """Exact UTF-8 bytes of the separate ``<= 4 KB`` pending ``constraint_changes`` zone."""
    active = derive_active_sets(state)
    if not active.pending_changes:
        return 0
    return canonical_utf8_len([c.to_dict() for c in active.pending_changes])


def required_section_bytes(state: HandoffAgentState | None) -> int:
    """Exact UTF-8 bytes of required handoff content counting toward the 32 KB ceiling (§7.4)."""
    if state is None:
        return 0
    active = derive_active_sets(state)
    payload: JsonValue = {
        "decisions": [d.to_dict() for d in active.decisions],
        "long_running": None if state.long_running is None else state.long_running.to_dict(),
        "next_action": None if state.next_action is None else state.next_action.to_dict(),
        "plan": [p.to_dict() for p in state.plan],
        "rejected": [r.to_dict() for r in active.rejected],
        "tooling": [t.to_dict() for t in state.tooling],
        "user_constraints": [c.to_dict() for c in active.user_constraints],
    }
    return canonical_utf8_len(payload)


def _check_patch_item_limits(raw_patch: Mapping[str, JsonValue]) -> None:
    if len(canonical_json(dict(raw_patch))) > HANDOFF_PATCH_MAX_BYTES:
        raise BrainError(ErrorCode.INVALID_INPUT, "handoff patch exceeds 16 KB UTF-8 limit")
    wg = raw_patch.get("working_goal")
    if isinstance(wg, str) and utf8_len(wg) > HANDOFF_ITEM_MAX_BYTES:
        raise BrainError(ErrorCode.INVALID_INPUT, "working_goal exceeds 2 KB UTF-8 limit")
    for list_key in (
        "plan",
        "decisions",
        "rejected",
        "user_constraints",
        "constraint_changes",
        "closed_changes",
        "tooling",
        "hypotheses",
    ):
        items = raw_patch.get(list_key)
        if isinstance(items, list):
            for entry in items:
                item_size = utf8_len(entry) if isinstance(entry, str) else canonical_utf8_len(entry)
                if item_size > HANDOFF_ITEM_MAX_BYTES:
                    raise BrainError(ErrorCode.INVALID_INPUT, "handoff item exceeds 2 KB UTF-8 limit")
    for single_key in ("next_action", "long_running"):
        val = raw_patch.get(single_key)
        if val is not None and canonical_utf8_len(val) > HANDOFF_ITEM_MAX_BYTES:
            raise BrainError(ErrorCode.INVALID_INPUT, "handoff item exceeds 2 KB UTF-8 limit")


def _uses_compaction(raw_patch: Mapping[str, JsonValue]) -> bool:
    decisions = raw_patch.get("decisions")
    if isinstance(decisions, list) and any(isinstance(d, Mapping) and "supersedes" in d for d in decisions):
        return True
    rejected = raw_patch.get("rejected")
    if isinstance(rejected, list) and any(isinstance(r, Mapping) and "merges" in r for r in rejected):
        return True
    return False


def validate_handoff_write_limits(
    before: HandoffAgentState | None,
    after: HandoffAgentState,
    raw_patch: Mapping[str, JsonValue],
) -> None:
    """Enforce item (2 KB), patch (16 KB), constraints (16 KB), pending changes (4 KB), and 32 KB limits."""
    _check_patch_item_limits(raw_patch)
    if active_constraints_bytes(after) > HANDOFF_CONSTRAINTS_MAX_BYTES:
        raise BrainError(ErrorCode.INVALID_INPUT, "active user_constraints exceed 16 KB UTF-8 limit")
    if pending_changes_bytes(after) > HANDOFF_PENDING_CHANGES_MAX_BYTES:
        raise BrainError(ErrorCode.INVALID_INPUT, "pending constraint_changes exceed 4 KB UTF-8 limit")
    after_req = required_section_bytes(after)
    if after_req > HANDOFF_REQUIRED_TOTAL_MAX_BYTES:
        before_req = required_section_bytes(before)
        if not (_uses_compaction(raw_patch) and after_req <= before_req):
            raise BrainError(ErrorCode.INVALID_INPUT, "required handoff sections exceed 32 KB UTF-8 limit")


__all__ = [
    "HANDOFF_CONSTRAINTS_MAX_BYTES",
    "HANDOFF_ITEM_MAX_BYTES",
    "HANDOFF_L0_GOAL_MAX_BYTES",
    "HANDOFF_L0_SUMMARY_MAX_BYTES",
    "HANDOFF_L1_GOAL_MAX_BYTES",
    "HANDOFF_L1_RESOURCE_MAX_BYTES",
    "HANDOFF_L2_MAX_BYTES",
    "HANDOFF_PATCH_MAX_BYTES",
    "HANDOFF_PENDING_CHANGES_MAX_BYTES",
    "HANDOFF_REPLY_EXCERPT_MAX_BYTES",
    "HANDOFF_REQUIRED_TOTAL_MAX_BYTES",
    "active_constraints_bytes",
    "canonical_utf8_len",
    "pending_changes_bytes",
    "required_section_bytes",
    "truncate_utf8_boundary",
    "utf8_byte_v1_tokens",
    "utf8_len",
    "validate_handoff_write_limits",
]
