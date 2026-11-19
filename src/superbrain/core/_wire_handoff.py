"""Strict MCP v2 validation helpers for handoff, resume, takeover, and fence payloads."""

from __future__ import annotations

from collections.abc import Callable, Mapping

from superbrain.core._json_parse import MAX_WIRE_TEXT_BYTES, _encode_wire_str
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    require_non_negative_int,
    require_opaque_id,
    require_positive_int,
    require_sha256_digest,
)

FORBIDDEN_AUTHORITY_KEYS = frozenset(
    {
        "source",
        "approval",
        "approval_receipt",
        "native_receipt",
        "snapshot_status",
        "degraded_codes",
        "unknown_source",
        "verified",
        "verification_status",
    }
)

_MAX_HANDOFF_LIST_ITEMS = 64
_VALID_PLAN_STATUSES = frozenset({"pending", "in_progress", "done", "blocked"})
_VALID_CLOSED_RESOLUTIONS = frozenset({"rejected", "withdrawn"})
_VALID_TASK_STATES = frozenset({"open", "done", "abandoned"})

_HANDOFF_PATCH_FIELDS = frozenset(
    {
        "working_goal",
        "plan",
        "decisions",
        "rejected",
        "user_constraints",
        "constraint_changes",
        "closed_changes",
        "tooling",
        "hypotheses",
        "next_action",
        "long_running",
        "task_state",
    }
)


def check_wire_keys(
    obj: Mapping[str, JsonValue],
    *,
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
) -> None:
    """Validate required and allowed object keys, flagging forbidden client authority fields."""
    allowed = required | optional
    for key in obj:
        if key in FORBIDDEN_AUTHORITY_KEYS and key not in allowed:
            raise BrainError(ErrorCode.INVALID_INPUT, "forbidden client-supplied authority field")
        if key not in allowed:
            raise BrainError(ErrorCode.INVALID_INPUT, "unknown field")
    for req in required:
        if req not in obj:
            raise BrainError(ErrorCode.INVALID_INPUT, "missing required field")


def require_nonempty_wire_text(value: object, *, max_bytes: int = MAX_WIRE_TEXT_BYTES) -> str:
    """Validate a non-empty bounded UTF-8 text scalar without unpaired surrogates."""
    if not isinstance(value, str) or not value:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    _encode_wire_str(value, max_bytes=max_bytes)
    return value


def _require_dict(value: JsonValue) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    return value


def _require_unique_opaque_id_list(
    value: JsonValue,
    *,
    label: str,
    min_items: int = 0,
    max_items: int = _MAX_HANDOFF_LIST_ITEMS,
) -> list[str]:
    if not isinstance(value, list) or not (min_items <= len(value) <= max_items):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    seen: set[str] = set()
    out: list[str] = []
    for item in value:
        oid = require_opaque_id(item, label=label)
        if oid in seen:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        seen.add(oid)
        out.append(oid)
    return out


def _validate_list_of(
    value: JsonValue,
    *,
    validator: Callable[[JsonValue], None],
    max_items: int = _MAX_HANDOFF_LIST_ITEMS,
) -> None:
    if not isinstance(value, list) or len(value) > max_items:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    for item in value:
        validator(item)


def validate_handoff_fence(value: JsonValue) -> None:
    """Validate ``HandoffFence`` ``{restore_epoch, writer_generation}``."""
    fence = _require_dict(value)
    check_wire_keys(fence, required=frozenset({"restore_epoch", "writer_generation"}))
    require_non_negative_int(fence["restore_epoch"])
    require_non_negative_int(fence["writer_generation"])


def validate_resume_ref(value: JsonValue) -> None:
    """Validate ``ResumeRefInput`` carried on ``prepare_task`` work calls."""
    ref = _require_dict(value)
    check_wire_keys(
        ref,
        required=frozenset({"artifact_id", "revision", "handoff_revision", "fence"}),
        optional=frozenset({"served_receipt_id"}),
    )
    if "served_receipt_id" in ref:
        require_opaque_id(ref["served_receipt_id"], label="served_receipt_id")
    require_opaque_id(ref["artifact_id"], label="artifact_id")
    require_positive_int(ref["revision"])
    require_non_negative_int(ref["handoff_revision"])
    validate_handoff_fence(ref["fence"])


def _validate_seen_handoff_ref(value: JsonValue) -> None:
    ref = _require_dict(value)
    check_wire_keys(ref, required=frozenset({"artifact_id", "revision_epoch", "revision", "digest"}))
    require_opaque_id(ref["artifact_id"], label="artifact_id")
    require_non_negative_int(ref["revision_epoch"])
    require_positive_int(ref["revision"])
    require_sha256_digest(ref["digest"])


def validate_seen_handoff_refs(value: JsonValue) -> None:
    """Validate bounded list of ``SeenHandoffRef`` objects."""
    _validate_list_of(value, validator=_validate_seen_handoff_ref)


def validate_handoff_takeover(value: JsonValue) -> None:
    """Validate ``HandoffTakeoverInput`` ``{acknowledge_active?, reason?}``."""
    takeover = _require_dict(value)
    check_wire_keys(takeover, required=frozenset(), optional=frozenset({"acknowledge_active", "reason"}))
    if "acknowledge_active" in takeover and not isinstance(takeover["acknowledge_active"], bool):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if "reason" in takeover:
        require_nonempty_wire_text(takeover["reason"])


def _validate_plan_step(value: JsonValue) -> None:
    item = _require_dict(value)
    check_wire_keys(
        item,
        required=frozenset({"id", "summary", "status"}),
        optional=frozenset({"depends_on_change"}),
    )
    require_opaque_id(item["id"], label="id")
    require_nonempty_wire_text(item["summary"])
    status = item["status"]
    if not isinstance(status, str) or status not in _VALID_PLAN_STATUSES:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if "depends_on_change" in item:
        require_opaque_id(item["depends_on_change"], label="depends_on_change")


def _validate_decision(value: JsonValue) -> None:
    item = _require_dict(value)
    check_wire_keys(
        item,
        required=frozenset({"id", "decision", "reason"}),
        optional=frozenset({"evidence_refs", "supersedes", "reopens"}),
    )
    require_opaque_id(item["id"], label="id")
    require_nonempty_wire_text(item["decision"])
    require_nonempty_wire_text(item["reason"])
    if "supersedes" in item and "reopens" in item:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if "supersedes" in item:
        require_opaque_id(item["supersedes"], label="supersedes")
    if "reopens" in item:
        require_opaque_id(item["reopens"], label="reopens")
    if "evidence_refs" in item:
        _require_unique_opaque_id_list(item["evidence_refs"], label="evidence_refs")


def _validate_rejected(value: JsonValue) -> None:
    item = _require_dict(value)
    check_wire_keys(
        item,
        required=frozenset({"id", "option", "reason"}),
        optional=frozenset({"merges"}),
    )
    require_opaque_id(item["id"], label="id")
    require_nonempty_wire_text(item["option"])
    require_nonempty_wire_text(item["reason"])
    if "merges" in item:
        _require_unique_opaque_id_list(item["merges"], label="merges", min_items=1)


def _validate_constraint(value: JsonValue) -> None:
    item = _require_dict(value)
    check_wire_keys(item, required=frozenset({"id", "constraint"}))
    require_opaque_id(item["id"], label="id")
    require_nonempty_wire_text(item["constraint"])


def _validate_constraint_change(value: JsonValue) -> None:
    item = _require_dict(value)
    check_wire_keys(
        item,
        required=frozenset({"id", "target_constraint_id", "proposed_constraint", "reason"}),
    )
    require_opaque_id(item["id"], label="id")
    require_opaque_id(item["target_constraint_id"], label="target_constraint_id")
    require_nonempty_wire_text(item["proposed_constraint"])
    require_nonempty_wire_text(item["reason"])


def _validate_closed_change(value: JsonValue) -> None:
    item = _require_dict(value)
    check_wire_keys(
        item,
        required=frozenset({"change_id", "resolution"}),
        optional=frozenset({"reason"}),
    )
    require_opaque_id(item["change_id"], label="change_id")
    res = item["resolution"]
    if not isinstance(res, str) or res not in _VALID_CLOSED_RESOLUTIONS:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if "reason" in item:
        require_nonempty_wire_text(item["reason"])


def _validate_tooling(value: JsonValue) -> None:
    item = _require_dict(value)
    check_wire_keys(item, required=frozenset({"purpose", "command"}))
    require_nonempty_wire_text(item["purpose"])
    require_nonempty_wire_text(item["command"])


def _validate_hypothesis(value: JsonValue) -> None:
    require_nonempty_wire_text(value)


def _validate_next_action(value: JsonValue) -> None:
    if value is None:
        return
    item = _require_dict(value)
    check_wire_keys(item, required=frozenset({"summary"}), optional=frozenset({"depends_on_change"}))
    require_nonempty_wire_text(item["summary"])
    if "depends_on_change" in item:
        require_opaque_id(item["depends_on_change"], label="depends_on_change")


def _validate_long_running(value: JsonValue) -> None:
    if value is None:
        return
    item = _require_dict(value)
    check_wire_keys(
        item,
        required=frozenset({"command", "cwd", "source_revision", "log_or_receipt_path", "next_action"}),
        optional=frozenset({"pid", "started_at"}),
    )
    for field in ("command", "cwd", "source_revision", "log_or_receipt_path", "next_action"):
        require_nonempty_wire_text(item[field])
    if "pid" in item:
        require_positive_int(item["pid"])
    if "started_at" in item:
        require_nonempty_wire_text(item["started_at"])


def _validate_task_state(value: JsonValue) -> None:
    if not isinstance(value, str) or value not in _VALID_TASK_STATES:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")


_HANDOFF_LIST_VALIDATORS: dict[str, Callable[[JsonValue], None]] = {
    "plan": _validate_plan_step,
    "decisions": _validate_decision,
    "rejected": _validate_rejected,
    "user_constraints": _validate_constraint,
    "constraint_changes": _validate_constraint_change,
    "closed_changes": _validate_closed_change,
    "tooling": _validate_tooling,
    "hypotheses": _validate_hypothesis,
}


def validate_handoff_patch(value: JsonValue) -> None:
    """Validate non-empty ``HandoffPatchInput`` carried on ``submit_episode``."""
    patch = _require_dict(value)
    if not patch:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    check_wire_keys(patch, required=frozenset(), optional=_HANDOFF_PATCH_FIELDS)
    if "working_goal" in patch:
        require_nonempty_wire_text(patch["working_goal"])
    for list_field, item_validator in _HANDOFF_LIST_VALIDATORS.items():
        if list_field in patch:
            _validate_list_of(patch[list_field], validator=item_validator)
    if "next_action" in patch:
        _validate_next_action(patch["next_action"])
    if "long_running" in patch:
        _validate_long_running(patch["long_running"])
    if "task_state" in patch:
        _validate_task_state(patch["task_state"])
