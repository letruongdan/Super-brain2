"""Argument normalization for prepare_task and submit_episode calls; ``wire`` re-exports these."""

from __future__ import annotations

from superbrain.core._wire_handoff import (
    validate_handoff_fence,
    validate_handoff_patch,
    validate_handoff_takeover,
    validate_resume_ref,
    validate_seen_handoff_refs,
)
from superbrain.core.errors import (
    BrainError,
    ErrorCode,
)
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    require_non_negative_int,
    require_object_kind,
    require_opaque_id,
)


def _normalize_prepare_task(business: dict[str, JsonValue]) -> None:
    mode = business.get("mode", "work")
    if mode == "discover":
        _m._check_keys(
            business,
            required=frozenset({"schema_version", "mode"}),
            optional=frozenset(
                {
                    "workspace_hint",
                    "workspace_id",
                    "checkout_id",
                    "task_id",
                    "context_budget_tokens",
                }
            ),
        )
        _m._validate_workspace_selector(business)
        if "task_id" in business:
            require_opaque_id(business["task_id"], label="task_id")
        if "context_budget_tokens" not in business:
            business["context_budget_tokens"] = _m.DEFAULT_CONTEXT_BUDGET_TOKENS
        _m._require_bounded_int(
            business["context_budget_tokens"],
            minimum=1,
            maximum=_m.MAX_CONTEXT_BUDGET_TOKENS,
        )
        return
    if mode != "work":
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    business["mode"] = "work"
    _m._check_keys(
        business,
        required=frozenset({"schema_version", "mode", "description", "idempotency_key"}),
        optional=frozenset(
            {
                "workspace_hint",
                "workspace_id",
                "checkout_id",
                "source_snapshot_id",
                "task_id",
                "resume_ref",
                "seen_handoff_refs",
                "context_budget_tokens",
            }
        ),
    )
    _m._validate_workspace_selector(business)

    if "source_snapshot_id" in business:
        require_opaque_id(business["source_snapshot_id"], label="source_snapshot_id")
    if "task_id" in business:
        require_opaque_id(business["task_id"], label="task_id")
    if "resume_ref" in business:
        if "task_id" not in business:
            raise BrainError(ErrorCode.INVALID_INPUT, "missing required field")
        validate_resume_ref(business["resume_ref"])
    if "seen_handoff_refs" in business:
        validate_seen_handoff_refs(business["seen_handoff_refs"])
    _m._require_nonempty_text(business["description"])
    if "context_budget_tokens" not in business:
        business["context_budget_tokens"] = _m.DEFAULT_CONTEXT_BUDGET_TOKENS
    _m._require_bounded_int(
        business["context_budget_tokens"],
        minimum=1,
        maximum=_m.MAX_CONTEXT_BUDGET_TOKENS,
    )
    _m._require_idempotency_key(business["idempotency_key"])


def _normalize_submit_episode(business: dict[str, JsonValue]) -> None:
    _m._check_keys(
        business,
        required=frozenset({"schema_version", "task_id", "session_id", "evidence", "idempotency_key"}),
        optional=frozenset(
            {
                "workspace_id",
                "checkout_id",
                "candidate_lesson",
                "read_acks",
                "handoff",
                "base_revision",
                "fence",
                "takeover",
            }
        ),
    )
    has_patch = "handoff" in business
    has_takeover = "takeover" in business
    has_base = "base_revision" in business
    has_fence = "fence" in business
    if (has_patch or has_takeover) != (has_base and has_fence) or (has_base != has_fence):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if has_base:
        require_non_negative_int(business["base_revision"])
    if has_fence:
        validate_handoff_fence(business["fence"])
    if has_takeover:
        validate_handoff_takeover(business["takeover"])
    if has_patch:
        validate_handoff_patch(business["handoff"])
    require_opaque_id(business["task_id"], label="task_id")
    require_opaque_id(business["session_id"], label="session_id")
    if "workspace_id" in business:
        require_opaque_id(business["workspace_id"], label="workspace_id")
    if "checkout_id" in business:
        require_opaque_id(business["checkout_id"], label="checkout_id")

    evidence = business["evidence"]
    if not isinstance(evidence, list):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    for item in evidence:
        if not isinstance(item, dict):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        _m._check_keys(item, required=frozenset({"kind", "data"}))
        require_object_kind(item["kind"])
        data = item["data"]
        if not isinstance(data, dict):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        _m._reject_nested_authority_keys(data)

    if "candidate_lesson" in business:
        lesson = business["candidate_lesson"]
        if not isinstance(lesson, dict):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        _m._check_keys(
            lesson,
            required=frozenset({"title", "content"}),
            optional=frozenset({"conditions"}),
        )
        title = _m._require_nonempty_text(lesson["title"])
        if len(title) > 256:
            raise BrainError(ErrorCode.INVALID_INPUT, "string exceeds size limit")
        _m._require_nonempty_text(lesson["content"])
        if "conditions" in lesson:
            conds = lesson["conditions"]
            if not isinstance(conds, list) or len(conds) > 64:
                raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
            for cond in conds:
                _m._require_nonempty_text(cond)

    if "read_acks" in business:
        _m._validate_read_acks(business["read_acks"])
    _m._require_idempotency_key(business["idempotency_key"])

# Imported last: the original module re-exports the names above, so it may import this module first.
from superbrain.core import wire as _m  # noqa: E402
