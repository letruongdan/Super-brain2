"""SP2-4 pure domain tests: handoff merge rules, UTF-8 byte limits, 32 KB exemption, and L0/L1/L2 rendering.

Requirement sources:
- docs/superpowers/specs/2026-10-30-super-brain2-system-design.md
  (§6.2, §7.4, §20 cases 37, 49, 50, 57, 58, 64, 66, 71, 72)
- docs/superpowers/plans/2026-11-18-sp2-capture-continuity.md (SP2-4 Step 1)
"""

from __future__ import annotations

import math

import pytest

from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue


def _long_mb(byte_target: int) -> str:
    """Deterministic multi-byte UTF-8 string ('é' is 2 UTF-8 bytes) with exact UTF-8 byte length."""
    half, rem = divmod(byte_target, 2)
    return ("é" * half) + ("a" * rem)


def test_partial_update_append_only_decisions_rejected_merges_and_reopens() -> None:
    from superbrain.domain.continuity.handoff_model import HandoffAgentState, parse_handoff_patch
    from superbrain.domain.continuity.merge_rules import apply_handoff_patch, derive_active_sets

    p1 = parse_handoff_patch(
        {
            "working_goal": "Initial working goal",
            "plan": [{"id": "step-1", "summary": "Write tests", "status": "done"}],
            "decisions": [{"id": "dec-1", "decision": "Use SQLite WAL", "reason": "local durability"}],
            "rejected": [
                {"id": "rej-1", "option": "JSON flat file", "reason": "no ACID"},
                {"id": "rej-2", "option": "In-memory cache", "reason": "lost on restart"},
            ],
            "user_constraints": [{"id": "con-1", "constraint": "Never leak raw session_id"}],
            "tooling": [{"purpose": "test", "command": "pytest -q"}],
            "hypotheses": ["WAL survives kill -9"],
            "next_action": {"summary": "Implement merge rules"},
            "task_state": "open",
        }
    )
    st1 = apply_handoff_patch(None, p1)
    assert isinstance(st1, HandoffAgentState)
    assert st1.working_goal == "Initial working goal"
    assert len(st1.decisions) == 1
    assert len(st1.rejected) == 2

    # Conflicting constraint is appended without replacing con-1 (case 66), omitted fields preserved.
    p2 = parse_handoff_patch(
        {
            "user_constraints": [{"id": "con-2", "constraint": "Always preserve con-1 even if later rules conflict"}],
            "decisions": [
                {"id": "dec-2", "decision": "Switch to staged swap", "reason": "atomic", "supersedes": "dec-1"}
            ],
            "rejected": [
                {
                    "id": "rej-merged",
                    "option": "Non-WAL volatile formats",
                    "reason": "combined flat file and in-memory rejections",
                    "merges": ["rej-1", "rej-2"],
                }
            ],
        }
    )
    st2 = apply_handoff_patch(st1, p2)
    assert st2.working_goal == "Initial working goal"
    assert [c.id for c in st2.user_constraints] == ["con-1", "con-2"]

    active2 = derive_active_sets(st2)
    assert [d.id for d in active2.decisions] == ["dec-2"]
    assert [r.id for r in active2.rejected] == ["rej-merged"]
    assert [r.id for r in st2.rejected] == ["rej-1", "rej-2", "rej-merged"]

    # Reopen rej-merged via decision.reopens (case 50).
    st3 = apply_handoff_patch(
        st2,
        parse_handoff_patch(
            {
                "decisions": [
                    {
                        "id": "dec-3",
                        "decision": "Re-evaluate rej-merged",
                        "reason": "new benchmark",
                        "reopens": "rej-merged",
                    }
                ]
            }
        ),
    )
    active3 = derive_active_sets(st3)
    assert [r.id for r in active3.rejected] == []
    assert [d.id for d in active3.decisions] == ["dec-2", "dec-3"]

    # Duplicate ID, wrong target type, already superseded, or missing/inactive merges -> INVALID_INPUT (ca 37, 50, 71).
    bad_patches: list[dict[str, JsonValue]] = [
        {"decisions": [{"id": "dec-1", "decision": "dup", "reason": "dup"}]},
        {"decisions": [{"id": "dec-bad-1", "decision": "x", "reason": "y", "supersedes": "rej-1"}]},
        {"decisions": [{"id": "dec-bad-2", "decision": "x", "reason": "y", "supersedes": "dec-1"}]},
        {"decisions": [{"id": "dec-bad-3", "decision": "x", "reason": "y", "reopens": "dec-2"}]},
        {"decisions": [{"id": "dec-bad-4", "decision": "x", "reason": "y", "reopens": "rej-1"}]},
        {"rejected": [{"id": "rej-bad-1", "option": "x", "reason": "y", "merges": ["rej-1"]}]},
        {"user_constraints": [{"id": "con-1", "constraint": "override"}]},
    ]
    for raw_bad in bad_patches:
        with pytest.raises(BrainError) as exc:
            apply_handoff_patch(st3, parse_handoff_patch(raw_bad))
        assert exc.value.code is ErrorCode.INVALID_INPUT


def test_constraint_changes_stay_proposed_and_validate_depends_on_change() -> None:
    from superbrain.domain.continuity.handoff_model import parse_handoff_patch
    from superbrain.domain.continuity.merge_rules import apply_handoff_patch, derive_active_sets

    st0 = apply_handoff_patch(
        None,
        parse_handoff_patch(
            {
                "user_constraints": [{"id": "con-strict", "constraint": "Never run network tests in gate"}],
                "constraint_changes": [
                    {
                        "id": "chg-1",
                        "target_constraint_id": "con-strict",
                        "proposed_constraint": "Allow loopback localhost sockets in tests",
                        "reason": "needed for daemon IPC",
                    }
                ],
                "plan": [
                    {
                        "id": "step-net",
                        "summary": "Bind loopback port",
                        "status": "in_progress",
                        "depends_on_change": "chg-1",
                    }
                ],
                "next_action": {"summary": "Ask user exception then run loopback suite", "depends_on_change": "chg-1"},
            }
        ),
    )
    active = derive_active_sets(st0)
    assert [c.id for c in active.user_constraints] == ["con-strict"]
    assert len(active.pending_changes) == 1
    assert active.pending_changes[0].status == "proposed"

    # Closing chg-1 removes it from pending queue; duplicate close or unknown change fails cleanly.
    st_closed = apply_handoff_patch(
        st0,
        parse_handoff_patch(
            {"closed_changes": [{"change_id": "chg-1", "resolution": "rejected", "reason": "user declined"}]}
        ),
    )
    assert derive_active_sets(st_closed).pending_changes == ()
    assert [c.change_id for c in st_closed.closed_changes] == ["chg-1"]
    assert [c.id for c in derive_active_sets(st_closed).user_constraints] == ["con-strict"]

    # depends_on_change pointing to unknown proposal -> INVALID_INPUT (case 72).
    with pytest.raises(BrainError) as exc_plan:
        apply_handoff_patch(
            st0,
            parse_handoff_patch(
                {"plan": [{"id": "s2", "summary": "bad", "status": "pending", "depends_on_change": "chg-missing"}]}
            ),
        )
    assert exc_plan.value.code is ErrorCode.INVALID_INPUT

    with pytest.raises(BrainError) as exc_next:
        apply_handoff_patch(
            st0,
            parse_handoff_patch({"next_action": {"summary": "bad", "depends_on_change": "chg-missing"}}),
        )
    assert exc_next.value.code is ErrorCode.INVALID_INPUT


def test_multibyte_utf8_write_limits_and_32kb_non_growing_exemption() -> None:
    from superbrain.domain.continuity.budget import (
        HANDOFF_CONSTRAINTS_MAX_BYTES,
        HANDOFF_ITEM_MAX_BYTES,
        HANDOFF_L0_GOAL_MAX_BYTES,
        HANDOFF_L0_SUMMARY_MAX_BYTES,
        HANDOFF_L1_GOAL_MAX_BYTES,
        HANDOFF_L1_RESOURCE_MAX_BYTES,
        HANDOFF_L2_MAX_BYTES,
        HANDOFF_PATCH_MAX_BYTES,
        HANDOFF_PENDING_CHANGES_MAX_BYTES,
        HANDOFF_REPLY_EXCERPT_MAX_BYTES,
        HANDOFF_REQUIRED_TOTAL_MAX_BYTES,
        truncate_utf8_boundary,
        utf8_byte_v1_tokens,
        utf8_len,
        validate_handoff_write_limits,
    )
    from superbrain.domain.continuity.handoff_model import parse_handoff_patch
    from superbrain.domain.continuity.merge_rules import apply_handoff_patch
    from superbrain.domain.continuity.rendering import (
        ResolvedSourceContent,
        render_handoff_l0,
        render_handoff_l1,
        select_discover_items,
    )

    assert HANDOFF_ITEM_MAX_BYTES == 2048
    assert HANDOFF_PATCH_MAX_BYTES == 16384
    assert HANDOFF_REQUIRED_TOTAL_MAX_BYTES == 32768
    assert HANDOFF_CONSTRAINTS_MAX_BYTES == 16384
    assert HANDOFF_PENDING_CHANGES_MAX_BYTES == 4096
    assert HANDOFF_REPLY_EXCERPT_MAX_BYTES == 512
    assert HANDOFF_L0_GOAL_MAX_BYTES == 200
    assert HANDOFF_L1_GOAL_MAX_BYTES == 2048
    assert HANDOFF_L0_SUMMARY_MAX_BYTES == 600
    assert HANDOFF_L1_RESOURCE_MAX_BYTES == 8192
    assert HANDOFF_L2_MAX_BYTES == 262144

    # Check exact UTF-8 char-boundary truncation for L0 <= 200 B with truncation marker (case 57).
    raw_goal = _long_mb(300)
    cut_l0, truncated = truncate_utf8_boundary(raw_goal, HANDOFF_L0_GOAL_MAX_BYTES)
    assert truncated is True
    assert utf8_len(cut_l0) <= HANDOFF_L0_GOAL_MAX_BYTES
    assert cut_l0.endswith("...")
    cut_l0.encode("utf-8", errors="strict")

    # Single-item limit > 2 KB fails with multi-byte UTF-8.
    over_item_raw: dict[str, JsonValue] = {"working_goal": _long_mb(2050)}
    over_item_state = apply_handoff_patch(None, parse_handoff_patch(over_item_raw))
    with pytest.raises(BrainError) as exc_item:
        validate_handoff_write_limits(None, over_item_state, over_item_raw)
    assert exc_item.value.code is ErrorCode.INVALID_INPUT

    # Single-patch limit > 16 KB fails even if each item <= 2 KB.
    many_steps_raw: dict[str, JsonValue] = {
        "decisions": [{"id": f"d-{i:02d}", "decision": _long_mb(900), "reason": _long_mb(900)} for i in range(10)]
    }
    many_steps_state = apply_handoff_patch(None, parse_handoff_patch(many_steps_raw))
    with pytest.raises(BrainError) as exc_patch:
        validate_handoff_write_limits(None, many_steps_state, many_steps_raw)
    assert exc_patch.value.code is ErrorCode.INVALID_INPUT

    # Build a handoff near the 32 KB required cap across multiple patches using >30 active items (case 57, 64, 71).
    state = None
    for batch in range(3):
        raw_batch: dict[str, JsonValue] = {
            "decisions": [{"id": f"dec-{batch}-{j}", "decision": "A" * 700, "reason": "R" * 150} for j in range(11)]
        }
        next_st = apply_handoff_patch(state, parse_handoff_patch(raw_batch))
        validate_handoff_write_limits(state, next_st, raw_batch)
        state = next_st
    assert state is not None
    assert len(state.decisions) == 33

    # Verify L1 chunks >30 active required items into <= 8 KB resources without dropping item #31+ (case 57).
    obs_sources = [
        ResolvedSourceContent(
            source_event_id=f"ev-{k}",
            source_digest=digest_bytes(f"obs-{k}".encode()),
            kind="command_exit",
            status="ok",
            payload={"command": "pytest", "exit_code": 0},
        )
        for k in range(3)
    ]
    resources, incomplete_opt = render_handoff_l1(
        task_id="task-33",
        artifact_id="art-33",
        revision=1,
        revision_epoch=0,
        handoff_revision=3,
        writer_generation=1,
        holder_harness_id="claude-code",
        session_state="active",
        agent_updated_at="2026-11-26T00:00:00Z",
        observed_through="2026-11-26T00:01:00Z",
        task_goal="G" * 2100,
        state=state,
        observed_sources=obs_sources,
    )
    assert incomplete_opt is False
    for res in resources:
        assert utf8_len(str(res["content"])) <= HANDOFF_L1_RESOURCE_MAX_BYTES
    joined_l1 = "\n".join(str(r["content"]) for r in resources if str(r["name"]) != "handoff_header")
    assert "dec-2-10" in joined_l1  # 33rd active decision must appear!

    # Push required section near 32 KB ceiling, then verify superseding patch is exempted (case 64, 71).
    pad_raw: dict[str, JsonValue] = {"user_constraints": [{"id": f"c-{k}", "constraint": "C" * 500} for k in range(3)]}
    padded_state = apply_handoff_patch(state, parse_handoff_patch(pad_raw))
    validate_handoff_write_limits(state, padded_state, pad_raw)
    # Near ~32 KB cap: growing patch fails, while non-growing supersedes + 4 KB pending change succeeds.
    big_grow_raw: dict[str, JsonValue] = {
        "decisions": [{"id": "dec-grow", "decision": "G" * 1800, "reason": "R" * 100}]
    }
    big_grow_st = apply_handoff_patch(padded_state, parse_handoff_patch(big_grow_raw))
    with pytest.raises(BrainError) as exc_cap:
        validate_handoff_write_limits(padded_state, big_grow_st, big_grow_raw)
    assert exc_cap.value.code is ErrorCode.INVALID_INPUT

    # Supersede an existing big decision with a much shorter replacement: net required bytes shrink!
    shrink_raw: dict[str, JsonValue] = {
        "decisions": [
            {
                "id": "dec-compact",
                "decision": "short",
                "reason": "compact",
                "supersedes": "dec-0-0",
            }
        ],
        "constraint_changes": [
            {
                "id": "chg-room",
                "target_constraint_id": "c-0",
                "proposed_constraint": "narrower rule",
                "reason": "test 4KB separate zone",
            }
        ],
    }
    shrink_st = apply_handoff_patch(padded_state, parse_handoff_patch(shrink_raw))
    validate_handoff_write_limits(padded_state, shrink_st, shrink_raw)

    # Render L0 <= 600 B UTF-8 even with huge multibyte goal, and verify whole-item discover budget (case 58).
    l0 = render_handoff_l0(
        task_goal=_long_mb(500),
        state=shrink_st,
        handoff_revision=4,
        session_state="active",
        agent_updated_at="2026-11-26T00:00:00Z",
        observed_through="2026-11-26T00:01:00Z",
        other_active_warning=True,
    )
    assert utf8_len(l0) <= HANDOFF_L0_SUMMARY_MAX_BYTES

    cands: list[dict[str, JsonValue]] = [
        {
            "kind": "handoff",
            "id": f"t-{i}",
            "revision_epoch": 0,
            "revision": 1,
            "digest": digest_bytes(b"d"),
            "summary": "S" * 300,
        }
        for i in range(3)
    ]
    selected, trunc = select_discover_items(cands, budget_tokens=utf8_byte_v1_tokens(1000))
    assert len(selected) == 2 and trunc is True
    too_small, trunc_small = select_discover_items(cands, budget_tokens=10)
    assert too_small == [] and trunc_small is True
    assert utf8_byte_v1_tokens(601) == math.ceil(601 / 4)
