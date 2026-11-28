"""Deterministic merge, supersession, reopen, merge, and constraint-change state machine (§7.4)."""

from __future__ import annotations

from dataclasses import dataclass

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.domain.continuity.handoff_model import (
    HandoffAgentState,
    HandoffClosedChange,
    HandoffConstraint,
    HandoffConstraintChange,
    HandoffDecision,
    HandoffPatch,
    HandoffRejected,
    Unset,
)


def _invalid(msg: str) -> BrainError:
    return BrainError(ErrorCode.INVALID_INPUT, msg)


@dataclass(frozen=True)
class HandoffActiveSets:
    """Deterministic active views derived from append-only handoff history."""

    decisions: tuple[HandoffDecision, ...]
    rejected: tuple[HandoffRejected, ...]
    user_constraints: tuple[HandoffConstraint, ...]
    pending_changes: tuple[HandoffConstraintChange, ...]
    closed_changes: tuple[HandoffClosedChange, ...]


def derive_active_sets(state: HandoffAgentState | None) -> HandoffActiveSets:
    """Compute currently active decisions, rejected options, constraints, pending & closed changes."""
    if state is None:
        return HandoffActiveSets((), (), (), (), ())

    superseded: set[str] = set()
    active_rejected_ids: set[str] = set()
    ordered_rejected: dict[str, HandoffRejected] = {}
    for item in state.rejected:
        for merged_id in item.merges:
            active_rejected_ids.discard(merged_id)
        active_rejected_ids.add(item.id)
        ordered_rejected[item.id] = item
    for dec in state.decisions:
        if dec.supersedes is not None:
            superseded.add(dec.supersedes)
        if dec.reopens is not None:
            active_rejected_ids.discard(dec.reopens)

    active_decisions = tuple(d for d in state.decisions if d.id not in superseded)
    active_rejected = tuple(r for r in state.rejected if r.id in active_rejected_ids)

    closed_ids = {c.change_id for c in state.closed_changes}
    pending_changes = tuple(ch for ch in state.constraint_changes if ch.id not in closed_ids)
    return HandoffActiveSets(
        decisions=active_decisions,
        rejected=active_rejected,
        user_constraints=state.user_constraints,
        pending_changes=pending_changes,
        closed_changes=state.closed_changes,
    )


def apply_handoff_patch(current: HandoffAgentState | None, patch: HandoffPatch) -> HandoffAgentState:
    """Validate and deterministically fold ``patch`` onto ``current`` enforcing all §7.4 append/ref rules."""
    base = current if current is not None else HandoffAgentState()

    decisions = list(base.decisions)
    decision_ids = {d.id for d in decisions}
    superseded_ids = {d.supersedes for d in decisions if d.supersedes is not None}

    rejected = list(base.rejected)
    rejected_ids = {r.id for r in rejected}
    inactive_rejected_ids = {m for r in rejected for m in r.merges} | {
        d.reopens for d in decisions if d.reopens is not None
    }

    for dec in patch.decisions:
        if dec.id in decision_ids:
            raise _invalid("duplicate decision id")
        if dec.supersedes is not None:
            if dec.supersedes not in decision_ids or dec.supersedes in superseded_ids:
                raise _invalid("supersedes must reference an active decision")
            superseded_ids.add(dec.supersedes)
        if dec.reopens is not None:
            if dec.reopens not in rejected_ids or dec.reopens in inactive_rejected_ids:
                raise _invalid("reopens must reference an active rejected option")
            inactive_rejected_ids.add(dec.reopens)
        decision_ids.add(dec.id)
        decisions.append(dec)

    for rej in patch.rejected:
        if rej.id in rejected_ids:
            raise _invalid("duplicate rejected id")
        if rej.merges:
            for merged_id in rej.merges:
                if merged_id not in rejected_ids or merged_id in inactive_rejected_ids:
                    raise _invalid("merges must reference active rejected options")
                inactive_rejected_ids.add(merged_id)
        rejected_ids.add(rej.id)
        rejected.append(rej)

    constraints = list(base.user_constraints)
    constraint_ids = {c.id for c in constraints}
    for con in patch.user_constraints:
        if con.id in constraint_ids:
            raise _invalid("duplicate user constraint id")
        constraint_ids.add(con.id)
        constraints.append(con)

    changes = list(base.constraint_changes)
    change_ids = {c.id for c in changes}
    for ch in patch.constraint_changes:
        if ch.id in change_ids:
            raise _invalid("duplicate constraint_change id")
        if ch.target_constraint_id not in constraint_ids:
            raise _invalid("target_constraint_id must reference an existing user constraint")
        change_ids.add(ch.id)
        changes.append(ch)

    closed = list(base.closed_changes)
    closed_ids = {c.change_id for c in closed}
    for cl in patch.closed_changes:
        if cl.change_id not in change_ids or cl.change_id in closed_ids:
            raise _invalid("closed_changes must reference a pending constraint_change")
        closed_ids.add(cl.change_id)
        closed.append(cl)

    next_working_goal = base.working_goal if isinstance(patch.working_goal, Unset) else patch.working_goal
    next_plan = base.plan if isinstance(patch.plan, Unset) else patch.plan
    next_tooling = base.tooling if isinstance(patch.tooling, Unset) else patch.tooling
    next_hypotheses = base.hypotheses if isinstance(patch.hypotheses, Unset) else patch.hypotheses
    next_action = base.next_action if isinstance(patch.next_action, Unset) else patch.next_action
    next_lr = base.long_running if isinstance(patch.long_running, Unset) else patch.long_running
    next_task_state = base.task_state if isinstance(patch.task_state, Unset) else patch.task_state

    for step in next_plan:
        if step.depends_on_change is not None and step.depends_on_change not in change_ids:
            raise _invalid("step depends_on_change references unknown proposal")
    if next_action is not None and next_action.depends_on_change is not None:
        if next_action.depends_on_change not in change_ids:
            raise _invalid("next_action depends_on_change references unknown proposal")

    return HandoffAgentState(
        working_goal=next_working_goal,
        plan=next_plan,
        decisions=tuple(decisions),
        rejected=tuple(rejected),
        user_constraints=tuple(constraints),
        constraint_changes=tuple(changes),
        closed_changes=tuple(closed),
        tooling=next_tooling,
        hypotheses=next_hypotheses,
        next_action=next_action,
        long_running=next_lr,
        task_state=next_task_state,
    )


__all__ = ["HandoffActiveSets", "apply_handoff_patch", "derive_active_sets"]
