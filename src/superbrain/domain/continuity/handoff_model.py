"""Pure immutable domain models and wire parsers for SP2-4 task handoffs (§7.4)."""

from __future__ import annotations

from superbrain.ports._handoff_types import (
    UNSET,
    HandoffAgentState,
    HandoffClosedChange,
    HandoffConstraint,
    HandoffConstraintChange,
    HandoffDecision,
    HandoffFence,
    HandoffLive,
    HandoffLongRunning,
    HandoffNextAction,
    HandoffPatch,
    HandoffPlanStep,
    HandoffRejected,
    HandoffRevisionHeader,
    HandoffTooling,
    Unset,
    parse_handoff_patch,
)

__all__ = [
    "UNSET",
    "HandoffAgentState",
    "HandoffClosedChange",
    "HandoffConstraint",
    "HandoffConstraintChange",
    "HandoffDecision",
    "HandoffFence",
    "HandoffLive",
    "HandoffLongRunning",
    "HandoffNextAction",
    "HandoffPatch",
    "HandoffPlanStep",
    "HandoffRejected",
    "HandoffRevisionHeader",
    "HandoffTooling",
    "Unset",
    "parse_handoff_patch",
]
