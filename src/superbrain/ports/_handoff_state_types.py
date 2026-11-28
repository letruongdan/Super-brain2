"""Agent state, revision header and resolved-source records of the handoff port; ``_handoff_types`` re-exports them."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from superbrain.core._kernel_base import (
    is_strict_int,
    require_non_negative_int,
    require_opaque_id,
    require_positive_int,
    require_sha256_digest,
)
from superbrain.core._wire_handoff import _VALID_TASK_STATES
from superbrain.core.jsonvalue import JsonValue


@dataclass(frozen=True)
class HandoffAgentState:
    """Canonical agent-reported section stored as an immutable CAS blob referenced by ``agent_ref``."""

    working_goal: str | None = None
    plan: tuple[_m.HandoffPlanStep, ...] = ()
    decisions: tuple[_m.HandoffDecision, ...] = ()
    rejected: tuple[_m.HandoffRejected, ...] = ()
    user_constraints: tuple[_m.HandoffConstraint, ...] = ()
    constraint_changes: tuple[_m.HandoffConstraintChange, ...] = ()
    closed_changes: tuple[_m.HandoffClosedChange, ...] = ()
    tooling: tuple[_m.HandoffTooling, ...] = ()
    hypotheses: tuple[str, ...] = ()
    next_action: _m.HandoffNextAction | None = None
    long_running: _m.HandoffLongRunning | None = None
    task_state: str = "open"

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "working_goal": self.working_goal,
            "plan": [s.to_dict() for s in self.plan],
            "decisions": [d.to_dict() for d in self.decisions],
            "rejected": [r.to_dict() for r in self.rejected],
            "user_constraints": [c.to_dict() for c in self.user_constraints],
            "constraint_changes": [c.to_dict() for c in self.constraint_changes],
            "closed_changes": [c.to_dict() for c in self.closed_changes],
            "tooling": [t.to_dict() for t in self.tooling],
            "hypotheses": list(self.hypotheses),
            "next_action": None if self.next_action is None else self.next_action.to_dict(),
            "long_running": None if self.long_running is None else self.long_running.to_dict(),
            "task_state": self.task_state,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, JsonValue]) -> HandoffAgentState:
        obj = _m._req_dict(raw)
        wg = obj.get("working_goal")
        na = obj.get("next_action")
        lr = obj.get("long_running")
        ts = obj.get("task_state", "open")
        if not isinstance(ts, str) or ts not in _VALID_TASK_STATES:
            raise _m._invalid()

        def _seq(key: str) -> Sequence[JsonValue]:
            val = obj.get(key, [])
            if not isinstance(val, Sequence) or isinstance(val, (str, bytes)):
                raise _m._invalid()
            return val

        return cls(
            working_goal=None if wg is None else _m._req_nonempty_str(wg),
            plan=tuple(_m.HandoffPlanStep.from_dict(_m._req_dict(x)) for x in _seq("plan")),
            decisions=tuple(_m.HandoffDecision.from_dict(_m._req_dict(x)) for x in _seq("decisions")),
            rejected=tuple(_m.HandoffRejected.from_dict(_m._req_dict(x)) for x in _seq("rejected")),
            user_constraints=tuple(_m.HandoffConstraint.from_dict(_m._req_dict(x)) for x in _seq("user_constraints")),
            constraint_changes=tuple(
                _m.HandoffConstraintChange.from_dict(_m._req_dict(x), allow_status=True)
                for x in _seq("constraint_changes")
            ),
            closed_changes=tuple(_m.HandoffClosedChange.from_dict(_m._req_dict(x)) for x in _seq("closed_changes")),
            tooling=tuple(_m.HandoffTooling.from_dict(_m._req_dict(x)) for x in _seq("tooling")),
            hypotheses=tuple(_m._req_nonempty_str(x) for x in _seq("hypotheses")),
            next_action=None if na is None else _m.HandoffNextAction.from_dict(_m._req_dict(na)),
            long_running=None if lr is None else _m.HandoffLongRunning.from_dict(_m._req_dict(lr)),
            task_state=ts,
        )


@dataclass(frozen=True)
class HandoffRevisionHeader:
    """Immutable snapshot header committed at ``(artifact_id, revision_epoch, revision)`` (§7.4)."""

    artifact_id: str
    revision_epoch: int
    revision: int
    handoff_revision: int
    task_id: str
    task_state: str
    task_state_source: str
    fence: _m.HandoffFence
    holder_harness_id: str | None
    holder_principal: str | None
    holder_session_ref: str | None
    session_state: str | None
    agent_ref: str | None
    observed_ref: str | None
    agent_updated_at: str | None
    observed_through: str | None
    events_since_agent: int = 0

    def __post_init__(self) -> None:
        require_opaque_id(self.artifact_id)
        require_non_negative_int(self.revision_epoch)
        require_positive_int(self.revision)
        require_non_negative_int(self.handoff_revision)
        require_non_negative_int(self.events_since_agent)
        require_opaque_id(self.task_id)
        if not is_strict_int(self.fence.restore_epoch):
            raise _m._invalid()
        if self.agent_ref is not None:
            require_sha256_digest(self.agent_ref)
        if self.observed_ref is not None:
            require_sha256_digest(self.observed_ref)

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "artifact_id": self.artifact_id,
            "revision_epoch": self.revision_epoch,
            "revision": self.revision,
            "handoff_revision": self.handoff_revision,
            "task_id": self.task_id,
            "task_state": self.task_state,
            "task_state_source": self.task_state_source,
            "fence": self.fence.to_dict(),
            "holder_harness_id": self.holder_harness_id,
            "holder_principal": self.holder_principal,
            "holder_session_ref": self.holder_session_ref,
            "session_state": self.session_state,
            "agent_ref": self.agent_ref,
            "observed_ref": self.observed_ref,
            "agent_updated_at": self.agent_updated_at,
            "observed_through": self.observed_through,
            "events_since_agent": self.events_since_agent,
        }


@dataclass(frozen=True)
class ResolvedSourceContent:
    """Read-time resolved observed or history item from live CAS + policy checks (never pre-copied into handoffs)."""

    source_event_id: str
    source_digest: str
    kind: str
    status: str  # "ok" | "redacted" | "expired"
    payload: Mapping[str, JsonValue] | None = None
    reason: str | None = None
    recorded_at: str | None = None

# Imported last: the original module re-exports the names above, so it may import this module first.
from superbrain.ports import _handoff_types as _m  # noqa: E402
