"""Layer-safe domain/port value objects & wire parsers for SP2-4 task handoffs (§7.4)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum

from superbrain.core._kernel_base import (
    is_strict_int,
    require_non_negative_int,
    require_opaque_id,
    require_positive_int,
    require_sha256_digest,
)
from superbrain.core._wire_handoff import _VALID_CLOSED_RESOLUTIONS, _VALID_PLAN_STATUSES, _VALID_TASK_STATES
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue


class Unset(Enum):
    """Sentinel distinguishing omitted optional patch fields from explicit values."""

    UNSET = "UNSET"


UNSET = Unset.UNSET


def _invalid(msg: str = "invalid handoff payload") -> BrainError:
    return BrainError(ErrorCode.INVALID_INPUT, msg)


def _req_nonempty_str(val: object) -> str:
    if not isinstance(val, str) or not val:
        raise _invalid()
    try:
        val.encode("utf-8", errors="strict")
    except UnicodeEncodeError as err:
        raise _invalid() from err
    return val


def _req_dict(val: object) -> Mapping[str, JsonValue]:
    if not isinstance(val, Mapping):
        raise _invalid()
    return val


def _check_keys(
    obj: Mapping[str, JsonValue], *, required: frozenset[str], optional: frozenset[str] = frozenset()
) -> None:
    allowed = required | optional
    for k in obj:
        if k not in allowed:
            raise _invalid(f"unexpected field: {k}")
    for r in required:
        if r not in obj:
            raise _invalid(f"missing field: {r}")


def _req_unique_ids(val: object, *, min_items: int = 0, max_items: int = 64) -> tuple[str, ...]:
    if not isinstance(val, Sequence) or isinstance(val, (str, bytes)) or not (min_items <= len(val) <= max_items):
        raise _invalid()
    out: list[str] = []
    seen: set[str] = set()
    for item in val:
        oid = require_opaque_id(item)
        if oid in seen:
            raise _invalid("duplicate id")
        seen.add(oid)
        out.append(oid)
    return tuple(out)


@dataclass(frozen=True)
class HandoffFence:
    """Generational fence ``(restore_epoch, writer_generation)`` guarding handoff writes."""

    restore_epoch: int
    writer_generation: int

    def __post_init__(self) -> None:
        require_non_negative_int(self.restore_epoch)
        require_non_negative_int(self.writer_generation)

    def to_dict(self) -> dict[str, JsonValue]:
        return {"restore_epoch": self.restore_epoch, "writer_generation": self.writer_generation}

    @classmethod
    def from_dict(cls, raw: Mapping[str, JsonValue]) -> HandoffFence:
        obj = _req_dict(raw)
        _check_keys(obj, required=frozenset({"restore_epoch", "writer_generation"}))
        return cls(
            restore_epoch=require_non_negative_int(obj["restore_epoch"]),
            writer_generation=require_non_negative_int(obj["writer_generation"]),
        )


@dataclass(frozen=True)
class HandoffLive:
    """Dynamic live handoff fence metadata computed on read/work/artifact delivery."""

    revision: int | None
    revision_epoch: int | None
    handoff_revision: int
    fence: HandoffFence

    def __post_init__(self) -> None:
        if self.revision is None:
            if self.revision_epoch is not None or self.handoff_revision != 0 or self.fence.writer_generation != 0:
                raise _invalid()
        else:
            require_positive_int(self.revision)
            if self.revision_epoch is None:
                raise _invalid()
            require_non_negative_int(self.revision_epoch)
        require_non_negative_int(self.handoff_revision)

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "revision": self.revision,
            "revision_epoch": self.revision_epoch,
            "handoff_revision": self.handoff_revision,
            "fence": self.fence.to_dict(),
        }


@dataclass(frozen=True)
class HandoffPlanStep:
    id: str
    summary: str
    status: str
    depends_on_change: str | None = None

    def __post_init__(self) -> None:
        require_opaque_id(self.id)
        _req_nonempty_str(self.summary)
        if self.status not in _VALID_PLAN_STATUSES:
            raise _invalid()
        if self.depends_on_change is not None:
            require_opaque_id(self.depends_on_change)

    def to_dict(self) -> dict[str, JsonValue]:
        out: dict[str, JsonValue] = {"id": self.id, "summary": self.summary, "status": self.status}
        if self.depends_on_change is not None:
            out["depends_on_change"] = self.depends_on_change
        return out

    @classmethod
    def from_dict(cls, raw: Mapping[str, JsonValue]) -> HandoffPlanStep:
        obj = _req_dict(raw)
        _check_keys(obj, required=frozenset({"id", "summary", "status"}), optional=frozenset({"depends_on_change"}))
        dep = obj.get("depends_on_change")
        return cls(
            id=require_opaque_id(obj["id"]),
            summary=_req_nonempty_str(obj["summary"]),
            status=_req_nonempty_str(obj["status"]),
            depends_on_change=None if dep is None else require_opaque_id(dep),
        )


@dataclass(frozen=True)
class HandoffDecision:
    id: str
    decision: str
    reason: str
    evidence_refs: tuple[str, ...] = ()
    supersedes: str | None = None
    reopens: str | None = None

    def __post_init__(self) -> None:
        require_opaque_id(self.id)
        _req_nonempty_str(self.decision)
        _req_nonempty_str(self.reason)
        if self.supersedes is not None and self.reopens is not None:
            raise _invalid()
        if self.supersedes is not None:
            require_opaque_id(self.supersedes)
        if self.reopens is not None:
            require_opaque_id(self.reopens)

    def to_dict(self) -> dict[str, JsonValue]:
        out: dict[str, JsonValue] = {"id": self.id, "decision": self.decision, "reason": self.reason}
        if self.evidence_refs:
            out["evidence_refs"] = list(self.evidence_refs)
        if self.supersedes is not None:
            out["supersedes"] = self.supersedes
        if self.reopens is not None:
            out["reopens"] = self.reopens
        return out

    @classmethod
    def from_dict(cls, raw: Mapping[str, JsonValue]) -> HandoffDecision:
        obj = _req_dict(raw)
        _check_keys(
            obj,
            required=frozenset({"id", "decision", "reason"}),
            optional=frozenset({"evidence_refs", "supersedes", "reopens"}),
        )
        ev = obj.get("evidence_refs")
        sup = obj.get("supersedes")
        reo = obj.get("reopens")
        return cls(
            id=require_opaque_id(obj["id"]),
            decision=_req_nonempty_str(obj["decision"]),
            reason=_req_nonempty_str(obj["reason"]),
            evidence_refs=() if ev is None else _req_unique_ids(ev),
            supersedes=None if sup is None else require_opaque_id(sup),
            reopens=None if reo is None else require_opaque_id(reo),
        )


@dataclass(frozen=True)
class HandoffRejected:
    id: str
    option: str
    reason: str
    merges: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        require_opaque_id(self.id)
        _req_nonempty_str(self.option)
        _req_nonempty_str(self.reason)
        for mid in self.merges:
            require_opaque_id(mid)

    def to_dict(self) -> dict[str, JsonValue]:
        out: dict[str, JsonValue] = {"id": self.id, "option": self.option, "reason": self.reason}
        if self.merges:
            out["merges"] = list(self.merges)
        return out

    @classmethod
    def from_dict(cls, raw: Mapping[str, JsonValue]) -> HandoffRejected:
        obj = _req_dict(raw)
        _check_keys(obj, required=frozenset({"id", "option", "reason"}), optional=frozenset({"merges"}))
        merges = obj.get("merges")
        return cls(
            id=require_opaque_id(obj["id"]),
            option=_req_nonempty_str(obj["option"]),
            reason=_req_nonempty_str(obj["reason"]),
            merges=() if merges is None else _req_unique_ids(merges, min_items=1),
        )


@dataclass(frozen=True)
class HandoffConstraint:
    id: str
    constraint: str

    def __post_init__(self) -> None:
        require_opaque_id(self.id)
        _req_nonempty_str(self.constraint)

    def to_dict(self) -> dict[str, JsonValue]:
        return {"id": self.id, "constraint": self.constraint}

    @classmethod
    def from_dict(cls, raw: Mapping[str, JsonValue]) -> HandoffConstraint:
        obj = _req_dict(raw)
        _check_keys(obj, required=frozenset({"id", "constraint"}))
        return cls(id=require_opaque_id(obj["id"]), constraint=_req_nonempty_str(obj["constraint"]))


@dataclass(frozen=True)
class HandoffConstraintChange:
    id: str
    target_constraint_id: str
    proposed_constraint: str
    reason: str
    status: str = "proposed"

    def __post_init__(self) -> None:
        require_opaque_id(self.id)
        require_opaque_id(self.target_constraint_id)
        _req_nonempty_str(self.proposed_constraint)
        _req_nonempty_str(self.reason)
        if self.status != "proposed":
            raise _invalid()

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "id": self.id,
            "target_constraint_id": self.target_constraint_id,
            "proposed_constraint": self.proposed_constraint,
            "reason": self.reason,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, JsonValue], *, allow_status: bool = False) -> HandoffConstraintChange:
        obj = _req_dict(raw)
        opt = frozenset({"status"}) if allow_status else frozenset()
        _check_keys(
            obj,
            required=frozenset({"id", "target_constraint_id", "proposed_constraint", "reason"}),
            optional=opt,
        )
        return cls(
            id=require_opaque_id(obj["id"]),
            target_constraint_id=require_opaque_id(obj["target_constraint_id"]),
            proposed_constraint=_req_nonempty_str(obj["proposed_constraint"]),
            reason=_req_nonempty_str(obj["reason"]),
            status="proposed" if obj.get("status") is None else _req_nonempty_str(obj["status"]),
        )


@dataclass(frozen=True)
class HandoffClosedChange:
    change_id: str
    resolution: str
    reason: str | None = None

    def __post_init__(self) -> None:
        require_opaque_id(self.change_id)
        if self.resolution not in _VALID_CLOSED_RESOLUTIONS:
            raise _invalid()
        if self.reason is not None:
            _req_nonempty_str(self.reason)

    def to_dict(self) -> dict[str, JsonValue]:
        out: dict[str, JsonValue] = {"change_id": self.change_id, "resolution": self.resolution}
        if self.reason is not None:
            out["reason"] = self.reason
        return out

    @classmethod
    def from_dict(cls, raw: Mapping[str, JsonValue]) -> HandoffClosedChange:
        obj = _req_dict(raw)
        _check_keys(obj, required=frozenset({"change_id", "resolution"}), optional=frozenset({"reason"}))
        reason = obj.get("reason")
        return cls(
            change_id=require_opaque_id(obj["change_id"]),
            resolution=_req_nonempty_str(obj["resolution"]),
            reason=None if reason is None else _req_nonempty_str(reason),
        )


@dataclass(frozen=True)
class HandoffTooling:
    purpose: str
    command: str

    def __post_init__(self) -> None:
        _req_nonempty_str(self.purpose)
        _req_nonempty_str(self.command)

    def to_dict(self) -> dict[str, JsonValue]:
        return {"purpose": self.purpose, "command": self.command}

    @classmethod
    def from_dict(cls, raw: Mapping[str, JsonValue]) -> HandoffTooling:
        obj = _req_dict(raw)
        _check_keys(obj, required=frozenset({"purpose", "command"}))
        return cls(purpose=_req_nonempty_str(obj["purpose"]), command=_req_nonempty_str(obj["command"]))


@dataclass(frozen=True)
class HandoffNextAction:
    summary: str
    depends_on_change: str | None = None

    def __post_init__(self) -> None:
        _req_nonempty_str(self.summary)
        if self.depends_on_change is not None:
            require_opaque_id(self.depends_on_change)

    def to_dict(self) -> dict[str, JsonValue]:
        out: dict[str, JsonValue] = {"summary": self.summary}
        if self.depends_on_change is not None:
            out["depends_on_change"] = self.depends_on_change
        return out

    @classmethod
    def from_dict(cls, raw: Mapping[str, JsonValue]) -> HandoffNextAction:
        obj = _req_dict(raw)
        _check_keys(obj, required=frozenset({"summary"}), optional=frozenset({"depends_on_change"}))
        dep = obj.get("depends_on_change")
        return cls(
            summary=_req_nonempty_str(obj["summary"]),
            depends_on_change=None if dep is None else require_opaque_id(dep),
        )


@dataclass(frozen=True)
class HandoffLongRunning:
    command: str
    cwd: str
    source_revision: str
    log_or_receipt_path: str
    next_action: str
    pid: int | None = None
    started_at: str | None = None

    def __post_init__(self) -> None:
        _req_nonempty_str(self.command)
        _req_nonempty_str(self.cwd)
        _req_nonempty_str(self.source_revision)
        _req_nonempty_str(self.log_or_receipt_path)
        _req_nonempty_str(self.next_action)
        if self.pid is not None:
            require_positive_int(self.pid)
        if self.started_at is not None:
            _req_nonempty_str(self.started_at)

    def to_dict(self) -> dict[str, JsonValue]:
        out: dict[str, JsonValue] = {
            "command": self.command,
            "cwd": self.cwd,
            "source_revision": self.source_revision,
            "log_or_receipt_path": self.log_or_receipt_path,
            "next_action": self.next_action,
        }
        if self.pid is not None:
            out["pid"] = self.pid
        if self.started_at is not None:
            out["started_at"] = self.started_at
        return out

    @classmethod
    def from_dict(cls, raw: Mapping[str, JsonValue]) -> HandoffLongRunning:
        obj = _req_dict(raw)
        _check_keys(
            obj,
            required=frozenset({"command", "cwd", "source_revision", "log_or_receipt_path", "next_action"}),
            optional=frozenset({"pid", "started_at"}),
        )
        raw_pid = obj.get("pid")
        raw_started = obj.get("started_at")
        return cls(
            command=_req_nonempty_str(obj["command"]),
            cwd=_req_nonempty_str(obj["cwd"]),
            source_revision=_req_nonempty_str(obj["source_revision"]),
            log_or_receipt_path=_req_nonempty_str(obj["log_or_receipt_path"]),
            next_action=_req_nonempty_str(obj["next_action"]),
            pid=None if raw_pid is None else require_positive_int(raw_pid),
            started_at=None if raw_started is None else _req_nonempty_str(raw_started),
        )


@dataclass(frozen=True)
class HandoffPatch:
    working_goal: str | Unset = UNSET
    plan: tuple[HandoffPlanStep, ...] | Unset = UNSET
    decisions: tuple[HandoffDecision, ...] = ()
    rejected: tuple[HandoffRejected, ...] = ()
    user_constraints: tuple[HandoffConstraint, ...] = ()
    constraint_changes: tuple[HandoffConstraintChange, ...] = ()
    closed_changes: tuple[HandoffClosedChange, ...] = ()
    tooling: tuple[HandoffTooling, ...] | Unset = UNSET
    hypotheses: tuple[str, ...] | Unset = UNSET
    next_action: HandoffNextAction | None | Unset = UNSET
    long_running: HandoffLongRunning | None | Unset = UNSET
    task_state: str | Unset = UNSET


_PATCH_KEYS = frozenset(
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


def parse_handoff_patch(raw: Mapping[str, JsonValue]) -> HandoffPatch:
    """Validate and decode wire ``submit_episode.handoff`` mapping into ``HandoffPatch``."""
    obj = _req_dict(raw)
    if not obj or any(k not in _PATCH_KEYS for k in obj):
        raise _invalid()

    def _seq(key: str) -> Sequence[JsonValue]:
        val = obj[key]
        if not isinstance(val, Sequence) or isinstance(val, (str, bytes)) or len(val) > 64:
            raise _invalid()
        return val

    working_goal: str | Unset = _req_nonempty_str(obj["working_goal"]) if "working_goal" in obj else UNSET
    plan: tuple[HandoffPlanStep, ...] | Unset = (
        tuple(HandoffPlanStep.from_dict(_req_dict(x)) for x in _seq("plan")) if "plan" in obj else UNSET
    )
    decisions = tuple(HandoffDecision.from_dict(_req_dict(x)) for x in _seq("decisions")) if "decisions" in obj else ()
    rejected = tuple(HandoffRejected.from_dict(_req_dict(x)) for x in _seq("rejected")) if "rejected" in obj else ()
    user_constraints = (
        tuple(HandoffConstraint.from_dict(_req_dict(x)) for x in _seq("user_constraints"))
        if "user_constraints" in obj
        else ()
    )
    constraint_changes = (
        tuple(HandoffConstraintChange.from_dict(_req_dict(x)) for x in _seq("constraint_changes"))
        if "constraint_changes" in obj
        else ()
    )
    closed_changes = (
        tuple(HandoffClosedChange.from_dict(_req_dict(x)) for x in _seq("closed_changes"))
        if "closed_changes" in obj
        else ()
    )
    tooling: tuple[HandoffTooling, ...] | Unset = (
        tuple(HandoffTooling.from_dict(_req_dict(x)) for x in _seq("tooling")) if "tooling" in obj else UNSET
    )
    hypotheses: tuple[str, ...] | Unset = (
        tuple(_req_nonempty_str(x) for x in _seq("hypotheses")) if "hypotheses" in obj else UNSET
    )
    next_action: HandoffNextAction | None | Unset = UNSET
    if "next_action" in obj:
        raw_na = obj["next_action"]
        next_action = None if raw_na is None else HandoffNextAction.from_dict(_req_dict(raw_na))
    long_running: HandoffLongRunning | None | Unset = UNSET
    if "long_running" in obj:
        raw_lr = obj["long_running"]
        long_running = None if raw_lr is None else HandoffLongRunning.from_dict(_req_dict(raw_lr))
    task_state: str | Unset = UNSET
    if "task_state" in obj:
        raw_ts = obj["task_state"]
        if not isinstance(raw_ts, str) or raw_ts not in _VALID_TASK_STATES:
            raise _invalid()
        task_state = raw_ts
    return HandoffPatch(
        working_goal=working_goal,
        plan=plan,
        decisions=decisions,
        rejected=rejected,
        user_constraints=user_constraints,
        constraint_changes=constraint_changes,
        closed_changes=closed_changes,
        tooling=tooling,
        hypotheses=hypotheses,
        next_action=next_action,
        long_running=long_running,
        task_state=task_state,
    )


@dataclass(frozen=True)
class HandoffAgentState:
    """Canonical agent-reported section stored as an immutable CAS blob referenced by ``agent_ref``."""

    working_goal: str | None = None
    plan: tuple[HandoffPlanStep, ...] = ()
    decisions: tuple[HandoffDecision, ...] = ()
    rejected: tuple[HandoffRejected, ...] = ()
    user_constraints: tuple[HandoffConstraint, ...] = ()
    constraint_changes: tuple[HandoffConstraintChange, ...] = ()
    closed_changes: tuple[HandoffClosedChange, ...] = ()
    tooling: tuple[HandoffTooling, ...] = ()
    hypotheses: tuple[str, ...] = ()
    next_action: HandoffNextAction | None = None
    long_running: HandoffLongRunning | None = None
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
        obj = _req_dict(raw)
        wg = obj.get("working_goal")
        na = obj.get("next_action")
        lr = obj.get("long_running")
        ts = obj.get("task_state", "open")
        if not isinstance(ts, str) or ts not in _VALID_TASK_STATES:
            raise _invalid()

        def _seq(key: str) -> Sequence[JsonValue]:
            val = obj.get(key, [])
            if not isinstance(val, Sequence) or isinstance(val, (str, bytes)):
                raise _invalid()
            return val

        return cls(
            working_goal=None if wg is None else _req_nonempty_str(wg),
            plan=tuple(HandoffPlanStep.from_dict(_req_dict(x)) for x in _seq("plan")),
            decisions=tuple(HandoffDecision.from_dict(_req_dict(x)) for x in _seq("decisions")),
            rejected=tuple(HandoffRejected.from_dict(_req_dict(x)) for x in _seq("rejected")),
            user_constraints=tuple(HandoffConstraint.from_dict(_req_dict(x)) for x in _seq("user_constraints")),
            constraint_changes=tuple(
                HandoffConstraintChange.from_dict(_req_dict(x), allow_status=True) for x in _seq("constraint_changes")
            ),
            closed_changes=tuple(HandoffClosedChange.from_dict(_req_dict(x)) for x in _seq("closed_changes")),
            tooling=tuple(HandoffTooling.from_dict(_req_dict(x)) for x in _seq("tooling")),
            hypotheses=tuple(_req_nonempty_str(x) for x in _seq("hypotheses")),
            next_action=None if na is None else HandoffNextAction.from_dict(_req_dict(na)),
            long_running=None if lr is None else HandoffLongRunning.from_dict(_req_dict(lr)),
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
    fence: HandoffFence
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
            raise _invalid()
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
    "ResolvedSourceContent",
    "Unset",
    "parse_handoff_patch",
]
