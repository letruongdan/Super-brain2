"""Storage/application boundary types for SP2-4 task handoffs, deliveries, episodes, and C5 receipts."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import Scope
from superbrain.ports._handoff_types import (
    HandoffAgentState,
    HandoffFence,
    HandoffLive,
    HandoffPatch,
    HandoffRevisionHeader,
    ResolvedSourceContent,
)
from superbrain.ports.kernel import KernelTx


@dataclass(frozen=True)
class ResumeRefSpec:
    artifact_id: str
    revision: int
    handoff_revision: int
    fence: HandoffFence
    served_receipt_id: str | None = None


@dataclass(frozen=True)
class SeenHandoffSpec:
    artifact_id: str
    revision_epoch: int
    revision: int
    digest: str


@dataclass(frozen=True)
class DeliveryOutcomeRecord:
    delivery_id: str
    task_id: str
    owner_id: str
    repo_id: str
    checkout_id: str
    principal_id: str
    session_ref: str | None
    source_snapshot_id: str | None
    snapshot_status: str
    assignment_id: str | None
    exposure_evidence: str
    degraded_codes: tuple[str, ...]
    resume_artifact_id: str | None
    resume_revision_epoch: int | None
    resume_revision: int | None
    resume_receipt_id: str | None
    seen_refs: tuple[tuple[str, int, int, str], ...]
    handoff_served_epoch: int | None = None
    handoff_served_rev: int | None = None
    handoff_served_digest: str | None = None


@dataclass(frozen=True)
class ArtifactGetRecord:
    result_id: str
    task_id: str
    artifact_id: str
    revision_epoch: int
    revision: int
    level: str
    owner_id: str
    repo_id: str
    checkout_id: str
    principal_id: str


@dataclass(frozen=True)
class EpisodeOutcomeRecord:
    episode_id: str
    task_id: str
    owner_id: str
    repo_id: str
    checkout_id: str
    principal_id: str
    session_ref: str
    has_handoff_op: bool
    handoff_status: str | None
    handoff_artifact_id: str | None
    committed_handoff_revision: int | None
    committed_revision: int | None
    committed_restore_epoch: int | None
    committed_writer_generation: int | None
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True)
class HandoffContentBundle:
    header: HandoffRevisionHeader
    live: HandoffHeaderState
    task_goal: str | None
    goal_status: str
    agent_state: HandoffAgentState | None
    agent_status: str
    observed_sources: tuple[ResolvedSourceContent, ...]
    conversation_sources: tuple[ResolvedSourceContent, ...]
    holder_harness_id: str | None
    session_state: str | None
    other_active_warning: bool
    revision_history: tuple[HandoffRevisionHeader, ...] = ()
    events_since_agent: int = 0


@dataclass(frozen=True)
class CreateWorkTaskResult:
    task_id: str
    artifact_id: str
    delivery_id: str
    goal_digest: str
    handoff_live: HandoffLive


@dataclass(frozen=True)
class DiscoverEntry:
    task_id: str
    artifact_id: str
    revision_epoch: int
    revision: int
    digest: str
    summary: str
    status: str  # "ok" | "redacted"
    reason: str | None = None


@dataclass(frozen=True)
class HandoffHeaderState:
    task_id: str
    artifact_id: str
    repo_id: str
    checkout_id: str
    revision: int
    revision_epoch: int
    handoff_revision: int
    writer_generation: int
    holder_principal: str | None
    holder_session_ref: str | None
    holder_restore_epoch: int
    live_restore_epoch: int
    task_state: str
    task_state_source: str
    goal_ref: str | None
    agent_ref: str | None
    observed_ref: str | None
    l0_summary_ref: str | None
    agent_updated_at: str | None
    observed_through: str | None

    @property
    def committed_fence(self) -> HandoffFence:
        return HandoffFence(restore_epoch=self.holder_restore_epoch, writer_generation=self.writer_generation)

    @property
    def live_fence(self) -> HandoffFence:
        return HandoffFence(restore_epoch=self.live_restore_epoch, writer_generation=self.writer_generation)

    @property
    def handoff_live(self) -> HandoffLive:
        if self.revision == 0:
            return HandoffLive(
                revision=None,
                revision_epoch=None,
                handoff_revision=0,
                fence=HandoffFence(restore_epoch=self.live_restore_epoch, writer_generation=0),
            )
        return HandoffLive(
            revision=self.revision,
            revision_epoch=self.revision_epoch,
            handoff_revision=self.handoff_revision,
            fence=self.live_fence,
        )


@dataclass(frozen=True)
class HandoffMutationOutcome:
    episode_id: str
    evidence_ids: tuple[str, ...]
    handoff_status: str  # "stored" | "not_stored_policy"
    handoff_revision: int | None
    revision: int | None
    revision_epoch: int | None
    fence: HandoffFence
    holder_principal: str | None
    holder_session_ref: str | None


class HandoffStorePort(Protocol):
    """Port implemented by ``storage.handoffs.HandoffStore``."""

    def read_header(self, task_id: str, *, principal_id: str, scope: Scope) -> HandoffHeaderState | None: ...

    def read_revision_header(
        self,
        *,
        artifact_id: str,
        revision_epoch: int,
        revision: int,
        principal_id: str,
        scope: Scope,
    ) -> HandoffRevisionHeader | None: ...

    def list_revision_history(
        self,
        *,
        artifact_id: str,
        task_id: str,
        revision_epoch: int,
        revision: int,
        principal_id: str,
        scope: Scope,
        limit: int = 1024,
    ) -> tuple[HandoffRevisionHeader, ...]: ...

    def list_discover(
        self,
        *,
        principal_id: str,
        owner_id: str,
        repo_id: str,
        checkout_id: str,
        task_id: str | None = None,
        now: datetime,
        render_l0: Callable[..., str] | None = None,
    ) -> tuple[DiscoverEntry, ...]: ...

    def create_work_task(
        self,
        *,
        task_id: str,
        owner_id: str,
        repo_id: str,
        checkout_id: str,
        principal_id: str,
        session_ref: str | None,
        description: str,
        delivery_id: str,
        now: datetime,
    ) -> CreateWorkTaskResult: ...

    def commit_handoff_mutation(
        self,
        *,
        task_id: str,
        owner_id: str,
        repo_id: str,
        checkout_id: str,
        principal_id: str,
        harness_id: str,
        session_ref: str,
        episode_id: str,
        base_revision: int | None,
        expected_fence: HandoffFence | None,
        takeover: bool,
        takeover_acknowledge_active: bool,
        patch: HandoffPatch | None,
        raw_patch: JsonValue | None = None,
        evidence_digests: Sequence[tuple[str, bytes]],
        manual_submission_enabled: bool,
        now: datetime,
        apply_patch: Callable[[HandoffAgentState | None, HandoffPatch], HandoffAgentState] | None = None,
        validate_limits: (
            Callable[[HandoffAgentState | None, HandoffAgentState, Mapping[str, JsonValue]], None] | None
        ) = None,
    ) -> HandoffMutationOutcome: ...

    def has_open_handoffs(
        self, *, owner_id: str, repo_id: str, checkout_id: str, now: datetime | None = None
    ) -> bool: ...

    def bind_session_for_episode(
        self,
        *,
        principal_id: str,
        repo_id: str,
        checkout_id: str,
        harness_id: str,
        raw_session_id: str,
        now: datetime,
    ) -> str: ...

    def resolve_task_scope(self, task_id: str, *, principal_id: str, scope: Scope) -> HandoffHeaderState: ...

    def read_task_header_scoped(
        self,
        task_id: str,
        *,
        owner_id: str,
        selected_scope: Scope | None,
    ) -> HandoffHeaderState: ...

    def try_read_task_header_scoped(
        self,
        task_id: str,
        *,
        owner_id: str,
        selected_scope: Scope | None,
    ) -> HandoffHeaderState | None: ...

    def resolve_artifact_revision_epoch(
        self,
        *,
        task_id: str,
        artifact_id: str,
        revision: int,
        revision_epoch: int | None,
        principal_id: str,
        scope: Scope,
    ) -> int: ...

    def load_agent_state_scoped(
        self,
        *,
        task_id: str,
        principal_id: str,
        scope: Scope,
        now: datetime,
    ) -> HandoffAgentState | None: ...

    def tx_record_work_delivery(
        self,
        tx: KernelTx,
        *,
        delivery_id: str,
        task_id: str,
        owner_id: str,
        repo_id: str,
        checkout_id: str,
        principal_id: str,
        session_ref: str | None,
        description_bytes: bytes | None,
        create_task: bool,
        source_snapshot_id: str | None,
        snapshot_status: str,
        assignment_id: str | None,
        resume_ref: ResumeRefSpec | None,
        seen_handoff_refs: Sequence[SeenHandoffSpec],
        exposure_evidence: str,
        degraded_codes: Sequence[str],
        now: datetime,
        task_id_provided: bool | None = None,
    ) -> CreateWorkTaskResult: ...

    def read_delivery_outcome(
        self,
        delivery_id: str,
        *,
        owner_id: str,
        principal_id: str,
        selected_scope: Scope | None,
    ) -> DeliveryOutcomeRecord: ...

    def render_delivery_handoff_l0(
        self,
        *,
        task_id: str,
        owner_id: str,
        repo_id: str,
        checkout_id: str,
        revision_epoch: int,
        revision: int,
        served_digest: str | None,
        now: datetime,
        render_l0: Callable[..., str] | None = None,
    ) -> DiscoverEntry: ...

    def tx_record_artifact_get(
        self,
        tx: KernelTx,
        *,
        result_id: str,
        task_id: str,
        artifact_id: str,
        revision_epoch: int,
        revision: int,
        level: str,
        owner_id: str,
        repo_id: str,
        checkout_id: str,
        principal_id: str,
        now: datetime,
    ) -> None: ...

    def read_artifact_get(
        self,
        result_id: str,
        *,
        owner_id: str,
        principal_id: str,
        selected_scope: Scope | None,
    ) -> ArtifactGetRecord: ...

    def read_handoff_content_bundle(
        self,
        *,
        artifact_id: str,
        revision_epoch: int,
        revision: int,
        task_id: str,
        principal_id: str,
        scope: Scope,
        now: datetime,
        include_history: bool = False,
    ) -> HandoffContentBundle: ...

    def tx_commit_handoff_mutation(
        self,
        tx: KernelTx,
        *,
        task_id: str,
        owner_id: str,
        repo_id: str,
        checkout_id: str,
        principal_id: str,
        harness_id: str,
        session_ref: str,
        episode_id: str,
        base_revision: int | None,
        expected_fence: HandoffFence | None,
        takeover: bool,
        takeover_acknowledge_active: bool,
        has_patch: bool,
        new_agent_bytes: bytes | None,
        next_task_state: str | None,
        evidence_items: Sequence[tuple[str, bytes]],
        manual_submission_enabled: bool,
        now: datetime,
    ) -> HandoffMutationOutcome: ...

    def read_episode_outcome(
        self,
        episode_id: str,
        *,
        owner_id: str,
        principal_id: str,
        selected_scope: Scope | None,
    ) -> EpisodeOutcomeRecord: ...

    def read_live_holder_status(
        self,
        task_id: str,
        *,
        principal_id: str,
        session_ref: str,
        scope: Scope,
    ) -> tuple[bool, HandoffFence]: ...


__all__ = [
    "ArtifactGetRecord",
    "CreateWorkTaskResult",
    "DeliveryOutcomeRecord",
    "DiscoverEntry",
    "EpisodeOutcomeRecord",
    "HandoffContentBundle",
    "HandoffHeaderState",
    "HandoffMutationOutcome",
    "HandoffStorePort",
    "ResumeRefSpec",
    "SeenHandoffSpec",
]
