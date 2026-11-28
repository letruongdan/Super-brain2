"""SP2-4 durable storage adapter for task handoffs, immutable revision headers, deliveries & episodes."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timedelta

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import Scope
from superbrain.ports._handoff_types import (
    HandoffAgentState,
    HandoffFence,
    HandoffPatch,
    HandoffRevisionHeader,
    ResolvedSourceContent,
)
from superbrain.ports.handoff import (
    ArtifactGetRecord,
    CreateWorkTaskResult,
    DeliveryOutcomeRecord,
    DiscoverEntry,
    EpisodeOutcomeRecord,
    HandoffContentBundle,
    HandoffHeaderState,
    HandoffMutationOutcome,
    HandoffStorePort,
    ResumeRefSpec,
    SeenHandoffSpec,
)
from superbrain.ports.kernel import KernelTx
from superbrain.storage import _handoff_apply, _handoff_delivery, _handoff_headers, _handoff_mutations, _handoff_reads
from superbrain.storage._handoff_rows import _check_blob_status as _check_blob_status
from superbrain.storage._handoff_rows import _has_open_handoffs_in_db as _has_open_handoffs_in_db
from superbrain.storage._handoff_rows import _insert_episode_evidence as _insert_episode_evidence
from superbrain.storage._handoff_rows import _req_int as _req_int
from superbrain.storage._handoff_rows import _require_v8_ready as _require_v8_ready
from superbrain.storage._handoff_rows import _row_to_header as _row_to_header
from superbrain.storage._handoff_rows import _row_to_rev_header as _row_to_rev_header
from superbrain.storage._handoff_rows import _txn_of as _txn_of
from superbrain.storage._handoff_rows import _unique_codes as _unique_codes
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.store import Store

_EVENT_RETENTION = timedelta(days=90)
_DISCOVER_WINDOW = timedelta(days=14)
_OPEN_HANDOFFS_PRESENT_CODE = "open_handoffs_present"
_OBSERVED_NEWER_CODE = "observed_newer"


_HEADER_SQL = (
    "SELECT h.task_id, h.artifact_id, h.repo_id, h.checkout_id, h.current_revision, h.current_revision_epoch, "
    "h.handoff_revision, h.writer_generation, h.holder_principal, h.holder_session_ref, h.holder_restore_epoch, "
    "h.task_state, h.task_state_source, COALESCE(h.goal_ref, t.goal_ref), h.agent_ref, h.observed_ref, "
    "h.l0_summary_ref, h.agent_updated_at, h.observed_through "
    "FROM task_handoffs AS h JOIN tasks AS t ON t.task_id = h.task_id "
)


_REV_HDR_SELECT = (
    "SELECT r.artifact_id, r.revision_epoch, r.revision, r.handoff_revision, r.task_id, r.task_state, "
    "r.task_state_source, r.holder_restore_epoch, r.writer_generation, r.holder_harness_id, "
    "r.holder_principal, r.holder_session_ref, r.session_state, r.agent_ref, r.observed_ref, "
    "r.agent_updated_at, r.observed_through, t.repo_id, t.checkout_id, r.events_since_agent "
    "FROM handoff_revision_headers AS r JOIN tasks AS t ON t.task_id = r.task_id "
)


class HandoffStore(HandoffStorePort):
    """Durable SP2-4 handoff, immutable revision header, delivery, and episode store over ``store v8``."""

    def __init__(self, store: Store, policy: PolicyStore) -> None:
        self._store = store
        self._policy = policy

    def read_header(self, task_id: str, *, principal_id: str, scope: Scope) -> HandoffHeaderState | None:
        return _handoff_headers.read_header(self, task_id, principal_id=principal_id, scope=scope)

    def read_header_by_artifact(
        self,
        artifact_id: str,
        *,
        task_id: str,
        scope: Scope,
    ) -> HandoffHeaderState:
        return _handoff_mutations.read_header_by_artifact(self, artifact_id, task_id=task_id, scope=scope)

    def read_revision_header(
        self,
        *,
        artifact_id: str,
        revision_epoch: int,
        revision: int,
        principal_id: str,
        scope: Scope,
    ) -> HandoffRevisionHeader | None:
        return _handoff_mutations.read_revision_header(
            self, artifact_id=artifact_id, revision_epoch=revision_epoch, revision=revision, principal_id=principal_id,
            scope=scope,
        )

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
    ) -> tuple[HandoffRevisionHeader, ...]:
        """Return pinned-branch headers newest-first up to ``limit``, isolating restore branches."""
        return _handoff_reads.list_revision_history(
            self, artifact_id=artifact_id, task_id=task_id, revision_epoch=revision_epoch, revision=revision,
            principal_id=principal_id, scope=scope, limit=limit,
        )

    def has_open_handoffs(
        self, *, owner_id: str, repo_id: str, checkout_id: str, now: datetime | None = None
    ) -> bool:
        return _handoff_headers.has_open_handoffs(
            self, owner_id=owner_id, repo_id=repo_id, checkout_id=checkout_id, now=now,
        )

    def _render_l0_row(
        self,
        *,
        tid: str,
        art_id: str,
        rev_epoch: int,
        rev: int,
        hrev: int,
        goal_ref: str | None,
        goal_hid: str | None,
        agent_ref: str | None,
        agent_hid: str | None,
        holder_sref: str | None,
        agent_at: str | None,
        obs_through: str | None,
        repo_id: str,
        checkout_id: str,
        now_utc: datetime,
        render_l0: Callable[..., str] | None,
    ) -> DiscoverEntry:
        return _handoff_delivery._render_l0_row(
            self, tid=tid, art_id=art_id, rev_epoch=rev_epoch, rev=rev, hrev=hrev, goal_ref=goal_ref,
            goal_hid=goal_hid, agent_ref=agent_ref, agent_hid=agent_hid, holder_sref=holder_sref, agent_at=agent_at,
            obs_through=obs_through, repo_id=repo_id, checkout_id=checkout_id, now_utc=now_utc, render_l0=render_l0,
        )

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
    ) -> DiscoverEntry:
        return _handoff_delivery.render_delivery_handoff_l0(
            self, task_id=task_id, owner_id=owner_id, repo_id=repo_id, checkout_id=checkout_id,
            revision_epoch=revision_epoch, revision=revision, served_digest=served_digest, now=now,
            render_l0=render_l0,
        )

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
    ) -> tuple[DiscoverEntry, ...]:
        return _handoff_reads.list_discover(
            self, principal_id=principal_id, owner_id=owner_id, repo_id=repo_id, checkout_id=checkout_id,
            task_id=task_id, now=now, render_l0=render_l0,
        )

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
    ) -> CreateWorkTaskResult:
        return _handoff_mutations.create_work_task(
            self, task_id=task_id, owner_id=owner_id, repo_id=repo_id, checkout_id=checkout_id,
            principal_id=principal_id, session_ref=session_ref, description=description, delivery_id=delivery_id,
            now=now,
        )

    def tx_create_work_task(
        self,
        tx: KernelTx,
        *,
        task_id: str,
        owner_id: str,
        repo_id: str,
        checkout_id: str,
        principal_id: str,
        session_ref: str | None,
        goal_bytes: bytes | None,
        delivery_id: str,
        now: datetime,
    ) -> CreateWorkTaskResult:
        return _handoff_mutations.tx_create_work_task(
            self, tx, task_id=task_id, owner_id=owner_id, repo_id=repo_id, checkout_id=checkout_id,
            principal_id=principal_id, session_ref=session_ref, goal_bytes=goal_bytes, delivery_id=delivery_id,
            now=now,
        )

    def _apply_create_work_task_in_tx(
        self,
        db: sqlite3.Connection,
        *,
        live_epoch: int,
        task_id: str,
        owner_id: str,
        repo_id: str,
        checkout_id: str,
        principal_id: str,
        session_ref: str | None,
        goal_digest: str | None,
        goal_holder_id: str | None,
        delivery_id: str,
        now: datetime,
    ) -> CreateWorkTaskResult:
        return _handoff_apply._apply_create_work_task_in_tx(
            self, db, live_epoch=live_epoch, task_id=task_id, owner_id=owner_id, repo_id=repo_id,
            checkout_id=checkout_id, principal_id=principal_id, session_ref=session_ref, goal_digest=goal_digest,
            goal_holder_id=goal_holder_id, delivery_id=delivery_id, now=now,
        )

    def _is_session_active(self, db: sqlite3.Connection, session_ref: str, *, now: datetime) -> bool:
        return _handoff_headers._is_session_active(self, db, session_ref, now=now)

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
    ) -> HandoffMutationOutcome:
        return _handoff_mutations.commit_handoff_mutation(
            self, task_id=task_id, owner_id=owner_id, repo_id=repo_id, checkout_id=checkout_id,
            principal_id=principal_id, harness_id=harness_id, session_ref=session_ref, episode_id=episode_id,
            base_revision=base_revision, expected_fence=expected_fence, takeover=takeover,
            takeover_acknowledge_active=takeover_acknowledge_active, patch=patch, raw_patch=raw_patch,
            evidence_digests=evidence_digests, manual_submission_enabled=manual_submission_enabled, now=now,
            apply_patch=apply_patch, validate_limits=validate_limits,
        )

    def _load_agent_state_checked(self, hdr: HandoffHeaderState, *, now: datetime) -> HandoffAgentState | None:
        return _handoff_headers._load_agent_state_checked(self, hdr, now=now)

    def _apply_handoff_mutation_in_tx(
        self,
        db: sqlite3.Connection,
        *,
        live_epoch: int,
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
        new_agent_ref: str | None,
        new_agent_holder_id: str | None,
        next_task_state: str | None,
        evidence_held: Sequence[tuple[str, str, str]],
        manual_submission_enabled: bool,
        now: datetime,
    ) -> HandoffMutationOutcome:
        return _handoff_apply._apply_handoff_mutation_in_tx(
            self, db, live_epoch=live_epoch, task_id=task_id, owner_id=owner_id, repo_id=repo_id,
            checkout_id=checkout_id, principal_id=principal_id, harness_id=harness_id, session_ref=session_ref,
            episode_id=episode_id, base_revision=base_revision, expected_fence=expected_fence, takeover=takeover,
            takeover_acknowledge_active=takeover_acknowledge_active, has_patch=has_patch, new_agent_ref=new_agent_ref,
            new_agent_holder_id=new_agent_holder_id, next_task_state=next_task_state, evidence_held=evidence_held,
            manual_submission_enabled=manual_submission_enabled, now=now,
        )

    def resolve_observed_sources(
        self,
        *,
        task_id: str,
        observed_ref: str | None,
        now: datetime,
    ) -> tuple[list[ResolvedSourceContent], list[ResolvedSourceContent]]:
        """Resolve pinned ``observed_ref`` sources live at read time (never scanning uncommitted events)."""
        return _handoff_reads.resolve_observed_sources(self, task_id=task_id, observed_ref=observed_ref, now=now)

    def bind_session_for_episode(
        self,
        *,
        principal_id: str,
        repo_id: str,
        checkout_id: str,
        harness_id: str,
        raw_session_id: str,
        now: datetime,
    ) -> str:
        return _handoff_delivery.bind_session_for_episode(
            self, principal_id=principal_id, repo_id=repo_id, checkout_id=checkout_id, harness_id=harness_id,
            raw_session_id=raw_session_id, now=now,
        )

    def resolve_task_scope(self, task_id: str, *, principal_id: str, scope: Scope) -> HandoffHeaderState:
        hdr = self.read_header(task_id, principal_id=principal_id, scope=scope)
        if hdr is None:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        return hdr

    def try_read_task_header_scoped(
        self,
        task_id: str,
        *,
        owner_id: str,
        selected_scope: Scope | None,
    ) -> HandoffHeaderState | None:
        return _handoff_mutations.try_read_task_header_scoped(
            self, task_id, owner_id=owner_id, selected_scope=selected_scope,
        )

    def read_task_header_scoped(
        self,
        task_id: str,
        *,
        owner_id: str,
        selected_scope: Scope | None,
    ) -> HandoffHeaderState:
        return _handoff_headers.read_task_header_scoped(self, task_id, owner_id=owner_id, selected_scope=selected_scope)

    def resolve_artifact_revision_epoch(
        self,
        *,
        task_id: str,
        artifact_id: str,
        revision: int,
        revision_epoch: int | None,
        principal_id: str,
        scope: Scope,
    ) -> int:
        return _handoff_reads.resolve_artifact_revision_epoch(
            self, task_id=task_id, artifact_id=artifact_id, revision=revision, revision_epoch=revision_epoch,
            principal_id=principal_id, scope=scope,
        )

    def load_agent_state_scoped(
        self,
        *,
        task_id: str,
        principal_id: str,
        scope: Scope,
        now: datetime,
    ) -> HandoffAgentState | None:
        return _handoff_headers.load_agent_state_scoped(
            self, task_id=task_id, principal_id=principal_id, scope=scope, now=now,
        )

    def _validate_resume_in_tx(
        self,
        db: sqlite3.Connection,
        *,
        task_id: str,
        owner_id: str,
        repo_id: str,
        checkout_id: str,
        principal_id: str,
        cur: HandoffHeaderState,
        resume_ref: ResumeRefSpec,
    ) -> tuple[str, int, int, str | None, str, bool]:
        return _handoff_apply._validate_resume_in_tx(
            self, db, task_id=task_id, owner_id=owner_id, repo_id=repo_id, checkout_id=checkout_id,
            principal_id=principal_id, cur=cur, resume_ref=resume_ref,
        )

    def _validate_seen_refs_in_tx(
        self,
        db: sqlite3.Connection,
        *,
        owner_id: str,
        repo_id: str,
        checkout_id: str,
        seen_refs: Sequence[SeenHandoffSpec],
    ) -> None:
        _handoff_apply._validate_seen_refs_in_tx(
            self, db, owner_id=owner_id, repo_id=repo_id, checkout_id=checkout_id, seen_refs=seen_refs,
        )

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
    ) -> CreateWorkTaskResult:
        return _handoff_delivery.tx_record_work_delivery(
            self, tx, delivery_id=delivery_id, task_id=task_id, owner_id=owner_id, repo_id=repo_id,
            checkout_id=checkout_id, principal_id=principal_id, session_ref=session_ref,
            description_bytes=description_bytes, create_task=create_task, source_snapshot_id=source_snapshot_id,
            snapshot_status=snapshot_status, assignment_id=assignment_id, resume_ref=resume_ref,
            seen_handoff_refs=seen_handoff_refs, exposure_evidence=exposure_evidence, degraded_codes=degraded_codes,
            now=now, task_id_provided=task_id_provided,
        )

    def read_delivery_outcome(
        self,
        delivery_id: str,
        *,
        owner_id: str,
        principal_id: str,
        selected_scope: Scope | None,
    ) -> DeliveryOutcomeRecord:
        return _handoff_delivery.read_delivery_outcome(
            self, delivery_id, owner_id=owner_id, principal_id=principal_id, selected_scope=selected_scope,
        )

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
    ) -> None:
        _handoff_mutations.tx_record_artifact_get(
            self, tx, result_id=result_id, task_id=task_id, artifact_id=artifact_id, revision_epoch=revision_epoch,
            revision=revision, level=level, owner_id=owner_id, repo_id=repo_id, checkout_id=checkout_id,
            principal_id=principal_id, now=now,
        )

    def read_artifact_get(
        self,
        result_id: str,
        *,
        owner_id: str,
        principal_id: str,
        selected_scope: Scope | None,
    ) -> ArtifactGetRecord:
        return _handoff_reads.read_artifact_get(
            self, result_id, owner_id=owner_id, principal_id=principal_id, selected_scope=selected_scope,
        )

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
    ) -> HandoffContentBundle:
        return _handoff_reads.read_handoff_content_bundle(
            self, artifact_id=artifact_id, revision_epoch=revision_epoch, revision=revision, task_id=task_id,
            principal_id=principal_id, scope=scope, now=now, include_history=include_history,
        )

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
    ) -> HandoffMutationOutcome:
        return _handoff_mutations.tx_commit_handoff_mutation(
            self, tx, task_id=task_id, owner_id=owner_id, repo_id=repo_id, checkout_id=checkout_id,
            principal_id=principal_id, harness_id=harness_id, session_ref=session_ref, episode_id=episode_id,
            base_revision=base_revision, expected_fence=expected_fence, takeover=takeover,
            takeover_acknowledge_active=takeover_acknowledge_active, has_patch=has_patch,
            new_agent_bytes=new_agent_bytes, next_task_state=next_task_state, evidence_items=evidence_items,
            manual_submission_enabled=manual_submission_enabled, now=now,
        )

    def read_episode_outcome(
        self,
        episode_id: str,
        *,
        owner_id: str,
        principal_id: str,
        selected_scope: Scope | None,
    ) -> EpisodeOutcomeRecord:
        return _handoff_delivery.read_episode_outcome(
            self, episode_id, owner_id=owner_id, principal_id=principal_id, selected_scope=selected_scope,
        )

    def read_live_holder_status(
        self,
        task_id: str,
        *,
        principal_id: str,
        session_ref: str,
        scope: Scope,
    ) -> tuple[bool, HandoffFence]:
        return _handoff_headers.read_live_holder_status(
            self, task_id, principal_id=principal_id, session_ref=session_ref, scope=scope,
        )


__all__ = ["HandoffStore"]
