"""Stored-result rendering (artifact, delivery, episode) for ``handoff_service.HandoffKernelDomain``."""

from __future__ import annotations

from superbrain.application import handoff_service as _m
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    Principal,
    Scope,
)
from superbrain.domain.continuity.handoff_model import HandoffFence
from superbrain.domain.continuity.rendering import (
    render_handoff_l0,
    render_handoff_l1,
    render_handoff_l2,
)
from superbrain.ports.handoff import (
    DiscoverEntry,
)


def _render_artifact(
    self: _m.HandoffKernelDomain,
    result_id: str,
    principal: Principal,
    *,
    selected_scope: Scope | None,
) -> dict[str, JsonValue]:
    rec = self._handoffs.read_artifact_get(
        result_id,
        owner_id=principal.owner_id,
        principal_id=principal.principal_id,
        selected_scope=selected_scope,
    )
    scope = Scope(rec.repo_id, rec.checkout_id)
    if not self._policy.allows(principal, scope, action="get_artifact"):
        raise BrainError(ErrorCode.NOT_FOUND, "not found")
    bundle = self._handoffs.read_handoff_content_bundle(
        artifact_id=rec.artifact_id,
        revision_epoch=rec.revision_epoch,
        revision=rec.revision,
        task_id=rec.task_id,
        principal_id=principal.principal_id,
        scope=scope,
        now=self._clock.now(),
        include_history=(rec.level == "L2"),
    )
    if bundle.goal_status != "ok" or bundle.agent_status != "ok":
        reason = bundle.goal_status if bundle.goal_status != "ok" else bundle.agent_status
        return {
            "artifact_id": rec.artifact_id,
            "revision_epoch": rec.revision_epoch,
            "revision": rec.revision,
            "level": rec.level,
            "status": "redacted",
            "reason": reason,
            "resources": [],
        }
    resources: list[dict[str, JsonValue]]
    if rec.level == "L0":
        l0 = render_handoff_l0(
            task_goal=bundle.task_goal or "",
            state=bundle.agent_state,
            handoff_revision=bundle.header.handoff_revision,
            session_state=bundle.session_state,
            agent_updated_at=bundle.header.agent_updated_at,
            observed_through=bundle.header.observed_through,
            other_active_warning=bundle.other_active_warning,
        )
        resources = [
            {
                "name": "handoff_l0",
                "digest": digest_bytes(l0.encode("utf-8")),
                "encoding": "utf-8",
                "content": l0,
            }
        ]
    else:
        l1_resources, _ = render_handoff_l1(
            task_id=bundle.header.task_id,
            artifact_id=bundle.header.artifact_id,
            revision=bundle.header.revision,
            revision_epoch=bundle.header.revision_epoch,
            handoff_revision=bundle.header.handoff_revision,
            writer_generation=bundle.header.fence.writer_generation,
            holder_harness_id=bundle.holder_harness_id,
            session_state=bundle.session_state,
            agent_updated_at=bundle.header.agent_updated_at,
            observed_through=bundle.header.observed_through,
            task_goal=bundle.task_goal or "",
            state=bundle.agent_state,
            observed_sources=bundle.observed_sources,
            agent_ref=bundle.header.agent_ref,
            observed_ref=bundle.header.observed_ref,
            task_state=bundle.header.task_state,
            task_state_source=bundle.header.task_state_source,
            restore_epoch_for_header=bundle.header.fence.restore_epoch,
            events_since_agent=bundle.events_since_agent,
        )
        if rec.level == "L1":
            resources = l1_resources
        else:
            hist_headers = bundle.revision_history or (bundle.header,)
            rev_hist: list[dict[str, JsonValue]] = [
                {
                    "artifact_id": h.artifact_id,
                    "revision_epoch": h.revision_epoch,
                    "revision": h.revision,
                    "handoff_revision": h.handoff_revision,
                    "task_state": h.task_state,
                    "task_state_source": h.task_state_source,
                    "fence": h.fence.to_dict(),
                    "agent_ref": h.agent_ref,
                    "observed_ref": h.observed_ref,
                    "agent_updated_at": h.agent_updated_at,
                    "observed_through": h.observed_through,
                    "events_since_agent": h.events_since_agent,
                }
                for h in hist_headers
            ]
            resources = render_handoff_l2(
                l1_resources=l1_resources,
                full_task_goal=bundle.task_goal or "",
                state=bundle.agent_state,
                revision_history=rev_hist,
                conversation_excerpts=bundle.conversation_sources,
            )
    return {
        "artifact_id": rec.artifact_id,
        "revision_epoch": rec.revision_epoch,
        "revision": rec.revision,
        "level": rec.level,
        "status": "ok",
        "resources": list(resources),
        "handoff_live": bundle.live.handoff_live.to_dict(),
    }


def _render_delivery(
    self: _m.HandoffKernelDomain,
    delivery_id: str,
    principal: Principal,
    *,
    selected_scope: Scope | None,
) -> dict[str, JsonValue]:
    rec = self._handoffs.read_delivery_outcome(
        delivery_id,
        owner_id=principal.owner_id,
        principal_id=principal.principal_id,
        selected_scope=selected_scope,
    )
    scope = Scope(rec.repo_id, rec.checkout_id)
    if not self._policy.allows(principal, scope, action="prepare_task"):
        raise BrainError(ErrorCode.NOT_FOUND, "not found")
    hdr = self._handoffs.resolve_task_scope(rec.task_id, principal_id=principal.principal_id, scope=scope)
    entries: tuple[DiscoverEntry, ...] = ()
    if rec.handoff_served_rev is not None and rec.handoff_served_epoch is not None:
        entries = (
            self._handoffs.render_delivery_handoff_l0(
                task_id=rec.task_id,
                owner_id=rec.owner_id,
                repo_id=rec.repo_id,
                checkout_id=rec.checkout_id,
                revision_epoch=rec.handoff_served_epoch,
                revision=rec.handoff_served_rev,
                served_digest=rec.handoff_served_digest,
                now=self._clock.now(),
                render_l0=render_handoff_l0,
            ),
        )
    continuity_items: list[JsonValue] = []
    for entry in entries:
        if entry.status == "redacted":
            continuity_items.append(
                {
                    "kind": "handoff",
                    "id": entry.artifact_id,
                    "status": "redacted",
                    "reason": entry.reason or "redacted",
                }
            )
        else:
            continuity_items.append(
                {
                    "kind": "handoff",
                    "id": entry.artifact_id,
                    "revision_epoch": entry.revision_epoch,
                    "revision": entry.revision,
                    "digest": entry.digest,
                    "summary": entry.summary,
                    "status": "ok",
                }
            )
    return {
        "workspace_id": rec.repo_id,
        "checkout_id": rec.checkout_id,
        "source_snapshot_id": rec.source_snapshot_id,
        "snapshot_status": rec.snapshot_status,
        "degraded_codes": list(rec.degraded_codes),
        "task_id": rec.task_id,
        "delivery_id": rec.delivery_id,
        "assignment_id": rec.assignment_id,
        "handoff_live": hdr.handoff_live.to_dict(),
        "skills": [],
        "lessons": [],
        "continuity": continuity_items,
        "context": [],
        "finishing_gates": [],
    }


def _render_episode(
    self: _m.HandoffKernelDomain,
    episode_id: str,
    principal: Principal,
    *,
    selected_scope: Scope | None,
) -> dict[str, JsonValue]:
    ep = self._handoffs.read_episode_outcome(
        episode_id,
        owner_id=principal.owner_id,
        principal_id=principal.principal_id,
        selected_scope=selected_scope,
    )
    scope = Scope(ep.repo_id, ep.checkout_id)
    if not self._policy.allows(principal, scope, action="submit_episode"):
        raise BrainError(ErrorCode.NOT_FOUND, "not found")
    if not ep.has_handoff_op:
        return {
            "episode_id": ep.episode_id,
            "evidence_ids": list(ep.evidence_ids),
        }
    is_holder, live_fence = self._handoffs.read_live_holder_status(
        ep.task_id,
        principal_id=principal.principal_id,
        session_ref=ep.session_ref,
        scope=scope,
    )
    if ep.committed_restore_epoch is not None and ep.committed_writer_generation is not None:
        ep_fence = HandoffFence(
            restore_epoch=ep.committed_restore_epoch,
            writer_generation=ep.committed_writer_generation,
        )
        writer_is_live_holder = is_holder and ep.principal_id == principal.principal_id and ep_fence == live_fence
    else:
        ep_fence = live_fence
        writer_is_live_holder = False
    return {
        "episode_id": ep.episode_id,
        "evidence_ids": list(ep.evidence_ids),
        "handoff_revision": ep.committed_handoff_revision,
        "handoff_status": ep.handoff_status or "not_stored_policy",
        "fence": ep_fence.to_dict(),
        "writer_status": "holder" if writer_is_live_holder else "not_holder",
    }
