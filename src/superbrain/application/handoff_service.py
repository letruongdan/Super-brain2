"""SP2-4 KernelToolDomain for ``prepare_task``, ``get_artifact``, and ``submit_episode``."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime

from superbrain.application.dispatch import KernelToolDomain, PreparedEffect
from superbrain.application.lineage import admit_source_snapshot, resolve_binding
from superbrain.application.privacy import PrivacyFilter, filter_policy_for
from superbrain.application.send_attempts import extract_projected_read_acks, record_projected_read_acks
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    ArtifactSendSpec,
    Call,
    CallContext,
    ObjectRef,
    Principal,
    RepoFlags,
    ResourceDigest,
    Scope,
    StoredResult,
    WorkspaceSelector,
    require_non_negative_int,
    require_opaque_id,
    require_positive_int,
)
from superbrain.domain.continuity.budget import validate_handoff_write_limits
from superbrain.domain.continuity.handoff_model import HandoffFence, parse_handoff_patch
from superbrain.domain.continuity.merge_rules import apply_handoff_patch
from superbrain.domain.continuity.rendering import (
    render_handoff_l0,
    render_handoff_l1,
    render_handoff_l2,
    select_discover_items,
)
from superbrain.ports.clock import Clock
from superbrain.ports.handoff import (
    DiscoverEntry,
    HandoffStorePort,
    ResumeRefSpec,
    SeenHandoffSpec,
)
from superbrain.ports.kernel import KernelPolicyPort, KernelSendAttemptPort, KernelTx

_DEFAULT_BUDGET_TOKENS = 4000
_UNAVAILABLE_SECTION_CODES: tuple[str, ...] = (
    "skills_unavailable",
    "lessons_unavailable",
    "context_unavailable",
    "finishing_gates_unavailable",
)
_CONTINUITY_TRUNCATED_CODE = "continuity_truncated"
_SNAPSHOT_UNAVAILABLE_CODE = "snapshot_unavailable"


def _discover_entries_to_dicts(entries: Sequence[DiscoverEntry]) -> list[dict[str, JsonValue]]:
    items: list[dict[str, JsonValue]] = []
    for entry in entries:
        if entry.status == "redacted":
            items.append(
                {
                    "kind": "handoff",
                    "id": entry.artifact_id,
                    "status": "redacted",
                    "reason": entry.reason or "redacted",
                }
            )
        else:
            items.append(
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
    return items


def _selector_from_args(args: Mapping[str, JsonValue]) -> WorkspaceSelector:
    raw_hint = args.get("workspace_hint")
    raw_ws = args.get("workspace_id")
    raw_chk = args.get("checkout_id")
    raw_snap = args.get("source_snapshot_id")
    return WorkspaceSelector(
        workspace_hint=raw_hint if isinstance(raw_hint, str) else None,
        workspace_id=raw_ws if isinstance(raw_ws, str) else None,
        checkout_id=raw_chk if isinstance(raw_chk, str) else None,
        source_snapshot_id=raw_snap if isinstance(raw_snap, str) else None,
    )


def _parse_resume_ref(raw: JsonValue | None) -> ResumeRefSpec | None:
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid resume_ref")
    raw_fence = raw.get("fence")
    if not isinstance(raw_fence, Mapping):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid resume_ref fence")
    fence = HandoffFence(
        restore_epoch=require_non_negative_int(raw_fence.get("restore_epoch")),
        writer_generation=require_non_negative_int(raw_fence.get("writer_generation")),
    )
    raw_receipt = raw.get("served_receipt_id")
    served_receipt_id = (
        require_opaque_id(raw_receipt, label="served_receipt_id") if raw_receipt is not None else None
    )
    return ResumeRefSpec(
        artifact_id=require_opaque_id(raw.get("artifact_id"), label="artifact_id"),
        revision=require_positive_int(raw.get("revision")),
        handoff_revision=require_non_negative_int(raw.get("handoff_revision")),
        fence=fence,
        served_receipt_id=served_receipt_id,
    )


def _parse_seen_refs(raw: JsonValue | None) -> tuple[SeenHandoffSpec, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid seen_handoff_refs")
    out: list[SeenHandoffSpec] = []
    for item in raw:
        if not isinstance(item, Mapping):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid seen_handoff_refs item")
        dig = item.get("digest")
        if not isinstance(dig, str) or not dig:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid seen_handoff_refs digest")
        out.append(
            SeenHandoffSpec(
                artifact_id=require_opaque_id(item.get("artifact_id"), label="artifact_id"),
                revision_epoch=require_non_negative_int(item.get("revision_epoch")),
                revision=require_positive_int(item.get("revision")),
                digest=dig,
            )
        )
    return tuple(out)


class HandoffKernelDomain(KernelToolDomain):
    """Production ``KernelToolDomain`` serving ``prepare_task``, ``get_artifact``, and ``submit_episode``."""

    def __init__(
        self,
        *,
        handoffs: HandoffStorePort,
        policy: KernelPolicyPort,
        clock: Clock,
        send_attempts: KernelSendAttemptPort | None = None,
        privacy_filter: PrivacyFilter | None = None,
    ) -> None:
        self._handoffs = handoffs
        self._policy = policy
        self._clock = clock
        self._send_attempts = send_attempts
        self._privacy = privacy_filter if privacy_filter is not None else PrivacyFilter()

    def rebind(
        self,
        *,
        handoffs: HandoffStorePort,
        policy: KernelPolicyPort,
        send_attempts: KernelSendAttemptPort | None = None,
    ) -> None:
        """Point subsequent operations at restored store/policy adapters."""
        self._handoffs = handoffs
        self._policy = policy
        self._send_attempts = send_attempts

    def supports_tool(self, tool: str, *, deep: bool = False) -> bool:
        return tool in {"prepare_task", "get_artifact", "submit_episode"} and not deep

    def _repo_flags(self, repo_id: str) -> RepoFlags:
        snap = self._policy.snapshot()
        repo_pol = snap.repo_policies.get(repo_id)
        if repo_pol is None:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        return RepoFlags.from_repo_policy(repo_pol)

    def execute_readonly(self, call: Call, ctx: CallContext) -> dict[str, JsonValue]:
        if call.tool != "prepare_task" or call.arguments.get("mode", "work") != "discover":
            raise BrainError(ErrorCode.INVALID_INPUT, "unsupported readonly tool")
        binding = resolve_binding(
            ctx.principal,
            _selector_from_args(call.arguments),
            self._policy,
            selected_scope=call.selected_scope,
        )
        raw_tid = call.arguments.get("task_id")
        task_id = require_opaque_id(raw_tid, label="task_id") if raw_tid is not None else None
        raw_budget = call.arguments.get("context_budget_tokens", _DEFAULT_BUDGET_TOKENS)
        budget_tokens = raw_budget if type(raw_budget) is int and raw_budget >= 1 else _DEFAULT_BUDGET_TOKENS
        entries = self._handoffs.list_discover(
            principal_id=ctx.principal.principal_id,
            owner_id=ctx.principal.owner_id,
            repo_id=binding.repo_id,
            checkout_id=binding.checkout_id,
            task_id=task_id,
            now=self._clock.now(),
            render_l0=render_handoff_l0,
        )
        selected, truncated = select_discover_items(
            _discover_entries_to_dicts(entries),
            budget_tokens=budget_tokens,
        )
        degraded: list[JsonValue] = list(_UNAVAILABLE_SECTION_CODES)
        if truncated:
            degraded.append(_CONTINUITY_TRUNCATED_CODE)
        return {
            "workspace_id": binding.repo_id,
            "checkout_id": binding.checkout_id,
            "continuity": list(selected[:3]),
            "degraded_codes": degraded,
        }

    def prepare_mutation(self, call: Call, ctx: CallContext, *, now: datetime) -> PreparedEffect:
        if call.tool == "prepare_task":
            return self._prepare_work_task(call, ctx, now=now)
        if call.tool == "get_artifact":
            return self._prepare_get_artifact(call, ctx, now=now)
        if call.tool == "submit_episode":
            return self._prepare_submit_episode(call, ctx, now=now)
        raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")

    def _prepare_work_task(self, call: Call, ctx: CallContext, *, now: datetime) -> PreparedEffect:
        args = call.arguments
        if args.get("mode", "work") != "work":
            raise BrainError(ErrorCode.INVALID_INPUT, "expected prepare_task work mode")
        binding = resolve_binding(
            ctx.principal,
            _selector_from_args(args),
            self._policy,
            selected_scope=call.selected_scope,
        )
        resume_spec = _parse_resume_ref(args.get("resume_ref"))
        seen_specs = _parse_seen_refs(args.get("seen_handoff_refs"))
        raw_tid = args.get("task_id")
        if raw_tid is not None:
            task_id = require_opaque_id(raw_tid, label="task_id")
            existing = self._handoffs.try_read_task_header_scoped(
                task_id,
                owner_id=ctx.principal.owner_id,
                selected_scope=Scope(binding.repo_id, binding.checkout_id),
            )
            if existing is None:
                if resume_spec is not None:
                    raise BrainError(ErrorCode.NOT_FOUND, "not found")
                create_task = True
            else:
                create_task = False
        else:
            if resume_spec is not None:
                raise BrainError(ErrorCode.INVALID_INPUT, "resume_ref requires task_id")
            task_id = new_id()
            create_task = True

        description = args.get("description")
        if not isinstance(description, str) or not description:
            raise BrainError(ErrorCode.INVALID_INPUT, "description required")
        flags = self._repo_flags(binding.repo_id)
        fpolicy = filter_policy_for(flags)
        filtered_payload = self._privacy.apply({"description": description}, fpolicy).value
        goal_bytes: bytes | None = None
        if create_task and isinstance(filtered_payload, Mapping):
            filtered_desc = filtered_payload.get("description")
            if isinstance(filtered_desc, str):
                goal_bytes = filtered_desc.encode("utf-8")
        raw_snap_id = args.get("source_snapshot_id")
        source_snapshot_id = (
            require_opaque_id(raw_snap_id, label="source_snapshot_id") if raw_snap_id is not None else None
        )
        if source_snapshot_id is not None:
            snapshot_status = "available"
            degraded_codes: tuple[str, ...] = _UNAVAILABLE_SECTION_CODES
        else:
            snapshot_status = "unavailable"
            degraded_codes = (_SNAPSHOT_UNAVAILABLE_CODE, *_UNAVAILABLE_SECTION_CODES)
        delivery_id = new_id()
        blobs = (goal_bytes,) if goal_bytes is not None else ()

        def _apply(tx: KernelTx) -> StoredResult:
            if source_snapshot_id is not None:
                admit_source_snapshot(tx, binding, source_snapshot_id)
            work_res = self._handoffs.tx_record_work_delivery(
                tx,
                delivery_id=delivery_id,
                task_id=task_id,
                owner_id=ctx.principal.owner_id,
                repo_id=binding.repo_id,
                checkout_id=binding.checkout_id,
                principal_id=ctx.principal.principal_id,
                session_ref=None,
                description_bytes=goal_bytes,
                create_task=create_task,
                task_id_provided=raw_tid is not None,
                source_snapshot_id=source_snapshot_id,
                snapshot_status=snapshot_status,
                assignment_id=None,
                resume_ref=resume_spec,
                seen_handoff_refs=seen_specs,
                exposure_evidence="none",
                degraded_codes=degraded_codes,
                now=now,
            )
            return StoredResult(
                result_id=delivery_id,
                assignment_id=None,
                refs=(
                    ObjectRef(
                        kind="delivery_result",
                        id=delivery_id,
                        revision=max(1, work_res.handoff_live.revision or 1),
                        digest=work_res.goal_digest,
                    ),
                ),
            )

        return PreparedEffect(blobs=blobs, apply=_apply)

    def _prepare_get_artifact(self, call: Call, ctx: CallContext, *, now: datetime) -> PreparedEffect:
        args = call.arguments
        workspace_id = require_opaque_id(args.get("workspace_id"), label="workspace_id")
        task_id = require_opaque_id(args.get("task_id"), label="task_id")
        artifact_id = require_opaque_id(args.get("artifact_id"), label="artifact_id")
        revision = require_positive_int(args.get("revision"))
        raw_level = args.get("level")
        if raw_level not in {"L0", "L1", "L2"}:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid artifact level")
        level = str(raw_level)
        raw_epoch = args.get("revision_epoch")
        req_epoch = require_non_negative_int(raw_epoch) if raw_epoch is not None else None

        sel_chk = call.selected_scope.checkout_id if call.selected_scope is not None else None
        hdr = self._handoffs.read_task_header_scoped(
            task_id,
            owner_id=ctx.principal.owner_id,
            selected_scope=Scope(workspace_id, sel_chk),
        )
        scope = Scope(hdr.repo_id, hdr.checkout_id)
        if not self._policy.allows(ctx.principal, scope, action="get_artifact"):
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        if hdr.artifact_id != artifact_id:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        resolved_epoch = self._handoffs.resolve_artifact_revision_epoch(
            task_id=task_id,
            artifact_id=artifact_id,
            revision=revision,
            revision_epoch=req_epoch,
            principal_id=ctx.principal.principal_id,
            scope=scope,
        )
        result_id = new_id()

        def _apply(tx: KernelTx) -> StoredResult:
            self._handoffs.tx_record_artifact_get(
                tx,
                result_id=result_id,
                task_id=task_id,
                artifact_id=artifact_id,
                revision_epoch=resolved_epoch,
                revision=revision,
                level=level,
                owner_id=ctx.principal.owner_id,
                repo_id=hdr.repo_id,
                checkout_id=hdr.checkout_id,
                principal_id=ctx.principal.principal_id,
                now=now,
            )
            return StoredResult(
                result_id=result_id,
                assignment_id=None,
                refs=(
                    ObjectRef(
                        kind="artifact_result",
                        id=result_id,
                        revision=revision,
                        digest=hdr.agent_ref or hdr.goal_ref or digest_bytes(result_id.encode("utf-8")),
                    ),
                ),
            )

        return PreparedEffect(blobs=(), apply=_apply)

    def _prepare_submit_episode(self, call: Call, ctx: CallContext, *, now: datetime) -> PreparedEffect:
        args = call.arguments
        task_id = require_opaque_id(args.get("task_id"), label="task_id")
        raw_session_id = args.get("session_id")
        if not isinstance(raw_session_id, str) or not raw_session_id:
            raise BrainError(ErrorCode.INVALID_INPUT, "session_id required")

        ws_id = args.get("workspace_id")
        chk_id = args.get("checkout_id")
        scope_hint: Scope | None
        if isinstance(ws_id, str):
            sel_chk = (
                str(chk_id)
                if isinstance(chk_id, str)
                else (call.selected_scope.checkout_id if call.selected_scope is not None else None)
            )
            scope_hint = Scope(ws_id, sel_chk)
        else:
            scope_hint = call.selected_scope

        hdr = self._handoffs.read_task_header_scoped(
            task_id,
            owner_id=ctx.principal.owner_id,
            selected_scope=scope_hint,
        )
        scope = Scope(hdr.repo_id, hdr.checkout_id)
        if not self._policy.allows(ctx.principal, scope, action="submit_episode"):
            raise BrainError(ErrorCode.NOT_FOUND, "not found")

        flags = self._repo_flags(hdr.repo_id)
        fpolicy = filter_policy_for(flags)
        session_ref = self._handoffs.bind_session_for_episode(
            principal_id=ctx.principal.principal_id,
            repo_id=hdr.repo_id,
            checkout_id=hdr.checkout_id,
            harness_id=ctx.principal.harness_id,
            raw_session_id=raw_session_id,
            now=now,
        )

        raw_evidence = args.get("evidence", [])
        if not isinstance(raw_evidence, list):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid evidence")

        evidence_items: list[tuple[str, bytes]] = []
        if flags.manual_submission:
            for item in raw_evidence:
                filtered_item = self._privacy.apply(item, fpolicy).value
                evidence_items.append((new_id(), canonical_json(filtered_item)))

        raw_acks = args.get("read_acks")
        projected_acks = (
            extract_projected_read_acks({"read_acks": raw_acks})
            if flags.manual_submission and raw_acks is not None
            else ()
        )

        raw_patch = args.get("handoff")
        raw_base_rev = args.get("base_revision")
        raw_fence = args.get("fence")
        raw_takeover = args.get("takeover")
        has_patch = raw_patch is not None
        takeover = raw_takeover is not None
        takeover_ack_active = (
            bool(raw_takeover.get("acknowledge_active", False)) if isinstance(raw_takeover, Mapping) else False
        )
        base_revision = require_non_negative_int(raw_base_rev) if raw_base_rev is not None else None
        expected_fence: HandoffFence | None = None
        if raw_fence is not None:
            if not isinstance(raw_fence, Mapping):
                raise BrainError(ErrorCode.INVALID_INPUT, "invalid fence")
            expected_fence = HandoffFence(
                restore_epoch=require_non_negative_int(raw_fence.get("restore_epoch")),
                writer_generation=require_non_negative_int(raw_fence.get("writer_generation")),
            )

        agent_bytes: bytes | None = None
        next_task_state: str | None = None
        if flags.manual_submission and has_patch:
            filtered_patch_val = self._privacy.apply(raw_patch, fpolicy).value
            if not isinstance(filtered_patch_val, Mapping):
                raise BrainError(ErrorCode.INVALID_INPUT, "invalid handoff patch")
            parsed_patch = parse_handoff_patch(dict(filtered_patch_val))
            prev_state = self._handoffs.load_agent_state_scoped(
                task_id=task_id,
                principal_id=ctx.principal.principal_id,
                scope=scope,
                now=now,
            )
            next_state = apply_handoff_patch(prev_state, parsed_patch)
            validate_handoff_write_limits(prev_state, next_state, filtered_patch_val)
            agent_bytes = canonical_json(next_state.to_dict())
            next_task_state = next_state.task_state

        episode_id = new_id()
        blobs_list: list[bytes] = [b for _, b in evidence_items]
        if agent_bytes is not None:
            blobs_list.append(agent_bytes)

        def _apply(tx: KernelTx) -> StoredResult:
            if projected_acks:
                record_projected_read_acks(
                    tx,
                    policy=self._policy,
                    principal=ctx.principal,
                    effective_scope=scope,
                    expected_task_id=task_id,
                    acks=projected_acks,
                    action="submit_episode",
                )
            mut_res = self._handoffs.tx_commit_handoff_mutation(
                tx,
                task_id=task_id,
                owner_id=ctx.principal.owner_id,
                repo_id=hdr.repo_id,
                checkout_id=hdr.checkout_id,
                principal_id=ctx.principal.principal_id,
                harness_id=ctx.principal.harness_id,
                session_ref=session_ref,
                episode_id=episode_id,
                base_revision=base_revision,
                expected_fence=expected_fence,
                takeover=takeover,
                takeover_acknowledge_active=takeover_ack_active,
                has_patch=has_patch,
                new_agent_bytes=agent_bytes,
                next_task_state=next_task_state,
                evidence_items=evidence_items,
                manual_submission_enabled=flags.manual_submission,
                now=now,
            )
            return StoredResult(
                result_id=episode_id,
                assignment_id=None,
                refs=(
                    ObjectRef(
                        kind="episode_result",
                        id=episode_id,
                        revision=max(1, mut_res.revision or 1),
                        digest=digest_bytes(episode_id.encode("utf-8")),
                    ),
                ),
            )

        return PreparedEffect(blobs=tuple(blobs_list), apply=_apply)

    def render_stored(
        self,
        result: StoredResult,
        principal: Principal,
        *,
        selected_scope: Scope | None,
    ) -> dict[str, JsonValue]:
        if not result.refs:
            raise BrainError(ErrorCode.INVALID_INPUT, "stored result missing refs")
        kind = result.refs[0].kind
        if kind == "delivery_result":
            return self._render_delivery(result.result_id, principal, selected_scope=selected_scope)
        if kind == "artifact_result":
            return self._render_artifact(result.result_id, principal, selected_scope=selected_scope)
        if kind == "episode_result":
            return self._render_episode(result.result_id, principal, selected_scope=selected_scope)
        raise BrainError(ErrorCode.INVALID_INPUT, f"unsupported stored ref kind: {kind}")

    def _render_delivery(
        self,
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

    def _render_artifact(
        self,
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

    def _render_episode(
        self,
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

    def describe_artifact_send(
        self,
        result: StoredResult,
        rendered: Mapping[str, JsonValue],
        principal: Principal,
        *,
        selected_scope: Scope | None,
    ) -> ArtifactSendSpec | None:
        if not result.refs or result.refs[0].kind != "artifact_result":
            return None
        if rendered.get("status") != "ok":
            return None
        rec = self._handoffs.read_artifact_get(
            result.result_id,
            owner_id=principal.owner_id,
            principal_id=principal.principal_id,
            selected_scope=selected_scope,
        )
        raw_resources = rendered.get("resources")
        if not isinstance(raw_resources, list) or not raw_resources:
            return None
        digests: list[ResourceDigest] = []
        for item in raw_resources:
            if not isinstance(item, Mapping):
                continue
            rname = item.get("name")
            rdig = item.get("digest")
            if isinstance(rname, str) and isinstance(rdig, str):
                digests.append(ResourceDigest(name=rname, digest=rdig))
        if not digests:
            return None
        return ArtifactSendSpec(
            logical_result_id=result.result_id,
            principal_id=principal.principal_id,
            task_id=rec.task_id,
            artifact_id=rec.artifact_id,
            revision=rec.revision,
            level=rec.level,
            revision_epoch=rec.revision_epoch,
            resource_digests=tuple(digests),
        )


__all__ = ["HandoffKernelDomain"]
