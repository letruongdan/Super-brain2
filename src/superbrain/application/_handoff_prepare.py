"""Mutation preparation (submit_episode, work task, get_artifact) for ``handoff_service.HandoffKernelDomain``."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime

from superbrain.application import handoff_service as _m
from superbrain.application.dispatch import PreparedEffect
from superbrain.application.lineage import admit_source_snapshot, resolve_binding
from superbrain.application.privacy import filter_policy_for
from superbrain.application.send_attempts import extract_projected_read_acks, record_projected_read_acks
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.kernel import (
    Call,
    CallContext,
    ObjectRef,
    Scope,
    StoredResult,
    require_non_negative_int,
    require_opaque_id,
    require_positive_int,
)
from superbrain.domain.continuity.budget import validate_handoff_write_limits
from superbrain.domain.continuity.handoff_model import HandoffFence, parse_handoff_patch
from superbrain.domain.continuity.merge_rules import apply_handoff_patch
from superbrain.ports.kernel import KernelTx


def _prepare_submit_episode(
    self: _m.HandoffKernelDomain, call: Call, ctx: CallContext, *, now: datetime
) -> PreparedEffect:
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


def _prepare_work_task(self: _m.HandoffKernelDomain, call: Call, ctx: CallContext, *, now: datetime) -> PreparedEffect:
    args = call.arguments
    if args.get("mode", "work") != "work":
        raise BrainError(ErrorCode.INVALID_INPUT, "expected prepare_task work mode")
    binding = resolve_binding(
        ctx.principal,
        _m._selector_from_args(args),
        self._policy,
        selected_scope=call.selected_scope,
    )
    resume_spec = _m._parse_resume_ref(args.get("resume_ref"))
    seen_specs = _m._parse_seen_refs(args.get("seen_handoff_refs"))
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
        degraded_codes: tuple[str, ...] = _m._UNAVAILABLE_SECTION_CODES
    else:
        snapshot_status = "unavailable"
        degraded_codes = (_m._SNAPSHOT_UNAVAILABLE_CODE, *_m._UNAVAILABLE_SECTION_CODES)
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


def _prepare_get_artifact(
    self: _m.HandoffKernelDomain, call: Call, ctx: CallContext, *, now: datetime
) -> PreparedEffect:
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
