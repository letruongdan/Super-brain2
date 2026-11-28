"""SP2-4 KernelToolDomain for ``prepare_task``, ``get_artifact``, and ``submit_episode``."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime

from superbrain.application import _handoff_prepare, _handoff_render
from superbrain.application.dispatch import KernelToolDomain, PreparedEffect
from superbrain.application.lineage import resolve_binding
from superbrain.application.privacy import PrivacyFilter
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    ArtifactSendSpec,
    Call,
    CallContext,
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
from superbrain.domain.continuity.handoff_model import HandoffFence
from superbrain.domain.continuity.rendering import (
    render_handoff_l0,
    select_discover_items,
)
from superbrain.ports.clock import Clock
from superbrain.ports.handoff import (
    DiscoverEntry,
    HandoffStorePort,
    ResumeRefSpec,
    SeenHandoffSpec,
)
from superbrain.ports.kernel import KernelPolicyPort, KernelSendAttemptPort

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
        # get_health(deep=true) belongs to the daemon doctor runner (SP1-I4), which also renders SP2-5 replays
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
        return _handoff_prepare._prepare_work_task(self, call, ctx, now=now)

    def _prepare_get_artifact(self, call: Call, ctx: CallContext, *, now: datetime) -> PreparedEffect:
        return _handoff_prepare._prepare_get_artifact(self, call, ctx, now=now)

    def _prepare_submit_episode(self, call: Call, ctx: CallContext, *, now: datetime) -> PreparedEffect:
        return _handoff_prepare._prepare_submit_episode(self, call, ctx, now=now)

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
        return _handoff_render._render_delivery(self, delivery_id, principal, selected_scope=selected_scope)

    def _render_artifact(
        self,
        result_id: str,
        principal: Principal,
        *,
        selected_scope: Scope | None,
    ) -> dict[str, JsonValue]:
        return _handoff_render._render_artifact(self, result_id, principal, selected_scope=selected_scope)

    def _render_episode(
        self,
        episode_id: str,
        principal: Principal,
        *,
        selected_scope: Scope | None,
    ) -> dict[str, JsonValue]:
        return _handoff_render._render_episode(self, episode_id, principal, selected_scope=selected_scope)

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
