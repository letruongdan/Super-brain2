"""Workspace binding lookup, monotonic lineage, egress eligibility and the S1=A labeled delivery step (Task 3).

Authorization reads only ``KernelPolicyPort`` (the policy DB). The main-store registry mirror is never consulted
here, so neither a stale mirror after a policy rollback nor a forged mirror row can grant access or mint IDs.

Owner ruling S1=A: a missing or late snapshot only means the exact content version is unknown. Task lineage still
holds the verified binding repo and every served source, ``unknown_source`` marks only items whose source is
genuinely unknown, and ``snapshot_status`` alone never decides provider egress.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterable, Sequence

from superbrain.application.privacy import PrivacyFilter
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    COMMIT_RESERVE_NS,
    LOCAL_PHASE_BUDGET_NS,
    DeliveryItem,
    FieldLineage,
    FilterPolicy,
    KernelRecord,
    LabeledDelivery,
    LineagedField,
    LineageRef,
    LineageSet,
    ObjectRef,
    Principal,
    RepoFlags,
    SafePayload,
    Scope,
    SelectorPath,
    SelectorReason,
    SnapshotDescriptor,
    SnapshotObservation,
    SnapshotStatus,
    SourceSnapshot,
    TaskBinding,
    WorkspaceBinding,
    WorkspaceSelector,
    binding_lineage_ref,
    field_path_descriptor,
    field_path_digest,
    is_registrable_alias,
    require_opaque_id,
)
from superbrain.ports.kernel import (
    KernelPolicyPort,
    KernelStorePort,
    KernelTx,
    SnapshotObserver,
    SourceRestrictionPort,
)

_FIELD_HOLDER_NAMESPACE = uuid.UUID("6f1d3c52-8a4e-5b7f-9c2d-0e1a2b3c4d5e")
_REDACTED_VALUE: JsonValue = {"status": "redacted"}


def _not_found() -> BrainError:
    return BrainError(ErrorCode.NOT_FOUND, "not found")


def _invalid() -> BrainError:
    return BrainError(ErrorCode.INVALID_INPUT, "invalid input")


def _deadline() -> BrainError:
    return BrainError(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")


# --- lineage algebra ----------------------------------------------------------------------------------------------


def _lineage_items(values: Iterable[object]) -> list[LineageRef]:
    items: list[LineageRef] = []
    for ref in values:
        if not isinstance(ref, LineageRef):
            raise _invalid()
        items.append(ref)
    return items


def union_lineage(current: LineageSet, served: Iterable[LineageRef]) -> LineageSet:
    """Monotonic set union: the result always contains ``current``; nothing a caller passes can remove a source."""
    if not isinstance(current, frozenset):
        raise _invalid()
    return frozenset((*_lineage_items(current), *_lineage_items(served)))


def lineage_field(value: JsonValue, scope: LineageSet, *, unknown_source: bool = False) -> LineagedField:
    return LineagedField(value=value, sources=frozenset(_lineage_items(scope)), unknown_source=unknown_source)


def admit_client_sources(
    current: LineageSet,
    claims: Iterable[ObjectRef],
    resolve: Callable[[ObjectRef], LineageRef | None],
) -> tuple[LineageSet, bool]:
    """Add only client-claimed sources the server resolves; any unresolved claim makes the result unknown."""
    resolved: list[LineageRef] = []
    unknown = False
    for claim in claims:
        if not isinstance(claim, ObjectRef):
            raise _invalid()
        ref = resolve(claim)
        if ref is None:
            unknown = True
        elif not isinstance(ref, LineageRef) or ref.source != claim:
            raise _invalid()
        else:
            resolved.append(ref)
    return union_lineage(current, resolved), unknown


def redact_lineaged_field(field: LineagedField) -> LineagedField:
    """Withdraw a revoked/quarantined value while keeping every lineage restriction and the unknown flag."""
    if not isinstance(field, LineagedField):
        raise _invalid()
    return LineagedField(value=_REDACTED_VALUE, sources=field.sources, unknown_source=field.unknown_source)


def evaluate_egress_eligibility(
    subject: LineagedField | FieldLineage | LineageSet,
    policy: KernelPolicyPort,
    *,
    restrictions: SourceRestrictionPort,
) -> bool:
    """Provider egress eligibility from the current policy of every lineage source (spec 9/14.2).

    Denied when the source is unknown or unproven (no sources), or any source's repo is missing, owned by someone
    else, has ``provider_egress`` disabled, or is restricted (quarantined/tombstoned/missing/unresolvable).
    ``restrictions`` is required: there is no fail-open default. Snapshot status is not an input (S1=A).
    """
    if restrictions is None or not callable(getattr(restrictions, "is_restricted", None)):
        raise _invalid()
    if isinstance(subject, (LineagedField, FieldLineage)):
        sources, unknown = subject.sources, subject.unknown_source
    elif isinstance(subject, frozenset):
        sources, unknown = frozenset(_lineage_items(subject)), False
    else:
        raise _invalid()
    if unknown or not sources:
        return False
    snapshot = policy.snapshot()
    for ref in sorted(sources, key=repr):
        repo = snapshot.repo_policies.get(ref.repo_id)
        if repo is None or repo.owner_id != ref.owner_id or not RepoFlags.from_repo_policy(repo).provider_egress:
            return False
        if restrictions.is_restricted(ref):
            return False
    return True


# --- workspace binding lookup (policy authority only) --------------------------------------------------------------


def resolve_binding(
    principal: Principal,
    selector: WorkspaceSelector,
    policy: KernelPolicyPort,
    *,
    selected_scope: Scope | None = None,
) -> WorkspaceBinding:
    """Lookup-only binding resolution against the policy registry: no filesystem access, registration or grant.

    Unknown hint/IDs and scope mismatches are ``NOT_FOUND``; an ambiguous hint is ``REVISION_CONFLICT``; a checkout
    of the principal's owner registered on another machine is ``IDENTITY_MISMATCH``.
    """
    if not isinstance(principal, Principal) or not isinstance(selector, WorkspaceSelector):
        raise _invalid()
    if selected_scope is not None and not isinstance(selected_scope, Scope):
        raise _invalid()
    hint = selector.workspace_hint
    if hint is not None and not is_registrable_alias(hint):
        raise _not_found()  # valid wire hint grammar, but never a registrable alias
    snapshot = policy.snapshot()
    if hint is not None:
        matches = [
            binding
            for binding in snapshot.checkouts.values()
            if binding.owner_id == principal.owner_id
            and binding.machine_id == principal.machine_id
            and binding.alias == hint
        ]
        if not matches:
            raise _not_found()
        if len(matches) > 1:
            raise BrainError(ErrorCode.REVISION_CONFLICT, "revision conflict")
        binding = matches[0]
    else:
        found = snapshot.checkouts.get(str(selector.checkout_id))
        if found is None or found.owner_id != principal.owner_id or found.repo_id != selector.workspace_id:
            raise _not_found()
        if found.machine_id != principal.machine_id:
            raise BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch")
        binding = found
    if selected_scope is not None and (
        selected_scope.repo_id != binding.repo_id
        or (selected_scope.checkout_id is not None and selected_scope.checkout_id != binding.checkout_id)
    ):
        raise _not_found()
    if not policy.allows(principal, Scope(binding.repo_id, binding.checkout_id), action="prepare_task"):
        raise _not_found()
    return binding


def resolve_task_binding(
    store: KernelStorePort,
    policy: KernelPolicyPort,
    principal: Principal,
    task_id: str,
    *,
    workspace_id: str | None = None,
    checkout_id: str | None = None,
    selected_scope: Scope | None = None,
) -> TaskBinding:
    """The existing task binding for a follow-up mutation (``submit_episode``); optional IDs are checked only."""
    require_opaque_id(task_id)
    bound = store.transact(lambda tx: tx.read_task_binding(task_id))
    if bound is None or bound.owner_id != principal.owner_id:
        raise _not_found()
    if (workspace_id is not None and workspace_id != bound.repo_id) or (
        checkout_id is not None and checkout_id != bound.checkout_id
    ):
        raise _not_found()
    if selected_scope is not None and (
        selected_scope.repo_id != bound.repo_id
        or (selected_scope.checkout_id is not None and selected_scope.checkout_id != bound.checkout_id)
    ):
        raise _not_found()
    if not policy.allows(principal, Scope(bound.repo_id, bound.checkout_id), action="submit_episode"):
        raise _not_found()
    return bound


# --- event-sourced snapshot and lineage records --------------------------------------------------------------------


def register_snapshot(tx: KernelTx, binding: WorkspaceBinding, descriptor: SnapshotDescriptor) -> str:
    """Record ``descriptor`` for ``binding`` (descriptor blob held in the same transaction); its snapshot ID.

    The same content for the same checkout returns an existing snapshot ID only while that snapshot is still
    readable (not tombstoned, descriptor not quarantined, blob present); otherwise a new snapshot is recorded. Any
    content change (a different dirty digest included) yields a new one. A quarantined descriptor is refused.
    """
    if not isinstance(binding, WorkspaceBinding) or not isinstance(descriptor, SnapshotDescriptor):
        raise _invalid()
    if tx.blob_restricted(descriptor.descriptor_digest):
        raise BrainError(ErrorCode.QUARANTINED, "quarantined")
    for existing in tx.find_source_snapshots(binding.checkout_id, descriptor.descriptor_digest):
        if existing.owner_id == binding.owner_id and _snapshot_readable(tx, existing):
            return existing.snapshot_id
    snapshot_id = new_id()
    digest = tx.hold_blob(descriptor.content_bytes(), holder_id=snapshot_id)
    if digest != descriptor.descriptor_digest:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "snapshot descriptor digest mismatch")
    tx.append_record(
        KernelRecord(
            "snapshot.observed",
            {
                "snapshot_id": snapshot_id,
                "owner_id": binding.owner_id,
                "repo_id": binding.repo_id,
                "checkout_id": binding.checkout_id,
                "kind": descriptor.kind,
                "dirty": descriptor.dirty,
                "descriptor_digest": digest,
                "observed_at": descriptor.observed_at,
            },
            refs=(digest,),
        )
    )
    return snapshot_id


def _snapshot_readable(tx: KernelTx, snapshot: SourceSnapshot) -> bool:
    return (
        not tx.holder_tombstoned(snapshot.snapshot_id)
        and not tx.blob_restricted(snapshot.descriptor_digest)
        and tx.blob_present(snapshot.descriptor_digest)
    )


def admit_source_snapshot(tx: KernelTx, binding: WorkspaceBinding, snapshot_id: str) -> SourceSnapshot:
    """An explicit snapshot must belong to ``binding``'s checkout and be readable: never a silent fallback.

    Unknown, foreign, tombstoned or blob-missing -> ``NOT_FOUND``; quarantined descriptor -> ``QUARANTINED``.
    """
    snapshot = tx.read_source_snapshot(snapshot_id)
    if (
        snapshot is None
        or snapshot.owner_id != binding.owner_id
        or snapshot.repo_id != binding.repo_id
        or snapshot.checkout_id != binding.checkout_id
        or tx.holder_tombstoned(snapshot.snapshot_id)
    ):
        raise _not_found()
    if tx.blob_restricted(snapshot.descriptor_digest):
        raise BrainError(ErrorCode.QUARANTINED, "quarantined")
    if not tx.blob_present(snapshot.descriptor_digest):
        raise _not_found()
    return snapshot


def _source_meta(ref: LineageRef) -> dict[str, JsonValue]:
    return {
        "owner_id": ref.owner_id,
        "repo_id": ref.repo_id,
        "source_kind": ref.source.kind,
        "source_id": ref.source.id,
        "source_revision": ref.source.revision,
        "source_digest": ref.source.digest,
    }


def record_task_lineage(tx: KernelTx, task_id: str, sources: LineageSet, *, unknown: bool) -> None:
    """Append only new task sources and a first unknown marker: the recorded lineage can never shrink."""
    existing, existing_unknown = tx.read_task_lineage(task_id)
    for ref in sorted(frozenset(_lineage_items(sources)) - existing, key=repr):
        tx.append_record(KernelRecord("lineage.task_source_added", {"task_id": task_id, **_source_meta(ref)}))
    if unknown and not existing_unknown:
        tx.append_record(KernelRecord("lineage.task_unknown_marked", {"task_id": task_id}))


def record_field_lineage(
    tx: KernelTx, task_id: str, path: Sequence[str | int], sources: LineageSet, *, unknown: bool
) -> FieldLineage:
    """Record a field's sources (and sticky unknown marker) keyed by its path digest; the path stays in CAS."""
    digest = field_path_digest(path)
    current = tx.read_field_lineage(task_id).get(digest)
    if current is None:
        holder = str(uuid.uuid5(_FIELD_HOLDER_NAMESPACE, f"{task_id}\0{digest}"))
        tx.hold_blob(field_path_descriptor(path), holder_id=holder)
    known = current.sources if current is not None else frozenset()
    for ref in sorted(frozenset(_lineage_items(sources)) - known, key=repr):
        tx.append_record(
            KernelRecord(
                "lineage.field_source_added",
                {"task_id": task_id, "field_path_digest": digest, **_source_meta(ref)},
                refs=(digest,),
            )
        )
    already_unknown = current is not None and current.unknown_source
    if unknown and not already_unknown:
        tx.append_record(
            KernelRecord(
                "lineage.field_unknown_marked", {"task_id": task_id, "field_path_digest": digest}, refs=(digest,)
            )
        )
    return FieldLineage(digest, union_lineage(known, sources), unknown_source=unknown or already_unknown)


# --- S1=A labeled delivery ------------------------------------------------------------------------------------------


def local_deadline_ns(local_phase_start_ns: int, total_deadline_ns: int) -> int:
    """``min(local_phase_start + 100 ms, total_deadline - 200 ms)``: shared admission/filter/observer budget."""
    return min(local_phase_start_ns + LOCAL_PHASE_BUDGET_NS, total_deadline_ns - COMMIT_RESERVE_NS)


def observe_within_budget(
    observer: SnapshotObserver | None,
    binding: WorkspaceBinding,
    *,
    monotonic_ns: Callable[[], int],
    local_deadline: int,
) -> SnapshotObservation:
    """Optional observation inside the remaining local budget: absent -> ``UNAVAILABLE``, late -> ``DEADLINE``.

    A result that arrives after ``local_deadline`` is discarded, never recorded.
    """
    if observer is None:
        return SnapshotObservation(SnapshotStatus.UNAVAILABLE, None)
    if monotonic_ns() >= local_deadline:
        return SnapshotObservation(SnapshotStatus.DEADLINE, None)
    failed: SnapshotStatus | None = None
    observation: object = None
    try:
        observation = observer.observe(binding, local_deadline)
    except BrainError as err:
        failed = SnapshotStatus.DEADLINE if err.code is ErrorCode.DEADLINE_EXCEEDED else SnapshotStatus.UNAVAILABLE
    if failed is not None or not isinstance(observation, SnapshotObservation):
        return SnapshotObservation(failed or SnapshotStatus.UNAVAILABLE, None)
    if monotonic_ns() > local_deadline:
        return SnapshotObservation(SnapshotStatus.DEADLINE, None)
    return observation


def _load_delivery(tx: KernelTx, task_id: str) -> LabeledDelivery | None:
    bound = tx.read_task_binding(task_id)
    if bound is None:
        return None
    lineage, unknown = tx.read_task_lineage(task_id)
    fields = tx.read_field_lineage(task_id)
    return LabeledDelivery(
        binding=bound,
        task_lineage=lineage,
        task_unknown=unknown,
        items=tuple(fields[digest] for digest in sorted(fields)),
        replayed=True,
    )


def _replay_for(replay: LabeledDelivery, binding: WorkspaceBinding) -> LabeledDelivery:
    bound = replay.binding
    if (bound.owner_id, bound.repo_id, bound.checkout_id) != (binding.owner_id, binding.repo_id, binding.checkout_id):
        raise _not_found()
    return replay


def prepare_labeled_delivery(
    *,
    store: KernelStorePort,
    policy: KernelPolicyPort,
    principal: Principal,
    selector: WorkspaceSelector,
    task_id: str,
    payload: JsonValue,
    filter_policy: FilterPolicy,
    items: Sequence[DeliveryItem] = (),
    served_sources: Iterable[LineageRef] = (),
    observer: SnapshotObserver | None,
    monotonic_ns: Callable[[], int],
    local_phase_start_ns: int,
    total_deadline_ns: int,
    selected_scope: Scope | None = None,
    selector_path: SelectorPath = SelectorPath.RULES,
    selector_reason: SelectorReason = SelectorReason.PROVIDER_UNAVAILABLE,
) -> LabeledDelivery:
    """Admission -> durable replay lookup -> privacy filter -> optional observation -> one atomic commit.

    Auth/scope/privacy failures, an explicit invalid or quarantined snapshot and an exhausted total deadline are
    typed errors with nothing committed. A missing or late observer within budget commits a labeled delivery
    (``source_snapshot_id=None``, ``snapshot_status`` unavailable/deadline) without any ``snapshot.observed``.
    A replay returns the committed binding unchanged and never observes again.
    """
    require_opaque_id(task_id)
    checked_items = tuple(items)
    served = tuple(_lineage_items(served_sources))
    if not all(isinstance(item, DeliveryItem) for item in checked_items):
        raise _invalid()
    commit_cutoff = total_deadline_ns - COMMIT_RESERVE_NS
    if monotonic_ns() >= commit_cutoff:
        raise _deadline()
    local_deadline = local_deadline_ns(local_phase_start_ns, total_deadline_ns)
    binding = resolve_binding(principal, selector, policy, selected_scope=selected_scope)
    replay = store.transact(lambda tx: _load_delivery(tx, task_id))
    if replay is not None:
        return _replay_for(replay, binding)
    safe = PrivacyFilter(monotonic_ns).apply(payload, filter_policy, deadline_ns=local_deadline)
    explicit = selector.source_snapshot_id
    observation: SnapshotObservation | None = None
    if explicit is not None:
        store.transact(lambda tx: admit_source_snapshot(tx, binding, explicit))
    else:
        observation = observe_within_budget(observer, binding, monotonic_ns=monotonic_ns, local_deadline=local_deadline)
    if monotonic_ns() >= commit_cutoff:
        raise _deadline()

    def commit(tx: KernelTx) -> LabeledDelivery:
        raced = _load_delivery(tx, task_id)
        if raced is not None:
            return _replay_for(raced, binding)
        snapshot_id: str | None = None
        status = SnapshotStatus.UNAVAILABLE
        if explicit is not None:
            snapshot_id, status = admit_source_snapshot(tx, binding, explicit).snapshot_id, SnapshotStatus.AVAILABLE
        elif observation is not None and observation.descriptor is not None:
            if tx.blob_restricted(observation.descriptor.descriptor_digest):
                status = SnapshotStatus.UNAVAILABLE
            else:
                snapshot_id = register_snapshot(tx, binding, observation.descriptor)
                status = SnapshotStatus.AVAILABLE
        elif observation is not None:
            status = observation.status
        return _commit_delivery(
            tx, binding, task_id, checked_items, served, snapshot_id, status, safe, selector_path, selector_reason
        )

    return store.transact(commit)


def _commit_delivery(
    tx: KernelTx,
    binding: WorkspaceBinding,
    task_id: str,
    items: tuple[DeliveryItem, ...],
    served: tuple[LineageRef, ...],
    snapshot_id: str | None,
    status: SnapshotStatus,
    safe: SafePayload,
    selector_path: SelectorPath,
    selector_reason: SelectorReason,
) -> LabeledDelivery:
    has_snapshot = status is SnapshotStatus.AVAILABLE
    kept = tuple(item for item in items if has_snapshot or not item.snapshot_dependent)
    omitted = tuple(field_path_digest(item.path) for item in items if item not in kept)
    task_lineage = union_lineage(
        frozenset({binding_lineage_ref(binding)}), [*served, *(ref for item in kept for ref in item.sources)]
    )
    unknown_flags = [item.unknown_source or not item.sources for item in kept]
    task = TaskBinding(
        task_id=task_id,
        owner_id=binding.owner_id,
        repo_id=binding.repo_id,
        checkout_id=binding.checkout_id,
        delivery_id=new_id(),
        assignment_id=new_id(),
        source_snapshot_id=snapshot_id,
        snapshot_status=status,
        selector_path=selector_path,
        selector_reason=selector_reason,
    )
    tx.append_record(
        KernelRecord(
            "lineage.task_bound",
            {
                "task_id": task.task_id,
                "owner_id": task.owner_id,
                "repo_id": task.repo_id,
                "checkout_id": task.checkout_id,
                "delivery_id": task.delivery_id,
                "assignment_id": task.assignment_id,
                "source_snapshot_id": task.source_snapshot_id,
                "snapshot_status": task.snapshot_status.value,
                "selector_path": task.selector_path.value,
                "selector_reason": task.selector_reason.value,
            },
        )
    )
    record_task_lineage(tx, task_id, task_lineage, unknown=any(unknown_flags))
    recorded = tuple(
        record_field_lineage(tx, task_id, item.path, item.sources, unknown=flag)
        for item, flag in zip(kept, unknown_flags, strict=True)
    )
    return LabeledDelivery(
        binding=task,
        task_lineage=task_lineage,
        task_unknown=any(unknown_flags),
        items=recorded,
        omitted_items=omitted,
        safe_payload=safe,
        replayed=False,
    )
