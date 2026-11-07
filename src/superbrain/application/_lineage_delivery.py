"""Internal helpers for S1=A labeled delivery field aggregation, replay loading and task binding commit."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence, Set
from dataclasses import dataclass

from superbrain.application.privacy import admissible_field_path
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    DeliveryItem,
    FieldLineage,
    FilterPolicy,
    KernelRecord,
    LabeledDelivery,
    LineageRef,
    LineageSet,
    SafePayload,
    SelectorPath,
    SelectorReason,
    SnapshotStatus,
    TaskBinding,
    WorkspaceBinding,
    binding_lineage_ref,
    field_path_digest,
)
from superbrain.ports.kernel import KernelTx


def source_meta(ref: LineageRef) -> dict[str, JsonValue]:
    """Ledger metadata dictionary for one ``LineageRef``."""
    return {
        "owner_id": ref.owner_id,
        "repo_id": ref.repo_id,
        "source_kind": ref.source.kind,
        "source_id": ref.source.id,
        "source_revision": ref.source.revision,
        "source_digest": ref.source.digest,
    }


def append_field_lineage_by_digest(
    tx: KernelTx,
    task_id: str,
    digest: str,
    current: FieldLineage | None,
    sources: Iterable[LineageRef],
    *,
    unknown: bool,
) -> FieldLineage:
    """Append monotonic field sources and sticky unknown marker for ``digest``."""
    known = current.sources if current is not None else frozenset()
    checked_sources = frozenset(sources)
    for ref in sorted(checked_sources - known, key=repr):
        tx.append_record(
            KernelRecord(
                "lineage.field_source_added",
                {"task_id": task_id, "field_path_digest": digest, **source_meta(ref)},
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
    return FieldLineage(digest, known | checked_sources, unknown_source=unknown or already_unknown)


@dataclass(frozen=True)
class AggregatedField:
    """Canonical per-field aggregation across all ``DeliveryItem`` contributions sharing ``digest``."""

    path: tuple[str | int, ...]
    digest: str
    sources: LineageSet
    unknown: bool
    snapshot_dependent: bool
    persistable: bool


def aggregate_delivery_fields(
    items: Sequence[DeliveryItem], filter_policy: FilterPolicy
) -> tuple[AggregatedField, ...]:
    """Group ``items`` by canonical field identity (``field_path_digest(item.path)``) monotonically.

    - ``sources`` is the set union across all items for that field;
    - ``unknown`` is True iff any contribution has ``unknown_source=True`` or empty ``sources``;
    - ``snapshot_dependent`` is True iff any contribution is ``snapshot_dependent=True``;
    - ``persistable`` follows ``admissible_field_path`` (I2-T3-R01: stripped paths are never persisted).
    """
    grouped: dict[str, list[DeliveryItem]] = {}
    paths: dict[str, tuple[str | int, ...]] = {}
    for item in items:
        digest = field_path_digest(item.path)
        if digest not in grouped:
            grouped[digest] = [item]
            paths[digest] = item.path
        else:
            grouped[digest].append(item)
    result: list[AggregatedField] = []
    for digest in sorted(grouped):
        group = grouped[digest]
        path = paths[digest]
        sources: frozenset[LineageRef] = frozenset(ref for entry in group for ref in entry.sources)
        unknown = any(entry.unknown_source or not entry.sources for entry in group)
        snapshot_dependent = any(entry.snapshot_dependent for entry in group)
        persistable = admissible_field_path(path, filter_policy)
        result.append(
            AggregatedField(
                path=path,
                digest=digest,
                sources=sources,
                unknown=unknown,
                snapshot_dependent=snapshot_dependent,
                persistable=persistable,
            )
        )
    return tuple(result)


def partition_delivery_fields(
    fields: Sequence[AggregatedField],
    status: SnapshotStatus,
    *,
    prior_digests: Set[str] = frozenset(),
) -> tuple[tuple[AggregatedField, ...], tuple[AggregatedField, ...]]:
    """Split aggregated fields into ``(kept_fields, omitted_fields)`` for ``status`` (S1=A).

    Any new field with ``snapshot_dependent=True`` is omitted as a unit when ``status`` is not ``AVAILABLE``.
    A field whose ``digest`` is already in ``prior_digests`` cannot be omitted from the committed projection, so its
    monotonic restrictions stay in ``kept_fields`` rather than being dropped.
    """
    has_snapshot = status is SnapshotStatus.AVAILABLE
    kept = tuple(
        field for field in fields if has_snapshot or not field.snapshot_dependent or field.digest in prior_digests
    )
    omitted = tuple(
        field for field in fields if not has_snapshot and field.snapshot_dependent and field.digest not in prior_digests
    )
    return kept, omitted


def load_delivery(tx: KernelTx, task_id: str) -> LabeledDelivery | None:
    """Read a previously committed ``LabeledDelivery`` for ``task_id`` from ``tx`` projections."""
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


def replay_for(replay: LabeledDelivery, binding: WorkspaceBinding) -> LabeledDelivery:
    """Ensure a replayed ``task_id`` belongs to the resolved ``(owner_id, repo_id, checkout_id)`` binding."""
    bound = replay.binding
    if (bound.owner_id, bound.repo_id, bound.checkout_id) != (binding.owner_id, binding.repo_id, binding.checkout_id):
        raise BrainError(ErrorCode.NOT_FOUND, "not found")
    return replay


def append_task_bound(
    tx: KernelTx,
    binding: WorkspaceBinding,
    task_id: str,
    snapshot_id: str | None,
    status: SnapshotStatus,
    selector_path: SelectorPath,
    selector_reason: SelectorReason,
) -> TaskBinding:
    """Construct ``TaskBinding`` and append ``lineage.task_bound`` to ``tx``."""
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
    return task


def commit_delivery_atomic(
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
    filter_policy: FilterPolicy,
    *,
    union_fn: Callable[[LineageSet, Iterable[LineageRef]], LineageSet],
    record_task_fn: Callable[[KernelTx, str, LineageSet, bool], None],
    record_field_fn: Callable[[KernelTx, str, Sequence[str | int], LineageSet, bool, FilterPolicy], FieldLineage],
) -> LabeledDelivery:
    """Shared atomic delivery commit body without ``load_delivery(task_id)`` shortcut."""
    prior_lineage, prior_unknown = tx.read_task_lineage(task_id)
    prior_fields = tx.read_field_lineage(task_id)
    fields = aggregate_delivery_fields(items, filter_policy)
    kept_fields, omitted_fields = partition_delivery_fields(fields, status, prior_digests=prior_fields.keys())
    base_task_lineage = union_fn(
        prior_lineage,
        [
            binding_lineage_ref(binding),
            *served,
            *(ref for pf in prior_fields.values() for ref in pf.sources),
            *(ref for field in kept_fields for ref in field.sources),
        ],
    )
    base_task_unknown = (
        prior_unknown
        or any(pf.unknown_source or not pf.sources for pf in prior_fields.values())
        or any(field.unknown for field in kept_fields)
    )
    task = append_task_bound(tx, binding, task_id, snapshot_id, status, selector_path, selector_reason)
    record_task_fn(tx, task_id, base_task_lineage, base_task_unknown)
    for field in kept_fields:
        if field.persistable:
            record_field_fn(
                tx,
                task_id,
                field.path,
                union_fn(base_task_lineage, field.sources),
                field.unknown,
                filter_policy,
            )
    if prior_fields:
        kept_by_digest = {field.digest: field for field in kept_fields}
        current_fields = tx.read_field_lineage(task_id)
        for digest in sorted(prior_fields):
            pf = prior_fields[digest]
            matched = kept_by_digest.get(digest)
            target_sources = (
                union_fn(base_task_lineage, pf.sources)
                if matched is None
                else union_fn(base_task_lineage, union_fn(pf.sources, matched.sources))
            )
            target_unknown = pf.unknown_source or not pf.sources or (matched is not None and matched.unknown)
            append_field_lineage_by_digest(
                tx,
                task_id,
                digest,
                current_fields.get(digest, pf),
                target_sources,
                unknown=target_unknown,
            )
    committed_lineage, committed_unknown = tx.read_task_lineage(task_id)
    committed_fields = tx.read_field_lineage(task_id)
    omitted = tuple(
        sorted(field.digest for field in omitted_fields if field.persistable and field.digest not in committed_fields)
    )
    return LabeledDelivery(
        binding=task,
        task_lineage=committed_lineage,
        task_unknown=committed_unknown,
        items=tuple(committed_fields[digest] for digest in sorted(committed_fields)),
        omitted_items=omitted,
        safe_payload=safe,
        replayed=False,
    )
