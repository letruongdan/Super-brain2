"""Internal helpers for S1=A labeled delivery field aggregation, replay loading and task binding commit."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from superbrain.application.privacy import admissible_field_path
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.kernel import (
    DeliveryItem,
    FilterPolicy,
    KernelRecord,
    LabeledDelivery,
    LineageRef,
    LineageSet,
    SelectorPath,
    SelectorReason,
    SnapshotStatus,
    TaskBinding,
    WorkspaceBinding,
    field_path_digest,
)
from superbrain.ports.kernel import KernelTx


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
    fields: Sequence[AggregatedField], status: SnapshotStatus
) -> tuple[tuple[AggregatedField, ...], tuple[AggregatedField, ...]]:
    """Split aggregated fields into ``(kept_fields, omitted_fields)`` for ``status`` (S1=A).

    Any field with ``snapshot_dependent=True`` is omitted as a unit when ``status`` is not ``AVAILABLE``.
    """
    has_snapshot = status is SnapshotStatus.AVAILABLE
    kept = tuple(field for field in fields if has_snapshot or not field.snapshot_dependent)
    omitted = tuple(field for field in fields if not has_snapshot and field.snapshot_dependent)
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
