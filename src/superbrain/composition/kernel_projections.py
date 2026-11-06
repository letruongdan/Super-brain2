"""Composition registration of the Task 3 kernel projections (registry mirror, snapshots, task/field lineage).

Every runtime that serves kernel workspace tools opens its store with these handlers and kinds, so the
event-sourced tables stay in step with the ledger (a handler added later is filled by replay on open).
"""

from __future__ import annotations

from superbrain.storage.kinds import KindRegistry
from superbrain.storage.ledger import ProjectionHandler
from superbrain.storage.workspaces import kernel_workspace_extensions


def kernel_store_extensions() -> tuple[tuple[ProjectionHandler, ...], KindRegistry]:
    """``(handlers, kinds)`` to pass to ``open_runtime``/``open_runtime_under_lease`` for a kernel store."""
    return kernel_workspace_extensions()
