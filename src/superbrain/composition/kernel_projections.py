"""Composition registration of the kernel projections: Task 3 (registry mirror, snapshots, task/field lineage) and
Task 5 (jobs, provider invocations), each reducer at the handler version its entry kinds declare.

Every runtime that serves kernel workspace tools opens its store with these handlers and kinds, so the
event-sourced tables stay in step with the ledger (a handler added later is filled by replay on open).
"""

from __future__ import annotations

from superbrain.storage.jobs import kernel_job_extensions
from superbrain.storage.kinds import KindRegistry
from superbrain.storage.ledger import ProjectionHandler
from superbrain.storage.workspaces import kernel_workspace_extensions


def kernel_store_extensions() -> tuple[tuple[ProjectionHandler, ...], KindRegistry]:
    """``(handlers, kinds)`` to pass to ``open_runtime``/``open_runtime_under_lease`` for a kernel store."""
    workspace_handlers, workspace_kinds = kernel_workspace_extensions()
    job_handlers, job_kinds = kernel_job_extensions()
    kinds = [registry.get(name) for registry in (workspace_kinds, job_kinds) for name in sorted(registry.kinds())]
    return (*workspace_handlers, *job_handlers), KindRegistry(kinds)
