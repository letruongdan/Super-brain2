"""Durable fixture domain behind the real daemon composition (SP1 increment 2, Task 8.2).

``FixtureKernelDomain`` writes typed ``fixture.*`` ledger entries and reads ``p_fixture_domain_*`` projections, so the
daemon's store must be opened with ``fixture_store_extensions()`` instead of ``kernel_store_extensions()``.
``use_fixture_store_extensions`` swaps that one lookup in ``daemon_entry`` (a test-process patch, the product has no
flag for it). ``FixtureDomainProxy`` is the ``KernelToolDomain`` handed to ``serve_config_path`` /
``create_daemon_owner_loop``; ``fixture_hooks`` binds it on the owner thread in ``DaemonTestHooks.before_job_recover``
to a ``FixtureKernelDomain(rt.store, rt.policy, ...)``, seeding the scenario once per data root.

Importable from the installed wheel venv (``inc2_t8_child.py serve-fixture``), which has no dev dependencies.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from typing import Literal

import superbrain.composition.daemon_entry as daemon_entry
from superbrain.application.dispatch import PreparedEffect
from superbrain.composition._daemon_session import DaemonTestHooks
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    ArtifactSendSpec,
    Call,
    CallContext,
    ObjectRef,
    Principal,
    Scope,
    SnapshotDescriptor,
    SnapshotObservation,
    SnapshotStatus,
    StoredResult,
    WorkspaceBinding,
)
from superbrain.ports.kernel import KernelPolicyPort, SnapshotObserver
from superbrain.storage.idempotency import KernelBlobStager
from superbrain.storage.runtime import Runtime
from tests.support.inc2_kernel_domain import (
    FixtureDeliveryRefSpec,
    FixtureKernelDomain,
    FixtureResourceSpec,
    fixture_store_extensions,
)

ART_ALLOWED = "art-t8-allowed"
"""Delivered in ``skills`` and as the snapshot-dependent ``context`` / ``finishing_gates`` items; stays readable."""
ART_REDACTABLE = "art-t8-redactable"
"""Delivered in ``skills``; tests quarantine its digest to tighten policy on that one ref."""
ART_UNKNOWN = "art-t8-unknown-source"
"""Delivered in ``lessons`` with an unknown source."""
L1_NAME = "L1.md"
L1_CONTENT = b"# T8 skill L1\n"
REF_NAME = "ref.md"
REF_CONTENT = b"# T8 skill reference\n"
SCENARIO_ALIAS = "ws-a"


def use_fixture_store_extensions() -> None:
    """Open the daemon's store with the fixture projections and kinds (this process only)."""
    setattr(daemon_entry, "kernel_store_extensions", fixture_store_extensions)  # noqa: B010 - module global swap


class FixtureDomainProxy:
    """``KernelToolDomain`` forwarding every method and the ``store``/``policy``/``monotonic_ns`` attributes to the
    ``FixtureKernelDomain`` bound on the owner thread."""

    def __init__(self) -> None:
        self._inner: FixtureKernelDomain | None = None

    def bind(self, inner: FixtureKernelDomain) -> None:
        self._inner = inner

    @property
    def inner(self) -> FixtureKernelDomain:
        if self._inner is None:
            raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")
        return self._inner

    @property
    def store(self) -> object:
        return self.inner.store

    @property
    def policy(self) -> object:
        return self.inner.policy

    @property
    def monotonic_ns(self) -> Callable[[], int]:
        return self.inner.monotonic_ns

    def supports_tool(self, tool: str, *, deep: bool = False) -> bool:
        return self.inner.supports_tool(tool, deep=deep)

    def prepare_mutation(self, call: Call, ctx: CallContext, *, now: datetime) -> PreparedEffect:
        return self.inner.prepare_mutation(call, ctx, now=now)

    def execute_readonly(self, call: Call, ctx: CallContext) -> dict[str, JsonValue]:
        return self.inner.execute_readonly(call, ctx)

    def render_stored(
        self, result: StoredResult, principal: Principal, *, selected_scope: Scope | None
    ) -> dict[str, JsonValue]:
        return self.inner.render_stored(result, principal, selected_scope=selected_scope)

    def describe_artifact_send(
        self,
        result: StoredResult,
        rendered: Mapping[str, JsonValue],
        principal: Principal,
        *,
        selected_scope: Scope | None,
    ) -> ArtifactSendSpec | None:
        return self.inner.describe_artifact_send(result, rendered, principal, selected_scope=selected_scope)


DESCRIPTOR = SnapshotDescriptor(
    kind="git",
    tree_or_head_digest="sha256:" + "7" * 64,
    dirty=False,
    dirty_digest=None,
    observed_at="2026-11-01T00:00:00.000000Z",
)


class GatedObserver:
    """Test-only ``SnapshotObserver`` (``source="fixture"``) answering ``DESCRIPTOR`` (``mode="available"``) or, with
    ``mode="hold"``, blocking until ``release`` is set so the test can move the fake monotonic clock past the local
    budget meanwhile."""

    source: Literal["fixture"] = "fixture"

    def __init__(self) -> None:
        self.mode: Literal["available", "hold"] = "available"
        self.calls = 0
        self.entered = threading.Event()
        self.release = threading.Event()

    def observe(self, binding: WorkspaceBinding, deadline_ns: int) -> SnapshotObservation:
        _ = (binding, deadline_ns)
        self.calls += 1
        if self.mode == "hold":
            self.entered.set()
            if not self.release.wait(timeout=10.0):
                raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")
        return SnapshotObservation(SnapshotStatus.AVAILABLE, DESCRIPTOR)


def scenario_binding(policy_view: KernelPolicyPort) -> WorkspaceBinding:
    snap = policy_view.snapshot()
    found = [b for b in snap.checkouts.values() if b.alias == SCENARIO_ALIAS]
    if len(found) != 1:
        raise BrainError(ErrorCode.NOT_FOUND, "not found")
    return found[0]


def scenario_refs(domain: FixtureKernelDomain) -> dict[str, ObjectRef]:
    with domain.store.transaction() as txn:
        rows = txn.db.execute(
            "SELECT artifact_id, revision, kind, artifact_digest FROM p_fixture_domain_artifacts"
        ).fetchall()
    return {str(a): ObjectRef(kind=str(k), id=str(a), revision=int(r), digest=str(d)) for a, r, k, d in rows}


def seed_scenario(domain: FixtureKernelDomain, rt: Runtime) -> None:
    """Three artifacts of the ``ws-a`` workspace, seeded once (a restart finds them in the projection)."""
    if scenario_refs(domain):
        return
    binding = scenario_binding(rt.policy)
    stage = KernelBlobStager(rt.store)
    for artifact_id in (ART_ALLOWED, ART_REDACTABLE, ART_UNKNOWN):
        extra = (
            (FixtureResourceSpec(name=REF_NAME, content=REF_CONTENT + artifact_id.encode()),)
            if artifact_id == ART_ALLOWED
            else ()
        )
        domain.seed_artifact(
            stage,
            artifact_id=artifact_id,
            revision=1,
            owner_id=binding.owner_id,
            repo_id=binding.repo_id,
            checkout_id=binding.checkout_id,
            resources=(
                FixtureResourceSpec(name=L1_NAME, content=L1_CONTENT + artifact_id.encode()),
                *extra,
            ),
        )


def scenario_plan(domain: FixtureKernelDomain) -> Callable[[WorkspaceBinding, str], Sequence[FixtureDeliveryRefSpec]]:
    """Every ``prepare_task`` delivers: two known-source skills, snapshot-dependent ``context`` and ``finishing_gates``
    items (known source), and one unknown-source lesson."""

    def plan(binding: WorkspaceBinding, task_id: str) -> Sequence[FixtureDeliveryRefSpec]:
        _ = task_id
        refs = scenario_refs(domain)
        return (
            FixtureDeliveryRefSpec(
                slot="skills", ref=refs[ART_ALLOWED], owner_id=binding.owner_id, repo_id=binding.repo_id
            ),
            FixtureDeliveryRefSpec(
                slot="skills", ref=refs[ART_REDACTABLE], owner_id=binding.owner_id, repo_id=binding.repo_id
            ),
            FixtureDeliveryRefSpec(
                slot="context",
                ref=refs[ART_ALLOWED],
                owner_id=binding.owner_id,
                repo_id=binding.repo_id,
                snapshot_dependent=True,
            ),
            FixtureDeliveryRefSpec(
                slot="finishing_gates",
                ref=refs[ART_ALLOWED],
                owner_id=binding.owner_id,
                repo_id=binding.repo_id,
                snapshot_dependent=True,
            ),
            FixtureDeliveryRefSpec(
                slot="lessons",
                ref=refs[ART_UNKNOWN],
                owner_id=binding.owner_id,
                repo_id=binding.repo_id,
                unknown_source=True,
            ),
        )

    return plan


def fixture_hooks(
    proxy: FixtureDomainProxy,
    *,
    monotonic_ns: Callable[[], int],
    observer: SnapshotObserver | None = None,
    base: DaemonTestHooks | None = None,
) -> DaemonTestHooks:
    """``base`` plus ``before_job_recover`` binding ``proxy`` to a seeded ``FixtureKernelDomain`` (owner thread)."""

    def before_job_recover(rt: Runtime) -> None:
        domain = FixtureKernelDomain(
            store=rt.store,
            policy=rt.policy,
            clock=rt.os_.clock,
            observer=observer,
            monotonic_ns=monotonic_ns,
        )
        seed_scenario(domain, rt)
        domain.delivery_plan = scenario_plan(domain)
        proxy.bind(domain)
        if base is not None and base.before_job_recover is not None:
            base.before_job_recover(rt)

    hooks = base if base is not None else DaemonTestHooks()
    return DaemonTestHooks(
        after_tls_verify=hooks.after_tls_verify,
        after_open_before_rebuild=hooks.after_open_before_rebuild,
        before_job_recover=before_job_recover,
        before_bind=hooks.before_bind,
        before_endpoint_publish=hooks.before_endpoint_publish,
        after_endpoint_publish_before_final_tls_check=hooks.after_endpoint_publish_before_final_tls_check,
        before_auth_gate_publish=hooks.before_auth_gate_publish,
        before_enter_commit=hooks.before_enter_commit,
        after_reserve_before_enqueue=hooks.after_reserve_before_enqueue,
        before_runtime_close=hooks.before_runtime_close,
    )
