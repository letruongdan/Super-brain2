"""Test-only kernel business domain for Task 4 idempotency, replay, CAS staging, and scope dispatch tests.

Per ``task-4-brief.md`` C1/C2:
- Registers immutable per-result typed ledger entry kinds (``handler_version=1``, zero free-text columns)
  and ``FixtureDomainProjection`` (``p_fixture_domain_*`` tables, cleanly shadow-rebuildable without cross-table FKs).
- Computes each result ``ObjectRef`` digest from the canonical ID/ref-only record (never a cached response body),
  verifying exact ``(id, revision, digest)`` on ``render_stored``.
- Stages all safe CAS blobs outside ``Store.transaction()`` and holds only pre-staged bytes via ``KernelTx.hold_blob``.
- Injected explicitly by tests; production ``KernelBridge`` has no flag enabling this fixture domain.
"""

from __future__ import annotations

import base64
import sqlite3
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import cast

import jsonschema

from superbrain.application._lineage_delivery import aggregate_delivery_fields
from superbrain.application.deadlines import begin_local_phase
from superbrain.application.dispatch import KernelToolDomain, PreparedEffect
from superbrain.application.lineage import (
    admit_source_snapshot,
    commit_new_labeled_delivery,
    observe_within_budget,
    register_snapshot,
    resolve_binding,
)
from superbrain.application.privacy import PrivacyFilter, filter_policy_for
from superbrain.application.send_attempts import extract_projected_read_acks, record_projected_read_acks
from superbrain.composition.kernel_projections import kernel_store_extensions
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    REDACTED_REASON_DEFAULT,
    SNAPSHOT_DEGRADED_CODES,
    AccountingStatus,
    ArtifactSendSpec,
    Call,
    CallContext,
    DeliveryItem,
    DirectRefRecord,
    FilterPolicy,
    JobState,
    KernelRecord,
    LineageRef,
    ObjectRef,
    Principal,
    RepoFlags,
    ResourceDigest,
    Scope,
    SelectorPath,
    SelectorReason,
    SnapshotObservation,
    SnapshotStatus,
    StoredResult,
    WorkspaceBinding,
    WorkspaceSelector,
    field_path_descriptor,
    field_path_digest,
    require_opaque_id,
)
from superbrain.core.wire import encode_envelope, load_catalog
from superbrain.ports.clock import Clock
from superbrain.ports.kernel import KernelBlobStagePort, KernelPolicyPort, KernelTx, SnapshotObserver
from superbrain.ports.policy import PolicyView
from superbrain.storage._pair_admission import verify_admitted_store_pair, verify_live_store_handle
from superbrain.storage.identity import authorize_direct_ref
from superbrain.storage.kernel_schema import KERNEL_WORKSPACE_KINDS
from superbrain.storage.kinds import CORE_KINDS, EntryKind, FieldType, KindRegistry
from superbrain.storage.ledger import LedgerEntry, ProjectionHandler
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.store import Store
from superbrain.storage.workspaces import StoreKernelTx

_SLOTS = frozenset({"skills", "lessons", "continuity", "context", "finishing_gates"})
_LEVELS = frozenset({"L0", "L1", "L2"})
_ENCODINGS = frozenset({"utf-8", "base64"})
_SNAPSHOT_STATUSES = frozenset({"available", "unavailable", "deadline"})
_SELECTOR_PATHS = frozenset({"rules", "jev"})
_SELECTOR_REASONS = frozenset(
    {"provider_unavailable", "egress_ineligible", "jev_selected", "jev_failed", "jev_deadline"}
)
_OUTCOMES = frozenset({"success", "failure", "unknown"})
_JOB_STATES = frozenset(s.value for s in JobState)
_ACCOUNTING_STATES = frozenset(s.value for s in AccountingStatus)

FIXTURE_DOMAIN_KINDS: tuple[EntryKind, ...] = (
    EntryKind(
        "fixture.delivery_result_recorded",
        1,
        {
            "result_id": FieldType.OPAQUE_ID,
            "task_id": FieldType.OPAQUE_ID,
            "owner_id": FieldType.OPAQUE_ID,
            "repo_id": FieldType.OPAQUE_ID,
            "checkout_id": FieldType.OPAQUE_ID,
            "delivery_id": FieldType.OPAQUE_ID,
            "assignment_id": FieldType.OPAQUE_ID,
            "source_snapshot_id": FieldType.UUID,
            "snapshot_status": FieldType.ENUM,
            "selector_path": FieldType.ENUM,
            "selector_reason": FieldType.ENUM,
            "record_digest": FieldType.DIGEST,
        },
        {
            "snapshot_status": _SNAPSHOT_STATUSES,
            "selector_path": _SELECTOR_PATHS,
            "selector_reason": _SELECTOR_REASONS,
        },
        nullable=frozenset({"assignment_id", "source_snapshot_id"}),
    ),
    EntryKind(
        "fixture.delivery_result_item",
        1,
        {
            "result_id": FieldType.OPAQUE_ID,
            "slot": FieldType.ENUM,
            "position": FieldType.INT,
            "omitted": FieldType.BOOL,
            "snapshot_dependent": FieldType.BOOL,
            "ref_kind": FieldType.OPAQUE_ID,
            "ref_id": FieldType.OPAQUE_ID,
            "ref_revision": FieldType.INT,
            "ref_digest": FieldType.DIGEST,
            "owner_id": FieldType.OPAQUE_ID,
            "repo_id": FieldType.OPAQUE_ID,
            "checkout_id": FieldType.OPAQUE_ID,
        },
        {"slot": _SLOTS},
        nullable=frozenset({"repo_id", "checkout_id"}),
    ),
    EntryKind(
        "fixture.artifact_seeded",
        1,
        {
            "artifact_id": FieldType.OPAQUE_ID,
            "revision": FieldType.INT,
            "kind": FieldType.OPAQUE_ID,
            "owner_id": FieldType.OPAQUE_ID,
            "repo_id": FieldType.OPAQUE_ID,
            "checkout_id": FieldType.OPAQUE_ID,
            "artifact_digest": FieldType.DIGEST,
            "holder_id": FieldType.UUID,
        },
        {},
        nullable=frozenset({"repo_id", "checkout_id"}),
    ),
    EntryKind(
        "fixture.artifact_resource_seeded",
        1,
        {
            "artifact_id": FieldType.OPAQUE_ID,
            "revision": FieldType.INT,
            "level": FieldType.ENUM,
            "position": FieldType.INT,
            "resource_name": FieldType.OPAQUE_ID,
            "encoding": FieldType.ENUM,
            "blob_digest": FieldType.DIGEST,
        },
        {"level": _LEVELS, "encoding": _ENCODINGS},
    ),
    EntryKind(
        "fixture.artifact_result_recorded",
        1,
        {
            "result_id": FieldType.OPAQUE_ID,
            "task_id": FieldType.OPAQUE_ID,
            "owner_id": FieldType.OPAQUE_ID,
            "repo_id": FieldType.OPAQUE_ID,
            "checkout_id": FieldType.OPAQUE_ID,
            "artifact_id": FieldType.OPAQUE_ID,
            "revision": FieldType.INT,
            "level": FieldType.ENUM,
            "artifact_digest": FieldType.DIGEST,
            "record_digest": FieldType.DIGEST,
        },
        {"level": _LEVELS},
    ),
    EntryKind(
        "fixture.outcome_result_recorded",
        1,
        {
            "result_id": FieldType.OPAQUE_ID,
            "outcome_id": FieldType.OPAQUE_ID,
            "delivery_id": FieldType.OPAQUE_ID,
            "task_id": FieldType.OPAQUE_ID,
            "owner_id": FieldType.OPAQUE_ID,
            "repo_id": FieldType.OPAQUE_ID,
            "checkout_id": FieldType.OPAQUE_ID,
            "outcome": FieldType.ENUM,
            "applied_ref_count": FieldType.INT,
            "record_digest": FieldType.DIGEST,
        },
        {"outcome": _OUTCOMES},
    ),
    EntryKind(
        "fixture.job_seeded",
        1,
        {
            "job_id": FieldType.OPAQUE_ID,
            "owner_id": FieldType.OPAQUE_ID,
            "repo_id": FieldType.OPAQUE_ID,
            "checkout_id": FieldType.OPAQUE_ID,
            "state": FieldType.ENUM,
            "attempt": FieldType.INT,
            "accounting_status": FieldType.ENUM,
            "job_digest": FieldType.DIGEST,
        },
        {"state": _JOB_STATES, "accounting_status": _ACCOUNTING_STATES},
        nullable=frozenset({"repo_id", "checkout_id"}),
    ),
)


@dataclass(frozen=True)
class FixtureDeliveryRefSpec:
    """One candidate knowledge/context ref for fixture ``prepare_task``."""

    slot: str
    ref: ObjectRef
    owner_id: str
    repo_id: str | None
    checkout_id: str | None = None
    snapshot_dependent: bool = False
    unknown_source: bool = False
    extra_sources: tuple[LineageRef, ...] = ()
    custom_field_path: tuple[str | int, ...] | None = None


@dataclass(frozen=True)
class FixtureResourceSpec:
    name: str
    content: bytes
    encoding: str = "utf-8"
    level: str = "L1"


def _delivery_record_digest(payload: Mapping[str, JsonValue]) -> str:
    return digest_bytes(b"fixture-delivery-result-v1\0" + canonical_json(dict(payload)))


def _artifact_record_digest(payload: Mapping[str, JsonValue]) -> str:
    return digest_bytes(b"fixture-artifact-result-v1\0" + canonical_json(dict(payload)))


def _outcome_record_digest(payload: Mapping[str, JsonValue]) -> str:
    return digest_bytes(b"fixture-outcome-result-v1\0" + canonical_json(dict(payload)))


class FixtureDomainProjection:
    """Event-sourced ``p_fixture_domain_*`` tables for the test-only business domain."""

    name = "fixture_domain"
    handler_version = 1
    kinds = frozenset(kind.kind for kind in FIXTURE_DOMAIN_KINDS)

    def create_tables(self, db: sqlite3.Connection, prefix: str) -> None:
        db.execute(
            f"CREATE TABLE {prefix}deliveries ("
            "result_id TEXT PRIMARY KEY, "
            "delivery_id TEXT NOT NULL UNIQUE, "
            "task_id TEXT NOT NULL, "
            "owner_id TEXT NOT NULL, "
            "repo_id TEXT NOT NULL, "
            "checkout_id TEXT NOT NULL, "
            "assignment_id TEXT, "
            "source_snapshot_id TEXT, "
            "snapshot_status TEXT NOT NULL, "
            "selector_path TEXT NOT NULL, "
            "selector_reason TEXT NOT NULL, "
            "record_digest TEXT NOT NULL, "
            "sequence INTEGER NOT NULL)"
        )
        db.execute(
            f"CREATE TABLE {prefix}delivery_items ("
            "result_id TEXT NOT NULL, "
            "slot TEXT NOT NULL, "
            "position INTEGER NOT NULL, "
            "omitted INTEGER NOT NULL, "
            "snapshot_dependent INTEGER NOT NULL, "
            "ref_kind TEXT NOT NULL, "
            "ref_id TEXT NOT NULL, "
            "ref_revision INTEGER NOT NULL, "
            "ref_digest TEXT NOT NULL, "
            "owner_id TEXT NOT NULL, "
            "repo_id TEXT, "
            "checkout_id TEXT, "
            "PRIMARY KEY(result_id, slot, position))"
        )
        db.execute(
            f"CREATE TABLE {prefix}artifacts ("
            "artifact_id TEXT NOT NULL, "
            "revision INTEGER NOT NULL, "
            "kind TEXT NOT NULL, "
            "owner_id TEXT NOT NULL, "
            "repo_id TEXT, "
            "checkout_id TEXT, "
            "artifact_digest TEXT NOT NULL, "
            "holder_id TEXT NOT NULL, "
            "PRIMARY KEY(artifact_id, revision))"
        )
        db.execute(
            f"CREATE TABLE {prefix}artifact_resources ("
            "artifact_id TEXT NOT NULL, "
            "revision INTEGER NOT NULL, "
            "level TEXT NOT NULL, "
            "position INTEGER NOT NULL, "
            "resource_name TEXT NOT NULL, "
            "encoding TEXT NOT NULL, "
            "blob_digest TEXT NOT NULL, "
            "PRIMARY KEY(artifact_id, revision, level, position))"
        )
        db.execute(
            f"CREATE TABLE {prefix}artifact_results ("
            "result_id TEXT PRIMARY KEY, "
            "task_id TEXT NOT NULL, "
            "owner_id TEXT NOT NULL, "
            "repo_id TEXT NOT NULL, "
            "checkout_id TEXT NOT NULL, "
            "artifact_id TEXT NOT NULL, "
            "revision INTEGER NOT NULL, "
            "level TEXT NOT NULL, "
            "artifact_digest TEXT NOT NULL, "
            "record_digest TEXT NOT NULL)"
        )
        db.execute(
            f"CREATE TABLE {prefix}outcomes ("
            "result_id TEXT PRIMARY KEY, "
            "outcome_id TEXT NOT NULL UNIQUE, "
            "delivery_id TEXT NOT NULL, "
            "task_id TEXT NOT NULL, "
            "owner_id TEXT NOT NULL, "
            "repo_id TEXT NOT NULL, "
            "checkout_id TEXT NOT NULL, "
            "outcome TEXT NOT NULL, "
            "applied_ref_count INTEGER NOT NULL, "
            "record_digest TEXT NOT NULL)"
        )
        db.execute(
            f"CREATE TABLE {prefix}jobs ("
            "job_id TEXT PRIMARY KEY, "
            "owner_id TEXT NOT NULL, "
            "repo_id TEXT, "
            "checkout_id TEXT, "
            "state TEXT NOT NULL, "
            "attempt INTEGER NOT NULL, "
            "accounting_status TEXT NOT NULL, "
            "job_digest TEXT NOT NULL)"
        )

    def apply(self, db: sqlite3.Connection, prefix: str, entry: LedgerEntry, policy: PolicyView) -> None:
        _ = policy
        m = entry.meta
        if entry.kind == "fixture.delivery_result_recorded":
            db.execute(
                f"INSERT INTO {prefix}deliveries VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    m["result_id"],
                    m["delivery_id"],
                    m["task_id"],
                    m["owner_id"],
                    m["repo_id"],
                    m["checkout_id"],
                    m["assignment_id"],
                    m["source_snapshot_id"],
                    m["snapshot_status"],
                    m["selector_path"],
                    m["selector_reason"],
                    m["record_digest"],
                    entry.sequence,
                ),
            )
        elif entry.kind == "fixture.delivery_result_item":
            db.execute(
                f"INSERT INTO {prefix}delivery_items VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    m["result_id"],
                    m["slot"],
                    m["position"],
                    1 if m["omitted"] else 0,
                    1 if m["snapshot_dependent"] else 0,
                    m["ref_kind"],
                    m["ref_id"],
                    m["ref_revision"],
                    m["ref_digest"],
                    m["owner_id"],
                    m["repo_id"],
                    m["checkout_id"],
                ),
            )
        elif entry.kind == "fixture.artifact_seeded":
            db.execute(
                f"INSERT OR REPLACE INTO {prefix}artifacts VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    m["artifact_id"],
                    m["revision"],
                    m["kind"],
                    m["owner_id"],
                    m["repo_id"],
                    m["checkout_id"],
                    m["artifact_digest"],
                    m["holder_id"],
                ),
            )
        elif entry.kind == "fixture.artifact_resource_seeded":
            db.execute(
                f"INSERT OR REPLACE INTO {prefix}artifact_resources VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    m["artifact_id"],
                    m["revision"],
                    m["level"],
                    m["position"],
                    m["resource_name"],
                    m["encoding"],
                    m["blob_digest"],
                ),
            )
        elif entry.kind == "fixture.artifact_result_recorded":
            db.execute(
                f"INSERT INTO {prefix}artifact_results VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    m["result_id"],
                    m["task_id"],
                    m["owner_id"],
                    m["repo_id"],
                    m["checkout_id"],
                    m["artifact_id"],
                    m["revision"],
                    m["level"],
                    m["artifact_digest"],
                    m["record_digest"],
                ),
            )
        elif entry.kind == "fixture.outcome_result_recorded":
            db.execute(
                f"INSERT INTO {prefix}outcomes VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    m["result_id"],
                    m["outcome_id"],
                    m["delivery_id"],
                    m["task_id"],
                    m["owner_id"],
                    m["repo_id"],
                    m["checkout_id"],
                    m["outcome"],
                    m["applied_ref_count"],
                    m["record_digest"],
                ),
            )
        elif entry.kind == "fixture.job_seeded":
            db.execute(
                f"INSERT OR REPLACE INTO {prefix}jobs VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    m["job_id"],
                    m["owner_id"],
                    m["repo_id"],
                    m["checkout_id"],
                    m["state"],
                    m["attempt"],
                    m["accounting_status"],
                    m["job_digest"],
                ),
            )


def fixture_store_extensions() -> tuple[tuple[ProjectionHandler, ...], KindRegistry]:
    """Return ``(handlers, kinds)`` combining production kernel workspace extensions with the test fixture domain."""
    ws_handlers, _ = kernel_store_extensions()
    all_kinds = KindRegistry([*CORE_KINDS, *KERNEL_WORKSPACE_KINDS, *FIXTURE_DOMAIN_KINDS])
    return ((*ws_handlers, FixtureDomainProjection()), all_kinds)


def validate_response_envelope(tool: str, envelope: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    """Validate ``envelope`` against both strict wire rules and packaged ``mcp-tools-v2.json`` output schema."""
    env_dict: dict[str, JsonValue] = dict(envelope)
    encode_envelope(env_dict)
    catalog = load_catalog()
    validator = jsonschema.Draft202012Validator(catalog.tools[tool].output_schema)
    validator.validate(env_dict)
    return env_dict


@dataclass
class FixtureKernelDomain(KernelToolDomain):
    """Test-only ``KernelToolDomain`` wired over real ``Store``, ``PolicyStore`` and ``SnapshotObserver``."""

    store: Store
    policy: KernelPolicyPort
    clock: Clock
    observer: SnapshotObserver | None = None
    monotonic_ns: Callable[[], int] = time.perf_counter_ns
    delivery_plan: Callable[[WorkspaceBinding, str], Sequence[FixtureDeliveryRefSpec]] | None = None
    repo_flags_overrides: dict[str, RepoFlags] = field(default_factory=dict)
    before_apply_hook: Callable[[KernelTx], None] | None = None
    prepare_calls: int = 0
    apply_calls: int = 0

    def __post_init__(self) -> None:
        self._check_live()

    def _check_live(self) -> None:
        if isinstance(self.policy, PolicyStore):
            verify_admitted_store_pair(self.store, self.policy)
        else:
            verify_live_store_handle(self.store)

    def supports_tool(self, tool: str, *, deep: bool = False) -> bool:
        if tool == "get_health":
            return not deep
        return tool in {"prepare_task", "get_artifact", "record_outcome", "get_job"}

    def seed_artifact(
        self,
        stage: KernelBlobStagePort,
        *,
        artifact_id: str,
        revision: int,
        owner_id: str,
        repo_id: str | None,
        checkout_id: str | None,
        resources: Sequence[FixtureResourceSpec],
        kind: str = "skill",
    ) -> ObjectRef:
        """Pre-stage resource blobs outside SQLite Txn, then seed the typed artifact & hold blobs atomically."""
        holder_id = new_id()
        staged_digests: list[tuple[FixtureResourceSpec, str]] = []
        for spec in resources:
            staged = stage.stage_blob(spec.content)
            staged_digests.append((spec, staged.digest))
        manifest_payload: dict[str, JsonValue] = {
            "artifact_id": artifact_id,
            "revision": revision,
            "kind": kind,
            "resources": [
                {"level": s.level, "name": s.name, "encoding": s.encoding, "digest": d} for s, d in staged_digests
            ],
        }
        artifact_digest = digest_bytes(b"fixture-artifact-v1\0" + canonical_json(manifest_payload))
        with self.store.transaction() as txn:
            from superbrain.storage.kinds import RetentionClass

            for _spec, digest in staged_digests:
                txn.hold(digest, "event", holder_id, RetentionClass.DURABLE, None)
            txn.append(
                "fixture.artifact_seeded",
                actor="system:kernel",
                owner_id=None,
                meta={
                    "artifact_id": artifact_id,
                    "revision": revision,
                    "kind": kind,
                    "owner_id": owner_id,
                    "repo_id": repo_id,
                    "checkout_id": checkout_id,
                    "artifact_digest": artifact_digest,
                    "holder_id": holder_id,
                },
            )
            for idx, (spec, digest) in enumerate(staged_digests):
                txn.append(
                    "fixture.artifact_resource_seeded",
                    actor="system:kernel",
                    owner_id=None,
                    meta={
                        "artifact_id": artifact_id,
                        "revision": revision,
                        "level": spec.level,
                        "position": idx,
                        "resource_name": spec.name,
                        "encoding": spec.encoding,
                        "blob_digest": digest,
                    },
                    refs=(digest,),
                )
        return ObjectRef(kind=kind, id=artifact_id, revision=revision, digest=artifact_digest)

    def seed_job(
        self,
        *,
        job_id: str,
        owner_id: str,
        repo_id: str | None,
        checkout_id: str | None,
        state: JobState = JobState.QUEUED,
        attempt: int = 1,
        accounting_status: AccountingStatus = AccountingStatus.NONE,
    ) -> ObjectRef:
        job_digest = digest_bytes(
            b"fixture-job-v1\0"
            + canonical_json(
                {
                    "job_id": job_id,
                    "owner_id": owner_id,
                    "repo_id": repo_id,
                    "checkout_id": checkout_id,
                    "attempt": attempt,
                }
            )
        )
        with self.store.transaction() as txn:
            txn.append(
                "fixture.job_seeded",
                actor="system:kernel",
                owner_id=None,
                meta={
                    "job_id": job_id,
                    "owner_id": owner_id,
                    "repo_id": repo_id,
                    "checkout_id": checkout_id,
                    "state": state.value,
                    "attempt": attempt,
                    "accounting_status": accounting_status.value,
                    "job_digest": job_digest,
                },
            )
        return ObjectRef(kind="job", id=job_id, revision=attempt, digest=job_digest)

    def _filter_policy_for_repo(self, repo_id: str) -> FilterPolicy:
        override = self.repo_flags_overrides.get(repo_id)
        if override is not None:
            return filter_policy_for(override)
        snap = self.policy.snapshot()
        repo_pol = snap.repo_policies.get(repo_id)
        if repo_pol is None:
            return FilterPolicy()
        return filter_policy_for(RepoFlags.from_repo_policy(repo_pol))

    def prepare_mutation(self, call: Call, ctx: CallContext, *, now: datetime) -> PreparedEffect:
        _ = now
        self._check_live()
        self.prepare_calls += 1
        if call.tool == "prepare_task":
            return self._prepare_task_effect(call, ctx)
        if call.tool == "get_artifact":
            return self._prepare_get_artifact_effect(call, ctx)
        if call.tool == "record_outcome":
            return self._prepare_record_outcome_effect(call, ctx)
        raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")

    def _prepare_task_effect(self, call: Call, ctx: CallContext) -> PreparedEffect:
        local_deadline = begin_local_phase(self.monotonic_ns, ctx.deadline_ns, local_deadline_ns=ctx.local_deadline_ns)
        args = call.arguments
        selector = WorkspaceSelector(
            workspace_id=cast(str | None, args.get("workspace_id")),
            checkout_id=cast(str | None, args.get("checkout_id")),
            workspace_hint=cast(str | None, args.get("workspace_hint")),
            source_snapshot_id=cast(str | None, args.get("source_snapshot_id")),
        )
        binding = resolve_binding(ctx.principal, selector, self.policy, selected_scope=call.selected_scope)
        task_id = str(args["task_id"]) if "task_id" in args else new_id()
        require_opaque_id(task_id, label="task_id")

        with self.store.transaction() as read_txn:
            row = read_txn.db.execute(
                "SELECT owner_id, repo_id, checkout_id FROM p_task_lineage_bindings WHERE task_id = ?",
                (task_id,),
            ).fetchone()
        if row is not None and (str(row[0]), str(row[1]), str(row[2])) != (
            binding.owner_id,
            binding.repo_id,
            binding.checkout_id,
        ):
            raise BrainError(ErrorCode.NOT_FOUND, "not found")

        fpol = self._filter_policy_for_repo(binding.repo_id)
        safe = PrivacyFilter(self.monotonic_ns).apply(dict(args), fpol, deadline_ns=local_deadline)

        explicit = selector.source_snapshot_id
        observation: SnapshotObservation | None = None
        if explicit is not None:
            with self.store.transaction() as chk_txn:
                from superbrain.storage.workspaces import StoreKernelTx

                admit_source_snapshot(StoreKernelTx(chk_txn, self.store.cas, self._policy_view()), binding, explicit)
            if self.monotonic_ns() >= local_deadline:
                raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")
        else:
            observation = observe_within_budget(
                self.observer,
                binding,
                monotonic_ns=self.monotonic_ns,
                local_deadline=local_deadline,
            )

        specs = tuple(self.delivery_plan(binding, task_id)) if self.delivery_plan is not None else ()
        lineage_items: list[DeliveryItem] = []
        slot_counts: dict[str, int] = {}
        spec_paths: list[tuple[FixtureDeliveryRefSpec, tuple[str | int, ...], str, int]] = []
        for spec in specs:
            pos = slot_counts.get(spec.slot, 0)
            slot_counts[spec.slot] = pos + 1
            path = spec.custom_field_path if spec.custom_field_path is not None else (spec.slot, pos)
            item_sources: list[LineageRef] = list(spec.extra_sources)
            if spec.repo_id is not None and not spec.unknown_source:
                item_sources.append(LineageRef(owner_id=spec.owner_id, repo_id=spec.repo_id, source=spec.ref))
            lineage_items.append(
                DeliveryItem(
                    path=path,
                    sources=frozenset(item_sources),
                    unknown_source=spec.unknown_source,
                    snapshot_dependent=spec.snapshot_dependent,
                )
            )
            spec_paths.append((spec, path, field_path_digest(path), pos))

        agg_fields = aggregate_delivery_fields(lineage_items, fpol)
        blobs: list[bytes] = []
        if (
            explicit is None
            and observation is not None
            and observation.descriptor is not None
            and not self._policy_view().is_quarantined(observation.descriptor.descriptor_digest)
        ):
            blobs.append(observation.descriptor.content_bytes())
        for field_entry in agg_fields:
            if field_entry.persistable:
                blobs.append(field_path_descriptor(field_entry.path))

        result_id = new_id()

        def apply(tx: KernelTx) -> StoredResult:
            self.apply_calls += 1
            if self.before_apply_hook is not None:
                self.before_apply_hook(tx)
            existing_bound = tx.read_task_binding(task_id)
            if existing_bound is not None and (
                existing_bound.owner_id,
                existing_bound.repo_id,
                existing_bound.checkout_id,
            ) != (binding.owner_id, binding.repo_id, binding.checkout_id):
                raise BrainError(ErrorCode.NOT_FOUND, "not found")

            snapshot_id: str | None = None
            status = SnapshotStatus.UNAVAILABLE
            if explicit is not None:
                snapshot_id = admit_source_snapshot(tx, binding, explicit).snapshot_id
                status = SnapshotStatus.AVAILABLE
            elif observation is not None and observation.descriptor is not None:
                if tx.blob_restricted(observation.descriptor.descriptor_digest):
                    status = SnapshotStatus.UNAVAILABLE
                else:
                    snapshot_id = register_snapshot(tx, binding, observation.descriptor)
                    status = SnapshotStatus.AVAILABLE
            elif observation is not None:
                status = observation.status

            persisted_paths = {fe.path for fe in agg_fields if fe.persistable}
            served_refs = tuple(
                LineageRef(owner_id=spec.owner_id, repo_id=spec.repo_id, source=spec.ref)
                for spec, path, _, _ in spec_paths
                if path in persisted_paths
                and (status is SnapshotStatus.AVAILABLE or not spec.snapshot_dependent)
                and spec.repo_id is not None
                and not spec.unknown_source
            )
            labeled = commit_new_labeled_delivery(
                tx,
                binding=binding,
                task_id=task_id,
                items=tuple(lineage_items),
                served_sources=served_refs,
                snapshot_id=snapshot_id,
                status=status,
                safe=safe,
                selector_path=SelectorPath.RULES,
                selector_reason=SelectorReason.PROVIDER_UNAVAILABLE,
                filter_policy=fpol,
            )
            omitted_digests = set(labeled.omitted_items)
            persisted_digests = {fl.field_path_digest for fl in labeled.items}

            selected_entries: list[dict[str, JsonValue]] = []
            omitted_entries: list[dict[str, JsonValue]] = []
            selected_refs: list[ObjectRef] = []
            item_records: list[KernelRecord] = []

            for spec, _path, p_digest, pos in spec_paths:
                # Non-admissible paths (stripped by privacy filter) are never delivered or persisted.
                if p_digest not in persisted_digests and p_digest not in omitted_digests:
                    continue
                is_omitted = (status is not SnapshotStatus.AVAILABLE and spec.snapshot_dependent) or (
                    p_digest in omitted_digests
                )
                entry_dict: dict[str, JsonValue] = {
                    "slot": spec.slot,
                    "position": pos,
                    "snapshot_dependent": spec.snapshot_dependent,
                    "ref": spec.ref.to_dict(),
                    "owner_id": spec.owner_id,
                    "repo_id": spec.repo_id,
                    "checkout_id": spec.checkout_id,
                }
                if is_omitted:
                    omitted_entries.append(entry_dict)
                else:
                    selected_entries.append(entry_dict)
                    selected_refs.append(spec.ref)
                item_records.append(
                    KernelRecord(
                        "fixture.delivery_result_item",
                        {
                            "result_id": result_id,
                            "slot": spec.slot,
                            "position": pos,
                            "omitted": is_omitted,
                            "snapshot_dependent": spec.snapshot_dependent,
                            "ref_kind": spec.ref.kind,
                            "ref_id": spec.ref.id,
                            "ref_revision": spec.ref.revision,
                            "ref_digest": spec.ref.digest,
                            "owner_id": spec.owner_id,
                            "repo_id": spec.repo_id,
                            "checkout_id": spec.checkout_id,
                        },
                    )
                )

            selected_entries.sort(key=lambda e: (str(e["slot"]), int(cast(int, e["position"]))))
            omitted_entries.sort(key=lambda e: (str(e["slot"]), int(cast(int, e["position"]))))
            delivery_id = labeled.binding.delivery_id
            assignment_id = labeled.binding.assignment_id
            record_payload: dict[str, JsonValue] = {
                "result_id": result_id,
                "task_id": task_id,
                "owner_id": binding.owner_id,
                "repo_id": binding.repo_id,
                "checkout_id": binding.checkout_id,
                "delivery_id": delivery_id,
                "assignment_id": assignment_id,
                "source_snapshot_id": snapshot_id,
                "snapshot_status": status.value,
                "selector_path": labeled.binding.selector_path.value,
                "selector_reason": labeled.binding.selector_reason.value,
                "selected_items": cast(list[JsonValue], selected_entries),
                "omitted_items": cast(list[JsonValue], omitted_entries),
            }
            rec_digest = _delivery_record_digest(record_payload)
            tx.append_record(
                KernelRecord(
                    "fixture.delivery_result_recorded",
                    {
                        "result_id": result_id,
                        "task_id": task_id,
                        "owner_id": binding.owner_id,
                        "repo_id": binding.repo_id,
                        "checkout_id": binding.checkout_id,
                        "delivery_id": delivery_id,
                        "assignment_id": assignment_id,
                        "source_snapshot_id": snapshot_id,
                        "snapshot_status": status.value,
                        "selector_path": labeled.binding.selector_path.value,
                        "selector_reason": labeled.binding.selector_reason.value,
                        "record_digest": rec_digest,
                    },
                )
            )
            for item_rec in item_records:
                tx.append_record(item_rec)

            delivery_ref = ObjectRef(kind="delivery_result", id=delivery_id, revision=1, digest=rec_digest)
            return StoredResult(
                result_id=result_id,
                assignment_id=assignment_id,
                refs=(delivery_ref, *selected_refs),
            )

        return PreparedEffect(blobs=tuple(blobs), apply=apply)

    def _prepare_get_artifact_effect(self, call: Call, ctx: CallContext) -> PreparedEffect:
        local_deadline = begin_local_phase(self.monotonic_ns, ctx.deadline_ns, local_deadline_ns=ctx.local_deadline_ns)
        scope = call.selected_scope
        if scope is None or scope.checkout_id is None:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        workspace_id = str(call.arguments["workspace_id"])
        task_id = str(call.arguments["task_id"])
        artifact_id = str(call.arguments["artifact_id"])
        revision = int(cast(int, call.arguments["revision"]))
        level = str(call.arguments["level"])
        if scope.repo_id != workspace_id:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")

        with self.store.transaction() as read_txn:
            t_row = read_txn.db.execute(
                "SELECT owner_id, repo_id, checkout_id FROM p_task_lineage_bindings WHERE task_id = ?",
                (task_id,),
            ).fetchone()
            a_row = read_txn.db.execute(
                "SELECT kind, owner_id, repo_id, checkout_id, artifact_digest, holder_id "
                "FROM p_fixture_domain_artifacts WHERE artifact_id = ? AND revision = ?",
                (artifact_id, revision),
            ).fetchone()
            res_rows = read_txn.db.execute(
                "SELECT resource_name, blob_digest FROM p_fixture_domain_artifact_resources "
                "WHERE artifact_id = ? AND revision = ? AND level = ? ORDER BY position",
                (artifact_id, revision, level),
            ).fetchall()

        if t_row is None or (str(t_row[0]), str(t_row[1]), str(t_row[2])) != (
            ctx.principal.owner_id,
            scope.repo_id,
            scope.checkout_id,
        ):
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        if a_row is None or not res_rows:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        a_kind, a_owner, a_repo, a_chk, a_digest, _holder = a_row
        if str(a_owner) != ctx.principal.owner_id:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        if a_repo is not None:
            eff_chk = str(a_chk) if a_chk is not None else scope.checkout_id
            if a_chk is not None and str(a_chk) != scope.checkout_id:
                raise BrainError(ErrorCode.NOT_FOUND, "not found")
            if not self.policy.allows(ctx.principal, Scope(str(a_repo), eff_chk), action="get_artifact"):
                raise BrainError(ErrorCode.NOT_FOUND, "not found")

        fpol = self._filter_policy_for_repo(scope.repo_id)
        PrivacyFilter(self.monotonic_ns).apply(dict(call.arguments), fpol, deadline_ns=local_deadline)

        result_id = new_id()
        art_ref = ObjectRef(kind=str(a_kind), id=artifact_id, revision=revision, digest=str(a_digest))

        def apply(tx: KernelTx) -> StoredResult:
            self.apply_calls += 1
            if self.before_apply_hook is not None:
                self.before_apply_hook(tx)
            rec_payload: dict[str, JsonValue] = {
                "result_id": result_id,
                "task_id": task_id,
                "owner_id": ctx.principal.owner_id,
                "repo_id": scope.repo_id,
                "checkout_id": scope.checkout_id,
                "artifact_id": artifact_id,
                "revision": revision,
                "level": level,
                "artifact_digest": str(a_digest),
            }
            rec_digest = _artifact_record_digest(rec_payload)
            tx.append_record(
                KernelRecord(
                    "fixture.artifact_result_recorded",
                    {
                        **rec_payload,
                        "record_digest": rec_digest,
                    },
                )
            )
            res_ref = ObjectRef(kind="artifact_result", id=result_id, revision=1, digest=rec_digest)
            return StoredResult(result_id=result_id, assignment_id=None, refs=(res_ref, art_ref))

        return PreparedEffect(blobs=(), apply=apply)

    def _prepare_record_outcome_effect(self, call: Call, ctx: CallContext) -> PreparedEffect:
        local_deadline = begin_local_phase(self.monotonic_ns, ctx.deadline_ns, local_deadline_ns=ctx.local_deadline_ns)
        scope = call.selected_scope
        if scope is None or scope.checkout_id is None:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        workspace_id = str(call.arguments["workspace_id"])
        delivery_id = str(call.arguments["delivery_id"])
        outcome = str(call.arguments["outcome"])
        if scope.repo_id != workspace_id:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")

        with self.store.transaction() as read_txn:
            d_row = read_txn.db.execute(
                "SELECT task_id, owner_id, repo_id, checkout_id FROM p_fixture_domain_deliveries WHERE delivery_id = ?",
                (delivery_id,),
            ).fetchone()
        if d_row is None or (str(d_row[1]), str(d_row[2]), str(d_row[3])) != (
            ctx.principal.owner_id,
            scope.repo_id,
            scope.checkout_id,
        ):
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        task_id = str(d_row[0])

        fpol = self._filter_policy_for_repo(scope.repo_id)
        safe = PrivacyFilter(self.monotonic_ns).apply(dict(call.arguments), fpol, deadline_ns=local_deadline)
        safe_dict = safe.value if isinstance(safe.value, dict) else {}
        kept_applied = safe_dict.get("applied_refs")
        applied_count = len(kept_applied) if isinstance(kept_applied, list) else 0
        projected_acks = extract_projected_read_acks(safe_dict)

        result_id = new_id()
        outcome_id = new_id()

        def apply(tx: KernelTx) -> StoredResult:
            self.apply_calls += 1
            if self.before_apply_hook is not None:
                self.before_apply_hook(tx)
            if projected_acks:
                record_projected_read_acks(
                    tx,
                    policy=self.policy,
                    principal=ctx.principal,
                    effective_scope=scope,
                    expected_task_id=task_id,
                    acks=projected_acks,
                )
            rec_payload: dict[str, JsonValue] = {
                "result_id": result_id,
                "outcome_id": outcome_id,
                "delivery_id": delivery_id,
                "task_id": task_id,
                "owner_id": ctx.principal.owner_id,
                "repo_id": scope.repo_id,
                "checkout_id": scope.checkout_id,
                "outcome": outcome,
                "applied_ref_count": applied_count,
            }
            rec_digest = _outcome_record_digest(rec_payload)
            tx.append_record(
                KernelRecord(
                    "fixture.outcome_result_recorded",
                    {
                        **rec_payload,
                        "record_digest": rec_digest,
                    },
                )
            )
            out_ref = ObjectRef(kind="outcome_result", id=outcome_id, revision=1, digest=rec_digest)
            return StoredResult(result_id=result_id, assignment_id=None, refs=(out_ref,))

        return PreparedEffect(blobs=(), apply=apply)

    def execute_readonly(self, call: Call, ctx: CallContext) -> dict[str, JsonValue]:
        self._check_live()
        if call.tool != "get_job":
            raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")
        job_id = str(call.arguments["job_id"])
        with self.store.transaction() as read_txn:
            row = read_txn.db.execute(
                "SELECT owner_id, repo_id, checkout_id, state, attempt, accounting_status, job_digest "
                "FROM p_fixture_domain_jobs WHERE job_id = ?",
                (job_id,),
            ).fetchone()
        if row is None:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        owner_id, repo_id, checkout_id, state, attempt, accounting, job_digest = row
        ref = ObjectRef(kind="job", id=job_id, revision=int(attempt), digest=str(job_digest))
        rec = DirectRefRecord(
            kind="job",
            id=job_id,
            revision=int(attempt),
            digest=str(job_digest),
            owner_id=str(owner_id),
            repo_id=str(repo_id) if repo_id is not None else None,
            checkout_id=str(checkout_id) if checkout_id is not None else None,
        )
        authorize_direct_ref(ctx.principal, call.selected_scope, ref, rec, self.policy, expected_kind="job")
        return {
            "job_id": job_id,
            "state": str(state),
            "attempt": int(attempt),
            "result_refs": [],
            "accounting_status": str(accounting),
        }

    def render_stored(
        self,
        result: StoredResult,
        principal: Principal,
        *,
        selected_scope: Scope | None,
    ) -> dict[str, JsonValue]:
        self._check_live()
        if not result.refs:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
        primary = result.refs[0]
        if primary.kind == "delivery_result":
            return self._render_delivery_result(result, primary, principal, selected_scope=selected_scope)
        if primary.kind == "artifact_result":
            return self._render_artifact_result(result, primary, principal, selected_scope=selected_scope)
        if primary.kind == "outcome_result":
            return self._render_outcome_result(result, primary, principal, selected_scope=selected_scope)
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")

    def describe_artifact_send(
        self,
        result: StoredResult,
        rendered: Mapping[str, JsonValue],
        principal: Principal,
        *,
        selected_scope: Scope | None,
    ) -> ArtifactSendSpec | None:
        _ = selected_scope
        self._check_live()
        if not result.refs or result.refs[0].kind != "artifact_result":
            return None
        if rendered.get("status") != "ok":
            return None
        raw_resources = rendered.get("resources")
        if not isinstance(raw_resources, list) or not raw_resources:
            return None
        with self.store.transaction() as read_txn:
            r_row = read_txn.db.execute(
                "SELECT task_id, artifact_id, revision FROM p_fixture_domain_artifact_results WHERE result_id = ?",
                (result.result_id,),
            ).fetchone()
        if r_row is None:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        task_id, artifact_id, revision = str(r_row[0]), str(r_row[1]), int(r_row[2])
        digests: list[ResourceDigest] = []
        for item in raw_resources:
            if not isinstance(item, Mapping):
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
            r_name = item.get("name")
            r_dig = item.get("digest")
            if not isinstance(r_name, str) or not isinstance(r_dig, str):
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
            digests.append(ResourceDigest(name=r_name, digest=r_dig))
        return ArtifactSendSpec(
            logical_result_id=result.result_id,
            principal_id=principal.principal_id,
            task_id=task_id,
            artifact_id=artifact_id,
            revision=revision,
            resource_digests=tuple(digests),
        )

    def _render_delivery_result(
        self,
        result: StoredResult,
        primary: ObjectRef,
        principal: Principal,
        *,
        selected_scope: Scope | None,
    ) -> dict[str, JsonValue]:
        pview = self._policy_view()
        snap_readable = False
        with self.store.transaction() as read_txn:
            d_row = read_txn.db.execute(
                "SELECT result_id, task_id, owner_id, repo_id, checkout_id, delivery_id, assignment_id, "
                "source_snapshot_id, snapshot_status, selector_path, selector_reason, record_digest "
                "FROM p_fixture_domain_deliveries WHERE delivery_id = ?",
                (primary.id,),
            ).fetchone()
            item_rows = (
                read_txn.db.execute(
                    "SELECT slot, position, omitted, snapshot_dependent, ref_kind, ref_id, ref_revision, ref_digest, "
                    "owner_id, repo_id, checkout_id FROM p_fixture_domain_delivery_items "
                    "WHERE result_id = ? ORDER BY slot, position",
                    (str(d_row[0]),),
                ).fetchall()
                if d_row is not None
                else []
            )
            if d_row is not None and d_row[7] is not None:
                ktx = StoreKernelTx(read_txn, self.store.cas, pview)
                snap = ktx.read_source_snapshot(str(d_row[7]))
                snap_readable = (
                    snap is not None
                    and snap.owner_id == str(d_row[2])
                    and snap.repo_id == str(d_row[3])
                    and snap.checkout_id == str(d_row[4])
                    and ktx.snapshot_held(snap.snapshot_id, snap.descriptor_digest)
                    and not ktx.holder_tombstoned(snap.snapshot_id)
                    and not pview.is_tombstoned("event", snap.snapshot_id)
                    and not ktx.blob_restricted(snap.descriptor_digest)
                    and not pview.is_quarantined(snap.descriptor_digest)
                    and ktx.blob_present(snap.descriptor_digest)
                )
        if d_row is None or primary.revision != 1:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        (
            rec_result_id,
            task_id,
            owner_id,
            repo_id,
            checkout_id,
            delivery_id,
            assignment_id,
            snapshot_id,
            snap_status,
            sel_path,
            sel_reason,
            stored_digest,
        ) = d_row
        if str(rec_result_id) != result.result_id or assignment_id != result.assignment_id:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")

        selected_entries: list[dict[str, JsonValue]] = []
        omitted_entries: list[dict[str, JsonValue]] = []
        for s_slot, s_pos, s_omit, s_snap_dep, r_kind, r_id, r_rev, r_dig, r_owner, r_repo, r_chk in item_rows:
            entry_obj: dict[str, JsonValue] = {
                "slot": str(s_slot),
                "position": int(s_pos),
                "snapshot_dependent": int(s_snap_dep) == 1,
                "ref": {
                    "kind": str(r_kind),
                    "id": str(r_id),
                    "revision": int(r_rev),
                    "digest": str(r_dig),
                },
                "owner_id": str(r_owner),
                "repo_id": None if r_repo is None else str(r_repo),
                "checkout_id": None if r_chk is None else str(r_chk),
            }
            if int(s_omit) == 1:
                omitted_entries.append(entry_obj)
            else:
                selected_entries.append(entry_obj)

        expected_digest = _delivery_record_digest(
            {
                "result_id": str(rec_result_id),
                "task_id": str(task_id),
                "owner_id": str(owner_id),
                "repo_id": str(repo_id),
                "checkout_id": str(checkout_id),
                "delivery_id": str(delivery_id),
                "assignment_id": None if assignment_id is None else str(assignment_id),
                "source_snapshot_id": None if snapshot_id is None else str(snapshot_id),
                "snapshot_status": str(snap_status),
                "selector_path": str(sel_path),
                "selector_reason": str(sel_reason),
                "selected_items": cast(list[JsonValue], selected_entries),
                "omitted_items": cast(list[JsonValue], omitted_entries),
            }
        )
        if expected_digest != str(stored_digest) or expected_digest != primary.digest:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")

        # Authorize recorded Delivery subject against live principal, workspace grant, machine & selected_scope (C1/D3).
        req_scope = Scope(str(repo_id), str(checkout_id))
        if (
            str(owner_id) != principal.owner_id
            or (selected_scope is not None and selected_scope != req_scope)
            or not self.policy.allows(principal, req_scope, action="prepare_task")
        ):
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        auth_snap = self.policy.snapshot()

        rendered_snapshot_id: str | None = None if snapshot_id is None else str(snapshot_id)
        status_enum = SnapshotStatus(str(snap_status))
        if (status_enum is SnapshotStatus.AVAILABLE) != (rendered_snapshot_id is not None):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")

        slots: dict[str, list[JsonValue]] = {
            "skills": [],
            "lessons": [],
            "continuity": [],
            "context": [],
            "finishing_gates": [],
        }
        for s_slot, _s_pos, s_omit, s_snap_dep, r_kind, r_id, r_rev, r_dig, r_owner, r_repo, r_chk in item_rows:
            if int(s_omit) == 1:
                continue
            if int(s_snap_dep) == 1 and (rendered_snapshot_id is None or not snap_readable):
                continue
            redacted = self._item_is_redacted(
                principal=principal,
                effective_scope=req_scope,
                auth_snap=auth_snap,
                pview=pview,
                ref_kind=str(r_kind),
                ref_id=str(r_id),
                ref_digest=str(r_dig),
                ref_owner=str(r_owner),
                ref_repo=None if r_repo is None else str(r_repo),
                ref_checkout=None if r_chk is None else str(r_chk),
            )
            if redacted:
                slots[str(s_slot)].append(
                    {
                        "id": str(r_id),
                        "status": "redacted",
                        "reason": REDACTED_REASON_DEFAULT,
                    }
                )
            else:
                slots[str(s_slot)].append(
                    {
                        "kind": str(r_kind),
                        "id": str(r_id),
                        "revision": int(r_rev),
                        "digest": str(r_dig),
                        "status": "ok",
                    }
                )

        degraded_code = SNAPSHOT_DEGRADED_CODES.get(status_enum)
        degraded_codes: list[JsonValue] = [degraded_code] if degraded_code is not None else []
        return {
            "workspace_id": str(repo_id),
            "checkout_id": str(checkout_id),
            "source_snapshot_id": rendered_snapshot_id,
            "snapshot_status": status_enum.value,
            "degraded_codes": degraded_codes,
            "task_id": str(task_id),
            "delivery_id": str(delivery_id),
            "assignment_id": None if assignment_id is None else str(assignment_id),
            **slots,
        }

    def _render_artifact_result(
        self,
        result: StoredResult,
        primary: ObjectRef,
        principal: Principal,
        *,
        selected_scope: Scope | None,
    ) -> dict[str, JsonValue]:
        with self.store.transaction() as read_txn:
            r_row = read_txn.db.execute(
                "SELECT task_id, owner_id, repo_id, checkout_id, artifact_id, revision, level, "
                "artifact_digest, record_digest FROM p_fixture_domain_artifact_results WHERE result_id = ?",
                (primary.id,),
            ).fetchone()
            if r_row is None or primary.revision != 1 or primary.id != result.result_id:
                raise BrainError(ErrorCode.NOT_FOUND, "not found")
            (
                task_id,
                owner_id,
                repo_id,
                checkout_id,
                artifact_id,
                revision,
                level,
                art_digest,
                stored_rec_digest,
            ) = r_row
            a_row = read_txn.db.execute(
                "SELECT kind, owner_id, repo_id, checkout_id, holder_id "
                "FROM p_fixture_domain_artifacts WHERE artifact_id = ? AND revision = ?",
                (str(artifact_id), int(revision)),
            ).fetchone()
            res_rows = read_txn.db.execute(
                "SELECT resource_name, encoding, blob_digest FROM p_fixture_domain_artifact_resources "
                "WHERE artifact_id = ? AND revision = ? AND level = ? ORDER BY position",
                (str(artifact_id), int(revision), str(level)),
            ).fetchall()

        expected_rec_digest = _artifact_record_digest(
            {
                "result_id": result.result_id,
                "task_id": str(task_id),
                "owner_id": str(owner_id),
                "repo_id": str(repo_id),
                "checkout_id": str(checkout_id),
                "artifact_id": str(artifact_id),
                "revision": int(revision),
                "level": str(level),
                "artifact_digest": str(art_digest),
            }
        )
        if expected_rec_digest != str(stored_rec_digest) or expected_rec_digest != primary.digest:
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
        req_scope = Scope(str(repo_id), str(checkout_id))
        if (
            str(owner_id) != principal.owner_id
            or selected_scope is None
            or selected_scope != req_scope
            or not self.policy.allows(principal, req_scope, action="get_artifact")
        ):
            raise BrainError(ErrorCode.NOT_FOUND, "not found")

        auth_snap = self.policy.snapshot()
        pview = self._policy_view()
        if a_row is None or not res_rows:
            return {
                "artifact_id": str(artifact_id),
                "revision": int(revision),
                "level": str(level),
                "status": "redacted",
                "reason": REDACTED_REASON_DEFAULT,
                "resources": [],
            }
        a_kind, a_owner, a_repo, a_chk, holder_id = a_row
        redacted = (
            pview.is_tombstoned("event", str(holder_id))
            or self._item_is_redacted(
                principal=principal,
                effective_scope=req_scope,
                auth_snap=auth_snap,
                pview=pview,
                ref_kind=str(a_kind),
                ref_id=str(artifact_id),
                ref_digest=str(art_digest),
                ref_owner=str(a_owner),
                ref_repo=None if a_repo is None else str(a_repo),
                ref_checkout=None if a_chk is None else str(a_chk),
            )
            or any(pview.is_quarantined(str(b_dig)) for _name, _enc, b_dig in res_rows)
        )
        if redacted:
            return {
                "artifact_id": str(artifact_id),
                "revision": int(revision),
                "level": str(level),
                "status": "redacted",
                "reason": REDACTED_REASON_DEFAULT,
                "resources": [],
            }

        rendered_resources: list[JsonValue] = []
        for r_name, r_enc, b_dig in res_rows:
            raw_bytes = self.store.cas.read(str(b_dig))
            text_val = (
                raw_bytes.decode("utf-8") if str(r_enc) == "utf-8" else base64.b64encode(raw_bytes).decode("ascii")
            )
            rendered_resources.append(
                {
                    "name": str(r_name),
                    "digest": str(b_dig),
                    "encoding": str(r_enc),
                    "content": text_val,
                }
            )
        return {
            "artifact_id": str(artifact_id),
            "revision": int(revision),
            "level": str(level),
            "status": "ok",
            "resources": rendered_resources,
        }

    def _render_outcome_result(
        self,
        result: StoredResult,
        primary: ObjectRef,
        principal: Principal,
        *,
        selected_scope: Scope | None,
    ) -> dict[str, JsonValue]:
        with self.store.transaction() as read_txn:
            row = read_txn.db.execute(
                "SELECT result_id, outcome_id, delivery_id, task_id, owner_id, repo_id, checkout_id, "
                "outcome, applied_ref_count, record_digest FROM p_fixture_domain_outcomes WHERE outcome_id = ?",
                (primary.id,),
            ).fetchone()
        if row is None or primary.revision != 1:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        (
            rec_res_id,
            outcome_id,
            delivery_id,
            task_id,
            owner_id,
            repo_id,
            checkout_id,
            outcome,
            applied_count,
            stored_digest,
        ) = row
        expected_digest = _outcome_record_digest(
            {
                "result_id": str(rec_res_id),
                "outcome_id": str(outcome_id),
                "delivery_id": str(delivery_id),
                "task_id": str(task_id),
                "owner_id": str(owner_id),
                "repo_id": str(repo_id),
                "checkout_id": str(checkout_id),
                "outcome": str(outcome),
                "applied_ref_count": int(applied_count),
            }
        )
        if (
            str(rec_res_id) != result.result_id
            or expected_digest != str(stored_digest)
            or expected_digest != primary.digest
        ):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
        req_scope = Scope(str(repo_id), str(checkout_id))
        if (
            str(owner_id) != principal.owner_id
            or (selected_scope is not None and selected_scope != req_scope)
            or not self.policy.allows(principal, req_scope, action="record_outcome")
        ):
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        return {"outcome_id": str(outcome_id), "status": "declared"}

    def _item_is_redacted(
        self,
        *,
        principal: Principal,
        effective_scope: Scope,
        auth_snap: object,
        pview: PolicyView,
        ref_kind: str,
        ref_id: str,
        ref_digest: str,
        ref_owner: str,
        ref_repo: str | None,
        ref_checkout: str | None,
    ) -> bool:
        from superbrain.core.kernel import AuthSnapshot
        from superbrain.storage.kinds import is_uuid

        assert isinstance(auth_snap, AuthSnapshot)
        if ref_owner != principal.owner_id:
            return True
        if pview.is_quarantined(ref_digest):
            return True
        if is_uuid(ref_id) and (pview.is_tombstoned("event", ref_id) or pview.is_tombstoned(ref_kind, ref_id)):
            return True
        if ref_repo is not None:
            if (principal.principal_id, ref_repo) not in auth_snap.grants:
                return True
            repo_pol = auth_snap.repo_policies.get(ref_repo)
            if repo_pol is None or repo_pol.owner_id != principal.owner_id:
                return True
            if ref_checkout is not None:
                if ref_repo != effective_scope.repo_id or ref_checkout != effective_scope.checkout_id:
                    return True
                chk = auth_snap.checkouts.get(ref_checkout)
                if chk is None or chk.machine_id != principal.machine_id or chk.repo_id != ref_repo:
                    return True
        return False

    def _policy_view(self) -> PolicyView:
        return cast(PolicyView, self.policy)
