"""Fixture-only SubmitEpisode ingress through the real privacy filter and kernel transaction."""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from datetime import datetime

from superbrain.application.deadlines import begin_local_phase
from superbrain.application.dispatch import PreparedEffect
from superbrain.application.privacy import PrivacyFilter
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import Call, CallContext, KernelRecord, ObjectRef, Principal, Scope, StoredResult
from superbrain.ports.kernel import KernelTx
from superbrain.ports.policy import PolicyView
from superbrain.storage.kinds import EntryKind, FieldType, KindRegistry
from superbrain.storage.ledger import LedgerEntry, ProjectionHandler
from tests.support.inc2_kernel_domain import fixture_store_extensions
from tests.support.inc2_t8_domain import FixtureDomainProxy

EPISODE_KIND = "fixture.privacy_episode_recorded"
EPISODE_TABLE = "p_fixture_privacy_episodes"
_FIELDS = {
    "episode_id": FieldType.UUID,
    "owner_id": FieldType.OPAQUE_ID,
    "repo_id": FieldType.OPAQUE_ID,
    "checkout_id": FieldType.OPAQUE_ID,
    "task_id": FieldType.OPAQUE_ID,
    "evidence_id": FieldType.UUID,
    "content_digest": FieldType.DIGEST,
}


class PrivacyEpisodeProjection:
    name = "fixture_privacy"
    handler_version = 1
    kinds = frozenset({EPISODE_KIND})

    def create_tables(self, db: sqlite3.Connection, prefix: str) -> None:
        db.execute(
            f"CREATE TABLE {prefix}episodes ("
            "episode_id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, repo_id TEXT NOT NULL, checkout_id TEXT NOT NULL, "
            "task_id TEXT NOT NULL, evidence_id TEXT, content_digest TEXT, record_digest TEXT NOT NULL)"
        )

    def apply(self, db: sqlite3.Connection, prefix: str, entry: LedgerEntry, policy: PolicyView) -> None:
        values = tuple(entry.meta[key] for key in _FIELDS)
        db.execute(
            f"INSERT INTO {prefix}episodes VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (*values, digest_bytes(canonical_json(dict(entry.meta)))),
        )


def privacy_store_extensions() -> tuple[tuple[ProjectionHandler, ...], KindRegistry]:
    handlers, registry = fixture_store_extensions()
    episode_kind = EntryKind(
        EPISODE_KIND,
        handler_version=1,
        fields=_FIELDS,
        enums={},
        nullable=frozenset({"evidence_id", "content_digest"}),
    )
    return (*handlers, PrivacyEpisodeProjection()), KindRegistry(
        [*(registry.get(name) for name in registry.kinds()), episode_kind]
    )


def episode_args(task_id: str, key: str, evidence: Sequence[JsonValue]) -> dict[str, JsonValue]:
    return {
        "schema_version": "2.0",
        "task_id": task_id,
        "session_id": "fixture-privacy-session",
        "idempotency_key": key,
        "evidence": list(evidence),
    }


class PrivacyDomainProxy(FixtureDomainProxy):
    """Accepts fixture evidence only, with no production capture or external outbox capability."""

    def __init__(self) -> None:
        super().__init__()
        self.filtered_calls = 0
        self.outbox: dict[str, bytes] = {}

    def supports_tool(self, tool: str, *, deep: bool = False) -> bool:
        return tool == "submit_episode" or super().supports_tool(tool, deep=deep)

    def prepare_mutation(self, call: Call, ctx: CallContext, *, now: datetime) -> PreparedEffect:
        if call.tool != "submit_episode":
            return super().prepare_mutation(call, ctx, now=now)
        scope = call.selected_scope
        if scope is None or scope.checkout_id is None:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        task_id = str(call.arguments["task_id"])
        with self.inner.store.transaction() as txn:
            row = txn.db.execute(
                "SELECT 1 FROM p_fixture_domain_deliveries "
                "WHERE task_id = ? AND owner_id = ? AND repo_id = ? AND checkout_id = ?",
                (task_id, ctx.principal.owner_id, scope.repo_id, scope.checkout_id),
            ).fetchone()
        if row is None:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")

        local_deadline = begin_local_phase(self.monotonic_ns, ctx.deadline_ns, local_deadline_ns=ctx.local_deadline_ns)
        self.filtered_calls += 1
        filtered = PrivacyFilter(self.monotonic_ns).apply(
            dict(call.arguments), self.inner._filter_policy_for_repo(scope.repo_id), deadline_ns=local_deadline
        )
        assert isinstance(filtered.value, dict)
        evidence = filtered.value.get("evidence")
        payload = canonical_json(evidence) if evidence else None
        episode_id = new_id()
        meta: dict[str, JsonValue] = {
            "episode_id": episode_id,
            "owner_id": ctx.principal.owner_id,
            "repo_id": scope.repo_id,
            "checkout_id": scope.checkout_id,
            "task_id": task_id,
            "evidence_id": new_id() if payload is not None else None,
            "content_digest": digest_bytes(payload) if payload is not None else None,
        }
        ref = ObjectRef(kind="privacy_episode", id=episode_id, revision=1, digest=digest_bytes(canonical_json(meta)))

        def apply(tx: KernelTx) -> StoredResult:
            if payload is not None:
                tx.hold_blob(payload, holder_id=episode_id)
            tx.append_record(KernelRecord(EPISODE_KIND, meta))
            if payload is not None:
                self.outbox[episode_id] = payload
            return StoredResult(result_id=episode_id, assignment_id=None, refs=(ref,))

        return PreparedEffect(blobs=(payload,) if payload is not None else (), apply=apply)

    def render_stored(
        self, result: StoredResult, principal: Principal, *, selected_scope: Scope | None
    ) -> dict[str, JsonValue]:
        if not result.refs or result.refs[0].kind != "privacy_episode":
            return super().render_stored(result, principal, selected_scope=selected_scope)
        if selected_scope is None:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        ref = result.refs[0]
        with self.inner.store.transaction() as txn:
            row = txn.db.execute(
                f"SELECT evidence_id FROM {EPISODE_TABLE} "
                "WHERE episode_id = ? AND owner_id = ? AND repo_id = ? AND checkout_id = ? AND record_digest = ?",
                (ref.id, principal.owner_id, selected_scope.repo_id, selected_scope.checkout_id, ref.digest),
            ).fetchone()
        if row is None:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        return {"episode_id": ref.id, "evidence_ids": [] if row[0] is None else [str(row[0])]}
