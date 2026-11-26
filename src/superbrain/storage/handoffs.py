"""SP2-4 durable storage adapter for task handoffs, immutable revision headers, deliveries & episodes."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timedelta

from superbrain.core._kernel_base import (
    require_non_negative_int,
    require_opaque_id,
    require_positive_int,
    require_sha256_digest,
)
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import Scope, SendAttemptState, require_aware_utc
from superbrain.ports._handoff_types import (
    HandoffAgentState,
    HandoffFence,
    HandoffPatch,
    HandoffRevisionHeader,
    ResolvedSourceContent,
)
from superbrain.ports.continuity import SessionState, decide_session_liveness
from superbrain.ports.handoff import (
    ArtifactGetRecord,
    CreateWorkTaskResult,
    DeliveryOutcomeRecord,
    DiscoverEntry,
    EpisodeOutcomeRecord,
    HandoffContentBundle,
    HandoffHeaderState,
    HandoffMutationOutcome,
    HandoffStorePort,
    ResumeRefSpec,
    SeenHandoffSpec,
)
from superbrain.ports.kernel import KernelTx
from superbrain.storage._restore_epoch import read_restore_epoch
from superbrain.storage._sessions_sources import live_event_record
from superbrain.storage._sessions_sql import parse_iso_utc
from superbrain.storage.cas import HOLDERS_TABLE, read_held_blob_or_none
from superbrain.storage.kinds import RetentionClass, is_uuid
from superbrain.storage.ledger import Txn, utc_timestamp
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.send_attempts import read_send_attempt_row
from superbrain.storage.sessions import SessionStore
from superbrain.storage.store import Store

_EVENT_RETENTION = timedelta(days=90)
_DISCOVER_WINDOW = timedelta(days=14)


def _txn_of(tx: object) -> Txn:
    txn = getattr(tx, "_txn", None)
    if not isinstance(txn, Txn):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "expected StoreKernelTx transaction")
    return txn


def _insert_episode_evidence(
    db: sqlite3.Connection,
    *,
    episode_id: str,
    task_id: str,
    evidence_held: Sequence[tuple[str, str, str]],
    stamp: str,
) -> None:
    """Insert ``episode_evidence`` child rows after the parent ``episodes`` row exists."""
    for idx, (ev_id, ev_dig, ev_hid) in enumerate(evidence_held):
        db.execute(
            "INSERT INTO episode_evidence "
            "(evidence_id, episode_id, task_id, idx, digest, cas_holder_id, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (ev_id, episode_id, task_id, idx, ev_dig, ev_hid, stamp),
        )


def _require_v8_ready(store: Store, policy: PolicyStore) -> int:
    store._check()
    policy._check()
    if store.schema_version < 8 or policy.schema_version < 5:
        raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")
    return read_restore_epoch(store.root, schema_version=store.schema_version, os_=store._os)


def _check_blob_status(
    db: sqlite3.Connection,
    store: Store,
    policy: PolicyStore,
    digest: str,
    *,
    holder_id: str | None,
    now: datetime,
) -> tuple[bytes | None, str]:
    """Return ``(bytes, 'ok')`` or ``(None, 'quarantined'|'tombstoned'|'expired')`` fail-closed."""
    if policy.is_quarantined(digest):
        return None, "quarantined"
    if holder_id is not None and is_uuid(holder_id):
        if policy.is_tombstoned("event", holder_id):
            return None, "tombstoned"
        data = read_held_blob_or_none(
            db,
            store.cas,
            policy,
            digest,
            holder_kind="event",
            holder_id=holder_id,
            now=now,
        )
        if data is None:
            return None, "expired"
        return data, "ok"

    cutoff = utc_timestamp(now)
    rows = db.execute(
        f"SELECT holder_id, retention_class, expires_at FROM {HOLDERS_TABLE} "
        "WHERE holder_kind = 'event' AND digest = ?",
        (digest,),
    ).fetchall()
    has_live_hold = False
    saw_tombstoned = False
    for hid_raw, ret_raw, exp_raw in rows:
        hid = str(hid_raw)
        if policy.is_tombstoned("event", hid):
            saw_tombstoned = True
            continue
        if str(ret_raw) == RetentionClass.DURABLE.value or exp_raw is None or str(exp_raw) > cutoff:
            has_live_hold = True
            break
    if not has_live_hold:
        return None, "tombstoned" if saw_tombstoned else "expired"
    if not store.cas.blob_intact(digest):
        return None, "expired"
    return store.cas.read(digest), "ok"


def _req_int(val: object) -> int:
    if type(val) is not int:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "expected integer column value")
    return val


def _row_to_header(row: Sequence[object], *, live_restore_epoch: int) -> HandoffHeaderState:
    return HandoffHeaderState(
        task_id=str(row[0]),
        artifact_id=str(row[1]),
        repo_id=str(row[2]),
        checkout_id=str(row[3]),
        revision=_req_int(row[4]),
        revision_epoch=_req_int(row[5]),
        handoff_revision=_req_int(row[6]),
        writer_generation=_req_int(row[7]),
        holder_principal=None if row[8] is None else str(row[8]),
        holder_session_ref=None if row[9] is None else str(row[9]),
        holder_restore_epoch=_req_int(row[10]),
        live_restore_epoch=live_restore_epoch,
        task_state=str(row[11]),
        task_state_source=str(row[12]),
        goal_ref=None if row[13] is None else str(row[13]),
        agent_ref=None if row[14] is None else str(row[14]),
        observed_ref=None if row[15] is None else str(row[15]),
        l0_summary_ref=None if row[16] is None else str(row[16]),
        agent_updated_at=None if row[17] is None else str(row[17]),
        observed_through=None if row[18] is None else str(row[18]),
    )


_HEADER_SQL = (
    "SELECT h.task_id, h.artifact_id, h.repo_id, h.checkout_id, h.current_revision, h.current_revision_epoch, "
    "h.handoff_revision, h.writer_generation, h.holder_principal, h.holder_session_ref, h.holder_restore_epoch, "
    "h.task_state, h.task_state_source, COALESCE(h.goal_ref, t.goal_ref), h.agent_ref, h.observed_ref, "
    "h.l0_summary_ref, h.agent_updated_at, h.observed_through "
    "FROM task_handoffs AS h JOIN tasks AS t ON t.task_id = h.task_id "
)


class HandoffStore(HandoffStorePort):
    """Durable SP2-4 handoff, immutable revision header, delivery, and episode store over ``store v8``."""

    def __init__(self, store: Store, policy: PolicyStore) -> None:
        self._store = store
        self._policy = policy

    def read_header(self, task_id: str, *, principal_id: str, scope: Scope) -> HandoffHeaderState | None:
        live_epoch = _require_v8_ready(self._store, self._policy)
        require_opaque_id(task_id, label="task_id")
        require_opaque_id(principal_id, label="principal_id")
        if scope.checkout_id is None:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        row = self._store._db.execute(_HEADER_SQL + "WHERE h.task_id = ?", (task_id,)).fetchone()
        if row is None:
            return None
        hdr = _row_to_header(row, live_restore_epoch=live_epoch)
        if hdr.repo_id != scope.repo_id or hdr.checkout_id != scope.checkout_id:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        return hdr

    def read_header_by_artifact(
        self,
        artifact_id: str,
        *,
        task_id: str,
        scope: Scope,
    ) -> HandoffHeaderState:
        live_epoch = _require_v8_ready(self._store, self._policy)
        require_opaque_id(artifact_id, label="artifact_id")
        require_opaque_id(task_id, label="task_id")
        if scope.checkout_id is None:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        row = self._store._db.execute(
            _HEADER_SQL + "WHERE h.artifact_id = ? AND h.task_id = ?",
            (artifact_id, task_id),
        ).fetchone()
        if row is None:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        hdr = _row_to_header(row, live_restore_epoch=live_epoch)
        if hdr.repo_id != scope.repo_id or hdr.checkout_id != scope.checkout_id:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        return hdr

    def read_revision_header(
        self,
        *,
        artifact_id: str,
        revision_epoch: int,
        revision: int,
        principal_id: str,
        scope: Scope,
    ) -> HandoffRevisionHeader | None:
        _require_v8_ready(self._store, self._policy)
        require_opaque_id(artifact_id, label="artifact_id")
        require_non_negative_int(revision_epoch)
        require_positive_int(revision)
        require_opaque_id(principal_id, label="principal_id")
        if scope.checkout_id is None:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        row = self._store._db.execute(
            "SELECT r.artifact_id, r.revision_epoch, r.revision, r.handoff_revision, r.task_id, r.task_state, "
            "r.task_state_source, r.holder_restore_epoch, r.writer_generation, r.holder_harness_id, "
            "r.holder_principal, r.holder_session_ref, r.session_state, r.agent_ref, r.observed_ref, "
            "r.agent_updated_at, r.observed_through, t.repo_id, t.checkout_id "
            "FROM handoff_revision_headers AS r JOIN tasks AS t ON t.task_id = r.task_id "
            "WHERE r.artifact_id = ? AND r.revision_epoch = ? AND r.revision = ?",
            (artifact_id, revision_epoch, revision),
        ).fetchone()
        if row is None or str(row[17]) != scope.repo_id or str(row[18]) != scope.checkout_id:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        return HandoffRevisionHeader(
            artifact_id=str(row[0]),
            revision_epoch=int(row[1]),
            revision=int(row[2]),
            handoff_revision=int(row[3]),
            task_id=str(row[4]),
            task_state=str(row[5]),
            task_state_source=str(row[6]),
            fence=HandoffFence(restore_epoch=int(row[7]), writer_generation=int(row[8])),
            holder_harness_id=None if row[9] is None else str(row[9]),
            holder_principal=None if row[10] is None else str(row[10]),
            holder_session_ref=None if row[11] is None else str(row[11]),
            session_state=None if row[12] is None else str(row[12]),
            agent_ref=None if row[13] is None else str(row[13]),
            observed_ref=None if row[14] is None else str(row[14]),
            agent_updated_at=None if row[15] is None else str(row[15]),
            observed_through=None if row[16] is None else str(row[16]),
        )

    def has_open_handoffs(self, *, owner_id: str, repo_id: str, checkout_id: str) -> bool:
        _require_v8_ready(self._store, self._policy)
        row = self._store._db.execute(
            "SELECT 1 FROM task_handoffs AS h JOIN tasks AS t ON t.task_id = h.task_id "
            "WHERE t.owner_id = ? AND t.repo_id = ? AND t.checkout_id = ? "
            "AND h.task_state IN ('open', 'in_progress') AND h.current_revision >= 1 LIMIT 1",
            (owner_id, repo_id, checkout_id),
        ).fetchone()
        return row is not None

    def list_discover(
        self,
        *,
        principal_id: str,
        owner_id: str,
        repo_id: str,
        checkout_id: str,
        task_id: str | None = None,
        now: datetime,
        render_l0: Callable[..., str] | None = None,
    ) -> tuple[DiscoverEntry, ...]:
        _require_v8_ready(self._store, self._policy)
        require_opaque_id(principal_id, label="principal_id")
        require_opaque_id(owner_id, label="owner_id")
        require_opaque_id(repo_id, label="repo_id")
        require_opaque_id(checkout_id, label="checkout_id")
        now_utc, _ = require_aware_utc(now)
        cutoff = utc_timestamp(now_utc - _DISCOVER_WINDOW)

        if task_id is not None:
            require_opaque_id(task_id, label="task_id")
            rows = self._store._db.execute(
                "SELECT h.task_id, h.artifact_id, h.current_revision_epoch, h.current_revision, "
                "h.handoff_revision, COALESCE(h.goal_ref, t.goal_ref), t.goal_holder_id, h.agent_ref, "
                "h.agent_holder_id, h.holder_session_ref, h.agent_updated_at, h.observed_through "
                "FROM task_handoffs AS h JOIN tasks AS t ON t.task_id = h.task_id "
                "WHERE t.task_id = ? AND t.owner_id = ? AND t.repo_id = ? AND t.checkout_id = ? "
                "AND h.current_revision >= 1",
                (task_id, owner_id, repo_id, checkout_id),
            ).fetchall()
        else:
            rows = self._store._db.execute(
                "SELECT h.task_id, h.artifact_id, h.current_revision_epoch, h.current_revision, "
                "h.handoff_revision, COALESCE(h.goal_ref, t.goal_ref), t.goal_holder_id, h.agent_ref, "
                "h.agent_holder_id, h.holder_session_ref, h.agent_updated_at, h.observed_through "
                "FROM task_handoffs AS h JOIN tasks AS t ON t.task_id = h.task_id "
                "WHERE t.owner_id = ? AND t.repo_id = ? AND t.checkout_id = ? "
                "AND h.task_state IN ('open', 'in_progress') "
                "AND COALESCE(NULLIF(h.updated_at, ''), t.updated_at) >= ? AND h.current_revision >= 1 "
                "ORDER BY COALESCE(NULLIF(h.updated_at, ''), t.updated_at) DESC, t.task_id ASC LIMIT 3",
                (owner_id, repo_id, checkout_id, cutoff),
            ).fetchall()

        out: list[DiscoverEntry] = []
        for row in rows:
            tid, art_id = str(row[0]), str(row[1])
            rev_epoch, rev, hrev = int(row[2]), int(row[3]), int(row[4])
            goal_ref = None if row[5] is None else str(row[5])
            goal_hid = None if row[6] is None else str(row[6])
            agent_ref = None if row[7] is None else str(row[7])
            agent_hid = None if row[8] is None else str(row[8])
            holder_sref = None if row[9] is None else str(row[9])
            agent_at = None if row[10] is None else str(row[10])
            obs_through = None if row[11] is None else str(row[11])

            task_goal = ""
            if goal_ref is not None:
                gbytes, gstatus = _check_blob_status(
                    self._store._db,
                    self._store,
                    self._policy,
                    goal_ref,
                    holder_id=goal_hid,
                    now=now_utc,
                )
                if gstatus != "ok" or gbytes is None:
                    out.append(
                        DiscoverEntry(
                            task_id=tid,
                            artifact_id=art_id,
                            revision_epoch=rev_epoch,
                            revision=rev,
                            digest=agent_ref or goal_ref,
                            summary="",
                            status="redacted",
                            reason=gstatus,
                        )
                    )
                    continue
                task_goal = gbytes.decode("utf-8", errors="replace")

            agent_state: HandoffAgentState | None = None
            if agent_ref is not None:
                abytes, astatus = _check_blob_status(
                    self._store._db,
                    self._store,
                    self._policy,
                    agent_ref,
                    holder_id=agent_hid,
                    now=now_utc,
                )
                if astatus != "ok" or abytes is None:
                    out.append(
                        DiscoverEntry(
                            task_id=tid,
                            artifact_id=art_id,
                            revision_epoch=rev_epoch,
                            revision=rev,
                            digest=agent_ref,
                            summary="",
                            status="redacted",
                            reason=astatus,
                        )
                    )
                    continue
                agent_state = HandoffAgentState.from_dict(json.loads(abytes.decode("utf-8")))

            sess_state: str | None = None
            other_active = False
            if holder_sref is not None:
                srow = self._store._db.execute(
                    "SELECT state, last_event_at FROM sessions WHERE session_ref = ?",
                    (holder_sref,),
                ).fetchone()
                if srow is not None:
                    sess_state = decide_session_liveness(
                        recorded_state=SessionState(str(srow[0])),
                        last_event_at=parse_iso_utc(str(srow[1])),
                        now=now_utc,
                    ).state.value
                other_row = self._store._db.execute(
                    "SELECT 1 FROM sessions WHERE repo_id = ? AND checkout_id = ? AND state = 'active' "
                    "AND session_ref != ? LIMIT 1",
                    (repo_id, checkout_id, holder_sref),
                ).fetchone()
                other_active = other_row is not None

            if render_l0 is not None:
                summary = render_l0(
                    task_goal=task_goal,
                    state=agent_state,
                    handoff_revision=hrev,
                    session_state=sess_state,
                    agent_updated_at=agent_at,
                    observed_through=obs_through,
                    other_active_warning=other_active,
                )
            else:
                summary = (task_goal or "")[:200]
            out.append(
                DiscoverEntry(
                    task_id=tid,
                    artifact_id=art_id,
                    revision_epoch=rev_epoch,
                    revision=rev,
                    digest=agent_ref or goal_ref or digest_bytes(summary.encode("utf-8")),
                    summary=summary,
                    status="ok",
                )
            )
        return tuple(out)

    def create_work_task(
        self,
        *,
        task_id: str,
        owner_id: str,
        repo_id: str,
        checkout_id: str,
        principal_id: str,
        session_ref: str | None,
        description: str,
        delivery_id: str,
        now: datetime,
    ) -> CreateWorkTaskResult:
        live_epoch = _require_v8_ready(self._store, self._policy)
        goal_bytes = description.encode("utf-8")
        self._store.cas.put(goal_bytes)
        goal_holder_id = new_id()
        with self._store.transaction() as txn:
            goal_digest = digest_bytes(goal_bytes)
            txn.hold(goal_digest, "event", goal_holder_id, RetentionClass.DURABLE, None)
            return self._apply_create_work_task_in_tx(
                txn.db,
                live_epoch=live_epoch,
                task_id=task_id,
                owner_id=owner_id,
                repo_id=repo_id,
                checkout_id=checkout_id,
                principal_id=principal_id,
                session_ref=session_ref,
                goal_digest=goal_digest,
                goal_holder_id=goal_holder_id,
                delivery_id=delivery_id,
                now=now,
            )

    def tx_create_work_task(
        self,
        tx: KernelTx,
        *,
        task_id: str,
        owner_id: str,
        repo_id: str,
        checkout_id: str,
        principal_id: str,
        session_ref: str | None,
        goal_bytes: bytes | None,
        delivery_id: str,
        now: datetime,
    ) -> CreateWorkTaskResult:
        live_epoch = _require_v8_ready(self._store, self._policy)
        goal_holder_id: str | None = None
        goal_digest: str | None = None
        if goal_bytes is not None:
            goal_holder_id = new_id()
            goal_digest = tx.hold_blob(goal_bytes, holder_id=goal_holder_id)
        return self._apply_create_work_task_in_tx(
            _txn_of(tx).db,
            live_epoch=live_epoch,
            task_id=task_id,
            owner_id=owner_id,
            repo_id=repo_id,
            checkout_id=checkout_id,
            principal_id=principal_id,
            session_ref=session_ref,
            goal_digest=goal_digest,
            goal_holder_id=goal_holder_id,
            delivery_id=delivery_id,
            now=now,
        )

    def _apply_create_work_task_in_tx(
        self,
        db: sqlite3.Connection,
        *,
        live_epoch: int,
        task_id: str,
        owner_id: str,
        repo_id: str,
        checkout_id: str,
        principal_id: str,
        session_ref: str | None,
        goal_digest: str | None,
        goal_holder_id: str | None,
        delivery_id: str,
        now: datetime,
    ) -> CreateWorkTaskResult:
        require_opaque_id(task_id, label="task_id")
        require_opaque_id(owner_id, label="owner_id")
        require_opaque_id(repo_id, label="repo_id")
        require_opaque_id(checkout_id, label="checkout_id")
        require_opaque_id(principal_id, label="principal_id")
        if session_ref is not None:
            require_sha256_digest(session_ref)
        if goal_digest is not None:
            require_sha256_digest(goal_digest)
        require_opaque_id(delivery_id, label="delivery_id")
        now_utc, _ = require_aware_utc(now)
        stamp = utc_timestamp(now_utc)
        artifact_id = task_id

        db.execute(
            "INSERT INTO tasks ("
            "task_id, owner_id, repo_id, checkout_id, current_revision, current_revision_epoch, "
            "task_state, task_state_source, holder_principal, holder_session_ref, created_at, updated_at, "
            "goal_ref, goal_holder_id"
            ") VALUES (?, ?, ?, ?, 0, ?, 'open', 'agent', NULL, NULL, ?, ?, ?, ?)",
            (task_id, owner_id, repo_id, checkout_id, live_epoch, stamp, stamp, goal_digest, goal_holder_id),
        )
        db.execute(
            "INSERT INTO task_handoffs ("
            "task_id, artifact_id, repo_id, checkout_id, current_revision, current_revision_epoch, "
            "handoff_revision, writer_generation, agent_ref, observed_ref, task_state, task_state_source, "
            "holder_principal, holder_session_ref, agent_updated_at, observed_through, "
            "holder_restore_epoch, goal_ref, goal_holder_id, agent_holder_id, l0_summary_ref, updated_at"
            ") VALUES (?, ?, ?, ?, 0, ?, 0, 0, NULL, NULL, 'open', 'agent', NULL, NULL, NULL, NULL, "
            "?, ?, ?, NULL, NULL, ?)",
            (task_id, artifact_id, repo_id, checkout_id, live_epoch, live_epoch, goal_digest, goal_holder_id, stamp),
        )
        return CreateWorkTaskResult(
            task_id=task_id,
            artifact_id=artifact_id,
            delivery_id=delivery_id,
            goal_digest=goal_digest or digest_bytes(b""),
            handoff_live=HandoffHeaderState(
                task_id=task_id,
                artifact_id=artifact_id,
                repo_id=repo_id,
                checkout_id=checkout_id,
                revision=0,
                revision_epoch=live_epoch,
                handoff_revision=0,
                writer_generation=0,
                holder_principal=None,
                holder_session_ref=None,
                holder_restore_epoch=live_epoch,
                live_restore_epoch=live_epoch,
                task_state="open",
                task_state_source="agent",
                goal_ref=goal_digest,
                agent_ref=None,
                observed_ref=None,
                l0_summary_ref=None,
                agent_updated_at=None,
                observed_through=None,
            ).handoff_live,
        )

    def _is_session_active(self, db: sqlite3.Connection, session_ref: str, *, now: datetime) -> bool:
        row = db.execute("SELECT state, last_event_at FROM sessions WHERE session_ref = ?", (session_ref,)).fetchone()
        if row is None:
            return False
        dec = decide_session_liveness(
            recorded_state=SessionState(str(row[0])),
            last_event_at=parse_iso_utc(str(row[1])),
            now=now,
        )
        return dec.state is SessionState.ACTIVE

    def commit_handoff_mutation(
        self,
        *,
        task_id: str,
        owner_id: str,
        repo_id: str,
        checkout_id: str,
        principal_id: str,
        harness_id: str,
        session_ref: str,
        episode_id: str,
        base_revision: int | None,
        expected_fence: HandoffFence | None,
        takeover: bool,
        takeover_acknowledge_active: bool,
        patch: HandoffPatch | None,
        raw_patch: JsonValue | None = None,
        evidence_digests: Sequence[tuple[str, bytes]],
        manual_submission_enabled: bool,
        now: datetime,
        apply_patch: Callable[[HandoffAgentState | None, HandoffPatch], HandoffAgentState] | None = None,
        validate_limits: (
            Callable[[HandoffAgentState | None, HandoffAgentState, Mapping[str, JsonValue]], None] | None
        ) = None,
    ) -> HandoffMutationOutcome:
        live_epoch = _require_v8_ready(self._store, self._policy)
        now_utc, _ = require_aware_utc(now)
        # Pre-compute agent_bytes outside tx when patching, then re-verify inside tx if concurrent check fails.
        staged_agent: tuple[bytes, str] | None = None
        if manual_submission_enabled and patch is not None:
            if apply_patch is None:
                raise BrainError(ErrorCode.INVALID_INPUT, "apply_patch callback required for handoff patch")
            cur = self.read_header(task_id, principal_id=principal_id, scope=Scope(repo_id, checkout_id))
            if cur is None:
                raise BrainError(ErrorCode.NOT_FOUND, "task not found")
            prev_state = self._load_agent_state_checked(cur, now=now_utc)
            next_state = apply_patch(prev_state, patch)
            if validate_limits is not None and isinstance(raw_patch, Mapping):
                validate_limits(prev_state, next_state, raw_patch)
            agent_bytes = canonical_json(next_state.to_dict())
            self._store.cas.put(agent_bytes)
            staged_agent = (agent_bytes, digest_bytes(agent_bytes))
        ev_tuples: list[tuple[str, str, bytes]] = []
        for ev_id, ev_bytes in evidence_digests:
            self._store.cas.put(ev_bytes)
            ev_tuples.append((ev_id, digest_bytes(ev_bytes), ev_bytes))
        with self._store.transaction() as txn:
            holder_id = new_id()
            if staged_agent is not None:
                txn.hold(staged_agent[1], "event", holder_id, RetentionClass.DURABLE, None)
            ev_held: list[tuple[str, str, str]] = []
            for ev_id, ev_dig, _ev_bytes in ev_tuples:
                ev_hid = new_id()
                txn.hold(ev_dig, "event", ev_hid, RetentionClass.DURABLE, None)
                ev_held.append((ev_id, ev_dig, ev_hid))
            return self._apply_handoff_mutation_in_tx(
                txn.db,
                live_epoch=live_epoch,
                task_id=task_id,
                owner_id=owner_id,
                repo_id=repo_id,
                checkout_id=checkout_id,
                principal_id=principal_id,
                harness_id=harness_id,
                session_ref=session_ref,
                episode_id=episode_id,
                base_revision=base_revision,
                expected_fence=expected_fence,
                takeover=takeover,
                takeover_acknowledge_active=takeover_acknowledge_active,
                has_patch=(patch is not None),
                new_agent_ref=None if staged_agent is None else staged_agent[1],
                new_agent_holder_id=None if staged_agent is None else holder_id,
                next_task_state=None if patch is None else next_state.task_state,
                evidence_held=ev_held,
                manual_submission_enabled=manual_submission_enabled,
                now=now_utc,
            )

    def _load_agent_state_checked(self, hdr: HandoffHeaderState, *, now: datetime) -> HandoffAgentState | None:
        if hdr.agent_ref is None:
            return None
        row = self._store._db.execute(
            "SELECT agent_holder_id FROM task_handoffs WHERE task_id = ?", (hdr.task_id,)
        ).fetchone()
        hid = None if row is None or row[0] is None else str(row[0])
        data, status = _check_blob_status(
            self._store._db, self._store, self._policy, hdr.agent_ref, holder_id=hid, now=now
        )
        if status != "ok" or data is None:
            raise BrainError(ErrorCode.NOT_FOUND, "handoff content unavailable")
        return HandoffAgentState.from_dict(json.loads(data.decode("utf-8")))

    def _apply_handoff_mutation_in_tx(
        self,
        db: sqlite3.Connection,
        *,
        live_epoch: int,
        task_id: str,
        owner_id: str,
        repo_id: str,
        checkout_id: str,
        principal_id: str,
        harness_id: str,
        session_ref: str,
        episode_id: str,
        base_revision: int | None,
        expected_fence: HandoffFence | None,
        takeover: bool,
        takeover_acknowledge_active: bool,
        has_patch: bool,
        new_agent_ref: str | None,
        new_agent_holder_id: str | None,
        next_task_state: str | None,
        evidence_held: Sequence[tuple[str, str, str]],
        manual_submission_enabled: bool,
        now: datetime,
    ) -> HandoffMutationOutcome:
        stamp = utc_timestamp(now)
        row = db.execute(_HEADER_SQL + "WHERE h.task_id = ?", (task_id,)).fetchone()
        if row is None:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        cur = _row_to_header(row, live_restore_epoch=live_epoch)
        if cur.repo_id != repo_id or cur.checkout_id != checkout_id:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")

        ev_ids = tuple(e[0] for e in evidence_held)

        if not manual_submission_enabled:
            db.execute(
                "INSERT INTO episodes ("
                "episode_id, task_id, owner_id, repo_id, checkout_id, principal_id, session_ref, "
                "has_handoff_op, handoff_status, handoff_artifact_id, committed_handoff_revision, "
                "committed_revision, committed_restore_epoch, committed_writer_generation, "
                "evidence_ids_json, created_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'not_stored_policy', ?, NULL, NULL, ?, ?, ?, ?)",
                (
                    episode_id,
                    task_id,
                    owner_id,
                    repo_id,
                    checkout_id,
                    principal_id,
                    session_ref,
                    1 if (has_patch or takeover) else 0,
                    cur.artifact_id,
                    cur.live_fence.restore_epoch,
                    cur.writer_generation,
                    canonical_json(list(ev_ids)).decode("utf-8"),
                    stamp,
                ),
            )
            _insert_episode_evidence(
                db, episode_id=episode_id, task_id=task_id, evidence_held=evidence_held, stamp=stamp
            )
            return HandoffMutationOutcome(
                episode_id=episode_id,
                evidence_ids=ev_ids,
                handoff_status="not_stored_policy",
                handoff_revision=None,
                revision=None,
                revision_epoch=None,
                fence=cur.live_fence,
                holder_principal=cur.holder_principal,
                holder_session_ref=cur.holder_session_ref,
            )

        if expected_fence is None or base_revision is None:
            raise BrainError(ErrorCode.INVALID_INPUT, "base_revision and fence required")
        if expected_fence != cur.live_fence or base_revision != cur.handoff_revision:
            raise BrainError(ErrorCode.REVISION_CONFLICT, "handoff revision or fence conflict")

        initial_claim = (
            cur.holder_principal is None
            and cur.holder_session_ref is None
            and cur.writer_generation == 0
            and cur.holder_restore_epoch == live_epoch
        )
        if not takeover and not initial_claim:
            if (
                cur.holder_principal != principal_id
                or cur.holder_session_ref != session_ref
                or cur.holder_restore_epoch != live_epoch
            ):
                raise BrainError(ErrorCode.REVISION_CONFLICT, "caller is not current handoff holder")
        elif takeover:
            if (
                cur.holder_session_ref is not None
                and cur.holder_session_ref != session_ref
                and self._is_session_active(db, cur.holder_session_ref, now=now)
                and not takeover_acknowledge_active
            ):
                raise BrainError(ErrorCode.INVALID_INPUT, "takeover requires acknowledge_active=true")

        next_rev = cur.revision + 1
        next_epoch = live_epoch
        next_hrev = (cur.handoff_revision + 1) if has_patch else cur.handoff_revision
        next_wgen = (cur.writer_generation + 1) if (takeover or initial_claim) else cur.writer_generation
        eff_agent_ref = new_agent_ref if has_patch else cur.agent_ref
        eff_task_state = (
            next_task_state if (has_patch and next_task_state is not None) else cur.task_state
        )
        eff_source = "agent" if (has_patch or cur.agent_ref is not None) else cur.task_state_source
        eff_agent_at = stamp if has_patch else cur.agent_updated_at
        take_from_p = cur.holder_principal if takeover else None
        take_from_s = cur.holder_session_ref if takeover else None

        if has_patch and new_agent_holder_id is not None:
            db.execute(
                "UPDATE task_handoffs SET agent_holder_id = ? WHERE task_id = ?",
                (new_agent_holder_id, task_id),
            )
            hdr_holder_id: str | None = new_agent_holder_id
        else:
            r_ah = db.execute("SELECT agent_holder_id FROM task_handoffs WHERE task_id = ?", (task_id,)).fetchone()
            hdr_holder_id = None if r_ah is None or r_ah[0] is None else str(r_ah[0])

        db.execute(
            "UPDATE task_handoffs SET current_revision = ?, current_revision_epoch = ?, handoff_revision = ?, "
            "writer_generation = ?, agent_ref = ?, task_state = ?, task_state_source = ?, holder_principal = ?, "
            "holder_session_ref = ?, holder_restore_epoch = ?, agent_updated_at = ?, "
            "takeover_from_principal = COALESCE(?, takeover_from_principal), "
            "takeover_from_session_ref = COALESCE(?, takeover_from_session_ref), updated_at = ? WHERE task_id = ?",
            (
                next_rev,
                next_epoch,
                next_hrev,
                next_wgen,
                eff_agent_ref,
                eff_task_state,
                eff_source,
                principal_id,
                session_ref,
                next_epoch,
                eff_agent_at,
                take_from_p,
                take_from_s,
                stamp,
                task_id,
            ),
        )
        db.execute(
            "UPDATE tasks SET current_revision = ?, current_revision_epoch = ?, task_state = ?, "
            "task_state_source = ?, holder_principal = ?, holder_session_ref = ?, updated_at = ? WHERE task_id = ?",
            (next_rev, next_epoch, eff_task_state, eff_source, principal_id, session_ref, stamp, task_id),
        )
        db.execute(
            "INSERT INTO handoff_revisions "
            "(task_id, handoff_revision, source_kind, agent_ref, observed_ref, recorded_at) "
            "VALUES (?, ?, 'agent', ?, ?, ?)",
            (task_id, next_hrev, eff_agent_ref, cur.observed_ref, stamp),
        )
        sess_state_str = "active" if self._is_session_active(db, session_ref, now=now) else "in_progress_unknown"
        db.execute(
            "INSERT INTO handoff_revision_headers ("
            "artifact_id, revision_epoch, revision, handoff_revision, task_id, task_state, task_state_source, "
            "holder_restore_epoch, writer_generation, holder_harness_id, holder_principal, holder_session_ref, "
            "session_state, agent_ref, agent_holder_id, observed_ref, agent_updated_at, observed_through, recorded_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                cur.artifact_id,
                next_epoch,
                next_rev,
                next_hrev,
                task_id,
                eff_task_state,
                eff_source,
                next_epoch,
                next_wgen,
                harness_id,
                principal_id,
                session_ref,
                sess_state_str,
                eff_agent_ref,
                hdr_holder_id,
                cur.observed_ref,
                eff_agent_at,
                cur.observed_through,
                stamp,
            ),
        )
        db.execute(
            "INSERT INTO episodes ("
            "episode_id, task_id, owner_id, repo_id, checkout_id, principal_id, session_ref, "
            "has_handoff_op, handoff_status, handoff_artifact_id, committed_handoff_revision, "
            "committed_revision, committed_restore_epoch, committed_writer_generation, evidence_ids_json, created_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, 1, 'stored', ?, ?, ?, ?, ?, ?, ?)",
            (
                episode_id,
                task_id,
                owner_id,
                repo_id,
                checkout_id,
                principal_id,
                session_ref,
                cur.artifact_id,
                next_hrev,
                next_rev,
                next_epoch,
                next_wgen,
                canonical_json(list(ev_ids)).decode("utf-8"),
                stamp,
            ),
        )
        _insert_episode_evidence(
            db, episode_id=episode_id, task_id=task_id, evidence_held=evidence_held, stamp=stamp
        )
        return HandoffMutationOutcome(
            episode_id=episode_id,
            evidence_ids=ev_ids,
            handoff_status="stored",
            handoff_revision=next_hrev,
            revision=next_rev,
            revision_epoch=next_epoch,
            fence=HandoffFence(restore_epoch=next_epoch, writer_generation=next_wgen),
            holder_principal=principal_id,
            holder_session_ref=session_ref,
        )

    def resolve_observed_sources(
        self,
        *,
        task_id: str,
        observed_ref: str | None,
        now: datetime,
    ) -> tuple[list[ResolvedSourceContent], list[ResolvedSourceContent]]:
        """Resolve observed event items & conversation excerpts live at read time (never cached in handoff)."""
        _require_v8_ready(self._store, self._policy)
        now_utc, _ = require_aware_utc(now)
        obs_items: list[ResolvedSourceContent] = []
        conv_items: list[ResolvedSourceContent] = []

        # Query linked events on this task to check quarantine/expiry individually.
        rows = self._store._db.execute(
            "SELECT producer_stream, sequence, event_id, kind, recorded_at, payload_digest "
            "FROM session_task_events WHERE task_id = ? ORDER BY event_order DESC LIMIT 64",
            (task_id,),
        ).fetchall()
        for stream, seq, eid, kind, rec_at, dig in rows:
            rec = live_event_record(
                self._store,
                self._policy,
                task_id=task_id,
                producer_stream=str(stream),
                sequence=int(seq),
                event_id=str(eid),
                payload_digest=str(dig),
                now=now_utc,
            )
            if rec is None:
                status = "redacted" if self._policy.is_quarantined(str(dig)) else "expired"
                content = ResolvedSourceContent(
                    source_event_id=str(eid),
                    source_digest=str(dig),
                    kind=str(kind),
                    status=status,
                    reason=status,
                    recorded_at=str(rec_at),
                )
            else:
                content = ResolvedSourceContent(
                    source_event_id=rec.event_id,
                    source_digest=str(dig),
                    kind=rec.kind,
                    status="ok",
                    payload=rec.payload,
                    recorded_at=rec.recorded_at,
                )
            if str(kind) in {"user_message", "user_prompt"}:
                conv_items.append(content)
            obs_items.append(content)
        _ = observed_ref
        return obs_items, conv_items

    def bind_session_for_episode(
        self,
        *,
        principal_id: str,
        repo_id: str,
        checkout_id: str,
        harness_id: str,
        raw_session_id: str,
        now: datetime,
    ) -> str:
        _require_v8_ready(self._store, self._policy)
        ss = SessionStore(self._store, self._policy)
        rec = ss.bind_session(
            principal_id=principal_id,
            repo_id=repo_id,
            checkout_id=checkout_id,
            harness_id=harness_id,
            raw_session_id=raw_session_id,
            now=now,
        )
        return rec.session_ref

    def resolve_task_scope(self, task_id: str, *, principal_id: str, scope: Scope) -> HandoffHeaderState:
        hdr = self.read_header(task_id, principal_id=principal_id, scope=scope)
        if hdr is None:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        return hdr

    def try_read_task_header_scoped(
        self,
        task_id: str,
        *,
        owner_id: str,
        selected_scope: Scope | None,
    ) -> HandoffHeaderState | None:
        live_epoch = _require_v8_ready(self._store, self._policy)
        require_opaque_id(task_id, label="task_id")
        require_opaque_id(owner_id, label="owner_id")
        row = self._store._db.execute(
            "SELECT h.task_id, h.artifact_id, h.repo_id, h.checkout_id, h.current_revision, "
            "h.current_revision_epoch, h.handoff_revision, h.writer_generation, h.holder_principal, "
            "h.holder_session_ref, h.holder_restore_epoch, h.task_state, h.task_state_source, "
            "COALESCE(h.goal_ref, t.goal_ref), h.agent_ref, h.observed_ref, h.l0_summary_ref, "
            "h.agent_updated_at, h.observed_through, t.owner_id "
            "FROM task_handoffs AS h JOIN tasks AS t ON t.task_id = h.task_id WHERE h.task_id = ?",
            (task_id,),
        ).fetchone()
        if row is None:
            return None
        row_owner = str(row[19])
        hdr = _row_to_header(row[:19], live_restore_epoch=live_epoch)
        if row_owner != owner_id:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        if selected_scope is not None:
            if hdr.repo_id != selected_scope.repo_id:
                raise BrainError(ErrorCode.NOT_FOUND, "not found")
            if selected_scope.checkout_id is not None and hdr.checkout_id != selected_scope.checkout_id:
                raise BrainError(ErrorCode.NOT_FOUND, "not found")
        return hdr

    def read_task_header_scoped(
        self,
        task_id: str,
        *,
        owner_id: str,
        selected_scope: Scope | None,
    ) -> HandoffHeaderState:
        hdr = self.try_read_task_header_scoped(task_id, owner_id=owner_id, selected_scope=selected_scope)
        if hdr is None:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        return hdr

    def resolve_artifact_revision_epoch(
        self,
        *,
        task_id: str,
        artifact_id: str,
        revision: int,
        revision_epoch: int | None,
        principal_id: str,
        scope: Scope,
    ) -> int:
        live_epoch = _require_v8_ready(self._store, self._policy)
        require_opaque_id(task_id, label="task_id")
        require_opaque_id(artifact_id, label="artifact_id")
        require_positive_int(revision)
        require_opaque_id(principal_id, label="principal_id")
        if scope.checkout_id is None:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        if revision_epoch is not None:
            require_non_negative_int(revision_epoch)
            hdr = self.read_revision_header(
                artifact_id=artifact_id,
                revision_epoch=revision_epoch,
                revision=revision,
                principal_id=principal_id,
                scope=scope,
            )
            if hdr is None or hdr.task_id != task_id:
                raise BrainError(ErrorCode.NOT_FOUND, "not found")
            return revision_epoch

        rows = self._store._db.execute(
            "SELECT r.revision_epoch, r.task_id, t.repo_id, t.checkout_id "
            "FROM handoff_revision_headers AS r JOIN tasks AS t ON t.task_id = r.task_id "
            "WHERE r.artifact_id = ? AND r.revision = ?",
            (artifact_id, revision),
        ).fetchall()
        scoped_epochs = [
            int(r[0])
            for r in rows
            if str(r[1]) == task_id and str(r[2]) == scope.repo_id and str(r[3]) == scope.checkout_id
        ]
        if not scoped_epochs:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        if live_epoch in scoped_epochs:
            return live_epoch
        if len(scoped_epochs) == 1:
            return scoped_epochs[0]
        raise BrainError(ErrorCode.INVALID_INPUT, "revision_epoch required after restore")

    def load_agent_state_scoped(
        self,
        *,
        task_id: str,
        principal_id: str,
        scope: Scope,
        now: datetime,
    ) -> HandoffAgentState | None:
        _require_v8_ready(self._store, self._policy)
        now_utc, _ = require_aware_utc(now)
        cur = self.resolve_task_scope(task_id, principal_id=principal_id, scope=scope)
        return self._load_agent_state_checked(cur, now=now_utc)

    def _validate_resume_in_tx(
        self,
        db: sqlite3.Connection,
        *,
        task_id: str,
        owner_id: str,
        repo_id: str,
        checkout_id: str,
        principal_id: str,
        live_fence: HandoffFence,
        resume_ref: ResumeRefSpec,
    ) -> tuple[str, int, int, str | None]:
        art_row = db.execute(
            "SELECT t.task_id, t.owner_id, t.repo_id, t.checkout_id "
            "FROM task_handoffs AS h JOIN tasks AS t ON t.task_id = h.task_id "
            "WHERE h.artifact_id = ?",
            (resume_ref.artifact_id,),
        ).fetchone()
        if (
            art_row is None
            or str(art_row[1]) != owner_id
            or str(art_row[2]) != repo_id
            or str(art_row[3]) != checkout_id
        ):
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        if str(art_row[0]) != task_id:
            raise BrainError(ErrorCode.INVALID_INPUT, "resume_ref does not belong to task_id")

        res_epoch: int | None = None
        if resume_ref.served_receipt_id is not None:
            attempt = read_send_attempt_row(db, resume_ref.served_receipt_id)
            if (
                attempt is None
                or attempt.principal_id != principal_id
                or attempt.task_id != task_id
                or attempt.state is SendAttemptState.UNKNOWN
            ):
                raise BrainError(ErrorCode.NOT_FOUND, "not found")
            if attempt.state is SendAttemptState.PENDING:
                raise BrainError(ErrorCode.IN_PROGRESS, "operation in progress")
            if attempt.artifact_id != resume_ref.artifact_id or attempt.revision != resume_ref.revision:
                raise BrainError(ErrorCode.INVALID_INPUT, "resume_ref mismatches served_receipt_id")
            res_epoch = attempt.revision_epoch
        else:
            cand_rows = db.execute(
                "SELECT revision_epoch FROM handoff_revision_headers WHERE artifact_id = ? AND revision = ?",
                (resume_ref.artifact_id, resume_ref.revision),
            ).fetchall()
            epochs = [int(r[0]) for r in cand_rows]
            if not epochs:
                raise BrainError(ErrorCode.NOT_FOUND, "not found")
            if resume_ref.fence.restore_epoch in epochs:
                res_epoch = resume_ref.fence.restore_epoch
            elif live_fence.restore_epoch in epochs:
                res_epoch = live_fence.restore_epoch
            elif len(epochs) == 1:
                res_epoch = epochs[0]
            else:
                raise BrainError(ErrorCode.INVALID_INPUT, "ambiguous resume_ref without served_receipt_id")

        hrow = db.execute(
            "SELECT handoff_revision, holder_restore_epoch, writer_generation "
            "FROM handoff_revision_headers WHERE artifact_id = ? AND revision_epoch = ? AND revision = ?",
            (resume_ref.artifact_id, res_epoch, resume_ref.revision),
        ).fetchone()
        if hrow is None:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        if int(hrow[0]) != resume_ref.handoff_revision:
            raise BrainError(ErrorCode.INVALID_INPUT, "resume_ref handoff_revision mismatch")
        hdr_fence = HandoffFence(restore_epoch=int(hrow[1]), writer_generation=int(hrow[2]))
        if resume_ref.fence not in (hdr_fence, live_fence):
            raise BrainError(ErrorCode.INVALID_INPUT, "resume_ref fence invalid")
        return resume_ref.artifact_id, res_epoch, resume_ref.revision, resume_ref.served_receipt_id

    def _validate_seen_refs_in_tx(
        self,
        db: sqlite3.Connection,
        *,
        owner_id: str,
        repo_id: str,
        checkout_id: str,
        seen_refs: Sequence[SeenHandoffSpec],
    ) -> None:
        for ref in seen_refs:
            row = db.execute(
                "SELECT r.agent_ref, COALESCE(h.goal_ref, t.goal_ref) "
                "FROM handoff_revision_headers AS r "
                "JOIN tasks AS t ON t.task_id = r.task_id "
                "JOIN task_handoffs AS h ON h.task_id = r.task_id "
                "WHERE r.artifact_id = ? AND r.revision_epoch = ? AND r.revision = ? "
                "AND t.owner_id = ? AND t.repo_id = ? AND t.checkout_id = ?",
                (ref.artifact_id, ref.revision_epoch, ref.revision, owner_id, repo_id, checkout_id),
            ).fetchone()
            if row is None:
                raise BrainError(ErrorCode.NOT_FOUND, "not found")
            agent_ref = None if row[0] is None else str(row[0])
            goal_ref = None if row[1] is None else str(row[1])
            allowed = {d for d in (agent_ref, goal_ref) if d is not None}
            if allowed and ref.digest not in allowed:
                raise BrainError(ErrorCode.INVALID_INPUT, "seen_handoff_refs digest mismatch")

    def tx_record_work_delivery(
        self,
        tx: KernelTx,
        *,
        delivery_id: str,
        task_id: str,
        owner_id: str,
        repo_id: str,
        checkout_id: str,
        principal_id: str,
        session_ref: str | None,
        description_bytes: bytes | None,
        create_task: bool,
        source_snapshot_id: str | None,
        snapshot_status: str,
        assignment_id: str | None,
        resume_ref: ResumeRefSpec | None,
        seen_handoff_refs: Sequence[SeenHandoffSpec],
        exposure_evidence: str,
        degraded_codes: Sequence[str],
        now: datetime,
    ) -> CreateWorkTaskResult:
        live_epoch = _require_v8_ready(self._store, self._policy)
        require_opaque_id(delivery_id, label="delivery_id")
        require_opaque_id(task_id, label="task_id")
        require_opaque_id(owner_id, label="owner_id")
        require_opaque_id(repo_id, label="repo_id")
        require_opaque_id(checkout_id, label="checkout_id")
        require_opaque_id(principal_id, label="principal_id")
        if session_ref is not None:
            require_sha256_digest(session_ref)
        now_utc, _ = require_aware_utc(now)
        stamp = utc_timestamp(now_utc)
        txn = _txn_of(tx)
        db = txn.db

        self._validate_seen_refs_in_tx(
            db, owner_id=owner_id, repo_id=repo_id, checkout_id=checkout_id, seen_refs=seen_handoff_refs
        )
        open_exist_row = db.execute(
            "SELECT 1 FROM task_handoffs AS h JOIN tasks AS t ON t.task_id = h.task_id "
            "WHERE t.owner_id = ? AND t.repo_id = ? AND t.checkout_id = ? "
            "AND h.task_state IN ('open', 'in_progress') AND h.current_revision >= 1 LIMIT 1",
            (owner_id, repo_id, checkout_id),
        ).fetchone()
        has_open_other = open_exist_row is not None

        res_art_id: str | None = None
        res_epoch: int | None = None
        res_rev: int | None = None
        res_receipt_id: str | None = None

        if create_task:
            if resume_ref is not None:
                raise BrainError(ErrorCode.NOT_FOUND, "not found")
            work_res = self.tx_create_work_task(
                tx,
                task_id=task_id,
                owner_id=owner_id,
                repo_id=repo_id,
                checkout_id=checkout_id,
                principal_id=principal_id,
                session_ref=session_ref,
                goal_bytes=description_bytes,
                delivery_id=delivery_id,
                now=now_utc,
            )
            eff_live = work_res.handoff_live
            goal_digest = work_res.goal_digest
            artifact_id = work_res.artifact_id
        else:
            row = db.execute(_HEADER_SQL + "WHERE h.task_id = ?", (task_id,)).fetchone()
            if row is None:
                raise BrainError(ErrorCode.NOT_FOUND, "not found")
            cur = _row_to_header(row, live_restore_epoch=live_epoch)
            if cur.repo_id != repo_id or cur.checkout_id != checkout_id:
                raise BrainError(ErrorCode.NOT_FOUND, "not found")
            towner_row = db.execute("SELECT owner_id FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
            if towner_row is None or str(towner_row[0]) != owner_id:
                raise BrainError(ErrorCode.NOT_FOUND, "not found")
            if resume_ref is not None:
                res_art_id, res_epoch, res_rev, res_receipt_id = self._validate_resume_in_tx(
                    db,
                    task_id=task_id,
                    owner_id=owner_id,
                    repo_id=repo_id,
                    checkout_id=checkout_id,
                    principal_id=principal_id,
                    live_fence=cur.live_fence,
                    resume_ref=resume_ref,
                )
            eff_live = cur.handoff_live
            goal_digest = cur.goal_ref or digest_bytes(b"")
            artifact_id = cur.artifact_id
            work_res = CreateWorkTaskResult(
                task_id=task_id,
                artifact_id=artifact_id,
                delivery_id=delivery_id,
                goal_digest=goal_digest,
                handoff_live=eff_live,
            )

        if resume_ref is not None:
            eff_exposure = "resumed"
        elif seen_handoff_refs:
            eff_exposure = "seen_l0"
        elif has_open_other:
            eff_exposure = "unreviewed_open_handoffs"
        else:
            eff_exposure = exposure_evidence or "none"

        served_ep = eff_live.revision_epoch
        served_rev = eff_live.revision
        served_dig: str | None = None
        if served_rev is not None:
            if not create_task:
                hrow_dig = db.execute(
                    "SELECT COALESCE(agent_ref, goal_ref) FROM task_handoffs WHERE task_id = ?", (task_id,)
                ).fetchone()
                if hrow_dig is not None and hrow_dig[0] is not None:
                    served_dig = str(hrow_dig[0])

        db.execute(
            "INSERT INTO deliveries ("
            "delivery_id, task_id, owner_id, repo_id, checkout_id, principal_id, session_ref, "
            "mode, source_snapshot_id, snapshot_status, assignment_id, "
            "resume_artifact_id, resume_revision_epoch, resume_revision, resume_receipt_id, "
            "exposure_evidence, degraded_codes_json, handoff_served_epoch, handoff_served_rev, "
            "handoff_served_digest, created_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, 'work', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                delivery_id,
                task_id,
                owner_id,
                repo_id,
                checkout_id,
                principal_id,
                session_ref,
                source_snapshot_id,
                snapshot_status,
                assignment_id,
                res_art_id,
                res_epoch,
                res_rev,
                res_receipt_id,
                eff_exposure,
                canonical_json(list(degraded_codes)).decode("utf-8"),
                served_ep,
                served_rev,
                served_dig,
                stamp,
            ),
        )
        for idx, ref in enumerate(seen_handoff_refs):
            db.execute(
                "INSERT INTO delivery_seen_handoffs "
                "(delivery_id, idx, artifact_id, revision_epoch, revision, digest) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (delivery_id, idx, ref.artifact_id, ref.revision_epoch, ref.revision, ref.digest),
            )
        return work_res

    def read_delivery_outcome(
        self,
        delivery_id: str,
        *,
        owner_id: str,
        principal_id: str,
        selected_scope: Scope | None,
    ) -> DeliveryOutcomeRecord:
        _require_v8_ready(self._store, self._policy)
        require_opaque_id(delivery_id, label="delivery_id")
        require_opaque_id(owner_id, label="owner_id")
        require_opaque_id(principal_id, label="principal_id")
        row = self._store._db.execute(
            "SELECT delivery_id, task_id, owner_id, repo_id, checkout_id, principal_id, session_ref, "
            "source_snapshot_id, snapshot_status, assignment_id, exposure_evidence, degraded_codes_json, "
            "resume_artifact_id, resume_revision_epoch, resume_revision, resume_receipt_id "
            "FROM deliveries WHERE delivery_id = ?",
            (delivery_id,),
        ).fetchone()
        if row is None or str(row[2]) != owner_id:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        if selected_scope is not None:
            if str(row[3]) != selected_scope.repo_id:
                raise BrainError(ErrorCode.NOT_FOUND, "not found")
            if selected_scope.checkout_id is not None and str(row[4]) != selected_scope.checkout_id:
                raise BrainError(ErrorCode.NOT_FOUND, "not found")
        raw_codes = json.loads(str(row[11]))
        codes = tuple(str(c) for c in raw_codes) if isinstance(raw_codes, list) else ()
        seen_rows = self._store._db.execute(
            "SELECT artifact_id, revision_epoch, revision, digest "
            "FROM delivery_seen_handoffs WHERE delivery_id = ? ORDER BY idx ASC",
            (delivery_id,),
        ).fetchall()
        seen_refs = tuple((str(r[0]), int(r[1]), int(r[2]), str(r[3])) for r in seen_rows)
        return DeliveryOutcomeRecord(
            delivery_id=str(row[0]),
            task_id=str(row[1]),
            owner_id=str(row[2]),
            repo_id=str(row[3]),
            checkout_id=str(row[4]),
            principal_id=str(row[5]),
            session_ref=None if row[6] is None else str(row[6]),
            source_snapshot_id=None if row[7] is None else str(row[7]),
            snapshot_status=str(row[8]),
            assignment_id=None if row[9] is None else str(row[9]),
            exposure_evidence=str(row[10]),
            degraded_codes=codes,
            resume_artifact_id=None if row[12] is None else str(row[12]),
            resume_revision_epoch=None if row[13] is None else int(row[13]),
            resume_revision=None if row[14] is None else int(row[14]),
            resume_receipt_id=None if row[15] is None else str(row[15]),
            seen_refs=seen_refs,
        )

    def tx_record_artifact_get(
        self,
        tx: KernelTx,
        *,
        result_id: str,
        task_id: str,
        artifact_id: str,
        revision_epoch: int,
        revision: int,
        level: str,
        owner_id: str,
        repo_id: str,
        checkout_id: str,
        principal_id: str,
        now: datetime,
    ) -> None:
        _require_v8_ready(self._store, self._policy)
        require_opaque_id(result_id, label="result_id")
        require_opaque_id(task_id, label="task_id")
        require_opaque_id(artifact_id, label="artifact_id")
        require_non_negative_int(revision_epoch)
        require_positive_int(revision)
        now_utc, _ = require_aware_utc(now)
        stamp = utc_timestamp(now_utc)
        db = _txn_of(tx).db
        row = db.execute(
            "SELECT r.task_id, t.owner_id, t.repo_id, t.checkout_id "
            "FROM handoff_revision_headers AS r JOIN tasks AS t ON t.task_id = r.task_id "
            "WHERE r.artifact_id = ? AND r.revision_epoch = ? AND r.revision = ?",
            (artifact_id, revision_epoch, revision),
        ).fetchone()
        if (
            row is None
            or str(row[0]) != task_id
            or str(row[1]) != owner_id
            or str(row[2]) != repo_id
            or str(row[3]) != checkout_id
        ):
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        db.execute(
            "INSERT INTO artifact_get_results ("
            "result_id, task_id, artifact_id, revision_epoch, revision, level, "
            "owner_id, repo_id, checkout_id, principal_id, created_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                result_id,
                task_id,
                artifact_id,
                revision_epoch,
                revision,
                level,
                owner_id,
                repo_id,
                checkout_id,
                principal_id,
                stamp,
            ),
        )

    def read_artifact_get(
        self,
        result_id: str,
        *,
        owner_id: str,
        principal_id: str,
        selected_scope: Scope | None,
    ) -> ArtifactGetRecord:
        _require_v8_ready(self._store, self._policy)
        require_opaque_id(result_id, label="result_id")
        require_opaque_id(owner_id, label="owner_id")
        require_opaque_id(principal_id, label="principal_id")
        row = self._store._db.execute(
            "SELECT result_id, task_id, artifact_id, revision_epoch, revision, level, "
            "owner_id, repo_id, checkout_id, principal_id "
            "FROM artifact_get_results WHERE result_id = ?",
            (result_id,),
        ).fetchone()
        if row is None or str(row[6]) != owner_id:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        if selected_scope is not None:
            if str(row[7]) != selected_scope.repo_id:
                raise BrainError(ErrorCode.NOT_FOUND, "not found")
            if selected_scope.checkout_id is not None and str(row[8]) != selected_scope.checkout_id:
                raise BrainError(ErrorCode.NOT_FOUND, "not found")
        return ArtifactGetRecord(
            result_id=str(row[0]),
            task_id=str(row[1]),
            artifact_id=str(row[2]),
            revision_epoch=int(row[3]),
            revision=int(row[4]),
            level=str(row[5]),
            owner_id=str(row[6]),
            repo_id=str(row[7]),
            checkout_id=str(row[8]),
            principal_id=str(row[9]),
        )

    def read_handoff_content_bundle(
        self,
        *,
        artifact_id: str,
        revision_epoch: int,
        revision: int,
        task_id: str,
        principal_id: str,
        scope: Scope,
        now: datetime,
    ) -> HandoffContentBundle:
        _require_v8_ready(self._store, self._policy)
        now_utc, _ = require_aware_utc(now)
        hdr = self.read_revision_header(
            artifact_id=artifact_id,
            revision_epoch=revision_epoch,
            revision=revision,
            principal_id=principal_id,
            scope=scope,
        )
        if hdr is None or hdr.task_id != task_id:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        live = self.resolve_task_scope(task_id, principal_id=principal_id, scope=scope)
        extra_row = self._store._db.execute(
            "SELECT r.agent_holder_id, t.goal_ref, t.goal_holder_id "
            "FROM handoff_revision_headers AS r JOIN tasks AS t ON t.task_id = r.task_id "
            "WHERE r.artifact_id = ? AND r.revision_epoch = ? AND r.revision = ?",
            (artifact_id, revision_epoch, revision),
        ).fetchone()
        if extra_row is None:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        agent_hid = None if extra_row[0] is None else str(extra_row[0])
        goal_ref = None if extra_row[1] is None else str(extra_row[1])
        goal_hid = None if extra_row[2] is None else str(extra_row[2])

        task_goal: str | None = ""
        goal_status = "ok"
        if goal_ref is not None:
            gbytes, gstatus = _check_blob_status(
                self._store._db,
                self._store,
                self._policy,
                goal_ref,
                holder_id=goal_hid,
                now=now_utc,
            )
            goal_status = gstatus
            if gstatus == "ok" and gbytes is not None:
                task_goal = gbytes.decode("utf-8", errors="replace")
            else:
                task_goal = None

        agent_state: HandoffAgentState | None = None
        agent_status = "ok"
        if hdr.agent_ref is not None:
            abytes, astatus = _check_blob_status(
                self._store._db,
                self._store,
                self._policy,
                hdr.agent_ref,
                holder_id=agent_hid,
                now=now_utc,
            )
            agent_status = astatus
            if astatus == "ok" and abytes is not None:
                agent_state = HandoffAgentState.from_dict(json.loads(abytes.decode("utf-8")))

        obs_items, conv_items = self.resolve_observed_sources(
            task_id=task_id, observed_ref=hdr.observed_ref, now=now_utc
        )

        sess_state = hdr.session_state
        holder_harness_id = hdr.holder_harness_id
        other_active = False
        if hdr.holder_session_ref is not None:
            srow = self._store._db.execute(
                "SELECT state, last_event_at, harness_id FROM sessions WHERE session_ref = ?",
                (hdr.holder_session_ref,),
            ).fetchone()
            if srow is not None:
                sess_state = decide_session_liveness(
                    recorded_state=SessionState(str(srow[0])),
                    last_event_at=parse_iso_utc(str(srow[1])),
                    now=now_utc,
                ).state.value
                if holder_harness_id is None:
                    holder_harness_id = str(srow[2])
            if scope.checkout_id is not None:
                orow = self._store._db.execute(
                    "SELECT 1 FROM sessions WHERE repo_id = ? AND checkout_id = ? AND state = 'active' "
                    "AND session_ref != ? LIMIT 1",
                    (scope.repo_id, scope.checkout_id, hdr.holder_session_ref),
                ).fetchone()
                other_active = orow is not None

        return HandoffContentBundle(
            header=hdr,
            live=live,
            task_goal=task_goal,
            goal_status=goal_status,
            agent_state=agent_state,
            agent_status=agent_status,
            observed_sources=tuple(obs_items),
            conversation_sources=tuple(conv_items),
            holder_harness_id=holder_harness_id,
            session_state=sess_state,
            other_active_warning=other_active,
        )

    def tx_commit_handoff_mutation(
        self,
        tx: KernelTx,
        *,
        task_id: str,
        owner_id: str,
        repo_id: str,
        checkout_id: str,
        principal_id: str,
        harness_id: str,
        session_ref: str,
        episode_id: str,
        base_revision: int | None,
        expected_fence: HandoffFence | None,
        takeover: bool,
        takeover_acknowledge_active: bool,
        has_patch: bool,
        new_agent_bytes: bytes | None,
        next_task_state: str | None,
        evidence_items: Sequence[tuple[str, bytes]],
        manual_submission_enabled: bool,
        now: datetime,
    ) -> HandoffMutationOutcome:
        live_epoch = _require_v8_ready(self._store, self._policy)
        now_utc, _ = require_aware_utc(now)
        stamp = utc_timestamp(now_utc)
        txn = _txn_of(tx)
        db = txn.db

        row = db.execute(_HEADER_SQL + "WHERE h.task_id = ?", (task_id,)).fetchone()
        if row is None:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        cur = _row_to_header(row, live_restore_epoch=live_epoch)
        if cur.repo_id != repo_id or cur.checkout_id != checkout_id:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")

        ev_held: list[tuple[str, str, str]] = []
        for ev_id, ev_bytes in evidence_items:
            ev_hid = new_id()
            ev_dig = tx.hold_blob(ev_bytes, holder_id=ev_hid)
            ev_held.append((ev_id, ev_dig, ev_hid))

        if not has_patch and not takeover:
            ev_ids = tuple(e[0] for e in ev_held)
            db.execute(
                "INSERT INTO episodes ("
                "episode_id, task_id, owner_id, repo_id, checkout_id, principal_id, session_ref, "
                "has_handoff_op, handoff_status, handoff_artifact_id, committed_handoff_revision, "
                "committed_revision, committed_restore_epoch, committed_writer_generation, "
                "evidence_ids_json, created_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, 0, NULL, NULL, NULL, NULL, NULL, NULL, ?, ?)",
                (
                    episode_id,
                    task_id,
                    owner_id,
                    repo_id,
                    checkout_id,
                    principal_id,
                    session_ref,
                    canonical_json(list(ev_ids)).decode("utf-8"),
                    stamp,
                ),
            )
            _insert_episode_evidence(
                db, episode_id=episode_id, task_id=task_id, evidence_held=ev_held, stamp=stamp
            )
            return HandoffMutationOutcome(
                episode_id=episode_id,
                evidence_ids=ev_ids,
                handoff_status="plain",
                handoff_revision=None,
                revision=None,
                revision_epoch=None,
                fence=cur.live_fence,
                holder_principal=cur.holder_principal,
                holder_session_ref=cur.holder_session_ref,
            )

        new_agent_ref: str | None = None
        new_agent_hid: str | None = None
        if manual_submission_enabled and has_patch:
            if new_agent_bytes is None:
                raise BrainError(ErrorCode.INVALID_INPUT, "new_agent_bytes required for patch")
            new_agent_hid = new_id()
            new_agent_ref = tx.hold_blob(new_agent_bytes, holder_id=new_agent_hid)

        return self._apply_handoff_mutation_in_tx(
            db,
            live_epoch=live_epoch,
            task_id=task_id,
            owner_id=owner_id,
            repo_id=repo_id,
            checkout_id=checkout_id,
            principal_id=principal_id,
            harness_id=harness_id,
            session_ref=session_ref,
            episode_id=episode_id,
            base_revision=base_revision,
            expected_fence=expected_fence,
            takeover=takeover,
            takeover_acknowledge_active=takeover_acknowledge_active,
            has_patch=has_patch,
            new_agent_ref=new_agent_ref,
            new_agent_holder_id=new_agent_hid,
            next_task_state=next_task_state,
            evidence_held=ev_held,
            manual_submission_enabled=manual_submission_enabled,
            now=now_utc,
        )

    def read_episode_outcome(
        self,
        episode_id: str,
        *,
        owner_id: str,
        principal_id: str,
        selected_scope: Scope | None,
    ) -> EpisodeOutcomeRecord:
        _require_v8_ready(self._store, self._policy)
        require_opaque_id(episode_id, label="episode_id")
        require_opaque_id(owner_id, label="owner_id")
        require_opaque_id(principal_id, label="principal_id")
        row = self._store._db.execute(
            "SELECT episode_id, task_id, owner_id, repo_id, checkout_id, principal_id, session_ref, "
            "has_handoff_op, handoff_status, handoff_artifact_id, committed_handoff_revision, "
            "committed_revision, committed_restore_epoch, committed_writer_generation, evidence_ids_json "
            "FROM episodes WHERE episode_id = ?",
            (episode_id,),
        ).fetchone()
        if row is None or str(row[2]) != owner_id:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        if selected_scope is not None:
            if str(row[3]) != selected_scope.repo_id:
                raise BrainError(ErrorCode.NOT_FOUND, "not found")
            if selected_scope.checkout_id is not None and str(row[4]) != selected_scope.checkout_id:
                raise BrainError(ErrorCode.NOT_FOUND, "not found")
        raw_ev = json.loads(str(row[14]))
        ev_ids = tuple(str(x) for x in raw_ev) if isinstance(raw_ev, list) else ()
        return EpisodeOutcomeRecord(
            episode_id=str(row[0]),
            task_id=str(row[1]),
            owner_id=str(row[2]),
            repo_id=str(row[3]),
            checkout_id=str(row[4]),
            principal_id=str(row[5]),
            session_ref=str(row[6]),
            has_handoff_op=bool(int(row[7])),
            handoff_status=None if row[8] is None else str(row[8]),
            handoff_artifact_id=None if row[9] is None else str(row[9]),
            committed_handoff_revision=None if row[10] is None else int(row[10]),
            committed_revision=None if row[11] is None else int(row[11]),
            committed_restore_epoch=None if row[12] is None else int(row[12]),
            committed_writer_generation=None if row[13] is None else int(row[13]),
            evidence_ids=ev_ids,
        )

    def read_live_holder_status(
        self,
        task_id: str,
        *,
        principal_id: str,
        session_ref: str,
        scope: Scope,
    ) -> tuple[bool, HandoffFence]:
        hdr = self.resolve_task_scope(task_id, principal_id=principal_id, scope=scope)
        is_holder = (
            hdr.holder_principal == principal_id
            and hdr.holder_session_ref == session_ref
            and hdr.holder_restore_epoch == hdr.live_restore_epoch
        )
        return is_holder, hdr.live_fence


__all__ = ["HandoffStore"]
