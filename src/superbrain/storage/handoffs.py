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
from superbrain.storage._handoff_schema import max_task_event_order_in_tx, read_revision_events_since_agent_in_tx
from superbrain.storage._restore_epoch import read_restore_epoch
from superbrain.storage._sessions_sources import live_event_record
from superbrain.storage._sessions_sql import parse_iso_utc
from superbrain.storage.cas import HOLDERS_TABLE, read_held_blob_or_none
from superbrain.storage.kinds import RetentionClass, is_uuid
from superbrain.storage.ledger import Txn, utc_timestamp
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.send_attempts import read_read_ack_by_receipt_row, read_send_attempt_row
from superbrain.storage.sessions import SessionStore
from superbrain.storage.store import Store

_EVENT_RETENTION = timedelta(days=90)
_DISCOVER_WINDOW = timedelta(days=14)
_OPEN_HANDOFFS_PRESENT_CODE = "open_handoffs_present"
_OBSERVED_NEWER_CODE = "observed_newer"


def _unique_codes(codes: Sequence[str]) -> list[str]:
    """Deduplicate degraded codes while preserving insertion order."""
    out: list[str] = []
    seen: set[str] = set()
    for code in codes:
        if code not in seen:
            seen.add(code)
            out.append(code)
    return out


def _has_open_handoffs_in_db(
    db: sqlite3.Connection,
    *,
    owner_id: str,
    repo_id: str,
    checkout_id: str,
    cutoff: str | None = None,
    exclude_task_id: str | None = None,
) -> bool:
    clauses = [
        "t.owner_id = ?",
        "t.repo_id = ?",
        "t.checkout_id = ?",
        "h.task_state IN ('open', 'in_progress')",
        "h.current_revision >= 1",
    ]
    params: list[object] = [owner_id, repo_id, checkout_id]
    if exclude_task_id is not None:
        clauses.append("h.task_id != ?")
        params.append(exclude_task_id)
    if cutoff is not None:
        clauses.append("COALESCE(NULLIF(h.updated_at, ''), t.updated_at) >= ?")
        params.append(cutoff)
    sql = (
        "SELECT 1 FROM task_handoffs AS h JOIN tasks AS t ON t.task_id = h.task_id "
        f"WHERE {' AND '.join(clauses)} LIMIT 1"
    )
    return db.execute(sql, tuple(params)).fetchone() is not None


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


_REV_HDR_SELECT = (
    "SELECT r.artifact_id, r.revision_epoch, r.revision, r.handoff_revision, r.task_id, r.task_state, "
    "r.task_state_source, r.holder_restore_epoch, r.writer_generation, r.holder_harness_id, "
    "r.holder_principal, r.holder_session_ref, r.session_state, r.agent_ref, r.observed_ref, "
    "r.agent_updated_at, r.observed_through, t.repo_id, t.checkout_id, r.events_since_agent "
    "FROM handoff_revision_headers AS r JOIN tasks AS t ON t.task_id = r.task_id "
)


def _row_to_rev_header(row: Sequence[object]) -> HandoffRevisionHeader:
    return HandoffRevisionHeader(
        artifact_id=str(row[0]),
        revision_epoch=require_non_negative_int(row[1]),
        revision=require_positive_int(row[2]),
        handoff_revision=require_non_negative_int(row[3]),
        task_id=str(row[4]),
        task_state=str(row[5]),
        task_state_source=str(row[6]),
        fence=HandoffFence(
            restore_epoch=require_non_negative_int(row[7]),
            writer_generation=require_non_negative_int(row[8]),
        ),
        holder_harness_id=None if row[9] is None else str(row[9]),
        holder_principal=None if row[10] is None else str(row[10]),
        holder_session_ref=None if row[11] is None else str(row[11]),
        session_state=None if row[12] is None else str(row[12]),
        agent_ref=None if row[13] is None else str(row[13]),
        observed_ref=None if row[14] is None else str(row[14]),
        agent_updated_at=None if row[15] is None else str(row[15]),
        observed_through=None if row[16] is None else str(row[16]),
        events_since_agent=require_non_negative_int(row[19]),
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
            _REV_HDR_SELECT + "WHERE r.artifact_id = ? AND r.revision_epoch = ? AND r.revision = ?",
            (artifact_id, revision_epoch, revision),
        ).fetchone()
        if row is None or str(row[17]) != scope.repo_id or str(row[18]) != scope.checkout_id:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        return _row_to_rev_header(row)

    def list_revision_history(
        self,
        *,
        artifact_id: str,
        task_id: str,
        revision_epoch: int,
        revision: int,
        principal_id: str,
        scope: Scope,
        limit: int = 1024,
    ) -> tuple[HandoffRevisionHeader, ...]:
        """Return pinned-branch headers newest-first up to ``limit``, isolating restore branches."""
        _require_v8_ready(self._store, self._policy)
        require_opaque_id(artifact_id, label="artifact_id")
        require_opaque_id(task_id, label="task_id")
        require_non_negative_int(revision_epoch)
        require_positive_int(revision)
        require_opaque_id(principal_id, label="principal_id")
        require_positive_int(limit)
        if scope.checkout_id is None:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        rows = self._store._db.execute(
            _REV_HDR_SELECT
            + "WHERE r.artifact_id = ? AND r.task_id = ? AND t.repo_id = ? AND t.checkout_id = ? "
            "AND r.revision_epoch <= ? AND r.revision <= ? "
            "ORDER BY r.revision DESC, r.revision_epoch DESC",
            (artifact_id, task_id, scope.repo_id, scope.checkout_id, revision_epoch, revision),
        ).fetchall()
        results: list[HandoffRevisionHeader] = []
        target_found = False
        cur_max_epoch = revision_epoch
        last_rev = revision + 1
        for row in rows:
            hdr = _row_to_rev_header(row)
            if not target_found:
                if hdr.revision == revision and hdr.revision_epoch == revision_epoch:
                    target_found = True
                    results.append(hdr)
                    cur_max_epoch = hdr.revision_epoch
                    last_rev = hdr.revision
                    if len(results) >= limit:
                        break
                continue
            if hdr.revision == last_rev:
                continue
            if hdr.revision > last_rev or hdr.revision_epoch > cur_max_epoch:
                continue
            results.append(hdr)
            cur_max_epoch = hdr.revision_epoch
            last_rev = hdr.revision
            if len(results) >= limit:
                break
        if not target_found:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        return tuple(results)

    def has_open_handoffs(
        self, *, owner_id: str, repo_id: str, checkout_id: str, now: datetime | None = None
    ) -> bool:
        _require_v8_ready(self._store, self._policy)
        cutoff: str | None = None
        if now is not None:
            cutoff = utc_timestamp(require_aware_utc(now)[0] - _DISCOVER_WINDOW)
        return _has_open_handoffs_in_db(
            self._store._db,
            owner_id=owner_id,
            repo_id=repo_id,
            checkout_id=checkout_id,
            cutoff=cutoff,
        )

    def _render_l0_row(
        self,
        *,
        tid: str,
        art_id: str,
        rev_epoch: int,
        rev: int,
        hrev: int,
        goal_ref: str | None,
        goal_hid: str | None,
        agent_ref: str | None,
        agent_hid: str | None,
        holder_sref: str | None,
        agent_at: str | None,
        obs_through: str | None,
        repo_id: str,
        checkout_id: str,
        now_utc: datetime,
        render_l0: Callable[..., str] | None,
    ) -> DiscoverEntry:
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
                return DiscoverEntry(
                    task_id=tid,
                    artifact_id=art_id,
                    revision_epoch=rev_epoch,
                    revision=rev,
                    digest=agent_ref or goal_ref,
                    summary="",
                    status="redacted",
                    reason=gstatus,
                )
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
                return DiscoverEntry(
                    task_id=tid,
                    artifact_id=art_id,
                    revision_epoch=rev_epoch,
                    revision=rev,
                    digest=agent_ref,
                    summary="",
                    status="redacted",
                    reason=astatus,
                )
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
        return DiscoverEntry(
            task_id=tid,
            artifact_id=art_id,
            revision_epoch=rev_epoch,
            revision=rev,
            digest=agent_ref or goal_ref or digest_bytes(summary.encode("utf-8")),
            summary=summary,
            status="ok",
        )

    def render_delivery_handoff_l0(
        self,
        *,
        task_id: str,
        owner_id: str,
        repo_id: str,
        checkout_id: str,
        revision_epoch: int,
        revision: int,
        served_digest: str | None,
        now: datetime,
        render_l0: Callable[..., str] | None = None,
    ) -> DiscoverEntry:
        _require_v8_ready(self._store, self._policy)
        require_opaque_id(task_id, label="task_id")
        require_opaque_id(owner_id, label="owner_id")
        require_opaque_id(repo_id, label="repo_id")
        require_opaque_id(checkout_id, label="checkout_id")
        require_non_negative_int(revision_epoch)
        require_positive_int(revision)
        now_utc, _ = require_aware_utc(now)

        row = self._store._db.execute(
            "SELECT r.task_id, r.artifact_id, r.revision_epoch, r.revision, r.handoff_revision, "
            "t.goal_ref, t.goal_holder_id, r.agent_ref, r.agent_holder_id, "
            "r.holder_session_ref, r.agent_updated_at, r.observed_through "
            "FROM handoff_revision_headers AS r JOIN tasks AS t ON t.task_id = r.task_id "
            "WHERE r.task_id = ? AND r.revision_epoch = ? AND r.revision = ? "
            "AND t.owner_id = ? AND t.repo_id = ? AND t.checkout_id = ?",
            (task_id, revision_epoch, revision, owner_id, repo_id, checkout_id),
        ).fetchone()
        if row is None:
            return DiscoverEntry(
                task_id=task_id,
                artifact_id=task_id,
                revision_epoch=revision_epoch,
                revision=revision,
                digest=served_digest or "",
                summary="",
                status="redacted",
                reason="not_found",
            )
        return self._render_l0_row(
            tid=str(row[0]),
            art_id=str(row[1]),
            rev_epoch=int(row[2]),
            rev=int(row[3]),
            hrev=int(row[4]),
            goal_ref=None if row[5] is None else str(row[5]),
            goal_hid=None if row[6] is None else str(row[6]),
            agent_ref=None if row[7] is None else str(row[7]),
            agent_hid=None if row[8] is None else str(row[8]),
            holder_sref=None if row[9] is None else str(row[9]),
            agent_at=None if row[10] is None else str(row[10]),
            obs_through=None if row[11] is None else str(row[11]),
            repo_id=repo_id,
            checkout_id=checkout_id,
            now_utc=now_utc,
            render_l0=render_l0,
        )

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

        return tuple(
            self._render_l0_row(
                tid=str(row[0]),
                art_id=str(row[1]),
                rev_epoch=int(row[2]),
                rev=int(row[3]),
                hrev=int(row[4]),
                goal_ref=None if row[5] is None else str(row[5]),
                goal_hid=None if row[6] is None else str(row[6]),
                agent_ref=None if row[7] is None else str(row[7]),
                agent_hid=None if row[8] is None else str(row[8]),
                holder_sref=None if row[9] is None else str(row[9]),
                agent_at=None if row[10] is None else str(row[10]),
                obs_through=None if row[11] is None else str(row[11]),
                repo_id=repo_id,
                checkout_id=checkout_id,
                now_utc=now_utc,
                render_l0=render_l0,
            )
            for row in rows
        )

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
        if has_patch:
            next_events_since_agent = 0
            next_agent_event_order: int | None = max_task_event_order_in_tx(db, task_id)
        else:
            next_events_since_agent = read_revision_events_since_agent_in_tx(
                db,
                artifact_id=cur.artifact_id,
                revision_epoch=cur.revision_epoch,
                revision=cur.revision,
            )
            next_agent_event_order = None

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
            "agent_event_order = COALESCE(?, agent_event_order), "
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
                next_agent_event_order,
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
            "session_state, agent_ref, agent_holder_id, observed_ref, agent_updated_at, observed_through, "
            "events_since_agent, recorded_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
                next_events_since_agent,
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
        """Resolve pinned ``observed_ref`` sources live at read time (never scanning uncommitted events)."""
        _require_v8_ready(self._store, self._policy)
        now_utc, _ = require_aware_utc(now)
        if observed_ref is None:
            return [], []

        raw_obs, obs_status = _check_blob_status(
            self._store._db,
            self._store,
            self._policy,
            observed_ref,
            holder_id=None,
            now=now_utc,
        )
        if obs_status != "ok" or raw_obs is None:
            redacted_status = "redacted" if obs_status in {"quarantined", "tombstoned"} else "expired"
            return (
                [
                    ResolvedSourceContent(
                        source_event_id=observed_ref,
                        source_digest=observed_ref,
                        kind="observed_summary",
                        status=redacted_status,
                        reason=obs_status,
                    )
                ],
                [],
            )

        try:
            decoded = json.loads(raw_obs.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return [], []
        if not isinstance(decoded, Mapping):
            return [], []
        raw_sources = decoded.get("source_events")
        if not isinstance(raw_sources, list):
            return [], []

        kind_by_eid: dict[str, str] = {}
        raw_items = decoded.get("items")
        if isinstance(raw_items, list):
            for it in raw_items:
                if (
                    isinstance(it, Sequence)
                    and not isinstance(it, (str, bytes))
                    and len(it) >= 2
                    and isinstance(it[0], str)
                    and isinstance(it[1], str)
                ):
                    kind_by_eid.setdefault(it[1], it[0])

        pinned_refs: list[tuple[str, int, str, str]] = []
        seen_keys: set[tuple[str, int, str, str]] = set()
        for entry in raw_sources:
            if (
                not isinstance(entry, Sequence)
                or isinstance(entry, (str, bytes))
                or len(entry) < 4
                or not isinstance(entry[0], str)
                or type(entry[1]) is not int
                or not isinstance(entry[2], str)
                or not isinstance(entry[3], str)
            ):
                continue
            ref_key = (entry[0], entry[1], entry[2], entry[3])
            if ref_key not in seen_keys:
                seen_keys.add(ref_key)
                pinned_refs.append(ref_key)

        obs_items: list[ResolvedSourceContent] = []
        conv_items: list[ResolvedSourceContent] = []

        for stream, seq, eid, dig in reversed(pinned_refs):
            meta_row = self._store._db.execute(
                "SELECT l.kind, l.recorded_at, e.cas_holder_id "
                "FROM session_task_events AS l "
                "LEFT JOIN capture_events AS e "
                "ON e.producer_stream = l.producer_stream AND e.sequence = l.sequence "
                "AND e.event_id = l.event_id AND e.payload_digest = l.payload_digest "
                "WHERE l.task_id = ? AND l.producer_stream = ? AND l.sequence = ? "
                "AND l.event_id = ? AND l.payload_digest = ?",
                (task_id, stream, seq, eid, dig),
            ).fetchone()
            meta_kind = (
                str(meta_row[0])
                if meta_row is not None and isinstance(meta_row[0], str)
                else kind_by_eid.get(eid, "event")
            )
            meta_rec_at = str(meta_row[1]) if meta_row is not None and isinstance(meta_row[1], str) else None
            cas_hid = str(meta_row[2]) if meta_row is not None and isinstance(meta_row[2], str) else None

            rec = live_event_record(
                self._store,
                self._policy,
                task_id=task_id,
                producer_stream=stream,
                sequence=seq,
                event_id=eid,
                payload_digest=dig,
                now=now_utc,
            )
            if rec is None:
                is_redacted = self._policy.is_quarantined(dig) or (
                    cas_hid is not None and is_uuid(cas_hid) and self._policy.is_tombstoned("event", cas_hid)
                )
                status = "redacted" if is_redacted else "expired"
                content = ResolvedSourceContent(
                    source_event_id=eid,
                    source_digest=dig,
                    kind=meta_kind,
                    status=status,
                    reason=status,
                    recorded_at=meta_rec_at,
                )
                eff_kind = meta_kind
            else:
                content = ResolvedSourceContent(
                    source_event_id=rec.event_id,
                    source_digest=dig,
                    kind=rec.kind,
                    status="ok",
                    payload=rec.payload,
                    recorded_at=rec.recorded_at,
                )
                eff_kind = rec.kind

            if eff_kind in {"user_message", "user_prompt"}:
                conv_items.append(content)
            obs_items.append(content)

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
        cur: HandoffHeaderState,
        resume_ref: ResumeRefSpec,
    ) -> tuple[str, int, int, str | None, str, bool]:
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
            or str(art_row[0]) != task_id
        ):
            raise BrainError(ErrorCode.NOT_FOUND, "not found")

        if resume_ref.served_receipt_id is not None:
            attempt = read_send_attempt_row(db, resume_ref.served_receipt_id)
            if (
                attempt is None
                or attempt.principal_id != principal_id
                or attempt.task_id != task_id
                or attempt.artifact_id != resume_ref.artifact_id
                or attempt.revision != resume_ref.revision
                or attempt.level != "L1"
                or attempt.state is SendAttemptState.UNKNOWN
            ):
                raise BrainError(ErrorCode.NOT_FOUND, "not found")
            if attempt.state is SendAttemptState.PENDING:
                raise BrainError(ErrorCode.IN_PROGRESS, "operation in progress")
            if attempt.state is not SendAttemptState.SERVED_ONLY or not attempt.resource_digests:
                raise BrainError(ErrorCode.NOT_FOUND, "not found")
            res_epoch = attempt.revision_epoch
            ack = read_read_ack_by_receipt_row(db, resume_ref.served_receipt_id)
            has_matching_ack = (
                ack is not None
                and ack.served_receipt_id == attempt.send_attempt_id
                and ack.principal_id == principal_id
                and ack.task_id == task_id
                and ack.artifact_id == attempt.artifact_id
                and ack.revision_epoch == attempt.revision_epoch
                and ack.revision == attempt.revision
                and ack.resource_digests == attempt.resource_digests
            )
            resume_exposure = "read_ack" if has_matching_ack else "served_only"
        else:
            resume_exposure = "unknown"
            cand_epoch = db.execute(
                "SELECT 1 FROM handoff_revision_headers "
                "WHERE artifact_id = ? AND revision_epoch = ? AND revision = ?",
                (resume_ref.artifact_id, resume_ref.fence.restore_epoch, resume_ref.revision),
            ).fetchone()
            if cand_epoch is None:
                any_rev = db.execute(
                    "SELECT 1 FROM handoff_revision_headers WHERE artifact_id = ? AND revision = ?",
                    (resume_ref.artifact_id, resume_ref.revision),
                ).fetchone()
                if any_rev is None:
                    raise BrainError(ErrorCode.NOT_FOUND, "not found")
                raise BrainError(ErrorCode.REVISION_CONFLICT, "resume_ref does not match revision header")
            res_epoch = resume_ref.fence.restore_epoch

        hrow = db.execute(
            "SELECT handoff_revision, holder_restore_epoch, writer_generation "
            "FROM handoff_revision_headers WHERE artifact_id = ? AND revision_epoch = ? AND revision = ?",
            (resume_ref.artifact_id, res_epoch, resume_ref.revision),
        ).fetchone()
        if hrow is None:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        hdr_hrev = int(hrow[0])
        hdr_fence = HandoffFence(restore_epoch=int(hrow[1]), writer_generation=int(hrow[2]))
        if resume_ref.handoff_revision != hdr_hrev or resume_ref.fence != hdr_fence:
            raise BrainError(ErrorCode.REVISION_CONFLICT, "resume_ref does not match revision header")
        if cur.handoff_revision != hdr_hrev or cur.committed_fence != hdr_fence:
            raise BrainError(ErrorCode.REVISION_CONFLICT, "handoff changed since read revision")
        observed_newer = (cur.revision_epoch, cur.revision) != (res_epoch, resume_ref.revision)
        return (
            resume_ref.artifact_id,
            res_epoch,
            resume_ref.revision,
            resume_ref.served_receipt_id,
            resume_exposure,
            observed_newer,
        )

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
        task_id_provided: bool | None = None,
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
        cutoff = utc_timestamp(now_utc - _DISCOVER_WINDOW)
        txn = _txn_of(tx)
        db = txn.db

        self._validate_seen_refs_in_tx(
            db, owner_id=owner_id, repo_id=repo_id, checkout_id=checkout_id, seen_refs=seen_handoff_refs
        )
        has_open_other = _has_open_handoffs_in_db(
            db,
            owner_id=owner_id,
            repo_id=repo_id,
            checkout_id=checkout_id,
            cutoff=cutoff,
            exclude_task_id=task_id,
        )

        res_art_id: str | None = None
        res_epoch: int | None = None
        res_rev: int | None = None
        res_receipt_id: str | None = None
        resume_exposure: str | None = None
        observed_newer = False

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
                res_art_id, res_epoch, res_rev, res_receipt_id, resume_exposure, observed_newer = (
                    self._validate_resume_in_tx(
                        db,
                        task_id=task_id,
                        owner_id=owner_id,
                        repo_id=repo_id,
                        checkout_id=checkout_id,
                        principal_id=principal_id,
                        cur=cur,
                        resume_ref=resume_ref,
                    )
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

        if resume_exposure is not None:
            eff_exposure = resume_exposure
        elif seen_handoff_refs:
            eff_exposure = "seen_l0"
        elif has_open_other:
            eff_exposure = "unreviewed_open_handoffs"
        else:
            eff_exposure = exposure_evidence or "none"

        explicit_task_id = (not create_task) if task_id_provided is None else task_id_provided
        eff_degraded_codes = _unique_codes(degraded_codes)
        if not explicit_task_id and has_open_other and _OPEN_HANDOFFS_PRESENT_CODE not in eff_degraded_codes:
            eff_degraded_codes.append(_OPEN_HANDOFFS_PRESENT_CODE)
        if observed_newer and _OBSERVED_NEWER_CODE not in eff_degraded_codes:
            eff_degraded_codes.append(_OBSERVED_NEWER_CODE)

        served_ep = eff_live.revision_epoch
        served_rev = eff_live.revision
        served_dig: str | None = None
        if served_rev is not None and served_ep is not None and not create_task:
            hrow_dig = db.execute(
                "SELECT COALESCE(r.agent_ref, t.goal_ref) "
                "FROM handoff_revision_headers AS r JOIN tasks AS t ON t.task_id = r.task_id "
                "WHERE r.task_id = ? AND r.revision_epoch = ? AND r.revision = ?",
                (task_id, served_ep, served_rev),
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
                canonical_json(eff_degraded_codes).decode("utf-8"),
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
            "resume_artifact_id, resume_revision_epoch, resume_revision, resume_receipt_id, "
            "handoff_served_epoch, handoff_served_rev, handoff_served_digest "
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
            handoff_served_epoch=None if row[16] is None else int(row[16]),
            handoff_served_rev=None if row[17] is None else int(row[17]),
            handoff_served_digest=None if row[18] is None else str(row[18]),
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
        include_history: bool = False,
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
            task_id=task_id,
            observed_ref=hdr.observed_ref,
            now=now_utc,
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

        revision_history: tuple[HandoffRevisionHeader, ...] = (
            self.list_revision_history(
                artifact_id=artifact_id,
                task_id=task_id,
                revision_epoch=revision_epoch,
                revision=revision,
                principal_id=principal_id,
                scope=scope,
            )
            if include_history
            else ()
        )

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
            revision_history=revision_history,
            events_since_agent=hdr.events_since_agent,
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
