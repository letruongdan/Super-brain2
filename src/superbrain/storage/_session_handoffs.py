"""Task handoff creation and agent handoff patches for ``sessions.SessionStore``."""

from __future__ import annotations

from datetime import datetime

from superbrain.core._kernel_base import require_non_negative_int, require_opaque_id, require_sha256_digest
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.kernel import require_aware_utc
from superbrain.ports.continuity import (
    TaskHandoffRecord,
)
from superbrain.storage import sessions as _m
from superbrain.storage._handoff_schema import record_v8_revision_header_in_tx
from superbrain.storage._sessions_sql import (
    TASK_SELECT_COLS,
    decode_handoff,
    require_ready,
)
from superbrain.storage.ledger import utc_timestamp


def ensure_task_handoff(
    self: _m.SessionStore,
    *,
    task_id: str,
    repo_id: str,
    checkout_id: str,
    session_ref: str | None = None,
    now: datetime,
    owner_id: str | None = None,
    artifact_id: str | None = None,
) -> TaskHandoffRecord:
    require_ready(self._store, self._policy)
    require_opaque_id(task_id, label="task_id")
    require_opaque_id(repo_id, label="repo_id")
    require_opaque_id(checkout_id, label="checkout_id")
    if session_ref is not None:
        require_sha256_digest(session_ref)
    now_utc, _ = require_aware_utc(now)
    stamp = utc_timestamp(now_utc)
    policy_owner, _, _ = self._policy.repo_policy_flags(repo_id)

    with self._store.transaction() as txn:
        holder_principal: str | None = None
        if session_ref is not None:
            srow = txn.db.execute(
                "SELECT principal_id, repo_id, checkout_id FROM sessions WHERE session_ref = ?", (session_ref,)
            ).fetchone()
            if srow is None:
                raise BrainError(ErrorCode.NOT_FOUND, "session not found")
            if str(srow[1]) != repo_id or str(srow[2]) != checkout_id:
                raise BrainError(ErrorCode.IDENTITY_MISMATCH, "session belongs to different workspace")
            holder_principal = str(srow[0])

        resolved_owner = owner_id or policy_owner or holder_principal
        if resolved_owner is None:
            raise BrainError(ErrorCode.NOT_FOUND, "repo policy owner not found")
        require_opaque_id(resolved_owner, label="owner_id")

        existing = txn.db.execute(
            f"SELECT {TASK_SELECT_COLS} FROM task_handoffs WHERE task_id = ?", (task_id,)
        ).fetchone()
        if existing is not None:
            rec = decode_handoff(tuple(existing))
            if rec.repo_id != repo_id or rec.checkout_id != checkout_id:
                raise BrainError(ErrorCode.IDENTITY_MISMATCH, "task belongs to different workspace")
            return rec

        art_id = artifact_id or new_id()
        txn.db.execute(
            "INSERT INTO tasks ("
            "task_id, owner_id, repo_id, checkout_id, current_revision, current_revision_epoch, "
            "task_state, task_state_source, holder_principal, holder_session_ref, created_at, updated_at"
            ") VALUES (?, ?, ?, ?, 0, 0, 'in_progress', 'inferred', ?, ?, ?, ?)",
            (task_id, resolved_owner, repo_id, checkout_id, holder_principal, session_ref, stamp, stamp),
        )
        txn.db.execute(
            "INSERT INTO task_handoffs ("
            "task_id, artifact_id, repo_id, checkout_id, current_revision, current_revision_epoch, "
            "handoff_revision, writer_generation, agent_ref, observed_ref, task_state, task_state_source, "
            "holder_principal, holder_session_ref, agent_updated_at, observed_through"
            ") VALUES (?, ?, ?, ?, 0, 0, 0, 0, NULL, NULL, 'in_progress', 'inferred', ?, ?, NULL, NULL)",
            (task_id, art_id, repo_id, checkout_id, holder_principal, session_ref),
        )
        if session_ref is not None:
            txn.db.execute(
                "INSERT INTO continuity_refresh_state ("
                "task_id, session_ref, owner_id, repo_id, checkout_id, pending_event_count, "
                "first_pending_event_at, observed_through, dirty_flag, active_job_id, pending_job_id, "
                "active_event_cutoff_seq, last_summarized_rowid"
                ") VALUES (?, ?, ?, ?, ?, 0, NULL, NULL, 0, NULL, NULL, 0, 0)",
                (task_id, session_ref, resolved_owner, repo_id, checkout_id),
            )
        return TaskHandoffRecord(
            task_id=task_id,
            artifact_id=art_id,
            repo_id=repo_id,
            checkout_id=checkout_id,
            current_revision=0,
            current_revision_epoch=0,
            handoff_revision=0,
            writer_generation=0,
            agent_ref=None,
            observed_ref=None,
            task_state="in_progress",
            task_state_source="inferred",
            holder_principal=holder_principal,
            holder_session_ref=session_ref,
        )


def apply_agent_handoff_patch(
    self: _m.SessionStore,
    *,
    task_id: str,
    repo_id: str,
    checkout_id: str,
    session_ref: str | None = None,
    base_revision: int,
    agent_ref: str,
    now: datetime,
) -> TaskHandoffRecord:
    require_ready(self._store, self._policy)
    require_opaque_id(task_id, label="task_id")
    require_opaque_id(repo_id, label="repo_id")
    require_opaque_id(checkout_id, label="checkout_id")
    require_non_negative_int(base_revision)
    require_sha256_digest(agent_ref)
    if session_ref is not None:
        require_sha256_digest(session_ref)
    now_utc, _ = require_aware_utc(now)
    stamp = utc_timestamp(now_utc)

    with self._store.transaction() as txn:
        row = txn.db.execute(
            f"SELECT {TASK_SELECT_COLS} FROM task_handoffs WHERE task_id = ?", (task_id,)
        ).fetchone()
        if row is None:
            raise BrainError(ErrorCode.NOT_FOUND, "task handoff not found")
        cur = decode_handoff(tuple(row))
        if cur.repo_id != repo_id or cur.checkout_id != checkout_id:
            raise BrainError(ErrorCode.IDENTITY_MISMATCH, "task belongs to different workspace")
        if cur.handoff_revision != base_revision:
            raise BrainError(ErrorCode.REVISION_CONFLICT, "handoff base_revision conflict")
        next_handoff_rev = cur.handoff_revision + 1
        next_current_rev = cur.current_revision + 1
        holder_sref = cur.holder_session_ref if cur.holder_session_ref is not None else session_ref
        txn.db.execute(
            "UPDATE task_handoffs SET agent_ref = ?, handoff_revision = ?, current_revision = ?, "
            "task_state_source = 'agent', holder_session_ref = ?, agent_updated_at = ? WHERE task_id = ?",
            (agent_ref, next_handoff_rev, next_current_rev, holder_sref, stamp, task_id),
        )
        txn.db.execute(
            "UPDATE tasks SET current_revision = ?, task_state_source = 'agent', updated_at = ? WHERE task_id = ?",
            (next_current_rev, stamp, task_id),
        )
        txn.db.execute(
            "INSERT INTO handoff_revisions "
            "(task_id, handoff_revision, source_kind, agent_ref, observed_ref, recorded_at) "
            "VALUES (?, ?, 'agent', ?, ?, ?)",
            (task_id, next_handoff_rev, agent_ref, cur.observed_ref, stamp),
        )
        record_v8_revision_header_in_tx(
            txn.db,
            task_id=task_id,
            next_revision=next_current_rev,
            next_handoff_revision=next_handoff_rev,
            next_task_state=cur.task_state,
            next_source="agent",
            principal_id=cur.holder_principal,
            session_ref=holder_sref,
            agent_ref=agent_ref,
            observed_ref=cur.observed_ref,
            agent_updated_at=stamp,
            observed_through=cur.observed_through,
            recorded_at=stamp,
            reset_events_since_agent=True,
            store=self._store,
        )
        updated = txn.db.execute(
            f"SELECT {TASK_SELECT_COLS} FROM task_handoffs WHERE task_id = ?", (task_id,)
        ).fetchone()
        assert updated is not None
        return decode_handoff(tuple(updated))
