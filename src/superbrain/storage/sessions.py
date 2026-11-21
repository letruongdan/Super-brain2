"""SP2-3 storage adapter: dual-store sessions, segments, exposure, task handoffs, and checkpoints."""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from datetime import datetime
from typing import cast

from superbrain.core._kernel_base import require_non_negative_int, require_opaque_id, require_sha256_digest
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.faults import crashpoint
from superbrain.core.ids import new_id
from superbrain.core.kernel import require_aware_utc
from superbrain.ports.continuity import (
    ContinuityStorePort,
    ExposureEvidence,
    RecipientProfile,
    SessionRecord,
    SessionSegmentRecord,
    SessionState,
    TaskHandoffRecord,
    compute_hmac_session_ref,
    register_continuity_store_factory,
)
from superbrain.storage._sessions_sql import (
    SESSION_SELECT_COLS,
    TASK_SELECT_COLS,
    decode_handoff,
    decode_segment,
    decode_session,
    require_ready,
    validate_session_binding_args,
    validate_session_ref_args,
)
from superbrain.storage._sessions_worker import SessionWorkerMixin
from superbrain.storage.errors import sqlite_error
from superbrain.storage.ledger import utc_timestamp
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.store import Store


class SessionStore(SessionWorkerMixin):
    """Dual-store SP2-3 session, recipient segment, exposure, task handoff, and checkpoint store."""

    def __init__(self, store: Store, policy: PolicyStore) -> None:
        self._store = store
        self._policy = policy

    def bind_session(
        self,
        *,
        principal_id: str,
        repo_id: str,
        checkout_id: str,
        harness_id: str,
        raw_session_id: str | None = None,
        session_ref: str | None = None,
        profile: RecipientProfile | None = None,
        now: datetime,
    ) -> SessionRecord:
        """Bind ``raw_session_id`` or precomputed ``session_ref`` in ``policy.db`` first, then project ``brain.db``."""
        require_ready(self._store, self._policy)
        require_opaque_id(principal_id, label="principal_id")
        require_opaque_id(repo_id, label="repo_id")
        require_opaque_id(checkout_id, label="checkout_id")
        require_opaque_id(harness_id, label="harness_id")
        if profile is not None and not isinstance(profile, RecipientProfile):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid recipient profile")
        if raw_session_id is not None:
            validate_session_binding_args(
                principal_id=principal_id,
                repo_id=repo_id,
                checkout_id=checkout_id,
                harness_id=harness_id,
                raw_session_id=raw_session_id,
            )
            derived = compute_hmac_session_ref(self._policy.session_hmac_key(), raw_session_id)
            if session_ref is not None and session_ref != derived:
                raise BrainError(ErrorCode.IDENTITY_MISMATCH, "session_ref mismatch")
            target_ref = derived
        elif session_ref is not None:
            require_sha256_digest(session_ref)
            target_ref = session_ref
        else:
            raise BrainError(ErrorCode.INVALID_INPUT, "raw_session_id or session_ref required")
        return self.bind_existing_session_ref(
            session_ref=target_ref,
            principal_id=principal_id,
            repo_id=repo_id,
            checkout_id=checkout_id,
            harness_id=harness_id,
            profile=profile,
            now=now,
        )

    def bind_existing_session_ref(
        self,
        *,
        session_ref: str,
        principal_id: str,
        repo_id: str,
        checkout_id: str,
        harness_id: str,
        profile: RecipientProfile | None = None,
        now: datetime,
    ) -> SessionRecord:
        """Bind or verify an already-derived ``session_ref`` in ``policy.db`` and project into ``brain.db``."""
        require_ready(self._store, self._policy)
        require_sha256_digest(session_ref)
        require_opaque_id(principal_id, label="principal_id")
        require_opaque_id(repo_id, label="repo_id")
        require_opaque_id(checkout_id, label="checkout_id")
        require_opaque_id(harness_id, label="harness_id")
        now_utc, _ = require_aware_utc(now)
        stamp = utc_timestamp(now_utc)

        self._policy.bind_or_verify_session_ref(
            session_ref,
            principal_id=principal_id,
            repo_id=repo_id,
            checkout_id=checkout_id,
            harness_id=harness_id,
            now=now_utc,
        )
        already_projected = (
            self._store._db.execute("SELECT 1 FROM sessions WHERE session_ref = ?", (session_ref,)).fetchone()
            is not None
        )
        if not already_projected:
            crashpoint("session.after_policy_bind_before_store_project")

        with self._store.transaction() as txn:
            row = txn.db.execute(
                f"SELECT {SESSION_SELECT_COLS} FROM sessions WHERE session_ref = ?", (session_ref,)
            ).fetchone()
            if row is not None:
                existing = decode_session(tuple(row))
                if (
                    existing.principal_id != principal_id
                    or existing.repo_id != repo_id
                    or existing.checkout_id != checkout_id
                ):
                    raise BrainError(ErrorCode.IDENTITY_MISMATCH, "session_ref bound to different identity")
                if profile is not None:
                    self._ensure_segment_in_tx(txn.db, existing, profile, stamp)
                    refreshed = txn.db.execute(
                        f"SELECT {SESSION_SELECT_COLS} FROM sessions WHERE session_ref = ?", (session_ref,)
                    ).fetchone()
                    assert refreshed is not None
                    return decode_session(tuple(refreshed))
                return existing

            txn.db.execute(
                "INSERT INTO sessions ("
                "session_ref, repo_id, checkout_id, principal_id, harness_id, state, last_event_at, "
                "active_segment_id, ended_at) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL)",
                (session_ref, repo_id, checkout_id, principal_id, harness_id, SessionState.ACTIVE.value, stamp),
            )
            created = SessionRecord(
                session_ref=session_ref,
                repo_id=repo_id,
                checkout_id=checkout_id,
                principal_id=principal_id,
                harness_id=harness_id,
                state=SessionState.ACTIVE,
                last_event_at=stamp,
            )
            if profile is not None:
                seg = self._ensure_segment_in_tx(txn.db, created, profile, stamp)
                created = SessionRecord(
                    session_ref=session_ref,
                    repo_id=repo_id,
                    checkout_id=checkout_id,
                    principal_id=principal_id,
                    harness_id=harness_id,
                    state=SessionState.ACTIVE,
                    last_event_at=stamp,
                    active_segment_id=seg.segment_id,
                )
            return created

    def reconcile_missing_sessions(self) -> int:
        """Project any ``policy.db`` bindings missing from ``brain.db.sessions`` after crash recovery."""
        require_ready(self._store, self._policy)
        bindings = self._policy.list_session_bindings()
        if not bindings:
            return 0
        fallback_stamp = utc_timestamp(self._policy._os.clock.now())
        projected = 0
        with self._store.transaction() as txn:
            existing_rows = {
                str(r[0]): str(r[1])
                for r in txn.db.execute("SELECT session_ref, principal_id FROM sessions").fetchall()
            }
            for binding in bindings:
                found_prin = existing_rows.get(binding.session_ref)
                if found_prin is not None:
                    if found_prin != binding.principal_id:
                        raise BrainError(ErrorCode.IDENTITY_MISMATCH, "session binding conflict with policy store")
                    continue
                if binding.repo_id is None or binding.checkout_id is None or binding.harness_id is None:
                    continue
                txn.db.execute(
                    "INSERT INTO sessions ("
                    "session_ref, repo_id, checkout_id, principal_id, harness_id, state, last_event_at, "
                    "active_segment_id, ended_at) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL)",
                    (
                        binding.session_ref,
                        binding.repo_id,
                        binding.checkout_id,
                        binding.principal_id,
                        binding.harness_id,
                        SessionState.ACTIVE.value,
                        binding.bound_at or fallback_stamp,
                    ),
                )
                projected += 1
        return projected

    def get_session(self, session_ref: str, *, checkout_id: str, repo_id: str | None = None) -> SessionRecord:
        """Fetch a session scoped strictly to ``checkout_id`` (and ``repo_id`` if provided)."""
        require_ready(self._store, self._policy)
        validate_session_ref_args(session_ref, checkout_id=checkout_id, repo_id=repo_id)
        try:
            if repo_id is not None:
                row = self._store._db.execute(
                    f"SELECT {SESSION_SELECT_COLS} FROM sessions "
                    "WHERE session_ref = ? AND repo_id = ? AND checkout_id = ?",
                    (session_ref, repo_id, checkout_id),
                ).fetchone()
            else:
                row = self._store._db.execute(
                    f"SELECT {SESSION_SELECT_COLS} FROM sessions WHERE session_ref = ? AND checkout_id = ?",
                    (session_ref, checkout_id),
                ).fetchone()
        except sqlite3.Error as exc:
            raise sqlite_error("cannot read session", exc) from exc
        if row is None:
            raise BrainError(ErrorCode.NOT_FOUND, "session not found")
        return decode_session(tuple(row))

    def _ensure_segment_in_tx(
        self, db: sqlite3.Connection, session: SessionRecord, profile: RecipientProfile, stamp: str
    ) -> SessionSegmentRecord:
        active_seg: SessionSegmentRecord | None = None
        if session.active_segment_id is not None:
            seg_row = db.execute(
                "SELECT segment_id, session_ref, segment_index, harness_id, provider_endpoint_digest, "
                "model_config_digest, account_digest, opened_at FROM session_segments WHERE segment_id = ?",
                (session.active_segment_id,),
            ).fetchone()
            if seg_row is not None:
                active_seg = decode_segment(tuple(seg_row))
        if active_seg is not None and active_seg.profile.segment_key() == profile.segment_key():
            return active_seg
        idx_row = db.execute(
            "SELECT COALESCE(MAX(segment_index), 0) FROM session_segments WHERE session_ref = ?",
            (session.session_ref,),
        ).fetchone()
        next_idx = (int(idx_row[0]) if idx_row is not None else 0) + 1
        seg_id = new_id()
        db.execute(
            "INSERT INTO session_segments ("
            "segment_id, session_ref, segment_index, harness_id, provider_endpoint_digest, "
            "model_config_digest, account_digest, opened_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                seg_id,
                session.session_ref,
                next_idx,
                profile.harness_id,
                profile.provider_endpoint_digest,
                profile.model_config_digest,
                profile.account_digest,
                stamp,
            ),
        )
        db.execute("UPDATE sessions SET active_segment_id = ? WHERE session_ref = ?", (seg_id, session.session_ref))
        return SessionSegmentRecord(
            segment_id=seg_id,
            session_ref=session.session_ref,
            segment_index=next_idx,
            profile=profile,
            opened_at=stamp,
        )

    def open_or_switch_segment(
        self, *, session_ref: str, checkout_id: str, profile: RecipientProfile, now: datetime
    ) -> SessionSegmentRecord:
        """Return active segment if profile matches or open the next indexed ``SessionSegment``."""
        require_ready(self._store, self._policy)
        validate_session_ref_args(session_ref, checkout_id=checkout_id)
        if not isinstance(profile, RecipientProfile):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid recipient profile")
        now_utc, _ = require_aware_utc(now)
        stamp = utc_timestamp(now_utc)
        with self._store.transaction() as txn:
            row = txn.db.execute(
                f"SELECT {SESSION_SELECT_COLS} FROM sessions WHERE session_ref = ? AND checkout_id = ?",
                (session_ref, checkout_id),
            ).fetchone()
            if row is None:
                raise BrainError(ErrorCode.NOT_FOUND, "session not found")
            return self._ensure_segment_in_tx(txn.db, decode_session(tuple(row)), profile, stamp)

    def record_capture_exposure(
        self,
        *,
        event_id: str,
        item_ref: str,
        item_digest: str,
        segment_id: str,
        exposure_evidence: ExposureEvidence,
        completed_model_call_id: str | None = None,
        recorded_at: datetime,
    ) -> None:
        """Persist per-segment ``ExposureEvidence`` classification."""
        require_ready(self._store, self._policy)
        require_opaque_id(event_id, label="event_id")
        require_opaque_id(item_ref, label="item_ref")
        require_sha256_digest(item_digest)
        require_opaque_id(segment_id, label="segment_id")
        if not isinstance(exposure_evidence, ExposureEvidence):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid exposure_evidence")
        if completed_model_call_id is not None:
            require_opaque_id(completed_model_call_id, label="completed_model_call_id")
        now_utc, _ = require_aware_utc(recorded_at)
        stamp = utc_timestamp(now_utc)
        with self._store.transaction() as txn:
            if txn.db.execute("SELECT 1 FROM session_segments WHERE segment_id = ?", (segment_id,)).fetchone() is None:
                raise BrainError(ErrorCode.NOT_FOUND, "segment not found")
            txn.db.execute(
                "INSERT INTO capture_exposure ("
                "segment_id, item_ref, event_id, item_digest, exposure_evidence, "
                "completed_model_call_id, recorded_at) VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (segment_id, item_ref) DO UPDATE SET "
                "event_id = excluded.event_id, item_digest = excluded.item_digest, "
                "exposure_evidence = excluded.exposure_evidence, "
                "completed_model_call_id = excluded.completed_model_call_id, recorded_at = excluded.recorded_at",
                (segment_id, item_ref, event_id, item_digest, exposure_evidence.value, completed_model_call_id, stamp),
            )

    def read_capture_exposure(self, *, item_ref: str, segment_id: str) -> ExposureEvidence:
        """Read ``ExposureEvidence`` for ``(item_ref, segment_id)`` (``UNKNOWN`` when absent)."""
        require_ready(self._store, self._policy)
        require_opaque_id(item_ref, label="item_ref")
        require_opaque_id(segment_id, label="segment_id")
        try:
            row = self._store._db.execute(
                "SELECT exposure_evidence FROM capture_exposure WHERE segment_id = ? AND item_ref = ?",
                (segment_id, item_ref),
            ).fetchone()
        except sqlite3.Error as exc:
            raise sqlite_error("cannot read capture exposure", exc) from exc
        return ExposureEvidence.UNKNOWN if row is None else ExposureEvidence(str(row[0]))

    def ensure_task_handoff(
        self,
        *,
        task_id: str,
        repo_id: str,
        checkout_id: str,
        session_ref: str | None = None,
        now: datetime,
        owner_id: str | None = None,
        artifact_id: str | None = None,
    ) -> TaskHandoffRecord:
        """Ensure initial ``tasks``, ``task_handoffs``, and ``continuity_refresh_state`` rows exist."""
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

    def read_task_handoff(self, task_id: str) -> TaskHandoffRecord | None:
        """Read current ``task_handoffs`` state, or ``None`` when absent."""
        require_ready(self._store, self._policy)
        require_opaque_id(task_id, label="task_id")
        try:
            row = self._store._db.execute(
                f"SELECT {TASK_SELECT_COLS} FROM task_handoffs WHERE task_id = ?", (task_id,)
            ).fetchone()
        except sqlite3.Error as exc:
            raise sqlite_error("cannot read task_handoffs", exc) from exc
        return None if row is None else decode_handoff(tuple(row))

    def apply_agent_handoff_patch(
        self,
        *,
        task_id: str,
        repo_id: str,
        checkout_id: str,
        session_ref: str | None = None,
        base_revision: int,
        agent_ref: str,
        now: datetime,
    ) -> TaskHandoffRecord:
        """Optimistic CAS update of ``agent_ref`` and ``handoff_revision`` while preserving ``observed_ref``."""
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
            updated = txn.db.execute(
                f"SELECT {TASK_SELECT_COLS} FROM task_handoffs WHERE task_id = ?", (task_id,)
            ).fetchone()
            assert updated is not None
            return decode_handoff(tuple(updated))


def bind_capture_batch_sessions(
    store: Store,
    policy: PolicyStore,
    staged_events: Sequence[object],
    *,
    principal_id: str,
    repo_id: str,
    checkout_id: str,
    now: datetime,
) -> None:
    """Bind non-null ``session_ref`` values from an authorized capture batch into both stores."""
    if policy.schema_version < 5 or store.schema_version < 6:
        return
    sessions = SessionStore(store, policy)
    for ev in staged_events:
        rec = getattr(ev, "record", None)
        sref = getattr(rec, "session_ref", None)
        if sref is not None:
            sessions.bind_existing_session_ref(
                session_ref=sref,
                principal_id=principal_id,
                repo_id=repo_id,
                checkout_id=checkout_id,
                harness_id=rec.harness_id,  # type: ignore[union-attr]
                now=now,
            )


def _session_store_factory(store: object, policy: object) -> ContinuityStorePort:
    return cast(ContinuityStorePort, SessionStore(cast(Store, store), cast(PolicyStore, policy)))


register_continuity_store_factory(_session_store_factory)

__all__ = [
    "SessionStore",
    "bind_capture_batch_sessions",
]
