"""SP2-3 session event recording, liveness refresh, watermarks, and continuity worker store mixin."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timedelta

from superbrain.core._kernel_base import require_opaque_id, require_sha256_digest
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import require_aware_utc
from superbrain.ports.capture import CaptureEventRecord
from superbrain.ports.continuity import (
    EVENT_KINDS_ENDING_SESSION,
    EVENT_KINDS_RESUMING_SESSION,
    ContinuityCommitOutcome,
    ContinuityEventRow,
    ContinuityWorkerState,
    LongRunningCheckpoint,
    SessionRecord,
    SessionState,
    decide_session_liveness,
)
from superbrain.storage._sessions_sql import (
    SESSION_SELECT_COLS,
    TASK_SELECT_COLS,
    decode_checkpoint,
    decode_handoff,
    decode_session,
    decode_worker_state,
    parse_iso_utc,
    persist_long_running_checkpoint,
    recompute_task_pending,
    require_ready,
    sync_producer_watermark,
    validate_session_ref_args,
)
from superbrain.storage.errors import sqlite_error
from superbrain.storage.kinds import RetentionClass
from superbrain.storage.ledger import Txn, utc_timestamp
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.store import Store

_EVENT_RETENTION = timedelta(days=90)


class SessionWorkerMixin:
    """Session event ingestion, liveness evaluation, and 3-phase continuity commit methods."""

    _store: Store
    _policy: PolicyStore

    def record_session_event(
        self,
        *,
        session_ref: str,
        repo_id: str,
        checkout_id: str,
        task_id: str | None = None,
        producer_stream: str,
        event: CaptureEventRecord,
        now: datetime | None = None,
    ) -> SessionRecord:
        """Persist a session capture event, advance monotonic watermarks, and update liveness/pending state."""
        require_ready(self._store, self._policy)
        require_sha256_digest(session_ref)
        require_opaque_id(repo_id, label="repo_id")
        require_opaque_id(checkout_id, label="checkout_id")
        require_opaque_id(producer_stream, label="producer_stream")
        if task_id is not None:
            require_opaque_id(task_id, label="task_id")
        if not isinstance(event, CaptureEventRecord) or event.producer_stream != producer_stream:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid session event")
        if event.session_ref is not None and event.session_ref != session_ref:
            raise BrainError(ErrorCode.IDENTITY_MISMATCH, "event session_ref mismatch")
        now_utc, _ = require_aware_utc(now if now is not None else self._policy._os.clock.now())
        stamp = utc_timestamp(now_utc)
        expires_at = now_utc + _EVENT_RETENTION

        binding = self._policy.lookup_session_binding(session_ref)
        payload_bytes = canonical_json(event.payload)
        payload_digest = digest_bytes(payload_bytes)
        event_json = canonical_json(event.to_dict()).decode("utf-8")

        already_captured = (
            self._store._db.execute(
                "SELECT 1 FROM capture_events WHERE producer_stream = ? AND sequence = ?",
                (producer_stream, event.sequence),
            ).fetchone()
            is not None
        )
        if not already_captured:
            self._store.cas.put(payload_bytes)

        with self._store.transaction() as txn:
            srow = txn.db.execute(
                f"SELECT {SESSION_SELECT_COLS} FROM sessions WHERE session_ref = ? AND repo_id = ? AND checkout_id = ?",
                (session_ref, repo_id, checkout_id),
            ).fetchone()
            if srow is None:
                raise BrainError(ErrorCode.NOT_FOUND, "session not found")
            session = decode_session(tuple(srow))
            if binding is None or binding.principal_id != session.principal_id:
                raise BrainError(ErrorCode.IDENTITY_MISMATCH, "policy session binding mismatch")

            sync_producer_watermark(txn.db, producer_stream, event.sequence, stamp)

            existing_ev = txn.db.execute(
                "SELECT 1 FROM capture_events WHERE producer_stream = ? AND sequence = ?",
                (producer_stream, event.sequence),
            ).fetchone()
            if existing_ev is None:
                holder_id = new_id()
                txn.hold(payload_digest, "event", holder_id, RetentionClass.DURABLE, expires_at)
                txn.db.execute(
                    "INSERT INTO capture_events ("
                    "producer_stream, sequence, event_id, harness_id, kind, recorded_at, payload_digest, "
                    "cas_holder_id, source, source_verification, repo_id, checkout_id, principal_id, "
                    "session_ref, source_metadata_json, committed_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'tool_observed', 'verified_host', ?, ?, ?, ?, ?, ?)",
                    (
                        producer_stream,
                        event.sequence,
                        event.event_id,
                        event.harness_id,
                        event.kind,
                        event.recorded_at,
                        payload_digest,
                        holder_id,
                        repo_id,
                        checkout_id,
                        session.principal_id,
                        session_ref,
                        canonical_json(event.source_metadata).decode("utf-8"),
                        stamp,
                    ),
                )

            cur_last_dt = parse_iso_utc(session.last_event_at)
            ev_dt = parse_iso_utc(event.recorded_at)
            next_last = event.recorded_at if ev_dt >= cur_last_dt else session.last_event_at

            if event.kind in EVENT_KINDS_ENDING_SESSION:
                next_state, next_ended_at = SessionState.ENDED.value, event.recorded_at
            elif session.state is SessionState.ENDED:
                if event.kind in EVENT_KINDS_RESUMING_SESSION:
                    next_state, next_ended_at = SessionState.ACTIVE.value, None
                else:
                    next_state, next_ended_at = SessionState.ENDED.value, session.ended_at
            else:
                next_state, next_ended_at = SessionState.ACTIVE.value, None

            txn.db.execute(
                "UPDATE sessions SET state = ?, last_event_at = ?, ended_at = ? WHERE session_ref = ?",
                (next_state, next_last, next_ended_at, session_ref),
            )

            if task_id is not None:
                self._link_task_event_in_tx(
                    txn.db,
                    task_id=task_id,
                    session=session,
                    producer_stream=producer_stream,
                    event=event,
                    payload_digest=payload_digest,
                    event_json=event_json,
                )

            out = txn.db.execute(
                f"SELECT {SESSION_SELECT_COLS} FROM sessions WHERE session_ref = ?", (session_ref,)
            ).fetchone()
            assert out is not None
            return decode_session(tuple(out))

    def _link_task_event_in_tx(
        self,
        db: sqlite3.Connection,
        *,
        task_id: str,
        session: SessionRecord,
        producer_stream: str,
        event: CaptureEventRecord,
        payload_digest: str,
        event_json: str,
    ) -> None:
        trow = db.execute("SELECT owner_id, repo_id, checkout_id FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
        if trow is None:
            raise BrainError(ErrorCode.NOT_FOUND, "task not found")
        if str(trow[1]) != session.repo_id or str(trow[2]) != session.checkout_id:
            raise BrainError(ErrorCode.IDENTITY_MISMATCH, "task belongs to different workspace")
        owner_id = str(trow[0])
        wrow = db.execute(
            "SELECT last_summarized_rowid, active_job_id, pending_job_id, dirty_flag "
            "FROM continuity_refresh_state WHERE task_id = ?",
            (task_id,),
        ).fetchone()
        if wrow is None:
            db.execute(
                "INSERT INTO continuity_refresh_state ("
                "task_id, session_ref, owner_id, repo_id, checkout_id, pending_event_count, "
                "first_pending_event_at, observed_through, dirty_flag, active_job_id, pending_job_id, "
                "active_event_cutoff_seq, last_summarized_rowid"
                ") VALUES (?, ?, ?, ?, ?, 0, NULL, NULL, 0, NULL, NULL, 0, 0)",
                (task_id, session.session_ref, owner_id, session.repo_id, session.checkout_id),
            )
            last_rowid, active_jid, pending_jid, dirty = 0, None, None, 0
        else:
            last_rowid, active_jid, pending_jid, dirty = int(wrow[0]), wrow[1], wrow[2], int(wrow[3])

        cur = db.execute(
            "INSERT INTO session_task_events ("
            "task_id, session_ref, producer_stream, sequence, event_id, harness_id, kind, "
            "recorded_at, payload_digest, event_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT (task_id, producer_stream, sequence) DO NOTHING",
            (
                task_id,
                session.session_ref,
                producer_stream,
                event.sequence,
                event.event_id,
                event.harness_id,
                event.kind,
                event.recorded_at,
                payload_digest,
                event_json,
            ),
        )
        inserted = cur.rowcount > 0
        pending_count, first_at = recompute_task_pending(db, task_id, last_rowid)
        next_dirty = 1 if (dirty or (inserted and (active_jid is not None or pending_jid is not None))) else 0
        db.execute(
            "UPDATE continuity_refresh_state SET session_ref = ?, pending_event_count = ?, "
            "first_pending_event_at = ?, dirty_flag = ? WHERE task_id = ?",
            (session.session_ref, pending_count, first_at, next_dirty, task_id),
        )

    def refresh_session_liveness(
        self,
        *,
        session_ref: str,
        checkout_id: str,
        now: datetime,
        process_killed: bool = False,
    ) -> tuple[SessionRecord, str | None]:
        """Re-evaluate liveness at ``now`` and create an ``in_progress_unknown`` checkpoint when overdue."""
        require_ready(self._store, self._policy)
        validate_session_ref_args(session_ref, checkout_id=checkout_id)
        if type(process_killed) is not bool:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid process_killed")
        now_utc, _ = require_aware_utc(now)
        stamp = utc_timestamp(now_utc)

        with self._store.transaction() as txn:
            srow = txn.db.execute(
                f"SELECT {SESSION_SELECT_COLS} FROM sessions WHERE session_ref = ? AND checkout_id = ?",
                (session_ref, checkout_id),
            ).fetchone()
            if srow is None:
                raise BrainError(ErrorCode.NOT_FOUND, "session not found")
            session = decode_session(tuple(srow))
            ckpt_exists = (
                txn.db.execute(
                    "SELECT 1 FROM session_checkpoints "
                    "WHERE session_ref = ? AND checkpoint_kind = 'in_progress_unknown' LIMIT 1",
                    (session_ref,),
                ).fetchone()
                is not None
            )
            decision = decide_session_liveness(
                recorded_state=session.state,
                last_event_at=parse_iso_utc(session.last_event_at),
                now=now_utc,
                checkpoint_exists=ckpt_exists,
                has_end_event=session.state is SessionState.ENDED,
                has_resumed_after_end=False,
                process_killed=process_killed,
            )
            if decision.state is not session.state:
                txn.db.execute(
                    "UPDATE sessions SET state = ? WHERE session_ref = ?",
                    (decision.state.value, session_ref),
                )
            ckpt_id: str | None = None
            if decision.should_create_unknown_checkpoint:
                ckpt_id = new_id()
                unknown_json = canonical_json(
                    {"last_event_at": session.last_event_at, "process_killed": process_killed}
                ).decode("utf-8")
                txn.db.execute(
                    "INSERT INTO session_checkpoints ("
                    "checkpoint_id, session_ref, task_id, checkpoint_kind, payload_json, updated_at) "
                    "VALUES (?, ?, NULL, 'in_progress_unknown', ?, ?)",
                    (ckpt_id, session_ref, unknown_json, stamp),
                )
            out = txn.db.execute(
                f"SELECT {SESSION_SELECT_COLS} FROM sessions WHERE session_ref = ?", (session_ref,)
            ).fetchone()
            assert out is not None
            return decode_session(tuple(out)), ckpt_id

    def read_long_running_checkpoint(self, task_id: str) -> LongRunningCheckpoint | None:
        """Read current durable ``LongRunningCheckpoint`` persisted for ``task_id``."""
        require_ready(self._store, self._policy)
        require_opaque_id(task_id, label="task_id")
        try:
            row = self._store._db.execute(
                "SELECT payload_json FROM session_checkpoints WHERE task_id = ? AND checkpoint_kind = 'long_running'",
                (task_id,),
            ).fetchone()
        except sqlite3.Error as exc:
            raise sqlite_error("cannot read long_running checkpoint", exc) from exc
        return None if row is None else decode_checkpoint(str(row[0]))

    def read_producer_watermark(
        self,
        producer_stream: str,
        *,
        repo_id: str | None = None,
        checkout_id: str | None = None,
    ) -> int:
        """Return monotonic ``high_seq`` persisted for ``producer_stream`` (0 when absent)."""
        require_ready(self._store, self._policy)
        require_opaque_id(producer_stream, label="producer_stream")
        if repo_id is not None:
            require_opaque_id(repo_id, label="repo_id")
        if checkout_id is not None:
            require_opaque_id(checkout_id, label="checkout_id")
        try:
            row = self._store._db.execute(
                "SELECT high_seq FROM producer_watermarks WHERE producer_stream = ?",
                (producer_stream,),
            ).fetchone()
        except sqlite3.Error as exc:
            raise sqlite_error("cannot read producer_watermarks", exc) from exc
        return 0 if row is None else int(row[0])

    def get_continuity_worker_state(self, task_id: str) -> ContinuityWorkerState | None:
        require_ready(self._store, self._policy)
        require_opaque_id(task_id, label="task_id")
        try:
            row = self._store._db.execute(
                "SELECT task_id, owner_id, repo_id, checkout_id, pending_event_count, "
                "first_pending_event_at, observed_through, dirty_flag, active_job_id, pending_job_id "
                "FROM continuity_refresh_state WHERE task_id = ?",
                (task_id,),
            ).fetchone()
        except sqlite3.Error as exc:
            raise sqlite_error("cannot read continuity_refresh_state", exc) from exc
        return None if row is None else decode_worker_state(tuple(row))

    def build_refresh_job_payload(self, task_id: str) -> tuple[bytes, int, int] | None:
        require_ready(self._store, self._policy)
        require_opaque_id(task_id, label="task_id")
        wrow = self._store._db.execute(
            "SELECT last_summarized_rowid FROM continuity_refresh_state WHERE task_id = ?", (task_id,)
        ).fetchone()
        if wrow is None:
            return None
        rows = self._store._db.execute(
            "SELECT event_order, event_json FROM session_task_events "
            "WHERE task_id = ? AND event_order > ? ORDER BY event_order ASC",
            (task_id, int(wrow[0])),
        ).fetchall()
        if not rows:
            return None
        max_order = int(rows[-1][0])
        events_list = [json.loads(str(r[1])) for r in rows]
        payload = canonical_json({"cutoff_order": max_order, "events": events_list, "task_id": task_id})
        return payload, max_order, len(events_list)

    def reserve_pending_job(self, task_id: str, job_id: str, *, now: datetime) -> None:
        _ = now
        require_ready(self._store, self._policy)
        with self._store.transaction() as txn:
            txn.db.execute(
                "UPDATE continuity_refresh_state SET pending_job_id = ? WHERE task_id = ?",
                (job_id, task_id),
            )

    def mark_job_running(self, task_id: str, job_id: str, *, now: datetime) -> None:
        _ = now
        require_ready(self._store, self._policy)
        with self._store.transaction() as txn:
            txn.db.execute(
                "UPDATE continuity_refresh_state SET active_job_id = ?, pending_job_id = NULL WHERE task_id = ?",
                (job_id, task_id),
            )

    def check_automatic_capture_enabled(self, repo_id: str) -> bool:
        require_ready(self._store, self._policy)
        return self._policy.repo_policy_flags(repo_id)[1]

    def check_manual_submission_enabled(self, repo_id: str) -> bool:
        require_ready(self._store, self._policy)
        return self._policy.repo_policy_flags(repo_id)[2]

    def read_task_owner(self, task_id: str) -> tuple[str, str, str]:
        require_ready(self._store, self._policy)
        row = self._store._db.execute(
            "SELECT owner_id, repo_id, checkout_id FROM tasks WHERE task_id = ?", (task_id,)
        ).fetchone()
        if row is None:
            raise BrainError(ErrorCode.NOT_FOUND, "task not found")
        return str(row[0]), str(row[1]), str(row[2])

    def read_events_for_streams(
        self, task_id: str, stream_watermarks: Mapping[str, int]
    ) -> tuple[ContinuityEventRow, ...]:
        require_ready(self._store, self._policy)
        rows = self._store._db.execute(
            "SELECT producer_stream, sequence, event_json, payload_digest FROM session_task_events "
            "WHERE task_id = ? ORDER BY event_order ASC",
            (task_id,),
        ).fetchall()
        out: list[ContinuityEventRow] = []
        for stream, seq_raw, ev_json, dig in rows:
            stream_s, seq = str(stream), int(seq_raw)
            if seq <= int(stream_watermarks.get(stream_s, 0)):
                continue
            out.append(
                ContinuityEventRow(
                    producer_stream=stream_s,
                    sequence=seq,
                    record=CaptureEventRecord.from_dict(json.loads(str(ev_json))),
                    payload_digest=str(dig),
                )
            )
        return tuple(out)

    def has_restricted_blobs_for_events(self, events: Sequence[tuple[str, int, str, str]]) -> bool:
        require_ready(self._store, self._policy)
        return any(
            self._policy.is_quarantined(payload_digest) or self._policy.is_tombstoned("event", event_id)
            for _stream, _seq, event_id, payload_digest in events
        )

    def clear_inflight_job_on_skip(self, task_id: str, job_id: str, *, now: datetime) -> None:
        _ = now
        require_ready(self._store, self._policy)
        with self._store.transaction() as txn:
            txn.db.execute(
                "UPDATE continuity_refresh_state SET "
                "active_job_id = CASE WHEN active_job_id = ? THEN NULL ELSE active_job_id END, "
                "pending_job_id = CASE WHEN pending_job_id = ? THEN NULL ELSE pending_job_id END "
                "WHERE task_id = ?",
                (job_id, job_id, task_id),
            )

    def apply_worker_commit_in_tx(
        self,
        tx: object,
        *,
        task_id: str,
        job_id: str,
        observed_digest: str,
        observed_summary: Mapping[str, JsonValue],
        now: datetime,
        dirty_followup_fn: Callable[[object], str | None] | None = None,
    ) -> ContinuityCommitOutcome:
        require_ready(self._store, self._policy)
        txn = getattr(tx, "_txn", None)
        if not isinstance(txn, Txn):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "expected StoreKernelTx transaction")
        db = txn.db
        now_utc, _ = require_aware_utc(now)
        stamp = utc_timestamp(now_utc)
        expires_at = now_utc + _EVENT_RETENTION

        if not self._store.cas.blob_intact(observed_digest):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "observed summary blob not staged in CAS")
        txn.hold(observed_digest, "event", job_id, RetentionClass.DURABLE, expires_at)

        hrow = db.execute(f"SELECT {TASK_SELECT_COLS} FROM task_handoffs WHERE task_id = ?", (task_id,)).fetchone()
        if hrow is None:
            raise BrainError(ErrorCode.NOT_FOUND, "task handoff not found")
        cur = decode_handoff(tuple(hrow))

        wrow = db.execute(
            "SELECT session_ref, last_summarized_rowid FROM continuity_refresh_state WHERE task_id = ?", (task_id,)
        ).fetchone()
        if wrow is None:
            raise BrainError(ErrorCode.NOT_FOUND, "continuity_refresh_state not found")
        session_ref, prev_rowid = str(wrow[0]), int(wrow[1])

        raw_sources = observed_summary.get("source_events")
        next_rowid, saw_lr = prev_rowid, False
        if isinstance(raw_sources, Sequence) and not isinstance(raw_sources, (str, bytes)):
            for item in raw_sources:
                if not isinstance(item, Sequence) or len(item) < 2:
                    continue
                raw_seq = item[1]
                seq_v = raw_seq if type(raw_seq) is int else -1
                if seq_v < 1:
                    continue
                erow = db.execute(
                    "SELECT event_order, kind FROM session_task_events "
                    "WHERE task_id = ? AND producer_stream = ? AND sequence = ?",
                    (task_id, str(item[0]), seq_v),
                ).fetchone()
                if erow is not None:
                    next_rowid = max(next_rowid, int(erow[0]))
                    saw_lr = saw_lr or str(erow[1]) == "long_running_job"

        remaining_count, earliest_at = recompute_task_pending(db, task_id, next_rowid)
        raw_last_ev = observed_summary.get("last_event_at")
        next_obs_through = str(raw_last_ev) if isinstance(raw_last_ev, str) and raw_last_ev else cur.observed_through
        next_current_rev = cur.current_revision + 1
        next_source = cur.task_state_source if cur.agent_ref is not None else "inferred"

        db.execute(
            "UPDATE task_handoffs SET observed_ref = ?, current_revision = ?, task_state_source = ?, "
            "observed_through = ? WHERE task_id = ?",
            (observed_digest, next_current_rev, next_source, next_obs_through, task_id),
        )
        db.execute(
            "UPDATE tasks SET current_revision = ?, task_state_source = ?, updated_at = ? WHERE task_id = ?",
            (next_current_rev, next_source, stamp, task_id),
        )
        db.execute(
            "INSERT INTO handoff_revisions "
            "(task_id, handoff_revision, source_kind, agent_ref, observed_ref, recorded_at) "
            "VALUES (?, ?, 'observed', ?, ?, ?)",
            (task_id, cur.handoff_revision, cur.agent_ref, observed_digest, stamp),
        )
        persist_long_running_checkpoint(
            db,
            task_id=task_id,
            session_ref=session_ref,
            long_running_raw=observed_summary.get("long_running"),
            saw_long_running_event=saw_lr,
            stamp=stamp,
            new_id_fn=new_id,
        )
        db.execute(
            "UPDATE continuity_refresh_state SET pending_event_count = ?, first_pending_event_at = ?, "
            "observed_through = ?, dirty_flag = 0, active_job_id = NULL, pending_job_id = NULL, "
            "last_summarized_rowid = ? WHERE task_id = ?",
            (remaining_count, earliest_at, next_obs_through, next_rowid, task_id),
        )
        followup_id = dirty_followup_fn(tx) if dirty_followup_fn is not None else None
        return ContinuityCommitOutcome(
            task_id=task_id,
            job_id=job_id,
            observed_ref=observed_digest,
            current_revision=next_current_rev,
            handoff_revision=cur.handoff_revision,
            dirty_followup_job_id=followup_id,
        )
