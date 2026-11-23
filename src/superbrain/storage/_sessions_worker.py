"""SP2-3 session event recording, liveness refresh, watermarks, and continuity worker store mixin."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timedelta

from superbrain.core._kernel_base import require_opaque_id, require_sha256_digest
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import require_aware_utc
from superbrain.ports._continuity_checkpoint import extract_long_running_checkpoint
from superbrain.ports.capture import CaptureEventRecord
from superbrain.ports.continuity import (
    ContinuityCommitOutcome,
    ContinuityEventRow,
    ContinuityWorkerState,
    LongRunningCheckpoint,
    SessionRecord,
    SessionState,
    decide_session_liveness,
)
from superbrain.storage._sessions_sources import (
    _advance_session_in_tx,
    bound_task_for_session,
    close_refresh_batch,
    legacy_sweep_rows,
    link_task_event,
    live_event_record,
    refresh_candidates,
    resolve_refresh_sources,
)
from superbrain.storage._sessions_sql import (
    SESSION_SELECT_COLS,
    TASK_SELECT_COLS,
    decode_checkpoint_source,
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
from superbrain.storage.cas import held_digests
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
                txn.hold(payload_digest, "event", holder_id, RetentionClass.EVENT_PAYLOAD, expires_at)
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

            _advance_session_in_tx(txn.db, session, event)

            if task_id is not None:
                link_task_event(
                    txn.db,
                    task_id=task_id,
                    session=session,
                    producer_stream=producer_stream,
                    event=event,
                    payload_digest=payload_digest,
                )

            out = txn.db.execute(
                f"SELECT {SESSION_SELECT_COLS} FROM sessions WHERE session_ref = ?", (session_ref,)
            ).fetchone()
            assert out is not None
            return decode_session(tuple(out))

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
        if row is None:
            return None
        stream, seq, event_id, digest = decode_checkpoint_source(str(row[0]))
        # Fields come from the pinned, verified source event at read time; anything else yields nothing.
        record = self._live_event_record(task_id, stream, seq, event_id, digest, now=self._policy._os.clock.now())
        return None if record is None else extract_long_running_checkpoint([record])

    def _live_event_record(
        self, task_id: str, producer_stream: str, sequence: int, event_id: str, payload_digest: str, *, now: datetime
    ) -> CaptureEventRecord | None:
        return live_event_record(
            self._store, self._policy, task_id=task_id, producer_stream=producer_stream, sequence=sequence,
            event_id=event_id, payload_digest=payload_digest, now=now,
        )

    def resolve_refresh_sources(self, payload: bytes, *, now: datetime) -> bytes:
        """Worker input built in memory from the job's refs; sources no longer live are left out."""
        require_ready(self._store, self._policy)
        return resolve_refresh_sources(self._store, self._policy, payload, now=now)

    def refresh_candidate_tasks(
        self, limit: int, after: tuple[str, str] | None = None
    ) -> tuple[tuple[str, str], ...]:
        """Tasks with committed events not yet summarized, oldest first (the durable refresh wake list)."""
        require_ready(self._store, self._policy)
        try:
            return refresh_candidates(self._store._db, limit, after)
        except sqlite3.Error as exc:
            raise sqlite_error("cannot read continuity refresh candidates", exc) from exc

    def link_committed_event_in_tx(
        self,
        db: sqlite3.Connection,
        *,
        event: CaptureEventRecord,
        payload_digest: str,
        repo_id: str,
        checkout_id: str,
    ) -> str | None:
        """Inside the capture commit: advance the event's session and link it to the task bound to that session.

        Returns the linked task ID, or ``None`` when the event has no bound session or the session has no task.
        """
        if event.session_ref is None:
            return None
        srow = db.execute(
            f"SELECT {SESSION_SELECT_COLS} FROM sessions WHERE session_ref = ? AND repo_id = ? AND checkout_id = ?",
            (event.session_ref, repo_id, checkout_id),
        ).fetchone()
        if srow is None:
            return None
        session = decode_session(tuple(srow))
        _advance_session_in_tx(db, session, event)
        task_id = bound_task_for_session(db, event.session_ref, repo_id, checkout_id)
        if task_id is None:
            return None
        link_task_event(
            db,
            task_id=task_id,
            session=session,
            producer_stream=event.producer_stream,
            event=event,
            payload_digest=payload_digest,
        )
        return task_id

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
        try:
            wrow = self._store._db.execute(
                "SELECT last_summarized_rowid FROM continuity_refresh_state WHERE task_id = ?", (task_id,)
            ).fetchone()
            if wrow is None:
                return None
            rows = self._store._db.execute(
                "SELECT event_order, producer_stream, sequence, event_id, payload_digest FROM session_task_events "
                "WHERE task_id = ? AND event_order > ? ORDER BY event_order ASC",
                (task_id, int(wrow[0])),
            ).fetchall()
        except sqlite3.Error as exc:
            raise sqlite_error("cannot read the pending continuity batch", exc) from exc
        if not rows:
            return None
        max_order = int(rows[-1][0])
        # Refs only: the job payload must not outlive or copy the events it names (spec 5.6, 7.4).
        refs: list[JsonValue] = [
            {"event_id": str(r[3]), "payload_digest": str(r[4]), "producer_stream": str(r[1]), "sequence": int(r[2])}
            for r in rows
        ]
        payload = canonical_json({"cutoff_order": max_order, "events": refs, "task_id": task_id})
        return payload, max_order, len(refs)

    def reserve_pending_job_in_tx(self, tx: object, task_id: str, job_id: str) -> None:
        """Record ``job_id`` as the task's pending job inside the transaction that enqueues it."""
        require_ready(self._store, self._policy)
        txn = _txn_of(tx)
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
        try:
            row = self._store._db.execute(
                "SELECT owner_id, repo_id, checkout_id FROM tasks WHERE task_id = ?", (task_id,)
            ).fetchone()
        except sqlite3.Error as exc:
            raise sqlite_error("cannot read task owner", exc) from exc
        if row is None:
            raise BrainError(ErrorCode.NOT_FOUND, "task not found")
        return str(row[0]), str(row[1]), str(row[2])

    def read_events_for_streams(
        self, task_id: str, stream_watermarks: Mapping[str, int]
    ) -> tuple[ContinuityEventRow, ...]:
        require_ready(self._store, self._policy)
        try:
            rows = self._store._db.execute(
                "SELECT producer_stream, sequence, event_id, payload_digest FROM session_task_events "
                "WHERE task_id = ? ORDER BY event_order ASC",
                (task_id,),
            ).fetchall()
        except sqlite3.Error as exc:
            raise sqlite_error("cannot read linked events", exc) from exc
        now = self._policy._os.clock.now()
        out: list[ContinuityEventRow] = []
        for stream, seq_raw, event_id, dig in rows:
            stream_s, seq = str(stream), int(seq_raw)
            if seq <= int(stream_watermarks.get(stream_s, 0)):
                continue
            record = self._live_event_record(task_id, stream_s, seq, str(event_id), str(dig), now=now)
            if record is None:
                continue
            out.append(
                ContinuityEventRow(producer_stream=stream_s, sequence=seq, record=record, payload_digest=str(dig))
            )
        return tuple(out)

    def has_restricted_blobs_for_events(self, task_id: str, events: Sequence[tuple[str, int, str, str]]) -> bool:
        require_ready(self._store, self._policy)
        now = self._policy._os.clock.now()
        return any(
            self._live_event_record(task_id, stream, seq, event_id, payload_digest, now=now) is None
            for stream, seq, event_id, payload_digest in events
        )

    def legacy_sweep_rows(self) -> tuple[tuple[str, str], ...]:
        require_ready(self._store, self._policy)
        return legacy_sweep_rows(self._store._db)

    def clear_legacy_sweep_in_tx(self, tx: object, job_id: str) -> None:
        """Release (``superseded``) every legacy copy still held for ``job_id`` and drop its sweep rows."""
        require_ready(self._store, self._policy)
        txn = _txn_of(tx)
        rows = txn.db.execute("SELECT digest FROM continuity_legacy_sweep WHERE job_id = ?", (job_id,)).fetchall()
        held = set(held_digests(txn.db, "event", job_id))
        for (digest,) in rows:
            if str(digest) in held:
                txn.release(str(digest), "event", job_id, "superseded")
        txn.db.execute("DELETE FROM continuity_legacy_sweep WHERE job_id = ?", (job_id,))

    def close_refresh_batch_in_tx(self, tx: object, *, task_id: str, cutoff_order: int) -> None:
        require_ready(self._store, self._policy)
        close_refresh_batch(_txn_of(tx).db, task_id, cutoff_order)

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
        cutoff_order: int = 0,
    ) -> ContinuityCommitOutcome:
        require_ready(self._store, self._policy)
        txn = _txn_of(tx)
        db = txn.db
        now_utc, _ = require_aware_utc(now)
        stamp = utc_timestamp(now_utc)
        expires_at = now_utc + _EVENT_RETENTION

        if not self._store.cas.blob_intact(observed_digest):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "observed summary blob not staged in CAS")
        txn.hold(observed_digest, "event", job_id, RetentionClass.EVENT_PAYLOAD, expires_at)

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

        next_rowid = max(next_rowid, cutoff_order)
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
            long_running_source=observed_summary.get("long_running_source"),
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


def _txn_of(tx: object) -> Txn:
    txn = getattr(tx, "_txn", None)
    if not isinstance(txn, Txn):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "expected StoreKernelTx transaction")
    return txn
