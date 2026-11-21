"""Store v6 capture event persistence, CAS 90-day holds, producer watermarks, and gap tracking."""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from datetime import datetime, timedelta

from superbrain.core._kernel_base import require_opaque_id, require_positive_int
from superbrain.core._kernel_dispatch import require_aware_utc
from superbrain.core.canonical import canonical_json
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.faults import crashpoint
from superbrain.core.ids import new_id
from superbrain.ports.capture import (
    CaptureBatchAck,
    CaptureHealthSnapshot,
    CaptureStorePort,
    ProducerCaptureGap,
    StagedCaptureEvent,
    compute_contiguous_event_acked_through,
)
from superbrain.storage.errors import sqlite_error
from superbrain.storage.kinds import RetentionClass
from superbrain.storage.store import Store

_EVENT_RETENTION = timedelta(days=90)


def _event_identity(
    ev: StagedCaptureEvent, *, repo_id: str, checkout_id: str
) -> tuple[str, str, str, str, str, str, str, str | None]:
    r = ev.record
    return (
        r.event_id,
        ev.payload_digest,
        r.kind,
        r.recorded_at,
        r.harness_id,
        repo_id,
        checkout_id,
        r.session_ref,
    )


def _gap_identity(gap: ProducerCaptureGap) -> tuple[str, str, str]:
    return (gap.gap_id, gap.reason, gap.recorded_at)


class KernelCaptureStore(CaptureStorePort):
    """Transactional ``store v6`` capture storage backed by ``Store`` + 90-day ``EVENT_PAYLOAD`` CAS holds."""

    def __init__(self, store: Store) -> None:
        if not isinstance(store, Store):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        self._store = store

    def _require_v6(self) -> None:
        if self._store.schema_version < 6:
            raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")

    def _read_existing_state(
        self,
        db: sqlite3.Connection,
        producer_stream: str,
    ) -> tuple[
        dict[int, tuple[str, str, str, str, str, str, str, str | None]],
        dict[int, tuple[str, str, str]],
        set[int],
    ]:
        ev_rows = db.execute(
            "SELECT sequence, event_id, payload_digest, kind, recorded_at, harness_id, "
            "repo_id, checkout_id, session_ref "
            "FROM capture_events WHERE producer_stream = ?",
            (producer_stream,),
        ).fetchall()
        events_by_seq: dict[int, tuple[str, str, str, str, str, str, str, str | None]] = {}
        for row in ev_rows:
            seq = int(row[0])
            events_by_seq[seq] = (
                str(row[1]),
                str(row[2]),
                str(row[3]),
                str(row[4]),
                str(row[5]),
                str(row[6]),
                str(row[7]),
                None if row[8] is None else str(row[8]),
            )

        gap_rows = db.execute(
            "SELECT sequence, gap_origin, gap_id, reason, recorded_at FROM capture_gaps WHERE producer_stream = ?",
            (producer_stream,),
        ).fetchall()
        prod_gaps: dict[int, tuple[str, str, str]] = {}
        daemon_gaps: set[int] = set()
        for row in gap_rows:
            seq = int(row[0])
            origin = str(row[1])
            if origin == "producer":
                prod_gaps[seq] = (str(row[2]), str(row[3]), str(row[4]))
            elif origin == "daemon":
                daemon_gaps.add(seq)
        return events_by_seq, prod_gaps, daemon_gaps

    def commit_staged_batch(
        self,
        *,
        producer_stream: str,
        repo_id: str,
        checkout_id: str,
        principal_id: str,
        events: Sequence[StagedCaptureEvent],
        gaps: Sequence[ProducerCaptureGap],
        now: datetime,
    ) -> CaptureBatchAck:
        """Stage event payloads in CAS outside TX, then commit events/gaps/holds/watermarks atomically."""
        self._require_v6()
        require_opaque_id(producer_stream, label="producer_stream")
        require_opaque_id(repo_id, label="repo_id")
        require_opaque_id(checkout_id, label="checkout_id")
        require_opaque_id(principal_id, label="principal_id")
        require_aware_utc(now)

        seen_events: dict[int, StagedCaptureEvent] = {}
        for ev in events:
            if not isinstance(ev, StagedCaptureEvent) or ev.record.producer_stream != producer_stream:
                raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
            prev_ev = seen_events.get(ev.record.sequence)
            if prev_ev is None:
                seen_events[ev.record.sequence] = ev
            elif _event_identity(prev_ev, repo_id=repo_id, checkout_id=checkout_id) != _event_identity(
                ev, repo_id=repo_id, checkout_id=checkout_id
            ):
                raise BrainError(ErrorCode.IDEMPOTENCY_CONFLICT, "idempotency conflict")

        seen_gaps: dict[int, ProducerCaptureGap] = {}
        for gap in gaps:
            if not isinstance(gap, ProducerCaptureGap) or gap.producer_stream != producer_stream:
                raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
            prev_gap = seen_gaps.get(gap.sequence)
            if prev_gap is None:
                seen_gaps[gap.sequence] = gap
            elif _gap_identity(prev_gap) != _gap_identity(gap):
                raise BrainError(ErrorCode.IDEMPOTENCY_CONFLICT, "idempotency conflict")

        self._store._check()
        try:
            existing_events, existing_prod_gaps, _ = self._read_existing_state(self._store._db, producer_stream)
        except sqlite3.Error as exc:
            raise sqlite_error("cannot read existing capture state", exc) from exc

        for seq, ev in seen_events.items():
            stored = existing_events.get(seq)
            if stored is not None and stored != _event_identity(ev, repo_id=repo_id, checkout_id=checkout_id):
                raise BrainError(ErrorCode.IDEMPOTENCY_CONFLICT, "idempotency conflict")
            if seq not in existing_events:
                staged_dig = self._store.cas.put(ev.payload_bytes)
                if staged_dig != ev.payload_digest:
                    raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")

        for seq, gap in seen_gaps.items():
            stored_gap = existing_prod_gaps.get(seq)
            if stored_gap is not None and stored_gap != _gap_identity(gap):
                raise BrainError(ErrorCode.IDEMPOTENCY_CONFLICT, "idempotency conflict")

        any_fresh_commit = False
        accepted_count = 0
        deduped_count = 0
        committed_seqs: set[int] = set()
        acked_gap_seqs: set[int] = set()

        with self._store.transaction() as txn:
            clock_now, committed_at = require_aware_utc(self._store._os.clock.now())
            expires_at_dt = clock_now + _EVENT_RETENTION
            cur_events, cur_prod_gaps, cur_daemon_gaps = self._read_existing_state(txn.db, producer_stream)

            for ev in events:
                seq = ev.record.sequence
                ident = _event_identity(ev, repo_id=repo_id, checkout_id=checkout_id)
                stored = cur_events.get(seq)
                if stored is not None:
                    if stored != ident:
                        raise BrainError(ErrorCode.IDEMPOTENCY_CONFLICT, "idempotency conflict")
                    deduped_count += 1
                    committed_seqs.add(seq)
                    continue
                cas_holder_id = new_id()
                txn.hold(ev.payload_digest, "event", cas_holder_id, RetentionClass.EVENT_PAYLOAD, expires_at_dt)
                txn.db.execute(
                    "INSERT INTO capture_events ("
                    "producer_stream, sequence, event_id, harness_id, kind, recorded_at, payload_digest, "
                    "cas_holder_id, source, source_verification, repo_id, checkout_id, principal_id, "
                    "session_ref, source_metadata_json, committed_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        producer_stream,
                        seq,
                        ev.record.event_id,
                        ev.record.harness_id,
                        ev.record.kind,
                        ev.record.recorded_at,
                        ev.payload_digest,
                        cas_holder_id,
                        ev.source,
                        ev.source_verification,
                        repo_id,
                        checkout_id,
                        principal_id,
                        ev.record.session_ref,
                        canonical_json(ev.record.source_metadata),
                        committed_at,
                    ),
                )
                if seq in cur_daemon_gaps:
                    txn.db.execute(
                        "DELETE FROM capture_gaps WHERE producer_stream = ? AND sequence = ? "
                        "AND gap_origin = 'daemon' AND status = 'open'",
                        (producer_stream, seq),
                    )
                cur_events[seq] = ident
                accepted_count += 1
                any_fresh_commit = True
                committed_seqs.add(seq)

            for gap in gaps:
                seq = gap.sequence
                g_ident = _gap_identity(gap)
                stored_g = cur_prod_gaps.get(seq)
                if stored_g is not None:
                    if stored_g != g_ident:
                        raise BrainError(ErrorCode.IDEMPOTENCY_CONFLICT, "idempotency conflict")
                    deduped_count += 1
                    acked_gap_seqs.add(seq)
                    continue
                txn.db.execute(
                    "INSERT INTO capture_gaps ("
                    "gap_id, producer_stream, sequence, gap_origin, status, reason, estimated_count, "
                    "duration_ms, repo_id, checkout_id, recorded_at, closed_at"
                    ") VALUES (?, ?, ?, 'producer', 'producer', ?, ?, ?, ?, ?, ?, NULL)",
                    (
                        gap.gap_id,
                        producer_stream,
                        seq,
                        gap.reason,
                        gap.estimated_count,
                        gap.duration_ms,
                        repo_id,
                        checkout_id,
                        gap.recorded_at,
                    ),
                )
                if seq in cur_daemon_gaps:
                    txn.db.execute(
                        "DELETE FROM capture_gaps WHERE producer_stream = ? AND sequence = ? "
                        "AND gap_origin = 'daemon' AND status = 'open'",
                        (producer_stream, seq),
                    )
                cur_prod_gaps[seq] = g_ident
                accepted_count += 1
                any_fresh_commit = True
                acked_gap_seqs.add(seq)

            # Refresh daemon gap detection across [1..high_seq] for this producer stream.
            high_seq = max((*cur_events.keys(), *cur_prod_gaps.keys()), default=0)
            contiguous = compute_contiguous_event_acked_through(cur_events.keys())
            for missing_seq in range(1, high_seq + 1):
                if (
                    missing_seq not in cur_events
                    and missing_seq not in cur_prod_gaps
                    and missing_seq not in cur_daemon_gaps
                ):
                    txn.db.execute(
                        "INSERT INTO capture_gaps ("
                        "gap_id, producer_stream, sequence, gap_origin, status, reason, estimated_count, "
                        "duration_ms, repo_id, checkout_id, recorded_at, closed_at"
                        ") VALUES (?, ?, ?, 'daemon', 'open', 'dropped', 1, NULL, ?, ?, ?, NULL)",
                        (new_id(), producer_stream, missing_seq, repo_id, checkout_id, committed_at),
                    )
                    cur_daemon_gaps.add(missing_seq)

            txn.db.execute(
                "INSERT INTO producer_watermarks (producer_stream, high_seq, contiguous_seq, updated_at) "
                "VALUES (?, ?, ?, ?) ON CONFLICT (producer_stream) DO UPDATE SET "
                "high_seq = excluded.high_seq, contiguous_seq = excluded.contiguous_seq, "
                "updated_at = excluded.updated_at",
                (producer_stream, high_seq, contiguous, committed_at),
            )

        if any_fresh_commit:
            crashpoint("capture.daemon.after_commit_before_ack")

        return CaptureBatchAck(
            producer_stream=producer_stream,
            repo_id=repo_id,
            checkout_id=checkout_id,
            committed_event_sequences=tuple(sorted(committed_seqs)),
            contiguous_event_acked_through=contiguous,
            acked_producer_gap_sequences=tuple(sorted(acked_gap_seqs)),
            accepted_count=accepted_count,
            deduped_count=deduped_count,
            policy_disabled=False,
        )

    def mark_daemon_gap_closed(
        self,
        *,
        producer_stream: str,
        sequence: int,
        now: datetime,
        repo_id: str | None = None,
        checkout_id: str | None = None,
    ) -> None:
        """Persistently mark a daemon-detected sequence gap as ``closed`` inside a store transaction."""
        self._require_v6()
        require_opaque_id(producer_stream, label="producer_stream")
        require_positive_int(sequence)
        _, closed_at = require_aware_utc(now)
        if repo_id is not None:
            require_opaque_id(repo_id, label="repo_id")
        if checkout_id is not None:
            require_opaque_id(checkout_id, label="checkout_id")

        with self._store.transaction() as txn:
            cur = txn.db.execute(
                "UPDATE capture_gaps SET status = 'closed', closed_at = ? "
                "WHERE producer_stream = ? AND sequence = ? AND gap_origin = 'daemon'",
                (closed_at, producer_stream, sequence),
            )
            if cur.rowcount == 0:
                txn.db.execute(
                    "INSERT INTO capture_gaps ("
                    "gap_id, producer_stream, sequence, gap_origin, status, reason, estimated_count, "
                    "duration_ms, repo_id, checkout_id, recorded_at, closed_at"
                    ") VALUES (?, ?, ?, 'daemon', 'closed', 'dropped', 1, NULL, ?, ?, ?, ?) "
                    "ON CONFLICT (producer_stream, sequence, gap_origin) DO UPDATE SET "
                    "status = 'closed', closed_at = excluded.closed_at",
                    (new_id(), producer_stream, sequence, repo_id, checkout_id, closed_at, closed_at),
                )

    def read_capture_health(self) -> CaptureHealthSnapshot:
        """Read durable store v6 event/gap counts without modifying store state."""
        self._store._check()
        if self._store.schema_version < 6:
            return CaptureHealthSnapshot(total_events=0, open_gaps=0, closed_gaps=0, producer_gaps=0)
        try:
            ev_row = self._store._db.execute("SELECT COUNT(*) FROM capture_events").fetchone()
            open_row = self._store._db.execute(
                "SELECT COUNT(*) FROM capture_gaps WHERE status = 'open'"
            ).fetchone()
            closed_row = self._store._db.execute(
                "SELECT COUNT(*) FROM capture_gaps WHERE status = 'closed'"
            ).fetchone()
            prod_row = self._store._db.execute(
                "SELECT COUNT(*) FROM capture_gaps WHERE gap_origin = 'producer'"
            ).fetchone()
        except sqlite3.Error as exc:
            raise sqlite_error("cannot read capture health", exc) from exc
        return CaptureHealthSnapshot(
            total_events=int(ev_row[0]) if ev_row is not None else 0,
            open_gaps=int(open_row[0]) if open_row is not None else 0,
            closed_gaps=int(closed_row[0]) if closed_row is not None else 0,
            producer_gaps=int(prod_row[0]) if prod_row is not None else 0,
        )

    def has_gaps(self) -> bool:
        """True if any open, closed, or producer capture gap is persisted in ``brain.db``."""
        return self.read_capture_health().has_gaps
