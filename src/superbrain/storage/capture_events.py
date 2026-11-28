"""Store v6 capture event persistence, CAS 90-day holds, producer watermarks, and O(batch) interval gap tracking."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from superbrain.core._kernel_base import require_opaque_id
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
    require_capture_sequence,
)
from superbrain.ports.capture_slots import fallback_gap_id
from superbrain.storage.errors import sqlite_error
from superbrain.storage.kinds import RetentionClass
from superbrain.storage.store import Store

_EVENT_RETENTION = timedelta(days=90)
_SQL_CHUNK = 200


@dataclass
class _DaemonGapSpan:
    gap_id: str
    start: int
    end: int
    status: str
    repo_id: str | None
    checkout_id: str | None
    recorded_at: str
    closed_at: str | None


def _chunk_ints(values: Iterable[int], size: int = _SQL_CHUNK) -> Iterator[list[int]]:
    buf: list[int] = []
    for val in values:
        buf.append(val)
        if len(buf) >= size:
            yield buf
            buf = []
    if buf:
        yield buf


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


def _query_existing_events(
    db: sqlite3.Connection, producer_stream: str, seqs: Iterable[int]
) -> dict[int, tuple[str, str, str, str, str, str, str, str | None]]:
    out: dict[int, tuple[str, str, str, str, str, str, str, str | None]] = {}
    for chunk in _chunk_ints(seqs):
        placeholders = ",".join("?" for _ in chunk)
        rows = db.execute(
            "SELECT sequence, event_id, payload_digest, kind, recorded_at, harness_id, "
            f"repo_id, checkout_id, session_ref FROM capture_events "
            f"WHERE producer_stream = ? AND sequence IN ({placeholders})",
            (producer_stream, *chunk),
        ).fetchall()
        for row in rows:
            out[int(row[0])] = (
                str(row[1]), str(row[2]), str(row[3]), str(row[4]),
                str(row[5]), str(row[6]), str(row[7]), None if row[8] is None else str(row[8]),
            )
    return out


def _query_existing_prod_gaps(
    db: sqlite3.Connection, producer_stream: str, seqs: Iterable[int]
) -> dict[int, tuple[tuple[str, str, str], str, str]]:
    """Stored producer gap per sequence: ``(identity, repo_id, checkout_id)``."""
    out: dict[int, tuple[tuple[str, str, str], str, str]] = {}
    for chunk in _chunk_ints(seqs):
        placeholders = ",".join("?" for _ in chunk)
        rows = db.execute(
            "SELECT sequence, gap_id, reason, recorded_at, repo_id, checkout_id FROM capture_gaps "
            f"WHERE producer_stream = ? AND gap_origin = 'producer' AND sequence IN ({placeholders})",
            (producer_stream, *chunk),
        ).fetchall()
        for row in rows:
            out[int(row[0])] = ((str(row[1]), str(row[2]), str(row[3])), str(row[4]), str(row[5]))
    return out


def _gap_replay_is_dedup(
    stored: tuple[tuple[str, str, str], str, str], gap: ProducerCaptureGap, *, repo_id: str, checkout_id: str,
) -> bool:
    """Same identity, or (owner-approved upgrade rule) a slot-derived fallback gap replayed onto a gap an earlier
    binary committed with a random id at the same slot and scope: the hook cannot recover that id once the old frame
    was ACKed and deleted, so the stored gap stays and the replay is a dedup. Anything else stays a conflict."""
    identity, stored_repo, stored_checkout = stored
    if identity == _gap_identity(gap):
        return True
    slot_id = fallback_gap_id(gap.producer_stream, gap.sequence)
    return (
        gap.gap_id == slot_id
        and identity[0] != slot_id  # the stored gap is an earlier binary's random id, never one of ours
        and (stored_repo, stored_checkout) == (repo_id, checkout_id)
    )


def _load_daemon_spans(db: sqlite3.Connection, producer_stream: str) -> list[_DaemonGapSpan]:
    rows = db.execute(
        "SELECT gap_id, sequence, estimated_count, status, repo_id, checkout_id, recorded_at, closed_at "
        "FROM capture_gaps WHERE producer_stream = ? AND gap_origin = 'daemon' ORDER BY sequence ASC",
        (producer_stream,),
    ).fetchall()
    spans: list[_DaemonGapSpan] = []
    for row in rows:
        start = int(row[1])
        count = max(1, int(row[2]))
        spans.append(
            _DaemonGapSpan(
                gap_id=str(row[0]),
                start=start,
                end=start + count - 1,
                status=str(row[3]),
                repo_id=None if row[4] is None else str(row[4]),
                checkout_id=None if row[5] is None else str(row[5]),
                recorded_at=str(row[6]),
                closed_at=None if row[7] is None else str(row[7]),
            )
        )
    return spans


def _insert_daemon_span(
    db: sqlite3.Connection,
    *,
    producer_stream: str,
    start: int,
    end: int,
    status: str,
    repo_id: str | None,
    checkout_id: str | None,
    recorded_at: str,
    closed_at: str | None,
) -> _DaemonGapSpan:
    gid = new_id()
    db.execute(
        "INSERT INTO capture_gaps ("
        "gap_id, producer_stream, sequence, gap_origin, status, reason, estimated_count, "
        "duration_ms, repo_id, checkout_id, recorded_at, closed_at"
        ") VALUES (?, ?, ?, 'daemon', ?, 'dropped', ?, NULL, ?, ?, ?, ?)",
        (gid, producer_stream, start, status, end - start + 1, repo_id, checkout_id, recorded_at, closed_at),
    )
    return _DaemonGapSpan(
        gap_id=gid,
        start=start,
        end=end,
        status=status,
        repo_id=repo_id,
        checkout_id=checkout_id,
        recorded_at=recorded_at,
        closed_at=closed_at,
    )


def _subtract_seq_from_open_spans(
    db: sqlite3.Connection,
    spans: list[_DaemonGapSpan],
    *,
    producer_stream: str,
    seq: int,
) -> None:
    for idx, span in enumerate(spans):
        if span.status != "open" or not (span.start <= seq <= span.end):
            continue
        orig_end = span.end
        if span.start == orig_end:
            db.execute("DELETE FROM capture_gaps WHERE gap_id = ?", (span.gap_id,))
            spans.pop(idx)
        elif seq == span.start:
            new_start = seq + 1
            db.execute(
                "UPDATE capture_gaps SET sequence = ?, estimated_count = ? WHERE gap_id = ?",
                (new_start, orig_end - new_start + 1, span.gap_id),
            )
            span.start = new_start
        elif seq == orig_end:
            new_end = seq - 1
            db.execute(
                "UPDATE capture_gaps SET estimated_count = ? WHERE gap_id = ?",
                (new_end - span.start + 1, span.gap_id),
            )
            span.end = new_end
        else:
            left_end = seq - 1
            db.execute(
                "UPDATE capture_gaps SET estimated_count = ? WHERE gap_id = ?",
                (left_end - span.start + 1, span.gap_id),
            )
            span.end = left_end
            right_span = _insert_daemon_span(
                db,
                producer_stream=producer_stream,
                start=seq + 1,
                end=orig_end,
                status="open",
                repo_id=span.repo_id,
                checkout_id=span.checkout_id,
                recorded_at=span.recorded_at,
                closed_at=None,
            )
            spans.insert(idx + 1, right_span)
        return


def _add_missing_interval(
    db: sqlite3.Connection,
    spans: list[_DaemonGapSpan],
    *,
    producer_stream: str,
    start: int,
    end: int,
    repo_id: str,
    checkout_id: str,
    recorded_at: str,
) -> None:
    if start > end:
        return
    cur = start
    for sp in list(spans):
        if sp.end < cur:
            continue
        if sp.start > end:
            break
        if cur < sp.start:
            new_sp = _insert_daemon_span(
                db,
                producer_stream=producer_stream,
                start=cur,
                end=sp.start - 1,
                status="open",
                repo_id=repo_id,
                checkout_id=checkout_id,
                recorded_at=recorded_at,
                closed_at=None,
            )
            spans.append(new_sp)
        cur = max(cur, sp.end + 1)
        if cur > end:
            break
    if cur <= end:
        spans.append(
            _insert_daemon_span(
                db,
                producer_stream=producer_stream,
                start=cur,
                end=end,
                status="open",
                repo_id=repo_id,
                checkout_id=checkout_id,
                recorded_at=recorded_at,
                closed_at=None,
            )
        )
    spans.sort(key=lambda item: item.start)


class KernelCaptureStore(CaptureStorePort):
    """Transactional ``store v6`` capture storage backed by ``Store`` + 90-day ``EVENT_PAYLOAD`` CAS holds."""

    def __init__(self, store: Store) -> None:
        if not isinstance(store, Store):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        self._store = store

    def _require_v6(self) -> None:
        if self._store.schema_version < 6:
            raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")

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
        on_event_committed_in_tx: Callable[[Any, StagedCaptureEvent], None] | None = None,
    ) -> CaptureBatchAck:
        """Stage event payloads in CAS outside TX, then commit events/gaps/holds/watermarks atomically.

        ``on_event_committed_in_tx`` runs inside the same transaction for each newly committed event (never for a
        dedup), so whatever it derives commits or rolls back with the event.
        """
        self._require_v6()
        require_opaque_id(producer_stream, label="producer_stream")
        require_opaque_id(repo_id, label="repo_id")
        require_opaque_id(checkout_id, label="checkout_id")
        require_opaque_id(principal_id, label="principal_id")
        clock_now, committed_at = require_aware_utc(now)

        seen_events: dict[int, StagedCaptureEvent] = {}
        for ev in events:
            if not isinstance(ev, StagedCaptureEvent) or ev.record.producer_stream != producer_stream:
                raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
            require_capture_sequence(ev.record.sequence)
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
            require_capture_sequence(gap.sequence)
            prev_gap = seen_gaps.get(gap.sequence)
            if prev_gap is None:
                seen_gaps[gap.sequence] = gap
            elif _gap_identity(prev_gap) != _gap_identity(gap):
                raise BrainError(ErrorCode.IDEMPOTENCY_CONFLICT, "idempotency conflict")

        self._store._check()
        try:
            existing_events = _query_existing_events(self._store._db, producer_stream, seen_events.keys())
            existing_prod_gaps = _query_existing_prod_gaps(self._store._db, producer_stream, seen_gaps.keys())
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
            if stored_gap is not None and not _gap_replay_is_dedup(
                stored_gap, gap, repo_id=repo_id, checkout_id=checkout_id
            ):
                raise BrainError(ErrorCode.IDEMPOTENCY_CONFLICT, "idempotency conflict")

        any_fresh_commit = False
        accepted_count = 0
        deduped_count = 0
        committed_seqs: set[int] = set()
        acked_gap_seqs: set[int] = set()

        with self._store.transaction() as txn:
            expires_at_dt = clock_now + _EVENT_RETENTION
            cur_events = _query_existing_events(txn.db, producer_stream, seen_events.keys())
            cur_prod_gaps = _query_existing_prod_gaps(txn.db, producer_stream, seen_gaps.keys())
            wm_row = txn.db.execute(
                "SELECT high_seq, contiguous_seq FROM producer_watermarks WHERE producer_stream = ?",
                (producer_stream,),
            ).fetchone()
            prev_high_seq = int(wm_row[0]) if wm_row is not None else 0
            prev_contiguous = int(wm_row[1]) if wm_row is not None else 0
            daemon_spans = _load_daemon_spans(txn.db, producer_stream)
            newly_covered: set[int] = set()

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
                        producer_stream, seq, ev.record.event_id, ev.record.harness_id, ev.record.kind,
                        ev.record.recorded_at, ev.payload_digest, cas_holder_id, ev.source,
                        ev.source_verification, repo_id, checkout_id, principal_id,
                        ev.record.session_ref, canonical_json(ev.record.source_metadata), committed_at,
                    ),
                )
                if on_event_committed_in_tx is not None:
                    on_event_committed_in_tx(txn.db, ev)
                cur_events[seq] = ident
                newly_covered.add(seq)
                accepted_count += 1
                any_fresh_commit = True
                committed_seqs.add(seq)

            for gap in gaps:
                seq = gap.sequence
                g_ident = _gap_identity(gap)
                stored_g = cur_prod_gaps.get(seq)
                if stored_g is not None:
                    if not _gap_replay_is_dedup(stored_g, gap, repo_id=repo_id, checkout_id=checkout_id):
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
                        gap.gap_id, producer_stream, seq, gap.reason,
                        gap.estimated_count, gap.duration_ms, repo_id, checkout_id, gap.recorded_at,
                    ),
                )
                cur_prod_gaps[seq] = (g_ident, repo_id, checkout_id)
                newly_covered.add(seq)
                accepted_count += 1
                any_fresh_commit = True
                acked_gap_seqs.add(seq)

            for cov_seq in sorted(s for s in newly_covered if s <= prev_high_seq):
                _subtract_seq_from_open_spans(txn.db, daemon_spans, producer_stream=producer_stream, seq=cov_seq)

            cursor = prev_high_seq
            for high_new in sorted(s for s in newly_covered if s > prev_high_seq):
                if high_new > cursor + 1:
                    _add_missing_interval(
                        txn.db, daemon_spans, producer_stream=producer_stream,
                        start=cursor + 1, end=high_new - 1, repo_id=repo_id,
                        checkout_id=checkout_id, recorded_at=committed_at,
                    )
                cursor = high_new
            high_seq = max(prev_high_seq, cursor)

            contiguous = prev_contiguous
            for (seq_val,) in txn.db.execute(
                "SELECT sequence FROM capture_events WHERE producer_stream = ? AND sequence > ? ORDER BY sequence ASC",
                (producer_stream, prev_contiguous),
            ):
                seq_int = int(seq_val)
                if seq_int == contiguous + 1:
                    contiguous = seq_int
                elif seq_int > contiguous + 1:
                    break

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
        require_capture_sequence(sequence)
        _, closed_at = require_aware_utc(now)
        if repo_id is not None:
            require_opaque_id(repo_id, label="repo_id")
        if checkout_id is not None:
            require_opaque_id(checkout_id, label="checkout_id")

        with self._store.transaction() as txn:
            spans = _load_daemon_spans(txn.db, producer_stream)
            for span in spans:
                if not (span.start <= sequence <= span.end):
                    continue
                if span.status == "closed":
                    txn.db.execute(
                        "UPDATE capture_gaps SET closed_at = ? WHERE gap_id = ?",
                        (closed_at, span.gap_id),
                    )
                    return
                orig_end = span.end
                eff_repo = repo_id if repo_id is not None else span.repo_id
                eff_chk = checkout_id if checkout_id is not None else span.checkout_id
                if span.start == orig_end:
                    txn.db.execute(
                        "UPDATE capture_gaps SET status = 'closed', closed_at = ? WHERE gap_id = ?",
                        (closed_at, span.gap_id),
                    )
                    return
                if sequence == span.start:
                    txn.db.execute(
                        "UPDATE capture_gaps SET sequence = ?, estimated_count = ? WHERE gap_id = ?",
                        (sequence + 1, orig_end - sequence, span.gap_id),
                    )
                elif sequence == orig_end:
                    txn.db.execute(
                        "UPDATE capture_gaps SET estimated_count = ? WHERE gap_id = ?",
                        (sequence - span.start, span.gap_id),
                    )
                else:
                    txn.db.execute(
                        "UPDATE capture_gaps SET estimated_count = ? WHERE gap_id = ?",
                        (sequence - span.start, span.gap_id),
                    )
                    _insert_daemon_span(
                        txn.db, producer_stream=producer_stream, start=sequence + 1, end=orig_end,
                        status="open", repo_id=span.repo_id, checkout_id=span.checkout_id,
                        recorded_at=span.recorded_at, closed_at=None,
                    )
                _insert_daemon_span(
                    txn.db, producer_stream=producer_stream, start=sequence, end=sequence,
                    status="closed", repo_id=eff_repo, checkout_id=eff_chk,
                    recorded_at=span.recorded_at, closed_at=closed_at,
                )
                return

            _insert_daemon_span(
                txn.db, producer_stream=producer_stream, start=sequence, end=sequence,
                status="closed", repo_id=repo_id, checkout_id=checkout_id,
                recorded_at=closed_at, closed_at=closed_at,
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
