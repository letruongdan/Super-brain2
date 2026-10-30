"""Ledger entries, projection handlers and the write transaction (spec 5.4).

One SQLite transaction holds the ledger append and every projection update (and, later, the idempotency record):
all of it commits or none of it does. ``Txn`` is only handed out by ``Store.transaction()``.
"""

import dataclasses
import json
import sqlite3
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Protocol

from superbrain.core.canonical import canonical_json
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.ports.clock import Clock
from superbrain.ports.policy import PolicyView
from superbrain.storage.kinds import KindRegistry, is_uuid, validate_envelope

if TYPE_CHECKING:
    from superbrain.storage.cas import RetentionClass

_SAVEPOINT = "ledger_entry"
_CAS_ACTOR = "system:cas"
_COLUMNS = (
    "sequence, entry_id, kind, schema_version, handler_version, writer_epoch, actor, owner_id, recorded_at, meta, refs"
)


@dataclass(frozen=True)
class LedgerEntry:
    sequence: int
    entry_id: str
    kind: str
    schema_version: int
    handler_version: int
    writer_epoch: int
    actor: str
    owner_id: str | None
    recorded_at: str
    meta: Mapping[str, JsonValue]
    refs: tuple[str, ...]


class ProjectionHandler(Protocol):
    """Maintains tables named with ``prefix``: ``p_<name>_`` live, ``r_<name>_`` while rebuilding."""

    @property
    def name(self) -> str: ...

    @property
    def handler_version(self) -> int: ...

    @property
    def kinds(self) -> frozenset[str]: ...

    def create_tables(self, db: sqlite3.Connection, prefix: str) -> None: ...

    def apply(self, db: sqlite3.Connection, prefix: str, entry: LedgerEntry, policy: PolicyView) -> None: ...


def live_prefix(handler: ProjectionHandler) -> str:
    return f"p_{handler.name}_"


def rebuild_prefix(handler: ProjectionHandler) -> str:
    return f"r_{handler.name}_"


def io_error(what: str, exc: sqlite3.Error) -> BrainError:
    return BrainError(ErrorCode.IO_ERROR, f"{what}: {exc}")


def utc_timestamp(moment: datetime) -> str:
    """``moment`` as the canonical TIMESTAMP ``YYYY-MM-DDTHH:MM:SS.ffffffZ``; a naive datetime is a bug."""
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise AssertionError("timestamps must be timezone-aware datetimes")
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _malformed(sequence: object, what: str) -> BrainError:
    return BrainError(ErrorCode.INTEGRITY_FAILURE, f"ledger entry {sequence}: {what}")


def _int(sequence: object, value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise _malformed(sequence, "an integer column holds a non-integer")
    return value


def _text(sequence: object, value: object) -> str:
    if not isinstance(value, str):
        raise _malformed(sequence, "a text column holds a non-text value")
    return value


def _json(sequence: object, value: object) -> object:
    if not isinstance(value, bytes):
        raise _malformed(sequence, "meta or refs is not a blob")
    try:
        return json.loads(value)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _malformed(sequence, "undecodable meta or refs") from exc


def _decode(row: Sequence[object]) -> LedgerEntry:
    seq, entry_id, kind, schema_version, handler_version, epoch, actor, owner_id, recorded_at, meta, refs = row
    meta_value, refs_value = _json(seq, meta), _json(seq, refs)
    if not isinstance(meta_value, dict) or not isinstance(refs_value, list):
        raise _malformed(seq, "meta is not an object or refs is not a list")
    return LedgerEntry(
        sequence=_int(seq, seq),
        entry_id=_text(seq, entry_id),
        kind=_text(seq, kind),
        schema_version=_int(seq, schema_version),
        handler_version=_int(seq, handler_version),
        writer_epoch=_int(seq, epoch),
        actor=_text(seq, actor),
        owner_id=None if owner_id is None else _text(seq, owner_id),
        recorded_at=_text(seq, recorded_at),
        meta=meta_value,
        refs=tuple(_text(seq, ref) for ref in refs_value),
    )


def read_entries(db: sqlite3.Connection, after: int, limit: int) -> list[LedgerEntry]:
    """Up to ``limit`` entries with ``sequence > after``, in sequence order."""
    try:
        rows = db.execute(
            f"SELECT {_COLUMNS} FROM ledger WHERE sequence > ? ORDER BY sequence LIMIT ?", (after, limit)
        ).fetchall()
    except sqlite3.Error as exc:
        raise io_error("cannot read the ledger", exc) from exc
    return [_decode(row) for row in rows]


def apply_to_handlers(
    db: sqlite3.Connection,
    handlers: Sequence[ProjectionHandler],
    entry: LedgerEntry,
    policy: PolicyView,
    prefix: Callable[[ProjectionHandler], str],
) -> None:
    for handler in handlers:
        if entry.kind not in handler.kinds:
            continue
        try:
            handler.apply(db, prefix(handler), entry, policy)
        except sqlite3.Error as exc:
            raise io_error(f"projection {handler.name} failed on entry {entry.sequence}", exc) from exc
        except BrainError:
            raise
        except Exception as exc:
            raise BrainError(
                ErrorCode.INTEGRITY_FAILURE, f"projection {handler.name} failed on entry {entry.sequence}: {exc!r}"
            ) from exc


class Txn:
    """A write transaction on the store. Obtain it with ``Store.transaction()``; it is unusable afterwards."""

    def __init__(
        self,
        db: sqlite3.Connection,
        *,
        kinds: KindRegistry,
        handlers: Sequence[ProjectionHandler],
        policy: PolicyView,
        writer_epoch: int,
        schema_version: int,
        clock: Clock,
        check_owner: Callable[[], None],
        blob_intact: Callable[[str], bool],
    ) -> None:
        self._db = db
        self._blob_intact = blob_intact
        self._kinds = kinds
        self._handlers = tuple(handlers)
        self._policy = policy
        self._writer_epoch = writer_epoch
        self._schema_version = schema_version
        self._clock = clock
        self._check_owner = check_owner
        self._active = True

    @property
    def db(self) -> sqlite3.Connection:
        self._check()
        return self._db

    def _end(self) -> None:
        """Called by the store when the transaction ends."""
        self._active = False

    def append(
        self,
        kind: str,
        *,
        actor: str,
        owner_id: str | None,
        meta: Mapping[str, JsonValue],
        refs: Sequence[str] = (),
    ) -> LedgerEntry:
        """Validate, then append one entry and apply it to every projection handling ``kind``.

        A reserved kind is ``INVALID_INPUT`` and writes nothing: it has its own helper.
        """
        self._check()
        if self._kinds.get(kind).reserved:
            raise BrainError(ErrorCode.INVALID_INPUT, f"{kind} is reserved and has its own helper")
        return self._write_entry(kind, actor=actor, owner_id=owner_id, meta=meta, refs=refs)

    def _append_reserved(
        self,
        kind: str,
        *,
        actor: str,
        owner_id: str | None,
        meta: Mapping[str, JsonValue],
        refs: Sequence[str] = (),
    ) -> LedgerEntry:
        """Append a reserved kind. Only ``Txn.hold``, ``Txn.release`` and ``Store.reconcile_policy`` may call it,
        after checking the kind's invariant; an architecture test enforces that."""
        self._check()
        if not self._kinds.get(kind).reserved:
            raise AssertionError(f"{kind} is not reserved; use append")
        return self._write_entry(kind, actor=actor, owner_id=owner_id, meta=meta, refs=refs)

    def hold(
        self,
        digest: str,
        holder_kind: str,
        holder_id: str,
        retention: "RetentionClass",
        expires_at: datetime | None,
    ) -> None:
        """Record that ``(holder_kind, holder_id)`` holds the blob ``digest`` until ``expires_at`` (``None``: no
        expiry).

        The blob is checked inside this write transaction, which GC's delete cannot interleave with: a blob that
        is missing or does not hash to ``digest`` is ``NOT_FOUND`` and nothing is written.
        """
        self._check()
        meta: dict[str, JsonValue] = {
            "digest": digest,
            "holder_kind": holder_kind,
            "holder_id": holder_id,
            "retention": str(retention),
            "expires_at": None if expires_at is None else utc_timestamp(expires_at),
        }
        self._kinds.validate("cas.hold", meta)
        if not self._blob_intact(digest):
            raise BrainError(ErrorCode.NOT_FOUND, f"blob {digest} is missing or does not match its digest")
        self._append_reserved("cas.hold", actor=_CAS_ACTOR, owner_id=None, meta=meta)

    def release(self, digest: str, holder_kind: str, holder_id: str, reason: str) -> None:
        """Record that ``(holder_kind, holder_id)`` no longer holds ``digest``; the blob itself is not checked."""
        self._check()
        meta: dict[str, JsonValue] = {
            "digest": digest,
            "holder_kind": holder_kind,
            "holder_id": holder_id,
            "reason": reason,
        }
        self._append_reserved("cas.release", actor=_CAS_ACTOR, owner_id=None, meta=meta)

    def mark_intent_applied(self, intent_id: str) -> bool:
        """Record that ``intent_id`` has been applied; ``False`` (and nothing changes) if it already was.

        ``applied_sequence`` is the ledger high-water at marking time: ``MAX(sequence)`` (0 for an empty ledger),
        including entries appended earlier in this transaction.
        """
        self._check()
        if not is_uuid(intent_id):
            raise BrainError(ErrorCode.INVALID_INPUT, "intent_id must be a canonical UUID")
        try:
            cursor = self._db.execute(
                "INSERT INTO applied_intents (intent_id, applied_sequence) "
                "SELECT ?, COALESCE(MAX(sequence), 0) FROM ledger WHERE true "
                "ON CONFLICT (intent_id) DO NOTHING",
                (intent_id,),
            )
        except sqlite3.Error as exc:
            raise io_error("cannot record the applied intent", exc) from exc
        return cursor.rowcount == 1

    def _check(self) -> None:
        self._check_owner()
        if not self._active:
            raise AssertionError("transaction is no longer active")

    def _write_entry(
        self,
        kind: str,
        *,
        actor: str,
        owner_id: str | None,
        meta: Mapping[str, JsonValue],
        refs: Sequence[str],
    ) -> LedgerEntry:
        checked_refs = validate_envelope(actor, owner_id, refs)
        spec = self._kinds.get(kind)
        self._kinds.validate(kind, meta)
        recorded_at = utc_timestamp(self._clock.now())
        entry_id = new_id()
        pending = LedgerEntry(
            sequence=0,
            entry_id=entry_id,
            kind=kind,
            schema_version=self._schema_version,
            handler_version=spec.handler_version,
            writer_epoch=self._writer_epoch,
            actor=actor,
            owner_id=owner_id,
            recorded_at=recorded_at,
            meta=dict(meta),
            refs=checked_refs,
        )
        meta_bytes, refs_bytes = canonical_json(pending.meta), canonical_json(list(checked_refs))
        # One append is all-or-nothing even if the caller catches its error and goes on to commit the transaction.
        try:
            self._db.execute(f"SAVEPOINT {_SAVEPOINT}")
        except sqlite3.Error as exc:
            raise io_error("cannot start the append", exc) from exc
        try:
            cursor = self._db.execute(
                "INSERT INTO ledger (entry_id, kind, schema_version, handler_version, writer_epoch, actor, owner_id,"
                " recorded_at, meta, refs) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    pending.entry_id,
                    pending.kind,
                    pending.schema_version,
                    pending.handler_version,
                    pending.writer_epoch,
                    pending.actor,
                    pending.owner_id,
                    pending.recorded_at,
                    meta_bytes,
                    refs_bytes,
                ),
            )
            assert cursor.lastrowid is not None
            entry = dataclasses.replace(pending, sequence=cursor.lastrowid)
            apply_to_handlers(self._db, self._handlers, entry, self._policy, live_prefix)
            self._db.execute(f"RELEASE {_SAVEPOINT}")
        except BaseException as err:
            try:
                self._db.execute(f"ROLLBACK TO {_SAVEPOINT}")
                self._db.execute(f"RELEASE {_SAVEPOINT}")
            except sqlite3.Error as exc:
                raise io_error("cannot undo the failed append", exc) from exc
            if isinstance(err, sqlite3.Error):
                raise io_error("cannot append to the ledger", err) from err
            raise
        return entry


def iter_entries(
    db: sqlite3.Connection, after: int, check: Callable[[], None], batch: int = 256
) -> Iterator[LedgerEntry]:
    """Every entry after ``after``, read in batches so no statement stays open across a ``yield``."""
    while True:
        check()
        page = read_entries(db, after, batch)
        if not page:
            return
        for entry in page:
            yield entry
            check()
        after = page[-1].sequence
