"""Policy v4 ``apply_turn_intent`` and ``recovery_grant`` lifecycle helpers (spec 11.2, I3-3)."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime

from superbrain.core._kernel_approval import ApprovalMessage, RecoveryGrant
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.proposals import ApplyTurnIntent, JournalDirection
from superbrain.ports.policy import IntentKind
from superbrain.storage._policy_approvals import record_intent_row, refused
from superbrain.storage._policy_layer2 import open_recovery_grant, read_recovery_grant
from superbrain.storage.kinds import is_uuid
from superbrain.storage.ledger import utc_timestamp

__all__ = [
    "approval_message",
    "begin_journal_turn",
    "end_recovery_grant_with_turn",
    "find_recovery_grant_for_journal",
    "list_recovery_grants",
    "list_turn_intents",
    "mark_active_turns_recovery_required",
    "open_turn_intent",
    "turn_intent_for_journal",
]

_TURN_COLUMNS = "turn_id, journal_id, approval_id, direction, state, created_at"
_GRANT_COLUMNS = "grant_id, approval_id, journal_id, subject_id, recovery_scope, trust_generation, state, end_reason"
_FINAL_TURN_STATES = frozenset({"applied", "rolled_back", "recovery_required", "ended"})


def _invalid() -> BrainError:
    return BrainError(ErrorCode.INVALID_INPUT, "invalid input")


def _conflict(msg: str = "revision conflict") -> BrainError:
    return BrainError(ErrorCode.REVISION_CONFLICT, msg)


def _decode_turn(row: tuple[object, ...]) -> ApplyTurnIntent:
    turn_id, journal_id, approval_id, direction, state, created_at = row
    return ApplyTurnIntent(
        turn_id=str(turn_id),
        journal_id=str(journal_id),
        approval_id=str(approval_id),
        direction=JournalDirection(str(direction)),
        state=str(state),
        created_at=str(created_at),
    )


def _decode_grant_row(row: tuple[object, ...]) -> RecoveryGrant:
    return read_recovery_grant_tuple(row)


def read_recovery_grant_tuple(row: tuple[object, ...]) -> RecoveryGrant:
    from superbrain.storage._policy_layer2 import _decode_grant

    return _decode_grant(row)


def turn_intent_for_journal(db: sqlite3.Connection, journal_id: str) -> ApplyTurnIntent | None:
    if not isinstance(journal_id, str) or not journal_id:
        return None
    row = db.execute(
        f"SELECT {_TURN_COLUMNS} FROM apply_turn_intent WHERE journal_id = ? ORDER BY rowid DESC LIMIT 1",
        (journal_id,),
    ).fetchone()
    return None if row is None else _decode_turn(tuple(row))


def list_turn_intents(db: sqlite3.Connection) -> tuple[ApplyTurnIntent, ...]:
    rows = db.execute(f"SELECT {_TURN_COLUMNS} FROM apply_turn_intent ORDER BY rowid").fetchall()
    return tuple(_decode_turn(tuple(r)) for r in rows)


def find_recovery_grant_for_journal(db: sqlite3.Connection, journal_id: str) -> RecoveryGrant | None:
    if not isinstance(journal_id, str) or not journal_id:
        return None
    row = db.execute(
        f"SELECT {_GRANT_COLUMNS} FROM recovery_grant WHERE journal_id = ? ORDER BY rowid DESC LIMIT 1",
        (journal_id,),
    ).fetchone()
    return None if row is None else _decode_grant_row(tuple(row))


def list_recovery_grants(db: sqlite3.Connection) -> tuple[RecoveryGrant, ...]:
    rows = db.execute(f"SELECT {_GRANT_COLUMNS} FROM recovery_grant ORDER BY rowid").fetchall()
    return tuple(_decode_grant_row(tuple(r)) for r in rows)


def approval_message(db: sqlite3.Connection, approval_id: str) -> ApprovalMessage | None:
    """Return the signed ``ApprovalMessage`` stored for ``approval_id``, or ``None`` if absent."""
    if not isinstance(approval_id, str) or not approval_id:
        return None
    row = db.execute(
        "SELECT message_json FROM approval_receipt_meta WHERE approval_id = ?",
        (approval_id,),
    ).fetchone()
    if row is None:
        return None
    blob = row[0]
    try:
        raw_text = bytes(blob).decode("utf-8") if isinstance(blob, (bytes, bytearray, memoryview)) else str(blob)
        parsed: JsonValue = json.loads(raw_text)
    except (UnicodeDecodeError, json.JSONDecodeError) as err:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt approval message record") from err
    if not isinstance(parsed, dict):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "corrupt approval message record")
    return ApprovalMessage.from_dict(parsed)


def _validate_turn_receipt(
    db: sqlite3.Connection,
    *,
    journal_id: str,
    approval_id: str,
    direction: JournalDirection,
    trust_generation: int,
) -> tuple[str, str]:
    """Validate receipt action/generation/scope and any existing journal grant; return ``(action, subject_id)``."""
    if (
        not isinstance(journal_id, str)
        or not is_uuid(journal_id)
        or not isinstance(approval_id, str)
        or not approval_id
        or not isinstance(direction, JournalDirection)
    ):
        raise _invalid()
    row = db.execute(
        "SELECT action, subject_id, trust_generation, recovery_scope FROM approval_receipt_meta WHERE approval_id = ?",
        (approval_id,),
    ).fetchone()
    if row is None:
        raise refused()
    action, subject_id, row_gen, recovery_scope = str(row[0]), str(row[1]), int(row[2]), str(row[3])
    if action not in ("apply", "rollback"):
        raise _invalid()
    if row_gen != trust_generation:
        raise refused()
    if direction is JournalDirection.APPLY:
        if action != "apply" or recovery_scope not in ("continue", "continue_or_rollback"):
            raise _invalid()
    elif recovery_scope not in ("rollback", "continue_or_rollback"):
        raise _invalid()
    return action, subject_id


def _validate_existing_grant_for_turn(
    grant: RecoveryGrant,
    *,
    approval_id: str,
    direction: JournalDirection,
    action: str,
    subject_id: str,
    trust_generation: int,
) -> None:
    if grant.state != "active" or grant.trust_generation != trust_generation:
        raise _conflict("recovery grant is not active for current generation")
    if grant.subject_id != subject_id:
        raise refused()
    if direction is JournalDirection.ROLLBACK and grant.recovery_scope not in ("rollback", "continue_or_rollback"):
        raise _invalid()
    if grant.approval_id != approval_id and not (direction is JournalDirection.ROLLBACK and action == "rollback"):
        raise _conflict("recovery grant already exists for journal")


def open_turn_intent(
    db: sqlite3.Connection,
    *,
    journal_id: str,
    approval_id: str,
    direction: JournalDirection,
    trust_generation: int,
    now: datetime,
) -> ApplyTurnIntent:
    """Record or transition ``apply_turn_intent`` for ``journal_id``; validates receipt and existing grant."""
    action, subject_id = _validate_turn_receipt(
        db, journal_id=journal_id, approval_id=approval_id, direction=direction, trust_generation=trust_generation
    )
    existing_grant = find_recovery_grant_for_journal(db, journal_id)
    if existing_grant is not None:
        _validate_existing_grant_for_turn(
            existing_grant,
            approval_id=approval_id,
            direction=direction,
            action=action,
            subject_id=subject_id,
            trust_generation=trust_generation,
        )

    existing = turn_intent_for_journal(db, journal_id)
    if existing is not None:
        if existing.state != "active":
            raise _conflict("turn intent is no longer active")
        if existing.direction is JournalDirection.ROLLBACK and direction is JournalDirection.APPLY:
            raise _conflict("cannot flip rollback turn intent back to apply")
        if existing.direction is direction and existing.approval_id == approval_id:
            return existing
        if existing.approval_id != approval_id:
            if not (direction is JournalDirection.ROLLBACK and action == "rollback"):
                raise _conflict("approval does not match active turn intent")
            prev_row = db.execute(
                "SELECT subject_id FROM approval_receipt_meta WHERE approval_id = ?",
                (existing.approval_id,),
            ).fetchone()
            if prev_row is None or str(prev_row[0]) != subject_id:
                raise refused()
        db.execute(
            "UPDATE apply_turn_intent SET direction = ?, approval_id = ? WHERE turn_id = ? AND state = 'active'",
            (direction.value, approval_id, existing.turn_id),
        )
        updated = turn_intent_for_journal(db, journal_id)
        assert updated is not None
        return updated

    turn_id = new_id()
    stamp = utc_timestamp(now)
    db.execute(
        "INSERT INTO apply_turn_intent (turn_id, journal_id, approval_id, direction, state, created_at) "
        "VALUES (?, ?, ?, ?, 'active', ?)",
        (turn_id, journal_id, approval_id, direction.value, stamp),
    )
    created = turn_intent_for_journal(db, journal_id)
    assert created is not None
    return created


def begin_journal_turn(
    db: sqlite3.Connection,
    *,
    approval_id: str,
    journal_id: str,
    direction: JournalDirection,
    trust_generation: int,
    now: datetime,
) -> tuple[RecoveryGrant, ApplyTurnIntent]:
    """Atomically open/reuse ``recovery_grant`` and record ``apply_turn_intent`` in one transaction."""
    action, subject_id = _validate_turn_receipt(
        db, journal_id=journal_id, approval_id=approval_id, direction=direction, trust_generation=trust_generation
    )
    existing_grant = find_recovery_grant_for_journal(db, journal_id)
    if existing_grant is not None:
        _validate_existing_grant_for_turn(
            existing_grant,
            approval_id=approval_id,
            direction=direction,
            action=action,
            subject_id=subject_id,
            trust_generation=trust_generation,
        )
        intent = open_turn_intent(
            db,
            journal_id=journal_id,
            approval_id=approval_id,
            direction=direction,
            trust_generation=trust_generation,
            now=now,
        )
        return existing_grant, intent
    grant = open_recovery_grant(
        db, approval_id=approval_id, journal_id=journal_id, trust_generation=trust_generation, now=now
    )
    intent = open_turn_intent(
        db,
        journal_id=journal_id,
        approval_id=approval_id,
        direction=direction,
        trust_generation=trust_generation,
        now=now,
    )
    return grant, intent


def end_recovery_grant_with_turn(
    db: sqlite3.Connection,
    *,
    grant_id: str,
    reason: str = "journal_closed",
    final_status: str | None = None,
    trust_generation: int,
    now: datetime,
) -> RecoveryGrant:
    """Close ``recovery_grant`` and atomically settle any active ``apply_turn_intent`` for its journal."""
    if not isinstance(grant_id, str) or not is_uuid(grant_id) or reason not in ("trust_reset", "journal_closed"):
        raise _invalid()
    if final_status is not None and final_status not in _FINAL_TURN_STATES:
        raise _invalid()
    current = read_recovery_grant(db, grant_id)
    if current.state != "active":
        raise _conflict()
    stamp = utc_timestamp(now)
    intent = record_intent_row(
        db,
        IntentKind.RECOVERY_GRANT_ENDED,
        {"grant_id": grant_id, "reason": reason, "trust_generation": trust_generation},
        now,
    )
    cursor = db.execute(
        "UPDATE recovery_grant SET state = 'ended', end_reason = ?, ended_intent_id = ?, ended_at = ? "
        "WHERE grant_id = ? AND state = 'active'",
        (reason, intent.intent_id, stamp, grant_id),
    )
    if cursor.rowcount != 1:
        raise _conflict()
    if final_status is not None:
        db.execute(
            "UPDATE apply_turn_intent SET state = ? WHERE journal_id = ? AND state = 'active'",
            (final_status, current.journal_id),
        )
    return read_recovery_grant(db, grant_id)


def mark_active_turns_recovery_required(db: sqlite3.Connection) -> None:
    db.execute("UPDATE apply_turn_intent SET state = 'recovery_required' WHERE state = 'active'")
