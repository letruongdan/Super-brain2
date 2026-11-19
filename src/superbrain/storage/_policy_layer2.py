"""Policy v4 harness layer-2 state, terminal-channel eligibility, recovery grants and signer reset (spec 11.2, 11.3)."""

from __future__ import annotations

import hashlib
import sqlite3
from datetime import datetime

from superbrain.core._kernel_approval import (
    CLI_HARNESS_ID,
    ApprovalAction,
    Layer2State,
    RecoveryGrant,
    RecoveryScope,
)
from superbrain.core._kernel_base import OPAQUE_ID_RE, require_sha256_digest
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.ports.policy import Intent, IntentKind
from superbrain.storage._policy_approvals import OWNER_META_KEY, record_intent_row, refused
from superbrain.storage.kinds import is_uuid
from superbrain.storage.ledger import utc_timestamp

SIGNER_RESET_META_KEY = "signer_reset_recorded"
_GRANT_ACTIONS = frozenset({ApprovalAction.APPLY.value, ApprovalAction.ROLLBACK.value})
_GRANT_COLUMNS = "grant_id, approval_id, journal_id, subject_id, recovery_scope, trust_generation, state, end_reason"


def _invalid() -> BrainError:
    return BrainError(ErrorCode.INVALID_INPUT, "invalid input")


def set_layer2_state(
    db: sqlite3.Connection, *, harness_id: str, host_version: str, config_digest: str, state: Layer2State, now: datetime
) -> Intent:
    """Record one ``(harness, host version, config digest) -> state`` tuple; the latest per harness is current."""
    if not isinstance(state, Layer2State):
        raise _invalid()
    for text in (harness_id, host_version):
        if not isinstance(text, str) or not OPAQUE_ID_RE.fullmatch(text):
            raise _invalid()
    require_sha256_digest(config_digest)
    intent = record_intent_row(
        db,
        IntentKind.LAYER2_STATE_SET,
        {
            "harness_id": harness_id,
            "host_version": host_version,
            "config_digest": config_digest,
            "state": state.value,
        },
        now,
    )
    db.execute(
        "INSERT INTO harness_layer2_state (harness_id, host_version, config_digest, state, intent_id, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (harness_id, host_version, config_digest, state.value, intent.intent_id, intent.created_at),
    )
    return intent


def terminal_channel_eligible(db: sqlite3.Connection, machine_id: str | None) -> bool:
    """``True`` iff there is at least one connected harness and every one of them has a ``verified`` layer 2.

    The connected set is every principal with an active credential and ``harness_id != "cli"`` (on ``machine_id``,
    or on every machine when it is ``None``). An empty set is never eligible: ``all([])`` is ``True``.
    """
    rows = db.execute(
        "SELECT DISTINCT p.harness_id FROM principal AS p WHERE p.harness_id != ? AND (? IS NULL OR p.machine_id = ?) "
        "AND EXISTS (SELECT 1 FROM credential AS c WHERE c.principal_id = p.id AND c.revoked_intent_id IS NULL)",
        (CLI_HARNESS_ID, machine_id, machine_id),
    ).fetchall()
    harnesses = [str(row[0]) for row in rows]
    if not harnesses:
        return False
    for harness_id in harnesses:
        current = db.execute(
            "SELECT state FROM harness_layer2_state WHERE harness_id = ? ORDER BY seq DESC LIMIT 1", (harness_id,)
        ).fetchone()
        if current is None or current[0] != Layer2State.VERIFIED.value:
            return False
    return True


def _decode_grant(row: tuple[object, ...]) -> RecoveryGrant:
    grant_id, approval_id, journal_id, subject_id, scope, generation, state, reason = row
    try:
        return RecoveryGrant(
            grant_id=str(grant_id),
            approval_id=str(approval_id),
            journal_id=str(journal_id),
            subject_id=str(subject_id),
            recovery_scope=RecoveryScope(str(scope)),
            trust_generation=int(generation) if isinstance(generation, int) else 0,
            state=str(state),
            end_reason=None if reason is None else str(reason),
        )
    except ValueError as exc:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "the policy store has a malformed recovery grant") from exc


def read_recovery_grant(db: sqlite3.Connection, grant_id: str) -> RecoveryGrant:
    row = db.execute(f"SELECT {_GRANT_COLUMNS} FROM recovery_grant WHERE grant_id = ?", (grant_id,)).fetchone()
    if row is None:
        raise BrainError(ErrorCode.NOT_FOUND, "not found")
    return _decode_grant(tuple(row))


def end_recovery_grant(
    db: sqlite3.Connection,
    *,
    grant_id: str,
    reason: str = "journal_closed",
    trust_generation: int,
    now: datetime,
) -> RecoveryGrant:
    """Close an active ``recovery_grant`` and record ``RECOVERY_GRANT_ENDED`` in one transaction."""
    if not isinstance(grant_id, str) or not is_uuid(grant_id) or reason not in ("trust_reset", "journal_closed"):
        raise _invalid()
    current = read_recovery_grant(db, grant_id)
    if current.state != "active":
        raise BrainError(ErrorCode.REVISION_CONFLICT, "revision conflict")
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
        raise BrainError(ErrorCode.REVISION_CONFLICT, "revision conflict")
    return read_recovery_grant(db, grant_id)


def open_recovery_grant(
    db: sqlite3.Connection, *, approval_id: str, journal_id: str, trust_generation: int, now: datetime
) -> RecoveryGrant:
    """Open the recovery grant of an ``apply``/``rollback`` approval of the current trust generation (once)."""
    if (
        not isinstance(approval_id, str)
        or not approval_id
        or not isinstance(journal_id, str)
        or not is_uuid(journal_id)
    ):
        raise _invalid()
    row = db.execute(
        "SELECT action, subject_id, trust_generation, recovery_scope FROM approval_receipt_meta WHERE approval_id = ?",
        (approval_id,),
    ).fetchone()
    if row is None:
        raise refused()
    action, subject_id, generation, scope = row
    if action not in _GRANT_ACTIONS:
        raise _invalid()
    if generation != trust_generation:
        raise refused()
    if db.execute("SELECT 1 FROM recovery_grant WHERE approval_id = ?", (approval_id,)).fetchone() is not None:
        raise BrainError(ErrorCode.REVISION_CONFLICT, "revision conflict")
    grant_id = new_id()
    subject_digest = "sha256:" + hashlib.sha256(str(subject_id).encode("utf-8")).hexdigest()
    intent = record_intent_row(
        db,
        IntentKind.RECOVERY_GRANT_OPENED,
        {
            "grant_id": grant_id,
            "approval_id": approval_id,
            "journal_id": journal_id,
            "subject_digest": subject_digest,
            "recovery_scope": str(scope),
            "trust_generation": trust_generation,
        },
        now,
    )
    db.execute(
        "INSERT INTO recovery_grant (grant_id, approval_id, journal_id, subject_id, recovery_scope, trust_generation, "
        "state, opened_intent_id, opened_at) VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?)",
        (grant_id, approval_id, journal_id, subject_id, scope, trust_generation, intent.intent_id, intent.created_at),
    )
    return read_recovery_grant(db, grant_id)


def reset_signers(db: sqlite3.Connection, *, previous_generation: int, new_generation: int, now: datetime) -> None:
    """Offline ``--reset-signers`` as one policy transaction: raise the generation, revoke every signer, cancel every
    pending nonce, end every active recovery grant with ``trust_reset``, set the durable flag and record one
    ``SIGNER_RESET`` intent. The caller raises the ``writer.lock`` high-water mark right after the commit.
    """
    stamp = utc_timestamp(now)
    cursor = db.execute("UPDATE trust SET generation = ? WHERE id = 1", (new_generation,))
    if cursor.rowcount != 1:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "the policy store has no trust row")
    revoked = db.execute("UPDATE signer SET revoked_at = ? WHERE revoked_at IS NULL", (stamp,)).rowcount
    cancelled = db.execute(
        "UPDATE approval_nonce SET state = 'cancelled', ended_at = ?, end_reason = 'trust_reset' "
        "WHERE state = 'pending'",
        (stamp,),
    ).rowcount
    active = db.execute("SELECT grant_id FROM recovery_grant WHERE state = 'active' ORDER BY rowid").fetchall()
    for (grant_id,) in active:
        ended: dict[str, JsonValue] = {
            "grant_id": str(grant_id),
            "reason": "trust_reset",
            "trust_generation": new_generation,
        }
        intent = record_intent_row(db, IntentKind.RECOVERY_GRANT_ENDED, ended, now)
        db.execute(
            "UPDATE recovery_grant SET state = 'ended', end_reason = 'trust_reset', ended_intent_id = ?, ended_at = ? "
            "WHERE grant_id = ? AND state = 'active'",
            (intent.intent_id, stamp, grant_id),
        )
    db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, '1')", (SIGNER_RESET_META_KEY,))
    db.execute("UPDATE apply_turn_intent SET state = 'recovery_required' WHERE state = 'active'")
    record_intent_row(
        db,
        IntentKind.SIGNER_RESET,
        {
            "previous_generation": previous_generation,
            "new_generation": new_generation,
            "signers_revoked": revoked,
            "nonces_cancelled": cancelled,
            "grants_ended": len(active),
        },
        now,
    )


def signer_reset_recorded(db: sqlite3.Connection) -> bool:
    row = db.execute("SELECT value FROM meta WHERE key = ?", (SIGNER_RESET_META_KEY,)).fetchone()
    return row is not None and row[0] == "1"


__all__ = [
    "OWNER_META_KEY",
    "SIGNER_RESET_META_KEY",
    "end_recovery_grant",
    "open_recovery_grant",
    "read_recovery_grant",
    "reset_signers",
    "set_layer2_state",
    "signer_reset_recorded",
    "terminal_channel_eligible",
]
