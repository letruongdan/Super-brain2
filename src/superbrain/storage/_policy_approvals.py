"""Policy v4 signer, single-use nonce and approval-receipt authority (spec 11.3).

Every function takes the policy ``sqlite3.Connection``; the mutating ones expect an open ``BEGIN IMMEDIATE`` (the
caller's ``PolicyStore._authority_tx``) so a refusal rolls back every write the call made, including the nonce.
"""

from __future__ import annotations

import base64
import os
import secrets
import sqlite3
from datetime import datetime

from superbrain.core._kernel_approval import (
    APPROVAL_TTL,
    ApprovalAction,
    ApprovalChannel,
    ApprovalMessage,
    ApprovalReceipt,
    IssuedNonce,
    RiskLevel,
    SignerEnrollment,
    SignerRecord,
    assurance_for,
    canonical_utc,
    effective_risk,
    required_channels,
)
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.ids import new_id
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import Principal
from superbrain.ports.policy import Intent, IntentKind
from superbrain.storage.identity import validate_policy_intent_payload
from superbrain.storage.ledger import utc_timestamp

OWNER_META_KEY = "owner_id"
_SIGNER_COLUMNS = "id, owner_id, channel, key_digest, tofu, revoked_at, public_key, credential_id, sign_count"


def refused() -> BrainError:
    """The one outward answer to every failed approval check: no oracle about which check failed."""
    return BrainError(ErrorCode.UNAUTHENTICATED, "unauthenticated")


def _integrity(what: str) -> BrainError:
    return BrainError(ErrorCode.INTEGRITY_FAILURE, f"the policy store has a malformed {what}")


def record_intent_row(db: sqlite3.Connection, kind: IntentKind, payload: dict[str, JsonValue], now: datetime) -> Intent:
    """Insert one validated policy intent row (security state first); the main store reconciles it later."""
    intent_id = new_id()
    checked = validate_policy_intent_payload(kind, payload, intent_id)
    created_at = utc_timestamp(now)
    db.execute(
        "INSERT INTO intents (intent_id, kind, payload, created_at) VALUES (?, ?, ?, ?)",
        (intent_id, kind.value, canonical_json(checked), created_at),
    )
    return Intent(intent_id=intent_id, kind=kind, payload=checked, created_at=created_at)


def provision_credential(
    db: sqlite3.Connection, *, owner_id: str, harness_id: str, machine_id: str, now: datetime
) -> tuple[Principal, str]:
    """Insert (or reuse) the principal ``(owner, harness, machine)`` and a new active bearer credential for it.

    Returns the principal and the bearer token ``<credential_id>.<base64url secret>``; only its digest is stored, so
    this is the one moment the token exists.
    """
    stamp = utc_timestamp(now)
    row = db.execute(
        "SELECT id FROM principal WHERE owner_id = ? AND harness_id = ? AND machine_id = ?",
        (owner_id, harness_id, machine_id),
    ).fetchone()
    principal_id = str(row[0]) if row is not None else new_id()
    principal = Principal(principal_id=principal_id, owner_id=owner_id, harness_id=harness_id, machine_id=machine_id)
    if row is None:
        db.execute(
            "INSERT INTO principal (id, owner_id, harness_id, machine_id, created_at) VALUES (?, ?, ?, ?, ?)",
            (principal_id, owner_id, harness_id, machine_id, stamp),
        )
    credential_id = new_id()
    secret = os.urandom(32)
    db.execute(
        "INSERT INTO credential (id, principal_id, secret_digest, created_at, revoked_intent_id) "
        "VALUES (?, ?, ?, ?, NULL)",
        (credential_id, principal_id, digest_bytes(secret), stamp),
    )
    token = f"{credential_id}.{base64.urlsafe_b64encode(secret).rstrip(b'=').decode('ascii')}"
    return principal, token


def store_owner(db: sqlite3.Connection) -> str | None:
    """The owner of this store: pinned by the first signer (TOFU) and kept across ``--reset-signers``."""
    row = db.execute("SELECT value FROM meta WHERE key = ?", (OWNER_META_KEY,)).fetchone()
    if row is not None and isinstance(row[0], str):
        return row[0]
    row = db.execute("SELECT owner_id FROM signer ORDER BY rowid LIMIT 1").fetchone()
    return str(row[0]) if row is not None else None


def _decode_signer(row: tuple[object, ...]) -> SignerRecord:
    signer_id, owner_id, channel, key_digest, tofu, revoked_at, public_key, credential_id, sign_count = row
    try:
        return SignerRecord(
            signer_id=str(signer_id),
            owner_id=str(owner_id),
            channel=ApprovalChannel(str(channel)),
            key_digest=str(key_digest),
            tofu=tofu == 1,
            revoked=revoked_at is not None,
            public_key=str(public_key),
            credential_id=None if credential_id is None else str(credential_id),
            sign_count=int(sign_count) if isinstance(sign_count, int) else 0,
        )
    except ValueError as exc:
        raise _integrity("signer row") from exc


def active_signers(db: sqlite3.Connection) -> tuple[SignerRecord, ...]:
    rows = db.execute(f"SELECT {_SIGNER_COLUMNS} FROM signer WHERE revoked_at IS NULL ORDER BY rowid").fetchall()
    return tuple(_decode_signer(tuple(row)) for row in rows)


def read_signer(db: sqlite3.Connection, signer_id: str) -> SignerRecord | None:
    row = db.execute(f"SELECT {_SIGNER_COLUMNS} FROM signer WHERE id = ?", (signer_id,)).fetchone()
    return None if row is None else _decode_signer(tuple(row))


_UINT32_MAX = 0xFFFFFFFF


def record_sign_count(db: sqlite3.Connection, signer_id: str, sign_count: int) -> None:
    if not isinstance(signer_id, str) or type(sign_count) is not int or not 0 <= sign_count <= _UINT32_MAX:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    spent = db.execute(
        "UPDATE signer SET sign_count = ? "
        "WHERE id = ? AND revoked_at IS NULL AND ((sign_count = 0 AND ? = 0) OR sign_count < ?)",
        (sign_count, signer_id, sign_count, sign_count),
    )
    if spent.rowcount != 1:
        raise refused()


def _insert_signer(db: sqlite3.Connection, enrollment: SignerEnrollment, *, tofu: bool, now: datetime) -> SignerRecord:
    owner = store_owner(db)
    if owner is not None and owner != enrollment.owner_id:
        raise BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch")
    if owner is None:
        db.execute("INSERT INTO meta (key, value) VALUES (?, ?)", (OWNER_META_KEY, enrollment.owner_id))
    signer_id = new_id()
    try:
        db.execute(
            "INSERT INTO signer (id, owner_id, channel, key_digest, public_key, credential_id, sign_count, tofu, "
            "created_at) VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)",
            (
                signer_id,
                enrollment.owner_id,
                enrollment.channel.value,
                enrollment.key_digest,
                enrollment.public_key,
                enrollment.credential_id,
                1 if tofu else 0,
                canonical_utc(now),
            ),
        )
    except sqlite3.IntegrityError as exc:
        raise BrainError(ErrorCode.REVISION_CONFLICT, "revision conflict") from exc
    record = read_signer(db, signer_id)
    assert record is not None
    return record


def enroll_first_signer(db: sqlite3.Connection, enrollment: SignerEnrollment, now: datetime) -> SignerRecord:
    """Trust on first use: only while no active signer exists (a fresh store or right after a signer reset)."""
    if not isinstance(enrollment, SignerEnrollment):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if db.execute("SELECT 1 FROM signer WHERE revoked_at IS NULL LIMIT 1").fetchone() is not None:
        raise refused()
    return _insert_signer(db, enrollment, tofu=True, now=now)


def issue_nonce(
    db: sqlite3.Connection,
    *,
    action: ApprovalAction,
    subject_id: str,
    risk_level: RiskLevel,
    trust_generation: int,
    now: datetime,
) -> IssuedNonce:
    """A fresh single-use nonce bound to ``(action, subject, risk, generation)``; always-high actions are HIGH."""
    if not isinstance(action, ApprovalAction) or not isinstance(risk_level, RiskLevel):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if not isinstance(subject_id, str) or not subject_id or "\x00" in subject_id:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    owner = store_owner(db)
    if owner is None:
        raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")
    risk = effective_risk(action, risk_level)
    expires_at = now + APPROVAL_TTL
    nonce = secrets.token_urlsafe(24)
    db.execute(
        "INSERT INTO approval_nonce (nonce, owner_id, action, subject_id, risk_level, trust_generation, issued_at, "
        "expires_at, state) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')",
        (
            nonce,
            owner,
            action.value,
            subject_id,
            risk.value,
            trust_generation,
            canonical_utc(now),
            canonical_utc(expires_at),
        ),
    )
    return IssuedNonce(
        nonce=nonce,
        action=action,
        subject_id=subject_id,
        risk_level=risk,
        trust_generation=trust_generation,
        expires_at=expires_at,
    )


def _fence_trust_generation(message: ApprovalMessage, nonce_generation: int, current: int) -> None:
    """Spec 5.7/11.3: an approval signed for another trust generation is dead (restore, reset)."""
    if message.trust_generation != current or nonce_generation != current:
        raise refused()


def _parse_utc(text: object) -> datetime:
    if not isinstance(text, str):
        raise _integrity("timestamp")
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise _integrity("timestamp") from exc


def _check_signer(
    db: sqlite3.Connection, message: ApprovalMessage, signer_id: str | None, channel: ApprovalChannel
) -> None:
    if channel is ApprovalChannel.TERMINAL:
        if signer_id is not None:
            raise refused()
        return
    if not isinstance(signer_id, str):
        raise refused()
    signer = read_signer(db, signer_id)
    if signer is None or signer.revoked or signer.owner_id != message.owner_id or signer.channel is not channel:
        raise refused()


def consume_approval(
    db: sqlite3.Connection,
    message: ApprovalMessage,
    *,
    signer_id: str | None,
    channel: ApprovalChannel,
    store_id: str,
    trust_generation: int,
    now: datetime,
    terminal_eligible: bool,
    new_sign_count: int | None = None,
) -> ApprovalReceipt:
    """Spend the nonce of ``message`` exactly once and record the receipt.

    Refusals are ``UNAUTHENTICATED`` (store or owner mismatch may be ``IDENTITY_MISMATCH``); a terminal approval at
    high risk or with a layer 2 that is not verified for every connected harness is ``CAPABILITY_UNAVAILABLE``.
    When ``new_sign_count`` is given, the passkey counter is enforced strictly monotonic and persisted atomically
    in the same transaction.
    """
    if not isinstance(message, ApprovalMessage) or not isinstance(channel, ApprovalChannel):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if new_sign_count is not None and (
        type(new_sign_count) is not int or not 0 <= new_sign_count <= _UINT32_MAX
    ):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if message.store_id != store_id:
        raise BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch")
    row = db.execute(
        "SELECT owner_id, action, subject_id, risk_level, trust_generation, issued_at, expires_at "
        "FROM approval_nonce WHERE nonce = ?",
        (message.nonce,),
    ).fetchone()
    if row is None:
        raise refused()
    owner_id, action, subject_id, risk_level, nonce_generation, issued_text, expires_text = row
    if message.owner_id != owner_id:
        raise BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch")
    if (
        message.action.value != action
        or message.subject_id != subject_id
        or message.risk_level.value != risk_level
        or type(nonce_generation) is not int
    ):
        raise refused()
    _fence_trust_generation(message, nonce_generation, trust_generation)
    if (
        canonical_utc(message.expires_at) != expires_text
        or now < _parse_utc(issued_text)
        or now >= _parse_utc(expires_text)
    ):
        raise refused()
    if channel not in required_channels(message.action, message.risk_level, terminal_eligible=terminal_eligible):
        raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")
    _check_signer(db, message, signer_id, channel)
    if new_sign_count is not None:
        if channel is not ApprovalChannel.PASSKEY_UV or signer_id is None:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        record_sign_count(db, signer_id, new_sign_count)
    stamp = canonical_utc(now)
    spent = db.execute(
        "UPDATE approval_nonce SET state = 'consumed', ended_at = ? WHERE nonce = ? AND state = 'pending'",
        (stamp, message.nonce),
    )
    if spent.rowcount != 1:
        raise refused()
    approval_id = new_id()
    assurance = assurance_for(channel)
    db.execute(
        "INSERT INTO approval_receipt_meta (approval_id, nonce, action, subject_id, risk_level, channel, assurance, "
        "signer_id, trust_generation, recovery_scope, message_json, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            approval_id,
            message.nonce,
            message.action.value,
            message.subject_id,
            message.risk_level.value,
            channel.value,
            assurance.value,
            signer_id,
            message.trust_generation,
            message.recovery_scope.value,
            message.canonical_bytes(),
            stamp,
        ),
    )
    if signer_id is not None:
        db.execute("UPDATE signer SET last_used_at = ? WHERE id = ?", (stamp, signer_id))
    return ApprovalReceipt(
        approval_id=approval_id, message=message, signer_id=signer_id, channel=channel, assurance=assurance
    )


def require_enroll_approval(db: sqlite3.Connection, enrollment: SignerEnrollment, approval: ApprovalMessage) -> None:
    """The approval must be a ``signer_enroll`` for exactly this key in this store's owner namespace."""
    if not isinstance(enrollment, SignerEnrollment) or not isinstance(approval, ApprovalMessage):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    owner = store_owner(db)
    if (
        approval.action is not ApprovalAction.SIGNER_ENROLL
        or approval.subject_id != enrollment.subject_id
        or enrollment.owner_id != approval.owner_id
        or owner != enrollment.owner_id
    ):
        raise refused()


def enroll_signer(
    db: sqlite3.Connection,
    enrollment: SignerEnrollment,
    *,
    approval: ApprovalMessage,
    approver_signer_id: str | None,
    channel: ApprovalChannel,
    store_id: str,
    trust_generation: int,
    now: datetime,
    terminal_eligible: bool,
    new_sign_count: int | None = None,
) -> SignerRecord:
    require_enroll_approval(db, enrollment, approval)
    consume_approval(
        db,
        approval,
        signer_id=approver_signer_id,
        channel=channel,
        store_id=store_id,
        trust_generation=trust_generation,
        now=now,
        terminal_eligible=terminal_eligible,
        new_sign_count=new_sign_count,
    )
    return _insert_signer(db, enrollment, tofu=False, now=now)


def revoke_signer(
    db: sqlite3.Connection,
    signer_id: str,
    *,
    approval: ApprovalMessage,
    approver_signer_id: str | None,
    channel: ApprovalChannel,
    store_id: str,
    trust_generation: int,
    now: datetime,
    terminal_eligible: bool,
    new_sign_count: int | None = None,
) -> SignerRecord:
    if not isinstance(signer_id, str) or not isinstance(approval, ApprovalMessage):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if approval.action is not ApprovalAction.SIGNER_REVOKE or approval.subject_id != signer_id:
        raise refused()
    target = read_signer(db, signer_id)
    if target is None or target.revoked:
        raise BrainError(ErrorCode.NOT_FOUND, "not found")
    consume_approval(
        db,
        approval,
        signer_id=approver_signer_id,
        channel=channel,
        store_id=store_id,
        trust_generation=trust_generation,
        now=now,
        terminal_eligible=terminal_eligible,
        new_sign_count=new_sign_count,
    )
    db.execute("UPDATE signer SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL", (canonical_utc(now), signer_id))
    revoked = read_signer(db, signer_id)
    assert revoked is not None
    return revoked
