"""Retention: default expiry per class and the expiry sweep that turns expired holds into tombstone intents.

An expired holder loses its blobs through a tombstone intent; the blob itself is deleted only by garbage
collection once nothing holds it. The ledger never contains payload bytes.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.policy import IntentKind
from superbrain.storage.kinds import RetentionClass
from superbrain.storage.ledger import utc_timestamp
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.store import Store

MIN_EVENT_PAYLOAD_DAYS = 1
MAX_EVENT_PAYLOAD_DAYS = 3650


@dataclass(frozen=True)
class RetentionPolicy:
    """How long an Event payload is kept: ``event_payload_days`` in ``1..3650`` (an int, not a bool)."""

    event_payload_days: int = 90

    def __post_init__(self) -> None:
        days = self.event_payload_days
        if type(days) is not int or not MIN_EVENT_PAYLOAD_DAYS <= days <= MAX_EVENT_PAYLOAD_DAYS:
            raise BrainError(
                ErrorCode.INVALID_INPUT,
                f"event_payload_days must be an integer in {MIN_EVENT_PAYLOAD_DAYS}..{MAX_EVENT_PAYLOAD_DAYS}",
            )


@dataclass(frozen=True)
class ExpiryReport:
    """The ``(holder_kind, holder_id)`` pairs tombstoned by one sweep, sorted."""

    expired: tuple[tuple[str, str], ...]


def default_expiry(retention: RetentionClass, now: datetime, policy: RetentionPolicy) -> datetime | None:
    """When a hold of this class expires if taken at ``now``; ``None`` means never. A naive ``now`` is a bug."""
    if now.tzinfo is None or now.utcoffset() is None:
        raise AssertionError("now must be a timezone-aware datetime")
    if retention is RetentionClass.EVENT_PAYLOAD:
        return now + timedelta(days=policy.event_payload_days)
    return None


def expire_due(store: Store, policy: PolicyStore, now: datetime) -> ExpiryReport:
    """Record one tombstone intent per due holder, then reconcile; returns the holders it expired.

    A tombstone acts on a whole holder, so a holder is due only when every one of its holds is non-durable, has an
    expiry and is due at ``now``; a holder with any durable, never-expiring or not yet due hold is skipped entirely
    and left out of the report. A ``now`` earlier than every expiry (a clock that went backwards) expires nothing.

    If ``reconcile_policy`` fails after the intents were recorded, they stay pending and the next ``expire_due`` or
    ``Store.open`` applies each exactly once. A holder that is already tombstoned but not yet reconciled still shows
    as due, but no second intent is recorded for it; the pending one is applied by the same reconcile.
    """
    if now.tzinfo is None or now.utcoffset() is None:
        raise BrainError(ErrorCode.INVALID_INPUT, "now must be timezone-aware")
    due = store.cas.due_holders(utc_timestamp(now))
    for holder_kind, holder_id in due:
        if policy.is_tombstoned(holder_kind, holder_id):
            continue
        policy.record_intent(IntentKind.TOMBSTONE, {"holder_kind": holder_kind, "holder_id": holder_id})
    if due:
        store.reconcile_policy()
    return ExpiryReport(expired=tuple(due))
