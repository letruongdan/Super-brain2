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
    """Record one tombstone intent per holder with a non-durable hold expiring at or before ``now``, then reconcile.

    A ``now`` earlier than every expiry (a clock that went backwards) expires nothing.
    """
    if now.tzinfo is None or now.utcoffset() is None:
        raise BrainError(ErrorCode.INVALID_INPUT, "now must be timezone-aware")
    due = store.cas.due_holders(utc_timestamp(now))
    for holder_kind, holder_id in due:
        policy.record_intent(IntentKind.TOMBSTONE, {"holder_kind": holder_kind, "holder_id": holder_id})
    if due:
        store.reconcile_policy()
    return ExpiryReport(expired=tuple(due))
