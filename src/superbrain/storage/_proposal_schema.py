"""Store v5 proposal/journal DDL, ``KERNEL_PROPOSAL_KINDS``, and ``ProposalProjectionHandler``."""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.proposals import JournalDirection, ProposalStatus
from superbrain.ports.policy import PolicyView
from superbrain.storage.kinds import EntryKind, FieldType
from superbrain.storage.ledger import LedgerEntry, ProjectionHandler

__all__ = [
    "KERNEL_PROPOSAL_KINDS",
    "ProposalProjectionHandler",
    "with_proposal_defaults",
]

_STATUS_VALUES: frozenset[str] = frozenset(status.value for status in ProposalStatus)
_DIRECTION_VALUES: frozenset[str] = frozenset(direction.value for direction in JournalDirection)
_RISK_VALUES: frozenset[str] = frozenset({"low", "high"})

KERNEL_PROPOSAL_KINDS: tuple[EntryKind, ...] = (
    EntryKind(
        "proposal.created",
        1,
        {
            "proposal_id": FieldType.OPAQUE_ID,
            "kind": FieldType.OPAQUE_ID,
            "risk_level": FieldType.ENUM,
            "subject_revision": FieldType.INT,
            "payload_digest": FieldType.DIGEST,
        },
        {"risk_level": _RISK_VALUES},
    ),
    EntryKind(
        "proposal.status_set",
        1,
        {
            "proposal_id": FieldType.OPAQUE_ID,
            "status": FieldType.ENUM,
            "subject_revision": FieldType.INT,
            "active_journal_id": FieldType.OPAQUE_ID,
            "updated_at": FieldType.TIMESTAMP,
        },
        {"status": _STATUS_VALUES},
        nullable=frozenset({"active_journal_id"}),
    ),
    EntryKind(
        "journal.recorded",
        1,
        {
            "journal_id": FieldType.UUID,
            "proposal_id": FieldType.OPAQUE_ID,
            "direction": FieldType.ENUM,
            "status": FieldType.ENUM,
            "grant_id": FieldType.UUID,
            "journal_digest": FieldType.DIGEST,
        },
        {"direction": _DIRECTION_VALUES, "status": _STATUS_VALUES},
    ),
    EntryKind(
        "journal.updated",
        1,
        {
            "journal_id": FieldType.UUID,
            "status": FieldType.ENUM,
            "journal_digest": FieldType.DIGEST,
            "updated_at": FieldType.TIMESTAMP,
        },
        {"status": _STATUS_VALUES},
    ),
    EntryKind(
        "manifest.recorded",
        1,
        {
            "proposal_id": FieldType.OPAQUE_ID,
            "target_key_digest": FieldType.DIGEST,
            "slice_digest": FieldType.DIGEST,
            "full_file_digest": FieldType.DIGEST,
            "manifest_digest": FieldType.DIGEST,
            "updated_at": FieldType.TIMESTAMP,
        },
        {},
    ),
)


def _corrupt(entry: LedgerEntry, what: str) -> BrainError:
    return BrainError(ErrorCode.INTEGRITY_FAILURE, f"ledger entry {entry.sequence}: {what}")


def _meta_str(entry: LedgerEntry, key: str) -> str:
    val = entry.meta.get(key)
    if not isinstance(val, str) or not val:
        raise _corrupt(entry, f"{key} missing or not str")
    return val


def _meta_opt_str(entry: LedgerEntry, key: str) -> str | None:
    val = entry.meta.get(key)
    if val is None:
        return None
    if not isinstance(val, str) or not val:
        raise _corrupt(entry, f"{key} not str")
    return val


def _meta_int(entry: LedgerEntry, key: str) -> int:
    val = entry.meta.get(key)
    if type(val) is not int:
        raise _corrupt(entry, f"{key} not int")
    return val


class ProposalProjectionHandler:
    """Event-sourced ``p_proposals_*`` projection rebuilt deterministically by ``Store.rebuild_projections()``."""

    name = "proposals"
    handler_version = 1
    kinds = frozenset(spec.kind for spec in KERNEL_PROPOSAL_KINDS)

    def create_tables(self, db: sqlite3.Connection, prefix: str) -> None:
        db.execute(
            f"CREATE TABLE {prefix}proposals ("
            "proposal_id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, kind TEXT NOT NULL, "
            "status TEXT NOT NULL, subject_revision INTEGER NOT NULL, risk_level TEXT NOT NULL, "
            "payload_digest TEXT NOT NULL, active_journal_id TEXT, created_at TEXT NOT NULL, "
            "updated_at TEXT NOT NULL, sequence INTEGER NOT NULL)"
        )
        db.execute(
            f"CREATE TABLE {prefix}journals ("
            "journal_id TEXT PRIMARY KEY, proposal_id TEXT NOT NULL, direction TEXT NOT NULL, "
            "status TEXT NOT NULL, grant_id TEXT NOT NULL, journal_digest TEXT NOT NULL, "
            "created_at TEXT NOT NULL, updated_at TEXT NOT NULL, sequence INTEGER NOT NULL)"
        )
        db.execute(
            f"CREATE TABLE {prefix}manifests ("
            "proposal_id TEXT NOT NULL, target_key_digest TEXT NOT NULL, slice_digest TEXT NOT NULL, "
            "full_file_digest TEXT NOT NULL, manifest_digest TEXT NOT NULL, updated_at TEXT NOT NULL, "
            "sequence INTEGER NOT NULL, PRIMARY KEY (proposal_id, target_key_digest))"
        )

    def apply(self, db: sqlite3.Connection, prefix: str, entry: LedgerEntry, policy: PolicyView) -> None:
        _ = policy
        seq = entry.sequence
        if entry.kind == "proposal.created":
            db.execute(
                f"INSERT INTO {prefix}proposals (proposal_id, owner_id, kind, status, subject_revision, "
                "risk_level, payload_digest, active_journal_id, created_at, updated_at, sequence) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)",
                (
                    _meta_str(entry, "proposal_id"),
                    entry.owner_id or "",
                    _meta_str(entry, "kind"),
                    ProposalStatus.PENDING.value,
                    _meta_int(entry, "subject_revision"),
                    _meta_str(entry, "risk_level"),
                    _meta_str(entry, "payload_digest"),
                    entry.recorded_at,
                    entry.recorded_at,
                    seq,
                ),
            )
            return
        if entry.kind == "proposal.status_set":
            cur = db.execute(
                f"UPDATE {prefix}proposals SET status = ?, subject_revision = ?, active_journal_id = ?, "
                "updated_at = ?, sequence = ? WHERE proposal_id = ?",
                (
                    _meta_str(entry, "status"),
                    _meta_int(entry, "subject_revision"),
                    _meta_opt_str(entry, "active_journal_id"),
                    _meta_str(entry, "updated_at"),
                    seq,
                    _meta_str(entry, "proposal_id"),
                ),
            )
            if cur.rowcount != 1:
                raise _corrupt(entry, "proposal.status_set target missing")
            return
        if entry.kind == "journal.recorded":
            db.execute(
                f"INSERT INTO {prefix}journals (journal_id, proposal_id, direction, status, grant_id, "
                "journal_digest, created_at, updated_at, sequence) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    _meta_str(entry, "journal_id"),
                    _meta_str(entry, "proposal_id"),
                    _meta_str(entry, "direction"),
                    _meta_str(entry, "status"),
                    _meta_str(entry, "grant_id"),
                    _meta_str(entry, "journal_digest"),
                    entry.recorded_at,
                    entry.recorded_at,
                    seq,
                ),
            )
            return
        if entry.kind == "journal.updated":
            cur = db.execute(
                f"UPDATE {prefix}journals SET status = ?, journal_digest = ?, updated_at = ?, sequence = ? "
                "WHERE journal_id = ?",
                (
                    _meta_str(entry, "status"),
                    _meta_str(entry, "journal_digest"),
                    _meta_str(entry, "updated_at"),
                    seq,
                    _meta_str(entry, "journal_id"),
                ),
            )
            if cur.rowcount != 1:
                raise _corrupt(entry, "journal.updated target missing")
            return
        if entry.kind == "manifest.recorded":
            db.execute(
                f"INSERT OR REPLACE INTO {prefix}manifests (proposal_id, target_key_digest, slice_digest, "
                "full_file_digest, manifest_digest, updated_at, sequence) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    _meta_str(entry, "proposal_id"),
                    _meta_str(entry, "target_key_digest"),
                    _meta_str(entry, "slice_digest"),
                    _meta_str(entry, "full_file_digest"),
                    _meta_str(entry, "manifest_digest"),
                    _meta_str(entry, "updated_at"),
                    seq,
                ),
            )
            return
        raise _corrupt(entry, f"unexpected proposal kind {entry.kind}")


def with_proposal_defaults(
    handlers: Sequence[ProjectionHandler],
    schema_ver: int,
    policy_kinds: Sequence[EntryKind],
) -> tuple[tuple[ProjectionHandler, ...], tuple[EntryKind, ...]]:
    """Append ``ProposalProjectionHandler`` on v5+ stores and return built-in extra entry kinds."""
    out_handlers = tuple(handlers)
    needs_proposals = schema_ver >= 5 or any(h.name == "proposals" for h in out_handlers)
    if schema_ver >= 5 and not any(h.name == "proposals" for h in out_handlers):
        out_handlers = (*out_handlers, ProposalProjectionHandler())
    extra = (*(policy_kinds if schema_ver >= 2 else ()), *(KERNEL_PROPOSAL_KINDS if needs_proposals else ()))
    return out_handlers, extra
