"""Proposal, ApplyJournal, and ManagedSliceManifest storage adapters + PolicyApplyAuthority (I3-2)."""

from __future__ import annotations

import sqlite3
import uuid
from collections.abc import Mapping, Sequence
from pathlib import Path

from superbrain.core._kernel_approval import (
    ApprovalChannel,
    ApprovalMessage,
    ApprovalReceipt,
    RecoveryGrant,
)
from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.proposals import (
    ApplyJournal,
    ApplyTurnIntent,
    ChangeProposal,
    JournalDirection,
    ManagedSliceManifest,
    ProposalStatus,
)
from superbrain.ports.os import OsAdapters
from superbrain.ports.proposals import ApplyAuthorityPort, ProposalStorePort
from superbrain.storage._proposal_codec import (
    decode_journal,
    decode_manifest,
    decode_proposal,
    encode_journal,
    encode_manifest,
    encode_proposal,
)
from superbrain.storage._proposal_schema import KERNEL_PROPOSAL_KINDS, ProposalProjectionHandler
from superbrain.storage.cas import RetentionClass
from superbrain.storage.errors import sqlite_error
from superbrain.storage.kinds import KindRegistry, is_uuid
from superbrain.storage.ledger import LedgerEntry, ProjectionHandler
from superbrain.storage.policy_store import PolicyStore
from superbrain.storage.store import Store

__all__ = [
    "KERNEL_PROPOSAL_KINDS",
    "PolicyApplyAuthority",
    "ProposalProjectionHandler",
    "StoreProposalAdapter",
    "kernel_proposal_extensions",
]

_ACTOR = "user:cli"


def _corrupt(entry: LedgerEntry | None, what: str) -> BrainError:
    where = f"ledger entry {entry.sequence}" if entry is not None else "proposal projection"
    return BrainError(ErrorCode.INTEGRITY_FAILURE, f"{where}: {what}")


def _holder_uuid(identifier: str) -> str:
    if is_uuid(identifier):
        return identifier
    return str(uuid.uuid5(uuid.NAMESPACE_URL, identifier))


def kernel_proposal_extensions() -> tuple[tuple[ProjectionHandler, ...], KindRegistry]:
    """Projection handlers and entry kinds for ``ChangeProposal`` / ``ApplyJournal``."""
    return (ProposalProjectionHandler(),), KindRegistry(KERNEL_PROPOSAL_KINDS)


def _as_int(value: object) -> int:
    if type(value) is not int:
        raise _corrupt(None, "integer column has wrong type")
    return value


class StoreProposalAdapter(ProposalStorePort):
    """Stores ``ChangeProposal``, ``ApplyJournal``, and ``ManagedSliceManifest`` in ``Store`` CAS + ledger."""

    def __init__(self, store: Store, os_: OsAdapters) -> None:
        self._store = store
        self._os = os_

    @property
    def store_id(self) -> str:
        return self._store.store_id

    def _query(self, sql: str, params: tuple[object, ...]) -> list[tuple[object, ...]]:
        self._store._check()
        try:
            return self._store._db.execute(sql, params).fetchall()
        except sqlite3.Error as exc:
            raise sqlite_error("cannot read proposal projection", exc) from exc

    def create_proposal(self, proposal: ChangeProposal, payloads: Mapping[str, bytes]) -> ChangeProposal:
        self._store._check()
        payload_digest = self._store.cas.put(encode_proposal(proposal))
        stored_refs: list[str] = [payload_digest]
        for expected_digest, raw_bytes in payloads.items():
            actual_digest = self._store.cas.put(raw_bytes)
            if actual_digest != expected_digest:
                raise BrainError(ErrorCode.INTEGRITY_FAILURE, "proposal payload digest mismatch")
            if actual_digest not in stored_refs:
                stored_refs.append(actual_digest)
        holder = _holder_uuid(proposal.proposal_id)
        with self._store.transaction() as txn:
            for ref in stored_refs:
                txn.hold(ref, "proposal", holder, RetentionClass.DURABLE, None)
            txn.append(
                "proposal.created",
                actor=_ACTOR,
                owner_id=proposal.owner_id,
                meta={
                    "proposal_id": proposal.proposal_id,
                    "kind": proposal.kind,
                    "risk_level": proposal.risk_level.value,
                    "subject_revision": proposal.subject_revision,
                    "payload_digest": payload_digest,
                },
                refs=stored_refs,
            )
        return self.get_proposal(proposal.proposal_id)

    def get_proposal(self, proposal_id: str) -> ChangeProposal:
        rows = self._query(
            "SELECT status, subject_revision, payload_digest, active_journal_id, updated_at "
            "FROM p_proposals_proposals WHERE proposal_id = ?",
            (proposal_id,),
        )
        if not rows:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        status, rev, digest, active_journal_id, updated_at = rows[0]
        raw = self._store.cas.read(str(digest))
        return decode_proposal(
            raw,
            status=str(status),
            subject_revision=_as_int(rev),
            active_journal_id=None if active_journal_id is None else str(active_journal_id),
            updated_at=str(updated_at),
        )

    def list_proposals(self) -> tuple[ChangeProposal, ...]:
        rows = self._query(
            "SELECT status, subject_revision, payload_digest, active_journal_id, updated_at "
            "FROM p_proposals_proposals ORDER BY created_at, proposal_id",
            (),
        )
        return tuple(
            decode_proposal(
                self._store.cas.read(str(digest)),
                status=str(status),
                subject_revision=_as_int(rev),
                active_journal_id=None if active_journal_id is None else str(active_journal_id),
                updated_at=str(updated_at),
            )
            for status, rev, digest, active_journal_id, updated_at in rows
        )

    def update_proposal_status(
        self,
        proposal_id: str,
        status: ProposalStatus,
        *,
        subject_revision: int | None = None,
        active_journal_id: str | None = None,
        updated_at: str,
    ) -> ChangeProposal:
        current = self.get_proposal(proposal_id)
        rev = current.subject_revision if subject_revision is None else subject_revision
        with self._store.transaction() as txn:
            txn.append(
                "proposal.status_set",
                actor=_ACTOR,
                owner_id=current.owner_id,
                meta={
                    "proposal_id": proposal_id,
                    "status": status.value,
                    "subject_revision": rev,
                    "active_journal_id": active_journal_id,
                    "updated_at": updated_at,
                },
            )
        return self.get_proposal(proposal_id)

    def read_payload_bytes(self, digest: str) -> bytes:
        return self._store.cas.read(digest)

    def save_journal(self, journal: ApplyJournal) -> ApplyJournal:
        prop = self.get_proposal(journal.proposal_id)
        journal_digest = self._store.cas.put(encode_journal(journal))
        holder = _holder_uuid(journal.journal_id)
        with self._store.transaction() as txn:
            txn.hold(journal_digest, "proposal", holder, RetentionClass.DURABLE, None)
            txn.append(
                "journal.recorded",
                actor=_ACTOR,
                owner_id=prop.owner_id,
                meta={
                    "journal_id": journal.journal_id,
                    "proposal_id": journal.proposal_id,
                    "direction": journal.direction.value,
                    "status": journal.status.value,
                    "grant_id": journal.grant_id,
                    "journal_digest": journal_digest,
                },
                refs=[journal_digest],
            )
        return self.get_journal(journal.journal_id)

    def update_journal(self, journal: ApplyJournal) -> ApplyJournal:
        prop = self.get_proposal(journal.proposal_id)
        journal_digest = self._store.cas.put(encode_journal(journal))
        holder = _holder_uuid(journal.journal_id)
        with self._store.transaction() as txn:
            txn.hold(journal_digest, "proposal", holder, RetentionClass.DURABLE, None)
            txn.append(
                "journal.updated",
                actor=_ACTOR,
                owner_id=prop.owner_id,
                meta={
                    "journal_id": journal.journal_id,
                    "status": journal.status.value,
                    "journal_digest": journal_digest,
                    "updated_at": journal.updated_at,
                },
                refs=[journal_digest],
            )
        return self.get_journal(journal.journal_id)

    def get_journal(self, journal_id: str) -> ApplyJournal:
        rows = self._query(
            "SELECT journal_digest FROM p_proposals_journals WHERE journal_id = ?",
            (journal_id,),
        )
        if not rows:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        raw = self._store.cas.read(str(rows[0][0]))
        return decode_journal(raw)

    def find_latest_apply_journal(self, proposal_id: str) -> ApplyJournal:
        rows = self._query(
            "SELECT journal_digest FROM p_proposals_journals "
            "WHERE proposal_id = ? AND direction = 'apply' ORDER BY sequence DESC LIMIT 1",
            (proposal_id,),
        )
        if not rows:
            raise BrainError(ErrorCode.NOT_FOUND, "not found")
        return decode_journal(self._store.cas.read(str(rows[0][0])))

    def list_incomplete_journals(self) -> tuple[ApplyJournal, ...]:
        rows = self._query(
            "SELECT journal_digest FROM p_proposals_journals "
            "WHERE status IN ('applying', 'partially_applied', 'rolling_back') ORDER BY sequence",
            (),
        )
        return tuple(decode_journal(self._store.cas.read(str(row[0]))) for row in rows)

    def save_manifests(self, manifests: Sequence[ManagedSliceManifest]) -> None:
        if not manifests:
            return
        prop = self.get_proposal(manifests[0].proposal_id)
        holder = _holder_uuid(prop.proposal_id)
        prepared: list[tuple[ManagedSliceManifest, str, str]] = []
        for manifest in manifests:
            m_digest = self._store.cas.put(encode_manifest(manifest))
            key_digest = digest_bytes(
                canonical_json(
                    {
                        "target_root": manifest.target_root,
                        "normalized_rel_path": manifest.normalized_rel_path,
                        "managed_format": manifest.managed_format.value,
                        "slice_id": manifest.slice_id,
                    }
                )
            )
            prepared.append((manifest, key_digest, m_digest))
        with self._store.transaction() as txn:
            for manifest, key_digest, m_digest in prepared:
                txn.hold(m_digest, "proposal", holder, RetentionClass.DURABLE, None)
                txn.append(
                    "manifest.recorded",
                    actor=_ACTOR,
                    owner_id=prop.owner_id,
                    meta={
                        "proposal_id": manifest.proposal_id,
                        "target_key_digest": key_digest,
                        "slice_digest": manifest.slice_digest,
                        "full_file_digest": manifest.full_file_digest,
                        "manifest_digest": m_digest,
                        "updated_at": manifest.updated_at,
                    },
                    refs=[m_digest],
                )

    def list_manifests(self, proposal_id: str) -> tuple[ManagedSliceManifest, ...]:
        rows = self._query(
            "SELECT manifest_digest FROM p_proposals_manifests WHERE proposal_id = ? ORDER BY sequence",
            (proposal_id,),
        )
        return tuple(decode_manifest(self._store.cas.read(str(row[0]))) for row in rows)

    def list_latest_manifests_for_owner(
        self, owner_id: str
    ) -> tuple[tuple[ManagedSliceManifest, ProposalStatus], ...]:
        rows = self._query(
            "SELECT m.target_key_digest, m.manifest_digest, p.status "
            "FROM p_proposals_manifests m "
            "JOIN p_proposals_proposals p ON m.proposal_id = p.proposal_id "
            "WHERE p.owner_id = ? "
            "ORDER BY m.sequence DESC",
            (owner_id,),
        )
        seen_keys: set[str] = set()
        out: list[tuple[ManagedSliceManifest, ProposalStatus]] = []
        for key_digest_obj, manifest_digest_obj, status_obj in rows:
            key_digest = str(key_digest_obj)
            if key_digest in seen_keys:
                continue
            seen_keys.add(key_digest)
            manifest = decode_manifest(self._store.cas.read(str(manifest_digest_obj)))
            out.append((manifest, ProposalStatus(str(status_obj))))
        return tuple(out)


class PolicyApplyAuthority(ApplyAuthorityPort):
    """Bridges ``PolicyStore`` v4 approval/grant authority to ``ApplyAuthorityPort``."""

    def __init__(self, policy: PolicyStore) -> None:
        self._policy = policy

    def trust_generation(self) -> int:
        return self._policy.trust_generation()

    def consume_approval(
        self,
        message: ApprovalMessage,
        *,
        signer_id: str | None,
        channel: ApprovalChannel,
        new_sign_count: int | None = None,
    ) -> ApprovalReceipt:
        return self._policy.consume_approval(
            message,
            signer_id=signer_id,
            channel=channel,
            new_sign_count=new_sign_count,
        )

    def approval_message(self, approval_id: str) -> ApprovalMessage | None:
        return self._policy.approval_message(approval_id)

    def open_recovery_grant(self, *, approval_id: str, journal_id: str) -> RecoveryGrant:
        return self._policy.open_recovery_grant(approval_id=approval_id, journal_id=journal_id)

    def recovery_grant(self, grant_id: str) -> RecoveryGrant:
        return self._policy.recovery_grant(grant_id)

    def find_recovery_grant_for_journal(self, journal_id: str) -> RecoveryGrant | None:
        return self._policy.find_recovery_grant_for_journal(journal_id)

    def list_recovery_grants(self) -> tuple[RecoveryGrant, ...]:
        return self._policy.list_recovery_grants()

    def open_turn_intent(
        self, *, journal_id: str, approval_id: str, direction: JournalDirection
    ) -> ApplyTurnIntent:
        return self._policy.open_turn_intent(
            journal_id=journal_id, approval_id=approval_id, direction=direction
        )

    def begin_journal_turn(
        self, *, approval_id: str, journal_id: str, direction: JournalDirection
    ) -> tuple[RecoveryGrant, ApplyTurnIntent]:
        return self._policy.begin_journal_turn(
            approval_id=approval_id, journal_id=journal_id, direction=direction
        )

    def turn_intent_for_journal(self, journal_id: str) -> ApplyTurnIntent | None:
        return self._policy.turn_intent_for_journal(journal_id)

    def list_turn_intents(self) -> tuple[ApplyTurnIntent, ...]:
        return self._policy.list_turn_intents()

    def end_recovery_grant(
        self, *, grant_id: str, reason: str = "journal_closed", final_status: str | None = None
    ) -> RecoveryGrant:
        return self._policy.end_recovery_grant(
            grant_id=grant_id, reason=reason, final_status=final_status
        )


_ = Path
