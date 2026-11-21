"""``PolicyStore`` policy-v4 authority API: signers, single-use approvals, layer-2 state, recovery grants and reset.

A mixin so ``policy_store.py`` stays small: it relies on the owner-thread/lease guards and the ``BEGIN IMMEDIATE``
scope that ``PolicyStore`` provides.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from datetime import datetime

from superbrain.core._kernel_approval import (
    ApprovalAction,
    ApprovalChannel,
    ApprovalMessage,
    ApprovalReceipt,
    IssuedNonce,
    Layer2State,
    RecoveryGrant,
    RiskLevel,
    SignerEnrollment,
    SignerRecord,
)
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import Principal
from superbrain.core.proposals import ApplyTurnIntent, JournalDirection
from superbrain.ports.os import OsAdapters
from superbrain.ports.policy import Intent
from superbrain.storage import _policy_approvals as approvals
from superbrain.storage import _policy_grants as grants
from superbrain.storage import _policy_layer2 as layer2
from superbrain.storage.errors import sqlite_error
from superbrain.storage.writer import WriterLease

_MIN_AUTHORITY_SCHEMA = 4


class PolicyAuthorityMixin:
    """Methods of ``PolicyStore`` that need policy schema v4 (``CAPABILITY_UNAVAILABLE`` below it)."""

    _db: sqlite3.Connection
    _os: OsAdapters
    _lease: WriterLease
    _store_id: str
    _schema_version: int

    def _check(self) -> None:
        raise NotImplementedError

    def _immediate(self) -> AbstractContextManager[sqlite3.Connection]:
        raise NotImplementedError

    def trust_generation(self) -> int:
        raise NotImplementedError

    @contextmanager
    def _authority_tx(self) -> Iterator[sqlite3.Connection]:
        """Owner-thread/lease checked ``BEGIN IMMEDIATE`` scope on policy v4; SQLite errors become ``BrainError``."""
        self._check()
        if self._schema_version < _MIN_AUTHORITY_SCHEMA:
            raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")
        try:
            with self._immediate() as db:
                yield db
        except sqlite3.Error as exc:
            raise sqlite_error("cannot use the policy authority tables", exc, busy=True) from exc

    def _now(self) -> datetime:
        return self._os.clock.now()

    def _read(self) -> sqlite3.Connection:
        self._check()
        if self._schema_version < _MIN_AUTHORITY_SCHEMA:
            raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")
        return self._db

    # --- operator principal ------------------------------------------------------------------------------------

    def provision_credential(self, *, owner_id: str, harness_id: str, machine_id: str) -> tuple[Principal, str]:
        """Create the principal if needed plus a new bearer credential; the token is returned once, never stored."""
        with self._authority_tx() as db:
            return approvals.provision_credential(
                db, owner_id=owner_id, harness_id=harness_id, machine_id=machine_id, now=self._now()
            )

    # --- signers -----------------------------------------------------------------------------------------------

    def enroll_first_signer(self, enrollment: SignerEnrollment) -> SignerRecord:
        """Trust on first use: refused (``UNAUTHENTICATED``) once any active signer exists."""
        with self._authority_tx() as db:
            return approvals.enroll_first_signer(db, enrollment, self._now())

    def enroll_signer(
        self,
        enrollment: SignerEnrollment,
        *,
        approval: ApprovalMessage,
        approver_signer_id: str | None,
        channel: ApprovalChannel,
        new_sign_count: int | None = None,
    ) -> SignerRecord:
        with self._authority_tx() as db:
            return approvals.enroll_signer(
                db,
                enrollment,
                approval=approval,
                approver_signer_id=approver_signer_id,
                channel=channel,
                store_id=self._store_id,
                trust_generation=self.trust_generation(),
                now=self._now(),
                terminal_eligible=layer2.terminal_channel_eligible(db, None),
                new_sign_count=new_sign_count,
            )

    def revoke_signer(
        self,
        signer_id: str,
        *,
        approval: ApprovalMessage,
        approver_signer_id: str | None,
        channel: ApprovalChannel,
        new_sign_count: int | None = None,
    ) -> SignerRecord:
        with self._authority_tx() as db:
            return approvals.revoke_signer(
                db,
                signer_id,
                approval=approval,
                approver_signer_id=approver_signer_id,
                channel=channel,
                store_id=self._store_id,
                trust_generation=self.trust_generation(),
                now=self._now(),
                terminal_eligible=layer2.terminal_channel_eligible(db, None),
                new_sign_count=new_sign_count,
            )

    def store_owner(self) -> str | None:
        return approvals.store_owner(self._read())

    def active_signers(self) -> tuple[SignerRecord, ...]:
        return approvals.active_signers(self._read())

    def record_signer_sign_count(self, signer_id: str, sign_count: int) -> None:
        """Persist the WebAuthn counter of ``signer_id`` after a verified assertion; it never goes down."""
        with self._authority_tx() as db:
            approvals.record_sign_count(db, signer_id, sign_count)

    def signer(self, signer_id: str) -> SignerRecord | None:
        return approvals.read_signer(self._read(), signer_id)

    # --- single-use approvals ----------------------------------------------------------------------------------

    def issue_nonce(self, *, action: ApprovalAction, subject_id: str, risk_level: RiskLevel) -> IssuedNonce:
        with self._authority_tx() as db:
            return approvals.issue_nonce(
                db,
                action=action,
                subject_id=subject_id,
                risk_level=risk_level,
                trust_generation=self.trust_generation(),
                now=self._now(),
            )

    def consume_approval(
        self,
        message: ApprovalMessage,
        *,
        signer_id: str | None,
        channel: ApprovalChannel,
        new_sign_count: int | None = None,
    ) -> ApprovalReceipt:
        """Spend ``message``'s nonce once. The signature is verified by the caller's verifier before this call."""
        with self._authority_tx() as db:
            return approvals.consume_approval(
                db,
                message,
                signer_id=signer_id,
                channel=channel,
                store_id=self._store_id,
                trust_generation=self.trust_generation(),
                now=self._now(),
                terminal_eligible=layer2.terminal_channel_eligible(db, None),
                new_sign_count=new_sign_count,
            )

    # --- layer 2 and the terminal channel ----------------------------------------------------------------------

    def set_layer2_state(self, *, harness_id: str, host_version: str, config_digest: str, state: Layer2State) -> None:
        with self._authority_tx() as db:
            layer2.set_layer2_state(
                db,
                harness_id=harness_id,
                host_version=host_version,
                config_digest=config_digest,
                state=state,
                now=self._now(),
            )

    def layer2_state(self, harness_id: str) -> tuple[str, str, str, Layer2State] | None:
        """Latest ``harness_layer2_state`` tuple for ``harness_id``, or ``None`` if absent/below v4."""
        self._check()
        if self._schema_version < _MIN_AUTHORITY_SCHEMA:
            return None
        try:
            return layer2.read_latest_layer2_state(self._db, harness_id=harness_id)
        except sqlite3.Error as exc:
            raise sqlite_error("cannot read layer2 state", exc) from exc

    def set_repo_policy(
        self,
        repo_id: str,
        *,
        automatic_capture_enabled: bool | None = None,
        manual_submission_enabled: bool | None = None,
        indexing_enabled: bool | None = None,
        provider_egress_enabled: bool | None = None,
        post_session_review_enabled: bool | None = None,
    ) -> Intent:
        """Update live repository capture/privacy/egress flags atomically under policy authority."""
        with self._authority_tx() as db:
            return layer2.set_repo_policy_flags(
                db,
                repo_id=repo_id,
                automatic_capture_enabled=automatic_capture_enabled,
                manual_submission_enabled=manual_submission_enabled,
                indexing_enabled=indexing_enabled,
                provider_egress_enabled=provider_egress_enabled,
                post_session_review_enabled=post_session_review_enabled,
                now=self._now(),
            )

    def terminal_channel_eligible(self, *, machine_id: str) -> bool:
        return layer2.terminal_channel_eligible(self._read(), machine_id)

    # --- recovery grants and signer reset ----------------------------------------------------------------------

    def open_recovery_grant(self, *, approval_id: str, journal_id: str) -> RecoveryGrant:
        with self._authority_tx() as db:
            return layer2.open_recovery_grant(
                db,
                approval_id=approval_id,
                journal_id=journal_id,
                trust_generation=self.trust_generation(),
                now=self._now(),
            )

    def recovery_grant(self, grant_id: str) -> RecoveryGrant:
        return layer2.read_recovery_grant(self._read(), grant_id)

    def find_recovery_grant_for_journal(self, journal_id: str) -> RecoveryGrant | None:
        return grants.find_recovery_grant_for_journal(self._read(), journal_id)

    def approval_message(self, approval_id: str) -> ApprovalMessage | None:
        return grants.approval_message(self._read(), approval_id)

    def list_recovery_grants(self) -> tuple[RecoveryGrant, ...]:
        return grants.list_recovery_grants(self._read())

    def open_turn_intent(
        self, *, journal_id: str, approval_id: str, direction: JournalDirection
    ) -> ApplyTurnIntent:
        with self._authority_tx() as db:
            return grants.open_turn_intent(
                db,
                journal_id=journal_id,
                approval_id=approval_id,
                direction=direction,
                trust_generation=self.trust_generation(),
                now=self._now(),
            )

    def begin_journal_turn(
        self, *, approval_id: str, journal_id: str, direction: JournalDirection
    ) -> tuple[RecoveryGrant, ApplyTurnIntent]:
        with self._authority_tx() as db:
            return grants.begin_journal_turn(
                db,
                approval_id=approval_id,
                journal_id=journal_id,
                direction=direction,
                trust_generation=self.trust_generation(),
                now=self._now(),
            )

    def turn_intent_for_journal(self, journal_id: str) -> ApplyTurnIntent | None:
        return grants.turn_intent_for_journal(self._read(), journal_id)

    def list_turn_intents(self) -> tuple[ApplyTurnIntent, ...]:
        return grants.list_turn_intents(self._read())

    def end_recovery_grant(
        self, *, grant_id: str, reason: str = "journal_closed", final_status: str | None = None
    ) -> RecoveryGrant:
        with self._authority_tx() as db:
            return grants.end_recovery_grant_with_turn(
                db,
                grant_id=grant_id,
                reason=reason,
                final_status=final_status,
                trust_generation=self.trust_generation(),
                now=self._now(),
            )

    def reset_signers_offline(self) -> int:
        """``brain init --reset-signers``: the new generation commits in ``policy.db`` first, then ``writer.lock``.

        A kill between the two leaves ``policy.db`` ahead; the next open raises the lock's high-water mark to it
        (``PolicyStore.open``), so the pair is never behind and the reset is all-or-nothing in ``policy.db``.
        """
        self._check()
        hwm = self._lease.state().trust_generation_hwm
        with self._authority_tx() as db:
            previous = self.trust_generation()
            generation = max(previous, hwm) + 1
            layer2.reset_signers(db, previous_generation=previous, new_generation=generation, now=self._now())
        self._lease.raise_trust_hwm(generation)
        return generation

    def signer_reset_recorded(self) -> bool:
        return layer2.signer_reset_recorded(self._read())
