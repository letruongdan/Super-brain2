"""Approval ports: what the operator surface asks of signature verifiers and of the policy store (spec 11.3).

The adapters (``ssh-keygen -Y verify``, the ``webauthn`` library) and ``PolicyStore`` implement these structurally;
nothing above ``ports`` imports them directly.
"""

from __future__ import annotations

from typing import Protocol

from superbrain.core._kernel_approval import (
    ApprovalAction,
    ApprovalChannel,
    ApprovalMessage,
    ApprovalReceipt,
    AssuranceLevel,
    IssuedNonce,
    RiskLevel,
    SignerEnrollment,
    SignerRecord,
)
from superbrain.core.kernel import AuthSnapshot, Principal


class SshApprovalVerifierPort(Protocol):
    def verify(
        self, message: ApprovalMessage, *, channel: ApprovalChannel, public_key: str, signature: bytes
    ) -> AssuranceLevel:
        """Verify an SSHSIG over ``message``; ``UNAUTHENTICATED`` on any failure."""
        ...


class WebAuthnVerification(Protocol):
    @property
    def assurance(self) -> AssuranceLevel: ...

    @property
    def new_sign_count(self) -> int: ...


class WebAuthnApprovalVerifierPort(Protocol):
    def verify(
        self,
        message: ApprovalMessage,
        *,
        response_json: str,
        credential_id: bytes,
        credential_public_key: bytes,
        stored_sign_count: int,
    ) -> WebAuthnVerification:
        """Verify a WebAuthn assertion whose challenge is ``message``; ``UNAUTHENTICATED`` on any failure."""
        ...


class ApprovalPolicyPort(Protocol):
    """The slice of ``PolicyStore`` the operator surface uses; called on the owner thread only."""

    def resolve_credential(self, token: str) -> Principal: ...

    def snapshot(self) -> AuthSnapshot: ...

    def active_signers(self) -> tuple[SignerRecord, ...]: ...

    def signer(self, signer_id: str) -> SignerRecord | None: ...

    def issue_nonce(self, *, action: ApprovalAction, subject_id: str, risk_level: RiskLevel) -> IssuedNonce: ...

    def enroll_signer(
        self,
        enrollment: SignerEnrollment,
        *,
        approval: ApprovalMessage,
        approver_signer_id: str | None,
        channel: ApprovalChannel,
        new_sign_count: int | None = None,
    ) -> SignerRecord: ...

    def revoke_signer(
        self,
        signer_id: str,
        *,
        approval: ApprovalMessage,
        approver_signer_id: str | None,
        channel: ApprovalChannel,
        new_sign_count: int | None = None,
    ) -> SignerRecord: ...

    def consume_approval(
        self,
        message: ApprovalMessage,
        *,
        signer_id: str | None,
        channel: ApprovalChannel,
        new_sign_count: int | None = None,
    ) -> ApprovalReceipt: ...

    def record_signer_sign_count(self, signer_id: str, sign_count: int) -> None: ...

    def trust_generation(self) -> int: ...

    @property
    def store_id(self) -> str: ...
