"""Formatting and offline proof verification helpers for ``application.maintenance``."""

from __future__ import annotations

import base64
import binascii
from collections.abc import Callable, Mapping

from superbrain.core._kernel_approval import (
    ApprovalChannel,
    ApprovalMessage,
    IssuedNonce,
    SignerRecord,
    assurance_for,
    canonical_utc,
)
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.ports.approval import SshApprovalVerifierPort, WebAuthnApprovalVerifierPort
from superbrain.ports.maintenance import PolicyRestoreAuthorityDiff


def diff_to_json(diff: PolicyRestoreAuthorityDiff) -> dict[str, JsonValue]:
    """Serialize a ``PolicyRestoreAuthorityDiff`` to JSON."""
    return {
        "backup_trust_generation": diff.backup_trust_generation,
        "next_trust_generation": diff.next_trust_generation,
        "revived_signers": [s.signer_id for s in diff.revived_signers],
        "revived_credential_ids": list(diff.revived_credential_ids),
        "removed_quarantines": list(diff.removed_quarantines),
        "removed_tombstones": [[k, h] for k, h in diff.removed_tombstones],
        "affected_periods": list(diff.affected_periods),
    }


def challenge_from_issued(store_id: str, issued: IssuedNonce) -> dict[str, JsonValue]:
    """Serialize an ``IssuedNonce`` approval challenge payload."""
    return {
        "store_id": store_id,
        "action": issued.action.value,
        "subject_id": issued.subject_id,
        "risk_level": issued.risk_level.value,
        "trust_generation": issued.trust_generation,
        "nonce": issued.nonce,
        "expires_at": canonical_utc(issued.expires_at),
    }


def parse_offline_approval(
    raw: Mapping[str, JsonValue],
) -> tuple[ApprovalMessage, ApprovalChannel, str]:
    """Parse and envelope-validate an offline restore approval JSON payload."""
    if not isinstance(raw, Mapping) or not isinstance(raw.get("message"), Mapping):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid approval payload")
    raw_ch = raw.get("channel")
    if not isinstance(raw_ch, str):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid channel")
    try:
        channel = ApprovalChannel(raw_ch)
    except ValueError as err:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid channel") from err
    if channel is ApprovalChannel.TERMINAL:
        raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "terminal channel unavailable for high-risk restore")
    expected_keys = (
        {"message", "channel", "signer_id", "response_json"}
        if channel is ApprovalChannel.PASSKEY_UV
        else {"message", "channel", "signer_id", "signature"}
    )
    if set(raw) != expected_keys:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid approval envelope")
    msg_map = raw["message"]
    assert isinstance(msg_map, Mapping)
    message = ApprovalMessage.from_dict(msg_map)
    signer_id = raw.get("signer_id")
    if not isinstance(signer_id, str) or not signer_id:
        raise BrainError(ErrorCode.UNAUTHENTICATED, "missing signer_id")
    return message, channel, signer_id


def verify_ssh_proof(
    message: ApprovalMessage,
    raw: Mapping[str, JsonValue],
    signer: SignerRecord,
    channel: ApprovalChannel,
    ssh_verifier: Callable[[], SshApprovalVerifierPort | None] | None,
) -> None:
    """Verify an SSH signature over ``message`` against ``signer.public_key``."""
    if ssh_verifier is None:
        raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "ssh verifier unavailable")
    verifier = ssh_verifier()
    if verifier is None:
        raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "ssh-keygen unavailable")
    sig_b64 = raw.get("signature")
    if not isinstance(sig_b64, str) or not sig_b64:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid ssh signature")
    try:
        sig_bytes = base64.b64decode(sig_b64, validate=True)
    except (binascii.Error, ValueError) as err:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid base64 signature") from err
    assurance = verifier.verify(message, channel=channel, public_key=signer.public_key, signature=sig_bytes)
    if assurance is not assurance_for(channel):
        raise BrainError(ErrorCode.UNAUTHENTICATED, "signature verification failed")


def verify_backup_signer_record_dr(
    signer: SignerRecord | None,
    message: ApprovalMessage,
    channel: ApprovalChannel,
    raw: Mapping[str, JsonValue],
    ssh_verifier: Callable[[], SshApprovalVerifierPort | None] | None,
    webauthn_verifier: WebAuthnApprovalVerifierPort | None,
) -> None:
    """Verify an offline disaster-recovery approval against a backup signer record."""
    _ = webauthn_verifier
    if channel is ApprovalChannel.PASSKEY_UV:
        raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "passkey verifier unavailable offline")
    if signer is None or signer.revoked or signer.channel is not channel or signer.owner_id != message.owner_id:
        raise BrainError(ErrorCode.UNAUTHENTICATED, "signer not active in verified policy backup")
    verify_ssh_proof(message, raw, signer, channel, ssh_verifier)
