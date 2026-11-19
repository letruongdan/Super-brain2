"""Operator service behind ``/v2/operator/*`` (``user:cli`` only, spec 11.3): signer list/enroll/revoke.

Supports both a single-call ``handle(...)`` for direct tests and a three-phase execution model
(``prepare_call`` on the owner thread -> ``verify_pending`` off the owner thread -> ``commit_call`` on the owner
thread) so ``ssh-keygen`` subprocess verification never blocks ``OwnerLoop``.
"""

from __future__ import annotations

import base64
import binascii
import inspect
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from superbrain.core._kernel_approval import (
    CLI_HARNESS_ID,
    ApprovalAction,
    ApprovalChannel,
    ApprovalMessage,
    RiskLevel,
    SignerEnrollment,
    SignerRecord,
    assurance_for,
    canonical_utc,
    strict_b64url_decode,
)
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import Principal
from superbrain.ports.approval import ApprovalPolicyPort, SshApprovalVerifierPort, WebAuthnApprovalVerifierPort

__all__ = ["OperatorHandle", "OperatorService", "PendingApprovalCall", "PreparedOperatorCall"]

_DEFERRED_PATHS = frozenset(
    {
        "/v2/operator/credential/revoke",
        "/v2/operator/policy/set",
        "/v2/operator/workspace/link",
        "/v2/operator/backup",
        "/v2/operator/job/cancel",
    }
)
_ENROLLMENT_FIELDS = frozenset({"channel", "public_key", "credential_id"})
_TERMINAL_APPROVAL_KEYS = frozenset({"message", "channel"})
_PASSKEY_APPROVAL_KEYS = frozenset({"message", "channel", "signer_id", "response_json"})
_SSH_APPROVAL_KEYS = frozenset({"message", "channel", "signer_id", "signature"})


def _invalid() -> BrainError:
    return BrainError(ErrorCode.INVALID_INPUT, "invalid input")


def _unauthenticated() -> BrainError:
    return BrainError(ErrorCode.UNAUTHENTICATED, "unauthenticated")


def _b64(value: object, *, urlsafe: bool) -> bytes:
    if urlsafe:
        return strict_b64url_decode(value)
    if not isinstance(value, str) or not value:
        raise _invalid()
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as err:
        raise _invalid() from err


def _signer_json(record: SignerRecord) -> dict[str, JsonValue]:
    return {
        "signer_id": record.signer_id,
        "channel": record.channel.value,
        "key_digest": record.key_digest,
        "tofu": record.tofu,
    }


@dataclass(frozen=True)
class PendingApprovalCall:
    """Validated approval-gated operator mutation awaiting off-owner-thread crypto verification."""

    path: str
    principal: Principal
    token: str | None
    enrollment: SignerEnrollment | None
    revoke_signer_id: str | None
    message: ApprovalMessage
    channel: ApprovalChannel
    signer: SignerRecord | None
    raw_approval: Mapping[str, JsonValue]


@dataclass(frozen=True)
class PreparedOperatorCall:
    immediate: dict[str, JsonValue] | None = None
    pending: PendingApprovalCall | None = None


class OperatorService:
    """Handles the admitted ``user:cli`` operator calls against the live policy store."""

    def __init__(
        self,
        policy: ApprovalPolicyPort,
        *,
        ssh_verifier: Callable[[], SshApprovalVerifierPort | None],
        webauthn_verifier: WebAuthnApprovalVerifierPort | None = None,
    ) -> None:
        self._policy = policy
        self._ssh_verifier = ssh_verifier
        self._webauthn = webauthn_verifier

    def handle(
        self,
        path: str,
        principal: Principal,
        body: Mapping[str, JsonValue],
        *,
        token: str | None = None,
    ) -> dict[str, JsonValue]:
        prepared = self.prepare_call(path, principal, body, token=token)
        if prepared.immediate is not None:
            return prepared.immediate
        assert prepared.pending is not None
        new_sign_count = self.verify_pending(prepared.pending)
        return self.commit_call(prepared.pending, new_sign_count=new_sign_count)

    def prepare_call(
        self,
        path: str,
        principal: Principal,
        body: Mapping[str, JsonValue],
        *,
        token: str | None = None,
    ) -> PreparedOperatorCall:
        """Phase 1 (owner thread): verify live caller credential and either answer immediately or prepare crypto."""
        self._verify_caller(principal, token)
        if path == "/v2/operator/signer/list":
            if body:
                raise _invalid()
            return PreparedOperatorCall(immediate={"signers": [_signer_json(r) for r in self._policy.active_signers()]})
        if path == "/v2/operator/signer/enroll":
            return self._prepare_enroll(principal, token, body)
        if path == "/v2/operator/signer/revoke":
            return self._prepare_revoke(principal, token, body)
        if path in _DEFERRED_PATHS:
            raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")
        raise BrainError(ErrorCode.NOT_FOUND, "not found")

    def verify_pending(self, pending: PendingApprovalCall, *, timeout_s: float | None = None) -> int | None:
        """Phase 2 (off owner thread): verify proof; return new ``sign_count`` if passkey."""
        if pending.channel is ApprovalChannel.TERMINAL:
            return None
        signer = pending.signer
        if signer is None:
            raise _unauthenticated()
        if pending.channel is ApprovalChannel.PASSKEY_UV:
            return self._verify_passkey(pending.message, pending.raw_approval, signer)
        verifier = self._ssh_verifier()
        if verifier is None:
            raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")
        signature = _b64(pending.raw_approval.get("signature"), urlsafe=False)
        sig = inspect.signature(verifier.verify)
        accepts_timeout = timeout_s is not None and (
            "timeout_s" in sig.parameters
            or any(p.kind is inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())
        )
        if accepts_timeout:
            assurance = verifier.verify(
                pending.message,
                channel=pending.channel,
                public_key=signer.public_key,
                signature=signature,
                timeout_s=timeout_s,  # type: ignore[call-arg]
            )
        else:
            assurance = verifier.verify(
                pending.message,
                channel=pending.channel,
                public_key=signer.public_key,
                signature=signature,
            )
        if assurance is not assurance_for(pending.channel):
            raise _unauthenticated()
        return None

    def commit_call(self, pending: PendingApprovalCall, *, new_sign_count: int | None) -> dict[str, JsonValue]:
        """Phase 3 (owner thread): re-verify live caller credential and commit mutation + ``sign_count`` atomically."""
        self._verify_caller(pending.principal, pending.token)
        signer_id = pending.signer.signer_id if pending.signer is not None else None
        if pending.enrollment is not None:
            record = self._policy.enroll_signer(
                pending.enrollment,
                approval=pending.message,
                approver_signer_id=signer_id,
                channel=pending.channel,
                new_sign_count=new_sign_count,
            )
            return {"signer": _signer_json(record)}
        assert pending.revoke_signer_id is not None
        record = self._policy.revoke_signer(
            pending.revoke_signer_id,
            approval=pending.message,
            approver_signer_id=signer_id,
            channel=pending.channel,
            new_sign_count=new_sign_count,
        )
        return {"signer": _signer_json(record)}

    # --- internals -----------------------------------------------------------------------------------------------

    def _verify_caller(self, principal: Principal, token: str | None) -> None:
        if principal.harness_id != CLI_HARNESS_ID:
            raise BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch")
        if token is not None:
            resolved = self._policy.resolve_credential(token)
            if resolved != principal or resolved.harness_id != CLI_HARNESS_ID:
                raise BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch")

    def _prepare_enroll(
        self, principal: Principal, token: str | None, body: Mapping[str, JsonValue]
    ) -> PreparedOperatorCall:
        if not set(body) <= {"enrollment", "approval"} or "enrollment" not in body:
            raise _invalid()
        raw = body["enrollment"]
        if (
            not isinstance(raw, Mapping)
            or not set(raw) <= _ENROLLMENT_FIELDS
            or not {"channel", "public_key"} <= set(raw)
        ):
            raise _invalid()
        channel, key, credential = raw["channel"], raw["public_key"], raw.get("credential_id")
        if (
            not isinstance(channel, str)
            or not isinstance(key, str)
            or not (credential is None or isinstance(credential, str))
        ):
            raise _invalid()
        try:
            parsed = ApprovalChannel(channel)
        except ValueError as err:
            raise _invalid() from err
        enrollment = SignerEnrollment(
            owner_id=principal.owner_id, channel=parsed, public_key=key, credential_id=credential
        )
        if "approval" not in body:
            return PreparedOperatorCall(immediate=self._challenge(ApprovalAction.SIGNER_ENROLL, enrollment.subject_id))
        message, channel_used, signer, raw_approval = self._parse_approval(principal, body["approval"])
        return PreparedOperatorCall(
            pending=PendingApprovalCall(
                path="/v2/operator/signer/enroll",
                principal=principal,
                token=token,
                enrollment=enrollment,
                revoke_signer_id=None,
                message=message,
                channel=channel_used,
                signer=signer,
                raw_approval=raw_approval,
            )
        )

    def _prepare_revoke(
        self, principal: Principal, token: str | None, body: Mapping[str, JsonValue]
    ) -> PreparedOperatorCall:
        if not set(body) <= {"signer_id", "approval"} or not isinstance(body.get("signer_id"), str):
            raise _invalid()
        target = str(body["signer_id"])
        if "approval" not in body:
            return PreparedOperatorCall(immediate=self._challenge(ApprovalAction.SIGNER_REVOKE, target))
        message, channel_used, signer, raw_approval = self._parse_approval(principal, body["approval"])
        return PreparedOperatorCall(
            pending=PendingApprovalCall(
                path="/v2/operator/signer/revoke",
                principal=principal,
                token=token,
                enrollment=None,
                revoke_signer_id=target,
                message=message,
                channel=channel_used,
                signer=signer,
                raw_approval=raw_approval,
            )
        )

    def _challenge(self, action: ApprovalAction, subject_id: str) -> dict[str, JsonValue]:
        issued = self._policy.issue_nonce(action=action, subject_id=subject_id, risk_level=RiskLevel.HIGH)
        return {
            "challenge": {
                "store_id": self._policy.store_id,
                "action": issued.action.value,
                "subject_id": issued.subject_id,
                "risk_level": issued.risk_level.value,
                "trust_generation": issued.trust_generation,
                "nonce": issued.nonce,
                "expires_at": canonical_utc(issued.expires_at),
            }
        }

    def _parse_approval(
        self, principal: Principal, raw: JsonValue
    ) -> tuple[ApprovalMessage, ApprovalChannel, SignerRecord | None, Mapping[str, JsonValue]]:
        if not isinstance(raw, Mapping) or not isinstance(raw.get("message"), Mapping):
            raise _invalid()
        raw_channel = raw.get("channel")
        if not isinstance(raw_channel, str):
            raise _invalid()
        try:
            channel = ApprovalChannel(raw_channel)
        except ValueError as err:
            raise _invalid() from err
        expected_keys = (
            _TERMINAL_APPROVAL_KEYS
            if channel is ApprovalChannel.TERMINAL
            else _PASSKEY_APPROVAL_KEYS
            if channel is ApprovalChannel.PASSKEY_UV
            else _SSH_APPROVAL_KEYS
        )
        if set(raw) != expected_keys:
            raise _invalid()
        message_raw = raw["message"]
        assert isinstance(message_raw, Mapping)
        message = ApprovalMessage.from_dict(message_raw)
        if message.owner_id != principal.owner_id:
            raise BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch")
        if channel is ApprovalChannel.TERMINAL:
            return message, channel, None, raw
        signer_id = raw.get("signer_id")
        if not isinstance(signer_id, str):
            raise _unauthenticated()
        signer = self._policy.signer(signer_id)
        if signer is None or signer.revoked or signer.channel is not channel or signer.owner_id != message.owner_id:
            raise _unauthenticated()
        return message, channel, signer, raw

    def _verify_passkey(self, message: ApprovalMessage, raw: Mapping[str, JsonValue], signer: SignerRecord) -> int:
        if self._webauthn is None:
            raise BrainError(ErrorCode.CAPABILITY_UNAVAILABLE, "capability unavailable")
        response = raw.get("response_json")
        if not isinstance(response, str) or signer.credential_id is None:
            raise _invalid()
        result = self._webauthn.verify(
            message,
            response_json=response,
            credential_id=_b64(signer.credential_id, urlsafe=True),
            credential_public_key=_b64(signer.public_key, urlsafe=True),
            stored_sign_count=signer.sign_count,
        )
        if result.assurance is not assurance_for(ApprovalChannel.PASSKEY_UV):
            raise _unauthenticated()
        return result.new_sign_count


class OperatorHandle:
    """Late-bound slot the owner session fills with its live ``OperatorService`` (owner-thread use only)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._service: OperatorService | None = None

    def bind(self, service: OperatorService) -> None:
        with self._lock:
            self._service = service

    def unbind(self) -> None:
        with self._lock:
            self._service = None

    def service(self) -> OperatorService | None:
        with self._lock:
            return self._service
