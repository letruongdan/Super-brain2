"""Application session coordinator for local WebAuthn proposal review (spec 11.2, 11.3, Case 31)."""

from __future__ import annotations

import base64
import hmac
import json
import secrets
import threading
from collections.abc import Mapping
from typing import Protocol

from superbrain.core._kernel_approval import (
    ApprovalAction,
    ApprovalChannel,
    ApprovalMessage,
    RecoveryScope,
    SignerRecord,
    strict_b64url_decode,
)
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue

__all__ = ["ReviewOperatorBackendPort", "ReviewSession"]

_ALLOWED_ACTIONS = frozenset(
    {ApprovalAction.APPROVE, ApprovalAction.REJECT, ApprovalAction.APPLY, ApprovalAction.ROLLBACK}
)
_MAX_RESPONSE_CHARS = 64 * 1024


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _scope_for(action: ApprovalAction) -> RecoveryScope:
    if action is ApprovalAction.APPLY:
        return RecoveryScope.CONTINUE_OR_ROLLBACK
    if action is ApprovalAction.ROLLBACK:
        return RecoveryScope.ROLLBACK
    return RecoveryScope.NONE


class ReviewOperatorBackendPort(Protocol):
    """Backend port used by ``ReviewSession`` to query proposals/signers and submit WebAuthn approvals."""

    def list_signers(self) -> tuple[SignerRecord, ...]: ...

    def show_proposal(self, proposal_id: str) -> Mapping[str, JsonValue]: ...

    def request_challenge(
        self,
        *,
        proposal_id: str,
        action: ApprovalAction,
        recovery_scope: RecoveryScope,
    ) -> tuple[ApprovalMessage, Mapping[str, JsonValue]]: ...

    def submit_approval(
        self,
        *,
        proposal_id: str,
        action: ApprovalAction,
        raw_approval: Mapping[str, JsonValue],
    ) -> Mapping[str, JsonValue]: ...


class ReviewSession:
    """Single-proposal WebAuthn review session with one-time bootstrap token, CSRF secret, and origin binding."""

    def __init__(
        self,
        *,
        backend: ReviewOperatorBackendPort,
        proposal_id: str,
        rp_id: str = "localhost",
        expected_origin: str,
        default_action: ApprovalAction = ApprovalAction.APPROVE,
    ) -> None:
        if not isinstance(proposal_id, str) or not proposal_id or "\x00" in proposal_id:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid proposal_id")
        if not isinstance(rp_id, str) or not rp_id or "\x00" in rp_id:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid rp_id")
        if not isinstance(expected_origin, str) or not expected_origin:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid expected_origin")
        if default_action not in _ALLOWED_ACTIONS:
            raise BrainError(ErrorCode.INVALID_INPUT, "unsupported review action")
        self._backend = backend
        self._proposal_id = proposal_id
        self._rp_id = rp_id
        self._expected_origin = expected_origin
        self._default_action = default_action
        self._bootstrap_token = secrets.token_urlsafe(32)
        self._session_id = secrets.token_urlsafe(32)
        self._csrf_token = secrets.token_urlsafe(32)
        self._token_redeemed = False
        self._lock = threading.Lock()

    @property
    def bootstrap_token(self) -> str:
        return self._bootstrap_token

    @property
    def proposal_id(self) -> str:
        return self._proposal_id

    @property
    def rp_id(self) -> str:
        return self._rp_id

    @property
    def expected_origin(self) -> str:
        with self._lock:
            return self._expected_origin

    @property
    def default_action(self) -> ApprovalAction:
        return self._default_action

    def bind_origin(self, origin: str) -> None:
        """Bind the ephemeral localhost origin once the loopback HTTP server starts listening."""
        if not isinstance(origin, str) or not origin.startswith("http://localhost:"):
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid review_web origin")
        with self._lock:
            self._expected_origin = origin

    def redeem_bootstrap_token(self, token: str) -> tuple[str, str]:
        """Exchange the one-time bootstrap token for ``(session_id, csrf_token)`` in constant time."""
        with self._lock:
            if (
                self._token_redeemed
                or not isinstance(token, str)
                or not token
                or not hmac.compare_digest(token, self._bootstrap_token)
            ):
                raise BrainError(ErrorCode.UNAUTHENTICATED, "unauthenticated")
            self._token_redeemed = True
            return self._session_id, self._csrf_token

    def verify_session(self, session_id: str | None) -> bool:
        """Constant-time check that the HTTP session cookie matches the redeemed session."""
        with self._lock:
            if not self._token_redeemed or not isinstance(session_id, str) or not session_id:
                return False
            return hmac.compare_digest(session_id, self._session_id)

    def verify_csrf(self, token: str | None) -> bool:
        """Constant-time check for ``X-CSRF-Token`` on state-changing ``POST`` calls."""
        with self._lock:
            if not self._token_redeemed or not isinstance(token, str) or not token:
                return False
            return hmac.compare_digest(token, self._csrf_token)

    def ssr_summary(self) -> Mapping[str, JsonValue]:
        """Fetch non-mutating proposal metadata for SSR HTML escaping."""
        return self._backend.show_proposal(self._proposal_id)

    def render_state(self, action: ApprovalAction | None = None) -> dict[str, JsonValue]:
        """Fetch fresh challenge + subject summary derived from the canonical ``ApprovalMessage``."""
        resolved = self._default_action if action is None else action
        if resolved not in _ALLOWED_ACTIONS:
            raise BrainError(ErrorCode.INVALID_INPUT, "unsupported review action")
        msg, prop = self._backend.request_challenge(
            proposal_id=self._proposal_id,
            action=resolved,
            recovery_scope=_scope_for(resolved),
        )
        passkey_signers = [
            s
            for s in self._backend.list_signers()
            if s.channel is ApprovalChannel.PASSKEY_UV and not s.revoked and s.credential_id
        ]
        allow_creds: list[JsonValue] = [
            {"type": "public-key", "id": str(s.credential_id)} for s in passkey_signers
        ]
        subject_summary: dict[str, JsonValue] = {
            "subject_id": msg.subject_id,
            "subject_revision": msg.subject_revision,
            "action": msg.action.value,
            "risk_level": msg.risk_level.value,
            "recovery_scope": msg.recovery_scope.value,
            "target_files": [tf.to_dict() for tf in msg.target_files],
            "resource_digests": [rd.to_dict() for rd in msg.resource_digests],
            "kind": prop.get("kind"),
            "reason": prop.get("reason"),
            "status": prop.get("status"),
        }
        webauthn_options: dict[str, JsonValue] = {
            "challenge": _b64u(msg.canonical_bytes()),
            "rpId": self._rp_id,
            "timeout": 60000,
            "userVerification": "required",
            "allowCredentials": allow_creds,
        }
        return {
            "action": resolved.value,
            "subject_summary": subject_summary,
            "challenge": msg.to_dict(),
            "webauthn_options": webauthn_options,
            "signers": [
                {"signer_id": s.signer_id, "key_digest": s.key_digest}
                for s in passkey_signers
            ],
        }

    def submit_passkey(
        self,
        *,
        action: ApprovalAction,
        signer_id: str,
        challenge_message: Mapping[str, JsonValue],
        response_json: str,
    ) -> Mapping[str, JsonValue]:
        """Validate WebAuthn origin/challenge/Case-31 subject revision, then submit ``passkey_uv`` approval."""
        if action not in _ALLOWED_ACTIONS:
            raise BrainError(ErrorCode.INVALID_INPUT, "unsupported review action")
        if not isinstance(signer_id, str) or not signer_id:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid signer_id")
        if not isinstance(response_json, str) or not response_json or len(response_json) > _MAX_RESPONSE_CHARS:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid response_json")

        msg = ApprovalMessage.from_dict(challenge_message)
        if msg.subject_id != self._proposal_id or msg.action is not action:
            raise BrainError(ErrorCode.INVALID_INPUT, "challenge does not match target proposal/action")

        try:
            payload = json.loads(response_json)
            if not isinstance(payload, dict):
                raise BrainError(ErrorCode.UNAUTHENTICATED, "unauthenticated")
            resp = payload.get("response")
            if not isinstance(resp, dict):
                raise BrainError(ErrorCode.UNAUTHENTICATED, "unauthenticated")
            cdj_raw = resp.get("clientDataJSON")
            if not isinstance(cdj_raw, str):
                raise BrainError(ErrorCode.UNAUTHENTICATED, "unauthenticated")
            cdj = json.loads(strict_b64url_decode(cdj_raw).decode("utf-8"))
            if not isinstance(cdj, dict):
                raise BrainError(ErrorCode.UNAUTHENTICATED, "unauthenticated")
        except BrainError:
            raise
        except Exception as err:
            raise BrainError(ErrorCode.UNAUTHENTICATED, "unauthenticated") from err
        with self._lock:
            expected_origin = self._expected_origin
        if cdj.get("type") != "webauthn.get" or cdj.get("origin") != expected_origin:
            raise BrainError(ErrorCode.UNAUTHENTICATED, "unauthenticated")

        current_prop = self._backend.show_proposal(self._proposal_id)
        if current_prop.get("subject_revision") != msg.subject_revision:
            raise BrainError(ErrorCode.REVISION_CONFLICT, "revision conflict")

        raw_approval: dict[str, JsonValue] = {
            "message": dict(challenge_message),
            "channel": ApprovalChannel.PASSKEY_UV.value,
            "signer_id": signer_id,
            "response_json": response_json,
        }
        return self._backend.submit_approval(
            proposal_id=self._proposal_id,
            action=action,
            raw_approval=raw_approval,
        )
