"""WebAuthn approval verifier (spec 11.3): the challenge is the canonical approval message, user verification required.

Uses the maintained ``webauthn`` library for challenge/origin/RP ID/UV/signature checks; the sign-count rule (strictly
increasing once either counter is non-zero, constant zero allowed for synced passkeys) and the credential id binding are
re-enforced here. Every refusal is ``UNAUTHENTICATED`` with the static safe message; library text is never surfaced.
"""

from __future__ import annotations

from dataclasses import dataclass

from webauthn import verify_authentication_response
from webauthn.helpers import parse_authentication_credential_json

from superbrain.core._kernel_approval import ApprovalMessage, AssuranceLevel
from superbrain.core.errors import BrainError, ErrorCode

_MAX_RESPONSE_CHARS = 64 * 1024
_MAX_COSE_KEY_BYTES = 4096
_MAX_CREDENTIAL_ID_BYTES = 1024
_UINT32_MAX = 0xFFFFFFFF


def _unauthenticated() -> BrainError:
    return BrainError(ErrorCode.UNAUTHENTICATED, "unauthenticated")


def _invalid() -> BrainError:
    return BrainError(ErrorCode.INVALID_INPUT, "invalid input")


@dataclass(frozen=True)
class WebAuthnResult:
    """A verified passkey assertion: its assurance level and the sign count to persist."""

    assurance: AssuranceLevel
    new_sign_count: int


class WebAuthnApprovalVerifier:
    """Verifies ``navigator.credentials.get`` assertions against one RP ID and one exact origin."""

    def __init__(self, *, rp_id: str, origin: str) -> None:
        if not isinstance(rp_id, str) or not rp_id or not isinstance(origin, str) or not origin:
            raise _invalid()
        self._rp_id = rp_id
        self._origin = origin

    def verify(
        self,
        message: ApprovalMessage,
        *,
        response_json: str,
        credential_id: bytes,
        credential_public_key: bytes,
        stored_sign_count: int,
    ) -> WebAuthnResult:
        if not isinstance(message, ApprovalMessage):
            raise _invalid()
        if (
            not isinstance(response_json, str)
            or len(response_json) > _MAX_RESPONSE_CHARS
            or not isinstance(credential_id, bytes)
            or not credential_id
            or len(credential_id) > _MAX_CREDENTIAL_ID_BYTES
            or not isinstance(credential_public_key, bytes)
            or not credential_public_key
            or len(credential_public_key) > _MAX_COSE_KEY_BYTES
            or type(stored_sign_count) is not int
            or not 0 <= stored_sign_count <= _UINT32_MAX
        ):
            raise _invalid()
        try:
            credential = parse_authentication_credential_json(response_json)
            if credential.raw_id != credential_id:
                raise _unauthenticated()
            verified = verify_authentication_response(
                credential=credential,
                expected_challenge=message.canonical_bytes(),
                expected_rp_id=self._rp_id,
                expected_origin=self._origin,
                credential_public_key=credential_public_key,
                credential_current_sign_count=stored_sign_count,
                require_user_verification=True,
            )
            new_count = verified.new_sign_count
            if verified.credential_id != credential_id or type(new_count) is not int:
                raise _unauthenticated()
            if (new_count > 0 or stored_sign_count > 0) and new_count <= stored_sign_count:
                raise _unauthenticated()
        except BrainError:
            raise
        except Exception as err:
            raise _unauthenticated() from err
        return WebAuthnResult(assurance=AssuranceLevel.HUMAN_VERIFIED, new_sign_count=new_count)


__all__ = ["WebAuthnApprovalVerifier", "WebAuthnResult"]
