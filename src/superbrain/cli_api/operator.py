"""``/v2/operator/*`` admission: ``user:cli`` bearers only (spec 11.3, plan I3-1).

The bearer is resolved against the published ``AuthGate`` snapshot *before* the request body is read or parsed: an
unknown or revoked token is ``UNAUTHENTICATED`` and any other principal (every harness) is ``IDENTITY_MISMATCH``,
with no body parsing and no write.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from superbrain.application.owner_loop import AuthGate
from superbrain.core._kernel_approval import CLI_HARNESS_ID
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import CallResult, Principal
from superbrain.core.wire import parse_json

__all__ = [
    "OPERATOR_PATHS",
    "OperatorExecutor",
    "OperatorRequest",
    "admit_operator_principal",
    "parse_operator_body",
]

OPERATOR_PATHS: frozenset[str] = frozenset(
    {
        "/v2/operator/signer/list",
        "/v2/operator/signer/enroll",
        "/v2/operator/signer/revoke",
        "/v2/operator/proposal/list",
        "/v2/operator/proposal/show",
        "/v2/operator/proposal/approve",
        "/v2/operator/proposal/reject",
        "/v2/operator/proposal/apply",
        "/v2/operator/proposal/rollback",
        "/v2/operator/proposal/continue",
        "/v2/operator/proposal/bootstrap",
        "/v2/operator/credential/revoke",
        "/v2/operator/policy/set",
        "/v2/operator/workspace/link",
        "/v2/operator/backup",
        "/v2/operator/restore",
        "/v2/operator/job/cancel",
    }
)


@dataclass(frozen=True)
class OperatorRequest:
    path: str
    principal: Principal
    body: dict[str, JsonValue]
    token: str | None = field(default=None, repr=False, compare=False)


OperatorExecutor = Callable[[OperatorRequest, int], CallResult]
"""Runs an admitted operator request on the owner thread and returns its response envelope."""


def admit_operator_principal(token: str, auth_gate: AuthGate) -> Principal:
    """The ``user:cli`` principal of ``token``; ``UNAUTHENTICATED`` if unknown, ``IDENTITY_MISMATCH`` if a harness."""
    view = auth_gate.current()
    if view is None:
        raise BrainError(ErrorCode.POLICY_UNAVAILABLE, "policy unavailable")
    principal = view.auth.resolve_credential(token)
    if principal.harness_id != CLI_HARNESS_ID:
        raise BrainError(ErrorCode.IDENTITY_MISMATCH, "identity mismatch")
    return principal


def parse_operator_body(raw: bytes) -> dict[str, JsonValue]:
    """The request body as a JSON object (strict parser); anything else is ``INVALID_INPUT``."""
    parsed = parse_json(raw)
    if not isinstance(parsed, Mapping):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    return dict(parsed)
