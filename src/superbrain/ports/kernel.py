"""Kernel policy authority port shared across storage and application layers."""

from __future__ import annotations

from typing import Protocol

from superbrain.core.kernel import (
    AuthSnapshot,
    BootstrapAuthorization,
    Principal,
    Scope,
    WorkspaceBinding,
    WorkspaceRegistration,
)
from superbrain.ports.policy import Intent


class KernelPolicyPort(Protocol):
    """Read/write authority interface over the policy database (``policy/policy.db``)."""

    def resolve_credential(self, token: str) -> Principal:
        """Resolve ``<credential_uuidv7>.<base64url>`` to an active ``Principal``."""
        ...

    def allows(self, principal: Principal, scope: Scope | None, *, action: str) -> bool:
        """Return True iff ``principal`` is active and authorized for ``scope`` and ``action``."""
        ...

    def snapshot(self) -> AuthSnapshot:
        """Return an immutable point-in-time snapshot of principals, credentials, grants, and checkouts."""
        ...

    def record_authorized_revocation(
        self, credential_id: str, authorization: BootstrapAuthorization
    ) -> Intent:
        """Commit an authorized ``credential_revoke`` intent and mark ``credential_id`` revoked."""
        ...

    def register_authorized_workspace(
        self, registration: WorkspaceRegistration, authorization: BootstrapAuthorization
    ) -> WorkspaceBinding:
        """Commit an authorized workspace registration, repo grant, and ``workspace_register`` intent."""
        ...

    def request_digest_key(self) -> tuple[str, bytes]:
        """Return the active ``(key_id, key_bytes)`` 32-byte per-store HMAC secret."""
        ...
