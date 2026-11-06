"""Test-only bootstrap and credential/principal seeding helpers for Increment 2 kernel storage tests.

Production code has no unauthenticated or default credential bootstrap; tests explicitly seed
principals, credentials, and bootstrap authorization proofs on isolated test roots.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from superbrain.core.canonical import digest_bytes
from superbrain.core.ids import new_id
from superbrain.storage.ledger import utc_timestamp

if TYPE_CHECKING:
    from superbrain.core.kernel import BootstrapAuthorization, Principal
    from superbrain.storage.policy_store import PolicyStore


@dataclass(frozen=True)
class SeededCredential:
    principal: Principal
    credential_id: str
    token: str
    secret_digest: str
    raw_secret_b64: str


def generate_bearer_token(
    *,
    credential_id: str | None = None,
    secret_bytes: bytes | None = None,
) -> tuple[str, str, str, str]:
    """Return ``(credential_id, token, secret_digest, raw_secret_b64)`` for a 32-byte random secret."""
    cred_id = credential_id if credential_id is not None else new_id()
    raw = secret_bytes if secret_bytes is not None else os.urandom(32)
    assert len(raw) == 32
    b64 = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    token = f"{cred_id}.{b64}"
    return cred_id, token, digest_bytes(raw), b64


def seed_principal_and_credential(
    policy: PolicyStore,
    *,
    owner_id: str = "dan",
    harness_id: str = "claude-code",
    machine_id: str = "devbox-1",
    principal_id: str | None = None,
    credential_id: str | None = None,
) -> SeededCredential:
    """Insert a principal (if absent) and a new active bearer credential in ``policy`` (test-only)."""
    from superbrain.core.kernel import Principal

    created_at = utc_timestamp(policy._os.clock.now())
    with policy._immediate() as db:
        existing = db.execute(
            "SELECT id FROM principal WHERE owner_id = ? AND harness_id = ? AND machine_id = ?",
            (owner_id, harness_id, machine_id),
        ).fetchone()
        if existing is not None:
            resolved_principal_id = str(existing[0])
        else:
            resolved_principal_id = principal_id if principal_id is not None else new_id()
            db.execute(
                "INSERT INTO principal (id, owner_id, harness_id, machine_id, created_at) VALUES (?, ?, ?, ?, ?)",
                (resolved_principal_id, owner_id, harness_id, machine_id, created_at),
            )
        cred_id, token, secret_digest, raw_b64 = generate_bearer_token(credential_id=credential_id)
        db.execute(
            "INSERT INTO credential (id, principal_id, secret_digest, created_at, revoked_intent_id) "
            "VALUES (?, ?, ?, ?, NULL)",
            (cred_id, resolved_principal_id, secret_digest, created_at),
        )
    principal = Principal(
        principal_id=resolved_principal_id,
        owner_id=owner_id,
        harness_id=harness_id,
        machine_id=machine_id,
    )
    return SeededCredential(
        principal=principal,
        credential_id=cred_id,
        token=token,
        secret_digest=secret_digest,
        raw_secret_b64=raw_b64,
    )


def seed_repo_grant(
    policy: PolicyStore,
    *,
    principal_id: str,
    repo_id: str,
    owner_id: str,
    provider_egress_enabled: bool = False,
    granted_intent_id: str | None = None,
) -> None:
    """Insert ``repo_policy`` and ``repo_grant`` rows directly for test setup."""
    now = utc_timestamp(policy._os.clock.now())
    grant_intent = granted_intent_id if granted_intent_id is not None else new_id()
    with policy._immediate() as db:
        db.execute(
            "INSERT OR IGNORE INTO repo_policy (repo_id, owner_id, provider_egress_enabled, updated_at) "
            "VALUES (?, ?, ?, ?)",
            (repo_id, owner_id, 1 if provider_egress_enabled else 0, now),
        )
        db.execute(
            "INSERT OR IGNORE INTO repo_grant (principal_id, repo_id, granted_intent_id, created_at) "
            "VALUES (?, ?, ?, ?)",
            (principal_id, repo_id, grant_intent, now),
        )


def make_bootstrap_auth(
    *,
    store_id: str,
    owner_id: str = "dan",
    action: str,
    subject_id: str,
    trust_generation: int = 1,
    expires_at: datetime,
    intent_id: str | None = None,
    issuer_id: str = "owner:local-bootstrap",
    destination: Path | None = None,
) -> BootstrapAuthorization:
    """Build an isolated owner/bootstrap authorization proof for Task 2 tests."""
    from superbrain.core.kernel import BootstrapAuthorization

    return BootstrapAuthorization(
        intent_id=intent_id if intent_id is not None else new_id(),
        store_id=store_id,
        owner_id=owner_id,
        action=action,
        subject_id=subject_id,
        trust_generation=trust_generation,
        expires_at=expires_at,
        issuer_id=issuer_id,
        destination=destination,
    )
