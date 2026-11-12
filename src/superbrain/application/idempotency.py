"""Task 4a request HMAC, stable lookup key_hash, tool idempotency classification, and 30-day TTL helpers."""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime

from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import (
    IDEMPOTENCY_KEY_RE,
    IDEMPOTENCY_TTL,
    Call,
    parse_canonical_utc,
    require_aware_utc,
    require_opaque_id,
    require_sha256_digest,
)
from superbrain.core.wire import canonical_request_payload

_ALWAYS_IDEMPOTENT_TOOLS: frozenset[str] = frozenset(
    {
        "prepare_task",
        "get_artifact",
        "submit_episode",
        "record_outcome",
        "request_improvement",
    }
)
_READONLY_TOOLS: frozenset[str] = frozenset({"search_knowledge", "get_job"})


def compute_idempotency_key_hash(principal_id: str, tool: str, idempotency_key: str) -> str:
    """Compute stable unkeyed lookup digest ``sha256(b"idem-lookup-v1\\0" + canonical_json(...))``."""
    require_opaque_id(principal_id, label="principal_id")
    if not isinstance(tool, str) or not tool:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if not isinstance(idempotency_key, str) or IDEMPOTENCY_KEY_RE.fullmatch(idempotency_key) is None:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    payload = canonical_json(
        {
            "idempotency_key": idempotency_key,
            "principal_id": principal_id,
            "tool": tool,
        }
    )
    return digest_bytes(b"idem-lookup-v1\0" + payload)


def compute_canonical_payload_hmac(key_bytes: bytes, canonical_payload: bytes) -> str:
    """Compute ``HMAC-SHA256(key_bytes, b"request-v1\\0" + canonical_payload)`` over immutable bytes (C3:92)."""
    if type(key_bytes) is not bytes or len(key_bytes) != 32:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if type(canonical_payload) is not bytes or not canonical_payload:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    mac = hmac.new(key_bytes, b"request-v1\0", hashlib.sha256)
    mac.update(canonical_payload)
    return f"sha256:{mac.hexdigest()}"


def compute_request_hmac(key_bytes: bytes, call: Call, canonical_payload: bytes | None = None) -> str:
    """Compute ``HMAC-SHA256(key_bytes, b"request-v1\\0" + canonical_request_payload(call))``.

    ``canonical_payload`` is that same encoding when the caller already holds it verified (the owner path checks
    it against the reconstructed call); it is never re-derived then, so the 1 MiB body is not serialized again.
    """
    if not isinstance(call, Call):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    payload = canonical_payload if canonical_payload is not None else canonical_request_payload(call)
    return compute_canonical_payload_hmac(key_bytes, payload)


def verify_request_hmac(
    key_bytes: bytes, call: Call, expected_digest: str, canonical_payload: bytes | None = None
) -> bool:
    """Constant-time verification of ``call`` against stored ``expected_digest`` under ``key_bytes``."""
    require_sha256_digest(expected_digest)
    actual = compute_request_hmac(key_bytes, call, canonical_payload)
    return hmac.compare_digest(actual.encode("ascii"), expected_digest.encode("ascii"))


def is_idempotency_expired(committed_at: str | datetime, now: datetime) -> bool:
    """Fixed C4 oracle: ``now < committed_at + 30d`` is live; ``now >= committed_at + 30d`` is expired."""
    committed_utc = (
        parse_canonical_utc(committed_at) if isinstance(committed_at, str) else require_aware_utc(committed_at)[0]
    )
    now_utc, _ = require_aware_utc(now)
    return now_utc >= committed_utc + IDEMPOTENCY_TTL


def tool_uses_idempotency(call: Call) -> bool:
    """Return True iff ``call`` belongs to a mutation/conditional-mutation branch requiring idempotency (C1)."""
    if not isinstance(call, Call):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if call.tool in _ALWAYS_IDEMPOTENT_TOOLS:
        return True
    if call.tool in _READONLY_TOOLS:
        return False
    if call.tool == "get_health":
        deep = call.arguments.get("deep", False)
        if type(deep) is not bool:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        return deep
    raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
