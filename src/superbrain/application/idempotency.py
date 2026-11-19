"""Task 4a request HMAC, stable lookup key_hash, tool idempotency classification, and 30-day TTL helpers."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable, Mapping
from datetime import datetime

from superbrain.core.canonical import canonical_json, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import (
    IDEMPOTENCY_KEY_RE,
    IDEMPOTENCY_TTL,
    ArtifactSendAttempt,
    Call,
    ResourceDigest,
    canonicalize_resource_digests,
    parse_canonical_utc,
    require_aware_utc,
    require_opaque_id,
    require_sha256_digest,
)
from superbrain.core.wire import canonical_request_payload

_ALWAYS_IDEMPOTENT_TOOLS: frozenset[str] = frozenset(
    {
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


def _verify_legacy_read_ack_hmac(
    key_bytes: bytes,
    call: Call,
    expected_digest: str,
    *,
    principal_id: str | None,
    resolve_send_attempt: Callable[[str], ArtifactSendAttempt | None] | None,
) -> bool:
    if call.tool not in {"submit_episode", "record_outcome"}:
        return False
    raw_acks = call.arguments.get("read_acks")
    if not isinstance(raw_acks, list) or not raw_acks:
        return False
    if principal_id is None or resolve_send_attempt is None:
        return False
    legacy_acks: list[dict[str, object]] = []
    for raw_ack in raw_acks:
        if not isinstance(raw_ack, dict) or "artifact_id" not in raw_ack or "revision_epoch" not in raw_ack:
            return False
        legacy_acks.append({k: v for k, v in raw_ack.items() if k not in {"artifact_id", "revision_epoch"}})
    legacy_payload = canonical_json(
        {
            "tool": call.tool,
            "selected_scope": call.selected_scope.to_dict() if call.selected_scope is not None else None,
            "arguments": {**call.arguments, "read_acks": legacy_acks},
        }
    )
    legacy_actual = compute_canonical_payload_hmac(key_bytes, legacy_payload)
    if not hmac.compare_digest(legacy_actual.encode("ascii"), expected_digest.encode("ascii")):
        return False
    parsed_acks: list[tuple[str, str, str, int, int, tuple[ResourceDigest, ...]]] = []
    for raw_ack in raw_acks:
        assert isinstance(raw_ack, dict)
        receipt_id = raw_ack.get("served_receipt_id")
        task_id = raw_ack.get("task_id")
        artifact_id = raw_ack.get("artifact_id")
        rev_epoch = raw_ack.get("revision_epoch")
        rev = raw_ack.get("revision")
        raw_digests = raw_ack.get("resource_digests")
        if (
            not isinstance(receipt_id, str)
            or not isinstance(task_id, str)
            or not isinstance(artifact_id, str)
            or isinstance(rev_epoch, bool)
            or not isinstance(rev_epoch, int)
            or rev_epoch < 0
            or isinstance(rev, bool)
            or not isinstance(rev, int)
            or rev < 1
            or not isinstance(raw_digests, list)
            or not raw_digests
        ):
            return False
        try:
            require_opaque_id(receipt_id, label="served_receipt_id")
            require_opaque_id(task_id, label="task_id")
            require_opaque_id(artifact_id, label="artifact_id")
            typed_digests: list[ResourceDigest] = []
            for entry in raw_digests:
                if not isinstance(entry, Mapping):
                    return False
                typed_digests.append(ResourceDigest.from_dict(entry))
            ordered_digests, _ = canonicalize_resource_digests(tuple(typed_digests))
        except BrainError as err:
            if err.code is ErrorCode.INVALID_INPUT:
                return False
            raise
        parsed_acks.append((receipt_id, task_id, artifact_id, rev_epoch, rev, ordered_digests))
    for receipt_id, task_id, artifact_id, rev_epoch, rev, ordered_digests in parsed_acks:
        # Store/policy lookup errors must propagate untouched instead of masquerading as payload conflicts.
        attempt = resolve_send_attempt(receipt_id)
        if attempt is None or (
            attempt.principal_id,
            attempt.task_id,
            attempt.artifact_id,
            attempt.revision_epoch,
            attempt.revision,
            attempt.resource_digests,
        ) != (
            principal_id,
            task_id,
            artifact_id,
            rev_epoch,
            rev,
            ordered_digests,
        ):
            return False
    return True


def verify_request_hmac(
    key_bytes: bytes,
    call: Call,
    expected_digest: str,
    canonical_payload: bytes | None = None,
    *,
    principal_id: str | None = None,
    resolve_send_attempt: Callable[[str], ArtifactSendAttempt | None] | None = None,
) -> bool:
    """Constant-time verification of ``call`` against stored ``expected_digest`` under ``key_bytes``."""
    require_sha256_digest(expected_digest)
    actual = compute_request_hmac(key_bytes, call, canonical_payload)
    if hmac.compare_digest(actual.encode("ascii"), expected_digest.encode("ascii")):
        return True
    # Preserve replay compatibility with pre-SP2-1 prepare_task(work) idempotency rows lacking defaulted "mode".
    if call.tool == "prepare_task" and call.arguments.get("mode") == "work":
        legacy_payload = canonical_json(
            {
                "tool": call.tool,
                "selected_scope": call.selected_scope.to_dict() if call.selected_scope is not None else None,
                "arguments": {k: v for k, v in call.arguments.items() if k != "mode"},
            }
        )
        legacy_actual = compute_canonical_payload_hmac(key_bytes, legacy_payload)
        return hmac.compare_digest(legacy_actual.encode("ascii"), expected_digest.encode("ascii"))
    return _verify_legacy_read_ack_hmac(
        key_bytes,
        call,
        expected_digest,
        principal_id=principal_id,
        resolve_send_attempt=resolve_send_attempt,
    )


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
    if call.tool == "prepare_task":
        mode = call.arguments.get("mode", "work")
        if mode == "work":
            return True
        if mode == "discover":
            return False
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if call.tool == "get_health":
        deep = call.arguments.get("deep", False)
        if type(deep) is not bool:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        return deep
    raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
