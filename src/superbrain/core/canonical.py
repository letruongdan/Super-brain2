"""Exact bytes digests and deterministic canonical manifest identities.

Extracted from f83271d:src/ensemble_brain/core/revisions.py (blob d80d7f5).
"""

import hashlib
import json
import math
from collections.abc import Mapping

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue


def _validate_utf8_text(text: str) -> None:
    if not text.isascii():
        text.encode("utf-8")


def validate_json(value: object, *, reject_floats: bool = False) -> None:
    """Require JSON values without Python's implicit tuple/key conversions."""

    def visit(item: object) -> None:
        if item is None or isinstance(item, (bool, int)):
            return
        if isinstance(item, str):
            _validate_utf8_text(item)
        elif isinstance(item, float):
            if reject_floats or not math.isfinite(item):
                raise ValueError("invalid numeric quantity")
        elif isinstance(item, list):
            for child in item:
                visit(child)
        elif isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise ValueError("JSON object keys must be strings")
                _validate_utf8_text(key)
                visit(child)
        else:
            raise ValueError("non-JSON value")

    try:
        visit(value)
    except (ValueError, RecursionError) as error:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid JSON value or manifest numeric quantity") from error


def canonical_json(value: object) -> bytes:
    """Encode JSON values as deterministic UTF-8 canonical JSON bytes."""
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def digest_bytes(data: bytes) -> str:
    if not isinstance(data, bytes):
        raise BrainError(ErrorCode.INVALID_INPUT, "resource data must be exact bytes")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def canonical_digest(kind: str, manifest: Mapping[str, JsonValue]) -> str:
    if not isinstance(kind, str) or not isinstance(manifest, dict):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid kind or manifest")
    payload = {"kind": kind, "manifest": manifest}
    validate_json(payload, reject_floats=True)
    return digest_bytes(canonical_json(payload))
