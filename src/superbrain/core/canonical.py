"""Exact bytes digests and deterministic canonical manifest identities.

Extracted from f83271d:src/ensemble_brain/core/revisions.py (blob d80d7f5).
"""

import hashlib
import json
import math
from collections.abc import Mapping
from typing import cast

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue


def _is_ascii_json(value: object) -> bool:
    stack: list[object] = [value]
    while stack:
        item = stack.pop()
        tp = type(item)
        if tp is str:
            if not cast(str, item).isascii():
                return False
        elif tp is dict:
            for key, child in cast(dict[object, object], item).items():
                if not isinstance(key, str) or not key.isascii():
                    return False
                stack.append(child)
        elif tp is list:
            stack.extend(cast(list[object], item))
        elif item is None or tp is bool or tp is int or tp is float:
            continue
        else:
            return False
    return True


def validate_json(value: object, *, reject_floats: bool = False) -> None:
    """Require JSON values without Python's implicit tuple/key conversions."""

    def visit(item: object) -> None:
        tp = type(item)
        if item is None or tp is bool or tp is int:
            return
        if tp is str:
            text = cast(str, item)
            if not text.isascii():
                text.encode("utf-8")
        elif tp is float:
            if reject_floats or not math.isfinite(cast(float, item)):
                raise ValueError("invalid numeric quantity")
        elif tp is list:
            for child in cast(list[object], item):
                visit(child)
        elif tp is dict:
            for key, child in cast(dict[object, object], item).items():
                if not isinstance(key, str):
                    raise ValueError("JSON object keys must be strings")
                if not key.isascii():
                    key.encode("utf-8")
                visit(child)
        elif isinstance(item, (bool, int)):
            return
        elif isinstance(item, str):
            if not item.isascii():
                item.encode("utf-8")
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
                if not key.isascii():
                    key.encode("utf-8")
                visit(child)
        else:
            raise ValueError("non-JSON value")

    try:
        visit(value)
    except (ValueError, RecursionError) as error:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid JSON value or manifest numeric quantity") from error


def canonical_json(value: object) -> bytes:
    if _is_ascii_json(value):
        return json.dumps(
            value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("ascii")
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
