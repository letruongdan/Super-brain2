"""Strict JSON wire parser and structural bounds shared by core kernel and wire codecs."""

from __future__ import annotations

import json
import math
from typing import cast

from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue

MAX_WIRE_BODY_BYTES = 1_048_576
MAX_WIRE_TEXT_BYTES = 65_536
MAX_WIRE_ARRAY_LEN = 1_024
MAX_WIRE_DEPTH = 32


def _encode_wire_str(value: str, *, max_bytes: int = MAX_WIRE_TEXT_BYTES) -> bytes:
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as err:
        raise BrainError(ErrorCode.INVALID_INPUT, "unpaired surrogate") from err
    if len(encoded) > max_bytes:
        raise BrainError(ErrorCode.INVALID_INPUT, "string exceeds size limit")
    return encoded


def _validate_wire_structure(root: object) -> None:
    """Iteratively verify depth <= 32, array length <= 1024, UTF-8 string caps, and finite numbers."""
    stack: list[tuple[object, int]] = [(root, 0)]
    while stack:
        item, depth = stack.pop()
        tp = type(item)
        if item is None or tp is bool or tp is int:
            continue
        if tp is str:
            text = cast(str, item)
            if text.isascii():
                if len(text) > MAX_WIRE_TEXT_BYTES:
                    raise BrainError(ErrorCode.INVALID_INPUT, "string exceeds size limit")
            else:
                _encode_wire_str(text)
            continue
        if tp is float:
            if not math.isfinite(cast(float, item)):
                raise BrainError(ErrorCode.INVALID_INPUT, "non-finite number")
            continue
        if tp is list:
            seq = cast(list[object], item)
            next_depth = depth + 1
            if next_depth > MAX_WIRE_DEPTH:
                raise BrainError(ErrorCode.INVALID_INPUT, "nesting depth exceeded")
            if len(seq) > MAX_WIRE_ARRAY_LEN:
                raise BrainError(ErrorCode.INVALID_INPUT, "array exceeds length limit")
            for child in seq:
                stack.append((child, next_depth))
            continue
        if tp is dict:
            mapping = cast(dict[object, object], item)
            next_depth = depth + 1
            if next_depth > MAX_WIRE_DEPTH:
                raise BrainError(ErrorCode.INVALID_INPUT, "nesting depth exceeded")
            for key, child in mapping.items():
                if type(key) is str:
                    if key.isascii():
                        if len(key) > MAX_WIRE_TEXT_BYTES:
                            raise BrainError(ErrorCode.INVALID_INPUT, "string exceeds size limit")
                    else:
                        _encode_wire_str(key)
                elif isinstance(key, str):
                    _encode_wire_str(key)
                else:
                    raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
                stack.append((child, next_depth))
            continue
        if isinstance(item, (bool, int)):
            continue
        if isinstance(item, float):
            if not math.isfinite(item):
                raise BrainError(ErrorCode.INVALID_INPUT, "non-finite number")
            continue
        if isinstance(item, str):
            _encode_wire_str(item)
            continue
        if isinstance(item, list):
            next_depth = depth + 1
            if next_depth > MAX_WIRE_DEPTH:
                raise BrainError(ErrorCode.INVALID_INPUT, "nesting depth exceeded")
            if len(item) > MAX_WIRE_ARRAY_LEN:
                raise BrainError(ErrorCode.INVALID_INPUT, "array exceeds length limit")
            for child in item:
                stack.append((child, next_depth))
            continue
        if isinstance(item, dict):
            next_depth = depth + 1
            if next_depth > MAX_WIRE_DEPTH:
                raise BrainError(ErrorCode.INVALID_INPUT, "nesting depth exceeded")
            for key, child in item.items():
                if not isinstance(key, str):
                    raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
                _encode_wire_str(key)
                stack.append((child, next_depth))
            continue
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")


def parse_json(raw: bytes) -> JsonValue:
    """Strictly parse UTF-8 JSON bytes enforcing size, duplicate-key, surrogate, and depth caps."""
    if not isinstance(raw, bytes):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if len(raw) > MAX_WIRE_BODY_BYTES:
        raise BrainError(ErrorCode.INVALID_INPUT, "payload exceeds size limit")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as err:
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid UTF-8 encoding") from err

    def unique_pairs(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
        obj: dict[str, JsonValue] = {}
        for key, val in pairs:
            if key in obj:
                raise BrainError(ErrorCode.INVALID_INPUT, "duplicate object key")
            obj[key] = val
        return obj

    def reject_nonfinite(_token: str) -> float:
        raise BrainError(ErrorCode.INVALID_INPUT, "non-finite number")

    try:
        parsed: JsonValue = json.loads(
            text,
            object_pairs_hook=unique_pairs,
            parse_constant=reject_nonfinite,
        )
    except BrainError:
        raise
    except RecursionError as err:
        raise BrainError(ErrorCode.INVALID_INPUT, "nesting depth exceeded") from err
    except ValueError as err:
        raise BrainError(ErrorCode.INVALID_INPUT, "malformed JSON") from err

    _validate_wire_structure(parsed)
    return parsed
