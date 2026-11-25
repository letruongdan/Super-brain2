"""JSON key-path merger preserving sibling keys and user settings (spec 11.2, I3-2)."""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any, cast

from superbrain.adapters.harness_config._common import (
    check_clean_text,
    digest_json_value,
    invalid_config,
    revision_conflict,
)
from superbrain.core._json_parse import parse_json
from superbrain.core.jsonvalue import JsonValue
from superbrain.ports.proposals import MergeOutput

__all__ = ["merge_json_keys", "merge_json_multi_keys", "remove_json_keys"]


def _parse_json_root(existing_text: str | None) -> dict[str, Any]:
    text = check_clean_text(existing_text)
    if not text.strip():
        return {}
    parsed = parse_json(text.encode("utf-8"))
    if not isinstance(parsed, dict):
        raise invalid_config("JSON config root must be an object")
    return dict(parsed)


def _validate_path(key_path: tuple[str, ...]) -> None:
    if not key_path or any(not isinstance(seg, str) or not seg or "\x00" in seg for seg in key_path):
        raise invalid_config()


def merge_json_keys(
    existing_text: str | None,
    *,
    key_path: tuple[str, ...],
    value: object,
    expected_slice_digest: str | None,
) -> MergeOutput:
    """Insert or update ``key_path`` in a JSON object without disturbing sibling keys."""
    _validate_path(key_path)
    new_digest = digest_json_value(value)  # type: ignore[arg-type]
    if existing_text is None:
        if expected_slice_digest is not None:
            raise revision_conflict("expected JSON slice is missing")
        doc: dict[str, Any] = {}
        cursor = doc
        for part in key_path[:-1]:
            child: dict[str, Any] = {}
            cursor[part] = child
            cursor = child
        cursor[key_path[-1]] = value
        return MergeOutput(updated_text=json.dumps(doc, indent=2) + "\n", slice_digest=new_digest, changed=True)

    doc = _parse_json_root(existing_text)
    cursor = doc
    for part in key_path[:-1]:
        if part not in cursor:
            if expected_slice_digest is not None:
                raise revision_conflict("expected JSON parent path is missing")
            nxt: dict[str, Any] = {}
            cursor[part] = nxt
            cursor = nxt
        else:
            existing_child = cursor[part]
            if not isinstance(existing_child, dict):
                raise invalid_config("JSON intermediate path is not an object")
            cursor = existing_child

    leaf = key_path[-1]
    if leaf in cursor:
        if expected_slice_digest is None:
            raise revision_conflict("unmanaged collision on existing JSON key")
        curr_digest = digest_json_value(cursor[leaf])
        if curr_digest != expected_slice_digest:
            raise revision_conflict("JSON managed key modified out-of-band")
        if curr_digest == new_digest:
            return MergeOutput(updated_text=existing_text, slice_digest=new_digest, changed=False)
    elif expected_slice_digest is not None:
        raise revision_conflict("expected JSON slice is missing")

    cursor[leaf] = value
    return MergeOutput(updated_text=json.dumps(doc, indent=2) + "\n", slice_digest=new_digest, changed=True)


def _set_json_path(doc: dict[str, Any], key_path: tuple[str, ...], value: object) -> None:
    cursor = doc
    for part in key_path[:-1]:
        child = cursor.get(part)
        if child is None:
            nxt: dict[str, Any] = {}
            cursor[part] = nxt
            cursor = nxt
        elif isinstance(child, dict):
            cursor = child
        else:
            raise invalid_config("JSON intermediate path is not an object")
    cursor[key_path[-1]] = value


def merge_json_multi_keys(
    existing_text: str | None,
    *,
    entries: Sequence[tuple[tuple[str, ...], object]],
    expected_slice_digest: str | None,
) -> MergeOutput:
    """Insert or update multiple JSON key paths as one combined managed slice."""
    if not entries:
        raise invalid_config()
    combined_new: dict[str, JsonValue] = {}
    for key_path, value in entries:
        _validate_path(key_path)
        dotted = ".".join(key_path)
        if dotted in combined_new:
            raise invalid_config()
        combined_new[dotted] = cast(JsonValue, value)
    new_digest = digest_json_value(combined_new)

    if existing_text is None:
        if expected_slice_digest is not None:
            raise revision_conflict("expected JSON slice is missing")
        doc: dict[str, Any] = {}
        for key_path, value in entries:
            _set_json_path(doc, key_path, value)
        return MergeOutput(updated_text=json.dumps(doc, indent=2) + "\n", slice_digest=new_digest, changed=True)

    doc = _parse_json_root(existing_text)
    combined_curr: dict[str, JsonValue] = {}
    missing_any = False
    for key_path, _ in entries:
        cursor: dict[str, Any] | None = doc
        for part in key_path[:-1]:
            assert cursor is not None
            if part not in cursor:
                cursor = None
                break
            nxt = cursor[part]
            if not isinstance(nxt, dict):
                raise invalid_config("JSON intermediate path is not an object")
            cursor = nxt
        leaf = key_path[-1]
        if cursor is not None and leaf in cursor:
            if expected_slice_digest is None:
                raise revision_conflict("unmanaged collision on existing JSON key")
            combined_curr[".".join(key_path)] = cast(JsonValue, cursor[leaf])
        else:
            missing_any = True

    if expected_slice_digest is not None:
        if missing_any:
            raise revision_conflict("expected JSON slice is missing")
        curr_digest = digest_json_value(combined_curr)
        if curr_digest != expected_slice_digest:
            raise revision_conflict("JSON managed key modified out-of-band")
        if curr_digest == new_digest:
            return MergeOutput(updated_text=existing_text, slice_digest=new_digest, changed=False)

    for key_path, value in entries:
        _set_json_path(doc, key_path, value)
    return MergeOutput(updated_text=json.dumps(doc, indent=2) + "\n", slice_digest=new_digest, changed=True)


def remove_json_keys(
    existing_text: str,
    *,
    key_path: tuple[str, ...],
    expected_slice_digest: str | None,
) -> MergeOutput:
    """Remove ``key_path`` from a JSON object while keeping sibling keys and user additions."""
    _validate_path(key_path)
    doc = _parse_json_root(existing_text)
    trail: list[tuple[dict[str, Any], str]] = []
    cursor: dict[str, Any] = doc
    for part in key_path[:-1]:
        child = cursor.get(part)
        if not isinstance(child, dict):
            if expected_slice_digest is not None:
                raise revision_conflict("expected JSON slice is missing")
            return MergeOutput(updated_text=existing_text, slice_digest=digest_json_value(None), changed=False)
        trail.append((cursor, part))
        cursor = child

    leaf = key_path[-1]
    if leaf not in cursor:
        if expected_slice_digest is not None:
            raise revision_conflict("expected JSON slice is missing")
        return MergeOutput(updated_text=existing_text, slice_digest=digest_json_value(None), changed=False)

    curr_digest = digest_json_value(cursor[leaf])
    if expected_slice_digest is not None and curr_digest != expected_slice_digest:
        raise revision_conflict("JSON managed key modified out-of-band")

    del cursor[leaf]
    for parent_dict, parent_key in reversed(trail):
        child_dict = parent_dict[parent_key]
        if not child_dict:
            del parent_dict[parent_key]
        else:
            break
    rendered = json.dumps(doc, indent=2) + "\n"
    return MergeOutput(updated_text=rendered, slice_digest=curr_digest, changed=True)


_ = JsonValue
