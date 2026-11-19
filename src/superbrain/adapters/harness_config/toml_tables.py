"""TOML table merger backed by ``tomlkit`` preserving comments, formatting and user tables (I3-2)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

import tomlkit
from tomlkit.exceptions import TOMLKitError
from tomlkit.items import Comment, Table, Whitespace

from superbrain.adapters.harness_config._common import (
    check_clean_text,
    digest_json_value,
    invalid_config,
    revision_conflict,
)
from superbrain.ports.proposals import MergeOutput

__all__ = ["merge_toml_table", "remove_toml_table"]


def _extract_trailing_trivia(tbl: Any, *, remove: bool = False) -> list[tuple[None, Any]]:
    value = getattr(tbl, "value", None)
    body = getattr(value, "body", None)
    if not isinstance(body, list):
        return []
    last_kv = max((i for i, (k, _) in enumerate(body) if k is not None), default=-1)
    tail = [(None, item) for k, item in body[last_kv + 1 :] if k is None and isinstance(item, (Comment, Whitespace))]
    if not any(isinstance(item, Comment) for _, item in tail):
        return []
    if remove:
        del body[last_kv + 1 :]
    return tail


def _locate_leaf_slot(
    doc: tomlkit.TOMLDocument, table_path: tuple[str, ...], leaf_obj: Any
) -> tuple[int | None, Any | None, int | None]:
    """Return ``(doc_body_idx, immediate_table, immediate_body_idx)`` for ``leaf_obj`` prior to deletion."""
    raw_body = getattr(doc, "_body", None)
    if not isinstance(raw_body, list):
        return None, None, None
    top_name = table_path[0]
    for doc_idx, (k, v) in enumerate(raw_body):
        if k is None or getattr(k, "key", None) != top_name:
            continue
        if len(table_path) == 1:
            if v is leaf_obj:
                return doc_idx, None, None
            continue
        cur = v
        for seg in table_path[1:-1]:
            if isinstance(cur, Mapping) and seg in cur:
                cur = cur[seg]
            else:
                cur = None
                break
        if cur is None:
            continue
        cur_body = getattr(getattr(cur, "value", None), "body", None)
        if isinstance(cur_body, list):
            for leaf_idx, (_, lv) in enumerate(cur_body):
                if lv is leaf_obj:
                    return doc_idx, cur, leaf_idx
    return None, None, None


def _insert_trivia(body: list[Any], index: int, trivia: list[tuple[None, Any]]) -> None:
    insert_at = min(index, len(body))
    for offset, pair in enumerate(trivia):
        body.insert(insert_at + offset, pair)


def _parse_toml(existing_text: str | None) -> tomlkit.TOMLDocument:
    text = check_clean_text(existing_text)
    if not text.strip():
        return tomlkit.document()
    try:
        return tomlkit.parse(text)
    except TOMLKitError as err:
        raise invalid_config(f"malformed TOML: {err}") from err


def _validate_path(table_path: tuple[str, ...]) -> None:
    if not table_path or any(not isinstance(seg, str) or not seg or "\x00" in seg for seg in table_path):
        raise invalid_config()


def _plain_dict(obj: Mapping[str, Any]) -> dict[str, Any]:
    raw = obj.unwrap() if hasattr(obj, "unwrap") else dict(obj)
    if not isinstance(raw, Mapping):
        raise invalid_config()
    return dict(raw)


def merge_toml_table(
    existing_text: str | None,
    *,
    table_path: tuple[str, ...],
    values: Mapping[str, Any],
    expected_slice_digest: str | None,
) -> MergeOutput:
    """Insert or update ``table_path`` using ``tomlkit`` while preserving all user comments and layout."""
    _validate_path(table_path)
    if not isinstance(values, Mapping):
        raise invalid_config()
    plain_values = _plain_dict(values)
    new_digest = digest_json_value(plain_values)

    doc = _parse_toml(existing_text)
    cursor: Any = doc
    for part in table_path[:-1]:
        if part not in cursor:
            if expected_slice_digest is not None:
                raise revision_conflict("expected TOML parent table is missing")
            parent_tbl = tomlkit.table(is_super_table=True)
            cursor.add(part, parent_tbl)
            cursor = parent_tbl
        else:
            existing_parent = cursor[part]
            if not isinstance(existing_parent, Mapping):
                raise invalid_config("TOML intermediate path is not a table")
            cursor = existing_parent

    leaf = table_path[-1]
    if leaf in cursor:
        existing_leaf: Any = cursor[leaf]
        if not isinstance(existing_leaf, Mapping):
            raise revision_conflict("TOML target key is not a table")
        if expected_slice_digest is None:
            raise revision_conflict("unmanaged collision on existing TOML table")
        curr_digest = digest_json_value(_plain_dict(existing_leaf))
        if curr_digest != expected_slice_digest:
            raise revision_conflict("TOML managed table modified out-of-band")
        if curr_digest == new_digest:
            assert existing_text is not None
            return MergeOutput(updated_text=existing_text, slice_digest=new_digest, changed=False)
        leaf_tbl = cast(Any, existing_leaf)
        trailing = _extract_trailing_trivia(leaf_tbl, remove=True)
        for existing_key in list(leaf_tbl.keys()):
            del leaf_tbl[existing_key]
        for key, val in plain_values.items():
            leaf_tbl.add(key, val)
        if trailing:
            body = getattr(getattr(existing_leaf, "value", None), "body", None)
            if isinstance(body, list):
                body.extend(trailing)
        return MergeOutput(updated_text=tomlkit.dumps(doc), slice_digest=new_digest, changed=True)
    elif expected_slice_digest is not None:
        raise revision_conflict("expected TOML table is missing")

    new_tbl = tomlkit.table()
    for key, val in plain_values.items():
        new_tbl.add(key, val)
    cursor.add(leaf, new_tbl)
    return MergeOutput(updated_text=tomlkit.dumps(doc), slice_digest=new_digest, changed=True)


def remove_toml_table(
    existing_text: str,
    *,
    table_path: tuple[str, ...],
    expected_slice_digest: str | None,
) -> MergeOutput:
    """Remove Brain's TOML table while keeping user comments, formatting and sibling tables untouched."""
    _validate_path(table_path)
    doc = _parse_toml(existing_text)
    trail: list[tuple[Any, str]] = []
    cursor: Any = doc
    for part in table_path[:-1]:
        if part not in cursor:
            if expected_slice_digest is not None:
                raise revision_conflict("expected TOML table is missing")
            return MergeOutput(updated_text=existing_text, slice_digest=digest_json_value({}), changed=False)
        child = cursor[part]
        if not isinstance(child, Mapping):
            raise invalid_config("TOML intermediate path is not a table")
        trail.append((cursor, part))
        cursor = child

    leaf = table_path[-1]
    if leaf not in cursor:
        if expected_slice_digest is not None:
            raise revision_conflict("expected TOML table is missing")
        return MergeOutput(updated_text=existing_text, slice_digest=digest_json_value({}), changed=False)

    existing_leaf = cursor[leaf]
    if not isinstance(existing_leaf, Mapping):
        raise revision_conflict("TOML target key is not a table")
    curr_digest = digest_json_value(_plain_dict(existing_leaf))
    if expected_slice_digest is not None and curr_digest != expected_slice_digest:
        raise revision_conflict("TOML managed table modified out-of-band")

    trailing_trivia = _extract_trailing_trivia(existing_leaf)
    doc_idx, imm_tbl, imm_idx = _locate_leaf_slot(doc, table_path, existing_leaf)
    raw_body = getattr(doc, "_body", None)
    top_item_before = raw_body[doc_idx][1] if isinstance(raw_body, list) and doc_idx is not None else None
    del cursor[leaf]
    removed_top = cursor is doc
    for parent_tbl, parent_key in reversed(trail):
        child_tbl = parent_tbl[parent_key]
        if isinstance(child_tbl, (Table, Mapping)) and len(child_tbl) == 0:
            del parent_tbl[parent_key]
            if parent_tbl is doc:
                removed_top = True
        else:
            break
    if trailing_trivia and doc_idx is not None and isinstance(raw_body, list):
        top_gone = removed_top or not any(item is top_item_before for _, item in raw_body)
        if top_gone:
            _insert_trivia(raw_body, doc_idx, trailing_trivia)
        elif imm_tbl is not None and imm_idx is not None:
            imm_body = getattr(getattr(imm_tbl, "value", None), "body", None)
            if isinstance(imm_body, list):
                _insert_trivia(imm_body, imm_idx, trailing_trivia)
    return MergeOutput(updated_text=tomlkit.dumps(doc), slice_digest=curr_digest, changed=True)
