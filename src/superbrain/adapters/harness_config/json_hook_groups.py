"""Managed hook handlers inside a host's ``hooks`` object (Claude Code settings, Codex ``hooks.json``).

Both hosts read ``{"hooks": {"<Event>": [{"matcher": ..., "hooks": [{"type": "command", ...}]}]}}``. The managed
slice ``hooks#super-brain`` is the set of handlers that run ``-m superbrain.composition.hook_entry``, kept in their
matcher groups; merging or removing it never touches the user's own handlers, even in a shared group. The object
form an earlier bootstrap wrote (``{"super_brain": {...}}``) is upgraded in place when it holds nothing else.
"""

from __future__ import annotations

import json
import shlex
from collections.abc import Mapping, Sequence
from typing import Any, cast

from superbrain.adapters.harness_config._common import digest_json_value, invalid_config, revision_conflict
from superbrain.adapters.harness_config.json_keys import _parse_json_root, _validate_path
from superbrain.core.jsonvalue import JsonValue
from superbrain.ports.proposals import MergeOutput

HOOK_GROUPS_SLICE = "hooks#super-brain"
_HOOK_MODULE = "superbrain.composition.hook_entry"
_QUOTE = '"'


def _argv_runs_hook(argv: Sequence[object]) -> bool:
    return any(argv[i] == "-m" and argv[i + 1] == _HOOK_MODULE for i in range(len(argv) - 1))


def _tokens(command: object, *, posix: bool) -> list[str]:
    if not isinstance(command, str):
        return []
    try:
        parts = shlex.split(command, posix=posix)
    except ValueError:
        return []
    return [part.strip(_QUOTE) for part in parts]


def is_managed_handler(handler: object) -> bool:
    """The handler runs the capture hook (``-m superbrain.composition.hook_entry``); a mention is not enough."""
    if not isinstance(handler, Mapping):
        return False
    args = handler.get("args")
    if isinstance(args, list) and _argv_runs_hook([handler.get("command"), *args]):
        return True
    return _argv_runs_hook(_tokens(handler.get("command"), posix=True)) or any(
        _argv_runs_hook(_tokens(handler.get(field), posix=False)) for field in ("commandWindows", "command_windows")
    )


def is_managed_group(group: object) -> bool:
    """A matcher group holds at least one managed handler."""
    handlers = group.get("hooks") if isinstance(group, Mapping) else None
    return isinstance(handlers, list) and any(is_managed_handler(h) for h in handlers)


def _is_legacy_object(value: object) -> bool:
    """The object form an earlier bootstrap owned whole: ``{"super_brain": {..., "command": [...]}}``."""
    if not isinstance(value, Mapping) or "super_brain" not in value:
        return False
    owned = value["super_brain"]
    command = owned.get("command") if isinstance(owned, Mapping) else None
    if not (isinstance(command, list) and _argv_runs_hook(command)):
        return False
    if set(value) != {"super_brain"}:
        raise revision_conflict("legacy hook object also holds user entries")  # never delete what is not ours
    return True


def _event_list(hooks: Mapping[str, Any], event: str) -> list[Any]:
    cur = hooks.get(event, [])
    if _is_legacy_object(cur):
        return []
    if not isinstance(cur, list):
        raise invalid_config("hook event entry is not a list of matcher groups")
    return cur


def _managed_only(group: Mapping[str, Any]) -> dict[str, Any]:
    return {**{k: v for k, v in group.items() if k != "hooks"},
            "hooks": [h for h in group["hooks"] if is_managed_handler(h)]}


def extract_hook_groups(doc: Mapping[str, Any]) -> dict[str, JsonValue]:
    """The managed groups per event, as currently written (events without managed groups omitted)."""
    hooks = doc.get("hooks")
    if hooks is None:
        return {}
    if not isinstance(hooks, Mapping):
        raise invalid_config("hooks entry is not an object")
    out: dict[str, JsonValue] = {}
    for event in sorted(hooks):
        managed = [_managed_only(g) for g in _event_list(hooks, event) if is_managed_group(g)]
        if managed:
            out[event] = cast(JsonValue, managed)
    return out


def _current_part(doc: Mapping[str, Any], part: str) -> tuple[bool, JsonValue]:
    if part == HOOK_GROUPS_SLICE:
        groups = extract_hook_groups(doc)
        return bool(groups), groups
    cursor: object = doc
    for seg in part.split("."):
        if not isinstance(cursor, Mapping) or seg not in cursor:
            return False, None
        cursor = cursor[seg]
    return True, cursor  # type: ignore[return-value]


def _set_hook_groups(doc: dict[str, Any], groups: Mapping[str, Any]) -> None:
    hooks = doc.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise invalid_config("hooks entry is not an object")
    for event in list(hooks):
        kept = []
        for group in _event_list(hooks, event):  # a legacy object reads as no groups and is replaced
            if not is_managed_group(group):
                kept.append(group)
                continue
            rest = [h for h in group["hooks"] if not is_managed_handler(h)]
            if rest:  # the user's handlers in a shared group stay where they were
                kept.append({**group, "hooks": rest})
        if kept:
            hooks[event] = kept
        else:
            del hooks[event]
    for event, event_groups in groups.items():
        if not isinstance(event_groups, list) or not all(
            is_managed_group(g) and all(is_managed_handler(h) for h in g["hooks"]) for g in event_groups
        ):
            raise invalid_config("managed hook slice holds a handler that does not run the capture hook")
        hooks[event] = [*_event_list(hooks, event), *event_groups]
    if not hooks:
        del doc["hooks"]


def _set_key_path(doc: dict[str, Any], part: str, value: object) -> None:
    key_path = tuple(part.split("."))
    _validate_path(key_path)
    cursor = doc
    for seg in key_path[:-1]:
        child = cursor.setdefault(seg, {})
        if not isinstance(child, dict):
            raise invalid_config("JSON intermediate path is not an object")
        cursor = child
    cursor[key_path[-1]] = value


def merge_json_slices(
    existing_text: str | None, *, entries: Sequence[tuple[str, JsonValue]], expected_slice_digest: str | None,
) -> MergeOutput:
    """Insert or update one combined managed slice made of key paths and/or ``hooks#super-brain``. A key path that
    exists without an expected digest is an unmanaged collision; managed hook groups are recognised by their hook."""
    if not entries or len({p for p, _v in entries}) != len(entries):
        raise invalid_config()
    new_digest = digest_json_value(dict(entries))
    doc = _parse_json_root(existing_text) if existing_text is not None else {}
    current: dict[str, JsonValue] = {}
    missing = False
    for part, _value in entries:
        present, value = _current_part(doc, part)
        if present:
            if expected_slice_digest is None and part != HOOK_GROUPS_SLICE:
                raise revision_conflict("unmanaged collision on existing JSON key")
            current[part] = value
        else:
            missing = True
            current[part] = {} if part == HOOK_GROUPS_SLICE else None
    if expected_slice_digest is not None:
        if missing or digest_json_value(current) != expected_slice_digest:
            raise revision_conflict("JSON managed slice modified out-of-band")
        if digest_json_value(current) == new_digest and existing_text is not None:
            return MergeOutput(updated_text=existing_text, slice_digest=new_digest, changed=False)
    for part, value in entries:
        if part == HOOK_GROUPS_SLICE:
            if not isinstance(value, Mapping):
                raise invalid_config("managed hook slice must map events to matcher groups")
            _set_hook_groups(doc, value)
        else:
            _set_key_path(doc, part, value)
    return MergeOutput(updated_text=json.dumps(doc, indent=2) + "\n", slice_digest=new_digest, changed=True)


def remove_json_slices(existing_text: str, *, parts: Sequence[str], expected_slice_digest: str | None) -> MergeOutput:
    """Remove a combined managed slice (key paths and/or ``hooks#super-brain``), keeping every user entry."""
    doc = _parse_json_root(existing_text)
    current: dict[str, JsonValue] = {}
    for part in parts:
        present, value = _current_part(doc, part)
        if not present and expected_slice_digest is not None:
            raise revision_conflict("expected JSON slice is missing")
        current[part] = value if present else ({} if part == HOOK_GROUPS_SLICE else None)
    if expected_slice_digest is not None and digest_json_value(current) != expected_slice_digest:
        raise revision_conflict("JSON managed slice modified out-of-band")
    for part in parts:
        if part == HOOK_GROUPS_SLICE:
            _set_hook_groups(doc, {})
            continue
        key_path = part.split(".")
        trail: list[tuple[dict[str, Any], str]] = []
        cursor: Any = doc
        for seg in key_path[:-1]:
            if not isinstance(cursor, dict) or not isinstance(cursor.get(seg), dict):
                cursor = None
                break
            trail.append((cursor, seg))
            cursor = cursor[seg]
        if isinstance(cursor, dict) and key_path[-1] in cursor:
            del cursor[key_path[-1]]
            for parent, key in reversed(trail):
                if parent[key]:
                    break
                del parent[key]
    return MergeOutput(updated_text=json.dumps(doc, indent=2) + "\n", slice_digest=digest_json_value(current),
                       changed=True)
