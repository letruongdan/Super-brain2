"""C-04 closure oracle: normalized arguments share no mutable container with the caller's input.

After ``normalize_call`` / ``normalize_shim_args`` return, mutating any nested dict/list of the input must leave
the result unchanged, and mutating the result must leave the input unchanged (the queued canonical bytes and the
fingerprint are taken from the result, so aliasing would let a caller change a request after admission).
"""

from __future__ import annotations

import copy
from collections.abc import Callable, Iterator

import pytest

from superbrain.core.client_profile import SelectedWorkspace
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import Principal, Scope
from superbrain.core.wire import normalize_call, normalize_shim_args

PRINCIPAL = Principal(principal_id="p-closure-1", owner_id="dan", harness_id="claude-code", machine_id="devbox-1")
SCOPE = Scope(repo_id="ws-repo-a", checkout_id="chk-a")
SELECTED = SelectedWorkspace(alias="ws-a", scope=SCOPE)


def _episode() -> dict[str, JsonValue]:
    return {
        "schema_version": "2.0",
        "workspace_id": "ws-repo-a",
        "task_id": "task-01",
        "session_id": "sess-01",
        "evidence": [
            {"kind": "log", "data": {"lines": ["a", "b"], "meta": {"tags": ["x"], "deep": [[1, {"k": "v"}]]}}},
        ],
        "candidate_lesson": {"title": "t", "content": "c", "conditions": ["when x"]},
        "idempotency_key": "idem_closure_0001",
    }


def _containers(node: JsonValue, path: tuple[object, ...] = ()) -> Iterator[tuple[tuple[object, ...], JsonValue]]:
    if isinstance(node, dict):
        yield path, node
        for key, child in node.items():
            yield from _containers(child, (*path, key))
    elif isinstance(node, list):
        yield path, node
        for index, child in enumerate(node):
            yield from _containers(child, (*path, index))


def _at(node: JsonValue, path: tuple[object, ...]) -> JsonValue:
    for step in path:
        node = node[step]  # type: ignore[index,call-overload]
    return node


def _mutate(container: JsonValue) -> None:
    if isinstance(container, dict):
        container["__injected__"] = "mutated"
    else:
        assert isinstance(container, list)
        container.append("mutated")


Normalizer = Callable[[dict[str, JsonValue]], dict[str, JsonValue]]


def _via_call(args: dict[str, JsonValue]) -> dict[str, JsonValue]:
    return normalize_call("submit_episode", args, PRINCIPAL, selected_scope=SCOPE).arguments


def _via_shim_selected(args: dict[str, JsonValue]) -> dict[str, JsonValue]:
    return normalize_shim_args("submit_episode", args, SELECTED)


def _via_shim_unselected(args: dict[str, JsonValue]) -> dict[str, JsonValue]:
    payload = {"schema_version": "2.0", "nested": args["evidence"]}
    return normalize_shim_args("get_health", payload, None)


NORMALIZERS: dict[str, Normalizer] = {
    "normalize_call": _via_call,
    "normalize_shim_args_selected": _via_shim_selected,
    "normalize_shim_args_unselected": _via_shim_unselected,
}


@pytest.mark.parametrize("name", sorted(NORMALIZERS))
def test_c04_positive_control_result_equals_input_content(name: str) -> None:
    args = _episode()
    result = NORMALIZERS[name](args)
    assert result is not args
    assert args == _episode(), "normalization must not modify the caller's input"
    if name != "normalize_shim_args_unselected":
        assert result == _episode()


@pytest.mark.parametrize("name", sorted(NORMALIZERS))
def test_c04_mutating_any_nested_input_container_leaves_result_unchanged(name: str) -> None:
    probe_paths = [path for path, _ in _containers(_episode())]
    for path in probe_paths:
        args = _episode()
        result = NORMALIZERS[name](args)
        snapshot = copy.deepcopy(result)
        _mutate(_at(args, path))
        assert result == snapshot, f"{name}: input container at {path!r} is shared with the result"


@pytest.mark.parametrize("name", sorted(NORMALIZERS))
def test_c04_mutating_any_nested_result_container_leaves_input_unchanged(name: str) -> None:
    args = _episode()
    paths = [path for path, _ in _containers(NORMALIZERS[name](args))]
    assert len(paths) >= 8
    for path in paths:
        args = _episode()
        result = NORMALIZERS[name](args)
        _mutate(_at(result, path))
        assert args == _episode(), f"{name}: result container at {path!r} is shared with the input"


@pytest.mark.parametrize("name", sorted(NORMALIZERS))
def test_c04_no_result_container_is_an_input_container(name: str) -> None:
    args = _episode()
    result = NORMALIZERS[name](args)
    input_ids = {id(node) for _, node in _containers(args)}
    shared = [path for path, node in _containers(result) if id(node) in input_ids]
    assert not shared, f"{name}: shared containers at {shared!r}"
