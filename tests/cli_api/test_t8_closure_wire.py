"""C-03 closure oracle: the client ``encode_call`` refuses an unsendable body before any byte reaches the wire.

Wire limits (spec): body <= ``MAX_WIRE_BODY_BYTES`` bytes, nesting depth <= 32 (the whole ``KernelHttpCall`` body,
whose root object is depth 1), arrays <= 1024 items, finite numbers, string keys, strings <= 64 KiB UTF-8 without
lone surrogates. Each violation is ``INVALID_INPUT``; the boundary values are accepted and decode on the server.
"""

from __future__ import annotations

import json
import math

import pytest

from superbrain.cli_api._loopback_wire import decode_call, encode_call
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import ToolCommand
from superbrain.core.wire import load_catalog

MAX_BODY = 1_048_576
MAX_TEXT = 65_536
MAX_DEPTH = 32
MAX_ARRAY = 1_024


def _command(arguments: object) -> ToolCommand:
    return ToolCommand(tool="get_health", arguments=arguments, token="cred.secret")  # type: ignore[arg-type]


def _body_len(arguments: dict[str, object]) -> int:
    body = {
        "arguments": arguments,
        "correlation_id": None,
        "schema_digest": load_catalog().schema_digest,
        "selected_scope": None,
        "tool": "get_health",
    }
    return len(json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())


def _nested(levels: int) -> object:
    value: object = "leaf"
    for _ in range(levels):
        value = [value]
    return value


def _refused(arguments: object) -> None:
    with pytest.raises(BrainError) as exc:
        encode_call(_command(arguments))
    assert exc.value.code is ErrorCode.INVALID_INPUT


def _accepted(arguments: dict[str, object]) -> bytes:
    body = encode_call(_command(arguments))
    assert decode_call(body, "cred.secret").arguments == arguments
    return body


def _at_size(target: int) -> dict[str, object]:
    """Arguments whose encoded body is exactly ``target`` bytes (strings stay under the 64 KiB text cap)."""
    chunk = MAX_TEXT - 16
    pad: list[str] = []
    arguments: dict[str, object] = {"schema_version": "2.0", "pad": pad}
    while _body_len(arguments) + chunk + 3 <= target:
        pad.append("a" * chunk)
    pad.append("")
    missing = target - _body_len(arguments)
    assert 0 <= missing <= MAX_TEXT
    pad[-1] = "a" * missing
    assert _body_len(arguments) == target
    return arguments


def test_c03_body_exactly_at_size_cap_is_accepted() -> None:
    body = _accepted(_at_size(MAX_BODY))
    assert len(body) == MAX_BODY


def test_c03_body_one_byte_over_size_cap_is_refused() -> None:
    _refused(_at_size(MAX_BODY + 1))


def test_c03_depth_boundary() -> None:
    # Body root (1) + arguments object (2) + n nested lists: n = 30 reaches depth 32 exactly.
    _accepted({"schema_version": "2.0", "deep": _nested(MAX_DEPTH - 2)})
    _refused({"schema_version": "2.0", "deep": _nested(MAX_DEPTH - 1)})


def test_c03_array_length_boundary() -> None:
    _accepted({"schema_version": "2.0", "items": list(range(MAX_ARRAY))})
    _refused({"schema_version": "2.0", "items": list(range(MAX_ARRAY + 1))})


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf], ids=["nan", "inf", "-inf"])
def test_c03_non_finite_float_is_refused(value: float) -> None:
    _refused({"schema_version": "2.0", "x": value})
    _refused({"schema_version": "2.0", "nested": {"list": [1.5, value]}})


def test_c03_finite_float_is_accepted() -> None:
    _accepted({"schema_version": "2.0", "x": 1.5, "nested": {"list": [-0.25, 1e300]}})


@pytest.mark.parametrize("key", [1, 2.5, None, True], ids=["int", "float", "none", "bool"])
def test_c03_non_string_key_is_refused(key: object) -> None:
    _refused({"schema_version": "2.0", "nested": {key: "v"}})
    _refused({"schema_version": "2.0", key: "v"})


def test_c03_string_text_cap_boundary() -> None:
    _accepted({"schema_version": "2.0", "s": "a" * MAX_TEXT})
    _accepted({"schema_version": "2.0", "s": "é" * (MAX_TEXT // 2)})
    _refused({"schema_version": "2.0", "s": "a" * (MAX_TEXT + 1)})
    _refused({"schema_version": "2.0", "s": "é" * (MAX_TEXT // 2) + "a"})
    _refused({"schema_version": "2.0", "k" * (MAX_TEXT + 1): "v"})


@pytest.mark.parametrize("text", ["\ud800", "a\udfffb", "\udc00\ud800"], ids=["high", "low", "reversed"])
def test_c03_lone_surrogate_is_refused(text: str) -> None:
    _refused({"schema_version": "2.0", "s": text})
    _refused({"schema_version": "2.0", "nested": [{text: 1}]})
