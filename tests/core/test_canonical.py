from pathlib import Path

import pytest

from superbrain.core.canonical import canonical_digest, digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue


@pytest.mark.parametrize("value", [1.0, 1.25, float("nan"), float("inf"), b"bad", (1, 2), {1: 2}, "\ud800"])
def test_canonical_digest_rejects_non_json_and_float_quantities(value: object) -> None:
    with pytest.raises(BrainError) as failure:
        canonical_digest("knowledge", {"quantity": value})  # type: ignore[dict-item]
    assert failure.value.code == ErrorCode.INVALID_INPUT


def test_canonical_digest_uses_utf8_not_ascii_escapes() -> None:
    assert canonical_digest("knowledge", {"title": "é"}) == (
        "sha256:eddaa692de85aab3ff2517bb0a4b619ce469ec3064ba3496e0d3662fc69e1f47")


def test_canonical_digest_is_order_independent_but_content_sensitive() -> None:
    left: dict[str, JsonValue] = {"z": {"b": 2, "a": 1}, "a": [True, None, "1.25"]}
    right: dict[str, JsonValue] = {"a": [True, None, "1.25"], "z": {"a": 1, "b": 2}}
    assert canonical_digest("knowledge", left) == canonical_digest("knowledge", right)
    assert canonical_digest("knowledge", left) != canonical_digest("research_note", left)
    assert canonical_digest("knowledge", left) != canonical_digest("knowledge", {**left, "z": 3})


def test_digest_bytes_hashes_exact_delivered_bytes() -> None:
    assert digest_bytes(b"abc") == "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert digest_bytes(b"abc\n") == "sha256:edeaaff3f1774ad2888673770c6d64097e391bc362d7d6fb34982ddf0efd18cb"
    assert digest_bytes(b"abc\r\n") == "sha256:552bab6864c7a7b69a502ed1854b9245c0e1a30f008aaa0b281da62585fdb025"
    body = Path(__file__).resolve().parents[1] / "fixtures" / "skill-body.txt"
    assert digest_bytes(body.read_bytes()) == "sha256:db70d6dd52eac093eb1c46c4d0daece722a287f8e2c417042160869883b99bbb"


@pytest.mark.parametrize("value", ["abc", bytearray(b"abc"), memoryview(b"abc"), None])
def test_digest_bytes_requires_bytes(value: object) -> None:
    with pytest.raises(BrainError) as failure:
        digest_bytes(value)  # type: ignore[arg-type]
    assert failure.value.code == ErrorCode.INVALID_INPUT
