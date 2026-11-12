"""Closure round C r4 oracles: rule gates read only literals every match must contain.

Requirement (D6): an added rule is applied to every input it matches. A literal made optional by ``?`` is not in
every match (``ab?cd`` matches ``acd``), and the letter of a ``\\d``-style escape is not a literal (``tok\\dkey``
matches ``tok7key``), so neither may become a required gate substring. Expected results follow from the compiled
rule itself (``pattern.search`` is asserted before the filter is checked); entropy is off so it cannot mask a skip.
"""

from __future__ import annotations

import re

import pytest

import superbrain.application._privacy_rules as rules_mod
import superbrain.application._privacy_scan as scan_mod
import superbrain.application.privacy as privacy_mod
from superbrain.application.privacy import PrivacyFilter
from superbrain.core.kernel import FilterPolicy

REDACTED = "[redacted]"
POLICY = FilterPolicy(entropy_min_length=4096)
_MODULES = (rules_mod, scan_mod, privacy_mod)
_SUFFIXES = ("", " ü")  # ASCII-only text, and text with a non-ASCII char elsewhere


def _filtered(text: str) -> tuple[object, int]:
    safe = PrivacyFilter().apply({"content": text, "ok": "safe prose kept"}, POLICY)
    assert isinstance(safe.value, dict)
    assert safe.value["ok"] == "safe prose kept"
    return safe.value["content"], safe.redacted_count


OPTIONAL_LITERAL_SHAPE = re.compile(r"\bab?cd-[a-z0-9]{8,}")


@pytest.fixture
def optional_literal_shape(monkeypatch: pytest.MonkeyPatch) -> re.Pattern[str]:
    extended = (*rules_mod._FIXED_TOKENS, OPTIONAL_LITERAL_SHAPE)
    for module in _MODULES:
        monkeypatch.setattr(module, "_FIXED_TOKENS", extended, raising=False)
    return OPTIONAL_LITERAL_SHAPE


@pytest.mark.parametrize("token", ["abcd-k3j4h5g6", "acd-k3j4h5g6"], ids=["with_optional", "without_optional"])
@pytest.mark.parametrize("suffix", _SUFFIXES, ids=["ascii", "non_ascii"])
def test_r4_added_shape_with_optional_literal_redacts_both_spellings(
    optional_literal_shape: re.Pattern[str], token: str, suffix: str,
) -> None:
    text = f"use {token} now{suffix}"
    assert optional_literal_shape.search(text)
    assert _filtered(text) == (f"use {REDACTED} now{suffix}", 1)


@pytest.mark.parametrize("suffix", _SUFFIXES, ids=["ascii", "non_ascii"])
def test_r4_optional_literal_shape_near_misses_are_kept(optional_literal_shape: re.Pattern[str], suffix: str) -> None:
    for token in ("abbcd-k3j4h5g6", "acd-short", "xacd-k3j4h5g6"):
        text = f"use {token} now{suffix}"
        assert not optional_literal_shape.search(text)
        assert _filtered(text) == (text, 0)


ESCAPE_ALTERNATIVE = r"tok\dkey"


@pytest.fixture
def escape_alternative(monkeypatch: pytest.MonkeyPatch) -> re.Pattern[str]:
    original = rules_mod._KEY_VALUE_SECRET
    assert r"\b(" in original.pattern
    extended = re.compile(original.pattern.replace(r"\b(", rf"\b({ESCAPE_ALTERNATIVE}|", 1), original.flags)
    for module in _MODULES:
        monkeypatch.setattr(module, "_KEY_VALUE_SECRET", extended, raising=False)
    return extended


@pytest.mark.parametrize("sep", ["=", ":", " = ", "\t:"])
@pytest.mark.parametrize("key", ["tok7key", "TOK0KEY"])
@pytest.mark.parametrize("suffix", _SUFFIXES, ids=["ascii", "non_ascii"])
def test_r4_added_key_value_alternative_ending_in_escape_then_literal_is_redacted(
    escape_alternative: re.Pattern[str], key: str, sep: str, suffix: str,
) -> None:
    text = f"cfg {key}{sep}s3cr3tvalue end{suffix}"
    assert escape_alternative.search(text)
    assert _filtered(text) == (f"cfg {key}{sep}{REDACTED} end{suffix}", 1)


@pytest.mark.parametrize("suffix", _SUFFIXES, ids=["ascii", "non_ascii"])
def test_r4_escape_alternative_near_misses_are_kept(escape_alternative: re.Pattern[str], suffix: str) -> None:
    for key in ("tokxkey", "tok77key", "tok7keys"):
        text = f"cfg {key}=s3cr3tvalue end{suffix}"
        assert not escape_alternative.search(text)
        assert _filtered(text) == (text, 0)
