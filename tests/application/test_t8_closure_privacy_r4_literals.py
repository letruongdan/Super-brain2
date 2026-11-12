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


# ``tok\dkey`` is the owner's example; its ``key`` is also a needle of the existing ``api[_-]?key`` alternative, which
# keeps the gate open by itself. ``tok\dzq`` shares no literal with any existing alternative, so only its own
# post-escape literal ``zq`` can open the gate.
ESCAPE_ALTERNATIVES: dict[str, tuple[str, tuple[str, ...]]] = {
    "tok_d_key": (r"tok\dkey", ("tok7key", "TOK0KEY")),
    "tok_d_zq": (r"tok\dzq", ("tok7zq", "TOK0ZQ")),
}


def _with_alternative(monkeypatch: pytest.MonkeyPatch, alternative: str) -> re.Pattern[str]:
    original = rules_mod._KEY_VALUE_SECRET
    assert r"\b(" in original.pattern
    extended = re.compile(original.pattern.replace(r"\b(", rf"\b({alternative}|", 1), original.flags)
    for module in _MODULES:
        monkeypatch.setattr(module, "_KEY_VALUE_SECRET", extended, raising=False)
    return extended


@pytest.mark.parametrize("sep", ["=", ":", " = ", "\t:"])
@pytest.mark.parametrize("suffix", _SUFFIXES, ids=["ascii", "non_ascii"])
@pytest.mark.parametrize("name", sorted(ESCAPE_ALTERNATIVES))
def test_r4_added_key_value_alternative_ending_in_escape_then_literal_is_redacted(
    monkeypatch: pytest.MonkeyPatch, name: str, sep: str, suffix: str,
) -> None:
    alternative, keys = ESCAPE_ALTERNATIVES[name]
    rule = _with_alternative(monkeypatch, alternative)
    for key in keys:
        text = f"cfg {key}{sep}s3cr3tvalue end{suffix}"
        assert rule.search(text)
        assert _filtered(text) == (f"cfg {key}{sep}{REDACTED} end{suffix}", 1), text


@pytest.mark.parametrize("suffix", _SUFFIXES, ids=["ascii", "non_ascii"])
@pytest.mark.parametrize("name", sorted(ESCAPE_ALTERNATIVES))
def test_r4_escape_alternative_near_misses_are_kept(monkeypatch: pytest.MonkeyPatch, name: str, suffix: str) -> None:
    alternative, keys = ESCAPE_ALTERNATIVES[name]
    rule = _with_alternative(monkeypatch, alternative)
    stem, tail = keys[0][:3], keys[0][4:]
    for key in (f"{stem}x{tail}", f"{stem}77{tail}", f"{keys[0]}s"):
        text = f"cfg {key}=s3cr3tvalue end{suffix}"
        assert not rule.search(text)
        assert _filtered(text) == (text, 0)
