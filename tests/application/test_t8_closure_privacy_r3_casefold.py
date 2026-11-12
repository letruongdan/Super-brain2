"""Closure round C r3 oracle: a case-insensitive rule is never skipped on non-ASCII text by a lowercase gate.

Requirement (D6): a rule is applied to every input it matches. Python ``re.IGNORECASE`` matches characters that
``str.lower()`` does not map to the rule's literal (``ſ`` LONG S matches ``s``, ``K`` KELVIN SIGN matches
``k``), so a substring gate built from lower-cased literals must not reject such text. Expected results follow from
the compiled rule itself (``pattern.search``), asserted in the test before the filter is checked.
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
POLICY = FilterPolicy(entropy_min_length=4096)  # entropy off: it must not mask a skipped rule
CASE_INSENSITIVE_SHAPE = re.compile(r"(?i)\bsxyz-[a-z0-9]{8,}")


def _filtered(text: str) -> tuple[object, int]:
    safe = PrivacyFilter().apply({"content": text, "ok": "safe prose kept"}, POLICY)
    assert isinstance(safe.value, dict)
    assert safe.value["ok"] == "safe prose kept"
    return safe.value["content"], safe.redacted_count


@pytest.fixture
def added_shape(monkeypatch: pytest.MonkeyPatch) -> re.Pattern[str]:
    extended = (*rules_mod._FIXED_TOKENS, CASE_INSENSITIVE_SHAPE)
    for module in (rules_mod, scan_mod, privacy_mod):
        monkeypatch.setattr(module, "_FIXED_TOKENS", extended, raising=False)
    return CASE_INSENSITIVE_SHAPE


@pytest.mark.parametrize(
    ("token", "suffixes"),
    [
        ("sxyz-abcdefgh12", ("", " ü")),  # positive control: the plain spelling on both branches
        ("SXYZ-abcdefgh12", ("", " ü")),
        ("ſxyz-abcdefgh12", (" ü",)),  # LONG S: non-ASCII by construction, plus another non-ASCII char
        ("ſXYZ-abcdefgh12", ("",)),
    ],
)
def test_r3_added_case_insensitive_fixed_shape_is_redacted_on_both_branches(
    added_shape: re.Pattern[str], token: str, suffixes: tuple[str, ...],
) -> None:
    for suffix in suffixes:
        text = f"use {token} now{suffix}"
        assert added_shape.search(text), "the rule itself matches this text"
        assert _filtered(text) == (f"use {REDACTED} now{suffix}", 1), (text, _filtered(text))


def test_r3_added_case_insensitive_shape_near_misses_are_kept(added_shape: re.Pattern[str]) -> None:
    for text in ("use sxyz-short now", "use sxyz-short now ü", "use xsxyz-abcdefgh12 now ü"):
        assert not added_shape.search(text)
        assert _filtered(text) == (text, 0)


@pytest.mark.parametrize("name", ["paſſword", "api_Key", "ſecret"])
def test_r3_existing_case_insensitive_key_value_rule_matches_folded_spelling(name: str) -> None:
    text = f"cfg {name}=hunter2xyz end ü"
    assert rules_mod._KEY_VALUE_SECRET.search(text), "the rule itself matches this spelling"
    assert _filtered(text) == (f"cfg {name}={REDACTED} end ü", 1)
