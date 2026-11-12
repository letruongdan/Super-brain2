"""Closure round C r5 oracles (review F1): any rule shape is applied to every input it matches.

Requirement (D6): an added or edited rule is applied to every input it matches. A derived prefilter may refuse only
input its rule cannot match, so a regex construct the gate reader does not understand must leave the rule ungated.
Rules are simulated by patching the module-level rule objects in ``_privacy_rules``, ``_privacy_scan`` and
``privacy`` (``raising=False``). Every sample is checked against the compiled rule itself before the filter runs,
in ASCII-only text and in text with a non-ASCII character elsewhere. Entropy is off so it cannot mask a skipped rule.
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
_SUFFIXES = ("", " \u00fc")


def _filtered(text: str) -> tuple[object, int]:
    safe = PrivacyFilter().apply({"content": text, "ok": "safe prose kept"}, POLICY)
    assert isinstance(safe.value, dict)
    assert safe.value["ok"] == "safe prose kept"  # positive control
    return safe.value["content"], safe.redacted_count


def _patch(monkeypatch: pytest.MonkeyPatch, name: str, value: object) -> None:
    for module in _MODULES:
        monkeypatch.setattr(module, name, value, raising=False)


# ------------------------------------------------------------------------------------------------------------------
# Added fixed-token shapes (each sample must be redacted as a whole token).
# ------------------------------------------------------------------------------------------------------------------

FIXED_SHAPES: dict[str, tuple[re.Pattern[str], tuple[str, ...]]] = {
    "quantified_leading_group": (re.compile(r"\b(?:sq|sr)*zz-[a-z0-9]{8,}"), ("zz-abcdefgh12", "sqzz-abcdefgh12")),
    "top_level_alternation": (re.compile(r"\bfoo-[a-z0-9]{8,}|bar-[a-z0-9]{8,}"), ("bar-abcdefgh12", "foo-abcdefgh12")),
    "named_group": (re.compile(r"\b(?P<p>ghx)_[a-z0-9]{8,}"), ("ghx_abcdefgh12",)),
    "scoped_ignorecase": (re.compile(r"\b(?i:sq)-[a-z0-9]{8,}"), ("SQ-abcdefgh12", "sq-abcdefgh12")),
    "negative_lookahead": (re.compile(r"\b(?!test)[a-z]{4}-[0-9]{8,}"), ("prod-12345678",)),
    "atomic_group": (re.compile(r"\b(?>ab|cd)-[0-9]{8,}"), ("cd-12345678", "ab-12345678")),
    "scoped_case_sensitive": (re.compile(r"(?i)\b(?-i:Zq)-[0-9]{8,}"), ("Zq-12345678",)),
    "group_repeated_zero_times": (re.compile(r"\b(?:zz){0}qq-[0-9]{8,}"), ("qq-12345678",)),
    "group_optional_by_range": (re.compile(r"\b(?:zz){0,1}qq-[0-9]{8,}"), ("qq-12345678", "zzqq-12345678")),
    "possessive_group": (re.compile(r"\b(?:xy)*+c-[0-9]{8,}"), ("c-12345678", "xyc-12345678")),
    "possessive_literal": (re.compile(r"\bab*+c-[0-9]{8,}"), ("ac-12345678", "abbc-12345678")),
    "hex_escape": (re.compile(r"\b(ab\x41|zz\x42)-[0-9]{8,}"), ("abA-12345678", "zzB-12345678")),
    "unicode_escape": (re.compile(r"\b(ab\u00e9|q)-[0-9]{8,}"), ("ab\u00e9-12345678", "q-12345678")),
    "raw_non_ascii_literal": (re.compile("\\b(ab\u00e9|q)-[0-9]{8,}"), ("ab\u00e9-12345678", "q-12345678")),
    "escaped_close_paren": (re.compile(r"\b(a\)b|c)-[0-9]{8,}"), ("c-12345678", "a)b-12345678")),
    "verbose_flag": (re.compile(r"\b ab - [0-9]{8,}", re.VERBOSE), ("ab-12345678",)),
    "ascii_flag": (re.compile(r"\bkq\d-[a-z]{8,}", re.ASCII), ("kq1-abcdefgh",)),
    "ascii_ignorecase_flags": (re.compile(r"\bkq-[a-z]{8,}", re.ASCII | re.IGNORECASE), ("KQ-abcdefgh",)),
    "bracket_first_in_class": (re.compile(r"\b(?:x[]a]y|zz)-[0-9]{8,}"), ("x]y-12345678", "xay-12345678")),
    "pipe_inside_class": (re.compile(r"\b(?:a[|]b|zz)-[0-9]{8,}"), ("a|b-12345678", "zz-12345678")),
    "conditional_group": (re.compile(r"\b(q)?(?(1)r|s)-[0-9]{8,}"), ("s-12345678", "qr-12345678")),
    "group_not_first": (re.compile(r"\bx(a|b)-[0-9]{8,}"), ("xb-12345678", "xa-12345678")),
}


@pytest.mark.parametrize("suffix", _SUFFIXES, ids=["ascii", "non_ascii"])
@pytest.mark.parametrize("name", sorted(FIXED_SHAPES))
def test_r5_added_fixed_shape_is_applied_to_every_match(
    monkeypatch: pytest.MonkeyPatch, name: str, suffix: str,
) -> None:
    rule, samples = FIXED_SHAPES[name]
    _patch(monkeypatch, "_FIXED_TOKENS", (*rules_mod._FIXED_TOKENS, rule))
    failures: list[str] = []
    for sample in samples:
        text = f"use {sample} now{suffix}"
        found = rule.search(text)
        assert found is not None and found.group(0) == sample, f"{name}: the rule itself must match {sample!r}"
        got = _filtered(text)
        if got != (f"use {REDACTED} now{suffix}", 1):
            failures.append(f"{name}: {text!r} -> {got!r}")
    assert not failures, "\n".join(failures)


def test_r5_positive_control_unpatched_text_without_a_match_is_kept() -> None:
    for suffix in _SUFFIXES:
        text = f"use zz-short now{suffix}"
        assert _filtered(text) == (text, 0)


# ------------------------------------------------------------------------------------------------------------------
# Added key=value alternatives with unusual shapes (group numbering kept: only non-capturing constructs added).
# ------------------------------------------------------------------------------------------------------------------

KV_SHAPES: dict[str, tuple[str, tuple[str, ...]]] = {
    "quantified_group": (r"(?:sq|sr)*zzk", ("zzk", "sqzzk")),
    "escaped_close_paren": (r"a\)b|qcq", ("a)b", "qcq")),
    "hex_escape": (r"ab\x41", ("abA",)),
    "bracket_first_in_class": (r"x[]a]y", ("x]y", "xay")),
    "pipe_inside_class": (r"a[|]b", ("a|b",)),
    "scoped_flag_group": (r"(?i:sq)zzv", ("SQzzv",)),
    "atomic_group": (r"(?>ab|cd)efk", ("cdefk",)),
    "zero_repeat": (r"zz(?:yy){0}qk", ("zzqk",)),
    "possessive_group": (r"(?:xy)*+wqk", ("wqk", "xywqk")),
}


def _kv_with(alternative: str) -> re.Pattern[str]:
    original = rules_mod._KEY_VALUE_SECRET
    assert r"\b(" in original.pattern
    return re.compile(original.pattern.replace(r"\b(", rf"\b({alternative}|", 1), original.flags)


@pytest.mark.parametrize("suffix", _SUFFIXES, ids=["ascii", "non_ascii"])
@pytest.mark.parametrize("name", sorted(KV_SHAPES))
def test_r5_added_key_value_alternative_shape_is_applied(
    monkeypatch: pytest.MonkeyPatch, name: str, suffix: str,
) -> None:
    alternative, keys = KV_SHAPES[name]
    rule = _kv_with(alternative)
    _patch(monkeypatch, "_KEY_VALUE_SECRET", rule)
    failures: list[str] = []
    for key in keys:
        text = f"cfg {key}=s3cr3tvalue end{suffix}"
        found = rule.search(text)
        assert found is not None and found.group(1) == key, f"{name}: the rule itself must match key {key!r}"
        got = _filtered(text)
        if got != (f"cfg {key}={REDACTED} end{suffix}", 1):
            failures.append(f"{name}: {text!r} -> {got!r}")
    assert not failures, "\n".join(failures)


# ------------------------------------------------------------------------------------------------------------------
# Edit in place: a shipped rule replaced by a semantically wider variant of itself.
# ------------------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("suffix", _SUFFIXES, ids=["ascii", "non_ascii"])
def test_r5_wider_shipped_fixed_token_rule_redacts_new_matches(monkeypatch: pytest.MonkeyPatch, suffix: str) -> None:
    shipped = rules_mod._FIXED_TOKENS
    assert shipped[1].pattern == r"\bgh[pousr]_[A-Za-z0-9_]{16,}", "test assumes the shipped GitHub token rule"
    wider = re.compile(r"\bgh[pousrx]_[A-Za-z0-9_]{16,}")
    _patch(monkeypatch, "_FIXED_TOKENS", (shipped[0], wider, *shipped[2:]))
    for sample in ("ghx_abcdefghijklmnop", "ghp_abcdefghijklmnop"):  # new match, and the old one still redacted
        text = f"use {sample} now{suffix}"
        assert wider.fullmatch(sample)
        assert _filtered(text) == (f"use {REDACTED} now{suffix}", 1), text


@pytest.mark.parametrize("suffix", _SUFFIXES, ids=["ascii", "non_ascii"])
def test_r5_wider_shipped_key_value_rule_redacts_new_matches(monkeypatch: pytest.MonkeyPatch, suffix: str) -> None:
    rule = _kv_with(r"vault[_-]?pass")
    _patch(monkeypatch, "_KEY_VALUE_SECRET", rule)
    for key in ("vault-pass", "VAULT_PASS", "vaultpass", "password"):
        text = f"cfg {key}: s3cr3tvalue end{suffix}"
        assert rule.search(text)
        assert _filtered(text) == (f"cfg {key}: {REDACTED} end{suffix}", 1), text


_PREFIXES = ("", "\u00fc ")


@pytest.mark.parametrize("prefix", _PREFIXES, ids=["ascii", "non_ascii"])
@pytest.mark.parametrize(
    "alternative",
    ["x-api-auth", "(?:sq|sr)*x-zauth"],
    ids=["extra_name", "quantified_group"],
)
def test_r5_wider_shipped_auth_header_rule_redacts_new_matches(
    monkeypatch: pytest.MonkeyPatch, alternative: str, prefix: str,
) -> None:
    original = rules_mod._AUTH_HEADER
    assert "(authorization|" in original.pattern
    rule = re.compile(original.pattern.replace("(authorization|", f"({alternative}|authorization|", 1), original.flags)
    _patch(monkeypatch, "_AUTH_HEADER", rule)
    for name in ("X-Api-Auth", "x-zauth") if alternative == "x-api-auth" else ("x-zauth", "sqx-zauth"):
        text = f"{prefix}hdr {name}: abc123def"
        found = rule.search(text)
        if found is None:
            continue  # this spelling belongs to the other parametrization
        assert found.group(1).lower() == name.lower()
        assert _filtered(text) == (f"{prefix}hdr {name}: {REDACTED}", 1), text
    # The shipped spelling keeps working under the edited rule.
    assert _filtered(f"{prefix}hdr Authorization: abc123def") == (f"{prefix}hdr Authorization: {REDACTED}", 1)


@pytest.mark.parametrize("prefix", _PREFIXES, ids=["ascii", "non_ascii"])
@pytest.mark.parametrize(
    ("alternative", "scheme"),
    [("apikey", "ApiKey"), ("(?:sq|sr)*zkey", "zkey")],
    ids=["extra_name", "quantified_group"],
)
def test_r5_wider_shipped_auth_scheme_rule_redacts_new_matches(
    monkeypatch: pytest.MonkeyPatch, alternative: str, scheme: str, prefix: str,
) -> None:
    original = rules_mod._AUTH_SCHEME
    assert "(bearer|" in original.pattern
    rule = re.compile(original.pattern.replace("(bearer|", f"({alternative}|bearer|", 1), original.flags)
    _patch(monkeypatch, "_AUTH_SCHEME", rule)
    text = f"{prefix}use {scheme} abcdefgh12 now"
    found = rule.search(text)
    assert found is not None and found.group(1) == scheme
    assert _filtered(text) == (f"{prefix}use {scheme} {REDACTED} now", 1), text
    assert _filtered(f"{prefix}use Bearer abcdefgh12 now") == (f"{prefix}use Bearer {REDACTED} now", 1)
