"""T8-P01-N4: a spelling shorter than the glob's fixed head plus tail never matches a glob with ``*``.

Requirement: system design §14.2 "Mẫu đường dẫn trong SP1" (fnmatch per component) with the "any trimmed spelling"
definition encoded by ``_reference_outcomes`` of ``test_t8_review_p01_r3_spellings.py``. A ``*`` glob with ``h``
fixed units before its first star and ``t`` after its last star needs at least ``h + t`` characters, so head and tail
may not overlap. Near misses below have a head fit and a tail fit only where they overlap (``?*a`` on ``a!``,
``?a*a`` on ``\\`a!``, ``x/?*a`` on ``x/a!``, ``a*?/x`` on ``\\`a/x``), plus the adjacent variants: ``[!...]`` classes
in head and tail matching the same wrapper character, chains with star edges at both ends, star-only globs, and
all-wrapper tokens of length ``h + t - 1``. Each has a positive twin one character longer. Checked against the
reference bare and under the r3 wrapper grid, in ASCII and non-ASCII text.
"""

from __future__ import annotations

import pytest

from superbrain.application.privacy import PrivacyFilter
from superbrain.core.kernel import DEFAULT_BLOCKED_PATH_PATTERNS, FilterPolicy
from tests.application.test_t8_review_p01_r3_spellings import REDACTED, _reference, _reference_outcomes, _wrapped

_SUFFIXES = ("", " über")

# (pattern, near misses: no spelling reaches h + t without overlap, positive twins: {token: exact result})
_CASES: list[tuple[str, tuple[str, ...], dict[str, str]]] = [
    ("?*a", ("a!", "a", "a.!"), {"ba!": REDACTED + "!", "`a!": REDACTED + "!"}),
    ("?a*a", ("`a!", "aa", "`a`"), {"`aa!": REDACTED + "!", "baa": REDACTED}),
    ("?*?", ("`", "a", "!"), {"ab": REDACTED, "``": REDACTED}),
    ("??*?", ("``", "ab", "`a"), {"```": REDACTED, "abc": REDACTED}),
    ("x/?*a", ("x/a!", "x/a", "x/a.!"), {"x/ba!": REDACTED + "!", "x/ba": REDACTED}),
    ("a*?/x", ("`a/x", "a/x", "*a/x"), {"`ab/x": "`" + REDACTED, "ab/x": REDACTED}),
    ("[!z]*[!z]", ("`", "a", "z!"), {"`a": REDACTED, "ab": REDACTED}),
    ("[`]*[`]", ("`", "a`"), {"``": REDACTED, "`a`": REDACTED}),
    ("[!a]*a", ("a!", "a"), {"`a!": REDACTED + "!", "ba": REDACTED}),
    ("?*a/b*?", ("a/b!", "a/b"), {"ca/bc": REDACTED, "ca/b.": REDACTED}),
    ("?*a/m/b*?", ("a/m/b!", "`a/m/b"), {"ca/m/bd": REDACTED}),
    ("*", (".", "./.", "/"), {"a": REDACTED, "ab": REDACTED}),
    ("**", (".", "/"), {"a": REDACTED}),
]
_IDS = [case[0] for case in _CASES]


def _policy(patterns: tuple[str, ...]) -> FilterPolicy:
    return FilterPolicy(blocked_path_patterns=patterns, entropy_min_length=4096)


def _check(texts: list[str], patterns: tuple[str, ...]) -> None:
    for start in range(0, len(texts), 1000):  # below the filter's 1024-item array limit
        _check_batch(texts[start : start + 1000], patterns)


def _check_batch(texts: list[str], patterns: tuple[str, ...]) -> None:
    safe = PrivacyFilter().apply(list(texts), _policy(patterns))  # a bare list: no key a star glob would strip
    assert isinstance(safe.value, list) and len(safe.value) == len(texts)
    expected = [_reference(text, patterns) for text in texts]
    wrong = [
        f"{text!r} -> {actual!r}, expected one of {sorted(forms)[:3]!r}"
        for text, actual, (forms, _count) in zip(texts, safe.value, expected, strict=True)
        if actual not in forms
    ]
    assert not wrong, f"{len(wrong)} of {len(texts)} for {patterns[-1]!r}:\n" + "\n".join(wrong[:20])
    assert safe.redacted_count == sum(count for _forms, count in expected)


@pytest.mark.parametrize(("pattern", "near", "twins"), _CASES, ids=_IDS)
def test_n04_fixtures_agree_with_the_reference(pattern: str, near: tuple[str, ...], twins: dict[str, str]) -> None:
    for token in near:
        assert _reference_outcomes(token, (pattern,)) == frozenset(), (pattern, token)
    for token, exact in twins.items():
        assert _reference_outcomes(token, (pattern,)) == {exact}, (pattern, token)


@pytest.mark.parametrize(("pattern", "near", "twins"), _CASES, ids=_IDS)
@pytest.mark.parametrize("suffix", _SUFFIXES, ids=["ascii", "non_ascii"])
def test_n04_near_misses_stay_and_twins_are_redacted(
    pattern: str, near: tuple[str, ...], twins: dict[str, str], suffix: str
) -> None:
    tokens = [*near, *twins]
    safe = PrivacyFilter().apply([token + suffix for token in tokens], _policy((pattern,)))
    assert isinstance(safe.value, list)
    for token, item in zip(tokens, safe.value, strict=True):
        got = str(item).split(" ")[0]  # the token itself; a star glob may also redact the suffix word
        assert got == twins.get(token, token), (pattern, token, item)
    _check([f"see {token} now{suffix}" for token in tokens], (pattern,))


@pytest.mark.parametrize(("pattern", "near", "twins"), _CASES, ids=_IDS)
def test_n04_tokens_follow_the_reference_under_every_wrapper_combination(
    pattern: str, near: tuple[str, ...], twins: dict[str, str]
) -> None:
    for suffix in _SUFFIXES:
        texts = [text + suffix for token in (*near, *twins) for text in _wrapped(token)]
        _check(texts, (pattern,))
        _check(texts[::5], (*DEFAULT_BLOCKED_PATH_PATTERNS, pattern))
