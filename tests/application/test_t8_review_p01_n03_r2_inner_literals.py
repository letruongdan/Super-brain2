"""T8-P01-N3 round 2: a glob with literal units between its stars still needs those literals on a wrapped token.

Requirement: system design §14.2 "Mẫu đường dẫn trong SP1": each component is matched by its fnmatch glob, with the
"any trimmed spelling" definition encoded by ``_reference_outcomes`` of ``test_t8_review_p01_r3_spellings.py``.

Invariant: a token is blocked only when some spelling matches the whole glob; fitting the glob's head and tail is
not enough when literal units, ``?`` or classes sit between its stars (``*x*``, ``a*x*b``, ``*?x*``, ``[!z]*x*y``).
Near misses fit head and tail but lack the inner literal and must stay unchanged (over-redaction direction); positive
twins carry it. Single components, first and last edges of chains, ASCII and non-ASCII text, bare and under the r3
wrapper grid.
"""

from __future__ import annotations

import pytest

from superbrain.application.privacy import PrivacyFilter
from superbrain.core.kernel import DEFAULT_BLOCKED_PATH_PATTERNS, FilterPolicy
from tests.application.test_t8_review_p01_r3_spellings import _reference, _reference_outcomes, _wrapped

_SUFFIXES = ("", " über")  # no one-character component, so "?"-led globs cannot match the suffix itself

# (pattern, tokens some spelling of which matches, near misses: head and tail fit, the inner literal is missing)
_CASES: list[tuple[str, tuple[str, ...], tuple[str, ...]]] = [
    ("*x*", ("`x`", "ab/x!", "``axb"), ("``ab", "ab/cd!", "`*`")),
    ("a*x*b", ("`axb`", "`a-x-b!"), ("`ab`", "`a--b!", "a/b")),
    ("*?x*", ("`ax`", "**qx!"), ("`ab`", "**qy!")),
    ("[!z]*x*y", ("`axy`", "*a-x-y!"), ("`ay`", "`a-y!", "zxy!")),
    ("*x*y", ("`xy!", "`axby"), ("`ay!", "`aby")),
    ("*x*?", ("`xa!", "`axbc"), ("`ab!", "`abc")),
    ("*x*/c", ("``x/c", "`ax/c"), ("``ab/c", "`a/c")),
    ("c/*x*", ("c/x!!", "c/axb."), ("c/ab!!", "c/a.")),
    ("c/*x*/d", ("c/ax/d", "`c/ax/d!"), ("c/ab/d", "`c/ab/d!")),
    ("*`*", ("a`b", "`a`b`"), ("ab", "a/b")),
    ("*!*", ("ab!", "a!b"), ("ab", "a/b")),
]
_IDS = [case[0] for case in _CASES]


def _policy(patterns: tuple[str, ...]) -> FilterPolicy:
    return FilterPolicy(blocked_path_patterns=patterns, entropy_min_length=4096)


def _apply(texts: list[str], patterns: tuple[str, ...]) -> tuple[list[object], int]:
    safe = PrivacyFilter().apply(list(texts), _policy(patterns))  # a bare list: no key to strip
    assert isinstance(safe.value, list) and len(safe.value) == len(texts)
    return list(safe.value), safe.redacted_count


@pytest.mark.parametrize(("pattern", "blocked", "near"), _CASES, ids=_IDS)
def test_n03_r2_fixtures_are_on_the_right_side_of_the_reference(
    pattern: str, blocked: tuple[str, ...], near: tuple[str, ...]
) -> None:
    for token in blocked:
        assert _reference_outcomes(token, (pattern,)), (pattern, token)
    for token in near:
        assert not _reference_outcomes(token, (pattern,)), (pattern, token)


@pytest.mark.parametrize(("pattern", "blocked", "near"), _CASES, ids=_IDS)
@pytest.mark.parametrize("suffix", _SUFFIXES, ids=["ascii", "non_ascii"])
def test_n03_r2_bare_tokens_follow_the_reference(
    pattern: str, blocked: tuple[str, ...], near: tuple[str, ...], suffix: str
) -> None:
    texts = [f"{token}{suffix}" for token in (*blocked, *near)]
    got, redacted = _apply(texts, (pattern,))
    expected = [_reference(text, (pattern,)) for text in texts]
    for text, actual, (forms, _count) in zip(texts, got, expected, strict=True):
        assert actual in forms, (pattern, text, actual, sorted(forms)[:4])
    for text, actual in zip(texts[len(blocked) :], got[len(blocked) :], strict=True):
        assert actual == text, f"near miss {text!r} redacted under {pattern!r}"  # inner literal missing
    assert redacted == sum(count for _forms, count in expected) and redacted >= len(blocked)


@pytest.mark.parametrize(("pattern", "blocked", "near"), _CASES, ids=_IDS)
def test_n03_r2_tokens_follow_the_reference_under_every_wrapper_combination(
    pattern: str, blocked: tuple[str, ...], near: tuple[str, ...]
) -> None:
    for patterns in ((pattern,), (*DEFAULT_BLOCKED_PATH_PATTERNS, pattern)):
        for suffix in _SUFFIXES:
            texts = [text + suffix for token in (*blocked, *near) for text in _wrapped(token)[::3]]
            got, redacted = _apply(texts, patterns)
            expected = [_reference(text, patterns) for text in texts]
            wrong = [
                f"{text!r} -> {actual!r}, expected one of {sorted(forms)[:3]!r}"
                for text, actual, (forms, _count) in zip(texts, got, expected, strict=True)
                if actual not in forms
            ]
            assert not wrong, f"{len(wrong)} of {len(texts)} for {patterns[-1]!r}:\n" + "\n".join(wrong[:20])
            assert redacted == sum(count for _forms, count in expected)


@pytest.mark.parametrize("suffix", _SUFFIXES, ids=["ascii", "non_ascii"])
def test_n03_r2_star_inner_wrapper_literal_never_matches_plain_words(suffix: str) -> None:
    # "*`*" needs a backtick in the component; plain words around the token have none.
    text = f"see ab now{suffix}"
    assert _reference(text, ("*`*",)) == ({text}, 0)
    assert _apply([text], ("*`*",)) == ([text], 0)
