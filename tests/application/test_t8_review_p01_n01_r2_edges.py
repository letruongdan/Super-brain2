"""T8-P01-N01 round 2: edge components at the start or end of a wrapped token follow §14.2 exactly.

Requirement: system design §14.2 "Mẫu đường dẫn trong SP1" (empty and ``.`` components are dropped, a chain matches a
window of consecutive components) with the "any trimmed spelling" definition encoded by the brute-force reference
``_reference_outcomes`` of ``test_t8_review_p01_r3_spellings.py``.

Two shapes no earlier oracle reached:

* a trimmed edge that leaves a bare ``.`` component (``\\`./ab``, ``ab/.\\```): that ``.`` is dropped, so a pattern
  that matches ``.`` (``[.]``, ``?``, ``[.!]``) must not block the token through it (over-redaction direction);
* a chain whose first (or last) component matches only a partially trimmed edge while its window ends (or starts) in
  the middle of the token (``\\`a/b`` with ``\\`\\`a/b/c``).

Each case is checked against the reference in ASCII and non-ASCII text, bare and under the r3 wrapper grid, with
positive twins for the negative cases and near misses for the positive ones.
"""

from __future__ import annotations

import pytest

from superbrain.application.privacy import PrivacyFilter
from superbrain.core.kernel import DEFAULT_BLOCKED_PATH_PATTERNS, FilterPolicy
from tests.application.test_t8_review_p01_r3_spellings import (
    _SUFFIXES,
    REDACTED,
    _reference,
    _reference_outcomes,
    _wrapped,
)


def _policy(patterns: tuple[str, ...]) -> FilterPolicy:
    return FilterPolicy(blocked_path_patterns=patterns, entropy_min_length=4096)


def _check(texts: list[str], patterns: tuple[str, ...]) -> None:
    for suffix in _SUFFIXES:
        batch = [text + suffix for text in texts]
        expected = [_reference(text, patterns) for text in batch]
        safe = PrivacyFilter().apply(list(batch), _policy(patterns))  # a bare list: no key to strip
        assert isinstance(safe.value, list) and len(safe.value) == len(batch)
        wrong = [
            f"{text!r} -> {actual!r}, expected one of {sorted(forms)[:4]!r}"
            for text, actual, (forms, _count) in zip(batch, safe.value, expected, strict=True)
            if actual not in forms
        ]
        assert not wrong, f"{len(wrong)} of {len(batch)} texts for {patterns!r}:\n" + "\n".join(wrong[:25])
        assert safe.redacted_count == sum(count for _forms, count in expected)


# (pattern, token, exact filtered token). ``None``: no spelling is blocked, the token stays.
_DOT_EDGES: list[tuple[str, str, str | None]] = [
    ("[.]", "`./ab", None),
    ("[.]", "*./ab", None),
    ("[.]", "ab/.`", None),
    ("[.]", "ab/.!", None),
    ("[.]", "`ab/.:", None),
    ("?", "`./ab", None),
    ("?", "ab/.?", None),
    ("[.!]", "`./ab", None),
    ("[.!]", "ab/.*", None),
    ("[.]/ab", "`./ab", None),
    ("ab/[.]", "ab/.!", None),
    # positive twins: the same shapes with a kept, non-dot edge component
    ("[.!]", "`!/ab", "`" + REDACTED),
    ("?", "`x/ab", "`" + REDACTED),
    ("[.]", "`ab/..", None),
    ("?", "ab/x`", REDACTED + "`"),
    ("[!a-z]", "ab/!.", REDACTED + "."),
]

_MIDDLE_WINDOWS: list[tuple[str, str, str | None]] = [
    ("`a/b", "``a/b/c", "`" + REDACTED),
    ("``a/b", "```a/b/c", "`" + REDACTED),
    ("`a/b/c", "``a/b/c/d", "`" + REDACTED),
    ("?a/b", "``a/b/c", "`" + REDACTED),
    ("[`]a/b", "*`a/b/c", "*" + REDACTED),
    ("b/c`", "a/b/c``", REDACTED + "`"),
    ("b/c?", "a/b/c!.", REDACTED + "."),
    # near misses: the window would need a middle component that is not there
    ("`a/b", "``a/x/c", None),
    ("`a/b", "``ab/c", None),
    ("b/c`", "a/b/x``", None),
]
_CASES = _DOT_EDGES + _MIDDLE_WINDOWS
_IDS = [f"{pattern}|{token}" for pattern, token, _exact in _CASES]


@pytest.mark.parametrize(("pattern", "token", "exact"), _CASES, ids=_IDS)
def test_n01_r2_fixture_agrees_with_the_reference(pattern: str, token: str, exact: str | None) -> None:
    assert _reference_outcomes(token, (pattern,)) == (frozenset() if exact is None else {exact})


@pytest.mark.parametrize(("pattern", "token", "exact"), _CASES, ids=_IDS)
@pytest.mark.parametrize("suffix", ["", " über"], ids=["ascii", "non_ascii"])  # one-char "ü" would match "?"
def test_n01_r2_edge_token_has_the_exact_outcome(pattern: str, token: str, exact: str | None, suffix: str) -> None:
    text = f"see {token} now{suffix}"
    safe = PrivacyFilter().apply({"note": text}, _policy((pattern,)))
    if exact is None:
        assert safe.value == {"note": text} and safe.redacted_count == 0
    else:
        assert safe.value == {"note": f"see {exact} now{suffix}"} and safe.redacted_count == 1


@pytest.mark.parametrize(("pattern", "token", "exact"), _CASES, ids=_IDS)
def test_n01_r2_edge_token_matches_the_reference_under_every_wrapper_combination(
    pattern: str, token: str, exact: str | None
) -> None:
    _check(_wrapped(token), (pattern,))
    _check(_wrapped(token)[::7], (*DEFAULT_BLOCKED_PATH_PATTERNS, pattern))


def test_n01_r2_both_directions_are_represented() -> None:
    assert sum(exact is None for _p, _t, exact in _CASES) >= 10
    assert sum(exact is not None for _p, _t, exact in _CASES) >= 10
