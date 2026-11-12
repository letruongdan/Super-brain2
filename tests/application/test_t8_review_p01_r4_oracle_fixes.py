"""T8-P01 round 4: corrected oracles for five sealed r3 nodes that no implementation of §14.2 can satisfy.

Supersedes (review must approve) in ``test_t8_review_p01_r3_spellings.py``:

* ``test_p01_r3_wrapper_only_edge_pattern_is_enforced_under_every_wrapper_combination[**]`` and ``[*?]``, and
  ``test_p01_r3_wrapper_only_edge_pattern_is_enforced_next_to_the_shipped_defaults[**]`` and ``[*?]``: a
  one-component pattern that matches every non-empty component also blocks the helper's control key ``ok`` and the
  words of its control value, so the helper's ``ok == CONTROL`` / ``stripped_keys_count == 0`` assertions are wrong
  for these patterns. Here the texts go in a top-level list (no key) and every item, the filler words included, is
  checked against the same brute-force reference.
* ``test_p01_r3_deadline_expiring_inside_the_path_phase_fails_closed_promptly``: the F3 invariant allows a fixed limit
  that fails closed with ``INVALID_INPUT`` at apply time too; the r3 node accepted it only at policy construction,
  and its token was over any reasonable per-token limit. Here the deadline is exercised with tokens whose search is
  slow but small (61 x 61 spellings), and the limit is pinned separately.

Invariants unchanged: a token with a blocked spelling is redacted (F1); all filter work is bounded by a fixed limit or
by the shared deadline and running out of either fails closed, never returning a blocked spelling (F3).
"""

from __future__ import annotations

import time

import pytest

from superbrain.application.privacy import PrivacyFilter
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
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


# ------------------------------------------------------------------------------------------------------------------
# match-all one-component patterns
# ------------------------------------------------------------------------------------------------------------------

_MATCH_ALL: list[tuple[str, tuple[str, ...]]] = [
    ("**", ("**", "``", "`*`", "plain")),
    ("*?", ("`", "*", "plain")),
    ("*", ("``", "`*.", "plain")),
]


def _check_list(texts: list[str], patterns: tuple[str, ...]) -> None:
    for suffix in _SUFFIXES:
        batch = [text + suffix for text in texts]
        expected = [_reference(text, patterns) for text in batch]
        assert all(count >= 1 for _forms, count in expected)  # every fixture holds a blocked token
        safe = PrivacyFilter().apply(list(batch), _policy(patterns))
        assert isinstance(safe.value, list) and len(safe.value) == len(batch)
        wrong = [
            f"{text!r} -> {actual!r}, expected one of {sorted(forms)[:4]!r}"
            for text, actual, (forms, _count) in zip(batch, safe.value, expected, strict=True)
            if actual not in forms
        ]
        assert not wrong, f"{len(wrong)} of {len(batch)} texts for {patterns!r}:\n" + "\n".join(wrong[:25])
        assert safe.redacted_count == sum(count for _forms, count in expected)
        assert safe.stripped_keys_count == 0


@pytest.mark.parametrize(("pattern", "tokens"), _MATCH_ALL, ids=[case[0] for case in _MATCH_ALL])
def test_p01_r4_match_all_pattern_redacts_every_token_under_every_wrapper_combination(
    pattern: str, tokens: tuple[str, ...]
) -> None:
    for token in tokens:
        assert _reference_outcomes(token, (pattern,)), (pattern, token)
        _check_list(_wrapped(token), (pattern,))


@pytest.mark.parametrize(("pattern", "tokens"), _MATCH_ALL, ids=[case[0] for case in _MATCH_ALL])
def test_p01_r4_match_all_pattern_redacts_every_token_next_to_the_shipped_defaults(
    pattern: str, tokens: tuple[str, ...]
) -> None:
    _check_list(_wrapped(tokens[0]), (*DEFAULT_BLOCKED_PATH_PATTERNS, pattern))


def test_p01_r4_match_all_pattern_exact_output() -> None:
    # Every token of the text is a single non-empty component; wrappers outside the replaced spelling stay.
    for suffix in _SUFFIXES:
        safe = PrivacyFilter().apply(["see `**` now" + suffix], _policy(("**",)))
        forms, count = _reference("see `**` now" + suffix, ("**",))
        assert isinstance(safe.value, list) and safe.value[0] in forms
        assert "**" not in str(safe.value[0]) and str(safe.value[0]).startswith(f"{REDACTED} ")
        assert safe.redacted_count == count == 3 + bool(suffix)


# ------------------------------------------------------------------------------------------------------------------
# F3: deadline inside the path phase, and the fixed per-token limit
# ------------------------------------------------------------------------------------------------------------------

_SLOW_PATTERN = "?" * 300 + "[z]"  # no literal needle: every token reaches the spelling search
_SLOW_MISS = "`" * 60 + "a" * 200 + "!" * 60  # 61 x 61 spellings, none ends in z
_SMALL_HIT = "`" * 60 + "b" * 240 + "z" + "!" * 60  # 61 x 61 spellings, only "`"*60 + "b"*240 + "z" is blocked
_HUGE_HIT = "`" * 300 + "z" + "!" * 300  # 301 x 301 spellings, only "`"*300 + "z" is blocked


def _outcome(payload: JsonValue, policy: FilterPolicy, **kwargs: int) -> tuple[JsonValue | BrainError, int, float]:
    start = time.perf_counter()
    try:
        safe = PrivacyFilter().apply(payload, policy, **kwargs)
    except BrainError as error:
        assert REDACTED not in str(error) and "``" not in str(error)  # the error carries no input text
        return error, 0, time.perf_counter() - start
    return safe.value, safe.redacted_count, time.perf_counter() - start


def test_p01_r4_fixtures_are_on_the_right_side_of_the_reference() -> None:
    assert _reference_outcomes(_SLOW_MISS, (_SLOW_PATTERN,)) == frozenset()
    assert _reference_outcomes(_SMALL_HIT, (_SLOW_PATTERN,)) == {REDACTED + "!" * 60}
    assert _reference_outcomes(_HUGE_HIT, (_SLOW_PATTERN,)) == {REDACTED + "!" * 300}


def test_p01_r4_deadline_expiring_inside_the_path_phase_fails_closed_promptly() -> None:
    policy = _policy((_SLOW_PATTERN,))
    text = " ".join([_SLOW_MISS] * 200)  # just under 64 KiB; seconds of spelling search without a deadline
    deadline = time.monotonic_ns() + 20_000_000  # 20 ms
    result, redacted, elapsed = _outcome({"note": text}, policy, deadline_ns=deadline)
    if isinstance(result, BrainError):
        assert result.code in (ErrorCode.DEADLINE_EXCEEDED, ErrorCode.INVALID_INPUT)
    else:  # finished inside the budget: then the result must be correct
        assert result == {"note": text} and redacted == 0
    assert elapsed < 0.25, f"deadline of 20 ms noticed only after {elapsed:.2f} s"


@pytest.mark.parametrize("suffix", _SUFFIXES, ids=["ascii", "non_ascii"])
def test_p01_r4_token_inside_the_limit_is_redacted_exactly(suffix: str) -> None:
    text = f"see {_SMALL_HIT} now{suffix}"
    result, redacted, _elapsed = _outcome({"note": text}, _policy((_SLOW_PATTERN,)))
    assert result == {"note": f"see {REDACTED}{'!' * 60} now{suffix}"} and redacted == 1


@pytest.mark.parametrize("suffix", _SUFFIXES, ids=["ascii", "non_ascii"])
def test_p01_r4_token_over_the_limit_is_refused_or_redacted_never_returned(suffix: str) -> None:
    text = f"see {_HUGE_HIT} now{suffix}"
    result, redacted, elapsed = _outcome({"note": text}, _policy((_SLOW_PATTERN,)))
    if isinstance(result, BrainError):
        assert result.code is ErrorCode.INVALID_INPUT
    else:
        assert result == {"note": f"see {REDACTED}{'!' * 300} now{suffix}"} and redacted == 1
    assert elapsed < 5.0
