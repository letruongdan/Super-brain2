"""Closure round C r2 oracles for D6 blocked paths: each pattern is enforced on its own, whatever else is listed.

Gap closed (owner mutant mc2): adding every extra pattern at once let one pattern that disables a prefilter for the
whole list mask a mishandled sibling. Here every pattern is checked alone (as a custom list and added alone to the
simulated shipped default), wide globs with no guaranteed literal are checked alone and mixed with the default, and
non-ASCII patterns are checked in ASCII-only and non-ASCII text. Expected values come from the independent
``reference_blocked`` rule (fnmatch per component, case-insensitive via ``str.lower``, ``/`` or ``\\`` separators).
"""

from __future__ import annotations

import pytest

from superbrain.application.privacy import PrivacyFilter
from superbrain.core.kernel import DEFAULT_BLOCKED_PATH_PATTERNS, FilterPolicy
from tests.application.test_t8_closure_privacy import (
    EXTRA_PATTERNS,
    INERT_PATTERN,
    REDACTED,
    _concrete_component,
    _set_shipped_default,
    matching_token,
    near_miss_tokens,
    path_cases,
    reference_blocked,
)

WIDE_PATTERNS: tuple[str, ...] = ("*", "?", "[0-9]", "[ab]*", "*/secret", "*/", "vault-*/")
NO_NEAR_MISS: frozenset[str] = frozenset({"*", "*/"})  # every component matches: no token can miss
NON_ASCII_PATTERNS: tuple[str, ...] = ("clé-privée.txt", "İnfo.txt", "Keyring.txt")

def _filtered(text: str, policy: FilterPolicy) -> tuple[object, int]:
    # A bare list: wide globs such as ``*`` also block object keys, so no keyed positive-control field is used here;
    # the near-miss cases are the positive controls.
    safe = PrivacyFilter().apply([text], policy)
    assert isinstance(safe.value, list) and len(safe.value) == 1
    return safe.value[0], safe.redacted_count


_CONTEXTS: tuple[tuple[str, ...], ...] = (("see", "now"), ("see", "now", "ü"))


def _expected(
    context: tuple[str, ...], fragment_out: str, active: tuple[str, ...], fragment_hit: int,
) -> tuple[str, int]:
    words = [context[0], fragment_out, *context[1:]]
    count = fragment_hit
    for index, word in enumerate(words):
        if index != 1 and reference_blocked(word, active):
            words[index] = REDACTED
            count += 1
    return " ".join(words), count


def _default_and_equivalent(extended: tuple[str, ...]) -> list[FilterPolicy]:
    equivalent = (*extended, INERT_PATTERN)
    return [FilterPolicy(blocked_path_patterns=extended), FilterPolicy(blocked_path_patterns=equivalent)]


def _check(pattern: str, active: tuple[str, ...], policies: list[FilterPolicy], *, extra_tokens: tuple[str, ...] = (),
           ascii_only: bool = False) -> list[str]:
    """Matching forms of ``pattern`` are redacted and near misses kept, identically under every policy given."""
    failures: list[str] = []
    tokens = (matching_token(pattern), *extra_tokens)
    cases: list[tuple[str, str, int]] = []
    for token in tokens:
        assert reference_blocked(token, active), f"generator produced a non-matching token for {pattern!r}"
        cases += [(fragment, expected, 1) for fragment, expected in path_cases(token)]
    misses = near_miss_tokens(pattern, active)
    if NO_NEAR_MISS.isdisjoint(active):
        assert misses, f"no near-miss control could be generated for {pattern!r}"
    cases += [(miss, miss, 0) for miss in misses]
    for fragment, fragment_out, hit in cases:
        for context in _CONTEXTS:
            text = " ".join([context[0], fragment, *context[1:]])
            if ascii_only and not text.isascii():
                continue
            want = _expected(context, fragment_out, active, hit)
            for policy in policies:
                got = _filtered(text, policy)
                if got != want:
                    failures.append(f"{pattern!r} in {active!r}: {text!r} -> {got!r}, expected {want!r}")
    return failures


# 1. Each extra pattern added ALONE to the simulated shipped default, and alone as a custom list.


@pytest.mark.parametrize("extra", EXTRA_PATTERNS)
def test_r2_each_extra_pattern_alone_in_shipped_default_is_enforced(
    monkeypatch: pytest.MonkeyPatch, extra: str,
) -> None:
    extended = (*DEFAULT_BLOCKED_PATH_PATTERNS, extra)
    _set_shipped_default(monkeypatch, extended)
    policies = _default_and_equivalent(extended)
    failures = _check(extra, extended, policies)
    for old in DEFAULT_BLOCKED_PATH_PATTERNS:
        failures += _check(old, extended, policies)
    assert not failures, "\n".join(failures)


@pytest.mark.parametrize("extra", EXTRA_PATTERNS)
def test_r2_each_extra_pattern_alone_as_custom_list_is_enforced(extra: str) -> None:
    alone = (extra,)
    failures = _check(extra, alone, [FilterPolicy(blocked_path_patterns=alone)])
    assert not failures, "\n".join(failures)


# 2. Patterns with no guaranteed literal, alone and mixed with the (simulated shipped) default.


@pytest.mark.parametrize("pattern", WIDE_PATTERNS)
def test_r2_wide_glob_alone_is_enforced(pattern: str) -> None:
    alone = (pattern,)
    failures = _check(pattern, alone, [FilterPolicy(blocked_path_patterns=alone)])
    assert not failures, "\n".join(failures)


@pytest.mark.parametrize("pattern", WIDE_PATTERNS)
def test_r2_wide_glob_mixed_with_shipped_default_is_enforced(monkeypatch: pytest.MonkeyPatch, pattern: str) -> None:
    extended = (*DEFAULT_BLOCKED_PATH_PATTERNS, pattern)
    _set_shipped_default(monkeypatch, extended)
    policies = _default_and_equivalent(extended)
    failures = _check(pattern, extended, policies)
    for old in DEFAULT_BLOCKED_PATH_PATTERNS:
        failures += _check(old, extended, policies)
    assert not failures, "\n".join(failures)


# 3. Non-ASCII patterns alone, in ASCII-only and non-ASCII text.


def _original_case_token(pattern: str) -> str:
    return "/".join(_concrete_component(part) for part in pattern.split("/") if part)


@pytest.mark.parametrize("pattern", NON_ASCII_PATTERNS)
def test_r2_non_ascii_pattern_alone_is_enforced(pattern: str) -> None:
    alone = (pattern,)
    failures = _check(pattern, alone, [FilterPolicy(blocked_path_patterns=alone)],
                      extra_tokens=(_original_case_token(pattern),))
    assert not failures, "\n".join(failures)


@pytest.mark.parametrize("pattern", NON_ASCII_PATTERNS)
def test_r2_non_ascii_pattern_alone_in_shipped_default_is_enforced(
    monkeypatch: pytest.MonkeyPatch, pattern: str,
) -> None:
    extended = (*DEFAULT_BLOCKED_PATH_PATTERNS, pattern)
    _set_shipped_default(monkeypatch, extended)
    policies = _default_and_equivalent(extended)
    failures = _check(pattern, extended, policies, extra_tokens=(_original_case_token(pattern),))
    assert not failures, "\n".join(failures)


def test_r2_kelvin_sign_pattern_redacts_its_ascii_lowercase_form_in_ascii_only_text() -> None:
    """``K`` lower-cases to ASCII ``k``: the ASCII spelling in pure-ASCII text matches case-insensitively."""
    pattern = "Keyring.txt"
    assert matching_token(pattern) == "keyring.txt"
    alone = (pattern,)
    failures = _check(pattern, alone, [FilterPolicy(blocked_path_patterns=alone)], ascii_only=True)
    assert not failures, "\n".join(failures)
    assert _filtered("see KEYRING.TXT now", FilterPolicy(blocked_path_patterns=alone)) == (f"see {REDACTED} now", 1)


@pytest.mark.parametrize("pattern", ["clé-privée.txt", "İnfo.txt"])
def test_r2_non_ascii_pattern_leaves_ascii_only_text_without_a_match_unchanged(pattern: str) -> None:
    policy = FilterPolicy(blocked_path_patterns=(pattern,))
    for text in ("see cle-privee.txt now", "see a/clé now".encode("ascii", "ignore").decode(), "plain prose kept"):
        assert text.isascii()
        assert not any(reference_blocked(word, (pattern,)) for word in text.split())
        assert _filtered(text, policy) == (text, 0)
