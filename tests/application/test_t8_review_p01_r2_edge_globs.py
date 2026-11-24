"""T8-P01 round 2: a glob at the edge of a pattern component may need wrapper punctuation kept in the match.

Requirement and invariant as in ``test_t8_review_p01_wrapped_paths.py`` (system design §14.2 "Mẫu đường dẫn trong
SP1"): whether a blocked path is redacted does not depend on the punctuation the text puts around it. The oracle,
wrapper grids and expected forms are reused from that file and stay computed from §14.2 with ``fnmatch``.

This file covers component edges made of glob syntax rather than literal punctuation, where a match must consume
one or more wrapper characters that are not part of the fully stripped token:

* a one-character glob ``?`` at the leading edge (``?`` is not a leading-wrapper character), alone, doubled, and
  behind or before a ``*``;
* a character class ``[...]`` at either edge, including negated classes;
* a ``*`` in front of (or behind) a literal wrapper character, which can match nothing, so the wrapper character
  after it must still be kept.

Each shape has exact expectations where one spelling alone is blocked, the full wrapper grid, ASCII and non-ASCII
text, a run next to the shipped defaults, and near misses with a positive twin.
"""

from __future__ import annotations

import pytest

from superbrain.core.kernel import DEFAULT_BLOCKED_PATH_PATTERNS
from tests.application.test_t8_review_p01_wrapped_paths import (
    _REUSABLE_FILTER,
    _SUFFIXES,
    LEAD,
    TRAIL,
    _apply,
    _check,
    _expected,
    _policy,
    _spec_blocked,
    _wrapped,
)

# (pattern, tokens it blocks only when a wrapper character next to the token is kept)
_GLOB_EDGES: list[tuple[str, tuple[str, ...]]] = [
    ("?vault", ("`vault", "*vault")),
    ("??vault", ("``vault", "*`vault")),
    ("*?vault", ("`vault",)),
    ("?*`vault", ("*`vault", "**`vault")),
    ("[`]vault", ("`vault",)),
    ("[*`]vault", ("*vault", "`vault")),
    ("[!a-z]vault", ("*vault", "`vault")),
    ("vault[.!]", ("vault.", "vault!")),
    ("vault[!a-z]", ("vault?", "vault:")),
    ("[`]conf/prod", ("`conf/prod",)),
    ("*`vault", ("`vault",)),
    ("`*vault", ("`vault",)),
    ("vault`*", ("vault`",)),
    ("vault*`", ("vault`",)),
    ("vault?*", ("vault.", "vault?")),
    ("*`*vault", ("`vault",)),
]
_IDS = [case[0] for case in _GLOB_EDGES]


def test_p01_r2_glob_edges_need_a_kept_wrapper_character() -> None:
    # Each fixture is blocked as spelled, while its fully stripped core is not: the match needs the wrapper.
    for pattern, tokens in _GLOB_EDGES:
        for token in tokens:
            core = token.lstrip(LEAD).rstrip(TRAIL)
            assert _spec_blocked(token, (pattern,)) and not _spec_blocked(core, (pattern,)), (pattern, token)


@pytest.mark.parametrize(
    ("pattern", "text", "expected"),
    [
        ("?vault", "see ``vault now", "see `[redacted] now"),
        ("?vault", "see *`vault. now", "see *[redacted]. now"),
        ("??vault", "see ```vault now", "see `[redacted] now"),
        ("*?vault", "see `vault: now", "see [redacted]: now"),
        ("[`]vault", "see *`vault* now", "see *[redacted]* now"),
        ("[!a-z]vault", "see **vault? now", "see *[redacted]? now"),
        ("vault[.!]", "see vault.: now", "see [redacted]: now"),
        ("vault[.!]", "see `vault!` now", "see `[redacted]` now"),
        ("vault[!a-z]", "see *vault?* now", "see *[redacted]* now"),
        ("[`]conf/prod", "see `conf/prod. now", "see [redacted]. now"),
        ("*`vault", "see `vault. now", "see [redacted]. now"),
        ("`*vault", "see *`vault now", "see *[redacted] now"),
        ("vault`*", "see *vault` now", "see *[redacted] now"),
        ("vault*`", "see vault`. now", "see [redacted]. now"),
        ("vault?*", "see *vault. now", "see *[redacted] now"),
    ],
)
@pytest.mark.parametrize("suffix", _SUFFIXES, ids=["ascii", "non_ascii"])
def test_p01_r2_glob_edge_token_is_redacted_and_keeps_the_other_wrappers(
    pattern: str, text: str, expected: str, suffix: str
) -> None:
    # Exactly one spelling of the token is blocked here, so the result is fixed by §14.2.
    assert _expected(text + suffix, (pattern,)) == ({expected + suffix}, 1)
    safe = _REUSABLE_FILTER.apply({"note": text + suffix, "ok": "safe prose kept"}, _policy((pattern,)))
    assert safe.value == {"note": expected + suffix, "ok": "safe prose kept"}
    assert safe.redacted_count == 1 and safe.stripped_keys_count == 0


@pytest.mark.parametrize(("pattern", "tokens"), _GLOB_EDGES, ids=_IDS)
def test_p01_r2_glob_edge_pattern_is_enforced_under_every_wrapper_combination(
    pattern: str, tokens: tuple[str, ...]
) -> None:
    for token in tokens:
        _check(list(_wrapped(token)), (pattern,), want_blocked=True)
    _check(list(_wrapped(tokens[0], full=True)), (pattern,), want_blocked=True, suffixes=("",))


@pytest.mark.parametrize(("pattern", "tokens"), _GLOB_EDGES, ids=_IDS)
def test_p01_r2_glob_edge_pattern_is_enforced_next_to_the_shipped_defaults(
    pattern: str, tokens: tuple[str, ...]
) -> None:
    _check(list(_wrapped(tokens[0])), (*DEFAULT_BLOCKED_PATH_PATTERNS, pattern), want_blocked=True)


_GLOB_NEAR_MISSES: list[tuple[str, tuple[str, ...]]] = [
    ("?vault", ("vaultx", "vaul", "ab\\vaultz")),
    ("??vault", ("vaultx", "xvaultx")),
    ("[`]vault", ("vaultx", "avault", "*vaultx")),
    ("[!a-z]vault", ("avault", "vaultx")),
    ("vault[.!]", ("vaulta", "vault?x", "xvault.x")),
    ("vault[!a-z]", ("vaulta", "vault/x")),
    ("[`]conf/prod", ("conf/prod.x", "`conf/x/prod")),
    ("*`vault", ("vaultx", "x`vaulty")),
    ("vault`*", ("xvault", "avault`b")),
    ("vault?*", ("vaul", "xvault/")),
]


@pytest.mark.parametrize(("pattern", "tokens"), _GLOB_NEAR_MISSES, ids=[case[0] for case in _GLOB_NEAR_MISSES])
def test_p01_r2_glob_edge_near_miss_stays_with_a_blocked_twin(pattern: str, tokens: tuple[str, ...]) -> None:
    patterns = (pattern,)
    kept: list[str] = []
    for token in tokens:
        texts = [text for text in _wrapped(token) if _expected(text, patterns)[1] == 0]
        assert len(texts) >= 43, f"near miss {token!r} is blocked under most wrappers; pick another fixture"
        kept += texts
    for suffix in _SUFFIXES:
        batch = [text + suffix for text in kept]
        got, redacted = _apply(batch, _policy(patterns))
        changed = [f"{text!r} -> {actual!r}" for text, actual in zip(batch, got, strict=True) if actual != text]
        assert not changed, f"{len(changed)} near misses changed for {pattern!r}:\n" + "\n".join(changed[:25])
        assert redacted == 0
    twin = next(blocked for case, blocked in _GLOB_EDGES if case == pattern)[0]
    assert _apply([f"see {twin} now"], _policy(patterns)) == (["see [redacted] now"], 1)
