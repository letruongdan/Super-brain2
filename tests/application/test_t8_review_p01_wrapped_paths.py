"""T8-P01: an accepted blocked-path pattern is enforced whatever punctuation the text puts around the token.

Requirement: system design §14.2 "Mẫu đường dẫn trong SP1". A pattern is compared with each path component by
glob after lowercasing; ``/`` and ``\\`` separate components; empty components and ``.`` are dropped, ``..`` is
kept; a one-component pattern matches at any position and a multi-component pattern matches a run of consecutive
components. When punctuation around a token is handled, the original spelling must still be checked, so that
patterns such as ``..``, ``vault.`` or ``vault?`` are enforced.

Invariant: whether a blocked path is redacted does not depend on which surrounding punctuation the text puts
around it.

The expectation is computed here from the specification with ``fnmatch`` (``_spec_blocked``), never from the
product matcher. Only the two wrapper character sets are read from the product at runtime, as the review asked.

What must be replaced. A token is a maximal run of characters that are not scanner boundaries (§14.2: whitespace,
quotes, ``< > | ( ) { } , ;`` and square brackets). A *spelling* of a token is the token minus a prefix made of
leading-wrapper characters and a suffix made of trailing-wrapper characters. If any spelling is blocked the token
is redacted exactly once:

* when the fully stripped spelling is blocked, exactly that spelling is replaced and every wrapper character is
  kept (already sealed by ``test_r01_matched_core_keeps_markdown_wrapper_punctuation``);
* otherwise §14.2 does not say which blocked spelling wins, so replacing any one blocked spelling is accepted;
  wrapper characters outside the replaced spelling are kept.

A token with no blocked spelling is unchanged and adds nothing to ``redacted_count``.

Wrapper grids. The full grid is every combination of 0-2 leading and 0-2 trailing wrapper characters (15 403
texts with today's sets); it runs once per edge pattern on ASCII text. Every other run (non-ASCII text, further
tokens, shipped defaults, near misses) uses the reduced grid, which drops only the two-character wrappers whose
character next to the token is a §14.2 boundary: there the outer character is cut off into a token of its own, so
the text adds nothing over the one-character wrapper. This keeps the file inside the gate's time budget.
"""

from __future__ import annotations

import fnmatch
import functools
import itertools
import re
from collections.abc import Iterator

import pytest

import superbrain.application._privacy_rules as rules_mod
from superbrain.application.privacy import PrivacyFilter
from superbrain.core.kernel import DEFAULT_BLOCKED_PATH_PATTERNS, FilterPolicy

REDACTED = "[redacted]"
LEAD: str = rules_mod._PATH_LEAD
TRAIL: str = rules_mod._PATH_TRAIL
_BOUNDARY = "\"'<>|(){},;[]"  # §14.2 scanner boundaries, plus whitespace
_TOKEN = re.compile(rf"[^\s{re.escape(_BOUNDARY)}]+")
_SEPARATOR = re.compile(r"[\\/]+")
_BATCH = 1000  # below the filter's 1024-item array limit
_SUFFIXES = ("", " ü")  # ASCII text, and text with a non-ASCII character elsewhere


def _components(path: str) -> list[str]:
    return [part for part in _SEPARATOR.split(path.lower()) if part and part != "."]


@functools.cache
def _spec_blocked(spelling: str, patterns: tuple[str, ...]) -> bool:
    parts = _components(spelling)
    for pattern in patterns:
        chain = _components(pattern)
        for start in range(len(parts) - len(chain) + 1):
            if all(fnmatch.fnmatchcase(p, g) for p, g in zip(parts[start : start + len(chain)], chain, strict=True)):
                return True
    return False


@functools.cache
def _token_outcomes(token: str, patterns: tuple[str, ...]) -> frozenset[str] | None:
    """Acceptable replacements of one token, or ``None`` when no spelling of it is blocked."""
    lead_max = len(token) - len(token.lstrip(LEAD))
    trail_max = len(token) - len(token.rstrip(TRAIL))
    core = token.lstrip(LEAD)
    lead = len(token) - len(core)
    core = core.rstrip(TRAIL)
    if core and _spec_blocked(core, patterns):
        return frozenset({token[:lead] + REDACTED + token[lead + len(core) :]})
    outcomes = frozenset(
        token[:start] + REDACTED + token[stop:]
        for start in range(lead_max + 1)
        for stop in range(len(token) - trail_max, len(token) + 1)
        if start < stop and _spec_blocked(token[start:stop], patterns)
    )
    return outcomes or None


def _expected(text: str, patterns: tuple[str, ...]) -> tuple[set[str], int]:
    """Every acceptable filtered form of ``text`` and the exact number of redactions."""
    pieces: list[frozenset[str] | set[str]] = []
    cursor = count = 0
    for match in _TOKEN.finditer(text):
        pieces.append({text[cursor : match.start()]})
        outcomes = _token_outcomes(match.group(0), patterns)
        count += outcomes is not None
        pieces.append(outcomes or {match.group(0)})
        cursor = match.end()
    pieces.append({text[cursor:]})
    return {"".join(parts) for parts in itertools.product(*pieces)}, count


def _wrappers(chars: str, *, inner: int, full: bool) -> list[str]:
    """No wrapper, each character, each pair; ``inner`` is the index of a pair's character next to the token."""
    pairs = (a + b for a in chars for b in chars)
    return ["", *chars, *(pair for pair in pairs if full or pair[inner] not in _BOUNDARY)]


def _wrapped(base: str, *, full: bool = False) -> Iterator[str]:
    """``base`` bare and inside the combinations of 0-2 leading and 0-2 trailing wrapper characters."""
    for lead in _wrappers(LEAD, inner=1, full=full):
        for trail in _wrappers(TRAIL, inner=0, full=full):
            yield f"see {lead}{base}{trail} now"


def _policy(patterns: tuple[str, ...]) -> FilterPolicy:
    return FilterPolicy(blocked_path_patterns=patterns, entropy_min_length=4096)  # entropy cannot mask a miss


def _apply(texts: list[str], policy: FilterPolicy) -> tuple[list[str], int]:
    got: list[str] = []
    redacted = 0
    for start in range(0, len(texts), _BATCH):
        safe = PrivacyFilter().apply({"items": list(texts[start : start + _BATCH]), "ok": "safe prose kept"}, policy)
        assert isinstance(safe.value, dict) and safe.value["ok"] == "safe prose kept"  # positive control
        assert safe.stripped_keys_count == 0
        items = safe.value["items"]
        assert isinstance(items, list) and len(items) == len(texts[start : start + _BATCH])
        got += [str(item) for item in items]
        redacted += safe.redacted_count
    return got, redacted


def _check(
    texts: list[str], patterns: tuple[str, ...], *, want_blocked: bool, suffixes: tuple[str, ...] = _SUFFIXES
) -> None:
    policy = _policy(patterns)
    for suffix in suffixes:
        batch = [text + suffix for text in texts]
        expected = [_expected(text, patterns) for text in batch]
        for text, (_forms, count) in zip(batch, expected, strict=True):
            assert (count >= 1) is want_blocked, f"oracle fixture is on the wrong side: {text!r}"
        got, redacted = _apply(batch, policy)
        wrong = [
            f"{text!r} -> {actual!r}, expected one of {sorted(forms)!r}"
            for text, actual, (forms, _count) in zip(batch, got, expected, strict=True)
            if actual not in forms
        ]
        assert not wrong, f"{len(wrong)} of {len(batch)} texts for {patterns!r}:\n" + "\n".join(wrong[:25])
        assert redacted == sum(count for _forms, count in expected)


# (pattern, tokens it blocks). Components begin or end with characters of the wrapper sets.
_EDGE_CASES: list[tuple[str, tuple[str, ...]]] = [
    ("vault?", ("vault?", "vault.", "VaultX")),
    ("vault.", ("vault.", "VAULT.")),
    ("..", ("..", "../notes")),
    ("vault!", ("vault!",)),
    ("vault:", ("vault:",)),
    ("a.b.", ("a.b.", "repo/a.b.")),
    ("*vault", ("*vault", "myvault")),
    ("vault*", ("vault*", "vault.")),
    ("`vault", ("`vault",)),
    ("vault`", ("vault`",)),
    ("conf/prod.", ("conf/prod.", "repo\\conf\\prod.")),
    ("conf./prod", ("conf./prod",)),
    ("*.d/vault?", ("x.d/vault!",)),
]


def test_p01_wrapper_sets_cover_the_reported_punctuation() -> None:
    # The oracles below iterate the runtime sets; an emptied set would make them vacuous.
    assert set("`*") <= set(LEAD) and set("`*.,:;!?") <= set(TRAIL)
    full, reduced = len(list(_wrapped("x", full=True))), len(list(_wrapped("x")))
    assert full == (1 + len(LEAD) + len(LEAD) ** 2) * (1 + len(TRAIL) + len(TRAIL) ** 2)
    assert full >= reduced >= 7 * 43  # at least the backtick/star leads and the sentence-punctuation trails


@pytest.mark.parametrize(
    ("pattern", "text", "expected"),
    [
        ("vault?", "see vault? now", "see [redacted] now"),
        ("vault?", "see `vault?` now", "see `[redacted]` now"),
        ("vault?", "see vault?. now", "see [redacted]. now"),
        ("vault?", "see *vault?* now", "see *[redacted]* now"),
        ("vault.", "see vault.. now", "see [redacted]. now"),
        ("vault.", "see `vault.` now", "see `[redacted]` now"),
        ("..", "cd `..` now", "cd `[redacted]` now"),
        ("..", "cd **..** now", "cd **[redacted]** now"),
        ("vault!", 'see "vault!", now', 'see "[redacted]", now'),
        ("conf/prod.", "see `conf/prod.`: now", "see `[redacted]`: now"),
    ],
)
@pytest.mark.parametrize("suffix", _SUFFIXES, ids=["ascii", "non_ascii"])
def test_p01_reported_wrapped_token_is_redacted_and_keeps_its_wrapper(
    pattern: str, text: str, expected: str, suffix: str
) -> None:
    # In each of these texts exactly one spelling is blocked, so the result is fixed by §14.2.
    assert _expected(text + suffix, (pattern,)) == ({expected + suffix}, 1)
    safe = PrivacyFilter().apply({"note": text + suffix, "ok": "safe prose kept"}, _policy((pattern,)))
    assert safe.value == {"note": expected + suffix, "ok": "safe prose kept"}
    assert safe.redacted_count == 1 and safe.stripped_keys_count == 0


@pytest.mark.parametrize(("pattern", "tokens"), _EDGE_CASES, ids=[case[0] for case in _EDGE_CASES])
def test_p01_edge_punctuation_pattern_is_enforced_under_every_wrapper_combination(
    pattern: str, tokens: tuple[str, ...]
) -> None:
    for token in tokens:
        assert _spec_blocked(token, (pattern,)), (pattern, token)
        _check(list(_wrapped(token)), (pattern,), want_blocked=True)
    _check(list(_wrapped(tokens[0], full=True)), (pattern,), want_blocked=True, suffixes=("",))


@pytest.mark.parametrize(("pattern", "tokens"), _EDGE_CASES[:6], ids=[case[0] for case in _EDGE_CASES[:6]])
def test_p01_edge_punctuation_pattern_is_enforced_next_to_the_shipped_defaults(
    pattern: str, tokens: tuple[str, ...]
) -> None:
    _check(list(_wrapped(tokens[0])), (*DEFAULT_BLOCKED_PATH_PATTERNS, pattern), want_blocked=True)


def _default_token(pattern: str) -> str:
    token = "repo/" + pattern.replace("*", "prod").rstrip("/") + ("/config" if pattern.endswith("/") else "")
    assert _spec_blocked(token, (pattern,)), (pattern, token)
    return token


@pytest.mark.parametrize("pattern", DEFAULT_BLOCKED_PATH_PATTERNS)
def test_p01_control_shipped_default_pattern_is_enforced_under_every_wrapper_combination(pattern: str) -> None:
    _check(list(_wrapped(_default_token(pattern))), DEFAULT_BLOCKED_PATH_PATTERNS, want_blocked=True)


_NEAR_MISSES: list[tuple[str, tuple[str, ...]]] = [
    ("vault?", ("vault", "vaul?", "vaultxy", "xvault?", "vault/x")),
    ("vault.", ("vault", "vaultx", "vault.x", "xvault.", "vault?")),
    ("..", (".", "a..b", "x.", ".x", "...x")),
    ("vault!", ("vault", "vault?", "vault!x")),
    ("a.b.", ("a.b", "a.b.c", "xa.b.")),
    ("conf/prod.", ("conf/prod", "conf/x/prod.", "prod./conf", "conf/prod.x")),
    ("*.d/vault?", ("x.d/vault", "x.e/vault!")),
]


@pytest.mark.parametrize(("pattern", "tokens"), _NEAR_MISSES, ids=[case[0] for case in _NEAR_MISSES])
def test_p01_near_miss_stays_under_every_wrapper_combination_with_a_blocked_twin(
    pattern: str, tokens: tuple[str, ...]
) -> None:
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
    # Positive twin: the same policy still redacts the bare blocked token.
    twin = next(blocked for case, blocked in _EDGE_CASES if case == pattern)[0]
    assert _apply([f"see {twin} now"], _policy(patterns)) == (["see [redacted] now"], 1)


def test_p01_default_policy_near_misses_stay_under_every_wrapper_combination() -> None:
    kept = [text for token in ("repo/env", "id_rsa_notes", "server.pemx", "ssh/config") for text in _wrapped(token)]
    _check(kept, DEFAULT_BLOCKED_PATH_PATTERNS, want_blocked=False)
    assert _apply(["see repo/.env now"], _policy(DEFAULT_BLOCKED_PATH_PATTERNS)) == (["see [redacted] now"], 1)
