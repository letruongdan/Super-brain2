"""T8-P01 round 3: every punctuation-trimmed spelling of a token is checked, and the search stays bounded.

Requirement: system design §14.2 "Mẫu đường dẫn trong SP1". Components split on ``/`` and ``\\``; empty and ``.``
components are dropped, ``..`` is kept; a pattern matches a window of consecutive components after lowercasing.
When punctuation around a token is handled, the original spelling must still be checked if the trimmed one does
not match.

F1 invariant: if any spelling of a token is blocked, the token is redacted. A *spelling* is the token after removing
a prefix of its leading run of ``_PATH_LEAD`` characters and a suffix of its trailing run of ``_PATH_TRAIL``
characters, including removing nothing (the raw spelling). ``_reference_outcomes`` enumerates every such removal
literally; that brute force is the definition and never calls the product matcher. When exactly one spelling is
blocked the output is fixed; otherwise any one blocked spelling may be the one replaced (review ruling 2026-11-12),
the wrapper characters outside it stay, and ``redacted_count`` is one per blocked token.

F2: shapes that 3527a99 redacted and d9ee99b leaks are pinned with their exact texts.

F3 invariant: all filter work is bounded by a fixed limit or by the shared deadline, and running out of either fails
closed (``DEADLINE_EXCEEDED`` or ``INVALID_INPUT``), never a returned payload that still holds a blocked spelling.
"""

from __future__ import annotations

import fnmatch
import functools
import itertools
import re
import time

import pytest

import superbrain.application._privacy_rules as rules_mod
from superbrain.application.privacy import PrivacyFilter
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import DEFAULT_BLOCKED_PATH_PATTERNS, FilterPolicy, SafePayload

REDACTED = "[redacted]"
LEAD: str = rules_mod._PATH_LEAD
TRAIL: str = rules_mod._PATH_TRAIL
_BOUNDARY = "\"'<>|(){},;[]"  # §14.2 scanner boundaries, plus whitespace
_TOKEN = re.compile(rf"[^\s{re.escape(_BOUNDARY)}]+")
_SEPARATOR = re.compile(r"[\\/]+")
_SUFFIXES = ("", " ü")  # ASCII text, and text with a non-ASCII character elsewhere
_BATCH = 1000  # below the filter's 1024-item array limit
CONTROL = "safe prose kept"


# ------------------------------------------------------------------------------------------------------------------
# reference (§14.2 by brute force)
# ------------------------------------------------------------------------------------------------------------------


def _components(path: str) -> tuple[str, ...]:
    return tuple(part for part in _SEPARATOR.split(path.lower()) if part and part != ".")


@functools.cache
def _blocked(spelling: str, patterns: tuple[str, ...]) -> bool:
    parts = _components(spelling)
    for pattern in patterns:
        chain = _components(pattern)
        for start in range(len(parts) - len(chain) + 1):
            if all(fnmatch.fnmatchcase(p, g) for p, g in zip(parts[start : start + len(chain)], chain, strict=True)):
                return True
    return False


def _run(token: str, chars: str, *, reverse: bool) -> int:
    text = token[::-1] if reverse else token
    return len(text) - len(text.lstrip(chars))


@functools.cache
def _reference_outcomes(token: str, patterns: tuple[str, ...]) -> frozenset[str]:
    """Every replacement of one blocked spelling; empty when no spelling of ``token`` is blocked."""
    n = len(token)
    return frozenset(
        token[:i] + REDACTED + token[n - j :]
        for i in range(_run(token, LEAD, reverse=False) + 1)
        for j in range(_run(token, TRAIL, reverse=True) + 1)
        if i < n - j and _blocked(token[i : n - j], patterns)
    )


def _reference(text: str, patterns: tuple[str, ...]) -> tuple[set[str], int]:
    pieces: list[frozenset[str]] = []
    cursor = count = 0
    for match in _TOKEN.finditer(text):
        pieces.append(frozenset({text[cursor : match.start()]}))
        outcomes = _reference_outcomes(match.group(0), patterns)
        count += bool(outcomes)
        pieces.append(outcomes or frozenset({match.group(0)}))
        cursor = match.end()
    pieces.append(frozenset({text[cursor:]}))
    return {"".join(parts) for parts in itertools.product(*pieces)}, count


def test_p01_r3_reference_enumerates_the_raw_and_every_trimmed_spelling() -> None:
    # Self-check of the brute force on a hand-computed token: lead run "`", trail run "*`".
    assert _reference_outcomes("`keys/*`", ("keys/*",)) == {"`[redacted]", "`[redacted]`"}
    assert _reference_outcomes("see", ("keys/*",)) == frozenset()
    assert _reference_outcomes("``", ("`",)) == {"[redacted]`", "`[redacted]"}


# ------------------------------------------------------------------------------------------------------------------
# filter helpers
# ------------------------------------------------------------------------------------------------------------------


def _policy(patterns: tuple[str, ...]) -> FilterPolicy:
    return FilterPolicy(blocked_path_patterns=patterns, entropy_min_length=4096)  # entropy cannot mask a miss


def _apply(texts: list[str], patterns: tuple[str, ...]) -> tuple[list[str], int]:
    got: list[str] = []
    redacted = 0
    for start in range(0, len(texts), _BATCH):
        chunk = texts[start : start + _BATCH]
        safe = PrivacyFilter().apply({"items": list(chunk), "ok": CONTROL}, _policy(patterns))
        assert isinstance(safe.value, dict) and safe.value["ok"] == CONTROL  # positive control
        assert safe.stripped_keys_count == 0
        items = safe.value["items"]
        assert isinstance(items, list) and len(items) == len(chunk)
        got += [str(item) for item in items]
        redacted += safe.redacted_count
    return got, redacted


def _check(texts: list[str], patterns: tuple[str, ...]) -> None:
    for suffix in _SUFFIXES:
        batch = [text + suffix for text in texts]
        expected = [_reference(text, patterns) for text in batch]
        got, redacted = _apply(batch, patterns)
        wrong = [
            f"{text!r} -> {actual!r}, expected one of {sorted(forms)[:4]!r}"
            for text, actual, (forms, _count) in zip(batch, got, expected, strict=True)
            if actual not in forms
        ]
        assert not wrong, f"{len(wrong)} of {len(batch)} texts for {patterns!r}:\n" + "\n".join(wrong[:25])
        assert redacted == sum(count for _forms, count in expected)


_LEAD_WRAPS = [w for w in ("", *LEAD, *(a + b for a in LEAD for b in LEAD)) if not set(w) & set(_BOUNDARY)]
_TRAIL_WRAPS = [w for w in ("", *TRAIL, *(a + b for a in TRAIL for b in TRAIL)) if not set(w) & set(_BOUNDARY)]


def _wrapped(token: str) -> list[str]:
    """``token`` bare and inside every 0-2 leading / 0-2 trailing wrapper that keeps it one scanner token."""
    return [f"see {lead}{token}{trail} now" for lead in _LEAD_WRAPS for trail in _TRAIL_WRAPS]


def test_p01_r3_wrapper_grid_is_not_vacuous() -> None:
    assert {"`", "*", "**", "`*"} <= set(_LEAD_WRAPS) and {".", "*`", "!.", "::"} <= set(_TRAIL_WRAPS)


# ------------------------------------------------------------------------------------------------------------------
# F1 and F2
# ------------------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("pattern", "text", "expected"),
    [
        # F2: redacted on 3527a99, the raw spelling alone is blocked.
        ("keys/*", "see keys/* now", {"see [redacted] now"}),
        ("config/.*", "see config/.* now", {"see [redacted] now"}),
        ("*/id_rsa", "see */id_rsa now", {"see [redacted] now"}),
        ("foo/*.", "see foo/!. now", {"see [redacted] now"}),
        ("keys/*", "see keys/... now", {"see [redacted] now", "see [redacted]. now"}),
        # F1: never redacted before; a wrapper-only edge component must be kept.
        ("keys/*", "see `keys/*` now", {"see `[redacted] now", "see `[redacted]` now"}),
        ("*/id_rsa", "see `*/id_rsa` now", {"see [redacted]` now", "see `[redacted]` now"}),
        ("keys\\*", "see `keys\\*` now", {"see `[redacted] now", "see `[redacted]` now"}),
        ("*\\id_rsa", "see */id_rsa now", {"see [redacted] now"}),
        ("keys/[*`]", "see keys/* now", {"see [redacted] now"}),
        ("dir/[!a]", "see dir/! now", {"see [redacted] now"}),
        ("[*]/x", "see */x now", {"see [redacted] now"}),
        ("*/x/*", "see */x/* now", {"see [redacted] now"}),
        ("a/..", "see a/.. now", {"see [redacted] now"}),
        ("a/..", "see `a/..`. now", {"see `[redacted]`. now"}),
        ("config/.*", "see `config/.*`: now", {"see `[redacted]`: now", "see `[redacted]: now", "see `[redacted] now"}),
    ],
)
@pytest.mark.parametrize("suffix", _SUFFIXES, ids=["ascii", "non_ascii"])
def test_p01_r3_wrapper_only_edge_component_token_is_redacted(
    pattern: str, text: str, expected: set[str], suffix: str
) -> None:
    forms, count = _reference(text + suffix, (pattern,))
    assert forms == {form + suffix for form in expected} and count == 1  # the hand table agrees with the definition
    safe = PrivacyFilter().apply({"note": text + suffix, "ok": CONTROL}, _policy((pattern,)))
    assert isinstance(safe.value, dict) and safe.value["ok"] == CONTROL
    assert safe.value["note"] in forms, (pattern, text + suffix, safe.value["note"])
    assert safe.redacted_count == 1 and safe.stripped_keys_count == 0


_WRAPPER_EDGES: list[tuple[str, tuple[str, ...]]] = [
    ("keys/*", ("keys/*", "`keys/*`", "keys/...", "keys/**", "keys/x")),
    ("keys\\*", ("keys/*", "`keys\\*`")),
    ("*/id_rsa", ("*/id_rsa", "`*/id_rsa`", "**/id_rsa")),
    ("*\\id_rsa", ("`*\\id_rsa`",)),
    ("config/.*", ("config/.*", "`config/.*`")),
    ("foo/*.", ("foo/!.", "foo/*.", "`foo/!.`")),
    ("keys/[*`]", ("keys/*", "keys/`", "`keys/*`")),
    ("dir/[!a]", ("dir/*", "dir/!")),
    ("[*]/x", ("*/x", "`*/x")),
    ("*/x/*", ("*/x/*", "`*/x/*`")),
    ("dir/**", ("dir/*", "dir/x")),
    ("a/..", ("a/..", "`a/..`.", "a/...")),
    ("**", ("**", "``", "`*`")),
    ("*?", ("`", "*")),
    ("`", ("``", "```")),
]
_EDGE_IDS = [case[0] for case in _WRAPPER_EDGES]


@pytest.mark.parametrize(("pattern", "tokens"), _WRAPPER_EDGES, ids=_EDGE_IDS)
def test_p01_r3_wrapper_only_edge_pattern_is_enforced_under_every_wrapper_combination(
    pattern: str, tokens: tuple[str, ...]
) -> None:
    for token in tokens:
        assert _reference_outcomes(token, (pattern,)), (pattern, token)
        _check(_wrapped(token), (pattern,))


@pytest.mark.parametrize(("pattern", "tokens"), _WRAPPER_EDGES, ids=_EDGE_IDS)
def test_p01_r3_wrapper_only_edge_pattern_is_enforced_next_to_the_shipped_defaults(
    pattern: str, tokens: tuple[str, ...]
) -> None:
    _check(_wrapped(tokens[0]), (*DEFAULT_BLOCKED_PATH_PATTERNS, pattern))


_NEAR_MISSES: list[tuple[str, tuple[str, ...]]] = [
    ("keys/*", ("keys", "key/x", "xkeys/a")),
    ("*/id_rsa", ("id_rsa", "a/id_rsa2", "id_rsa/a")),
    ("config/.*", ("config/x", "config", "xconfig/.a")),
    ("foo/*.", ("foo/ab", "foo", "fooa/b.")),
    ("keys/[*`]", ("keys/a", "keys", "keys/ab")),
    ("[*]/x", ("a/x", "*x")),
    ("*/x/*", ("a/x", "x/a")),
    ("a/..", ("a/.x", "b/..x")),
    ("`", ("a", "a`b")),
]


@pytest.mark.parametrize(("pattern", "tokens"), _NEAR_MISSES, ids=[case[0] for case in _NEAR_MISSES])
def test_p01_r3_near_miss_stays_with_a_blocked_twin(pattern: str, tokens: tuple[str, ...]) -> None:
    patterns = (pattern,)
    kept: list[str] = []
    for token in tokens:
        texts = [text for text in _wrapped(token) if _reference(text, patterns)[1] == 0]
        assert len(texts) >= 43, f"near miss {token!r} is blocked under most wrappers; pick another fixture"
        kept += texts
    for suffix in _SUFFIXES:
        batch = [text + suffix for text in kept]
        got, redacted = _apply(batch, patterns)
        changed = [f"{text!r} -> {actual!r}" for text, actual in zip(batch, got, strict=True) if actual != text]
        assert not changed, f"{len(changed)} near misses changed for {pattern!r}:\n" + "\n".join(changed[:25])
        assert redacted == 0
    twin = next(blocked for case, blocked in _WRAPPER_EDGES if case == pattern)[0]
    forms, count = _reference(f"see {twin} now", patterns)
    got, redacted = _apply([f"see {twin} now"], patterns)
    assert got[0] in forms and redacted == count >= 1


# ------------------------------------------------------------------------------------------------------------------
# F3: bounded work, fail closed
# ------------------------------------------------------------------------------------------------------------------

_HEAVY_PATTERN = "?" * 300 + "[z]"  # valid §14.2 glob, no literal needle: every token reaches the matcher
_HEAVY_MISS = "`" * 300 + "a" + "!" * 300  # long wrapper runs, no spelling ends in z
_HEAVY_HIT = "`" * 300 + "z" + "!" * 300  # exactly one spelling ("`"*300 + "z") is blocked


def _heavy_policy() -> FilterPolicy | None:
    """The pathological policy, or ``None`` when policy construction refuses it (a fixed limit, fail closed)."""
    try:
        return _policy((_HEAVY_PATTERN,))
    except BrainError as error:
        assert error.code is ErrorCode.INVALID_INPUT
        return None


def test_p01_r3_heavy_fixture_is_on_the_right_side_of_the_reference() -> None:
    assert _reference_outcomes(_HEAVY_MISS, (_HEAVY_PATTERN,)) == frozenset()
    assert _reference_outcomes(_HEAVY_HIT, (_HEAVY_PATTERN,)) == {REDACTED + "!" * 300}


def test_p01_r3_deadline_expiring_inside_the_path_phase_fails_closed_promptly() -> None:
    policy = _heavy_policy()
    if policy is None:
        return  # refused by a fixed limit: fail closed, nothing to search
    text = " ".join([_HEAVY_MISS] * 3)
    reads = 0

    def clock() -> int:  # the real monotonic clock, injected so every deadline read is counted
        nonlocal reads
        reads += 1
        return time.monotonic_ns()

    start = time.perf_counter()
    deadline = time.monotonic_ns() + 20_000_000  # 20 ms, far less than the unbounded search of one token
    try:
        safe = PrivacyFilter(monotonic_ns=clock).apply({"note": text, "ok": CONTROL}, policy, deadline_ns=deadline)
    except BrainError as error:
        assert error.code is ErrorCode.DEADLINE_EXCEEDED
        assert REDACTED not in str(error) and _HEAVY_MISS not in str(error)
    else:  # finished inside the budget: then the result must be correct
        assert safe.value == {"note": text, "ok": CONTROL} and safe.redacted_count == 0
    elapsed = time.perf_counter() - start
    assert elapsed < 0.25, f"deadline of 20 ms noticed only after {elapsed:.2f} s ({reads} clock reads)"


def test_p01_r3_pathological_policy_over_64_kib_is_bounded_without_a_deadline() -> None:
    tokens = [_HEAVY_HIT if index % 10 == 0 else _HEAVY_MISS for index in range(108)]
    text = " ".join(tokens)
    assert len(text.encode()) <= 64 * 1024
    expected = " ".join(REDACTED + "!" * 300 if token == _HEAVY_HIT else token for token in tokens)
    start = time.perf_counter()
    outcome: SafePayload | BrainError
    try:
        policy = _policy((_HEAVY_PATTERN,))
        outcome = PrivacyFilter().apply({"note": text, "ok": CONTROL}, policy)
    except BrainError as error:
        outcome = error
    elapsed = time.perf_counter() - start
    if isinstance(outcome, BrainError):
        assert outcome.code is ErrorCode.INVALID_INPUT  # refused by a fixed limit: fail closed
    else:
        assert outcome.value == {"note": expected, "ok": CONTROL}, "a blocked spelling survived"
        assert outcome.redacted_count == sum(token == _HEAVY_HIT for token in tokens)
    assert elapsed < 5.0, f"filtering 64 KiB under one policy took {elapsed:.1f} s"


def test_p01_r3_control_ordinary_text_with_the_shipped_defaults_is_fast_and_unchanged() -> None:
    prose = "the river runs past nine quiet hills, and `notes.md` stays readable! "
    text = (prose * (60_000 // len(prose))) + "see `repo/.env`. now"
    start = time.perf_counter()
    safe = PrivacyFilter().apply({"note": text, "ok": CONTROL}, _policy(DEFAULT_BLOCKED_PATH_PATTERNS))
    elapsed = time.perf_counter() - start
    assert safe.value == {"note": text.replace("`repo/.env`", f"`{REDACTED}`"), "ok": CONTROL}
    assert safe.redacted_count == 1 and elapsed < 1.0
