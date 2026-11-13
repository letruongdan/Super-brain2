"""T8-P01-N1/N2: path enforcement never refuses benign text, costs linear time, and keeps the §14.2 semantics.

Requirement. System design §14.2 "Mẫu đường dẫn trong SP1" names only build-time refusals for path patterns; a token is
blocked when any spelling left after removing part of its leading wrapper run and part of its trailing wrapper run
(or nothing) is blocked (brute-force reference ``_reference_outcomes`` of ``test_t8_review_p01_r3_spellings.py``).
Plan 8.6(b): filter time grows linearly with input size.

N2 invariant: a policy that ``FilterPolicy`` accepts never makes benign text be refused; every token is decided.
N1 invariant: filter time and memory grow linearly in the input with a small constant, with or without a deadline.
Equivalence: a seeded corpus of small tokens keeps the exact §14.2 outcome (any one blocked spelling replaced,
wrappers outside it kept, one redaction per blocked token).

The brute-force reference is quadratic per token, so it is used directly only on small tokens; the long-token
expectations below are fixtures where exactly one spelling is blocked (or none), cross-checked on a short twin.
"""

from __future__ import annotations

import random
import time
import tracemalloc

import pytest

from superbrain.application.privacy import PrivacyFilter
from superbrain.core.errors import BrainError
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import DEFAULT_BLOCKED_PATH_PATTERNS, FilterPolicy
from tests.application.test_t8_review_p01_r3_spellings import (
    _BOUNDARY,
    _SUFFIXES,
    LEAD,
    REDACTED,
    TRAIL,
    _reference,
    _reference_outcomes,
)

DEFAULTS = DEFAULT_BLOCKED_PATH_PATTERNS
_LEAD_CHARS = "".join(ch for ch in LEAD if ch not in _BOUNDARY)  # wrappers that stay inside one scanner token
_TRAIL_CHARS = "".join(ch for ch in TRAIL if ch not in _BOUNDARY)


def _policy(patterns: tuple[str, ...]) -> FilterPolicy:
    return FilterPolicy(blocked_path_patterns=patterns, entropy_min_length=4096)  # entropy cannot mask a miss


def _filter(payload: JsonValue, patterns: tuple[str, ...]) -> tuple[JsonValue, int, float]:
    start = time.perf_counter()
    try:
        safe = PrivacyFilter().apply(payload, _policy(patterns))
    except BrainError as error:  # N2: no refusal for a policy FilterPolicy accepted
        pytest.fail(f"benign payload refused with {error.code.value}")
    return safe.value, safe.redacted_count, time.perf_counter() - start


def _run(chars: str, n: int) -> str:
    return "".join(chars[i % len(chars)] for i in range(n))


def test_n01_wrapper_alphabets_are_not_vacuous() -> None:
    assert set("`*") <= set(_LEAD_CHARS) and set("`*.:!?") <= set(_TRAIL_CHARS)


# ------------------------------------------------------------------------------------------------------------------
# N2: no runtime refusal; tokens far above the old 4,096-spelling cap are decided
# ------------------------------------------------------------------------------------------------------------------

_N2_CASES: list[tuple[str, tuple[str, ...], str, str, str]] = [
    # (id, patterns, lead run, core, trail run): exactly the bare core is blocked, or nothing is
    ("defaults-64-backticks", DEFAULTS, "`" * 64, "id_rsa", "`" * 64),
    ("defaults-2000-backticks", DEFAULTS, "`" * 2000, "id_rsa", "`" * 2000),
    ("defaults-mixed-64", DEFAULTS, _run("`*", 64), "id_rsa", _run("`.!*", 64)),
    ("defaults-mixed-2000", DEFAULTS, _run("*`", 2000), "id_rsa", _run("!*.`", 2000)),
    ("defaults-100x100-bangs", DEFAULTS, "`" * 100, "id_rsa", "!" * 100),
    ("class-no-needle-64", ("[.]env",), "*" * 64, ".env", "*" * 64),
    ("class-no-needle-5000", ("[.]env",), "*" * 5000, ".env", "*" * 5000),
]


def _short_twin(lead: str, trail: str) -> tuple[str, str]:
    return lead[:5], trail[:5]


@pytest.mark.parametrize(
    ("patterns", "lead", "core", "trail"), [c[1:] for c in _N2_CASES], ids=[c[0] for c in _N2_CASES]
)
@pytest.mark.parametrize("suffix", _SUFFIXES, ids=["ascii", "non_ascii"])
def test_n01_n2_long_wrapper_runs_are_decided_never_refused(
    patterns: tuple[str, ...], lead: str, core: str, trail: str, suffix: str
) -> None:
    assert (len(lead) + 1) * (len(trail) + 1) > 4096
    short_lead, short_trail = _short_twin(lead, trail)  # the reference agrees on a short twin of the same shape
    assert _reference_outcomes(short_lead + core + short_trail, patterns) == {short_lead + REDACTED + short_trail}
    text = f"see {lead}{core}{trail} now{suffix}"
    value, redacted, _elapsed = _filter({"note": text}, patterns)
    assert value == {"note": f"see {lead}{REDACTED}{trail} now{suffix}"} and redacted == 1


@pytest.mark.parametrize(
    ("patterns", "token"),
    [(("[.]env",), "*" * 64), (("[.]env",), "*" * 5000), (DEFAULTS, "`" * 5000)],
    ids=["class-64-stars", "class-5000-stars", "defaults-5000-backticks"],
)
@pytest.mark.parametrize("suffix", _SUFFIXES, ids=["ascii", "non_ascii"])
def test_n01_n2_wrapper_only_banner_is_kept_never_refused(patterns: tuple[str, ...], token: str, suffix: str) -> None:
    assert _reference_outcomes(token[:7], patterns) == frozenset()
    text = f"see {token} ok{suffix}"
    value, redacted, _elapsed = _filter({"note": text}, patterns)
    assert value == {"note": text} and redacted == 0


def test_n01_n2_small_wrapped_paths_match_the_reference_with_the_defaults() -> None:
    for token in ("`" * 64 + "repo/.ssh/config" + "`" * 64, "*" * 64 + "x/.env" + "!." * 32, "`" * 64 + "id_rsa"):
        forms, count = _reference(f"see {token} now", DEFAULTS)
        value, redacted, _elapsed = _filter({"note": f"see {token} now"}, DEFAULTS)
        assert isinstance(value, dict) and value["note"] in forms and redacted == count == 1


# ------------------------------------------------------------------------------------------------------------------
# N1: linear time and memory
# ------------------------------------------------------------------------------------------------------------------

_KIB64 = 64 * 1024


def _long_miss(wrap: int) -> str:
    """One needle-bearing token (``.env``) of about 64 KiB with ``wrap`` wrappers each side and no blocked spelling."""
    middle = "a" * (_KIB64 - 2 * wrap - 40) + "x.envy"
    return "`" * wrap + middle + "!" * wrap


def _long_hit(wrap: int) -> str:
    return "`" * wrap + "a" * (_KIB64 - 2 * wrap - 40) + "/id_rsa" + "!" * wrap


def test_n01_n1_long_fixtures_are_on_the_right_side_of_the_reference() -> None:
    assert _reference_outcomes("`" * 3 + "a" * 9 + "x.envy" + "!" * 3, DEFAULTS) == frozenset()
    # Every spelling that keeps the whole trailing run out and any part of the leading run is blocked.
    assert _reference_outcomes("`" * 3 + "a" * 9 + "/id_rsa" + "!" * 3, DEFAULTS) == {
        "`" * k + REDACTED + "!" * 3 for k in range(4)
    }


@pytest.mark.parametrize("wrap", [63, 2000])
def test_n01_n1_one_64_kib_token_without_a_blocked_spelling_is_fast(wrap: int) -> None:
    token = _long_miss(wrap)
    assert len(token) <= _KIB64
    value, redacted, elapsed = _filter({"note": token}, DEFAULTS)
    assert value == {"note": token} and redacted == 0
    assert elapsed < 0.5, f"one 64 KiB token with {wrap}x{wrap} wrappers took {elapsed:.2f} s"


@pytest.mark.parametrize("wrap", [63, 2000])
def test_n01_n1_one_64_kib_token_with_a_blocked_spelling_is_fast(wrap: int) -> None:
    token = _long_hit(wrap)
    value, redacted, elapsed = _filter({"note": token}, DEFAULTS)
    assert isinstance(value, dict) and isinstance(value["note"], str) and redacted == 1
    kept = len(value["note"]) - len(value["note"].lstrip("`"))  # leading wrappers kept outside the replaced spelling
    assert kept <= wrap and value["note"] == token[:kept] + REDACTED + "!" * wrap  # one of the blocked spellings
    assert elapsed < 0.5, f"one 64 KiB token with {wrap}x{wrap} wrappers took {elapsed:.2f} s"


def test_n01_n1_one_64_kib_token_peak_memory_is_small() -> None:
    token = _long_miss(63)
    tracemalloc.start()
    try:
        value, redacted, _elapsed = _filter({"note": token}, DEFAULTS)
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert value == {"note": token} and redacted == 0
    assert peak < 16 * 1024 * 1024, f"peak {peak / 2**20:.1f} MiB for a 64 KiB text"


def test_n01_n1_64_kib_text_of_many_wrapped_tokens_is_fast() -> None:
    miss = "`" * 64 + "a" * 200 + "x.envy" + "!" * 64
    hit = "`" * 64 + "id_rsa" + "`" * 64
    tokens = [hit if index % 3 == 0 else miss for index in range(_KIB64 // (len(miss) + 1))]
    text = " ".join(tokens)
    assert len(text) <= _KIB64
    expected = " ".join("`" * 64 + REDACTED + "`" * 64 if token == hit else token for token in tokens)
    value, redacted, elapsed = _filter({"note": text}, DEFAULTS)
    assert value == {"note": expected} and redacted == tokens.count(hit)
    assert elapsed < 0.5, f"64 KiB of wrapped tokens took {elapsed:.2f} s"


def test_n01_n1_pathological_custom_policy_over_64_kib_is_decided_fast() -> None:
    pattern = "?" * 300 + "[z]"
    miss, hit = "`" * 300 + "a" + "!" * 300, "`" * 300 + "z" + "!" * 300
    assert _reference_outcomes("`" * 2 + "a" + "!" * 2, ("??[z]",)) == frozenset()
    assert _reference_outcomes("`" * 2 + "z" + "!" * 2, ("??[z]",)) == {REDACTED + "!!"}  # short twin of the shape
    tokens = [hit if index % 10 == 0 else miss for index in range(108)]
    text = " ".join(tokens)
    assert len(text.encode()) <= _KIB64
    expected = " ".join(REDACTED + "!" * 300 if token == hit else token for token in tokens)
    value, redacted, elapsed = _filter({"note": text}, (pattern,))
    assert value == {"note": expected} and redacted == tokens.count(hit)
    assert elapsed < 2.0, f"pathological policy over 64 KiB took {elapsed:.2f} s"


# ------------------------------------------------------------------------------------------------------------------
# equivalence on a seeded corpus of small tokens
# ------------------------------------------------------------------------------------------------------------------

_PATTERNS = (
    "vault?", "vault.", "..", "vault!", "a.b.", "*vault", "vault*", "`vault", "vault`", "conf/prod.", "?vault",
    "[`]vault", "vault[.!]", "*`vault", "vault`*", "keys/*", "*/id_rsa", "config/.*", "foo/*.", "keys/[*`]",
    "*/x/*", "a/..", "**", "*?", "*", "`", "[.]env", "dir/[!a]", "keys\\*", "[*]/x", "dir/**",
)  # fmt: skip
_WORDS = (
    "vault", "vaultx", "keys", "x", "id_rsa", "config", ".env", "a.b", "a.b.", "prod.", "conf", "foo", "!.", "dir",
    "a", "..", ".", "", "`vault", "vault`", "*", "**", "`", "vault!", "vault?", "repo", ".ssh", "z.pem",
)  # fmt: skip
_SEED = 20261112
_CASES = 3000


def _corpus() -> list[tuple[tuple[str, ...], str]]:
    rng = random.Random(_SEED)
    cases: list[tuple[tuple[str, ...], str]] = []
    while len(cases) < _CASES:
        pattern = rng.choice(_PATTERNS)
        patterns = (*DEFAULTS, pattern) if rng.random() < 0.25 else (pattern,)
        words = [rng.choice(_WORDS) for _ in range(rng.randint(1, 3))]
        core = "".join(word + rng.choice(("/", "\\", "//")) for word in words[:-1]) + words[-1]
        lead = "".join(rng.choice(_LEAD_CHARS) for _ in range(rng.randint(0, 6)))
        trail = "".join(rng.choice(_TRAIL_CHARS) for _ in range(rng.randint(0, 6)))
        token = lead + core + trail
        if token and not set(token) & set(_BOUNDARY):
            cases.append((patterns, token))
    return cases


@pytest.mark.parametrize("suffix", _SUFFIXES, ids=["ascii", "non_ascii"])
def test_n01_seeded_small_tokens_keep_the_exact_reference_outcome(suffix: str) -> None:
    by_policy: dict[tuple[str, ...], list[str]] = {}
    for patterns, token in _corpus():
        by_policy.setdefault(patterns, []).append(f"see {token} now{suffix}")
    blocked = total = 0
    wrong: list[str] = []
    for patterns, texts in by_policy.items():
        expected = [_reference(text, patterns) for text in texts]
        value, redacted, _elapsed = _filter(list(texts), patterns)  # a bare list: no key a match-all would strip
        assert isinstance(value, list) and len(value) == len(texts)
        wrong += [
            f"{patterns[-1]!r}: {text!r} -> {actual!r}, expected one of {sorted(forms)[:3]!r}"
            for text, actual, (forms, _count) in zip(texts, value, expected, strict=True)
            if actual not in forms
        ]
        if redacted != sum(count for _forms, count in expected):
            wrong.append(f"{patterns[-1]!r}: redacted_count {redacted} != {sum(c for _f, c in expected)}")
        blocked += sum(1 for text in texts if _reference_outcomes(text.split(" ")[1], patterns))
        total += len(texts)
    assert not wrong, f"{len(wrong)} mismatches:\n" + "\n".join(wrong[:25])
    assert total == _CASES and blocked >= _CASES // 5, f"only {blocked} of {total} seeded tokens are blocked"
