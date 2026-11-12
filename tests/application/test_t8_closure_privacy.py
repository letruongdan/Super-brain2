"""Closure round C oracles for the D6 privacy filter (C-01 blocked paths, C-05 entropy bound, C-06 fallback).

Expected values are derived from the D6 / spec 14.2 rules, never from the filter's own output:

* C-01: a path token matching any configured blocked pattern (``name``, ``dir/``, ``a/b`` chains, fnmatch globs,
  case-insensitive, whole components split on ``/`` or ``\\``) is redacted whatever list the policy carries,
  including when that list *is* the shipped default list (simulated by editing the default constant).
* C-05: an ASCII run of at least ``entropy_min_length`` characters is redacted iff its exact Shannon entropy in
  bits/char is ``>= entropy_min_bits``; the entropy is computed independently here.
* C-06: the pure-Python ``_count_elements`` fallback gives byte-identical results to the C accelerator.
"""

from __future__ import annotations

import fnmatch
import json
import math
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

import superbrain.application.privacy as privacy_mod
from superbrain.application.privacy import PrivacyFilter
from superbrain.core.kernel import DEFAULT_BLOCKED_PATH_PATTERNS, FilterPolicy

REDACTED = "[redacted]"
REPO_ROOT = Path(__file__).resolve().parents[2]

# --------------------------------------------------------------------------------------------------------------------
# C-01 helpers: an independent reference matcher and a token generator for a glob pattern.
# --------------------------------------------------------------------------------------------------------------------


def _components(pattern: str) -> list[str]:
    return [part for part in pattern.lower().split("/") if part]


def reference_blocked(token: str, patterns: tuple[str, ...]) -> bool:
    """D6 path rule: some window of consecutive token components fnmatches every component of some pattern."""
    parts = [p for p in re.split(r"[\\/]+", token.lower()) if p and p != "."]
    for pattern in patterns:
        globs = _components(pattern)
        for start in range(len(parts) - len(globs) + 1):
            window = parts[start : start + len(globs)]
            if all(fnmatch.fnmatchcase(part, glob) for part, glob in zip(window, globs, strict=True)):
                return True
    return False


def _concrete_component(glob: str) -> str:
    """A concrete component matched by ``glob``: ``*`` -> ``prod``, ``?`` -> ``7``, ``[..]`` -> a member."""
    out: list[str] = []
    i = 0
    while i < len(glob):
        ch = glob[i]
        if ch == "*":
            out.append("prod")
        elif ch == "?":
            out.append("7")
        elif ch == "[":
            close = glob.index("]", i + 2)
            body = glob[i + 1 : close]
            assert body[0] not in "!^", "negated classes are not generated"
            out.append(body[0])
            i = close
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def matching_token(pattern: str) -> str:
    comps = [_concrete_component(glob) for glob in _components(pattern)]
    if pattern.endswith("/"):
        comps.append("notes")
    return "/".join(comps)


def near_miss_tokens(pattern: str, patterns: tuple[str, ...]) -> list[str]:
    """Tokens one edit away from a match of ``pattern`` that match no pattern of the active list."""
    comps = matching_token(pattern).split("/")
    found: list[str] = []
    for index, comp in enumerate(comps):
        variants = [comp + "q9"]
        alnum = next((k for k, c in enumerate(comp) if c.isalnum()), None)
        if alnum is not None:
            variants.append(comp[:alnum] + ("q" if comp[alnum] != "q" else "z") + comp[alnum + 1 :])
        for variant in variants:
            candidate = "/".join([*comps[:index], variant, *comps[index + 1 :]])
            if not reference_blocked(candidate, patterns):
                found.append(candidate)
    return found


def path_cases(token: str) -> list[tuple[str, str]]:
    """``(text fragment, expected fragment)`` for bare, nested, upper-case and punctuation-wrapped forms."""
    nested_slash = f"a/{token}"
    nested_back = "a\\" + token.replace("/", "\\")
    upper = token.upper()
    return [
        (token, REDACTED),
        (nested_slash, REDACTED),
        (nested_back, REDACTED),
        (upper, REDACTED),
        (f"({token})", f"({REDACTED})"),
        (f"`{token}`", f"`{REDACTED}`"),
        (f"{token},", f"{REDACTED},"),
        (f"{token}.", f"{REDACTED}."),
        (f"'{upper}'", f"'{REDACTED}'"),
    ]


def _texts(fragment: str, expected: str) -> list[tuple[str, str]]:
    out = [(f"see {fragment} now ü", f"see {expected} now ü")]
    if fragment.isascii():
        out.append((f"see {fragment} now", f"see {expected} now"))
    return out


def _filtered(text: str, policy: FilterPolicy) -> tuple[object, int]:
    # Positive control: short key and words (< 8 chars) stay intact under every policy used here.
    safe = PrivacyFilter().apply({"content": text, "ok": "safe prose kept"}, policy)
    assert isinstance(safe.value, dict)
    assert safe.value["ok"] == "safe prose kept"
    return safe.value["content"], safe.redacted_count


def _check_patterns_redacted(patterns_to_check: tuple[str, ...], active: tuple[str, ...], policy: FilterPolicy,
                             equivalent: FilterPolicy | None = None) -> list[str]:
    failures: list[str] = []
    for pattern in patterns_to_check:
        token = matching_token(pattern)
        assert reference_blocked(token, active), f"generator produced a non-matching token for {pattern!r}"
        for fragment, expected_fragment in path_cases(token):
            for text, expected in _texts(fragment, expected_fragment):
                got, count = _filtered(text, policy)
                if got != expected or count != 1:
                    failures.append(f"{pattern!r}: {text!r} -> {got!r} (count {count}), expected {expected!r}")
                if equivalent is not None:
                    other = _filtered(text, equivalent)
                    if other != (got, count):
                        failures.append(f"{pattern!r}: {text!r} default-list {got!r} != equivalent-list {other[0]!r}")
    return failures


def _check_near_misses(patterns_to_check: tuple[str, ...], active: tuple[str, ...], policy: FilterPolicy) -> list[str]:
    failures: list[str] = []
    for pattern in patterns_to_check:
        misses = near_miss_tokens(pattern, active)
        assert misses, f"no near-miss control could be generated for {pattern!r}"
        for miss in misses:
            for text, _ in _texts(miss, miss):
                got, count = _filtered(text, policy)
                if got != text or count != 0:
                    failures.append(f"near miss of {pattern!r}: {text!r} -> {got!r} (count {count})")
    return failures


EXTRA_PATTERNS: tuple[str, ...] = (
    "secrets.yaml",
    "*.tfstate",
    "config/prod/*.json",
    "vault/",
    "dump?.db",
    "backup[0-9].sql",
    "kubeconfig",
    "clé-privée.txt",
)
INERT_PATTERN = "zz-inert-pattern-q7"


def _set_shipped_default(monkeypatch: pytest.MonkeyPatch, value: tuple[str, ...]) -> None:
    """Simulate a source edit of the shipped default list in every module that exposes the name."""
    import superbrain.core._kernel_workspace as workspace_mod
    import superbrain.core.kernel as kernel_mod

    for module in (workspace_mod, kernel_mod, privacy_mod):
        monkeypatch.setattr(module, "DEFAULT_BLOCKED_PATH_PATTERNS", value, raising=False)


# --------------------------------------------------------------------------------------------------------------------
# C-01.1: every pattern of the current shipped default list is enforced under the default policy.
# --------------------------------------------------------------------------------------------------------------------


def test_c01_every_current_default_pattern_redacts_generated_tokens_under_default_policy() -> None:
    patterns = tuple(DEFAULT_BLOCKED_PATH_PATTERNS)
    assert patterns, "the shipped default list is iterated at runtime and must not be empty"
    failures = _check_patterns_redacted(patterns, patterns, FilterPolicy())
    assert not failures, "\n".join(failures)


def test_c01_near_miss_tokens_of_default_patterns_are_not_redacted() -> None:
    patterns = tuple(DEFAULT_BLOCKED_PATH_PATTERNS)
    failures = _check_near_misses(patterns, patterns, FilterPolicy())
    assert not failures, "\n".join(failures)


# --------------------------------------------------------------------------------------------------------------------
# C-01.2: when the shipped default list itself contains a new pattern, that pattern is enforced (RED on 9e36caf).
# --------------------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("extra", EXTRA_PATTERNS)
def test_c01_shipped_default_containing_new_pattern_redacts_it(monkeypatch: pytest.MonkeyPatch, extra: str) -> None:
    extended = tuple(DEFAULT_BLOCKED_PATH_PATTERNS) + EXTRA_PATTERNS
    _set_shipped_default(monkeypatch, extended)
    policy = FilterPolicy(blocked_path_patterns=extended)
    equivalent = FilterPolicy(blocked_path_patterns=(*extended, INERT_PATTERN))
    failures = _check_patterns_redacted((extra,), extended, policy, equivalent)
    assert not failures, "\n".join(failures)


def test_c01_shipped_default_extension_keeps_old_patterns_and_near_misses(monkeypatch: pytest.MonkeyPatch) -> None:
    extended = tuple(DEFAULT_BLOCKED_PATH_PATTERNS) + EXTRA_PATTERNS
    _set_shipped_default(monkeypatch, extended)
    policy = FilterPolicy(blocked_path_patterns=extended)
    equivalent = FilterPolicy(blocked_path_patterns=(*extended, INERT_PATTERN))
    failures = _check_patterns_redacted(tuple(DEFAULT_BLOCKED_PATH_PATTERNS), extended, policy, equivalent)
    failures += _check_near_misses(extended, extended, policy)
    assert not failures, "\n".join(failures)


# --------------------------------------------------------------------------------------------------------------------
# C-01.3: custom (non-default) lists: positive controls and list scoping.
# --------------------------------------------------------------------------------------------------------------------


def test_c01_custom_list_with_the_same_patterns_redacts_every_pattern() -> None:
    custom = (*DEFAULT_BLOCKED_PATH_PATTERNS, *EXTRA_PATTERNS, INERT_PATTERN)
    policy = FilterPolicy(blocked_path_patterns=custom)
    failures = _check_patterns_redacted(custom[:-1], custom, policy)
    failures += _check_near_misses(custom[:-1], custom, policy)
    assert not failures, "\n".join(failures)


def test_c01_custom_list_only_blocks_its_own_patterns() -> None:
    policy = FilterPolicy(blocked_path_patterns=("secrets.yaml",))
    assert _filtered("see secrets.yaml now", policy) == (f"see {REDACTED} now", 1)
    assert _filtered("see .env now", policy) == ("see .env now", 0)


# --------------------------------------------------------------------------------------------------------------------
# C-05: entropy rule at the exact minimum-entropy boundary.
# --------------------------------------------------------------------------------------------------------------------

# Printable ASCII without whitespace, quotes, separators or characters that start other D6 rules (= : < > . / \).
_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&*+-?@^_~|"
assert len(set(_ALPHABET)) == len(_ALPHABET)


def min_entropy_token(length: int, distinct: int) -> str:
    """One character repeated ``length - distinct + 1`` times followed by ``distinct - 1`` singletons."""
    assert 1 <= distinct <= min(length, len(_ALPHABET))
    return _ALPHABET[0] * (length - distinct + 1) + _ALPHABET[1:distinct]


def shannon_bits(token: str) -> float:
    total = len(token)
    counts: dict[str, int] = {}
    for ch in token:
        counts[ch] = counts.get(ch, 0) + 1
    return -math.fsum((c / total) * math.log2(c / total) for c in counts.values())


def _boundary_us(length: int, bits: float) -> list[int]:
    top = min(length, len(_ALPHABET))
    first = next((u for u in range(1, top + 1) if shannon_bits(min_entropy_token(length, u)) >= bits), None)
    if first is None:
        return [u for u in (top - 2, top - 1, top) if u >= 1]
    return [u for u in (first - 2, first - 1, first, first + 1) if 1 <= u <= top]


def _entropy_failures(cases: list[tuple[float, int, int]]) -> list[str]:
    failures: list[str] = []
    for bits, length, min_length in cases:
        policy = FilterPolicy(entropy_min_bits=bits, entropy_min_length=min_length)
        for distinct in _boundary_us(length, bits):
            token = min_entropy_token(length, distinct)
            entropy = shannon_bits(token)
            if abs(entropy - bits) < 1e-9:
                continue  # float tie: the exact comparison is not decidable here
            text = f"start {token} end"
            expected = f"start {REDACTED} end" if length >= min_length and entropy >= bits else text
            got, _ = _filtered(text, policy)
            if got != expected:
                failures.append(
                    f"bits={bits} L={length} u={distinct} H={entropy:.12f}: expected "
                    f"{'redacted' if expected != text else 'kept'}"
                )
    return failures


_LENGTHS = (8, 9, 10, 12, 16, 20, 24, 31, 32, 33, 48, 64, 77, 100, 128, 200, 255, 256, 257, 300, 1000)


@pytest.mark.parametrize("bits", [2.5, 3.0, 4.0, 4.5, 8.0])
def test_c05_min_entropy_distribution_redacted_iff_entropy_reaches_threshold(bits: float) -> None:
    failures = _entropy_failures([(bits, length, 8) for length in _LENGTHS])
    assert not failures, "\n".join(failures)


def test_c05_threshold_just_above_an_achievable_entropy_keeps_that_token() -> None:
    """Thresholds a hair above H(L, u): the u-token is kept, the (u+1)-token is redacted (exact bound, no slack)."""
    failures: list[str] = []
    for length in (8, 12, 16, 24, 32, 40, 64, 96, 128, 160, 200, 255, 256, 257, 300, 512):
        for distinct in sorted({max(2, min(length, len(_ALPHABET)) - k) for k in (0, 3, 9, 20)}):
            if distinct + 1 > min(length, len(_ALPHABET)):
                continue
            entropy = shannon_bits(min_entropy_token(length, distinct))
            bits = entropy + 1e-7
            if not (0.0 < bits <= 8.0):
                continue
            policy = FilterPolicy(entropy_min_bits=bits, entropy_min_length=8)
            kept = min_entropy_token(length, distinct)
            above = min_entropy_token(length, distinct + 1)
            assert shannon_bits(above) > bits
            got_kept, _ = _filtered(f"start {kept} end", policy)
            got_above, _ = _filtered(f"start {above} end", policy)
            if got_kept != f"start {kept} end":
                failures.append(f"L={length} u={distinct} bits=H+1e-7 was redacted")
            if got_above != f"start {REDACTED} end":
                failures.append(f"L={length} u={distinct + 1} above bits=H(u)+1e-7 was kept")
    assert not failures, "\n".join(failures)


def test_c05_runs_shorter_than_min_length_are_kept_even_at_maximum_entropy() -> None:
    policy = FilterPolicy(entropy_min_bits=2.5, entropy_min_length=40)
    token = _ALPHABET[:39]
    assert shannon_bits(token) > 5.0
    assert _filtered(f"start {token} end", policy) == (f"start {token} end", 0)
    assert _filtered(f"start {_ALPHABET[:40]} end", policy) == (f"start {REDACTED} end", 1)


# --------------------------------------------------------------------------------------------------------------------
# C-06: the pure-Python counting fallback is byte-identical to the accelerated import.
# --------------------------------------------------------------------------------------------------------------------

_CORPUS_SCRIPT = r"""
import json, sys
if sys.argv[1] == "fallback":
    import _collections
    del _collections._count_elements
import superbrain.application.privacy as privacy
from superbrain.core.errors import BrainError
from superbrain.core.kernel import FilterPolicy
uses_fallback = getattr(privacy._count_elements, "__module__", None) == "superbrain.application.privacy"
corpus = json.loads(sys.stdin.read())
policies = [FilterPolicy(), FilterPolicy(entropy_min_bits=3.0, entropy_min_length=8),
            FilterPolicy(entropy_min_bits=4.5, entropy_min_length=12)]
rows = []
for item in corpus:
    for policy in policies:
        try:
            safe = privacy.PrivacyFilter().apply(item, policy)
            rows.append(["ok", safe.value, safe.redacted_count, safe.stripped_keys_count])
        except BrainError as err:
            rows.append(["error", err.code.value])
sys.stdout.write(json.dumps({"fallback": uses_fallback, "rows": rows}, sort_keys=True, ensure_ascii=True))
"""


def _corpus() -> list[object]:
    entropy_tokens = [min_entropy_token(length, u) for length, u in ((24, 16), (24, 17), (40, 30), (300, 70))]
    return [
        {"content": f"start {tok} end"} for tok in entropy_tokens
    ] + [
        {"content": "q8Zr2Lm9Xv4Tn7Wp1Ks6Jd3Hf5 and café q8Zr2Lm9Xv4Tn7Wp1Ks6Jd3Hf5"},
        {"content": "open config/.env.local now", "password": "discarded"},
        {"content": "alpha <private>hidden</private> omega", "rows": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "x"]},
        {"content": "token=abcdefgh12345678 and https://u:p@example.invalid/x"},
        {"content": "ordinary safe prose with no secrets at all"},
        {"content": "ü" * 40 + " " + "0123456789abcdefghijABCDEFGHIJ!#$%"},
        {"content": "<private>unterminated"},
    ]


def _run_corpus(mode: str) -> dict[str, object]:
    proc = subprocess.run(
        [sys.executable, "-c", _CORPUS_SCRIPT, mode],
        input=json.dumps(_corpus()), capture_output=True, text=True, encoding="utf-8",
        cwd=REPO_ROOT, env=dict(os.environ), timeout=120, check=False,
    )
    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout)
    assert isinstance(result, dict)
    return result


def test_c06_count_elements_fallback_gives_byte_identical_results() -> None:
    normal = _run_corpus("normal")
    fallback = _run_corpus("fallback")
    assert normal["fallback"] is False, "the normal import must use the accelerator"
    assert fallback["fallback"] is True, "the fallback subprocess must exercise the pure-Python counter"
    assert fallback["rows"] == normal["rows"]
    # Positive control: the corpus actually exercises entropy redaction and keeps the safe row.
    rows = normal["rows"]
    assert isinstance(rows, list)
    assert any(row[0] == "ok" and REDACTED in json.dumps(row[1]) for row in rows)
    assert ["ok", {"content": "ordinary safe prose with no secrets at all"}, 0, 0] in rows
