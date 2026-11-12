"""Closure round C r2 sibling oracles: fast gates never hide a key=value secret or fixed token the rule defines.

Invariant (sibling of C-01): a prefilter never rejects input that the rule it guards would match. Cases are derived
at runtime from the compiled rule regexes themselves (``_KEY_VALUE_SECRET`` alternation, every ``_FIXED_TOKENS``
pattern), so a rule edit that a hand-written gate does not mirror shows up here. Each case must be redacted exactly
as the rule defines, identically in ASCII-only text and in text with a non-ASCII character elsewhere. Entropy
redaction is disabled (``entropy_min_length=4096``) so it cannot mask a skipped rule.
"""

from __future__ import annotations

import itertools
import re
from collections.abc import Iterator

import pytest

import superbrain.application._privacy_rules as rules_mod
import superbrain.application._privacy_scan as scan_mod
import superbrain.application.privacy as privacy_mod
from superbrain.application.privacy import PrivacyFilter
from superbrain.core.kernel import FilterPolicy

REDACTED = "[redacted]"
POLICY = FilterPolicy(entropy_min_length=4096)
_MODULES = (rules_mod, scan_mod, privacy_mod)


def _filtered(text: str) -> tuple[object, int]:
    safe = PrivacyFilter().apply({"content": text, "ok": "safe prose kept"}, POLICY)
    assert isinstance(safe.value, dict)
    assert safe.value["ok"] == "safe prose kept"  # positive control
    return safe.value["content"], safe.redacted_count


def _both_paths(text: str, expected: str) -> list[str]:
    failures: list[str] = []
    for suffix in ("", " \u00fc"):
        got = _filtered(text + suffix)
        if got != (expected + suffix, 1):
            failures.append(f"{text + suffix!r} -> {got!r}, expected {(expected + suffix, 1)!r}")
    return failures


# ------------------------------------------------------------------------------------------------------------------
# key=value secrets
# ------------------------------------------------------------------------------------------------------------------


def key_value_names(pattern: re.Pattern[str]) -> list[str]:
    """Every literal key name of group 1, expanding ``[_-]?`` to ``_``, ``-`` and nothing."""
    match = re.search(r"\\b\((.*?)\)\(", pattern.pattern)
    assert match, "group 1 of the key=value rule could not be located"
    names: list[str] = []
    for alternative in match.group(1).split("|"):
        pieces = alternative.split("[_-]?")
        for piece in pieces:
            assert re.fullmatch(r"[a-z]+", piece), f"unsupported construct in key alternative {alternative!r}"
        for seps in itertools.product(("_", "-", ""), repeat=len(pieces) - 1):
            names.append("".join(itertools.chain.from_iterable(zip(pieces, (*seps, ""), strict=True))))
    return names


_SEPARATORS = ("=", ":", " = ", "\t:\t", " " * 16 + "=" + " " * 16, "\t" * 16 + ":")
_VALUES = ("hunter2xyz", '"two words"', "'single q'")


def _key_value_cases(names: list[str]) -> Iterator[tuple[str, str]]:
    for name in names:
        for spelled in (name, name.upper(), name.title()):
            for sep in _SEPARATORS:
                for value in _VALUES:
                    yield f"cfg {spelled}{sep}{value} end", f"cfg {spelled}{sep}{REDACTED} end"


def test_r2_every_key_value_name_is_redacted_identically_on_ascii_and_non_ascii_paths() -> None:
    names = key_value_names(rules_mod._KEY_VALUE_SECRET)
    assert "api_key" in names and "apikey" in names and "api-key" in names and "password" in names
    failures = [f for text, expected in _key_value_cases(names) for f in _both_paths(text, expected)]
    assert not failures, "\n".join(failures[:40])


def test_r2_key_value_near_misses_are_kept() -> None:
    for text in ("cfg passwordless login end", "cfg secretary=alice end", "cfg keyring end", "cfg pwd end"):
        for suffix in ("", " \u00fc"):
            assert _filtered(text + suffix) == (text + suffix, 0)


@pytest.mark.parametrize("extra", ["session[_-]?key", "credential"])
def test_r2_added_key_value_alternative_is_redacted(monkeypatch: pytest.MonkeyPatch, extra: str) -> None:
    original = rules_mod._KEY_VALUE_SECRET
    extended = re.compile(original.pattern.replace(r"\b(", rf"\b({extra}|", 1), original.flags)
    for module in _MODULES:
        monkeypatch.setattr(module, "_KEY_VALUE_SECRET", extended, raising=False)
    names = [n for n in key_value_names(extended) if n not in key_value_names(original)]
    assert names
    failures = [f for text, expected in _key_value_cases(names) for f in _both_paths(text, expected)]
    assert not failures, "\n".join(failures[:40])


# ------------------------------------------------------------------------------------------------------------------
# fixed token shapes
# ------------------------------------------------------------------------------------------------------------------

_TOKEN_RE = re.compile(r"\\b|\\\.|\(\?:([^)]*)\)|\[([^\]]+)\](?:\{(\d+)(?:,(\d*))?\})?|([A-Za-z0-9_-])")


def _expand_class(body: str) -> list[str]:
    out: list[str] = []
    i = 0
    while i < len(body):
        if i + 2 < len(body) and body[i + 1] == "-":
            out += [chr(c) for c in range(ord(body[i]), ord(body[i + 2]) + 1)]
            i += 3
        else:
            out.append(body[i])
            i += 1
    return out


def fixed_token_samples(pattern: re.Pattern[str]) -> list[str]:
    """Each literal prefix spelling (classes/alternations enumerated) plus a minimal valid tail of each quantifier."""
    choices: list[list[str]] = []
    pos = 0
    source = pattern.pattern
    while pos < len(source):
        match = _TOKEN_RE.match(source, pos)
        assert match, f"unsupported construct in fixed token rule {source!r} at {pos}"
        alternation, klass, low, _high, literal = match.groups()
        token = match.group(0)
        if token == r"\b":
            pass
        elif token == r"\.":
            choices.append(["."])
        elif alternation is not None:
            choices.append(alternation.split("|"))
        elif klass is not None:
            members = _expand_class(klass)
            if low is None:
                choices.append(members)
            else:
                count = int(low)
                tail = "".join(itertools.islice(itertools.cycle(members[::7] or members), count))
                choices.append([tail])
        else:
            assert literal is not None
            choices.append([literal])
        pos = match.end()
    samples = ["".join(parts) for parts in itertools.product(*choices)]
    for sample in samples:
        assert pattern.fullmatch(sample), f"generated {sample!r} does not match {source!r}"
    return samples


_TOKEN_CONTEXTS = (("use ", " now"), ("use (", ") now"), ('use "', '", now'), ("x\n", ". y"))


def _fixed_token_failures(patterns: tuple[re.Pattern[str], ...]) -> list[str]:
    failures: list[str] = []
    for pattern in patterns:
        for sample in fixed_token_samples(pattern):
            for before, after in _TOKEN_CONTEXTS:
                failures += _both_paths(f"{before}{sample}{after}", f"{before}{REDACTED}{after}")
    return failures


def test_r2_every_fixed_token_shape_is_redacted_identically_on_ascii_and_non_ascii_paths() -> None:
    patterns = tuple(rules_mod._FIXED_TOKENS)
    assert len(patterns) >= 7
    failures = _fixed_token_failures(patterns)
    assert not failures, "\n".join(failures[:40])


def test_r2_fixed_token_near_misses_are_kept() -> None:
    for text in ("use sk-short now", "use ghx_abcdefghijklmnopqrstu now", "use AKIA123 now", "use eyJabc now"):
        for suffix in ("", " \u00fc"):
            assert _filtered(text + suffix) == (text + suffix, 0)


def test_r2_added_fixed_token_shape_is_redacted(monkeypatch: pytest.MonkeyPatch) -> None:
    extra = re.compile(r"\bglpat-[A-Za-z0-9_-]{20}")
    extended = (*rules_mod._FIXED_TOKENS, extra)
    for module in _MODULES:
        monkeypatch.setattr(module, "_FIXED_TOKENS", extended, raising=False)
    failures = _fixed_token_failures((extra,))
    failures += _fixed_token_failures(extended[:-1])  # the existing shapes keep working with the longer tuple
    assert not failures, "\n".join(failures[:40])
