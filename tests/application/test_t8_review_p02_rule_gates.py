"""T8-P02: every shipped redaction rule keeps a gate, and each gate is a necessary condition of its rule.

Gates are pinned to a digest of the exact rule text (``_RULE_GATES``). Editing a shipped rule keeps privacy correct
(a rule without a gate always runs) but silently drops its gate, so the 1 MiB filter slows down unnoticed (plan
8.6 budget). Two invariants, checked on rules iterated at runtime:

* every shipped rule has a gate, and no gate is left without a shipped rule;
* on ASCII text, a gate is open for every sample its rule matches. Samples are derived from the compiled rule
  text, so a needle removed from a gate or an alternative added to a rule shows up here.
"""

from __future__ import annotations

import itertools
import re

import pytest

import superbrain.application._privacy_rules as rules_mod
from tests.application.test_t8_closure_privacy_r2_gates import (
    _SEPARATORS,
    _TOKEN_CONTEXTS,
    _VALUES,
    fixed_token_samples,
    key_value_names,
)


def _shipped_rules() -> list[tuple[str, re.Pattern[str]]]:
    rules = [
        ("_AUTH_HEADER", rules_mod._AUTH_HEADER),
        ("_AUTH_SCHEME", rules_mod._AUTH_SCHEME),
        ("_KEY_VALUE_SECRET", rules_mod._KEY_VALUE_SECRET),
    ]
    return rules + [(f"_FIXED_TOKENS[{index}]", rule) for index, rule in enumerate(rules_mod._FIXED_TOKENS)]


def _spellings(name: str) -> tuple[str, ...]:
    return (name, name.upper(), name.title())


def _first_group_names(rule: re.Pattern[str]) -> list[str]:
    match = re.search(r"\\b\(([^()]*)\)", rule.pattern)
    assert match, f"group 1 of {rule.pattern!r} could not be located"
    names = match.group(1).split("|")
    assert all(re.fullmatch(r"[a-z-]+", name) for name in names), names
    return names


def _samples(name: str, rule: re.Pattern[str]) -> list[str]:
    """ASCII texts the rule matches, one per literal spelling the rule text allows."""
    if name == "_AUTH_HEADER":
        heads = [s for n in _first_group_names(rule) for s in _spellings(n)]
        return [f"x {head}{sep}abc123 y" for head in heads for sep in (":", "=", " : ", "\t=\t", " " * 16 + ":")]
    if name == "_AUTH_SCHEME":
        heads = [s for n in _first_group_names(rule) for s in _spellings(n)]
        return [f"x {head}{gap}abcd1234 y" for head in heads for gap in (" ", "\t", " " * 16)]
    if name == "_KEY_VALUE_SECRET":
        heads = [s for n in key_value_names(rule) for s in _spellings(n)]
        return [f"cfg {head}{sep}{value} end" for head in heads for sep in _SEPARATORS for value in _VALUES]
    return [f"{before}{sample}{after}" for sample in fixed_token_samples(rule) for before, after in _TOKEN_CONTEXTS]


def test_p02_there_are_shipped_rules_to_check() -> None:
    assert len(rules_mod._FIXED_TOKENS) >= 7 and len(_shipped_rules()) >= 10


def test_p02_every_shipped_rule_has_a_gate() -> None:
    missing = [name for name, rule in _shipped_rules() if rules_mod._rule_gate(rule) is None]
    assert not missing, f"shipped rules without a gate (they always run): {missing}"


def test_p02_no_gate_is_left_without_a_shipped_rule() -> None:
    shipped = {rules_mod._rule_text_digest(rule) for _name, rule in _shipped_rules()}
    assert set(rules_mod._RULE_GATES) == shipped


@pytest.mark.parametrize(("name", "rule"), _shipped_rules(), ids=[name for name, _rule in _shipped_rules()])
def test_p02_gate_is_open_for_every_ascii_sample_its_rule_matches(name: str, rule: re.Pattern[str]) -> None:
    samples = _samples(name, rule)
    assert len(samples) >= 4
    closed: list[str] = []
    for text in samples:
        assert text.isascii() and rule.search(text), f"fixture {text!r} does not match {rule.pattern!r}"
        if not rules_mod._gate_open(rule, text, text.lower()):
            closed.append(text)
    assert not closed, f"gate of {name} rejects {len(closed)} texts the rule matches: {closed[:10]}"


def test_p02_gate_stays_closed_on_text_without_any_rule_literal() -> None:
    # Positive twin of the test above: a gate that is always open would pass it while guarding nothing.
    text = " ".join(itertools.repeat("plain prose about a river and nine quiet hills", 8))
    opened = [name for name, rule in _shipped_rules() if rules_mod._gate_open(rule, text, text.lower())]
    assert not opened, f"gates open on text their rules cannot match: {opened}"
    assert not [name for name, rule in _shipped_rules() if rule.search(text)]
