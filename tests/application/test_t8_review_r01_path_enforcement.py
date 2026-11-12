"""T8-R01, sibling of closure F2: a configured path is enforced or refused.

D6 treats configured blocked paths as a privacy boundary. Fnmatch metacharacters
remain supported. A policy must not silently accept a literal filename the
text scanner can never match, including punctuation used as token boundaries.
"""

from __future__ import annotations

import fnmatch

import pytest

from superbrain.application.privacy import PrivacyFilter
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import DEFAULT_BLOCKED_PATH_PATTERNS, FilterPolicy

REDACTED = "[redacted]"
CONTROL = "ordinary safe prose"


def _enforced_or_refused(pattern: str, token: str, *, with_defaults: bool = False, suffix: str = "") -> None:
    assert fnmatch.fnmatchcase(token.lower(), pattern.lower()), "oracle fixture must match the configured glob"
    patterns = (*DEFAULT_BLOCKED_PATH_PATTERNS, pattern) if with_defaults else (pattern,)
    try:
        policy = FilterPolicy(blocked_path_patterns=patterns, entropy_min_bits=8)
    except BrainError as error:
        assert error.code is ErrorCode.INVALID_INPUT
        return
    payload: JsonValue = {"note": f"open {token} now{suffix}", "ok": CONTROL}
    safe = PrivacyFilter().apply(payload, policy)
    assert safe.value == {"note": f"open {REDACTED} now{suffix}", "ok": CONTROL}, (
        "configured path remained visible under an accepted policy",
        pattern,
        safe.value,
    )
    assert safe.redacted_count == 1 and safe.stripped_keys_count == 0


@pytest.mark.parametrize("delimiter", [",", ";", "(", ")", "{", "}", "<", ">", "|", "'", '"'])
def test_r01_literal_token_delimiter_path_is_enforced_or_refused(delimiter: str) -> None:
    token = f"secrets{delimiter}prod.yaml"
    _enforced_or_refused(token, token)


@pytest.mark.parametrize(
    ("pattern", "token"),
    [
        ("vault[[]prod.yaml", "vault[prod.yaml"),
        ("vault[]]prod.yaml", "vault]prod.yaml"),
        ("vault[,]prod.yaml", "vault,prod.yaml"),
        ("vault[;]prod.yaml", "vault;prod.yaml"),
        ("vault[|]prod.yaml", "vault|prod.yaml"),
        ("vault[()]prod.yaml", "vault(prod.yaml"),
    ],
)
def test_r01_fnmatch_literal_delimiter_class_is_enforced_or_refused(pattern: str, token: str) -> None:
    _enforced_or_refused(pattern, token)


@pytest.mark.parametrize("token", ["secret.", "vault:", "secret!", "`secret", "secret`"])
def test_r01_exact_edge_punctuation_path_is_enforced_or_refused(token: str) -> None:
    _enforced_or_refused(token, token)


@pytest.mark.parametrize("token", ["secrets,prod.yaml", "secrets;prod.yaml", "secrets|prod.yaml"])
@pytest.mark.parametrize("suffix", ["", " ü"], ids=["ascii", "non_ascii"])
def test_r01_literal_delimiter_rule_is_enforced_with_defaults_and_unicode(token: str, suffix: str) -> None:
    _enforced_or_refused(token, token, with_defaults=True, suffix=suffix)


@pytest.mark.parametrize(
    ("pattern", "blocked", "allowed"),
    [
        ("vault[ab].yaml", "vaulta.yaml", "vaultc.yaml"),
        ("vault[0-9].yaml", "vault7.yaml", "vaultx.yaml"),
        ("vault[!x].yaml", "vaulta.yaml", "vaultx.yaml"),
        ("vault?.yaml", "vaultx.yaml", "vaultxx.yaml"),
        ("vault*.yaml", "vaultprod.yaml", "not-vaultprod.yaml"),
        ("config/[ab]/secret.txt", "config/a/secret.txt", "config/c/secret.txt"),
    ],
)
def test_r01_supported_fnmatch_policy_keeps_positive_and_near_miss_twins(
    pattern: str, blocked: str, allowed: str
) -> None:
    assert fnmatch.fnmatchcase(blocked, pattern) and not fnmatch.fnmatchcase(allowed, pattern)
    policy = FilterPolicy(blocked_path_patterns=(pattern,), entropy_min_bits=8)
    safe = PrivacyFilter().apply({"blocked": f"open {blocked} now", "allowed": allowed, "ok": CONTROL}, policy)
    assert safe.value == {"blocked": f"open {REDACTED} now", "allowed": allowed, "ok": CONTROL}
    assert safe.redacted_count == 1 and safe.stripped_keys_count == 0


def test_r01_default_policy_still_blocks_known_credentials_and_preserves_near_misses() -> None:
    safe = PrivacyFilter().apply(
        {"blocked": "open repo/.ssh/config now", "allowed": "repo/ssh/config", "ok": CONTROL},
        FilterPolicy(),
    )
    assert safe.value == {"blocked": f"open {REDACTED} now", "allowed": "repo/ssh/config", "ok": CONTROL}
    assert safe.redacted_count == 1 and safe.stripped_keys_count == 0


@pytest.mark.parametrize(("pattern", "token"), [("..", ".."), ("secret?", "secret?"), ("[*]secret", "*secret")])
def test_r01_supported_edge_token_pattern_is_enforced_without_policy_refusal(pattern: str, token: str) -> None:
    policy = FilterPolicy(blocked_path_patterns=(pattern,), entropy_min_bits=8)
    safe = PrivacyFilter().apply({"note": f"open {token} now", "ok": CONTROL}, policy)
    assert safe.value == {"note": f"open {REDACTED} now", "ok": CONTROL}
    assert safe.redacted_count == 1 and safe.stripped_keys_count == 0


def test_r01_matched_core_keeps_markdown_wrapper_punctuation() -> None:
    safe = PrivacyFilter().apply(
        {"note": "open `repo/secrets.txt` now", "ok": CONTROL},
        FilterPolicy(blocked_path_patterns=("*secrets*",), entropy_min_bits=8),
    )
    assert safe.value == {"note": f"open `{REDACTED}` now", "ok": CONTROL}
    assert safe.redacted_count == 1 and safe.stripped_keys_count == 0
