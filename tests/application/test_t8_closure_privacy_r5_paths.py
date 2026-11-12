"""Closure round C r5 oracles (review F2): a blocked-path pattern is enforced, or refused when the policy is built.

Requirement (D6, owner ruling: path patterns are fnmatch globs per component, case-insensitive):
* ``/`` and ``\\`` are equivalent separators in patterns, as they are in tokens;
* repeated or leading separators create no empty component;
* a trailing separator means "directory component" (a window of components anywhere in the token);
* ``..`` is an ordinary component and is enforced;
* a pattern with no component (``/``, ``\\``, ``//``) or with whitespace inside a component can never be enforced on a
  path token (tokens never hold whitespace), so ``FilterPolicy(...)`` refuses it with ``INVALID_INPUT``.
"""

from __future__ import annotations

import pytest

from superbrain.application.privacy import PrivacyFilter
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import DEFAULT_BLOCKED_PATH_PATTERNS, FilterPolicy

REDACTED = "[redacted]"
_SUFFIXES = ("", " ü")


def _filtered(text: str, policy: FilterPolicy) -> tuple[object, int]:
    safe = PrivacyFilter().apply({"content": text, "ok": "safe prose kept"}, policy)
    assert isinstance(safe.value, dict)
    assert safe.value["ok"] == "safe prose kept"  # positive control
    return safe.value["content"], safe.redacted_count


# pattern -> (tokens that must be redacted, near misses that must be kept)
ENFORCED: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "/vault/": (("vault/notes", "x/vault/notes", "VAULT\\notes"), ("vaults/notes", "my-vault/notes")),
    "config/prod/": (
        ("config/prod/app.json", "repo/config/prod/app.json", "config\\prod\\x.yaml"),
        ("config/dev/app.json", "prod/config/app.json", "config/production/app.json"),
    ),
    ".aws\\credentials": (
        (".aws/credentials", ".aws\\credentials", "home/.aws/credentials", ".AWS\\Credentials"),
        (".aws/credentialsx", ".aws2/credentials", "aws/credentials"),
    ),
    "a//b/": (("a/b/c", "x/a/b/c", "a\\b\\c"), ("a/x/b/c", "ab/c", "b/a/c")),
    "vault\\": (("vault/notes", "vault\\notes", "x\\vault\\notes"), ("vaultx/notes", "avault/notes")),
    "\\\\secrets//keys": (("secrets/keys", "x/secrets/keys/y"), ("secrets/key", "keys/secrets")),
    "..": (("a/../b", "..\\etc"), ("a/.../b", "a/.b")),
    "../secret.txt": (("x/../secret.txt", "..\\secret.txt"), ("x/./secret.txt", "../secret.txtx")),
}


@pytest.mark.parametrize("suffix", _SUFFIXES, ids=["ascii", "non_ascii"])
@pytest.mark.parametrize("pattern", sorted(ENFORCED))
def test_r5_path_pattern_spelling_is_enforced(pattern: str, suffix: str) -> None:
    policy = FilterPolicy(blocked_path_patterns=(pattern,))
    blocked, kept = ENFORCED[pattern]
    failures: list[str] = []
    for token in blocked:
        text = f"see {token} now{suffix}"
        got = _filtered(text, policy)
        if got != (f"see {REDACTED} now{suffix}", 1):
            failures.append(f"{pattern!r}: {text!r} -> {got!r} (expected redacted)")
    for token in kept:
        text = f"see {token} now{suffix}"
        got = _filtered(text, policy)
        if got != (text, 0):
            failures.append(f"{pattern!r}: near miss {text!r} -> {got!r}")
    assert not failures, "\n".join(failures)


@pytest.mark.parametrize("suffix", _SUFFIXES, ids=["ascii", "non_ascii"])
@pytest.mark.parametrize("pattern", sorted(ENFORCED))
def test_r5_path_pattern_spelling_is_enforced_alongside_the_default_list(pattern: str, suffix: str) -> None:
    policy = FilterPolicy(blocked_path_patterns=(*DEFAULT_BLOCKED_PATH_PATTERNS, pattern))
    for token in ENFORCED[pattern][0]:
        text = f"see {token} now{suffix}"
        assert _filtered(text, policy) == (f"see {REDACTED} now{suffix}", 1), (pattern, text)
    assert _filtered(f"see .ssh/config now{suffix}", policy) == (f"see {REDACTED} now{suffix}", 1)


@pytest.mark.parametrize(
    "pattern",
    ["/", "\\", "//", "\\\\", "/\\/", "my vault/", "a b", "a\tb", " vault", "vault ", "x/\ny", "config/ prod/"],
)
def test_r5_unenforceable_path_pattern_is_refused_at_policy_build(pattern: str) -> None:
    with pytest.raises(BrainError) as exc:
        FilterPolicy(blocked_path_patterns=(pattern,))
    assert exc.value.code is ErrorCode.INVALID_INPUT
    with pytest.raises(BrainError) as exc_mixed:
        FilterPolicy(blocked_path_patterns=(*DEFAULT_BLOCKED_PATH_PATTERNS, pattern))
    assert exc_mixed.value.code is ErrorCode.INVALID_INPUT


def test_r5_positive_control_ordinary_patterns_are_still_accepted() -> None:
    for patterns in (DEFAULT_BLOCKED_PATH_PATTERNS, ("vault/",), ("a/b",), ("*.pem", "secrets.yaml"), ("..",)):
        assert FilterPolicy(blocked_path_patterns=tuple(patterns)).blocked_path_patterns == tuple(patterns)
