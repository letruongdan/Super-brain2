"""T8-P02 note: a compiled pattern added to the privacy modules is either a gated rule or a reviewed helper.

``test_t8_review_p02_rule_gates.py`` lists the gated shipped rules by name. A new redaction rule bound under another
name (in ``_privacy_rules``, ``_privacy_scan`` or ``privacy``) would escape that list and run without a gate. Here
every module-level ``re.Pattern`` (or tuple of them) is discovered at runtime and must be one of the gated rules or a
helper named below (structural matchers, tokenizers, the ungated PEM markers). A new name fails until a reviewer
classifies it.
"""

from __future__ import annotations

import re
from types import ModuleType

import superbrain.application._privacy_rules as rules_mod
import superbrain.application._privacy_scan as scan_mod
import superbrain.application.privacy as privacy_mod
from tests.application.test_t8_review_p02_rule_gates import _shipped_rules

_HELPERS = frozenset(
    {
        "OPAQUE_ID_RE",
        "SHA256_DIGEST_RE",
        "_UUID_RE",
        "_STATUS_VALUE_RE",
        "_PEM_BEGIN",
        "_PEM_END",
        "_AUTHORITY",
        "_SEGMENT",
        "_CREDENTIAL_USER",
        "_PATH_TOKEN",
        "_DOTTED_PATH_TOKEN",
        "_PATH_SPLIT",
        "_WORD_BOUNDARY",
        "_KEY_WORD_SPLIT",
        "_ID_SEGMENTS",
    }
)


def _discovered(module: ModuleType) -> list[tuple[str, re.Pattern[str]]]:
    found: list[tuple[str, re.Pattern[str]]] = []
    for name, value in vars(module).items():
        if isinstance(value, re.Pattern):
            found.append((name, value))
        elif isinstance(value, tuple) and value and all(isinstance(item, re.Pattern) for item in value):
            found += [(f"{name}[{index}]", item) for index, item in enumerate(value)]
    return found


def test_p02_r2_every_module_level_pattern_is_a_gated_rule_or_a_reviewed_helper() -> None:
    gated = {id(rule) for _name, rule in _shipped_rules()}
    unclassified = [
        f"{module.__name__}.{name}"
        for module in (rules_mod, scan_mod, privacy_mod)
        for name, pattern in _discovered(module)
        if id(pattern) not in gated and name.split("[")[0] not in _HELPERS
    ]
    assert not unclassified, f"compiled patterns that are neither gated rules nor reviewed helpers: {unclassified}"


def test_p02_r2_discovery_sees_the_gated_rules() -> None:
    # Positive twin: discovery that found nothing would pass the test above vacuously.
    discovered = {id(pattern) for module in (rules_mod, scan_mod) for _name, pattern in _discovered(module)}
    assert {id(rule) for _name, rule in _shipped_rules()} <= discovered
