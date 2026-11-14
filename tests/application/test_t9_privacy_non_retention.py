"""Task 9 privacy cache non-retention and scanner edge-case regression tests."""

from __future__ import annotations

import gc
import types
from collections.abc import Mapping

import pytest

from superbrain.application import _privacy_rules, _privacy_scan, privacy
from superbrain.application.privacy import PrivacyFilter
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import FilterPolicy

REDACTED = "[redacted]"
HIGH_ENTROPY = "q8Zr2Lm9Xv4Tn7Wp1Ks6Jd3Hf5"
LOW_ENTROPY = "a" * 28
CANARY_PREFIX = "t9_nonretain_probe_"


def _apply(value: JsonValue, policy: FilterPolicy | None = None) -> JsonValue:
    return PrivacyFilter().apply(value, policy if policy is not None else FilterPolicy()).value


def _retained_probe_strings(flt: PrivacyFilter, needle: str) -> list[str]:
    skip_types = (
        type,
        types.ModuleType,
        types.FunctionType,
        types.BuiltinFunctionType,
        types.MethodType,
        types.CodeType,
        types.FrameType,
        types.TracebackType,
        int,
        float,
        bool,
        bytes,
        type(None),
    )
    seen: set[int] = set()
    found: set[str] = set()
    stack: list[object] = [flt, privacy.__dict__, _privacy_scan.__dict__, _privacy_rules.__dict__]
    while stack:
        obj = stack.pop()
        oid = id(obj)
        if oid in seen:
            continue
        seen.add(oid)
        if isinstance(obj, str):
            if needle in obj:
                found.add(obj)
            continue
        if isinstance(obj, skip_types):
            continue
        if isinstance(obj, Mapping):
            for key, val in obj.items():
                if not isinstance(key, skip_types):
                    stack.append(key)
                if not isinstance(val, skip_types):
                    stack.append(val)
            continue
        if isinstance(obj, (list, tuple, set, frozenset)):
            for item in obj:
                if not isinstance(item, skip_types):
                    stack.append(item)
            continue
        obj_dict = getattr(obj, "__dict__", None)
        if isinstance(obj_dict, dict):
            stack.append(obj_dict)
        for cls in type(obj).__mro__:
            slots = getattr(cls, "__slots__", ())
            for slot_name in (slots,) if isinstance(slots, str) else slots:
                slot_val = getattr(obj, slot_name, None)
                if not isinstance(slot_val, skip_types):
                    stack.append(slot_val)
        for ref in gc.get_referents(obj):
            if not isinstance(ref, skip_types):
                stack.append(ref)
    return sorted(found)


def test_repeated_apply_does_not_retain_input_tokens_in_compiled_policy_or_module_caches() -> None:
    flt = PrivacyFilter()
    default_policy = FilterPolicy()
    custom_policy = FilterPolicy(blocked_path_patterns=("*.secret", ".tokens/", "id_rsa"))

    for idx in range(150):
        payload: JsonValue = {
            "hit_env": f"/work/{CANARY_PREFIX}env_{idx:04d}/.env",
            "hit_ssh": f"C:/Users/{CANARY_PREFIX}ssh_{idx:04d}/.ssh/config",
            "hit_rsa": f"/home/{CANARY_PREFIX}rsa_{idx:04d}/id_rsa",
            "hit_pem": f"/certs/{CANARY_PREFIX}pem_{idx:04d}.pem",
            "miss_cred": f"/notes/{CANARY_PREFIX}cred_{idx:04d}/credentials_guide.md",
            "miss_rsa": f"/docs/{CANARY_PREFIX}doc_{idx:04d}/id_rsa_tutorial.txt",
            "url": f"https://{CANARY_PREFIX}u_{idx:04d}:pw@example.com/p",
            "secret": f"{CANARY_PREFIX}secret_{idx:04d}_{HIGH_ENTROPY}",
        }
        _ = flt.apply(payload, default_policy)
        _ = flt.apply(
            {
                "custom_hit": f"/var/{CANARY_PREFIX}cust_{idx:04d}.secret",
                "custom_miss": f"/var/{CANARY_PREFIX}miss_{idx:04d}/id_rsa_ref",
            },
            custom_policy,
        )
        del _

    gc.collect()
    leaked = _retained_probe_strings(flt, CANARY_PREFIX)
    assert leaked == [], f"PrivacyFilter / module policy caches retained {len(leaked)} input strings: {leaked[:5]}"

    # Positive twin: repeated calls still redact blocked paths, URL userinfo, and high-entropy tokens accurately.
    after = flt.apply(
        {
            "hit_env": "/work/final_run/.env",
            "miss_readme": "/notes/readme.md",
            "url": "https://alice:hunter2@example.com/path",
            "note": f"tok {HIGH_ENTROPY} ok",
        },
        default_policy,
    ).value
    assert after == {
        "hit_env": REDACTED,
        "miss_readme": "/notes/readme.md",
        "url": f"https://{REDACTED}@example.com/path",
        "note": f"tok {REDACTED} ok",
    }
    after_custom = flt.apply(
        {"custom_hit": "/var/final.secret", "other_env": "/work/final/.env"}, custom_policy
    ).value
    assert after_custom == {"custom_hit": REDACTED, "other_env": "/work/final/.env"}


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        # Single URL / ASCII spaces-only
        ("see https://user:secret@example.com/path ok", f"see https://{REDACTED}@example.com/path ok"),
        # Tabs, newlines, CR and multi-URL mixed with non-auth @ in path/query
        (
            "prefix\thttps://alice:hunter2@host.example/a\nsuffix\rhttps://bob@other.example/b",
            f"prefix\thttps://{REDACTED}@host.example/a\nsuffix\rhttps://{REDACTED}@other.example/b",
        ),
        (
            "https://a.com/@handle/post https://u:p@b.com/z",
            f"https://a.com/@handle/post https://{REDACTED}@b.com/z",
        ),
        (
            "http://first.com/path?foo@bar http://u:p@second.com/",
            f"http://first.com/path?foo@bar http://{REDACTED}@second.com/",
        ),
        (
            "https://a.com/p:q@h https://u:p@b.com/z",
            f"https://a.com/p:q@h https://{REDACTED}@b.com/z",
        ),
        (
            "https://a.com?k:v@h https://u:p@b.com/z",
            f"https://a.com?k:v@h https://{REDACTED}@b.com/z",
        ),
        (
            "https://a.com#f:g@h https://u:p@b.com/z",
            f"https://a.com#f:g@h https://{REDACTED}@b.com/z",
        ),
        # Embedded control char \x1c (whitespace in Python regex): stops scheme-authority match inside cred
        ("before\x1chttps://user:pw@host.example/p", f"before\x1chttps://{REDACTED}@host.example/p"),
        ("https://user:pw@host\x1c.example/p", f"https://{REDACTED}@host\x1c.example/p"),
        ("https://us\x1cer:pw@host.example/p", "https://us\x1cer:pw@host.example/p"),
        ("https://us\ter:pw@host.example/p", "https://us\ter:pw@host.example/p"),
        ("https://us\ner:pw@host.example/p", "https://us\ner:pw@host.example/p"),
        # Non-ASCII surrounding and inside authority/path
        ("préfix https://usér:páss@exámple.com/pâth", f"préfix https://{REDACTED}@exámple.com/pâth"),
        ("café\u00a0https://user:pw@example.com/résumé", f"café\u00a0https://{REDACTED}@example.com/résumé"),
        # Empty userinfo before @ stays unredacted while u:@ is redacted
        ("https://@host.example/p https://u:@host.example/p", f"https://@host.example/p https://{REDACTED}@host.example/p"),
    ],
)
def test_userinfo_redaction_preserves_whitespace_non_ascii_control_and_multi_url_boundaries(
    raw: str, expected: str
) -> None:
    assert _apply({"v": raw}) == {"v": expected}


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        # ASCII spaces vs \t / \n / \r / \x1c delimiters
        (f"keep {HIGH_ENTROPY} and {LOW_ENTROPY}", f"keep {REDACTED} and {LOW_ENTROPY}"),
        (f"keep\t{HIGH_ENTROPY}\nand\r{LOW_ENTROPY}", f"keep\t{REDACTED}\nand\r{LOW_ENTROPY}"),
        (f"keep\x1c{HIGH_ENTROPY}\x1c{LOW_ENTROPY}", f"keep\x1c{REDACTED}\x1c{LOW_ENTROPY}"),
        # Non-whitespace control char \x07 (BEL) must bound [\x21-\x7e] runs rather than using split() alone
        (HIGH_ENTROPY[:15] + "\x07" + HIGH_ENTROPY[15:], HIGH_ENTROPY[:15] + "\x07" + HIGH_ENTROPY[15:]),
        (f"prefix\x07{HIGH_ENTROPY}", f"prefix\x07{REDACTED}"),
        # Control char \x1c splits a 26-char candidate into two sub-24-char segments -> unredacted
        (HIGH_ENTROPY[:15] + "\x1c" + HIGH_ENTROPY[15:], HIGH_ENTROPY[:15] + "\x1c" + HIGH_ENTROPY[15:]),
        # Non-ASCII characters are outside [\x21-\x7e], splitting candidates and extending adjacent ASCII
        (f"café{HIGH_ENTROPY}résumé", f"café{REDACTED}ésumé"),
        ("abc" * 5 + "é" + HIGH_ENTROPY[:12], "abc" * 5 + "é" + HIGH_ENTROPY[:12]),
        (
            f"préfix {LOW_ENTROPY} \u00e9 {HIGH_ENTROPY} \x1c {HIGH_ENTROPY}",
            f"préfix {LOW_ENTROPY} \u00e9 {REDACTED} \x1c {REDACTED}",
        ),
    ],
)
def test_entropy_redaction_preserves_ascii_whitespace_control_and_non_ascii_boundaries(
    raw: str, expected: str
) -> None:
    assert _apply({"v": raw}) == {"v": expected}
