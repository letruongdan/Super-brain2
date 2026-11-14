"""Privacy performance changes preserve D6 byte/count, policy and deadline behavior."""

from __future__ import annotations

import math

import pytest

from superbrain.application._privacy_rules import MAX_TOTAL_BYTES
from superbrain.application.privacy import PrivacyFilter
from superbrain.core.canonical import canonical_json
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import FilterPolicy

REDACTED = "[redacted]"
ENTROPY = "q8Zr2Lm9Xv4Tn7Wp1Ks6Jd3Hf5"
OPAQUE = "outcome-2026-11-06-Zx9Qw3Er7Ty1"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("alpha <private>hidden</private> omega", f"alpha {REDACTED} omega"),
        ("https://person:pw@example.invalid/a", f"https://{REDACTED}@example.invalid/a"),
        ("open config/.env.local now", f"open {REDACTED} now"),
        (f"first {ENTROPY} end", f"first {REDACTED} end"),
    ],
)
def test_repeated_redaction_counts_every_occurrence_and_stripped_subtree(text: str, expected: str) -> None:
    payload: JsonValue = {
        "rows": [{"password": "discarded", "text": text}, {"password": "discarded", "text": text}],
        "positive_control": "ordinary safe prose",
    }
    safe = PrivacyFilter().apply(payload, FilterPolicy())
    assert safe.value == {
        "rows": [{"text": expected}, {"text": expected}],
        "positive_control": "ordinary safe prose",
    }
    assert safe.redacted_count == 2
    assert safe.stripped_keys_count == 2


def test_repeated_text_in_structural_and_free_fields_uses_each_field_type() -> None:
    safe = PrivacyFilter().apply(
        {"outcome_id": OPAQUE, "rows": [{"note": OPAQUE}, {"outcome_id": OPAQUE}], "note": OPAQUE},
        FilterPolicy(),
    )
    assert safe.value == {
        "outcome_id": OPAQUE, "rows": [{"note": REDACTED}, {"outcome_id": OPAQUE}], "note": REDACTED,
    }
    assert safe.redacted_count == 2
    assert safe.stripped_keys_count == 0


def test_repeat_calls_apply_current_policy_for_bare_path_keys_and_manual_projection() -> None:
    flt = PrivacyFilter()
    payload: JsonValue = {
        "note": "open sensitive now", "rows": ["open sensitive now"], "custompin": "ordinary",
    }
    strict = FilterPolicy(blocked_path_patterns=("sensitive",), sensitive_keys=frozenset({"custompin"}))
    safe = flt.apply(payload, strict)
    assert safe.value == {"note": f"open {REDACTED} now", "rows": [f"open {REDACTED} now"]}
    assert safe.redacted_count == 2 and safe.stripped_keys_count == 1
    relaxed = flt.apply(payload, FilterPolicy(blocked_path_patterns=(), sensitive_keys=frozenset()))
    assert relaxed.value == payload
    assert relaxed.redacted_count == relaxed.stripped_keys_count == 0
    assert flt.apply(payload, strict) == safe

    content: JsonValue = {"outcome_id": OPAQUE, "status": "declared", "body": "ordinary safe prose"}
    assert flt.apply(content, FilterPolicy(manual_submission=False)).value == {
        "outcome_id": OPAQUE, "status": "declared",
    }
    assert flt.apply(content, FilterPolicy()).value == content


def test_entropy_replacements_preserve_order_and_punctuation_of_multiple_runs() -> None:
    text = f"first {ENTROPY} middle ({ENTROPY}) last {ENTROPY} end"
    safe = PrivacyFilter().apply([text, text], FilterPolicy())
    expected = f"first {REDACTED} middle {REDACTED} last {REDACTED} end"
    assert safe.value == [expected, expected]
    assert safe.redacted_count == 6 and safe.stripped_keys_count == 0


@pytest.mark.parametrize("text", ["<private>unclosed", "orphan</private>", "<private>a<private>b</private></private>"])
def test_repeated_malformed_private_text_still_refuses(text: str) -> None:
    with pytest.raises(BrainError) as exc:
        PrivacyFilter().apply([text, text], FilterPolicy())
    assert exc.value.code is ErrorCode.INVALID_INPUT
    assert exc.value.message == "privacy filter rejected payload"


def test_repeated_values_keep_counting_the_input_size_cap() -> None:
    with pytest.raises(BrainError) as exc:
        PrivacyFilter().apply(["a" * 4096] * 257, FilterPolicy())
    assert exc.value.code is ErrorCode.INVALID_INPUT


def test_repeated_values_still_observe_an_expiring_deadline() -> None:
    now = 0

    def clock() -> int:
        nonlocal now
        now += 1
        return now

    with pytest.raises(BrainError) as exc:
        PrivacyFilter(clock).apply(["ordinary safe prose"] * 512, FilterPolicy(), deadline_ns=100)
    assert exc.value.code is ErrorCode.DEADLINE_EXCEEDED
    assert now == 100


@pytest.mark.parametrize(
    ("key", "stripped"),
    [
        ("ordinary_" * 1000 + "APIKey", True),
        ("ordinary_" * 1000 + "token_budget", False),
        ("ordinary_" * 1000 + "secretary", False),
        ("ordinary_" * 1000 + "secret2", True),
    ],
)
def test_long_key_fast_paths_preserve_suffix_word_rules(key: str, stripped: bool) -> None:
    payload: JsonValue = {key: 1, "positive_control": "ordinary safe prose"}
    safe = PrivacyFilter().apply(payload, FilterPolicy())
    assert safe.value == ({"positive_control": "ordinary safe prose"} if stripped else payload)
    assert safe.stripped_keys_count == int(stripped)
    assert safe.redacted_count == 0


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Baſic abcdefghijkl", f"Baſic {REDACTED}"),
        ("TOKEN aB3dE5fG", f"TOKEN {REDACTED}"),
        ("Authorızatıon: plaincred", f"Authorızatıon: {REDACTED}"),
    ],
)
def test_ascii_fast_paths_keep_unicode_case_insensitive_authentication_rules(text: str, expected: str) -> None:
    safe = PrivacyFilter().apply([text, text], FilterPolicy())
    assert safe.value == [expected, expected]
    assert safe.redacted_count == 2 and safe.stripped_keys_count == 0


def test_default_path_candidate_fast_path_keeps_every_blocked_family() -> None:
    paths = [
        ".env", ".env.production", ".ssh/config", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
        ".aws/credentials", ".npmrc", ".pypirc", ".netrc", "_netrc",
        "cert.pem", "cert.key", "cert.p12", "cert.pfx", r"C:\mixed/ID_RSA",
    ]
    benign = ["README", ".environment", "id_rsa_backup", "cert.pem.backup"]
    safe = PrivacyFilter().apply([*paths, *benign], FilterPolicy())
    assert safe.value == [*([REDACTED] * len(paths)), *benign]
    assert safe.redacted_count == len(paths) and safe.stripped_keys_count == 0


def test_literal_prefix_shortcuts_preserve_each_fixed_secret_pattern() -> None:
    secrets: list[JsonValue] = [
        "github_pat_" + "a" * 20,
        *("gh" + kind + "_" + "a" * 16 for kind in "pousr"),
        "sk-" + "a" * 16,
        "AKIA" + "A" * 16,
        "ASIA" + "A" * 16,
        *("xox" + kind + "-" + "a" * 10 for kind in "baprs"),
        "AIza" + "A" * 35,
        "eyJaaaa.aaaa.aaaa",
    ]
    safe = PrivacyFilter().apply(secrets, FilterPolicy())
    assert safe.value == [REDACTED] * len(secrets)
    assert safe.redacted_count == len(secrets) and safe.stripped_keys_count == 0


@pytest.mark.parametrize("threshold", [4.0, math.nextafter(4.0, math.inf)])
def test_entropy_contribution_cache_preserves_exact_threshold_comparison(threshold: float) -> None:
    # Sixteen symbols, each appearing twice, give exactly 4 bits per symbol.
    uniform = "abcdefghijklmnop" * 2
    below = "abcdefghijklmnop" + "abcdefghijklmnoa"
    safe = PrivacyFilter().apply([uniform, below, uniform, below], FilterPolicy(entropy_min_bits=threshold))
    expected_uniform = REDACTED if threshold == 4.0 else uniform
    assert safe.value == [expected_uniform, below, expected_uniform, below]
    assert safe.redacted_count == (2 if threshold == 4.0 else 0)
    assert safe.stripped_keys_count == 0


def _padded_json_cap_pair(base: list[JsonValue] | dict[str, JsonValue]) -> tuple[JsonValue, JsonValue]:
    if isinstance(base, list):
        probe: JsonValue = [*base, ""]
        pad_len = MAX_TOTAL_BYTES - len(canonical_json(probe))
        assert 0 < pad_len < 64 * 1024, f"pad_len out of text bound: {pad_len}"
        pad = ("a " * (pad_len // 2)) + ("a" * (pad_len % 2))
        ok: JsonValue = [*base, pad]
        over: JsonValue = [*base, pad + "a"]
    else:
        probe = {**base, "z_pad": ""}
        pad_len = MAX_TOTAL_BYTES - len(canonical_json(probe))
        assert 0 < pad_len < 64 * 1024, f"pad_len out of text bound: {pad_len}"
        pad = ("a " * (pad_len // 2)) + ("a" * (pad_len % 2))
        ok = {**base, "z_pad": pad}
        over = {**base, "z_pad": pad + "a"}
    assert len(canonical_json(ok)) == MAX_TOTAL_BYTES
    assert len(canonical_json(over)) == MAX_TOTAL_BYTES + 1
    return ok, over


def test_json_expansion_cap_rejects_escaped_and_mixed_payloads_past_max_total_bytes() -> None:
    nl_chunks: list[JsonValue] = [("a " * 20_000) + ("\n" * 10_000) for _ in range(17)]
    cases: dict[str, list[JsonValue] | dict[str, JsonValue]] = {
        "newlines_in_str": nl_chunks,
        "quotes_and_backslashes_in_str": [
            ("a " * 15_000) + ('" ' * 4_500) + ("\\ " * 4_500) for _ in range(18)
        ],
        "newlines_quotes_and_backslashes_in_str": [
            ("a " * 15_000) + ("\n" * 4_000) + ('" ' * 2_500) + ("\\ " * 2_500) for _ in range(19)
        ],
        "quotes_and_backslashes_in_dict_keys": {
            f"k_{idx:02d}_" + ("a " * 3_500) + ('" \\ ' * 4_250): "x" for idx in range(32)
        },
        "control_escapes_in_str": [
            ("a " * 15_000) + ("\t\r\x08\x0c" * 3_000) for _ in range(19)
        ],
        "nonprintable_dict_keys": {
            f"k_{idx:02d}_" + ("\x0b" * 10_000): "x" for idx in range(17)
        },
        "non_ascii_sibling_after_ascii_container": [nl_chunks, "é" + ("b " * 4_000)],
    }
    flt = PrivacyFilter()
    policy = FilterPolicy()
    for name, prefix in cases.items():
        ok, over = _padded_json_cap_pair(prefix)
        assert flt.apply(ok, policy).value == ok, f"exact MAX_TOTAL_BYTES rejected for {name}"
        with pytest.raises(BrainError) as exc:
            flt.apply(over, policy)
        assert exc.value.code is ErrorCode.INVALID_INPUT, f"MAX_TOTAL_BYTES + 1 accepted for {name}"


@pytest.mark.parametrize(
    ("text", "expected", "expected_count"),
    [
        ("https://u:p@h/ok https://a:b@c/x@y", f"https://{REDACTED}@h/ok https://{REDACTED}@y", 2),
        ("https://a:b@c/x@y https://u:p@h/ok", f"https://{REDACTED}@y https://{REDACTED}@h/ok", 2),
        ("https://host/@handle https://user:pw@h/x@y", f"https://host/@handle https://{REDACTED}@y", 1),
        ("https://user:pw@h/x@y https://host/@handle", f"https://{REDACTED}@y https://host/@handle", 1),
        ("https://u:p@h/ok\thttps://a:b@c/x@y", f"https://{REDACTED}@h/ok\thttps://{REDACTED}@y", 2),
        ("https://u:p@h/ok\nhttps://a:b@c/x@y", f"https://{REDACTED}@h/ok\nhttps://{REDACTED}@y", 2),
        ("https://u:p@h/ok\x1chttps://a:b@c/x@y", f"https://{REDACTED}@h/ok\x1chttps://{REDACTED}@y", 2),
        ("https://u:p@h/ok\xa0https://a:b@c/x@y", f"https://{REDACTED}@h/ok\xa0https://{REDACTED}@y", 2),
        ("https://u:p@h/ok?next=https://x/y", f"https://{REDACTED}@h/ok?next=https://x/y", 1),
        ("https://u:p@h/p://nested https://a:b@c/x@y", f"https://{REDACTED}@h/p://nested https://{REDACTED}@y", 2),
        ("https://" + ("a" * 5000) + ":pw@h/ok", f"https://{REDACTED}@h/ok", 1),
    ],
)
def test_multi_url_userinfo_fallback_and_delimiter_parity(
    text: str, expected: str, expected_count: int
) -> None:
    safe = PrivacyFilter().apply(text, FilterPolicy())
    assert safe.value == expected
    assert safe.redacted_count == expected_count
    assert safe.stripped_keys_count == 0


def test_ascii_fast_path_parity_blocked_redacted_needles_del_0x7f_and_kv_passw() -> None:
    flt = PrivacyFilter()
    # Needle matching "[redacted]" must rerun path checks cleanly on both ASCII and non-ASCII text.
    for pattern, expected_count in (("*red*", 2), ("red*", 2), ("*edact*", 2), ("edact", 1)):
        policy = FilterPolicy(blocked_path_patterns=(pattern,))
        for sample in ("Authorization: abcdefghijkl, ok", "sk-0123456789abcdef", "https://u:p@h/ok"):
            ascii_res = flt.apply(sample, policy)
            nonascii_res = flt.apply(sample + ", \u00e9", policy)
            assert ascii_res.redacted_count == expected_count, (pattern, sample)
            assert nonascii_res.redacted_count == expected_count, (pattern, sample)
            assert nonascii_res.value == f"{ascii_res.value}, \u00e9", (pattern, sample)

    # DEL (0x7F) is neither printable nor in [\x21-\x7e]; it splits entropy runs without widening spans.
    split_del = ENTROPY[:15] + "\x7f" + ENTROPY[15:]
    prefixed_del = "prefix\x7f" + ENTROPY
    for raw, exp, cnt in (
        (split_del, split_del, 0),
        (prefixed_del, f"prefix\x7f{REDACTED}", 1),
        (split_del + " \u00e9", split_del + " \u00e9", 0),
        (prefixed_del + " \u00e9", f"prefix\x7f{REDACTED} \u00e9", 1),
    ):
        res = flt.apply(raw, FilterPolicy())
        assert res.value == exp
        assert res.redacted_count == cnt

    # Short key-value secret stems ("passw") remain covered alongside "password" / "secret" / "token".
    kv = flt.apply(["password=alpha_beta_gamma", "passwd: delta_epsilon_zeta"], FilterPolicy())
    assert kv.value == [f"password={REDACTED}", f"passwd: {REDACTED}"]
    assert kv.redacted_count == 2 and kv.stripped_keys_count == 0
