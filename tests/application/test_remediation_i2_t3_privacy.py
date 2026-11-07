"""Independent regressions for Task 3 review findings I2-T3-R05 and I2-T3-R06 (privacy filter, D6 / spec 14.2).

Oracle source (derived from requirements, not from current output):

- Spec 14.2 and D6: the filter removes secrets/tokens by fixed pattern before any durable write; a filter that cannot
  decide refuses the payload instead of returning it. Once an HTTP auth scheme (``Bearer``/``Basic``) is recognised,
  the following credential is a secret whatever its character classes; the plain English word "token" is not.
- Task 3 privacy-first userinfo ruling (fix round 2): after ``scheme://`` a ``user:`` prefix makes everything up to the
  last ``@`` before whitespace credential-like, including ``/ ? #``. A length bound may refuse the payload, but it can
  never fall back to returning the credential verbatim. Matching stays linear in the input size.

Every canary below is a fake test value.
"""

from __future__ import annotations

import time

import pytest

from superbrain.application.privacy import PrivacyFilter
from superbrain.core.canonical import canonical_json
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import FilterPolicy

LOWER_TOKEN = "abcdefghijklmnop"  # 16 lowercase chars: below the 24-char entropy candidate length
URL_CANARY = "localcanary"


def _filtered_text(value: JsonValue) -> str | None:
    """Canonical JSON of the safe payload, or ``None`` when the filter refused the payload (``INVALID_INPUT``)."""
    try:
        safe = PrivacyFilter().apply(value, FilterPolicy())
    except BrainError as err:
        assert err.code is ErrorCode.INVALID_INPUT, err.code
        return None
    return canonical_json(safe.value).decode("utf-8")


# --- I2-T3-R05: recognised Bearer/Basic credential is redacted regardless of its charset --------------------------


@pytest.mark.parametrize(
    ("text", "credential"),
    [
        (f"Bearer {LOWER_TOKEN}", LOWER_TOKEN),
        (f"Authorization: Bearer {LOWER_TOKEN}", LOWER_TOKEN),
        (f"curl -H 'Authorization: Bearer {LOWER_TOKEN}' https://api.example.invalid/v1", LOWER_TOKEN),
        (f"Basic {LOWER_TOKEN}", LOWER_TOKEN),
        (f"Authorization: Basic {LOWER_TOKEN}", LOWER_TOKEN),
        ("Bearer 4815162342108815", "4815162342108815"),
    ],
    ids=["bearer", "bearer-header", "bearer-curl", "basic", "basic-header", "bearer-digits"],
)
def test_recognised_auth_scheme_credential_is_redacted_whatever_its_charset(text: str, credential: str) -> None:
    safe = PrivacyFilter().apply({"description": text}, FilterPolicy())
    rendered = canonical_json(safe.value).decode("utf-8")
    assert credential not in rendered, rendered
    assert safe.redacted_count >= 1


@pytest.mark.parametrize(
    "text",
    [
        "Please rotate the token before Friday.",
        "Send the Bearer token in the Authorization header.",
        "The token budget defaults to 4000 tokens per task.",
    ],
)
def test_ordinary_prose_using_the_word_token_is_preserved(text: str) -> None:
    safe = PrivacyFilter().apply({"description": text}, FilterPolicy())
    assert safe.value == {"description": text}
    assert safe.redacted_count == 0


# --- I2-T3-R06: credential-like userinfo never fails open on long usernames ---------------------------------------


@pytest.mark.parametrize("delimiter", ["/", "?", "#"], ids=["slash", "query", "fragment"])
@pytest.mark.parametrize("user_len", [255, 256, 257])
def test_long_username_credential_like_url_never_keeps_the_password(user_len: int, delimiter: str) -> None:
    url = "https://" + "a" * user_len + f":{URL_CANARY}{delimiter}part@example.invalid/repo"
    rendered = _filtered_text({"description": f"clone {url} now"})
    assert rendered is None or URL_CANARY not in rendered, rendered


@pytest.mark.parametrize("user_len", [1_000, 20_000, 60_000])
def test_very_long_username_is_refused_or_redacted_in_linear_time(user_len: int) -> None:
    text = "https://" + "a" * user_len + f":{URL_CANARY}/part@example.invalid/repo"
    best = float("inf")
    rendered: str | None = None
    for _ in range(3):
        start = time.perf_counter()
        rendered = _filtered_text({"description": text})
        best = min(best, time.perf_counter() - start)
        if best < 0.05:
            break
    assert rendered is None or URL_CANARY not in rendered, rendered[:200] if rendered else rendered
    assert best < 0.1, f"{best:.3f}s"


# --- I2-T3-R06 (reopened by the independent review): empty and raw-@ usernames ------------------------------------
# Same ledger invariant: after ``scheme://`` a credential-like ``user:password`` segment never survives, through the
# last ``@`` before whitespace, including ``/ ? #``. The 0-length username and a username that itself contains ``@``
# are boundary forms of that same segment, not new requirements.


# Low-entropy fillers (``aa@aa.aa``) keep the entropy layer from masking the rule under test.


@pytest.mark.parametrize("tail", ["aa@aa.aa", "aa@aa.aa/repo"], ids=["host", "host-path"])
@pytest.mark.parametrize("delimiter", ["/", "?", "#", ""], ids=["slash", "query", "fragment", "none"])
@pytest.mark.parametrize(
    "prefix",
    ["https://:", "https://aa@aa.aa:", "https://dan@aa.aa:"],
    ids=["empty-user", "raw-at-user", "raw-at-email-user"],
)
def test_empty_or_raw_at_username_credential_like_url_never_keeps_the_password(
    prefix: str, delimiter: str, tail: str
) -> None:
    url = f"{prefix}{URL_CANARY}{delimiter}{tail}"
    rendered = _filtered_text({"description": f"clone {url} now"})
    assert rendered is None or URL_CANARY not in rendered, rendered


@pytest.mark.parametrize(
    "text",
    [
        "https://:" + URL_CANARY + "/" + "a" * 60_000 + "@aa.aa",
        "https://" + "a@" * 20_000 + "aa.aa:" + URL_CANARY + "/aa@aa.aa",
        "https://" + "a@" * 20_000 + ":" + URL_CANARY + "?aa@aa.aa",
        "https://" + "a" * 30_000 + "@aa.aa:" + URL_CANARY + "#aa@aa.aa",
    ],
    ids=["empty-user-long-password", "many-raw-at-user", "many-raw-at-empty-host", "long-user-raw-at"],
)
def test_empty_or_raw_at_username_forms_stay_linear_and_never_keep_the_password(text: str) -> None:
    best = float("inf")
    rendered: str | None = None
    for _ in range(3):
        start = time.perf_counter()
        rendered = _filtered_text({"description": text})
        best = min(best, time.perf_counter() - start)
        if best < 0.05:
            break
    assert rendered is None or URL_CANARY not in rendered, rendered[:200] if rendered else rendered
    assert best < 0.1, f"{best:.3f}s"
