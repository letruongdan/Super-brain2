"""Task 3 privacy filter tests (D6, spec 14.2): ingress payloads are bounded, secret-free and canonical."""

from __future__ import annotations

import time
import traceback
from collections.abc import Iterator

import pytest

from superbrain.application.privacy import PrivacyFilter, filter_policy_for, project_manual_submission
from superbrain.core._json_parse import parse_json
from superbrain.core.canonical import canonical_json
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import FilterPolicy, RepoFlags, RepoPolicy, SafePayload

CANARY = "CANARYxQ7"
REDACTED = "[redacted]"
UUID_ID = "0192f2d4-5a6b-7c8d-9e0f-a1b2c3d4e5f6"
SHA_ID = "sha256:" + "0123456789abcdef" * 4
HIGH_ENTROPY = "q8Zr2Lm9Xv4Tn7Wp1Ks6Jd3Hf5"  # 26 ASCII chars, all distinct: entropy ~4.7 bits/symbol


def _apply(value: JsonValue, policy: FilterPolicy | None = None) -> SafePayload:
    return PrivacyFilter().apply(value, policy if policy is not None else FilterPolicy())


def _walk_strings(value: JsonValue) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from _walk_strings(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _walk_strings(item)


def _assert_no_canary(value: JsonValue) -> None:
    blob = canonical_json(value).decode("utf-8")
    assert CANARY not in blob, blob


def _assert_safe_error(err: BrainError, *raw: str) -> None:
    rendered = [str(err), repr(err), err.message, *map(str, err.args)]
    rendered.append("".join(traceback.format_exception(err)))
    for text in rendered:
        for needle in (CANARY, *raw):
            assert needle not in text, text
    assert err.__cause__ is None
    assert err.__context__ is None


def test_nested_secrets_in_keys_values_and_lists_are_removed() -> None:
    payload: JsonValue = {
        "schema_version": "2.0",
        "notes": ["plain note", {"password": f"{CANARY}-pw", "keep": "visible"}],
        "outer": {"inner": [{"api_key": f"{CANARY}-k"}, {"Authorization": f"Bearer {CANARY}abcdefgh"}]},
        f"token ghp_{CANARY}aaaaaaaaaaaaaaaaaaaaaaaa": {"nested": "value under secret-bearing key"},
        "list": [[f"see https://user:{CANARY}@example.invalid/repo"]],
    }
    safe = _apply(payload)
    _assert_no_canary(safe.value)
    assert isinstance(safe.value, dict)
    assert safe.value["notes"] == ["plain note", {"keep": "visible"}]
    assert safe.value["outer"] == {"inner": [{}, {}]}
    assert all("ghp_" not in key for key in safe.value)
    assert safe.value["list"] == [[f"see https://{REDACTED}@example.invalid/repo"]]
    assert safe.stripped_keys_count == 4
    assert safe.redacted_count >= 1


@pytest.mark.parametrize(
    "key",
    [
        "password",
        "PASSWORD",
        "Passwd",
        "db_password",
        "client-secret",
        "API_KEY",
        "apiKey",
        "access_token",
        "Refresh-Token",
        "private_key",
        "Set-Cookie",
        "cookie",
        "session_token",
        "pwd",
        "token",
        "auth_token",
        "X-Auth-Token",
        "x-api-key",
        "Passphrase",
        "github_token",
        "ＰＡＳＳＷＯＲＤ",  # fullwidth PASSWORD (NFKC)
        "password_hash",
        "credential",
        "bearer",
        "authorization",
    ],
)
def test_sensitive_key_variants_remove_whole_subtree(key: str) -> None:
    payload: JsonValue = {key: {"deep": [CANARY, {"x": CANARY}]}, "safe": 1}
    safe = _apply(payload)
    assert safe.value == {"safe": 1}
    assert safe.stripped_keys_count == 1


def test_url_userinfo_query_secret_and_connection_strings_are_redacted() -> None:
    payload: JsonValue = {
        "a": f"clone https://alice:{CANARY}@git.example.invalid/x.git now",
        "b": f"ssh://bob:{CANARY}@host.invalid:22/repo",
        "c": f"postgres://svc:{CANARY}@db.invalid:5432/app",
        "d": f"Server=db;User Id=svc;Password={CANARY};",
        "e": f"export API_KEY={CANARY}",
    }
    safe = _apply(payload)
    _assert_no_canary(safe.value)
    assert isinstance(safe.value, dict)
    assert safe.value["a"] == f"clone https://{REDACTED}@git.example.invalid/x.git now"
    assert safe.value["b"] == f"ssh://{REDACTED}@host.invalid:22/repo"
    assert safe.value["c"] == f"postgres://{REDACTED}@db.invalid:5432/app"
    assert REDACTED in str(safe.value["d"]) and "Server=db" in str(safe.value["d"])
    assert REDACTED in str(safe.value["e"])


@pytest.mark.parametrize(
    "secret",
    [
        f"-----BEGIN RSA PRIVATE KEY-----\nMIIE{CANARY}\n-----END RSA PRIVATE KEY-----",
        f"-----BEGIN OPENSSH PRIVATE KEY-----\n{CANARY}",
        f"Authorization: Bearer {CANARY}abcdefghijk",
        f"Basic dXNlcjp{CANARY}wYXNz",
        f"ghp_{CANARY}AbCdEfGhIjKlMnOpQrStUv",
        f"github_pat_11ABCDEFG_{CANARY}abcdefghijklmnop",
        f"gho_{CANARY}abcdefghijklmnopqrstu",
        f"ghs_{CANARY}abcdefghijklmnopqrstu",
        f"sk-{CANARY}abcdefghijklmnopqrstuvwx",
        f"sk-ant-api03-{CANARY}abcdefghijklmnopqrst",
        f"xoxb-{CANARY}-123456789012-abcdef",
        f"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ{CANARY}.abc{CANARY}def",
    ],
)
def test_fixed_secret_patterns_are_redacted(secret: str) -> None:
    safe = _apply({"text": f"prefix {secret} suffix"})
    _assert_no_canary(safe.value)
    assert safe.redacted_count >= 1


def test_aws_access_key_id_is_redacted() -> None:
    safe = _apply({"text": "key AKIAIOSFODNN7EXAMPLE used"})
    assert safe.value == {"text": f"key {REDACTED} used"}


def test_high_entropy_ascii_redacted_but_uuid_and_sha256_preserved() -> None:
    payload: JsonValue = {
        "free": f"token {HIGH_ENTROPY} end",
        "uuid_text": f"ref {UUID_ID} ok",
        "sha_text": f"digest {SHA_ID} ok",
        "task_id": UUID_ID,
        "digest": SHA_ID,
    }
    safe = _apply(payload)
    assert isinstance(safe.value, dict)
    assert safe.value["free"] == f"token {REDACTED} end"
    assert safe.value["uuid_text"] == f"ref {UUID_ID} ok"
    assert safe.value["sha_text"] == f"digest {SHA_ID} ok"
    assert safe.value["task_id"] == UUID_ID
    assert safe.value["digest"] == SHA_ID
    assert safe.redacted_count == 1


@pytest.mark.parametrize(
    "text",
    [
        "q8Zr2Lm9Xv4Tn7Wp1Ks6Jd3",  # 23 chars: below the 24-char candidate length
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",  # long but zero entropy
        "configuration_management_system_value",  # long ASCII identifier, low entropy
        "the quick brown fox jumps over the lazy dog many times",
    ],
)
def test_short_or_low_entropy_ascii_is_preserved(text: str) -> None:
    safe = _apply({"text": text})
    assert safe.value == {"text": text}
    assert safe.redacted_count == 0


def test_private_blocks_redacted_case_insensitively() -> None:
    safe = _apply({"t": f"keep <private>{CANARY} hidden</private> and <PRIVATE>{CANARY}</Private> done"})
    assert safe.value == {"t": f"keep {REDACTED} and {REDACTED} done"}
    assert safe.redacted_count == 2


@pytest.mark.parametrize(
    "text",
    [
        f"start <private>{CANARY} never closed",
        f"orphan {CANARY}</private> close",
        f"<private>a <private>{CANARY}</private></private>",
        f"malformed <private {CANARY}",
        f"</private><private>{CANARY}",
    ],
)
def test_unclosed_or_orphan_private_marker_refuses_payload(text: str) -> None:
    payloads: tuple[JsonValue, ...] = ({"t": text}, {text: "value"}, [text])
    for payload in payloads:
        with pytest.raises(BrainError) as exc:
            _apply(payload)
        assert exc.value.code is ErrorCode.INVALID_INPUT
        assert exc.value.message == "privacy filter rejected payload"
        _assert_safe_error(exc.value, text)


@pytest.mark.parametrize(
    "path",
    [
        "/home/u/project/.env",
        "C:\\Users\\u\\project\\.env.local",
        "C:/Users/u\\mixed/.env.production",
        "/home/u/.ssh/config",
        "C:\\Users\\u\\.ssh\\known_hosts",
        "~/.ssh/id_rsa",
        "keys\\id_ed25519",
        "/home/u/.aws/credentials",
        "C:\\Users\\u\\.aws\\credentials",
        "/home/u/.npmrc",
        "D:\\work\\.pypirc",
        "/root/.netrc",
        "certs/server.pem",
        "certs\\tls.key",
        "C:/bundle/client.p12",
        "store/identity.PFX",
        ".env",
    ],
)
def test_blocked_paths_with_separator_variants_are_redacted(path: str) -> None:
    safe = _apply({"t": f"open {path} now"})
    assert safe.value == {"t": f"open {REDACTED} now"}
    assert safe.redacted_count == 1


@pytest.mark.parametrize(
    "path",
    [
        "/home/u/environment.txt",
        "src/my.envelope.py",
        "docs/keynote.md",
        "C:\\work\\keys\\README.md",
        "/srv/aws/credentials-guide.md",
        "src/env/settings.py",
    ],
)
def test_blocked_path_component_boundaries_do_not_overmatch(path: str) -> None:
    safe = _apply({"t": f"open {path} now"})
    assert safe.value == {"t": f"open {path} now"}


def test_clean_unicode_prose_is_preserved() -> None:
    prose = (
        "Sửa lỗi đăng nhập khi người dùng đổi mật khẩu trên điện thoại; "
        "修复登录问题并更新文档；ログイン処理を修正しました。🙂 Ünïcödé façade naïve"
    )
    payload: JsonValue = {"mô_tả": prose, "ghi_chú": ["không có bí mật", "đã kiểm tra kỹ lưỡng toàn bộ"]}
    safe = _apply(payload)
    assert safe.value == payload
    assert safe.redacted_count == 0
    assert safe.stripped_keys_count == 0


def test_structural_id_fields_keep_validated_ids_only() -> None:
    policy = FilterPolicy(structural_id_fields=frozenset({"task_id", "delivery_id"}))
    safe = _apply({"task_id": UUID_ID, "delivery_id": f"x {HIGH_ENTROPY}"}, policy)
    assert safe.value == {"task_id": UUID_ID, "delivery_id": f"x {REDACTED}"}


@pytest.mark.parametrize(
    "payload",
    [
        {"deep": __import__("functools").reduce(lambda acc, _: [acc], range(40), [CANARY])},
        {"big": "a" * (64 * 1024 + 1)},
        {"arr": [CANARY] * 1025},
        {"num": float("nan")},
        {"num": float("inf")},
        {"bad": object()},
        {1: CANARY},
        {"lone": "\ud800" + CANARY},
    ],
)
def test_bounds_and_non_json_values_refuse_payload(payload: object) -> None:
    with pytest.raises(BrainError) as exc:
        PrivacyFilter().apply(payload, FilterPolicy())  # type: ignore[arg-type]
    assert exc.value.code is ErrorCode.INVALID_INPUT
    _assert_safe_error(exc.value)


def test_total_size_bound_refuses_payload() -> None:
    payload: JsonValue = {"chunks": ["b" * 60_000 for _ in range(20)]}
    with pytest.raises(BrainError) as exc:
        _apply(payload)
    assert exc.value.code is ErrorCode.INVALID_INPUT
    _assert_safe_error(exc.value)


def test_manual_submission_false_projection_keeps_ids_and_status_only() -> None:
    policy = FilterPolicy(manual_submission=False)
    payload: JsonValue = {
        "schema_version": "2.0",
        "outcome_id": UUID_ID,
        "delivery_id": UUID_ID,
        "outcome": "success",
        "status": "declared",
        "body": f"long free text {CANARY}",
        "evidence": [{"kind": "log", "data": "content"}],
        "read_acks": [{"served_receipt_id": UUID_ID, "task_id": UUID_ID}],
        "candidate_lesson": {"text": "lesson"},
    }
    safe = _apply(payload, policy)
    assert safe.value == {
        "schema_version": "2.0",
        "outcome_id": UUID_ID,
        "delivery_id": UUID_ID,
        "outcome": "success",
        "status": "declared",
    }
    assert project_manual_submission(payload, policy) == safe.value
    assert project_manual_submission(payload, FilterPolicy()) == payload


def test_filter_policy_follows_repo_flags() -> None:
    flags = RepoFlags.from_repo_policy(RepoPolicy(repo_id="repo-1", owner_id="dan", provider_egress_enabled=False))
    assert flags.provider_egress is False
    assert flags.manual_submission is True
    assert flags.automatic_capture is True and flags.indexing is True
    assert filter_policy_for(flags).manual_submission is True
    assert filter_policy_for(RepoFlags(manual_submission=False)).manual_submission is False


def test_filter_policy_rejects_invalid_parameters() -> None:
    with pytest.raises(BrainError):
        FilterPolicy(entropy_min_length=3)
    with pytest.raises(BrainError):
        FilterPolicy(entropy_min_bits=float("nan"))
    with pytest.raises(BrainError):
        FilterPolicy(sensitive_keys=frozenset({""}))


def test_deadline_exhausted_raises_deadline_exceeded() -> None:
    ticks = iter(range(0, 10_000_000_000, 1_000_000))
    flt = PrivacyFilter(monotonic_ns=lambda: next(ticks))
    payload: JsonValue = {"items": [f"value {i}" for i in range(500)]}
    with pytest.raises(BrainError) as exc:
        flt.apply(payload, FilterPolicy(), deadline_ns=50_000_000)
    assert exc.value.code is ErrorCode.DEADLINE_EXCEEDED
    _assert_safe_error(exc.value)


def test_safe_payload_is_canonical_bounded_and_canary_free() -> None:
    payload: JsonValue = {
        "a": [f"<private>{CANARY}</private>", {"secret": CANARY}],
        "b": f"https://u:{CANARY}@h.invalid/p",
        "c": f"see /home/u/.ssh/{CANARY}",
    }
    safe = _apply(payload)
    _assert_no_canary(safe.value)
    for text in _walk_strings(safe.value):
        assert CANARY not in text
    assert parse_json(canonical_json(safe.value)) == safe.value
    with pytest.raises(BrainError):
        SafePayload(value=float("nan"), redacted_count=0, stripped_keys_count=0)
    with pytest.raises(BrainError):
        SafePayload(value="x", redacted_count=-1, stripped_keys_count=0)


# --- fix round 1 ----------------------------------------------------------------------------------------------------

ADVERSARIAL: tuple[str, ...] = (
    "a." * 30_000,
    "a://" * 15_000,
    "https://" + "a@" * 29_000,
    "x@" * 30_000,
    "sk-" * 20_000,
    "<" + " " * 60_000 + "x",
    "< " * 30_000,
    "</" * 30_000,
    "private " * 7_000,
    'password="' * 6_000,
    "Bearer " * 9_000,
    "eyJa." * 12_000,
    "-----BEGIN " * 5_000,
    "/." * 30_000,
    "a" * 60_000,
    "q8Zr2Lm9" * 7_500,
)


@pytest.mark.parametrize("text", ADVERSARIAL, ids=[f"adv{i}" for i in range(len(ADVERSARIAL))])
def test_adversarial_inputs_stay_within_local_budget(text: str) -> None:
    flt = PrivacyFilter()
    best = float("inf")
    for _ in range(3):
        start = time.perf_counter()
        try:
            flt.apply({"t": text}, FilterPolicy())
        except BrainError as err:
            assert err.code is ErrorCode.INVALID_INPUT
        best = min(best, time.perf_counter() - start)
        if best < 0.05:
            break
    assert best < 0.1, f"{best:.3f}s"


def test_tiny_deadline_raises_promptly_inside_long_strings() -> None:
    payloads: tuple[JsonValue, ...] = (
        {"t": "a." * 30_000},
        {"t": "https://" + "a@" * 29_000},
        [text[:60_000] for text in ADVERSARIAL],
    )
    for payload in payloads:
        start = time.perf_counter()
        with pytest.raises(BrainError) as exc:
            PrivacyFilter().apply(payload, FilterPolicy(), deadline_ns=time.monotonic_ns() + 1_000_000)
        assert exc.value.code is ErrorCode.DEADLINE_EXCEEDED
        assert time.perf_counter() - start < 0.05
        _assert_safe_error(exc.value)


@pytest.mark.parametrize(
    "token",
    [
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",  # AWS-style secret key with '/'
        "qWeRtYuIoPaSdFgHjKlZxCvBnMmNbVcXzLkJhGfD",  # 40 random letters, no digit
        "Zx9.Qw3.Er7.Ty1.Ui5.Op2.As8.Df4",  # dotted alnum
        "https://github.com/anthropics/claude-code",  # D6 accepts redacting long high-entropy runs
    ],
)
def test_d6_entropy_rule_covers_any_printable_run(token: str) -> None:
    safe = _apply({"t": f"value {token} end"})
    assert safe.value == {"t": f"value {REDACTED} end"}


def test_opaque_structural_id_survives_filter_and_manual_projection() -> None:
    opaque = "outcome-2026-11-06-Zx9Qw3Er7Ty1"  # >=24 chars, entropy >= 4.0, valid opaque ID
    payload: JsonValue = {"outcome_id": opaque, "status": "declared", "body": "dropped"}
    safe = _apply(payload, FilterPolicy(manual_submission=False))
    assert safe.value == {"outcome_id": opaque, "status": "declared"}
    assert project_manual_submission(payload, FilterPolicy(manual_submission=False)) == safe.value
    assert _apply({"note": opaque}).value == {"note": REDACTED}  # outside a structural field it is free text


def test_userinfo_is_redacted_up_to_the_last_at_before_host() -> None:
    safe = _apply({"u": f"https://user:p@ss{CANARY}@host.invalid/x"})
    assert safe.value == {"u": f"https://{REDACTED}@host.invalid/x"}


@pytest.mark.parametrize(
    ("text", "core"),
    [
        ("see `.env` here", ".env"),
        ("see `server.pem` here", "server.pem"),
        ("copy id_rsa. then", "id_rsa"),
        ("open ~/.ssh. then", ".ssh"),
        ("use prod.pem: now", "prod.pem"),
        ("**/home/u/.npmrc**", ".npmrc"),
    ],
)
def test_blocked_paths_in_markdown_and_punctuation_are_redacted(text: str, core: str) -> None:
    safe = _apply({"t": text})
    assert isinstance(safe.value, dict)
    out = str(safe.value["t"])
    assert core not in out and REDACTED in out


def test_keys_embedding_userinfo_entropy_or_blocked_path_drop_subtree() -> None:
    payload: JsonValue = {
        f"https://u:{CANARY}@h.invalid/x": {"v": 1},
        HIGH_ENTROPY: {"v": 2},
        "/home/u/.ssh/id_rsa": {"v": 3},
        "plain": 4,
    }
    safe = _apply(payload)
    assert safe.value == {"plain": 4}
    assert safe.stripped_keys_count == 3


def test_non_sensitive_keys_are_kept() -> None:
    payload: JsonValue = {"context_budget_tokens": 4000, "tokenizer": "utf8-byte-v1", "description": "x"}
    assert _apply(payload).value == payload


def test_input_size_cap_applies_before_redaction_shrinks_it() -> None:
    chunk = "<private>" + "b" * 59_000 + "</private>"
    payload: JsonValue = {"chunks": [chunk for _ in range(20)]}  # ~1.2 MB in, ~0.3 KB out
    with pytest.raises(BrainError) as exc:
        _apply(payload)
    assert exc.value.code is ErrorCode.INVALID_INPUT
