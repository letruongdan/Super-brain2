"""Ingress privacy filter (D6, spec 14.2): every payload is bounded and cleaned before it can be persisted.

The filter walks object keys and values and lists, drops sensitive-key subtrees and keys that themselves carry
secrets, redacts ``<private>`` blocks, fixed secret shapes, URL userinfo, ``key=value`` secrets, blocked paths and
high-entropy ASCII tokens to ``[redacted]``, and refuses the whole payload on anything ambiguous (malformed private
markers, bounds, non-JSON values). Errors carry only a static allowlisted reason: never input text or ``str(exc)``.
"""

from __future__ import annotations

import dataclasses
import fnmatch
import math
import re
import time
from collections import Counter
from collections.abc import Callable

from superbrain.core.canonical import canonical_json
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import OPAQUE_ID_RE, SHA256_DIGEST_RE, FilterPolicy, RepoFlags, SafePayload

REDACTED = "[redacted]"
REJECTED_MESSAGE = "privacy filter rejected payload"
MAX_DEPTH = 32
MAX_TEXT_BYTES = 64 * 1024
MAX_ARRAY_ITEMS = 1024
MAX_OBJECT_KEYS = 1024
MAX_TOTAL_BYTES = 1024 * 1024
_MAX_INT = 2**63
STATUS_FIELDS: frozenset[str] = frozenset({"schema_version", "status", "outcome", "state"})

_UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_STRUCTURAL_SPAN_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:sha256:[0-9a-f]{64}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?![A-Za-z0-9])"
)
_STATUS_VALUE_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")
_PRIVATE_STRICT = re.compile(r"<\s*(/?)\s*private\s*>", re.IGNORECASE)
_PRIVATE_LOOSE = re.compile(r"<\s*/?\s*private", re.IGNORECASE)
_PEM = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)", re.DOTALL)
_AUTH_HEADER = re.compile(r"(?i)\b(authorization|proxy-authorization)(\s*[:=]\s*)[^\r\n,;]+")
_AUTH_SCHEME = re.compile(r"(?i)\b(bearer|basic|token)\s+([A-Za-z0-9._~+/=-]{8,})")
_FIXED_TOKENS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{16,}"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}"),
)
_URL_USERINFO = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)([^\s/@?#\[\]]+)@")
_KEY_VALUE_SECRET = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret"
    r"|auth[_-]?token|private[_-]?key)(\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s;,&]+)"
)
_PATH_TOKEN = re.compile(r"[^\s\"'<>|()\[\]{},;]+")
_PATH_SPLIT = re.compile(r"[\\/]+")


class _Reject(Exception):
    """Internal refusal; deliberately carries no text."""


class _Deadline(Exception):
    """Internal deadline signal; deliberately carries no text."""


def _normalize_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key.lower())


def _shannon_bits(text: str) -> float:
    counts = Counter(text)
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def _is_structural_id(value: str) -> bool:
    return _UUID_RE.fullmatch(value) is not None or SHA256_DIGEST_RE.fullmatch(value) is not None


def _tokenish(token: str) -> bool:
    """Credential-shaped: more than a lowercase prose word (a digit, a symbol or an inner capital)."""
    return any(ch.isdigit() or ch in "+/=_-.~" for ch in token) or any(ch.isupper() for ch in token[1:])


class _PathMatcher:
    def __init__(self, patterns: tuple[str, ...]) -> None:
        self._dirs: list[str] = []
        self._chains: list[list[str]] = []
        self._names: list[str] = []
        for pattern in patterns:
            lowered = pattern.lower()
            if lowered.endswith("/"):
                self._dirs.append(lowered.rstrip("/"))
            elif "/" in lowered:
                self._chains.append([part for part in lowered.split("/") if part])
            else:
                self._names.append(lowered)

    def blocked(self, token: str) -> bool:
        parts = [p.lower() for p in _PATH_SPLIT.split(token) if p]
        for index, part in enumerate(parts):
            if part in self._dirs or any(fnmatch.fnmatchcase(part, name) for name in self._names):
                return True
            for chain in self._chains:
                window = parts[index : index + len(chain)]
                if len(window) != len(chain):
                    continue
                if all(fnmatch.fnmatchcase(p, c) for p, c in zip(window, chain, strict=True)):
                    return True
        return False


class _Run:
    def __init__(self, policy: FilterPolicy, monotonic_ns: Callable[[], int], deadline_ns: int | None) -> None:
        self.policy = policy
        self.redacted = 0
        self.stripped = 0
        self._monotonic_ns = monotonic_ns
        self._deadline_ns = deadline_ns
        self._sensitive = tuple(sorted({_normalize_key(k) for k in policy.sensitive_keys} - {""}))
        self._paths = _PathMatcher(policy.blocked_path_patterns)

    def tick(self) -> None:
        if self._deadline_ns is not None and self._monotonic_ns() >= self._deadline_ns:
            raise _Deadline

    def value(self, item: object, depth: int, key: str | None = None) -> JsonValue:
        self.tick()
        if depth > MAX_DEPTH:
            raise _Reject
        if item is None or type(item) is bool:
            return item
        if type(item) is int:
            if not (-_MAX_INT <= item < _MAX_INT):
                raise _Reject
            return item
        if type(item) is float:
            if not math.isfinite(item):
                raise _Reject
            return item
        if type(item) is str:
            self._check_text(item)
            if key is not None and key in self.policy.structural_id_fields and _is_structural_id(item):
                return item
            return self.redact(item)
        if type(item) is list:
            if len(item) > MAX_ARRAY_ITEMS:
                raise _Reject
            return [self.value(child, depth + 1) for child in item]
        if type(item) is dict:
            return self._object(item, depth)
        raise _Reject

    def _object(self, item: dict[object, object], depth: int) -> JsonValue:
        if len(item) > MAX_OBJECT_KEYS:
            raise _Reject
        out: dict[str, JsonValue] = {}
        for raw_key, child in item.items():
            if type(raw_key) is not str:
                raise _Reject
            self._check_text(raw_key)
            normalized = _normalize_key(raw_key)
            if any(name in normalized for name in self._sensitive):
                self.stripped += 1
                continue
            before = self.redacted
            if self.redact(raw_key) != raw_key:
                # A key that itself embeds a secret, private block or blocked path drops its whole subtree.
                self.redacted = before
                self.stripped += 1
                continue
            out[raw_key] = self.value(child, depth + 1, key=raw_key)
        return out

    @staticmethod
    def _check_text(text: str) -> None:
        if len(text.encode("utf-8")) > MAX_TEXT_BYTES:
            raise _Reject

    def _sub(self, pattern: re.Pattern[str], repl: str | Callable[[re.Match[str]], str], text: str) -> str:
        new, count = pattern.subn(repl, text)
        self.redacted += count
        return new

    def _private(self, text: str) -> str:
        strict = list(_PRIVATE_STRICT.finditer(text))
        if len(_PRIVATE_LOOSE.findall(text)) != len(strict):
            raise _Reject
        out: list[str] = []
        cursor, open_at = 0, -1
        for match in strict:
            closing = match.group(1) == "/"
            if not closing:
                if open_at >= 0:
                    raise _Reject
                out.append(text[cursor : match.start()])
                open_at = match.start()
            else:
                if open_at < 0:
                    raise _Reject
                out.append(REDACTED)
                self.redacted += 1
                cursor, open_at = match.end(), -1
        if open_at >= 0:
            raise _Reject
        out.append(text[cursor:])
        return "".join(out)

    def _auth_scheme(self, match: re.Match[str]) -> str:
        if not _tokenish(match.group(2)):
            return match.group(0)
        self.redacted += 1
        return f"{match.group(1)} {REDACTED}"

    def _blocked_path(self, match: re.Match[str]) -> str:
        token = match.group(0)
        if not self._paths.blocked(token):
            return token
        self.redacted += 1
        return REDACTED

    def _entropy(self, text: str) -> str:
        masked = _STRUCTURAL_SPAN_RE.sub(lambda m: " " * len(m.group(0)), text)
        min_len = self.policy.entropy_min_length
        candidate = re.compile(rf"[A-Za-z0-9+=_~-]{{{min_len},}}")
        spans = []
        for match in candidate.finditer(masked):
            token = match.group(0)
            has_digit = any(ch.isdigit() for ch in token)
            has_alpha = any(ch.isalpha() for ch in token)
            if has_digit and has_alpha and _shannon_bits(token) >= self.policy.entropy_min_bits:
                spans.append(match.span())
        for start, end in reversed(spans):
            text = text[:start] + REDACTED + text[end:]
        self.redacted += len(spans)
        return text

    def redact(self, text: str) -> str:
        text = self._private(text)
        text = self._sub(_PEM, REDACTED, text)
        text = self._sub(_AUTH_HEADER, rf"\1\2{REDACTED}", text)
        text = _AUTH_SCHEME.sub(self._auth_scheme, text)
        for pattern in _FIXED_TOKENS:
            text = self._sub(pattern, REDACTED, text)
        text = self._sub(_URL_USERINFO, rf"\1{REDACTED}@", text)
        text = self._sub(_KEY_VALUE_SECRET, rf"\1\2{REDACTED}", text)
        text = _PATH_TOKEN.sub(self._blocked_path, text)
        return self._entropy(text)


def project_manual_submission(value: JsonValue, policy: FilterPolicy) -> JsonValue:
    """Spec 14.2 ``manual_submission=false``: keep only structural IDs and status metadata of an object.

    Bodies, content, evidence and read acks are dropped; with ``manual_submission=true`` ``value`` is unchanged.
    """
    if not isinstance(policy, FilterPolicy):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    if policy.manual_submission:
        return value
    if not isinstance(value, dict):
        return {}
    kept: dict[str, JsonValue] = {}
    for key, item in value.items():
        if key in policy.structural_id_fields:
            if (isinstance(item, str) and OPAQUE_ID_RE.fullmatch(item)) or (
                isinstance(item, str) and SHA256_DIGEST_RE.fullmatch(item)
            ):
                kept[key] = item
            elif type(item) is int and item >= 0:
                kept[key] = item
        elif key in STATUS_FIELDS and isinstance(item, str) and _STATUS_VALUE_RE.fullmatch(item):
            kept[key] = item
    return kept


def filter_policy_for(flags: RepoFlags, base: FilterPolicy | None = None) -> FilterPolicy:
    """The filter policy for a repo's current flags (``manual_submission`` follows the repo flag)."""
    if not isinstance(flags, RepoFlags):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    return dataclasses.replace(base if base is not None else FilterPolicy(), manual_submission=flags.manual_submission)


class PrivacyFilter:
    """Stateless filter; ``monotonic_ns`` is injectable so the shared local budget can be tested exactly."""

    def __init__(self, monotonic_ns: Callable[[], int] = time.monotonic_ns) -> None:
        self._monotonic_ns = monotonic_ns

    def apply(self, value: JsonValue, policy: FilterPolicy, *, deadline_ns: int | None = None) -> SafePayload:
        """Filter ``value`` under ``policy`` by ``deadline_ns``.

        ``INVALID_INPUT`` (``privacy filter rejected payload``) on refusal, ``DEADLINE_EXCEEDED`` when the shared
        local budget runs out first; both raised outside any handler so no raw text rides along as context.
        """
        if not isinstance(policy, FilterPolicy):
            raise BrainError(ErrorCode.INVALID_INPUT, REJECTED_MESSAGE)
        if deadline_ns is not None and type(deadline_ns) is not int:
            raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
        run = _Run(policy, self._monotonic_ns, deadline_ns)
        outcome: ErrorCode | None = None
        cleaned: JsonValue = None
        try:
            cleaned = project_manual_submission(run.value(value, 1), policy)
            if len(canonical_json(cleaned)) > MAX_TOTAL_BYTES:
                outcome = ErrorCode.INVALID_INPUT
        except _Deadline:
            outcome = ErrorCode.DEADLINE_EXCEEDED
        except (_Reject, UnicodeError, ValueError, TypeError, RecursionError, OverflowError):
            outcome = ErrorCode.INVALID_INPUT
        if outcome is ErrorCode.DEADLINE_EXCEEDED:
            raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")
        if outcome is not None:
            raise BrainError(ErrorCode.INVALID_INPUT, REJECTED_MESSAGE)
        return SafePayload(value=cleaned, redacted_count=run.redacted, stripped_keys_count=run.stripped)
