"""Ingress privacy filter (D6, spec 14.2): every payload is bounded and cleaned before it can be persisted.

The filter walks object keys and values and lists, drops sensitive-key subtrees and keys that themselves carry
secrets, redacts ``<private>`` blocks, fixed secret shapes, URL userinfo, ``key=value`` secrets, blocked paths and
high-entropy ASCII runs to ``[redacted]``, and refuses the whole payload on anything ambiguous (malformed private
markers, bounds, non-JSON values). Errors carry only a static allowlisted reason: never input text or ``str(exc)``.

Every scan is linear in the input (literal anchors, bounded quantifiers or hand-written scanners, never nested
unbounded quantifiers), and the shared local deadline is checked between scans inside each string.

Known limitation (outside D6): sensitive key names are matched after NFKC + casefold normalisation, so
compatibility forms (fullwidth letters, ligatures) are caught, but cross-script confusables (a Cyrillic ``а`` in
``pаssword``) are not; their values still pass through every value-level rule.
"""

from __future__ import annotations

import dataclasses
import fnmatch
import math
import re
import time
import unicodedata
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
_NODE_OVERHEAD = 2
_MAX_INT = 2**63
STATUS_FIELDS: frozenset[str] = frozenset({"schema_version", "status", "outcome", "state"})

_UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_STATUS_VALUE_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")
_PEM_BEGIN = re.compile(r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----")
_PEM_END = re.compile(r"-----END [A-Z0-9 ]{0,40}PRIVATE KEY-----")
_AUTH_HEADER = re.compile(r"(?i)\b(authorization|proxy-authorization)([ \t]{0,16}[:=][ \t]{0,16})[^\r\n,;]+")
_AUTH_SCHEME = re.compile(r"(?i)\b(bearer|basic|token)[ \t]{1,16}([A-Za-z0-9._~+/=-]{8,})")
_FIXED_TOKENS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{16,}"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}"),
)
_AUTHORITY = re.compile(r"[^/?#\s]*")
_SEGMENT = re.compile(r"\S*")
# Credential-like userinfo prefix ``user:`` right after ``scheme://``: the username may be empty and may contain
# a raw ``@`` (I2-T3-R06); it stops at whitespace, ``:``, ``/``, ``?`` or ``#``. Runs after successive ``://``
# are disjoint (each ``://`` holds a ``:`` and a ``/``), so matching stays linear.
_CREDENTIAL_USER = re.compile(r"[^\s:/?#]*:")
_KEY_VALUE_SECRET = re.compile(
    r"(?i)\b(password|passwd|pwd|passphrase|secret|api[_-]?key|access[_-]?token|refresh[_-]?token"
    r"|client[_-]?secret|auth[_-]?token|private[_-]?key)([ \t]{0,16}[=:][ \t]{0,16})"
    r"(\"[^\"\r\n]{0,512}\"|'[^'\r\n]{0,512}'|[^\s;,&]+)"
)
_PATH_TOKEN = re.compile(r"[^\s\"'<>|()\[\]{},;]+")
_PATH_SPLIT = re.compile(r"[\\/]+")
_PATH_LEAD = "`*([{<\"'"
_PATH_TRAIL = "`*)]}>\"'.,:;!?"
_ENTROPY_EDGE = "\"'()[]{}<>,;.!?:`*"
# Zero-width word boundaries (O(1) per position, so linear on any key): camelCase, acronym->Camel, letter<->digit.
_WORD_BOUNDARY = re.compile(
    r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])|(?<=[A-Za-z])(?=[0-9])|(?<=[0-9])(?=[A-Za-z])"
)
_KEY_WORD_SPLIT = re.compile(r"[^0-9a-z]+")
_ID_SEGMENTS = re.compile(r"[._-]")
_BENIGN_NEXT_WORDS: dict[str, frozenset[str]] = {
    "token": frozenset({"estimator", "estimate", "budget", "count", "counts", "limit", "usage", "total"}),
}
"""Word n-grams that are measurements, not credentials (``token_estimator``), when followed by these words."""
_CONTAINMENT_MIN = 6
"""A single word containing a sensitive name at least this long is sensitive (``mypassword``); ``token`` is not."""
_BENIGN_CONTAINING_WORDS: frozenset[str] = frozenset({"secretary", "secretaries", "secretariat", "secretarial"})


class _Reject(Exception):
    """Internal refusal; deliberately carries no text."""


class _Deadline(Exception):
    """Internal deadline signal; deliberately carries no text."""


def _key_words(key: str) -> list[str]:
    """NFKC + casefold words of a key, split at separators, camelCase, acronym->Camel and letter<->digit."""
    normalized = unicodedata.normalize("NFKC", key)
    return [word for word in _KEY_WORD_SPLIT.split(_WORD_BOUNDARY.sub(" ", normalized).casefold()) if word]


def _joined_key(key: str) -> str:
    return "".join(_key_words(key))


def _shannon_bits(text: str) -> float:
    counts = Counter(text)
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def _structural_kind(key: str) -> str:
    """Field type of a structural field (mcp-tools-v2 catalog): ``digest``, ``revision`` or an ID field."""
    if key == "digest" or key.endswith("_digest"):
        return "digest"
    if key == "revision":
        return "revision"
    return "id"


def _exempt_structural(key: str, value: object, min_segment: int) -> bool:
    """Whether ``value`` is a valid typed structural value for field ``key`` (never free text).

    ``digest``: only ``sha256:<64 lower hex>``. ``revision``: only a positive int. ID fields: a canonical UUID, or a
    catalog ``OpaqueId`` whose ``.``/``_``/``-`` separated segments are all shorter than the entropy candidate length
    (a separator-free credential-shaped run is never an ID).
    """
    kind = _structural_kind(key)
    if kind == "revision":
        return type(value) is int and value >= 1
    if not isinstance(value, str):
        return False
    if kind == "digest":
        return SHA256_DIGEST_RE.fullmatch(value) is not None
    if _UUID_RE.fullmatch(value):
        return True
    return OPAQUE_ID_RE.fullmatch(value) is not None and all(
        len(segment) < min_segment for segment in _ID_SEGMENTS.split(value)
    )


def _is_structural_id(value: str) -> bool:
    return _UUID_RE.fullmatch(value) is not None or SHA256_DIGEST_RE.fullmatch(value) is not None


def _tokenish(token: str) -> bool:
    """Credential-shaped: more than a lowercase prose word (a digit, a symbol or an inner capital)."""
    return any(ch.isdigit() or ch in "+/=_-.~" for ch in token) or any(ch.isupper() for ch in token[1:])


class _PathMatcher:
    """Component-boundary matcher for blocked path patterns (``name``, ``dir/`` and ``a/b`` chains)."""

    def __init__(self, patterns: tuple[str, ...]) -> None:
        self._dirs: set[str] = set()
        self._chains: list[list[re.Pattern[str]]] = []
        names: list[str] = []
        for pattern in patterns:
            lowered = pattern.lower()
            if lowered.endswith("/"):
                self._dirs.add(lowered.rstrip("/"))
            elif "/" in lowered:
                self._chains.append([re.compile(fnmatch.translate(part)) for part in lowered.split("/") if part])
            else:
                names.append(fnmatch.translate(lowered))
        self._names = re.compile("|".join(f"(?:{n})" for n in names)) if names else None

    def blocked(self, token: str) -> bool:
        parts = [p.lower() for p in _PATH_SPLIT.split(token) if p and p != "."]
        for index, part in enumerate(parts):
            if part in self._dirs or (self._names is not None and self._names.fullmatch(part)):
                return True
            for chain in self._chains:
                window = parts[index : index + len(chain)]
                if len(window) == len(chain) and all(rx.fullmatch(p) for rx, p in zip(chain, window, strict=True)):
                    return True
        return False


class _Run:
    def __init__(self, policy: FilterPolicy, monotonic_ns: Callable[[], int], deadline_ns: int | None) -> None:
        self.policy = policy
        self.redacted = 0
        self.stripped = 0
        self._input_bytes = 0
        self._monotonic_ns = monotonic_ns
        self._deadline_ns = deadline_ns
        self._sensitive = frozenset(_joined_key(k) for k in policy.sensitive_keys) - {""}
        self._paths = _PathMatcher(policy.blocked_path_patterns)
        self._min_segment = policy.entropy_min_length
        self._max_words = max((len(_key_words(k)) for k in policy.sensitive_keys), default=1)
        # Vocabulary = joined forms of every sensitive name (``access_token`` -> ``accesstoken``), so one word equal
        # to a joined multi-word name matches; ``_prefixes`` only prunes windows that can no longer reach one.
        self._prefixes = frozenset(name[:i] for name in self._sensitive for i in range(1, len(name) + 1))
        self._contained = tuple(sorted(name for name in self._sensitive if len(name) >= _CONTAINMENT_MIN))

    def tick(self) -> None:
        if self._deadline_ns is not None and self._monotonic_ns() >= self._deadline_ns:
            raise _Deadline

    def _count(self, size: int) -> None:
        """Input size cap: refuse before any redaction can shrink an oversized payload."""
        self._input_bytes += size + _NODE_OVERHEAD
        if self._input_bytes > MAX_TOTAL_BYTES:
            raise _Reject

    def value(self, item: object, depth: int, key: str | None = None) -> JsonValue:
        self.tick()
        if depth > MAX_DEPTH:
            raise _Reject
        self._count(0)
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
            structural = key is not None and key in self.policy.structural_id_fields
            if structural and _is_structural_id(item) and _exempt_structural(str(key), item, self._min_segment):
                return item
            exempt = structural and _exempt_structural(str(key), item, self._min_segment)
            # A typed structural ID is exempt from the entropy rule only, never from the fixed patterns.
            return self.redact(item, entropy=not exempt)
        if type(item) is list:
            if len(item) > MAX_ARRAY_ITEMS:
                raise _Reject
            return [self.value(child, depth + 1) for child in item]
        if type(item) is dict:
            return self._object(item, depth)
        raise _Reject

    def _sensitive_key(self, key: str) -> bool:
        """A key is sensitive when, over its NFKC/casefold words:

        * any contiguous window of words, joined, equals a sensitive name (exact word n-gram; a single word equal to
          a joined multi-word name such as ``accesstoken`` counts), unless a benign follower makes it a measurement
          (``token_estimator``); or
        * one word contains a sensitive name of >= 6 chars (``mypassword``), unless that word is benign
          (``secretary``).

        Windows are bounded by the longest name and pruned by name prefixes, so the check is linear in the key.
        """
        words = _key_words(key)
        for start, word in enumerate(words):
            if (
                len(word) >= _CONTAINMENT_MIN
                and word not in _BENIGN_CONTAINING_WORDS
                and any(name in word for name in self._contained)
            ):
                return True
            joined = ""
            for size in range(1, min(self._max_words, len(words) - start) + 1):
                joined += words[start + size - 1]
                if joined not in self._prefixes:
                    break
                if joined not in self._sensitive:
                    continue
                following = words[start + size] if start + size < len(words) else None
                if following is None or following not in _BENIGN_NEXT_WORDS.get(joined, frozenset()):
                    return True
        return False

    def _object(self, item: dict[object, object], depth: int) -> JsonValue:
        if len(item) > MAX_OBJECT_KEYS:
            raise _Reject
        out: dict[str, JsonValue] = {}
        for raw_key, child in item.items():
            if type(raw_key) is not str:
                raise _Reject
            self._check_text(raw_key)
            if self._sensitive_key(raw_key):
                self.stripped += 1
                self._measure(child, depth + 1)
                continue
            before = self.redacted
            if self.redact(raw_key) != raw_key:
                # A key that itself embeds a secret, private block or blocked path drops its whole subtree.
                self.redacted = before
                self.stripped += 1
                self._measure(child, depth + 1)
                continue
            out[raw_key] = self.value(child, depth + 1, key=raw_key)
        return out

    def _measure(self, item: object, depth: int) -> None:
        """Count a dropped subtree toward the input cap and bounds without redacting it (it is never kept)."""
        self.tick()
        if depth > MAX_DEPTH:
            raise _Reject
        self._count(0)
        if type(item) is str:
            self._check_text(item)
        elif type(item) is list:
            if len(item) > MAX_ARRAY_ITEMS:
                raise _Reject
            for child in item:
                self._measure(child, depth + 1)
        elif type(item) is dict:
            if len(item) > MAX_OBJECT_KEYS:
                raise _Reject
            for key, child in item.items():
                if type(key) is not str:
                    raise _Reject
                self._check_text(key)
                self._measure(child, depth + 1)
        elif not (item is None or type(item) in (bool, int, float)):
            raise _Reject

    def _check_text(self, text: str) -> None:
        size = len(text.encode("utf-8"))
        if size > MAX_TEXT_BYTES:
            raise _Reject
        self._count(size)

    def _sub(self, pattern: re.Pattern[str], repl: str | Callable[[re.Match[str]], str], text: str) -> str:
        new, count = pattern.subn(repl, text)
        self.redacted += count
        return new

    def _private(self, text: str) -> str:
        """``<private>…</private>`` -> ``[redacted]``; any malformed, orphan or nested marker refuses.

        A marker is ``<`` [ws] [``/``] [ws] ``private`` [ws] ``>`` (case-insensitive). Each ``private`` occurrence
        is inspected once, looking back over the whitespace run before it and forward over the one after it.
        """
        low = text.lower()
        if len(low) != len(text):  # a few characters lowercase to two; keep offsets aligned with ``text``
            low = "".join(ch.lower() if len(ch.lower()) == 1 else ch for ch in text)
        markers: list[tuple[int, int, bool]] = []
        index = low.find("private")
        while index != -1:
            j = index - 1
            while j >= 0 and low[j].isspace():
                j -= 1
            closing = j >= 0 and low[j] == "/"
            if closing:
                j -= 1
                while j >= 0 and low[j].isspace():
                    j -= 1
            if j >= 0 and low[j] == "<":
                k = index + 7
                while k < len(low) and low[k].isspace():
                    k += 1
                if k >= len(low) or low[k] != ">":
                    raise _Reject
                markers.append((j, k + 1, closing))
            index = low.find("private", index + 7)
        out: list[str] = []
        cursor, open_at = 0, -1
        for start, end, closing in markers:
            if not closing:
                if open_at >= 0:
                    raise _Reject
                out.append(text[cursor:start])
                open_at = start
            else:
                if open_at < 0:
                    raise _Reject
                out.append(REDACTED)
                self.redacted += 1
                cursor, open_at = end, -1
        if open_at >= 0:
            raise _Reject
        out.append(text[cursor:])
        return "".join(out)

    def _pem(self, text: str) -> str:
        out: list[str] = []
        cursor = 0
        begin = _PEM_BEGIN.search(text)
        while begin is not None:
            out.append(text[cursor : begin.start()])
            out.append(REDACTED)
            self.redacted += 1
            end = _PEM_END.search(text, begin.end())
            if end is None:  # unterminated key: redact to the end of the string
                return "".join(out)
            cursor = end.end()
            begin = _PEM_BEGIN.search(text, cursor)
        out.append(text[cursor:])
        return "".join(out)

    def _userinfo(self, text: str) -> str:
        """``scheme://user:pass@host`` -> ``scheme://[redacted]@host``.

        Privacy-first: a credential-like ``user:`` right after ``://`` is redacted through the last ``@`` before the
        next whitespace, even when ``/ ? #`` appear inside it. Otherwise userinfo is redacted up to the last ``@`` of
        the authority. Linear: each whitespace-delimited segment's end and last ``@`` are computed once.
        """
        out: list[str] = []
        cursor = 0
        seg_end = seg_last_at = -1
        index = text.find("://")
        while index != -1:
            start = index + 3
            if start > seg_end:
                segment = _SEGMENT.match(text, start)
                seg_end = segment.end() if segment is not None else start
                seg_last_at = text.rfind("@", start, seg_end)
            if seg_last_at > start and _CREDENTIAL_USER.match(text, start, seg_end):
                at = seg_last_at
            else:
                authority = _AUTHORITY.match(text, start)
                stop = authority.end() if authority is not None else start
                at = text.rfind("@", start, stop)
            if at > start:
                out.append(text[cursor:start])
                out.append(REDACTED)
                self.redacted += 1
                cursor = at
            index = text.find("://", max(at, start))
        out.append(text[cursor:])
        return "".join(out)

    def _auth_scheme(self, match: re.Match[str]) -> str:
        # Once ``Bearer``/``Basic`` is recognised its credential is a secret whatever its charset (I2-T3-R05); only
        # the plain word ``token`` keeps the prose heuristic ("the token validation step").
        if match.group(1).lower() == "token" and not _tokenish(match.group(2)):
            return match.group(0)
        self.redacted += 1
        return f"{match.group(1)} {REDACTED}"

    def _blocked_path(self, match: re.Match[str]) -> str:
        token = match.group(0)
        core = token.lstrip(_PATH_LEAD)
        lead = len(token) - len(core)
        core = core.rstrip(_PATH_TRAIL)
        if not core or not self._paths.blocked(core):
            return token
        self.redacted += 1
        return token[:lead] + REDACTED + token[lead + len(core) :]

    def _entropy(self, text: str) -> str:
        """D6: a maximal run of >= N printable non-whitespace ASCII chars with Shannon >= bits is redacted.

        Exempt: a run that is (inside surrounding punctuation) a canonical UUID or ``sha256:<64 hex>``. The
        ``[redacted]`` sentinel is a run boundary, never part of a candidate.
        """
        min_len = self.policy.entropy_min_length
        candidate = re.compile(rf"[\x21-\x7e]{{{min_len},}}")
        masked = text.replace(REDACTED, " " * len(REDACTED))
        spans = []
        for match in candidate.finditer(masked):
            token = match.group(0)
            if _is_structural_id(token.strip(_ENTROPY_EDGE)):
                continue
            if _shannon_bits(token) >= self.policy.entropy_min_bits:
                spans.append(match.span())
        for start, end in reversed(spans):
            text = text[:start] + REDACTED + text[end:]
        self.redacted += len(spans)
        return text

    def redact(self, text: str, *, entropy: bool = True) -> str:
        text = self._private(text)
        self.tick()
        text = self._pem(text)
        text = self._sub(_AUTH_HEADER, rf"\1\2{REDACTED}", text)
        self.tick()
        text = _AUTH_SCHEME.sub(self._auth_scheme, text)
        for pattern in _FIXED_TOKENS:
            text = self._sub(pattern, REDACTED, text)
            self.tick()
        text = self._userinfo(text)
        text = self._sub(_KEY_VALUE_SECRET, rf"\1\2{REDACTED}", text)
        self.tick()
        text = _PATH_TOKEN.sub(self._blocked_path, text)
        self.tick()
        if entropy:
            text = self._entropy(text)
        self.tick()  # after the last phase too: a late expiry is never hidden by returning
        return text


def _low_entropy_opaque_id(key: str, item: object, policy: FilterPolicy) -> bool:
    """An ``OpaqueId`` in an ID field whose long segments are low-entropy (same segment rule as the filter)."""
    if _structural_kind(key) != "id" or not isinstance(item, str) or not OPAQUE_ID_RE.fullmatch(item):
        return False
    return all(
        len(segment) < policy.entropy_min_length or _shannon_bits(segment) < policy.entropy_min_bits
        for segment in _ID_SEGMENTS.split(item)
    )


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
            if _exempt_structural(key, item, policy.entropy_min_length) or _low_entropy_opaque_id(key, item, policy):
                kept[key] = item
        elif key in STATUS_FIELDS and isinstance(item, str) and _STATUS_VALUE_RE.fullmatch(item):
            kept[key] = item
    return kept


def filter_policy_for(flags: RepoFlags, base: FilterPolicy | None = None) -> FilterPolicy:
    """The filter policy for a repo's current flags (``manual_submission`` follows the repo flag)."""
    if not isinstance(flags, RepoFlags):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    return dataclasses.replace(base if base is not None else FilterPolicy(), manual_submission=flags.manual_submission)


def admissible_field_path(path: tuple[str | int, ...], policy: FilterPolicy) -> bool:
    """Whether a structural field path may be persisted (CAS descriptor, ledger digest) under ``policy``.

    Every string segment must survive the filter exactly as an object key would: not a sensitive key and unchanged by
    every redaction rule. A path naming a key the filter strips is never persisted (I2-T3-R01).
    """
    if not isinstance(policy, FilterPolicy) or not isinstance(path, tuple):
        raise BrainError(ErrorCode.INVALID_INPUT, "invalid input")
    run = _Run(policy, time.monotonic_ns, None)
    admissible = True
    try:
        for segment in path:
            if isinstance(segment, str) and (run._sensitive_key(segment) or run.redact(segment) != segment):
                admissible = False
                break
    except (_Reject, UnicodeError, ValueError, TypeError, RecursionError):
        admissible = False
    return admissible


class PrivacyFilter:
    """Stateless filter; ``monotonic_ns`` is injectable so the shared local budget can be tested exactly.

    Deadline semantics are fail-closed: the deadline is checked per node, after every redaction phase and immediately
    before returning. The default clock is ``time.monotonic_ns``, whose resolution is platform-dependent (about
    15.6 ms on Windows with CPython 3.11, sub-microsecond on 3.13+); a deadline is "expired" when that clock says so.
    """

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
            run.tick()  # fail closed: no SafePayload is returned once now >= deadline_ns
        except _Deadline:
            outcome = ErrorCode.DEADLINE_EXCEEDED
        except (_Reject, UnicodeError, ValueError, TypeError, RecursionError, OverflowError):
            outcome = ErrorCode.INVALID_INPUT
        if outcome is ErrorCode.DEADLINE_EXCEEDED:
            raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded")
        if outcome is not None:
            raise BrainError(ErrorCode.INVALID_INPUT, REJECTED_MESSAGE)
        return SafePayload(value=cleaned, redacted_count=run.redacted, stripped_keys_count=run.stripped)
