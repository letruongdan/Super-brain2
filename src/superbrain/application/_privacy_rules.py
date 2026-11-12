"""Privacy filter rules (D6): limits, secret shapes, structural IDs and the blocked-path matcher."""

from __future__ import annotations

import fnmatch
import re
import unicodedata
from functools import lru_cache

from superbrain.core.kernel import (
    OPAQUE_ID_RE,
    SHA256_DIGEST_RE,
)

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
# A token holding ``.`` or ``_``: enough when every blocked-pattern needle holds one (lower() never makes them).
_DOTTED_PATH_TOKEN = re.compile(
    r"(?<![^\s\"'<>|()\[\]{},;])(?=[^\s\"'<>|()\[\]{},;]*[._])[^\s\"'<>|()\[\]{},;]+"
)
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
    return (
        len(value) == 36 and _UUID_RE.fullmatch(value) is not None
        or len(value) == 71 and SHA256_DIGEST_RE.fullmatch(value) is not None
    )


def _tokenish(token: str) -> bool:
    """Credential-shaped: more than a lowercase prose word (a digit, a symbol or an inner capital)."""
    return any(ch.isdigit() or ch in "+/=_-.~" for ch in token) or any(ch.isupper() for ch in token[1:])


def _component_needle(part: str) -> str:
    """Longest literal run every fnmatch fullmatch of ``part`` must contain; ``""`` when none is guaranteed."""
    if "[" in part:  # a bracket class matches one of several characters: keep only the literal text before it
        part = part[: part.index("[")]
    return max(re.split(r"[*?]", part), key=len)


@lru_cache(maxsize=32)
def _path_needles(patterns: tuple[str, ...]) -> tuple[str, ...] | None:
    """Lowercase substrings one of which every blocked token's lowercase form contains; ``None``: no prefilter.

    Derived from the policy's own patterns, so a pattern added to any list (the shipped default included) is never
    skipped by a stale hand-written prefilter.
    """
    needles: set[str] = set()
    for pattern in patterns:
        lowered = pattern.lower()
        parts = [lowered.rstrip("/")] if lowered.endswith("/") else [part for part in lowered.split("/") if part]
        best = max((_component_needle(part) for part in parts), key=len, default="")
        if not best:
            return None
        needles.add(best)
    return tuple(sorted(needles))


_REGEX_META = frozenset(r".^$*+?{}[]\|()")
# (leading literals, literal last chars of the leading group's alternatives, case-folded, separator chars)
_RuleGate = tuple[tuple[str, ...], frozenset[str] | None, bool, str | None]


def _literal_run(text: str) -> str:
    end = 0
    while end < len(text) and text[end] not in _REGEX_META:
        end += 1
    return text[:end]


@lru_cache(maxsize=64)
def _rule_gate(pattern: re.Pattern[str]) -> _RuleGate | None:
    r"""Cheap necessary condition for a ``\b``-anchored rule, read from the rule itself; ``None``: always run it.

    Every match starts with one of the leading literals. When the leading group is followed by
    ``([ \t]{0,16}[=:]``, a match also holds one of the alternatives' last characters (or a blank) right before
    ``=`` or ``:``. Anything the reader does not recognise gives no gate, never a stale one.
    """
    fold = bool(pattern.flags & re.IGNORECASE)
    source = pattern.pattern.removeprefix("(?i)")
    if not source.startswith(r"\b"):
        return None
    source = source[2:]
    ends: set[str] | None = None
    seps: str | None = None
    if source.startswith("("):
        start = 3 if source.startswith("(?:") else 1
        close = source.find(")")
        if close < 0 or "(" in source[start:close]:
            return None
        alternatives = source[start:close].split("|")
        if source[close + 1 :].startswith(r"([ \t]{0,16}[=:]"):
            ends, seps = set(), "=:"
    else:
        alternatives = [source]
    leads: list[str] = []
    for alternative in alternatives:
        lead = _literal_run(alternative)
        if not lead:
            return None
        leads.append(lead.lower() if fold else lead)
        if ends is not None:
            last = alternative[-1:]
            if not last or last in _REGEX_META or alternative[-2:-1] == "\\":
                ends, seps = None, None
            else:
                ends.add(last.lower() if fold else last)
    return tuple(leads), (frozenset(ends) if ends is not None else None), fold, seps


def _gate_open(pattern: re.Pattern[str], text: str, ascii_text: bool) -> bool:
    """False only when ``pattern`` cannot match ``text``; case-folded gates are trusted on ASCII text only."""
    gate = _rule_gate(pattern)
    if gate is None:
        return True
    leads, ends, fold, seps = gate
    if fold:
        if not ascii_text:
            return True
        text = text.lower()
    if not any(lead in text for lead in leads):
        return False
    if ends is None or seps is None:
        return True
    return any(f"{end}{sep}" in text for end in (*ends, " ", "\t") for sep in seps)


class _PathMatcher:
    """Component-boundary matcher for blocked path patterns (``name``, ``dir/`` and ``a/b`` chains)."""

    def __init__(self, patterns: tuple[str, ...]) -> None:
        self._chains: list[list[re.Pattern[str]]] = []
        names: list[str] = []
        for pattern in patterns:
            lowered = pattern.lower()
            if lowered.endswith("/"):  # ``dir/``: any component matching the glob, like a name pattern
                names.append(fnmatch.translate(lowered.rstrip("/")))
            elif "/" in lowered:
                self._chains.append([re.compile(fnmatch.translate(part)) for part in lowered.split("/") if part])
            else:
                names.append(fnmatch.translate(lowered))
        self._names = re.compile("|".join(f"(?:{n})" for n in names)) if names else None
        self._results: dict[str, bool] = {}
        self._needles = _path_needles(patterns)

    def blocked(self, token: str) -> bool:
        cached = self._results.get(token)
        if cached is not None:
            return cached
        result = self._matches(token)
        if len(self._results) < 1024:
            self._results[token] = result
        return result

    def _matches(self, token: str) -> bool:
        low = token.lower()
        if self._needles is not None and not any(needle in low for needle in self._needles):
            return False
        parts = [p for p in _PATH_SPLIT.split(low) if p and p != "."]
        for index, part in enumerate(parts):
            if self._names is not None and self._names.fullmatch(part):
                return True
            for chain in self._chains:
                window = parts[index : index + len(chain)]
                if len(window) == len(chain) and all(rx.fullmatch(p) for rx, p in zip(chain, window, strict=True)):
                    return True
        return False
