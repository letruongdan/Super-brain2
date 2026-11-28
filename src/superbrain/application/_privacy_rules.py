"""Privacy filter rules (D6): limits, secret shapes, structural IDs and the blocked-path matcher."""

from __future__ import annotations

import dataclasses
import fnmatch
import hashlib
import re
import unicodedata
from collections.abc import Sequence
from functools import lru_cache

from superbrain.application._privacy_globs import _Glob as _Glob
from superbrain.application._privacy_globs import _glob_units as _glob_units
from superbrain.application._privacy_globs import _unit_regex as _unit_regex
from superbrain.core._kernel_base import OPAQUE_ID_RE, SHA256_DIGEST_RE
from superbrain.core._kernel_workspace import blocked_path_components

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
# Exact ASCII printable + split-whitespace bytes (excludes \x1c-\x1f where bytes.split and str.split differ).
_PRINTABLE_AND_WS_BYTES = bytes(range(0x20, 0x7F)) + b"\t\n\r\x0b\x0c"
_PRINTABLE_NON_WS_BYTES = bytes(range(0x21, 0x7F))
_JSON_SAFE_NL_BYTES = bytes(range(0x20, 0x7F)) + b"\n"
# Stems covering every alternation in ``_KEY_VALUE_SECRET`` (``pass`` covers ``password``/``passwd``/``passphrase``).
_KV_WORDS = ("token", "pass", "pwd", "secret", "key")

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
_ASCII_WORD_SPLIT = re.compile(r"[0-9]+|[A-Z]+(?![a-z])|[A-Z]?[a-z]+")
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
    if key.isascii():
        words = _ASCII_WORD_SPLIT.findall(key)
        return words if key.islower() else [word.lower() for word in words]
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
        best = max((_component_needle(part) for part in blocked_path_components(pattern)), key=len, default="")
        if not best:
            return None
        needles.add(best)
    raw = sorted(needles)
    kept = [needle for needle in raw if not any(other != needle and other in needle for other in raw)]
    return tuple(kept)


def _trie_regex(strings: Sequence[str]) -> str:
    """Compile sorted non-empty literal suffixes into a prefix-factored regex alternation."""
    buckets: dict[str, list[str]] = {}
    for item in strings:
        buckets.setdefault(item[0], []).append(item)
    parts: list[str] = []
    for ch, items in buckets.items():
        if len(items) == 1:
            parts.append(re.escape(items[0]))
            continue
        tails = [item[1:] for item in items]
        if "" in tails:
            parts.append(re.escape(ch))
            continue
        parts.append(f"{re.escape(ch)}(?:{_trie_regex(tails)})")
    return "|".join(parts)


@dataclasses.dataclass(frozen=True, slots=True)
class _PathPrefilter:
    """Linear prefilter equivalent to ``any(n in lowered for n in needles)`` (or open when ``open_all``)."""

    open_all: bool
    dot_re: re.Pattern[str] | None
    groups: tuple[tuple[str, tuple[str, ...]], ...]
    singles: tuple[str, ...]

    def matches(self, lowered: str) -> bool:
        if self.open_all:
            return True
        for needle in self.singles:
            if needle in lowered:
                return True
        for prefix, group in self.groups:
            if prefix in lowered:
                for needle in group:
                    if needle in lowered:
                        return True
        return self.dot_re is not None and "." in lowered and self.dot_re.search(lowered) is not None


@lru_cache(maxsize=32)
def _build_path_prefilter(needles: tuple[str, ...] | None) -> _PathPrefilter:
    """Group path needles into singleton literals, 3-char prefix buckets, and a factored dot regex."""
    if needles is None:
        return _PathPrefilter(open_all=True, dot_re=None, groups=(), singles=())
    dot_tails: list[str] = []
    other: list[str] = []
    for needle in needles:
        if len(needle) > 1 and needle[0] == ".":
            dot_tails.append(needle[1:])
        else:
            other.append(needle)
    dot_re: re.Pattern[str] | None = None
    if len(dot_tails) >= 2:
        dot_re = re.compile(rf"\.(?:{_trie_regex(dot_tails)})")
    elif dot_tails:
        other.append("." + dot_tails[0])
    prefix_buckets: dict[str, list[str]] = {}
    singles: list[str] = []
    for needle in other:
        if len(needle) >= 3:
            prefix_buckets.setdefault(needle[:3], []).append(needle)
        else:
            singles.append(needle)
    groups: list[tuple[str, tuple[str, ...]]] = []
    for prefix, items in prefix_buckets.items():
        if len(items) >= 2:
            groups.append((prefix, tuple(items)))
        elif len(items[0]) >= 5 and items[0][0] == "_":
            # Guard rare leading-underscore filenames (e.g. ``_netrc``) by their rarer tail first.
            groups.append((items[0][1:], (items[0],)))
        else:
            singles.append(items[0])
    return _PathPrefilter(open_all=False, dot_re=dot_re, groups=tuple(groups), singles=tuple(singles))


# Gates for the shipped rules, each pinned to the exact rule text (flags + pattern) it was checked against. An edited
# or added rule has no entry and always runs, so a gate can never be stale; no regex is parsed to build one.
# (needles one of which every match holds, "<last char><separator>" pairs or None, compare case-folded)
_RuleGate = tuple[tuple[str, ...], tuple[str, ...] | None, bool]
_KV_EQ_PAIRS = ("d=", "e=", "n=", "t=", "y=", " =", "\t=")
_KV_COLON_PAIRS = ("d:", "e:", "n:", "t:", "y:", " :", "\t:")
_KV_PAIRS = (*_KV_EQ_PAIRS, *_KV_COLON_PAIRS)
_RULE_GATES: dict[str, _RuleGate] = {
    "a640d3fcd03f3622": (("authorization", "proxy-authorization"), None, True),  # _AUTH_HEADER
    "2b74d6348b7f85b8": (("bearer", "basic", "token"), None, True),  # _AUTH_SCHEME
    "800fedecfd83067a": (("password", "passwd", "pwd", "passphrase", "secret", "key", "token"), _KV_PAIRS, True),
    "b28cd107992a4ba1": (("github_pat_",), None, False),  # _FIXED_TOKENS[0]
    "092ac9a36b30cd8f": (("ghp_", "gho_", "ghu_", "ghs_", "ghr_"), None, False),  # _FIXED_TOKENS[1]
    "86297f39e32a8e45": (("sk-",), None, False),  # _FIXED_TOKENS[2]
    "4aed425b63d1fcb7": (("AKIA", "ASIA"), None, False),  # _FIXED_TOKENS[3]
    "4f2fc09f0b773dcb": (("xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"), None, False),  # _FIXED_TOKENS[4]
    "fb1e448c567540e2": (("AIza",), None, False),  # _FIXED_TOKENS[5]
    "a05f078b9a278638": (("eyJ",), None, False),  # _FIXED_TOKENS[6]
}  # the third entry is _KEY_VALUE_SECRET


@lru_cache(maxsize=64)
def _rule_text_digest(pattern: re.Pattern[str]) -> str:
    return hashlib.sha256(f"{pattern.flags}\0{pattern.pattern}".encode()).hexdigest()[:16]


@lru_cache(maxsize=64)
def _rule_gate(pattern: re.Pattern[str]) -> _RuleGate | None:
    """The gate checked for exactly this rule text, or ``None``: the rule always runs."""
    return _RULE_GATES.get(_rule_text_digest(pattern))


def _shipped_rules_intact(
    auth_header: re.Pattern[str],
    auth_scheme: re.Pattern[str],
    fixed_tokens: tuple[re.Pattern[str], ...],
    key_value: re.Pattern[str],
) -> bool:
    """True only when every rule passed matches a shipped gate pinned in ``_RULE_GATES``."""
    return (
        _rule_gate(auth_header) is not None
        and _rule_gate(auth_scheme) is not None
        and _rule_gate(key_value) is not None
        and all(_rule_gate(pattern) is not None for pattern in fixed_tokens)
    )


_FIXED_TOKEN_DIGESTS: tuple[str, ...] = (
    "b28cd107992a4ba1",
    "092ac9a36b30cd8f",
    "86297f39e32a8e45",
    "4aed425b63d1fcb7",
    "4f2fc09f0b773dcb",
    "fb1e448c567540e2",
    "a05f078b9a278638",
)


@dataclasses.dataclass(frozen=True, slots=True)
class _FastScanPatterns:
    """Prefilter and fast-path helper patterns bound inside an ``lru_cache``, keeping module globals untouched."""

    priv_lower: re.Pattern[str]
    ui_neg: re.Pattern[str]
    ui_repl: str
    b_auth: re.Pattern[str]
    gh_both: re.Pattern[str]
    gh: re.Pattern[str]
    sk: re.Pattern[str]
    xox: re.Pattern[str]
    eyj: re.Pattern[str]


@lru_cache(maxsize=1)
def _fast_patterns() -> _FastScanPatterns:
    """Compile and cache non-rule helper/prefilter regexes once without adding module ``re.Pattern`` globals."""
    return _FastScanPatterns(
        priv_lower=re.compile(r"<private>[^<]*</private>"),
        ui_neg=re.compile(r"://[^/?#\s@]+@(?![^\s@]*@)"),
        ui_repl=f"://{REDACTED}@",
        b_auth=re.compile(r"b(?:earer|asic)"),
        gh_both=re.compile(r"g(?:ithub_pat_|h[pousr]_)"),
        gh=re.compile(r"gh[pousr]_"),
        sk=re.compile(r"sk-[A-Za-z0-9_-]{16,}"),
        xox=re.compile(r"xox[baprs]-"),
        eyj=re.compile(r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}"),
    )


def _fast_scans_intact(
    auth_header: re.Pattern[str],
    auth_scheme: re.Pattern[str],
    fixed_tokens: tuple[re.Pattern[str], ...],
    key_value: re.Pattern[str],
    priv_mark: re.Pattern[str],
    priv_block: re.Pattern[str],
    authority: re.Pattern[str],
    segment: re.Pattern[str],
    cred_user: re.Pattern[str],
) -> bool:
    """True only when every shipped rule and scan helper matches its exact unmodified pattern and order."""
    return (
        auth_header is _AUTH_HEADER
        and auth_scheme is _AUTH_SCHEME
        and fixed_tokens == _FIXED_TOKENS
        and key_value is _KEY_VALUE_SECRET
        and _rule_text_digest(auth_header) == "a640d3fcd03f3622"
        and _rule_text_digest(auth_scheme) == "2b74d6348b7f85b8"
        and _rule_text_digest(key_value) == "800fedecfd83067a"
        and len(fixed_tokens) == 7
        and tuple(_rule_text_digest(pattern) for pattern in fixed_tokens) == _FIXED_TOKEN_DIGESTS
        and _rule_text_digest(priv_mark) == "5e39f4b39086bff6"
        and _rule_text_digest(priv_block) == "04d7c49d316c286e"
        and _rule_text_digest(authority) == "e8c71458b8472664"
        and _rule_text_digest(segment) == "bbd92f285662d9bb"
        and _rule_text_digest(cred_user) == "838390bd43b0bdde"
    )


def _gate_open(pattern: re.Pattern[str], text: str, lowered: str | None) -> bool:
    """False only when ``pattern`` cannot match ``text``.

    ``lowered`` is ``text.lower()`` for ASCII text and ``None`` otherwise: ``re.IGNORECASE`` matches characters that
    ``str.lower()`` does not map (``ſ`` matches ``s``), so a case-folded gate is trusted on ASCII text only.
    """
    gate = _rule_gate(pattern)
    if gate is None:
        return True
    needles, pairs, fold = gate
    if fold:
        if lowered is None:
            return True
        text = lowered
    if pairs is _KV_PAIRS:
        has_pair = False
        if "=" in text:
            for pair in _KV_EQ_PAIRS:
                if pair in text:
                    has_pair = True
                    break
        if not has_pair and ":" in text:
            for pair in _KV_COLON_PAIRS:
                if pair in text:
                    has_pair = True
                    break
        if not has_pair:
            return False
    elif pairs is not None:
        if "=" not in text and ":" not in text:
            return False
        for pair in pairs:
            if pair in text:
                break
        else:
            return False
    if len(needles) == 5:
        first = needles[0]
        if first == "ghp_" and "gh" not in text:
            return False
        if first == "xoxb-" and "xox" not in text:
            return False
    for needle in needles:
        if needle in text:
            return True
    return False


class _PathMatcher:
    """Component-boundary matcher for blocked path patterns (``name``, ``dir/`` and ``a/b`` chains)."""

    def __init__(self, patterns: tuple[str, ...]) -> None:
        self._chains: list[list[re.Pattern[str]]] = []
        self._name_globs: list[_Glob] = []
        self._chain_globs: list[list[_Glob]] = []
        names: list[str] = []
        for pattern in patterns:
            # ``name``, ``dir/`` and ``a/b`` (either separator): globs over a window of consecutive token components.
            parts = blocked_path_components(pattern)
            if len(parts) == 1:
                names.append(fnmatch.translate(parts[0]))
                self._name_globs.append(_Glob(parts[0]))
            elif parts:
                self._chains.append([re.compile(fnmatch.translate(part)) for part in parts])
                self._chain_globs.append([_Glob(part) for part in parts])
        self._names = re.compile("|".join(f"(?:{n})" for n in names)) if names else None
        self._results: dict[str, bool] = {}
        self._find_results: dict[str, tuple[int, int] | tuple[()]] = {}
        self._needles = _path_needles(patterns)
        self._single_needle: str | None = (
            self._needles[0] if (self._needles is not None and len(self._needles) == 1) else None
        )
        self._prefilter: _PathPrefilter | None = (
            _build_path_prefilter(self._needles) if (self._needles is not None and len(self._needles) > 1) else None
        )

    def fresh(self) -> _PathMatcher:
        """Clone immutable compiled matchers with an empty per-run result cache."""
        clone = object.__new__(_PathMatcher)
        clone._chains = self._chains
        clone._name_globs = self._name_globs
        clone._chain_globs = self._chain_globs
        clone._names = self._names
        clone._needles = self._needles
        clone._single_needle = self._single_needle
        clone._prefilter = self._prefilter
        clone._results = {}
        clone._find_results = {}
        return clone

    def may_block(self, token: str) -> bool:
        """False only when no spelling inside ``token`` can match: every match holds one of the needles."""
        if self._needles is None:
            return True
        low = token.lower()
        if self._single_needle is not None:
            return self._single_needle in low
        assert self._prefilter is not None
        return self._prefilter.matches(low)

    def find_cached(self, token: str) -> tuple[int, int] | None:
        """Per-run bounded cache over ``may_block`` + ``find`` for repeated tokens."""
        cached = self._find_results.get(token)
        if cached is not None:
            return cached if cached else None
        found = self.find(token) if self.may_block(token) else None
        if len(token) <= 256 and len(self._find_results) < 2048:
            self._find_results[token] = found if found is not None else ()
        return found

    def blocked(self, token: str) -> bool:
        cached = self._results.get(token)
        if cached is not None:
            return cached
        result = self._matches(token)
        if len(token) <= 256 and len(self._results) < 1024:  # bounded memory: long tokens are not cached
            self._results[token] = result
        return result

    def find(self, token: str) -> tuple[int, int] | None:
        """§14.2 for a wrapped token: ``(p, s)`` such that ``token[p:len - s]`` is a blocked spelling, where ``p``
        and ``s`` trim inside the leading and trailing wrapper runs (measured on the whole token), else ``None``.

        Trimming only changes the first and the last component, so the token is split once and each glob is tested
        on a handful of edge spellings (see ``_Glob``): linear in the token, with no cap on the wrapper runs.
        """
        low = token.lower()  # wrapper runs are ASCII, so their lengths match between ``token`` and ``low``
        lead = len(low) - len(low.lstrip(_PATH_LEAD))
        trail = len(low) - len(low.rstrip(_PATH_TRAIL))
        if lead + trail < len(low) and self.blocked(token[lead : len(token) - trail]):
            return lead, trail  # the fully trimmed spelling first: every wrapper outside it is kept
        if not lead and not trail:
            return None
        if "/" not in low and "\\" not in low:
            rev = low[::-1]
            return next((hit for g in self._name_globs if (hit := g.single(low, rev, lead, trail)) is not None), None)
        segs = _PATH_SPLIT.split(low)
        if len(segs) == 1:
            rev = low[::-1]
            return next((hit for g in self._name_globs if (hit := g.single(low, rev, lead, trail)) is not None), None)
        first, last = segs[0], segs[-1]
        last_rev = last[::-1]
        mid = [part for part in segs[1:-1] if part and part != "."]
        for g in self._name_globs:
            if (p := g.first_edge(first, lead)) is not None:
                return p, trail
            if (s := g.last_edge(last, last_rev, trail)) is not None:
                return lead, s
        for chain in self._chain_globs:
            inner = len(chain) - 1
            if len(mid) >= inner and all(g.full.fullmatch(part) for g, part in zip(chain[1:], mid, strict=False)):
                if (p := chain[0].first_edge(first, lead)) is not None:
                    return p, trail
            if len(mid) >= inner and all(
                g.full.fullmatch(part) for g, part in zip(chain[:-1], mid[len(mid) - inner :], strict=True)
            ):
                if (s := chain[-1].last_edge(last, last_rev, trail)) is not None:
                    return lead, s
            if len(mid) == len(chain) - 2 and all(
                g.full.fullmatch(part) for g, part in zip(chain[1:-1], mid, strict=True)
            ):
                p, s = chain[0].first_edge(first, lead), chain[-1].last_edge(last, last_rev, trail)
                if p is not None and s is not None:
                    return p, s
        return None

    def _matches(self, token: str) -> bool:
        low = token.lower()
        if self._needles is not None:
            if self._single_needle is not None:
                if self._single_needle not in low:
                    return False
            else:
                assert self._prefilter is not None
                if not self._prefilter.matches(low):
                    return False
        if "/" not in low and "\\" not in low:
            parts = [] if low == "." else ([low] if low else [])
        else:
            parts = [p for p in _PATH_SPLIT.split(low) if p and p != "."]
        return self._matches_parts(parts)

    def _matches_parts(self, parts: list[str]) -> bool:
        for index, part in enumerate(parts):
            if self._names is not None and self._names.fullmatch(part):
                return True
            for chain in self._chains:
                window = parts[index : index + len(chain)]
                if len(window) == len(chain) and all(rx.fullmatch(p) for rx, p in zip(chain, window, strict=True)):
                    return True
        return False
