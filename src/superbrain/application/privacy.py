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
import math
import re
import time
from collections.abc import Callable, Iterable, Mapping
from functools import lru_cache
from typing import TypeVar

from superbrain.application._privacy_rules import (
    _BENIGN_CONTAINING_WORDS,
    _BENIGN_NEXT_WORDS,
    _CONTAINMENT_MIN,
    _DOTTED_PATH_TOKEN,
    _ENTROPY_EDGE,
    _ID_SEGMENTS,
    _JSON_SAFE_NL_BYTES,
    _MAX_INT,
    _NODE_OVERHEAD,
    _PATH_TOKEN,
    _PRINTABLE_AND_WS_BYTES,
    _PRINTABLE_NON_WS_BYTES,
    _STATUS_VALUE_RE,
    MAX_ARRAY_ITEMS,
    MAX_DEPTH,
    MAX_OBJECT_KEYS,
    MAX_TEXT_BYTES,
    MAX_TOTAL_BYTES,
    REDACTED,
    REJECTED_MESSAGE,
    STATUS_FIELDS,
    _build_path_prefilter,
    _Deadline,
    _exempt_structural,
    _fast_patterns,
    _FastScanPatterns,
    _is_structural_id,
    _joined_key,
    _key_words,
    _path_needles,
    _PathMatcher,
    _PathPrefilter,
    _Reject,
    _structural_kind,
)
from superbrain.application._privacy_scan import (
    _fast_scans_active,
    _shipped_rules_active,
    _TextScans,
)
from superbrain.core._kernel_base import OPAQUE_ID_RE
from superbrain.core._kernel_workspace import (
    FilterPolicy,
    RepoFlags,
    SafePayload,
)
from superbrain.core.canonical import canonical_json
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue

_CountKeyT = TypeVar("_CountKeyT", str, int)

try:
    from _collections import _count_elements  # type: ignore[import-not-found]
except ImportError:

    def _count_elements(mapping: dict[_CountKeyT, int], iterable: Iterable[_CountKeyT]) -> None:
        for elem in iterable:
            mapping[elem] = mapping.get(elem, 0) + 1


def _shannon_from_counts(counts: Mapping[str, int] | Mapping[int, int], total: int) -> float:
    if total <= 256:
        weights = _entropy_weights(total)
        return -sum([weights[c] for c in counts.values()])
    return -sum([(count / total) * math.log2(count / total) for count in counts.values()])


def _shannon_bits(text: str) -> float:
    counts: dict[str, int] = {}
    _count_elements(counts, text)
    return _shannon_from_counts(counts, len(text))


@lru_cache(maxsize=128)
def _entropy_weights(total: int) -> tuple[float, ...]:
    """Cache bounded numeric probability tables, without retaining input text."""
    return (0.0, *((count / total) * math.log2(count / total) for count in range(1, total + 1)))


@lru_cache(maxsize=1)
def _entropy_weights_table() -> tuple[tuple[float, ...], ...]:
    """Tuple of per-length entropy weights for lengths 0..256 (math constants only)."""
    return tuple(_entropy_weights(n) for n in range(257))


@lru_cache(maxsize=32)
def _min_u_table(min_bits: float) -> tuple[int, ...]:
    """Lowest distinct character count guaranteeing Shannon entropy above ``min_bits`` for length <= 256."""
    out = [0] * 257
    out[0] = 1
    target = min_bits + 1e-9
    for total in range(1, 257):
        found = total + 1
        inv_total = 1.0 / total
        log_inv = math.log2(inv_total)
        for u in range(1, total + 1):
            c1 = total - u + 1
            p1 = c1 * inv_total
            worst_bits = -(p1 * math.log2(p1)) - ((u - 1) * inv_total) * log_inv
            if worst_bits >= target:
                found = u
                break
        out[total] = found
    return tuple(out)


def _high_entropy(text: str, minimum: float) -> bool:
    counts: dict[str, int] = {}
    _count_elements(counts, text)
    total = len(text)
    thresh = 2 ** -(minimum + 1e-12)
    if sum([c * c for c in counts.values()]) < thresh * (total * total):
        return True
    return _shannon_from_counts(counts, total) >= minimum


_ASCII_LOWER_TABLE = bytes.maketrans(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ", b"abcdefghijklmnopqrstuvwxyz")
_ASCII_NON_ALNUM_BYTES = bytes(b for b in range(256) if not (48 <= b <= 57 or 65 <= b <= 90 or 97 <= b <= 122))


@dataclasses.dataclass(frozen=True)
class _CompiledPolicy:
    sensitive: frozenset[str]
    paths: _PathMatcher
    min_segment: int
    min_word: int
    max_words: int
    prefixes: frozenset[str]
    contained: tuple[str, ...]
    contained_re: re.Pattern[str] | None
    sensitive_sub_re: re.Pattern[str] | None
    candidate: re.Pattern[str]
    entropy_thresh: float
    entropy_min_distinct: float
    min_u: tuple[int, ...]
    w_table: tuple[tuple[float, ...], ...]
    thresh_sq: tuple[float, ...]
    fast: _FastScanPatterns
    redacted_spaces: str
    edge_bytes: bytes
    path_scan: bool
    path_prefilter: _PathPrefilter
    path_token: re.Pattern[str]
    reusable_lower: bool


@lru_cache(maxsize=32)
def _compile_policy(policy: FilterPolicy) -> _CompiledPolicy:
    sensitive = frozenset(_joined_key(k) for k in policy.sensitive_keys) - {""}
    paths = _PathMatcher(policy.blocked_path_patterns)
    min_segment = policy.entropy_min_length
    max_words = max((len(_key_words(k)) for k in policy.sensitive_keys), default=1)
    prefixes = frozenset(name[:i] for name in sensitive for i in range(1, len(name) + 1))
    contained = tuple(sorted(name for name in sensitive if len(name) >= _CONTAINMENT_MIN))
    contained_re = re.compile("|".join(re.escape(name) for name in contained)) if contained else None
    sensitive_sub_re = (
        re.compile("|".join(re.escape(name) for name in sorted(sensitive, key=len, reverse=True)))
        if sensitive
        else None
    )
    candidate = re.compile(rf"[\x21-\x7e]{{{policy.entropy_min_length},}}")
    entropy_thresh = 2 ** -(policy.entropy_min_bits + 1e-12)
    entropy_min_distinct = 2 ** (policy.entropy_min_bits - 1e-12)
    min_word = max(min_segment, math.ceil(entropy_min_distinct))
    min_u = _min_u_table(float(policy.entropy_min_bits))
    w_table = _entropy_weights_table()
    thresh_sq = tuple(entropy_thresh * (n * n) for n in range(257))
    fast = _fast_patterns()
    needles = _path_needles(policy.blocked_path_patterns)
    path_scan = bool(policy.blocked_path_patterns)
    path_prefilter = _build_path_prefilter(needles)
    reusable_lower = needles is None or not any(n in REDACTED for n in needles)
    dotted = needles is not None and all("." in needle or "_" in needle for needle in needles)
    path_token = _DOTTED_PATH_TOKEN if dotted else _PATH_TOKEN
    return _CompiledPolicy(
        sensitive=sensitive,
        paths=paths,
        min_segment=min_segment,
        min_word=min_word,
        max_words=max_words,
        prefixes=prefixes,
        contained=contained,
        contained_re=contained_re,
        sensitive_sub_re=sensitive_sub_re,
        candidate=candidate,
        entropy_thresh=entropy_thresh,
        entropy_min_distinct=entropy_min_distinct,
        min_u=min_u,
        w_table=w_table,
        thresh_sq=thresh_sq,
        fast=fast,
        redacted_spaces=" " * len(REDACTED),
        edge_bytes=_ENTROPY_EDGE.encode("ascii"),
        path_scan=path_scan,
        path_prefilter=path_prefilter,
        path_token=path_token,
        reusable_lower=reusable_lower,
    )


class _Run(_TextScans):
    def __init__(self, policy: FilterPolicy, monotonic_ns: Callable[[], int], deadline_ns: int | None) -> None:
        self.policy = policy
        self.redacted = 0
        self.stripped = 0
        self._input_bytes = 0
        self._monotonic_ns = monotonic_ns
        self._deadline_ns = deadline_ns
        self._has_deadline = deadline_ns is not None
        compiled = _compile_policy(policy)
        self._sensitive = compiled.sensitive
        self._paths = compiled.paths.fresh()
        self._min_segment = compiled.min_segment
        self._min_word = compiled.min_word
        self._max_words = compiled.max_words
        self._prefixes = compiled.prefixes
        self._contained = compiled.contained
        self._contained_re = compiled.contained_re
        self._sensitive_sub_re = compiled.sensitive_sub_re
        self._candidate = compiled.candidate
        self._entropy_thresh = compiled.entropy_thresh
        self._entropy_min_distinct = compiled.entropy_min_distinct
        self._min_u = compiled.min_u
        self._w_table = compiled.w_table
        self._thresh_sq = compiled.thresh_sq
        self._fast = compiled.fast
        self._redacted_spaces = compiled.redacted_spaces
        self._edge_bytes = compiled.edge_bytes
        self._path_scan = compiled.path_scan
        self._path_prefilter = compiled.path_prefilter
        self._path_token = compiled.path_token
        self._reusable_lower = compiled.reusable_lower and _shipped_rules_active()
        self._shipped_scans_ok = _fast_scans_active()
        self._redactions: dict[tuple[str, bool], tuple[str, int]] = {}
        self._entropy_verdict_b: dict[bytes, bool] = {}
        self._verdict_hits = 0
        self._verdict_probes = 0

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
        if key.isascii() and len(key) >= 128:
            sub_re = self._sensitive_sub_re
            if sub_re is None:
                return False
            alnum = key.encode("ascii").translate(_ASCII_LOWER_TABLE, _ASCII_NON_ALNUM_BYTES).decode("ascii")
            if sub_re.search(alnum) is None:
                return False
        words = _key_words(key)
        word_count = len(words)
        contained_re = self._contained_re
        prefixes = self._prefixes
        sensitive = self._sensitive
        max_words = self._max_words
        for start, word in enumerate(words):
            if (
                contained_re is not None
                and len(word) >= _CONTAINMENT_MIN
                and word not in _BENIGN_CONTAINING_WORDS
                and contained_re.search(word) is not None
            ):
                return True
            if word not in prefixes:
                continue
            if word not in sensitive and (
                start + 1 == word_count or word + words[start + 1] not in prefixes
            ):
                continue
            joined = ""
            for size in range(1, min(max_words, word_count - start) + 1):
                joined += words[start + size - 1]
                if joined not in prefixes:
                    break
                if joined not in sensitive:
                    continue
                following = words[start + size] if start + size < word_count else None
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
        size = len(text) if text.isascii() else len(text.encode("utf-8"))
        if size > MAX_TEXT_BYTES:
            raise _Reject
        self._count(size)

    def _entropy(self, text: str) -> str:
        """D6: a maximal run of >= N printable non-whitespace ASCII chars with Shannon >= bits is redacted.

        Exempt: a run that is (inside surrounding punctuation) a canonical UUID or ``sha256:<64 hex>``. The
        ``[redacted]`` sentinel is a run boundary, never part of a candidate.
        """
        min_len = self._min_segment
        if len(text) < min_len:
            return text
        masked = text.replace(REDACTED, self._redacted_spaces) if REDACTED in text else text
        min_bits = self.policy.entropy_min_bits
        thresh = self._entropy_thresh
        min_distinct = self._entropy_min_distinct
        min_u_table = self._min_u
        count_elements = _count_elements
        shannon_from_counts = _shannon_from_counts
        is_structural = _is_structural_id
        edge = _ENTROPY_EDGE
        redacted_sentinel = REDACTED

        if masked.isascii():
            mb = masked.encode("ascii")
            if not mb.translate(None, _PRINTABLE_AND_WS_BYTES):
                min_word = self._min_word
                candidates = [word for word in mb.split() if len(word) >= min_word]
                if not candidates:
                    return text
                parts: list[str] = []
                append = parts.append
                cursor = 0
                search_pos = 0
                count = 0
                find = mb.find
                edge_b = self._edge_bytes
                w_table = self._w_table
                thresh_sq = self._thresh_sq
                p94_tr = _PRINTABLE_NON_WS_BYTES.translate
                counts_b: dict[int, int] = {}
                clear_counts = counts_b.clear
                count_vals = counts_b.values
                verdict_b = self._entropy_verdict_b
                verdict_get = verdict_b.get
                s_len = len
                use_verdict = self._verdict_hits > 0 or self._verdict_probes < 4
                for token_b in candidates:
                    total = s_len(token_b)
                    idx = find(token_b, search_pos)
                    search_pos = idx + total
                    if use_verdict:
                        cached = verdict_get(token_b)
                        if cached is not None:
                            self._verdict_hits += 1
                            if cached:
                                append(text[cursor:idx])
                                append(redacted_sentinel)
                                cursor = search_pos
                                count += 1
                            continue
                        self._verdict_probes += 1
                        if self._verdict_hits == 0 and self._verdict_probes >= 4:
                            use_verdict = False
                    if total >= 36 and (total == 36 or total == 71 or token_b[0] in edge_b or token_b[-1] in edge_b):
                        clean_b = token_b.strip(edge_b)
                        if s_len(clean_b) in (36, 71) and is_structural(clean_b.decode("ascii")):
                            if use_verdict and s_len(verdict_b) < 512:
                                verdict_b[token_b] = False
                            continue
                    distinct = 94 - s_len(p94_tr(None, token_b))
                    if distinct < min_distinct:
                        if use_verdict and s_len(verdict_b) < 512:
                            verdict_b[token_b] = False
                        continue
                    if total <= 256 and distinct >= min_u_table[total]:
                        if use_verdict and s_len(verdict_b) < 512:
                            verdict_b[token_b] = True
                        append(text[cursor:idx])
                        append(redacted_sentinel)
                        cursor = search_pos
                        count += 1
                        continue
                    clear_counts()
                    count_elements(counts_b, token_b)
                    sq = 0
                    for c in count_vals():
                        sq += c * c
                    if total <= 256:
                        if sq < thresh_sq[total]:
                            redact_token = True
                        else:
                            weights = w_table[total]
                            redact_token = -sum([weights[c] for c in count_vals()]) >= min_bits
                    elif sq < thresh * (total * total):
                        redact_token = True
                    else:
                        redact_token = shannon_from_counts(counts_b, total) >= min_bits
                    if use_verdict and s_len(verdict_b) < 512:
                        verdict_b[token_b] = redact_token
                    if redact_token:
                        append(text[cursor:idx])
                        append(redacted_sentinel)
                        cursor = search_pos
                        count += 1
                if not count:
                    return text
                append(text[cursor:])
                self.redacted += count
                return "".join(parts)

        parts_fb: list[str] = []
        cursor = 0
        count = 0
        for match in self._candidate.finditer(masked):
            token = match.group(0)
            total = len(token)
            if total < min_distinct:
                continue
            if total >= 36:
                clean = token.strip(edge) if (token[0] in edge or token[-1] in edge) else token
                if is_structural(clean):
                    continue
            distinct = len(set(token))
            if distinct < min_distinct:
                continue
            if total <= 256 and distinct >= min_u_table[total]:
                start, end = match.span()
                parts_fb.extend((text[cursor:start], redacted_sentinel))
                cursor = end
                count += 1
                continue
            counts_fb: dict[str, int] = {}
            count_elements(counts_fb, token)
            if (
                sum([c * c for c in counts_fb.values()]) < thresh * (total * total)
                or shannon_from_counts(counts_fb, total) >= min_bits
            ):
                start, end = match.span()
                parts_fb.extend((text[cursor:start], redacted_sentinel))
                cursor = end
                count += 1
        if not count:
            return text
        parts_fb.append(text[cursor:])
        self.redacted += count
        return "".join(parts_fb)


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


_JSON_FALLBACK = object()


def _exact_json_bytes(value: object, limit: int) -> int | object:
    if value is None:
        return 4
    if type(value) is bool:
        return 4 if value else 5
    if type(value) is int:
        return len(str(value))
    if type(value) is str:
        if value.isascii():
            if value.isprintable():
                return 2 + len(value) + value.count('"') + value.count("\\")
            vb = value.encode("ascii")
            if not vb.translate(None, _JSON_SAFE_NL_BYTES):
                return 2 + len(vb) + vb.count(b'"') + vb.count(b"\\") + vb.count(b"\n")
        return _JSON_FALLBACK
    if type(value) is list:
        n = len(value)
        total = 2 + (n - 1 if n > 1 else 0)
        for item in value:
            size = _exact_json_bytes(item, limit)
            if size is _JSON_FALLBACK:
                return _JSON_FALLBACK
            assert type(size) is int
            total += size
            if total > limit:
                return limit + 1
        return total
    if type(value) is dict:
        n = len(value)
        total = 2 + (n - 1 if n > 1 else 0)
        for key, item in value.items():
            if type(key) is not str or not (key.isascii() and key.isprintable()):
                return _JSON_FALLBACK
            key_size = 2 + len(key) + key.count('"') + key.count("\\")
            val_size = _exact_json_bytes(item, limit)
            if val_size is _JSON_FALLBACK:
                return _JSON_FALLBACK
            assert type(val_size) is int
            total += key_size + 1 + val_size
            if total > limit:
                return limit + 1
        return total
    return _JSON_FALLBACK


def _json_bytes_within_cap(value: JsonValue, limit: int) -> bool:
    """Exact UTF-8 ``canonical_json`` byte cap check without allocating a full 1 MiB JSON buffer on ASCII trees."""
    size = _exact_json_bytes(value, limit)
    if size is _JSON_FALLBACK:
        return len(canonical_json(value)) <= limit
    assert type(size) is int
    return size <= limit


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
            if not _json_bytes_within_cap(cleaned, MAX_TOTAL_BYTES):
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
