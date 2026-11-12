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

try:
    from _collections import _count_elements  # type: ignore[import-not-found]
except ImportError:

    def _count_elements(mapping: dict[str, int], iterable: str) -> None:
        for elem in iterable:
            mapping[elem] = mapping.get(elem, 0) + 1
from collections.abc import Callable, Mapping
from functools import lru_cache

from superbrain.application._privacy_rules import (
    _BENIGN_CONTAINING_WORDS,
    _BENIGN_NEXT_WORDS,
    _CONTAINMENT_MIN,
    _DOTTED_PATH_TOKEN,
    _ENTROPY_EDGE,
    _ID_SEGMENTS,
    _MAX_INT,
    _NODE_OVERHEAD,
    _PATH_TOKEN,
    _STATUS_VALUE_RE,
    MAX_ARRAY_ITEMS,
    MAX_DEPTH,
    MAX_OBJECT_KEYS,
    MAX_TEXT_BYTES,
    MAX_TOTAL_BYTES,
    REDACTED,
    REJECTED_MESSAGE,
    STATUS_FIELDS,
    _Deadline,
    _exempt_structural,
    _is_structural_id,
    _joined_key,
    _key_words,
    _path_needles,
    _PathMatcher,
    _Reject,
    _structural_kind,
)
from superbrain.application._privacy_scan import _TextScans
from superbrain.core.canonical import canonical_json
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import (
    OPAQUE_ID_RE,
    FilterPolicy,
    RepoFlags,
    SafePayload,
)


def _shannon_from_counts(counts: Mapping[str, int], total: int) -> float:
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


class _Run(_TextScans):
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
        self._redactions: dict[tuple[str, bool], tuple[str, int]] = {}
        self._candidate = re.compile(rf"[\x21-\x7e]{{{self.policy.entropy_min_length},}}")
        self._entropy_thresh = 2 ** -(policy.entropy_min_bits + 1e-12)
        self._entropy_min_distinct = 2 ** (policy.entropy_min_bits - 1e-12)
        self._min_u = _min_u_table(float(policy.entropy_min_bits))
        needles = _path_needles(policy.blocked_path_patterns)
        self._path_scan = bool(policy.blocked_path_patterns)
        self._path_needle = re.compile("|".join(map(re.escape, needles))) if needles else None
        dotted = needles is not None and all("." in needle or "_" in needle for needle in needles)
        self._path_token = _DOTTED_PATH_TOKEN if dotted else _PATH_TOKEN

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
        word_count = len(words)
        for start, word in enumerate(words):
            if (
                len(word) >= _CONTAINMENT_MIN
                and word not in _BENIGN_CONTAINING_WORDS
                and any(name in word for name in self._contained)
            ):
                return True
            if word not in self._prefixes:
                continue
            if word not in self._sensitive and (
                start + 1 == word_count or word + words[start + 1] not in self._prefixes
            ):
                continue
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

    def _entropy(self, text: str) -> str:
        """D6: a maximal run of >= N printable non-whitespace ASCII chars with Shannon >= bits is redacted.

        Exempt: a run that is (inside surrounding punctuation) a canonical UUID or ``sha256:<64 hex>``. The
        ``[redacted]`` sentinel is a run boundary, never part of a candidate.
        """
        masked = text.replace(REDACTED, " " * len(REDACTED)) if REDACTED in text else text
        min_len = self._min_segment
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
            candidates = [word for word in masked.split() if len(word) >= min_len]
            if not candidates:
                return text
            if masked.isprintable() or all(word.isprintable() for word in candidates):
                parts: list[str] = []
                cursor = 0
                search_pos = 0
                count = 0
                find = masked.find
                for token in candidates:
                    total = len(token)
                    idx = find(token, search_pos)
                    search_pos = idx + total
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
                        parts.extend((text[cursor:idx], redacted_sentinel))
                        cursor = search_pos
                        count += 1
                        continue
                    counts: dict[str, int] = {}
                    count_elements(counts, token)
                    if (
                        sum([c * c for c in counts.values()]) < thresh * (total * total)
                        or shannon_from_counts(counts, total) >= min_bits
                    ):
                        parts.extend((text[cursor:idx], redacted_sentinel))
                        cursor = search_pos
                        count += 1
                if not count:
                    return text
                parts.append(text[cursor:])
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
