"""Entropy and sensitive-key checks of ``privacy._Run``."""

from __future__ import annotations

from superbrain.application import privacy as _m
from superbrain.application._privacy_rules import (
    _BENIGN_CONTAINING_WORDS,
    _BENIGN_NEXT_WORDS,
    _CONTAINMENT_MIN,
    _ENTROPY_EDGE,
    _PRINTABLE_AND_WS_BYTES,
    _PRINTABLE_NON_WS_BYTES,
    REDACTED,
    _is_structural_id,
    _key_words,
)


def _entropy(self: _m._Run, text: str) -> str:
    min_len = self._min_segment
    if len(text) < min_len:
        return text
    masked = text.replace(REDACTED, self._redacted_spaces) if REDACTED in text else text
    min_bits = self.policy.entropy_min_bits
    thresh = self._entropy_thresh
    min_distinct = self._entropy_min_distinct
    min_u_table = self._min_u
    count_elements = _m._count_elements
    shannon_from_counts = _m._shannon_from_counts
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


def _sensitive_key(self: _m._Run, key: str) -> bool:
    if key.isascii() and len(key) >= 128:
        sub_re = self._sensitive_sub_re
        if sub_re is None:
            return False
        alnum = key.encode("ascii").translate(_m._ASCII_LOWER_TABLE, _m._ASCII_NON_ALNUM_BYTES).decode("ascii")
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
