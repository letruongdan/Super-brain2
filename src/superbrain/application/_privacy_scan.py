"""Per-string redaction phases of the privacy filter (D6), mixed into ``privacy._Run``."""

from __future__ import annotations

import re
from collections.abc import Callable

from superbrain.application._privacy_rules import (
    _AUTH_HEADER,
    _AUTH_SCHEME,
    _AUTHORITY,
    _CREDENTIAL_USER,
    _FIXED_TOKENS,
    _KEY_VALUE_SECRET,
    _KV_COLON_PAIRS,
    _KV_EQ_PAIRS,
    _KV_WORDS,
    _PEM_BEGIN,
    _PEM_END,
    _SEGMENT,
    REDACTED,
    _fast_scans_intact,
    _FastScanPatterns,
    _gate_open,
    _PathMatcher,
    _PathPrefilter,
    _Reject,
    _shipped_rules_intact,
    _tokenish,
)

# ``\s`` and ``str.isspace`` agree (one Unicode whitespace table). Only ASCII letters lowercase to the letters of
# "private" (checked over every code point), so these classes equal a match on the lowercased text. Two blank
# runs are never adjacent (a ``/`` sits between them), which keeps long blank runs linear.
_PRIVATE_WORD = "[pP][rR][iI][vV][aA][tT][eE]"
_PRIVATE_START = rf"<\s*(?:/\s*)?{_PRIVATE_WORD}"
_PRIVATE_MARK = re.compile(_PRIVATE_START)
# Block body: runs of non-``<`` text and ``<`` that does not start a marker (unrolled, so each character is
# consumed once). It stops right before the first marker start, which must then be a closing marker.
_PRIVATE_BLOCK = re.compile(
    rf"<\s*{_PRIVATE_WORD}\s*>[^<]*(?:<(?!\s*(?:/\s*)?{_PRIVATE_WORD})[^<]*)*<\s*/\s*{_PRIVATE_WORD}\s*>"
)
# ASCII non-space whitespace characters matched by ``\s``, kept as a string tuple (no module regex).
_NON_SPACE_ASCII_WS = ("\t", "\n", "\r", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x1f")


def _shipped_rules_active() -> bool:
    """Whether ``_privacy_scan`` still binds shipped rule patterns recognized by ``_RULE_GATES``."""
    return _shipped_rules_intact(_AUTH_HEADER, _AUTH_SCHEME, _FIXED_TOKENS, _KEY_VALUE_SECRET)


def _fast_scans_active() -> bool:
    """Whether ``_privacy_scan`` still binds exact unmodified rule/helper patterns in canonical order."""
    return _fast_scans_intact(
        _AUTH_HEADER,
        _AUTH_SCHEME,
        _FIXED_TOKENS,
        _KEY_VALUE_SECRET,
        _PRIVATE_MARK,
        _PRIVATE_BLOCK,
        _AUTHORITY,
        _SEGMENT,
        _CREDENTIAL_USER,
    )


class _TextScans:
    """Redaction phases for one string; the run state lives on ``privacy._Run``."""

    redacted: int
    _deadline_ns: int | None = None
    _has_deadline: bool = True
    _paths: _PathMatcher
    _redactions: dict[tuple[str, bool], tuple[str, int]]
    _path_scan: bool
    _path_prefilter: _PathPrefilter
    _path_token: re.Pattern[str]
    _reusable_lower: bool
    _shipped_scans_ok: bool = False
    _fast: _FastScanPatterns

    def tick(self) -> None:
        raise NotImplementedError

    def _entropy(self, text: str) -> str:
        raise NotImplementedError

    def _sub(self, pattern: re.Pattern[str], repl: str | Callable[[re.Match[str]], str], text: str) -> str:
        new, count = pattern.subn(repl, text)
        self.redacted += count
        return new

    def _private(self, text: str) -> str:
        """``<private>…</private>`` -> ``[redacted]``; any malformed, orphan or nested marker refuses.

        A marker starts with ``<`` [ws] [``/``] [ws] ``private`` (case-insensitive) and must close with [ws] ``>``.
        Valid blocks are an opening marker, text holding no marker start, and a closing marker; a marker start left
        after replacing them (unclosed, orphan, nested or without ``>``) refuses. Two regex passes, linear.
        """
        if "<" not in text:
            return text
        if self._shipped_scans_ok:
            new, count = self._fast.priv_lower.subn(REDACTED, text)
            if "<" not in new:
                self.redacted += count
                return new
        new, count = _PRIVATE_BLOCK.subn(REDACTED, text)
        if "<" in new and _PRIVATE_MARK.search(new):
            raise _Reject
        self.redacted += count
        return new

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
        if "://" not in text or "@" not in text:
            return text
        if self._shipped_scans_ok:
            fast = self._fast
            new, count = fast.ui_neg.subn(fast.ui_repl, text)
            if count and count == text.count("://"):
                self.redacted += count
                return new
        spaces_only = text.isascii()
        if spaces_only:
            for ws in _NON_SPACE_ASCII_WS:
                if ws in text:
                    spaces_only = False
                    break
        out: list[str] = []
        append = out.append
        cursor = 0
        seg_end = seg_last_at = -1
        text_len = len(text)
        find = text.find
        rfind = text.rfind
        redacted = REDACTED
        index = find("://")
        while index != -1:
            start = index + 3
            if start > seg_end:
                if spaces_only:
                    sp = find(" ", start)
                    seg_end = text_len if sp == -1 else sp
                else:
                    segment = _SEGMENT.match(text, start)
                    seg_end = segment.end() if segment is not None else start
                seg_last_at = rfind("@", start, seg_end)
            if seg_last_at <= start:
                index = find("://", seg_end if seg_end > start else start)
                continue
            if spaces_only:
                colon = find(":", start, seg_end)
                if colon != -1:
                    user = text[start:colon]
                    cred = "/" not in user and "?" not in user and "#" not in user
                else:
                    cred = False
                if cred:
                    at = seg_last_at
                else:
                    stop = seg_end
                    for sep in ("/", "?", "#"):
                        pos = find(sep, start, stop)
                        if pos != -1:
                            stop = pos
                    at = rfind("@", start, stop)
            elif _CREDENTIAL_USER.match(text, start, seg_end):
                at = seg_last_at
            else:
                authority = _AUTHORITY.match(text, start)
                stop = authority.end() if authority is not None else start
                at = rfind("@", start, stop)
            if at > start:
                append(text[cursor:start])
                append(redacted)
                self.redacted += 1
                cursor = at
                index = find("://", at)
            else:
                index = find("://", start)
        if not out:
            return text
        append(text[cursor:])
        return "".join(out)

    def _auth_scheme(self, match: re.Match[str]) -> str:
        # Once ``Bearer``/``Basic`` is recognised its credential is a secret whatever its charset (I2-T3-R05); only
        # the plain word ``token`` keeps the prose heuristic ("the token validation step").
        if match.group(1).lower() == "token" and not _tokenish(match.group(2)):
            return match.group(0)
        self.redacted += 1
        return f"{match.group(1)} {REDACTED}"

    def _blocked_path(self, match: re.Match[str]) -> str:
        """§14.2: replace a blocked spelling of the token (any trim of its wrapper runs); wrappers outside it stay."""
        token = match.group(0)
        if not self._paths.may_block(token):
            return token
        found = self._paths.find(token)
        if found is None:
            return token
        start, cut = found
        self.redacted += 1
        return token[:start] + REDACTED + token[len(token) - cut :]

    def _redact_ascii_fast(self, text: str, has_deadline: bool) -> str:
        fast = self._fast
        reusable = self._reusable_lower
        lowered = text.lower()
        if "authorization" in lowered:
            new = self._sub(_AUTH_HEADER, rf"\1\2{REDACTED}", text)
            if new != text:
                text = new
                if not reusable:
                    lowered = new.lower()
        if has_deadline:
            self.tick()
        if "token" in lowered or fast.b_auth.search(lowered) is not None:
            new = _AUTH_SCHEME.sub(self._auth_scheme, text)
            if new != text:
                text = new
                if not reusable:
                    lowered = new.lower()
        ft = _FIXED_TOKENS
        if fast.gh_both.search(text) is not None:
            if "github_pat_" in text:
                new = self._sub(ft[0], REDACTED, text)
                if new != text:
                    text = new
                    if not reusable:
                        lowered = new.lower()
            if has_deadline:
                self.tick()
            if fast.gh.search(text) is not None:
                new = self._sub(ft[1], REDACTED, text)
                if new != text:
                    text = new
                    if not reusable:
                        lowered = new.lower()
            if has_deadline:
                self.tick()
        elif has_deadline:
            self.tick()
            self.tick()
        if "sk-" in text and fast.sk.search(text) is not None:
            new = self._sub(ft[2], REDACTED, text)
            if new != text:
                text = new
                if not reusable:
                    lowered = new.lower()
        if has_deadline:
            self.tick()
        if "AKIA" in text or "ASIA" in text:
            new = self._sub(ft[3], REDACTED, text)
            if new != text:
                text = new
                if not reusable:
                    lowered = new.lower()
        if has_deadline:
            self.tick()
        if "xox" in text and fast.xox.search(text) is not None:
            new = self._sub(ft[4], REDACTED, text)
            if new != text:
                text = new
                if not reusable:
                    lowered = new.lower()
        if has_deadline:
            self.tick()
        if "AIza" in text:
            new = self._sub(ft[5], REDACTED, text)
            if new != text:
                text = new
                if not reusable:
                    lowered = new.lower()
        if has_deadline:
            self.tick()
        if "eyJ" in text and fast.eyj.search(text) is not None:
            new = self._sub(ft[6], REDACTED, text)
            if new != text:
                text = new
                if not reusable:
                    lowered = new.lower()
        if has_deadline:
            self.tick()
        new = self._userinfo(text)
        if new != text:
            text = new
            if not reusable or len(new) < len(lowered) - 4096:
                lowered = new.lower()
        kv_pair = False
        if "=" in lowered:
            for pair in _KV_EQ_PAIRS:
                if pair in lowered:
                    kv_pair = True
                    break
        if not kv_pair and ":" in lowered:
            for pair in _KV_COLON_PAIRS:
                if pair in lowered:
                    kv_pair = True
                    break
        if kv_pair:
            for word in _KV_WORDS:
                if word in lowered:
                    new = self._sub(_KEY_VALUE_SECRET, rf"\1\2{REDACTED}", text)
                    if new != text:
                        text = new
                        if not reusable:
                            lowered = new.lower()
                    break
        if has_deadline:
            self.tick()
        # The cheap candidate scan keeps the full component matcher as the authority.
        if self._path_scan and self._path_prefilter.matches(lowered):
            text = self._path_token.sub(self._blocked_path, text)
        return text

    def _redact_generic(self, text: str, ascii_text: bool, has_deadline: bool) -> str:
        lowered: str | None = text.lower() if ascii_text else None
        reusable = self._reusable_lower if ascii_text else True
        if _gate_open(_AUTH_HEADER, text, lowered):
            new = self._sub(_AUTH_HEADER, rf"\1\2{REDACTED}", text)
            if new != text:
                text = new
                if ascii_text and not reusable:
                    lowered = new.lower()
        if has_deadline:
            self.tick()
        if _gate_open(_AUTH_SCHEME, text, lowered):
            new = _AUTH_SCHEME.sub(self._auth_scheme, text)
            if new != text:
                text = new
                if ascii_text and not reusable:
                    lowered = new.lower()
        for pattern in _FIXED_TOKENS:
            if _gate_open(pattern, text, lowered):
                new = self._sub(pattern, REDACTED, text)
                if new != text:
                    text = new
                    if ascii_text and not reusable:
                        lowered = new.lower()
            if has_deadline:
                self.tick()
        new = self._userinfo(text)
        if new != text:
            text = new
            if ascii_text and not reusable:
                lowered = new.lower()
        if _gate_open(_KEY_VALUE_SECRET, text, lowered):
            new = self._sub(_KEY_VALUE_SECRET, rf"\1\2{REDACTED}", text)
            if new != text:
                text = new
                if ascii_text and not reusable:
                    lowered = new.lower()
        if has_deadline:
            self.tick()
        # The cheap candidate scan keeps the full component matcher as the authority.
        if self._path_scan and (lowered is None or self._path_prefilter.matches(lowered)):
            text = self._path_token.sub(self._blocked_path, text)
        return text

    def redact(self, text: str, *, entropy: bool = True) -> str:
        has_deadline = self._has_deadline
        if has_deadline:
            self.tick()
        key = (text, entropy)
        cached = self._redactions.get(key)
        if cached is not None:
            value, redacted = cached
            self.redacted += redacted
            return value
        before = self.redacted
        text = self._private(text)
        if has_deadline:
            self.tick()
        if "-----BEGIN " in text:
            text = self._pem(text)
        ascii_text = text.isascii()
        if ascii_text and self._shipped_scans_ok:
            text = self._redact_ascii_fast(text, has_deadline)
        else:  # lowered=None on non-ASCII text; patched rules also use generic _gate_open
            text = self._redact_generic(text, ascii_text, has_deadline)
        if has_deadline:
            self.tick()
        if entropy:
            text = self._entropy(text)
        if has_deadline:
            self.tick()  # after the last phase too: a late expiry is never hidden by returning
        if len(self._redactions) < 1024:
            self._redactions[key] = (text, self.redacted - before)
        return text
