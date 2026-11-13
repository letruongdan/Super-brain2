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
    _PEM_BEGIN,
    _PEM_END,
    _SEGMENT,
    REDACTED,
    _gate_open,
    _PathMatcher,
    _Reject,
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


class _TextScans:
    """Redaction phases for one string; the run state lives on ``privacy._Run``."""

    redacted: int
    _paths: _PathMatcher
    _redactions: dict[tuple[str, bool], tuple[str, int]]
    _path_scan: bool
    _path_needle: re.Pattern[str] | None
    _path_token: re.Pattern[str]

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
        new, count = _PRIVATE_BLOCK.subn(REDACTED, text)
        if _PRIVATE_MARK.search(new):
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

    def redact(self, text: str, *, entropy: bool = True) -> str:
        self.tick()
        key = (text, entropy)
        cached = self._redactions.get(key)
        if cached is not None:
            value, redacted = cached
            self.redacted += redacted
            return value
        before = self.redacted
        text = self._private(text)
        self.tick()
        if "-----BEGIN " in text:
            text = self._pem(text)
        ascii_text = text.isascii()
        if ascii_text:
            lowered = text.lower()
            if _gate_open(_AUTH_HEADER, text, lowered):
                text = self._sub(_AUTH_HEADER, rf"\1\2{REDACTED}", text)
                lowered = text.lower()
            self.tick()
            if _gate_open(_AUTH_SCHEME, text, lowered):
                text = _AUTH_SCHEME.sub(self._auth_scheme, text)
                lowered = text.lower()
            for pattern in _FIXED_TOKENS:
                if _gate_open(pattern, text, lowered):
                    text = self._sub(pattern, REDACTED, text)
                    lowered = text.lower()
                self.tick()
            new = self._userinfo(text)
            if new != text:
                text, lowered = new, new.lower()
            if _gate_open(_KEY_VALUE_SECRET, text, lowered):
                text = self._sub(_KEY_VALUE_SECRET, rf"\1\2{REDACTED}", text)
                lowered = text.lower()
            self.tick()
            # The cheap candidate scan keeps the full component matcher as the authority.
            if self._path_scan:
                if self._path_needle is None or self._path_needle.search(lowered):
                    text = self._path_token.sub(self._blocked_path, text)
        else:  # lowered=None: only case-sensitive gates are trusted on non-ASCII text
            if _gate_open(_AUTH_HEADER, text, None):
                text = self._sub(_AUTH_HEADER, rf"\1\2{REDACTED}", text)
            self.tick()
            if _gate_open(_AUTH_SCHEME, text, None):
                text = _AUTH_SCHEME.sub(self._auth_scheme, text)
            for pattern in _FIXED_TOKENS:
                if _gate_open(pattern, text, None):
                    text = self._sub(pattern, REDACTED, text)
                self.tick()
            text = self._userinfo(text)
            if _gate_open(_KEY_VALUE_SECRET, text, None):
                text = self._sub(_KEY_VALUE_SECRET, rf"\1\2{REDACTED}", text)
            self.tick()
            # The cheap candidate scan keeps the full component matcher as the authority.
            if self._path_scan:
                text = self._path_token.sub(self._blocked_path, text)
        self.tick()
        if entropy:
            text = self._entropy(text)
        self.tick()  # after the last phase too: a late expiry is never hidden by returning
        if len(self._redactions) < 1024:
            self._redactions[key] = (text, self.redacted - before)
        return text
