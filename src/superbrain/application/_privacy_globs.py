"""Path glob compilation used by the privacy path matcher; ``_privacy_rules`` re-exports these."""

from __future__ import annotations

import fnmatch
import re


def _glob_units(glob: str) -> list[str]:
    """fnmatch units of one component: ``*``, ``?``, a closed ``[...]`` class, or one literal character."""
    units: list[str] = []
    i = 0
    while i < len(glob):
        if glob[i] == "[":
            j = i + 1
            if j < len(glob) and glob[j] == "!":
                j += 1
            if j < len(glob) and glob[j] == "]":
                j += 1
            close = glob.find("]", j)
            if close >= 0:
                units.append(glob[i : close + 1])
                i = close + 1
                continue
        units.append(glob[i])
        i += 1
    return units


def _unit_regex(unit: str) -> str:
    """One fnmatch unit as an unanchored regex (``fnmatch.translate`` ends with a two-character end anchor)."""
    translated = fnmatch.translate(unit)
    assert translated.endswith(("\\Z", "\\z"))
    return translated[:-2]


class _Glob:
    """One component glob, with the fixed-width head/tail used to pick the few trimmed spellings worth testing.

    Each non-``*`` unit matches exactly one character. Without ``*`` a match has a fixed width. With ``*``, a match
    is head + anything + tail with stars at both inner ends, so keeping more characters next to a matching head or
    tail never breaks a match: the smallest trim whose head (tail) fits is the only one to test. Fits are found by
    one regex search (the tail on the reversed text), so the cost is linear in the wrapper run, not per position.
    """

    def __init__(self, glob: str) -> None:
        self.full = re.compile(fnmatch.translate(glob))
        units = _glob_units(glob)
        self.star = "*" in units
        if self.star:
            first = units.index("*")
            last = len(units) - 1 - units[::-1].index("*")
            head, tail = units[:first], units[last + 1 :]
            # Only stars between head and tail: a fitting head and tail with room between them is a full match.
            self.simple = all(unit == "*" for unit in units[first : last + 1])
        else:
            head, tail = units, []
            self.simple = True
        self.h, self.t = len(head), len(tail)
        self.head_rx = re.compile("".join(map(_unit_regex, head)))
        self.tail_rx = re.compile("".join(map(_unit_regex, tail)))
        self.tail_rev_rx = re.compile("".join(map(_unit_regex, reversed(tail))))

    def _kept(self, piece: str) -> bool:
        return piece not in ("", ".") and (self.simple or self.full.fullmatch(piece) is not None)

    def _head_at(self, seg: str, low: int, high: int) -> int | None:
        """Smallest ``p`` in ``[low, high]`` where the head fits at ``seg[p:]``."""
        if high < low:
            return None
        found = self.head_rx.search(seg, low, high + self.h)
        return found.start() if found else None

    def _tail_at(self, rev: str, high: int) -> int | None:
        """Smallest ``s <= high`` where the tail fits right before the last ``s`` characters (``rev`` = reversed)."""
        if high < 0:
            return None
        found = self.tail_rev_rx.search(rev, 0, high + self.t)
        return found.start() if found else None

    def first_edge(self, seg: str, lead: int) -> int | None:
        """Smallest ``p <= lead`` with ``seg[p:]`` a kept, matching component (``None`` when there is none)."""
        n, h, t = len(seg), self.h, self.t
        if not self.star:
            p = n - h if 0 <= n - h <= lead and self.head_rx.fullmatch(seg, n - h) else None
        else:
            tail_fits = n - t >= 0 and self.tail_rx.fullmatch(seg, n - t) is not None
            p = self._head_at(seg, 0, min(lead, n - h - t)) if tail_fits else None
        return p if p is not None and self._kept(seg[p:]) else None

    def last_edge(self, seg: str, rev: str, trail: int) -> int | None:
        """Smallest ``s <= trail`` with ``seg[:len - s]`` a kept, matching component."""
        n, h, t = len(seg), self.h, self.t
        if not self.star:
            s = n - h if 0 <= n - h <= trail and self.head_rx.fullmatch(seg, 0, h) else None
        else:
            head_fits = self.head_rx.fullmatch(seg, 0, h) is not None
            s = self._tail_at(rev, min(trail, n - h - t)) if head_fits else None
        return s if s is not None and self._kept(seg[: n - s]) else None

    def single(self, seg: str, rev: str, lead: int, trail: int) -> tuple[int, int] | None:
        """``(p, s)`` with ``seg[p:len - s]`` a kept match, both trims inside their runs (``None`` when none)."""
        n, h, t = len(seg), self.h, self.t
        if not self.star:
            low, high = max(0, n - h - trail), min(lead, n - h)
            # A lone "." can only sit at the end of the leading run, so no later start is left to try.
            p = self._head_at(seg, low, high)
            return (p, n - h - p) if p is not None and self._kept(seg[p : p + h]) else None
        p = self._head_at(seg, 0, lead)
        if p is None:
            return None
        s = self._tail_at(rev, min(trail, n - h - t - p))  # negative when head and tail would overlap: no match
        return (p, s) if s is not None and self._kept(seg[p : n - s]) else None
