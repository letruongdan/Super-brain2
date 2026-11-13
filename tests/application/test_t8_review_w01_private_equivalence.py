"""T8-W01 change 1: the two-regex ``<private>`` scan keeps the exact semantics of the reviewed per-occurrence loop.

Requirement: D6 private blocks (``<private>…</private>`` is replaced by ``[redacted]``; any malformed, orphan, nested,
unclosed marker or a marker without ``>`` refuses the payload) as implemented by the reviewed loop of
``3d116cf:src/superbrain/application/_privacy_scan.py``. ``_old_private`` below is a verbatim copy of that loop's logic
(returning the text and count, raising ``_OldReject``); it is the oracle, never the product.

Invariant: for every text, the filter's value, redaction count and refusal equal the reviewed loop's, and the scan
stays linear on long blank runs after ``<`` and ``</``.
"""

from __future__ import annotations

import random
import time

import pytest

from superbrain.application._privacy_scan import _TextScans
from superbrain.application.privacy import PrivacyFilter
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import FilterPolicy
from tests.application.test_kernel_privacy import ADVERSARIAL, USERINFO_ADVERSARIAL

REDACTED = "[redacted]"


class _OldReject(Exception):
    pass


def _old_private(text: str) -> tuple[str, int]:
    """Copy of the reviewed loop at 3d116cf (only ``self.redacted`` became a local count)."""
    redacted = 0
    if "<" not in text:
        return text, 0
    low = text.lower()
    if "private" not in low:
        return text, 0
    if len(low) != len(text):
        low = "".join(ch.lower() if len(ch.lower()) == 1 else ch for ch in text)
    n = len(low)
    out: list[str] = []
    cursor = 0
    open_at = -1
    find = low.find
    index = find("private")
    while index != -1:
        end = index + 7
        if index >= 1 and end < n:
            prev_ch = low[index - 1]
            next_ch = low[end]
            if prev_ch == "<" and next_ch == ">":
                if open_at >= 0:
                    raise _OldReject
                out.append(text[cursor : index - 1])
                open_at = index - 1
                index = find("private", end)
                continue
            if prev_ch == "/" and index >= 2 and low[index - 2] == "<" and next_ch == ">":
                if open_at < 0:
                    raise _OldReject
                out.append(REDACTED)
                redacted += 1
                cursor = end + 1
                open_at = -1
                index = find("private", end)
                continue
        j = index - 1
        while j >= 0 and low[j].isspace():
            j -= 1
        closing = j >= 0 and low[j] == "/"
        if closing:
            j -= 1
            while j >= 0 and low[j].isspace():
                j -= 1
        if j >= 0 and low[j] == "<":
            k = end
            while k < n and low[k].isspace():
                k += 1
            if k >= n or low[k] != ">":
                raise _OldReject
            if not closing:
                if open_at >= 0:
                    raise _OldReject
                out.append(text[cursor:j])
                open_at = j
            else:
                if open_at < 0:
                    raise _OldReject
                out.append(REDACTED)
                redacted += 1
                cursor, open_at = k + 1, -1
        index = find("private", end)
    if open_at >= 0:
        raise _OldReject
    out.append(text[cursor:])
    return "".join(out), redacted


def _old(text: str) -> tuple[str, int] | None:
    try:
        return _old_private(text)
    except _OldReject:
        return None


class _Phase(_TextScans):
    """The product's ``_private`` phase alone (the other phases are not involved)."""

    def __init__(self) -> None:
        self.redacted = 0


def _new_phase(text: str) -> tuple[str, int] | None:
    phase = _Phase()
    try:
        out = phase._private(text)
    except Exception as exc:  # noqa: BLE001 - only the product's internal refusal is expected here
        assert type(exc).__name__ == "_Reject", repr(exc)
        return None
    return out, phase.redacted


_POLICY = FilterPolicy(entropy_min_length=4096)


def _filtered(texts: list[str]) -> list[tuple[str, int] | None]:
    """End to end, one payload per text: (value, count) or ``None`` for an ``INVALID_INPUT`` refusal."""
    results: list[tuple[str, int] | None] = []
    for text in texts:
        try:
            safe = PrivacyFilter().apply({"note": text}, _POLICY)
        except BrainError as error:
            assert error.code is ErrorCode.INVALID_INPUT and text not in str(error)
            results.append(None)
            continue
        assert isinstance(safe.value, dict) and isinstance(safe.value["note"], str)
        results.append((safe.value["note"], safe.redacted_count))
    return results


# ------------------------------------------------------------------------------------------------------------------
# seeded random marker texts
# ------------------------------------------------------------------------------------------------------------------

_BLANKS = (" ", "\t", "\n", "\x1c", "\x1d", "\x1e", "\x1f", " ", " ", "　", "  ")
_WORDS = ("private", "PRIVATE", "Private", "pRiVaTe", "privatE", "PRİVATE", "prıvate", "priv", "ate", "privat")
_PIECES = ("<", "</", "<<", ">", "/", "x", "ab", "İ", "ı", "K", "=", "<p", "e>", "private>")


def _blank(rng: random.Random) -> str:
    return "".join(rng.choice(_BLANKS) for _ in range(rng.choice((0, 0, 1, 2, 3))))


def _marker(rng: random.Random, *, closing: bool) -> str:
    slash = "/" + _blank(rng) if closing else ""
    tail = rng.choice((">", ">", ">", "", "x>", " "))
    return f"<{_blank(rng)}{slash}{rng.choice(_WORDS[:5])}{_blank(rng)}{tail}"


def _well_formed(rng: random.Random) -> str:
    """Valid blocks between plain words (no marker start outside the blocks): the filter must accept these."""
    parts: list[str] = []
    for _ in range(rng.randint(1, 4)):
        word = rng.choice(("x", "ab ", "İ", "K", "/", ">", "privat", "ate", "<x", "< /p", " "))
        body = "".join(rng.choice(("x", "ab ", "İ", ">", "/", _blank(rng))) for _ in range(3))
        opening = f"<{_blank(rng)}{rng.choice(_WORDS[:5])}{_blank(rng)}>"
        closing = f"<{_blank(rng)}/{_blank(rng)}{rng.choice(_WORDS[:5])}{_blank(rng)}>"
        parts.append(word + opening + body + closing)
    return "".join(parts)


def _text(rng: random.Random) -> str:
    if rng.random() < 0.4:
        return _well_formed(rng)
    parts: list[str] = []
    for _ in range(rng.randint(1, 6)):
        roll = rng.random()
        if roll < 0.35:
            body = "".join(rng.choice(("x", "ab ", "İ", "K", "/", ">", _blank(rng))) for _ in range(3))
            parts.append(_marker(rng, closing=False) + body + _marker(rng, closing=True))
        elif roll < 0.55:
            parts.append(_marker(rng, closing=rng.random() < 0.5))
        elif roll < 0.75:
            parts.append(rng.choice(_WORDS))
        else:
            parts.append(rng.choice(_PIECES) + _blank(rng))
    return "".join(parts)


_SEED = 20261113
_CASES = 4000


def _corpus() -> list[str]:
    rng = random.Random(_SEED)
    return [_text(rng) for _ in range(_CASES)]


def test_w01_corpus_covers_accepted_refused_and_redacted_cases() -> None:
    outcomes = [_old(text) for text in _corpus()]
    refused = sum(o is None for o in outcomes)
    redacted = sum(o is not None and o[1] >= 1 for o in outcomes)
    multi = sum(o is not None and o[1] >= 2 for o in outcomes)
    assert refused >= _CASES // 5 and redacted >= _CASES // 5 and multi >= 50, (refused, redacted, multi)


def test_w01_private_phase_equals_the_reviewed_loop_on_the_seeded_corpus() -> None:
    wrong = [f"{t!r}: new {_new_phase(t)!r} old {_old(t)!r}" for t in _corpus() if _new_phase(t) != _old(t)]
    assert not wrong, f"{len(wrong)} mismatches:\n" + "\n".join(wrong[:25])


def test_w01_filter_equals_the_reviewed_loop_on_the_seeded_corpus() -> None:
    # The corpus alphabet holds no other rule's trigger, so the filter result is the private phase's result.
    texts = _corpus()
    wrong = [
        f"{t!r}: filter {got!r} old {_old(t)!r}" for t, got in zip(texts, _filtered(texts), strict=True)
        if got != _old(t)
    ]  # fmt: skip
    assert not wrong, f"{len(wrong)} mismatches:\n" + "\n".join(wrong[:25])


@pytest.mark.parametrize(
    "text",
    [
        "<private>x</private>",
        "< \x1c / private  >",
        "<\x1fprivate\x1e>a</\nPRIVATE>",
        "<<private>x</private>>",
        "private <private>x</private> private",
        "<private>x</private><private>y</private>",
        "<PRİVATE>x</PRİVATE>",
        "<prıvate>",
        "<Kprivate>",
        "<private>x",
        "x</private>",
        "<private><private>x</private></private>",
        "<private>x</private",
        "< private x>",
        "<private>a</private b</private>",
        "<privateprivate>",
        "</ private>",
        "<private >　</private >",
    ],
)
def test_w01_hand_cases_equal_the_reviewed_loop(text: str) -> None:
    assert _new_phase(text) == _old(text)
    assert _filtered([text]) == [_old(text)]


@pytest.mark.parametrize("index", range(len(ADVERSARIAL + USERINFO_ADVERSARIAL)))
def test_w01_private_phase_equals_the_reviewed_loop_on_the_adversarial_set(index: int) -> None:
    text = (ADVERSARIAL + USERINFO_ADVERSARIAL)[index]
    assert _new_phase(text) == _old(text)


# ------------------------------------------------------------------------------------------------------------------
# linear time on long blank runs
# ------------------------------------------------------------------------------------------------------------------

_LONG = 60_000
_SLOW: list[str] = [
    "<" + " " * _LONG + "x",
    "<" + " " * _LONG + "private",
    "</" + " " * _LONG + "x",
    "< /" + " " * _LONG + "private>",
    "<" + " " * (_LONG // 4) + "/" + "\x1c" * (_LONG // 4) + "privat",
    "<private>" + " " * _LONG,
    "<private>" + "< " * (_LONG // 2) + "</private>",
    "<private>" + "</ " * (_LONG // 3) + "</private>",
    "<private" + " " * _LONG + ">x</private>",
    "<private>x</private" + " " * _LONG,
    "< private" * (_LONG // 9),
    "<private>x</private>" * (_LONG // 20),
]


@pytest.mark.parametrize("index", range(len(_SLOW)))
def test_w01_long_blank_runs_are_linear_and_equal_the_reviewed_loop(index: int) -> None:
    text = _SLOW[index]
    assert len(text.encode()) <= 64 * 1024
    best = float("inf")
    for _ in range(3):
        start = time.perf_counter()
        got = _new_phase(text)
        best = min(best, time.perf_counter() - start)
    assert got == _old(text)
    assert best < 0.050, f"private scan of {len(text)} characters took {best * 1000:.0f} ms"
