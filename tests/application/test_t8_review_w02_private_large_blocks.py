"""T8-W01-F1: the ``<private>`` scan stays linear with a small constant on large blocks.

Requirement: plan 8.6(b) (local privacy p95 <= 100 ms per 1 MiB, filter time linear in the input) and the rule that a
performance change must not worsen the worst case it touches. Threshold: <= 50 ms per 1 MiB of private-block text on
this host (minimum of three runs, the host is shared). Semantics stay those of the reviewed loop: every result is
compared with ``_old_private`` (the verbatim copy of ``3d116cf``'s loop in ``test_t8_review_w01_private_equivalence``),
which is linear, so it runs on the large inputs too.

Shapes: 16 closed blocks of about 60 KB (about 1 MiB) as 16 strings through the filter and as one text through the
phase; one unclosed 64 KiB block (refused quickly); blocks full of ``<`` that is not a marker (HTML or code); many
4 KiB blocks; non-ASCII content.
"""

from __future__ import annotations

import time
from collections.abc import Callable

import pytest

from superbrain.application.privacy import PrivacyFilter
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import FilterPolicy
from tests.application.test_t8_review_w01_private_equivalence import _new_phase, _old

LIMIT_PER_MIB_S = 0.050
_POLICY = FilterPolicy(entropy_min_length=4096)
_BLOCK = 60_000

_PROSE = "the river runs past nine quiet hills and the notes stay readable "
_HTML = "<div><b>a</b> < b, x<y, <br/> <p class=x>t</p> <privat <privacy> "
_CODE = "if (a < b && c<d) { x = y <<< 2; } // < privat notes "
_VIET = "Tiếng Việt có dấu ở đây, và văn bản vẫn đọc được. "


def _fill(unit: str, size: int) -> str:
    """``unit`` repeated to ``size`` UTF-8 bytes (or just under, never splitting a character)."""
    text = unit * (size // len(unit.encode()) + 1)
    while len(text.encode()) > size:
        text = text[: len(text) - max(1, (len(text.encode()) - size) // 4)]
    return text


def _block(content: str) -> str:
    return f"<private>{content}</private>"


def _best(fn: Callable[[], object]) -> tuple[object, float]:
    best = float("inf")
    result: object = None
    for _ in range(3):
        start = time.perf_counter()
        result = fn()
        best = min(best, time.perf_counter() - start)
    return result, best


def _mib(texts: list[str]) -> float:
    return sum(len(t.encode()) for t in texts) / (1024 * 1024)


def _filter_all(texts: list[str]) -> object:
    try:
        safe = PrivacyFilter().apply(list(texts), _POLICY)
    except BrainError as error:
        return error.code
    return safe.value, safe.redacted_count


def _expected_all(texts: list[str]) -> object:
    outcomes = [_old(t) for t in texts]
    if any(o is None for o in outcomes):
        return ErrorCode.INVALID_INPUT
    return [o[0] for o in outcomes if o is not None], sum(o[1] for o in outcomes if o is not None)


# Every string is distinct (index prefix): the filter caches identical strings within one payload.
_STRING_SETS: dict[str, list[str]] = {
    "prose-16x60k": [f"s{i} " + _block(_fill(_PROSE, _BLOCK)) for i in range(16)],
    "html-16x60k": [f"s{i} " + _block(_fill(_HTML, _BLOCK)) for i in range(16)],
    "code-16x60k": [f"s{i} " + _block(_fill(_CODE, _BLOCK)) for i in range(16)],
    "viet-16x60k": [f"s{i} " + _block(_fill(_VIET, _BLOCK)) for i in range(16)],
    "many-4k-blocks": [f"s{i} " + "".join(_block(_fill(_PROSE, 4_000)) + " x " for _ in range(15)) for i in range(16)],
    "html-4k-blocks": [f"s{i} " + "".join(_block(_fill(_HTML, 4_000)) + " < y " for _ in range(15)) for i in range(16)],
}


@pytest.mark.parametrize("name", list(_STRING_SETS))
def test_w02_large_blocks_across_strings_are_linear_and_equal_the_reviewed_loop(name: str) -> None:
    texts = _STRING_SETS[name]
    assert all(len(t.encode()) <= 64 * 1024 for t in texts) and _mib(texts) >= 0.85
    result, best = _best(lambda: _filter_all(texts))
    assert result == _expected_all(texts), "filter result differs from the reviewed loop"
    per_mib = best / _mib(texts)
    assert per_mib <= LIMIT_PER_MIB_S, f"{name}: {per_mib * 1000:.1f} ms per MiB (limit {LIMIT_PER_MIB_S * 1000:.0f})"


@pytest.mark.parametrize("unit", [_PROSE, _HTML, _CODE, _VIET], ids=["prose", "html", "code", "viet"])
def test_w02_sixteen_large_blocks_in_one_text_are_linear_in_the_private_phase(unit: str) -> None:
    text = "".join(_block(_fill(unit, _BLOCK)) + " between " for _ in range(16))
    result, best = _best(lambda: _new_phase(text))
    assert result == _old(text) and result is not None and result[1] == 16
    per_mib = best / _mib([text])
    assert per_mib <= LIMIT_PER_MIB_S, f"{per_mib * 1000:.1f} ms per MiB (limit {LIMIT_PER_MIB_S * 1000:.0f})"


@pytest.mark.parametrize("unit", [_PROSE, _HTML, _VIET], ids=["prose", "html", "viet"])
def test_w02_unclosed_64_kib_block_is_refused_quickly(unit: str) -> None:
    text = "<private>" + _fill(unit, 64 * 1024 - 40)
    while len(text.encode()) > 64 * 1024:
        text = text[:-100]
    assert _old(text) is None
    result, best = _best(lambda: _filter_all([text]))
    assert result is ErrorCode.INVALID_INPUT
    assert best <= LIMIT_PER_MIB_S / 16 + 0.002, f"refusal of one unclosed 64 KiB block took {best * 1000:.1f} ms"


def test_w02_private_blocks_cost_about_the_same_as_the_same_text_without_markers() -> None:
    # Relative guard: the private phase must not dominate the filter on block-heavy input.
    blocks = _STRING_SETS["html-16x60k"]
    plain = [t.replace("<private>", "[private]").replace("</private>", "[/private]") for t in blocks]
    assert len(set(blocks)) == len(blocks) and len(set(plain)) == len(plain)
    _r1, with_markers = _best(lambda: _filter_all(blocks))
    _r2, without = _best(lambda: _filter_all(plain))
    assert with_markers <= 2 * without + 0.010, f"{with_markers * 1000:.1f} ms with blocks vs {without * 1000:.1f} ms"
