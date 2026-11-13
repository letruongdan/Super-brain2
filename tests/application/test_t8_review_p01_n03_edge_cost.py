"""T8-P01-N3: the edge search over long wrapper runs is linear with a small constant and honours the deadline.

Requirement. Invariant of F3/N1: all path-filter work is bounded by the shared deadline or a fixed limit, and grows
linearly with a small constant. Plan 8.6(b): local privacy p95 <= 100 ms per 1 MiB, about 6 ms per 64 KiB; the
thresholds here are 50 ms per 64 KiB text without a deadline (about 8x the plan budget, taken as the minimum of three
runs because the host is shared), and a deadline is noticed within 50 ms of expiring. Semantics stay §14.2 "any
trimmed spelling": each long fixture has a short twin of the same shape checked against the brute-force reference
``_reference_outcomes`` of ``test_t8_review_p01_r3_spellings.py``; the long results are checked exactly where one
spelling is blocked and structurally where several are.

A policy that a fixed limit refuses at construction (``INVALID_INPUT`` from ``FilterPolicy``) also satisfies the
invariant for the custom-policy cases; the shipped defaults must always be decided.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from superbrain.application.privacy import PrivacyFilter
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.kernel import DEFAULT_BLOCKED_PATH_PATTERNS, FilterPolicy
from tests.application.test_t8_review_p01_r3_spellings import REDACTED, _reference_outcomes

DEFAULTS = DEFAULT_BLOCKED_PATH_PATTERNS
RUN = 32_000  # wrapper run on each side: the longest that fits a 64 KiB text
LIMIT_S = 0.050  # per 64 KiB text, no deadline
SLACK_S = 0.050  # a deadline is noticed within this much of expiring
_SUFFIXES = ("", " über")  # ASCII text, and text with a non-ASCII word elsewhere
_STAR_HEAD = "*" + "?" * 200 + "[q]"  # reviewer shape: a star, then a long fixed tail
_ROOT = Path(__file__).resolve().parents[2]


def _policy(patterns: tuple[str, ...]) -> FilterPolicy | None:
    try:
        return FilterPolicy(blocked_path_patterns=patterns, entropy_min_length=4096)
    except BrainError as error:  # a fixed limit at construction: fail closed, allowed for custom policies
        assert error.code is ErrorCode.INVALID_INPUT
        return None


def _timed(text: str, patterns: tuple[str, ...]) -> tuple[str, int, float] | None:
    policy = _policy(patterns)
    if policy is None:
        assert patterns != DEFAULTS
        return None
    PrivacyFilter().apply({"note": "warm up x/y"}, policy)
    best = float("inf")
    value: object = None
    redacted = -1
    for _ in range(3):
        start = time.perf_counter()
        safe = PrivacyFilter().apply({"note": text}, policy)
        best = min(best, time.perf_counter() - start)
        assert isinstance(safe.value, dict)
        value, redacted = safe.value["note"], safe.redacted_count
    assert isinstance(value, str)
    return value, redacted, best


# ------------------------------------------------------------------------------------------------------------------
# long-token shapes: (id, patterns, short twin, short twin outcomes, long token, structural check of the long result)
# ------------------------------------------------------------------------------------------------------------------


def _exact(expected: str) -> object:
    return lambda got: got == expected


def _shape_ok(token: str, min_len: int) -> object:
    """The result replaces one spelling token[p:n-s] (p, s inside the wrapper runs, length >= min_len)."""
    lead = len(token) - len(token.lstrip("`*"))
    trail = len(token) - len(token.rstrip("`*.:!?"))

    def check(got: str) -> bool:
        if got.count(REDACTED) != 1:
            return False
        before, after = got.split(REDACTED)
        p, s = len(before), len(after)
        return (
            p <= lead and s <= trail and token.startswith(before) and token.endswith(after)
            and len(token) - p - s >= min_len
        )

    return check


_MISS = "`" * RUN + ".envx" + "!" * RUN
_IDRSA = "`" * RUN + "id_rsa" + "!" * RUN
_Z = "`" * RUN + "z" + "!" * RUN
_Q = "`" * RUN + "q" + "!" * RUN

_SHAPES: list[tuple[str, tuple[str, ...], str, frozenset[str], str, object]] = [
    ("defaults-miss", DEFAULTS, "```.envx!!!", frozenset(), _MISS, _exact(_MISS)),
    ("defaults-hit", DEFAULTS, "```id_rsa!!!", frozenset({"```" + REDACTED + "!!!"}), _IDRSA,
     _exact("`" * RUN + REDACTED + "!" * RUN)),
    ("star-tail-miss", (_STAR_HEAD,), "```z!!!", frozenset(), _Z, _exact(_Z)),
    ("star-tail-hit", (_STAR_HEAD,), "", frozenset(), _Q, _shape_ok(_Q, 202)),
    ("long-head-star-hit", ("?" * 200 + "*",), "", frozenset(), _Z, _shape_ok(_Z, 200)),
    ("fixed-width-miss", ("?" * 300 + "[q]",), "```z!!!", frozenset(), _Z, _exact(_Z)),
    ("fixed-width-hit", ("?" * 300 + "[q]",), "```q!!", frozenset({"`" + REDACTED + "!!"}), _Q,
     _exact("`" * (RUN - 300) + REDACTED + "!" * RUN)),
    ("chain-star-edge-first", ("*`/x",), "```/x", frozenset({"`" * k + REDACTED for k in range(3)}),
     "`" * RUN + "/x", _shape_ok("`" * RUN + "/x", 3)),
    ("chain-star-edge-last", ("x/!*",), "x/!!!", frozenset({REDACTED + "!" * k for k in range(3)}),
     "x/" + "!" * RUN, _shape_ok("x/" + "!" * RUN, 3)),
]  # fmt: skip
_SHAPE_IDS = [shape[0] for shape in _SHAPES]
# Long fixed widths shrink with the twin: the same shape (star / fixed width, then a class) at a short width.
_TWIN_PATTERNS: dict[tuple[str, ...], tuple[str, ...]] = {(_STAR_HEAD,): ("*??[q]",), ("?" * 300 + "[q]",): ("??[q]",)}


def test_n03_twin_fixtures_agree_with_the_reference() -> None:
    for name, patterns, twin, outcomes, _token, _check in _SHAPES:
        if twin:
            assert _reference_outcomes(twin, _TWIN_PATTERNS.get(patterns, patterns)) == outcomes, name
    # Short twins of the shapes whose long result is structural.
    assert _reference_outcomes("``q!!", ("*?[q]",)) == {"`" * k + REDACTED + "!!" for k in range(2)}
    assert _reference_outcomes("```z!!!", ("??*",)) == {
        "`" * p + REDACTED + "!" * s for p in range(4) for s in range(4) if 7 - p - s >= 2
    }
    assert _reference_outcomes("`z!", ("????*",)) == frozenset()  # near miss: shorter than the head


@pytest.mark.parametrize(
    ("patterns", "token", "check"), [shape[1:2] + shape[4:6] for shape in _SHAPES], ids=_SHAPE_IDS
)
@pytest.mark.parametrize("suffix", _SUFFIXES, ids=["ascii", "non_ascii"])
def test_n03_long_wrapper_run_token_is_decided_in_linear_time(
    patterns: tuple[str, ...], token: str, check: object, suffix: str
) -> None:
    text = f"{token}{suffix}"
    assert len(text.encode()) <= 64 * 1024
    timed = _timed(text, patterns)
    if timed is None:
        return
    value, redacted, best = timed
    got = value[: len(value) - len(suffix)] if suffix else value
    assert value.endswith(suffix) and callable(check) and check(got), "result differs from the §14.2 definition"
    assert redacted == (0 if got == token else 1)
    assert best < LIMIT_S, f"64 KiB text took {best * 1000:.0f} ms (limit {LIMIT_S * 1000:.0f} ms)"


def test_n03_short_token_under_a_long_head_stays() -> None:
    timed = _timed("see " + "`" * 90 + "z" + "!" * 90 + " now", ("?" * 200 + "*",))
    if timed is not None:
        assert timed[:2] == ("see " + "`" * 90 + "z" + "!" * 90 + " now", 0)


# ------------------------------------------------------------------------------------------------------------------
# deadline promptness, and many long patterns (run in a child process so an unbounded search cannot hang the suite)
# ------------------------------------------------------------------------------------------------------------------

_CHILD = r"""
import json, sys, time
from superbrain.application.privacy import PrivacyFilter
from superbrain.core.errors import BrainError
from superbrain.core.kernel import FilterPolicy
job = json.load(sys.stdin)
try:
    policy = FilterPolicy(blocked_path_patterns=tuple(job["patterns"]), entropy_min_length=4096)
except BrainError as error:
    print(json.dumps({"outcome": "refused_at_build", "code": error.code.value})); sys.exit(0)
PrivacyFilter().apply({"note": "warm up x/y"}, policy)
deadline = None if job["deadline_ms"] is None else time.monotonic_ns() + job["deadline_ms"] * 1_000_000
start = time.perf_counter()
try:
    safe = PrivacyFilter().apply({"note": job["text"]}, policy, deadline_ns=deadline)
except BrainError as error:
    print(json.dumps({"outcome": "error", "code": error.code.value, "elapsed": time.perf_counter() - start}))
else:
    print(json.dumps({"outcome": "ok", "same": safe.value == {"note": job["text"]},
                      "redacted": safe.redacted_count, "elapsed": time.perf_counter() - start}))
"""


def _child(patterns: tuple[str, ...], text: str, deadline_ms: int | None, timeout_s: float = 20.0) -> dict[str, object]:
    job = json.dumps({"patterns": list(patterns), "text": text, "deadline_ms": deadline_ms})
    try:
        done = subprocess.run(
            [sys.executable, "-c", _CHILD], input=job, capture_output=True, text=True, timeout=timeout_s,
            cwd=_ROOT, encoding="utf-8", check=False,
        )  # fmt: skip
    except subprocess.TimeoutExpired:
        pytest.fail(f"filter still running after {timeout_s:.0f} s (deadline_ms={deadline_ms})")
    assert done.returncode == 0, done.stderr[-2000:]
    result = json.loads(done.stdout.strip().splitlines()[-1])
    assert isinstance(result, dict)
    return result


_TWENTY = tuple("*" + "?" * (200 + i) + "[q]" for i in range(20))


@pytest.mark.parametrize(("patterns", "label"), [((_STAR_HEAD,), "one"), (_TWENTY, "twenty")], ids=["one", "twenty"])
def test_n03_deadline_is_honoured_promptly_during_the_edge_search(patterns: tuple[str, ...], label: str) -> None:
    result = _child(patterns, _Z, deadline_ms=200)
    if result["outcome"] == "refused_at_build":
        assert result["code"] == ErrorCode.INVALID_INPUT.value
        return
    elapsed = result["elapsed"]
    assert isinstance(elapsed, float)
    if result["outcome"] == "error":
        assert result["code"] == ErrorCode.DEADLINE_EXCEEDED.value
    else:
        assert result["same"] is True and result["redacted"] == 0
    assert elapsed <= 0.200 + SLACK_S, f"{label}: deadline of 200 ms honoured only after {elapsed:.2f} s"


def test_n03_twenty_long_patterns_without_a_deadline_are_linear() -> None:
    result = _child(_TWENTY, _Z, deadline_ms=None)
    if result["outcome"] == "refused_at_build":
        assert result["code"] == ErrorCode.INVALID_INPUT.value
        return
    assert result["outcome"] == "ok" and result["same"] is True and result["redacted"] == 0
    elapsed = result["elapsed"]
    assert isinstance(elapsed, float) and elapsed < LIMIT_S, f"20 patterns over 64 KiB took {elapsed:.2f} s"
