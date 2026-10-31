"""SP1-C08 round 4: ANY failure of the environment preflight is a reason; ``run_gate`` never crashes, never accepts.

Requirement (spec 4.3 owner policy: the acceptance environment is checked for real; spec 17.2: a gate that did not
complete is "chưa nghiệm thu", never accepted; C08 contract: "if ``collect_environment`` raises,
``receipt["environment"]`` is ``None`` and a reason contains 'environment preflight'"; independent review round 1
observation and owner round-2 survivor "narrow exception list"): whatever exception the preflight raises, of any
``Exception`` type, ``run_gate`` returns a receipt that is NOT accepted, records no environment section, and gives a
reason naming the failure. The tests drive the real ``run_gate``; exceptions come from the module-level
``collect_environment`` and, through the real collection path, from the real probe's token query.
"""

import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from scripts import gate
from tests.architecture.test_remediation_c08_gate_environment import GreenRunner


class UnforeseenPreflightError(Exception):
    """An exception type no preflight could list in advance."""


FAILURES: dict[str, Callable[[], BaseException]] = {
    "attribute-error": lambda: AttributeError("c08-r4 marker: probe has no attribute"),
    "key-error": lambda: KeyError("c08-r4 marker: LOCALAPPDATA"),
    "custom-exception": lambda: UnforeseenPreflightError("c08-r4 marker: unforeseen"),
    "type-error": lambda: TypeError("c08-r4 marker: wrong type"),
    "zero-division": lambda: ZeroDivisionError("c08-r4 marker: arithmetic"),
}
MARKER = "c08-r4 marker"


def run_gate_green(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    monkeypatch.setattr(gate, "run", GreenRunner())
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    try:
        receipt, _ = gate.run_gate(tmp_path / "repo", "3.14")
    except Exception as err:  # noqa: BLE001 - the oracle: run_gate must not crash on a preflight failure
        pytest.fail(f"run_gate crashed instead of returning a refused receipt: {type(err).__name__}: {err}")
    return dict(receipt)


def assert_refused_naming(receipt: dict[str, Any], failure: BaseException) -> None:
    assert receipt["accepted"] is False, "a run whose environment preflight failed was accepted"
    assert receipt.get("environment", "absent") is None
    reasons = [str(r) for r in receipt["reasons"]]
    assert any("environment preflight" in r and MARKER in r for r in reasons), reasons
    assert any(type(failure).__name__ in r for r in reasons), (type(failure).__name__, reasons)


@pytest.mark.parametrize("name", sorted(FAILURES))
def test_any_exception_from_collect_environment_is_a_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    failure = FAILURES[name]()

    def broken(*args: object, **kwargs: object) -> Any:
        raise failure

    monkeypatch.setattr(gate, "collect_environment", broken)

    receipt = run_gate_green(tmp_path, monkeypatch)

    assert_refused_naming(receipt, failure)


@pytest.mark.parametrize("name", ["attribute-error", "custom-exception"])
def test_any_exception_from_the_real_probe_is_a_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    """Through the real ``collect_environment``: the real probe's token query fails unexpectedly."""
    failure = FAILURES[name]()

    def broken(self: object) -> bool | None:
        raise failure

    monkeypatch.setattr(gate.OsEnvironmentProbe, "app_container", broken)

    receipt = run_gate_green(tmp_path, monkeypatch)

    assert_refused_naming(receipt, failure)
