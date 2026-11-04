"""C08: absent configured data roots still reject linked ancestors (spec 4.3/5.9).

The same configured path must fail real runtime admission and real gate preflight.
Only the final component is absent; its existing parent is a real link/junction to
an otherwise admissible directory. No path is resolved before testing the oracle.
"""

from pathlib import Path

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.storage.runtime import open_runtime
from tests.architecture.test_remediation_c08_r6_root_itself import (
    environment_of,
    path_entry,
    reasons_naming,
    redirect_trusted_root,
    run_gate_with_real_preflight,
    secure_dir,
)
from tests.architecture.test_remediation_c08_r8_root_links import make_directory_link


def test_an_absent_data_root_under_a_linked_parent_is_not_accepted(
    trusted_tmp: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    redirect_trusted_root(trusted_tmp, monkeypatch)
    homes = secure_dir(trusted_tmp / "homes")
    target = secure_dir(homes / "real-parent")
    linked = homes / "linked-parent"
    make_directory_link(linked, target)
    configured = linked / "absent-data-root"
    assert not configured.exists()
    assert os_adapters().permissions.object_problems(target) == []

    with pytest.raises(BrainError) as refused:
        open_runtime(configured, os_adapters())
    assert refused.value.code == ErrorCode.UNSAFE_PATH
    assert not (target / configured.name).exists()
    monkeypatch.setenv("SUPERBRAIN_HOME", str(configured))

    receipt = run_gate_with_real_preflight(tmp_path, monkeypatch)

    assert path_entry(receipt, "default_data_root")["exists"] is False
    assert receipt["accepted"] is False, "an absent data root through a linked parent was accepted"
    assert environment_of(receipt)["accepted"] is False
    assert reasons_naming(receipt, "default_data_root", configured.name), receipt["reasons"]
    assert not (target / configured.name).exists(), "preflight created the absent data root"


def test_an_absent_data_root_under_a_safe_parent_remains_accepted(
    trusted_tmp: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    redirect_trusted_root(trusted_tmp, monkeypatch)
    configured = secure_dir(trusted_tmp / "homes") / "absent-data-root"
    monkeypatch.setenv("SUPERBRAIN_HOME", str(configured))

    receipt = run_gate_with_real_preflight(tmp_path, monkeypatch)

    assert receipt["accepted"] is True, receipt["reasons"]
    assert environment_of(receipt)["accepted"] is True
    assert path_entry(receipt, "default_data_root")["exists"] is False
    assert not configured.exists(), "preflight created the absent data root"
