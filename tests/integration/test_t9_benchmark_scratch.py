"""The Windows benchmark must launch its owner from an owner-verified scratch tree."""

from __future__ import annotations

import json
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import TracebackType
from typing import NoReturn

import pytest

from scripts import perf_probe
from superbrain.adapters.os import os_adapters
from superbrain.core.errors import ErrorCode
from tests.support import inc2_cli, inc2_fixture
from tests.support.inc2_fixture import InstalledEnv
from tests.support.platform import windows_only
from tests.support.winacl import grant

_REPO = Path(__file__).resolve().parents[2]
_READ_CONFIG = """
import json, sys
from pathlib import Path
from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.daemon_config import read_daemon_config
from superbrain.core.errors import BrainError
try:
    config = read_daemon_config(Path(sys.argv[1]), os_adapters())
except BrainError as error:
    print(json.dumps({"ok": False, "code": error.code.value}))
else:
    print(json.dumps({"ok": True, "store_id": config.expected_store_id}))
"""


class _ConfigObserved(Exception):
    """The real installed owner reader reached the startup boundary successfully."""


def _read_from_wheel(env: InstalledEnv, config: Path) -> dict[str, object]:
    result = subprocess.run(
        [str(env.venv_python), "-I", "-c", _READ_CONFIG, str(config)],
        capture_output=True, text=True, encoding="utf-8", timeout=15, check=True,
    )
    parsed: dict[str, object] = json.loads(result.stdout)
    return parsed


@windows_only
@pytest.mark.parametrize("unsafe_default", [False, True], ids=["private-default", "takeover-default"])
def test_benchmark_owner_config_is_readable_when_default_temp_has_takeover_access(
    trusted_tmp: Path, inc2_installed_env: InstalledEnv, monkeypatch: pytest.MonkeyPatch, unsafe_default: bool,
) -> None:
    # Build the real wheel and reusable source template before redirecting the default temporary location.
    template = inc2_cli.get_shared_t7_transport_template()
    adapters = os_adapters()
    default_temp = trusted_tmp / "os-temp"
    default_temp.mkdir()
    adapters.permissions.secure_directory(default_temp)
    if unsafe_default:
        # Taint only this disposable fixture. The real reader must continue to reject this parent.
        grant(default_temp, "S-1-5-32-545", 0x40)  # BUILTIN Users, FILE_DELETE_CHILD
    problems = adapters.permissions.check_ancestors(default_temp / "child" / "daemon.json")
    assert bool([problem for problem in problems if problem.path == default_temp]) is unsafe_default

    control = inc2_cli.write_daemon_config_file(
        default_temp / "control" / "daemon.json", data_root=template.root,
        expected_store_id=template.store_id, cert_path=template.tls.cert_path, key_path=template.tls.key_path,
    )
    expected_control: dict[str, object] = (
        {"ok": False, "code": ErrorCode.INSECURE_PERMISSIONS.value} if unsafe_default
        else {"ok": True, "store_id": template.store_id}
    )
    assert _read_from_wheel(inc2_installed_env, control) == expected_control
    config_paths: list[Path] = []

    @contextmanager
    def installed(_scratch: Path) -> Iterator[InstalledEnv]:
        # Reuse the genuine installed fixture; installation itself is outside this reader/path regression.
        yield inc2_installed_env

    class CheckedOwnerStart:
        def __init__(self, env: InstalledEnv, config: Path, _repo: Path, _attempt: Path) -> None:
            self.env = env
            self.config = config

        def __enter__(self) -> NoReturn:
            config_paths.append(self.config)
            assert adapters.permissions.object_problems(self.config) == []
            actual = _read_from_wheel(self.env, self.config)
            assert actual == {"ok": True, "store_id": template.store_id}, (
                "benchmark scratch rejected by the unchanged installed owner reader", actual
            )
            raise _ConfigObserved

        def __exit__(
            self, _kind: type[BaseException] | None, _value: BaseException | None, _trace: TracebackType | None,
        ) -> None:
            pass

    monkeypatch.setattr(tempfile, "tempdir", str(default_temp))
    monkeypatch.setattr(inc2_fixture, "open_inc2_installed_env", installed)
    monkeypatch.setattr(perf_probe, "_daemon", CheckedOwnerStart)
    attempt = trusted_tmp / "evidence"
    attempt.mkdir()
    with pytest.raises(_ConfigObserved):
        perf_probe.measure(_REPO, attempt)

    assert len(config_paths) == 1, "the benchmark never reached its owner configuration boundary"
    assert not config_paths[0].parent.exists(), "benchmark left its private scratch tree behind"
    after = adapters.permissions.check_ancestors(default_temp / "new-child" / "daemon.json")
    assert bool([problem for problem in after if problem.path == default_temp]) is unsafe_default
