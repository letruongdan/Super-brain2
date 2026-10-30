"""Shared pytest fixtures."""

import os
import shutil
import sys
import uuid
import warnings
from collections.abc import Iterator
from pathlib import Path

import pytest


@pytest.fixture
def trusted_tmp(tmp_path: Path) -> Iterator[Path]:
    """A directory whose whole ancestor chain passes ``check_ancestors``.

    POSIX: ``tmp_path``. Windows: a protected directory under ``%LOCALAPPDATA%``, because the system temp
    directory may carry ACEs for other accounts.
    """
    if sys.platform == "win32":
        from superbrain.adapters.os.permissions import WindowsPermissionGuard

        root = Path(os.environ["LOCALAPPDATA"]) / "superbrain-tests" / str(uuid.uuid4())
        root.mkdir(parents=True)
        WindowsPermissionGuard().secure_directory(root)
        try:
            yield root
        finally:
            try:
                shutil.rmtree(root)
            except OSError as err:
                warnings.warn(f"could not remove test directory {root}: {err}", stacklevel=1)
    else:
        yield tmp_path
