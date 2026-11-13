"""Task 9: data-root entries named store.*/policy.* are reserved in any letter case, on every OS (fail closed)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.storage.layout import prepare_data_root, verify_existing_data_root
from tests.storage.test_layout import loosen

# The lowercase spelling is the control; the others must be classified the same way.
NAMES = ["store.restoring", "STORE.RESTORING", "POLICY.MIGRATING", "Store.Stage-x"]


def _link_dir(target: Path, link: Path) -> None:
    if sys.platform == "win32":
        import _winapi

        _winapi.CreateJunction(str(target), str(link))
    else:
        link.symlink_to(target, target_is_directory=True)


@pytest.mark.parametrize("name", NAMES)
def test_reserved_sibling_link_is_rejected_in_any_case(trusted_tmp: Path, name: str) -> None:
    adapters = os_adapters()
    root = prepare_data_root(trusted_tmp / "root", adapters).root
    outside = trusted_tmp / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel.txt"
    sentinel.write_bytes(b"outside bytes stay intact")
    entry = root / name
    _link_dir(outside, entry)
    try:
        for check in (verify_existing_data_root, prepare_data_root):
            with pytest.raises(BrainError) as raised:
                check(root, adapters)
            assert raised.value.code is ErrorCode.UNSAFE_PATH, check.__name__
        assert sentinel.read_bytes() == b"outside bytes stay intact"
    finally:
        if sys.platform == "win32":
            os.rmdir(entry)
        else:
            entry.unlink()


@pytest.mark.parametrize("name", NAMES)
def test_reserved_sibling_that_is_not_owner_only_is_rejected_in_any_case(trusted_tmp: Path, name: str) -> None:
    adapters = os_adapters()
    root = prepare_data_root(trusted_tmp / "root", adapters).root
    entry = root / name
    entry.mkdir()
    if sys.platform != "win32":
        os.chmod(entry, 0o700)  # on Windows it inherits the root's owner-only rules
    # Twin: the same owner-only entry is accepted, so the rejection below is about its permissions.
    assert verify_existing_data_root(root, adapters).root == root
    loosen(entry)
    with pytest.raises(BrainError) as raised:
        verify_existing_data_root(root, adapters)
    assert raised.value.code is ErrorCode.INSECURE_PERMISSIONS
