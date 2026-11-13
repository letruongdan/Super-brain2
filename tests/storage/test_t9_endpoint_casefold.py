"""Task 9 endpoint preflight classifies reserved names consistently across OSes."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.storage.layout import check_endpoint_entries_under_lease, prepare_data_root
from superbrain.storage.writer import acquire_writer


@pytest.mark.parametrize(
    "name", ["endpoint.json", "ENDPOINT.JSON", "endpoint.json.stage-fake", "ENDPOINT.JSON.STAGE-FAKE"],
)
def test_endpoint_name_variants_validate_file_and_reject_link_under_lease(trusted_tmp: Path, name: str) -> None:
    adapters = os_adapters()
    root = prepare_data_root(trusted_tmp / "root", adapters)
    outside = trusted_tmp / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel.txt"
    sentinel.write_bytes(b"outside bytes stay intact")

    with acquire_writer(root, adapters) as lease:
        entry = root.root / name
        entry.write_bytes(b"safe endpoint candidate")
        adapters.permissions.secure_file(entry)
        assert check_endpoint_entries_under_lease(root, lease, adapters) == (entry,)
        entry.unlink()
        if sys.platform == "win32":
            import _winapi

            _winapi.CreateJunction(str(outside), str(entry))
        else:
            entry.symlink_to(outside, target_is_directory=True)
        with root.lock_path.open("rb") as lock_file:
            lock_file.seek(1)  # Windows holds the lease lock on byte zero.
            lock_before = lock_file.read()
        try:
            with pytest.raises(BrainError) as raised:
                check_endpoint_entries_under_lease(root, lease, adapters)
            assert raised.value.code is ErrorCode.UNSAFE_PATH
            assert sentinel.read_bytes() == b"outside bytes stay intact"
            with root.lock_path.open("rb") as lock_file:
                lock_file.seek(1)
                assert lock_file.read() == lock_before
            assert lease.held
        finally:
            if sys.platform == "win32":
                os.rmdir(entry)
            else:
                entry.unlink()
