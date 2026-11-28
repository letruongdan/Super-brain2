"""A full disk is STORAGE_FULL on every durable outbox write, so the hook records an outbox_full CaptureGap.

Before, only frame writes kept the code: a directory fsync (POSIX), an ACK page, a binding bucket or a cursor write
turned ENOSPC into IO_ERROR, and the hook's gap fallback (DEADLINE_EXCEEDED / STORAGE_FULL only) never ran.
"""

from __future__ import annotations

import errno
import os
from pathlib import Path
from typing import Any

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports import capture as capture_ports
from superbrain.storage._outbox_durable import sync_dir
from superbrain.storage.outbox import OutboxSpool
from tests.storage.test_outbox_r10_ack_durability import _ack, _enqueue_hook


def _enospc(*_args: Any, **_kwargs: Any) -> None:
    raise OSError(errno.ENOSPC, "No space left on device")


def test_directory_sync_on_a_full_disk_is_storage_full(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(capture_ports, "_DEFAULT_OUTBOX_DIR_SYNC", _enospc)
    with pytest.raises(BrainError) as err:
        sync_dir(tmp_path)
    assert err.value.code is ErrorCode.STORAGE_FULL


@pytest.mark.parametrize(
    ("target", "action"),
    [(".seq_cursor.json", "enqueue"), (".bindings", "enqueue"), (".acks", "ack")],
    ids=["cursor", "binding-bucket", "ack-page"],
)
def test_metadata_writes_on_a_full_disk_are_storage_full(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch, target: str, action: str
) -> None:
    spool = OutboxSpool(trusted_tmp / "outbox", permissions=os_adapters().permissions)
    stream = "stream-full-disk"
    _enqueue_hook(spool, stream=stream, dk=digest_bytes(b"full-disk-1"))
    real_replace = os.replace
    hits = [0]

    def _full_for(src: Any, dst: Any) -> None:
        # the first write of the target is the pre-publication one, which must fail closed; post-publication
        # upkeep (the second cursor write) is deferred by design
        if target in str(dst) and hits[0] == 0:
            hits[0] += 1
            _enospc()
        real_replace(src, dst)

    monkeypatch.setattr(os, "replace", _full_for)
    with pytest.raises(BrainError) as err:
        if action == "enqueue":
            _enqueue_hook(spool, stream=stream, dk=digest_bytes(b"full-disk-2"))
        else:
            spool.apply_ack(_ack(stream, committed=(5_000,)))  # out of the window: written as an ACK page
    assert err.value.code is ErrorCode.STORAGE_FULL, err.value
