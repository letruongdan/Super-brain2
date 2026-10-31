import errno
import json
import signal
import sys
import zlib
from pathlib import Path

import pytest

from superbrain.adapters.os import locks, os_adapters
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.storage.layout import DataRoot, prepare_data_root
from superbrain.storage.writer import LockState, acquire_writer
from tests.support.crash import paused_child, run_child, run_until_crash
from tests.support.fs import corrupt_bytes

SLOT_OFFSETS = (1, 257)


def fresh_root(base: Path) -> DataRoot:
    return prepare_data_root(base / "r", os_adapters())


def slot_bytes(seq: int, epoch: int, hwm: int) -> bytes:
    fields = {"seq": seq, "writer_epoch": epoch, "trust_generation_hwm": hwm}
    body = json.dumps(fields, separators=(",", ":")).encode().ljust(252, b" ")
    return body + zlib.crc32(body).to_bytes(4, "big")


def write_raw_slots(root: DataRoot, slots: dict[int, bytes]) -> None:
    data = bytearray(root.lock_path.read_bytes().ljust(513, b"\0"))
    for offset, raw in slots.items():
        data[offset : offset + len(raw)] = raw
    root.lock_path.write_bytes(bytes(data))


def test_second_process_cannot_acquire_while_held(trusted_tmp: Path) -> None:
    root = fresh_root(trusted_tmp)
    with acquire_writer(root, os_adapters()):
        assert run_child("acquire_writer", root.root).error_code == "writer_held"


def test_second_acquire_in_the_same_process_is_refused(trusted_tmp: Path) -> None:
    root = fresh_root(trusted_tmp)
    with acquire_writer(root, os_adapters()):
        with pytest.raises(BrainError) as e:
            acquire_writer(root, os_adapters())
    assert e.value.code == ErrorCode.WRITER_HELD


def test_lock_released_when_holder_process_is_killed(trusted_tmp: Path) -> None:
    root = fresh_root(trusted_tmp)
    with paused_child("acquire_writer_and_pause", "writer.held", root.root) as child:
        child.kill()
    assert child.returncode != 0
    if sys.platform != "win32":
        assert child.returncode == -signal.SIGKILL
    with acquire_writer(root, os_adapters()) as lease:
        assert lease.epoch == 2


def test_release_lets_the_next_writer_in(trusted_tmp: Path) -> None:
    root = fresh_root(trusted_tmp)
    lease = acquire_writer(root, os_adapters())
    lease.release()
    lease.release()  # idempotent
    assert run_child("acquire_writer", root.root).returncode == 0


def test_epoch_increments_on_every_acquisition(trusted_tmp: Path) -> None:
    root = fresh_root(trusted_tmp)
    epochs = []
    for _ in range(3):
        with acquire_writer(root, os_adapters()) as lease:
            epochs.append(lease.epoch)
    assert epochs == [1, 2, 3]


def test_epoch_is_durable_before_acquire_returns(trusted_tmp: Path) -> None:
    root = fresh_root(trusted_tmp)
    with acquire_writer(root, os_adapters()), root.lock_path.open("rb") as f:
        f.seek(1)  # on Windows byte 0 is the locked region, unreadable through another handle
        on_disk = f.read(256)
    assert on_disk == slot_bytes(1, 1, 0)


def test_acquire_fails_without_a_lease_when_the_epoch_cannot_be_made_durable(
    trusted_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = fresh_root(trusted_tmp)
    with acquire_writer(root, os_adapters()):
        pass

    def failing_fsync(fd: int) -> None:
        raise OSError(errno.EIO, "injected fsync failure")

    monkeypatch.setattr(locks, "_full_fsync", failing_fsync)
    with pytest.raises(BrainError) as e:
        acquire_writer(root, os_adapters())
    assert e.value.code == ErrorCode.IO_ERROR
    monkeypatch.undo()
    # The lock was released, and the epoch that never became durable was not issued.
    with acquire_writer(root, os_adapters()) as lease:
        assert lease.epoch == 2


@pytest.mark.parametrize("value", [True, -1])
def test_trust_hwm_must_be_a_non_negative_int(trusted_tmp: Path, value: int) -> None:
    root = fresh_root(trusted_tmp)
    with acquire_writer(root, os_adapters()) as lease:
        with pytest.raises(BrainError) as e:
            lease.raise_trust_hwm(value)
        assert e.value.code == ErrorCode.INVALID_INPUT
        assert lease.state().trust_generation_hwm == 0


def test_trust_hwm_never_decreases(trusted_tmp: Path) -> None:
    root = fresh_root(trusted_tmp)
    with acquire_writer(root, os_adapters()) as lease:
        lease.raise_trust_hwm(5)
        lease.raise_trust_hwm(3)
        assert lease.state() == LockState(writer_epoch=1, trust_generation_hwm=5)
    with acquire_writer(root, os_adapters()) as lease:
        assert lease.state() == LockState(writer_epoch=2, trust_generation_hwm=5)


def test_bump_epoch_is_persisted(trusted_tmp: Path) -> None:
    root = fresh_root(trusted_tmp)
    with acquire_writer(root, os_adapters()) as lease:
        assert lease.bump_epoch() == 2
        assert lease.epoch == 2
    with acquire_writer(root, os_adapters()) as lease:
        assert lease.epoch == 3


def test_every_write_overwrites_the_older_slot(trusted_tmp: Path) -> None:
    root = fresh_root(trusted_tmp)
    with acquire_writer(root, os_adapters()) as lease:  # seq 1 -> slot at offset 1
        lease.raise_trust_hwm(5)  # seq 2 -> offset 257
        lease.bump_epoch()  # seq 3 -> offset 1 again
    data = root.lock_path.read_bytes()
    assert data[1:257] == slot_bytes(3, 2, 5) and data[257:513] == slot_bytes(2, 1, 5)


def test_torn_slot_write_falls_back_to_other_slot(trusted_tmp: Path) -> None:
    root = fresh_root(trusted_tmp)
    with acquire_writer(root, os_adapters()):
        pass
    run_until_crash("acquire_writer", "writer.mid_slot_write", root.root)
    with acquire_writer(root, os_adapters()) as lease:
        assert lease.epoch == 2


def test_both_slots_corrupt_is_integrity_failure(trusted_tmp: Path) -> None:
    root = fresh_root(trusted_tmp)
    for _ in range(2):
        with acquire_writer(root, os_adapters()):
            pass
    corrupt_bytes(root.lock_path, offsets=[10, 266])
    with pytest.raises(BrainError) as e:
        acquire_writer(root, os_adapters())
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE


def test_corrupt_slot_beside_an_absent_slot_is_integrity_failure(trusted_tmp: Path) -> None:
    # No valid slot and not a fresh file: refusing is safer than restarting the epoch and trust high-water at 0.
    root = fresh_root(trusted_tmp)
    with acquire_writer(root, os_adapters()):
        pass
    corrupt_bytes(root.lock_path, offsets=[10])
    with pytest.raises(BrainError) as e:
        acquire_writer(root, os_adapters())
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE


def test_valid_slot_with_the_highest_seq_wins(trusted_tmp: Path) -> None:
    root = fresh_root(trusted_tmp)
    write_raw_slots(root, {SLOT_OFFSETS[0]: slot_bytes(7, 4, 9), SLOT_OFFSETS[1]: slot_bytes(6, 3, 2)})
    with acquire_writer(root, os_adapters()) as lease:
        assert lease.state() == LockState(writer_epoch=5, trust_generation_hwm=9)
    # The older slot (offset 257) was overwritten; the newer one is untouched.
    assert root.lock_path.read_bytes()[1:257] == slot_bytes(7, 4, 9)


def test_slots_with_equal_seq_and_different_content_are_integrity_failure(trusted_tmp: Path) -> None:
    root = fresh_root(trusted_tmp)
    write_raw_slots(root, {SLOT_OFFSETS[0]: slot_bytes(3, 2, 0), SLOT_OFFSETS[1]: slot_bytes(3, 1, 0)})
    with pytest.raises(BrainError) as e:
        acquire_writer(root, os_adapters())
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE


@pytest.mark.parametrize(
    "body",
    [
        {"seq": 1, "writer_epoch": "1", "trust_generation_hwm": 0},
        {"seq": 1, "writer_epoch": -1, "trust_generation_hwm": 0},
        {"seq": 1, "writer_epoch": 1, "trust_generation_hwm": True},
        {"seq": 1, "writer_epoch": 1},
        {"seq": 1, "writer_epoch": 1, "trust_generation_hwm": 0, "extra": 1},
    ],
)
def test_slot_with_valid_crc_but_bad_fields_is_not_trusted(trusted_tmp: Path, body: dict[str, object]) -> None:
    root = fresh_root(trusted_tmp)
    raw = json.dumps(body).encode().ljust(252, b" ")
    write_raw_slots(root, {SLOT_OFFSETS[0]: raw + zlib.crc32(raw).to_bytes(4, "big")})
    with pytest.raises(BrainError) as e:
        acquire_writer(root, os_adapters())
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE


def test_lock_file_is_never_deleted(trusted_tmp: Path) -> None:
    root = fresh_root(trusted_tmp)
    with acquire_writer(root, os_adapters()):
        pass
    assert root.lock_path.is_file()


def test_handle_registry(trusted_tmp: Path) -> None:
    root = fresh_root(trusted_tmp)
    with acquire_writer(root, os_adapters()) as lease:
        lease.register_handle("store")
        lease.register_handle("policy")
        with pytest.raises(AssertionError):
            lease.register_handle("store")
        assert lease.open_handles() == frozenset({"store", "policy"})
        lease.unregister_handle("store")
        assert lease.open_handles() == frozenset({"policy"})
        with pytest.raises(AssertionError):
            lease.unregister_handle("store")
        lease.unregister_handle("policy")  # the lease is released on exit, which needs every handle closed


def test_released_lease_refuses_further_writes(trusted_tmp: Path) -> None:
    root = fresh_root(trusted_tmp)
    with acquire_writer(root, os_adapters()) as lease:
        pass
    with pytest.raises(AssertionError):
        lease.raise_trust_hwm(1)
    with pytest.raises(AssertionError):
        lease.bump_epoch()


def test_mid_slot_write_pauses_once_per_write(trusted_tmp: Path) -> None:
    root = fresh_root(trusted_tmp)
    # stdin is /dev/null, so each pause returns at once; acquire_writer writes exactly one slot.
    result = run_child("acquire_writer", root.root, env={"SUPERBRAIN_PAUSEPOINT": "writer.mid_slot_write"})
    assert result.returncode == 0
    assert result.stderr.count("PAUSED writer.mid_slot_write") == 1


def test_release_with_open_handles_is_refused_and_keeps_the_lock(trusted_tmp: Path) -> None:
    root = fresh_root(trusted_tmp)
    with acquire_writer(root, os_adapters()) as lease:
        lease.register_handle("store")
        with pytest.raises(AssertionError, match="open handles"):
            lease.release()
        assert lease.held and run_child("acquire_writer", root.root).error_code == "writer_held"
        lease.unregister_handle("store")
    assert not lease.held and run_child("acquire_writer", root.root).error_code is None
