import errno
import os
import sys
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import NoReturn

import pytest

from superbrain.adapters.os import durable
from superbrain.adapters.os.durable import (
    DarwinPublisher,
    PosixPublisher,
    WindowsPublisher,
    detect_fs,
    publisher_for,
)
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.os import DurabilityTier, DurablePublisher, FsInfo
from tests.support.platform import posix_only, windows_only

if sys.platform == "win32":
    KNOWN_GOOD_FS = FsInfo("NTFS", False)
elif sys.platform == "darwin":
    KNOWN_GOOD_FS = FsInfo("apfs", False)
else:
    KNOWN_GOOD_FS = FsInfo("ext4", False)


def publisher_with(fs: FsInfo) -> DurablePublisher:
    return publisher_for(sys.platform, fs_info=lambda _path: fs)


@pytest.fixture
def publisher() -> DurablePublisher:
    return publisher_for(sys.platform)


def raising(err: Exception) -> Callable[..., NoReturn]:
    def fn(*_args: object, **_kwargs: object) -> NoReturn:
        raise err

    return fn


def staged(directory: Path, data: bytes = b"payload") -> Path:
    path = directory / f"staged-{uuid.uuid4().hex}"
    path.write_bytes(data)
    return path


def test_publisher_for_selects_by_platform() -> None:
    assert isinstance(publisher_for("win32"), WindowsPublisher)
    assert isinstance(publisher_for("darwin"), DarwinPublisher)
    assert isinstance(publisher_for("linux"), PosixPublisher)
    assert type(publisher_for("freebsd13")) is PosixPublisher


def test_write_new_writes_bytes(tmp_path: Path, publisher: DurablePublisher) -> None:
    publisher.write_new(tmp_path / "a", b"hello")
    assert (tmp_path / "a").read_bytes() == b"hello"


def test_publish_moves_bytes_and_leaves_no_staging(tmp_path: Path, publisher: DurablePublisher) -> None:
    source = staged(tmp_path)
    publisher.publish(source, tmp_path / "final")
    assert (tmp_path / "final").read_bytes() == b"payload"
    assert not source.exists()


def test_publish_replaces_existing_final(tmp_path: Path, publisher: DurablePublisher) -> None:
    (tmp_path / "final").write_bytes(b"old")
    publisher.publish(staged(tmp_path, b"new"), tmp_path / "final")
    assert (tmp_path / "final").read_bytes() == b"new"


def test_write_new_refuses_existing_file(tmp_path: Path, publisher: DurablePublisher) -> None:
    (tmp_path / "x").write_bytes(b"keep")
    with pytest.raises(FileExistsError):
        publisher.write_new(tmp_path / "x", b"data")
    assert (tmp_path / "x").read_bytes() == b"keep"


def test_rename_dir_moves_directory(tmp_path: Path, publisher: DurablePublisher) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "f").write_bytes(b"1")
    publisher.rename_dir(tmp_path / "src", tmp_path / "dst")
    assert (tmp_path / "dst" / "f").read_bytes() == b"1"
    assert not (tmp_path / "src").exists()


def test_rename_dir_refuses_existing_target(tmp_path: Path, publisher: DurablePublisher) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "dst").mkdir()
    with pytest.raises(FileExistsError):
        publisher.rename_dir(tmp_path / "src", tmp_path / "dst")
    assert (tmp_path / "src").is_dir()


@pytest.mark.parametrize("code", [errno.ENOSPC, errno.EDQUOT])
def test_disk_full_maps_to_storage_full(
    tmp_path: Path, publisher: DurablePublisher, monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    monkeypatch.setattr(os, "write", raising(OSError(code, "full")))
    with pytest.raises(BrainError) as e:
        publisher.write_new(tmp_path / "x", b"data")
    assert e.value.code == ErrorCode.STORAGE_FULL
    assert isinstance(e.value.__cause__, OSError)
    assert not (tmp_path / "x").exists()


def test_write_new_loops_over_short_writes(
    tmp_path: Path, publisher: DurablePublisher, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_write = os.write

    def short_write(fd: int, data: bytes | memoryview) -> int:
        return real_write(fd, bytes(data[:2]))

    monkeypatch.setattr(os, "write", short_write)
    publisher.write_new(tmp_path / "x", b"abcdefg")
    assert (tmp_path / "x").read_bytes() == b"abcdefg"


@pytest.mark.parametrize(
    ("info", "reason"),
    [
        (FsInfo("tmpfs", False), "volatile filesystem tmpfs"),
        (FsInfo("ramfs", False), "volatile filesystem ramfs"),
        (FsInfo("weirdfs", False), "unknown filesystem weirdfs"),
        (FsInfo("ext4", True), "remote filesystem"),
        (FsInfo("unknown", False), "unknown filesystem unknown"),
    ],
)
def test_non_allowlisted_filesystems_are_process_crash(tmp_path: Path, info: FsInfo, reason: str) -> None:
    report = publisher_with(info).durability(tmp_path, {})
    assert report.tier == DurabilityTier.PROCESS_CRASH
    assert reason in report.reasons
    assert list(tmp_path.iterdir()) == []  # the probe is not run against a disqualified filesystem


def test_onedrive_folder_is_process_crash(tmp_path: Path) -> None:
    (tmp_path / "d").mkdir()
    for key in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial"):
        report = publisher_with(KNOWN_GOOD_FS).durability(tmp_path / "d", {key: str(tmp_path)})
        assert report.tier == DurabilityTier.PROCESS_CRASH
        assert "cloud-synced folder (OneDrive)" in report.reasons


def test_missing_directory_is_process_crash_and_not_created(tmp_path: Path) -> None:
    report = publisher_with(KNOWN_GOOD_FS).durability(tmp_path / "nope", {})
    assert report.tier == DurabilityTier.PROCESS_CRASH
    assert "directory does not exist" in report.reasons
    assert not (tmp_path / "nope").exists()


def test_failed_probe_is_process_crash(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(durable, "full_fsync", raising(OSError(errno.EINVAL, "no")))
    report = publisher_with(KNOWN_GOOD_FS).durability(tmp_path, {})
    assert report.tier == DurabilityTier.PROCESS_CRASH
    assert any(r.startswith("sync probe failed: ") for r in report.reasons)
    assert list(tmp_path.iterdir()) == []


def test_known_filesystem_with_passing_probe_is_power_loss(tmp_path: Path) -> None:
    report = publisher_with(KNOWN_GOOD_FS).durability(tmp_path, {})
    assert report.tier == DurabilityTier.POWER_LOSS
    assert report.reasons == ()
    assert list(tmp_path.iterdir()) == []


def test_detect_fs_reports_this_machine(tmp_path: Path) -> None:
    info = detect_fs(tmp_path)
    assert info.fs_type != ""


def test_platform_detector_reports_a_real_filesystem(tmp_path: Path) -> None:
    # Calls the private detector directly: unlike detect_fs it cannot hide a broken implementation.
    if sys.platform == "win32":
        info = durable._detect_windows(tmp_path)
        assert info.fs_type in {"NTFS", "ReFS"}
    elif sys.platform == "darwin":
        info = durable._detect_darwin(tmp_path)
        assert info.fs_type in {"apfs", "hfs"}
    else:
        info = durable._detect_linux(tmp_path)
        assert info.fs_type not in {"", "unknown"}  # CI may use overlay or another local fs
    assert info.remote is False


def test_detect_fs_never_raises_for_missing_path(tmp_path: Path) -> None:
    assert detect_fs(tmp_path / "a" / "b").fs_type != ""


def assert_io_error(err: pytest.ExceptionInfo[BrainError]) -> None:
    assert err.value.code == ErrorCode.IO_ERROR
    assert isinstance(err.value.__cause__, OSError)


def test_write_new_io_error_is_brain_error(
    tmp_path: Path, publisher: DurablePublisher, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(durable, "full_fsync", raising(OSError(errno.EIO, "io")))
    with pytest.raises(BrainError) as e:
        publisher.write_new(tmp_path / "x", b"data")
    assert_io_error(e)
    assert not (tmp_path / "x").exists()


def test_write_new_open_failure_is_brain_error(tmp_path: Path, publisher: DurablePublisher) -> None:
    with pytest.raises(BrainError) as e:
        publisher.write_new(tmp_path / "missing" / "x", b"data")
    assert_io_error(e)


def test_publish_io_error_is_brain_error(
    tmp_path: Path, publisher: DurablePublisher, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(os, "replace", raising(OSError(errno.EIO, "io")))
    monkeypatch.setattr(durable, "_move_file_ex", raising(OSError(errno.EIO, "io")))
    with pytest.raises(BrainError) as e:
        publisher.publish(staged(tmp_path), tmp_path / "f")
    assert_io_error(e)


def test_rename_dir_io_error_is_brain_error(
    tmp_path: Path, publisher: DurablePublisher, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "s").mkdir()
    monkeypatch.setattr(os, "rename", raising(OSError(errno.EIO, "io")))
    monkeypatch.setattr(durable, "_move_file_ex", raising(OSError(errno.EIO, "io")))
    with pytest.raises(BrainError) as e:
        publisher.rename_dir(tmp_path / "s", tmp_path / "d")
    assert_io_error(e)


@posix_only
def test_sync_directory_io_error_is_brain_error(
    tmp_path: Path, publisher: DurablePublisher, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(durable, "full_fsync", raising(OSError(errno.EIO, "io")))
    with pytest.raises(BrainError) as e:
        publisher.sync_directory(tmp_path)
    assert_io_error(e)


def test_sync_directory_missing_directory_is_brain_error_on_posix(tmp_path: Path) -> None:
    if sys.platform == "win32":
        pytest.skip("Windows has no separate directory sync")
    with pytest.raises(BrainError) as e:
        publisher_for(sys.platform).sync_directory(tmp_path / "nope")
    assert_io_error(e)


def test_probe_io_error_reports_errno_without_raising(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(durable, "full_fsync", raising(OSError(errno.EIO, "io")))
    report = publisher_with(KNOWN_GOOD_FS).durability(tmp_path, {})
    assert "sync probe failed: EIO" in report.reasons


MOUNTINFO = b"""\
24 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
30 24 0:25 / /run rw - tmpfs tmpfs rw
31 24 0:26 / /mnt/with\\040space rw - xfs /dev/sdb1 rw
32 24 0:27 / /mnt/net rw - nfs4 server:/x rw
33 24 0:28 / /mnt/fuse rw shared:2 - fuse.sshfs u@h:/ rw
"""


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/home/me", FsInfo("ext4", False)),
        ("/run/user/1000", FsInfo("tmpfs", False)),
        ("/mnt/with space/x", FsInfo("xfs", False)),
        ("/mnt/net/x", FsInfo("nfs4", True)),
        ("/mnt/fuse", FsInfo("fuse.sshfs", True)),
        ("/mnt/network", FsInfo("ext4", False)),  # "/mnt/net" is not a path prefix of "/mnt/network"
    ],
)
def test_parse_mountinfo(path: str, expected: FsInfo) -> None:
    assert durable._fs_from_mountinfo(MOUNTINFO, path.encode()) == expected


class FlakyMoveFileEx:
    def __init__(self, *, failures: int, winerror: int) -> None:
        self.failures = failures
        self.winerror = winerror
        self.calls = 0

    def __call__(self, src: str, dst: str, flags: int) -> None:
        self.calls += 1
        if self.calls <= self.failures:
            raise OSError(0, "simulated", None, self.winerror)
        os.replace(src, dst)


@windows_only
def test_transient_sharing_violation_is_retried(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FlakyMoveFileEx(failures=2, winerror=32)
    monkeypatch.setattr(durable, "_move_file_ex", fake)
    sleeps: list[float] = []
    WindowsPublisher(sleep=sleeps.append).publish(staged(tmp_path), tmp_path / "f")
    assert fake.calls == 3
    assert sleeps == [0.05, 0.1]


@windows_only
def test_persistent_sharing_violation_is_filesystem_busy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FlakyMoveFileEx(failures=99, winerror=32)
    monkeypatch.setattr(durable, "_move_file_ex", fake)
    sleeps: list[float] = []
    with pytest.raises(BrainError) as e:
        WindowsPublisher(sleep=sleeps.append).publish(staged(tmp_path), tmp_path / "f")
    assert e.value.code == ErrorCode.FILESYSTEM_BUSY
    assert fake.calls == 6
    assert sleeps == [0.05, 0.1, 0.2, 0.4, 0.8]


@windows_only
def test_windows_disk_full_maps_to_storage_full(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(durable, "_move_file_ex", FlakyMoveFileEx(failures=99, winerror=112))
    with pytest.raises(BrainError) as e:
        WindowsPublisher(sleep=lambda s: None).publish(staged(tmp_path), tmp_path / "f")
    assert e.value.code == ErrorCode.STORAGE_FULL


@windows_only
def test_windows_unrelated_move_error_is_io_error_and_not_retried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FlakyMoveFileEx(failures=99, winerror=2)
    monkeypatch.setattr(durable, "_move_file_ex", fake)
    with pytest.raises(BrainError) as e:
        WindowsPublisher(sleep=lambda s: None).publish(staged(tmp_path), tmp_path / "f")
    assert e.value.code == ErrorCode.IO_ERROR
    assert isinstance(e.value.__cause__, OSError)
    assert fake.calls == 1


@windows_only
def test_windows_rename_dir_existing_target_is_file_exists(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(durable, "_move_file_ex", FlakyMoveFileEx(failures=99, winerror=183))
    with pytest.raises(FileExistsError):
        WindowsPublisher().rename_dir(tmp_path / "a", tmp_path / "b")


@windows_only
def test_windows_flags_use_write_through(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[int] = []
    real = durable._move_file_ex

    def spy(src: str, dst: str, flags: int) -> None:
        seen.append(flags)
        real(src, dst, flags)

    monkeypatch.setattr(durable, "_move_file_ex", spy)
    (tmp_path / "d1").mkdir()
    publisher = WindowsPublisher()
    publisher.publish(staged(tmp_path), tmp_path / "f")
    publisher.rename_dir(tmp_path / "d1", tmp_path / "d2")
    assert seen == [0x1 | 0x8, 0x8]


def test_non_utf8_mount_point_is_matched_as_bytes() -> None:
    data = b"1 0 8:1 / / rw - ext4 /dev/sda1 rw\n2 1 0:5 / /mnt/\xff rw - tmpfs tmpfs rw\n"
    assert durable._fs_from_mountinfo(data, b"/mnt/\xff/data") == FsInfo("tmpfs", False)
    assert durable._fs_from_mountinfo(data, b"/mnt/other") == FsInfo("ext4", False)


def test_durability_never_raises_when_directory_cannot_be_inspected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Path, "is_dir", raising(PermissionError(errno.EACCES, "denied")))
    report = publisher_with(KNOWN_GOOD_FS).durability(tmp_path, {})
    assert report.tier == DurabilityTier.PROCESS_CRASH
    assert "cannot inspect directory: PermissionError" in report.reasons


def test_durability_never_raises_on_symlink_loop_in_onedrive_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_resolve = Path.resolve

    def resolve(self: Path, strict: bool = False) -> Path:
        if self.name == "loop":
            raise RuntimeError("Symlink loop")
        return real_resolve(self, strict)

    monkeypatch.setattr(Path, "resolve", resolve)
    report = publisher_with(KNOWN_GOOD_FS).durability(tmp_path, {"OneDrive": str(tmp_path / "loop")})
    assert report.tier == DurabilityTier.PROCESS_CRASH
    assert "cannot inspect OneDrive path: RuntimeError" in report.reasons


def test_durability_never_raises_when_directory_resolve_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Path, "resolve", raising(RuntimeError("Symlink loop")))
    report = publisher_with(KNOWN_GOOD_FS).durability(tmp_path, {"OneDrive": str(tmp_path)})
    assert report.tier == DurabilityTier.PROCESS_CRASH
    assert "cannot inspect directory: RuntimeError" in report.reasons


# --- full fsync, directory fsync and flush_file ------------------------------------------------------------------


class FakeFcntl:
    """Stands in for macOS ``fcntl``: ``fcntl(fd, F_FULLFSYNC)`` fails with ``err``, if given."""

    F_FULLFSYNC = 51

    def __init__(self, err: OSError | None) -> None:
        self.err = err
        self.calls: list[int] = []

    def fcntl(self, fd: int, command: int) -> int:
        self.calls.append(command)
        if self.err is not None:
            raise self.err
        return 0


def file_fd(tmp_path: Path) -> int:
    path = tmp_path / f"f-{uuid.uuid4().hex}"
    path.write_bytes(b"payload")
    return os.open(path, os.O_RDWR | getattr(os, "O_BINARY", 0))


def spy_fsync(monkeypatch: pytest.MonkeyPatch, err: OSError | None = None) -> list[int]:
    calls: list[int] = []

    def fsync(fd: int) -> None:
        calls.append(fd)
        if err is not None:
            raise err

    monkeypatch.setattr(os, "fsync", fsync)
    return calls


def test_darwin_full_fsync_uses_f_fullfsync(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeFcntl(None)
    monkeypatch.setitem(sys.modules, "fcntl", fake)
    fd = file_fd(tmp_path)
    try:
        synced = spy_fsync(monkeypatch)
        assert durable.full_fsync(fd, platform="darwin") is True
    finally:
        os.close(fd)
    assert fake.calls == [FakeFcntl.F_FULLFSYNC] and synced == []


@pytest.mark.parametrize("code", [errno.ENOTSUP, errno.EINVAL, errno.ENOTTY])
def test_darwin_full_fsync_falls_back_to_fsync_where_unsupported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    fake = FakeFcntl(OSError(code, "unsupported"))
    monkeypatch.setitem(sys.modules, "fcntl", fake)
    fd = file_fd(tmp_path)
    try:
        synced = spy_fsync(monkeypatch)
        assert durable.full_fsync(fd, platform="darwin") is False  # degraded, not failed
    finally:
        os.close(fd)
    assert fake.calls == [FakeFcntl.F_FULLFSYNC] and synced == [fd]


@pytest.mark.parametrize("code", [errno.EIO, errno.ENOSPC])
def test_darwin_full_fsync_failure_still_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: int) -> None:
    monkeypatch.setitem(sys.modules, "fcntl", FakeFcntl(OSError(code, "injected")))
    fd = file_fd(tmp_path)
    try:
        synced = spy_fsync(monkeypatch)
        with pytest.raises(OSError) as e:
            durable.full_fsync(fd, platform="darwin")
    finally:
        os.close(fd)
    assert e.value.errno == code and synced == []


def test_full_fsync_elsewhere_is_fsync(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fd = file_fd(tmp_path)
    try:
        synced = spy_fsync(monkeypatch)
        assert durable.full_fsync(fd, platform="linux") is True
        spy_fsync(monkeypatch, OSError(errno.EIO, "injected"))
        with pytest.raises(OSError):
            durable.full_fsync(fd, platform="linux")
    finally:
        os.close(fd)
    assert synced == [fd]


def directory_fd_from_a_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Make ``os.open`` return a regular file's descriptor (Windows cannot open a directory with it)."""
    opened: list[int] = []
    real_open = os.open
    target = tmp_path / "stand-in"
    target.write_bytes(b"")

    def open_(path: object, flags: int, *args: object) -> int:
        fd = real_open(target, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        opened.append(fd)
        return fd

    monkeypatch.setattr(os, "open", open_)
    return opened


@pytest.mark.parametrize("code", [errno.EINVAL, errno.ENOTSUP, errno.ENOSYS, errno.EBADF])
def test_unsupported_directory_fsync_is_skipped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: int) -> None:
    opened = directory_fd_from_a_file(tmp_path, monkeypatch)
    synced = spy_fsync(monkeypatch, OSError(code, "unsupported"))
    assert durable._fsync_directory(tmp_path, nt=False) is False
    assert synced == opened and len(opened) == 1


@pytest.mark.parametrize("code", [errno.EIO, errno.ENOSPC])
def test_directory_fsync_failure_still_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: int) -> None:
    directory_fd_from_a_file(tmp_path, monkeypatch)
    spy_fsync(monkeypatch, OSError(code, "injected"))
    with pytest.raises(OSError) as e:
        durable._fsync_directory(tmp_path, nt=False)
    assert e.value.errno == code


def test_sync_directory_continues_past_an_unsupported_directory_fsync(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(durable, "_fsync_directory", lambda path: False)
    PosixPublisher().sync_directory(tmp_path)


def test_probe_reports_an_unsupported_directory_fsync(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(durable, "_fsync_directory", lambda path: False)
    report = PosixPublisher(fs_info=lambda _p: FsInfo("ext4", False)).durability(tmp_path, {})
    assert report.tier == DurabilityTier.PROCESS_CRASH
    assert any("directory" in r for r in report.reasons) and list(tmp_path.iterdir()) == []


def test_probe_reports_a_degraded_full_fsync(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(durable, "full_fsync", lambda fd: False)
    report = DarwinPublisher(fs_info=lambda _p: FsInfo("apfs", False)).durability(tmp_path, {})
    assert report.tier == DurabilityTier.PROCESS_CRASH
    assert any("F_FULLFSYNC" in r for r in report.reasons) and list(tmp_path.iterdir()) == []


def test_flush_file_full_fsyncs_the_whole_file(
    tmp_path: Path, publisher: DurablePublisher, monkeypatch: pytest.MonkeyPatch
) -> None:
    flushed: list[int] = []
    real = durable.full_fsync

    def spy(fd: int) -> bool:
        flushed.append(os.fstat(fd).st_size)
        return real(fd)

    monkeypatch.setattr(durable, "full_fsync", spy)
    publisher.flush_file(staged(tmp_path, b"seven b"))
    assert flushed == [7]


@pytest.mark.parametrize(
    ("code", "expected"), [(errno.EIO, ErrorCode.IO_ERROR), (errno.ENOSPC, ErrorCode.STORAGE_FULL)]
)
def test_flush_file_failure_is_brain_error(
    tmp_path: Path, publisher: DurablePublisher, monkeypatch: pytest.MonkeyPatch, code: int, expected: ErrorCode
) -> None:
    monkeypatch.setattr(durable, "full_fsync", raising(OSError(code, "injected")))
    with pytest.raises(BrainError) as e:
        publisher.flush_file(staged(tmp_path))
    assert e.value.code == expected and isinstance(e.value.__cause__, OSError)


def test_flush_file_of_a_missing_file_is_io_error(tmp_path: Path, publisher: DurablePublisher) -> None:
    with pytest.raises(BrainError) as e:
        publisher.flush_file(tmp_path / "missing")
    assert_io_error(e)
