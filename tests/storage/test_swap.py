"""Directory swaps (spec 5.5, 5.7): staging, the two renames, and recovery of an interrupted swap under the lease."""

import hashlib
import os
import re
from collections import Counter
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import NoReturn

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.os import OsAdapters
from superbrain.storage.layout import DataRoot, prepare_data_root
from superbrain.storage.runtime import open_runtime
from superbrain.storage.swap import READY, recover_interrupted_swaps, stage_and_swap
from superbrain.storage.writer import WriterLease, acquire_writer
from tests.storage.conftest import CLOCK_START, maintenance_lease
from tests.support.clock import FakeClock
from tests.support.fs import digest_data_root, digest_tree, file_identity

UUID = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
STAMP = "20261030T120000Z"


def fake_clock_os() -> OsAdapters:
    return os_adapters(clock=FakeClock(CLOCK_START))


def raising(err: BaseException) -> Callable[..., NoReturn]:
    def fn(*_args: object, **_kwargs: object) -> NoReturn:
        raise err

    return fn


def write_file(directory: Path, name: str, data: bytes) -> None:
    directory.mkdir(exist_ok=True)
    (directory / name).write_bytes(data)


def builder(data: bytes) -> Callable[[Path], None]:
    def build(stage: Path) -> None:
        (stage / "data").write_bytes(data)

    return build


def siblings(root: DataRoot, prefix: str) -> list[str]:
    return sorted(name for name in os.listdir(root.root) if name.startswith(prefix))


def file_contents(path: Path) -> Counter[str]:
    """Every file's content digest under ``path``, as a multiset: renames keep it, deleting anything changes it."""
    found: Counter[str] = Counter()
    for directory, _dirs, files in os.walk(path):
        for name in files:
            if name != "writer.lock":
                found[hashlib.sha256((Path(directory) / name).read_bytes()).hexdigest()] += 1
    return found


@pytest.fixture
def held(trusted_tmp: Path) -> Iterator[tuple[DataRoot, WriterLease]]:
    """A maintenance lease on a data root whose ``store/`` and ``policy/`` each hold ``data = b"old <target>"``."""
    with maintenance_lease(trusted_tmp / "r") as (root, lease):
        write_file(root.store_dir, "data", b"old store")
        write_file(root.policy_dir, "data", b"old policy")
        yield root, lease


# --- stage_and_swap ----------------------------------------------------------------------------------------------


@pytest.mark.parametrize("target", ["store", "policy"])
@pytest.mark.parametrize("purpose", ["restoring", "migrating"])
def test_swap_publishes_the_stage_and_keeps_the_original(
    held: tuple[DataRoot, WriterLease], target: str, purpose: str
) -> None:
    root, lease = held
    live = root.root / target
    epoch, lock = lease.epoch, file_identity(root.lock_path)
    replaced = stage_and_swap(
        root, lease, os_adapters(), target=target, purpose=purpose, build=builder(b"new"), now=CLOCK_START  # type: ignore[arg-type]
    )
    assert re.fullmatch(rf"{target}\.replaced-{STAMP}-{UUID}", replaced.name) and replaced.parent == root.root
    assert (replaced / "data").read_bytes() == f"old {target}".encode()
    assert (live / "data").read_bytes() == b"new" and (live / READY).is_file()
    assert siblings(root, f"{target}.") == [replaced.name]
    assert lease.epoch == epoch + 1 and lease.state().writer_epoch == epoch + 1
    assert file_identity(root.lock_path) == lock


def test_swap_with_the_target_open_is_refused_before_staging(held: tuple[DataRoot, WriterLease]) -> None:
    root, lease = held
    lease.register_handle("store")
    before = digest_tree(root.store_dir)
    with pytest.raises(BrainError) as e:
        stage_and_swap(
            root, lease, os_adapters(), target="store", purpose="restoring", build=builder(b"new"), now=CLOCK_START
        )
    lease.unregister_handle("store")
    assert e.value.code == ErrorCode.STORE_BUSY
    assert siblings(root, "store.") == [] and digest_tree(root.store_dir) == before


def test_existing_stage_is_an_integrity_failure(held: tuple[DataRoot, WriterLease]) -> None:
    root, lease = held
    write_file(root.root / "store.restoring", "data", b"left over")
    with pytest.raises(BrainError) as e:
        stage_and_swap(
            root, lease, os_adapters(), target="store", purpose="restoring", build=builder(b"new"), now=CLOCK_START
        )
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE
    assert (root.root / "store.restoring" / "data").read_bytes() == b"left over"
    assert (root.store_dir / "data").read_bytes() == b"old store" and siblings(root, "store.") == ["store.restoring"]


def test_missing_target_is_refused_before_staging(held: tuple[DataRoot, WriterLease]) -> None:
    root, lease = held
    os.rename(root.policy_dir, root.root / "elsewhere")
    with pytest.raises(BrainError) as e:
        stage_and_swap(
            root, lease, os_adapters(), target="policy", purpose="restoring", build=builder(b"new"), now=CLOCK_START
        )
    assert e.value.code == ErrorCode.NOT_FOUND and siblings(root, "policy") == []


@pytest.mark.parametrize(
    "bad",
    [
        {"target": "outbox"},
        {"purpose": "copying"},
        {"now": CLOCK_START.replace(tzinfo=None)},
    ],
)
def test_bad_arguments_are_invalid_input(held: tuple[DataRoot, WriterLease], bad: dict[str, object]) -> None:
    root, lease = held
    args: dict[str, object] = {"target": "store", "purpose": "restoring", "build": builder(b"new"), "now": CLOCK_START}
    with pytest.raises(BrainError) as e:
        stage_and_swap(root, lease, os_adapters(), **{**args, **bad})  # type: ignore[arg-type]
    assert e.value.code == ErrorCode.INVALID_INPUT and siblings(root, "store.") == []


def test_swap_needs_the_lease_of_this_root(held: tuple[DataRoot, WriterLease], trusted_tmp: Path) -> None:
    root, _lease = held
    with maintenance_lease(trusted_tmp / "other") as (_other, other_lease), pytest.raises(AssertionError):
        stage_and_swap(
            root, other_lease, os_adapters(), target="store", purpose="restoring", build=builder(b"x"), now=CLOCK_START
        )


def test_failed_build_is_set_aside_and_its_error_propagates(held: tuple[DataRoot, WriterLease]) -> None:
    root, lease = held
    epoch = lease.epoch

    def build(stage: Path) -> None:
        (stage / "half").write_bytes(b"half built")
        raise BrainError(ErrorCode.STORAGE_FULL, "injected")

    with pytest.raises(BrainError) as e:
        stage_and_swap(root, lease, os_adapters(), target="store", purpose="restoring", build=build, now=CLOCK_START)
    assert e.value.code == ErrorCode.STORAGE_FULL and e.value.message == "injected"
    (aside,) = siblings(root, "store.")
    assert re.fullmatch(rf"store\.restoring\.abandoned-{STAMP}-{UUID}", aside)
    assert (root.root / aside / "half").read_bytes() == b"half built" and not (root.root / aside / READY).exists()
    assert (root.store_dir / "data").read_bytes() == b"old store" and lease.epoch == epoch


def test_failure_to_set_a_failed_stage_aside_is_noted_on_the_original_error(
    held: tuple[DataRoot, WriterLease], monkeypatch: pytest.MonkeyPatch
) -> None:
    root, lease = held
    os_ = os_adapters()
    monkeypatch.setattr(os_.publisher, "rename_dir", raising(BrainError(ErrorCode.FILESYSTEM_BUSY, "locked")))
    with pytest.raises(ValueError, match="bad") as e:
        stage_and_swap(
            root, lease, os_, target="store", purpose="restoring", build=raising(ValueError("bad")), now=CLOCK_START
        )
    assert any("could not be set aside" in note and "locked" in note for note in e.value.__notes__)
    assert siblings(root, "store.") == ["store.restoring"]  # left for recovery, which sets it aside
    assert (root.store_dir / "data").read_bytes() == b"old store"


# --- recover_interrupted_swaps -----------------------------------------------------------------------------------


def make_stage(root: DataRoot, name: str, data: bytes, *, ready: bool) -> Path:
    stage = root.root / name
    write_file(stage, "data", data)
    if ready:
        (stage / READY).write_bytes(b"")
    return stage


def test_recovery_on_a_fresh_root_does_nothing(trusted_tmp: Path) -> None:
    os_ = os_adapters()
    root = prepare_data_root(trusted_tmp / "r", os_)
    with acquire_writer(root, os_) as lease:
        assert recover_interrupted_swaps(root, lease, os_) == []
    assert os.listdir(root.root) == ["writer.lock"]


def test_recovery_with_nothing_interrupted_does_nothing(held: tuple[DataRoot, WriterLease]) -> None:
    root, lease = held
    before = digest_tree(root.root / "store")
    assert recover_interrupted_swaps(root, lease, fake_clock_os()) == []
    assert digest_tree(root.root / "store") == before and siblings(root, "store.") == []


@pytest.mark.parametrize("target", ["store", "policy"])
@pytest.mark.parametrize("purpose", ["restoring", "migrating"])
def test_recovery_completes_a_ready_stage_whose_target_was_moved_aside(
    held: tuple[DataRoot, WriterLease], target: str, purpose: str
) -> None:
    root, lease = held
    live = root.root / target
    os.rename(live, root.root / f"{target}.replaced-{STAMP}-x")
    make_stage(root, f"{target}.{purpose}", b"new", ready=True)
    before = file_contents(root.root)
    actions = recover_interrupted_swaps(root, lease, fake_clock_os())
    assert len(actions) == 1 and f"{target}.{purpose}" in actions[0]
    assert (live / "data").read_bytes() == b"new" and (live / READY).is_file()
    assert siblings(root, f"{target}.") == [f"{target}.replaced-{STAMP}-x"]
    assert file_contents(root.root) == before  # nothing deleted


@pytest.mark.parametrize("target", ["store", "policy"])
@pytest.mark.parametrize("purpose", ["restoring", "migrating"])
@pytest.mark.parametrize("ready", [True, False])
def test_recovery_sets_aside_a_stage_next_to_an_intact_target(
    held: tuple[DataRoot, WriterLease], target: str, purpose: str, ready: bool
) -> None:
    root, lease = held
    make_stage(root, f"{target}.{purpose}", b"new", ready=ready)
    before = file_contents(root.root)
    actions = recover_interrupted_swaps(root, lease, fake_clock_os())
    (aside,) = siblings(root, f"{target}.")
    assert len(actions) == 1 and aside in actions[0]
    assert re.fullmatch(rf"{target}\.{purpose}\.abandoned-{STAMP}-{UUID}", aside)
    assert (root.root / aside / "data").read_bytes() == b"new"
    assert (root.root / target / "data").read_bytes() == f"old {target}".encode()
    assert file_contents(root.root) == before


def test_recovery_handles_each_target(held: tuple[DataRoot, WriterLease]) -> None:
    root, lease = held
    make_stage(root, "store.migrating", b"new store", ready=False)
    os.rename(root.policy_dir, root.root / f"policy.replaced-{STAMP}-x")
    make_stage(root, "policy.restoring", b"new policy", ready=True)
    assert len(recover_interrupted_swaps(root, lease, fake_clock_os())) == 2
    assert (root.store_dir / "data").read_bytes() == b"old store"
    assert (root.policy_dir / "data").read_bytes() == b"new policy"


@pytest.mark.parametrize("target_present", [True, False])
def test_both_stages_for_one_target_is_an_integrity_failure_that_touches_nothing(
    held: tuple[DataRoot, WriterLease], target_present: bool
) -> None:
    root, lease = held
    make_stage(root, "policy.restoring", b"other target", ready=False)  # would be set aside, but must not be
    if not target_present:
        os.rename(root.store_dir, root.root / f"store.replaced-{STAMP}-x")
    make_stage(root, "store.restoring", b"a", ready=True)
    make_stage(root, "store.migrating", b"b", ready=True)
    before = digest_data_root(root.root.parent)
    with pytest.raises(BrainError) as e:
        recover_interrupted_swaps(root, lease, fake_clock_os())
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE
    assert digest_data_root(root.root.parent) == before


def test_missing_target_with_an_unready_stage_is_an_integrity_failure(held: tuple[DataRoot, WriterLease]) -> None:
    root, lease = held
    os.rename(root.store_dir, root.root / f"store.replaced-{STAMP}-x")
    make_stage(root, "store.restoring", b"new", ready=False)
    before = digest_data_root(root.root.parent)
    with pytest.raises(BrainError) as e:
        recover_interrupted_swaps(root, lease, fake_clock_os())
    assert e.value.code == ErrorCode.INTEGRITY_FAILURE and "store.restoring" in e.value.message
    assert digest_data_root(root.root.parent) == before


def test_recover_requires_matching_lease(trusted_tmp: Path) -> None:
    root = prepare_data_root(trusted_tmp / "r", os_adapters())
    with maintenance_lease(trusted_tmp / "other") as (_other, lease), pytest.raises(AssertionError):
        recover_interrupted_swaps(root, lease, fake_clock_os())


# --- start-up runs recovery under the lease ----------------------------------------------------------------------


def test_open_runtime_completes_an_interrupted_swap_before_opening(trusted_tmp: Path) -> None:
    open_runtime(trusted_tmp / "r", os_adapters()).close()
    with maintenance_lease(trusted_tmp / "r") as (root, _lease):
        stage = root.root / "store.restoring"
        os.rename(root.store_dir, stage)  # a ready stage holding a complete store, the original moved aside
        (stage / READY).write_bytes(b"")
        os.mkdir(root.root / f"store.replaced-{STAMP}-x")
    rt = open_runtime(trusted_tmp / "r", os_adapters())
    try:
        assert rt.root.store_db.is_file() and (rt.root.store_dir / READY).is_file()
        assert siblings(rt.root, "store.") == [f"store.replaced-{STAMP}-x"]
    finally:
        rt.close()


def test_maintenance_lease_recovers_too(trusted_tmp: Path) -> None:
    with maintenance_lease(trusted_tmp / "r") as (root, _lease):
        make_stage(root, "store.migrating", b"new", ready=False)
    with maintenance_lease(trusted_tmp / "r") as (root, _lease):
        (aside,) = siblings(root, "store.")
        assert aside.startswith("store.migrating.abandoned-")
