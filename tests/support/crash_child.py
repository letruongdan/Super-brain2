"""Operations run in a child interpreter by ``tests/support/crash.py``.

Started through ``runpy`` under ``python -I``: it imports only ``superbrain`` and the standard library, never
``tests``. Usage: ``crash_child.py <operation> <data_root> [args...]``. A ``BrainError`` prints ``ERROR <code>``
to stdout and exits 1; success exits 0. Later tasks add the operations their tests need to ``OPERATIONS``.
"""

import sys
from collections.abc import Callable
from pathlib import Path

import superbrain
from superbrain.adapters.os import os_adapters
from superbrain.core.errors import BrainError
from superbrain.core.faults import pausepoint
from superbrain.storage.layout import prepare_data_root
from superbrain.storage.writer import acquire_writer


def ping(data_root: Path, args: list[str]) -> None:
    print(superbrain.__file__)


def acquire_writer_once(data_root: Path, args: list[str]) -> None:
    os_ = os_adapters()
    root = prepare_data_root(data_root, os_)
    with acquire_writer(root, os_):
        pass


def acquire_writer_and_pause(data_root: Path, args: list[str]) -> None:
    os_ = os_adapters()
    root = prepare_data_root(data_root, os_)
    with acquire_writer(root, os_):
        pausepoint("writer.held")


OPERATIONS: dict[str, Callable[[Path, list[str]], None]] = {
    "ping": ping,
    "acquire_writer": acquire_writer_once,
    "acquire_writer_and_pause": acquire_writer_and_pause,
}


def main(argv: list[str]) -> int:
    # -I ignores PYTHONIOENCODING, so make the pipes UTF-8 explicitly (paths may hold non-ASCII characters).
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8")
    if len(argv) < 2 or argv[0] not in OPERATIONS:
        sys.stderr.write(f"usage: crash_child.py <{'|'.join(OPERATIONS)}> <data_root> [args...]\n")
        return 2
    operation, data_root, *args = argv
    try:
        OPERATIONS[operation](Path(data_root), args)
    except BrainError as err:
        print(f"ERROR {err.code.value}")
        return 1
    return 0


if __name__ == "__main__":
    # argv: ["-c", <this file>, <operation>, <data_root>, *args]
    sys.exit(main(sys.argv[2:]))
