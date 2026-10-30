"""OS-facing ports."""

from collections.abc import Sequence
from pathlib import Path
from typing import Protocol


class PathSafety(Protocol):
    def reject_unsafe_path(self, raw: str) -> None:
        """Raise ``BrainError(UNSAFE_PATH)`` for path spellings that bypass normal path rules."""
        ...

    def reject_links(self, path: Path, *, entries: Sequence[Path] = ()) -> None:
        """Raise ``BrainError(UNSAFE_PATH)`` if ``path``, an existing ancestor or an existing entry is a link."""
        ...
