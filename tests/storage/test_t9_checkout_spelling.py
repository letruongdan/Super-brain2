"""Task 9: one checkout directory yields one spelling under the file system's own name equivalence (APFS-like).

Seam: ``_on_disk_spelling`` is tested directly. It alone decides the spelling that becomes ``path_identity``
(``physical_checkout`` returns ``path:{resolved}`` from it unchanged), and testing it directly lets the test run on
every OS, Windows included, where ``physical_checkout`` skips it. The module's ``os`` is replaced by a fake whose
file-system calls see an in-memory directory tree; real ``os`` is never consulted for file-system state.
"""

from __future__ import annotations

import os as real_os
import stat
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from superbrain.adapters.os import workspaces

NFC_CAFE = unicodedata.normalize("NFC", "Café")  # "Caf\xe9"
NFD_CAFE = unicodedata.normalize("NFD", "Café")  # "Café"
assert NFC_CAFE != NFD_CAFE


def _fold(name: str) -> str:
    return unicodedata.normalize("NFD", unicodedata.normalize("NFD", name).casefold())


@dataclass(eq=False)
class _Node:
    """A directory (``children``) or a symlink (``target``); identity is object identity."""

    children: dict[str, _Node] = field(default_factory=dict)
    target: str | None = None
    insensitive: bool = True  # normalization- and case-insensitive lookups, like APFS
    unlistable: bool = False
    # Unlisted names the file system resolves to a specific child: lets one directory hold several listed names
    # that fold alike while the caller's spelling reaches exactly one directory.
    aliases: dict[str, _Node] = field(default_factory=dict)


class _FakeFs:
    def __init__(self, root: _Node) -> None:
        self.root = root

    def _lookup(self, path: Any, *, follow: bool, depth: int = 0) -> _Node:
        if depth > 8:
            raise OSError("too many links")
        node = self.root
        parts = Path(path).parts[1:]
        for i, name in enumerate(parts):
            if node.target is not None:
                node = self._lookup(node.target, follow=True, depth=depth + 1)
            child = node.children.get(name) or node.aliases.get(name)
            if child is None and node.insensitive:
                hits = [c for k, c in node.children.items() if _fold(k) == _fold(name)]
                child = hits[0] if len(hits) == 1 else None
            if child is None:
                raise FileNotFoundError(str(path))
            node = child
            last = i == len(parts) - 1
            if node.target is not None and (follow or not last):
                node = self._lookup(node.target, follow=True, depth=depth + 1)
        return node

    def listdir(self, path: Any) -> list[str]:
        node = self._lookup(path, follow=True)
        if node.unlistable:
            raise PermissionError(str(path))
        return list(node.children)

    def _stat(self, node: _Node) -> SimpleNamespace:
        mode = stat.S_IFLNK if node.target is not None else stat.S_IFDIR
        return SimpleNamespace(st_mode=mode | 0o700, st_ino=id(node), st_dev=1)

    def stat(self, path: Any, *, follow_symlinks: bool = True) -> SimpleNamespace:
        return self._stat(self._lookup(path, follow=follow_symlinks))

    def lstat(self, path: Any) -> SimpleNamespace:
        return self.stat(path, follow_symlinks=False)

    def scandir(self, path: Any) -> Any:
        names = self.listdir(path)
        fs = self

        class _Entry:
            def __init__(self, name: str) -> None:
                self.name = name
                self.path = str(Path(path) / name)

            def is_symlink(self) -> bool:
                return fs._lookup(self.path, follow=False).target is not None

            def is_dir(self, *, follow_symlinks: bool = True) -> bool:
                return fs._lookup(self.path, follow=follow_symlinks).target is None

            def stat(self, *, follow_symlinks: bool = True) -> SimpleNamespace:
                return fs.stat(self.path, follow_symlinks=follow_symlinks)

            def inode(self) -> int:
                return int(self.stat(follow_symlinks=False).st_ino)

        class _It:
            def __iter__(self) -> Any:
                return iter([_Entry(n) for n in names])

            def __enter__(self) -> _It:
                return self

            def __exit__(self, *exc: object) -> None:
                return None

        return _It()

    def samefile(self, a: Any, b: Any) -> bool:
        return self._lookup(a, follow=True) is self._lookup(b, follow=True)

    def islink(self, path: Any) -> bool:
        try:
            return self._lookup(path, follow=False).target is not None
        except OSError:
            return False

    def lexists(self, path: Any) -> bool:
        try:
            self._lookup(path, follow=False)
        except OSError:
            return False
        return True


def _install(monkeypatch: pytest.MonkeyPatch, fs: _FakeFs) -> list[tuple[str, str]]:
    """Point the module's ``os`` at ``fs``; returns the log of ``samefile`` calls."""
    calls: list[tuple[str, str]] = []

    def samefile(a: Any, b: Any) -> bool:
        calls.append((str(a), str(b)))
        return fs.samefile(a, b)

    fake_path = SimpleNamespace(
        samefile=samefile,
        islink=fs.islink,
        lexists=fs.lexists,
        exists=fs.lexists,
        isdir=lambda p: fs.lexists(p) and fs._lookup(p, follow=True).target is None,
        samestat=lambda a, b: (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino),
        join=real_os.path.join,
        normcase=lambda p: p,
    )

    class _FakeOs:
        path = fake_path
        listdir = staticmethod(fs.listdir)
        scandir = staticmethod(fs.scandir)
        stat = staticmethod(fs.stat)
        lstat = staticmethod(fs.lstat)

        def __getattr__(self, name: str) -> Any:  # non-file-system helpers (fspath, sep, ...)
            return getattr(real_os, name)

    monkeypatch.setattr(workspaces, "os", _FakeOs())
    return calls


def _spelling(path: str) -> str:
    return workspaces._on_disk_spelling(str(Path(path)))


def _tree(leaf_name: str, **leaf: Any) -> _Node:
    """/vol/<leaf_name>/repo where <leaf_name> is a real directory."""
    repo = _Node()
    return _Node(children={"vol": _Node(children={leaf_name: _Node(children={"repo": repo}, **leaf)})})


@pytest.mark.parametrize(
    ("on_disk", "given"),
    [
        (NFD_CAFE, NFC_CAFE),
        (NFC_CAFE, NFD_CAFE),
        (NFD_CAFE, NFC_CAFE.upper()),
        (NFD_CAFE, NFC_CAFE.lower()),
        (NFC_CAFE, NFD_CAFE.upper()),
        (NFC_CAFE, NFD_CAFE.lower()),
    ],
    ids=["nfd-disk-nfc-in", "nfc-disk-nfd-in", "nfd-disk-nfc-upper", "nfd-disk-nfc-lower", "nfc-disk-nfd-upper",
         "nfc-disk-nfd-lower"],
)
def test_equivalent_spelling_is_rewritten_to_the_listed_name(
    monkeypatch: pytest.MonkeyPatch, on_disk: str, given: str
) -> None:
    # Normalization and case variants of one directory all yield the bytes its parent lists.
    _install(monkeypatch, _FakeFs(_tree(on_disk)))
    assert _spelling(f"/vol/{given}/repo") == str(Path(f"/vol/{on_disk}/repo"))


def test_only_the_equivalent_entry_that_is_the_same_directory_is_chosen(monkeypatch: pytest.MonkeyPatch) -> None:
    # Several listed names fold to the input; only the one that is the same directory supplies the spelling.
    real = _Node(children={"repo": _Node()})
    other = _Node(children={"repo": _Node()})
    vol = _Node(children={NFC_CAFE.upper(): other, NFD_CAFE: real}, aliases={NFC_CAFE.lower(): real})
    _install(monkeypatch, _FakeFs(_Node(children={"vol": vol})))
    assert _spelling(f"/vol/{NFC_CAFE.lower()}/repo") == str(Path(f"/vol/{NFD_CAFE}/repo"))


@pytest.mark.parametrize("link_name", [NFC_CAFE.upper(), NFD_CAFE], ids=["case-variant", "nfd-variant"])
def test_a_symlink_entry_is_never_chosen(monkeypatch: pytest.MonkeyPatch, link_name: str) -> None:
    # A listed symlink that folds to the input and leads to the same directory must not supply the spelling:
    # the result would then contain a link. With no other equivalent entry, the resolved spelling is kept.
    real = _Node(children={"repo": _Node()})
    vol = _Node(children={link_name: _Node(target=str(Path("/data/real")))}, aliases={NFC_CAFE: real})
    fs = _FakeFs(_Node(children={"vol": vol, "data": _Node(children={"real": real})}))
    _install(monkeypatch, fs)
    result = _spelling(f"/vol/{NFC_CAFE}/repo")
    assert not any(fs.islink(p) for p in (Path(result), *Path(result).parents)), result
    assert result == str(Path(f"/vol/{NFC_CAFE}/repo"))


def test_exact_listed_name_is_kept_without_a_listing_based_rewrite(monkeypatch: pytest.MonkeyPatch) -> None:
    # The input is listed exactly; an equivalent sibling that is the same directory must not replace it.
    real = _Node(children={"repo": _Node()})
    vol = _Node(children={NFD_CAFE: real, NFC_CAFE: real}, insensitive=False)
    calls = _install(monkeypatch, _FakeFs(_Node(children={"vol": vol})))
    assert _spelling(f"/vol/{NFC_CAFE}/repo") == str(Path(f"/vol/{NFC_CAFE}/repo"))
    assert calls == []


def test_unlistable_ancestor_keeps_its_spelling_and_later_components_are_still_canonical(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # An ancestor that cannot be listed keeps the resolved spelling of its child; deeper listable levels still
    # yield their listed spelling.
    leaf = _Node(children={"Leaf": _Node(children={"Repo": _Node()})})
    vol = _Node(children={"Mid": leaf}, unlistable=True)
    _install(monkeypatch, _FakeFs(_Node(children={"vol": vol})))
    assert _spelling("/vol/mid/leaf/repo") == str(Path("/vol/mid/Leaf/Repo"))
