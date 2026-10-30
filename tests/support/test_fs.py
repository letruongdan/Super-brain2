from pathlib import Path

from tests.support.fs import corrupt_bytes, digest_tree, file_identity, read_all_bytes


def test_digest_tree_tracks_content_and_directories(tmp_path: Path) -> None:
    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "f").write_bytes(b"x")
    before = digest_tree(tmp_path)
    assert set(before) == {"d", "d/f"} and before["d"] == "<dir>"
    (tmp_path / "d" / "f").write_bytes(b"y")
    assert digest_tree(tmp_path) != before


def test_file_identity_distinguishes_files_with_equal_content(tmp_path: Path) -> None:
    a, b = tmp_path / "a", tmp_path / "b"
    a.write_bytes(b"same")
    b.write_bytes(b"same")
    assert file_identity(a) == file_identity(a) and file_identity(a) != file_identity(b)


def test_read_all_bytes_and_corrupt_bytes(tmp_path: Path) -> None:
    a, b = tmp_path / "a", tmp_path / "b"
    a.write_bytes(b"\x00\x01")
    b.write_bytes(b"\x02")
    corrupt_bytes(a, offsets=[1])
    assert read_all_bytes([b, a]) == b"\x02\x00\xfe"
