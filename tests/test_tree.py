"""Listing untrusted folders and reading untrusted JSON."""

import errno
from pathlib import Path

import pytest

from doorcheck.tree import Entry, entries, json_object, read_json_object


@pytest.mark.parametrize("kind", ["file", "link"])
def test_non_directory_roots_explain_the_failure(tmp_path: Path, kind: str) -> None:
    root = tmp_path / kind
    target = tmp_path / "target"
    target.mkdir()
    if kind == "file":
        root.write_text("data")
    else:
        root.symlink_to(target, target_is_directory=True)
    with pytest.raises(NotADirectoryError) as raised:
        list(entries(root))
    assert raised.value.errno == errno.ENOTDIR
    assert raised.value.strerror == "scan root must be a directory, not a link or file"
    assert raised.value.filename == str(root)


def test_walk_errors_raise_by_default_or_reach_the_callers_handler(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    error = PermissionError(13, "denied", str(tmp_path))

    def failing_walk(root, *, onerror):
        onerror(error)
        return iter(())

    monkeypatch.setattr("doorcheck.tree.os.walk", failing_walk)
    with pytest.raises(PermissionError) as raised:
        list(entries(tmp_path))
    assert raised.value is error
    errors = []
    assert list(entries(tmp_path, errors.append)) == []
    assert errors == [error]


def test_every_file_is_listed_in_a_stable_order_including_git(tmp_path: Path) -> None:
    for name in ("b.py", "a/z.py", "a/b/c.py", ".git/hooks/p.py", ".hidden"):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("")
    assert [e.relative for e in entries(tmp_path)] == [
        ".hidden",
        "b.py",
        ".git/hooks/p.py",
        "a/z.py",
        "a/b/c.py",
    ]


def test_links_are_listed_and_never_entered(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("x")
    root = tmp_path / "root"
    root.mkdir()
    (root / "folder").symlink_to(outside, target_is_directory=True)
    (root / "file").symlink_to(outside / "secret.txt")
    (root / "real.py").write_text("")
    assert list(entries(root)) == [
        Entry(root / "file", "file", True),
        Entry(root / "folder", "folder", True),
        Entry(root / "real.py", "real.py", False),
    ]


@pytest.mark.parametrize(
    ("data", "value"),
    [
        (b'{"a": 1}', {"a": 1}),
        (b"[1]", None),
        (b"3", None),
        (b"{broken", None),
        (b"\xff", None),
        (b"[" * 100_000, None),
        (b"", None),
        (None, None),
    ],
)
def test_json_object(data: bytes | None, value: object) -> None:
    assert json_object(data) == value


def test_reading_json_from_a_file(tmp_path: Path) -> None:
    (tmp_path / "a.json").write_text('{"x": true}')
    assert read_json_object(tmp_path / "a.json") == {"x": True}
    assert read_json_object(tmp_path / "missing.json") is None
    assert read_json_object(tmp_path) is None  # a folder can't be read
