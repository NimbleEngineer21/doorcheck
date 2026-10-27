import errno
import importlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from doorcheck.capabilities import Kind, ScanLimits, scan
from doorcheck.findings import Location, param

scanner = importlib.import_module("doorcheck.capabilities.scan")


@pytest.mark.parametrize("kind", ["missing", "file", "link"])
def test_invalid_scan_roots_are_problems_instead_of_empty_scans(tmp_path: Path, kind: str) -> None:
    root = tmp_path / kind
    if kind == "file":
        root.write_text("exec(x)")
    elif kind == "link":
        real = tmp_path / "real"
        real.mkdir()
        (real / "a.py").write_text("exec(x)")
        root.symlink_to(real, target_is_directory=True)
    result = scan(root)
    assert result.capabilities == ()
    assert len(result.problems) == 1
    assert result.problems[0].key == "problem.directory_not_readable"
    assert result.problems[0].location is None
    assert result.problems[0].params["detail"]


def test_unreadable_subdirectories_are_reported_and_siblings_are_scanned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    (blocked / "hidden.py").write_text("exec(hidden)")
    visible = tmp_path / "z-visible"
    visible.mkdir()
    (visible / "good.py").write_text("exec(visible)")
    real_scandir = os.scandir

    def denied(path):
        if Path(path) == blocked:
            raise PermissionError(errno.EACCES, "denied", str(blocked))
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", denied)
    result = scan(tmp_path)
    assert [(c.kind, c.location.path) for c in result.capabilities] == [
        (Kind.DYNAMIC_CODE, "z-visible/good.py")
    ]
    assert len(result.problems) == 1
    assert result.problems[0].key == "problem.directory_not_readable"
    assert result.problems[0].location == Location("blocked", 1)
    assert "denied" in result.problems[0].params["detail"]


@pytest.mark.parametrize("failure", ["permission", "deleted", "link-removed"])
def test_file_errors_are_problems_and_do_not_abort_the_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    file = tmp_path / "a.py"
    file.write_text("exec(hidden)")
    (tmp_path / "b.py").write_text("exec(visible)")
    real_open = os.open
    real_readlink = Path.readlink
    if failure == "link-removed":
        file.unlink()
        file.symlink_to("missing")

    def broken_open(path, flags):
        if Path(path) == file:
            if failure == "deleted":
                file.unlink()
            else:
                raise PermissionError(errno.EACCES, "denied", str(file))
        return real_open(path, flags)

    def broken_link(path):
        if path == file:
            file.unlink()
        return real_readlink(path)

    monkeypatch.setattr(os, "open", broken_open)
    monkeypatch.setattr(Path, "readlink", broken_link)
    result = scan(tmp_path)
    assert [(c.kind, c.location.path) for c in result.capabilities] == [(Kind.DYNAMIC_CODE, "b.py")]
    assert len(result.problems) == 1
    assert result.problems[0].key == "problem.file_not_readable"
    assert result.problems[0].location == Location("a.py", 1)
    expected = (
        PermissionError(errno.EACCES, "denied", str(file))
        if failure == "permission"
        else FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), str(file))
    )
    assert result.problems[0].params == {"detail": param(str(expected))}


def test_named_pipes_are_rejected_without_blocking(tmp_path: Path) -> None:
    os.mkfifo(tmp_path / "a.py")
    script = (
        "from pathlib import Path; import json, sys; "
        "from doorcheck.capabilities import scan; "
        "print(json.dumps([p.key for p in scan(Path(sys.argv[1])).problems]))"
    )
    done = subprocess.run(  # noqa: S603 - fixed scanner script on a private test directory
        [sys.executable, "-c", script, str(tmp_path)],
        check=True,
        capture_output=True,
        text=True,
        timeout=3,
    )
    assert json.loads(done.stdout) == ["problem.file_not_regular"]
    result = scan(tmp_path)
    assert result.capabilities == ()
    assert result.problems[0].key == "problem.file_not_regular"
    assert result.problems[0].location == Location("a.py", 1)


@pytest.mark.parametrize("replacement", ["pipe", "link"])
def test_files_replaced_after_stat_are_not_followed_or_blocking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, replacement: str
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    file = root / "a.py"
    file.write_text("pass")
    outside = tmp_path / "outside.py"
    outside.write_text("exec(secret)")
    real_open = os.open

    def replace_file(path, flags):
        assert flags & os.O_NONBLOCK
        assert flags & os.O_NOFOLLOW
        if Path(path) == file:
            file.unlink()
            if replacement == "pipe":
                os.mkfifo(file)
            else:
                file.symlink_to(outside)
        return real_open(path, flags)

    monkeypatch.setattr(os, "open", replace_file)
    result = scan(root)
    assert result.capabilities == ()
    assert len(result.problems) == 1
    assert result.problems[0].key == "problem.file_not_readable"
    assert result.problems[0].location == Location("a.py", 1)
    if replacement == "pipe":
        expected = OSError(errno.EINVAL, "not a regular file", str(file))
        assert result.problems[0].params == {"detail": param(str(expected))}
    assert outside.read_text() == "exec(secret)"


def test_reads_stay_bounded_when_a_file_grows_after_stat(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    file = tmp_path / "a.py"
    file.write_text("pass")
    real_open = os.open

    def grow_file(path, flags):
        file.write_text("exec(x)\n" * 100)
        return real_open(path, flags)

    monkeypatch.setattr(os, "open", grow_file)
    result = scan(tmp_path, ScanLimits(max_python_bytes=8))
    assert result.capabilities == ()
    assert len(result.problems) == 1
    assert result.problems[0].key == "problem.file_too_large"
    assert result.problems[0].params == {"size": "9"}


def test_unknown_files_only_read_the_binary_magic_header(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "data.txt").write_bytes(b"x" * 1000)
    real_read = scanner._read_file
    reads = []

    def bounded_read(path, limit):
        data = real_read(path, limit)
        reads.append(len(data))
        assert len(data) <= 4
        return data

    monkeypatch.setattr(scanner, "_read_file", bounded_read)
    result = scan(tmp_path)
    assert result.capabilities == ()
    assert result.problems == ()
    assert reads == [4]


@pytest.mark.parametrize("filename", [None, "/outside-the-root"])
def test_walk_errors_without_a_relative_filename_still_report_the_gap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, filename: str | None
) -> None:
    def failing_walk(root, *, onerror):
        onerror(OSError(errno.EACCES, "denied", filename))
        return iter(())

    monkeypatch.setattr(os, "walk", failing_walk)
    result = scan(tmp_path)
    assert result.capabilities == ()
    assert len(result.problems) == 1
    assert result.problems[0].key == "problem.directory_not_readable"
    assert result.problems[0].location is None
    assert "denied" in result.problems[0].params["detail"]


def test_unrepresentable_path_at_file_budget(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("pass")
    (tmp_path / "z\\bad.py").write_text("import os")
    result = scan(tmp_path, ScanLimits(max_files=1))
    assert result.capabilities == ()
    assert len(result.problems) == 1
    assert result.problems[0].key == "problem.file_path_not_supported"
    assert result.problems[0].location is None
    assert result.problems[0].params == {"path": "z\\bad.py"}


def test_unrepresentable_unreadable_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    blocked = tmp_path / "bad\\directory"
    blocked.mkdir()
    real_scandir = os.scandir

    def denied(path):
        if Path(path) == blocked:
            raise PermissionError(errno.EACCES, "denied", str(blocked))
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", denied)
    result = scan(tmp_path)
    assert result.capabilities == ()
    assert len(result.problems) == 1
    assert result.problems[0].key == "problem.file_path_not_supported"
    assert result.problems[0].location is None
    assert result.problems[0].params == {"path": "bad\\directory"}
