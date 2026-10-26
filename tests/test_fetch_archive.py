import hashlib
import io
import re
import stat
import zipfile
from pathlib import Path

import pytest

from doorcheck.errors import DoorcheckError
from doorcheck.fetch.archive import (
    MAX_BYTES,
    MAX_DEPTH,
    MAX_MEMBERS,
    MAX_PART_BYTES,
    Archive,
    ArchiveLimits,
)
from doorcheck.fetch.errors import FetchError, UnsafeArchive
from tests.conftest import LINK, make_zip

COMMIT = "0123456789abcdef0123456789abcdef01234567"


def rejected(message: str) -> pytest.RaisesExc[UnsafeArchive]:
    return pytest.raises(UnsafeArchive, match=f"^{re.escape(message)}$")


def test_default_limits_match_marketplace() -> None:
    assert (MAX_BYTES, MAX_MEMBERS) == (100 * 1024 * 1024, 50_000)
    assert ArchiveLimits() == ArchiveLimits(max_bytes=MAX_BYTES, max_members=MAX_MEMBERS)


def test_top_folder_is_stripped_and_folder_entries_dropped() -> None:
    data = make_zip({"repo-1.0/": None, "repo-1.0/a/": None, "repo-1.0/a/b.py": "x"})
    archive = Archive(data, strip_top=True)
    assert list(archive.files) == ["a/b.py"]


def test_names_are_kept_whole_without_stripping() -> None:
    archive = Archive(make_zip({"a/b.py": "x", "c.py": "y", "./d/./e.py": "z"}))
    assert list(archive.files) == ["a/b.py", "c.py", "d/e.py"]


@pytest.mark.parametrize(
    ("comment", "commit"),
    [
        (COMMIT.encode(), COMMIT),
        (COMMIT.upper().encode(), None),
        (COMMIT[:-1].encode(), None),
        (COMMIT.encode() + b"\n", None),
        (b"\xff" * 40, None),
        (b"", None),
    ],
)
def test_commit_comes_from_the_git_archive_comment(comment: bytes, commit: str | None) -> None:
    assert Archive(make_zip({"a": "x"}, comment)).commit == commit


# --- limits -------------------------------------------------------------------------


def test_downloads_over_the_byte_limit_are_rejected() -> None:
    data = make_zip({"a": "x"})
    Archive(data, limits=ArchiveLimits(max_bytes=len(data)))
    with rejected(f"archive is {len(data)} bytes, over {len(data) - 1}"):
        Archive(data, limits=ArchiveLimits(max_bytes=len(data) - 1))


def test_too_many_entries_are_rejected() -> None:
    data = make_zip({f"f{n}": "" for n in range(3)})
    Archive(data, limits=ArchiveLimits(max_members=3))
    with rejected("archive has 3 entries, over 2"):
        Archive(data, limits=ArchiveLimits(max_members=2))


def test_unpacked_size_over_the_limit_is_rejected() -> None:
    data = make_zip({"a": "x" * 6000, "b": "y" * 4000})
    assert len(data) < 1000
    Archive(data, limits=ArchiveLimits(max_bytes=10_000))
    with rejected("archive unpacks to 10000 bytes, over 9999"):
        Archive(data, limits=ArchiveLimits(max_bytes=9999))


def test_a_real_zip_bomb_is_rejected_at_the_default_limit() -> None:
    bomb = make_zip({"zeros": bytes(MAX_BYTES + 1)})
    assert len(bomb) < 1_000_000  # small to download, huge to unpack
    with rejected(f"archive unpacks to {MAX_BYTES + 1} bytes, over {MAX_BYTES}"):
        Archive(bomb)


def test_an_entry_flood_is_rejected_at_the_default_limit() -> None:
    flood = make_zip({f"e{n}": "" for n in range(MAX_MEMBERS + 1)})
    with rejected(f"archive has {MAX_MEMBERS + 1} entries, over {MAX_MEMBERS}"):
        Archive(flood)


# --- unsafe names --------------------------------------------------------------------


def test_non_zips_are_rejected() -> None:
    with rejected("not a zip archive: File is not a zip file"):
        Archive(b"PK not really")


@pytest.mark.parametrize(
    ("name", "message"),
    [
        ("/etc/passwd", "absolute path '/etc/passwd'"),
        ("C:/Windows/x", "absolute path 'C:/Windows/x'"),
        ("c:x", "absolute path 'c:x'"),
        ("../outside", "path escapes the folder: '../outside'"),
        ("repo/a/../../outside", "path escapes the folder: 'repo/a/../../outside'"),
        ("repo/..", "path escapes the folder: 'repo/..'"),
        ("repo\\..\\outside", "backslash in 'repo\\\\..\\\\outside'"),
    ],
)
def test_names_that_escape_are_rejected(name: str, message: str) -> None:
    with rejected(message):
        Archive(make_zip({name: "x"}), strip_top=True)


@pytest.mark.parametrize(
    "name",
    ["repo/\x1b[2J\x1b[32mALL CLEAR.py", "repo/a\nb.py", "repo/a\u202eb.py", "repo/ex\u200bec.py"],
    ids=["escape-codes", "newline", "bidi", "zero-width"],
)
def test_names_with_control_or_invisible_characters_are_rejected(name: str) -> None:
    with rejected(f"control or invisible character in {name!r}"):
        Archive(make_zip({name: "x"}), strip_top=True)


def test_names_deeper_than_a_file_system_allows_are_rejected() -> None:
    assert MAX_DEPTH == 64
    fits = "/".join(["d"] * MAX_DEPTH)
    assert list(Archive(make_zip({fits: "x"})).files) == [fits]
    too_deep = f"{fits}/x"
    with rejected(f"path too deep or too long: {too_deep[:100]!r}"):
        Archive(make_zip({too_deep: "x"}))


def test_name_parts_longer_than_a_file_system_allows_are_rejected() -> None:
    assert MAX_PART_BYTES == 255
    fits = "a" * 255
    assert list(Archive(make_zip({fits: "x"})).files) == [fits]
    too_long = "é" * 128  # 256 bytes in UTF-8
    with rejected(f"path too deep or too long: {too_long[:100]!r}"):
        Archive(make_zip({too_long: "x"}))


def test_dots_inside_names_are_fine() -> None:
    archive = Archive(make_zip({"repo/a..b/..c.py": "x", "repo/x:y": "z"}), strip_top=True)
    assert list(archive.files) == ["a..b/..c.py", "x:y"]


def test_links_are_rejected() -> None:
    with rejected("link 'repo/secrets.yaml'"):
        Archive(make_zip({"repo/secrets.yaml": (LINK, "../../secrets.yaml")}), strip_top=True)


@pytest.mark.parametrize(
    ("entries", "message"),
    [
        ({"repo/a.py": "x", "repo//a.py": "y"}, "repo//a.py appears twice"),
        ({"repo/a.py": "x", "repo/./a.py": "y"}, "repo/./a.py appears twice"),
        ({"one/a.py": "x", "two/a.py": "y"}, "two/a.py appears twice"),
        ({"repo/a": "x", "repo/a/b.py": "y"}, "a is both a file and a folder"),
        ({"repo/a/b/c.py": "x", "repo/a/b": "y"}, "a/b is both a file and a folder"),
    ],
)
def test_ambiguous_archives_are_rejected(entries: dict[str, str], message: str) -> None:
    # A scanner and an installer could each pick a different one of these files.
    with rejected(message):
        Archive(make_zip(entries), strip_top=True)


@pytest.mark.parametrize(
    ("offset", "error"),
    [
        (0, "Error -3 while decompressing data: invalid code lengths set"),
        (3, "Bad CRC-32 for file 'a.txt'"),
    ],
    ids=["broken-stream", "bad-checksum"],
)
def test_a_corrupted_member_is_rejected_when_read(offset: int, error: str) -> None:
    data = bytearray(make_zip({"a.txt": "hello world " * 20}))
    data[30 + len("a.txt") + offset] ^= 0xFF  # inside a.txt's compressed bytes
    archive = Archive(bytes(data))
    with rejected(f"can't read a.txt: {error}"):
        archive.read("a.txt")


def test_names_containing_nul_are_rejected_before_zipfile_truncates_them() -> None:
    data = make_zip({"evil.py": "x"}).replace(b"evil.py", b"e\0il.py")
    with rejected("control or invisible character in 'e\\x00il.py'"):
        Archive(data)


# --- reading and extracting ----------------------------------------------------------


@pytest.fixture
def source() -> Archive:
    entries = {
        "repo/hacs.json": "{}",
        "repo/custom_components/demo/__init__.py": "init",
        "repo/custom_components/demo/sub/x.py": "x",
        "repo/custom_components/demoextra/y.py": "y",
        "repo/custom_components/alpha/z.py": "z",
        "repo/custom_components/README.md": "readme",
    }
    return Archive(make_zip(entries), strip_top=True)


def test_read(source: Archive) -> None:
    assert source.read("hacs.json") == b"{}"
    assert source.read("missing.json") is None


def test_folders_lists_direct_child_folders_only(source: Archive) -> None:
    assert source.folders("custom_components") == ["alpha", "demo", "demoextra"]
    assert source.folders("custom_components/demo") == ["sub"]
    assert source.folders("nothing") == []


def test_digests_cover_only_files_inside_the_folder(source: Archive) -> None:
    def sha(text: str) -> str:
        return hashlib.sha256(text.encode()).hexdigest()

    assert source.digests("custom_components/demo") == {
        "__init__.py": sha("init"),
        "sub/x.py": sha("x"),
    }
    assert len(source.digests()) == 6


def test_extract_writes_only_the_folder(source: Archive, tmp_path: Path) -> None:
    dest = tmp_path / "custom_components" / "demo"
    assert source.extract(dest, "custom_components/demo") == 2
    written = sorted(p.relative_to(dest).as_posix() for p in dest.rglob("*") if p.is_file())
    assert written == ["__init__.py", "sub/x.py"]
    assert (dest / "sub/x.py").read_text() == "x"


def test_extract_everything(source: Archive, tmp_path: Path) -> None:
    assert source.extract(tmp_path / "all") == 6


def test_extract_needs_a_new_folder_and_leaves_an_existing_one_alone(
    source: Archive, tmp_path: Path
) -> None:
    (tmp_path / "keep.txt").write_text("mine")
    with pytest.raises(FetchError, match=r"^can't create ") as error:
        source.extract(tmp_path, "custom_components/demo")
    assert not isinstance(error.value, UnsafeArchive)
    assert [p.name for p in tmp_path.iterdir()] == ["keep.txt"]


def test_a_member_that_fails_while_unpacking_leaves_nothing_behind(tmp_path: Path) -> None:
    data = bytearray(make_zip({"a.txt": "first", "b.txt": "hello world " * 20}))
    member = data.index(b"b.txt") + len("b.txt") + 3
    data[member] ^= 0xFF
    dest = tmp_path / "out"
    with pytest.raises(UnsafeArchive, match=r"^can't unpack into .*Bad CRC-32 for file 'b.txt'"):
        Archive(bytes(data)).extract(dest)
    assert not dest.exists()


def test_a_clean_up_that_fails_still_reports_the_archive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = bytearray(make_zip({"a.txt": "first", "b.txt": "hello world " * 20}))
    data[data.index(b"b.txt") + len("b.txt") + 3] ^= 0xFF

    def refuse(path: object, *args: object, **kwargs: object) -> None:
        raise PermissionError("can't remove")

    monkeypatch.setattr("os.rmdir", refuse)
    with pytest.raises(UnsafeArchive, match=r"^can't unpack into "):
        Archive(bytes(data)).extract(tmp_path / "out")


def test_a_path_the_file_system_refuses_leaves_nothing_behind(tmp_path: Path) -> None:
    deep = "/".join(["d" * 250] * 20) + "/x.py"  # each part fits, the whole path doesn't
    dest = tmp_path / "out"
    with pytest.raises(UnsafeArchive, match=r"^can't unpack into .*File name too long"):
        Archive(make_zip({"a.py": "x", deep: "y"})).extract(dest)
    assert not dest.exists()


@pytest.mark.parametrize(
    ("below", "message"),
    [("custom_components/none", "custom_components/none"), ("", "the top folder")],
)
def test_extracting_nothing_is_an_error(tmp_path: Path, below: str, message: str) -> None:
    archive = Archive(make_zip({"repo/": None}), strip_top=True)
    with rejected(f"nothing to install below {message}"):
        archive.extract(tmp_path / "dest", below)


def test_written_files_are_never_executable(tmp_path: Path) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        info = zipfile.ZipInfo("run.sh")
        info.external_attr = (stat.S_IFREG | 0o755) << 16  # the zip asks for an executable
        archive.writestr(info, "#!/bin/sh")
    Archive(buffer.getvalue()).extract(tmp_path / "d")
    assert (tmp_path / "d" / "run.sh").stat().st_mode & 0o111 == 0


def test_folders_are_created_at_any_depth(tmp_path: Path) -> None:
    Archive(make_zip({"a/b/c/d.py": "x"})).extract(tmp_path / "dest")
    assert (tmp_path / "dest/a/b/c/d.py").read_text() == "x"


def test_names_are_not_stripped_by_default() -> None:
    assert list(Archive(make_zip({"top/a.py": "x"})).files) == ["top/a.py"]


def test_fetch_errors_have_their_own_keys() -> None:
    assert FetchError("x").key == "problem.fetch_failed"
    assert UnsafeArchive("x").key == "problem.unsafe_archive"
    assert FetchError("x", "problem.download_failed").key == "problem.download_failed"
    assert issubclass(UnsafeArchive, FetchError)
    assert issubclass(FetchError, DoorcheckError)


@pytest.mark.parametrize(
    "entries",
    [
        {"one/a.py": "x", "two/b.py": "y"},
        {"repo/a.py": "x", "loose.py": "y"},
        {"single.py": "x"},
        {"./": None},
        {},
    ],
)
def test_source_archives_require_one_top_folder(entries: dict[str, str | None]) -> None:
    with rejected("source archive must contain one top-level folder"):
        Archive(make_zip(entries), strip_top=True)


@pytest.mark.parametrize("entries", [{"a/": None, "a": "x"}, {"a": "x", "a/": None}])
def test_explicit_directory_file_clashes_are_rejected(entries: dict[str, str | None]) -> None:
    with rejected("a is both a file and a folder"):
        Archive(make_zip(entries))


def test_encrypted_members_are_keyed_errors_and_leave_no_partial_install(tmp_path: Path) -> None:
    data = bytearray(make_zip({"a.py": "first", "secret.py": "encrypted"}))
    local = data.index(b"PK\x03\x04", 4)
    central = data.index(b"PK\x01\x02", data.index(b"PK\x01\x02") + 4)
    data[local + 6] |= 1
    data[central + 8] |= 1
    dest = tmp_path / "out"
    with pytest.raises(UnsafeArchive, match=r"^can't unpack into .*encrypted"):
        Archive(bytes(data)).extract(dest)
    assert not dest.exists()


def test_directory_file_clashes_are_checked_after_top_folder_stripping() -> None:
    with rejected("a is both a file and a folder"):
        Archive(make_zip({"repo/a/": None, "repo/a": "x"}), strip_top=True)


def test_invalid_utf8_in_the_zip_directory_is_a_keyed_archive_error() -> None:
    data = bytearray(make_zip({"a.py": "x"}))
    central = data.index(b"PK\x01\x02")
    data[central + 9] |= 8  # mark the central-directory filename as UTF-8
    data[central + 46] = 0xFF
    with pytest.raises(UnsafeArchive, match=r"^not a zip archive: .*utf-8") as error:
        Archive(bytes(data))
    assert error.value.key == "problem.unsafe_archive"


def test_invalid_utf8_in_a_local_zip_header_cleans_up_the_install(tmp_path: Path) -> None:
    data = bytearray(make_zip({"a.txt": "first", "b.py": "second"}))
    local = data.index(b"PK\x03\x04", 4)
    data[local + 7] |= 8
    data[local + 30] = 0xFF
    dest = tmp_path / "out"
    with pytest.raises(UnsafeArchive, match=r"^can't unpack into .*utf-8") as error:
        Archive(bytes(data)).extract(dest)
    assert error.value.key == "problem.unsafe_archive"
    assert not dest.exists()
