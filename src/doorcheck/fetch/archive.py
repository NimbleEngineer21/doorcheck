"""Read and unpack an untrusted zip without letting it write outside its folder.

Every member name is checked before anything is written. Names that are
absolute, climb out with "..", use backslashes, are links, appear twice, are
both a file and a folder, hold control or invisible formatting characters, or
are deeper or longer than a file system allows reject the whole archive: an
archive built like that is itself a warning sign, so it is never partly unpacked.
"""

import hashlib
import io
import re
import shutil
import stat
import unicodedata
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from doorcheck.fetch.errors import FetchError, UnsafeArchive

# The same ceilings Home Assistant's Marketplace applies to what it downloads.
MAX_BYTES = 100 * 1024 * 1024
MAX_MEMBERS = 50_000
MAX_DEPTH = 64
MAX_PART_BYTES = 255  # the longest file name most file systems allow
COMMIT = re.compile(r"[0-9a-f]{40}")


@dataclass(frozen=True, slots=True)
class ArchiveLimits:
    max_bytes: int = MAX_BYTES
    max_members: int = MAX_MEMBERS


class Archive:
    """A checked zip. GitHub source archives put everything below one top folder
    named after the repo and ref; strip_top leaves that folder out of the names."""

    def __init__(
        self, data: bytes, *, strip_top: bool = False, limits: ArchiveLimits | None = None
    ) -> None:
        limits = limits or ArchiveLimits()
        if len(data) > limits.max_bytes:
            raise UnsafeArchive(f"archive is {len(data)} bytes, over {limits.max_bytes}")
        try:
            self._zip = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile as error:
            raise UnsafeArchive(f"not a zip archive: {error}") from error
        _check_size(self._zip.infolist(), limits)
        self.files = _files(self._zip.infolist(), strip_top)
        if strip_top:
            _check_top(self._zip.infolist())
        self.commit = _commit(self._zip.comment)

    def read(self, path: str) -> bytes | None:
        info = self.files.get(path)
        return self._read(info) if info else None

    def folders(self, below: str) -> list[str]:
        """The folders directly inside `below`, sorted."""
        prefix = f"{below}/"
        names = {
            path[len(prefix) :].split("/")[0] for path in self.files if path.startswith(prefix)
        }
        return sorted(name for name in names if f"{prefix}{name}" not in self.files)

    def digests(self, below: str = "") -> dict[str, str]:
        """SHA-256 of every file inside `below`, keyed by its path relative to it."""
        return {
            relative: hashlib.sha256(self._read(info)).hexdigest()
            for relative, info in self._below(below)
        }

    def extract(self, dest: Path, below: str = "") -> int:
        """Write the files inside `below` into dest, which must not exist yet."""
        members = self._below(below)
        if not members:
            raise UnsafeArchive(f"nothing to install below {below or 'the top folder'}")
        try:
            dest.mkdir(parents=True)
        except OSError as error:  # it must be a new folder, so nothing else is removed below
            raise FetchError(f"can't create {dest}: {error}") from error
        try:
            for relative, info in members:
                target = dest / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(self._read(info))
        except (OSError, UnsafeArchive) as error:
            shutil.rmtree(dest, ignore_errors=True)  # never leave a partial install behind
            raise UnsafeArchive(f"can't unpack into {dest}: {error}") from error
        return len(members)

    def _below(self, below: str) -> list[tuple[str, zipfile.ZipInfo]]:
        prefix = f"{below}/" if below else ""
        return [
            (path[len(prefix) :], info)
            for path, info in sorted(self.files.items())
            if path.startswith(prefix)
        ]

    def _read(self, info: zipfile.ZipInfo) -> bytes:
        try:
            return self._zip.read(info)
        except (
            zipfile.BadZipFile,
            zlib.error,
            NotImplementedError,
            EOFError,
            RuntimeError,
        ) as error:
            raise UnsafeArchive(f"can't read {info.filename}: {error}") from error


def _commit(comment: bytes) -> str | None:
    """git archive, which GitHub uses, stores the commit as the zip comment."""
    text = comment.decode("ascii", "replace")  # pragma: no mutate - codec names ignore case
    return text if COMMIT.fullmatch(text) else None


def _check_size(infos: list[zipfile.ZipInfo], limits: ArchiveLimits) -> None:
    if len(infos) > limits.max_members:
        raise UnsafeArchive(f"archive has {len(infos)} entries, over {limits.max_members}")
    size = sum(info.file_size for info in infos)
    if size > limits.max_bytes:
        raise UnsafeArchive(f"archive unpacks to {size} bytes, over {limits.max_bytes}")


def _files(infos: list[zipfile.ZipInfo], strip_top: bool) -> dict[str, zipfile.ZipInfo]:
    """Checked file names -> entries. Folder entries are dropped; folders follow from paths."""
    files: dict[str, zipfile.ZipInfo] = {}
    for info in infos:
        name = _name(info, strip_top)
        if name in files and info.is_dir():
            raise UnsafeArchive(f"{name} is both a file and a folder")
        if name in files:
            raise UnsafeArchive(f"{info.filename} appears twice")
        if name and not info.is_dir():
            files[name] = info
    _check_clashes(files, {_name(info, strip_top) for info in infos if info.is_dir()})
    return files


def _check_clashes(files: dict[str, zipfile.ZipInfo], directories: set[str]) -> None:
    for name in files:
        if name in directories:
            raise UnsafeArchive(f"{name} is both a file and a folder")
        for parent in PurePosixPath(name).parents:
            if str(parent) in files:
                raise UnsafeArchive(f"{parent} is both a file and a folder")


def _name(info: zipfile.ZipInfo, strip_top: bool) -> str:
    raw = info.orig_filename
    if "\\" in raw:
        raise UnsafeArchive(f"backslash in {raw!r}")
    if raw.startswith("/") or re.match(r"[A-Za-z]:", raw):
        raise UnsafeArchive(f"absolute path {raw!r}")
    parts = [part for part in raw.split("/") if part not in ("", ".")]
    if ".." in parts:
        raise UnsafeArchive(f"path escapes the folder: {raw!r}")
    if any(unicodedata.category(char) in ("Cc", "Cf") for char in raw):
        raise UnsafeArchive(f"control or invisible character in {raw!r}")
    too_long = any(len(part.encode()) > MAX_PART_BYTES for part in parts)
    if len(parts) > MAX_DEPTH or too_long:
        raise UnsafeArchive(f"path too deep or too long: {raw[:100]!r}")
    if stat.S_ISLNK(info.external_attr >> 16):
        raise UnsafeArchive(f"link {raw!r}")
    return "/".join(parts[1:] if strip_top else parts)


def _check_top(infos: list[zipfile.ZipInfo]) -> None:
    roots: set[str] = set()
    for info in infos:
        parts = PurePosixPath(info.filename).parts
        if not parts or (len(parts) == 1 and not info.is_dir()):
            raise UnsafeArchive("source archive must contain one top-level folder")
        roots.add(parts[0])
    if len(roots) != 1:
        raise UnsafeArchive("source archive must contain one top-level folder")
