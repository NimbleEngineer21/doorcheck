"""The exact files an install puts on disk, and which version they are.

Marketplace records a release install by its tag name only, and a release can
ship a zip that differs from the tagged source. So a repo is fetched the way
Marketplace fetches it, the files that would be installed are hashed, and any
difference between the release zip and the source is listed.
"""

import hashlib
import re
from dataclasses import dataclass
from itertools import islice
from pathlib import Path
from urllib.parse import quote

from doorcheck.fetch.archive import COMMIT, MAX_BYTES, MAX_MEMBERS, Archive
from doorcheck.fetch.errors import FetchError
from doorcheck.fetch.marketplace import hacs_manifest, source_folder
from doorcheck.fetch.transport import Get, https_get
from doorcheck.report import Target
from doorcheck.tree import entries, json_object, read_regular

REPO = re.compile(r"[A-Za-z0-9-]+/[A-Za-z0-9_.-]+")
TAG = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+/-]*")
ASSET = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+ -]*")


@dataclass(frozen=True, slots=True)
class Installed:
    root: Path
    target: Target
    # Files where the release zip and the tagged source disagree, or None when
    # the source itself is what gets installed.
    differs_from_source: tuple[str, ...] | None = None


def from_folder(folder: Path) -> Installed:
    """An integration folder already on disk, such as custom_components/<domain>."""
    try:
        manifest = json_object(_file_bytes(folder / "manifest.json", MAX_BYTES)) or {}
    except FileNotFoundError:
        manifest = {}
    except OSError as error:
        raise FetchError(f"cannot read manifest: {error}") from error
    name, version = manifest.get("domain"), manifest.get("version")
    target = Target(
        name=name if isinstance(name, str) and name else folder.name,
        version=version if isinstance(version, str) else None,
        artifact_sha256=tree_digest(folder),
    )
    return Installed(folder, target)


def from_repo(repo: str, tag: str, dest: Path, get: Get = https_get) -> Installed:
    """Fetch what Marketplace installs for `repo` at release `tag` into dest."""
    _require(TAG, tag, "tag")
    return _install(repo, f"archive/refs/tags/{quote(tag)}.zip", dest, get, tag=tag)


def from_commit(repo: str, commit: str, dest: Path, get: Get = https_get) -> Installed:
    """Fetch what Marketplace installs for `repo` at a commit, as it does for repos
    without releases (it installs the default branch and records the commit)."""
    if not COMMIT.fullmatch(commit):
        raise FetchError(f"invalid commit: {commit!r}")
    return _install(repo, f"archive/{commit}.zip", dest, get, commit=commit)


def _install(
    repo: str, archive: str, dest: Path, get: Get, tag: str | None = None, commit: str | None = None
) -> Installed:
    _require(REPO, repo, "repository")
    base = f"https://github.com/{repo}"
    source = Archive(get(f"{base}/{archive}"), strip_top=True)
    if commit and source.commit != commit:
        raise FetchError(f"archive is for commit {source.commit}, not {commit}")
    manifest = hacs_manifest(source.read("hacs.json"))
    folder = source_folder(source, manifest)
    differs = None
    if asset_name := manifest.release_asset:
        if tag is None:
            raise FetchError("this repo installs a release file, which needs a release tag")
        _require(ASSET, asset_name, "release file name")
        release = Archive(get(f"{base}/releases/download/{quote(tag)}/{quote(asset_name)}"))
        release.extract(dest)
        differs = _differences(release.digests(), source.digests(folder))
    else:
        source.extract(dest, folder)
    target = Target(repo, tag, source.commit, tree_digest(dest))
    return Installed(dest, target, differs)


def tree_digest(root: Path) -> str:
    """One SHA-256 for a folder: every file's path and content, links by target.

    Folders and file times don't count, so the same files hash the same whether
    they were just fetched or have been installed for months."""
    try:
        return _tree_digest(root)
    except OSError as error:
        raise FetchError(f"cannot hash folder: {error}") from error


def _tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    members = list(islice(entries(root), MAX_MEMBERS + 1))
    if len(members) > MAX_MEMBERS:
        raise FetchError("folder contains too many files")
    remaining = MAX_BYTES
    for entry in sorted(members, key=lambda e: e.relative):
        content = (
            str(entry.path.readlink()).encode()
            if entry.is_link
            else _file_bytes(entry.path, remaining)
        )
        remaining -= len(content)
        if remaining < 0:
            raise FetchError("folder exceeds byte limit")
        kind = "link" if entry.is_link else "file"
        digest.update(f"{kind}\0{entry.relative}\0{hashlib.sha256(content).hexdigest()}\n".encode())
    return digest.hexdigest()


def _file_bytes(path: Path, limit: int) -> bytes:
    data = read_regular(path, limit + 1)
    if len(data) > limit:
        raise FetchError("folder exceeds byte limit")
    return data


def _differences(installed: dict[str, str], source: dict[str, str]) -> tuple[str, ...]:
    paths = installed.keys() | source.keys()
    return tuple(sorted(path for path in paths if installed.get(path) != source.get(path)))


def _require(pattern: re.Pattern[str], value: str, what: str) -> None:
    if not pattern.fullmatch(value) or ".." in value:
        raise FetchError(f"invalid {what}: {value!r}")
