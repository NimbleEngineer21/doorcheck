"""Which version of a PyPI package a fresh install gets.

Home Assistant installs a requirement with `uv pip install --upgrade`, which
takes the newest release the specifiers allow. Scanners need that exact version:
GuardDog only understands a single `>=` bound and OSV-Scanner only exact pins,
so without this a bounded range like `>=1.2,<2` isn't checked at all.

Home Assistant's own pinned packages can hold a few shared libraries back from
the newest release; those are core dependencies, not the integration's.
"""

import json
from collections.abc import Callable, Iterator
from typing import Any
from urllib.parse import quote

from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion, Version

from doorcheck import https
from doorcheck.errors import DoorcheckError
from doorcheck.https import Get
from doorcheck.requirements import PypiRequirement

PYPI_HOSTS = frozenset({"pypi.org"})
MAX_INDEX_BYTES = 50 * 1024 * 1024  # the release list of a package with years of wheels

Resolve = Callable[[PypiRequirement], str]


def pypi_get(url: str) -> bytes:
    return https.get(url, PYPI_HOSTS, MAX_INDEX_BYTES)


class PackageIndexError(DoorcheckError):
    key = "problem.package_index_unreadable"


def newest_version(requirement: PypiRequirement, get: Get = pypi_get) -> str:
    """The newest release the requirement allows. Raises a DoorcheckError when that
    can't be known: offline, not on PyPI, an unreadable index, or no matching release."""
    try:
        specifiers = SpecifierSet(requirement.specifiers)
        if pinned := requirement.pinned_version:
            return str(Version(pinned))
    except ValueError as error:
        raise PackageIndexError(f"invalid requirement for {requirement.name}: {error}") from error
    data = get(f"https://pypi.org/pypi/{quote(requirement.name)}/json")
    try:
        releases = _releases(json.loads(data)["releases"])
        matching = list(specifiers.filter(releases))
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError) as error:
        raise PackageIndexError(f"unreadable index for {requirement.name}: {error!r}") from error
    if not matching:
        raise PackageIndexError(
            f"no release of {requirement.name} matches {requirement.specifiers!r}",
            "problem.no_matching_release",
        )
    return str(max(matching))


def _releases(releases: dict[str, Any]) -> Iterator[Version]:
    """Versions with at least one file that isn't yanked; unparsable versions are skipped."""
    for text, files in releases.items():
        if all(file.get("yanked") for file in files):  # also skips releases with no files
            continue
        try:
            yield Version(text)
        except InvalidVersion:
            continue
