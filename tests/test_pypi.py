"""Picking the version a fresh install gets, from PyPI's release list."""

import json
import re

import pytest

from doorcheck.pypi import (
    MAX_INDEX_BYTES,
    PYPI_HOSTS,
    PackageIndexError,
    newest_version,
    pypi_get,
)
from doorcheck.requirements import PypiRequirement

pytestmark = pytest.mark.usefixtures("offline")

FILE = [{"filename": "x.whl", "yanked": False}]
YANKED = [{"filename": "x.whl", "yanked": True}]


def index(releases: dict[str, list[dict[str, object]]]) -> bytes:
    return json.dumps({"info": {}, "releases": releases}).encode()


class FakePypi:
    def __init__(self, releases: dict[str, list[dict[str, object]]]) -> None:
        self.page = index(releases)
        self.requested: list[str] = []

    def __call__(self, url: str) -> bytes:
        self.requested.append(url)
        return self.page


RELEASES = {
    "1.0": FILE,
    "1.9": FILE,
    "2.0": FILE,
    "2.1rc1": FILE,
    "2.2": YANKED,
    "3.0": [],
    "not-a-version": FILE,
}


@pytest.mark.parametrize(
    ("specifiers", "version"),
    [
        ("", "2.0"),
        (">=1", "2.0"),
        (">=1,<2", "1.9"),
        ("~=1.0", "1.9"),
        ("!=2.0", "1.9"),
        (">=2.1rc1", "2.1rc1"),
        (">2.0", "2.1rc1"),  # only a pre-release matches, so it's used
    ],
)
def test_the_newest_allowed_release(specifiers: str, version: str) -> None:
    get = FakePypi(RELEASES)
    assert newest_version(PypiRequirement("pkg", specifiers), get) == version
    assert get.requested == ["https://pypi.org/pypi/pkg/json"]


def test_yanked_and_empty_releases_are_never_picked() -> None:
    get = FakePypi(RELEASES)
    with pytest.raises(
        PackageIndexError, match=re.escape("no release of pkg matches '>=2.2'")
    ) as e:
        newest_version(PypiRequirement("pkg", ">=2.2"), get)
    assert e.value.key == "problem.no_matching_release"


def test_a_release_with_one_good_file_counts() -> None:
    get = FakePypi({"1.0": FILE, "2.0": YANKED + FILE})
    assert newest_version(PypiRequirement("pkg", ""), get) == "2.0"


def test_an_exact_pin_needs_no_lookup() -> None:
    get = FakePypi({})
    assert newest_version(PypiRequirement("pkg", "==1.2.3"), get) == "1.2.3"
    assert get.requested == []


def test_names_are_quoted_in_the_url() -> None:
    get = FakePypi({"1.0": FILE})
    newest_version(PypiRequirement("a.b_c-d", ""), get)
    assert get.requested == ["https://pypi.org/pypi/a.b_c-d/json"]


def test_pypi_downloads_are_held_to_pypi(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []

    def recording(url: str, hosts: frozenset[str], limit: int) -> bytes:
        calls.append((url, hosts, limit))
        return b"{}"

    monkeypatch.setattr("doorcheck.https.get", recording)
    assert pypi_get("https://pypi.org/pypi/x/json") == b"{}"
    assert calls == [("https://pypi.org/pypi/x/json", PYPI_HOSTS, MAX_INDEX_BYTES)]
    assert frozenset({"pypi.org"}) == PYPI_HOSTS


@pytest.mark.parametrize(
    "page",
    [b"not json", b"[]", b'{"info": {}}', b'{"releases": []}', b'{"releases": {"1.0": 3}}'],
    ids=["not-json", "not-an-object", "no-releases", "releases-not-a-map", "files-not-a-list"],
)
def test_an_unreadable_index_is_a_keyed_error(page: bytes) -> None:
    with pytest.raises(PackageIndexError, match="unreadable index for pkg") as error:
        newest_version(PypiRequirement("pkg", ""), lambda url: page)
    assert error.value.key == "problem.package_index_unreadable"


def test_a_deeply_nested_index_is_an_error_not_a_crash() -> None:
    with pytest.raises(PackageIndexError):
        newest_version(PypiRequirement("pkg", ""), lambda url: b"[" * 100_000)


def test_skipped_releases_dont_hide_the_ones_after_them() -> None:
    get = FakePypi({"9.0": YANKED, "8.0": [], "bad version": FILE, "1.5": FILE})
    assert newest_version(PypiRequirement("pkg", ""), get) == "1.5"
