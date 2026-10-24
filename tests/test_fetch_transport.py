"""Fetching an integration may only download from GitHub."""

import re
import urllib.request

import pytest

from doorcheck.fetch import FetchError, transport
from doorcheck.fetch.archive import MAX_BYTES
from doorcheck.fetch.transport import GITHUB_HOSTS, github_opener, https_get
from doorcheck.https import AllowedRedirects
from tests.conftest import FakeHTTPS

pytestmark = pytest.mark.usefixtures("offline")

ARCHIVE = "https://github.com/o/r/archive/refs/tags/1.0.zip"
CODELOAD = "https://codeload.github.com/o/r/zip/refs/tags/1.0"


def test_the_github_hosts() -> None:
    expected = {
        "github.com",
        "codeload.github.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
    }
    assert expected == GITHUB_HOSTS


def test_archive_downloads_follow_redirects_within_github() -> None:
    pages = {ARCHIVE: (302, CODELOAD), CODELOAD: b"zip bytes"}
    assert https_get(ARCHIVE, 100, github_opener(FakeHTTPS(pages))) == b"zip bytes"


@pytest.mark.parametrize("url", ["https://pypi.org/x", "http://github.com/o/r"])
def test_anything_else_is_a_fetch_error(url: str) -> None:
    with pytest.raises(FetchError, match=f"^refusing to download from {re.escape(url)}$") as error:
        https_get(url, 100, github_opener(FakeHTTPS({})))
    assert error.value.key == "problem.download_refused"


def test_a_fetch_error_keeps_the_downloads_reason() -> None:
    with pytest.raises(FetchError) as error:
        https_get(ARCHIVE, 100, github_opener(FakeHTTPS({ARCHIVE: (404, "")})))
    assert error.value.key == "problem.download_not_found"


def test_the_default_limit_is_the_archive_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []

    def recording(url: str, hosts: frozenset[str], limit: int, using: object) -> bytes:
        calls.append((url, hosts, limit))
        return b"zip"

    monkeypatch.setattr("doorcheck.https.get", recording)
    assert https_get(ARCHIVE) == b"zip"
    assert calls == [(ARCHIVE, GITHUB_HOSTS, MAX_BYTES)]


def test_the_default_opener_only_follows_github(monkeypatch: pytest.MonkeyPatch) -> None:
    pages = {ARCHIVE: (302, "https://evil.example/x")}
    monkeypatch.setattr(
        transport,
        "github_opener",
        lambda: urllib.request.build_opener(AllowedRedirects(GITHUB_HOSTS), FakeHTTPS(pages)),
    )
    with pytest.raises(FetchError, match=r"^refusing to download from https://evil\.example/x$"):
        https_get(ARCHIVE)
