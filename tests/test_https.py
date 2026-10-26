"""The shared downloader, with a fake HTTPS handler so nothing reaches the network."""

import http.client
import io
import re
import urllib.error
import urllib.request
from http.client import HTTPMessage

import pytest

from doorcheck.https import (
    TIMEOUT_SECONDS,
    USER_AGENT,
    AllowedRedirects,
    DownloadError,
    check_url,
    get,
    opener,
)
from tests.conftest import CountingBody, FakeHTTPS

pytestmark = pytest.mark.usefixtures("offline")

HOSTS = frozenset({"files.example.org", "cdn.example.org"})
PAGE = "https://files.example.org/a.zip"
CDN = "https://cdn.example.org/a.zip"


def fetch(pages: dict[str, object], url: str = PAGE, limit: int = 100) -> bytes:
    return get(url, HOSTS, limit, opener(HOSTS, FakeHTTPS(pages)))


@pytest.mark.parametrize(
    "url", [PAGE, CDN, "https://files.example.org", "https://files.example.org:443/a"]
)
def test_listed_hosts_are_allowed(url: str) -> None:
    check_url(url, HOSTS)


@pytest.mark.parametrize(
    "url",
    [
        "http://files.example.org/a",
        "https://evil.example/a",
        "https://files.example.org.evil.example/x",
        "https://files.example.org@evil.example/x",
        "file:///etc/passwd",
        "files.example.org/a",
    ],
)
def test_other_urls_are_refused(url: str) -> None:
    with pytest.raises(DownloadError, match=f"^refusing to download from {re.escape(url)}$"):
        check_url(url, HOSTS)


def test_download() -> None:
    handler = FakeHTTPS({PAGE: b"bytes"})
    assert get(PAGE, HOSTS, 100, opener(HOSTS, handler)) == b"bytes"
    assert handler.timeouts == [TIMEOUT_SECONDS]


def test_downloads_say_they_come_from_doorcheck() -> None:
    handler = FakeHTTPS({PAGE: (302, CDN), CDN: b"bytes"})
    get(PAGE, HOSTS, 100, opener(HOSTS, handler))
    assert handler.user_agents == [USER_AGENT, USER_AGENT]  # kept across redirects
    assert USER_AGENT == "doorcheck (+https://github.com/nimbleengineer21/doorcheck)"


def test_at_most_one_byte_past_the_cap_is_read() -> None:
    body = CountingBody(b"x" * 10_000)
    with pytest.raises(DownloadError):
        fetch({PAGE: body}, limit=100)
    assert body.consumed == 101


def test_a_redirect_urllib_refuses_keeps_the_original_response() -> None:
    # urllib won't repeat a POST on 307; the refusal must carry the real response.
    request = urllib.request.Request(PAGE, data=b"x", method="POST")
    body, headers = io.BytesIO(b"page"), HTTPMessage()
    with pytest.raises(urllib.error.HTTPError) as refused:
        AllowedRedirects(HOSTS).redirect_request(request, body, 307, "Moved", headers, CDN)
    assert (refused.value.code, refused.value.msg, refused.value.hdrs) == (307, "Moved", headers)
    assert refused.value.fp is body


def test_redirects_within_the_hosts_are_followed() -> None:
    assert fetch({PAGE: (302, CDN), CDN: b"bytes"}) == b"bytes"


def test_redirects_elsewhere_are_refused() -> None:
    with pytest.raises(DownloadError, match=r"^refusing to download from https://evil\.example/x$"):
        fetch({PAGE: (302, "https://evil.example/x")})


def test_the_download_is_capped() -> None:
    assert fetch({PAGE: b"x" * 100}) == b"x" * 100
    with pytest.raises(DownloadError, match=f"^download from {re.escape(PAGE)} is over 99 bytes$"):
        fetch({PAGE: b"x" * 100}, limit=99)


@pytest.mark.parametrize(
    ("error", "message"),
    [
        (urllib.error.URLError("no route"), "<urlopen error no route>"),
        (TimeoutError("timed out"), "timed out"),
        (ConnectionResetError("reset"), "reset"),
        (
            http.client.IncompleteRead(b"x", 5),
            re.escape("IncompleteRead(1 bytes read, 5 more expected)"),
        ),
        (http.client.RemoteDisconnected("gone"), "gone"),
    ],
)
def test_network_failures(error: Exception, message: str) -> None:
    with pytest.raises(
        DownloadError, match=f"^download failed for {re.escape(PAGE)}: {message}$"
    ) as e:
        fetch({PAGE: error})
    assert e.value.key == "problem.download_failed"


def test_a_failure_while_reading_the_body_is_a_download_error() -> None:
    class Broken(io.BytesIO):
        def read(self, size: int | None = -1) -> bytes:
            raise http.client.IncompleteRead(b"", 10)

    with pytest.raises(DownloadError):
        fetch({PAGE: Broken(b"")})


@pytest.mark.parametrize(
    ("status", "key"), [(404, "problem.download_not_found"), (500, "problem.download_failed")]
)
def test_http_errors(status: int, key: str) -> None:
    with pytest.raises(DownloadError, match=rf": HTTP Error {status}: fake$") as error:
        fetch({PAGE: (status, "")})
    assert error.value.key == key


def test_errors_are_keyed_and_not_value_errors() -> None:
    with pytest.raises(DownloadError) as refused:
        fetch({}, url="https://evil.example/x")
    assert refused.value.key == "problem.download_refused"
    assert not isinstance(refused.value, ValueError)
    with pytest.raises(DownloadError) as large:
        fetch({PAGE: b"x" * 100}, limit=99)
    assert large.value.key == "problem.download_too_large"


def test_refused_urls_are_never_requested() -> None:
    with pytest.raises(DownloadError):
        fetch({}, url="https://evil.example/x")


def test_the_default_opener_only_follows_the_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    pages = {PAGE: (302, "https://evil.example/x")}
    monkeypatch.setattr(
        "doorcheck.https.opener",
        lambda hosts: urllib.request.build_opener(AllowedRedirects(hosts), FakeHTTPS(pages)),
    )
    with pytest.raises(DownloadError, match=r"^refusing to download from https://evil\.example/x$"):
        get(PAGE, HOSTS, 100)


@pytest.mark.parametrize(
    "url",
    [
        "https://[bad",
        "https://files.example.org:invalid/a",
        "https://files.example.org:8443/a",
        "https://user@files.example.org/a",
        "https://user:password@files.example.org/a",
    ],
)
def test_malformed_or_unexpected_authorities_are_refused(url: str) -> None:
    with pytest.raises(DownloadError) as error:
        fetch({}, url=url)
    assert error.value.key == "problem.download_refused"
    assert str(error.value) == f"refusing to download from {url}"
