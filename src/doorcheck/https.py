"""Download over HTTPS from a fixed set of hosts, with a size cap.

Redirects are held to the same hosts, so a repo or a package index entry can't
point a download anywhere else. Each caller names its own hosts.
"""

import urllib.error
import urllib.request
from collections.abc import Callable
from http.client import HTTPException, HTTPMessage
from typing import IO
from urllib.parse import urlsplit

from doorcheck.errors import DoorcheckError

TIMEOUT_SECONDS = 60
# Services like PyPI ask clients to say who they are, so a misbehaving one can be traced.
USER_AGENT = "doorcheck (+https://github.com/nimbleengineer21/doorcheck)"

Get = Callable[[str], bytes]


class DownloadError(DoorcheckError):
    """A download was refused, failed or was too large."""

    key = "problem.download_failed"


def check_url(url: str, hosts: frozenset[str]) -> None:
    try:
        parts = urlsplit(url)
        allowed = parts.scheme == "https" and parts.hostname in hosts
        authority = parts.username is None and parts.password is None and parts.port in (None, 443)
    except ValueError as error:
        raise DownloadError(
            f"refusing to download from {url}", "problem.download_refused"
        ) from error
    if not allowed or not authority:
        raise DownloadError(f"refusing to download from {url}", "problem.download_refused")


class AllowedRedirects(urllib.request.HTTPRedirectHandler):
    def __init__(self, hosts: frozenset[str]) -> None:
        self.hosts = hosts

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> urllib.request.Request | None:
        check_url(newurl, self.hosts)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def opener(
    hosts: frozenset[str], *handlers: urllib.request.BaseHandler
) -> urllib.request.OpenerDirector:
    """An opener whose redirects can only lead to `hosts`."""
    return urllib.request.build_opener(AllowedRedirects(hosts), *handlers)


def get(
    url: str,
    hosts: frozenset[str],
    limit: int,
    using: urllib.request.OpenerDirector | None = None,
) -> bytes:
    check_url(url, hosts)
    active = using or opener(hosts)
    # The URL was checked above (S310).
    headers = {"User-Agent": USER_AGENT}  # pragma: no mutate - header names ignore case
    request = urllib.request.Request(url, headers=headers)  # noqa: S310
    try:
        with active.open(request, timeout=TIMEOUT_SECONDS) as response:
            data: bytes = response.read(limit + 1)
    except urllib.error.HTTPError as error:
        key = "problem.download_not_found" if error.code == 404 else "problem.download_failed"
        raise DownloadError(f"download failed for {url}: {error}", key) from error
    except (OSError, HTTPException) as error:  # URLError and timeouts are OSErrors
        raise DownloadError(f"download failed for {url}: {error}") from error
    if len(data) > limit:
        raise DownloadError(
            f"download from {url} is over {limit} bytes", "problem.download_too_large"
        )
    return data
