"""Downloads for fetching an integration: GitHub only, see doorcheck.https."""

import urllib.request

from doorcheck import https
from doorcheck.fetch.archive import MAX_BYTES
from doorcheck.fetch.errors import FetchError
from doorcheck.https import Get

GITHUB_HOSTS = frozenset(
    {
        "github.com",
        "codeload.github.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
    }
)

__all__ = ["GITHUB_HOSTS", "Get", "github_opener", "https_get"]


def github_opener(*handlers: urllib.request.BaseHandler) -> urllib.request.OpenerDirector:
    return https.opener(GITHUB_HOSTS, *handlers)


def https_get(
    url: str, limit: int = MAX_BYTES, opener: urllib.request.OpenerDirector | None = None
) -> bytes:
    try:
        return https.get(url, GITHUB_HOSTS, limit, opener or github_opener())
    except https.DownloadError as error:
        raise FetchError(str(error), error.key) from error
