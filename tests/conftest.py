import hashlib
import io
import json
import os
import socket
import stat
import subprocess
import urllib.request
import urllib.response
import zipfile
from http.client import HTTPMessage
from pathlib import Path
from typing import Any

import pytest

from doorcheck.findings import Confidence, Finding, Location, Severity


def make_finding(**overrides: Any) -> Finding:
    fields: dict[str, Any] = {
        "rule_id": "ha-reads-credential-store",
        "severity": Severity.REVIEW,
        "confidence": Confidence.HIGH,
        "location": Location("custom_components/demo/__init__.py", 42, 9),
        "message_key": "finding.reads_credential_store",
        "tool": "doorcheck",
        "cwe": 522,
        "evidence": "open(hass.config.path('.storage/auth'))",
        "params": {"file": ".storage/auth"},
    }
    fields.update(overrides)
    return Finding(**fields)


def make_repo(root: Path, repo: str, files: dict[str, str]) -> str:
    """A local git repo at root/repo holding these files; returns its commit. Called again
    for the same repo, it adds a commit on top."""
    path = root / repo
    path.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (path / name).parent.mkdir(parents=True, exist_ok=True)
        (path / name).write_text(text)
    git = ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"]
    subprocess.run([*git, "init", "-q"], cwd=path, check=True)  # noqa: S603
    subprocess.run([*git, "add", "-A"], cwd=path, check=True)  # noqa: S603
    subprocess.run([*git, "commit", "-qm", "c"], cwd=path, check=True)  # noqa: S603
    head = subprocess.run(  # noqa: S603
        [*git, "rev-parse", "HEAD"], cwd=path, check=True, capture_output=True, text=True
    )
    return head.stdout.strip()


# The official SARIF 2.1.0 schema, pinned by commit and checked by hash. It isn't
# vendored because it's published under OASIS terms, not an open-source license.
SARIF_SCHEMA_URL = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
    "1742a253eb654bf8a4ed7c60eaef7412b2c23553/sarif-2.1/schema/sarif-schema-2.1.0.json"
)
SARIF_SCHEMA_SHA256 = "c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e"


@pytest.fixture(scope="session")
def sarif_schema(pytestconfig: pytest.Config) -> dict[str, Any]:
    cached = pytestconfig.cache.mkdir("sarif") / "sarif-schema-2.1.0.json"
    if not cached.exists():
        try:
            with urllib.request.urlopen(SARIF_SCHEMA_URL, timeout=30) as response:
                cached.write_bytes(response.read())
        except OSError as error:
            # Offline on a fresh clone. CI always has the network, so there it fails.
            if os.environ.get("CI"):
                raise
            pytest.skip(f"SARIF schema not cached and not downloadable: {error}")
    data = cached.read_bytes()
    if hashlib.sha256(data).hexdigest() != SARIF_SCHEMA_SHA256:
        cached.unlink()
        pytest.fail("Downloaded SARIF schema doesn't match its pinned hash.")
    schema: dict[str, Any] = json.loads(data)
    return schema


@pytest.fixture
def offline(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail the test if anything tries to open a network connection."""

    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("tests must not use the network")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


class FakeHTTPS(urllib.request.BaseHandler):
    """Serves canned responses: bytes for a page, (status, location) for a redirect,
    or an exception to raise. It runs before urllib's own HTTPS handler, so tests
    never reach the network."""

    handler_order = 100

    def __init__(self, pages: dict[str, object]) -> None:
        self.pages = pages
        self.timeouts: list[float] = []
        self.user_agents: list[str | None] = []

    def https_open(self, request: urllib.request.Request) -> urllib.response.addinfourl:
        self.timeouts.append(request.timeout)  # type: ignore[attr-defined]  # set by urllib
        self.user_agents.append(request.get_header("User-agent"))
        page = self.pages[request.full_url]
        if isinstance(page, BaseException):
            raise page
        headers = HTTPMessage()
        status, body = 200, page
        if isinstance(page, io.BytesIO):
            response = urllib.response.addinfourl(page, headers, request.full_url, 200)
            response.msg = "fake"
            return response
        if isinstance(page, tuple):
            status, location = page
            headers["Location"] = location
            body = b""
        response = urllib.response.addinfourl(io.BytesIO(body), headers, request.full_url, status)  # type: ignore[arg-type]
        response.msg = "fake"
        return response


class CountingBody(io.BytesIO):
    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.consumed = 0

    def read(self, size: int | None = -1) -> bytes:
        chunk = super().read(size)
        self.consumed += len(chunk)
        return chunk


LINK = object()  # marks a zip entry as a link; the value after it is the target


def make_zip(entries: dict[str, Any], comment: bytes = b"") -> bytes:
    """A zip in memory. A value is file content, None for a folder entry, or
    (LINK, target) for a link entry as git archive writes them."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.comment = comment
        for name, value in entries.items():
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED
            if value is None:
                info.external_attr = (stat.S_IFDIR | 0o755) << 16
                archive.writestr(info, b"")
            elif isinstance(value, tuple) and value[0] is LINK:
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(info, value[1])
            else:
                archive.writestr(info, value)
    return buffer.getvalue()
