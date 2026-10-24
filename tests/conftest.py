import hashlib
import json
import os
import subprocess
import urllib.request
import urllib.response
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
