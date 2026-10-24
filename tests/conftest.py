import subprocess
from pathlib import Path
from typing import Any

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
