"""zizmor, for GitHub Actions workflows: offline, so it never calls GitHub.

Workflows are never installed, so this is for authors, not for people deciding
whether to install. The scanned repo can't change what zizmor reports: its
`zizmor.yml`, its ignore comments and its `.gitignore` are all ignored.
"""

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from doorcheck.adapters.base import (
    Audience,
    Command,
    Parsed,
    ScanInput,
    relative,
)
from doorcheck.findings import Confidence, Finding, Location, Severity, evidence, param

SEVERITIES = {
    "high": Severity.SERIOUS,
    "medium": Severity.REVIEW,
    "low": Severity.NOTICE,
    "informational": Severity.INFO,
}
NO_INPUTS = 3
FLAGS = (
    *("--format", "json-v1", "--offline", "--no-exit-codes", "--no-progress"),
    *("--collect=all", "--no-config", "--no-ignores"),
)
CONFIDENCES = {"high": Confidence.HIGH, "medium": Confidence.MEDIUM, "low": Confidence.LOW}


class Zizmor:
    name = "zizmor"
    version = "1.31.1"  # renovate: datasource=pypi depName=zizmor
    audience = Audience.AUTHORS
    experimental = False

    def __init__(self, executable: str = "zizmor") -> None:
        self.executable = executable

    def version_command(self) -> Sequence[str]:
        return (self.executable, "--version")

    def command(self, scan: ScanInput, work: Path) -> Command | Parsed:
        if not (scan.root / ".github").is_dir():
            return Parsed()
        # Exit code 3: no workflows or other inputs to audit (docs/usage.md, zizmor 1.21+).
        return Command((self.executable, *FLAGS, "."), scan.root, frozenset({0, NO_INPUTS}))

    def parse(self, output: bytes, scan: ScanInput) -> Parsed:
        if not output.strip():
            if _workflow_files(scan.root):
                raise ValueError("zizmor audited nothing, but the repo has workflow files")
            return Parsed()
        return Parsed(tuple(_finding(item, scan.root) for item in json.loads(output)))


def _workflow_files(root: Path) -> list[Path]:
    return [p for p in (root / ".github").rglob("*") if p.suffix in (".yml", ".yaml")]


def _finding(item: Any, target: Path) -> Finding:
    determinations = item["determinations"]
    locations = item["locations"]
    primary = next(loc for loc in locations if loc["symbolic"]["kind"] == "Primary")
    key = primary["symbolic"]["key"]
    concrete = primary["concrete"]
    start = concrete["location"]["start_point"]
    return Finding(
        rule_id=f"zizmor/{item['ident']}",
        severity=SEVERITIES.get(determinations["severity"].lower(), Severity.REVIEW),
        confidence=CONFIDENCES.get(determinations["confidence"].lower(), Confidence.LOW),
        location=Location(
            relative(key["Local"]["verbatim_path"], target), start["row"] + 1, start["column"] + 1
        ),
        message_key="finding.tool_reported",
        tool=Zizmor.name,
        evidence=evidence(str(concrete["feature"])) or None,
        params={"message": param(str(item["desc"]))},
    )
