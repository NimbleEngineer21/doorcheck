"""OSV-Scanner, for known vulnerabilities in the PyPI packages an integration installs.

OSV-Scanner needs exact versions, so it gets each requirement pinned to the
version a fresh install gets (doorcheck.dependencies), rebuilt from its parts
so a manifest can't pass requirement-file options such as `-r /etc/passwd`.
A requirement that couldn't be pinned is reported as not covered.

OSV also lists packages known to be malicious (`MAL-` advisories). Those carry no
severity score, so they are rated here instead of by score.
"""

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from doorcheck.adapters.base import Audience, Command, Parsed, ScanInput
from doorcheck.dependencies import MANIFEST, pins_file, unresolved_problem
from doorcheck.findings import Confidence, Finding, Location, Severity, param
from doorcheck.requirements import normalized

MALICIOUS = "MAL-"


class OsvScanner:
    name = "osv-scanner"
    version = "2.7.0"  # also pinned with its SHA-256 in .github/workflows/ci.yml
    audience = Audience.USERS
    experimental = False

    def __init__(self, executable: str = "osv-scanner") -> None:
        self.executable = executable

    def version_command(self) -> Sequence[str]:
        return (self.executable, "--version")

    def command(self, scan: ScanInput, work: Path) -> Command | Parsed:
        dependencies = scan.dependencies
        if not dependencies.pins:
            return Parsed(problems=tuple(map(unresolved_problem, dependencies.unresolved)))
        (work / "requirements.txt").write_text(pins_file(dependencies.pins))
        flags = ("--format", "json", "--no-resolve", "-L", "requirements.txt")
        # Exit code 1 means vulnerabilities were found.
        return Command((self.executable, "scan", "source", *flags), work, frozenset({0, 1}))

    def parse(self, output: bytes, scan: ScanInput) -> Parsed:
        lines = {normalized(pin.requirement.name): pin.line for pin in scan.dependencies.pins}
        findings = tuple(
            _finding(entry["package"], group, entry["vulnerabilities"], lines)
            for result in json.loads(output)["results"]
            for entry in result["packages"]
            for group in entry["groups"]
        )
        return Parsed(findings, tuple(map(unresolved_problem, scan.dependencies.unresolved)))


def _finding(package: Any, group: Any, vulns: Any, lines: dict[str, int]) -> Finding:
    ids = group["ids"]
    summary = next((str(v.get("summary") or "") for v in vulns if v["id"] in ids), "")
    name, version = package["name"], package["version"]
    malicious = any(str(i).startswith(MALICIOUS) for i in ids)
    return Finding(
        rule_id="osv/malicious-package" if malicious else "osv/known-vulnerability",
        severity=Severity.SERIOUS if malicious else _severity(group.get("max_severity")),
        confidence=Confidence.HIGH,
        location=Location(MANIFEST, lines.get(normalized(name), 1)),
        message_key="finding.malicious_package" if malicious else "finding.known_vulnerability",
        tool=OsvScanner.name,
        params={
            "package": param(name),
            "version": param(version),
            "ids": param(", ".join(ids)),
            "summary": param(summary),
        },
    )


def _severity(score: object) -> Severity:
    """From the group's highest CVSS score; an unscored advisory is still worth a look."""
    try:
        value = float(str(score))
    except ValueError:
        return Severity.REVIEW
    if value >= 7:
        return Severity.SERIOUS
    return Severity.REVIEW if value >= 4 else Severity.NOTICE
