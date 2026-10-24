"""Semgrep, running doorcheck's own rule files.

By default Semgrep skips files the scanned code itself asks it to skip (its own
.semgrepignore), untracked or git-ignored files, and files over 1 MB, and it
drops any match on a line marked `# nosemgrep`, all without an error. Scanned
code is untrusted, so Semgrep is given every file by name, which no ignore file
applies to, with the size limit and suppression comments off. A Python file it
still didn't scan is reported as not covered.

Semgrep's own Python parser lags behind Python: 1.182 can't read `type X = ...`
(Python 3.12). A file it couldn't read is reported as not covered too; any
other Semgrep error fails the run.

Semgrep's free engine replaces the matched code with "requires login" in its
JSON, so the evidence is read from the scanned file instead.
"""

import json
import re
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from doorcheck.adapters.base import (
    Audience,
    Command,
    Parsed,
    ScanInput,
    ToolError,
    relative,
)
from doorcheck.checks import Problem
from doorcheck.findings import Confidence, Finding, Location, Severity, evidence, param
from doorcheck.tree import entries

SEVERITIES = {
    "CRITICAL": Severity.SERIOUS,
    "HIGH": Severity.SERIOUS,
    "ERROR": Severity.SERIOUS,
    "MEDIUM": Severity.REVIEW,
    "WARNING": Severity.REVIEW,
    "LOW": Severity.NOTICE,
    "INFO": Severity.NOTICE,
}
CWE = re.compile(r"CWE-(\d+)")
ERROR_LINE = re.compile(r":(\d+):")
FLAGS = ("--json", "--metrics=off", "--disable-version-check", "--quiet", "--no-rewrite-rule-ids")
SCAN_EVERYTHING = ("--no-git-ignore", "--project-root=.", "--max-target-bytes=0", "--disable-nosem")
MAX_ARGUMENT_BYTES = 1_000_000  # well under the usual 2 MB limit for a command line


class Semgrep:
    name = "semgrep"
    version = "1.182.0"  # renovate: datasource=pypi depName=semgrep
    audience = Audience.USERS
    experimental = False

    def __init__(self, rules: Sequence[Path] = (), executable: str = "semgrep") -> None:
        self.rules = tuple(rules)
        self.executable = executable

    def version_command(self) -> Sequence[str]:
        return (self.executable, "--version", "--disable-version-check")

    def command(self, scan: ScanInput, work: Path) -> Command | Parsed:
        if not self.rules:
            raise ToolError("semgrep has no rules to run", "problem.no_rules")
        files = scanned_files(scan.root)
        if not files:
            return Parsed()
        if sum(len(name) + 1 for name in files) > MAX_ARGUMENT_BYTES:
            raise ToolError(f"too many files to list ({len(files)})", "problem.too_many_files")
        configs = [part for rule in self.rules for part in ("--config", str(rule.absolute()))]
        # "--" so a file named like an option is read as a file.
        argv = (self.executable, "scan", *configs, *FLAGS, *SCAN_EVERYTHING, "--", *files)
        return Command(argv, scan.root)

    def parse(self, output: bytes, scan: ScanInput) -> Parsed:
        report = json.loads(output)
        unread = [_unread(error, scan.root) for error in report["errors"]]
        python = [name for name in scanned_files(scan.root) if name.endswith(".py")]
        scanned = set(report["paths"]["scanned"])
        skipped = [_not_scanned(name) for name in python if name not in scanned]
        findings = tuple(_finding(result, scan.root) for result in report["results"])
        return Parsed(findings, (*unread, *skipped))


def scanned_files(target: Path) -> list[str]:
    """Every regular file under target, sorted; links aren't entered or listed."""
    return sorted(entry.relative for entry in entries(target) if not entry.is_link)


def _finding(result: Any, target: Path) -> Finding:
    extra = result["extra"]
    metadata = extra.get("metadata") or {}
    path = relative(str(result["path"]), target)
    start = result["start"]
    end = result["end"]
    return Finding(
        rule_id=str(result["check_id"]),
        severity=SEVERITIES.get(str(extra["severity"]).upper(), Severity.REVIEW),
        confidence=_confidence(metadata.get("confidence")),
        location=Location(path, start["line"], start["col"]),
        message_key=str(metadata.get("message_key", "finding.tool_reported")),
        tool=Semgrep.name,
        cwe=_cwe(metadata.get("cwe")),
        evidence=_lines(target / path, start["line"], end["line"]),
        params={"message": param(str(extra["message"]))},
    )


def _unread(error: Any, target: Path) -> Problem:
    """A file Semgrep couldn't parse; any other error is a failure."""
    if error.get("type") != "Syntax error" or "path" not in error:
        raise ValueError(f"semgrep reported an error: {error}")
    message = str(error.get("message", ""))
    line = ERROR_LINE.search(message)
    path = relative(str(error["path"]), target)
    location = Location(path, int(line.group(1)) if line else 1)
    return Problem("problem.file_not_parsed", location, {"detail": param(message)})


def _not_scanned(path: str) -> Problem:
    return Problem("problem.file_not_scanned", Location(path, 1))


def _confidence(value: object) -> Confidence:
    try:
        return Confidence(str(value).lower())
    except ValueError:
        return Confidence.MEDIUM


def _cwe(value: object) -> int | None:
    """The first CWE number in Semgrep's metadata, a string or a list of strings."""
    match = CWE.search(str(value))
    return int(match.group(1)) if match else None


def _lines(path: Path, first: int, last: int) -> str | None:
    try:
        lines = path.read_bytes().decode(errors="replace").splitlines()
    except OSError:
        return None
    return evidence("\n".join(lines[first - 1 : last])) or None
