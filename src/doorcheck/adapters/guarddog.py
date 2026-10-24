"""GuardDog, Datadog's heuristics for malicious packages, in two places:
the integration's own code, and the PyPI packages its manifest installs.

Both are experimental: off unless asked for. On the benchmark corpus GuardDog's
`threat-*` rules matched no known bug and fired on 11 of 75 benign
integrations, on unit symbols, Cyrillic labels and town-name tables, and its
package-metadata rules (typosquatting, a maintainer's lapsed email domain)
flagged only benign packages. That changes when the malicious test set shows a
rule earns it. Until then code heuristics are information and metadata rules
are notices.

A check GuardDog couldn't run, and a requirement it didn't report on at all,
are recorded as not covered: a gap in the scan is shown, never passed off as clean.
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
from doorcheck.checks import Problem
from doorcheck.dependencies import MANIFEST, Pin, pins_file, unresolved_problem
from doorcheck.findings import Confidence, Finding, Location, Severity, evidence, param
from doorcheck.requirements import normalized


class GuardDog:
    """The integration's own files."""

    name = "guarddog"
    version = "3.2.0"  # renovate: datasource=pypi depName=guarddog
    audience = Audience.USERS
    experimental = True

    def __init__(self, executable: str = "guarddog") -> None:
        self.executable = executable

    def version_command(self) -> Sequence[str]:
        return (self.executable, "--version")

    def command(self, scan: ScanInput, work: Path) -> Command | Parsed:
        argv = (self.executable, "pypi", "scan", ".", "--output-format", "json")
        return Command(argv, scan.root)

    def parse(self, output: bytes, scan: ScanInput) -> Parsed:
        report = json.loads(output)
        findings = tuple(
            _code_finding(rule, match, self.name, Location(*_place(match, scan.root)), {})
            for rule, matches in sorted(report["results"].items())
            if isinstance(matches, list)  # rules with no match, and metadata rules, aren't
            for match in matches
        )
        return Parsed(findings, tuple(_check_failures(report["errors"], None, {})))


class GuardDogDependencies:
    """The PyPI packages manifest.json installs, at the version a fresh install gets.
    GuardDog misreads a range with more than one bound as a version, so it gets
    exact pins (doorcheck.dependencies)."""

    name = "guarddog-dependencies"
    version = GuardDog.version
    audience = Audience.USERS
    experimental = True

    def __init__(self, executable: str = "guarddog") -> None:
        self.executable = executable

    def version_command(self) -> Sequence[str]:
        return (self.executable, "--version")

    def command(self, scan: ScanInput, work: Path) -> Command | Parsed:
        dependencies = scan.dependencies
        if not dependencies.pins:
            return Parsed(problems=tuple(map(unresolved_problem, dependencies.unresolved)))
        (work / "requirements.txt").write_text(pins_file(dependencies.pins))
        argv = (self.executable, "pypi", "verify", "requirements.txt", "--output-format", "json")
        return Command(argv, work)

    def parse(self, output: bytes, scan: ScanInput) -> Parsed:
        pins = {normalized(pin.requirement.name): pin for pin in scan.dependencies.pins}
        unreported = dict(pins)
        findings: list[Finding] = []
        problems = list(map(unresolved_problem, scan.dependencies.unresolved))
        for item in json.loads(output):
            package = normalized(item["dependency"])
            unreported.pop(package, None)
            here = Location(MANIFEST, pins[package].line if package in pins else 1)
            about = {"package": param(item["dependency"]), "version": param(item["version"])}
            found, failed = _package_results(item["result"], self.name, here, about)
            findings += found
            problems += failed
        # GuardDog leaves out, without an error, a package it couldn't download.
        problems += [_not_checked(pin) for pin in unreported.values()]
        return Parsed(tuple(findings), tuple(problems))


def _package_results(
    result: Any, tool: str, here: Location, about: dict[str, str]
) -> tuple[list[Finding], list[Problem]]:
    findings = []
    for rule, matches in sorted(result.get("results", {}).items()):  # absent if not downloaded
        if isinstance(matches, list):
            findings += [
                _code_finding(rule, m, tool, here, {**about, "file": param(m["location"])})
                for m in matches
            ]
        elif isinstance(matches, str) and matches:
            findings.append(_metadata_finding(rule, matches, tool, here, about))
    return findings, _check_failures(result["errors"], here, about)


def _code_finding(
    rule: str, match: Any, tool: str, here: Location, about: dict[str, str]
) -> Finding:
    return Finding(
        rule_id=f"{tool}/{_rule_name(rule)}",
        severity=Severity.INFO,
        confidence=Confidence.LOW,
        location=here,
        message_key="finding.tool_reported",
        tool=tool,
        evidence=evidence(match["code"]) or None,
        params={**about, "message": param(match["message"])},
    )


def _metadata_finding(
    rule: str, message: str, tool: str, here: Location, about: dict[str, str]
) -> Finding:
    return Finding(
        rule_id=f"{tool}/{_rule_name(rule)}",
        severity=Severity.NOTICE,
        confidence=Confidence.LOW,
        location=here,
        message_key="finding.tool_reported",
        tool=tool,
        params={**about, "message": param(message)},
    )


def _check_failures(errors: Any, here: Location | None, about: dict[str, str]) -> list[Problem]:
    return [
        Problem(
            "problem.tool_check_failed",
            here,
            {**about, "check": param(rule), "detail": param(str(message))},
        )
        for rule, message in sorted(errors.items())
    ]


def _not_checked(pin: Pin) -> Problem:
    params = {"requirement": param(str(pin.requirement))}
    return Problem("problem.dependency_not_checked", Location(MANIFEST, pin.line), params)


def _place(match: Any, target: Path) -> tuple[str, int]:
    path, _, line = match["location"].rpartition(":")
    return relative(path, target), int(line)


def _rule_name(rule: str) -> str:
    return rule.replace("_", "-")
