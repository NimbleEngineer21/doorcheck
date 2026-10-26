"""Export a report as SARIF 2.1.0, for GitHub code scanning and other CI tools.

Findings hold message keys, not text, so the caller supplies a renderer that
turns a key and its parameters into a sentence. What a check couldn't cover is
reported as a tool notification, and a failed check marks the run as not
successful, so CI never reads a gap as a clean result.
"""

from collections.abc import Callable, Mapping
from typing import Any
from urllib.parse import quote

from doorcheck.checks import Problem, Status
from doorcheck.findings import Finding, Location, Severity
from doorcheck.report import Report

Renderer = Callable[[str, Mapping[str, str]], str]

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/nimbleengineer21/doorcheck"

# SARIF level, and GitHub's numeric security-severity (None: no security rating).
_LEVELS: Mapping[Severity, tuple[str, str | None]] = {
    Severity.SERIOUS: ("error", "8.0"),
    Severity.REVIEW: ("warning", "5.0"),
    Severity.NOTICE: ("note", "2.0"),
    Severity.INFO: ("none", None),
}


def to_sarif(report: Report, render: Renderer) -> dict[str, Any]:
    driver = {
        "name": "Doorcheck",
        "version": report.doorcheck_version,
        "informationUri": INFORMATION_URI,
        "rules": _rules(report.findings),
    }
    run = {
        "tool": {"driver": driver},
        "invocations": [_invocation(report, render)],
        "results": [_result(f, render) for f in report.findings],
    }
    return {"version": SARIF_VERSION, "$schema": SARIF_SCHEMA, "runs": [run]}


def _invocation(report: Report, render: Renderer) -> dict[str, Any]:
    return {
        "executionSuccessful": all(c.status is not Status.FAILED for c in report.checks),
        "toolExecutionNotifications": [
            _notification(check.name, problem, render)
            for check in report.checks
            for problem in check.problems
        ],
    }


def _notification(check: str, problem: Problem, render: Renderer) -> dict[str, Any]:
    notification: dict[str, Any] = {
        "descriptor": {"id": check},
        "level": "warning",
        "message": {"text": render(problem.key, problem.params)},
        "properties": {"key": problem.key},
    }
    if problem.location is not None:
        notification["locations"] = [_location(problem.location)]
    return notification


def _location(loc: Location) -> dict[str, Any]:
    region: dict[str, Any] = {"startLine": loc.line}
    if loc.column is not None:
        region["startColumn"] = loc.column
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": quote(loc.path)},
            "region": region,
        }
    }


def _rules(findings: tuple[Finding, ...]) -> list[dict[str, Any]]:
    """One entry per rule, rated by its most urgent finding."""
    worst: dict[str, Finding] = {}
    for finding in findings:
        current = worst.get(finding.rule_id)
        if current is None or finding.severity.rank < current.severity.rank:
            worst[finding.rule_id] = finding
    return [_rule(worst[rule_id]) for rule_id in sorted(worst)]


def _rule(finding: Finding) -> dict[str, Any]:
    level, security_severity = _LEVELS[finding.severity]
    tags = ["security"] + ([f"external/cwe/cwe-{finding.cwe}"] if finding.cwe else [])
    properties: dict[str, Any] = {"tags": tags}
    if security_severity is not None:
        properties["security-severity"] = security_severity
    return {
        "id": finding.rule_id,
        "defaultConfiguration": {"level": level},
        "properties": properties,
    }


def _result(finding: Finding, render: Renderer) -> dict[str, Any]:
    location = _location(finding.location)
    if finding.evidence is not None:
        location["physicalLocation"]["region"]["snippet"] = {"text": finding.evidence}
    return {
        "ruleId": finding.rule_id,
        "level": _LEVELS[finding.severity][0],
        "message": {"text": render(finding.message_key, finding.params)},
        "locations": [location],
        "partialFingerprints": {"doorcheck/v1": finding.fingerprint},
        "properties": {"confidence": finding.confidence.value, "tool": finding.tool},
    }
