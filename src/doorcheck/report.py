"""A scan report and its versioned JSON form.

A report says what was scanned, what each check covered (`checks`), what the
code can do (`capabilities`) and what deserves a look (`findings`). Without
the checks, a scan that found nothing couldn't be told apart from one that
couldn't look.

Loading is strict: unknown fields, a different schema version or invalid values
are rejected rather than guessed at, so a malformed or tampered report can't
quietly lose findings. Field validation lives in the model classes.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from doorcheck.capabilities.model import Capability, Kind
from doorcheck.checks import Check, Problem, Status
from doorcheck.findings import (
    Confidence,
    Finding,
    Location,
    Severity,
    is_int,
    is_optional_str,
    require,
    sort_key,
)

SCHEMA_VERSION = 1

_TARGET_FIELDS = frozenset({"name", "version", "commit", "artifact_sha256"})
_FINDING_FIELDS = frozenset(
    {"rule_id", "severity", "confidence", "location", "message_key"}
    | {"tool", "cwe", "evidence", "params", "fingerprint"}
)
_LOCATION_FIELDS = frozenset({"path", "line", "column"})
_CHECK_FIELDS = frozenset({"name", "version", "status", "problems"})
_PROBLEM_FIELDS = frozenset({"key", "location", "params"})
_CAPABILITY_FIELDS = frozenset({"kind", "location", "subject", "attrs"})
_REPORT_FIELDS = frozenset(
    {"schema_version", "doorcheck_version", "target", "checks", "capabilities", "findings"}
)


@dataclass(frozen=True, slots=True)
class Target:
    """What was scanned: a repo or folder, and exactly which version of it."""

    name: str
    version: str | None = None
    commit: str | None = None
    artifact_sha256: str | None = None

    def __post_init__(self) -> None:
        require(isinstance(self.name, str) and self.name, "target name is required")
        optional = (self.version, self.commit, self.artifact_sha256)
        require(all(is_optional_str(v) for v in optional), "target fields must be strings")


@dataclass(frozen=True, slots=True)
class Report:
    doorcheck_version: str
    target: Target
    checks: tuple[Check, ...]
    capabilities: tuple[Capability, ...]
    findings: tuple[Finding, ...]

    def __post_init__(self) -> None:
        require(isinstance(self.doorcheck_version, str), "doorcheck_version must be a string")
        require(isinstance(self.target, Target), "target must be a Target")
        require(all(isinstance(c, Check) for c in self.checks), "checks must be Checks")
        capabilities_ok = all(isinstance(c, Capability) for c in self.capabilities)
        require(capabilities_ok, "capabilities must be Capabilities")
        require(all(isinstance(f, Finding) for f in self.findings), "findings must be Findings")
        object.__setattr__(self, "capabilities", tuple(self.capabilities))
        names = [check.name for check in self.checks]
        require(len(names) == len(set(names)), "each check appears once")
        object.__setattr__(self, "checks", tuple(sorted(self.checks, key=lambda c: c.name)))
        object.__setattr__(self, "findings", tuple(sorted(self.findings, key=sort_key)))


def to_dict(report: Report) -> dict[str, Any]:
    target = report.target
    return {
        "schema_version": SCHEMA_VERSION,
        "doorcheck_version": report.doorcheck_version,
        "target": {key: getattr(target, key) for key in sorted(_TARGET_FIELDS)},
        "checks": [_check_to_dict(c) for c in report.checks],
        "capabilities": [capability_to_dict(c) for c in report.capabilities],
        "findings": [_finding_to_dict(f) for f in report.findings],
    }


def _location_to_dict(loc: Location | None) -> dict[str, Any] | None:
    if loc is None:
        return None
    return {"path": loc.path, "line": loc.line, "column": loc.column}


def _check_to_dict(check: Check) -> dict[str, Any]:
    return {
        "name": check.name,
        "version": check.version,
        "status": check.status.value,
        "problems": [
            {"key": p.key, "location": _location_to_dict(p.location), "params": dict(p.params)}
            for p in check.problems
        ],
    }


def capability_to_dict(capability: Capability) -> dict[str, Any]:
    return {
        "kind": capability.kind.value,
        "location": _location_to_dict(capability.location),
        "subject": capability.subject,
        "attrs": dict(capability.attrs),
    }


def _finding_to_dict(finding: Finding) -> dict[str, Any]:
    return {
        "rule_id": finding.rule_id,
        "severity": finding.severity.value,
        "confidence": finding.confidence.value,
        "location": _location_to_dict(finding.location),
        "message_key": finding.message_key,
        "tool": finding.tool,
        "cwe": finding.cwe,
        "evidence": finding.evidence,
        "params": dict(finding.params),
        "fingerprint": finding.fingerprint,
    }


def from_dict(data: object) -> Report:
    """Rebuild a report, rejecting anything this schema version doesn't define."""
    record = _record(data, _REPORT_FIELDS, "report")
    if not is_int(record["schema_version"]) or record["schema_version"] != SCHEMA_VERSION:
        raise ValueError(f"unsupported schema version: {record['schema_version']!r}")
    return Report(
        doorcheck_version=record["doorcheck_version"],
        target=Target(**_record(record["target"], _TARGET_FIELDS, "target")),
        checks=tuple(map(_check_from_dict, _list(record["checks"], "checks"))),
        capabilities=tuple(
            map(_capability_from_dict, _list(record["capabilities"], "capabilities"))
        ),
        findings=tuple(map(_finding_from_dict, _list(record["findings"], "findings"))),
    )


def _location_from_dict(data: object) -> Location:
    return Location(**_record(data, _LOCATION_FIELDS, "location"))


def _check_from_dict(data: object) -> Check:
    record = _record(data, _CHECK_FIELDS, "check")
    problems = []
    for item in _list(record["problems"], "problems"):
        problem = _record(item, _PROBLEM_FIELDS, "problem")
        location = problem["location"]
        problems.append(
            Problem(
                key=problem["key"],
                location=None if location is None else _location_from_dict(location),
                params=problem["params"],
            )
        )
    return Check(record["name"], record["version"], Status(record["status"]), tuple(problems))


def _capability_from_dict(data: object) -> Capability:
    record = _record(data, _CAPABILITY_FIELDS, "capability")
    location = _location_from_dict(record["location"])
    return Capability(Kind(record["kind"]), location, record["subject"], record["attrs"])


def _finding_from_dict(data: object) -> Finding:
    record = _record(data, _FINDING_FIELDS, "finding")
    finding = Finding(
        rule_id=record["rule_id"],
        severity=Severity(record["severity"]),
        confidence=Confidence(record["confidence"]),
        location=_location_from_dict(record["location"]),
        message_key=record["message_key"],
        tool=record["tool"],
        cwe=record["cwe"],
        evidence=record["evidence"],
        params=record["params"],
    )
    require(record["fingerprint"] == finding.fingerprint, "fingerprint doesn't match the finding")
    return finding


def _record(data: object, expected: frozenset[str], what: str) -> Mapping[str, Any]:
    """The mapping itself, if it has exactly the expected fields."""
    if not isinstance(data, Mapping) or set(data) != expected:
        raise ValueError(f"{what} must have exactly the fields {sorted(expected)}")
    return data


def _list(data: object, what: str) -> list[Any]:
    if not isinstance(data, list):
        raise ValueError(f"{what} must be a list")
    return data
