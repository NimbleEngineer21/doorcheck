"""Helpers shared by the adapter tests."""

import json
from pathlib import Path

from doorcheck.adapters import Parsed, ScanInput
from doorcheck.checks import Problem
from doorcheck.dependencies import Dependencies, Pin, Unresolved, resolve
from doorcheck.findings import Finding, Location
from doorcheck.requirements import PypiRequirement

FIXTURES = Path(__file__).parent / "fixtures"
UNSAFE = FIXTURES / "integrations" / "unsafe"
CLEAN = FIXTURES / "integrations" / "clean"
# What PyPI answered when the output was recorded: the newest release `icmplib>=3.0` allows.
RECORDED_VERSIONS = {"icmplib": "3.0.4"}


def dump(value: object) -> bytes:
    return json.dumps(value).encode()


def at(root: Path, dependencies: Dependencies | None = None) -> ScanInput:
    return ScanInput(root, dependencies or Dependencies())


def only(parsed: Parsed) -> Finding:
    assert parsed.problems == ()
    (finding,) = parsed.findings
    return finding


def recorded(tool: str, case: str) -> bytes:
    return (FIXTURES / "tools" / tool / f"{case}.json").read_bytes()


def recorded_resolver(requirement: PypiRequirement) -> str:
    return requirement.pinned_version or RECORDED_VERSIONS[requirement.name]


def as_recorded(root: Path) -> ScanInput:
    """The scan input the recordings were made with."""
    return ScanInput(root, resolve(root, recorded_resolver))


def summary(findings: tuple[Finding, ...]) -> list[tuple[object, ...]]:
    return [
        (f.rule_id, f.severity, f.confidence, f.location.path, f.location.line, f.location.column)
        for f in findings
    ]


PINS = (Pin(PypiRequirement("a", "==1"), 3), Pin(PypiRequirement("Foo_Bar", "==1.9"), 4))
GAPS = (
    Unresolved("-r /etc/passwd", 5, "problem.requirement_outside_pypi"),
    Unresolved("gone", 6, "problem.download_not_found"),
)
DEPENDENCIES = Dependencies(PINS, GAPS)
GAP_PROBLEMS = (
    Problem(
        "problem.requirement_outside_pypi",
        Location("manifest.json", 5),
        {"requirement": "-r /etc/passwd"},
    ),
    Problem("problem.download_not_found", Location("manifest.json", 6), {"requirement": "gone"}),
)
