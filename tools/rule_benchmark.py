"""Benchmark adapter: incomplete source reads must not look like clean cases."""

from pathlib import Path

from doorcheck.findings import Finding
from doorcheck.rules import scan


def findings(folder: Path) -> tuple[Finding, ...]:
    result = scan(folder)
    if result.problems:
        raise RuntimeError(f"{folder.name}: rule scan incomplete ({len(result.problems)} gaps)")
    return result.findings
