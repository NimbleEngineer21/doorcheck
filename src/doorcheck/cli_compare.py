"""Bounded offline report loading and command-line comparison output."""

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

from doorcheck.cli_output import report_body, single_line
from doorcheck.cli_report import exit_code, read_report
from doorcheck.comparison import Comparison, comparability, compare
from doorcheck.messages import render
from doorcheck.report import Report, to_dict


def metadata_matches(change: Comparison) -> bool:
    return comparability(change.before, change.after).matches


def _projections(change: Comparison) -> tuple[Report, Report]:
    added = replace(
        change.after, capabilities=change.capabilities.added, findings=change.findings.added
    )
    removed = replace(
        change.before, capabilities=change.capabilities.removed, findings=change.findings.removed
    )
    return added, removed


def as_dict(change: Comparison) -> dict[str, Any]:
    added, removed = map(to_dict, _projections(change))
    return {
        "schema_version": 1,
        "metadata_matches": metadata_matches(change),
        "before": to_dict(change.before),
        "after": to_dict(change.after),
        "added": {"capabilities": added["capabilities"], "findings": added["findings"]},
        "removed": {"capabilities": removed["capabilities"], "findings": removed["findings"]},
    }


def _versions(report: Report) -> str:
    lines = [render("cli.compare_engine", {"version": single_line(report.doorcheck_version)})]
    if report.target.version is not None:
        lines.append(render("cli.compare_version", {"version": single_line(report.target.version)}))
    for check in report.checks:
        lines.append(
            render(
                "cli.compare_check_version",
                {"check": single_line(check.name), "version": single_line(check.version)},
            )
        )
    return "\n".join(lines) + "\n"


def human_comparison(change: Comparison) -> str:
    added, removed = _projections(change)
    limits = comparability(change.before, change.after).limits
    status = render("cli.compare_limited") if limits else render("cli.compare_matched")
    reasons = [render("comparison." + limit.value) for limit in limits]
    return "\n".join(
        [
            render("cli.compare_scope"),
            status,
            *reasons,
            render("cli.compare_removed"),
            _versions(removed) + report_body(removed),
            render("cli.compare_added"),
            _versions(added) + report_body(added),
        ]
    )


def command(before: Path, after: Path, *, json_output: bool) -> tuple[str, int]:
    change = compare(read_report(before), read_report(after))
    output = json.dumps(as_dict(change)) + "\n" if json_output else human_comparison(change)
    code = exit_code(_projections(change)[0]) if metadata_matches(change) else 2
    return output, code
