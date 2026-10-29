"""Offline host evidence summaries with the original report and coverage retained."""

import json
from pathlib import Path
from typing import Any

from doorcheck.checks import Status
from doorcheck.cli_output import report_body, single_line
from doorcheck.cli_report import read_report
from doorcheck.cli_scan import exit_code
from doorcheck.hosts import Evidence, HostSummary, summarize
from doorcheck.messages import render, render_capability
from doorcheck.report import capability_to_dict, to_dict

LABELS = {
    "mentions": "cli.hosts_mentions",
    "requests": "cli.hosts_requests",
    "frontend_scripts": "cli.hosts_frontend_scripts",
}


def _evidence_dict(evidence: Evidence) -> dict[str, Any]:
    return {
        "mentions": [capability_to_dict(c) for c in evidence.mentions],
        "requests": [capability_to_dict(c) for c in evidence.requests],
        "frontend_scripts": [capability_to_dict(c) for c in evidence.frontend_scripts],
    }


def as_dict(summary: HostSummary) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "report": to_dict(summary.report),
        "hosts": [
            {"subject": host.subject, **_evidence_dict(host.evidence)} for host in summary.hosts
        ],
        "unresolved": _evidence_dict(summary.unresolved),
    }


def _evidence_lines(evidence: Evidence) -> list[str]:
    lines = []
    for role, label in LABELS.items():
        for capability in getattr(evidence, role):
            loc = capability.location
            location = f"{loc.path}:{loc.line}"
            if loc.column is not None:
                location += f":{loc.column}"
            lines.append(
                render(
                    "cli.hosts_evidence",
                    {
                        "kind": render(label),
                        "location": single_line(location),
                        "message": single_line(render_capability(capability)),
                    },
                )
            )
    return lines


def human(summary: HostSummary) -> str:
    lines = [render("cli.hosts_scope"), report_body(summary.report, capabilities=())]
    if not summary.report.checks:
        lines.append(render("cli.hosts_checks_absent"))
    for host in summary.hosts:
        lines.append(render("cli.hosts_subject", {"subject": single_line(host.subject)}))
        lines.extend(_evidence_lines(host.evidence))
    unresolved = _evidence_lines(summary.unresolved)
    if unresolved:
        lines.append(render("cli.hosts_unresolved"))
        lines.extend(unresolved)
    if not summary.hosts and not unresolved:
        lines.append(render("cli.hosts_empty"))
    return "\n".join(lines) + "\n"


def command(path: Path, *, json_output: bool) -> tuple[str, int]:
    summary = summarize(read_report(path))
    output = json.dumps(as_dict(summary)) + "\n" if json_output else human(summary)
    checks = summary.report.checks
    code = (
        exit_code(summary.report)
        if checks and all(check.status is Status.COMPLETE for check in checks)
        else 2
    )
    return output, code
