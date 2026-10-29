"""Plain terminal output. Source values cannot add terminal control sequences."""

from doorcheck.capabilities.model import Capability
from doorcheck.findings import Location
from doorcheck.messages import render, render_capability
from doorcheck.report import Report
from doorcheck.text import display_safe


def single_line(value: str) -> str:
    # Shared rendering preserves newlines/tabs for prose. Source fields must not
    # manufacture new rows that look like trusted check statuses or findings.
    return display_safe(value).replace("\n", "⟨U+000A⟩").replace("\t", "⟨U+0009⟩")


def _location(location: Location | None) -> str:
    if location is None:
        return "-"
    return single_line(f"{location.path}:{location.line}")


def report_body(report: Report, *, capabilities: tuple[Capability, ...] | None = None) -> str:
    lines = [render("cli.target", {"target": single_line(report.target.name)})]
    if report.target.version is not None:
        lines.append(render("cli.version", {"version": single_line(report.target.version)}))
    if report.target.commit is not None:
        lines.append(render("cli.commit", {"commit": single_line(report.target.commit)}))
    if report.target.artifact_sha256 is not None:
        lines.append(render("cli.digest", {"digest": single_line(report.target.artifact_sha256)}))
    for check in report.checks:
        lines.append(
            render(
                "cli.check",
                {"check": single_line(check.name), "status": render(f"status.{check.status}")},
            )
        )
        for problem in check.problems:
            lines.append(
                render(
                    "cli.problem",
                    {
                        "location": _location(problem.location),
                        "message": single_line(render(problem.key, problem.params)),
                    },
                )
            )
    for finding in report.findings:
        lines.append(
            render(
                "cli.finding",
                {
                    "severity": render(f"severity.{finding.severity}"),
                    "location": _location(finding.location),
                    "rule": finding.rule_id,
                    "message": single_line(render(finding.message_key, finding.params)),
                },
            )
        )
    selected = report.capabilities if capabilities is None else capabilities
    for capability in selected:
        lines.append(
            render(
                "cli.capability",
                {
                    "location": _location(capability.location),
                    "message": single_line(render_capability(capability)),
                },
            )
        )
    lines.append(
        render(
            "cli.counts",
            {"findings": str(len(report.findings)), "observations": str(len(report.capabilities))},
        )
    )
    return "\n".join(lines) + "\n"


def human(report: Report) -> str:
    return report_body(report) + render("cli.scope") + "\n"
