"""Bounded strict loading shared by offline report commands."""

import json
from pathlib import Path
from typing import Any

from doorcheck.checks import Status
from doorcheck.errors import DoorcheckError
from doorcheck.findings import Severity
from doorcheck.messages import MessageError, render
from doorcheck.report import Report, from_dict
from doorcheck.tree import read_regular

MAX_REPORT_BYTES = 20 * 1024 * 1024


class ReportInputError(DoorcheckError):
    """A report cannot be read and explained with this version of Doorcheck."""

    key = "cli.report_invalid"


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def read_report(path: Path) -> Report:
    try:
        data = read_regular(path, MAX_REPORT_BYTES + 1)
        if len(data) > MAX_REPORT_BYTES:
            raise ValueError
        report = from_dict(json.loads(data.decode(), object_pairs_hook=_unique_object))
        # Validate unchanged messages too, so text and JSON accept the same inputs.
        for finding in report.findings:
            render(finding.message_key, finding.params)
        for check in report.checks:
            for problem in check.problems:
                render(problem.key, problem.params)
        return report
    except (OSError, ValueError, RecursionError, MessageError) as error:
        raise ReportInputError(str(path)) from error


def exit_code(report: Report) -> int:
    """Coverage gaps take precedence over findings, including when both exist."""
    if any(check.status in (Status.PARTIAL, Status.FAILED) for check in report.checks):
        return 2
    if any(finding.severity in (Severity.REVIEW, Severity.SERIOUS) for finding in report.findings):
        return 1
    return 0
