"""Local, offline scan orchestration for the command-line surface."""

import stat
from importlib.metadata import version
from pathlib import Path

from doorcheck import capabilities, rules
from doorcheck.checks import Check, Problem, Status, status_for
from doorcheck.findings import Severity
from doorcheck.report import Report, Target


def scan_folder(root: Path) -> Report:
    installed = version("doorcheck")  # pragma: no mutate - package names ignore case
    try:
        mode = root.lstat().st_mode
    except OSError:
        return _invalid(root, installed)
    if not stat.S_ISDIR(mode):
        return _invalid(root, installed)
    observed = capabilities.scan(root)
    detected = rules.scan(root)
    checks = (
        Check("capabilities", installed, status_for(observed.problems), observed.problems),
        Check("python-rules", installed, status_for(detected.problems), detected.problems),
    )
    return Report(installed, Target(str(root)), checks, observed.capabilities, detected.findings)


def _invalid(root: Path, installed: str) -> Report:
    check = Check(
        "local-target", installed, Status.FAILED, (Problem("problem.target_not_directory"),)
    )
    return Report(installed, Target(str(root)), (check,), (), ())


def exit_code(report: Report) -> int:
    """Coverage gaps take precedence over findings, including when both exist."""
    if any(check.status in (Status.PARTIAL, Status.FAILED) for check in report.checks):
        return 2
    if any(finding.severity in (Severity.REVIEW, Severity.SERIOUS) for finding in report.findings):
        return 1
    return 0
