"""Built-in scan orchestration for the command-line surface."""

import stat
from collections.abc import Callable
from dataclasses import replace
from importlib.metadata import version
from pathlib import Path
from tempfile import TemporaryDirectory

from doorcheck import capabilities, rules
from doorcheck.adapters.base import ScanInput, run
from doorcheck.adapters.semgrep import Semgrep
from doorcheck.checks import Check, Problem, Status, status_for
from doorcheck.cli_report import exit_code as exit_code
from doorcheck.fetch import FetchError, Installed, from_commit, from_repo
from doorcheck.report import Report, Target


def scan_repository(repo: str, commit: str, *, semgrep_rules: tuple[Path, ...] = ()) -> Report:
    """Fetch an explicit commit, scan installed files, then remove the snapshot."""
    return _remote(repo, commit, from_commit, semgrep_rules)


def scan_release(repo: str, tag: str, *, semgrep_rules: tuple[Path, ...] = ()) -> Report:
    """Fetch an explicit tag and scan the selected installed files, including assets."""
    return _remote(repo, tag, from_repo, semgrep_rules)


def _remote(
    repo: str,
    revision: str,
    fetch: Callable[[str, str, Path], Installed],
    semgrep_rules: tuple[Path, ...],
) -> Report:
    installed_version = version("doorcheck")  # pragma: no mutate - package names ignore case
    try:
        with TemporaryDirectory() as temporary:
            # The private child name has no effect on scan results or cleanup.
            destination = Path(temporary) / "source"  # pragma: no mutate - arbitrary private name
            installed = fetch(repo, revision, destination)
            report = scan_folder(installed.root, semgrep_rules=semgrep_rules)
            fetched = Check("fetch", installed_version, Status.COMPLETE)
            return replace(report, target=installed.target, checks=(fetched, *report.checks))
    except FetchError as error:
        return _fetch_failed(repo, installed_version, error.key)
    except OSError:
        return _fetch_failed(repo, installed_version, "problem.fetch_failed")


def _fetch_failed(repo: str, installed_version: str, key: str) -> Report:
    check = Check("fetch", installed_version, Status.FAILED, (Problem(key),))
    return Report(installed_version, Target(repo), (check,), (), ())


def scan_folder(root: Path, *, semgrep_rules: tuple[Path, ...] = ()) -> Report:
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
    report = Report(installed, Target(str(root)), checks, observed.capabilities, detected.findings)
    if not semgrep_rules:
        return report
    result = run(Semgrep(semgrep_rules), ScanInput(root))
    # Operator-supplied rule messages are data, not shared-catalog template keys.
    findings = tuple(replace(f, message_key="finding.tool_reported") for f in result.findings)
    return replace(
        report, checks=(*report.checks, result.check), findings=(*report.findings, *findings)
    )


def _invalid(root: Path, installed: str) -> Report:
    check = Check(
        "local-target", installed, Status.FAILED, (Problem("problem.target_not_directory"),)
    )
    return Report(installed, Target(str(root)), (check,), (), ())
