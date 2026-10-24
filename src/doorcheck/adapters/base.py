"""The one interface every scanning tool plugs into.

An adapter builds a command and reads that command's output; running it
(timeout, a clean environment, exit codes, the pinned version) is shared here,
so each tool's quirks stay inside its own adapter.

A run always ends in a Check: a tool that is missing, too slow or misbehaving
gives a failed check instead of an empty list, so a gap never looks clean.
"""

import os
import subprocess
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from doorcheck.checks import Check, Problem, Status, status_for
from doorcheck.dependencies import Dependencies, resolve
from doorcheck.errors import DoorcheckError
from doorcheck.findings import Finding, param
from doorcheck.pypi import Resolve, newest_version

TIMEOUT_SECONDS = 300
STDERR_SHOWN = 300


class ToolError(DoorcheckError):
    """A tool couldn't run, failed, or wrote output its adapter doesn't understand."""

    key = "problem.tool_failed"


class Audience(StrEnum):
    USERS = "users"  # about the code an install puts on disk
    AUTHORS = "authors"  # about how the project is built, such as its CI workflows


@dataclass(frozen=True, slots=True)
class ScanInput:
    """What every tool scans. Dependencies are resolved once, for all of them."""

    root: Path
    dependencies: Dependencies = field(default_factory=Dependencies)


def prepare(root: Path, resolve_one: Resolve = newest_version) -> ScanInput:
    return ScanInput(root, resolve(root, resolve_one))


@dataclass(frozen=True, slots=True)
class Command:
    argv: tuple[str, ...]
    cwd: Path
    ok_exit_codes: frozenset[int] = frozenset({0})


@dataclass(frozen=True, slots=True)
class Parsed:
    findings: tuple[Finding, ...] = ()
    problems: tuple[Problem, ...] = ()


@dataclass(frozen=True, slots=True)
class ToolRun:
    check: Check
    findings: tuple[Finding, ...] = ()


class Adapter(Protocol):
    name: str
    version: str  # the version doorcheck is tested with; any other is refused
    executable: str
    audience: Audience
    experimental: bool  # off unless asked for, until test data shows it catches something

    def version_command(self) -> Sequence[str]: ...

    def command(self, scan: ScanInput, work: Path) -> Command | Parsed:
        """The scan to run. When there is nothing for the tool to run on, the result
        itself: empty, or listing what couldn't be covered. `work` is an empty
        scratch folder the adapter may write inputs to."""
        ...

    def parse(self, output: bytes, scan: ScanInput) -> Parsed: ...


def run(adapter: Adapter, scan: ScanInput, timeout: float = TIMEOUT_SECONDS) -> ToolRun:
    try:
        result = _result(adapter, scan, timeout)
    except ToolError as error:
        problem = Problem(error.key, params={"detail": param(str(error))})
        return ToolRun(Check(adapter.name, adapter.version, Status.FAILED, (problem,)))
    if result is None:
        return ToolRun(Check(adapter.name, adapter.version, Status.NOTHING_TO_SCAN))
    check = Check(adapter.name, adapter.version, status_for(result.problems), result.problems)
    return ToolRun(check, result.findings)


def _result(adapter: Adapter, scan: ScanInput, timeout: float) -> Parsed | None:
    output = raw_output(adapter, scan, timeout)
    if isinstance(output, Parsed):
        return output if output.findings or output.problems else None
    try:
        return adapter.parse(output, scan)
    except (ValueError, KeyError, TypeError, IndexError, AttributeError) as error:
        message = f"{adapter.name} output not understood: {error!r}"
        raise ToolError(message, "problem.tool_output_not_understood") from error


def raw_output(
    adapter: Adapter, scan: ScanInput, timeout: float = TIMEOUT_SECONDS
) -> bytes | Parsed:
    """What the tool prints for the scan, or the adapter's result if it didn't need to run."""
    with tempfile.TemporaryDirectory() as work, tempfile.TemporaryDirectory() as home:
        check_version(adapter, Path(home), timeout)
        command = adapter.command(scan, Path(work))
        if isinstance(command, Parsed):
            return command
        return _execute(adapter.name, command, Path(home), timeout)


def check_version(adapter: Adapter, home: Path, timeout: float) -> None:
    command = Command(tuple(adapter.version_command()), home)
    reported = _execute(adapter.name, command, home, timeout).decode(errors="replace")
    if adapter.version not in reported.split():
        found = reported.strip()[:STDERR_SHOWN]
        message = f"{adapter.name} {adapter.version} is required, found: {found}"
        raise ToolError(message, "problem.tool_wrong_version")


def _execute(name: str, command: Command, home: Path, timeout: float) -> bytes:
    try:
        done = subprocess.run(  # noqa: S603 - an adapter's argv list, never a shell
            command.argv,
            cwd=command.cwd,
            env=_environment(home),
            capture_output=True,
            timeout=timeout,
        )
    except FileNotFoundError as error:
        message = f"{name} is not installed: {command.argv[0]}"
        raise ToolError(message, "problem.tool_not_installed") from error
    except subprocess.TimeoutExpired as error:
        message = f"{name} took longer than {timeout} seconds"
        raise ToolError(message, "problem.tool_timed_out") from error
    if done.returncode not in command.ok_exit_codes:
        detail = done.stderr.decode(errors="replace").strip()[-STDERR_SHOWN:]
        raise ToolError(f"{name} failed with exit code {done.returncode}: {detail}")
    return done.stdout


def _environment(home: Path) -> dict[str, str]:
    """Only what tools need. A fresh HOME keeps them from reading the user's settings
    or tokens; the proxy and certificate settings (paths, not secrets) keep
    downloads working behind a proxy."""
    kept = {"PATH", "LANG", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy"}
    kept |= {"SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"}
    env = {key: value for key, value in os.environ.items() if key in kept}
    return {**env, "HOME": str(home), "NO_COLOR": "1"}


def relative(path: str, target: Path) -> str:
    """A tool's path as a path inside the scanned folder; anything outside is refused.
    Links aren't resolved: a finding is placed where the tool saw it."""
    given = Path(path)
    if given.is_absolute():
        given = given.relative_to(target.absolute())  # ValueError when outside
    normal = os.path.normpath(given.as_posix())
    if normal == "." or normal == ".." or normal.startswith("../"):
        raise ValueError(f"path outside the scanned folder: {path!r}")
    return normal
