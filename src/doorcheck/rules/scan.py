"""Bounded source reader for the initial Python rule, with explicit gaps."""

import sys
import time
from dataclasses import dataclass
from pathlib import Path

from doorcheck.capabilities.model import ScanLimits
from doorcheck.checks import Problem
from doorcheck.findings import Finding, Location, param
from doorcheck.rules.file_view import analyze
from doorcheck.tree import entries, read_regular


@dataclass(frozen=True, slots=True)
class Scanned:
    findings: tuple[Finding, ...]
    problems: tuple[Problem, ...]


def scan(root: Path, limits: ScanLimits | None = None) -> Scanned:
    limits = limits or ScanLimits()
    findings: list[Finding] = []
    problems: list[Problem] = []
    deadline = time.monotonic() + limits.max_seconds

    def walk_error(error: OSError) -> None:
        problems.append(
            Problem("problem.directory_not_readable", params={"detail": param(str(error))})
        )

    try:
        for count, entry in enumerate(entries(root, walk_error), 1):
            # Clock equality differs by one tick, as in the capability reader.
            late = time.monotonic() > deadline  # pragma: no mutate - > and >= differ by one tick
            if count > limits.max_files or late:
                reason = "file_count" if count > limits.max_files else "time"
                problems.append(
                    Problem(
                        "problem.scan_limit_reached", _location(entry.relative), {"limit": reason}
                    )
                )
                break
            if entry.path.suffix == ".py":
                result = _file(entry.path, entry.relative, limits.max_python_bytes)
                findings.extend(result.findings)
                problems.extend(result.problems)
    except OSError as error:
        walk_error(error)
    return Scanned(tuple(findings), tuple(problems))


def _location(relative: str) -> Location | None:
    try:
        return Location(relative, 1)
    except ValueError:
        return None


def _file(path: Path, relative: str, cap: int) -> Scanned:
    location = _location(relative)
    if location is None:
        problem = Problem("problem.file_path_not_supported", params={"path": param(relative)})
        return Scanned((), (problem,))
    try:
        data = read_regular(path, cap + 1)
        if len(data) > cap:
            problem = Problem("problem.file_too_large", location, {"size": str(len(data))})
            return Scanned((), (problem,))
        source = data.decode("utf-8")  # pragma: no mutate - codec names ignore case
        return Scanned(tuple(analyze(source, relative)), ())
    except OSError as error:
        problem = Problem("problem.file_not_readable", location, {"detail": param(str(error))})
    except (SyntaxError, ValueError) as error:
        line = getattr(error, "lineno", None) or 1
        problem = Problem(
            "problem.file_not_parsed",
            Location(relative, line),
            {
                "detail": param(str(error)),
                "python": f"{sys.version_info.major}.{sys.version_info.minor}",
            },
        )
    except (RecursionError, MemoryError):
        problem = Problem("problem.file_too_complex", location)
    return Scanned((), (problem,))
