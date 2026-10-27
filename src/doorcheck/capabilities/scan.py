"""Walk a folder of untrusted files and list what the code in it can do.

Nothing is executed or imported. Links are reported and never followed, every
file is size-capped, and file-count and time budgets are checked between files.
Anything that couldn't be read, or wasn't because a limit was hit, is a
problem of the scan rather than a capability of the code.
"""

import errno
import os
import stat
import sys
import time
import tokenize
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from doorcheck.capabilities import python_code, source_text
from doorcheck.capabilities.model import Capability, Kind, ScanLimits
from doorcheck.checks import Problem
from doorcheck.findings import Location, param
from doorcheck.requirements import parse_manifest, pypi_requirement
from doorcheck.tree import Entry, entries

BINARY_SUFFIXES = frozenset({".pyc", ".pyo", ".so", ".pyd", ".dll", ".dylib", ".exe", ".pth"})
# ELF, Windows PE, Mach-O (both byte orders, 32 and 64 bit) and universal binaries.
BINARY_MAGIC = (
    b"\x7fELF",
    b"MZ",
    b"\xfe\xed\xfa",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
)
# Python files are parsed with the running Python, so newer syntax may not parse.
PYTHON = f"{sys.version_info.major}.{sys.version_info.minor}"
MAX_REQUIREMENTS = 200

Found = list[Capability | Problem]


@dataclass(frozen=True, slots=True)
class Scanned:
    capabilities: tuple[Capability, ...]
    problems: tuple[Problem, ...]


def scan(root: Path, limits: ScanLimits | None = None) -> Scanned:
    limits = limits or ScanLimits()
    found: Found = []

    def walk_error(error: OSError) -> None:
        found.append(_walk_problem(root, error))

    _walk(root, limits, found, walk_error)
    capabilities = [item for item in found if isinstance(item, Capability)]
    problems = [item for item in found if isinstance(item, Problem)]
    return Scanned(tuple(sorted(capabilities, key=_order)), tuple(problems))


def _walk(
    root: Path, limits: ScanLimits, found: Found, walk_error: Callable[[OSError], None]
) -> None:
    deadline = time.monotonic() + limits.max_seconds
    try:
        for count, entry in enumerate(entries(root, walk_error), start=1):
            late = time.monotonic() > deadline  # pragma: no mutate - > and >= differ by one tick
            if count > limits.max_files or late:
                reason = "file_count" if count > limits.max_files else "time"
                found.append(_problem("problem.scan_limit_reached", entry.relative, limit=reason))
                return
            found.extend(_scan_entry(entry, limits))
    except OSError as error:
        walk_error(error)


def _walk_problem(root: Path, error: OSError) -> Problem:
    path = Path(error.filename or root)
    relative = path.relative_to(root).as_posix() if path.is_relative_to(root) else "."
    if relative != ".":
        return _problem("problem.directory_not_readable", relative, detail=str(error))
    return Problem("problem.directory_not_readable", params={"detail": param(str(error))})


def _order(capability: Capability) -> tuple[str, int, int, str, str]:
    loc = capability.location
    # Only whole-file entries lack a column, and they never share a line with one that has it.
    column = loc.column or 0  # pragma: no mutate - see above
    return (loc.path, loc.line, column, capability.kind.value, capability.subject)


def _scan_entry(entry: Entry, limits: ScanLimits) -> Found:
    try:
        Location(entry.relative, 1)  # pragma: no mutate - validation only; any positive line works
    except ValueError:
        return [_unsupported_path(entry.relative)]
    try:
        return _read_entry(entry, limits)
    except OSError as error:
        return [_problem("problem.file_not_readable", entry.relative, detail=str(error))]


def _read_entry(entry: Entry, limits: ScanLimits) -> Found:
    if entry.is_link:
        target = str(entry.path.readlink())  # where it points, as written; never followed
        return [Capability(Kind.SYMLINK, Location(entry.relative, 1), target)]
    path, relative = entry.path, entry.relative
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        return [_problem("problem.file_not_regular", relative)]
    size = info.st_size
    cap = limits.max_python_bytes if path.suffix == ".py" else limits.max_file_bytes
    if size > cap:
        return [_problem("problem.file_too_large", relative, size=str(size))]
    if path.suffix in BINARY_SUFFIXES:
        return [Capability(Kind.SHIPPED_BINARY, Location(relative, 1), path.suffix)]
    return _contents(path, relative, cap)


def _contents(path: Path, relative: str, cap: int) -> Found:
    reader = _READERS.get(path.suffix) or _READERS.get(path.name)
    data = _read_file(path, cap + 1 if reader else 4)
    if len(data) > cap:
        return [_problem("problem.file_too_large", relative, size=str(len(data)))]
    if data.startswith(BINARY_MAGIC):
        return [Capability(Kind.SHIPPED_BINARY, Location(relative, 1), path.suffix or "executable")]
    return reader(data, relative) if reader else []


def _read_file(path: Path, limit: int) -> bytes:
    # Nonblocking/no-follow also protect a file replaced by a pipe or link after lstat.
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise OSError(errno.EINVAL, "not a regular file", str(path))
        return handle.read(limit)


def _python(data: bytes, relative: str) -> Found:
    try:
        source = data.decode("utf-8")  # pragma: no mutate - codec names ignore case
        found: Found = list(python_code.analyze(source, relative))
    except (SyntaxError, ValueError) as error:  # UnicodeDecodeError is a ValueError
        line = getattr(error, "lineno", None) or 1
        detail = f"{type(error).__name__}: {error}"
        return [_problem("problem.file_not_parsed", relative, line, detail=detail, python=PYTHON)]
    except (RecursionError, MemoryError):
        return [_problem("problem.file_too_complex", relative)]
    try:
        found.extend(source_text.confusable_names(source, relative))
    except (tokenize.TokenError, SyntaxError) as error:
        detail = f"{type(error).__name__}: {error}"
        found.append(_problem("problem.file_not_parsed", relative, detail=detail, python=PYTHON))
    found.extend(source_text.bidi_controls(source, relative))
    return found


def _text(data: bytes, relative: str) -> Found:
    """Other source files: only the invisible-character check applies."""
    text = data.decode("utf-8", "replace")  # pragma: no mutate - codec names ignore case
    return list(source_text.bidi_controls(text, relative))


def _manifest(data: bytes, relative: str) -> Found:
    manifest = parse_manifest(data)
    if manifest is None or manifest.requirements is None:
        return [_problem("problem.manifest_not_parsed", relative)]
    found: Found = []
    for index, requirement in enumerate(manifest.requirements):
        if index == MAX_REQUIREMENTS:
            found.append(_problem("problem.too_many_requirements", relative))
            break
        if not isinstance(requirement, str):
            found.append(_problem("problem.requirement_not_text", relative))
            continue
        kind = Kind.DEPENDENCY if pypi_requirement(requirement) else Kind.DEPENDENCY_OUTSIDE_PYPI
        found.append(Capability(kind, Location(relative, manifest.line(requirement)), requirement))
    return found


def _problem(key: str, relative: str, line: int = 1, **params: str) -> Problem:
    try:
        location = Location(relative, line)
    except ValueError:
        return _unsupported_path(relative)
    return Problem(key, location, {k: param(v) for k, v in params.items()})


def _unsupported_path(relative: str) -> Problem:
    return Problem("problem.file_path_not_supported", params={"path": param(relative)})


_READERS: dict[str, Callable[[bytes, str], Found]] = {
    ".py": _python,
    "manifest.json": _manifest,
    **dict.fromkeys((".js", ".mjs", ".cjs", ".ts", ".yaml", ".yml"), _text),
}
