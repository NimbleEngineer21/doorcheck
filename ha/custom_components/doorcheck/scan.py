"""Scan a bounded, descriptor-anchored private copy of one installed folder."""

import hashlib
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field
from importlib.metadata import version
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic

from doorcheck import capabilities, rules
from doorcheck.capabilities.model import ScanLimits
from doorcheck.checks import Check, Problem, Status, status_for
from doorcheck.report import Report, Target
from doorcheck.tree import read_json_object

from .inventory import _directory

MAX_ENTRIES = 256
MAX_BYTES = 8 * 1024 * 1024
MAX_FILE_BYTES = 256 * 1024
MAX_DEPTH = 16
SECONDS = 5.0


class SnapshotError(Exception):
    """The selected tree could not be copied within the snapshot contract."""


@dataclass(frozen=True, slots=True)
class Scan:
    """A report plus the SHA-256 of every file in the private copy it read."""

    report: Report
    files: Mapping[str, str] = field(default_factory=dict)
    bytecode: Mapping[str, str] = field(default_factory=dict)


@dataclass
class Budget:
    deadline: float
    entries: int = 0
    size: int = 0
    hashes: dict[str, str] = field(default_factory=dict)

    def tick(self) -> None:
        self.entries += 1
        if self.entries > MAX_ENTRIES or monotonic() >= self.deadline:
            raise SnapshotError


def _file(parent: int, name: str, destination: Path, budget: Budget, relative: str) -> None:
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    with os.fdopen(descriptor, "rb") as handle:
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise SnapshotError
        data = handle.read(MAX_FILE_BYTES + 1)
        after = os.fstat(handle.fileno())
    budget.size += len(data)
    if len(data) > MAX_FILE_BYTES or budget.size > MAX_BYTES:
        raise SnapshotError
    if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        raise SnapshotError
    destination.write_bytes(data)
    budget.hashes[relative] = hashlib.sha256(data).hexdigest()


def _copy(parent: int, destination: Path, budget: Budget, depth: int = 0, prefix: str = "") -> None:
    if depth > MAX_DEPTH:
        raise SnapshotError
    with os.scandir(parent) as entries:
        for entry in entries:
            budget.tick()
            mode = os.lstat(entry.name, dir_fd=parent).st_mode
            child = destination / entry.name
            relative = prefix + entry.name
            if stat.S_ISDIR(mode):
                with _directory(entry.name, parent) as folder:
                    child.mkdir()
                    _copy(folder, child, budget, depth + 1, relative + "/")
            elif stat.S_ISREG(mode):
                _file(parent, entry.name, child, budget, relative)
            else:
                raise SnapshotError
    if monotonic() >= budget.deadline:
        raise SnapshotError


def is_bytecode(relative: str) -> bool:
    """Interpreter-written bytecode changes after first load; it is kept apart."""
    *folders, name = relative.split("/")
    return "__pycache__" in folders and name.endswith(".pyc")


def source_digest(files: Mapping[str, str]) -> str:
    """The engine's installed-file digest format, for a copy holding only files."""
    digest = hashlib.sha256()
    for path in sorted(files):
        digest.update(f"file\0{path}\0{files[path]}\n".encode())
    return digest.hexdigest()


def _manifest_version(snapshot: Path) -> str | None:
    manifest = read_json_object(snapshot / "manifest.json") or {}
    value = manifest.get("version")
    return value if isinstance(value, str) and value.strip() else None


def scan_integration(root: Path, directory: str) -> Scan:
    """Never scan the live tree with the engine's path-based walkers."""
    installed = version("doorcheck")  # pragma: no mutate - package names ignore case
    try:
        with TemporaryDirectory() as temporary:
            snapshot = Path(temporary)
            budget = Budget(monotonic() + SECONDS)
            with _directory(root) as parent, _directory(directory, parent) as selected:
                _copy(selected, snapshot, budget)
            limits = ScanLimits(
                max_files=MAX_ENTRIES,
                max_file_bytes=MAX_FILE_BYTES,
                max_python_bytes=MAX_FILE_BYTES,
                max_seconds=SECONDS,
            )
            observed = capabilities.scan(snapshot, limits)
            detected = rules.scan(snapshot, limits)
            manifest_version = _manifest_version(snapshot)
        files = {path: h for path, h in budget.hashes.items() if not is_bytecode(path)}
        bytecode = {path: h for path, h in budget.hashes.items() if is_bytecode(path)}
        target = Target(directory, manifest_version, None, source_digest(files))
        checks = (
            Check("snapshot", installed, Status.COMPLETE),
            Check("capabilities", installed, status_for(observed.problems), observed.problems),
            Check("python-rules", installed, status_for(detected.problems), detected.problems),
        )
        report = Report(installed, target, checks, observed.capabilities, detected.findings)
        return Scan(report, files, bytecode)
    except (OSError, SnapshotError):
        check = Check(
            "snapshot", installed, Status.FAILED, (Problem("problem.ha_snapshot_failed"),)
        )
        return Scan(Report(installed, Target(directory), (check,), (), ()))
