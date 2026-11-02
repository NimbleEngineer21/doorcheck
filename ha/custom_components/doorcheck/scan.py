"""Scan a bounded, descriptor-anchored private copy of one installed folder."""

import os
import stat
from dataclasses import dataclass
from importlib.metadata import version
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic

from doorcheck import capabilities, rules
from doorcheck.capabilities.model import ScanLimits
from doorcheck.checks import Check, Problem, Status, status_for
from doorcheck.report import Report, Target

from .inventory import _directory

MAX_ENTRIES = 256
MAX_BYTES = 8 * 1024 * 1024
MAX_FILE_BYTES = 128 * 1024
MAX_DEPTH = 16
SECONDS = 5.0


class SnapshotError(Exception):
    """The selected tree could not be copied within the snapshot contract."""


@dataclass
class Budget:
    deadline: float
    entries: int = 0
    size: int = 0

    def tick(self) -> None:
        self.entries += 1
        if self.entries > MAX_ENTRIES or monotonic() >= self.deadline:
            raise SnapshotError


def _file(parent: int, name: str, destination: Path, budget: Budget) -> None:
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


def _copy(parent: int, destination: Path, budget: Budget, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise SnapshotError
    with os.scandir(parent) as entries:
        for entry in entries:
            budget.tick()
            mode = os.lstat(entry.name, dir_fd=parent).st_mode
            child = destination / entry.name
            if stat.S_ISDIR(mode):
                with _directory(entry.name, parent) as folder:
                    child.mkdir()
                    _copy(folder, child, budget, depth + 1)
            elif stat.S_ISREG(mode):
                _file(parent, entry.name, child, budget)
            else:
                raise SnapshotError
    if monotonic() >= budget.deadline:
        raise SnapshotError


def scan_integration(root: Path, directory: str) -> Report:
    """Never scan the live tree with the engine's path-based walkers."""
    installed = version("doorcheck")  # pragma: no mutate - package names ignore case
    target = Target(directory)
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
        checks = (
            Check("snapshot", installed, Status.COMPLETE),
            Check("capabilities", installed, status_for(observed.problems), observed.problems),
            Check("python-rules", installed, status_for(detected.problems), detected.problems),
        )
        return Report(installed, target, checks, observed.capabilities, detected.findings)
    except (OSError, SnapshotError):
        check = Check(
            "snapshot", installed, Status.FAILED, (Problem("problem.ha_snapshot_failed"),)
        )
        return Report(installed, target, (check,), (), ())
