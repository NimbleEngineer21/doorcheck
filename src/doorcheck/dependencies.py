"""The PyPI packages an integration's manifest installs, pinned to the version a
fresh install gets.

Resolved once per scan and shared by every tool that checks dependencies.
Whatever can't be pinned is kept with the reason, so each of those tools can
report it as not covered instead of leaving it out.
"""

from dataclasses import dataclass
from pathlib import Path

from doorcheck.checks import Problem
from doorcheck.errors import DoorcheckError
from doorcheck.findings import Location, param
from doorcheck.pypi import Resolve, newest_version
from doorcheck.requirements import (
    Manifest,
    PypiRequirement,
    normalized,
    pypi_requirement,
    read_manifest,
)

MANIFEST = "manifest.json"
# Far above any real manifest; each requirement costs a download from PyPI.
MAX_REQUIREMENTS = 200


@dataclass(frozen=True, slots=True)
class Pin:
    requirement: PypiRequirement  # rebuilt with an exact version
    line: int


@dataclass(frozen=True, slots=True)
class Unresolved:
    written: str  # the requirement as the manifest has it, for display
    line: int
    key: str  # why it couldn't be pinned


@dataclass(frozen=True, slots=True)
class Dependencies:
    pins: tuple[Pin, ...] = ()
    unresolved: tuple[Unresolved, ...] = ()


def resolve(root: Path, resolve_one: Resolve = newest_version) -> Dependencies:
    manifest = read_manifest(root / MANIFEST)
    if manifest is None or not manifest.requirements:
        return Dependencies()
    pins: dict[str, Pin] = {}  # a package listed twice installs once: the first one counts
    unresolved: list[Unresolved] = []
    for index, item in enumerate(manifest.requirements):
        result = _one(item, index, manifest, resolve_one)
        if isinstance(result, Unresolved):
            unresolved.append(result)
        else:
            pins.setdefault(normalized(result.requirement.name), result)
    return Dependencies(tuple(pins.values()), tuple(unresolved))


def _one(item: object, index: int, manifest: Manifest, resolve_one: Resolve) -> Pin | Unresolved:
    if not isinstance(item, str):
        return Unresolved(repr(item), 1, "problem.requirement_not_text")
    line = manifest.line(item)
    if index >= MAX_REQUIREMENTS:
        return Unresolved(item, line, "problem.too_many_requirements")
    parsed = pypi_requirement(item)
    if parsed is None:
        return Unresolved(item, line, "problem.requirement_outside_pypi")
    try:
        version = resolve_one(parsed)
    except DoorcheckError as error:
        return Unresolved(item, line, error.key)
    return Pin(PypiRequirement(parsed.name, f"=={version}"), line)


def pins_file(pins: tuple[Pin, ...]) -> str:
    """A requirements file of rebuilt pins, so a manifest can't slip in options."""
    return "".join(f"{pin.requirement}\n" for pin in pins)


def unresolved_problem(unresolved: Unresolved) -> Problem:
    location = Location(MANIFEST, unresolved.line)
    return Problem(unresolved.key, location, {"requirement": param(unresolved.written)})
