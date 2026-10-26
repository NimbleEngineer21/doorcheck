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
    parse_manifest,
    pypi_requirement,
)
from doorcheck.tree import read_regular

MANIFEST = "manifest.json"
MAX_MANIFEST_BYTES = 2_000_000
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
    manifest = _manifest(root)
    if isinstance(manifest, Unresolved):
        return Dependencies(unresolved=(manifest,))
    if manifest is None:
        return Dependencies()
    pins: dict[str, Pin] = {}
    unresolved: list[Unresolved] = []
    conflicts: set[str] = set()
    for index, item in enumerate(manifest.requirements or ()):
        result = _one(item, index, manifest, resolve_one)
        if isinstance(result, Unresolved):
            unresolved.append(result)
        else:
            _add_pin(pins, conflicts, unresolved, result, str(item))
    return Dependencies(tuple(pins.values()), tuple(unresolved))


def _add_pin(
    pins: dict[str, Pin],
    conflicts: set[str],
    unresolved: list[Unresolved],
    result: Pin,
    written: str,
) -> None:
    name = normalized(result.requirement.name)
    previous = pins.get(name)
    if name in conflicts or (
        previous and previous.requirement.specifiers != result.requirement.specifiers
    ):
        conflicts.add(name)
        pins.pop(name, None)
        unresolved.append(Unresolved(written, result.line, "problem.conflicting_requirements"))
    else:
        pins.setdefault(name, result)
    if "[" in written:
        unresolved.append(
            Unresolved(written, result.line, "problem.requirement_extras_not_checked")
        )


def _manifest(root: Path) -> Manifest | Unresolved | None:
    try:
        data = read_regular(root / MANIFEST, MAX_MANIFEST_BYTES + 1)
    except FileNotFoundError:
        return None
    except OSError:
        return Unresolved(MANIFEST, 1, "problem.manifest_not_readable")
    if len(data) > MAX_MANIFEST_BYTES:
        return Unresolved(MANIFEST, 1, "problem.file_too_large")
    manifest = parse_manifest(data)
    if manifest is None:
        return Unresolved(MANIFEST, 1, "problem.manifest_not_parsed")
    if manifest.requirements is None:
        return Unresolved(MANIFEST, 1, "problem.requirements_not_list")
    return manifest


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
