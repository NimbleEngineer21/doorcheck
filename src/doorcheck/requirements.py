"""Requirement strings from an integration's manifest.json.

Home Assistant hands each string unchanged to `uv pip install`, so besides a
PyPI package (`name`, `name>=1`, `name==1.2; python_version>'3'`) a string can
be a URL or VCS link, or start with "-" and be read as an option such as
`--index-url`. Anything that isn't a plain PyPI requirement installs code from
somewhere vulnerability and malware checks can't follow, so it is told apart.

Requirement text is never passed on as written: tools get a requirement rebuilt
from the parts this module accepted, so it can't carry options of its own.
"""

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from doorcheck.tree import json_object

# Possessive quantifiers (*+ ++) never give characters back, so text that almost
# matches is rejected in linear time instead of backtracking through every split.
NAME = r"[A-Za-z0-9](?:[A-Za-z0-9._-]*+(?<=[A-Za-z0-9]))?"
VERSION = r"[A-Za-z0-9.*+!_-]++"
SPECIFIER = rf"(?:===|==|!=|~=|<=|>=|<|>)\s*+{VERSION}"
PLAIN = re.compile(
    rf"(?P<name>{NAME})\s*+(?P<extras>\[\s*+{NAME}(?:\s*+,\s*+{NAME})*+\s*+\])?"
    rf"\s*+(?P<specifiers>{SPECIFIER}(?:\s*+,\s*+{SPECIFIER})*+)?"
)
PIN = re.compile(r"==\s*(?P<version>[A-Za-z0-9.+!_-]+)")
STRING = re.compile(r'"(?:[^"\\\n]|\\.)*+"')  # a JSON string, escapes included


@dataclass(frozen=True, slots=True)
class PypiRequirement:
    name: str
    specifiers: str  # e.g. ">=1.0,<2", without spaces; "" for any version

    @property
    def pinned_version(self) -> str | None:
        """The version for an exact pin (`==1.2`), the only kind that names one install."""
        match = PIN.fullmatch(self.specifiers)
        return match.group("version") if match else None

    def __str__(self) -> str:
        return f"{self.name}{self.specifiers}"


def pypi_requirement(text: str) -> PypiRequirement | None:
    """The PyPI package a requirement installs, or None if it installs from elsewhere.
    Environment markers (after ";") don't change where a package comes from."""
    match = PLAIN.fullmatch(text.partition(";")[0].strip())
    if not match:
        return None
    return PypiRequirement(match.group("name"), re.sub(r"\s", "", match.group("specifiers") or ""))


@dataclass(frozen=True, slots=True)
class Manifest:
    """An integration's manifest.json. `requirements` is None when the field isn't a
    list; its items are kept as written, text or not, for each reader to judge."""

    text: str
    requirements: tuple[object, ...] | None
    lines: Mapping[str, int]  # each string in the file -> the first line it's on

    def line(self, requirement: str) -> int:
        """The line a requirement string is written on, else 1."""
        return self.lines.get(requirement, 1)


def parse_manifest(data: bytes) -> Manifest | None:
    """None for anything that isn't a JSON object."""
    values = json_object(data)
    if values is None:
        return None
    text = data.decode(errors="replace")
    listed = values.get("requirements", [])
    requirements = tuple(listed) if isinstance(listed, list) else None
    return Manifest(text, requirements, _string_lines(text))


def read_manifest(path: Path) -> Manifest | None:
    try:
        return parse_manifest(path.read_bytes())
    except OSError:
        return None


def _string_lines(text: str) -> dict[str, int]:
    """One pass over the text, so finding many requirements' lines stays linear."""
    lines: dict[str, int] = {}
    for number, line in enumerate(text.splitlines(), start=1):
        for match in STRING.finditer(line):
            try:
                value = json.loads(match.group())  # escapes as written: "caf\u00e9" is "café"
            except ValueError:
                continue  # a UTF-16 manifest, read as UTF-8 for its lines, can hold these
            lines.setdefault(value, number)
    return lines


def normalized(name: str) -> str:
    """A package name as PyPI compares names (PEP 503)."""
    return re.sub(r"[-_.]+", "-", name).lower()
