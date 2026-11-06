"""Check that every release version agrees, and build the integration ZIP for HACS.

The engine version is written in four places: the engine project, the HA test
project's pin, and the integration manifest's requirement and version. A release
tag must name that same version. `hacs.json` must point HACS at the ZIP this tool
builds and declare the oldest Home Assistant the acceptance suite runs.

The ZIP holds the integration files at its root, the layout HACS unpacks into
`custom_components/doorcheck`. Entries are sorted, stored uncompressed, and carry a
fixed timestamp and mode, so the same files always give the same bytes.
"""

import argparse
import json
import sys
import tomllib
import zipfile
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

ROOT = Path(__file__).resolve().parents[1]
INTEGRATION = PurePosixPath("custom_components/doorcheck")
ZIP_NAME = "doorcheck.zip"
# A regular file, readable by everyone and writable by its owner.
ZIP_MODE = 0o100644 << 16
UNIX = 3

PROJECT = "pyproject.toml version"
HA_PIN = "ha/pyproject.toml doorcheck pin"
REQUIREMENT = "manifest.json requirement"
MANIFEST = "manifest.json version"


@dataclass(frozen=True)
class Sources:
    """The parsed files that carry a version or a release setting."""

    project: Mapping[str, Any]
    ha_project: Mapping[str, Any]
    manifest: Mapping[str, Any]
    hacs: Mapping[str, Any]
    images: Mapping[str, Any]


def pin(requirements: Iterable[str]) -> str | None:
    """The version of the one exact `doorcheck==` requirement, else None."""
    pins = []
    for text in requirements:
        try:
            requirement = Requirement(text)
        except InvalidRequirement:
            return None
        if canonicalize_name(requirement.name) != "doorcheck":
            continue
        specifiers = list(requirement.specifier)
        exact = (
            len(specifiers) == 1
            and specifiers[0].operator == "=="
            and "*" not in specifiers[0].version
            and not requirement.extras
            and requirement.marker is None
            and requirement.url is None
        )
        pins.append(specifiers[0].version if exact else None)
    return pins[0] if len(pins) == 1 else None


def versions(sources: Sources) -> dict[str, str | None]:
    return {
        PROJECT: sources.project["project"]["version"],
        HA_PIN: pin(sources.ha_project["project"]["dependencies"]),
        REQUIREMENT: pin(sources.manifest["requirements"]),
        MANIFEST: sources.manifest["version"],
    }


def normalized(version: str) -> bool:
    """True if the version is valid PEP 440 and already in its normal form."""
    try:
        return str(Version(version)) == version
    except InvalidVersion:
        return False


def problems(sources: Sources, tag: str | None = None) -> list[str]:
    """Every reason the files, and the tag if given, are not ready to release."""
    found = versions(sources)
    expected = sources.project["project"]["version"]
    issues = []
    if not normalized(expected):
        issues.append(f"{PROJECT}: {expected!r} is not a normalized PEP 440 version")
    for where, version in found.items():
        if version is None:
            issues.append(f"{where}: no single exact doorcheck== requirement")
        elif version != expected:
            issues.append(f"{where}: {version} differs from {PROJECT} {expected}")
    hacs = sources.hacs
    if hacs.get("zip_release") is not True:
        issues.append("hacs.json: zip_release must be true")
    if hacs.get("filename") != ZIP_NAME:
        issues.append(f"hacs.json: filename must be {ZIP_NAME}")
    minimum = sources.images["minimum"]["version"]
    if hacs.get("homeassistant") != minimum:
        issues.append(f"hacs.json: homeassistant must be {minimum}, the minimum acceptance image")
    if tag is not None and tag != f"v{expected}":
        issues.append(f"tag {tag} must be v{expected}")
    return issues


def wheel_name(version: str) -> str:
    return f"doorcheck-{version}-py3-none-any.whl"


def included(relative: PurePosixPath) -> bool:
    """True for files that ship: no bytecode caches and no hidden files."""
    return relative.suffix != ".pyc" and not any(
        part == "__pycache__" or part.startswith(".") for part in relative.parts
    )


def write_zip(members: Mapping[str, bytes], output: Path | str) -> None:
    # A new ZipInfo is stored uncompressed and dated 1980-01-01 00:00, the earliest
    # time a ZIP entry can hold. The tests pin both values.
    with zipfile.ZipFile(output, "w") as archive:
        for name in sorted(members):
            info = zipfile.ZipInfo(name)
            info.create_system = UNIX
            info.external_attr = ZIP_MODE
            archive.writestr(info, members[name])


def read_sources(root: Path) -> Sources:
    def toml(path: str) -> dict[str, Any]:
        return tomllib.loads((root / path).read_text())

    def data(path: str | PurePosixPath) -> Any:
        return json.loads((root / path).read_text())

    return Sources(
        project=toml("pyproject.toml"),
        ha_project=toml("ha/pyproject.toml"),
        manifest=data(INTEGRATION / "manifest.json"),
        hacs=data("hacs.json"),
        images=data("ha/acceptance/images.json"),
    )


def project_version(root: Path = ROOT) -> str:
    version: str = tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"]
    return version


def integration_files(root: Path) -> dict[str, bytes]:
    folder = root / INTEGRATION
    members = {}
    for path in folder.rglob("*"):
        relative = PurePosixPath(path.relative_to(folder).as_posix())
        if path.is_file() and included(relative):
            members[str(relative)] = path.read_bytes()
    return members


def main(argv: list[str], root: Path = ROOT) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check")
    check.add_argument("--tag")
    build = commands.add_parser("zip")
    build.add_argument("output")
    args = parser.parse_args(argv)
    if args.command == "zip":
        write_zip(integration_files(root), args.output)
        print(f"Wrote {args.output}.")
        return 0
    issues = problems(read_sources(root), args.tag)
    for issue in issues:
        print(issue)
    if issues:
        return 1
    print(f"Release files agree on {project_version(root)}.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
