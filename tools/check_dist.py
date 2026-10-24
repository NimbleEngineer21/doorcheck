"""Fail if a built wheel or sdist contains anything besides the package itself.

Tests and detection fixtures must never reach PyPI, which forbids distributing
malware or deliberately obfuscated code.
"""

import sys
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

FORBIDDEN_DIRS = frozenset({"tests", "tools", "fixtures", ".github"})


def is_forbidden(member: str) -> bool:
    """True if any directory in the archive path is one that must not ship."""
    return any(part in FORBIDDEN_DIRS for part in PurePosixPath(member).parts[:-1])


def archive_members(path: Path) -> list[str]:
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as wheel:
            return wheel.namelist()
    with tarfile.open(path) as sdist:
        return sdist.getnames()


def main(argv: list[str]) -> int:
    archives = [Path(arg) for arg in argv[1:]]
    if not archives:
        print("No archives given.")
        return 1
    bad = [f"{a.name}: {m}" for a in archives for m in archive_members(a) if is_forbidden(m)]
    for line in bad:
        print(f"Must not ship: {line}")
    if bad:
        return 1
    print(f"Checked {len(archives)} archive(s); only package files ship.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
