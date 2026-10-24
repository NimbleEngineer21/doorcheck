"""Listing untrusted folders and reading untrusted JSON, the same way everywhere.

Nothing is skipped: a `.git` folder or any other hidden folder that an
install puts on disk gets scanned like the rest.
"""

import json
import os
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Entry:
    path: Path
    relative: str  # POSIX path below the root
    is_link: bool


def entries(root: Path) -> Iterator[Entry]:
    """Every file and link under root, in a stable order. Links, to files or
    folders, are listed and never entered."""
    for folder, dirs, files in os.walk(root):  # os.walk never enters linked folders
        dirs.sort()
        here = Path(folder)
        for name in sorted([*files, *(d for d in dirs if (here / d).is_symlink())]):
            path = here / name
            yield Entry(path, path.relative_to(root).as_posix(), path.is_symlink())


def json_object(data: bytes | None) -> dict[str, object] | None:
    """A JSON object, or None for anything else: missing, invalid, or not an object."""
    if data is None:
        return None
    try:
        value = json.loads(data)
    except (ValueError, RecursionError):  # invalid UTF-8 is a ValueError; [[[... recurses
        return None
    return value if isinstance(value, dict) else None


def read_json_object(path: Path) -> dict[str, object] | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    return json_object(data)
