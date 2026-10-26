"""Listing untrusted folders and reading untrusted JSON, the same way everywhere.

Nothing is skipped: a `.git` folder or any other hidden folder that an
install puts on disk gets scanned like the rest.
"""

import errno
import json
import os
import stat
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Entry:
    path: Path
    relative: str  # POSIX path below the root
    is_link: bool


def entries(root: Path, on_error: Callable[[OSError], None] | None = None) -> Iterator[Entry]:
    """Every file and link under root, in a stable order. Links, to files or
    folders, are listed and never entered. Walk errors are reported to on_error,
    or raised when no handler is supplied."""
    if not stat.S_ISDIR(root.lstat().st_mode):
        raise NotADirectoryError(
            errno.ENOTDIR, "scan root must be a directory, not a link or file", str(root)
        )
    for folder, dirs, files in os.walk(root, onerror=on_error or _raise_walk_error):
        dirs.sort()
        here = Path(folder)
        for name in sorted([*files, *(d for d in dirs if (here / d).is_symlink())]):
            path = here / name
            yield Entry(path, path.relative_to(root).as_posix(), path.is_symlink())


def _raise_walk_error(error: OSError) -> None:
    raise error


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


def read_regular(path: Path, limit: int) -> bytes:
    """Read at most limit bytes, refusing links and nonregular files without blocking."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise OSError(f"not a regular file: {path}")
        return handle.read(limit)
