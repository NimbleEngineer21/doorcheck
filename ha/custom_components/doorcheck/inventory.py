"""Bounded manifest inventory; never import custom-integration Python."""

import json
import os
import stat
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from itertools import islice
from pathlib import Path
from time import monotonic
from typing import Any, Never

from homeassistant.util import slugify

from doorcheck.text import display_safe

MAX_ENTRIES = 512
MAX_MANIFEST_BYTES = 64 * 1024
TIME_SECONDS = 5.0


@dataclass(frozen=True, slots=True)
class Item:
    directory: str
    domain: str | None = None
    name: str | None = None
    version: str | None = None
    problem: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "directory": self.directory,
            "domain": self.domain,
            "name": self.name,
            "version": self.version,
            "origin": "unknown",
            "problems": [self.problem] if self.problem else [],
        }


@dataclass(frozen=True, slots=True)
class Inventory:
    items: tuple[Item, ...] = ()
    problems: tuple[str, ...] = ()
    failed: bool = False

    def as_dict(self) -> dict[str, Any]:
        partial = bool(self.problems) or any(item.problem for item in self.items)
        status = "failed" if self.failed else "partial" if partial else "complete"
        return {
            "schema_version": 1,
            "scope": "custom_integrations_on_disk",
            "status": status,
            "items": [item.as_dict() for item in self.items],
            "problems": list(self.problems),
        }


@contextmanager
def _directory(path: str | Path, parent: int | None = None) -> Iterator[int]:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        yield descriptor
    finally:
        os.close(descriptor)


def _display(name: str) -> str:
    valid_unicode = name.encode(errors="backslashreplace").decode()
    return display_safe(valid_unicode).replace("\n", "⟨U+000A⟩").replace("\t", "⟨U+0009⟩")


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _nonfinite(value: str) -> Never:
    raise ValueError


def _field(value: object) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        raise ValueError
    value.encode()
    return value


def _manifest(parent: int, limit: int) -> dict[str, Any]:
    descriptor = os.open(
        "manifest.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent
    )
    with os.fdopen(descriptor, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise OSError
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError
    manifest = json.loads(data.decode(), object_pairs_hook=_unique, parse_constant=_nonfinite)
    if not isinstance(manifest, dict):
        raise ValueError
    return manifest


def _item(parent: int, name: str, limit: int) -> Item:
    label = _display(name)
    if slugify(name) != name:
        return Item(label, problem="problem.inventory_folder_invalid")
    try:
        with _directory(name, parent) as folder:
            manifest = _manifest(folder, limit)
        domain = _field(manifest.get("domain"))
        title = _field(manifest.get("name"))
        version = _field(manifest.get("version"))
        if domain != name:
            raise ValueError
        return Item(label, domain, title, version)
    except FileNotFoundError:
        return Item(label, problem="problem.inventory_manifest_missing")
    except OSError:
        return Item(label, problem="problem.inventory_entry_unreadable")
    except (ValueError, RecursionError):
        return Item(label, problem="problem.inventory_manifest_invalid")


def _candidate(parent: int, name: str) -> bool:
    try:
        mode = os.lstat(name, dir_fd=parent).st_mode
        return stat.S_ISDIR(mode) or stat.S_ISLNK(mode)
    except OSError:
        # A raced/unreadable entry remains a candidate and yields its own gap.
        return True


def _candidates(parent: int, maximum: int) -> list[str] | None:
    with os.scandir(parent) as scan:
        entries = list(islice(scan, maximum + 1))
    if len(entries) > maximum:
        return None
    return sorted(entry.name for entry in entries)


def read_inventory(
    root: Path,
    *,
    max_entries: int = MAX_ENTRIES,
    max_manifest_bytes: int = MAX_MANIFEST_BYTES,
    seconds: float = TIME_SECONDS,
    clock: Callable[[], float] = monotonic,
) -> Inventory:
    deadline = clock() + seconds
    items: list[Item] = []
    try:
        with _directory(root) as parent:
            names = _candidates(parent, max_entries)
            if names is None:
                return Inventory(problems=("problem.inventory_entry_limit",))
            for name in names:
                if clock() >= deadline:
                    return Inventory(tuple(items), ("problem.inventory_time_limit",))
                if name != "__pycache__" and _candidate(parent, name):
                    items.append(_item(parent, name, max_manifest_bytes))
            if clock() >= deadline:
                return Inventory(tuple(items), ("problem.inventory_time_limit",))
    except OSError:
        return Inventory(tuple(items), ("problem.inventory_root_unreadable",), failed=True)
    return Inventory(tuple(items))
