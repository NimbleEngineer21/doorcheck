"""Saved scan results: a reviewed baseline and the latest scan per directory.

Stored reports are reloaded with the engine's strict report reader. An entry
that fails any check is dropped and reported, never partly trusted. A store
that cannot be read is left untouched on disk: saving stops for this run
instead of overwriting data Doorcheck could not read. One lock orders every
change, so a clear or review is never undone by a save already in progress.
"""

import asyncio
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Self

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers.storage import Store
from homeassistant.util import dt as dt_util
from homeassistant.util import slugify

from doorcheck.checks import Status
from doorcheck.report import Report, from_dict, to_dict

from .const import DOMAIN
from .scan import Scan, source_digest

STORE_KEY = f"{DOMAIN}.results"
STORE_VERSION = 1
MAX_ITEMS = 256
MAX_BYTES = 4 * 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}")

LIMIT = "problem.ha_results_limit"
UNAVAILABLE = "problem.ha_results_unavailable"
INVALID = "problem.ha_results_entry_invalid"
REVIEW_ERROR = "results_invalid_request"

_RECORD_FIELDS = frozenset({"scanned_at", "report", "files", "bytecode"})
_ITEM_FIELDS = frozenset({"baseline", "latest"})


def complete(report: Report) -> bool:
    """Every check finished; only such a scan can become a reviewed baseline."""
    return bool(report.checks) and all(c.status is Status.COMPLETE for c in report.checks)


@dataclass(frozen=True, slots=True)
class Saved:
    scanned_at: str
    report: Report
    files: Mapping[str, str] = field(default_factory=dict)
    bytecode: Mapping[str, str] = field(default_factory=dict)

    @classmethod
    def from_scan(cls, scan: Scan) -> Self:
        now = dt_util.utcnow().isoformat(timespec="seconds")
        return cls(now, scan.report, dict(scan.files), dict(scan.bytecode))

    def as_dict(self) -> dict[str, Any]:
        return {
            "scanned_at": self.scanned_at,
            "report": to_dict(self.report),
            "files": dict(self.files),
            "bytecode": dict(self.bytecode),
        }


@dataclass(frozen=True, slots=True)
class Item:
    latest: Saved
    baseline: Saved | None = None

    def as_dict(self) -> dict[str, Any]:
        baseline = self.baseline.as_dict() if self.baseline else None
        return {"baseline": baseline, "latest": self.latest.as_dict()}


def _hashes(data: object) -> dict[str, str]:
    if not isinstance(data, dict) or not all(
        isinstance(k, str) and isinstance(v, str) and SHA256.fullmatch(v) for k, v in data.items()
    ):
        raise ValueError("invalid file hashes")
    return data


def _record(directory: str, data: object) -> Saved:
    if not isinstance(data, dict) or data.keys() != _RECORD_FIELDS:
        raise ValueError("invalid saved record")
    scanned_at = data["scanned_at"]
    if not isinstance(scanned_at, str) or dt_util.parse_datetime(scanned_at) is None:
        raise ValueError("invalid scan time")
    report = from_dict(data["report"])
    files, bytecode = _hashes(data["files"]), _hashes(data["bytecode"])
    digest = report.target.artifact_sha256
    if report.target.name != directory or ((digest or files) and digest != source_digest(files)):
        raise ValueError("saved record does not match its directory or files")
    return Saved(scanned_at, report, files, bytecode)


def _item(directory: str, data: object) -> Item:
    if slugify(directory) != directory or not isinstance(data, dict):
        raise ValueError("invalid saved item")
    if data.keys() != _ITEM_FIELDS:
        raise ValueError("invalid saved item")
    baseline = None if data["baseline"] is None else _record(directory, data["baseline"])
    if baseline is not None and not complete(baseline.report):
        raise ValueError("an incomplete scan cannot be a baseline")
    return Item(_record(directory, data["latest"]), baseline)


class _Store(Store[dict[str, Any]]):
    """Refuse any store version this release cannot read, on every supported HA."""

    async def _async_migrate_func(
        self, old_major_version: int, old_minor_version: int, old_data: dict[str, Any]
    ) -> dict[str, Any]:
        if old_major_version == STORE_VERSION:
            return old_data
        # Older HA calls this for a newer store too; load() then leaves it unread.
        raise HomeAssistantError


def _open(hass: HomeAssistant) -> Store[dict[str, Any]]:
    return _Store(hass, STORE_VERSION, STORE_KEY, private=True, atomic_writes=True)


async def delete(hass: HomeAssistant) -> None:
    """Delete the saved results store without reading it."""
    await _open(hass).async_remove()


class Results:
    """In-memory saved results, mirrored to a private Home Assistant store."""

    def __init__(self, hass: HomeAssistant, *, enabled: bool) -> None:
        self.enabled = enabled
        self.writable = True
        self.items: dict[str, Item] = {}
        self.problems: list[str] = []
        self._store = _open(hass)
        self._lock = asyncio.Lock()

    async def load(self) -> None:
        """Read saved results; turning saving off deletes them instead."""
        if not self.enabled:
            await self._store.async_remove()
            return
        try:
            data = await self._store.async_load()
        except HomeAssistantError:
            self.writable = False
            self.problems.append(UNAVAILABLE)
            return
        entries = data.get("items") if isinstance(data, dict) else None
        if data is not None and not isinstance(entries, dict):
            self._problem(INVALID)
        for directory, raw in sorted((entries or {}).items())[:MAX_ITEMS]:
            try:
                self.items[directory] = _item(directory, raw)
            except ValueError:
                self._problem(INVALID)
        if len(entries or {}) > MAX_ITEMS:
            self._problem(INVALID)

    def _problem(self, key: str) -> None:
        if key not in self.problems:
            self.problems.append(key)

    def status(self) -> str | None:
        """Why a result would not be saved now, or None when saving works."""
        if not self.enabled:
            return "disabled"
        return None if self.writable else UNAVAILABLE

    async def record(self, directory: str, scan: Scan) -> tuple[Item, list[str]]:
        """Keep the scan as latest; the first complete scan also becomes the baseline."""
        saved = Saved.from_scan(scan)
        async with self._lock:
            previous = self.items.get(directory)
            baseline = previous.baseline if previous else None
            if baseline is None and complete(saved.report):
                baseline = saved
            item = Item(saved, baseline)
            if self.status() is not None:
                # The saving status, and the store problem when unreadable, say why.
                return item, []
            candidate = {**self.items, directory: item}
            if len(candidate) > MAX_ITEMS or _size(candidate) > MAX_BYTES:
                return item, [LIMIT]
            await self._save(candidate)
            return item, []

    async def review(self, directory: str, digest: object) -> Item:
        """Make the latest scan the baseline, only if it is the scan the caller names."""
        async with self._lock:
            # Checked under the lock: a scan saved while this call waited is refused.
            self._reviewable(directory, digest)
            latest = self.items[directory].latest
            item = Item(latest, latest)
            await self._save({**self.items, directory: item})
            return item

    def _reviewable(self, directory: str, digest: object) -> None:
        item = self.items.get(directory)
        if item is None:
            key = "results_not_found"
        elif not isinstance(digest, str) or not SHA256.fullmatch(digest):
            key = REVIEW_ERROR
        elif item.latest.report.target.artifact_sha256 != digest:
            key = "results_stale"
        elif not complete(item.latest.report):
            key = "results_incomplete"
        elif self.status() is not None:
            key = "results_not_saving"
        else:
            return
        raise ServiceValidationError(translation_domain=DOMAIN, translation_key=key)

    async def prune(self, directories: set[str]) -> None:
        """Forget folders that a complete inventory no longer lists."""
        async with self._lock:
            kept = {d: item for d, item in self.items.items() if d in directories}
            if kept.keys() != self.items.keys() and self.status() is None:
                await self._save(kept)

    async def clear(self) -> None:
        """Delete everything, including a store this run could not read."""
        async with self._lock:
            await self._store.async_remove()
            self.items = {}
            self.problems = []
            self.writable = True

    async def _save(self, items: dict[str, Item]) -> None:
        await self._store.async_save({"items": _serialize(items)})
        self.items = items


def _serialize(items: Mapping[str, Item]) -> dict[str, Any]:
    return {directory: item.as_dict() for directory, item in sorted(items.items())}


def _size(items: Mapping[str, Item]) -> int:
    return len(json.dumps({"items": _serialize(items)}).encode())
