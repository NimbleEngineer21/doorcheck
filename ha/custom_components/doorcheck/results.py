"""Saved scan results: a reviewed baseline and the latest scan per directory.

Stored reports are reloaded with the engine's strict report reader. An entry
that fails any check is dropped and reported, never partly trusted. A store
that cannot be read is left untouched on disk: saving stops for this run
instead of overwriting data Doorcheck could not read. One lock orders every
change, so a clear or review is never undone by a save already in progress.
Encoding and parsing run in the executor, never on the event loop.
"""

import asyncio
import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Self

import orjson
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
WRITE_FAILED = "problem.ha_results_write_failed"
REVIEW_ERROR = "results_invalid_request"
UNLOADED = "unloaded"

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


def scan_id(saved: Saved) -> str:
    """Names one saved scan exactly: its report, time and every file and bytecode hash."""
    canonical = orjson.dumps(saved.as_dict(), option=orjson.OPT_SORT_KEYS)
    return hashlib.sha256(canonical).hexdigest()


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


def _parse(data: object) -> tuple[dict[str, Item], list[str]]:
    entries = data.get("items") if isinstance(data, dict) else None
    if not isinstance(entries, dict):
        return {}, [] if data is None else [INVALID]
    items: dict[str, Item] = {}
    invalid = len(entries) > MAX_ITEMS
    for directory, raw in sorted(entries.items())[:MAX_ITEMS]:
        try:
            items[directory] = _item(directory, raw)
        except ValueError:
            invalid = True
    return items, [INVALID] if invalid else []


def _payload(items: Mapping[str, Item]) -> bytes:
    return orjson.dumps({d: item.as_dict() for d, item in sorted(items.items())})


class _Store(Store[dict[str, Any]]):
    """Refuse any store version other than 1.1, and record whether a write happened."""

    written = False

    async def _async_migrate_func(
        self, old_major_version: int, old_minor_version: int, old_data: dict[str, Any]
    ) -> dict[str, Any]:
        # HA calls this for any other version. Returning the data would let HA rewrite
        # a newer minor version as 1.1, and the strict reader would then drop entries.
        raise HomeAssistantError

    async def _async_write_data(self, *args: Any) -> None:
        # HA logs and swallows write and serialization errors; this flag says if it wrote.
        await super()._async_write_data(*args)
        self.written = True


def _open(hass: HomeAssistant) -> _Store:
    return _Store(hass, STORE_VERSION, STORE_KEY, private=True, atomic_writes=True)


async def delete(hass: HomeAssistant) -> None:
    """Delete the saved results store without reading it."""
    await _open(hass).async_remove()


def _refused(key: str) -> ServiceValidationError:
    return ServiceValidationError(translation_domain=DOMAIN, translation_key=key)


class Results:
    """In-memory saved results, mirrored to a private Home Assistant store."""

    def __init__(self, hass: HomeAssistant, *, enabled: bool) -> None:
        self.enabled = enabled
        self.writable = True
        self.closed = False  # pragma: no mutate - None is equally false
        self.items: dict[str, Item] = {}
        self.problems: list[str] = []
        self._hass = hass
        self._store = _open(hass)
        self._lock = asyncio.Lock()

    async def load(self) -> None:
        """Read saved results; turning saving off deletes them instead."""
        if not self.enabled:
            await self._store.async_remove()
            return
        try:
            data = await self._store.async_load()
        except (HomeAssistantError, KeyError, TypeError):
            # HA's loader raises KeyError or TypeError for JSON without a valid envelope.
            self.writable = False
            self.problems.append(UNAVAILABLE)
            return
        self.items, self.problems = await self._hass.async_add_executor_job(_parse, data)

    async def close(self) -> None:
        """Stop all writes once the entry unloads; a later store belongs to a new entry."""
        async with self._lock:
            self.closed = True

    def status(self) -> str | None:
        """Why a result would not be saved now, or None when saving works."""
        if self.closed:
            return UNLOADED
        if not self.enabled:
            return "disabled"
        return None if self.writable else UNAVAILABLE

    async def record(self, directory: str, scan: Scan) -> tuple[Item, list[str]]:
        """Keep the scan as latest; the first complete scan also becomes the baseline."""
        saved = Saved.from_scan(scan)
        async with self._lock:
            # After unload this memory may describe a store that was deleted or replaced.
            previous = None if self.closed else self.items.get(directory)
            # A result that is not saved shows only a baseline that is in the store.
            unsaved = Item(saved, previous.baseline if previous else None)
            if scan.missing or self.status() is not None:
                # The report, the saving status and any store problem say why.
                return unsaved, []
            baseline = unsaved.baseline
            if baseline is None and complete(saved.report):
                baseline = saved
            item = Item(saved, baseline)
            candidate = {**self.items, directory: item}
            if len(candidate) > MAX_ITEMS:
                return unsaved, [LIMIT]
            payload = await self._hass.async_add_executor_job(_payload, candidate)
            if len(payload) > MAX_BYTES:
                return unsaved, [LIMIT]
            if not await self._save(candidate, payload):
                return unsaved, [WRITE_FAILED]
            return item, []

    async def review(self, directory: str, wanted: object) -> Item:
        """Make the latest scan the baseline, only if it is the scan the caller names."""
        async with self._lock:
            # Checked under the lock: a scan saved while this call waited is refused.
            item = self.items.get(directory)
            if item is None:
                raise _refused("results_not_found")
            if not isinstance(wanted, str) or not SHA256.fullmatch(wanted):
                raise _refused(REVIEW_ERROR)
            if await self._hass.async_add_executor_job(scan_id, item.latest) != wanted:
                raise _refused("results_stale")
            if not complete(item.latest.report):
                raise _refused("results_incomplete")
            if self.status() is not None:
                raise _refused("results_not_saving")
            reviewed = Item(item.latest, item.latest)
            candidate = {**self.items, directory: reviewed}
            payload = await self._hass.async_add_executor_job(_payload, candidate)
            if not await self._save(candidate, payload):
                raise HomeAssistantError(
                    translation_domain=DOMAIN, translation_key="results_write_failed"
                )
            return reviewed

    async def prune(self, directories: set[str]) -> None:
        """Forget folders that a complete inventory no longer lists."""
        async with self._lock:
            kept = {d: item for d, item in self.items.items() if d in directories}
            if kept.keys() != self.items.keys() and self.status() is None:
                # A failed write keeps the entries; the next complete inventory retries.
                await self._save(kept, await self._hass.async_add_executor_job(_payload, kept))

    async def clear(self) -> None:
        """Delete everything, including a store this run could not read."""
        async with self._lock:
            if self.closed:
                # The store now belongs to the reloaded entry, or to nobody.
                raise _refused("inventory_not_configured")
            await self._store.async_remove()
            self.items = {}
            self.problems = []
            self.writable = True

    async def _save(self, items: dict[str, Item], payload: bytes) -> bool:
        """Write already encoded items; memory changes only when the store was written."""
        self._store.written = False  # pragma: no mutate - None is equally false
        await self._store.async_save({"items": orjson.Fragment(payload)})
        if self._store.written:
            self.items = items
        return self._store.written
