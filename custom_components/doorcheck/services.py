"""Native admin-authorized inventory, explicit scans and saved-result actions."""

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING, Any

from homeassistant.core import HomeAssistant, ServiceCall, ServiceResponse, SupportsResponse
from homeassistant.exceptions import ServiceValidationError
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.service import async_register_admin_service
from homeassistant.util import slugify

from doorcheck.comparison import comparability, compare
from doorcheck.report import to_dict

from .const import DOMAIN
from .inventory import read_inventory
from .results import REVIEW_ERROR, Item, Results, Saved, scan_id
from .scan import scan_integration

if TYPE_CHECKING:
    from . import DoorcheckEntry

SERVICE_INVENTORY = "get_inventory"
SERVICE_SCAN = "scan_integration"
SERVICE_RESULTS = "get_results"
SERVICE_REVIEW = "mark_reviewed"
SERVICE_CLEAR = "clear_results"
DIRECTORY_ERROR = "scan_invalid_directory"
CLEAR_ERROR = "results_clear_invalid"


def register(hass: HomeAssistant) -> None:
    active: asyncio.Future[ServiceResponse] | None = None

    def finished(future: asyncio.Future[ServiceResponse]) -> None:
        nonlocal active
        active = None
        if not future.cancelled():
            future.exception()

    async def scan_and_record(results: Results, root: Path, directory: str) -> ServiceResponse:
        scanned = await hass.async_add_executor_job(scan_integration, root, directory)
        item, problems = await results.record(directory, scanned)
        view = await _view(hass, results, directory, item, problems)
        return {
            "scope": "custom_integration_snapshot",
            "origin": "unknown",
            # The latest result is always this scan: serialize its report once.
            "report": view["latest"]["report"],
            "results": view,
        }

    async def scan(call: ServiceCall) -> ServiceResponse:
        nonlocal active
        results = _loaded(hass).runtime_data.results
        directory = _directory(call.data)
        if active is not None:
            raise ServiceValidationError(translation_domain=DOMAIN, translation_key="scan_busy")
        root = Path(hass.config.path("custom_components"))
        # A caller leaving early must not lose the scan or its saved result.
        active = hass.async_create_task(scan_and_record(results, root, directory))
        active.add_done_callback(finished)
        return await asyncio.shield(active)

    async def inventory(call: ServiceCall) -> ServiceResponse:
        results = _loaded(hass).runtime_data.results
        root = Path(hass.config.path("custom_components"))
        result = await hass.async_add_executor_job(read_inventory, root)
        listed = result.as_dict()
        if listed["status"] == "complete":
            await results.prune({item["directory"] for item in listed["items"]})
        return listed

    async def saved(call: ServiceCall) -> ServiceResponse:
        results = _loaded(hass).runtime_data.results
        directory = _directory(call.data)
        item = results.items.get(directory)
        view = None if item is None else await _view(hass, results, directory, item, [])
        # Store problems are listed even when no entry for this directory survived.
        return {"scope": "saved_results", "problems": list(results.problems), "results": view}

    async def review(call: ServiceCall) -> ServiceResponse:
        results = _loaded(hass).runtime_data.results
        directory = _directory(call.data)
        item = await results.review(directory, call.data.get("scan_id"))
        return {
            "scope": "saved_results",
            "problems": list(results.problems),
            "results": await _view(hass, results, directory, item, []),
        }

    async def clear(call: ServiceCall) -> None:
        await _loaded(hass).runtime_data.results.clear()

    async_register_admin_service(
        hass, DOMAIN, SERVICE_INVENTORY, inventory, supports_response=SupportsResponse.ONLY
    )
    for name, handler, schema in (
        (SERVICE_SCAN, scan, _fields({"directory"}, DIRECTORY_ERROR)),
        (SERVICE_RESULTS, saved, _fields({"directory"}, DIRECTORY_ERROR)),
        (SERVICE_REVIEW, review, _fields({"directory", "scan_id"}, REVIEW_ERROR)),
    ):
        async_register_admin_service(
            hass,
            DOMAIN,
            name,
            handler,
            # Use the native schema implementation across the HA validator migration.
            schema=type(cv.PLATFORM_SCHEMA)(schema),
            supports_response=SupportsResponse.ONLY,
        )
    async_register_admin_service(
        hass,
        DOMAIN,
        SERVICE_CLEAR,
        clear,
        schema=type(cv.PLATFORM_SCHEMA)(_fields(set(), CLEAR_ERROR)),
    )


def _fields(expected: set[str], error: str) -> Any:
    def validate(data: dict[str, Any]) -> dict[str, Any]:
        if set(data) != expected or not all(isinstance(data[k], str) for k in expected):
            raise ServiceValidationError(translation_domain=DOMAIN, translation_key=error)
        return data

    return validate


def _directory(data: Any) -> str:
    directory: str = data["directory"]
    if not directory or len(directory) > 255 or slugify(directory) != directory:
        raise ServiceValidationError(
            translation_domain=DOMAIN, translation_key="scan_invalid_directory"
        )
    return directory


def _loaded(hass: HomeAssistant) -> "DoorcheckEntry":
    for entry in hass.config_entries.async_loaded_entries(DOMAIN):
        return entry
    raise ServiceValidationError(
        translation_domain=DOMAIN, translation_key="inventory_not_configured"
    )


async def _view(
    hass: HomeAssistant, results: Results, directory: str, item: Item, problems: list[str]
) -> dict[str, Any]:
    return await hass.async_add_executor_job(_view_data, results, directory, item, problems)


def _view_data(results: Results, directory: str, item: Item, problems: list[str]) -> dict[str, Any]:
    stored = results.items.get(directory) is item
    baseline = item.baseline
    latest = _record(item.latest)
    if baseline is item.latest:
        reviewed: dict[str, Any] | None = latest  # The same scan: serialize it once.
    else:
        reviewed = None if baseline is None else _record(baseline)
    return {
        "directory": directory,
        "saving": results.status() or "on",
        "saved": stored,
        "problems": [*results.problems, *problems],
        "latest": latest,
        "baseline": reviewed,
        "comparison": None if baseline is None else _comparison(baseline, item.latest),
    }


def _record(saved: Saved) -> dict[str, Any]:
    return {
        "scan_id": scan_id(saved),
        "scanned_at": saved.scanned_at,
        "report": to_dict(saved.report),
        # The capability list leaves interpreter bytecode out; these paths show it.
        "bytecode": sorted(saved.bytecode),
    }


def _changed(before: Any, after: Any) -> dict[str, list[str]]:
    return {
        "added": sorted(after.keys() - before.keys()),
        "removed": sorted(before.keys() - after.keys()),
        "changed": sorted(p for p in before.keys() & after.keys() if before[p] != after[p]),
    }


def _positions(items: tuple[object, ...], chosen: tuple[object, ...]) -> list[int]:
    """Each chosen object's position; one object listed twice takes both positions."""
    free: dict[int, list[int]] = {}
    for number, item in enumerate(items):
        free.setdefault(id(item), []).append(number)
    return [free[id(item)].pop(0) for item in chosen]


def _comparison(baseline: Saved, latest: Saved) -> dict[str, Any]:
    result = comparability(baseline.report, latest.report)
    compared = compare(baseline.report, latest.report)
    # Positions in the report that holds each item: added in latest, removed in
    # baseline. compare() returns the reports' own objects, so no item is copied.
    items = {
        kind: {
            "added": _positions(getattr(latest.report, kind), getattr(compared, kind).added),
            "removed": _positions(getattr(baseline.report, kind), getattr(compared, kind).removed),
        }
        for kind in ("findings", "capabilities")
    }
    files = _changed(baseline.files, latest.files)
    bytecode = _changed(baseline.bytecode, latest.bytecode)
    groups = (items["findings"], items["capabilities"], files, bytecode)
    return {
        # A limit alone is a change: the two scans cannot be read as equal.
        "changed": bool(result.limits) or any(v for group in groups for v in group.values()),
        "limits": [limit.value for limit in result.limits],
        "same_artifact": result.same_artifact,
        **items,
        "files": files,
        "bytecode": bytecode,
    }
