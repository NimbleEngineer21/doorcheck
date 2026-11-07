"""Allowlisted diagnostics: never export configuration, paths, reports or credentials."""

from typing import Any

from homeassistant.core import HomeAssistant

from . import DoorcheckEntry
from .results import STORE_VERSION


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: DoorcheckEntry
) -> dict[str, Any]:
    results = entry.runtime_data.results
    status = entry.runtime_data.status
    return {
        "engine_version": entry.runtime_data.engine_version,
        "scanning_available": True,
        "saved_results": {
            "status": results.status() or "on",
            "items": len(results.items),
            "store_version": STORE_VERSION,
        },
        "status_check": status.diagnostics() if status is not None else {"state": "off"},
    }
