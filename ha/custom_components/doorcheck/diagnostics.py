"""Allowlisted diagnostics: never export configuration, paths or credentials."""

from homeassistant.core import HomeAssistant

from . import DoorcheckEntry


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: DoorcheckEntry
) -> dict[str, str | bool]:
    return {"engine_version": entry.runtime_data.engine_version, "scanning_available": True}
