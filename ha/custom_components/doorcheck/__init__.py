"""Development preview with explicit scans and saved results; no background alerts."""

from dataclasses import dataclass
from importlib.metadata import version

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.typing import ConfigType

from . import panel
from .const import DOMAIN, SAVE_RESULTS
from .results import Results, delete
from .services import register

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)


@dataclass(frozen=True, slots=True)
class RuntimeData:
    """Only runtime facts needed by this development scaffold."""

    engine_version: str
    results: Results


type DoorcheckEntry = ConfigEntry[RuntimeData]


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Register the action even when the config entry is unloaded."""
    register(hass)
    await panel.register(hass)
    return True


async def async_setup_entry(hass: HomeAssistant, entry: DoorcheckEntry) -> bool:
    """Load saved results and record the engine version without starting any scans."""
    engine_version = await hass.async_add_executor_job(version, DOMAIN)
    results = Results(hass, enabled=entry.options.get(SAVE_RESULTS, True))
    await results.load()
    await panel.setup(hass)
    entry.runtime_data = RuntimeData(engine_version, results)
    entry.async_on_unload(entry.add_update_listener(_options_updated))
    return True


async def _options_updated(hass: HomeAssistant, entry: DoorcheckEntry) -> None:
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: DoorcheckEntry) -> bool:
    """Remove the sidebar; actions still enforce the loaded-entry gate."""
    panel.unload(hass)
    return True


async def async_remove_entry(hass: HomeAssistant, entry: DoorcheckEntry) -> None:
    """Removing Doorcheck deletes its saved results."""
    await delete(hass)
