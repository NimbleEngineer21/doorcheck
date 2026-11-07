"""Explicit scans, saved results, and a daily signed check for withdrawn versions."""

from dataclasses import dataclass
from importlib.metadata import version

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.typing import ConfigType

from . import panel
from .const import CHECK_STATUS, DOMAIN, SAVE_RESULTS
from .results import Results, delete
from .services import register
from .status import StatusCheck, clear_issues, remove

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)


@dataclass(frozen=True, slots=True)
class RuntimeData:
    """Only runtime facts needed by this development scaffold."""

    engine_version: str
    results: Results
    status: StatusCheck | None


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
    status = None
    if entry.options.get(CHECK_STATUS, True):
        status = StatusCheck(hass, engine_version)
        await status.start()
    else:
        clear_issues(hass)
    entry.runtime_data = RuntimeData(engine_version, results, status)
    entry.async_on_unload(entry.add_update_listener(_options_updated))
    return True


async def _options_updated(hass: HomeAssistant, entry: DoorcheckEntry) -> None:
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: DoorcheckEntry) -> bool:
    """Remove the sidebar and stop saving; actions still enforce the loaded-entry gate."""
    panel.unload(hass)
    if entry.runtime_data.status is not None:
        entry.runtime_data.status.stop()
    # A scan still running must not write a store that a reload or removal replaced.
    await entry.runtime_data.results.close()
    return True


async def async_remove_entry(hass: HomeAssistant, entry: DoorcheckEntry) -> None:
    """Removing Doorcheck deletes its saved results, status record and Repairs issues."""
    await delete(hass)
    await remove(hass)
