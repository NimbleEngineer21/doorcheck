"""Development scaffold; scanning and update alerts are not available yet."""

from dataclasses import dataclass
from importlib.metadata import version

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.typing import ConfigType

from .const import DOMAIN
from .services import register

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)


@dataclass(frozen=True, slots=True)
class RuntimeData:
    """Only runtime facts needed by this development scaffold."""

    engine_version: str


type DoorcheckEntry = ConfigEntry[RuntimeData]


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Register the action even when the config entry is unloaded."""
    register(hass)
    return True


async def async_setup_entry(hass: HomeAssistant, entry: DoorcheckEntry) -> bool:
    """Record the installed engine version without starting any scans."""
    engine_version = await hass.async_add_executor_job(version, DOMAIN)
    entry.runtime_data = RuntimeData(engine_version)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: DoorcheckEntry) -> bool:
    """There are no platforms, tasks or subscriptions to unload yet."""
    return True
