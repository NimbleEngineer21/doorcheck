"""Single-instance setup and its two options, through native flows."""

from importlib import import_module
from typing import Any

from homeassistant.config_entries import ConfigEntry, ConfigFlow, ConfigFlowResult, OptionsFlow
from homeassistant.core import callback
from homeassistant.helpers import config_validation as cv

from .const import CHECK_STATUS, DOMAIN, NAME, SAVE_RESULTS


class DoorcheckConfigFlow(ConfigFlow, domain=DOMAIN):
    """Confirm setup without requesting credentials or enabling scans."""

    VERSION = 1

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        await self.async_set_unique_id(DOMAIN)
        self._abort_if_unique_id_configured()
        if user_input is None:
            return self.async_show_form()
        return self.async_create_entry(title=NAME, data={})

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlow:
        return DoorcheckOptionsFlow()


class DoorcheckOptionsFlow(OptionsFlow):
    """Turning saving off deletes saved results; turning the status check off stops it."""

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        if user_input is not None:
            return self.async_create_entry(
                data={key: user_input[key] for key in (SAVE_RESULTS, CHECK_STATUS)}
            )
        options = self.config_entry.options
        # Use the native schema implementation across the HA validator migration.
        native = type(cv.PLATFORM_SCHEMA)
        required = import_module(native.__module__).Required
        schema = native(
            {
                required(SAVE_RESULTS, default=options.get(SAVE_RESULTS, True)): bool,
                required(CHECK_STATUS, default=options.get(CHECK_STATUS, True)): bool,
            }
        )
        return self.async_show_form(step_id="init", data_schema=schema)
