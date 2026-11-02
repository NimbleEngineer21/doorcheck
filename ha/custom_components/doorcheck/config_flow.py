"""Single-instance setup through Home Assistant's native config flow."""

from typing import Any

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult

from .const import DOMAIN, NAME


class DoorcheckConfigFlow(ConfigFlow, domain=DOMAIN):
    """Confirm setup without requesting credentials or enabling scans."""

    VERSION = 1

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        await self.async_set_unique_id(DOMAIN)
        self._abort_if_unique_id_configured()
        if user_input is None:
            return self.async_show_form()
        return self.async_create_entry(title=NAME, data={})
