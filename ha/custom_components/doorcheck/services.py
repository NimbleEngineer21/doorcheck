"""Native admin-authorized inventory action, independent of scan execution."""

from pathlib import Path

from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant, ServiceCall, ServiceResponse, SupportsResponse
from homeassistant.exceptions import ServiceValidationError
from homeassistant.helpers.service import async_register_admin_service

from .const import DOMAIN
from .inventory import read_inventory

SERVICE_INVENTORY = "get_inventory"


def register(hass: HomeAssistant) -> None:
    async def inventory(call: ServiceCall) -> ServiceResponse:
        if not any(
            entry.state is ConfigEntryState.LOADED
            for entry in hass.config_entries.async_entries(DOMAIN)
        ):
            raise ServiceValidationError(
                translation_domain=DOMAIN, translation_key="inventory_not_configured"
            )
        root = Path(hass.config.path("custom_components"))
        result = await hass.async_add_executor_job(read_inventory, root)
        return result.as_dict()

    async_register_admin_service(
        hass, DOMAIN, SERVICE_INVENTORY, inventory, supports_response=SupportsResponse.ONLY
    )
