"""Native admin-authorized inventory and explicit single-worker scan actions."""

import asyncio
from pathlib import Path
from typing import Any

from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant, ServiceCall, ServiceResponse, SupportsResponse
from homeassistant.exceptions import ServiceValidationError
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.service import async_register_admin_service
from homeassistant.util import slugify

from doorcheck.report import to_dict

from .const import DOMAIN
from .inventory import read_inventory
from .scan import scan_integration

SERVICE_INVENTORY = "get_inventory"
SERVICE_SCAN = "scan_integration"


def register(hass: HomeAssistant) -> None:
    active: asyncio.Future[ServiceResponse] | None = None

    def finished(future: asyncio.Future[ServiceResponse]) -> None:
        nonlocal active
        active = None
        if not future.cancelled():
            future.exception()

    async def scan(call: ServiceCall) -> ServiceResponse:
        nonlocal active
        _require_loaded(hass)
        directory = call.data["directory"]
        if not directory or len(directory) > 255 or slugify(directory) != directory:
            raise ServiceValidationError(
                translation_domain=DOMAIN, translation_key="scan_invalid_directory"
            )
        if active is not None:
            raise ServiceValidationError(translation_domain=DOMAIN, translation_key="scan_busy")
        root = Path(hass.config.path("custom_components"))
        active = hass.async_add_executor_job(_scan_response, root, directory)
        active.add_done_callback(finished)
        return await asyncio.shield(active)

    async def inventory(call: ServiceCall) -> ServiceResponse:
        _require_loaded(hass)
        root = Path(hass.config.path("custom_components"))
        result = await hass.async_add_executor_job(read_inventory, root)
        return result.as_dict()

    async_register_admin_service(
        hass, DOMAIN, SERVICE_INVENTORY, inventory, supports_response=SupportsResponse.ONLY
    )

    async_register_admin_service(
        hass,
        DOMAIN,
        SERVICE_SCAN,
        scan,
        # Use the native schema implementation across the HA validator migration.
        schema=type(cv.PLATFORM_SCHEMA)(_scan_data),
        supports_response=SupportsResponse.ONLY,
    )


def _scan_data(data: dict[str, Any]) -> dict[str, Any]:
    if set(data) != {"directory"} or not isinstance(data["directory"], str):
        raise ServiceValidationError(
            translation_domain=DOMAIN, translation_key="scan_invalid_directory"
        )
    return data


def _require_loaded(hass: HomeAssistant) -> None:
    if not any(
        entry.state is ConfigEntryState.LOADED
        for entry in hass.config_entries.async_entries(DOMAIN)
    ):
        raise ServiceValidationError(
            translation_domain=DOMAIN, translation_key="inventory_not_configured"
        )


def _scan_response(root: Path, directory: str) -> ServiceResponse:
    return {
        "scope": "custom_integration_snapshot",
        "origin": "unknown",
        "report": to_dict(scan_integration(root, directory)),
    }
