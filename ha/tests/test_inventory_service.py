"""Authorization, on-demand I/O and lifecycle of the native inventory action."""

import asyncio
from pathlib import Path
from unittest.mock import patch

import pytest
from homeassistant.auth.const import GROUP_ID_ADMIN, GROUP_ID_USER
from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import Context, HomeAssistant, SupportsResponse
from homeassistant.exceptions import ServiceValidationError, Unauthorized, UnknownUser
from homeassistant.setup import async_setup_component
from pytest_homeassistant_custom_component.common import MockConfigEntry

try:
    from probatio import Invalid as SchemaError
except ImportError:
    from voluptuous import Invalid as SchemaError

from custom_components.doorcheck import DOMAIN, services
from tests.test_inventory import integration


async def loaded(hass: HomeAssistant) -> MockConfigEntry:
    entry = MockConfigEntry(domain=DOMAIN, unique_id=DOMAIN)
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    return entry


async def test_inventory_requires_response_and_only_runs_on_demand(
    hass: HomeAssistant, tmp_path: Path
) -> None:
    original = services.read_inventory
    calls = []

    def read(root: Path):
        with pytest.raises(RuntimeError, match="no running event loop"):
            asyncio.get_running_loop()
        calls.append(root)
        return original(root)

    with patch.object(services, "read_inventory", new=read):
        entry = await loaded(hass)
        assert calls == []
        hass.config.config_dir = str(tmp_path)
        integration(tmp_path / "custom_components", name="User's integration")
        admin = await hass.auth.async_create_user("Admin", group_ids=[GROUP_ID_ADMIN])
        response = await hass.services.async_call(
            DOMAIN,
            "get_inventory",
            {},
            blocking=True,
            return_response=True,
            context=Context(user_id=admin.id),
        )
        assert response["status"] == "complete"
        assert response["items"][0]["name"] == "User's integration"
        assert calls == [tmp_path / "custom_components"]
        assert hass.services.supports_response(DOMAIN, "get_inventory") is SupportsResponse.ONLY
        with pytest.raises(ServiceValidationError):
            await hass.services.async_call(DOMAIN, "get_inventory", {}, blocking=True)
        with pytest.raises(SchemaError, match="root"):
            await hass.services.async_call(
                DOMAIN,
                "get_inventory",
                {"root": "/private"},
                blocking=True,
                return_response=True,
                context=Context(user_id=admin.id),
            )
        assert len(calls) == 1
        assert await hass.config_entries.async_unload(entry.entry_id)
        with pytest.raises(ServiceValidationError) as stopped:
            await hass.services.async_call(
                DOMAIN,
                "get_inventory",
                {},
                blocking=True,
                return_response=True,
                context=Context(user_id=admin.id),
            )
        assert stopped.value.translation_key == "inventory_not_configured"
        assert stopped.value.translation_domain == DOMAIN
        assert len(calls) == 1


@pytest.mark.parametrize("identity", ["user", "unknown"])
async def test_non_admin_and_unknown_users_never_read_files(
    hass: HomeAssistant, identity: str
) -> None:
    await loaded(hass)
    await hass.auth.async_create_user("Owner", group_ids=[GROUP_ID_ADMIN])
    user = await hass.auth.async_create_user("User", group_ids=[GROUP_ID_USER])
    user_id = user.id if identity == "user" else "missing-user"
    expected = Unauthorized if identity == "user" else UnknownUser
    with (
        patch.object(services, "read_inventory", side_effect=AssertionError("must not read")),
        pytest.raises(expected),
    ):
        await hass.services.async_call(
            DOMAIN,
            "get_inventory",
            {},
            blocking=True,
            return_response=True,
            context=Context(user_id=user_id),
        )


async def test_native_internal_calls_follow_ha_admin_service_semantics(
    hass: HomeAssistant, tmp_path: Path
) -> None:
    await loaded(hass)
    hass.config.config_dir = str(tmp_path)
    root = tmp_path / "custom_components"
    root.mkdir()
    result = await hass.services.async_call(
        DOMAIN, "get_inventory", {}, blocking=True, return_response=True
    )
    assert result["status"] == "complete" and result["items"] == []


async def test_registered_without_entry_and_available_after_reload(hass: HomeAssistant) -> None:
    assert await async_setup_component(hass, DOMAIN, {})
    assert hass.services.has_service(DOMAIN, "get_inventory")
    with pytest.raises(ServiceValidationError) as stopped:
        await hass.services.async_call(
            DOMAIN, "get_inventory", {}, blocking=True, return_response=True
        )
    assert stopped.value.translation_key == "inventory_not_configured"
    entry = await loaded(hass)
    assert await hass.config_entries.async_reload(entry.entry_id)
    await hass.async_block_till_done()
    assert hass.services.has_service(DOMAIN, "get_inventory")
    assert len(hass.config_entries.async_entries(DOMAIN)) == 1


async def test_other_loaded_integrations_do_not_authorize_unloaded_doorcheck(
    hass: HomeAssistant,
) -> None:
    assert await async_setup_component(hass, DOMAIN, {})
    other = MockConfigEntry(domain="other")
    other.add_to_hass(hass)
    other.mock_state(hass, ConfigEntryState.LOADED)
    with (
        patch.object(services, "read_inventory", side_effect=AssertionError("must not read")),
        pytest.raises(ServiceValidationError) as stopped,
    ):
        await hass.services.async_call(
            DOMAIN, "get_inventory", {}, blocking=True, return_response=True
        )
    assert stopped.value.translation_key == "inventory_not_configured"
    other.mock_state(hass, ConfigEntryState.NOT_LOADED)
