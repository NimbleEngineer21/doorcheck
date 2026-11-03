"""Native authorization, exact selection, concurrency and cancellation."""

import asyncio
import threading
from pathlib import Path
from unittest.mock import patch

import pytest
from homeassistant.auth.const import GROUP_ID_ADMIN, GROUP_ID_USER
from homeassistant.core import Context, HomeAssistant, SupportsResponse
from homeassistant.exceptions import ServiceValidationError, Unauthorized, UnknownUser
from homeassistant.setup import async_setup_component

from custom_components.doorcheck import DOMAIN, services
from tests.test_inventory_service import loaded


async def invoke(hass, data=None, context=None):
    return await hass.services.async_call(
        DOMAIN,
        "scan_integration",
        {"directory": "example"} if data is None else data,
        blocking=True,
        return_response=True,
        context=context,
    )


async def test_scan_only_on_demand_from_fixed_root(hass: HomeAssistant, tmp_path: Path) -> None:
    original = services.scan_integration
    calls = []

    def scan(root, directory):
        with pytest.raises(RuntimeError, match="no running event loop"):
            asyncio.get_running_loop()
        calls.append((root, directory))
        return original(root, directory)

    serialize = services.to_dict

    def serialized(report):
        with pytest.raises(RuntimeError, match="no running event loop"):
            asyncio.get_running_loop()
        return serialize(report)

    with (
        patch.object(services, "scan_integration", new=scan),
        patch.object(services, "to_dict", new=serialized),
    ):
        entry = await loaded(hass)
        assert calls == []
        hass.config.config_dir = str(tmp_path)
        selected = tmp_path / "custom_components/example"
        selected.mkdir(parents=True)
        (selected / "code.py").write_text('import os\nos.system("example")')
        admin = await hass.auth.async_create_user("Admin", group_ids=[GROUP_ID_ADMIN])
        response = await invoke(hass, context=Context(user_id=admin.id))
        assert response["scope"] == "custom_integration_snapshot"
        assert response["origin"] == "unknown"
        assert response["report"]["target"]["name"] == "example"
        assert any(c["kind"] == "process" for c in response["report"]["capabilities"])
        assert calls == [(tmp_path / "custom_components", "example")]
        assert hass.services.supports_response(DOMAIN, "scan_integration") is SupportsResponse.ONLY
        with pytest.raises(ServiceValidationError):
            await hass.services.async_call(
                DOMAIN, "scan_integration", {"directory": "example"}, blocking=True
            )
        assert await hass.config_entries.async_unload(entry.entry_id)
        with pytest.raises(ServiceValidationError) as stopped:
            await invoke(hass)
        assert stopped.value.translation_key == "inventory_not_configured"
        assert stopped.value.translation_domain == DOMAIN
        assert len(calls) == 1


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"directory": 1},
        {"directory": "example", "root": "/private"},
        {"directory": ""},
        {"directory": "../example"},
        {"directory": "/example"},
        {"directory": "a/b"},
        {"directory": "a\\b"},
        {"directory": "Example"},
        {"directory": "__pycache__"},
        {"directory": "a" * 256},
    ],
)
async def test_invalid_selection_never_reads(hass: HomeAssistant, data: dict) -> None:
    await loaded(hass)
    with (
        patch.object(services, "scan_integration") as scan,
        pytest.raises(ServiceValidationError) as invalid,
    ):
        await invoke(hass, data)
    assert invalid.value.translation_key == "scan_invalid_directory"
    assert invalid.value.translation_domain == DOMAIN
    scan.assert_not_called()


@pytest.mark.parametrize("identity", ["user", "unknown"])
async def test_scan_rejects_nonadmins_before_io(hass: HomeAssistant, identity: str) -> None:
    await loaded(hass)
    await hass.auth.async_create_user("Owner", group_ids=[GROUP_ID_ADMIN])
    user = await hass.auth.async_create_user("User", group_ids=[GROUP_ID_USER])
    expected = Unauthorized if identity == "user" else UnknownUser
    with patch.object(services, "scan_integration") as scan, pytest.raises(expected):
        await invoke(hass, context=Context(user_id=user.id if identity == "user" else "missing"))
    scan.assert_not_called()


async def test_registered_without_loaded_entry(hass: HomeAssistant) -> None:
    assert await async_setup_component(hass, DOMAIN, {})
    with pytest.raises(ServiceValidationError) as stopped:
        await invoke(hass)
    assert stopped.value.translation_key == "inventory_not_configured"
    assert stopped.value.translation_domain == DOMAIN


async def test_cancelled_caller_retains_single_worker_slot(
    hass: HomeAssistant, tmp_path: Path
) -> None:
    await loaded(hass)
    hass.config.config_dir = str(tmp_path)
    entered, release = threading.Event(), threading.Event()
    original = services.scan_integration

    def blocked(root, directory):
        entered.set()
        assert release.wait(10)
        return original(root, directory)

    futures = []
    executor = hass.async_add_executor_job

    def submit(target, *args):
        future = executor(target, *args)
        if target is services._scan_response:
            futures.append(future)
        return future

    with (
        patch.object(services, "scan_integration", new=blocked),
        patch.object(hass, "async_add_executor_job", new=submit),
    ):
        task = asyncio.create_task(invoke(hass))
        try:
            assert await hass.async_add_executor_job(entered.wait, 5)
            with pytest.raises(ServiceValidationError) as busy:
                await invoke(hass)
            assert busy.value.translation_key == "scan_busy"
            assert busy.value.translation_domain == DOMAIN
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            with pytest.raises(ServiceValidationError) as busy:
                await invoke(hass)
            assert busy.value.translation_key == "scan_busy"
            assert busy.value.translation_domain == DOMAIN
        finally:
            release.set()
            await futures[0]
            await hass.async_block_till_done()
    result = await invoke(hass)
    assert result["report"]["checks"][0]["status"] == "failed"


async def test_cancelled_executor_future_clears_slot(hass: HomeAssistant) -> None:
    await loaded(hass)
    future = asyncio.get_running_loop().create_future()
    future.cancel()
    with (
        patch.object(hass, "async_add_executor_job", return_value=future),
        pytest.raises(asyncio.CancelledError),
    ):
        await invoke(hass)
    await hass.async_block_till_done()
    result = await invoke(hass)
    assert result["report"]["checks"][0]["status"] == "failed"


async def test_other_loaded_entries_do_not_allow_scan(hass: HomeAssistant) -> None:
    from homeassistant.config_entries import ConfigEntryState
    from pytest_homeassistant_custom_component.common import MockConfigEntry

    assert await async_setup_component(hass, DOMAIN, {})
    other = MockConfigEntry(domain="other")
    other.add_to_hass(hass)
    other.mock_state(hass, ConfigEntryState.LOADED)
    with (
        patch.object(services, "scan_integration") as scan,
        pytest.raises(ServiceValidationError) as stopped,
    ):
        await invoke(hass)
    assert stopped.value.translation_key == "inventory_not_configured"
    assert stopped.value.translation_domain == DOMAIN
    scan.assert_not_called()
    other.mock_state(hass, ConfigEntryState.NOT_LOADED)


async def test_maximum_directory_name_is_accepted(hass: HomeAssistant) -> None:
    await loaded(hass)
    response = await invoke(hass, {"directory": "a" * 255})
    assert response["report"]["target"]["name"] == "a" * 255
