"""Lifecycle and configuration through Home Assistant's actual flow manager."""

import asyncio
import json
from importlib.metadata import version
from pathlib import Path
from unittest.mock import patch

import pytest
from homeassistant.config_entries import SOURCE_USER, ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.doorcheck import DOMAIN
from custom_components.doorcheck.diagnostics import async_get_config_entry_diagnostics


async def test_setup_unload_reload_and_remove(hass: HomeAssistant) -> None:
    with (
        patch("doorcheck.capabilities.scan", side_effect=AssertionError("must not scan")),
        patch("doorcheck.rules.scan", side_effect=AssertionError("must not scan")),
        patch("doorcheck.adapters.base.run", side_effect=AssertionError("must not run tools")),
    ):
        form = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})
        assert form["type"] is FlowResultType.FORM
        assert form["step_id"] == "user"
        assert form["data_schema"] is None
        result = await hass.config_entries.flow.async_configure(form["flow_id"], {})
        await hass.async_block_till_done()
        assert result["type"] is FlowResultType.CREATE_ENTRY
        assert result["title"] == "Doorcheck"
        assert result["data"] == {}
        entry = result["result"]
        assert entry.version == 1
        assert entry.unique_id == DOMAIN
        assert entry.state is ConfigEntryState.LOADED
        previous = entry.runtime_data
        assert previous.engine_version == version("doorcheck")
        assert await hass.config_entries.async_unload(entry.entry_id)
        assert entry.state is ConfigEntryState.NOT_LOADED
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
        assert entry.state is ConfigEntryState.LOADED
        assert entry.runtime_data is not previous
        assert await hass.config_entries.async_remove(entry.entry_id)
        assert not hass.config_entries.async_entries(DOMAIN)


async def test_existing_instance_cannot_be_duplicated(hass: HomeAssistant) -> None:
    entry = MockConfigEntry(domain=DOMAIN, unique_id=DOMAIN)
    entry.add_to_hass(hass)
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "single_instance_allowed"
    assert len(hass.config_entries.async_entries(DOMAIN)) == 1


async def test_concurrent_setup_is_single_instance(hass: HomeAssistant) -> None:
    first = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})
    second = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})
    assert second["type"] is FlowResultType.ABORT
    assert second["reason"] == "already_in_progress"
    hass.config_entries.flow.async_abort(first["flow_id"])


async def test_diagnostics_never_export_configuration(hass: HomeAssistant) -> None:
    entry = MockConfigEntry(
        domain=DOMAIN,
        unique_id=DOMAIN,
        data={"api_key": "private-key", "path": "/private/config", "name": "private-name"},
        options={"access_token": "private-token", "nested": {"secret": "private-value"}},
    )
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    data = await async_get_config_entry_diagnostics(hass, entry)
    assert data == {"engine_version": version("doorcheck"), "scanning_available": False}
    assert "private" not in json.dumps(data)


def test_manifest_requires_the_actual_local_engine() -> None:
    manifest = json.loads(Path("custom_components/doorcheck/manifest.json").read_text())
    assert manifest["requirements"] == [f"doorcheck=={version('doorcheck')}"]
    assert manifest["domain"] == DOMAIN
    assert manifest["config_flow"] is True
    assert manifest["single_config_entry"] is True


async def test_engine_metadata_read_is_off_the_event_loop(hass: HomeAssistant) -> None:
    expected = version("doorcheck")

    def metadata(name: str) -> str:
        assert name == DOMAIN
        with pytest.raises(RuntimeError, match="no running event loop"):
            asyncio.get_running_loop()
        return expected

    entry = MockConfigEntry(domain=DOMAIN, unique_id=DOMAIN)
    entry.add_to_hass(hass)
    with patch("custom_components.doorcheck.version", new=metadata):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
    assert entry.runtime_data.engine_version == expected
