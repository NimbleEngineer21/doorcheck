"""Native panel lifecycle, server authorization and safe presentation."""

import asyncio
from unittest.mock import patch

import pytest
from doorcheck.capabilities.model import Capability, Kind
from doorcheck.checks import Check, Problem, Status
from doorcheck.findings import Confidence, Finding, Location, Severity
from doorcheck.messages import ENGLISH, render
from doorcheck.report import Report, Target, to_dict
from homeassistant.components.frontend import DATA_PANELS

from custom_components.doorcheck import panel
from tests.test_inventory_service import loaded


def response(checks=None, evidence="<img src=x onerror=alert(1)>\u202e", capabilities=()):
    return {
        "report": to_dict(
            Report(
                "0.1.0",
                Target("example"),
                (Check("snapshot", "0.1.0", Status.COMPLETE),) if checks is None else checks,
                capabilities,
                (
                    Finding(
                        "test-rule",
                        Severity.REVIEW,
                        Confidence.HIGH,
                        Location("code.py", 8, 1),
                        "finding.unauth_file_path",
                        tool="builtin",
                        evidence=evidence,
                    ),
                ),
            )
        )
    }


def test_shared_configuration_and_shadow_tokens() -> None:
    config = panel.configuration()
    expected = {
        key.removeprefix("ha.panel."): value
        for key, value in ENGLISH.items()
        if key.startswith("ha.panel.") and key != "ha.panel.confidence"
    }
    expected.update(
        {
            "scan_busy": render("ha.service.scan_busy"),
            "scan_invalid_directory": render("ha.service.scan_invalid_directory"),
            "inventory_not_configured": render("ha.service.not_configured"),
        }
    )
    assert config["messages"] == expected
    assert config["messages"]["scan_busy"] == render("ha.service.scan_busy")
    assert ":host {" in config["tokens"]
    assert ':host([data-theme="dark"]) {' in config["tokens"]
    assert ":root" not in config["tokens"]


async def test_sidebar_lifecycle_and_public_assets(hass, hass_client) -> None:
    entry = await loaded(hass)
    registered = hass.data[DATA_PANELS]["doorcheck"]
    assert registered.require_admin is True
    assert registered.component_name == "custom"
    assert registered.sidebar_title == "Doorcheck"
    assert registered.sidebar_icon == "mdi:text-box-search-outline"
    assert registered.frontend_url_path == "doorcheck"
    assert registered.config["messages"] == panel.configuration()["messages"]
    assert registered.config["tokens"] == panel.configuration()["tokens"]
    assert registered.config["_panel_custom"]["name"] == "doorcheck-panel"
    assert registered.config["_panel_custom"]["module_url"] == "/doorcheck_static/panel.js"
    client = await hass_client()
    for asset in ("panel.js", "panel.css"):
        result = await client.get("/doorcheck_static/" + asset)
        assert result.status == 200
        assert len(await result.read()) > 100
    assert (await client.get("/doorcheck_static/../manifest.json")).status == 404
    assert await hass.config_entries.async_reload(entry.entry_id)
    assert hass.data[DATA_PANELS]["doorcheck"].require_admin
    assert await hass.config_entries.async_remove(entry.entry_id)
    assert "doorcheck" not in hass.data[DATA_PANELS]


async def test_native_inventory_scan_and_loaded_gate(hass, hass_ws_client, tmp_path) -> None:
    entry = await loaded(hass)
    hass.config.config_dir = str(tmp_path)
    folder = tmp_path / "custom_components/example"
    folder.mkdir(parents=True)
    (folder / "manifest.json").write_text('{"domain":"example","name":"Example","version":"1"}')
    (folder / "__init__.py").write_text('import os\nos.system("example")')
    client = await hass_ws_client(hass)
    await client.send_json({"id": 1, "type": "doorcheck/panel_inventory"})
    inventory = await client.receive_json()
    assert inventory["success"] is True
    assert inventory["result"]["complete"] is True
    assert inventory["result"]["items"] == [
        {"directory": "example", "name": "Example", "version": "1", "problems": []}
    ]
    await client.send_json({"id": 2, "type": "doorcheck/panel_scan", "directory": "example"})
    result = await client.receive_json()
    assert result["success"] is True
    assert result["result"]["target"] == "example"
    assert result["result"]["complete"] is True
    assert result["result"]["findings"] == []
    assert result["result"]["capabilities"][0]["message"]
    await hass.config_entries.async_unload(entry.entry_id)
    for number, command in ((3, "inventory"), (4, "scan")):
        message = {"id": number, "type": "doorcheck/panel_" + command}
        if command == "scan":
            message["directory"] = "example"
        await client.send_json(message)
        error = await client.receive_json()
        assert error["success"] is False
        assert error["error"]["translation_key"] == "inventory_not_configured"


@pytest.mark.parametrize("command", ["inventory", "scan"])
async def test_non_admin_rejected_before_any_io(
    hass, hass_ws_client, hass_read_only_access_token, command
) -> None:
    await loaded(hass)
    client = await hass_ws_client(hass, access_token=hass_read_only_access_token)
    with patch.object(panel, "call", side_effect=AssertionError("unauthorized I/O")):
        await client.send_json(
            {
                "id": 1,
                "type": "doorcheck/panel_" + command,
                **({"directory": "example"} if command == "scan" else {}),
            }
        )
        error = await client.receive_json()
    assert error["success"] is False
    assert error["error"]["code"] == "unauthorized"


@pytest.mark.parametrize(
    "data",
    [{}, {"directory": "../outside"}, {"directory": 1}, {"directory": "example", "extra": True}],
)
async def test_scan_validation_preserved(hass, hass_ws_client, data) -> None:
    await loaded(hass)
    client = await hass_ws_client(hass)
    await client.send_json({"id": 1, "type": "doorcheck/panel_scan", **data})
    error = await client.receive_json()
    assert error["success"] is False
    assert error["error"]["code"] in {"invalid_format", "home_assistant_error"}


async def test_rendering_runs_off_loop_and_keeps_user_context(
    hass, hass_ws_client, hass_admin_user
) -> None:
    await loaded(hass)
    client = await hass_ws_client(hass)
    original = panel.inventory_view
    contexts = []

    async def service(*args, **kwargs):
        contexts.append(kwargs["context"].user_id)
        return {"status": "complete", "items": [], "problems": []}

    def view(data):
        with pytest.raises(RuntimeError, match="no running event loop"):
            asyncio.get_running_loop()
        return original(data)

    with (
        patch("homeassistant.core.ServiceRegistry.async_call", new=service),
        patch.object(panel, "inventory_view", new=view),
    ):
        await client.send_json({"id": 1, "type": "doorcheck/panel_inventory"})
        assert (await client.receive_json())["success"]
    assert contexts == [hass_admin_user.id]


def test_report_view_keeps_coverage_evidence_and_locations() -> None:
    loc = Location("broken.py", 2, 1)
    check = Check(
        "python-rules",
        "0.1.0",
        Status.PARTIAL,
        (Problem("problem.file_not_parsed", loc), Problem("problem.scan_limit_reached")),
    )
    view = panel.report_view(
        response((check,), capabilities=(Capability(Kind.PROCESS, loc, "command\u202e"),))
    )
    assert view["complete"] is False
    assert view["checks"] == [
        {
            "name": "python-rules",
            "status": render("status.partial"),
            "problems": [
                {"message": render("problem.file_not_parsed"), "location": "broken.py:2:1"},
                {"message": render("problem.scan_limit_reached"), "location": None},
            ],
        }
    ]
    finding = view["findings"][0]
    assert finding["evidence"] == "<img src=x onerror=alert(1)>⟨U+202E⟩"
    assert finding["severity"] == "review"
    assert finding["rule"] == "test-rule"
    assert finding["action"] == render("finding.unauth_file_path_action")
    assert finding["detail"] == render("finding.unauth_file_path_detail")
    assert finding["label"] == render("severity.review")
    assert finding["confidence"] == render("ha.panel.confidence", {"value": "high"})
    assert finding["location"] == "code.py:8:1"
    assert "⟨U+202E⟩" in view["capabilities"][0]["message"]
    assert view["capabilities"][0]["location"] == "broken.py:2:1"
    assert panel.report_view(response(()))["complete"] is False
    assert panel.report_view(response(evidence=None))["findings"][0]["evidence"] == ""


def test_inventory_view_preserves_gaps_and_fallback_name() -> None:
    assert panel.inventory_view(
        {
            "status": "partial",
            "problems": ["problem.inventory_time_limit"],
            "items": [
                {
                    "directory": "example",
                    "name": None,
                    "version": None,
                    "problems": ["problem.inventory_manifest_invalid"],
                }
            ],
        }
    ) == {
        "status": render("status.partial"),
        "complete": False,
        "problems": [render("problem.inventory_time_limit")],
        "items": [
            {
                "directory": "example",
                "name": "example",
                "version": None,
                "problems": [render("problem.inventory_manifest_invalid")],
            }
        ],
    }


async def test_response_contract_is_not_silently_lost(hass) -> None:
    from unittest.mock import Mock

    with (
        patch("homeassistant.core.ServiceRegistry.async_call", return_value=None),
        pytest.raises(RuntimeError, match=r"^Response-only action returned no response$"),
    ):
        await panel.call(hass, Mock(), {}, "get_inventory", {})


def test_location_without_column() -> None:
    assert panel.location(Location("name\u202e", 1)) == "name⟨U+202E⟩:1"


def test_finding_without_action_does_not_borrow_another_rules_advice() -> None:
    finding = Finding(
        "external",
        Severity.NOTICE,
        Confidence.LOW,
        Location("file.py", 1),
        "problem.unexpected",
        "external",
        evidence=None,
    )
    assert panel.finding_view(finding)["action"] is None
    assert panel.finding_view(finding)["detail"] is None
    assert panel.finding_view(finding)["message"] == render("problem.unexpected")


async def test_public_asset_registration_is_scoped_and_uncached() -> None:
    from pathlib import Path
    from unittest.mock import AsyncMock, Mock

    hass = Mock()
    hass.http.async_register_static_paths = AsyncMock()
    with patch.object(panel.websocket_api, "async_register_command"):
        await panel.register(hass)
    paths = hass.http.async_register_static_paths.call_args.args[0]
    assert len(paths) == 1
    assert paths[0].url_path == "/doorcheck_static"
    assert Path(paths[0].path) == Path(panel.__file__).parent / "frontend"
    assert paths[0].cache_headers is False


def test_packaged_tokens_are_case_sensitive(tmp_path) -> None:
    from importlib.resources import files
    from zipfile import Path as ZipPath
    from zipfile import ZipFile

    css = files("doorcheck.presentation").joinpath("tokens.css").read_text()
    target = tmp_path / "assets.zip"
    with ZipFile(target, "w") as archive:
        archive.writestr("tokens.css", css)
    with ZipFile(target) as archive, patch.object(panel, "files", return_value=ZipPath(archive)):
        assert ":host {" in panel.configuration()["tokens"]


async def test_action_context_contract(hass) -> None:
    from unittest.mock import Mock

    connection = Mock()
    msg = {"id": 123, "type": "doorcheck/panel_inventory"}
    with patch("homeassistant.core.ServiceRegistry.async_call", return_value={}) as action:
        assert await panel.call(hass, connection, msg, "get_inventory", {}) == {}
    connection.context.assert_called_once_with(msg)
    assert action.call_args.kwargs["context"] is connection.context.return_value


def test_parameterized_findings_and_problems_preserve_safe_values() -> None:
    finding = Finding(
        "external",
        Severity.NOTICE,
        Confidence.LOW,
        Location("file.py", 1),
        "finding.tool_reported",
        "external",
        params={"message": "value\u202e"},
    )
    assert panel.finding_view(finding)["message"] == "The scanner reported: value⟨U+202E⟩"
    problem = Problem("problem.file_path_not_supported", params={"path": "name\u202e"})
    checks = (Check("python-rules", "0.1.0", Status.PARTIAL, (problem,)),)
    view = panel.report_view(response(checks))
    assert "name⟨U+202E⟩" in view["checks"][0]["problems"][0]["message"]
