"""Native panel lifecycle, server authorization and safe presentation."""

import asyncio
from unittest.mock import patch

import pytest
from doorcheck.capabilities.model import Capability, Kind
from doorcheck.checks import Check, Problem, Status
from doorcheck.findings import Confidence, Finding, Location, Severity
from doorcheck.messages import ENGLISH, render
from doorcheck.report import Report, Target, from_dict, to_dict
from homeassistant.components.frontend import DATA_PANELS

from custom_components.doorcheck import panel, results, scan, services
from tests.test_inventory_service import loaded
from tests.test_scan import compiled


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


def report_view(data):
    return panel.report_data(from_dict(data["report"]))


def test_shared_configuration_and_shadow_tokens() -> None:
    config = panel.configuration()
    expected = {
        key.rpartition(".")[2]: value
        for key, value in ENGLISH.items()
        if key.startswith("ha.panel.") and key != "ha.panel.confidence"
    }
    expected.update(
        {
            "scan_busy": render("ha.service.scan_busy"),
            "scan_invalid_directory": render("ha.service.scan_invalid_directory"),
            "inventory_not_configured": render("ha.service.not_configured"),
            **{key.rpartition(".")[2]: render(key) for key in panel.REVIEW_ERRORS},
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
    first = result["result"]["latest"]
    assert first["report"]["target"] == "example"
    assert first["report"]["complete"] is True
    assert first["report"]["findings"] == []
    assert first["report"]["capabilities"][0]["message"]
    assert result["result"]["reviewed"] is True
    assert result["result"]["comparison"] is None
    (folder / "__pycache__").mkdir()
    (folder / "__pycache__/__init__.cpython-314.pyc").write_bytes(compiled())
    (folder / "extra.py").write_text("import subprocess\nsubprocess.run(['x'])")
    await client.send_json({"id": 3, "type": "doorcheck/panel_scan", "directory": "example"})
    second = (await client.receive_json())["result"]
    assert second["reviewed"] is False
    assert second["reviewable"] is True
    assert second["latest"]["bytecode"] == ["__pycache__/__init__.cpython-314.pyc"]
    assert second["comparison"]["changed"] is True
    assert second["comparison"]["files"]["added"] == ["extra.py"]
    assert second["comparison"]["bytecode"]["added"] == ["__pycache__/__init__.cpython-314.pyc"]
    capabilities = second["latest"]["report"]["capabilities"]
    added = {capabilities[i]["location"] for i in second["comparison"]["added"]["capabilities"]}
    assert added == {"extra.py:1:1", "extra.py:2:1"}
    # Opening the saved result reads the store and never scans again.
    with patch.object(scan, "scan_integration", side_effect=AssertionError("scanned")):
        await client.send_json({"id": 4, "type": "doorcheck/panel_results", "directory": "example"})
        assert (await client.receive_json())["result"] == second
    await client.send_json(
        {
            "id": 5,
            "type": "doorcheck/panel_review",
            "directory": "example",
            "scan_id": first["scan_id"],
        }
    )
    stale = await client.receive_json()
    assert stale["error"]["translation_key"] == "results_stale"
    await client.send_json(
        {
            "id": 6,
            "type": "doorcheck/panel_review",
            "directory": "example",
            "scan_id": second["latest"]["scan_id"],
        }
    )
    reviewed = (await client.receive_json())["result"]
    assert reviewed["reviewed"] is True
    assert reviewed["baseline"]["scan_id"] == second["latest"]["scan_id"]
    await client.send_json({"id": 7, "type": "doorcheck/panel_clear"})
    assert (await client.receive_json())["result"] == {"cleared": True}
    await client.send_json({"id": 8, "type": "doorcheck/panel_results", "directory": "example"})
    assert (await client.receive_json())["result"] == {"problems": [], "latest": None}
    await hass.config_entries.async_unload(entry.entry_id)
    for number, command in enumerate(COMMANDS, start=9):
        await client.send_json({"id": number, **command})
        error = await client.receive_json()
        assert error["success"] is False
        assert error["error"]["translation_key"] == "inventory_not_configured"


COMMANDS = [
    {"type": "doorcheck/panel_inventory"},
    {"type": "doorcheck/panel_scan", "directory": "example"},
    {"type": "doorcheck/panel_results", "directory": "example"},
    {"type": "doorcheck/panel_review", "directory": "example", "scan_id": "0" * 64},
    {"type": "doorcheck/panel_clear"},
]


@pytest.mark.parametrize("command", COMMANDS, ids=lambda c: c["type"])
async def test_non_admin_rejected_before_any_io(
    hass, hass_ws_client, hass_read_only_access_token, command
) -> None:
    await loaded(hass)
    client = await hass_ws_client(hass, access_token=hass_read_only_access_token)
    unauthorized = AssertionError("unauthorized I/O")
    with patch("homeassistant.core.ServiceRegistry.async_call", side_effect=unauthorized):
        await client.send_json({"id": 1, **command})
        error = await client.receive_json()
    assert error["success"] is False
    assert error["error"]["code"] == "unauthorized"


@pytest.mark.parametrize(
    "data",
    [
        {"type": "doorcheck/panel_scan"},
        {"type": "doorcheck/panel_scan", "directory": "../outside"},
        {"type": "doorcheck/panel_scan", "directory": 1},
        {"type": "doorcheck/panel_scan", "directory": "example", "extra": True},
        {"type": "doorcheck/panel_results", "directory": "../outside"},
        {"type": "doorcheck/panel_results", "directory": "example", "extra": True},
        {"type": "doorcheck/panel_review", "directory": "example"},
        {"type": "doorcheck/panel_review", "directory": "example", "scan_id": 1},
        {"type": "doorcheck/panel_review", "directory": "example", "scan_id": "<script>"},
        {"type": "doorcheck/panel_clear", "extra": True},
    ],
)
async def test_scan_validation_preserved(hass, hass_ws_client, data) -> None:
    await loaded(hass)
    client = await hass_ws_client(hass)
    await client.send_json({"id": 1, **data})
    error = await client.receive_json()
    assert error["success"] is False
    assert error["error"]["code"] in {"invalid_format", "home_assistant_error"}
    assert "<script>" not in str(error)


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
    view = report_view(
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
    assert report_view(response(()))["complete"] is False
    assert report_view(response(evidence=None))["findings"][0]["evidence"] == ""


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
    view = report_view(response(checks))
    assert "name⟨U+202E⟩" in view["checks"][0]["problems"][0]["message"]


def saved_record(report: Report, files=None, bytecode=None, at="2026-11-06T10:00:00+00:00"):
    return results.Saved(at, report, files or {}, bytecode or {})


def results_view(latest, baseline=None, saving="on", saved=True, problems=()):
    return {
        "results": {
            "directory": "example",
            "saving": saving,
            "saved": saved,
            "problems": list(problems),
            "latest": services._record(latest),
            "baseline": None if baseline is None else services._record(baseline),
            "comparison": None if baseline is None else services._comparison(baseline, latest),
        }
    }


def report(version="0.1.0", status=Status.COMPLETE, capabilities=(), findings=()):
    gaps = () if status is Status.COMPLETE else (Problem("problem.scan_limit_reached"),)
    checks = (Check("capabilities", version, status, gaps),)
    return Report(version, Target("example"), checks, capabilities, findings)


PROCESS = Capability(Kind.PROCESS, Location("code.py", 2, 1), "command")
FINDING = Finding(
    "test-rule",
    Severity.REVIEW,
    Confidence.HIGH,
    Location("code.py", 8, 1),
    "finding.unauth_file_path",
    tool="builtin",
)


def test_saved_view_without_saved_result_keeps_store_problems() -> None:
    view = panel.saved_view({"problems": ["problem.ha_results_entry_invalid"], "results": None})
    assert view == {"problems": [render("problem.ha_results_entry_invalid")], "latest": None}


def test_saved_view_reviewed_scan_has_no_comparison() -> None:
    first = saved_record(report(capabilities=(PROCESS,)), bytecode={"__pycache__/a‮.pyc": "0" * 64})
    view = panel.saved_view(results_view(first, first))
    assert view["reviewed"] is True
    assert view["reviewable"] is False
    assert view["comparison"] is None
    assert view["saving"] == "on"
    assert view["saved"] is True
    assert view["latest"]["bytecode"] == ["__pycache__/a⟨U+202E⟩.pyc"]
    assert view["latest"]["scanned_at"] == "2026-11-06T10:00:00+00:00"
    assert view["latest"]["scan_id"] == results.scan_id(first)
    assert view["latest"]["report"] == report_view({"report": to_dict(first.report)})
    assert view["baseline"] == {
        "scan_id": results.scan_id(first),
        "scanned_at": "2026-11-06T10:00:00+00:00",
    }


def test_saved_view_lists_changes_since_the_reviewed_scan() -> None:
    baseline = saved_record(
        report(capabilities=(PROCESS,)), {"code.py": "0" * 64, "gone‮.py": "1" * 64}
    )
    latest = saved_record(
        report(findings=(FINDING,)),
        {"code.py": "2" * 64, "new.py": "3" * 64},
        {"__pycache__/code.pyc": "4" * 64},
        at="2026-11-07T10:00:00+00:00",
    )
    view = panel.saved_view(results_view(latest, baseline))
    assert view["reviewed"] is False
    assert view["reviewable"] is True
    comparison = view["comparison"]
    assert comparison["changed"] is True
    assert comparison["limits"] == []
    assert comparison["rules_changed"] is False
    assert comparison["unproven"] is False
    assert comparison["added"] == {"findings": [0], "capabilities": []}
    assert comparison["removed"] == {
        "findings": [],
        "capabilities": [panel.capability_view(PROCESS)],
    }
    assert comparison["files"] == {
        "added": ["new.py"],
        "removed": ["gone⟨U+202E⟩.py"],
        "changed": ["code.py"],
    }
    assert comparison["bytecode"] == {
        "added": ["__pycache__/code.pyc"],
        "removed": [],
        "changed": [],
    }


@pytest.mark.parametrize(
    ("change", "kind"),
    [
        ({"files": {"a.py": "1" * 64}}, "files"),
        ({"bytecode": {"__pycache__/a.pyc": "1" * 64}}, "bytecode"),
        ({"capabilities": (PROCESS,)}, "added"),
        (None, "removed"),
    ],
)
def test_any_single_difference_is_a_change(change, kind) -> None:
    baseline = saved_record(report(capabilities=() if change else (PROCESS,)), {})
    files = (change or {}).get("files", {})
    bytecode = (change or {}).get("bytecode", {})
    capabilities = (change or {}).get("capabilities", ())
    latest = saved_record(
        report(capabilities=capabilities), files, bytecode, at="2026-11-07T00:00:00+00:00"
    )
    comparison = panel.saved_view(results_view(latest, baseline))["comparison"]
    assert comparison["changed"] is True
    assert comparison["limits"] == []


def test_same_files_and_observations_are_unchanged() -> None:
    baseline = saved_record(report(capabilities=(PROCESS,)), {"code.py": "0" * 64})
    latest = saved_record(
        report(capabilities=(PROCESS,)), {"code.py": "0" * 64}, at="2026-11-07T00:00:00+00:00"
    )
    comparison = panel.saved_view(results_view(latest, baseline))["comparison"]
    assert comparison["changed"] is False


def test_incomplete_latest_scan_marks_removals_unproven_and_cannot_be_reviewed() -> None:
    baseline = saved_record(report(capabilities=(PROCESS,)))
    latest = saved_record(report(status=Status.PARTIAL), at="2026-11-07T00:00:00+00:00")
    view = panel.saved_view(results_view(latest, baseline))
    assert view["reviewable"] is False
    comparison = view["comparison"]
    assert comparison["unproven"] is True
    assert comparison["rules_changed"] is False
    assert comparison["changed"] is True
    assert comparison["limits"] == [render("comparison.after_incomplete")]


def test_changed_rules_are_labeled() -> None:
    baseline = saved_record(report())
    latest = saved_record(report(version="0.2.0"), at="2026-11-07T00:00:00+00:00")
    comparison = panel.saved_view(results_view(latest, baseline))["comparison"]
    assert comparison["rules_changed"] is True
    assert comparison["unproven"] is False
    assert comparison["changed"] is True
    assert render("comparison.engine_version") in comparison["limits"]
    assert render("comparison.checks") in comparison["limits"]


def test_only_check_versions_changed_is_a_rules_change() -> None:
    baseline = saved_record(report())
    changed = Report(
        "0.1.0", Target("example"), (Check("capabilities", "0.2.0", Status.COMPLETE),), (), ()
    )
    latest = saved_record(changed, at="2026-11-07T00:00:00+00:00")
    comparison = panel.saved_view(results_view(latest, baseline))["comparison"]
    assert comparison["limits"] == [render("comparison.checks")]
    assert comparison["rules_changed"] is True


@pytest.mark.parametrize(
    ("saving", "saved"), [("disabled", False), ("unloaded", False), ("on", False)]
)
def test_an_unsaved_or_unsaving_result_cannot_be_reviewed(saving, saved) -> None:
    baseline = saved_record(report())
    latest = saved_record(report(capabilities=(PROCESS,)), at="2026-11-07T00:00:00+00:00")
    view = panel.saved_view(results_view(latest, baseline, saving=saving, saved=saved))
    assert view["reviewable"] is False
    assert view["saving"] == saving


def test_saving_on_but_store_unwritable_is_not_reviewable() -> None:
    baseline = saved_record(report())
    latest = saved_record(report(capabilities=(PROCESS,)), at="2026-11-07T00:00:00+00:00")
    unavailable = "problem.ha_results_unavailable"
    view = panel.saved_view(results_view(latest, baseline, saving=unavailable, saved=True))
    assert view["reviewable"] is False


def test_no_baseline_and_problems_are_rendered() -> None:
    latest = saved_record(report(status=Status.PARTIAL))
    view = panel.saved_view(results_view(latest, saved=True, problems=["problem.ha_results_limit"]))
    assert view["baseline"] is None
    assert view["comparison"] is None
    assert view["reviewed"] is False
    assert view["reviewable"] is False
    assert view["problems"] == [render("problem.ha_results_limit")]


async def test_saved_view_runs_off_loop(hass, hass_ws_client) -> None:
    await loaded(hass)
    client = await hass_ws_client(hass)
    original = panel.saved_view

    async def service(*args, **kwargs):
        return {"scope": "saved_results", "problems": [], "results": None}

    def view(data):
        with pytest.raises(RuntimeError, match="no running event loop"):
            asyncio.get_running_loop()
        return original(data)

    with (
        patch("homeassistant.core.ServiceRegistry.async_call", new=service),
        patch.object(panel, "saved_view", new=view),
    ):
        for number, command in enumerate(COMMANDS[1:4], start=1):
            await client.send_json({"id": number, **command})
            assert (await client.receive_json())["result"] == {"problems": [], "latest": None}


def test_a_finding_no_longer_found_is_listed_as_removed() -> None:
    baseline = saved_record(report(findings=(FINDING,)))
    latest = saved_record(report(), at="2026-11-07T00:00:00+00:00")
    comparison = panel.saved_view(results_view(latest, baseline))["comparison"]
    assert comparison["removed"]["findings"] == [panel.finding_view(FINDING)]
    assert comparison["added"]["findings"] == []


def test_added_items_are_positions_in_the_latest_report() -> None:
    other = Capability(Kind.PROCESS, Location("other.py", 1, 1), "other")
    baseline = saved_record(report(capabilities=(PROCESS,)))
    latest = saved_record(
        report(capabilities=(PROCESS, other, other)), at="2026-11-07T00:00:00+00:00"
    )
    view = panel.saved_view(results_view(latest, baseline))
    # Equal duplicates keep distinct positions; the item itself is sent once.
    assert view["comparison"]["added"]["capabilities"] == [1, 2]
    assert [c["location"] for c in view["latest"]["report"]["capabilities"]] == [
        "code.py:2:1",
        "other.py:1:1",
        "other.py:1:1",
    ]


def test_the_action_sends_removals_as_positions_in_the_reviewed_report() -> None:
    other = Capability(Kind.PROCESS, Location("other.py", 1, 1), "other")
    baseline = saved_record(report(capabilities=(other, PROCESS, PROCESS), findings=(FINDING,)))
    latest = saved_record(report(capabilities=(other,)), at="2026-11-07T00:00:00+00:00")
    data = services._comparison(baseline, latest)
    # One object listed twice takes both of its positions.
    assert data["capabilities"] == {"added": [], "removed": [1, 2]}
    assert data["findings"] == {"added": [], "removed": [0]}
    assert data["changed"] is True
    view = panel.saved_view(results_view(latest, baseline))["comparison"]
    assert view["removed"]["capabilities"] == [panel.capability_view(PROCESS)] * 2


def test_the_reviewed_report_is_parsed_only_for_removals() -> None:
    baseline = saved_record(report())
    latest = saved_record(report(capabilities=(PROCESS,)), at="2026-11-07T00:00:00+00:00")
    view = results_view(latest, baseline)
    view["results"]["baseline"]["report"] = {"not": "a report"}
    comparison = panel.saved_view(view)["comparison"]
    assert comparison["added"] == {"findings": [], "capabilities": [0]}
    assert comparison["removed"] == {"findings": [], "capabilities": []}
