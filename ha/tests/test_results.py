"""Saved baselines and latest scans: restarts, review, retention and strict loading."""

import asyncio
import copy
import json
import threading
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from doorcheck.checks import Check, Problem, Status
from doorcheck.report import to_dict
from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers import storage
from homeassistant.util import dt as dt_util
from homeassistant.util.file import WriteError
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.doorcheck import DOMAIN, results, scan, services
from custom_components.doorcheck.config_flow import DoorcheckOptionsFlow
from custom_components.doorcheck.diagnostics import async_get_config_entry_diagnostics
from tests.test_inventory_service import loaded
from tests.test_scan import compiled

KEY = results.STORE_KEY
# Captured before the hass_storage fixture replaces it, to read a real store file.
REAL_LOAD = storage.Store._async_load


async def call(hass: HomeAssistant, service: str, **data: Any) -> Any:
    response = service != "clear_results"
    return await hass.services.async_call(
        DOMAIN, service, data, blocking=True, return_response=response
    )


def installed(hass: HomeAssistant, tmp_path: Path, name: str = "example", code: str = "A = 1"):
    hass.config.config_dir = str(tmp_path)
    folder = tmp_path / "custom_components" / name
    folder.mkdir(parents=True, exist_ok=True)
    manifest = {"domain": name, "name": name, "version": "1.0"}
    (folder / "manifest.json").write_text(json.dumps(manifest))
    (folder / "code.py").write_text(code)
    return folder


async def restart(hass: HomeAssistant, entry: MockConfigEntry) -> results.Results:
    assert await hass.config_entries.async_reload(entry.entry_id)
    await hass.async_block_till_done()
    return entry.runtime_data.results


async def test_first_complete_scan_becomes_the_baseline_and_survives_restart(
    hass: HomeAssistant, hass_storage: dict[str, Any], tmp_path: Path
) -> None:
    entry = await loaded(hass)
    installed(hass, tmp_path)
    first = await call(hass, "scan_integration", directory="example")
    view = first["results"]
    assert view["directory"] == "example"
    assert dt_util.parse_datetime(view["latest"]["scanned_at"]) is not None
    assert view["saving"] == "on"
    assert view["saved"] is True
    assert view["problems"] == []
    # The first complete scan is both, serialized once; so is the top-level report.
    assert view["baseline"] is view["latest"]
    assert first["report"] is view["latest"]["report"]
    assert view["comparison"] == {
        "changed": False,
        "limits": [],
        "same_artifact": True,
        "findings": {"added": [], "removed": []},
        "capabilities": {"added": [], "removed": []},
        "files": {"added": [], "removed": [], "changed": []},
        "bytecode": {"added": [], "removed": [], "changed": []},
    }
    assert first["report"] == view["latest"]["report"]
    assert hass_storage[KEY]["version"] == results.STORE_VERSION
    assert list(hass_storage[KEY]["data"]["items"]) == ["example"]
    saved = await restart(hass, entry)
    assert saved.problems == []
    after = await call(hass, "get_results", directory="example")
    assert after == {"scope": "saved_results", "problems": [], "results": view}


async def test_changes_are_compared_with_the_reviewed_scan_until_marked(
    hass: HomeAssistant, tmp_path: Path
) -> None:
    entry = await loaded(hass)
    folder = installed(hass, tmp_path)
    first = (await call(hass, "scan_integration", directory="example"))["results"]
    (folder / "code.py").write_text('import os\nos.system("x")')
    (folder / "extra.py").write_text("B = 2")
    cache = folder / "__pycache__"
    cache.mkdir()
    (cache / "code.cpython-314.pyc").write_bytes(compiled())
    second = (await call(hass, "scan_integration", directory="example"))["results"]
    assert second["baseline"] == first["latest"]
    assert second["baseline"] is not second["latest"]
    assert second["comparison"] == {
        "changed": True,
        "limits": [],
        "same_artifact": False,
        "findings": {"added": [], "removed": []},
        "capabilities": {"added": [0], "removed": []},
        "files": {"added": ["extra.py"], "removed": [], "changed": ["code.py"]},
        "bytecode": {"added": ["__pycache__/code.cpython-314.pyc"], "removed": [], "changed": []},
    }
    third = (await call(hass, "scan_integration", directory="example"))["results"]
    assert third["baseline"] == first["latest"]
    await restart(hass, entry)
    assert (await call(hass, "get_results", directory="example"))["results"] == third
    reviewed = await call(
        hass, "mark_reviewed", directory="example", scan_id=third["latest"]["scan_id"]
    )
    assert reviewed["scope"] == "saved_results"
    assert reviewed["problems"] == []
    assert reviewed["results"]["directory"] == "example"
    assert reviewed["results"]["baseline"] == third["latest"]
    assert reviewed["results"]["comparison"]["same_artifact"] is True


async def test_incomplete_scan_is_latest_but_never_the_baseline(
    hass: HomeAssistant, tmp_path: Path
) -> None:
    entry = await loaded(hass)
    hass.config.config_dir = str(tmp_path)
    (tmp_path / "custom_components/example").mkdir(parents=True)
    (tmp_path / "custom_components/example/data").symlink_to("/etc/hosts")
    view = (await call(hass, "scan_integration", directory="example"))["results"]
    assert view["saved"] is True
    assert view["baseline"] is view["comparison"] is None
    target = view["latest"]["report"]["target"]
    assert target["artifact_sha256"] is None
    assert (await restart(hass, entry)).problems == []
    assert (await call(hass, "get_results", directory="example"))["results"] == view
    with pytest.raises(ServiceValidationError) as refused:
        await call(hass, "mark_reviewed", directory="example", scan_id="0" * 64)
    assert refused.value.translation_key == "results_stale"


async def test_review_refusals(hass: HomeAssistant, tmp_path: Path) -> None:
    entry = await loaded(hass)
    installed(hass, tmp_path)
    for data, key in (
        ({"directory": "example", "scan_id": "0" * 64}, "results_not_found"),
        ({"directory": "example"}, "results_invalid_request"),
        ({"directory": "example", "scan_id": 1}, "results_invalid_request"),
        ({"directory": "example", "digest": "0" * 64}, "results_invalid_request"),
    ):
        with pytest.raises(ServiceValidationError) as refused:
            await call(hass, "mark_reviewed", **data)
        assert refused.value.translation_key == key
    view = (await call(hass, "scan_integration", directory="example"))["results"]
    digest = view["latest"]["scan_id"]
    assert digest == results.scan_id(entry.runtime_data.results.items["example"].latest)
    for value, key in (
        ("A" * 64, "results_invalid_request"),
        (digest[:-1], "results_invalid_request"),
        ("0" * 64, "results_stale"),
    ):
        with pytest.raises(ServiceValidationError) as refused:
            await call(hass, "mark_reviewed", directory="example", scan_id=value)
        assert refused.value.translation_domain == DOMAIN
        assert refused.value.translation_key == key
    saved = entry.runtime_data.results
    latest = saved.items["example"].latest
    gap = (Problem("problem.tool_failed"),)
    partial = copy.replace(latest.report, checks=(Check("capabilities", "1", Status.PARTIAL, gap),))
    unfinished = copy.replace(latest, report=partial)
    saved.items["example"] = results.Item(unfinished, latest)
    with pytest.raises(ServiceValidationError) as refused:
        await call(hass, "mark_reviewed", directory="example", scan_id=results.scan_id(unfinished))
    assert refused.value.translation_domain == DOMAIN
    assert refused.value.translation_key == "results_incomplete"
    saved.items["example"] = results.Item(latest, latest)
    saved.writable = False
    with pytest.raises(ServiceValidationError) as refused:
        await call(hass, "mark_reviewed", directory="example", scan_id=digest)
    assert refused.value.translation_key == "results_not_saving"


def held_first_save(saved: results.Results) -> tuple[asyncio.Event, asyncio.Event]:
    """Hold the next store write open until released, as a slow disk would."""
    store = saved._store
    original = store.async_save
    entered, release = asyncio.Event(), asyncio.Event()

    async def held(data: Any) -> None:
        store.async_save = original  # type: ignore[method-assign]
        entered.set()
        await release.wait()
        await original(data)

    store.async_save = held  # type: ignore[method-assign]
    return entered, release


async def test_clear_during_a_save_is_not_undone(
    hass: HomeAssistant, hass_storage: dict[str, Any], tmp_path: Path
) -> None:
    entry = await loaded(hass)
    installed(hass, tmp_path)
    saved = entry.runtime_data.results
    entered, release = held_first_save(saved)
    scanning = asyncio.create_task(call(hass, "scan_integration", directory="example"))
    await entered.wait()
    clearing = asyncio.create_task(call(hass, "clear_results"))
    await asyncio.sleep(0)
    release.set()
    await scanning
    await clearing
    await hass.async_block_till_done()
    assert saved.items == {}
    assert KEY not in hass_storage


async def test_review_waiting_on_a_save_refuses_the_new_scan(
    hass: HomeAssistant, tmp_path: Path
) -> None:
    entry = await loaded(hass)
    folder = installed(hass, tmp_path)
    first = (await call(hass, "scan_integration", directory="example"))["results"]
    old = first["latest"]["scan_id"]
    (folder / "code.py").write_text("A = 2")
    saved = entry.runtime_data.results
    entered, release = held_first_save(saved)
    scanning = asyncio.create_task(call(hass, "scan_integration", directory="example"))
    await entered.wait()
    reviewing = asyncio.create_task(call(hass, "mark_reviewed", directory="example", scan_id=old))
    await asyncio.sleep(0)
    release.set()
    second = (await scanning)["results"]
    with pytest.raises(ServiceValidationError) as refused:
        await reviewing
    assert refused.value.translation_key == "results_stale"
    item = saved.items["example"]
    assert item.baseline is not None
    assert to_dict(item.baseline.report) == first["latest"]["report"]
    assert to_dict(item.latest.report) == second["latest"]["report"]


async def test_concurrent_changes_to_two_folders_are_both_kept(
    hass: HomeAssistant, hass_storage: dict[str, Any], tmp_path: Path
) -> None:
    entry = await loaded(hass)
    folder = installed(hass, tmp_path)
    installed(hass, tmp_path, "other")
    await call(hass, "scan_integration", directory="example")
    (folder / "code.py").write_text("A = 2")
    second = (await call(hass, "scan_integration", directory="example"))["results"]
    digest = second["latest"]["scan_id"]
    saved = entry.runtime_data.results
    entered, release = held_first_save(saved)
    scanning = asyncio.create_task(call(hass, "scan_integration", directory="other"))
    await entered.wait()
    reviewing = asyncio.create_task(
        call(hass, "mark_reviewed", directory="example", scan_id=digest)
    )
    await asyncio.sleep(0)
    release.set()
    await scanning
    await reviewing
    await hass.async_block_till_done()
    assert sorted(saved.items) == ["example", "other"]
    assert saved.items["example"].baseline == saved.items["example"].latest
    stored = hass_storage[KEY]["data"]["items"]
    assert sorted(stored) == ["example", "other"]
    assert stored["example"]["baseline"] == stored["example"]["latest"]


async def test_results_are_kept_only_under_the_scanned_directory(
    hass: HomeAssistant, hass_storage: dict[str, Any], tmp_path: Path
) -> None:
    await loaded(hass)
    installed(hass, tmp_path, "first")
    installed(hass, tmp_path, "second", "B = 2")
    await call(hass, "scan_integration", directory="first")
    assert (await call(hass, "get_results", directory="second"))["results"] is None
    await call(hass, "scan_integration", directory="second")
    stored = hass_storage[KEY]["data"]["items"]
    assert sorted(stored) == ["first", "second"]
    for name in stored:
        assert stored[name]["latest"]["report"]["target"]["name"] == name
    for directory in ("", "../first", "First", "a" * 256):
        with pytest.raises(ServiceValidationError) as refused:
            await call(hass, "get_results", directory=directory)
        assert refused.value.translation_key == "scan_invalid_directory"
    with pytest.raises(ServiceValidationError) as refused:
        await call(hass, "get_results", directory="first", digest="0" * 64)
    assert refused.value.translation_key == "scan_invalid_directory"


async def test_clear_deletes_everything(
    hass: HomeAssistant, hass_storage: dict[str, Any], tmp_path: Path
) -> None:
    entry = await loaded(hass)
    installed(hass, tmp_path)
    await call(hass, "scan_integration", directory="example")
    assert KEY in hass_storage
    assert await call(hass, "clear_results") is None
    assert KEY not in hass_storage
    assert entry.runtime_data.results.items == {}
    assert (await call(hass, "get_results", directory="example"))["results"] is None
    with pytest.raises(ServiceValidationError) as refused:
        await hass.services.async_call(DOMAIN, "clear_results", {"all": "yes"}, blocking=True)
    assert refused.value.translation_key == "results_clear_invalid"


async def test_turning_saving_off_deletes_results_and_stops_saving(
    hass: HomeAssistant, hass_storage: dict[str, Any], tmp_path: Path
) -> None:
    entry = await loaded(hass)
    installed(hass, tmp_path)
    await call(hass, "scan_integration", directory="example")
    form = await hass.config_entries.options.async_init(entry.entry_id)
    assert form["type"] is FlowResultType.FORM
    assert form["step_id"] == "init"
    assert form["data_schema"]({}) == {"save_results": True, "check_status": True}
    done = await hass.config_entries.options.async_configure(
        form["flow_id"], {"save_results": False}
    )
    assert done["type"] is FlowResultType.CREATE_ENTRY
    await hass.async_block_till_done()
    assert entry.state is ConfigEntryState.LOADED
    assert entry.options == {"save_results": False, "check_status": True}
    assert KEY not in hass_storage
    view = (await call(hass, "scan_integration", directory="example"))["results"]
    assert view["saving"] == "disabled"
    assert view["saved"] is False
    assert view["problems"] == []
    assert view["baseline"] is view["comparison"] is None
    assert KEY not in hass_storage
    assert (await call(hass, "get_results", directory="example"))["results"] is None
    diagnostics = await async_get_config_entry_diagnostics(hass, entry)
    assert diagnostics["saved_results"] == {"status": "disabled", "items": 0, "store_version": 1}
    form = await hass.config_entries.options.async_init(entry.entry_id)
    assert form["data_schema"]({}) == {"save_results": False, "check_status": True}


async def test_removing_doorcheck_deletes_saved_results(
    hass: HomeAssistant, hass_storage: dict[str, Any], tmp_path: Path
) -> None:
    entry = await loaded(hass)
    installed(hass, tmp_path)
    await call(hass, "scan_integration", directory="example")
    assert await hass.config_entries.async_remove(entry.entry_id)
    await hass.async_block_till_done()
    assert KEY not in hass_storage


@pytest.mark.parametrize("status", ["complete", "partial"])
async def test_only_a_complete_inventory_forgets_removed_folders(
    hass: HomeAssistant, hass_storage: dict[str, Any], tmp_path: Path, status: str
) -> None:
    entry = await loaded(hass)
    folder = installed(hass, tmp_path, "gone")
    installed(hass, tmp_path, "kept")
    await call(hass, "scan_integration", directory="gone")
    await call(hass, "scan_integration", directory="kept")
    for path in folder.iterdir():
        path.unlink()
    folder.rmdir()
    if status == "partial":
        (tmp_path / "custom_components/Bad Name").mkdir()
    listed = await call(hass, "get_inventory")
    assert listed["status"] == status
    expected = ["kept"] if status == "complete" else ["gone", "kept"]
    assert sorted(entry.runtime_data.results.items) == expected
    assert sorted(hass_storage[KEY]["data"]["items"]) == expected


async def test_unchanged_inventory_does_not_write(hass: HomeAssistant, tmp_path: Path) -> None:
    await loaded(hass)
    installed(hass, tmp_path)
    await call(hass, "scan_integration", directory="example")
    with patch.object(results.Results, "_save") as save:
        await call(hass, "get_inventory")
    save.assert_not_called()


@pytest.mark.parametrize("limit", ["MAX_ITEMS", "MAX_BYTES"])
async def test_limits_keep_the_result_visible_but_unsaved(
    hass: HomeAssistant, hass_storage: dict[str, Any], tmp_path: Path, limit: str
) -> None:
    entry = await loaded(hass)
    installed(hass, tmp_path, "first")
    installed(hass, tmp_path, "second")
    await call(hass, "scan_integration", directory="first")
    size = len(results._payload(entry.runtime_data.results.items))
    with patch.object(results, limit, 1 if limit == "MAX_ITEMS" else size):
        repeat = (await call(hass, "scan_integration", directory="first"))["results"]
        assert repeat["saved"] is True
        view = (await call(hass, "scan_integration", directory="second"))["results"]
    assert view["saved"] is False
    assert view["problems"] == [results.LIMIT]
    assert view["baseline"] is view["comparison"] is None
    assert view["latest"]["report"]["target"]["name"] == "second"
    assert sorted(hass_storage[KEY]["data"]["items"]) == ["first"]


def stored_item(hass_storage: dict[str, Any]) -> dict[str, Any]:
    item: dict[str, Any] = hass_storage[KEY]["data"]["items"]["example"]
    return item


ITEM = "invalid saved item"
RECORD = "invalid saved record"
TIME = "invalid scan time"
HASHES = "invalid file hashes"
MISMATCH = "saved record does not match its directory or files"


@pytest.mark.parametrize(
    ("damage", "reason"),
    [
        (lambda item: item.update(extra=1), ITEM),
        (lambda item: item.pop("baseline"), ITEM),
        (lambda item: item["latest"].update(scanned_at="yesterday"), TIME),
        (lambda item: item["latest"].update(scanned_at=1), TIME),
        (lambda item: item["latest"].pop("bytecode"), RECORD),
        (lambda item: item["latest"].update(files={"code.py": "0" * 63}), HASHES),
        (lambda item: item["latest"].update(files=[]), HASHES),
        (lambda item: item["latest"].update(bytecode={"__pycache__/a.pyc": "z" * 64}), HASHES),
        (lambda item: item["latest"]["files"].update({"other.py": "0" * 64}), MISMATCH),
        (lambda item: item["latest"]["report"].update(schema_version=2), None),
        (lambda item: item["latest"]["report"]["target"].update(name="other"), MISMATCH),
        (lambda item: item["latest"]["report"]["target"].update(artifact_sha256=None), MISMATCH),
        (
            lambda item: item["baseline"]["report"]["checks"][0].update(
                status="failed",
                problems=[{"key": "problem.tool_failed", "location": None, "params": {}}],
            ),
            "an incomplete scan cannot be a baseline",
        ),
    ],
)
async def test_invalid_saved_entries_are_dropped_and_reported(
    hass: HomeAssistant,
    hass_storage: dict[str, Any],
    tmp_path: Path,
    damage: Any,
    reason: str | None,
) -> None:
    entry = await loaded(hass)
    installed(hass, tmp_path)
    installed(hass, tmp_path, "intact")
    await call(hass, "scan_integration", directory="example")
    await call(hass, "scan_integration", directory="intact")
    damage(stored_item(hass_storage))
    damaged = copy.deepcopy(stored_item(hass_storage))
    with pytest.raises(ValueError, match=None if reason is None else f"^{reason}$"):
        results._item("example", damaged)
    saved = await restart(hass, entry)
    assert list(saved.items) == ["intact"]
    assert saved.problems == [results.INVALID]
    view = (await call(hass, "get_results", directory="intact"))["results"]
    assert view["problems"] == [results.INVALID]
    dropped = await call(hass, "get_results", directory="example")
    assert dropped == {"scope": "saved_results", "problems": [results.INVALID], "results": None}


@pytest.mark.parametrize(
    "data",
    [
        {"items": []},
        {"items": [1]},
        {"items": {"Bad Name": {}}},
        {"items": {"example": [], "other": {}}},
        [],
    ],
)
async def test_invalid_store_shapes_are_reported(
    hass: HomeAssistant, hass_storage: dict[str, Any], data: object
) -> None:
    hass_storage[KEY] = {"version": 1, "minor_version": 1, "key": KEY, "data": data}
    entry = await loaded(hass)
    saved = entry.runtime_data.results
    assert saved.items == {}
    assert saved.problems == [results.INVALID]
    assert saved.status() is None


@pytest.mark.parametrize("item", [object(), []])
def test_saved_items_must_be_objects_under_a_folder_name(item: object) -> None:
    with pytest.raises(ValueError, match=f"^{ITEM}$"):
        results._item("Bad Name" if isinstance(item, list) else "example", item)


@pytest.mark.parametrize(("limit", "problems"), [(1, [results.INVALID]), (2, [])])
async def test_extra_saved_items_beyond_the_limit_are_reported(
    hass: HomeAssistant,
    hass_storage: dict[str, Any],
    tmp_path: Path,
    limit: int,
    problems: list[str],
) -> None:
    entry = await loaded(hass)
    installed(hass, tmp_path, "first")
    installed(hass, tmp_path, "second")
    await call(hass, "scan_integration", directory="first")
    await call(hass, "scan_integration", directory="second")
    with patch.object(results, "MAX_ITEMS", limit):
        saved = await restart(hass, entry)
    assert list(saved.items) == ["first", "second"][:limit]
    assert saved.problems == problems


async def test_unreadable_store_is_never_overwritten(
    hass: HomeAssistant, hass_storage: dict[str, Any], tmp_path: Path
) -> None:
    future = {"version": 2, "minor_version": 1, "key": KEY, "data": {"items": {}}}
    hass_storage[KEY] = copy.deepcopy(future)
    entry = await loaded(hass)
    saved = entry.runtime_data.results
    assert saved.status() == results.UNAVAILABLE
    assert saved.writable is False
    installed(hass, tmp_path)
    view = (await call(hass, "scan_integration", directory="example"))["results"]
    assert view["saved"] is False
    assert view["saving"] == results.UNAVAILABLE
    assert view["problems"] == [results.UNAVAILABLE]
    assert view["baseline"] is None
    assert hass_storage[KEY] == future
    diagnostics = await async_get_config_entry_diagnostics(hass, entry)
    assert diagnostics["saved_results"]["status"] == results.UNAVAILABLE
    await call(hass, "clear_results")
    assert saved.status() is None
    assert saved.problems == []
    view = (await call(hass, "scan_integration", directory="example"))["results"]
    assert view["saved"] is True
    assert hass_storage[KEY]["version"] == 1


@pytest.mark.parametrize(("version", "minor"), [(0, 1), (2, 1), (1, 0), (1, 2)])
async def test_other_store_versions_are_left_unread(
    hass: HomeAssistant, hass_storage: dict[str, Any], version: int, minor: int
) -> None:
    other = {"version": version, "minor_version": minor, "key": KEY, "data": {"items": {}}}
    hass_storage[KEY] = copy.deepcopy(other)
    saved = (await loaded(hass)).runtime_data.results
    assert saved.status() == results.UNAVAILABLE
    assert hass_storage[KEY] == other


async def test_a_newer_minor_version_is_left_unread_and_unchanged(
    hass: HomeAssistant, hass_storage: dict[str, Any], tmp_path: Path
) -> None:
    entry = await loaded(hass)
    installed(hass, tmp_path)
    await call(hass, "scan_integration", directory="example")
    # A newer minor version may add fields this release's strict reader would drop.
    hass_storage[KEY]["minor_version"] = 2
    hass_storage[KEY]["data"]["items"]["example"]["latest"]["note"] = "added later"
    newer = copy.deepcopy(hass_storage[KEY])
    saved = await restart(hass, entry)
    assert saved.status() == results.UNAVAILABLE
    assert saved.items == {}
    assert hass_storage[KEY] == newer


async def test_store_is_private_and_written_atomically(hass: HomeAssistant) -> None:
    with patch.object(results, "_Store", wraps=results._Store) as store:
        results.Results(hass, enabled=True)
    store.assert_called_once_with(
        hass, results.STORE_VERSION, KEY, private=True, atomic_writes=True
    )


async def test_version_is_read_from_the_lowercase_manifest(
    hass: HomeAssistant, tmp_path: Path
) -> None:
    await loaded(hass)
    installed(hass, tmp_path)
    with patch.object(scan, "read_json_object", wraps=scan.read_json_object) as read:
        view = (await call(hass, "scan_integration", directory="example"))["results"]
    assert view["latest"]["report"]["target"]["version"] == "1.0"
    assert [path.name for (path,), _ in read.call_args_list] == ["manifest.json"]


async def test_options_step_names_itself(hass: HomeAssistant) -> None:
    entry = await loaded(hass)
    flow = DoorcheckOptionsFlow()
    flow.hass = hass
    flow.handler = entry.entry_id
    form = await flow.async_step_init()
    assert form["step_id"] == "init"


async def test_a_rescan_that_only_adds_bytecode_cannot_be_reviewed_with_the_old_id(
    hass: HomeAssistant, tmp_path: Path
) -> None:
    await loaded(hass)
    folder = installed(hass, tmp_path)
    first = (await call(hass, "scan_integration", directory="example"))["results"]
    (folder / "__pycache__").mkdir()
    (folder / "__pycache__/code.cpython-314.pyc").write_bytes(compiled())
    second = (await call(hass, "scan_integration", directory="example"))["results"]
    # The source digest is unchanged; only the scan ID tells the two scans apart.
    target = second["latest"]["report"]["target"]
    assert target["artifact_sha256"] == first["latest"]["report"]["target"]["artifact_sha256"]
    assert second["latest"]["scan_id"] != first["latest"]["scan_id"]
    assert second["baseline"]["scan_id"] == first["latest"]["scan_id"]
    # Interpreter-shaped bytecode is not a capability; the saved paths show it.
    assert second["latest"]["report"]["capabilities"] == first["latest"]["report"]["capabilities"]
    assert second["latest"]["bytecode"] == ["__pycache__/code.cpython-314.pyc"]
    assert second["baseline"]["bytecode"] == []
    with pytest.raises(ServiceValidationError) as refused:
        await call(hass, "mark_reviewed", directory="example", scan_id=first["latest"]["scan_id"])
    assert refused.value.translation_key == "results_stale"


def test_the_scan_id_covers_every_saved_field(tmp_path: Path) -> None:
    folder = tmp_path / "example"
    folder.mkdir()
    (folder / "code.py").write_text("A = 1")
    saved = results.Saved.from_scan(scan.scan_integration(tmp_path, "example"))
    assert results.SHA256.fullmatch(results.scan_id(saved))
    changed = [
        copy.replace(saved, scanned_at="2000-01-01T00:00:00+00:00"),
        copy.replace(saved, files={"code.py": "0" * 64}),
        copy.replace(saved, bytecode={"__pycache__/a.pyc": "0" * 64}),
        copy.replace(
            saved,
            report=copy.replace(
                saved.report, target=copy.replace(saved.report.target, version="2")
            ),
        ),
    ]
    ids = {results.scan_id(saved), *(results.scan_id(other) for other in changed)}
    assert len(ids) == 5
    # The same content in another key order, as a hand-edited store may hold, has the same ID.
    files = {"b.py": "1" * 64, "a.py": "0" * 64}
    reordered = copy.replace(saved, files=dict(reversed(files.items())))
    assert results.scan_id(copy.replace(saved, files=files)) == results.scan_id(reordered)


def blocked_scan() -> tuple[threading.Event, threading.Event, Any]:
    entered, release = threading.Event(), threading.Event()
    original = services.scan_integration

    def blocked(root: Path, directory: str) -> scan.Scan:
        entered.set()
        assert release.wait(10)
        return original(root, directory)

    return entered, release, patch.object(services, "scan_integration", new=blocked)


async def test_a_scan_finishing_after_saving_is_turned_off_writes_nothing(
    hass: HomeAssistant, hass_storage: dict[str, Any], tmp_path: Path
) -> None:
    entry = await loaded(hass)
    installed(hass, tmp_path)
    await call(hass, "scan_integration", directory="example")
    entered, release, blocking = blocked_scan()
    with blocking:
        scanning = asyncio.create_task(call(hass, "scan_integration", directory="example"))
        try:
            assert await hass.async_add_executor_job(entered.wait, 5)
            old = entry.runtime_data.results
            hass.config_entries.async_update_entry(entry, options={"save_results": False})
            # Not async_block_till_done: it would wait for the held scan.
            for _ in range(500):
                # HA removes runtime_data between unload and the next setup.
                data = getattr(entry, "runtime_data", None)
                if entry.state is ConfigEntryState.LOADED and data and data.results is not old:
                    break
                await asyncio.sleep(0.01)
            assert entry.runtime_data.results.enabled is False
        finally:
            release.set()
        view = (await scanning)["results"]
    await hass.async_block_till_done()
    assert view["saving"] == results.UNLOADED
    assert view["saved"] is False
    # The old entry's reviewed scan was deleted with the store; it is not shown.
    assert view["baseline"] is view["comparison"] is None
    assert KEY not in hass_storage


async def test_a_scan_finishing_after_removal_writes_nothing(
    hass: HomeAssistant, hass_storage: dict[str, Any], tmp_path: Path
) -> None:
    entry = await loaded(hass)
    installed(hass, tmp_path)
    await call(hass, "scan_integration", directory="example")
    entered, release, blocking = blocked_scan()
    with blocking:
        scanning = asyncio.create_task(call(hass, "scan_integration", directory="example"))
        try:
            assert await hass.async_add_executor_job(entered.wait, 5)
            assert await hass.config_entries.async_remove(entry.entry_id)
            assert KEY not in hass_storage
        finally:
            release.set()
        view = (await scanning)["results"]
    await hass.async_block_till_done()
    assert view["saving"] == results.UNLOADED
    assert view["saved"] is False
    assert view["baseline"] is None
    assert KEY not in hass_storage


async def test_an_inventory_finishing_after_a_reload_prunes_nothing(
    hass: HomeAssistant, hass_storage: dict[str, Any], tmp_path: Path
) -> None:
    entry = await loaded(hass)
    folder = installed(hass, tmp_path, "gone")
    await call(hass, "scan_integration", directory="gone")
    for path in folder.iterdir():
        path.unlink()
    folder.rmdir()
    entered, release = threading.Event(), threading.Event()
    original = services.read_inventory

    def blocked(root: Path) -> Any:
        entered.set()
        assert release.wait(10)
        return original(root)

    with patch.object(services, "read_inventory", new=blocked):
        listing = asyncio.create_task(call(hass, "get_inventory"))
        try:
            assert await hass.async_add_executor_job(entered.wait, 5)
            assert await hass.config_entries.async_reload(entry.entry_id)
        finally:
            release.set()
        assert (await listing)["status"] == "complete"
    assert list(hass_storage[KEY]["data"]["items"]) == ["gone"]
    assert list(entry.runtime_data.results.items) == ["gone"]


async def test_a_closed_store_refuses_to_clear_and_review(
    hass: HomeAssistant, hass_storage: dict[str, Any], tmp_path: Path
) -> None:
    entry = await loaded(hass)
    installed(hass, tmp_path)
    view = (await call(hass, "scan_integration", directory="example"))["results"]
    saved = entry.runtime_data.results
    await saved.close()
    assert saved.status() == results.UNLOADED
    with pytest.raises(ServiceValidationError) as refused:
        await saved.clear()
    assert refused.value.translation_key == "inventory_not_configured"
    with pytest.raises(ServiceValidationError) as refused:
        await saved.review("example", view["latest"]["scan_id"])
    assert refused.value.translation_key == "results_not_saving"
    assert list(hass_storage[KEY]["data"]["items"]) == ["example"]


@pytest.mark.parametrize(
    "content",
    ['{"data": {}}', '{"version": 1}', "[1]", '{"version": "1", "data": {}}'],
)
async def test_a_store_file_without_a_valid_envelope_is_unavailable_and_kept(
    hass: HomeAssistant, tmp_path: Path, content: str
) -> None:
    hass.config.config_dir = str(tmp_path)
    path = tmp_path / ".storage" / KEY
    path.parent.mkdir()
    path.write_text(content)
    storage.get_internal_store_manager(hass).async_invalidate(KEY)
    with patch.object(storage.Store, "_async_load", REAL_LOAD):
        entry = await loaded(hass)
    assert entry.state is ConfigEntryState.LOADED
    saved = entry.runtime_data.results
    assert saved.status() == results.UNAVAILABLE
    assert saved.problems == [results.UNAVAILABLE]
    assert path.read_text() == content
    await call(hass, "clear_results")
    assert saved.status() is None


async def test_a_failed_write_is_not_reported_as_saved(
    hass: HomeAssistant, hass_storage: dict[str, Any], tmp_path: Path
) -> None:
    entry = await loaded(hass)
    folder = installed(hass, tmp_path)
    first = (await call(hass, "scan_integration", directory="example"))["results"]
    before = copy.deepcopy(hass_storage[KEY])
    saved = entry.runtime_data.results
    kept = saved.items
    (folder / "code.py").write_text("A = 2")
    failing = patch.object(storage.Store, "_async_write_data", side_effect=WriteError("full"))
    with failing:
        view = (await call(hass, "scan_integration", directory="example"))["results"]
        assert view["saved"] is False
        assert view["problems"] == [results.WRITE_FAILED]
        assert view["baseline"] == first["latest"]
        with pytest.raises(HomeAssistantError) as refused:
            await call(
                hass, "mark_reviewed", directory="example", scan_id=first["latest"]["scan_id"]
            )
        assert refused.value.translation_key == "results_write_failed"
        assert refused.value.translation_domain == DOMAIN
    assert saved.items is kept
    assert hass_storage[KEY] == before


async def test_store_data_is_parsed_and_encoded_off_the_event_loop(
    hass: HomeAssistant, tmp_path: Path
) -> None:
    entry = await loaded(hass)
    installed(hass, tmp_path)
    threads: list[str] = []

    def watched(function: Any) -> Any:
        def run(*args: Any) -> Any:
            threads.append(function.__name__)
            assert threading.current_thread() is not threading.main_thread()
            return function(*args)

        return run

    with (
        patch.object(results, "_parse", new=watched(results._parse)),
        patch.object(results, "_payload", new=watched(results._payload)),
        patch.object(results, "scan_id", new=watched(results.scan_id)),
    ):
        view = (await call(hass, "scan_integration", directory="example"))["results"]
        await call(hass, "mark_reviewed", directory="example", scan_id=view["latest"]["scan_id"])
        await restart(hass, entry)
    assert {"_parse", "_payload", "scan_id"} <= set(threads)


async def test_a_folder_that_does_not_exist_is_not_saved(
    hass: HomeAssistant, hass_storage: dict[str, Any], tmp_path: Path
) -> None:
    await loaded(hass)
    hass.config.config_dir = str(tmp_path)
    # Neither custom_components nor the folder exists yet.
    for name in ("a" * 255, "example"):
        view = (await call(hass, "scan_integration", directory=name))["results"]
        assert view["saved"] is False
        assert view["latest"]["report"]["checks"][0]["status"] == "failed"
    installed(hass, tmp_path, "present")
    view = (await call(hass, "scan_integration", directory="a" * 255))["results"]
    assert view["saved"] is False
    assert view["problems"] == []
    assert view["saving"] == "on"
    assert KEY not in hass_storage
    # A folder that exists but cannot be copied is saved as a failed scan.
    (tmp_path / "custom_components/linked").symlink_to(tmp_path / "custom_components/present")
    view = (await call(hass, "scan_integration", directory="linked"))["results"]
    assert view["saved"] is True
    assert list(hass_storage[KEY]["data"]["items"]) == ["linked"]
