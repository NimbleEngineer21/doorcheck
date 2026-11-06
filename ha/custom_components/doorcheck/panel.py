"""Admin panel lifecycle and presentation over the existing authorized actions."""

from importlib.resources import files
from pathlib import Path
from typing import Any

from homeassistant.components import frontend, http, panel_custom, websocket_api
from homeassistant.components.websocket_api.connection import ActiveConnection
from homeassistant.components.websocket_api.decorators import (
    async_response,
    require_admin,
    websocket_command,
)
from homeassistant.core import HomeAssistant

from doorcheck.capabilities import Capability
from doorcheck.comparison import Limit, compare
from doorcheck.findings import Finding, Location
from doorcheck.messages import ENGLISH, render, render_capability
from doorcheck.report import Report, from_dict
from doorcheck.text import display_safe

from .const import DOMAIN
from .results import complete

URL = "/doorcheck_static"
REVIEW_ERRORS = (
    "ha.service.results_incomplete",
    "ha.service.results_not_found",
    "ha.service.results_not_saving",
    "ha.service.results_stale",
    "ha.service.results_write_failed",
)
SAVED_MESSAGES = (
    "ha.panel.added_capabilities",
    "ha.panel.added_findings",
    "ha.panel.bytecode",
    "ha.panel.bytecode_added",
    "ha.panel.bytecode_changed",
    "ha.panel.bytecode_note",
    "ha.panel.bytecode_removed",
    "ha.panel.cancel",
    "ha.panel.changed",
    "ha.panel.changes",
    "ha.panel.clear",
    "ha.panel.clear_confirm",
    "ha.panel.clear_detail",
    "ha.panel.clear_title",
    "ha.panel.cleared",
    "ha.panel.clearing",
    "ha.panel.files_added",
    "ha.panel.files_changed",
    "ha.panel.files_note",
    "ha.panel.files_removed",
    "ha.panel.full_results",
    "ha.panel.latest_scan",
    "ha.panel.no_baseline",
    "ha.panel.no_saved",
    "ha.panel.opening",
    "ha.panel.removed_capabilities",
    "ha.panel.removed_findings",
    "ha.panel.review",
    "ha.panel.review_detail",
    "ha.panel.reviewed",
    "ha.panel.reviewed_scan",
    "ha.panel.reviewing",
    "ha.panel.rules_changed",
    "ha.panel.saving_disabled",
    "ha.panel.saving_unloaded",
    "ha.panel.unchanged",
    "ha.panel.unproven",
)


def configuration() -> dict[str, Any]:
    """Read trusted packaged presentation assets off the event loop."""
    messages = {
        "title": render("ha.panel.title"),
        "intro": render("ha.panel.intro"),
        "integration": render("ha.panel.integration"),
        "refresh": render("ha.panel.refresh"),
        "scan": render("ha.panel.scan"),
        "loading": render("ha.panel.loading"),
        "scanning": render("ha.panel.scanning"),
        "ready": render("ha.panel.ready"),
        "empty": render("ha.panel.empty"),
        "findings": render("ha.panel.findings"),
        "capabilities": render("ha.panel.capabilities"),
        "coverage": render("ha.panel.coverage"),
        "no_findings": render("ha.panel.no_findings"),
        "no_capabilities": render("ha.panel.no_capabilities"),
        "incomplete": render("ha.panel.incomplete"),
        "unknown_origin": render("ha.panel.unknown_origin"),
        "evidence": render("ha.panel.evidence"),
        "technical": render("ha.panel.technical"),
        "admin": render("ha.panel.admin"),
        "error": render("ha.panel.error"),
        "scan_busy": render("ha.service.scan_busy"),
        "scan_invalid_directory": render("ha.service.scan_invalid_directory"),
        "inventory_not_configured": render("ha.service.not_configured"),
        "more": render("ha.panel.more"),
        "menu": render("ha.panel.menu"),
        **{key.rpartition(".")[2]: render(key) for key in SAVED_MESSAGES},
        **{key.rpartition(".")[2]: render(key) for key in REVIEW_ERRORS},
    }
    css = files("doorcheck.presentation").joinpath("tokens.css").read_text()
    css = css.replace(":root", ":host").replace('[data-theme="', ':host([data-theme="')
    css = css.replace('"] {', '"]) {')
    return {"messages": messages, "tokens": css}


async def register(hass: HomeAssistant) -> None:
    """Register public code assets once, without any report or credential data."""
    # HA moved this public runtime export between modules across supported versions.
    static_path = getattr(http, "StaticPathConfig")  # noqa: B009 - moved public HA runtime export
    await hass.http.async_register_static_paths(
        [static_path(URL, str(Path(__file__).parent / "frontend"), False)]
    )
    for command in (inventory, scan, saved, review, clear):
        websocket_api.async_register_command(hass, command)


async def setup(hass: HomeAssistant) -> None:
    config = await hass.async_add_executor_job(configuration)
    await panel_custom.async_register_panel(
        hass,
        frontend_url_path=DOMAIN,
        webcomponent_name="doorcheck-panel",
        sidebar_title="Doorcheck",
        sidebar_icon="mdi:text-box-search-outline",
        module_url=f"{URL}/panel.js",
        require_admin=True,
        config=config,
    )


def unload(hass: HomeAssistant) -> None:
    frontend.async_remove_panel(hass, DOMAIN)


async def call(
    hass: HomeAssistant,
    connection: ActiveConnection,
    msg: dict[str, Any],
    service: str,
    data: dict[str, Any],
) -> dict[str, Any]:
    response = await hass.services.async_call(
        DOMAIN, service, data, blocking=True, return_response=True, context=connection.context(msg)
    )
    if response is None:
        raise RuntimeError("Response-only action returned no response")
    return response


def fields(msg: dict[str, Any]) -> dict[str, Any]:
    """Pass every sent field on, so the action's own validation rejects extras."""
    return {key: value for key, value in msg.items() if key not in {"id", "type"}}


@websocket_command({"type": "doorcheck/panel_inventory"})
@require_admin
@async_response
async def inventory(hass: HomeAssistant, connection: ActiveConnection, msg: dict[str, Any]) -> None:
    result = await call(hass, connection, msg, "get_inventory", {})
    connection.send_result(msg["id"], await hass.async_add_executor_job(inventory_view, result))


@websocket_command({"type": "doorcheck/panel_scan", "directory": str})
@require_admin
@async_response
async def scan(hass: HomeAssistant, connection: ActiveConnection, msg: dict[str, Any]) -> None:
    result = await call(hass, connection, msg, "scan_integration", fields(msg))
    connection.send_result(msg["id"], await hass.async_add_executor_job(saved_view, result))


@websocket_command({"type": "doorcheck/panel_results", "directory": str})
@require_admin
@async_response
async def saved(hass: HomeAssistant, connection: ActiveConnection, msg: dict[str, Any]) -> None:
    result = await call(hass, connection, msg, "get_results", fields(msg))
    connection.send_result(msg["id"], await hass.async_add_executor_job(saved_view, result))


@websocket_command({"type": "doorcheck/panel_review", "directory": str, "scan_id": str})
@require_admin
@async_response
async def review(hass: HomeAssistant, connection: ActiveConnection, msg: dict[str, Any]) -> None:
    result = await call(hass, connection, msg, "mark_reviewed", fields(msg))
    connection.send_result(msg["id"], await hass.async_add_executor_job(saved_view, result))


@websocket_command({"type": "doorcheck/panel_clear"})
@require_admin
@async_response
async def clear(hass: HomeAssistant, connection: ActiveConnection, msg: dict[str, Any]) -> None:
    await hass.services.async_call(
        DOMAIN, "clear_results", fields(msg), blocking=True, context=connection.context(msg)
    )
    connection.send_result(msg["id"], {"cleared": True})


def inventory_view(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": render("status." + result["status"]),
        "complete": result["status"] == "complete",
        "problems": [render(key) for key in result["problems"]],
        "items": [
            {
                "directory": item["directory"],
                "name": item["name"] or item["directory"],
                "version": item["version"],
                "problems": [render(key) for key in item["problems"]],
            }
            for item in result["items"]
        ],
    }


def location(value: Location) -> str:
    parts = [value.path, *(str(v) for v in (value.line, value.column) if v is not None)]
    return display_safe(":".join(parts))


def report_data(report: Report) -> dict[str, Any]:
    return {
        "target": display_safe(report.target.name),
        "complete": complete(report),
        "checks": [
            {
                "name": display_safe(c.name),
                "status": render("status." + c.status.value),
                "problems": [
                    {
                        "message": render(p.key, p.params),
                        "location": location(p.location) if p.location else None,
                    }
                    for p in c.problems
                ],
            }
            for c in report.checks
        ],
        "findings": [finding_view(f) for f in report.findings],
        "capabilities": [capability_view(c) for c in report.capabilities],
    }


def finding_view(finding: Finding) -> dict[str, Any]:
    action_key = finding.message_key + "_action"
    detail_key = finding.message_key + "_detail"
    return {
        "severity": finding.severity.value,
        "label": render("severity." + finding.severity.value),
        "message": render(finding.message_key, finding.params),
        "action": render(action_key) if action_key in ENGLISH else None,
        "detail": render(detail_key) if detail_key in ENGLISH else None,
        "location": location(finding.location),
        "rule": display_safe(finding.rule_id),
        "confidence": render("ha.panel.confidence", {"value": finding.confidence.value}),
        "evidence": display_safe(finding.evidence or ""),
    }


def capability_view(capability: Capability) -> dict[str, Any]:
    return {"message": render_capability(capability), "location": location(capability.location)}


def paths(values: list[str]) -> list[str]:
    return [display_safe(value) for value in values]


def changes(data: dict[str, list[str]]) -> dict[str, list[str]]:
    return {kind: paths(data[kind]) for kind in ("added", "removed", "changed")}


def positions(items: tuple[object, ...], chosen: tuple[object, ...]) -> list[int]:
    index = {id(item): number for number, item in enumerate(items)}
    return [index[id(item)] for item in chosen]


def comparison_view(baseline: Report, latest: Report, data: dict[str, Any]) -> dict[str, Any]:
    compared = compare(baseline, latest)
    limits = set(data["limits"])
    # Added items are already in the latest report; send their positions, not copies.
    added = {
        "findings": positions(latest.findings, compared.findings.added),
        "capabilities": positions(latest.capabilities, compared.capabilities.added),
    }
    removed = {
        "findings": [finding_view(f) for f in compared.findings.removed],
        "capabilities": [capability_view(c) for c in compared.capabilities.removed],
    }
    files, bytecode = changes(data["files"]), changes(data["bytecode"])
    lists = [*added.values(), *removed.values(), *files.values(), *bytecode.values()]
    return {
        "changed": bool(limits) or any(lists),
        "limits": [render("comparison." + limit) for limit in data["limits"]],
        "rules_changed": bool(limits & {Limit.ENGINE_VERSION, Limit.CHECKS}),
        # A removal is proven only when the latest scan covered everything.
        "unproven": Limit.AFTER_INCOMPLETE in limits,
        "added": added,
        "removed": removed,
        "files": files,
        "bytecode": bytecode,
    }


def saved_view(result: dict[str, Any]) -> dict[str, Any]:
    """One shape for a scan, a saved read and a review: the comparison first."""
    results = result["results"]
    problems = results["problems"] if results else result["problems"]
    view: dict[str, Any] = {"problems": [render(key) for key in problems], "latest": None}
    if results is None:
        return view
    latest, baseline = results["latest"], results["baseline"]
    latest_report = from_dict(latest["report"])
    reviewed = baseline is not None and baseline["scan_id"] == latest["scan_id"]
    view.update(
        {
            "saving": results["saving"],
            "saved": results["saved"],
            "latest": {
                "scan_id": latest["scan_id"],
                "scanned_at": latest["scanned_at"],
                "bytecode": paths(latest["bytecode"]),
                "report": report_data(latest_report),
            },
            "baseline": None
            if baseline is None
            else {"scan_id": baseline["scan_id"], "scanned_at": baseline["scanned_at"]},
            "reviewed": reviewed,
            "reviewable": results["saved"]
            and results["saving"] == "on"
            and not reviewed
            and complete(latest_report),
            "comparison": None
            if baseline is None or reviewed
            else comparison_view(
                from_dict(baseline["report"]), latest_report, results["comparison"]
            ),
        }
    )
    return view
