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

from doorcheck.findings import Finding, Location
from doorcheck.messages import ENGLISH, render, render_capability
from doorcheck.report import from_dict
from doorcheck.text import display_safe

from .const import DOMAIN

URL = "/doorcheck_static"


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
    websocket_api.async_register_command(hass, inventory)
    websocket_api.async_register_command(hass, scan)


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
    data = {key: value for key, value in msg.items() if key not in {"id", "type"}}
    result = await call(hass, connection, msg, "scan_integration", data)
    connection.send_result(msg["id"], await hass.async_add_executor_job(report_view, result))


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


def report_view(result: dict[str, Any]) -> dict[str, Any]:
    report = from_dict(result["report"])
    return {
        "target": display_safe(report.target.name),
        "complete": bool(report.checks)
        and all(c.status.value == "complete" for c in report.checks),
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
        "capabilities": [
            {"message": render_capability(c), "location": location(c.location)}
            for c in report.capabilities
        ],
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
