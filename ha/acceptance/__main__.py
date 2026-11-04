"""Exercise the disposable HA instance through its real authenticated HTTP APIs."""

import argparse
import asyncio
import contextlib
import hashlib
import json
import os
import platform
import socket
import sys
import tempfile
import zipfile
from importlib.metadata import version
from pathlib import Path
from time import perf_counter
from typing import Any

import aiohttp

from .fixtures import REFERENCES, fingerprint, prepare
from .isolation import boundaries

Record = dict[str, Any]
CHECKS: dict[str, bool] = {}


class AcceptanceFailure(Exception):
    """A named check failed; never include raw responses or credentials."""


def require(condition: bool, check: str) -> None:
    CHECKS[check] = CHECKS.get(check, True) and condition
    if not condition:
        raise AcceptanceFailure(check)


class Instance:
    def __init__(
        self, child: asyncio.subprocess.Process, port: int, validation_status: int
    ) -> None:
        self.validation_status = validation_status
        self.child = child
        if child.stdout is None or child.stdin is None:
            raise AcceptanceFailure("child_pipes")
        self.reader = child.stdout
        self.writer = child.stdin
        self.url = f"http://127.0.0.1:{port}"
        self.tokens: dict[str, str] = {}

    async def record(self) -> dict[str, Any]:
        line = await asyncio.wait_for(self.reader.readline(), 120)
        require(bool(line), "child_ready")
        value = json.loads(line)
        if not isinstance(value, dict):
            raise AcceptanceFailure("child_record")
        return value

    async def command(self, name: str) -> dict[str, Any]:
        self.writer.write(json.dumps({"command": name}).encode() + b"\n")
        await self.writer.drain()
        return await self.record()

    async def request(
        self,
        session: aiohttp.ClientSession,
        method: str,
        path: str,
        data: Record | None = None,
        identity: str = "admin",
    ) -> tuple[int, Any]:
        headers = {"Authorization": f"Bearer {self.tokens[identity]}"} if identity else {}
        async with session.request(method, self.url + path, json=data, headers=headers) as response:
            try:
                body = await response.json(content_type=None)
            except (ValueError, aiohttp.ContentTypeError):
                body = {"non_json": True}
            return response.status, body

    async def scan(
        self, session: aiohttp.ClientSession, directory: str, identity: str = "admin"
    ) -> tuple[int, Any]:
        return await self.request(
            session,
            "POST",
            "/api/services/doorcheck/scan_integration?return_response",
            {"directory": directory},
            identity,
        )


async def configured(instance: Instance, session: aiohttp.ClientSession) -> str:
    status, form = await instance.request(
        session, "POST", "/api/config/config_entries/flow", {"handler": "doorcheck"}
    )
    require(status == 200 and form["type"] == "form", "native_setup_form")
    status, created = await instance.request(
        session, "POST", f"/api/config/config_entries/flow/{form['flow_id']}", {}
    )
    require(status == 200 and created["type"] == "create_entry", "native_setup_confirm")
    for _ in range(200):
        _, entries = await instance.request(
            session, "GET", "/api/config/config_entries/entry?domain=doorcheck"
        )
        if entries and entries[0]["state"] == "loaded":
            entry_id = entries[0]["entry_id"]
            if not isinstance(entry_id, str):
                raise AcceptanceFailure("entry_identifier")
            return entry_id
        await asyncio.sleep(0.05)
    raise AcceptanceFailure("native_entry_loaded")


async def measured_scan(
    instance: Instance, session: aiohttp.ClientSession, directory: str
) -> tuple[Record, Record]:
    before = await instance.command("metrics")
    start = perf_counter()
    status, body = await instance.scan(session, directory)
    elapsed = perf_counter() - start
    require(status == 200, "admin_scan_response")
    after = await instance.command("metrics")
    from doorcheck.report import from_dict

    require(body["service_response"]["origin"] == "unknown", "unknown_origin")
    report = body["service_response"]["report"]
    from_dict(report)
    metrics = {
        "directory": directory,
        "snapshot_limits": before["snapshot_limits"],
        "elapsed_seconds": elapsed,
        "cpu_seconds": after["cpu_seconds"] - before["cpu_seconds"],
        "peak_rss_bytes": after["peak_rss_bytes"],
        "event_loop_max_lag_seconds": after["event_loop_max_lag_seconds"],
        "checks": {check["name"]: check["status"] for check in report["checks"]},
        "problems": sorted(
            {problem["key"] for check in report["checks"] for problem in check["problems"]}
        ),
        "findings": len(report["findings"]),
        "observations": len(report["capabilities"]),
    }
    return report, metrics


async def exercise(instance: Instance) -> Record:
    async with aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=40), trust_env=False
    ) as session:
        entry = await configured(instance, session)
        await panel_api(instance, session)
        status, inventory = await instance.request(
            session, "POST", "/api/services/doorcheck/get_inventory?return_response", {}
        )
        require(status == 200, "inventory_response")
        domains = {item["directory"] for item in inventory["service_response"]["items"]}
        require(
            {"dc_acceptance", *(domain for _, domain in REFERENCES)} <= domains,
            "inventory_selection",
        )
        for identity, expected in (("", 401), ("user", 401)):
            status, _ = await instance.scan(session, "dc_acceptance", identity)
            require(status == expected, "scan_authorization")
        status, _ = await instance.request(
            session,
            "POST",
            "/api/services/doorcheck/scan_integration",
            {"directory": "dc_acceptance"},
        )
        require(status == 400, "response_required")
        status, _ = await instance.scan(session, "../outside")
        require(status == instance.validation_status, "path_rejected")
        await validation_error(
            instance, session, {"directory": "../outside"}, "scan_invalid_directory"
        )
        checks = {}
        measurements = []
        report, metrics = await measured_scan(instance, session, "dc_acceptance")
        measurements.append(metrics)
        require(len(report["findings"]) == 1, "known_finding")
        require(report["target"]["name"] == "dc_acceptance", "selected_target")
        require(
            report["findings"][0]["location"] == {"path": "__init__.py", "line": 8, "column": None},
            "finding_location",
        )
        require(
            metrics["checks"]
            == {name: "complete" for name in ("snapshot", "capabilities", "python-rules")},
            "known_complete",
        )
        require(report["findings"][0]["rule_id"] == "ha-unauth-view-unsanitized-path", "known_rule")
        for directory in (
            "dc_helpers",
            "dc_helpers_fixed",
            "dc_broken",
            "dc_oversized",
            "dc_linked",
            "missing",
            "doorcheck",
            *(domain for _, domain in REFERENCES),
        ):
            report, metrics = await measured_scan(instance, session, directory)
            measurements.append(metrics)
            statuses = metrics["checks"]
            if directory in {"dc_helpers", "dc_helpers_fixed"}:
                checks[directory] = all(value == "complete" for value in statuses.values()) and len(
                    report["findings"]
                ) == (1 if directory == "dc_helpers" else 0)
                if directory == "dc_helpers":
                    require(
                        report["findings"][0]["location"]
                        == {"path": "__init__.py", "line": 9, "column": None},
                        "helper_finding_location",
                    )
                    require(
                        report["findings"][0]["params"]["sink_path"] == "reader.py",
                        "helper_sink_path",
                    )
            elif directory == "dc_broken":
                checks["parse_gap"] = (
                    statuses["capabilities"] == statuses["python-rules"] == "partial"
                )
            elif directory in {"dc_oversized", "dc_linked", "missing"}:
                checks[directory] = statuses == {"snapshot": "failed"} and not report["findings"]
            else:
                checks[directory] = statuses.get("snapshot") == "complete"
        measurements.append(await disconnected_scan(instance, session))
        status, _ = await instance.request(
            session, "POST", f"/api/config/config_entries/entry/{entry}/reload", {}
        )
        require(status == 200, "native_reload")
        status, _ = await instance.scan(session, "dc_acceptance")
        require(status == 200, "scan_after_reload")
        status, _ = await instance.request(
            session, "DELETE", f"/api/config/config_entries/entry/{entry}"
        )
        require(status == 200, "native_remove")
        status, _ = await instance.scan(session, "dc_acceptance")
        require(status == instance.validation_status, "unconfigured_scan_rejected")
        await validation_error(
            instance, session, {"directory": "dc_acceptance"}, "inventory_not_configured"
        )
        await panel_removed(instance, session)
    return {"measurements": measurements, "checks": checks}


async def panel_message(
    instance: Instance,
    connection: aiohttp.ClientWebSocketResponse,
    number: int,
    command: str,
    **data: Any,
) -> Record:
    await connection.send_json({"id": number, "type": command, **data})
    response = await asyncio.wait_for(connection.receive_json(), 40)
    if not isinstance(response, dict):
        raise AcceptanceFailure("panel_message_record")
    require(response["id"] == number, "panel_message_id")
    return response


async def panel_api(instance: Instance, session: aiohttp.ClientSession) -> None:
    for asset in ("panel.js", "panel.css"):
        status, _ = await instance.request(
            session, "GET", "/doorcheck_static/" + asset, identity=""
        )
        require(status == 200, "panel_public_code_assets")
    async with session.ws_connect(instance.url + "/api/websocket") as connection:
        await authenticated_socket(instance, connection)
        panels = await panel_message(instance, connection, 1, "get_panels")
        config = panels["result"]["doorcheck"]
        require(config["require_admin"] is True, "panel_admin_registration")
        require(
            config["config"]["_panel_custom"]["module_url"] == "/doorcheck_static/panel.js",
            "panel_module",
        )
        inventory = await panel_message(instance, connection, 2, "doorcheck/panel_inventory")
        require(
            inventory["success"]
            and any(item["directory"] == "dc_acceptance" for item in inventory["result"]["items"]),
            "panel_inventory",
        )
        result = await panel_message(
            instance, connection, 3, "doorcheck/panel_scan", directory="dc_acceptance"
        )
        require(result["success"] and result["result"]["complete"], "panel_scan")
        finding = result["result"]["findings"][0]
        require(
            finding["rule"] == "ha-unauth-view-unsanitized-path"
            and "__init__.py:8" in finding["location"],
            "panel_finding",
        )
    async with session.ws_connect(instance.url + "/api/websocket") as connection:
        await connection.receive_json()
        await connection.send_json({"type": "auth", "access_token": instance.tokens["user"]})
        require((await connection.receive_json())["type"] == "auth_ok", "panel_user_authenticated")
        panels = await panel_message(instance, connection, 1, "get_panels")
        require("doorcheck" not in panels["result"], "panel_hidden_for_user")
        for number, command in ((2, "inventory"), (3, "scan")):
            data = {"directory": "dc_acceptance"} if command == "scan" else {}
            denied = await panel_message(
                instance, connection, number, "doorcheck/panel_" + command, **data
            )
            require(
                not denied["success"] and denied["error"]["code"] == "unauthorized",
                "panel_commands_admin_only",
            )


async def panel_removed(instance: Instance, session: aiohttp.ClientSession) -> None:
    async with session.ws_connect(instance.url + "/api/websocket") as connection:
        await authenticated_socket(instance, connection)
        panels = await panel_message(instance, connection, 1, "get_panels")
        require("doorcheck" not in panels["result"], "panel_removed")
        response = await panel_message(instance, connection, 2, "doorcheck/panel_inventory")
        require(
            not response["success"]
            and response["error"].get("translation_key") == "inventory_not_configured",
            "panel_unconfigured",
        )


async def authenticated_socket(
    instance: Instance, connection: aiohttp.ClientWebSocketResponse
) -> None:
    require((await connection.receive_json())["type"] == "auth_required", "ws_auth_required")
    await connection.send_json({"type": "auth", "access_token": instance.tokens["admin"]})
    require((await connection.receive_json())["type"] == "auth_ok", "ws_authenticated")


async def validation_error(
    instance: Instance, session: aiohttp.ClientSession, data: Record, key: str
) -> None:
    async with session.ws_connect(instance.url + "/api/websocket") as connection:
        await authenticated_socket(instance, connection)
        await connection.send_json(
            {
                "id": 1,
                "type": "call_service",
                "domain": "doorcheck",
                "service": "scan_integration",
                "service_data": data,
                "return_response": True,
            }
        )
        response = await asyncio.wait_for(connection.receive_json(), 10)
        require(not response["success"], "ws_validation_rejected")
        require(response["error"].get("translation_key") == key, "ws_" + key)


async def disconnected_scan(instance: Instance, session: aiohttp.ClientSession) -> Record:
    before = await instance.command("metrics")
    start = perf_counter()
    async with session.ws_connect(instance.url + "/api/websocket") as connection:
        await authenticated_socket(instance, connection)
        for number, directory in ((1, "dc_heavy"), (2, "dc_acceptance")):
            await connection.send_json(
                {
                    "id": number,
                    "type": "call_service",
                    "domain": "doorcheck",
                    "service": "scan_integration",
                    "service_data": {"directory": directory},
                    "return_response": True,
                }
            )
        busy = await asyncio.wait_for(connection.receive_json(), 10)
        require(busy["id"] == 2 and not busy["success"], "concurrent_scan_rejected")
        require(busy["error"].get("translation_key") == "scan_busy", "native_busy_error")
        pending = asyncio.create_task(connection.receive_json())
        try:
            ping_start = perf_counter()
            status, _ = await instance.request(session, "GET", "/api/")
            ping_seconds = perf_counter() - ping_start
            require(status == 200 and not pending.done(), "responsive_during_scan")
        finally:
            pending.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await pending
    status, _ = await instance.scan(session, "dc_acceptance")
    require(status == instance.validation_status, "disconnect_retains_worker")
    for _ in range(600):
        status, body = await instance.scan(session, "dc_acceptance")
        if status == 200:
            require(
                len(body["service_response"]["report"]["findings"]) == 1, "scan_after_disconnect"
            )
            break
        require(status == instance.validation_status, "busy_until_complete")
        await asyncio.sleep(0.05)
    else:
        raise AcceptanceFailure("worker_finishes_after_disconnect")
    after = await instance.command("metrics")
    return {
        "directory": "dc_heavy",
        "response": "discarded_by_client",
        "elapsed_seconds": perf_counter() - start,
        "api_ping_seconds": ping_seconds,
        "cpu_seconds": after["cpu_seconds"] - before["cpu_seconds"],
        "peak_rss_bytes": after["peak_rss_bytes"],
        "event_loop_max_lag_seconds": after["event_loop_max_lag_seconds"],
    }


def configure(config: Path) -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    (config / "configuration.yaml").write_text(
        "homeassistant:\n  latitude: 0\n  longitude: 0\n  elevation: 0\n  time_zone: UTC\n"
        "  country: US\n  unit_system: metric\nhttp:\n  server_host: 127.0.0.1\n"
        f"  server_port: {port}\napi:\nconfig:\nwebsocket_api:\n"
    )
    return int(port)


async def run(
    source: Path, cache: Path, wheel: Path, expected: str, validation_status: int
) -> Record:
    with tempfile.TemporaryDirectory(prefix="doorcheck-acceptance-") as temporary:
        workspace = Path(temporary)
        engine = workspace / "engine"
        with zipfile.ZipFile(wheel) as archive:
            archive.extractall(engine)
        sys.path.insert(0, str(engine))
        manifest = json.loads((source / "ha/custom_components/doorcheck/manifest.json").read_text())
        require(
            manifest["requirements"] == [f"doorcheck=={version('doorcheck')}"],
            "local_engine_requirement",
        )
        config = workspace / "config"
        config.mkdir()
        original = prepare(config, source, cache)
        integration_digest = fingerprint(config / "custom_components/doorcheck")
        port = configure(config)
        scan_tmp = workspace / "scan-tmp"
        scan_tmp.mkdir()
        environment = {
            **os.environ,
            "PYTHONPATH": f"{engine}:{source / 'ha'}",
            "TMPDIR": str(scan_tmp),
        }
        with (workspace / "ha.log").open("w") as log:
            child = await asyncio.create_subprocess_exec(
                sys.executable,
                "-m",
                "acceptance.instance",
                str(config),
                env=environment,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=log,
            )
            instance = Instance(child, port, validation_status)
            try:
                ready = await instance.record()
                require(ready["ready"], "normal_bootstrap")
                instance.tokens = ready["tokens"]
                result = await exercise(instance)
                final = await instance.command("stop")
                await asyncio.wait_for(child.wait(), 30)
                require(child.returncode == 0, "clean_shutdown")
                require(not final["control_imported"], "candidate_not_imported")
                require(
                    all(
                        fingerprint(config / "custom_components" / name) == digest
                        for name, digest in original.items()
                    ),
                    "installed_sources_unchanged",
                )
                require(not list(scan_tmp.iterdir()), "snapshot_cleanup")
            finally:
                if child.returncode is None:
                    child.kill()
                    await child.wait()
        result["checks"].update(CHECKS)
        require(
            not any(token in json.dumps(result) for token in instance.tokens.values()),
            "credential_redaction",
        )
        result["checks"].update(CHECKS)
        result.update(
            {
                "schema_version": 1,
                "home_assistant_version": expected,
                "rest_validation_status": validation_status,
                "python": platform.python_version(),
                "architecture": platform.machine(),
                "integration_tree_sha256": integration_digest,
                "engine_wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
                "resources": final,
                "status": "passed" if all(result["checks"].values()) else "failed",
            }
        )
        return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("/work"))
    parser.add_argument("--cache", type=Path, default=Path("/work/.benchmark-cache"))
    parser.add_argument(
        "--wheel", type=Path, default=Path("/work/dist/doorcheck-0.1.0-py3-none-any.whl")
    )
    parser.add_argument("--expected-ha", required=True)
    parser.add_argument("--validation-status", type=int, choices=(400, 500), required=True)
    args = parser.parse_args()
    try:
        require(version("homeassistant") == args.expected_ha, "installed_ha_version")
        for check, passed in boundaries().items():
            require(passed, check)
        result = asyncio.run(
            run(args.source, args.cache, args.wheel, args.expected_ha, args.validation_status)
        )
    except AcceptanceFailure as error:
        result = {
            "schema_version": 1,
            "status": "failed",
            "checks": CHECKS,
            "failed_check": str(error),
        }
    except Exception as error:
        CHECKS["runtime_" + type(error).__name__.lower()] = False
        result = {
            "schema_version": 1,
            "status": "failed",
            "checks": CHECKS,
            "failed_check": "runtime_error",
        }

    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
