"""Reject accidental raw responses and incomplete success summaries before export."""

from typing import Any

FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "checks",
        "failed_check",
        "measurements",
        "resources",
        "home_assistant_version",
        "rest_validation_status",
        "python",
        "architecture",
        "integration_tree_sha256",
        "engine_wheel_sha256",
    }
)
MEASUREMENTS = frozenset(
    {
        "directory",
        "snapshot_limits",
        "elapsed_seconds",
        "cpu_seconds",
        "peak_rss_bytes",
        "event_loop_max_lag_seconds",
        "checks",
        "problems",
        "findings",
        "observations",
        "response",
        "api_ping_seconds",
    }
)
RESOURCES = frozenset(
    {
        "cpu_seconds",
        "peak_rss_bytes",
        "event_loop_max_lag_seconds",
        "heartbeat_samples",
        "control_imported",
    }
)
REQUIRED = frozenset(
    {
        "panel_message_id",
        "panel_public_code_assets",
        "panel_admin_registration",
        "panel_module",
        "panel_inventory",
        "panel_scan",
        "panel_finding",
        "panel_user_authenticated",
        "panel_hidden_for_user",
        "panel_commands_admin_only",
        "panel_removed",
        "panel_unconfigured",
        "installed_ha_version",
        "local_engine_requirement",
        "network_loopback_only",
        "capabilities_dropped",
        "no_new_privileges",
        "root_readonly",
        "source_readonly",
        "repository_mount_is_scoped",
        "docker_socket_not_mounted",
        "memory_capped",
        "pids_capped",
        "cpu_capped",
        "normal_bootstrap",
        "native_setup_form",
        "native_setup_confirm",
        "inventory_response",
        "inventory_selection",
        "scan_authorization",
        "response_required",
        "path_rejected",
        "ws_scan_invalid_directory",
        "known_finding",
        "known_rule",
        "selected_target",
        "finding_location",
        "known_complete",
        "parse_gap",
        "dc_helpers",
        "dc_helpers_fixed",
        "helper_finding_location",
        "helper_sink_path",
        "dc_oversized",
        "dc_linked",
        "missing",
        "frigate",
        "alexa_media",
        "doorcheck",
        "concurrent_scan_rejected",
        "native_busy_error",
        "responsive_during_scan",
        "disconnect_retains_worker",
        "scan_after_disconnect",
        "native_reload",
        "scan_after_reload",
        "native_remove",
        "unconfigured_scan_rejected",
        "ws_inventory_not_configured",
        "clean_shutdown",
        "candidate_not_imported",
        "installed_sources_unchanged",
        "snapshot_cleanup",
        "credential_redaction",
    }
)


def record(value: object, allowed: frozenset[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or not set(value) <= allowed:
        raise ValueError("Unexpected evidence fields")
    return value


def validate(value: object) -> dict[str, Any]:
    data = record(value, FIELDS)
    checks = data.get("checks")
    if (
        not isinstance(checks, dict)
        or not checks
        or any(type(v) is not bool for v in checks.values())
    ):
        raise ValueError("Missing check results")
    if (
        type(data.get("schema_version")) is not int
        or data["schema_version"] != 1
        or not isinstance(data.get("status"), str)
        or data["status"] not in {"passed", "failed"}
    ):
        raise ValueError("Invalid evidence header")
    if data["status"] == "passed" and (
        not (FIELDS - {"failed_check"}) <= set(data)
        or not set(checks) >= REQUIRED
        or not all(checks.values())
    ):
        raise ValueError("Incomplete acceptance success")
    record(data.get("resources", {}), RESOURCES)
    for measurement in data.get("measurements", []):
        record(measurement, MEASUREMENTS)
    return data
