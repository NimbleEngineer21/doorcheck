"""The exported acceptance artifact cannot silently claim incomplete success."""

import json
import os
import re
from importlib.metadata import version
from pathlib import Path

import pytest

from acceptance.evidence import REQUIRED, validate


def success():
    return {
        "schema_version": 1,
        "status": "passed",
        "checks": dict.fromkeys(REQUIRED, True),
        "home_assistant_version": "2026.10.4",
        "rest_validation_status": 400,
        "python": "3.14.9",
        "architecture": "aarch64",
        "engine_wheel_sha256": "a" * 64,
        "integration_tree_sha256": "b" * 64,
        "resources": {
            "cpu_seconds": 1.0,
            "peak_rss_bytes": 123,
            "event_loop_max_lag_seconds": 0.01,
            "heartbeat_samples": 1,
            "control_imported": False,
        },
        "measurements": [
            {"directory": "frigate", "elapsed_seconds": 0.5, "checks": {"snapshot": "complete"}}
        ],
    }


def test_complete_named_checks_are_required() -> None:
    evidence = success()
    assert validate(evidence) == evidence
    evidence["checks"].pop("scan_authorization")
    with pytest.raises(ValueError, match=r"^Incomplete acceptance success$"):
        validate(evidence)


def test_a_failing_reference_cannot_be_published_as_success() -> None:
    evidence = success()
    evidence["checks"]["alexa_media"] = False
    with pytest.raises(ValueError, match=r"^Incomplete acceptance success$"):
        validate(evidence)
    evidence["status"] = "failed"
    assert validate(evidence)["status"] == "failed"


@pytest.mark.parametrize("field", ["tokens", "raw_response", "config_dir", "logs"])
def test_raw_runtime_fields_are_rejected(field: str) -> None:
    evidence = success()
    evidence[field] = "must not be exported"
    with pytest.raises(ValueError, match=r"^Unexpected evidence fields$"):
        validate(evidence)


def test_raw_nested_fields_are_rejected() -> None:
    evidence = success()
    evidence["resources"] = {"access_token": "must not be exported"}
    with pytest.raises(ValueError, match=r"^Unexpected evidence fields$"):
        validate(evidence)
    evidence["resources"] = success()["resources"]
    evidence["measurements"] = [{"evidence": "source content must not be exported"}]
    with pytest.raises(ValueError, match=r"^Unexpected evidence fields$"):
        validate(evidence)


@pytest.mark.parametrize(
    "evidence",
    [
        None,
        {},
        {"schema_version": 2, "status": "failed", "checks": {"x": False}},
        {"schema_version": 1, "status": "failed", "checks": {"x": "false"}},
    ],
)
def test_invalid_evidence_is_not_exported(evidence) -> None:
    with pytest.raises(ValueError):
        validate(evidence)


@pytest.mark.parametrize(
    "field,value", [("schema_version", True), ("status", []), ("checks", {}), ("status", "unknown")]
)
def test_malformed_headers_are_rejected(field, value) -> None:
    evidence = success()
    evidence[field] = value
    with pytest.raises(ValueError):
        validate(evidence)


def test_failed_artifact_must_still_name_a_check() -> None:
    with pytest.raises(ValueError, match=r"^Missing check results$"):
        validate({"schema_version": 1, "status": "failed", "checks": {}})


@pytest.mark.parametrize("version,status", [(2, "failed"), (True, "passed"), (1, "unknown")])
def test_invalid_headers_have_a_distinct_diagnostic(version, status) -> None:
    with pytest.raises(ValueError, match=r"^Invalid evidence header$"):
        validate({"schema_version": version, "status": status, "checks": {"x": False}})


def test_success_without_measurements_cannot_be_exported() -> None:
    evidence = success()
    evidence.pop("measurements")
    with pytest.raises(ValueError, match=r"^Incomplete acceptance success$"):
        validate(evidence)


def test_startup_failure_can_be_exported_without_scan_measurements() -> None:
    evidence = {"schema_version": 1, "status": "failed", "checks": {"child_ready": False}}
    assert validate(evidence) == evidence


def test_container_profiles_match_framework_version_and_use_immutable_images() -> None:
    profiles = json.loads((Path(__file__).parents[1] / "acceptance/images.json").read_text())
    assert set(profiles) == {"minimum", "previous", "current"}
    installed = version("homeassistant")
    assert installed in {profile["version"] for profile in profiles.values()}
    if selected := os.environ.get("HA_PROFILE"):
        assert profiles[selected]["version"] == installed
    for profile in profiles.values():
        assert re.fullmatch(
            "ghcr.io/home-assistant/home-assistant:"
            + re.escape(profile["version"])
            + r"@sha256:[0-9a-f]{64}",
            profile["image"],
        )
