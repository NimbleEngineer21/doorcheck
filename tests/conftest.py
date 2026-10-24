from typing import Any

from doorcheck.findings import Confidence, Finding, Location, Severity


def make_finding(**overrides: Any) -> Finding:
    fields: dict[str, Any] = {
        "rule_id": "ha-reads-credential-store",
        "severity": Severity.REVIEW,
        "confidence": Confidence.HIGH,
        "location": Location("custom_components/demo/__init__.py", 42, 9),
        "message_key": "finding.reads_credential_store",
        "tool": "doorcheck",
        "cwe": 522,
        "evidence": "open(hass.config.path('.storage/auth'))",
        "params": {"file": ".storage/auth"},
    }
    fields.update(overrides)
    return Finding(**fields)
