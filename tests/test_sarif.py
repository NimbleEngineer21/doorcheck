from collections.abc import Mapping
from typing import Any

import jsonschema

from doorcheck.checks import Check, Problem, Status
from doorcheck.findings import Location, Severity
from doorcheck.report import Report, Target
from doorcheck.sarif import to_sarif
from tests.conftest import make_finding

GAP = Problem("problem.file_not_parsed", Location("a.py", 4, 2), {"detail": "bad"})


def render(key: str, params: Mapping[str, str]) -> str:
    return f"{key}|{','.join(f'{k}={v}' for k, v in sorted(params.items()))}"


def _report(*findings: Any, checks: tuple[Check, ...] = ()) -> Report:
    target = Target(name="o/r")
    return Report("0.1.0", target, checks=checks, capabilities=(), findings=findings)


def _run(report: Report) -> dict[str, Any]:
    run: dict[str, Any] = to_sarif(report, render)["runs"][0]
    return run


def test_output_is_valid_sarif(sarif_schema: dict[str, Any]) -> None:
    report = _report(
        make_finding(),
        make_finding(severity=Severity.INFO, cwe=None, evidence=None),
        make_finding(location=Location("x.py", 3)),
    )
    jsonschema.validate(to_sarif(report, render), sarif_schema)


def test_output_with_gaps_is_valid_sarif(sarif_schema: dict[str, Any]) -> None:
    checks = (
        Check("semgrep", "1", Status.PARTIAL, (GAP, Problem("problem.no_rules"))),
        Check("osv-scanner", "2", Status.FAILED, (Problem("problem.tool_timed_out"),)),
    )
    jsonschema.validate(to_sarif(_report(make_finding(), checks=checks), render), sarif_schema)


def test_gaps_become_tool_notifications() -> None:
    checks = (
        Check("semgrep", "1", Status.PARTIAL, (GAP, Problem("problem.no_rules"))),
        Check("zizmor", "1", Status.COMPLETE),
    )
    invocation = _run(_report(checks=checks))["invocations"][0]
    assert invocation == {
        "executionSuccessful": True,
        "toolExecutionNotifications": [
            {
                "descriptor": {"id": "semgrep"},
                "level": "warning",
                "message": {"text": "problem.file_not_parsed|detail=bad"},
                "properties": {"key": "problem.file_not_parsed"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "a.py"},
                            "region": {"startLine": 4, "startColumn": 2},
                        }
                    }
                ],
            },
            {
                "descriptor": {"id": "semgrep"},
                "level": "warning",
                "message": {"text": "problem.no_rules|"},
                "properties": {"key": "problem.no_rules"},
            },
        ],
    }


def test_a_failed_check_marks_the_run_unsuccessful() -> None:
    failed = Check("osv-scanner", "2", Status.FAILED, (Problem("problem.tool_timed_out"),))
    others = (Check("a", "1", Status.NOTHING_TO_SCAN), Check("b", "1", Status.PARTIAL, (GAP,)))
    assert _run(_report(checks=others))["invocations"][0]["executionSuccessful"] is True
    assert _run(_report(checks=(*others, failed)))["invocations"][0]["executionSuccessful"] is False


def test_results_carry_the_fingerprint() -> None:
    finding = make_finding()
    result = _run(_report(finding))["results"][0]
    assert result["partialFingerprints"] == {"doorcheck/v1": finding.fingerprint}


def test_empty_report_is_valid_sarif(sarif_schema: dict[str, Any]) -> None:
    jsonschema.validate(to_sarif(_report(), render), sarif_schema)


def test_result_carries_location_snippet_and_rendered_message() -> None:
    result = _run(_report(make_finding()))["results"][0]
    assert result["ruleId"] == "ha-reads-credential-store"
    assert result["level"] == "warning"
    assert result["message"] == {"text": "finding.reads_credential_store|file=.storage/auth"}
    physical = result["locations"][0]["physicalLocation"]
    assert physical["artifactLocation"] == {"uri": "custom_components/demo/__init__.py"}
    assert physical["region"] == {
        "startLine": 42,
        "startColumn": 9,
        "snippet": {"text": "open(hass.config.path('.storage/auth'))"},
    }
    assert result["properties"] == {"confidence": "high", "tool": "doorcheck"}


def test_region_omits_missing_column_and_evidence() -> None:
    finding = make_finding(location=Location("a.py", 7), evidence=None)
    region = _run(_report(finding))["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert region == {"startLine": 7}


def test_levels_and_security_severity_per_severity() -> None:
    expected = {
        Severity.SERIOUS: ("error", "8.0"),
        Severity.REVIEW: ("warning", "5.0"),
        Severity.NOTICE: ("note", "2.0"),
        Severity.INFO: ("none", None),
    }
    for severity, (level, security) in expected.items():
        run = _run(_report(make_finding(severity=severity)))
        assert run["results"][0]["level"] == level
        rule = run["tool"]["driver"]["rules"][0]
        assert rule["defaultConfiguration"] == {"level": level}
        assert rule["properties"].get("security-severity") == security


def test_rule_is_rated_by_its_most_urgent_finding() -> None:
    report = _report(
        make_finding(severity=Severity.NOTICE),
        make_finding(severity=Severity.SERIOUS, location=Location("z.py", 1)),
        make_finding(severity=Severity.REVIEW, location=Location("y.py", 1)),
    )
    rules = _run(report)["tool"]["driver"]["rules"]
    assert len(rules) == 1
    assert rules[0]["defaultConfiguration"] == {"level": "error"}


def test_rules_are_listed_once_each_in_order_with_cwe_tags() -> None:
    report = _report(
        make_finding(rule_id="zeta", cwe=None),
        make_finding(rule_id="alpha", cwe=22),
        make_finding(rule_id="zeta", cwe=None, location=Location("q.py", 1)),
    )
    rules = _run(report)["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == ["alpha", "zeta"]
    assert rules[0]["properties"]["tags"] == ["security", "external/cwe/cwe-22"]
    assert rules[1]["properties"]["tags"] == ["security"]


def test_driver_identifies_doorcheck() -> None:
    sarif = to_sarif(_report(), render)
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "Doorcheck"
    assert driver["version"] == "0.1.0"
    assert driver["informationUri"] == "https://github.com/nimbleengineer21/doorcheck"


def test_rule_ties_keep_the_first_finding_in_report_order() -> None:
    report = _report(
        make_finding(cwe=79, location=Location("b.py", 1)),
        make_finding(cwe=22, location=Location("a.py", 1)),
    )
    rule = _run(report)["tool"]["driver"]["rules"][0]
    assert rule["properties"]["tags"] == ["security", "external/cwe/cwe-22"]


def test_artifact_paths_are_encoded_as_relative_uri_paths() -> None:
    from urllib.parse import unquote, urlsplit

    path = "custom_components/demo/a:b #?%é.py"
    report = _report(
        make_finding(location=Location(path, 1)),
        checks=(
            Check(
                "reader", "1", Status.PARTIAL, (Problem("problem.unreadable", Location(path, 1)),)
            ),
        ),
    )
    run = _run(report)
    result = run["results"][0]["locations"][0]
    notification = run["invocations"][0]["toolExecutionNotifications"][0]["locations"][0]
    for location in (result, notification):
        uri = location["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == "custom_components/demo/a%3Ab%20%23%3F%25%C3%A9.py"
        parsed = urlsplit(uri)
        assert not (parsed.scheme or parsed.query or parsed.fragment)
        assert unquote(parsed.path) == path
