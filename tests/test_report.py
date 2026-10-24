import json
from importlib import resources
from typing import Any

import jsonschema
import pytest

from doorcheck.capabilities import Capability, Kind
from doorcheck.checks import Check, Problem, Status
from doorcheck.findings import Location, Severity
from doorcheck.report import SCHEMA_VERSION, Report, Target, from_dict, to_dict
from tests.conftest import make_finding

TARGET = Target(name="owner/repo", version="2.3.0", commit="a" * 40, artifact_sha256="b" * 64)
CHECKS = (
    Check("semgrep", "1.182.0", Status.COMPLETE),
    Check(
        "osv-scanner",
        "2.7.0",
        Status.PARTIAL,
        (
            Problem("problem.requirement_outside_pypi", Location("manifest.json", 4), {"r": "x"}),
            Problem("problem.no_rules"),
        ),
    ),
)
CAPABILITIES = (
    Capability(Kind.WEB_VIEW, Location("v.py", 3, 1), "/x/{f}", {"auth": "none", "class": "V"}),
    Capability(Kind.PROCESS, Location("p.py", 9), "git"),
)


def _report(**overrides: Any) -> Report:
    findings = (
        make_finding(severity=Severity.INFO, location=Location("b.py", 1), params={}),
        make_finding(),
        make_finding(cwe=None, evidence=None, location=Location("a.py", 3)),
    )
    fields: dict[str, Any] = {
        "doorcheck_version": "0.1.0",
        "target": TARGET,
        "checks": CHECKS,
        "capabilities": CAPABILITIES,
        "findings": findings,
    }
    return Report(**{**fields, **overrides})


def _schema() -> dict[str, Any]:
    text = resources.files("doorcheck").joinpath("schemas/report-v1.schema.json").read_text()
    schema: dict[str, Any] = json.loads(text)
    return schema


def test_round_trip_preserves_every_field() -> None:
    report = _report()
    assert from_dict(json.loads(json.dumps(to_dict(report)))) == report


def test_findings_are_stored_most_urgent_first() -> None:
    severities = [f.severity for f in _report().findings]
    assert severities == [Severity.REVIEW, Severity.REVIEW, Severity.INFO]
    assert [f.location.path for f in _report().findings][:2] == [
        "a.py",
        "custom_components/demo/__init__.py",
    ]


def test_output_matches_the_published_schema() -> None:
    jsonschema.validate(to_dict(_report()), _schema())


def test_schema_and_code_require_the_same_fields() -> None:
    schema = _schema()
    data = to_dict(_report())
    assert set(schema["required"]) == set(data)
    assert set(schema["properties"]["target"]["required"]) == set(data["target"])
    assert set(schema["$defs"]["finding"]["required"]) == set(data["findings"][0])
    assert set(schema["$defs"]["check"]["required"]) == set(data["checks"][0])
    assert set(schema["$defs"]["problem"]["required"]) == set(data["checks"][0]["problems"][0])
    assert set(schema["$defs"]["capability"]["required"]) == set(data["capabilities"][0])


def test_the_schema_lists_every_status_and_kind() -> None:
    defs = _schema()["$defs"]
    assert defs["check"]["properties"]["status"]["enum"] == [s.value for s in Status]
    assert defs["capability"]["properties"]["kind"]["enum"] == [k.value for k in Kind]


def test_checks_are_stored_by_name_and_each_appears_once() -> None:
    assert [c.name for c in _report().checks] == ["osv-scanner", "semgrep"]
    with pytest.raises(ValueError, match=r"^each check appears once$"):
        _report(checks=(CHECKS[0], CHECKS[0]))


def test_the_json_form_of_checks_and_capabilities() -> None:
    data = to_dict(_report())
    assert data["checks"][0] == {
        "name": "osv-scanner",
        "version": "2.7.0",
        "status": "partial",
        "problems": [
            {
                "key": "problem.requirement_outside_pypi",
                "location": {"path": "manifest.json", "line": 4, "column": None},
                "params": {"r": "x"},
            },
            {"key": "problem.no_rules", "location": None, "params": {}},
        ],
    }
    assert data["capabilities"][0] == {
        "kind": "web_view",
        "location": {"path": "v.py", "line": 3, "column": 1},
        "subject": "/x/{f}",
        "attrs": {"auth": "none", "class": "V"},
    }
    assert data["findings"][0]["fingerprint"] == _report().findings[0].fingerprint


def test_a_finding_whose_fingerprint_doesnt_match_is_refused() -> None:
    data = to_dict(_report())
    data["findings"][0]["fingerprint"] = "0" * 16
    with pytest.raises(ValueError, match=r"^fingerprint doesn't match the finding$"):
        from_dict(data)


def _mutate(path: list[str | int], value: Any) -> dict[str, Any]:
    data = to_dict(_report())
    node: Any = data
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    return data


@pytest.mark.parametrize(
    ("path", "value", "error"),
    [
        (["schema_version"], 2, "^unsupported schema version: 2$"),
        (["findings"], "not a list", "^findings must be a list$"),
        (["checks"], {}, "^checks must be a list$"),
        (["capabilities"], None, "^capabilities must be a list$"),
        (["checks", 1, "problems"], "x", "^problems must be a list$"),
        (["checks", 0, "status"], "done", "is not a valid Status"),
        (["checks", 0, "problems", 0, "key"], "Text", "^key required$"),
        (
            ["checks", 0, "problems", 0, "location"],
            {},
            r"^location must have exactly the fields \[",
        ),
        (["capabilities", 0, "kind"], "teleport", "is not a valid Kind"),
        (["capabilities", 0, "attrs", "auth"], 3, "^attrs must be strings$"),
        (["target"], "not a mapping", r"^target must have exactly the fields \["),
        (["findings", 0], "not a mapping", r"^finding must have exactly the fields \["),
        (["findings", 0, "location"], [], r"^location must have exactly the fields \["),
        (["findings", 0, "severity"], "critical", "is not a valid Severity"),
        (["findings", 0, "location", "line"], 0, "^line must be an integer from 1$"),
        (["findings", 0, "message_key"], "Display text", "^not a key: 'Display text'$"),
        (["doorcheck_version"], 1, "^doorcheck_version must be a string$"),
        (["target", "name"], "", "^target name is required$"),
        (["target", "commit"], 5, "^target fields must be strings$"),
    ],
)
def test_loading_rejects_invalid_values(path: list[str | int], value: Any, error: str) -> None:
    with pytest.raises(ValueError, match=error):
        from_dict(_mutate(path, value))


def test_report_error_names_its_fields() -> None:
    with pytest.raises(ValueError) as caught:
        from_dict({})
    assert str(caught.value) == (
        "report must have exactly the fields "
        "['capabilities', 'checks', 'doorcheck_version', 'findings', 'schema_version', 'target']"
    )


@pytest.mark.parametrize(
    ("path", "what"),
    [
        ([], "report"),
        (["target"], "target"),
        (["findings", 0], "finding"),
        (["findings", 0, "location"], "location"),
        (["checks", 0], "check"),
        (["checks", 0, "problems", 0], "problem"),
        (["capabilities", 0], "capability"),
    ],
)
def test_loading_rejects_unknown_fields(path: list[str | int], what: str) -> None:
    data = to_dict(_report())
    node: Any = data
    for key in path:
        node = node[key]
    node["unexpected"] = True
    with pytest.raises(ValueError, match=rf"^{what} must have exactly the fields \["):
        from_dict(data)


def test_loading_rejects_missing_fields() -> None:
    data = to_dict(_report())
    del data["findings"][0]["tool"]
    with pytest.raises(ValueError, match=r"^finding must have exactly the fields \["):
        from_dict(data)


def test_schema_version_is_one() -> None:
    assert SCHEMA_VERSION == 1
    assert to_dict(_report())["schema_version"] == 1


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("findings", ("x",), "findings must be Findings"),
        ("checks", ("x",), "checks must be Checks"),
        ("capabilities", ("x",), "capabilities must be Capabilities"),
        ("target", "x", "target must be a Target"),
        ("doorcheck_version", 1, "doorcheck_version must be a string"),
    ],
)
def test_report_rejects_wrong_types(field: str, value: Any, message: str) -> None:
    with pytest.raises(ValueError, match=f"^{message}$"):
        _report(**{field: value})
