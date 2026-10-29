"""Saved-report host summaries are offline, coverage-first and safely rendered."""

import json
import os
from dataclasses import replace
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

import jsonschema
import pytest
from referencing import Registry, Resource

from doorcheck import cli
from doorcheck.capabilities.model import COMPUTED, Capability, Kind
from doorcheck.checks import Check, Problem, Status
from doorcheck.cli_hosts import as_dict, human
from doorcheck.hosts import summarize
from doorcheck.messages import render
from doorcheck.report import Report, Target, to_dict
from tests.conftest import make_finding
from tests.test_hosts import cap

pytestmark = pytest.mark.usefixtures("offline")
EMPTY = Report(
    "1", Target("demo", "v1", "a" * 40, "b" * 64), (Check("source", "1", Status.COMPLETE),), (), ()
)


def save(root: Path, report: Report) -> Path:
    path = root / "report.json"
    path.write_text(json.dumps(to_dict(report)))
    return path


def run(tmp_path: Path, report: Report = EMPTY, *, json_output: bool = True) -> int:
    return cli.main(["hosts", str(save(tmp_path, report)), *(["--json"] if json_output else [])])


def test_json_retains_original_and_exact_evidence(tmp_path: Path, capsys) -> None:
    mention = cap(Kind.NETWORK_HOST, "example.invalid")
    request = cap(
        Kind.HTTP_REQUEST,
        "example.invalid",
        2,
        9,
        destination="static",
        method="GET",
        operation="requests.get",
    )
    script = cap(Kind.HA_FRONTEND_SCRIPT, "cdn.invalid", 3, 5, destination="static", es5="false")
    unknown = cap(Kind.HTTP_REQUEST, COMPUTED, 4, destination="computed")
    report = replace(EMPTY, capabilities=(request, script, mention, unknown, request))
    with (
        patch("doorcheck.cli.scan_folder", side_effect=AssertionError("no rescan")),
        patch("doorcheck.cli.scan_repository", side_effect=AssertionError("no fetch")),
    ):
        assert run(tmp_path, report) == 0
    output = capsys.readouterr()
    assert output.err == ""
    data = json.loads(output.out)
    assert data == as_dict(summarize(report))
    assert data["schema_version"] == 1
    assert data["report"] == to_dict(report)
    raw = to_dict(report)["capabilities"]
    assert data["hosts"] == [
        {"subject": "cdn.invalid", "mentions": [], "requests": [], "frontend_scripts": [raw[1]]},
        {
            "subject": "example.invalid",
            "mentions": [raw[2]],
            "requests": [raw[0], raw[0]],
            "frontend_scripts": [],
        },
    ]
    assert data["unresolved"] == {"mentions": [], "requests": [raw[3]], "frontend_scripts": []}
    report_schema = json.loads(
        files("doorcheck").joinpath("schemas/report-v1.schema.json").read_text()
    )
    schema = json.loads(
        files("doorcheck").joinpath("schemas/host-summary-v1.schema.json").read_text()
    )
    registry = Registry().with_resource(report_schema["$id"], Resource.from_contents(report_schema))
    jsonschema.Draft202012Validator(schema, registry=registry).validate(data)


def test_human_separates_roles_findings_coverage_and_unresolved(tmp_path: Path, capsys) -> None:
    problem = Problem("problem.no_rules")
    report = replace(
        EMPTY,
        checks=(Check("source", "1", Status.PARTIAL, (problem,)),),
        findings=(make_finding(message_key="finding.unauth_file_path"),),
        capabilities=(
            cap(Kind.NETWORK_HOST, "example.invalid", 2),
            cap(Kind.HTTP_REQUEST, "example.invalid", 3, 7, destination="static"),
            cap(Kind.HA_FRONTEND_SCRIPT, "cdn.invalid", 4, 9, destination="static", es5="true"),
            cap(Kind.HTTP_REQUEST, COMPUTED, 5, destination="computed"),
            cap(Kind.PROCESS, "git"),
        ),
    )
    assert run(tmp_path, report, json_output=False) == 2
    text = capsys.readouterr().out
    assert text == human(summarize(report))
    assert text.startswith(render("cli.hosts_scope") + "\nTarget: demo\nVersion: v1\n")
    assert "source: Scan partly completed" in text
    assert render("problem.no_rules") in text
    assert "Review at custom_components/demo/__init__.py:42" in text
    assert "1 finding(s); 5 source observation(s)." in text
    assert "Reported host: cdn.invalid\n" in text
    assert "Host mention at source.py:2:" in text
    assert "HTTP request source at source.py:3:7:" in text
    assert "Frontend script registration source at source.py:4:9:" in text
    assert "Unresolved host destinations:\n  HTTP request source at source.py:5:" in text
    assert "Names a program" not in text
    assert "Observation at " not in text


@pytest.mark.parametrize(
    "checks",
    [
        (),
        (Check("empty", "1", Status.NOTHING_TO_SCAN),),
        (Check("source", "1", Status.FAILED, (Problem("problem.no_rules"),)),),
        (Check("source", "1", Status.PARTIAL, (Problem("problem.no_rules"),)),),
        (Check("source", "1", Status.COMPLETE), Check("empty", "1", Status.NOTHING_TO_SCAN)),
    ],
)
@pytest.mark.parametrize("finding", [False, True])
def test_absent_or_incomplete_coverage_has_priority(
    tmp_path: Path, capsys, checks, finding
) -> None:
    report = replace(
        EMPTY,
        checks=checks,
        findings=(make_finding(message_key="finding.unauth_file_path"),) if finding else (),
    )
    assert run(tmp_path, report) == 2
    assert json.loads(capsys.readouterr().out)["report"] == to_dict(report)


@pytest.mark.parametrize("finding,code", [(False, 0), (True, 1)])
def test_complete_coverage_retains_finding_exit_policy(
    tmp_path: Path, capsys, finding, code
) -> None:
    report = replace(
        EMPTY, findings=(make_finding(message_key="finding.unauth_file_path"),) if finding else ()
    )
    assert run(tmp_path, report) == code
    assert json.loads(capsys.readouterr().out)["report"] == to_dict(report)


def test_empty_summary_explains_its_limits(tmp_path: Path, capsys) -> None:
    assert run(tmp_path, json_output=False) == 0
    text = capsys.readouterr().out
    assert render("cli.hosts_empty") + "\n" in text
    assert "0 finding(s); 0 source observation(s)." in text
    assert "Reported host:" not in text
    assert "Unresolved host destinations:" not in text


def test_only_unresolved_has_its_own_heading_without_empty_claim(tmp_path: Path, capsys) -> None:
    report = replace(EMPTY, capabilities=(cap(Kind.HA_FRONTEND_SCRIPT, COMPUTED),))
    assert run(tmp_path, report, json_output=False) == 0
    text = capsys.readouterr().out
    assert render("cli.hosts_empty") not in text
    assert render("cli.hosts_unresolved") in text
    assert "Reported host:" not in text


def test_hostile_subjects_and_evidence_cannot_create_terminal_rows(tmp_path: Path, capsys) -> None:
    hostile = "\x1b[2J\n\t\u202e"
    value = Capability(Kind.NETWORK_HOST, cap(Kind.NETWORK_HOST).location, hostile)
    report = replace(
        EMPTY, target=Target(hostile, hostile, hostile, hostile), capabilities=(value,)
    )
    assert run(tmp_path, report, json_output=False) == 0
    text = capsys.readouterr().out
    assert "\x1b" not in text and "\t" not in text and "\u202e" not in text
    assert "Reported host: ⟨U+001B⟩[2J⟨U+000A⟩⟨U+0009⟩⟨U+202E⟩\n" in text
    assert text.count("\n") == 10
    assert run(tmp_path, report) == 0
    raw = capsys.readouterr().out
    assert "\\u001b" in raw and "\\u202e" in raw
    assert json.loads(raw)["hosts"][0]["subject"] == hostile


@pytest.mark.parametrize("kind", ["absent", "directory", "link", "fifo"])
def test_only_regular_report_files_are_read(tmp_path: Path, capsys, kind) -> None:
    path = tmp_path / "input"
    if kind == "directory":
        path.mkdir()
    elif kind == "link":
        path.symlink_to(save(tmp_path, EMPTY))
    elif kind == "fifo":
        os.mkfifo(path)
    assert cli.main(["hosts", str(path)]) == 2
    result = capsys.readouterr()
    assert result.out == ""
    assert render("cli.report_invalid", {"path": str(path)}) in result.err


@pytest.mark.parametrize(
    "data", [b"{}", b'{"schema_version":1,"schema_version":1}', b"\xff", b"[]", b"null"]
)
def test_invalid_reports_have_no_partial_stdout(tmp_path: Path, capsys, data) -> None:
    path = tmp_path / "report.json"
    path.write_bytes(data)
    assert cli.main(["hosts", str(path), "--json"]) == 2
    result = capsys.readouterr()
    assert result.out == ""
    assert render("cli.report_invalid", {"path": str(path)}) in result.err


@pytest.mark.parametrize(
    "args",
    [
        ["hosts"],
        ["hosts", "a", "b"],
        ["hosts", "a", "--sarif"],
        ["hosts", "a", "--js"],
        ["hosts", "--repo", "owner/repo"],
    ],
)
def test_invalid_arguments_never_read(args, capsys) -> None:
    with patch("doorcheck.cli_hosts.read_report", side_effect=AssertionError("no read")):
        assert cli.main(args) == 2
    result = capsys.readouterr()
    assert result.out == ""
    assert result.err == render("cli.invalid_arguments") + "\n"


def test_help_is_shared_and_interrupts_remain_keyed(tmp_path: Path, capsys) -> None:
    assert cli.main(["hosts", "--help"]) == 0
    assert capsys.readouterr().out == render("cli.help") + "\n"
    with patch("doorcheck.cli_hosts.read_report", side_effect=KeyboardInterrupt):
        assert cli.main(["hosts", str(tmp_path / "input")]) == 130
    result = capsys.readouterr()
    assert result.out == ""
    assert result.err == render("cli.interrupted") + "\n"


def test_missing_check_metadata_is_explained_in_text(tmp_path: Path, capsys) -> None:
    assert run(tmp_path, replace(EMPTY, checks=()), json_output=False) == 2
    assert render("cli.hosts_checks_absent") + "\n" in capsys.readouterr().out
    assert run(tmp_path, EMPTY, json_output=False) == 0
    assert render("cli.hosts_checks_absent") not in capsys.readouterr().out
