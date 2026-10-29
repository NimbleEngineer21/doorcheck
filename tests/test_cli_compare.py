"""Offline comparison input, output, exit codes and hostile report data."""

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
from doorcheck.capabilities.model import Capability, Kind
from doorcheck.checks import Check, Problem, Status
from doorcheck.cli_compare import MAX_REPORT_BYTES, ReportInputError, read_report
from doorcheck.findings import Location, Severity
from doorcheck.messages import render
from doorcheck.report import Report, Target, to_dict
from tests.conftest import make_finding

pytestmark = pytest.mark.usefixtures("offline")
CAP = Capability(Kind.PROCESS, Location("source.py", 3), "git")
FINDING = make_finding(
    location=Location("source.py", 7),
    evidence="open(filename)",
    message_key="finding.unauth_file_path",
    params={},
)
EMPTY = Report(
    "1", Target("demo", "v1", "a" * 40, "b" * 64), (Check("source", "1", Status.COMPLETE),), (), ()
)


def save(root: Path, name: str, report: Report) -> Path:
    path = root / name
    path.write_text(json.dumps(to_dict(report)))
    return path


def args(tmp_path: Path, before: Report = EMPTY, after: Report = EMPTY, *, json_output=True):
    return [
        "compare",
        str(save(tmp_path, "before.json", before)),
        str(save(tmp_path, "after.json", after)),
        *(["--json"] if json_output else []),
    ]


def test_json_preserves_original_reports_and_only_the_expected_changes(
    tmp_path: Path, capsys
) -> None:
    before = replace(EMPTY, findings=(FINDING,))
    after = replace(EMPTY, target=Target("demo", "v2", "c" * 40, "d" * 64), capabilities=(CAP,))
    assert cli.main(args(tmp_path, before, after)) == 0
    output = capsys.readouterr()
    assert output.err == ""
    assert output.out.endswith("\n")
    data = json.loads(output.out)
    assert data == {
        "schema_version": 1,
        "metadata_matches": True,
        "before": to_dict(before),
        "after": to_dict(after),
        "added": {"capabilities": to_dict(after)["capabilities"], "findings": []},
        "removed": {"capabilities": [], "findings": to_dict(before)["findings"]},
    }
    schema_root = files("doorcheck").joinpath("schemas")
    report_schema = json.loads(schema_root.joinpath("report-v1.schema.json").read_text())
    schema = json.loads(schema_root.joinpath("comparison-v1.schema.json").read_text())
    registry = Registry().with_resource(report_schema["$id"], Resource.from_contents(report_schema))
    jsonschema.Draft202012Validator(schema, registry=registry).validate(data)
    assert (
        save(tmp_path, "roundtrip.json", before).read_text()
        == (tmp_path / "before.json").read_text()
    )


def test_human_labels_and_versions_make_removed_and_added_distinct(tmp_path: Path, capsys) -> None:
    before = replace(EMPTY, findings=(FINDING,))
    after = replace(EMPTY, target=replace(EMPTY.target, version="v2"), capabilities=(CAP,))
    assert cli.main(args(tmp_path, before, after, json_output=False)) == 0
    output = capsys.readouterr()
    assert output.err == ""
    assert output.out.startswith(
        render("cli.compare_scope") + "\n" + render("cli.compare_matched") + "\n"
    )
    removed, added = output.out.split(render("cli.compare_added"))
    assert render("cli.compare_removed") in removed
    assert "Review at source.py:7" in removed
    assert "Target version: v1" in removed and "Target version: v2" in added
    assert "Doorcheck report version: 1" in added
    assert "Check version: source = 1" in added
    assert "Observation at source.py:3" in added
    assert "Review at" not in added
    assert render("cli.scope") not in output.out
    assert output.out.endswith("1 source observation(s).\n")


@pytest.mark.parametrize(
    "severity,expected",
    [(Severity.INFO, 0), (Severity.NOTICE, 0), (Severity.REVIEW, 1), (Severity.SERIOUS, 1)],
)
def test_only_added_findings_determine_exit_one(tmp_path: Path, capsys, severity, expected) -> None:
    finding = replace(FINDING, severity=severity)
    old = replace(EMPTY, findings=(FINDING,))
    new = replace(EMPTY, findings=(FINDING, finding))
    assert cli.main(args(tmp_path, old, new)) == expected
    assert len(json.loads(capsys.readouterr().out)["added"]["findings"]) == 1
    assert cli.main(args(tmp_path, old, old)) == 0
    assert json.loads(capsys.readouterr().out)["added"]["findings"] == []


@pytest.mark.parametrize("side", ["before", "after"])
@pytest.mark.parametrize(
    "checks",
    [
        (),
        (Check("source", "1", Status.PARTIAL, (Problem("problem.tool_failed"),)),),
        (Check("source", "1", Status.FAILED, (Problem("problem.tool_failed"),)),),
        (Check("source", "1", Status.NOTHING_TO_SCAN),),
    ],
)
def test_missing_or_incomplete_checks_take_precedence(tmp_path: Path, capsys, side, checks) -> None:
    before = replace(EMPTY, checks=checks) if side == "before" else EMPTY
    after = replace(EMPTY, checks=checks) if side == "after" else EMPTY
    after = replace(after, findings=(FINDING,))
    assert cli.main(args(tmp_path, before, after)) == 2
    data = json.loads(capsys.readouterr().out)
    assert data["metadata_matches"] is False
    assert data[side]["checks"] == to_dict(replace(EMPTY, checks=checks))["checks"]
    assert len(data["added"]["findings"]) == 1


@pytest.mark.parametrize(
    "change",
    [
        {"doorcheck_version": "2"},
        {"target": Target("other")},
        {"checks": (Check("other", "1", Status.COMPLETE),)},
        {"checks": (Check("source", "2", Status.COMPLETE),)},
        {"checks": (Check("source", "1", Status.COMPLETE), Check("extra", "1", Status.COMPLETE))},
    ],
)
def test_metadata_mismatches_are_limited_but_preserve_changes(
    tmp_path: Path, capsys, change
) -> None:
    after = replace(EMPTY, findings=(FINDING,), **change)
    assert cli.main(args(tmp_path, EMPTY, after)) == 2
    output = json.loads(capsys.readouterr().out)
    assert output["metadata_matches"] is False
    assert output["after"] == to_dict(after)
    assert len(output["added"]["findings"]) == 1


@pytest.mark.parametrize("version", ["", " "])
def test_unrecorded_versions_do_not_establish_matching_coverage(
    tmp_path: Path, capsys, version
) -> None:
    for report in (
        replace(EMPTY, doorcheck_version=version),
        replace(EMPTY, checks=(Check("source", version, Status.COMPLETE),)),
    ):
        assert cli.main(args(tmp_path, report, report)) == 2
        assert json.loads(capsys.readouterr().out)["metadata_matches"] is False


def test_limited_text_retains_both_problems_without_source_scope_claims(
    tmp_path: Path, capsys
) -> None:
    bad = replace(
        EMPTY, checks=(Check("tool", "9", Status.FAILED, (Problem("problem.tool_failed"),)),)
    )
    assert cli.main(args(tmp_path, bad, bad, json_output=False)) == 2
    text = capsys.readouterr().out
    assert render("cli.compare_limited") in text
    assert text.count("Coverage gap at -: The scanner failed.") == 2
    assert text.count("Check version: tool = 9") == 2
    assert render("cli.scope") not in text


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"[]",
        b"{}",
        b"not JSON",
        b"\xff",
        ("[" * 2000).encode(),
        b'{"schema_version":1,"schema_version":1}',
        b'{"target":{"name":"first","name":"second"}}',
        ("1" * 10000).encode(),
    ],
)
def test_malformed_reports_are_errors_without_stdout(tmp_path: Path, capsys, raw) -> None:
    path = tmp_path / "bad.json"
    path.write_bytes(raw)
    assert cli.main(["compare", str(path), str(path), "--json"]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == render("cli.report_invalid", {"path": str(path)}) + "\n"


@pytest.mark.parametrize(
    "change",
    [
        lambda r: r.update(schema_version=2),
        lambda r: r.update(extra="field"),
        lambda r: r["findings"][0].update(fingerprint="forged"),
        lambda r: r["findings"][0].update(message_key="finding.unknown"),
        lambda r: r["findings"][0].update(message_key="finding.tool_reported", params={}),
        lambda r: r.update(
            checks=[
                {
                    "name": "x",
                    "version": "1",
                    "status": "failed",
                    "problems": [{"key": "problem.unknown", "location": None, "params": {}}],
                }
            ]
        ),
    ],
)
@pytest.mark.parametrize("flag", ["--json", "human"])
def test_invalid_schema_and_message_contracts_are_rejected_in_all_formats(
    tmp_path: Path, capsys, change, flag
) -> None:
    raw = to_dict(replace(EMPTY, findings=(FINDING,)))
    change(raw)
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(raw))
    assert cli.main(["compare", str(path), str(path), *([] if flag == "human" else [flag])]) == 2
    out = capsys.readouterr()
    assert out.out == ""
    assert "could not read a supported report" in out.err


@pytest.mark.parametrize("kind", ["absent", "directory", "link", "fifo"])
def test_only_regular_input_files_are_read(tmp_path: Path, capsys, kind) -> None:
    path = tmp_path / "input"
    if kind == "directory":
        path.mkdir()
    elif kind == "link":
        path.symlink_to(save(tmp_path, "report.json", EMPTY))
    elif kind == "fifo":
        os.mkfifo(path)
    assert cli.main(["compare", str(path), str(path)]) == 2
    assert capsys.readouterr().out == ""


def test_report_byte_boundary_and_bounded_read(tmp_path: Path, monkeypatch) -> None:
    assert MAX_REPORT_BYTES == 20 * 1024 * 1024
    path = save(tmp_path, "report.json", EMPTY)
    size = len(path.read_bytes())
    monkeypatch.setattr("doorcheck.cli_compare.MAX_REPORT_BYTES", size)
    from doorcheck.tree import read_regular

    with patch("doorcheck.cli_compare.read_regular", wraps=read_regular) as read:
        assert read_report(path) == EMPTY
    read.assert_called_once_with(path, size + 1)
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(ReportInputError, match=str(path)):
        read_report(path)


def test_after_input_failure_produces_no_partial_output(tmp_path: Path, capsys) -> None:
    before = save(tmp_path, "before.json", EMPTY)
    after = tmp_path / "absent\n\x1b"
    assert cli.main(["compare", str(before), str(after)]) == 2
    out = capsys.readouterr()
    assert out.out == ""
    assert "⟨U+000A⟩⟨U+001B⟩" in out.err
    assert out.err.count("\n") == 1


def test_no_rescanning_execution_or_input_writes(tmp_path: Path, capsys) -> None:
    marker = tmp_path / "executed"
    cap = replace(CAP, subject=f'__import__("pathlib").Path({str(marker)!r}).touch()')
    arguments = args(tmp_path, EMPTY, replace(EMPTY, capabilities=(cap,)))
    snapshots = [(tmp_path / name).read_bytes() for name in ("before.json", "after.json")]
    with (
        patch("doorcheck.cli.scan_folder", side_effect=AssertionError("no rescan")),
        patch("doorcheck.cli.scan_repository", side_effect=AssertionError("no fetch")),
    ):
        assert cli.main(arguments) == 0
    assert not marker.exists()
    assert snapshots == [(tmp_path / name).read_bytes() for name in ("before.json", "after.json")]
    assert json.loads(capsys.readouterr().out)["added"]["capabilities"][0]["subject"] == cap.subject


def test_hostile_report_fields_cannot_add_terminal_rows(tmp_path: Path, capsys) -> None:
    hostile = "\x1b[2J\n\t\u202e"
    report = replace(
        EMPTY,
        doorcheck_version=hostile,
        target=Target(hostile, hostile, hostile, hostile),
        checks=(Check(hostile, hostile, Status.COMPLETE),),
        capabilities=(replace(CAP, subject=hostile),),
    )
    assert cli.main(args(tmp_path, EMPTY, report, json_output=False)) == 2
    text = capsys.readouterr().out
    assert "\x1b" not in text and "\t" not in text and "\u202e" not in text
    assert "⟨U+000A⟩⟨U+0009⟩⟨U+202E⟩" in text
    assert text.count("\n") == 24


@pytest.mark.parametrize(
    "arguments",
    [
        ["compare"],
        ["compare", "one"],
        ["compare", "one", "two", "three"],
        ["compare", "one", "two", "--sarif"],
        ["compare", "one", "two", "--j"],
    ],
)
def test_compare_usage_errors(arguments, capsys) -> None:
    assert cli.main(arguments) == 2
    out = capsys.readouterr()
    assert out.out == ""
    assert out.err == render("cli.invalid_arguments") + "\n"


def test_compare_help(capsys) -> None:
    assert cli.main(["compare", "--help"]) == 0
    assert capsys.readouterr().out == render("cli.help") + "\n"


def test_dash_report_paths(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    save(tmp_path, "-before.json", EMPTY)
    save(tmp_path, "-after.json", EMPTY)
    assert cli.main(["compare", "--json", "--", "-before.json", "-after.json"]) == 0
    assert json.loads(capsys.readouterr().out)["metadata_matches"] is True


@pytest.mark.parametrize("part", ["root", "target", "attributes"])
def test_duplicate_fields_in_otherwise_valid_reports_are_refused(
    tmp_path: Path, capsys, part
) -> None:
    report = replace(EMPTY, capabilities=(replace(CAP, attrs={"x": "1"}),))
    raw = json.dumps(to_dict(report))
    if part == "root":
        raw = '{"schema_version": 1, ' + raw[1:]
    elif part == "target":
        raw = raw.replace('"target": {', '"target": {"name": "demo", ')
    else:
        raw = raw.replace('"attrs": {', '"attrs": {"x": "1", ')
    path = tmp_path / "duplicate.json"
    path.write_text(raw)
    assert cli.main(["compare", str(path), str(path), "--json"]) == 2
    assert capsys.readouterr().out == ""


def test_unchanged_observations_do_not_leak_into_change_arrays(tmp_path: Path, capsys) -> None:
    report = replace(EMPTY, capabilities=(CAP,), findings=(FINDING,))
    assert cli.main(args(tmp_path, report, report)) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["added"] == data["removed"] == {"capabilities": [], "findings": []}
    assert (
        data["before"]["capabilities"]
        == data["after"]["capabilities"]
        == to_dict(report)["capabilities"]
    )
    assert data["before"]["findings"] == data["after"]["findings"] == to_dict(report)["findings"]


def test_valid_message_parameters_are_kept_when_loading(tmp_path: Path) -> None:
    finding = replace(FINDING, message_key="finding.tool_reported", params={"message": "test data"})
    problem = Problem("problem.tool_check_failed", params={"check": "x", "detail": "y"})
    report = replace(
        EMPTY, findings=(finding,), checks=(Check("source", "1", Status.PARTIAL, (problem,)),)
    )
    assert read_report(save(tmp_path, "report.json", report)) == report


def test_version_lines_are_exact_and_show_each_reports_own_values(tmp_path: Path, capsys) -> None:
    after = replace(
        EMPTY,
        doorcheck_version="2",
        target=replace(EMPTY.target, version=""),
        checks=(Check("other", "3", Status.COMPLETE),),
    )
    assert cli.main(args(tmp_path, EMPTY, after, json_output=False)) == 2
    text = capsys.readouterr().out
    assert (
        "Doorcheck report version: 1\nTarget version: v1\nCheck version: source = 1\nTarget: demo\n"
        in text
    )
    assert (
        "Doorcheck report version: 2\nTarget version: \nCheck version: other = 3\nTarget: demo\n"
        in text
    )
    without_version = replace(after, target=Target("demo"))
    assert cli.main(args(tmp_path, without_version, without_version, json_output=False)) == 0
    text = capsys.readouterr().out
    assert "Target version:" not in text
    assert text.count("Doorcheck report version: 2\nCheck version: other = 3\nTarget: demo\n") == 2


def test_utf8_source_text_is_preserved_and_utf16_is_refused(tmp_path: Path, capsys) -> None:
    report = replace(EMPTY, capabilities=(replace(CAP, subject="é"),))
    path = tmp_path / "utf8.json"
    text = json.dumps(to_dict(report), ensure_ascii=False)
    path.write_bytes(text.encode("utf-8"))
    assert read_report(path) == report
    path.write_bytes(text.encode("utf-16"))
    assert cli.main(["compare", str(path), str(path), "--json"]) == 2
    assert capsys.readouterr().out == ""


def test_comparison_interrupt_and_output_failure(tmp_path: Path, capsys) -> None:
    with patch("doorcheck.cli_compare.read_report", side_effect=KeyboardInterrupt):
        assert cli.main(["compare", "before", "after"]) == 130
    out = capsys.readouterr()
    assert out.out == ""
    assert out.err == render("cli.interrupted") + "\n"
    arguments = args(tmp_path)
    with patch("sys.stdout.write", side_effect=BrokenPipeError):
        assert cli.main(arguments) == 2
    assert capsys.readouterr().err == render("cli.output_failed") + "\n"


@pytest.mark.parametrize(
    "arguments",
    [
        ["other", "."],
        ["scan", ".", "--commit", "a" * 40],
        ["scan", "--repo", "owner/demo"],
        ["scan", "--repo", ""],
    ],
)
def test_invalid_routing_arguments_never_start_a_scan(arguments, capsys) -> None:
    with (
        patch(
            "doorcheck.cli.scan_folder", side_effect=AssertionError("invalid input must not scan")
        ),
        patch(
            "doorcheck.cli.scan_repository",
            side_effect=AssertionError("invalid input must not fetch"),
        ),
    ):
        assert cli.main(arguments) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == render("cli.invalid_arguments") + "\n"
