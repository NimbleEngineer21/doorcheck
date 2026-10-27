"""Local CLI contracts, real source scans and hostile terminal fields."""

import importlib.metadata
import json
import runpy
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from doorcheck import cli
from doorcheck.capabilities.model import Capability, Kind
from doorcheck.checks import Check, Problem, Status
from doorcheck.cli_output import human
from doorcheck.cli_scan import exit_code, scan_folder
from doorcheck.findings import Confidence, Finding, Location, Severity
from doorcheck.messages import render
from doorcheck.report import Report, Target, from_dict

SOURCE = """from homeassistant.components.http import HomeAssistantView
from aiohttp import web
class Files(HomeAssistantView):
    requires_auth = False
    url = '/files/{filename:.*}'
    async def get(self, request, filename):
        return web.FileResponse(filename)
"""


def test_scan_folder_real_results(tmp_path: Path) -> None:
    (tmp_path / "view.py").write_text(SOURCE)
    report = scan_folder(tmp_path)
    assert report.doorcheck_version == importlib.metadata.version("doorcheck")
    assert report.target == Target(str(tmp_path))
    assert [c.name for c in report.checks] == ["capabilities", "python-rules"]
    assert all(
        c.version == report.doorcheck_version and c.status is Status.COMPLETE for c in report.checks
    )
    assert len(report.capabilities) > 0
    assert len(report.findings) == 1
    assert report.findings[0].location == Location("view.py", 7)
    assert exit_code(report) == 1


@pytest.mark.parametrize("kind", ["missing", "file", "link", "broken-link"])
def test_invalid_root_report(tmp_path: Path, kind: str) -> None:
    root = tmp_path / "target"
    if kind == "file":
        root.write_text("pass")
    elif kind == "link":
        root.symlink_to(tmp_path, target_is_directory=True)
    elif kind == "broken-link":
        root.symlink_to(tmp_path / "absent")
    report = scan_folder(root)
    assert report.target.name == str(root)
    assert report.checks == (
        Check(
            "local-target",
            report.doorcheck_version,
            Status.FAILED,
            (Problem("problem.target_not_directory"),),
        ),
    )
    assert report.capabilities == report.findings == ()
    assert exit_code(report) == 2


def test_partial_both_checks_and_findings(tmp_path: Path) -> None:
    (tmp_path / "view.py").write_text(SOURCE)
    (tmp_path / "broken.py").write_text("def broken(:")
    report = scan_folder(tmp_path)
    assert len(report.findings) == 1
    for check in report.checks:
        assert check.status is Status.PARTIAL
        assert len(check.problems) == 1
        assert check.problems[0].key == "problem.file_not_parsed"
        assert check.problems[0].location == Location("broken.py", 1)
    assert exit_code(report) == 2


def test_empty_folder(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["scan", str(tmp_path)]) == 0
    output = capsys.readouterr()
    assert output.err == ""
    assert output.out == "\n".join(
        [
            f"Target: {tmp_path}",
            "capabilities: Scan complete",
            "python-rules: Scan complete",
            "0 finding(s); 0 source observation(s).",
            render("cli.scope"),
            "",
        ]
    )


@pytest.mark.parametrize("args", [[], ["--help"], ["scan", "--help"]])
def test_help(args: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(args) == 0
    assert capsys.readouterr().out == render("cli.help") + "\n"


@pytest.mark.parametrize(
    "args",
    [
        ["scan"],
        ["other", "."],
        ["scan", ".", "--j"],
        ["scan", ".", "--json", "--sarif"],
        ["scan", ".", "extra"],
        ["scan", "--unknown", "."],
        ["--help", "extra"],
    ],
)
def test_usage_errors(args: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(args) == 2
    out = capsys.readouterr()
    assert out.out == ""
    assert out.err == render("cli.invalid_arguments") + "\n"


@pytest.mark.parametrize("flag", ["--json", "--sarif", "human"])
def test_cli_formats(tmp_path: Path, capsys: pytest.CaptureFixture[str], flag: str) -> None:
    (tmp_path / "view.py").write_text(SOURCE)
    args = ["scan", str(tmp_path)] + ([] if flag == "human" else [flag])
    assert cli.main(args) == 1
    output = capsys.readouterr()
    assert output.err == ""
    assert output.out.endswith("\n")
    if flag == "--json":
        report = from_dict(json.loads(output.out))
        assert len(report.findings) == 1
        assert report.target.name == str(tmp_path)
    elif flag == "--sarif":
        data = json.loads(output.out)
        assert data["version"] == "2.1.0"
        assert data["runs"][0]["results"][0]["ruleId"] == "ha-unauth-view-unsanitized-path"
        assert data["runs"][0]["invocations"][0]["executionSuccessful"] is True
    else:
        assert "Review at view.py:7 [ha-unauth-view-unsanitized-path]" in output.out
        assert "Observation at view.py:" in output.out
        assert output.out.endswith(render("cli.scope") + "\n")


def test_actual_arguments_and_module(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    with (
        patch("sys.argv", ["doorcheck", "scan", str(tmp_path), "--json"]),
        pytest.raises(SystemExit) as exc,
    ):
        runpy.run_path("src/doorcheck/__main__.py", run_name="__main__")
    assert exc.value.code == 0
    assert from_dict(json.loads(capsys.readouterr().out)).target.name == str(tmp_path)


@pytest.mark.parametrize(
    "exception,code,key",
    [
        (KeyboardInterrupt, 130, "cli.interrupted"),
        (OSError, 2, "cli.output_failed"),
    ],
)
def test_scan_errors(
    exception: type[BaseException], code: int, key: str, capsys: pytest.CaptureFixture[str]
) -> None:
    with patch("doorcheck.cli.scan_folder", side_effect=exception):
        assert cli.main(["scan", "."]) == code
    output = capsys.readouterr()
    assert output.err == render(key) + "\n"
    assert output.out == ""


def test_output_failure(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    with patch("sys.stdout.write", side_effect=BrokenPipeError):
        assert cli.main(["scan", str(tmp_path)]) == 2
    assert capsys.readouterr().err == render("cli.output_failed") + "\n"


def test_dash_folder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "-folder"
    root.mkdir()
    monkeypatch.chdir(tmp_path)
    assert cli.main(["scan", "--json", "--", "-folder"]) == 0
    assert from_dict(json.loads(capsys.readouterr().out)).target.name == "-folder"


def report_with(*, severity: Severity = Severity.INFO, status: Status = Status.COMPLETE) -> Report:
    problems = (
        (Problem("problem.tool_failed"),) if status in (Status.PARTIAL, Status.FAILED) else ()
    )
    finding = Finding(
        "sample",
        severity,
        Confidence.MEDIUM,
        Location("sample.py", 2),
        "finding.tool_reported",
        tool="doorcheck",
        params={"message": "sample"},
    )
    return Report("1", Target("sample"), (Check("source", "1", status, problems),), (), (finding,))


@pytest.mark.parametrize(
    "severity,expected",
    [(Severity.INFO, 0), (Severity.NOTICE, 0), (Severity.REVIEW, 1), (Severity.SERIOUS, 1)],
)
def test_exit_severity(severity: Severity, expected: int) -> None:
    assert exit_code(report_with(severity=severity)) == expected


@pytest.mark.parametrize("status", [Status.PARTIAL, Status.FAILED])
def test_exit_gap_precedence(status: Status) -> None:
    assert exit_code(report_with(severity=Severity.SERIOUS, status=status)) == 2


def test_terminal_hostile_fields() -> None:
    hostile = "\x1b[2J\r\n\t\u202e"
    report = Report(
        "1",
        Target(hostile),
        (
            Check(
                "source",
                "1",
                Status.PARTIAL,
                (
                    Problem(
                        "problem.tool_check_failed",
                        Location("p" + hostile + ".py", 2),
                        {"check": hostile, "detail": hostile},
                    ),
                    Problem("problem.tool_failed"),
                ),
            ),
        ),
        (Capability(Kind.NETWORK_HOST, Location("host.py", 3), hostile),),
        (
            Finding(
                "sample",
                Severity.REVIEW,
                Confidence.MEDIUM,
                Location("f.py", 4),
                "finding.tool_reported",
                tool="doorcheck",
                params={"message": hostile},
            ),
        ),
    )
    output = human(report)
    assert (
        "\x1b" not in output
        and "\r" not in output
        and "\t" not in output
        and "\u202e" not in output
    )
    assert "⟨U+001B⟩[2J⟨U+000D⟩⟨U+000A⟩⟨U+0009⟩⟨U+202E⟩" in output
    assert output.count("\n") == 8
    assert "Coverage gap at -: The scanner failed." in output
    assert "Coverage gap at p⟨U+001B⟩[2J⟨U+000D⟩⟨U+000A⟩⟨U+0009⟩⟨U+202E⟩.py:2:" in output
    assert "Review at f.py:4 [sample]: The scanner reported:" in output
    assert "Observation at host.py:3: Names a network host:" in output


def test_json_keeps_data_but_escapes_terminal_controls(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "folder\x1b\u202e"
    root.mkdir()
    assert cli.main(["scan", str(root), "--json"]) == 0
    output = capsys.readouterr().out
    assert "\x1b" not in output and "\u202e" not in output
    assert from_dict(json.loads(output)).target.name == str(root)


def test_partial_sarif_notifications(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / "invalid.py").write_text("def broken(:")
    assert cli.main(["scan", str(tmp_path), "--sarif"]) == 2
    inv = json.loads(capsys.readouterr().out)["runs"][0]["invocations"][0]
    assert len(inv["toolExecutionNotifications"]) == 2
    assert all(
        n["properties"]["key"] == "problem.file_not_parsed"
        for n in inv["toolExecutionNotifications"]
    )


def test_unsupported_source_path_is_a_gap(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "bad\\name.py").write_text("import os")
    assert cli.main(["scan", str(tmp_path), "--json"]) == 2
    report = from_dict(json.loads(capsys.readouterr().out))
    assert report.capabilities == report.findings == ()
    assert len(report.checks) == 2
    assert all(
        check.problems
        == (Problem("problem.file_path_not_supported", params={"path": "bad\\name.py"}),)
        for check in report.checks
    )


def test_source_is_not_executed(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    marker = tmp_path / "executed"
    (tmp_path / "source.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).touch()\n"
        'raise RuntimeError("do not execute")\n'
    )
    assert cli.main(["scan", str(tmp_path)]) == 0
    assert not marker.exists()
    assert capsys.readouterr().err == ""


def test_local_command_does_not_fetch_urls(capsys: pytest.CaptureFixture[str]) -> None:
    with patch("urllib.request.urlopen", side_effect=AssertionError("must stay offline")):
        assert cli.main(["scan", "https://example.invalid/repo", "--json"]) == 2
    report = from_dict(json.loads(capsys.readouterr().out))
    assert report.checks[0].problems[0].key == "problem.target_not_directory"


@pytest.mark.parametrize(
    "exception", [BrokenPipeError, UnicodeEncodeError("ascii", "\u202e", 0, 1, "encoding")]
)
def test_shutdown_flush_failures(exception, capsys: pytest.CaptureFixture[str]) -> None:
    with (
        patch("doorcheck.cli.main", return_value=1),
        patch("sys.stdout.flush", side_effect=exception),
        patch("sys.stdout") as output,
        pytest.raises(SystemExit) as exc,
    ):
        output.flush.side_effect = exception
        try:
            cli.entrypoint()
        finally:
            assert sys.stdout is None
    assert exc.value.code == 2
    assert capsys.readouterr().err == render("cli.output_failed") + "\n"


def test_unencodable_stdout(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    error = UnicodeEncodeError("ascii", "\u202e", 0, 1, "encoding")
    with patch("sys.stdout.write", side_effect=error):
        assert cli.main(["scan", str(tmp_path)]) == 2
    assert capsys.readouterr().err == render("cli.output_failed") + "\n"
