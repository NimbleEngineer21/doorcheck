"""Opt-in CLI scans through the real adapter runner and output renderers."""

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from doorcheck import cli
from doorcheck.adapters.process import OutputLimitError
from doorcheck.adapters.semgrep import Semgrep
from doorcheck.checks import Status
from doorcheck.cli_scan import scan_folder
from doorcheck.fetch.transport import github_opener
from doorcheck.messages import render
from doorcheck.report import from_dict
from tests.conftest import FakeHTTPS, make_zip
from tests.test_cli import SOURCE
from tests.test_cli_repository import ARGS, COMMIT, REPO, URL, archive

pytestmark = pytest.mark.usefixtures("offline")


@pytest.fixture
def rule(tmp_path: Path) -> Path:
    path = tmp_path / "rules.yaml"
    path.write_text("rules: []")
    return path


def output(*, partial: bool = False) -> bytes:
    return json.dumps(
        {
            "errors": [{"type": "Syntax error", "path": "view.py"}] if partial else [],
            "paths": {"scanned": ["view.py"]},
            "results": [
                {
                    "check_id": "operator-rule",
                    "path": "view.py",
                    "start": {"line": 7, "col": 1},
                    "end": {"line": 7},
                    "extra": {
                        "severity": "WARNING",
                        "message": "Review this call\nnot a trusted status",
                        "metadata": {"message_key": "custom.not_in_catalog"},
                    },
                }
            ],
        }
    ).encode()


@pytest.mark.parametrize("format", ["human", "--json", "--sarif"])
@pytest.mark.parametrize("partial", [False, True])
def test_opt_in_preserves_builtins_and_tool_results(
    tmp_path: Path, rule: Path, capsys: pytest.CaptureFixture[str], format: str, partial: bool
) -> None:
    target = tmp_path / "source"
    target.mkdir()
    (target / "view.py").write_text(SOURCE)
    second = tmp_path / "second.yaml"
    second.write_text("rules: []")
    calls = []

    def capture(argv, cwd, env, timeout, limit):
        calls.append((argv, cwd, env, timeout, limit))
        data = Semgrep.version.encode() if "--version" in argv else output(partial=partial)
        return subprocess.CompletedProcess(argv, 0, data, b"")

    with patch("doorcheck.adapters.base.capture", side_effect=capture):
        code = cli.main(
            ["scan", str(target), "--semgrep-rule", str(rule), "--semgrep-rule", str(second)]
            + ([] if format == "human" else [format])
        )
    assert code == (2 if partial else 1)
    assert len(calls) == 2
    argv, cwd, env, timeout, limit = calls[1]
    assert argv[:6] == ("semgrep", "scan", "--config", str(rule), "--config", str(second))
    assert cwd == target
    assert timeout == 300 and limit == 20 * 1024 * 1024
    assert "--metrics=off" in argv and "--disable-nosem" in argv
    assert argv[-2:] == ("--", "view.py")
    assert env["HOME"] != str(target) and env["NO_COLOR"] == "1"
    displayed = capsys.readouterr()
    assert displayed.err == ""
    if format == "--json":
        report = from_dict(json.loads(displayed.out))
        assert [c.name for c in report.checks] == ["capabilities", "python-rules", "semgrep"]
        assert report.checks[-1].version == Semgrep.version
        assert report.checks[-1].status is (Status.PARTIAL if partial else Status.COMPLETE)
        assert len(report.capabilities) > 0
        assert [f.tool for f in report.findings] == ["doorcheck", "semgrep"]
        finding = report.findings[1]
        assert finding.message_key == "finding.tool_reported"
        assert finding.params == {"message": "Review this call\nnot a trusted status"}
        assert finding.evidence == "return web.FileResponse(filename)"
    elif format == "--sarif":
        run = json.loads(displayed.out)["runs"][0]
        assert {r["ruleId"] for r in run["results"]} == {
            "ha-unauth-view-unsanitized-path",
            "operator-rule",
        }
        assert bool(run["invocations"][0]["toolExecutionNotifications"]) is partial
    else:
        assert (
            "semgrep: " + render(f"status.{'partial' if partial else 'complete'}") in displayed.out
        )
        assert "operator-rule" in displayed.out
        assert "Review this call⟨U+000A⟩not a trusted status" in displayed.out
        assert displayed.out.endswith(render("cli.scope") + "\n")


@pytest.mark.parametrize(
    "failure,key",
    [
        (FileNotFoundError(), "problem.tool_not_installed"),
        (subprocess.TimeoutExpired("semgrep", 300), "problem.tool_timed_out"),
        (OutputLimitError(), "problem.tool_output_too_large"),
        (b"0.0.0", "problem.tool_wrong_version"),
        (b"not json", "problem.tool_output_not_understood"),
        (b"{}", "problem.tool_output_not_understood"),
        (b"exit", "problem.tool_failed"),
    ],
)
def test_tool_failures_retain_source_results(
    tmp_path: Path, rule: Path, failure: object, key: str, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "view.py").write_text(SOURCE)

    def capture(argv, *args):
        if isinstance(failure, BaseException):
            raise failure
        if failure == b"0.0.0":
            return subprocess.CompletedProcess(argv, 0, failure, b"")
        data = Semgrep.version.encode() if "--version" in argv else failure
        return subprocess.CompletedProcess(argv, 1 if data == b"exit" else 0, data, b"detail")

    with patch("doorcheck.adapters.base.capture", side_effect=capture):
        assert cli.main(["scan", str(tmp_path), "--semgrep-rule", str(rule), "--json"]) == 2
    report = from_dict(json.loads(capsys.readouterr().out))
    assert len(report.findings) == 1
    assert report.findings[0].tool == "doorcheck"
    assert len(report.capabilities) > 0
    check = report.checks[-1]
    assert (check.name, check.status, check.problems[0].key) == ("semgrep", Status.FAILED, key)


@pytest.mark.parametrize("kind", ["missing", "directory", "symlink", "fifo"])
def test_invalid_rule_refused_before_fetch(
    tmp_path: Path, kind: str, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "rule"
    if kind == "directory":
        path.mkdir()
    elif kind == "symlink":
        real = tmp_path / "real"
        real.write_text("rules: []")
        path.symlink_to(real)
    elif kind == "fifo":
        import os

        os.mkfifo(path)
    with patch("doorcheck.cli.scan_repository", side_effect=AssertionError("must not fetch")):
        assert cli.main([*ARGS, "--semgrep-rule", str(path)]) == 2
    displayed = capsys.readouterr()
    assert displayed.out == ""
    assert displayed.err == render("cli.invalid_arguments") + "\n"


def test_relative_rule_uses_invocation_directory(
    tmp_path: Path, rule: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "source"
    target.mkdir()
    with patch("doorcheck.cli_scan.run") as run:
        from doorcheck.adapters.base import ToolRun
        from doorcheck.checks import Check

        run.return_value = ToolRun(Check("semgrep", Semgrep.version, Status.NOTHING_TO_SCAN))
        assert cli.main(["scan", "source", "--semgrep-rule", rule.name]) == 0
    adapter, scan = run.call_args.args
    assert adapter.rules == (rule,)
    assert scan.root == Path("source")
    assert scan.dependencies.pins == ()


def test_default_and_invalid_target_do_not_execute(tmp_path: Path, rule: Path) -> None:
    with patch("doorcheck.cli_scan.run", side_effect=AssertionError("must not run")):
        assert len(scan_folder(tmp_path).checks) == 2
        report = scan_folder(tmp_path / "missing", semgrep_rules=(rule,))
    assert [c.name for c in report.checks] == ["local-target"]


@pytest.mark.parametrize("mode", ["commit", "tag", "asset"])
def test_remote_scans_tool_before_snapshot_cleanup(
    mode: str, rule: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    tag_url = f"https://github.com/{REPO}/archive/refs/tags/v1.zip"
    release_api = f"https://api.github.com/repos/{REPO}/releases/tags/v1"
    asset_url = f"https://github.com/{REPO}/releases/download/v1/demo.zip"
    hacs = '{"zip_release": true, "filename": "demo.zip"}' if mode == "asset" else "{}"
    pages = {URL: archive(), tag_url: archive(hacs=hacs)}
    pages[release_api] = json.dumps(
        {"assets": [{"name": "demo.zip", "browser_download_url": asset_url}]}
    ).encode()
    pages[asset_url] = make_zip({"view.py": SOURCE})
    roots = []

    def capture(argv, cwd, env, timeout, limit):
        if "--version" in argv:
            return subprocess.CompletedProcess(argv, 0, Semgrep.version.encode(), b"")
        assert (cwd / "view.py").read_text() == SOURCE
        assert str(rule) in argv
        roots.append(cwd)
        return subprocess.CompletedProcess(argv, 0, output(), b"")

    args = ARGS if mode == "commit" else ["scan", "--repo", REPO, "--tag", "v1"]
    with (
        patch(
            "doorcheck.fetch.transport.github_opener", return_value=github_opener(FakeHTTPS(pages))
        ),
        patch("doorcheck.adapters.base.capture", side_effect=capture),
    ):
        assert cli.main([*args, "--semgrep-rule", str(rule), "--json"]) == 1
    report = from_dict(json.loads(capsys.readouterr().out))
    assert report.target.name == REPO
    assert report.target.commit == COMMIT
    assert report.target.artifact_sha256
    assert [c.name for c in report.checks] == ["capabilities", "fetch", "python-rules", "semgrep"]
    assert len(report.findings) == 2
    assert len(roots) == 1 and not roots[0].parent.exists()
