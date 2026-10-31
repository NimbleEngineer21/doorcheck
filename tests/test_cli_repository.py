"""Pinned remote command contracts through real fetching, extraction and scans."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from doorcheck import cli
from doorcheck.checks import Check, Problem, Status
from doorcheck.cli_scan import exit_code, scan_repository
from doorcheck.fetch import FetchError, tree_digest
from doorcheck.fetch.transport import github_opener
from doorcheck.messages import render
from doorcheck.report import from_dict
from tests.conftest import FakeHTTPS, make_zip
from tests.test_cli import SOURCE

COMMIT = "0123456789abcdef0123456789abcdef01234567"
REPO = "owner/demo"
URL = f"https://github.com/{REPO}/archive/{COMMIT}.zip"
ARGS = ["scan", "--repo", REPO, "--commit", COMMIT]
pytestmark = pytest.mark.usefixtures("offline")


def archive(source: str = SOURCE, *, hacs: str = "{}", comment: str = COMMIT) -> bytes:
    return make_zip(
        {
            "demo/custom_components/demo/view.py": source,
            "demo/custom_components/demo/manifest.json": '{"domain": "demo"}',
            "demo/ignored.py": "def broken(:",
            "demo/hacs.json": hacs,
        },
        comment=comment.encode(),
    )


@pytest.mark.parametrize("flag", ["--json", "--sarif", "human"])
def test_remote_formats_and_provenance(flag: str, capsys: pytest.CaptureFixture[str]) -> None:
    # The default getter is bound in from_commit, so intercept its transport instead.
    handler = FakeHTTPS({URL: archive()})
    with patch("doorcheck.fetch.transport.github_opener", return_value=github_opener(handler)):
        assert cli.main(ARGS + ([] if flag == "human" else [flag])) == 1
    output = capsys.readouterr()
    assert output.err == ""
    if flag == "--json":
        report = from_dict(json.loads(output.out))
        assert report.target.name == REPO
        assert report.target.version is None
        assert report.target.commit == COMMIT
        assert len(report.target.artifact_sha256) == 64
        assert [c.name for c in report.checks] == ["capabilities", "fetch", "python-rules"]
        assert all(c.status is Status.COMPLETE for c in report.checks)
        assert len(report.findings) == 1
        assert report.findings[0].location.path == "view.py"
        assert report.findings[0].location.line == 7
    elif flag == "--sarif":
        data = json.loads(output.out)["runs"][0]
        assert data["invocations"][0]["executionSuccessful"] is True
        assert (
            data["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            == "view.py"
        )
        assert data["invocations"][0]["toolExecutionNotifications"] == []
    else:
        assert output.out.startswith(f"Target: {REPO}\nCommit: {COMMIT}\nInstalled files SHA-256: ")
        assert "fetch: Scan complete\n" in output.out
        assert "Review at view.py:7" in output.out


@pytest.mark.parametrize(
    "args",
    [
        ["scan", "--repo", REPO],
        ["scan", "--commit", COMMIT],
        ["scan", ".", "--commit", COMMIT],
        ["scan", ".", "--repo", REPO, "--commit", COMMIT],
        ["scan", "--repo", "", "--commit", COMMIT],
    ],
)
def test_ambiguous_targets_do_not_fetch(
    args: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    with (
        patch(
            "doorcheck.cli.scan_folder", side_effect=AssertionError("invalid input must not scan")
        ),
        patch(
            "doorcheck.cli.scan_repository",
            side_effect=AssertionError("invalid input must not fetch"),
        ),
    ):
        assert cli.main(args) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == render("cli.invalid_arguments") + "\n"


@pytest.mark.parametrize(
    "repo,commit",
    [
        ("https://github.com/owner/demo", COMMIT),
        ("owner/../demo", COMMIT),
        (REPO, "main"),
        (REPO, "abc"),
        (REPO, COMMIT.upper()),
        (REPO, ""),
    ],
)
def test_invalid_pins_do_not_download(repo: str, commit: str) -> None:
    report = scan_repository(repo, commit)
    assert exit_code(report) == 2
    assert report.target.name == repo
    assert report.target.commit is None
    assert report.checks == (
        Check("fetch", report.doorcheck_version, Status.FAILED, (Problem("problem.fetch_failed"),)),
    )
    assert report.capabilities == report.findings == ()


@pytest.mark.parametrize(
    "data,key",
    [
        (b"not a zip", "problem.unsafe_archive"),
        (archive(comment="f" * 40), "problem.fetch_failed"),
        (archive(hacs='{"zip_release": true, "filename": "demo.zip"}'), "problem.fetch_failed"),
        (make_zip({"demo/../escape.py": "x"}, comment=COMMIT.encode()), "problem.unsafe_archive"),
    ],
)
def test_failed_fetch_has_no_source_results(
    data: bytes, key: str, capsys: pytest.CaptureFixture[str]
) -> None:
    handler = FakeHTTPS({URL: data})
    with patch("doorcheck.fetch.transport.github_opener", return_value=github_opener(handler)):
        assert cli.main([*ARGS, "--json"]) == 2
    report = from_dict(json.loads(capsys.readouterr().out))
    assert report.target.name == REPO
    assert report.target.commit is report.target.artifact_sha256 is None
    assert report.checks[0].problems == (Problem(key),)
    assert report.capabilities == report.findings == ()


def test_snapshot_digest_cleanup_and_no_execution(tmp_path: Path) -> None:
    marker = tmp_path / "executed"
    source = f"from pathlib import Path\nPath({str(marker)!r}).touch()\n"
    handler = FakeHTTPS({URL: archive(source)})
    from doorcheck.cli_scan import scan_folder

    snapshots = []

    def inspect(root: Path, *, semgrep_rules: tuple[Path, ...]):
        snapshots.append(root)
        assert root.is_dir()
        report = scan_folder(root)
        assert report.findings == ()
        assert sorted(p.name for p in root.iterdir()) == ["manifest.json", "view.py"]
        snapshots.append(tree_digest(root))
        return report

    with (
        patch("doorcheck.fetch.transport.github_opener", return_value=github_opener(handler)),
        patch("doorcheck.cli_scan.scan_folder", side_effect=inspect),
    ):
        report = scan_repository(REPO, COMMIT)
    assert report.target.artifact_sha256 == snapshots[1]
    assert not snapshots[0].parent.exists()
    assert not marker.exists()
    assert exit_code(report) == 0


@pytest.mark.parametrize(
    "failure", [FetchError("secret detail", "problem.download_refused"), OSError("private path")]
)
def test_fetch_errors_are_keyed_and_do_not_leak_details(failure: Exception) -> None:
    with patch("doorcheck.cli_scan.from_commit", side_effect=failure):
        report = scan_repository(REPO, COMMIT)
    key = "problem.download_refused" if isinstance(failure, FetchError) else "problem.fetch_failed"
    assert report.checks == (
        Check("fetch", report.doorcheck_version, Status.FAILED, (Problem(key),)),
    )
    assert exit_code(report) == 2


def test_remote_parse_gap_takes_precedence() -> None:
    handler = FakeHTTPS({URL: archive(SOURCE + "\ndef broken(:")})
    with patch("doorcheck.fetch.transport.github_opener", return_value=github_opener(handler)):
        report = scan_repository(REPO, COMMIT)
    assert report.target.commit == COMMIT
    assert report.checks[1].status is Status.COMPLETE
    assert report.checks[0].status is report.checks[2].status is Status.PARTIAL
    assert exit_code(report) == 2


@pytest.mark.parametrize("failure", [KeyboardInterrupt, OSError])
def test_snapshot_removed_when_scan_stops(failure: type[BaseException]) -> None:
    handler = FakeHTTPS({URL: archive()})
    roots = []

    def stop(root: Path, *, semgrep_rules: tuple[Path, ...]):
        roots.append(root)
        raise failure

    with (
        patch("doorcheck.fetch.transport.github_opener", return_value=github_opener(handler)),
        patch("doorcheck.cli_scan.scan_folder", side_effect=stop),
    ):
        if failure is KeyboardInterrupt:
            with pytest.raises(KeyboardInterrupt):
                scan_repository(REPO, COMMIT)
        else:
            assert exit_code(scan_repository(REPO, COMMIT)) == 2
    assert len(roots) == 1
    assert not roots[0].parent.exists()


@pytest.mark.parametrize("flag", ["--sarif", "human"])
def test_failed_fetch_outputs(flag: str, capsys: pytest.CaptureFixture[str]) -> None:
    with patch("doorcheck.cli_scan.from_commit", side_effect=FetchError("private detail")):
        assert cli.main(ARGS + ([] if flag == "human" else [flag])) == 2
    output = capsys.readouterr()
    assert output.err == ""
    assert "private detail" not in output.out
    if flag == "--sarif":
        run = json.loads(output.out)["runs"][0]
        assert run["results"] == []
        assert run["invocations"][0]["executionSuccessful"] is False
        notice = run["invocations"][0]["toolExecutionNotifications"]
        assert len(notice) == 1
        assert notice[0]["properties"]["key"] == "problem.fetch_failed"
    else:
        assert "fetch: Scan failed" in output.out
        assert "Doorcheck could not retrieve the files to scan." in output.out


def test_content_in_root_is_scanned() -> None:
    data = make_zip(
        {"demo/hacs.json": '{"content_in_root": true}', "demo/view.py": SOURCE},
        comment=COMMIT.encode(),
    )
    handler = FakeHTTPS({URL: data})
    with patch("doorcheck.fetch.transport.github_opener", return_value=github_opener(handler)):
        report = scan_repository(REPO, COMMIT)
    assert report.findings[0].location.path == "view.py"
    assert exit_code(report) == 1


def test_remote_findings_survive_a_neighbor_gap() -> None:
    data = make_zip(
        {
            "demo/custom_components/demo/view.py": SOURCE,
            "demo/custom_components/demo/broken.py": "def broken(:",
        },
        comment=COMMIT.encode(),
    )
    handler = FakeHTTPS({URL: data})
    with patch("doorcheck.fetch.transport.github_opener", return_value=github_opener(handler)):
        report = scan_repository(REPO, COMMIT)
    assert len(report.findings) == 1
    assert report.findings[0].location.path == "view.py"
    assert report.checks[1].status is Status.COMPLETE
    assert report.checks[0].status is report.checks[2].status is Status.PARTIAL
    assert exit_code(report) == 2


def test_provenance_terminal_controls_are_escaped() -> None:
    from doorcheck.cli_output import human
    from doorcheck.report import Report, Target

    hostile = "\x1b[2J\n\t\u202e"
    text = human(Report("1", Target("repo", commit=hostile, artifact_sha256=hostile), (), (), ()))
    assert "\x1b" not in text and "\t" not in text and "\u202e" not in text
    assert text.count("\n") == 5
    assert "Commit: ⟨U+001B⟩[2J⟨U+000A⟩⟨U+0009⟩⟨U+202E⟩\n" in text
    assert "Installed files SHA-256: ⟨U+001B⟩[2J⟨U+000A⟩⟨U+0009⟩⟨U+202E⟩\n" in text
