"""Tagged integration scans through bounded fetching and actual file selection."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from doorcheck import cli
from doorcheck.checks import Check, Problem, Status
from doorcheck.cli_scan import exit_code, scan_release
from doorcheck.fetch import FetchError, tree_digest
from doorcheck.fetch.transport import github_opener
from doorcheck.messages import render
from doorcheck.report import from_dict
from tests.conftest import FakeHTTPS, make_zip
from tests.test_cli import SOURCE
from tests.test_cli_repository import COMMIT, REPO, archive

TAG = "v1.2.0"
URL = f"https://github.com/{REPO}/archive/refs/tags/{TAG}.zip"
ASSET = f"https://github.com/{REPO}/releases/download/{TAG}/demo.zip"
ARGS = ["scan", "--repo", REPO, "--tag", TAG]
pytestmark = pytest.mark.usefixtures("offline")


@pytest.mark.parametrize("flag", ["--json", "--sarif", "human"])
def test_tagged_source_formats(flag: str, capsys: pytest.CaptureFixture[str]) -> None:
    handler = FakeHTTPS({URL: archive()})
    with patch("doorcheck.fetch.transport.github_opener", return_value=github_opener(handler)):
        assert cli.main(ARGS + ([] if flag == "human" else [flag])) == 1
    output = capsys.readouterr()
    assert output.err == ""
    if flag == "--json":
        report = from_dict(json.loads(output.out))
        assert report.target.name == REPO
        assert report.target.version == TAG
        assert report.target.commit == COMMIT
        assert len(report.target.artifact_sha256) == 64
        assert [c.name for c in report.checks] == ["capabilities", "fetch", "python-rules"]
        assert all(c.status is Status.COMPLETE for c in report.checks)
        assert len(report.findings) == 1
        assert report.findings[0].location.path == "view.py"
        assert report.findings[0].location.line == 7
    elif flag == "--sarif":
        run = json.loads(output.out)["runs"][0]
        assert run["invocations"][0]["executionSuccessful"] is True
        assert run["results"][0]["ruleId"] == "ha-unauth-view-unsanitized-path"
        assert run["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 7
    else:
        assert output.out.startswith(f"Target: {REPO}\nVersion: {TAG}\nCommit: {COMMIT}\n")
        assert "Installed files SHA-256: " in output.out
        assert "fetch: Scan complete\n" in output.out
        assert "Review at view.py:7" in output.out


@pytest.mark.parametrize(
    "args",
    [
        ["scan", "--tag", TAG],
        ["scan", ".", "--tag", TAG],
        ["scan", "--repo", REPO],
        ["scan", "--repo", REPO, "--tag", TAG, "--commit", COMMIT],
        ["scan", ".", "--repo", REPO, "--tag", TAG],
        ["scan", "--repo", "", "--tag", TAG],
        ["scan", "--repo", REPO, "--tag", TAG, "--json", "--sarif"],
    ],
)
def test_invalid_target_combinations_do_not_scan(args: list[str], capsys) -> None:
    with (
        patch("doorcheck.cli.scan_release", side_effect=AssertionError("must not fetch")),
        patch("doorcheck.cli.scan_repository", side_effect=AssertionError("must not fetch")),
        patch("doorcheck.cli.scan_folder", side_effect=AssertionError("must not scan")),
    ):
        assert cli.main(args) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == render("cli.invalid_arguments") + "\n"


@pytest.mark.parametrize("tag", ["", "../bad", "a..b", "-v1", "v1\nother", "v1?token=x", "v1#x"])
def test_invalid_tags_do_not_download(tag: str) -> None:
    report = scan_release(REPO, tag)
    assert report.target.name == REPO
    assert report.target.version is report.target.commit is report.target.artifact_sha256 is None
    assert report.checks == (
        Check("fetch", report.doorcheck_version, Status.FAILED, (Problem("problem.fetch_failed"),)),
    )
    assert report.capabilities == report.findings == ()
    assert exit_code(report) == 2


@pytest.mark.parametrize("tag", ["release/1.2.0", "v1.2.0+build"])
def test_explicit_tag_encoding(tag: str) -> None:
    from urllib.parse import quote

    url = f"https://github.com/{REPO}/archive/refs/tags/{quote(tag)}.zip"
    handler = FakeHTTPS({url: archive("pass")})
    with patch("doorcheck.fetch.transport.github_opener", return_value=github_opener(handler)):
        report = scan_release(REPO, tag)
    assert report.target.version == tag
    assert report.target.commit == COMMIT
    assert exit_code(report) == 0


def test_named_release_asset_is_scanned_instead_of_tagged_source(tmp_path: Path) -> None:
    marker = tmp_path / "executed"
    asset_source = f"from pathlib import Path\nPath({str(marker)!r}).touch()\n" + SOURCE
    release = make_zip({"shipped.py": asset_source, "manifest.json": '{"version":"9"}'})
    handler = FakeHTTPS(
        {
            URL: archive("def broken(:", hacs='{"zip_release":true,"filename":"demo.zip"}'),
            ASSET: release,
        }
    )
    roots = []
    from doorcheck.cli_scan import scan_folder

    def inspect(root: Path, *, semgrep_rules: tuple[Path, ...]):
        roots.append(root)
        assert sorted(p.name for p in root.iterdir()) == ["manifest.json", "shipped.py"]
        roots.append(tree_digest(root))
        return scan_folder(root)

    with (
        patch("doorcheck.fetch.transport.github_opener", return_value=github_opener(handler)),
        patch("doorcheck.cli_scan.scan_folder", side_effect=inspect),
    ):
        report = scan_release(REPO, TAG)
    assert report.target.version == TAG
    assert report.target.commit == COMMIT
    assert report.target.artifact_sha256 == roots[1]
    assert all(c.status is Status.COMPLETE for c in report.checks)
    assert report.findings[0].location.path == "shipped.py"
    assert report.findings[0].location.line == 9
    assert exit_code(report) == 1
    assert not roots[0].parent.exists()
    assert not marker.exists()


@pytest.mark.parametrize(
    "payload,key",
    [
        (b"not a zip", "problem.unsafe_archive"),
        (make_zip({"../escape.py": "pass"}), "problem.unsafe_archive"),
    ],
)
def test_unsafe_release_does_not_fall_back_to_source(payload: bytes, key: str) -> None:
    handler = FakeHTTPS(
        {
            URL: archive(hacs='{"zip_release":true,"filename":"demo.zip"}'),
            ASSET: payload,
        }
    )
    with patch("doorcheck.fetch.transport.github_opener", return_value=github_opener(handler)):
        report = scan_release(REPO, TAG)
    assert report.capabilities == report.findings == ()
    assert report.checks == (
        Check("fetch", report.doorcheck_version, Status.FAILED, (Problem(key),)),
    )
    assert report.target.version is report.target.commit is report.target.artifact_sha256 is None
    assert exit_code(report) == 2


@pytest.mark.parametrize(
    "failure", [FetchError("private detail", "problem.download_refused"), OSError("private path")]
)
@pytest.mark.parametrize("flag", ["--json", "--sarif", "human"])
def test_keyed_fetch_failures(failure: Exception, flag: str, capsys) -> None:
    with patch("doorcheck.cli_scan.from_repo", side_effect=failure):
        assert cli.main(ARGS + ([] if flag == "human" else [flag])) == 2
    output = capsys.readouterr()
    assert output.err == "" and "private" not in output.out
    key = "problem.download_refused" if isinstance(failure, FetchError) else "problem.fetch_failed"
    if flag == "--json":
        report = from_dict(json.loads(output.out))
        assert report.checks[0].problems == (Problem(key),)
        assert (
            report.target.version is report.target.commit is report.target.artifact_sha256 is None
        )
    elif flag == "--sarif":
        run = json.loads(output.out)["runs"][0]
        assert run["invocations"][0]["executionSuccessful"] is False
        assert run["invocations"][0]["toolExecutionNotifications"][0]["properties"]["key"] == key
    else:
        assert render(key) in output.out


@pytest.mark.parametrize("failure", [KeyboardInterrupt, OSError])
def test_temporary_snapshot_is_removed_when_scan_stops(failure: type[BaseException]) -> None:
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
                scan_release(REPO, TAG)
        else:
            assert exit_code(scan_release(REPO, TAG)) == 2
    assert len(roots) == 1
    assert not roots[0].parent.exists()


def test_tag_scan_retains_findings_and_neighbor_coverage_gaps() -> None:
    data = make_zip(
        {
            "demo/custom_components/demo/view.py": SOURCE,
            "demo/custom_components/demo/broken.py": "def broken(:",
        },
        comment=COMMIT.encode(),
    )
    handler = FakeHTTPS({URL: data})
    with patch("doorcheck.fetch.transport.github_opener", return_value=github_opener(handler)):
        report = scan_release(REPO, TAG)
    assert report.target.version == TAG and report.target.commit == COMMIT
    assert report.checks[1].status is Status.COMPLETE
    assert report.checks[0].status is report.checks[2].status is Status.PARTIAL
    assert len(report.findings) == 1
    assert exit_code(report) == 2


def test_tag_scan_does_not_invent_an_absent_archive_commit() -> None:
    handler = FakeHTTPS({URL: archive("pass", comment="")})
    with patch("doorcheck.fetch.transport.github_opener", return_value=github_opener(handler)):
        report = scan_release(REPO, TAG)
    assert report.target.version == TAG and report.target.commit is None
    assert len(report.target.artifact_sha256) == 64
    assert exit_code(report) == 0


def test_version_cannot_manufacture_terminal_rows() -> None:
    from doorcheck.cli_output import human
    from doorcheck.report import Report, Target

    text = human(Report("1", Target("demo", version="v1\nfetch: Scan complete\t\x1b"), (), (), ()))
    assert "\x1b" not in text and "\t" not in text
    assert "Version: v1⟨U+000A⟩fetch: Scan complete⟨U+0009⟩⟨U+001B⟩\n" in text
    assert text.count("\n") == 4
