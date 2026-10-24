"""OSV-Scanner: parsing its output, and output recorded from the real tool."""

import json
from pathlib import Path

import pytest

from doorcheck.adapters import Audience, Parsed, load
from doorcheck.adapters.osv import OsvScanner
from doorcheck.dependencies import Dependencies
from doorcheck.findings import Confidence, Location, Severity
from tests.adapters_support import (
    DEPENDENCIES,
    GAP_PROBLEMS,
    GAPS,
    UNSAFE,
    as_recorded,
    at,
    dump,
    recorded,
)

pytestmark = pytest.mark.usefixtures("offline")


def test_osv_is_registered_for_users() -> None:
    adapter = load().adapters["osv-scanner"]
    assert isinstance(adapter, OsvScanner)
    assert (adapter.version, adapter.audience, adapter.experimental) == (
        "2.7.0",
        Audience.USERS,
        False,
    )


def test_osv_writes_rebuilt_pins(tmp_path: Path) -> None:
    work = tmp_path / "w"
    work.mkdir()
    command = OsvScanner().command(at(tmp_path, DEPENDENCIES), work)
    assert not isinstance(command, Parsed)
    assert (work / "requirements.txt").read_text() == "a==1\nFoo_Bar==1.9\n"
    assert command.cwd == work


def test_with_nothing_pinned_osvs_gaps_are_the_result(tmp_path: Path) -> None:
    command = OsvScanner().command(at(tmp_path, Dependencies((), GAPS)), tmp_path)
    assert command == Parsed(problems=GAP_PROBLEMS)
    assert OsvScanner().command(at(tmp_path), tmp_path) == Parsed()


def test_osv_command(tmp_path: Path) -> None:
    command = OsvScanner("/opt/osv").command(at(tmp_path, DEPENDENCIES), tmp_path)
    assert not isinstance(command, Parsed)
    assert command.argv == (
        "/opt/osv", "scan", "source", "--format", "json", "--no-resolve", "-L", "requirements.txt",
    )  # fmt: skip
    assert command.ok_exit_codes == {0, 1}
    assert OsvScanner().version_command() == ("osv-scanner", "--version")


def osv_output(
    max_severity: object, summary: object = "s", ids: tuple[str, ...] = ("GHSA-1",)
) -> bytes:
    vulns = [{"id": "OTHER-1", "summary": "not this one"}, {"id": ids[0], "summary": summary}]
    group: dict[str, object] = {"ids": list(ids)}
    if max_severity is not None:
        group["max_severity"] = max_severity
    package = {
        "package": {"name": "foo-bar", "version": "1.9"},
        "vulnerabilities": vulns,
        "groups": [group],
    }
    return dump({"results": [{"packages": [package]}]})


@pytest.mark.parametrize(
    ("score", "severity"),
    [("9.8", Severity.SERIOUS), ("7.0", Severity.SERIOUS), ("6.9", Severity.REVIEW),
     ("4", Severity.REVIEW), ("3.9", Severity.NOTICE), ("", Severity.REVIEW),
     (None, Severity.REVIEW)],
)  # fmt: skip
def test_osv_severity_follows_the_cvss_score(
    tmp_path: Path, score: object, severity: Severity
) -> None:
    (finding,) = OsvScanner().parse(osv_output(score), at(tmp_path)).findings
    assert finding.severity is severity


def test_osv_finding_points_at_the_pin_and_the_gaps_are_kept(tmp_path: Path) -> None:
    parsed = OsvScanner().parse(osv_output("5"), at(tmp_path, DEPENDENCIES))
    (finding,) = parsed.findings
    assert finding.location == Location("manifest.json", 4)
    assert (finding.rule_id, finding.message_key, finding.confidence, finding.tool) == (
        "osv/known-vulnerability",
        "finding.known_vulnerability",
        Confidence.HIGH,
        "osv-scanner",
    )
    assert dict(finding.params) == {
        "package": "foo-bar",
        "version": "1.9",
        "ids": "GHSA-1",
        "summary": "s",
    }
    assert parsed.problems == GAP_PROBLEMS


@pytest.mark.parametrize("ids", [("MAL-2026-1",), ("GHSA-2", "MAL-2026-1")])
def test_a_known_malicious_package_is_serious_whatever_its_score(
    tmp_path: Path, ids: tuple[str, ...]
) -> None:
    (finding,) = OsvScanner().parse(osv_output(None, ids=ids), at(tmp_path)).findings
    assert (finding.rule_id, finding.severity, finding.message_key) == (
        "osv/malicious-package",
        Severity.SERIOUS,
        "finding.malicious_package",
    )


def test_osv_summary_when_no_advisory_matches_the_group(tmp_path: Path) -> None:
    output = json.loads(osv_output("5"))
    output["results"][0]["packages"][0]["groups"][0]["ids"] = ["UNLISTED-1"]
    (finding,) = OsvScanner().parse(dump(output), at(tmp_path)).findings
    assert finding.params["summary"] == ""


def test_osv_finding_for_a_package_that_wasnt_asked_for(tmp_path: Path) -> None:
    (finding,) = OsvScanner().parse(osv_output("5", summary=None), at(tmp_path)).findings
    assert finding.location.line == 1
    assert finding.params["summary"] == ""


# --- recorded output ---------------------------------------------------------------


def test_osv_finds_the_vulnerable_pin_and_reports_what_it_couldnt_check() -> None:
    parsed = OsvScanner().parse(recorded("osv-scanner", "unsafe"), as_recorded(UNSAFE))
    findings = parsed.findings
    assert {(f.rule_id, f.location.path, f.location.line) for f in findings} == {
        ("osv/known-vulnerability", "manifest.json", 6)
    }
    assert [f.params["ids"] for f in findings] == [
        "PYSEC-2026-1872, GHSA-9hjg-9r4m-mvj7",
        "PYSEC-2026-1873, GHSA-9wx4-h78v-vm56",
        "PYSEC-2026-2275, GHSA-gc5v-m9x4-r6x2",
    ]
    assert {(f.params["package"], f.params["version"]) for f in findings} == {
        ("requests", "2.31.0")
    }
    summaries = [f.params["summary"] for f in findings]
    assert summaries[0] == "Requests vulnerable to .netrc credentials leak via malicious URLs"
    assert summaries[2] == ""  # this advisory has no summary in OSV
    assert {f.severity for f in findings} == {Severity.REVIEW}
    assert {f.message_key for f in findings} == {"finding.known_vulnerability"}
    assert [(p.key, p.location, p.params["requirement"]) for p in parsed.problems] == [
        ("problem.requirement_outside_pypi", Location("manifest.json", 8), "-r /etc/passwd"),
        (
            "problem.requirement_outside_pypi",
            Location("manifest.json", 9),
            "demo @ https://example.invalid/demo-1.0.zip",
        ),
    ]


def test_osv_had_nothing_to_look_at_in_the_clean_fixture() -> None:
    assert not (UNSAFE.parent.parent / "tools" / "osv-scanner" / "clean.json").exists()
