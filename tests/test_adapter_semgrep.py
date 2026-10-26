"""Semgrep: parsing its output, and output recorded from the real tool."""

import json
import re
from pathlib import Path
from typing import Any

import pytest

from doorcheck.adapters import Audience, Parsed, ToolError, load
from doorcheck.adapters.semgrep import Semgrep, scanned_files
from doorcheck.checks import Problem
from doorcheck.findings import Confidence, Location, Severity
from tests.adapters_support import (
    CLEAN,
    UNSAFE,
    as_recorded,
    at,
    dump,
    only,
    recorded,
    summary,
)

pytestmark = pytest.mark.usefixtures("offline")


def test_semgrep_is_registered_for_users() -> None:
    adapter = load().adapters["semgrep"]
    assert isinstance(adapter, Semgrep)
    assert (adapter.version, adapter.audience, adapter.experimental) == (
        "1.182.0",
        Audience.USERS,
        False,
    )


def semgrep_result(**extra: Any) -> dict[str, Any]:
    return {
        "check_id": "demo-rule",
        "path": "a.py",
        "start": {"line": 2, "col": 5},
        "end": {"line": 3, "col": 1},
        "extra": {"message": "msg", "severity": "WARNING", "lines": "requires login", **extra},
    }


def semgrep_output(*results: dict[str, Any], scanned: tuple[str, ...] = ("a.py",)) -> bytes:
    return dump({"results": list(results), "errors": [], "paths": {"scanned": list(scanned)}})


@pytest.fixture
def code(tmp_path: Path) -> Path:
    (tmp_path / "a.py").write_text("one\n  two\nthree\nfour\n")
    return tmp_path


@pytest.mark.parametrize(
    ("severity", "expected"),
    [
        ("CRITICAL", Severity.SERIOUS),
        ("high", Severity.SERIOUS),
        ("ERROR", Severity.SERIOUS),
        ("MEDIUM", Severity.REVIEW),
        ("WARNING", Severity.REVIEW),
        ("LOW", Severity.NOTICE),
        ("INFO", Severity.NOTICE),
        ("EXPERIMENT", Severity.REVIEW),
    ],
)
def test_semgrep_severities(code: Path, severity: str, expected: Severity) -> None:
    finding = only(Semgrep().parse(semgrep_output(semgrep_result(severity=severity)), at(code)))
    assert finding.severity is expected


def test_semgrep_reads_evidence_from_the_file(code: Path) -> None:
    finding = only(Semgrep().parse(semgrep_output(semgrep_result()), at(code)))
    assert finding.evidence == "two\nthree"
    assert (finding.location.line, finding.location.column) == (2, 5)
    assert (finding.confidence, finding.cwe, finding.message_key, finding.tool) == (
        Confidence.MEDIUM,
        None,
        "finding.tool_reported",
        "semgrep",
    )
    assert finding.params == {"message": "msg"}


def test_semgrep_evidence_from_a_file_that_isnt_utf8(code: Path) -> None:
    (code / "a.py").write_bytes(b"one\nt\xffo\n")
    assert only(Semgrep().parse(semgrep_output(semgrep_result()), at(code))).evidence == "t�o"


def test_tool_paths_given_absolute(code: Path) -> None:
    result = semgrep_result()
    result["path"] = str(code / "a.py")
    assert only(Semgrep().parse(semgrep_output(result), at(code))).location.path == "a.py"


def test_semgrep_without_the_file_has_no_evidence(code: Path) -> None:
    (code / "a.py").unlink()
    parsed = Semgrep().parse(semgrep_output(semgrep_result(), scanned=()), at(code))
    assert only(parsed).evidence is None


@pytest.mark.parametrize(
    ("metadata", "confidence", "cwe", "key"),
    [
        (
            {"confidence": "HIGH", "cwe": "CWE-79: XSS"},
            Confidence.HIGH,
            79,
            "finding.tool_reported",
        ),
        (
            {"confidence": "LOW", "cwe": ["no number", "CWE-22: x", "CWE-23"]},
            Confidence.LOW,
            22,
            "finding.tool_reported",
        ),
        (
            {"confidence": "sure", "cwe": ["none"], "message_key": "finding.unauth_view"},
            Confidence.MEDIUM,
            None,
            "finding.unauth_view",
        ),
        (None, Confidence.MEDIUM, None, "finding.tool_reported"),
    ],
)
def test_semgrep_rule_metadata(
    code: Path, metadata: Any, confidence: Confidence, cwe: int | None, key: str
) -> None:
    finding = only(Semgrep().parse(semgrep_output(semgrep_result(metadata=metadata)), at(code)))
    assert (finding.confidence, finding.cwe, finding.message_key) == (confidence, cwe, key)


# The shape Semgrep 1.182 reported for two valid files of a real integration.
SYNTAX_ERROR = {
    "code": 3,
    "level": "warn",
    "type": "Syntax error",
    "message": "Syntax error at line a.py:674:\n `ConfigEntryFields` was unexpected",
    "path": "a.py",
}


def semgrep_errors(*errors: dict[str, Any]) -> bytes:
    return dump({"results": [], "errors": list(errors), "paths": {"scanned": ["a.py"]}})


def test_a_file_semgrep_couldnt_read_is_a_problem(code: Path) -> None:
    parsed = Semgrep().parse(semgrep_errors(SYNTAX_ERROR), at(code))
    assert parsed == Parsed(
        problems=(
            Problem(
                "problem.file_not_parsed",
                Location("a.py", 674),
                {"detail": str(SYNTAX_ERROR["message"])},
            ),
        )
    )


def test_findings_are_kept_beside_problems(code: Path) -> None:
    output = json.loads(semgrep_output(semgrep_result()))
    output["errors"] = [SYNTAX_ERROR]
    parsed = Semgrep().parse(dump(output), at(code))
    assert ([f.rule_id for f in parsed.findings], [p.key for p in parsed.problems]) == (
        ["demo-rule"],
        ["problem.file_not_parsed"],
    )


def test_a_syntax_error_with_an_absolute_path(code: Path) -> None:
    error = {**SYNTAX_ERROR, "path": str(code / "a.py")}
    (problem,) = Semgrep().parse(semgrep_errors(error), at(code)).problems
    assert problem.location == Location("a.py", 674)


def test_a_syntax_error_without_a_line(code: Path) -> None:
    error = {**SYNTAX_ERROR, "message": "no position"}
    (problem,) = Semgrep().parse(semgrep_errors(error), at(code)).problems
    assert problem.location == Location("a.py", 1)
    bare = {"type": "Syntax error", "path": "a.py"}
    (problem,) = Semgrep().parse(semgrep_errors(bare), at(code)).problems
    assert (problem.location, dict(problem.params)) == (Location("a.py", 1), {"detail": ""})


@pytest.mark.parametrize(
    "error",
    [
        {"type": "Rule parse error", "message": "rule broken"},
        {"type": "Syntax error", "message": "no file named"},
    ],
)
def test_other_semgrep_errors_fail_the_run(code: Path, error: dict[str, str]) -> None:
    with pytest.raises(ValueError, match=f"^semgrep reported an error: {re.escape(str(error))}$"):
        Semgrep().parse(semgrep_errors(error), at(code))


def test_a_python_file_semgrep_skipped_is_a_problem(code: Path) -> None:
    for name in ("sub/payload.py", ".git/hook.py", "notes.txt"):
        (code / name).parent.mkdir(exist_ok=True)
        (code / name).write_text("x")
    parsed = Semgrep().parse(semgrep_output(), at(code))
    assert parsed.problems == (
        Problem("problem.file_not_scanned", Location(".git/hook.py", 1)),
        Problem("problem.file_not_scanned", Location("sub/payload.py", 1)),
    )


def test_scanned_files_include_git_but_not_links(tmp_path: Path) -> None:
    for name in ("a.py", "b.txt", "pkg/c.py", ".git/hooks/d.py", "gitx/e.py"):
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text("")
    (tmp_path / "linked.py").symlink_to(tmp_path / "a.py")
    assert scanned_files(tmp_path) == [".git/hooks/d.py", "a.py", "b.txt", "gitx/e.py", "pkg/c.py"]


def test_semgrep_without_rules_refuses_to_run(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("")
    with pytest.raises(ToolError, match=r"^semgrep has no rules to run$") as error:
        Semgrep().command(at(tmp_path), tmp_path)
    assert error.value.key == "problem.no_rules"


def test_semgrep_without_files_has_nothing_to_run(tmp_path: Path) -> None:
    assert Semgrep([Path("r.yaml")]).command(at(tmp_path), tmp_path) == Parsed()


def test_semgrep_gets_every_file_by_name_and_ignores_suppressions(tmp_path: Path) -> None:
    for name in ("b.py", "a/c.yaml", "--config=x.py", ".git/d.py"):
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text("")
    rules = Path("rules/a.yaml")
    command = Semgrep([rules], executable="/opt/semgrep").command(at(tmp_path), tmp_path / "w")
    assert not isinstance(command, Parsed)
    assert command.cwd == tmp_path
    assert command.argv == (
        "/opt/semgrep", "scan", "--config", str(rules.absolute()),
        "--json", "--metrics=off", "--disable-version-check", "--quiet", "--no-rewrite-rule-ids",
        "--no-git-ignore", "--project-root=.", "--max-target-bytes=0", "--disable-nosem",
        "--", "--config=x.py", ".git/d.py", "a/c.yaml", "b.py",
    )  # fmt: skip
    assert command.ok_exit_codes == {0}
    assert Semgrep().version_command() == ("semgrep", "--version", "--disable-version-check")


def test_too_many_files_for_one_command_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("doorcheck.adapters.semgrep.MAX_ARGUMENT_BYTES", 17)
    (tmp_path / "abcd.py").write_text("")  # 7 characters and a separator
    (tmp_path / "efghi.py").write_text("")  # 8 and a separator: 17 in all, at the limit
    assert not isinstance(Semgrep([Path("r.yaml")]).command(at(tmp_path), tmp_path), Parsed)
    (tmp_path / "j.py").write_text("")
    with pytest.raises(ToolError, match=r"^too many files to list \(3\)$") as error:
        Semgrep([Path("r.yaml")]).command(at(tmp_path), tmp_path)
    assert error.value.key == "problem.too_many_files"


# --- recorded output ---------------------------------------------------------------


def test_semgrep_finds_the_unauthenticated_path_joins() -> None:
    parsed = Semgrep().parse(recorded("semgrep", "unsafe"), as_recorded(UNSAFE))
    rule = "test-unauth-view-path-join"
    assert summary(parsed.findings) == [
        (rule, Severity.SERIOUS, Confidence.HIGH, "__init__.py", 18, 16),
        (rule, Severity.SERIOUS, Confidence.HIGH, "suppressed.py", 16, 16),
    ]
    finding = parsed.findings[0]
    assert (finding.cwe, finding.tool, finding.message_key) == (
        22,
        "semgrep",
        "finding.tool_reported",
    )
    assert finding.evidence == 'path = os.path.join(os.path.dirname(__file__), "www", filename)'
    assert finding.params["message"].startswith("URL parameter 'filename' is joined")
    assert parsed.problems == ()


def test_semgrep_ignores_the_scanned_codes_suppression_comment() -> None:
    # suppressed.py marks its unsafe line `# nosemgrep`; the recorded run still reports it.
    line = (UNSAFE / "suppressed.py").read_text().splitlines()[15]
    assert line.endswith("# nosemgrep")
    parsed = Semgrep().parse(recorded("semgrep", "unsafe"), as_recorded(UNSAFE))
    assert ("suppressed.py", 16) in {(f.location.path, f.location.line) for f in parsed.findings}


def test_semgrep_scanned_the_file_hidden_by_semgrepignore() -> None:
    # The fixture's own .semgrepignore lists hidden.py; the recorded run still scanned it.
    assert (UNSAFE / ".semgrepignore").read_text().splitlines()[-1] == "hidden.py"
    parsed = Semgrep().parse(recorded("semgrep", "unsafe"), as_recorded(UNSAFE))
    assert parsed.problems == ()  # a skipped Python file would be a problem


def test_semgrep_on_clean_code() -> None:
    assert Semgrep().parse(recorded("semgrep", "clean"), as_recorded(CLEAN)) == Parsed()


def test_evidence_reading_has_a_byte_ceiling(tmp_path: Path) -> None:
    from doorcheck.adapters.semgrep import _lines

    path = tmp_path / "large.py"
    path.write_bytes(b"\n" * 2_000_000 + b"beyond the evidence budget")
    assert _lines(path, 2_000_001, 2_000_001) is None
