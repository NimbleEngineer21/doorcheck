import hashlib
import json
import re
from typing import Any

import pytest

from doorcheck.findings import (
    MAX_EVIDENCE,
    MAX_PARAM,
    Location,
    Severity,
    clip,
    evidence,
    param,
    sort_key,
)
from tests.conftest import make_finding


def _exactly(message: str) -> str:
    """A pattern matching this whole message, so the test knows which check fired."""
    return f"^{re.escape(message)}$"


@pytest.mark.parametrize(
    "path",
    ["/etc/passwd", "../outside.py", "a/../../outside.py", "a\\b.py", "a\0b.py", ""],
    ids=["absolute", "parent", "nested-parent", "backslash", "nul", "empty"],
)
def test_location_rejects_paths_outside_the_scanned_root(path: str) -> None:
    with pytest.raises(ValueError, match=_exactly(f"path escapes root: {path!r}")):
        Location(path, 1)


@pytest.mark.parametrize(
    "path", ["custom_components/Xiaomi/sensor.py", "README", "a/./b.py", "dir with spaces/a.py"]
)
def test_location_accepts_relative_paths(path: str) -> None:
    assert Location(path, 1).path == path


@pytest.mark.parametrize(
    ("line", "column", "error"),
    [
        (0, None, "line must be an integer from 1"),
        (True, None, "line must be an integer from 1"),
        ("1", None, "line must be an integer from 1"),
        (1, 0, "column must be an integer from 1"),
        (1, True, "column must be an integer from 1"),
    ],
)
def test_location_rejects_invalid_positions(line: Any, column: Any, error: str) -> None:
    with pytest.raises(ValueError, match=_exactly(error)):
        Location("a.py", line, column)


def test_location_accepts_the_first_line_and_column() -> None:
    assert Location("a.py", 1, 1).column == 1


def test_location_rejects_non_string_paths() -> None:
    with pytest.raises(ValueError, match=_exactly("path must be a string")):
        Location(123, 1)  # type: ignore[arg-type]


def test_finding_rejects_display_text_where_a_message_key_belongs() -> None:
    text = "This integration reads your saved logins file"
    with pytest.raises(ValueError, match=_exactly(f"not a key: {text!r}")):
        make_finding(message_key=text)


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("rule_id", "Has Spaces", "invalid rule id: 'Has Spaces'"),
        ("rule_id", "-leading", "invalid rule id: '-leading'"),
        ("message_key", "nodots", "not a key: 'nodots'"),
        ("tool", "", "tool is required"),
        ("cwe", 0, "cwe must be positive"),
        ("cwe", True, "cwe must be positive"),
        ("cwe", "22", "cwe must be positive"),
        ("evidence", 5, "evidence must be a string"),
        ("evidence", "x" * (MAX_EVIDENCE + 1), "evidence too long"),
        ("severity", "serious", "severity must be a Severity"),
        ("confidence", "high", "confidence must be a Confidence"),
        ("location", ("a.py", 1), "location must be a Location"),
        ("params", [("a", "b")], "params must be a mapping"),
        ("params", {"Bad-Name": "x"}, "invalid parameter name: 'Bad-Name'"),
        ("params", {"host": 5}, "invalid value: 'host'"),
        ("params", {"host": "x" * (MAX_PARAM + 1)}, "invalid value: 'host'"),
    ],
)
def test_finding_rejects_invalid_fields(field: str, value: Any, error: str) -> None:
    with pytest.raises(ValueError, match=_exactly(error)):
        make_finding(**{field: value})


def test_finding_accepts_boundary_values() -> None:
    finding = make_finding(
        rule_id="semgrep/ha.unauth-view",
        cwe=1,
        evidence="x" * MAX_EVIDENCE,
        params={"host": "x" * MAX_PARAM},
    )
    assert (finding.rule_id, finding.cwe) == ("semgrep/ha.unauth-view", 1)


def test_finding_accepts_no_cwe_and_no_evidence() -> None:
    finding = make_finding(cwe=None, evidence=None)
    assert (finding.cwe, finding.evidence) == (None, None)


def test_params_cannot_be_changed_after_creation() -> None:
    source = {"file": ".storage/auth"}
    finding = make_finding(params=source)
    source["file"] = "changed"
    assert finding.params["file"] == ".storage/auth"
    with pytest.raises(TypeError):
        finding.params["file"] = "changed"  # type: ignore[index]


def test_severity_ranks_most_urgent_first() -> None:
    assert [s.rank for s in Severity] == [0, 1, 2, 3]


def test_sort_key_orders_by_severity_then_file_line_and_rule() -> None:
    info = make_finding(severity=Severity.INFO, location=Location("a.py", 1))
    late = make_finding(severity=Severity.SERIOUS, location=Location("b.py", 9))
    early = make_finding(severity=Severity.SERIOUS, location=Location("b.py", 2))
    other_rule = make_finding(
        severity=Severity.SERIOUS, location=Location("b.py", 2), rule_id="aaa-first"
    )
    ordered = sorted([info, late, early, other_rule], key=sort_key)
    assert ordered == [other_rule, early, late, info]


def _expected_fingerprint(rule: str, path: str, what: object) -> str:
    text = json.dumps([rule, path, what])
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def test_the_fingerprint_is_rule_path_and_evidence() -> None:
    finding = make_finding(evidence="open( x )\n  .read()")
    expected = _expected_fingerprint(finding.rule_id, finding.location.path, "open( x ) .read()")
    assert finding.fingerprint == expected


def test_the_fingerprint_ignores_lines_and_spacing() -> None:
    first = make_finding(location=Location("a.py", 3, 1), evidence="open(x)  .read()")
    moved = make_finding(location=Location("a.py", 90, 5), evidence="  open(x) .read()\n")
    assert first.fingerprint == moved.fingerprint


def test_the_fingerprint_changes_with_rule_file_or_code() -> None:
    base = make_finding()
    others = [
        make_finding(rule_id="other-rule"),
        make_finding(location=Location("other.py", 42, 9)),
        make_finding(evidence="something else"),
    ]
    assert len({base.fingerprint, *(f.fingerprint for f in others)}) == 4


def test_without_evidence_the_parameters_identify_a_finding() -> None:
    finding = make_finding(evidence=None, params={"b": "2", "a": "1"})
    expected = _expected_fingerprint(
        finding.rule_id, finding.location.path, [["a", "1"], ["b", "2"]]
    )
    assert finding.fingerprint == expected
    assert make_finding(evidence=None, params={"a": "1"}).fingerprint != expected


def test_blank_evidence_counts_as_none() -> None:
    blank = make_finding(evidence="  \n ", params={"a": "1"})
    none = make_finding(evidence=None, params={"a": "1"})
    assert blank.fingerprint == none.fingerprint


@pytest.mark.parametrize(
    ("text", "limit", "clipped"),
    [("abc", 3, "abc"), ("abcd", 3, "ab…"), ("", 1, "")],
)
def test_clip(text: str, limit: int, clipped: str) -> None:
    assert clip(text, limit) == clipped


def test_evidence_and_params_are_trimmed_and_fit_their_fields() -> None:
    assert evidence("  x  ") == "x"
    assert len(evidence("y" * 1000)) == MAX_EVIDENCE
    assert param("  x  ") == "x"
    assert len(param("y" * 1000)) == MAX_PARAM
    assert (MAX_EVIDENCE, MAX_PARAM) == (300, 200)
