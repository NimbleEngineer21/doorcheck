"""Observation identities, assessment changes, multiplicity and coverage retention."""

from dataclasses import FrozenInstanceError, replace

import pytest

from doorcheck.capabilities.model import Capability, Kind
from doorcheck.checks import Check, Problem, Status
from doorcheck.comparison import Changes, compare
from doorcheck.findings import Confidence, Location, Severity
from doorcheck.report import Report, Target, from_dict, to_dict
from tests.conftest import make_finding

CAPABILITY = Capability(Kind.PROCESS, Location("run.py", 3, 2), "git", {"a": "1", "b": "2"})
FINDING = make_finding(location=Location("run.py", 7, 4), evidence="open(filename)")


def report(*, capabilities=(), findings=(), checks=(), name="demo", version="1") -> Report:
    return Report("0.1.0", Target(name, version), checks, capabilities, findings)


def test_empty_comparison_retains_reports_and_their_metadata() -> None:
    before = report(version="old")
    after = report(version="new", name="other")
    result = compare(before, after)
    assert result.before is before
    assert result.after is after
    assert result.capabilities == Changes((), ())
    assert result.findings == Changes((), ())
    with pytest.raises(FrozenInstanceError):
        result.after = before
    with pytest.raises(FrozenInstanceError):
        result.findings.added = (FINDING,)


def test_add_remove_and_no_change_round_trip() -> None:
    empty = report()
    full = report(capabilities=(CAPABILITY,), findings=(FINDING,))
    added = compare(empty, from_dict(to_dict(full)))
    assert added.capabilities == Changes((CAPABILITY,), ())
    assert added.findings == Changes((FINDING,), ())
    removed = compare(full, empty)
    assert removed.capabilities == Changes((), (CAPABILITY,))
    assert removed.findings == Changes((), (FINDING,))
    same = compare(full, from_dict(to_dict(full)))
    assert same.capabilities == same.findings == Changes((), ())


@pytest.mark.parametrize(
    "location", [Location("run.py", 99, 1), Location("run.py", 3), Location("run.py", 3, 99)]
)
def test_line_and_column_moves_do_not_change_identity(location: Location) -> None:
    old = report(capabilities=(CAPABILITY,), findings=(FINDING,))
    new = report(
        capabilities=(replace(CAPABILITY, location=location),),
        findings=(replace(FINDING, location=location),),
    )
    result = compare(old, new)
    assert result.capabilities == result.findings == Changes((), ())


@pytest.mark.parametrize(
    "change",
    [
        {"kind": Kind.DYNAMIC_CODE},
        {"location": Location("other.py", 3, 2)},
        {"subject": "sh"},
        {"attrs": {"a": "1", "b": "3"}},
        {"attrs": {"a": "1"}},
        {"attrs": {"a": "1", "b": "2", "c": "3"}},
    ],
)
def test_each_capability_identity_field_matters(change) -> None:
    changed = replace(CAPABILITY, **change)
    result = compare(report(capabilities=(CAPABILITY,)), report(capabilities=(changed,)))
    assert result.capabilities == Changes((changed,), (CAPABILITY,))
    assert result.findings == Changes((), ())


@pytest.mark.parametrize(
    "change",
    [
        {"rule_id": "another-rule"},
        {"location": Location("another.py", 7, 4)},
        {"evidence": "open(other)"},
        {"severity": Severity.SERIOUS},
        {"confidence": Confidence.LOW},
        {"message_key": "finding.tool_reported"},
        {"tool": "another"},
        {"cwe": None},
        {"params": {"file": "other"}},
    ],
)
def test_finding_identity_and_assessment_changes_are_visible(change) -> None:
    changed = replace(FINDING, **change)
    result = compare(report(findings=(FINDING,)), report(findings=(changed,)))
    assert result.findings == Changes((changed,), (FINDING,))
    assert result.capabilities == Changes((), ())


def test_metadata_escalation_is_not_hidden_by_stable_fingerprint() -> None:
    changed = replace(FINDING, severity=Severity.SERIOUS)
    assert changed.fingerprint == FINDING.fingerprint
    result = compare(report(findings=(FINDING,)), report(findings=(changed,)))
    assert result.findings.added[0].severity is Severity.SERIOUS
    assert result.findings.removed[0].severity is Severity.REVIEW


def test_mapping_order_and_surrounding_evidence_whitespace_are_ignored() -> None:
    before = report(
        capabilities=(CAPABILITY,),
        findings=(replace(FINDING, params={"a": "1", "b": "2"}),),
    )
    after = report(
        capabilities=(replace(CAPABILITY, attrs={"b": "2", "a": "1"}),),
        findings=(replace(FINDING, evidence=" \nopen(filename)\t", params={"b": "2", "a": "1"}),),
    )
    result = compare(before, after)
    assert result.capabilities == result.findings == Changes((), ())


def test_internal_evidence_whitespace_is_significant() -> None:
    before = replace(FINDING, evidence='open("a b")')
    after = replace(FINDING, evidence='open("a  b")')
    result = compare(report(findings=(before,)), report(findings=(after,)))
    assert result.findings == Changes((after,), (before,))


def test_parameter_fallback_without_evidence() -> None:
    before = replace(FINDING, evidence=None, params={"a": "1", "b": "2"})
    reordered = replace(before, evidence=" \n", params={"b": "2", "a": "1"})
    assert compare(report(findings=(before,)), report(findings=(reordered,))).findings == Changes(
        (), ()
    )
    changed = replace(before, params={"a": "2", "b": "2"})
    assert compare(report(findings=(before,)), report(findings=(changed,))).findings == Changes(
        (changed,), (before,)
    )


def test_repeated_observations_are_not_collapsed_and_latest_positions_are_retained() -> None:
    cap2 = replace(CAPABILITY, location=Location("run.py", 20))
    cap3 = replace(CAPABILITY, location=Location("run.py", 30))
    find2 = replace(FINDING, location=Location("run.py", 20))
    find3 = replace(FINDING, location=Location("run.py", 30))
    before = report(capabilities=(CAPABILITY,), findings=(FINDING,))
    after = report(capabilities=(cap3, cap2), findings=(find3, find2))
    assert find2.fingerprint == find3.fingerprint
    result = compare(before, after)
    assert result.capabilities == Changes((cap3,), ())
    assert result.findings == Changes((find3,), ())
    inverse = compare(after, before)
    assert inverse.capabilities == Changes((), (cap3,))
    assert inverse.findings == Changes((), (find3,))
    assert compare(after, after).findings == Changes((), ())


def test_same_position_duplicates_still_count() -> None:
    before = report(capabilities=(CAPABILITY, CAPABILITY), findings=(FINDING, FINDING))
    after = report(capabilities=(CAPABILITY,), findings=(FINDING,))
    result = compare(before, after)
    assert result.capabilities == Changes((), (CAPABILITY,))
    assert result.findings == Changes((), (FINDING,))


@pytest.mark.parametrize("status", list(Status))
def test_coverage_checks_are_retained_without_turning_removal_into_a_fix(status: Status) -> None:
    problems = (
        (Problem("problem.tool_failed"),) if status in (Status.PARTIAL, Status.FAILED) else ()
    )
    checks = (Check("source", "1", status, problems),)
    before = report(capabilities=(CAPABILITY,), findings=(FINDING,), checks=checks)
    after = report(checks=checks)
    result = compare(before, after)
    assert result.before.checks == result.after.checks == checks
    assert result.findings == Changes((), (FINDING,))
    assert result.capabilities == Changes((), (CAPABILITY,))


def test_changed_check_sets_versions_and_targets_are_not_observation_changes() -> None:
    before = report(
        capabilities=(CAPABILITY,), findings=(FINDING,), checks=(Check("a", "1", Status.COMPLETE),)
    )
    after = replace(
        before,
        doorcheck_version="next",
        target=Target("renamed", "2", "c", "d"),
        checks=(Check("b", "2", Status.NOTHING_TO_SCAN),),
    )
    result = compare(before, after)
    assert result.before is before and result.after is after
    assert result.capabilities == result.findings == Changes((), ())


def test_output_order_is_independent_of_input_order_and_compares_all_identities() -> None:
    a = replace(CAPABILITY, subject="a")
    z = replace(CAPABILITY, subject="z")
    f2 = replace(FINDING, rule_id="another-rule")
    first = report(capabilities=(z, a, CAPABILITY), findings=(f2, FINDING))
    reverse = report(
        capabilities=tuple(reversed(first.capabilities)), findings=tuple(reversed(first.findings))
    )
    empty = report()
    assert compare(empty, first).capabilities == compare(empty, reverse).capabilities
    assert compare(empty, first).findings == compare(empty, reverse).findings
    assert (
        compare(first, reverse).findings == compare(first, reverse).capabilities == Changes((), ())
    )
    assert compare(first, report(capabilities=(a,), findings=(f2,))).capabilities == Changes(
        (), (CAPABILITY, z)
    )


def test_equivalent_evidence_ties_have_a_stable_representative() -> None:
    padded = replace(FINDING, evidence=" open(filename) ")
    before = report(findings=(FINDING,))
    first = report(findings=(padded, FINDING))
    reverse = report(findings=(FINDING, padded))
    assert (
        compare(before, first).findings
        == compare(before, reverse).findings
        == Changes((FINDING,), ())
    )


@pytest.mark.parametrize("kind", ["capability", "finding"])
def test_unknown_columns_sort_before_known_columns(kind: str) -> None:
    original = CAPABILITY if kind == "capability" else FINDING
    unknown = replace(original, location=Location("run.py", 3))
    first = replace(original, location=Location("run.py", 3, 1))
    last = replace(original, location=Location("run.py", 3, 9))
    field = "capabilities" if kind == "capability" else "findings"
    baseline = report(**{field: (original,)})
    new = report(**{field: (last, first, unknown)})
    changes = getattr(compare(baseline, new), field)
    assert changes == Changes((first, last), ())
    assert changes == getattr(compare(baseline, report(**{field: (unknown, first, last)})), field)


def test_empty_and_missing_evidence_ties_are_deterministic() -> None:
    absent = replace(FINDING, evidence=None)
    empty = replace(FINDING, evidence="")
    space = replace(FINDING, evidence=" ")
    baseline = report(findings=(absent,))
    first = report(findings=(absent, empty, space))
    reverse = report(findings=(space, empty, absent))
    assert (
        compare(baseline, first).findings
        == compare(baseline, reverse).findings
        == Changes((empty, absent), ())
    )
