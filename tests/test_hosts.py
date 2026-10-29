"""Exact-subject grouping preserves original evidence, uncertainty and coverage."""

from dataclasses import FrozenInstanceError, replace

import pytest

from doorcheck.capabilities.model import COMPUTED, Capability, Kind
from doorcheck.checks import Check, Problem, Status
from doorcheck.findings import Location
from doorcheck.hosts import Evidence, Host, HostSummary, summarize
from doorcheck.report import Report, Target

EMPTY = Report("1", Target("demo", "v1", "a" * 40, "b" * 64), (), (), ())


def cap(
    kind: Kind,
    subject: str = "example.invalid",
    line: int = 1,
    column: int | None = None,
    **attrs: str,
) -> Capability:
    return Capability(kind, Location("source.py", line, column), subject, attrs)


def test_separate_roles_exact_subjects_and_original_report() -> None:
    mention = cap(Kind.NETWORK_HOST)
    request = cap(
        Kind.HTTP_REQUEST, line=2, destination="static", operation="requests.get", method="GET"
    )
    script = cap(
        Kind.HA_FRONTEND_SCRIPT, line=3, destination="static", operation="frontend.add_extra_js_url"
    )
    other = cap(Kind.PROCESS, "git")
    report = replace(EMPTY, capabilities=(script, other, request, mention))
    summary = summarize(report)
    assert summary.report is report
    assert summary.hosts == (Host("example.invalid", Evidence((mention,), (request,), (script,))),)
    assert summary.unresolved == Evidence((), (), ())
    assert summary.report.capabilities == (script, other, request, mention)
    with pytest.raises(FrozenInstanceError):
        summary.hosts = ()
    with pytest.raises(FrozenInstanceError):
        summary.hosts[0].subject = "other"
    with pytest.raises(FrozenInstanceError):
        summary.hosts[0].evidence.mentions = ()


@pytest.mark.parametrize("kind", [Kind.NETWORK_HOST, Kind.HTTP_REQUEST, Kind.HA_FRONTEND_SCRIPT])
@pytest.mark.parametrize("subject", ["", COMPUTED])
def test_empty_or_computed_subjects_are_unresolved(kind: Kind, subject: str) -> None:
    value = cap(kind, subject, destination="static")
    summary = summarize(replace(EMPTY, capabilities=(value,)))
    assert summary.hosts == ()
    expected = {
        Kind.NETWORK_HOST: Evidence((value,), (), ()),
        Kind.HTTP_REQUEST: Evidence((), (value,), ()),
        Kind.HA_FRONTEND_SCRIPT: Evidence((), (), (value,)),
    }
    assert summary.unresolved == expected[kind]


@pytest.mark.parametrize("kind", [Kind.HTTP_REQUEST, Kind.HA_FRONTEND_SCRIPT])
@pytest.mark.parametrize("attrs", [{}, {"destination": "computed"}, {"destination": "unknown"}])
def test_request_destinations_need_explicit_static_fact(kind: Kind, attrs: dict[str, str]) -> None:
    value = cap(kind, "unresolved.invalid", **attrs)
    summary = summarize(replace(EMPTY, capabilities=(value,)))
    assert summary.hosts == ()
    assert summary.unresolved.requests == ((value,) if kind is Kind.HTTP_REQUEST else ())
    assert summary.unresolved.frontend_scripts == (
        (value,) if kind is Kind.HA_FRONTEND_SCRIPT else ()
    )


def test_mentions_do_not_borrow_request_destination_attributes() -> None:
    value = cap(Kind.NETWORK_HOST, destination="computed")
    assert summarize(replace(EMPTY, capabilities=(value,))).hosts == (
        Host(value.subject, Evidence((value,), (), ())),
    )


@pytest.mark.parametrize(
    "subject",
    [
        "EXAMPLE.invalid",
        "example.invalid",
        "example.invalid.",
        "2001:db8::1",
        "[2001:db8::1]",
        "例.invalid",
        "xn--fsq.invalid",
        "localhost",
        "not a DNS name",
        "private\n\x1b\u202e",
    ],
)
def test_subjects_are_not_dns_normalized_validated_or_queried(subject: str) -> None:
    values = (cap(Kind.NETWORK_HOST, subject), cap(Kind.NETWORK_HOST, "other.invalid"))
    summary = summarize(replace(EMPTY, capabilities=values))
    assert [h.subject for h in summary.hosts] == sorted([subject, "other.invalid"])
    assert sorted(c.subject for h in summary.hosts for c in h.evidence.mentions) == sorted(
        [subject, "other.invalid"]
    )


def test_distinct_case_script_and_punctuation_remain_distinct() -> None:
    subjects = ["EXAMPLE.invalid", "example.invalid", "example.invalid.", "é.invalid", "é.invalid"]
    summary = summarize(
        replace(EMPTY, capabilities=tuple(cap(Kind.NETWORK_HOST, h) for h in subjects))
    )
    assert [h.subject for h in summary.hosts] == sorted(subjects)


def test_order_is_deterministic_numeric_and_preserves_duplicates_and_attributes() -> None:
    values = [
        cap(Kind.NETWORK_HOST, line=10),
        cap(Kind.NETWORK_HOST, line=2, column=1),
        cap(Kind.NETWORK_HOST, line=2),
        cap(Kind.NETWORK_HOST, line=2, column=1, a="z"),
        cap(Kind.NETWORK_HOST, line=2, column=1, a="a"),
    ]
    first = replace(values[0], location=Location("a.py", 99))
    values += [first, values[0]]
    report = replace(EMPTY, capabilities=tuple(values))
    expected = (first, values[2], values[1], values[4], values[3], values[0], values[0])
    assert summarize(report).hosts[0].evidence.mentions == expected
    assert (
        summarize(replace(report, capabilities=tuple(reversed(values)))).hosts[0].evidence.mentions
        == expected
    )


def test_unresolved_order_uses_original_subject_and_attribute_ties() -> None:
    a = cap(Kind.HTTP_REQUEST, "a", destination="computed")
    b = cap(Kind.HTTP_REQUEST, "b", destination="computed")
    c = cap(Kind.HTTP_REQUEST, "b", destination="computed", method="POST")
    d = replace(c, attrs={"method": "POST", "destination": "computed"})
    summary = summarize(replace(EMPTY, capabilities=(d, b, a, c)))
    assert summary.unresolved.requests == (a, b, c, d)


@pytest.mark.parametrize(
    "kind",
    [k for k in Kind if k not in (Kind.NETWORK_HOST, Kind.HTTP_REQUEST, Kind.HA_FRONTEND_SCRIPT)],
)
def test_unrelated_capabilities_are_retained_in_original_but_not_grouped(kind: Kind) -> None:
    report = replace(EMPTY, capabilities=(cap(kind),))
    assert summarize(report) == HostSummary(report, (), Evidence((), (), ()))


def test_coverage_failures_and_nothing_to_scan_are_never_reclassified() -> None:
    report = replace(
        EMPTY,
        checks=(
            Check("failed", "1", Status.FAILED, (Problem("problem.no_rules"),)),
            Check("empty", "1", Status.NOTHING_TO_SCAN),
        ),
    )
    summary = summarize(report)
    assert summary.report is report
    assert summary.report.checks == report.checks
    assert summary.hosts == ()
