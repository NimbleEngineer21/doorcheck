"""What each check covered, and Doorcheck's own keyed errors."""

import re
from typing import Any

import pytest

from doorcheck.checks import Check, Problem, Status, status_for
from doorcheck.errors import DoorcheckError
from doorcheck.findings import Location

GAP = Problem("problem.file_not_parsed", Location("a.py", 3), {"detail": "bad"})


def test_a_problem_holds_a_key_a_place_and_parameters() -> None:
    assert (GAP.key, GAP.location, dict(GAP.params)) == (
        "problem.file_not_parsed",
        Location("a.py", 3),
        {"detail": "bad"},
    )
    assert Problem("problem.no_rules").location is None


def test_problem_parameters_cannot_be_changed() -> None:
    source = {"detail": "x"}
    problem = Problem("problem.tool_failed", params=source)
    source["detail"] = "changed"
    assert problem.params["detail"] == "x"
    with pytest.raises(TypeError):
        problem.params["detail"] = "y"  # type: ignore[index]


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        ({"key": "Tool failed"}, "key required"),
        ({"key": 3}, "key required"),
        ({"location": ("a.py", 1)}, "bad location"),
        ({"params": {"Bad": "x"}}, "invalid parameter name: 'Bad'"),
        ({"params": {"a": 1}}, "invalid value: 'a'"),
    ],
)
def test_invalid_problems_are_refused(fields: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError, match=f"^{re.escape(message)}$"):
        Problem(**{"key": "problem.tool_failed", **fields})


@pytest.mark.parametrize(
    ("status", "problems"),
    [
        (Status.COMPLETE, ()),
        (Status.NOTHING_TO_SCAN, ()),
        (Status.PARTIAL, (GAP,)),
        (Status.FAILED, (GAP,)),
    ],
)
def test_partial_and_failed_checks_say_why(status: Status, problems: tuple[Problem, ...]) -> None:
    assert Check("semgrep", "1.0", status, problems).status is status


@pytest.mark.parametrize(
    ("status", "problems"),
    [
        (Status.COMPLETE, (GAP,)),
        (Status.NOTHING_TO_SCAN, (GAP,)),
        (Status.PARTIAL, ()),
        (Status.FAILED, ()),
    ],
)
def test_a_status_has_problems_exactly_when_something_wasnt_covered(
    status: Status, problems: tuple[Problem, ...]
) -> None:
    with pytest.raises(ValueError, match=f"^{status} needs problems iff it has gaps$"):
        Check("semgrep", "1.0", status, problems)


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        ({"name": ""}, "check name is required"),
        ({"name": 3}, "check name is required"),
        ({"version": None}, "version must be a string"),
        ({"status": "complete"}, "status must be a Status"),
        ({"problems": ("gap",)}, "problems must be Problems"),
    ],
)
def test_invalid_checks_are_refused(fields: dict[str, Any], message: str) -> None:
    defaults: dict[str, Any] = {"name": "semgrep", "version": "1", "status": Status.COMPLETE}
    with pytest.raises(ValueError, match=f"^{re.escape(message)}$"):
        Check(**{**defaults, **fields})


def test_status_for_a_check_that_ran() -> None:
    assert (status_for(()), status_for((GAP,))) == (Status.COMPLETE, Status.PARTIAL)


def test_errors_carry_a_key_and_are_not_value_errors() -> None:
    error = DoorcheckError("boom")
    assert (str(error), error.key, isinstance(error, ValueError)) == (
        "boom",
        "problem.unexpected",
        False,
    )
    assert DoorcheckError("boom", "problem.tool_failed").key == "problem.tool_failed"
