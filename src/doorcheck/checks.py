"""What each check covered, so a scan that found nothing can be told apart
from one that couldn't look.

A check is one scanning tool or doorcheck's own capability reader. Anything
it couldn't cover is a Problem, recorded instead of a finding: a gap is a fact
about the scan, not about the code, and never passed off as clean.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType

from doorcheck.findings import MESSAGE_KEY, Location, check_params, require


class Status(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"  # ran, but some files, packages or checks weren't covered
    NOTHING_TO_SCAN = "nothing_to_scan"
    FAILED = "failed"  # no results at all


@dataclass(frozen=True, slots=True)
class Problem:
    key: str
    location: Location | None = None
    params: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        require(isinstance(self.key, str) and MESSAGE_KEY.fullmatch(self.key), "key required")
        require(self.location is None or isinstance(self.location, Location), "bad location")
        check_params(self.params)
        object.__setattr__(self, "params", MappingProxyType(dict(self.params)))


@dataclass(frozen=True, slots=True)
class Check:
    name: str
    version: str
    status: Status
    problems: tuple[Problem, ...] = ()

    def __post_init__(self) -> None:
        require(isinstance(self.name, str) and self.name, "check name is required")
        require(isinstance(self.version, str), "version must be a string")
        require(isinstance(self.status, Status), "status must be a Status")
        require(all(isinstance(p, Problem) for p in self.problems), "problems must be Problems")
        has_gaps = self.status in (Status.PARTIAL, Status.FAILED)
        require(has_gaps == bool(self.problems), f"{self.status} needs problems iff it has gaps")


def status_for(problems: tuple[Problem, ...]) -> Status:
    """A check that ran: complete, or partial when something wasn't covered."""
    return Status.PARTIAL if problems else Status.COMPLETE
