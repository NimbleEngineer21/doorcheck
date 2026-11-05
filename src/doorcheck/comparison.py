"""Compare observations in two reports without claiming that a gap is a fix.

Both original reports remain available, including checks, versions and targets.
A difference describes reported observations, not a verdict about either target.
"""

import json
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum

from doorcheck.capabilities.model import Capability
from doorcheck.checks import Status
from doorcheck.findings import Finding
from doorcheck.report import Report


@dataclass(frozen=True, slots=True)
class Changes[T]:
    added: tuple[T, ...]
    removed: tuple[T, ...]


@dataclass(frozen=True, slots=True)
class Comparison:
    before: Report
    after: Report
    capabilities: Changes[Capability]
    findings: Changes[Finding]


def compare(before: Report, after: Report) -> Comparison:
    """Compare caller-selected snapshots; no I/O, rule execution or severity changes.

    Line/column moves do not change identity. Repeated occurrences are counted,
    so adding a second identical observation is still a change. A finding whose
    severity or other assessment metadata changes is removed and added, even
    when its fingerprint stays the same. Coverage must be read from both reports.
    """
    return Comparison(
        before,
        after,
        _changes(before.capabilities, after.capabilities, _capability_key),
        _changes(before.findings, after.findings, _finding_key),
    )


class Limit(StrEnum):
    """Why a comparison cannot be read as one target's update. Order is fixed."""

    TARGET_NAME = "target_name"
    ENGINE_VERSION = "engine_version"
    CHECKS = "checks"  # different check names or versions; reports sort checks by name
    BEFORE_INCOMPLETE = "before_incomplete"  # an added observation may not be new
    AFTER_INCOMPLETE = "after_incomplete"  # a removed observation may still be there


@dataclass(frozen=True, slots=True)
class Comparability:
    limits: tuple[Limit, ...]
    # None unless both reports record an installed-file digest.
    same_artifact: bool | None

    @property
    def matches(self) -> bool:
        return not self.limits


def comparability(before: Report, after: Report) -> Comparability:
    """Read declared metadata only; this does not verify authenticity or scan roots.

    Target version and commit changes are expected in an update and are not limits.
    """
    found = {
        Limit.TARGET_NAME: before.target.name != after.target.name,
        Limit.ENGINE_VERSION: before.doorcheck_version != after.doorcheck_version,
        Limit.CHECKS: _check_list(before) != _check_list(after),
        Limit.BEFORE_INCOMPLETE: not _complete(before),
        Limit.AFTER_INCOMPLETE: not _complete(after),
    }
    digests = (before.target.artifact_sha256, after.target.artifact_sha256)
    same = None if None in digests else digests[0] == digests[1]
    return Comparability(tuple(limit for limit in Limit if found[limit]), same)


def _check_list(report: Report) -> list[tuple[str, str]]:
    return [(check.name, check.version) for check in report.checks]


def _complete(report: Report) -> bool:
    return (
        bool(report.doorcheck_version.strip())
        and bool(report.checks)
        and all(
            check.status is Status.COMPLETE and check.version.strip() for check in report.checks
        )
    )


def _capability_key(capability: Capability) -> str:
    return json.dumps(
        [
            capability.kind.value,
            capability.location.path,
            capability.subject,
            sorted(capability.attrs.items()),
        ]
    )


def _finding_key(finding: Finding) -> str:
    # A fingerprint excludes the assessment. Retaining that metadata in the
    # comparison prevents an escalation from disappearing as an unchanged hit.
    return json.dumps(
        [
            finding.fingerprint,
            finding.severity.value,
            finding.confidence.value,
            finding.message_key,
            finding.tool,
            finding.cwe,
            sorted(finding.params.items()),
        ]
    )


def _changes[T: (Capability, Finding)](
    before: tuple[T, ...], after: tuple[T, ...], key: Callable[[T], str]
) -> Changes[T]:
    return Changes(_unmatched(after, before, key), _unmatched(before, after, key))


def _evidence_order(item: Capability | Finding) -> str:
    if isinstance(item, Finding):
        return json.dumps(item.evidence)
    return ""  # pragma: no mutate - the same tie key for every capability


def _unmatched[T: (Capability, Finding)](
    items: tuple[T, ...], baseline: tuple[T, ...], key: Callable[[T], str]
) -> tuple[T, ...]:
    remaining = Counter(key(item) for item in baseline)
    ordered = sorted(
        items,
        key=lambda item: (
            key(item),
            item.location.line,
            item.location.column or 0,
            _evidence_order(item),
        ),
    )
    result = []
    for item in ordered:
        identity = key(item)
        if remaining[identity]:
            remaining[identity] -= 1
        else:
            result.append(item)
    return tuple(result)
