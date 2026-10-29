"""Group reported host evidence without inferring traffic, ownership or purpose."""

from dataclasses import dataclass

from doorcheck.capabilities.model import COMPUTED, Capability, Kind
from doorcheck.report import Report

KINDS = (Kind.NETWORK_HOST, Kind.HTTP_REQUEST, Kind.HA_FRONTEND_SCRIPT)


@dataclass(frozen=True, slots=True)
class Evidence:
    mentions: tuple[Capability, ...]
    requests: tuple[Capability, ...]
    frontend_scripts: tuple[Capability, ...]


@dataclass(frozen=True, slots=True)
class Host:
    subject: str
    evidence: Evidence


@dataclass(frozen=True, slots=True)
class HostSummary:
    report: Report
    hosts: tuple[Host, ...]
    unresolved: Evidence


def summarize(report: Report) -> HostSummary:
    """Group exact subject strings and retain the original report and coverage.

    Host subjects are already bounded source observations, not validated DNS or
    proof of an outside destination. Case, Unicode spelling and duplicates are
    retained; no public-suffix, DNS or ownership lookup is performed.
    """
    grouped: dict[str, list[Capability]] = {}
    unresolved = []
    for capability in report.capabilities:
        if capability.kind not in KINDS:
            continue
        if _unresolved(capability):
            unresolved.append(capability)
        else:
            grouped.setdefault(capability.subject, []).append(capability)
    return HostSummary(
        report,
        tuple(Host(subject, _evidence(grouped[subject])) for subject in sorted(grouped)),
        _evidence(unresolved),
    )


def _unresolved(capability: Capability) -> bool:
    return capability.subject in (COMPUTED, "") or (
        capability.kind is not Kind.NETWORK_HOST and capability.attrs.get("destination") != "static"
    )


def _order(
    capability: Capability,
) -> tuple[str, int, tuple[int, ...], tuple[tuple[str, str], ...], str]:
    loc = capability.location
    column = () if loc.column is None else (loc.column,)
    return loc.path, loc.line, column, tuple(sorted(capability.attrs.items())), capability.subject


def _evidence(capabilities: list[Capability]) -> Evidence:
    return Evidence(
        *(tuple(sorted((c for c in capabilities if c.kind is kind), key=_order)) for kind in KINDS)
    )
