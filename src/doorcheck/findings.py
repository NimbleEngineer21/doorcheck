"""The finding: one observation about scanned code, shared by every surface.

Findings carry string keys, never display text, so every surface renders them
from the same translated catalog. Every field is validated here, so any way of
building a finding (a scanner, a loaded report) gets the same checks.
"""

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import PurePosixPath
from types import MappingProxyType

RULE_ID = re.compile(r"[a-z0-9]+(?:[./-][a-z0-9]+)*")
MESSAGE_KEY = re.compile(r"[a-z0-9_]+(?:\.[a-z0-9_]+)+")
PARAM_NAME = re.compile(r"[a-z][a-z0-9_]*")
MAX_EVIDENCE = 300
MAX_PARAM = 200


class Severity(StrEnum):
    """Ordered from most to least urgent."""

    SERIOUS = "serious"
    REVIEW = "review"
    NOTICE = "notice"
    INFO = "info"

    @property
    def rank(self) -> int:
        """0 is the most urgent, for sorting."""
        return list(Severity).index(self)


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


def require(condition: object, message: str) -> None:
    if not condition:
        raise ValueError(message)


def is_int(value: object) -> bool:
    """True for real integers; bool is excluded even though it subclasses int."""
    return isinstance(value, int) and not isinstance(value, bool)


def is_optional_str(value: object) -> bool:
    return value is None or isinstance(value, str)


@dataclass(frozen=True, slots=True)
class Location:
    """A position in the scanned files, relative to the scanned root."""

    path: str
    line: int
    column: int | None = None

    def __post_init__(self) -> None:
        require(isinstance(self.path, str), "path must be a string")
        parts = PurePosixPath(self.path).parts
        inside = bool(parts) and parts[0] != "/" and ".." not in parts
        plain = "\\" not in self.path and "\0" not in self.path
        require(inside and plain, f"path escapes root: {self.path!r}")
        require(is_int(self.line) and self.line >= 1, "line must be an integer from 1")
        column_ok = self.column is None or (is_int(self.column) and self.column >= 1)
        require(column_ok, "column must be an integer from 1")


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    severity: Severity
    confidence: Confidence
    location: Location
    message_key: str
    tool: str
    cwe: int | None = None
    evidence: str | None = None
    params: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        require(_matches(RULE_ID, self.rule_id), f"invalid rule id: {self.rule_id!r}")
        require(_matches(MESSAGE_KEY, self.message_key), f"not a key: {self.message_key!r}")
        require(isinstance(self.severity, Severity), "severity must be a Severity")
        require(isinstance(self.confidence, Confidence), "confidence must be a Confidence")
        require(isinstance(self.location, Location), "location must be a Location")
        require(isinstance(self.tool, str) and self.tool, "tool is required")
        require(self.cwe is None or (is_int(self.cwe) and self.cwe > 0), "cwe must be positive")
        require(is_optional_str(self.evidence), "evidence must be a string")
        require(len(self.evidence or "") <= MAX_EVIDENCE, "evidence too long")
        check_params(self.params)
        # A read-only copy, so nobody can change a frozen finding through the mapping.
        object.__setattr__(self, "params", MappingProxyType(dict(self.params)))

    @property
    def fingerprint(self) -> str:
        """The same for the same finding in another version of the code: line numbers
        and spacing are left out, so moved or reformatted code keeps its fingerprint."""
        what = " ".join((self.evidence or "").split()) or sorted(self.params.items())
        text = json.dumps([self.rule_id, self.location.path, what])
        return hashlib.sha256(text.encode()).hexdigest()[:16]


def _matches(pattern: re.Pattern[str], value: object) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def check_params(params: object) -> None:
    if not isinstance(params, Mapping):
        raise ValueError("params must be a mapping")
    for name, value in params.items():
        require(_matches(PARAM_NAME, name), f"invalid parameter name: {name!r}")
        require(isinstance(value, str) and len(value) <= MAX_PARAM, f"invalid value: {name!r}")


def sort_key(finding: Finding) -> tuple[int, str, int, str]:
    """Most urgent first, then by file, line and rule."""
    loc = finding.location
    return (finding.severity.rank, loc.path, loc.line, finding.rule_id)


def clip(text: str, limit: int) -> str:
    """Untrusted text, shortened to fit a field."""
    return text if len(text) <= limit else text[: limit - 1] + "…"


def evidence(text: str) -> str:
    return clip(text.strip(), MAX_EVIDENCE)


def param(text: str) -> str:
    return clip(text.strip(), MAX_PARAM)
