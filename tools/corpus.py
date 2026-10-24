"""Load the benchmark corpus and fetch each case at its pinned commit.

Fetched repos are untrusted: hooks are disabled, Git LFS downloads are skipped,
and the checked-out commit must be exactly the pinned one. Nothing is executed.
"""

import os
import re
import subprocess
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from doorcheck.findings import RULE_ID, Location

REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
COMMIT = re.compile(r"[0-9a-f]{40}")
CASE_ID = re.compile(r"[a-z0-9][a-z0-9._-]*")
GITHUB = "https://github.com/{repo}.git"

_CASE_FIELDS = frozenset({"id", "repo", "commit", "kind", "note", "expect"})
_EXPECT_FIELDS = frozenset({"rule", "path", "line"})


class CaseKind(StrEnum):
    VULNERABLE = "vulnerable"
    FIXED = "fixed"
    REFERENCE = "reference"


@dataclass(frozen=True, slots=True)
class Expectation:
    rule: str
    path: str
    line: int


@dataclass(frozen=True, slots=True)
class Case:
    id: str
    repo: str
    commit: str
    kind: CaseKind
    expect: tuple[Expectation, ...] = ()


def load(path: Path) -> tuple[Case, ...]:
    cases = tuple(_case(raw) for raw in tomllib.loads(path.read_text())["case"])
    ids = [c.id for c in cases]
    if len(ids) != len(set(ids)):
        raise ValueError("case ids must be unique")
    # The corpus is public, so a bug only goes in once its fix has shipped.
    fixed = {c.repo for c in cases if c.kind is CaseKind.FIXED}
    unfixed = [c.id for c in cases if c.kind is CaseKind.VULNERABLE and c.repo not in fixed]
    if unfixed:
        raise ValueError(f"vulnerable cases need their fixed release in the corpus: {unfixed}")
    return cases


def _case(raw: Mapping[str, Any]) -> Case:
    unknown = set(raw) - _CASE_FIELDS
    if unknown:
        raise ValueError(f"unknown case fields: {sorted(unknown)}")
    case = Case(
        id=_matching(CASE_ID, raw["id"], "case id"),
        repo=_matching(REPO, raw["repo"], "repo"),
        commit=_matching(COMMIT, raw["commit"], "commit"),
        kind=CaseKind(raw["kind"]),
        expect=tuple(_expectation(e) for e in raw.get("expect", [])),
    )
    if bool(case.expect) != (case.kind is CaseKind.VULNERABLE):
        raise ValueError(f"{case.id}: vulnerable cases, and only they, list expectations")
    return case


def _expectation(raw: Mapping[str, Any]) -> Expectation:
    if set(raw) != _EXPECT_FIELDS:
        raise ValueError(f"expectations need exactly {sorted(_EXPECT_FIELDS)}")
    location = Location(raw["path"], raw["line"])  # same path and line rules as findings
    return Expectation(_matching(RULE_ID, raw["rule"], "rule"), location.path, location.line)


def _matching(pattern: re.Pattern[str], value: object, what: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValueError(f"invalid {what}: {value!r}")
    return value


def fetch(case: Case, cache: Path, url_template: str = GITHUB) -> Path:
    """Check out the case at its pinned commit, reusing a verified cached copy."""
    target = cache / case.id
    if not _at_commit(target, case.commit):
        target.mkdir(parents=True, exist_ok=True)
        _git(target, "init")
        _git(target, "fetch", "--depth", "1", url_template.format(repo=case.repo), case.commit)
        _git(target, "checkout", "FETCH_HEAD")
    if not _at_commit(target, case.commit):
        raise RuntimeError(f"{case.id}: checked-out commit doesn't match the pin")
    return target


def _at_commit(target: Path, commit: str) -> bool:
    # Check for the folder's own .git first: git would otherwise search parent
    # folders and could report a surrounding repository's commit.
    if not (target / ".git").is_dir():
        return False
    try:
        return _git(target, "rev-parse", "HEAD") == commit
    except subprocess.CalledProcessError:
        return False  # initialized but nothing checked out yet


# Safety settings for running git on untrusted repos: no hooks, no Git LFS
# downloads, and never a credential prompt that would hang the run.
SAFE_GIT_ENV = {"GIT_LFS_SKIP_SMUDGE": "1", "GIT_TERMINAL_PROMPT": "0"}
SAFE_GIT_CONFIG = ("-c", "core.hooksPath=/dev/null")  # pragma: no mutate - git keys ignore case


def _git(cwd: Path, *args: str) -> str:
    """Run git in cwd with the safety settings; return its trimmed output."""
    result = subprocess.run(  # noqa: S603 - fixed git command, no shell
        ["git", *SAFE_GIT_CONFIG, *args],  # noqa: S607 - git from PATH, like any developer tool
        cwd=cwd,
        env={**os.environ, **SAFE_GIT_ENV},
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()
