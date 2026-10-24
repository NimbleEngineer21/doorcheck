"""Every regular expression in doorcheck runs on text from scanned code or tool
output, so each must reject long, almost-matching text in linear time.

Patterns are checked the way the code uses them. `search` tries every start
position, so it is checked for the patterns the code searches with, found by
reading the source."""

import importlib
import pkgutil
import re
import time
from pathlib import Path

import pytest

import doorcheck

SECONDS = 0.5  # a backtracking pattern takes minutes on these inputs, a linear one milliseconds
CHARACTERS = " a1.-_,:=<>[]/+*!#@\\\"'"
SOURCE = Path(doorcheck.__file__).parent


def searched() -> set[str]:
    """Module-level patterns the code calls search, finditer, findall or sub on."""
    found = set()
    for path in SOURCE.rglob("*.py"):
        module = "doorcheck." + ".".join(path.relative_to(SOURCE).with_suffix("").parts)
        names = re.findall(
            r"\b([A-Z][A-Z0-9_]*)\.(?:search|finditer|findall|sub)\(", path.read_text()
        )
        found |= {f"{module}.{name}" for name in names}
    return found


SEARCHED = searched()


def patterns() -> list[tuple[str, re.Pattern[str]]]:
    found = []
    for module in pkgutil.walk_packages(doorcheck.__path__, "doorcheck."):
        loaded = importlib.import_module(module.name)
        for name, value in vars(loaded).items():
            if isinstance(value, re.Pattern) and value.pattern:
                found.append((f"{module.name}.{name}", value))
    return found


def hostile_inputs() -> list[str]:
    runs = [c * 50_000 for c in CHARACTERS]
    pairs = [(a + b) * 25_000 for a in "a1 .-," for b in " .-,=["]
    return [text + end for text in runs + pairs for end in ("", "!", "\0")] + [
        "a" + run for run in runs
    ]


def test_patterns_are_found() -> None:
    names = {name for name, _ in patterns()}
    assert {"doorcheck.findings.RULE_ID", "doorcheck.findings.MESSAGE_KEY"} <= names


@pytest.mark.parametrize(
    ("name", "pattern"), patterns(), ids=lambda p: p if isinstance(p, str) else ""
)
def test_pattern_runs_in_linear_time(name: str, pattern: re.Pattern[str]) -> None:
    for text in hostile_inputs():
        start = time.perf_counter()
        pattern.fullmatch(text)
        pattern.match(text)
        if name in SEARCHED:
            pattern.search(text)
        took = time.perf_counter() - start
        assert took < SECONDS, f"{name} took {took:.1f} s on {text[:20]!r}… ({len(text)} chars)"
