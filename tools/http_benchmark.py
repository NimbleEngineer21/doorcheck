"""Reproducible source-observation counts on every pinned reference case.

Integration targets are custom_components (the installed code), excluding the
checkout's generated Git database. Card targets are their source folders.
No source, dependency, session or request is executed.
"""

import json
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from doorcheck.capabilities import COMPUTED, Kind, scan
from tools.corpus import Case, CaseKind, fetch, load

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "benchmark/http-observations.json"
REPORT = ROOT / "docs/http-observations-coverage.md"
TEMPLATE = ROOT / "tools/templates/http-observations.md"


def measure(cases: Iterable[Case], cache: Path) -> list[dict[str, Any]]:
    rows = []
    for case in cases:
        if case.kind is CaseKind.REFERENCE:
            rows.append(_case(case, fetch(case, cache)))
    return rows


def _case(case: Case, folder: Path) -> dict[str, Any]:
    installed = folder / "custom_components"
    target = installed if installed.is_dir() else folder
    result = scan(target)
    calls = [c for c in result.capabilities if c.kind is Kind.HTTP_REQUEST]
    return {
        "case": case.id,
        "target": target.relative_to(folder).as_posix(),
        "requests": len(calls),
        "static": sum(c.subject != COMPUTED for c in calls),
        "computed": sum(c.subject == COMPUTED for c in calls),
        "problems": [
            {"key": p.key, "path": p.location.path if p.location else None} for p in result.problems
        ],
    }


def markdown(rows: list[dict[str, Any]]) -> str:
    calls = sum(r["requests"] for r in rows)
    static = sum(r["static"] for r in rows)
    gaps = sum(len(r["problems"]) for r in rows)
    text = TEMPLATE.read_text().format(calls=calls, cases=len(rows), static=static, gaps=gaps)
    for row in rows:
        text += (
            f"| {row['case']} | {row['target']} | {row['requests']} | {row['static']} "
            f"| {row['computed']} | {len(row['problems'])} |\n"
        )
    return text


def main(argv: list[str]) -> int:
    if argv not in (["--check"], ["--write"]):
        print("Usage: python -m tools.http_benchmark --check|--write")
        return 1
    rows = measure(load(ROOT / "benchmark/corpus.toml"), ROOT / ".benchmark-cache")
    outputs = {BASELINE: json.dumps(rows, indent=2) + "\n", REPORT: markdown(rows)}
    stale = [
        path for path, text in outputs.items() if not path.exists() or path.read_text() != text
    ]
    if argv == ["--write"]:
        for path, text in outputs.items():
            path.write_text(text)
    elif stale:
        print("HTTP observation evidence is stale; review before regenerating.")
        return 1
    print(f"Checked {len(rows)} pinned reference cases; HTTP source observations match.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
