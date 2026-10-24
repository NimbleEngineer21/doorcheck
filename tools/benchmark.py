"""Score a scanner against the benchmark corpus and guard against regressions.

Usage:
    python -m tools.benchmark <module:function> [--corpus PATH] [--baseline PATH]
        [--cache DIR] [--json PATH] [--markdown PATH] [--update-baseline]

The scanner is any function taking a checked-out folder and returning findings.
The run fails if any rule catches fewer cases, or raises more false alarms, than
the stored baseline: a weaker rule can't merge quietly.
"""

import argparse
import importlib
import json
import sys
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass
from pathlib import Path

from doorcheck.findings import Finding, Severity
from tools.corpus import Case, CaseKind, fetch, load

Scanner = Callable[[Path], Iterable[Finding]]

# Only these severities count as alarms; Notice and Info are capabilities, not claims.
ALARMS = frozenset({Severity.SERIOUS, Severity.REVIEW})


@dataclass
class RuleScore:
    caught: int = 0
    missed: int = 0
    false_alarms: int = 0


def score_case(case: Case, findings: Iterable[Finding], scores: dict[str, RuleScore]) -> None:
    found = list(findings)
    if case.kind is CaseKind.VULNERABLE:
        _score_expectations(case, found, scores)
    else:
        for finding in found:
            if finding.severity in ALARMS:
                scores.setdefault(finding.rule_id, RuleScore()).false_alarms += 1


def _score_expectations(case: Case, found: list[Finding], scores: dict[str, RuleScore]) -> None:
    hits = {(f.rule_id, f.location.path, f.location.line) for f in found}
    for expected in case.expect:
        score = scores.setdefault(expected.rule, RuleScore())
        if (expected.rule, expected.path, expected.line) in hits:
            score.caught += 1
        else:
            score.missed += 1


def run(
    cases: Iterable[Case], scanner: Scanner, checkout: Callable[[Case], Path]
) -> dict[str, RuleScore]:
    scores: dict[str, RuleScore] = {}
    for case in cases:
        score_case(case, scanner(checkout(case)), scores)
    return dict(sorted(scores.items()))


def regressions(scores: dict[str, RuleScore], baseline: dict[str, RuleScore]) -> list[str]:
    """Rules that now catch less, or alarm more, than the baseline allows."""
    problems = []
    for rule, before in baseline.items():
        now = scores.get(rule, RuleScore())
        if now.caught < before.caught:
            problems.append(f"{rule}: caught {now.caught}, baseline {before.caught}")
        if now.false_alarms > before.false_alarms:
            problems.append(
                f"{rule}: {now.false_alarms} false alarms, baseline {before.false_alarms}"
            )
    for rule in scores.keys() - baseline.keys():
        if scores[rule].false_alarms:
            problems.append(f"{rule}: new rule with {scores[rule].false_alarms} false alarms")
    return problems


def markdown(scores: dict[str, RuleScore], baseline: dict[str, RuleScore]) -> str:
    rows = ["| Rule | Caught | Missed | False alarms |", "| --- | --- | --- | --- |"]
    for rule, now in scores.items():
        before = baseline.get(rule, RuleScore())
        rows.append(
            f"| {rule} | {_delta(now.caught, before.caught)} | {now.missed} "
            f"| {_delta(now.false_alarms, before.false_alarms)} |"
        )
    return "\n".join(rows) + "\n"


def _delta(now: int, before: int) -> str:
    return str(now) if now == before else f"{now} ({now - before:+d})"


def load_scores(path: Path) -> dict[str, RuleScore]:
    """A missing baseline is an error: comparing against nothing would pass any rule."""
    if not path.exists():
        raise FileNotFoundError(f"no baseline at {path}; record one with --update-baseline")
    return {rule: RuleScore(**counts) for rule, counts in json.loads(path.read_text()).items()}


def dump_scores(scores: dict[str, RuleScore]) -> str:
    return json.dumps({rule: asdict(s) for rule, s in scores.items()}, indent=2) + "\n"


def no_findings(folder: Path) -> list[Finding]:
    """A scanner that reports nothing: checks every pinned case can still be fetched."""
    return []


def load_scanner(spec: str) -> Scanner:
    parts = spec.split(":")
    if len(parts) != 2 or not all(parts):
        raise ValueError(f"scanner must look like module:function, got {spec!r}")
    scanner: Scanner = getattr(importlib.import_module(parts[0]), parts[1])
    return scanner


def main(argv: list[str]) -> int:
    args = _parser().parse_args(argv)
    cases = load(args.corpus)
    scores = run(cases, load_scanner(args.scanner), lambda case: fetch(case, args.cache))
    if args.update_baseline:
        args.baseline.write_text(dump_scores(scores))
        return 0
    baseline = load_scores(args.baseline)
    _write(args.json, dump_scores(scores))
    _write(args.markdown, markdown(scores, baseline))
    problems = regressions(scores, baseline)
    for problem in problems:
        print(f"Regression: {problem}")
    print(markdown(scores, baseline))
    return 1 if problems else 0


def _write(path: Path | None, text: str) -> None:
    if path is not None:
        path.write_text(text)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m tools.benchmark")
    parser.add_argument("scanner", help="module:function returning findings for a folder")
    parser.add_argument("--corpus", type=Path, default=Path("benchmark/corpus.toml"))
    parser.add_argument("--baseline", type=Path, default=Path("benchmark/baseline.json"))
    parser.add_argument("--cache", type=Path, default=Path(".benchmark-cache"))
    parser.add_argument("--json", type=Path)
    parser.add_argument("--markdown", type=Path)
    parser.add_argument("--update-baseline", action="store_true")
    return parser


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
