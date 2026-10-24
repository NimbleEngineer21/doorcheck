import re
from collections.abc import Iterator
from pathlib import Path

import pytest

from doorcheck.findings import Finding, Location, Severity
from tests.conftest import make_finding, make_repo
from tools import benchmark
from tools.benchmark import (
    RuleScore,
    dump_scores,
    load_scores,
    markdown,
    regressions,
    run,
    score_case,
)
from tools.corpus import Case, CaseKind, Expectation

RULE = "ha-reads-credential-store"
VULN = Case(
    id="vuln",
    repo="o/vuln",
    commit="a" * 40,
    kind=CaseKind.VULNERABLE,
    expect=(Expectation(RULE, "a.py", 3), Expectation(RULE, "b.py", 7)),
)
FIXED = Case(id="fixed", repo="o/fixed", commit="b" * 40, kind=CaseKind.FIXED)
REFERENCE = Case(id="ref", repo="o/ref", commit="c" * 40, kind=CaseKind.REFERENCE)


def _at(path: str, line: int, severity: Severity = Severity.REVIEW) -> Finding:
    return make_finding(location=Location(path, line), severity=severity)


def test_planted_hit_and_miss_are_scored_correctly() -> None:
    scores: dict[str, RuleScore] = {}
    # Finds the first expected bug, misses the second, and adds an unrelated finding.
    score_case(VULN, [_at("a.py", 3), _at("c.py", 1)], scores)
    assert scores == {RULE: RuleScore(caught=1, missed=1, false_alarms=0)}


def test_right_file_wrong_line_is_a_miss() -> None:
    scores: dict[str, RuleScore] = {}
    score_case(VULN, [_at("a.py", 4), _at("b.py", 7)], scores)
    assert scores[RULE] == RuleScore(caught=1, missed=1)


def test_wrong_rule_at_the_right_place_is_a_miss() -> None:
    scores: dict[str, RuleScore] = {}
    score_case(VULN, [make_finding(rule_id="other", location=Location("a.py", 3))], scores)
    assert scores[RULE] == RuleScore(caught=0, missed=2)


@pytest.mark.parametrize("case", [FIXED, REFERENCE], ids=["fixed", "reference"])
def test_serious_and_review_on_clean_code_are_false_alarms(case: Case) -> None:
    scores: dict[str, RuleScore] = {}
    found = [
        _at("a.py", 1, Severity.SERIOUS),
        _at("a.py", 2, Severity.REVIEW),
        _at("a.py", 3, Severity.NOTICE),
        _at("a.py", 4, Severity.INFO),
    ]
    score_case(case, found, scores)
    assert scores == {RULE: RuleScore(false_alarms=2)}


def test_run_scores_every_case_through_the_checkout() -> None:
    seen: list[str] = []

    def checkout(case: Case) -> Path:
        seen.append(case.id)
        return Path(case.id)

    def scanner(folder: Path) -> Iterator[Finding]:
        if folder.name == "vuln":
            yield _at("a.py", 3)
        if folder.name == "fixed":
            yield _at("x.py", 1)

    scores = run([VULN, FIXED, REFERENCE], scanner, checkout)
    assert seen == ["vuln", "fixed", "ref"]
    assert scores == {RULE: RuleScore(caught=1, missed=1, false_alarms=1)}


def test_scores_are_sorted_by_rule() -> None:
    def scanner(folder: Path) -> list[Finding]:
        return [make_finding(rule_id="zeta"), make_finding(rule_id="alpha")]

    assert list(run([FIXED], scanner, lambda c: Path(c.id))) == ["alpha", "zeta"]


def test_regressions_flag_weaker_and_noisier_rules() -> None:
    baseline = {"a": RuleScore(caught=3, false_alarms=1), "b": RuleScore(caught=2)}
    scores = {"a": RuleScore(caught=2, false_alarms=2)}
    assert regressions(scores, baseline) == [
        "a: caught 2, baseline 3",
        "a: 2 false alarms, baseline 1",
        "b: caught 0, baseline 2",
    ]


def test_new_rules_may_not_add_false_alarms() -> None:
    scores = {"new": RuleScore(caught=1, false_alarms=1), "clean": RuleScore(caught=1)}
    assert regressions(scores, {}) == ["new: new rule with 1 false alarms"]


def test_equal_or_better_scores_pass() -> None:
    baseline = {"a": RuleScore(caught=2, false_alarms=1)}
    assert regressions({"a": RuleScore(caught=3, false_alarms=0)}, baseline) == []
    assert regressions({"a": RuleScore(caught=2, false_alarms=1)}, baseline) == []


def test_a_rule_missing_from_the_baseline_counts_from_zero() -> None:
    table = markdown({"new": RuleScore(caught=1, missed=2, false_alarms=3)}, {})
    assert table.splitlines()[-1] == "| new | 1 (+1) | 2 | 3 (+3) |"


def test_markdown_shows_changes_against_the_baseline() -> None:
    scores = {"a": RuleScore(caught=3, missed=1, false_alarms=0), "b": RuleScore(caught=1)}
    baseline = {"a": RuleScore(caught=2, false_alarms=1), "b": RuleScore(caught=1)}
    assert markdown(scores, baseline) == (
        "| Rule | Caught | Missed | False alarms |\n"
        "| --- | --- | --- | --- |\n"
        "| a | 3 (+1) | 1 | 0 (-1) |\n"
        "| b | 1 | 0 | 0 |\n"
    )


def test_scores_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    scores = {"a": RuleScore(caught=1, missed=2, false_alarms=3)}
    path.write_text(dump_scores(scores))
    assert load_scores(path) == scores


# --- end to end, against local repos ------------------------------------------


def planted_scanner(folder: Path) -> list[Finding]:
    """Finds the bug wherever the file still contains it."""
    source = folder / "a.py"
    if source.exists() and "bug" in source.read_text():
        return [_at("a.py", 1)]
    return []


def weaker_scanner(folder: Path) -> list[Finding]:
    return []


def _corpus(tmp_path: Path) -> Path:
    vulnerable = make_repo(tmp_path / "remote", "o/demo", {"a.py": "bug\n"})
    fixed = make_repo(tmp_path / "remote", "o/demo", {"a.py": "fine\n"})
    corpus = tmp_path / "corpus.toml"
    corpus.write_text(
        f'[[case]]\nid = "v"\nrepo = "o/demo"\ncommit = "{vulnerable}"\nkind = "vulnerable"\n'
        f'[[case.expect]]\nrule = "{RULE}"\npath = "a.py"\nline = 1\n\n'
        f'[[case]]\nid = "f"\nrepo = "o/demo"\ncommit = "{fixed}"\nkind = "fixed"\n'
    )
    return corpus


def test_end_to_end_baseline_then_regression(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(benchmark, "fetch", _local_fetch(tmp_path))
    corpus, baseline = _corpus(tmp_path), tmp_path / "baseline.json"
    common = ["--corpus", str(corpus), "--baseline", str(baseline), "--cache", str(tmp_path / "c")]

    assert (
        benchmark.main(["tests.test_benchmark:planted_scanner", *common, "--update-baseline"]) == 0
    )
    assert load_scores(baseline) == {RULE: RuleScore(caught=1)}

    summary = tmp_path / "summary.md"
    args = ["tests.test_benchmark:weaker_scanner", *common, "--markdown", str(summary)]
    assert benchmark.main(args) == 1
    assert f"Regression: {RULE}: caught 0, baseline 1" in capsys.readouterr().out
    assert f"| {RULE} | 0 (-1) | 1 | 0 |" in summary.read_text()


def test_a_missing_baseline_fails_instead_of_passing_everything(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(benchmark, "fetch", _local_fetch(tmp_path))
    args = ["tests.test_benchmark:planted_scanner", "--corpus", str(_corpus(tmp_path))]
    args += ["--baseline", str(tmp_path / "none.json"), "--cache", str(tmp_path / "c")]
    with pytest.raises(FileNotFoundError, match=r"^no baseline at .*none\.json; record one with"):
        benchmark.main(args)
    assert not (tmp_path / "none.json").exists()


def _with_baseline(tmp_path: Path) -> list[str]:
    args = ["--corpus", str(_corpus(tmp_path)), "--baseline", str(tmp_path / "baseline.json")]
    args += ["--cache", str(tmp_path / "c")]
    benchmark.main(["tests.test_benchmark:planted_scanner", *args, "--update-baseline"])
    return args


def test_end_to_end_passes_and_writes_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(benchmark, "fetch", _local_fetch(tmp_path))
    results = tmp_path / "results.json"
    args = ["tests.test_benchmark:planted_scanner", *_with_baseline(tmp_path)]
    assert benchmark.main([*args, "--json", str(results)]) == 0
    assert load_scores(results) == {RULE: RuleScore(caught=1)}


def _local_fetch(tmp_path: Path):  # type: ignore[no-untyped-def]
    from tools.corpus import fetch

    return lambda case, cache: fetch(case, cache, f"file://{tmp_path}/remote/{{repo}}")


def test_two_catches_of_one_rule_in_one_case_both_count() -> None:
    scores: dict[str, RuleScore] = {}
    score_case(VULN, [_at("a.py", 3), _at("b.py", 7)], scores)
    assert scores[RULE] == RuleScore(caught=2, missed=0)


def test_baseline_file_is_stable_and_readable_in_diffs() -> None:
    text = dump_scores({"a": RuleScore(caught=1, missed=0, false_alarms=2)})
    assert text == (
        '{\n  "a": {\n    "caught": 1,\n    "missed": 0,\n    "false_alarms": 2\n  }\n}\n'
    )


@pytest.mark.parametrize("spec", ["no_colon", "a:b:c", ":func", "mod:"])
def test_scanner_spec_must_be_module_colon_function(spec: str) -> None:
    with pytest.raises(ValueError, match=r"^scanner must look like module:function, got "):
        benchmark.load_scanner(spec)


def test_scanner_spec_loads_the_named_function(tmp_path: Path) -> None:
    scanner = benchmark.load_scanner("tests.test_benchmark:planted_scanner")
    (tmp_path / "a.py").write_text("bug\n")
    assert [f.location.path for f in scanner(tmp_path)] == ["a.py"]


def test_cli_defaults_point_at_the_committed_corpus() -> None:
    args = benchmark._parser().parse_args(["mod:func"])
    assert args.corpus == Path("benchmark/corpus.toml")
    assert args.baseline == Path("benchmark/baseline.json")
    assert args.cache == Path(".benchmark-cache")
    assert (args.json, args.markdown, args.update_baseline) == (None, None, False)


def test_cli_help_explains_the_scanner_argument(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        benchmark._parser().parse_args(["--help"])
    out = capsys.readouterr().out
    assert out.startswith("usage: python -m tools.benchmark ")
    assert re.search(r"\n  scanner +module:function returning findings for a folder\n", out)


def test_end_to_end_prints_the_summary_table(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(benchmark, "fetch", _local_fetch(tmp_path))
    args = ["tests.test_benchmark:planted_scanner", *_with_baseline(tmp_path)]
    capsys.readouterr()
    assert benchmark.main(args) == 0
    scores = {RULE: RuleScore(caught=1)}
    assert capsys.readouterr().out == markdown(scores, scores) + "\n"


def test_no_findings_scanner_reports_nothing(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("bug\n")
    assert benchmark.no_findings(tmp_path) == []
