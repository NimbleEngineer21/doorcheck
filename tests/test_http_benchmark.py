"""Reproducible coverage evidence without fetching or executing source."""

from pathlib import Path
from unittest.mock import patch

import pytest

from doorcheck.capabilities import COMPUTED, Capability, Kind, Scanned
from doorcheck.checks import Problem
from doorcheck.findings import Location
from tools import http_benchmark as evidence
from tools.corpus import Case, CaseKind

CASE = Case("ref-sample", "owner/repo", "a" * 40, CaseKind.REFERENCE, ())


def test_all_reference_cases_and_only_references_are_measured(tmp_path: Path) -> None:
    other = Case("fixed", "owner/repo", "b" * 40, CaseKind.FIXED, ())
    with (
        patch.object(evidence, "fetch", return_value=tmp_path) as fetch,
        patch.object(evidence, "scan", return_value=Scanned((), ())),
    ):
        rows = evidence.measure([CASE, other], tmp_path / "cache")
    fetch.assert_called_once_with(CASE, tmp_path / "cache")
    assert rows == [
        {
            "case": "ref-sample",
            "target": ".",
            "requests": 0,
            "static": 0,
            "computed": 0,
            "problems": [],
        }
    ]


def test_installed_integration_target_and_problem_locations(tmp_path: Path) -> None:
    target = tmp_path / "custom_components"
    target.mkdir()
    caps = (
        Capability(Kind.HTTP_REQUEST, Location("x.py", 1), "example.invalid"),
        Capability(Kind.HTTP_REQUEST, Location("x.py", 2), COMPUTED),
        Capability(Kind.HTTP_REQUEST, Location("x.py", 3), COMPUTED),
        Capability(Kind.NETWORK_HOST, Location("x.py", 1), "example.invalid"),
    )
    problems = (
        Problem("problem.file_not_readable", Location("x.py", 1)),
        Problem("problem.directory_not_readable"),
    )
    with patch.object(evidence, "scan", return_value=Scanned(caps, problems)) as scan:
        row = evidence._case(CASE, tmp_path)
    scan.assert_called_once_with(target)
    assert row == {
        "case": "ref-sample",
        "target": "custom_components",
        "requests": 3,
        "static": 1,
        "computed": 2,
        "problems": [
            {"key": "problem.file_not_readable", "path": "x.py"},
            {"key": "problem.directory_not_readable", "path": None},
        ],
    }
    text = evidence.markdown([row])
    assert "3 supported request-call patterns across 1 reference cases" in text
    assert "1 have a statically named initial authority. 2 coverage problems." in text
    assert "| ref-sample | custom_components | 3 | 1 | 2 | 2 |" in text
    assert "not traffic, malware detections or alarm rates" in text
    assert evidence.markdown([]).endswith("| --- | --- | ---: | ---: | ---: | ---: |\n")


def test_cli_stale_check_and_explicit_regeneration(tmp_path: Path, capsys) -> None:
    baseline, report = tmp_path / "baseline.json", tmp_path / "report.md"
    with (
        patch.object(evidence, "BASELINE", baseline),
        patch.object(evidence, "REPORT", report),
        patch.object(evidence, "load", return_value=(CASE,)) as load,
        patch.object(
            evidence,
            "measure",
            return_value=[
                {
                    "case": "a",
                    "requests": 0,
                    "static": 0,
                    "computed": 0,
                    "target": ".",
                    "problems": [],
                }
            ],
        ) as measure,
    ):
        assert evidence.main(["--check"]) == 1
        assert not baseline.exists() and not report.exists()
        assert evidence.main(["--write"]) == 0
        assert baseline.read_text().startswith('[\n  {\n    "case": "a",\n')
        assert baseline.read_text().endswith("\n")
        import json

        assert json.loads(baseline.read_text())[0]["case"] == "a"
        assert "| a | . | 0 | 0 | 0 | 0 |" in report.read_text()
        assert evidence.main(["--check"]) == 0
        baseline.write_text("changed")
        assert evidence.main(["--check"]) == 1
        assert baseline.read_text() == "changed"
    load.assert_called_with(evidence.ROOT / "benchmark/corpus.toml")
    measure.assert_called_with((CASE,), evidence.ROOT / ".benchmark-cache")
    assert capsys.readouterr().out == (
        "HTTP observation evidence is stale; review before regenerating.\n"
        "Checked 1 pinned reference cases; HTTP source observations match.\n"
        "Checked 1 pinned reference cases; HTTP source observations match.\n"
        "HTTP observation evidence is stale; review before regenerating.\n"
    )


@pytest.mark.parametrize("argv", [[], ["--bad"], ["--check", "--write"]])
def test_cli_requires_explicit_mode(argv: list[str], capsys) -> None:
    with patch.object(evidence, "measure", side_effect=AssertionError("must not scan")):
        assert evidence.main(argv) == 1
    assert capsys.readouterr().out == "Usage: python -m tools.http_benchmark --check|--write\n"
