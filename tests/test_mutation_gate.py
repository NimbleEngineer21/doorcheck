import json
from pathlib import Path

import pytest

from tools.mutation_gate import main, uncaught


def test_counts_survivors() -> None:
    assert uncaught({"total": 5, "killed": 3, "survived": 2}) == 2


def test_counts_mutants_that_were_never_tested() -> None:
    # A broken run reports nothing survived and nothing killed; that must fail.
    assert uncaught({"total": 37, "killed": 0, "survived": 0}) == 37


def test_timeouts_count_as_caught() -> None:
    assert uncaught({"total": 4, "killed": 3, "timeout": 1}) == 0


def test_skipped_mutants_are_excluded() -> None:
    assert uncaught({"total": 4, "killed": 3, "skipped": 1}) == 0


def _write(tmp_path: Path, content: str) -> str:
    path = tmp_path / "stats.json"
    path.write_text(content)
    return str(path)


def test_gate_fails_and_says_how_many(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["gate", _write(tmp_path, json.dumps({"total": 4, "killed": 3}))]) == 1
    assert capsys.readouterr().out == (
        "1 mutant(s) not caught by any test. Run `mutmut browse` to see them.\n"
    )


def test_gate_passes_and_says_so(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["gate", _write(tmp_path, json.dumps({"total": 4, "killed": 4}))]) == 0
    assert capsys.readouterr().out == "All 4 mutants caught.\n"


@pytest.mark.parametrize(
    "content",
    [json.dumps({"killed": 4}), "not json", json.dumps({"total": "4", "killed": 4})],
    ids=["missing-total", "invalid-json", "wrong-type"],
)
def test_gate_fails_closed_on_bad_stats(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], content: str
) -> None:
    assert main(["gate", _write(tmp_path, content)]) == 1
    assert capsys.readouterr().out.startswith("Mutation stats missing or unreadable")


def test_gate_fails_closed_when_stats_file_is_absent(tmp_path: Path) -> None:
    assert main(["gate", str(tmp_path / "absent.json")]) == 1


def test_gate_reads_the_default_stats_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    stats_dir = tmp_path / "mutants"
    stats_dir.mkdir()
    (stats_dir / "mutmut-cicd-stats.json").write_text(json.dumps({"total": 1, "killed": 1}))
    monkeypatch.chdir(tmp_path)
    assert main(["gate"]) == 0
