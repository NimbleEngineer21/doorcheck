"""Inertness, hand-authored signal expectations and fail-closed local benchmarking."""

import ast
import copy
import json
import re
from pathlib import Path
from typing import Any

import pytest

from doorcheck.capabilities.model import Capability, Kind
from doorcheck.capabilities.scan import Scanned
from doorcheck.checks import Problem
from doorcheck.findings import Location
from tools import adversarial

pytestmark = pytest.mark.usefixtures("offline")
DATA = adversarial.load()
PAIRS = DATA["pairs"]


def test_manifest_is_complete_and_has_unique_pairs() -> None:
    assert DATA["version"] == 1
    assert len(PAIRS) == 22
    assert len({pair["id"] for pair in PAIRS}) == 22
    referenced = set()
    for pair in PAIRS:
        assert pair["origin"] in DATA["sources"]
        assert pair["note"] and pair["gaps"]
        for variant in ("adversarial", "benign"):
            specimen = pair[variant]
            assert specimen["files"]
            assert len(specimen["files"].values()) == len(set(specimen["files"].values()))
            for logical, name in specimen["files"].items():
                Location(logical, 1)
                assert adversarial.SOURCE_NAME.fullmatch(name)
                source = adversarial.FIXTURES / pair["id"] / variant / name
                assert not source.is_symlink()
                referenced.add(source)
            for expected in specimen["expect"]:
                assert expected["path"] in specimen["files"]
                assert Kind(expected["kind"])
                assert expected["line"] > 0
            assert all(Kind(kind) for kind in specimen["absent"])
    assert referenced == set(adversarial.FIXTURES.rglob("*.txt"))
    assert all(
        source.suffix in {".txt", ".md"}
        for source in adversarial.FIXTURES.rglob("*")
        if source.is_file()
    )


@pytest.mark.parametrize("pair", PAIRS, ids=lambda p: p["id"])
def test_sources_are_non_executing_and_use_only_reserved_network_addresses(
    pair: dict[str, Any],
) -> None:
    for variant in ("adversarial", "benign"):
        for logical, name in pair[variant]["files"].items():
            source = (adversarial.FIXTURES / pair["id"] / variant / name).read_text()
            urls = re.findall(r'https?://([^/\s\'"<>]+)', source)
            assert all(host == "example.invalid" for host in urls)
            if logical.endswith(".py"):
                tree = ast.parse(source)
                assert len(tree.body) == 2
                assert isinstance(tree.body[0], ast.Expr)
                assert isinstance(tree.body[0].value, ast.Constant)
                assert tree.body[0].value.value.startswith("Inert specimen:")
                guard = tree.body[1]
                assert isinstance(guard, ast.If)
                assert isinstance(guard.test, ast.Constant) and guard.test.value is False
                assert guard.orelse == []
            elif logical.endswith(".js"):
                assert source.startswith("// Inert specimen: static reading only.\nif (false) {\n")
                assert source.endswith("\n}\n")
            elif logical.endswith(".pyc"):
                assert source == "INERT-NOT-PYTHON-BYTECODE\n"
            elif logical.endswith(".yaml"):
                assert source.startswith("fixture_only: true\n")
            elif logical == "manifest.json":
                assert json.loads(source)["domain"].startswith("doorcheck_fixture_")


@pytest.mark.parametrize("variant", ["adversarial", "benign"])
@pytest.mark.parametrize("pair", PAIRS, ids=lambda p: p["id"])
def test_every_pair_keeps_its_signal_and_absence_expectations(
    pair: dict[str, Any], variant: str
) -> None:
    row = adversarial.evaluate(pair, variant)
    assert row["pair"] == pair["id"]
    assert row["variant"] == variant
    assert row["matched"] == row["expected"] == len(pair[variant]["expect"])
    assert row["missing"] == row["forbidden"] == row["problems"] == []


def test_observations_in_benign_twins_are_not_false_alarms() -> None:
    rows = adversarial.measure(DATA)
    assert len(rows) == 44
    assert any(row["observations"] for row in rows if row["variant"] == "benign")
    assert {row["variant"] for row in rows} == {"adversarial", "benign"}
    for path, expected in adversarial.outputs(DATA, rows).items():
        assert path.read_bytes() == expected, str(path)
    text = adversarial.markdown(DATA, rows)
    assert "not a malware detection score" in text
    assert "not false alarms" in text
    assert "javascript-data-flow" in text


def test_matches_checks_position_subject_kind_and_attributes() -> None:
    cap = Capability(Kind.WEB_VIEW, Location("probe.py", 4), "/fixture", {"auth": "none"})
    expected = {"kind": "web_view", "subject": "/fixture", "path": "probe.py", "line": 4}
    assert adversarial.matches(expected, cap)
    assert adversarial.matches({**expected, "attrs": {"auth": "none"}}, cap)
    for key, wrong in [
        ("kind", "process"),
        ("subject", "other"),
        ("path", "wrong.py"),
        ("line", 5),
        ("attrs", {"auth": "required"}),
    ]:
        assert not adversarial.matches({**expected, key: wrong}, cap)


def test_missing_and_forbidden_signals_and_scan_problems_are_preserved() -> None:
    pair = copy.deepcopy(PAIRS[0])
    pair["adversarial"]["absent"] = ["process"]
    seen = []

    def scanner(folder: Path) -> Scanned:
        seen.append(folder)
        assert (folder / "probe.py").read_text().startswith('"""Inert specimen:')
        return Scanned(
            (Capability(Kind.PROCESS, Location("probe.py", 1), "x"),),
            (Problem("problem.file_not_readable"),),
        )

    row = adversarial.evaluate(pair, "adversarial", scanner)
    assert row == {
        "pair": "credential-file",
        "variant": "adversarial",
        "expected": 2,
        "matched": 0,
        "observations": 1,
        "missing": pair["adversarial"]["expect"],
        "forbidden": ["process"],
        "problems": ["problem.file_not_readable"],
    }
    assert not seen[0].exists()


@pytest.mark.parametrize(
    "pair_id, variant", [("../outside", "benign"), ("good", "outside"), ("/abs", "benign")]
)
def test_materializer_rejects_bad_identity(tmp_path: Path, pair_id: str, variant: str) -> None:
    with pytest.raises(ValueError, match=r"^invalid specimen identity$"):
        adversarial.materialize({"id": pair_id}, variant, tmp_path)


@pytest.mark.parametrize(
    "source", ["../outside.txt", "/absolute.txt", "00-probe.py", "00-a.txt/child"]
)
def test_materializer_rejects_bad_source_names(tmp_path: Path, source: str) -> None:
    with pytest.raises(ValueError, match=r"^invalid specimen source name$"):
        adversarial.materialize(
            {"id": "good", "benign": {"files": {"probe.py": source}}}, "benign", tmp_path
        )


@pytest.mark.parametrize(
    "logical", ["../outside", "/absolute", "a/../../outside", "a\\outside", "", ".", "bad\0name"]
)
def test_materializer_rejects_target_escape(tmp_path: Path, logical: str) -> None:
    pair = {"id": "good", "benign": {"files": {logical: "00-source.txt"}}}
    with pytest.raises(ValueError):
        adversarial.materialize(pair, "benign", tmp_path)


def test_source_byte_limit_and_links(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixtures = tmp_path / "fixtures"
    folder = fixtures / "good/benign"
    folder.mkdir(parents=True)
    source = folder / "00-source.txt"
    pair = {"id": "good", "benign": {"files": {"data": "00-source.txt"}}}
    monkeypatch.setattr(adversarial, "FIXTURES", fixtures)
    source.write_bytes(b"a" * 100_000)
    target = tmp_path / "output"
    adversarial.materialize(pair, "benign", target)
    assert (target / "data").read_bytes() == b"a" * 100_000
    source.write_bytes(b"a" * 100_001)
    with pytest.raises(ValueError, match=r"^specimen exceeds size limit$"):
        adversarial.materialize(pair, "benign", target)
    source.unlink()
    source.symlink_to(target / "data")
    with pytest.raises(OSError):
        adversarial.materialize(pair, "benign", target)


def test_cli_usage_and_current_reports(capsys: pytest.CaptureFixture[str]) -> None:
    assert adversarial.main([]) == 1
    assert capsys.readouterr().out == "Usage: python -m tools.adversarial --check|--write\n"
    assert adversarial.main(["--bad"]) == 1
    capsys.readouterr()
    assert adversarial.main(["--check"]) == 0
    assert capsys.readouterr().out == (
        "Checked 44 inert specimens; capability expectations match. Detection gaps remain open.\n"
    )


@pytest.mark.parametrize("failure", ["missing", "forbidden", "problems"])
def test_cli_never_updates_a_regressed_baseline(
    failure: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    row = {"pair": "test", "variant": "benign", "missing": [], "forbidden": [], "problems": []}
    row[failure] = ["bad"]
    monkeypatch.setattr(adversarial, "measure", lambda data: [row])
    assert adversarial.main(["--write"]) == 1
    assert capsys.readouterr().out == "Specimen coverage regressions: ['test/benign']\n"


def test_cli_check_is_read_only_and_write_refreshes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    stale, missing = tmp_path / "stale", tmp_path / "missing"
    stale.write_bytes(b"old")
    monkeypatch.setattr(adversarial, "ROOT", tmp_path)
    monkeypatch.setattr(adversarial, "load", lambda: DATA)
    monkeypatch.setattr(
        adversarial, "outputs", lambda data, rows: {stale: b"new", missing: b"created"}
    )
    assert adversarial.main(["--check"]) == 1
    assert capsys.readouterr().out == "Stale specimen reports: ['stale', 'missing']\n"
    assert stale.read_bytes() == b"old" and not missing.exists()
    assert adversarial.main(["--write"]) == 0
    assert capsys.readouterr().out == (
        "Checked 44 inert specimens; capability expectations match. Detection gaps remain open.\n"
    )
    assert stale.read_bytes() == b"new"
    assert missing.read_bytes() == b"created"


def test_open_work_is_documented_and_sources_are_attributed() -> None:
    documentation = (adversarial.ROOT / "docs/adversarial-fixtures.md").read_text()
    for pair in PAIRS:
        assert all(f"| {gap} |" in documentation for gap in pair["gaps"])
    for source in DATA["sources"].values():
        assert source["url"].startswith("https://")
        assert source["note"]


def test_manifest_filename_is_portable(monkeypatch: pytest.MonkeyPatch) -> None:
    from unittest.mock import MagicMock

    root = MagicMock()
    resource = MagicMock()
    root.__truediv__.side_effect = lambda name: {"benchmark/adversarial.json": resource}[name]
    resource.read_bytes.return_value = b'{"version": 1, "pairs": []}'
    monkeypatch.setattr(adversarial, "ROOT", root)
    assert adversarial.load() == {"version": 1, "pairs": []}


def test_generated_report_paths_are_portable() -> None:
    assert set(adversarial.outputs(DATA, adversarial.measure(DATA))) == {
        adversarial.ROOT / "benchmark/adversarial-baseline.json",
        adversarial.ROOT / "docs/adversarial-coverage.md",
    }


def test_materializer_bounds_reads_and_creates_nested_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_read = adversarial.read_regular
    requested = []

    def bounded(path: Path, limit: int) -> bytes:
        requested.append(limit)
        return real_read(path, limit)

    monkeypatch.setattr(adversarial, "read_regular", bounded)
    pair = copy.deepcopy(PAIRS[0])
    source = next(iter(pair["adversarial"]["files"].values()))
    pair["adversarial"]["files"] = {".git/objects/fixture.py": source}
    target = tmp_path / "target"
    adversarial.materialize(pair, "adversarial", target)
    assert (target / ".git/objects/fixture.py").read_bytes() == (
        adversarial.FIXTURES / pair["id"] / "adversarial" / source
    ).read_bytes()
    assert requested == [100_001]


def test_measure_uses_the_supplied_scanner_for_every_specimen() -> None:
    seen = []

    def scanner(folder: Path) -> Scanned:
        seen.append(folder)
        return Scanned((), ())

    rows = adversarial.measure(DATA, scanner)
    assert len(seen) == len(set(seen)) == len(rows) == 44
    assert all(row["matched"] == row["observations"] == 0 for row in rows)
    assert all(
        row["missing"] == PAIRS[index // 2][row["variant"]]["expect"]
        for index, row in enumerate(rows)
    )
    assert all(not folder.exists() for folder in seen)


@pytest.mark.parametrize(
    "logical", ["", ".", "/absolute", "../escape", "a/../../escape", "a\\name", "bad\0name"]
)
def test_target_path_rejects_unsafe_names_before_any_io(logical: str) -> None:
    with pytest.raises(ValueError, match=r"^invalid specimen target path$"):
        adversarial.target_path(logical)


@pytest.mark.parametrize(
    "logical, expected",
    [("probe.py", "probe.py"), (".git/objects/probe.py", ".git/objects/probe.py"), ("a//b", "a/b")],
)
def test_target_path_preserves_relative_components(logical: str, expected: str) -> None:
    assert adversarial.target_path(logical) == Path(expected)
