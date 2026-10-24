"""The script that records real tool output for the adapter tests."""

import json
import sys
from collections.abc import Sequence
from pathlib import Path

import pytest

from doorcheck.adapters import Audience, Command, Parsed, ScanInput, load
from doorcheck.adapters.semgrep import Semgrep
from tools import record_tool_output


class Printer:
    name = "printer"
    version = "1.0"
    audience = Audience.USERS
    experimental = False
    executable = sys.executable

    def version_command(self) -> Sequence[str]:
        return (self.executable, "-c", "print('printer 1.0')")

    def command(self, scan: ScanInput, work: Path) -> Command | Parsed:
        if scan.root.name == "skipped":
            return Parsed()
        return Command((self.executable, "-c", "print('[1]')"), scan.root)

    def parse(self, output: bytes, scan: ScanInput) -> Parsed:
        return Parsed()


def test_recording_writes_each_tool_and_case(tmp_path: Path) -> None:
    cases = ("one", "skipped", "two")
    for case in cases:
        (tmp_path / "integrations" / case).mkdir(parents=True)
    written = record_tool_output.record([Printer(), Printer()], tmp_path, cases)
    one, two = f"{tmp_path}/tools/printer/one.json", f"{tmp_path}/tools/printer/two.json"
    assert written == [one, two, one, two]
    assert json.loads((tmp_path / "tools/printer/one.json").read_text()) == [1]


def test_every_registered_tool_is_recorded_semgrep_with_the_fixture_rule() -> None:
    adapters = record_tool_output.adapters(Path("f"))
    assert sorted(a.name for a in adapters) == sorted(load().adapters)
    (semgrep,) = (a for a in adapters if isinstance(a, Semgrep))
    assert semgrep.rules == (Path("f/semgrep/path-join.yaml"),)


def test_recording_main(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls = []

    def fake_record(tools: list[object], fixtures: Path) -> list[str]:
        calls.append((sorted(getattr(t, "name", "") for t in tools), fixtures))
        return ["a/b.json"]

    monkeypatch.setattr(record_tool_output, "record", fake_record)
    assert record_tool_output.main(["--fixtures", str(tmp_path)]) == 0
    assert record_tool_output.main([]) == 0
    names = sorted(load().adapters)
    assert calls == [(names, tmp_path), (names, Path("tests/fixtures"))]
    assert capsys.readouterr().out == "wrote a/b.json\nwrote a/b.json\n"


def test_recording_help(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        record_tool_output.main(["--help"])
    assert "Record what each scanning tool prints for the test fixtures." in capsys.readouterr().out
