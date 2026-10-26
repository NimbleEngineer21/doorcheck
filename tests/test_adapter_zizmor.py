"""zizmor: parsing its output, and output recorded from the real tool."""

from pathlib import Path
from typing import Any

import pytest

from doorcheck.adapters import Audience, Command, Parsed, load
from doorcheck.adapters.zizmor import Zizmor
from doorcheck.findings import Confidence, Location, Severity
from tests.adapters_support import (
    UNSAFE,
    as_recorded,
    at,
    dump,
    only,
    recorded,
    summary,
)

pytestmark = pytest.mark.usefixtures("offline")


def test_zizmor_is_registered_for_authors() -> None:
    adapter = load().adapters["zizmor"]
    assert isinstance(adapter, Zizmor)
    assert (adapter.version, adapter.audience, adapter.experimental) == (
        "1.31.1",
        Audience.AUTHORS,
        False,
    )


def zizmor_item(
    severity: str = "Low", confidence: str = "Low", feature: str = "x"
) -> dict[str, Any]:
    def location(kind: str, row: int) -> dict[str, Any]:
        return {
            "symbolic": {"key": {"Local": {"verbatim_path": "./w.yml"}}, "kind": kind},
            "concrete": {
                "location": {"start_point": {"row": row, "column": 4}},
                "feature": feature,
            },
        }

    return {
        "ident": "demo-audit",
        "desc": "a description",
        "determinations": {"severity": severity, "confidence": confidence},
        "locations": [location("Related", 0), location("Primary", 7)],
    }


@pytest.mark.parametrize(
    ("severity", "confidence", "expected"),
    [
        ("High", "High", (Severity.SERIOUS, Confidence.HIGH)),
        ("Medium", "Medium", (Severity.REVIEW, Confidence.MEDIUM)),
        ("Low", "Low", (Severity.NOTICE, Confidence.LOW)),
        ("Informational", "Unknown", (Severity.INFO, Confidence.LOW)),
        ("Unknown", "Low", (Severity.REVIEW, Confidence.LOW)),
    ],
)
def test_zizmor_determinations(
    tmp_path: Path, severity: str, confidence: str, expected: tuple[Severity, Confidence]
) -> None:
    finding = only(Zizmor().parse(dump([zizmor_item(severity, confidence)]), at(tmp_path)))
    assert (finding.severity, finding.confidence) == expected


def test_zizmor_uses_the_primary_location(tmp_path: Path) -> None:
    finding = only(Zizmor().parse(dump([zizmor_item(feature="  ")]), at(tmp_path)))
    assert finding.location == Location("w.yml", 8, 5)
    assert finding.evidence is None
    assert finding.params == {"message": "a description"}
    assert (finding.rule_id, finding.tool, finding.message_key) == (
        "zizmor/demo-audit",
        "zizmor",
        "finding.tool_reported",
    )


@pytest.mark.parametrize("output", [b"", b"  \n"])
def test_zizmor_with_nothing_to_audit(tmp_path: Path, output: bytes) -> None:
    (tmp_path / ".github").mkdir()
    (tmp_path / ".github" / "notes.md").write_text("")
    assert Zizmor().parse(output, at(tmp_path)) == Parsed()


@pytest.mark.parametrize("name", ["workflows/ci.yml", "workflows/ci.yaml", "dependabot.yml"])
def test_zizmor_auditing_nothing_when_there_are_workflows_fails(tmp_path: Path, name: str) -> None:
    (tmp_path / ".github" / name).parent.mkdir(parents=True)
    (tmp_path / ".github" / name).write_text("on: push")
    with pytest.raises(
        ValueError, match=r"^zizmor audited nothing, but the repo has workflow files$"
    ):
        Zizmor().parse(b"", at(tmp_path))


def test_zizmor_paths_given_absolute(tmp_path: Path) -> None:
    item = zizmor_item()
    item["locations"][1]["symbolic"]["key"]["Local"]["verbatim_path"] = str(tmp_path / "w.yml")
    assert only(Zizmor().parse(dump([item]), at(tmp_path))).location.path == "w.yml"


def test_zizmor_ignores_the_repos_own_config_and_ignores(tmp_path: Path) -> None:
    assert Zizmor().command(at(tmp_path), tmp_path) == Parsed()
    (tmp_path / ".github").mkdir()
    command = Zizmor("/opt/zizmor").command(at(tmp_path), tmp_path / "w")
    assert not isinstance(command, Parsed)
    assert command.argv == (
        "/opt/zizmor", "--format", "json-v1", "--offline", "--no-exit-codes", "--no-progress",
        "--collect=all", "--no-config", "--no-ignores", ".",
    )  # fmt: skip
    assert command.cwd == tmp_path
    assert command.ok_exit_codes == {0, 3}  # 3: nothing to audit
    assert Zizmor().version_command() == ("zizmor", "--version")


# --- recorded output ---------------------------------------------------------------


def test_zizmor_ignores_the_scanned_repos_own_config_and_ignore_comments() -> None:
    assert "template-injection" in (UNSAFE / ".github" / "zizmor.yml").read_text()
    assert (
        "zizmor: ignore[template-injection]"
        in (UNSAFE / ".github/workflows/triage.yml").read_text()
    )
    parsed = Zizmor().parse(recorded("zizmor", "unsafe"), as_recorded(UNSAFE))
    workflow = ".github/workflows/triage.yml"
    assert summary(parsed.findings) == [
        ("zizmor/excessive-permissions", Severity.REVIEW, Confidence.MEDIUM, workflow, 6, 3),
        ("zizmor/template-injection", Severity.SERIOUS, Confidence.HIGH, workflow, 11, 22),
    ]
    assert {f.tool for f in parsed.findings} == {"zizmor"}
    injection = parsed.findings[1]
    assert "${{ github.event.issue.body }}" in (injection.evidence or "")
    assert injection.cwe is None


def test_zizmor_had_nothing_to_look_at_in_the_clean_fixture() -> None:
    assert not (UNSAFE.parent.parent / "tools" / "zizmor" / "clean.json").exists()


def test_workflow_lookup_uses_githubs_exact_folder_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_dir = Path.is_dir
    original_glob = Path.rglob
    seen = []

    def is_dir(path: Path):
        seen.append(path.name)
        return original_dir(path)

    def rglob(path: Path, pattern: str):
        seen.append(path.name)
        return original_glob(path, pattern)

    folder = tmp_path / ".github"
    folder.mkdir()
    (folder / "workflow.yml").write_text("jobs: {}")
    monkeypatch.setattr(Path, "is_dir", is_dir)
    monkeypatch.setattr(Path, "rglob", rglob)
    tool = Zizmor()
    assert isinstance(tool.command(at(tmp_path), tmp_path), Command)
    with pytest.raises(ValueError, match="audited nothing"):
        tool.parse(b"", at(tmp_path))
    assert seen == [".github", ".github"]
