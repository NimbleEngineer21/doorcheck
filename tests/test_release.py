import json
import shutil
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from tools.release import (
    HA_PIN,
    MANIFEST,
    PROJECT,
    REQUIREMENT,
    ROOT,
    Sources,
    included,
    integration_files,
    main,
    normalized,
    pin,
    problems,
    project_version,
    read_sources,
    wheel_name,
    write_zip,
)


def _sources(
    version: str = "1.2.0a1",
    *,
    ha_pin: str | None = None,
    requirement: str | None = None,
    manifest_version: str | None = None,
    hacs: dict[str, Any] | None = None,
    minimum: str = "2025.11.0",
) -> Sources:
    return Sources(
        project={"project": {"version": version}},
        ha_project={
            "project": {"dependencies": [ha_pin or f"doorcheck=={version}", "mutmut==3.8.0"]}
        },
        manifest={
            "requirements": [requirement or f"doorcheck=={version}"],
            "version": manifest_version or version,
        },
        hacs={"name": "Doorcheck", "zip_release": True, "filename": "doorcheck.zip"}
        | {"homeassistant": minimum}
        | (hacs or {}),
        images={"minimum": {"version": minimum}},
    )


def test_agreeing_files_and_tag_pass() -> None:
    assert problems(_sources(), "v1.2.0a1") == []
    assert problems(_sources()) == []


@pytest.mark.parametrize(
    ("requirements", "expected"),
    [
        (["doorcheck==1.0"], "1.0"),
        (["other==2", "doorcheck==1.0"], "1.0"),
        (["Doorcheck==1.0"], "1.0"),
        (["door_check==1.0"], None),
        ([], None),
        (["other==1.0"], None),
        (["doorcheck>=1.0"], None),
        (["doorcheck~=1.0"], None),
        (["doorcheck===1.0"], None),
        (["doorcheck==1.*"], None),
        (["doorcheck==1.0,!=1.1"], None),
        (["doorcheck"], None),
        (["doorcheck[extra]==1.0"], None),
        (["doorcheck==1.0; python_version>'3'"], None),
        (["doorcheck @ https://example.invalid/doorcheck.whl"], None),
        (["doorcheck==1.0", "doorcheck==1.0"], None),
        (["doorcheck==1.0", "not a requirement !"], None),
    ],
)
def test_pin_accepts_only_one_exact_requirement(
    requirements: list[str], expected: str | None
) -> None:
    assert pin(requirements) == expected


@pytest.mark.parametrize(
    ("version", "expected"),
    [("0.1.0a1", True), ("1.0", True), ("0.1.0-alpha.1", False), ("v0.1.0", False), ("x", False)],
)
def test_normalized(version: str, expected: bool) -> None:
    assert normalized(version) is expected


@pytest.mark.parametrize(
    ("sources", "issue"),
    [
        (
            _sources(ha_pin="doorcheck==1.2.0"),
            f"{HA_PIN}: 1.2.0 differs from {PROJECT} 1.2.0a1",
        ),
        (
            _sources(requirement="doorcheck==1.2.0"),
            f"{REQUIREMENT}: 1.2.0 differs from {PROJECT} 1.2.0a1",
        ),
        (
            _sources(manifest_version="1.2.0a0"),
            f"{MANIFEST}: 1.2.0a0 differs from {PROJECT} 1.2.0a1",
        ),
        (
            _sources(ha_pin="doorcheck>=1.2.0a1"),
            f"{HA_PIN}: no single exact doorcheck== requirement",
        ),
        (
            _sources(requirement="doorcheck~=1.2.0a1"),
            f"{REQUIREMENT}: no single exact doorcheck== requirement",
        ),
        (
            _sources(hacs={"zip_release": False}),
            "hacs.json: zip_release must be true",
        ),
        (
            _sources(hacs={"zip_release": "true"}),
            "hacs.json: zip_release must be true",
        ),
        (
            _sources(hacs={"filename": "other.zip"}),
            "hacs.json: filename must be doorcheck.zip",
        ),
        (
            _sources(hacs={"homeassistant": "2025.10.0"}),
            "hacs.json: homeassistant must be 2025.11.0, the minimum acceptance image",
        ),
    ],
)
def test_each_disagreement_is_reported(sources: Sources, issue: str) -> None:
    assert problems(sources) == [issue]


def test_missing_hacs_keys_are_reported() -> None:
    sources = _sources()
    bare = Sources(sources.project, sources.ha_project, sources.manifest, {}, sources.images)
    assert problems(bare) == [
        "hacs.json: zip_release must be true",
        "hacs.json: filename must be doorcheck.zip",
        "hacs.json: homeassistant must be 2025.11.0, the minimum acceptance image",
    ]


def test_unnormalized_project_version_is_reported() -> None:
    assert problems(_sources("1.2.0-alpha1")) == [
        f"{PROJECT}: '1.2.0-alpha1' is not a normalized PEP 440 version"
    ]


@pytest.mark.parametrize("tag", ["1.2.0a1", "v1.2.0", "v1.2.0a1 ", "V1.2.0a1", "v1.2.0a2"])
def test_tag_must_be_v_and_the_version(tag: str) -> None:
    assert problems(_sources(), tag) == [f"tag {tag} must be v1.2.0a1"]


def test_wheel_name() -> None:
    assert wheel_name("0.1.0a1") == "doorcheck-0.1.0a1-py3-none-any.whl"


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("manifest.json", True),
        ("frontend/panel.js", True),
        ("translations/en.json", True),
        ("scan.pyc", False),
        ("__pycache__/scan.cpython-314.pyc", False),
        ("__pycache__/notes.txt", False),
        ("frontend/__pycache__/x.py", False),
        (".DS_Store", False),
        (".hidden/panel.js", False),
    ],
)
def test_included(path: str, expected: bool) -> None:
    assert included(PurePosixPath(path)) is expected


def test_zip_is_sorted_stored_and_fixed(tmp_path: Path) -> None:
    output = tmp_path / "out.zip"
    write_zip({"b.py": b"b", "a/c.json": b"{}", "a.py": b"a"}, output)
    with zipfile.ZipFile(output) as archive:
        infos = archive.infolist()
        assert [info.filename for info in infos] == ["a.py", "a/c.json", "b.py"]
        assert archive.read("a/c.json") == b"{}"
        assert archive.comment == b""
    for info in infos:
        assert info.date_time == (1980, 1, 1, 0, 0, 0)
        assert info.compress_type == zipfile.ZIP_STORED
        assert info.create_system == 3
        assert info.external_attr == 0o100644 << 16
        assert info.extra == b""


def test_zip_bytes_do_not_depend_on_input_order(tmp_path: Path) -> None:
    first, second = tmp_path / "1.zip", tmp_path / "2.zip"
    write_zip({"a.py": b"a", "b.py": b"b"}, first)
    write_zip({"b.py": b"b", "a.py": b"a"}, second)
    assert first.read_bytes() == second.read_bytes()


def _tree(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    shutil.copytree(ROOT / "custom_components/doorcheck", root / "custom_components/doorcheck")
    for path in ("pyproject.toml", "hacs.json", "ha/pyproject.toml", "ha/acceptance/images.json"):
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / path, root / path)
    return root


def test_integration_files_hold_the_folder_at_the_root(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    folder = root / "custom_components/doorcheck"
    (folder / "__pycache__").mkdir(exist_ok=True)
    (folder / "__pycache__/scan.cpython-314.pyc").write_bytes(b"x")
    (folder / ".DS_Store").write_bytes(b"x")
    members = integration_files(root)
    assert "manifest.json" in members
    assert "frontend/panel.js" in members
    assert not any("__pycache__" in name or name.startswith(".") for name in members)
    assert members["manifest.json"] == (folder / "manifest.json").read_bytes()
    assert set(members) == {
        path.relative_to(folder).as_posix()
        for path in folder.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts and not path.name.startswith(".")
    }


def test_repository_files_agree() -> None:
    assert problems(read_sources(ROOT)) == []


def test_project_version_reads_pyproject(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "9.9.9"\n')
    assert project_version(tmp_path) == "9.9.9"
    assert project_version() == read_sources(ROOT).project["project"]["version"]


def test_check_command(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = _tree(tmp_path)
    version = project_version(root)
    assert main(["check", "--tag", f"v{version}"], root) == 0
    assert capsys.readouterr().out == f"Release files agree on {version}.\n"
    assert main(["check", "--tag", "v0.0.0"], root) == 1
    assert capsys.readouterr().out == f"tag v0.0.0 must be v{version}\n"
    hacs = root / "hacs.json"
    hacs.write_text(json.dumps(json.loads(hacs.read_text()) | {"filename": "x.zip"}))
    assert main(["check"], root) == 1
    assert capsys.readouterr().out == "hacs.json: filename must be doorcheck.zip\n"


def test_zip_command_builds_identical_archives(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _tree(tmp_path)
    first, second = tmp_path / "1.zip", tmp_path / "2.zip"
    assert main(["zip", str(first)], root) == 0
    assert capsys.readouterr().out == f"Wrote {first}.\n"
    assert main(["zip", str(second)], root) == 0
    assert first.read_bytes() == second.read_bytes()
    with zipfile.ZipFile(first) as archive:
        assert sorted(archive.namelist()) == sorted(integration_files(root))


@pytest.mark.parametrize("argv", [[], ["zip"], ["publish"]])
def test_invalid_arguments_exit_two(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as raised:
        main(argv)
    assert raised.value.code == 2


def test_help_describes_the_tool(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as raised:
        main(["--help"])
    assert raised.value.code == 0
    assert "Check that every release version agrees" in capsys.readouterr().out
