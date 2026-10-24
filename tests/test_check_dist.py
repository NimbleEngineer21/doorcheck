import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from tools.check_dist import is_forbidden, main


@pytest.mark.parametrize(
    "member",
    [
        "doorcheck-0.0.0/tests/test_x.py",
        "doorcheck-0.0.0/tests/fixtures/evil/__init__.py",
        "doorcheck/fixtures/sample.py",
        "doorcheck-0.0.0/tools/mutation_gate.py",
        "doorcheck-0.0.0/.github/workflows/ci.yml",
    ],
)
def test_forbidden_paths(member: str) -> None:
    assert is_forbidden(member)


@pytest.mark.parametrize(
    "member",
    [
        "doorcheck/__init__.py",
        "doorcheck-0.0.0/pyproject.toml",
        "doorcheck-0.0.0.dist-info/METADATA",
        # Only directories count: a file merely named like one is fine.
        "doorcheck/tests",
    ],
)
def test_allowed_paths(member: str) -> None:
    assert not is_forbidden(member)


def _wheel(tmp_path: Path, members: list[str]) -> Path:
    path = tmp_path / "doorcheck-0.0.0-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as wheel:
        for member in members:
            wheel.writestr(member, "")
    return path


def _sdist(tmp_path: Path, members: list[str]) -> Path:
    path = tmp_path / "doorcheck-0.0.0.tar.gz"
    with tarfile.open(path, "w:gz") as sdist:
        for member in members:
            info = tarfile.TarInfo(member)
            sdist.addfile(info, io.BytesIO(b""))
    return path


def test_clean_archives_pass(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    wheel = _wheel(tmp_path, ["doorcheck/__init__.py"])
    sdist = _sdist(tmp_path, ["doorcheck-0.0.0/src/doorcheck/__init__.py"])
    assert main(["check", str(wheel), str(sdist)]) == 0
    assert capsys.readouterr().out == "Checked 2 archive(s); only package files ship.\n"


def test_sdist_with_tests_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    sdist = _sdist(tmp_path, ["doorcheck-0.0.0/tests/test_x.py"])
    assert main(["check", str(sdist)]) == 1
    assert capsys.readouterr().out == (
        "Must not ship: doorcheck-0.0.0.tar.gz: doorcheck-0.0.0/tests/test_x.py\n"
    )


def test_wheel_with_fixtures_fails(tmp_path: Path) -> None:
    wheel = _wheel(tmp_path, ["doorcheck/__init__.py", "doorcheck/fixtures/x.py"])
    assert main(["check", str(wheel)]) == 1


def test_no_archives_fails_closed(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["check"]) == 1
    assert capsys.readouterr().out == "No archives given.\n"
