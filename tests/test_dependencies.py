"""Pinning a manifest's requirements once, and keeping what couldn't be pinned."""

import json
from pathlib import Path

import pytest

from doorcheck.checks import Problem
from doorcheck.dependencies import (
    MAX_REQUIREMENTS,
    Dependencies,
    Pin,
    Unresolved,
    pins_file,
    resolve,
    unresolved_problem,
)
from doorcheck.errors import DoorcheckError
from doorcheck.findings import Location
from doorcheck.https import DownloadError
from doorcheck.requirements import PypiRequirement

pytestmark = pytest.mark.usefixtures("offline")


class Resolver:
    def __init__(self, versions: dict[str, str | DoorcheckError]) -> None:
        self.versions = versions
        self.asked: list[str] = []

    def __call__(self, requirement: PypiRequirement) -> str:
        self.asked.append(str(requirement))
        answer = self.versions[requirement.name]
        if isinstance(answer, DoorcheckError):
            raise answer
        return answer


def manifest(root: Path, requirements: object) -> Path:
    text = json.dumps({"domain": "demo", "requirements": requirements}, indent=1)
    (root / "manifest.json").write_text(text)
    return root


def test_requirements_are_pinned_to_what_an_install_gets(tmp_path: Path) -> None:
    resolver = Resolver({"a": "1.5", "B": "2.0"})
    found = resolve(manifest(tmp_path, ["a>=1", "B==2.0"]), resolver)
    assert found == Dependencies(
        pins=(Pin(PypiRequirement("a", "==1.5"), 4), Pin(PypiRequirement("B", "==2.0"), 5)),
    )
    assert resolver.asked == ["a>=1", "B==2.0"]


def test_what_cant_be_pinned_is_kept_with_the_reason(tmp_path: Path) -> None:
    resolver = Resolver({"gone": DownloadError("404", "problem.download_not_found"), "ok": "1"})
    root = manifest(tmp_path, ["gone", "pkg @ https://x.invalid/p.zip", "ok", 7, "-r x"])
    found = resolve(root, resolver)
    assert found.pins == (Pin(PypiRequirement("ok", "==1"), 6),)
    assert found.unresolved == (
        Unresolved("gone", 4, "problem.download_not_found"),
        Unresolved("pkg @ https://x.invalid/p.zip", 5, "problem.requirement_outside_pypi"),
        Unresolved("7", 1, "problem.requirement_not_text"),
        Unresolved("-r x", 8, "problem.requirement_outside_pypi"),
    )


def test_a_package_listed_twice_is_pinned_once(tmp_path: Path) -> None:
    found = resolve(
        manifest(tmp_path, ["a>=1", "A_==2", "b"]), Resolver({"a": "1", "A_": "2", "b": "3"})
    )
    assert [str(pin.requirement) for pin in found.pins] == ["a==1", "b==3"]


def test_requirements_past_the_limit_arent_resolved(tmp_path: Path) -> None:
    names = [f"p{n}" for n in range(MAX_REQUIREMENTS + 2)]
    resolver = Resolver(dict.fromkeys(names, "1"))
    found = resolve(manifest(tmp_path, names), resolver)
    assert len(found.pins) == MAX_REQUIREMENTS
    assert [u.written for u in found.unresolved] == names[MAX_REQUIREMENTS:]
    assert {u.key for u in found.unresolved} == {"problem.too_many_requirements"}
    assert found.unresolved[0].line == 4 + MAX_REQUIREMENTS  # its own line, after the first 200
    assert len(resolver.asked) == MAX_REQUIREMENTS
    assert MAX_REQUIREMENTS == 200


@pytest.mark.parametrize(
    "content", [None, "{broken", '{"requirements": "a"}', '{"requirements": []}']
)
def test_no_usable_requirements_means_nothing_to_resolve(
    tmp_path: Path, content: str | None
) -> None:
    if content is not None:
        (tmp_path / "manifest.json").write_text(content)
    assert resolve(tmp_path, Resolver({})) == Dependencies()


def test_other_errors_are_not_hidden(tmp_path: Path) -> None:
    def broken(requirement: PypiRequirement) -> str:
        raise RuntimeError("bug")

    with pytest.raises(RuntimeError):
        resolve(manifest(tmp_path, ["a"]), broken)


def test_a_pins_file_is_rebuilt_from_the_parts() -> None:
    pins = (Pin(PypiRequirement("a", "==1"), 3), Pin(PypiRequirement("b", "==2.0"), 4))
    assert pins_file(pins) == "a==1\nb==2.0\n"


def test_an_unresolved_requirement_is_a_problem_at_its_line() -> None:
    problem = unresolved_problem(Unresolved("x" * 300, 4, "problem.download_failed"))
    assert problem == Problem(
        "problem.download_failed",
        Location("manifest.json", 4),
        {"requirement": "x" * 199 + "…"},
    )
