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


@pytest.mark.parametrize("content", [None, '{"requirements": []}'])
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


@pytest.mark.parametrize(
    ("data", "key"),
    [
        ("{broken", "problem.manifest_not_parsed"),
        ('{"requirements":"a"}', "problem.requirements_not_list"),
    ],
)
def test_unreadable_dependency_declarations_are_coverage_gaps(
    tmp_path: Path, data: str, key: str
) -> None:
    (tmp_path / "manifest.json").write_text(data)
    assert resolve(tmp_path, Resolver({})) == Dependencies(
        unresolved=(Unresolved("manifest.json", 1, key),)
    )


def test_dependency_manifest_special_files_and_links_are_not_read(tmp_path: Path) -> None:
    import os

    file = tmp_path / "manifest.json"
    os.mkfifo(file)
    expected = Dependencies(
        unresolved=(Unresolved("manifest.json", 1, "problem.manifest_not_readable"),)
    )
    assert resolve(tmp_path, Resolver({})) == expected
    file.unlink()
    file.symlink_to("/dev/null")
    assert resolve(tmp_path, Resolver({})) == expected


def test_dependency_manifest_read_is_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("doorcheck.dependencies.MAX_MANIFEST_BYTES", 4)
    (tmp_path / "manifest.json").write_bytes(b"{}    ")
    assert resolve(tmp_path, Resolver({})) == Dependencies(
        unresolved=(Unresolved("manifest.json", 1, "problem.file_too_large"),)
    )


def test_inconsistent_duplicate_pins_are_not_presented_as_a_resolved_package(
    tmp_path: Path,
) -> None:
    found = resolve(manifest(tmp_path, ["a==1", "A==2", "a==1"]), Resolver({"a": "1", "A": "2"}))
    assert found.pins == ()
    assert found.unresolved == (
        Unresolved("A==2", 5, "problem.conflicting_requirements"),
        Unresolved("a==1", 4, "problem.conflicting_requirements"),
    )


def test_equal_duplicate_pins_keep_the_first_location(tmp_path: Path) -> None:
    found = resolve(manifest(tmp_path, ["a==1", "a==1"]), Resolver({"a": "1"}))
    assert found == Dependencies((Pin(PypiRequirement("a", "==1"), 4),))


def test_extras_are_explicitly_reported_as_unchecked(tmp_path: Path) -> None:
    found = resolve(manifest(tmp_path, ["a[extra]>=1"]), Resolver({"a": "2"}))
    assert found.pins == (Pin(PypiRequirement("a", "==2"), 4),)
    assert found.unresolved == (
        Unresolved("a[extra]>=1", 4, "problem.requirement_extras_not_checked"),
    )


def test_equivalent_package_names_do_not_create_false_conflicts(tmp_path: Path) -> None:
    found = resolve(
        manifest(tmp_path, ["foo-bar==1", "Foo_Bar==1"]), Resolver({"foo-bar": "1", "Foo_Bar": "1"})
    )
    assert found == Dependencies((Pin(PypiRequirement("foo-bar", "==1"), 4),))


def test_manifest_budget_has_one_overflow_byte_and_includes_its_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from doorcheck import dependencies

    original = dependencies.read_regular
    seen = []

    def read(path: Path, limit: int):
        seen.append(limit)
        return original(path, limit)

    monkeypatch.setattr(dependencies, "MAX_MANIFEST_BYTES", 4)
    monkeypatch.setattr(dependencies, "read_regular", read)
    path = tmp_path / "manifest.json"
    path.write_bytes(b"{}    ")
    assert resolve(tmp_path).unresolved[0].key == "problem.file_too_large"
    path.write_bytes(b"{}  ")
    assert resolve(tmp_path) == Dependencies()
    assert seen == [5, 5]
