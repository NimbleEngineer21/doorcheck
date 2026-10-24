import json
import time
from pathlib import Path

import pytest

from doorcheck.requirements import (
    PypiRequirement,
    _string_lines,
    normalized,
    parse_manifest,
    pypi_requirement,
    read_manifest,
)


@pytest.mark.parametrize(
    ("text", "name", "specifiers"),
    [
        ("a", "a", ""),
        ("a-b.c_d", "a-b.c_d", ""),
        ("A1", "A1", ""),
        ("pkg[x, y] >= 1.0 , < 2", "pkg", ">=1.0,<2"),
        ("p==1.0.post1", "p", "==1.0.post1"),
        ("p~=2.1", "p", "~=2.1"),
        ("p===1", "p", "===1"),
        ("p!=1.*", "p", "!=1.*"),
        ("p>1", "p", ">1"),
        ("p<=1", "p", "<=1"),
        ("  p  ==  1  ", "p", "==1"),
        ("p; python_version>'3'", "p", ""),
        ("p==1;", "p", "==1"),
        ("p; python_version>'3'; extra", "p", ""),
    ],
)
def test_plain_pypi_requirements(text: str, name: str, specifiers: str) -> None:
    assert pypi_requirement(text) == PypiRequirement(name, specifiers)


@pytest.mark.parametrize(
    "text",
    [
        "-r /etc/passwd",
        "--index-url=https://evil.example/simple",
        "-e .",
        "pkg @ https://example.invalid/pkg.zip",
        "git+https://github.com/o/r#egg=pkg",
        "https://example.invalid/pkg.tar.gz",
        "a b",
        "a==",
        "a[]",
        "",
        "a.",
        "_a",
        "a-",
        "a==1 # comment",
        "a==1\n--index-url=x",
    ],
)
def test_anything_else_installs_from_outside_pypi(text: str) -> None:
    assert pypi_requirement(text) is None


@pytest.mark.parametrize(
    ("specifiers", "version"),
    [("==1.2", "1.2"), ("==1.2.post1", "1.2.post1"), (">=1", None), ("==1,<2", None), ("", None)],
)
def test_only_an_exact_pin_names_one_version(specifiers: str, version: str | None) -> None:
    assert PypiRequirement("p", specifiers).pinned_version == version


def test_requirements_are_rebuilt_from_their_parts() -> None:
    assert str(pypi_requirement("pkg [x] >= 1 , < 2 ; sys_platform == 'linux'")) == "pkg>=1,<2"


@pytest.mark.parametrize(
    ("name", "expected"),
    [("Foo_Bar", "foo-bar"), ("foo.bar", "foo-bar"), ("foo--__..bar", "foo-bar"), ("x", "x")],
)
def test_names_compare_the_way_pypi_compares_them(name: str, expected: str) -> None:
    assert normalized(name) == expected


MANIFEST = """{
  "domain": "demo",
  "requirements": [
    "Requests==2.31.0",
    "icmplib>=3",
    "pkg @ https://example.invalid/p.zip", 3
  ]
}
"""


def test_a_manifest_keeps_its_requirements_as_written() -> None:
    manifest = parse_manifest(MANIFEST.encode())
    assert manifest is not None
    assert manifest.text == MANIFEST
    assert manifest.requirements == (
        "Requests==2.31.0",
        "icmplib>=3",
        "pkg @ https://example.invalid/p.zip",
        3,
    )


def test_requirement_lines() -> None:
    manifest = parse_manifest(MANIFEST.encode())
    assert manifest is not None
    assert [manifest.line(r) for r in ("Requests==2.31.0", "icmplib>=3", "missing")] == [4, 5, 1]
    assert manifest.line("pkg @ https://example.invalid/p.zip") == 6


def test_a_line_is_found_for_the_exact_string_only() -> None:
    text = json.dumps({"requirements": ["ab", "a"]}, indent=1)
    manifest = parse_manifest(text.encode())
    assert manifest is not None
    assert (manifest.line("a"), manifest.line("ab"), manifest.line("b")) == (4, 3, 1)


def test_the_first_line_of_a_repeated_string_counts() -> None:
    manifest = parse_manifest(b'{"requirements": [\n"a",\n"a"]}')
    assert manifest is not None
    assert manifest.line("a") == 2


def test_lines_are_found_for_text_outside_ascii_and_with_escapes() -> None:
    text = '{\n"requirements": [\n"caf\u00e9-lib",\n"q\\"uote"]}'
    manifest = parse_manifest(text.encode())
    assert manifest is not None
    assert (manifest.line("café-lib"), manifest.line('q"uote')) == (3, 4)


def test_escapes_are_read_the_way_json_reads_them() -> None:
    manifest = parse_manifest(b'{\n"requirements": [\n"caf\\u00e9-lib",\n"ok"]}')
    assert manifest is not None
    assert (manifest.line("café-lib"), manifest.line("ok")) == (3, 4)


def test_an_invalid_escape_skips_only_that_string() -> None:
    text = '{\n"requirements": [\n"bad \\x", "same-line",\n"ok"]}'
    assert _string_lines(text) == {"requirements": 2, "same-line": 3, "ok": 4}


def test_many_requirements_are_placed_in_linear_time() -> None:
    requirements = [f"package-{n}==1" for n in range(20_000)]
    text = json.dumps({"requirements": requirements}, indent=1)
    start = time.perf_counter()
    manifest = parse_manifest(text.encode())
    assert manifest is not None
    lines = [manifest.line(r) for r in requirements]
    assert time.perf_counter() - start < 2
    assert lines[:2] == [3, 4]


@pytest.mark.parametrize("content", [b"{broken", b"[1]", b"\xff", b"[" * 100_000, b""])
def test_anything_but_a_json_object_is_no_manifest(content: bytes) -> None:
    assert parse_manifest(content) is None


@pytest.mark.parametrize(
    ("content", "requirements"),
    [
        (b'{"requirements": "a"}', None),
        (b'{"requirements": {"a": 1}}', None),
        (b'{"domain": "x"}', ()),
        (b'{"requirements": []}', ()),
    ],
)
def test_requirements_that_arent_a_list(
    content: bytes, requirements: tuple[object, ...] | None
) -> None:
    manifest = parse_manifest(content)
    assert manifest is not None
    assert manifest.requirements == requirements


def test_a_manifest_that_isnt_utf8_is_unreadable() -> None:
    # Home Assistant reads manifest.json as UTF-8, so it can't load this either.
    assert parse_manifest(b'{"name": "\xff", "requirements": ["a"]}') is None


def test_reading_a_manifest_file(tmp_path: Path) -> None:
    (tmp_path / "manifest.json").write_text(MANIFEST)
    manifest = read_manifest(tmp_path / "manifest.json")
    assert manifest is not None
    assert manifest.requirements is not None
    assert len(manifest.requirements) == 4
    assert read_manifest(tmp_path / "missing.json") is None
