import json
import sys
import tokenize
from pathlib import Path
from typing import Any

import pytest

from doorcheck.capabilities import Capability, Kind, ScanLimits, scan
from doorcheck.capabilities.model import MAX_SUBJECT
from doorcheck.capabilities.scan import MAX_REQUIREMENTS, PYTHON
from doorcheck.findings import Location


def write(root: Path, files: dict[str, str | bytes]) -> Path:
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
    return root


def summary(root: Path, limits: ScanLimits | None = None) -> list[tuple[str, int, Kind, str]]:
    return [
        (c.location.path, c.location.line, c.kind, c.subject)
        for c in scan(root, limits).capabilities
    ]


def problems(
    root: Path, limits: ScanLimits | None = None
) -> list[tuple[str, int, str, dict[str, str]]]:
    found = scan(root, limits).problems
    return [(p.location.path, p.location.line, p.key, dict(p.params)) for p in found if p.location]


# --- model ----------------------------------------------------------------------


def test_subjects_and_attributes_from_untrusted_code_are_capped() -> None:
    long = "x" * (MAX_SUBJECT + 50)
    capability = Capability(Kind.PROCESS, Location("a.py", 1), long, {"name": long})
    assert capability.subject == "x" * (MAX_SUBJECT - 1) + "…"
    assert capability.attrs["name"] == "x" * (MAX_SUBJECT - 1) + "…"
    assert MAX_SUBJECT == 200


def test_attributes_cannot_be_changed_after_creation() -> None:
    source = {"auth": "none"}
    capability = Capability(Kind.WEB_VIEW, Location("a.py", 1), "/x", source)
    source["auth"] = "required"
    assert capability.attrs["auth"] == "none"
    with pytest.raises(TypeError):
        capability.attrs["auth"] = "x"  # type: ignore[index]


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        ({"kind": "process"}, "kind must be a Kind"),
        ({"location": ("a.py", 1)}, "location must be a Location"),
        ({"subject": 3}, "subject must be a string"),
        ({"attrs": [("a", "b")]}, "attrs must be a mapping"),
        ({"attrs": {"a": 1}}, "attrs must be strings"),
        ({"attrs": {"Bad": "x"}}, "invalid parameter name: 'Bad'"),
    ],
)
def test_capabilities_are_validated(fields: dict[str, Any], message: str) -> None:
    defaults: dict[str, Any] = {
        "kind": Kind.PROCESS,
        "location": Location("a.py", 1),
        "subject": "x",
    }
    with pytest.raises(ValueError, match=f"^{message}$"):
        Capability(**{**defaults, **fields})


def test_default_limits() -> None:
    assert ScanLimits() == ScanLimits(
        max_files=10_000, max_file_bytes=10_000_000, max_python_bytes=2_000_000, max_seconds=60.0
    )


# --- walking ----------------------------------------------------------------------


def test_results_are_sorted_by_path_then_position(tmp_path: Path) -> None:
    write(
        tmp_path,
        {
            "b.py": "import os\nos.system('b')\n",
            "a/z.py": "open('z', 'w')\nfrom subprocess import run\nrun(['y'])\n",
            "a.py": "exec(x)\n",
        },
    )
    assert summary(tmp_path) == [
        ("a.py", 1, Kind.DYNAMIC_CODE, "exec"),
        ("a/z.py", 1, Kind.FILE_WRITE, "z"),
        ("a/z.py", 2, Kind.SYSTEM_MODULE, "subprocess"),
        ("a/z.py", 3, Kind.PROCESS, "y"),
        ("b.py", 2, Kind.PROCESS, "b"),
    ]


def test_same_position_is_ordered_by_kind_then_subject(tmp_path: Path) -> None:
    write(tmp_path, {"m.py": "__import__('os').system('id')\n"})
    assert summary(tmp_path) == [
        ("m.py", 1, Kind.DYNAMIC_IMPORT, "os"),
        ("m.py", 1, Kind.PROCESS, "id"),
    ]


def test_columns_order_results_on_one_line(tmp_path: Path) -> None:
    write(tmp_path, {"m.py": "eval(a); exec(b)\n"})
    assert summary(tmp_path) == [
        ("m.py", 1, Kind.DYNAMIC_CODE, "eval"),
        ("m.py", 1, Kind.DYNAMIC_CODE, "exec"),
    ]
    assert [c.location.column for c in scan(tmp_path).capabilities] == [1, 10]


def test_nothing_is_skipped_not_even_git(tmp_path: Path) -> None:
    write(tmp_path, {".git/hooks/x.py": "exec(x)\n", "git/x.py": "exec(x)\n"})
    assert summary(tmp_path) == [
        (".git/hooks/x.py", 1, Kind.DYNAMIC_CODE, "exec"),
        ("git/x.py", 1, Kind.DYNAMIC_CODE, "exec"),
    ]


def test_links_are_reported_with_their_target_and_never_followed(tmp_path: Path) -> None:
    outside = write(tmp_path / "outside", {"secret.py": "exec(x)\n"})
    root = tmp_path / "root"
    root.mkdir()
    (root / "file_link.py").symlink_to(outside / "secret.py")
    (root / "dir_link").symlink_to(outside, target_is_directory=True)
    (root / "relative").symlink_to("../../.storage/auth")
    assert summary(root) == [
        ("dir_link", 1, Kind.SYMLINK, str(outside)),
        ("file_link.py", 1, Kind.SYMLINK, str(outside / "secret.py")),
        ("relative", 1, Kind.SYMLINK, "../../.storage/auth"),
    ]


def test_an_empty_folder_has_nothing(tmp_path: Path) -> None:
    result = scan(tmp_path)
    assert (result.capabilities, result.problems) == ((), ())


# --- binaries and limits --------------------------------------------------------


@pytest.mark.parametrize("name", ["cache.pyc", "lib.so", "helper.exe", "evil.pth", "x.dylib"])
def test_binaries_by_suffix(tmp_path: Path, name: str) -> None:
    write(tmp_path, {name: b"anything"})
    assert summary(tmp_path) == [(name, 1, Kind.SHIPPED_BINARY, Path(name).suffix)]


@pytest.mark.parametrize(
    "magic",
    [
        b"\x7fELF",
        b"MZ\x90\x00",
        b"\xfe\xed\xfa\xce",
        b"\xce\xfa\xed\xfe",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
    ],
)
def test_binaries_by_content(tmp_path: Path, magic: bytes) -> None:
    write(tmp_path, {"tool": magic + b"rest", "data.bin": magic + b"rest"})
    assert summary(tmp_path) == [
        ("data.bin", 1, Kind.SHIPPED_BINARY, ".bin"),
        ("tool", 1, Kind.SHIPPED_BINARY, "executable"),
    ]


def test_data_files_are_not_binaries(tmp_path: Path) -> None:
    write(
        tmp_path,
        {"data.bin": b"\x00\x01ELF", "short": b"M", "notes.txt": "a note that mentions MZ"},
    )
    assert summary(tmp_path) == []


def test_python_has_a_tighter_size_limit(tmp_path: Path) -> None:
    write(tmp_path, {"big.py": "x = 1\n" * 3, "big.js": "x\n" * 9, "ok.js": "x\n" * 4})
    too_large = {"size": "18"}
    limits = ScanLimits(max_python_bytes=17, max_file_bytes=17)
    assert problems(tmp_path, limits) == [
        ("big.js", 1, "problem.file_too_large", too_large),
        ("big.py", 1, "problem.file_too_large", too_large),
    ]
    limits = ScanLimits(max_python_bytes=17, max_file_bytes=18)
    assert problems(tmp_path, limits) == [("big.py", 1, "problem.file_too_large", too_large)]


def test_file_count_limit_stops_the_scan(tmp_path: Path) -> None:
    write(tmp_path, {f"{n}.py": "exec(x)\n" for n in "abc"})
    limits = ScanLimits(max_files=2)
    assert summary(tmp_path, limits) == [
        ("a.py", 1, Kind.DYNAMIC_CODE, "exec"),
        ("b.py", 1, Kind.DYNAMIC_CODE, "exec"),
    ]
    assert problems(tmp_path, limits) == [
        ("c.py", 1, "problem.scan_limit_reached", {"limit": "file_count"})
    ]


def test_time_limit_stops_the_scan(tmp_path: Path) -> None:
    write(tmp_path, {"a.py": "exec(x)\n"})
    limits = ScanLimits(max_seconds=-1)
    assert summary(tmp_path, limits) == []
    assert problems(tmp_path, limits) == [
        ("a.py", 1, "problem.scan_limit_reached", {"limit": "time"})
    ]


def test_time_is_named_when_only_time_ran_out(tmp_path: Path) -> None:
    write(tmp_path, {"a.py": "exec(x)\n"})
    limits = ScanLimits(max_files=1, max_seconds=-1)
    assert problems(tmp_path, limits) == [
        ("a.py", 1, "problem.scan_limit_reached", {"limit": "time"})
    ]


def test_exactly_at_the_limits_is_fine(tmp_path: Path) -> None:
    write(tmp_path, {"a.py": "exec(x)\n"})
    limits = ScanLimits(max_files=1, max_python_bytes=8, max_seconds=60)
    assert summary(tmp_path, limits) == [("a.py", 1, Kind.DYNAMIC_CODE, "exec")]
    assert scan(tmp_path, limits).problems == ()


# --- readers ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("content", "line", "detail"),
    [
        (b"x = 1\ndef broken(:\n", 2, "SyntaxError: invalid syntax (<unknown>, line 2)"),
        (b"x = '\xff'\n", 1, "UnicodeDecodeError: 'utf-8' codec can't decode byte 0xff"),
        (b"x = 1\x00\n", 1, "SyntaxError: source code string cannot contain null bytes"),
    ],
)
def test_unreadable_python_is_a_problem_at_its_line(
    tmp_path: Path, content: bytes, line: int, detail: str
) -> None:
    write(tmp_path, {"bad.py": content})
    ((path, at, key, params),) = problems(tmp_path)
    assert (path, at, key, params["python"]) == ("bad.py", line, "problem.file_not_parsed", PYTHON)
    assert params["detail"].startswith(detail)
    assert summary(tmp_path) == []


def test_the_python_version_parsing_the_code_is_named() -> None:
    assert f"{sys.version_info.major}.{sys.version_info.minor}" == PYTHON


@pytest.mark.skipif(sys.version_info >= (3, 14), reason="Python 3.14 reads this syntax")
def test_newer_syntax_on_an_older_python_is_a_gap_not_a_clean_file(tmp_path: Path) -> None:
    write(tmp_path, {"new.py": "try:\n    pass\nexcept ValueError, TypeError:\n    exec(x)\n"})
    assert summary(tmp_path) == []
    assert [p[2] for p in problems(tmp_path)] == ["problem.file_not_parsed"]


@pytest.mark.parametrize(
    "source",
    [
        "x = " + "-" * 100_000 + "1",  # the parser runs out of stack: MemoryError
        "x = " + "1+" * 100_000 + "1",  # compiling runs out of stack: RecursionError
        "__import__(" + "'a'+" * 3_000 + "'b')",  # folding the assembled name recurses
    ],
    ids=["parser", "compiler", "folding"],
)
def test_deeply_nested_python_is_a_problem(tmp_path: Path, source: str) -> None:
    write(tmp_path, {"deep.py": source})
    assert problems(tmp_path) == [("deep.py", 1, "problem.file_too_complex", {})]


def test_tokenizer_failure_after_parsing_is_a_problem(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(source: str, path: str) -> list[Capability]:
        raise tokenize.TokenError("unexpected EOF")

    monkeypatch.setattr("doorcheck.capabilities.source_text.confusable_names", broken)
    write(tmp_path, {"a.py": f"exec(x)  # {chr(0x202E)}\n"})
    assert summary(tmp_path) == [
        ("a.py", 1, Kind.DYNAMIC_CODE, "exec"),
        ("a.py", 1, Kind.BIDI_CONTROL, "U+202E"),
    ]
    assert problems(tmp_path) == [
        (
            "a.py",
            1,
            "problem.file_not_parsed",
            {"detail": "TokenError: unexpected EOF", "python": PYTHON},
        )
    ]


def test_python_gets_all_three_checks(tmp_path: Path) -> None:
    fullwidth_e = chr(0xFF45)
    write(tmp_path, {"a.py": f"{fullwidth_e}val(x)\n# {chr(0x2066)}\n"})
    assert summary(tmp_path) == [
        ("a.py", 1, Kind.CONFUSABLE_NAME, f"{fullwidth_e}val"),
        ("a.py", 1, Kind.DYNAMIC_CODE, "eval"),
        ("a.py", 2, Kind.BIDI_CONTROL, "U+2066"),
    ]


@pytest.mark.parametrize("suffix", [".js", ".mjs", ".cjs", ".ts", ".yaml", ".yml"])
def test_other_source_files_are_checked_for_bidi(tmp_path: Path, suffix: str) -> None:
    write(tmp_path, {f"card{suffix}": b"ok\nif (a\xe2\x80\xae) {}\n\xff"})
    assert summary(tmp_path) == [(f"card{suffix}", 2, Kind.BIDI_CONTROL, "U+202E")]


def test_unknown_text_files_are_not_read(tmp_path: Path) -> None:
    write(tmp_path, {"README.md": f"exec(x) {chr(0x202E)}", "x.py.txt": "exec(x)"})
    assert summary(tmp_path) == []


def test_manifest_requirements_are_dependencies(tmp_path: Path) -> None:
    manifest = {"domain": "x", "requirements": ["pyfoo==1.0", "bar>=2"]}
    write(tmp_path, {"custom_components/x/manifest.json": json.dumps(manifest)})
    assert summary(tmp_path) == [
        ("custom_components/x/manifest.json", 1, Kind.DEPENDENCY, "bar>=2"),
        ("custom_components/x/manifest.json", 1, Kind.DEPENDENCY, "pyfoo==1.0"),
    ]


def test_a_manifest_without_requirements_has_none(tmp_path: Path) -> None:
    write(tmp_path, {"manifest.json": '{"domain": "x"}', "other.json": '{"requirements": ["a"]}'})
    assert summary(tmp_path) == []
    assert scan(tmp_path).problems == ()


@pytest.mark.parametrize("content", ["{not json", '["a list"]', '{"requirements": "pyfoo"}'])
def test_invalid_manifests_are_problems(tmp_path: Path, content: str) -> None:
    write(tmp_path, {"manifest.json": content})
    assert problems(tmp_path) == [("manifest.json", 1, "problem.manifest_not_parsed", {})]


def test_requirements_from_outside_pypi_are_told_apart(tmp_path: Path) -> None:
    manifest = {
        "domain": "x",
        "requirements": ["pkg==1", 3, "-r /etc/passwd", "p @ https://example.invalid/p.zip"],
    }
    write(tmp_path, {"manifest.json": json.dumps(manifest, indent=1)})
    assert summary(tmp_path) == [
        ("manifest.json", 4, Kind.DEPENDENCY, "pkg==1"),
        ("manifest.json", 6, Kind.DEPENDENCY_OUTSIDE_PYPI, "-r /etc/passwd"),
        ("manifest.json", 7, Kind.DEPENDENCY_OUTSIDE_PYPI, "p @ https://example.invalid/p.zip"),
    ]
    assert problems(tmp_path) == [("manifest.json", 1, "problem.requirement_not_text", {})]


def test_requirements_past_the_limit_are_one_problem(tmp_path: Path) -> None:
    names = [f"p{n}" for n in range(MAX_REQUIREMENTS + 5)]
    write(tmp_path, {"manifest.json": json.dumps({"requirements": names})})
    assert len(summary(tmp_path)) == MAX_REQUIREMENTS
    assert problems(tmp_path) == [("manifest.json", 1, "problem.too_many_requirements", {})]


def test_exactly_the_limit_of_requirements_is_fine(tmp_path: Path) -> None:
    names = [f"p{n}" for n in range(MAX_REQUIREMENTS)]
    write(tmp_path, {"manifest.json": json.dumps({"requirements": names})})
    assert len(summary(tmp_path)) == MAX_REQUIREMENTS
    assert scan(tmp_path).problems == ()


def test_a_utf16_manifest_still_lists_its_requirements(tmp_path: Path) -> None:
    # json reads UTF-16 by its byte order mark; the line lookup can't, so it says line 1.
    write(tmp_path, {"manifest.json": '{"requirements": ["pkg==1"]}'.encode("utf-16")})
    assert summary(tmp_path) == [("manifest.json", 1, Kind.DEPENDENCY, "pkg==1")]
