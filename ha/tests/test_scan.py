"""Snapshot boundaries and real engine results, without candidate execution."""

import hashlib
import os
from pathlib import Path
from unittest.mock import patch

import pytest
from doorcheck.checks import Status
from doorcheck.fetch import tree_digest
from doorcheck.report import from_dict, to_dict

from custom_components.doorcheck import scan


def source(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "custom_components"
    selected = root / "example"
    selected.mkdir(parents=True)
    return root, selected


def failed(root: Path) -> None:
    result = scan.scan_integration(root, "example").report
    assert result.target.name == "example"
    assert result.capabilities == result.findings == ()
    assert len(result.checks) == 1
    assert result.checks[0].name == "snapshot"
    assert result.checks[0].status is Status.FAILED
    assert [p.key for p in result.checks[0].problems] == ["problem.ha_snapshot_failed"]


def test_scan_uses_engine_and_removes_private_snapshot(tmp_path: Path) -> None:
    root, selected = source(tmp_path)
    nested = selected / "nested"
    nested.mkdir()
    (nested / "code.py").write_text('import os\nos.system("example")\nraise RuntimeError\n')
    (selected / "manifest.json").write_text('{"requirements": ["example==1"]}')
    original = scan.capabilities.scan
    snapshots = []

    def observe(path, limits):
        assert limits == scan.ScanLimits(
            max_files=256, max_file_bytes=262144, max_python_bytes=262144, max_seconds=5.0
        )
        snapshots.append(path)
        assert path != selected
        assert (path / "nested/code.py").read_bytes() == (nested / "code.py").read_bytes()
        return original(path, limits)

    original_rules = scan.rules.scan

    def detect(path, limits=None):
        assert limits == scan.ScanLimits(
            max_files=256, max_file_bytes=262144, max_python_bytes=262144, max_seconds=5.0
        )
        return original_rules(path, limits)

    with (
        patch.object(scan.capabilities, "scan", side_effect=observe),
        patch.object(scan.rules, "scan", side_effect=detect),
    ):
        scanned = scan.scan_integration(root, "example")
    result = scanned.report
    assert not snapshots[0].exists()
    assert all(c.status is Status.COMPLETE for c in result.checks)
    assert {c.name for c in result.checks} == {"snapshot", "capabilities", "python-rules"}
    assert any(
        c.kind.value == "process" and c.location.path == "nested/code.py"
        for c in result.capabilities
    )
    assert result.target.version is result.target.commit is None
    # The same digest as the engine's installed-file digest of the live folder.
    assert result.target.artifact_sha256 == tree_digest(selected)
    assert scanned.files == {
        "manifest.json": hashlib.sha256((selected / "manifest.json").read_bytes()).hexdigest(),
        "nested/code.py": hashlib.sha256((nested / "code.py").read_bytes()).hexdigest(),
    }
    assert scanned.bytecode == {}
    assert from_dict(to_dict(result)) == result


@pytest.mark.parametrize(
    "kind", ["missing", "root_link", "selected_link", "file_link", "dir_link", "fifo"]
)
def test_refuses_unsafe_trees(tmp_path: Path, kind: str) -> None:
    root, selected = source(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    if kind == "missing":
        selected.rmdir()
    elif kind == "root_link":
        selected.rmdir()
        root.rmdir()
        root.symlink_to(outside)
    elif kind == "selected_link":
        selected.rmdir()
        selected.symlink_to(outside)
    elif kind in {"file_link", "dir_link"}:
        target = outside / "secret.py" if kind == "file_link" else outside
        (selected / "link").symlink_to(target)
    else:
        os.mkfifo(selected / "pipe")
    failed(root)


@pytest.mark.parametrize(
    "setting,value",
    [("MAX_ENTRIES", 0), ("MAX_BYTES", 0), ("MAX_FILE_BYTES", 0), ("MAX_DEPTH", 0), ("SECONDS", 0)],
)
def test_snapshot_limits_fail_without_scanning(tmp_path: Path, setting: str, value: int) -> None:
    root, selected = source(tmp_path)
    (selected / "nested").mkdir()
    (selected / "nested/code.py").write_text("pass")
    with patch.object(scan, setting, value), patch.object(scan.capabilities, "scan") as engine:
        failed(root)
    engine.assert_not_called()


def test_empty_tree_deadline_is_checked(tmp_path: Path) -> None:
    root, _ = source(tmp_path)
    with patch.object(scan, "monotonic", side_effect=[0, scan.SECONDS]):
        failed(root)


def test_scan_preserves_engine_coverage_gaps(tmp_path: Path) -> None:
    root, selected = source(tmp_path)
    (selected / "bad.py").write_bytes(b"\xff")
    result = scan.scan_integration(root, "example").report
    assert {c.name: c.status for c in result.checks} == {
        "snapshot": Status.COMPLETE,
        "capabilities": Status.PARTIAL,
        "python-rules": Status.PARTIAL,
    }
    assert all(
        c.problems[0].key == "problem.file_not_parsed"
        for c in result.checks
        if c.name != "snapshot"
    )


def test_file_changed_during_read_fails(tmp_path: Path) -> None:
    root, selected = source(tmp_path)
    path = selected / "code.py"
    path.write_text("pass")
    original = os.fstat
    count = 0

    def changed(fd):
        nonlocal count
        count += 1
        if count == 2:
            path.write_text("changed contents")
        return original(fd)

    with patch.object(scan.os, "fstat", side_effect=changed):
        failed(root)


def test_file_replaced_with_fifo_before_open_fails_without_blocking(tmp_path: Path) -> None:
    root, selected = source(tmp_path)
    path = selected / "code.py"
    path.write_text("pass")
    original = scan._file

    def raced(parent, name, destination, budget, relative):
        path.unlink()
        os.mkfifo(path)
        original(parent, name, destination, budget, relative)

    with patch.object(scan, "_file", side_effect=raced):
        failed(root)


def test_entry_budget_accepts_boundary_then_stops(tmp_path: Path) -> None:
    root, selected = source(tmp_path)
    for name in ("a", "b"):
        (selected / name).write_bytes(b"")
    with patch.object(scan, "MAX_ENTRIES", 2):
        assert all(
            c.status is Status.COMPLETE
            for c in scan.scan_integration(root, "example").report.checks
        )
        (selected / "c").write_bytes(b"")
        failed(root)


def test_entry_deadline_equality_stops(tmp_path: Path) -> None:
    root, selected = source(tmp_path)
    (selected / "a").touch()
    with patch.object(scan, "monotonic", side_effect=[0, scan.SECONDS]):
        failed(root)


def test_size_budgets_accept_exact_boundary_and_count_all_files(tmp_path: Path) -> None:
    root, selected = source(tmp_path)
    (selected / "a").write_bytes(b"1234")
    (selected / "b").write_bytes(b"5678")
    with patch.object(scan, "MAX_FILE_BYTES", 4), patch.object(scan, "MAX_BYTES", 8):
        assert all(
            c.status is Status.COMPLETE
            for c in scan.scan_integration(root, "example").report.checks
        )
        (selected / "c").write_bytes(b"9")
        failed(root)
    with patch.object(scan, "MAX_FILE_BYTES", 3):
        failed(root)


def test_copy_accepts_exact_depth_boundary(tmp_path: Path) -> None:
    root, selected = source(tmp_path)
    (selected / "a/b").mkdir(parents=True)
    with patch.object(scan, "MAX_DEPTH", 2):
        assert all(
            c.status is Status.COMPLETE
            for c in scan.scan_integration(root, "example").report.checks
        )
        (selected / "a/b/c").mkdir()
        failed(root)


def test_raced_file_link_is_not_followed(tmp_path: Path) -> None:
    root, selected = source(tmp_path)
    path = selected / "code.py"
    path.write_text("pass")
    secret = tmp_path / "secret.py"
    secret.write_text("import os")
    original = scan._file

    def raced(parent, name, destination, budget, relative):
        path.unlink()
        path.symlink_to(secret)
        original(parent, name, destination, budget, relative)

    with patch.object(scan, "_file", side_effect=raced):
        failed(root)


def test_renamed_selected_parent_keeps_original_descriptor(tmp_path: Path) -> None:
    root, selected = source(tmp_path)
    (selected / "code.py").write_text("import subprocess")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "code.py").write_text("syntax invalid !")
    original = scan._copy

    def raced(parent, destination, budget, depth=0):
        selected.rename(root / "moved")
        selected.symlink_to(outside)
        original(parent, destination, budget, depth)

    with patch.object(scan, "_copy", side_effect=raced):
        result = scan.scan_integration(root, "example").report
    assert all(c.status is Status.COMPLETE for c in result.checks)
    assert result.capabilities[0].subject == "subprocess"


def test_snapshot_read_has_a_bounded_overflow_sentinel(tmp_path: Path) -> None:
    _root, selected = source(tmp_path)
    (selected / "data").write_bytes(b"abc")
    original = os.fdopen

    class Handle:
        def __init__(self, handle):
            self.handle = handle

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.handle.close()

        def fileno(self):
            return self.handle.fileno()

        def read(self, limit):
            assert limit == scan.MAX_FILE_BYTES + 1
            return self.handle.read(limit)

    def opened(*args):
        return Handle(original(*args))

    destination = tmp_path / "copied"
    with patch.object(scan.os, "fdopen", new=opened), scan._directory(selected) as parent:
        scan._file(parent, "data", destination, scan.Budget(float("inf")), "data")
    assert destination.read_bytes() == b"abc"


def test_real_python_rule_finding_is_retained(tmp_path: Path) -> None:
    root, selected = source(tmp_path)
    (selected / "view.py").write_text("""from homeassistant.components.http import HomeAssistantView
from aiohttp import web
class Files(HomeAssistantView):
    requires_auth = False
    url = '/files/{filename:.*}'
    async def get(self, request, filename):
        return web.FileResponse(filename)
""")
    result = scan.scan_integration(root, "example").report
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "ha-unauth-view-unsanitized-path"
    assert finding.location.path == "view.py"
    assert finding.location.line == 7
    assert from_dict(to_dict(result)) == result


def test_representative_source_above_old_snapshot_cap_is_scanned(tmp_path: Path) -> None:
    root, selected = source(tmp_path)
    (selected / "code.py").write_text("pass\n" * 30_000)
    result = scan.scan_integration(root, "example").report
    assert {check.name: check.status for check in result.checks} == {
        "snapshot": Status.COMPLETE,
        "capabilities": Status.COMPLETE,
        "python-rules": Status.COMPLETE,
    }


@pytest.mark.parametrize("argument,count", [("filename", 1), ("sanitize_path(filename)", 0)])
def test_selected_snapshot_resolves_local_helpers_without_import(tmp_path, argument, count):
    root, selected = source(tmp_path)
    (selected / "manifest.json").write_text('{"domain":"example"}')
    (selected / "__init__.py").write_text(
        "from homeassistant.components.http import HomeAssistantView\n"
        "from custom_components.example.reader import read\n"
        "from homeassistant.util import sanitize_path\n"
        "raise RuntimeError('Never execute')\n"
        "class Files(HomeAssistantView):\n    requires_auth = False\n"
        "    url = '/files/{filename:.*}'\n"
        "    async def get(self, request, filename):\n"
        f"        return read({argument})\n"
    )
    (selected / "reader.py").write_text(
        "from aiohttp import web\nraise RuntimeError('Never execute')\n"
        "def read(path):\n    return web.FileResponse(path)\n"
    )
    report = scan.scan_integration(root, "example").report
    assert all(check.status is Status.COMPLETE for check in report.checks)
    assert len(report.findings) == count
    if count:
        assert report.findings[0].location.line == 9
        assert report.findings[0].params["sink_path"] == "reader.py"


def test_bytecode_is_recorded_apart_from_the_source_digest(tmp_path: Path) -> None:
    root, selected = source(tmp_path)
    (selected / "code.py").write_text("VALUE = 1\n")
    clean = scan.scan_integration(root, "example")
    cache = selected / "__pycache__"
    cache.mkdir()
    (cache / "code.cpython-314.pyc").write_bytes(b"compiled")
    (cache / "notes.txt").write_text("not bytecode")
    loaded = scan.scan_integration(root, "example")
    assert loaded.bytecode == {
        "__pycache__/code.cpython-314.pyc": hashlib.sha256(b"compiled").hexdigest()
    }
    assert "__pycache__/notes.txt" in loaded.files
    assert "__pycache__/code.cpython-314.pyc" not in loaded.files
    (cache / "notes.txt").unlink()
    after_load = scan.scan_integration(root, "example")
    assert after_load.report.target.artifact_sha256 == clean.report.target.artifact_sha256
    assert after_load.files == clean.files


def test_bytecode_is_hashed_but_never_scanned(tmp_path: Path) -> None:
    root, selected = source(tmp_path)
    (selected / "code.py").write_text("VALUE = 1\n")
    (selected / "loose.pyc").write_bytes(b"sourceless")
    clean = scan.scan_integration(root, "example").report
    cache = selected / "pkg/__pycache__"
    cache.mkdir(parents=True)
    (cache / "code.cpython-314.pyc").write_bytes(b"\x7fELF compiled")
    (cache / "notes.txt").write_text("not bytecode")
    loaded = scan.scan_integration(root, "example")
    # Only the loose .pyc is reported; the interpreter cache is shown by its hashes.
    assert [(c.kind.value, c.location.path) for c in loaded.report.capabilities] == [
        ("shipped_binary", "loose.pyc")
    ]
    assert loaded.report.capabilities == clean.capabilities
    assert loaded.report.checks == clean.checks
    assert set(loaded.bytecode) == {"pkg/__pycache__/code.cpython-314.pyc"}
    assert "pkg/__pycache__/notes.txt" in loaded.files


def test_bytecode_counts_toward_snapshot_limits(tmp_path: Path) -> None:
    root, selected = source(tmp_path)
    cache = selected / "__pycache__"
    cache.mkdir()
    (cache / "a.pyc").write_bytes(b"1234")
    with patch.object(scan, "MAX_ENTRIES", 2), patch.object(scan, "MAX_BYTES", 4):
        assert scan.scan_integration(root, "example").bytecode
        (cache / "b.pyc").write_bytes(b"5")
        failed(root)
    with patch.object(scan, "MAX_FILE_BYTES", 3):
        failed(root)


@pytest.mark.parametrize(
    ("relative", "expected"),
    [
        ("__pycache__/a.cpython-314.pyc", True),
        ("pkg/__pycache__/a.pyc", True),
        ("__pycache__/a.py", False),
        ("a.pyc", False),
        ("__pycache__.pyc", False),
        ("pkg/__pycache__x/a.pyc", False),
    ],
)
def test_only_pyc_files_in_cache_folders_are_bytecode(relative: str, expected: bool) -> None:
    assert scan.is_bytecode(relative) is expected


@pytest.mark.parametrize(
    ("manifest", "expected"),
    [
        ('{"version": "2.1.0"}', "2.1.0"),
        ('{"version": " "}', None),
        ('{"version": 2}', None),
        ("[]", None),
        ("not json", None),
        (None, None),
    ],
)
def test_manifest_version_names_the_target(tmp_path: Path, manifest, expected) -> None:
    root, selected = source(tmp_path)
    if manifest is not None:
        (selected / "manifest.json").write_text(manifest)
    assert scan.scan_integration(root, "example").report.target.version == expected


def test_failed_snapshot_has_no_identity(tmp_path: Path) -> None:
    root, _ = source(tmp_path)
    result = scan.scan_integration(root, "missing")
    assert result.report.target == scan.Target("missing")
    assert result.files == result.bytecode == {}


def test_source_digest_matches_the_engine_for_an_empty_folder(tmp_path: Path) -> None:
    assert scan.source_digest({}) == tree_digest(tmp_path)
