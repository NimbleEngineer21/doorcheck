"""Snapshot boundaries and real engine results, without candidate execution."""

import os
from pathlib import Path
from unittest.mock import patch

import pytest
from doorcheck.checks import Status
from doorcheck.report import from_dict, to_dict

from custom_components.doorcheck import scan


def source(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "custom_components"
    selected = root / "example"
    selected.mkdir(parents=True)
    return root, selected


def failed(root: Path) -> None:
    result = scan.scan_integration(root, "example")
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
            max_files=256, max_file_bytes=131072, max_python_bytes=131072, max_seconds=5.0
        )
        snapshots.append(path)
        assert path != selected
        assert (path / "nested/code.py").read_bytes() == (nested / "code.py").read_bytes()
        return original(path, limits)

    original_rules = scan.rules.scan

    def detect(path, limits=None):
        assert limits == scan.ScanLimits(
            max_files=256, max_file_bytes=131072, max_python_bytes=131072, max_seconds=5.0
        )
        return original_rules(path, limits)

    with (
        patch.object(scan.capabilities, "scan", side_effect=observe),
        patch.object(scan.rules, "scan", side_effect=detect),
    ):
        result = scan.scan_integration(root, "example")
    assert not snapshots[0].exists()
    assert all(c.status is Status.COMPLETE for c in result.checks)
    assert {c.name for c in result.checks} == {"snapshot", "capabilities", "python-rules"}
    assert any(
        c.kind.value == "process" and c.location.path == "nested/code.py"
        for c in result.capabilities
    )
    assert result.target.version is result.target.commit is result.target.artifact_sha256 is None
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
    result = scan.scan_integration(root, "example")
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

    def raced(parent, name, destination, budget):
        path.unlink()
        os.mkfifo(path)
        original(parent, name, destination, budget)

    with patch.object(scan, "_file", side_effect=raced):
        failed(root)


def test_entry_budget_accepts_boundary_then_stops(tmp_path: Path) -> None:
    root, selected = source(tmp_path)
    for name in ("a", "b"):
        (selected / name).write_bytes(b"")
    with patch.object(scan, "MAX_ENTRIES", 2):
        assert all(
            c.status is Status.COMPLETE for c in scan.scan_integration(root, "example").checks
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
            c.status is Status.COMPLETE for c in scan.scan_integration(root, "example").checks
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
            c.status is Status.COMPLETE for c in scan.scan_integration(root, "example").checks
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

    def raced(parent, name, destination, budget):
        path.unlink()
        path.symlink_to(secret)
        original(parent, name, destination, budget)

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
        result = scan.scan_integration(root, "example")
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
        scan._file(parent, "data", destination, scan.Budget(float("inf")))
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
    result = scan.scan_integration(root, "example")
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "ha-unauth-view-unsanitized-path"
    assert finding.location.path == "view.py"
    assert finding.location.line == 7
    assert from_dict(to_dict(result)) == result
