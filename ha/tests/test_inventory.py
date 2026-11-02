"""Filesystem evidence, limits and race resistance without importing target code."""

import json
import os
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

import pytest

from custom_components.doorcheck import inventory


def integration(root: Path, directory: str = "demo", **fields: object) -> Path:
    folder = root / directory
    folder.mkdir(parents=True)
    manifest = {"domain": directory, "name": "Demo", "version": "1.2.3", **fields}
    (folder / "manifest.json").write_text(json.dumps(manifest))
    return folder


def test_manifest_facts_are_deterministic_and_not_safety_claims(tmp_path: Path) -> None:
    marker = tmp_path / "executed"
    first = integration(
        tmp_path, "zeta", documentation="private-token", extra={"password": "secret"}
    )
    (first / "__init__.py").write_text(f"open({str(marker)!r}, 'w').write('executed')")
    integration(tmp_path, "alpha", name="Réparations")
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__init__.py").write_text("raise AssertionError('never import')")
    result = inventory.read_inventory(tmp_path).as_dict()
    assert result == {
        "schema_version": 1,
        "scope": "custom_integrations_on_disk",
        "status": "complete",
        "items": [
            {
                "directory": "alpha",
                "domain": "alpha",
                "name": "Réparations",
                "version": "1.2.3",
                "origin": "unknown",
                "problems": [],
            },
            {
                "directory": "zeta",
                "domain": "zeta",
                "name": "Demo",
                "version": "1.2.3",
                "origin": "unknown",
                "problems": [],
            },
        ],
        "problems": [],
    }
    assert not marker.exists()
    assert str(tmp_path) not in json.dumps(result)
    assert "private-token" not in json.dumps(result) and "secret" not in json.dumps(result)


@pytest.mark.parametrize("root_kind", ["missing", "file", "symlink", "fifo"])
def test_unavailable_root_is_failed_not_empty_complete(tmp_path: Path, root_kind: str) -> None:
    root = tmp_path / "root"
    if root_kind == "fifo":
        os.mkfifo(root)
    elif root_kind == "file":
        root.write_text("{}")
    elif root_kind == "symlink":
        root.symlink_to(tmp_path, target_is_directory=True)
    result = inventory.read_inventory(root).as_dict()
    assert result["status"] == "failed"
    assert result["items"] == []
    assert result["problems"] == ["problem.inventory_root_unreadable"]


def test_empty_root_and_nonintegration_files(tmp_path: Path) -> None:
    assert inventory.read_inventory(tmp_path).as_dict()["status"] == "complete"
    (tmp_path / "readme.txt").write_text("not an integration")
    assert inventory.read_inventory(tmp_path).items == ()


@pytest.mark.parametrize(
    "raw",
    [
        "not json",
        "[]",
        "null",
        '{"domain":"demo","domain":"demo","name":"Demo","version":"1"}',
        '{"domain":"demo","name":"Demo","version":"1","nested":{"x":1,"x":2}}',
        '{"domain":"demo","name":"Demo","version":"1","x":NaN}',
        '{"domain":"demo","name":"Demo","version":"1","x":Infinity}',
        '{"domain":"demo","name":"Demo","version":"1","x":-Infinity}',
        "[" * 1100,
        "\ufeff{}",
    ],
)
def test_malformed_manifest_is_explicit_partial(tmp_path: Path, raw: str) -> None:
    folder = integration(tmp_path)
    (folder / "manifest.json").write_text(raw)
    result = inventory.read_inventory(tmp_path).as_dict()
    assert result["status"] == "partial"
    assert result["items"][0] == {
        "directory": "demo",
        "domain": None,
        "name": None,
        "version": None,
        "origin": "unknown",
        "problems": ["problem.inventory_manifest_invalid"],
    }


@pytest.mark.parametrize("field", ["domain", "name", "version"])
@pytest.mark.parametrize("value", [None, False, 123, "", " ", "a" * 257, "bad\ud800"])
def test_invalid_required_fields(tmp_path: Path, field: str, value: object) -> None:
    integration(tmp_path, **{field: value})
    assert (
        inventory.read_inventory(tmp_path).items[0].problem == "problem.inventory_manifest_invalid"
    )


def test_mismatched_domain_and_long_valid_domain(tmp_path: Path) -> None:
    integration(tmp_path, domain="different")
    integration(tmp_path, "a" * 128)
    result = inventory.read_inventory(tmp_path)
    assert result.items[0].domain == "a" * 128
    assert result.items[1].problem == "problem.inventory_manifest_invalid"


def test_missing_manifest_and_invalid_folder_name(tmp_path: Path) -> None:
    (tmp_path / "missing").mkdir()
    integration(tmp_path, "bad\nname")
    items = inventory.read_inventory(tmp_path).items
    assert items[0].directory == "bad⟨U+000A⟩name"
    assert items[0].problem == "problem.inventory_folder_invalid"
    assert items[1].problem == "problem.inventory_manifest_missing"
    assert inventory._display("bad\udcff\t\u202e") == "bad\\udcff⟨U+0009⟩⟨U+202E⟩"


@pytest.mark.parametrize(
    "kind", ["folder_link", "manifest_link", "fifo", "directory_manifest", "invalid_utf8"]
)
def test_special_files_are_not_followed_or_blocking(tmp_path: Path, kind: str) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = integration(tmp_path / "outside")
    if kind == "folder_link":
        (root / "demo").symlink_to(outside, target_is_directory=True)
    else:
        folder = integration(root)
        manifest = folder / "manifest.json"
        manifest.unlink()
        if kind == "manifest_link":
            manifest.symlink_to(outside / "manifest.json")
        elif kind == "fifo":
            os.mkfifo(manifest)
        elif kind == "directory_manifest":
            manifest.mkdir()
        else:
            manifest.write_bytes(b"\xff")
    item = inventory.read_inventory(root).items[0]
    expected = (
        "problem.inventory_manifest_invalid"
        if kind == "invalid_utf8"
        else "problem.inventory_entry_unreadable"
    )
    assert item.directory == "demo"
    assert item.problem == expected and item.domain is None


def test_byte_and_entry_limits_include_ignored_entries(tmp_path: Path) -> None:
    folder = integration(tmp_path)
    size = (folder / "manifest.json").stat().st_size
    assert inventory.read_inventory(tmp_path, max_manifest_bytes=size).items[0].problem is None
    assert (
        inventory.read_inventory(tmp_path, max_manifest_bytes=size - 1).items[0].problem
        == "problem.inventory_manifest_invalid"
    )
    assert inventory.read_inventory(tmp_path, max_entries=1).items[0].domain == "demo"
    (tmp_path / "ignored.txt").touch()
    result = inventory.read_inventory(tmp_path, max_entries=1).as_dict()
    assert result["status"] == "partial" and result["items"] == []
    assert result["problems"] == ["problem.inventory_entry_limit"]


@pytest.mark.parametrize("times, expected_items", [([0, 5], 0), ([0, 0, 5], 1)])
def test_time_budget_is_explicit_before_and_after_reads(
    tmp_path: Path, times: list[int], expected_items: int
) -> None:
    integration(tmp_path)
    readings = iter(times)
    result = inventory.read_inventory(tmp_path, seconds=5, clock=lambda: next(readings)).as_dict()
    assert len(result["items"]) == expected_items
    assert result["status"] == "partial"
    assert result["problems"] == ["problem.inventory_time_limit"]


def test_scandir_failure_is_not_an_empty_success(tmp_path: Path) -> None:
    with patch.object(inventory.os, "scandir", side_effect=PermissionError("private path")):
        result = inventory.read_inventory(tmp_path).as_dict()
    assert result["status"] == "failed"
    assert result["problems"] == ["problem.inventory_root_unreadable"]
    assert "private" not in json.dumps(result)


def test_disappeared_entry_keeps_other_entries(tmp_path: Path) -> None:
    integration(tmp_path, "valid")

    class Disappeared:
        name = "unreadable"

    original = inventory.os.scandir

    @contextmanager
    def entries(parent):
        with original(parent) as scan:
            yield iter([Disappeared(), *scan])

    with patch.object(inventory.os, "scandir", side_effect=entries):
        result = inventory.read_inventory(tmp_path)
    assert [item.directory for item in result.items] == ["unreadable", "valid"]
    assert result.items[0].problem == "problem.inventory_manifest_missing"
    assert result.items[1].domain == "valid"


def test_open_directory_descriptor_survives_path_replacement(tmp_path: Path) -> None:
    root = tmp_path / "root"
    folder = integration(root, name="Inside")
    outside = integration(tmp_path / "outside", name="Outside")
    original = inventory._manifest

    def replace(parent: int, limit: int):
        folder.rename(root / "moved")
        folder.symlink_to(outside, target_is_directory=True)
        return original(parent, limit)

    with patch.object(inventory, "_manifest", side_effect=replace):
        item = inventory.read_inventory(root).items[0]
    assert item.name == "Inside"


def test_folder_swapped_to_link_before_open_is_refused(tmp_path: Path) -> None:
    root = tmp_path / "root"
    folder = integration(root)
    outside = integration(tmp_path / "outside", name="Outside")
    original = os.open

    def replace(path, flags, **kwargs):
        if path == "demo":
            folder.rename(root / "moved")
            folder.symlink_to(outside, target_is_directory=True)
        return original(path, flags, **kwargs)

    with patch.object(inventory.os, "open", side_effect=replace):
        item = inventory.read_inventory(root).items[0]
    assert item.domain is None and item.problem == "problem.inventory_entry_unreadable"


def test_oversized_valid_json_prefix_cannot_look_complete(tmp_path: Path) -> None:
    folder = integration(tmp_path)
    path = folder / "manifest.json"
    original = path.read_bytes()
    path.write_bytes(original + b" ")
    result = inventory.read_inventory(tmp_path, max_manifest_bytes=len(original))
    assert result.items[0].problem == "problem.inventory_manifest_invalid"


def test_directory_enumeration_stops_at_the_bound(tmp_path: Path) -> None:
    @contextmanager
    def entries(parent):
        def bounded():
            yield object()
            yield object()
            raise AssertionError("enumerated beyond the configured limit plus sentinel")

        yield bounded()

    with patch.object(inventory.os, "scandir", side_effect=entries):
        result = inventory.read_inventory(tmp_path, max_entries=1)
    assert result.problems == ("problem.inventory_entry_limit",)


def test_manifest_read_never_consumes_unbounded_output(tmp_path: Path) -> None:
    integration(tmp_path)
    original = inventory.os.fdopen

    @contextmanager
    def opened(descriptor, mode):
        with original(descriptor, mode) as handle:

            class Bounded:
                def fileno(self):
                    return handle.fileno()

                def read(self, amount=None):
                    assert amount is not None and 0 < amount <= 65
                    return handle.read(amount)

            yield Bounded()

    with patch.object(inventory.os, "fdopen", side_effect=opened):
        result = inventory.read_inventory(tmp_path, max_manifest_bytes=64)
    assert result.items[0].domain == "demo"


def test_maximum_text_length_is_accepted(tmp_path: Path) -> None:
    integration(tmp_path, name="n" * 256, version="v" * 256)
    item = inventory.read_inventory(tmp_path).items[0]
    assert item.problem is None
    assert item.name == "n" * 256 and item.version == "v" * 256


def test_manifest_filename_is_case_sensitive_on_every_test_platform(tmp_path: Path) -> None:
    integration(tmp_path)
    original = os.open

    def case_sensitive(path, flags, **kwargs):
        if isinstance(path, str) and path.lower() == "manifest.json" and path != "manifest.json":
            raise FileNotFoundError(path)
        return original(path, flags, **kwargs)

    with patch.object(inventory.os, "open", side_effect=case_sensitive):
        assert inventory.read_inventory(tmp_path).items[0].domain == "demo"
