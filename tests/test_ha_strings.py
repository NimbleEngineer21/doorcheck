"""Native HA setup translations stay tied to the shared message catalog."""

import json
import runpy
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from doorcheck.messages import render
from tools import ha_strings


def test_native_structure_uses_shared_messages() -> None:
    assert ha_strings.catalog("en") == {
        "config": {
            "step": {"user": {"description": render("ha.config.description")}},
            "abort": {
                "already_configured": render("ha.config.already_configured"),
                "single_instance_allowed": render("ha.config.already_configured"),
                "already_in_progress": render("ha.config.already_in_progress"),
            },
        },
        "services": {
            "scan_integration": {
                "name": render("ha.service.scan_name"),
                "description": render("ha.service.scan_description"),
                "fields": {
                    "directory": {
                        "name": render("ha.service.scan_directory_name"),
                        "description": render("ha.service.scan_directory_description"),
                    }
                },
            },
            "get_inventory": {
                "name": render("ha.service.inventory_name"),
                "description": render("ha.service.inventory_description"),
            },
        },
        "exceptions": {
            "scan_busy": {"message": render("ha.service.scan_busy")},
            "scan_invalid_directory": {"message": render("ha.service.scan_invalid_directory")},
            "inventory_not_configured": {
                "message": render("ha.service.not_configured"),
            },
        },
    }


def test_repository_setup_strings_are_current(capsys: pytest.CaptureFixture[str]) -> None:
    assert ha_strings.main(["--check"]) == 0
    assert capsys.readouterr().out == "Home Assistant setup strings match the shared catalogs.\n"


def test_export_check_detects_missing_and_changed_files(tmp_path: Path) -> None:
    root = tmp_path / "missing" / "doorcheck"
    with patch.object(ha_strings, "ROOT", root):
        assert ha_strings.main(["--check"]) == 1
        assert ha_strings.main(["--write"]) == 0
        assert ha_strings.main(["--check"]) == 0
        assert sorted(p.relative_to(root).as_posix() for p in root.rglob("*.json")) == [
            "strings.json",
            "translations/en.json",
        ]
        paths = [root / "strings.json", root / "translations/en.json"]
        assert paths[0].read_bytes() == paths[1].read_bytes()
        for path in paths:
            original = path.read_bytes()
            path.write_text("{}")
            assert ha_strings.main(["--check"]) == 1
            path.write_bytes(original)


def test_export_uses_the_selected_locale(tmp_path: Path) -> None:
    def render_selected(key: str, *, locale: str | None) -> str:
        return f"{locale or 'en'}:{key}"

    with (
        patch.object(ha_strings, "ROOT", tmp_path),
        patch.object(ha_strings, "inventory", return_value={"de"}),
        patch.object(ha_strings, "render", side_effect=render_selected),
    ):
        assert ha_strings.main(["--write"]) == 0
        data = json.loads((tmp_path / "translations/de.json").read_text())
        assert data["config"]["step"]["user"]["description"] == "de:ha.config.description"
        assert data["config"]["abort"] == {
            "already_configured": "de:ha.config.already_configured",
            "single_instance_allowed": "de:ha.config.already_configured",
            "already_in_progress": "de:ha.config.already_in_progress",
        }
        english = json.loads((tmp_path / "strings.json").read_text())
        assert english["config"]["step"]["user"]["description"] == "en:ha.config.description"
        assert english["config"]["abort"] == {
            "already_configured": "en:ha.config.already_configured",
            "single_instance_allowed": "en:ha.config.already_configured",
            "already_in_progress": "en:ha.config.already_in_progress",
        }
        for locale, translated in (("de", data), ("en", english)):
            assert translated["services"]["scan_integration"] == {
                "name": f"{locale}:ha.service.scan_name",
                "description": f"{locale}:ha.service.scan_description",
                "fields": {
                    "directory": {
                        "name": f"{locale}:ha.service.scan_directory_name",
                        "description": f"{locale}:ha.service.scan_directory_description",
                    }
                },
            }
            for key in ("scan_busy", "scan_invalid_directory"):
                assert translated["exceptions"][key]["message"] == f"{locale}:ha.service.{key}"
            assert translated["services"]["get_inventory"] == {
                "name": f"{locale}:ha.service.inventory_name",
                "description": f"{locale}:ha.service.inventory_description",
            }
            assert (
                translated["exceptions"]["inventory_not_configured"]["message"]
                == f"{locale}:ha.service.not_configured"
            )
        assert ha_strings.main(["--check"]) == 0


@pytest.mark.parametrize("args", [[], ["--unknown"], ["--write", "extra"]])
def test_invalid_export_arguments(args: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    assert ha_strings.main(args) == 1
    assert capsys.readouterr().out == "Usage: python -m tools.ha_strings --check|--write\n"


def test_export_entrypoint() -> None:
    with patch.dict(sys.modules), patch.object(sys, "argv", ["ha_strings", "--check"]):
        sys.modules.pop("tools.ha_strings", None)
        with pytest.raises(SystemExit) as stopped:
            runpy.run_module("tools.ha_strings", run_name="__main__")
    assert stopped.value.code == 0


def test_orphaned_translation_is_reported_and_not_silently_deleted(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with patch.object(ha_strings, "ROOT", tmp_path):
        assert ha_strings.main(["--write"]) == 0
        capsys.readouterr()
        (tmp_path / "translations/yy.json").write_text("{}")
        orphan = tmp_path / "translations/xx.json"
        orphan.write_text("{}")
        assert ha_strings.main(["--check"]) == 1
        assert capsys.readouterr().out == "Stale Home Assistant strings: xx.json, yy.json\n"
        assert ha_strings.main(["--write"]) == 1
        assert orphan.read_text() == "{}"


def test_exports_keep_readable_unicode_and_stable_formatting(tmp_path: Path) -> None:
    path = tmp_path / "translations/fr.json"
    assert ha_strings.synchronize(path, {"description": "Réparations"}, write=True)
    assert path.read_text() == '{\n  "description": "Réparations"\n}\n'
    assert ha_strings.synchronize(path, {"description": "Réparations"}, write=False)
