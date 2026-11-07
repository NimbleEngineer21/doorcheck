"""Export Home Assistant setup strings from the shared message catalog."""

import json
import sys
from pathlib import Path

from doorcheck.messages import render
from tools.localization import inventory

ROOT = Path(__file__).resolve().parents[1] / "custom_components/doorcheck"


def catalog(locale: str | None = None) -> dict[str, object]:
    directory = {
        "name": render("ha.service.scan_directory_name", locale=locale),
        "description": render("ha.service.scan_directory_description", locale=locale),
    }
    return {
        "config": {
            "step": {"user": {"description": render("ha.config.description", locale=locale)}},
            "abort": {
                "already_configured": render("ha.config.already_configured", locale=locale),
                "single_instance_allowed": render("ha.config.already_configured", locale=locale),
                "already_in_progress": render("ha.config.already_in_progress", locale=locale),
            },
        },
        "options": {
            "step": {
                "init": {
                    "description": render("ha.options.description", locale=locale),
                    "data": {
                        "save_results": render("ha.options.save_results", locale=locale),
                        "check_status": render("ha.options.check_status", locale=locale),
                    },
                }
            }
        },
        "services": {
            "scan_integration": {
                "name": render("ha.service.scan_name", locale=locale),
                "description": render("ha.service.scan_description", locale=locale),
                "fields": {"directory": directory},
            },
            "get_inventory": {
                "name": render("ha.service.inventory_name", locale=locale),
                "description": render("ha.service.inventory_description", locale=locale),
            },
            "get_results": {
                "name": render("ha.service.results_name", locale=locale),
                "description": render("ha.service.results_description", locale=locale),
                "fields": {"directory": directory},
            },
            "mark_reviewed": {
                "name": render("ha.service.review_name", locale=locale),
                "description": render("ha.service.review_description", locale=locale),
                "fields": {
                    "directory": directory,
                    "scan_id": {
                        "name": render("ha.service.review_scan_id_name", locale=locale),
                        "description": render(
                            "ha.service.review_scan_id_description", locale=locale
                        ),
                    },
                },
            },
            "clear_results": {
                "name": render("ha.service.clear_name", locale=locale),
                "description": render("ha.service.clear_description", locale=locale),
            },
        },
        "issues": {
            "revoked": {
                "title": render("ha.issue.revoked_title", locale=locale),
                "description": render("ha.issue.revoked_description", locale=locale),
            },
            "status_unknown": {
                "title": render("ha.issue.unknown_title", locale=locale),
                "description": render("ha.issue.unknown_description", locale=locale),
            },
        },
        "exceptions": {
            "scan_busy": {"message": render("ha.service.scan_busy", locale=locale)},
            "scan_invalid_directory": {
                "message": render("ha.service.scan_invalid_directory", locale=locale)
            },
            "inventory_not_configured": {
                "message": render("ha.service.not_configured", locale=locale)
            },
            "results_clear_invalid": {
                "message": render("ha.service.results_clear_invalid", locale=locale)
            },
            "results_incomplete": {
                "message": render("ha.service.results_incomplete", locale=locale)
            },
            "results_invalid_request": {
                "message": render("ha.service.results_invalid_request", locale=locale)
            },
            "results_not_found": {"message": render("ha.service.results_not_found", locale=locale)},
            "results_not_saving": {
                "message": render("ha.service.results_not_saving", locale=locale)
            },
            "results_stale": {"message": render("ha.service.results_stale", locale=locale)},
            "results_write_failed": {
                "message": render("ha.service.results_write_failed", locale=locale)
            },
        },
    }


def synchronize(path: Path, data: dict[str, object], *, write: bool) -> bool:
    encoder = json.JSONEncoder(indent=2)
    encoder.ensure_ascii = False  # pragma: no mutate - False/None both preserve Unicode
    expected = encoder.encode(data) + "\n"
    if write:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(expected)
        return True
    return path.exists() and path.read_text() == expected


def main(argv: list[str]) -> int:
    if argv not in (["--check"], ["--write"]):
        print("Usage: python -m tools.ha_strings --check|--write")
        return 1
    outputs = {ROOT / "strings.json": catalog()}
    outputs.update(
        {ROOT / f"translations/{code}.json": catalog(code) for code in {"en", *inventory()}}
    )
    # Removed locales must not leave old strings active in Home Assistant.
    stale = [path.name for path in (ROOT / "translations").glob("*.json") if path not in outputs]
    stale.extend(
        path.name
        for path, data in outputs.items()
        if not synchronize(path, data, write=argv == ["--write"])
    )
    if stale:
        print(f"Stale Home Assistant strings: {', '.join(sorted(stale))}")
        return 1
    print("Home Assistant setup strings match the shared catalogs.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
