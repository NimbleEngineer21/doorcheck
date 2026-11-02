"""Export Home Assistant setup strings from the shared message catalog."""

import json
import sys
from pathlib import Path

from doorcheck.messages import render
from tools.localization import inventory

ROOT = Path(__file__).resolve().parents[1] / "ha/custom_components/doorcheck"


def catalog(locale: str | None = None) -> dict[str, object]:
    return {
        "config": {
            "step": {"user": {"description": render("ha.config.description", locale=locale)}},
            "abort": {
                "already_configured": render("ha.config.already_configured", locale=locale),
                "single_instance_allowed": render("ha.config.already_configured", locale=locale),
                "already_in_progress": render("ha.config.already_in_progress", locale=locale),
            },
        },
        "services": {
            "get_inventory": {
                "name": render("ha.service.inventory_name", locale=locale),
                "description": render("ha.service.inventory_description", locale=locale),
            }
        },
        "exceptions": {
            "inventory_not_configured": {
                "message": render("ha.service.not_configured", locale=locale)
            }
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
