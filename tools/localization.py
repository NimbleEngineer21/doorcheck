"""Offline translation freshness and structural checks; no provider credentials."""

import json
import sys
from pathlib import Path

from doorcheck.messages import ENGLISH, MessageError
from doorcheck.messages.localization import catalog, context, decode, locales, source_hashes

ROOT = Path(__file__).resolve().parents[1]
MESSAGES = ROOT / "src/doorcheck/messages"


def check() -> list[str]:
    settings = context()
    registry = locales()
    expected = source_hashes(ENGLISH, settings)
    if decode((MESSAGES / "source-hashes.json").read_bytes()) != expected:
        raise MessageError("English/context changed: refresh translation source receipts")
    shipped = inventory()
    actual = {path.stem for path in (MESSAGES / "translations").glob("*.json")}
    if actual != shipped:
        raise MessageError("shipped locale inventory does not match catalogs")
    coverage = []
    for path in sorted((MESSAGES / "translations").glob("*.json")):
        locale = path.stem
        if locale == "en" or locale not in registry:
            raise MessageError("translation locale is outside the registry")
        rows = catalog(decode(path.read_bytes()), locale, ENGLISH, settings)
        coverage.append(f"{locale}: {len(rows)}/{len(ENGLISH)} translated messages")
    return coverage


def inventory() -> set[str]:
    shipped = decode((MESSAGES / "shipped-locales.json").read_bytes())
    if not isinstance(shipped, list) or any(not isinstance(code, str) for code in shipped):
        raise MessageError("invalid shipped locale inventory")
    if len(shipped) != len(set(shipped)):
        raise MessageError("duplicate shipped locale inventory")
    return set(shipped)


def snapshot_english() -> None:
    if inventory() or list((MESSAGES / "translations").glob("*.json")):
        raise MessageError("English-only snapshot refused while translated catalogs are active")
    data = source_hashes(ENGLISH, context())
    (MESSAGES / "source-hashes.json").write_text(json.dumps(data, indent=2) + "\n")


def main(argv: list[str]) -> int:
    if argv == ["--snapshot-english"]:
        try:
            snapshot_english()
        except (OSError, MessageError) as error:
            print(f"English snapshot failed: {error}")
            return 1
        print("Updated English-only source receipts; no provider call was made.")
        return 0
    if argv != ["--check"]:
        print("Usage: python -m tools.localization --check|--snapshot-english")
        return 1
    try:
        coverage = check()
    except (OSError, MessageError) as error:
        print(f"Localization check failed: {error}")
        return 1
    print(f"Checked {len(ENGLISH)} English messages and {len(locales())} registered locales.")
    print(
        "\n".join(coverage)
        if coverage
        else "No translated catalogs shipped; English fallback only."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
