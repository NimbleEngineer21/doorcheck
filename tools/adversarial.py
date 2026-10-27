"""Offline capability benchmark over inert, paired source specimens.

Only text is materialized, under fresh temporary directories. Samples are never
imported, compiled to bytecode, installed, executed or sent to external tools.
This measures source observations, not malicious-behavior detection.
"""

import json
import re
import sys
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from typing import Any

from doorcheck.capabilities import scan
from doorcheck.capabilities.model import Capability
from doorcheck.capabilities.scan import Scanned
from doorcheck.tree import read_regular
from tools.corpus import CASE_ID

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/malicious"
SOURCE_NAME = re.compile(r"[0-9]{2}-[a-zA-Z0-9_.-]+\.txt")
MAX_SOURCE_BYTES = 100_000
Scanner = Callable[[Path], Scanned]


def load() -> dict[str, Any]:
    """Repository-owned manifest; fixture identities and paths are checked on use."""
    data: dict[str, Any] = json.loads((ROOT / "benchmark/adversarial.json").read_bytes())
    return data


def target_path(logical: str) -> Path:
    path = PurePosixPath(logical)
    if not path.parts or path.is_absolute() or ".." in path.parts:
        raise ValueError("invalid specimen target path")
    if "\\" in logical or "\0" in logical:
        raise ValueError("invalid specimen target path")
    return Path(*path.parts)


def materialize(pair: dict[str, Any], variant: str, target: Path) -> None:
    if not CASE_ID.fullmatch(pair["id"]) or variant not in ("adversarial", "benign"):
        raise ValueError("invalid specimen identity")
    for logical, source in pair[variant]["files"].items():
        relative = target_path(logical)
        if not SOURCE_NAME.fullmatch(source):
            raise ValueError("invalid specimen source name")
        data = read_regular(FIXTURES / pair["id"] / variant / source, MAX_SOURCE_BYTES + 1)
        if len(data) > MAX_SOURCE_BYTES:
            raise ValueError("specimen exceeds size limit")
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)


def matches(expected: dict[str, Any], capability: Capability) -> bool:
    return (
        expected["kind"] == capability.kind.value
        and expected["subject"] == capability.subject
        and expected["path"] == capability.location.path
        and expected["line"] == capability.location.line
        and ("attrs" not in expected or expected["attrs"] == dict(capability.attrs))
    )


def evaluate(pair: dict[str, Any], variant: str, scanner: Scanner = scan) -> dict[str, Any]:
    specimen = pair[variant]
    with TemporaryDirectory() as directory:
        folder = Path(directory)
        materialize(pair, variant, folder)
        result = scanner(folder)
    missing = [e for e in specimen["expect"] if not any(matches(e, c) for c in result.capabilities)]
    forbidden = sorted({c.kind.value for c in result.capabilities} & set(specimen["absent"]))
    return {
        "pair": pair["id"],
        "variant": variant,
        "expected": len(specimen["expect"]),
        "matched": len(specimen["expect"]) - len(missing),
        "observations": len(result.capabilities),
        "missing": missing,
        "forbidden": forbidden,
        "problems": [p.key for p in result.problems],
    }


def measure(data: dict[str, Any], scanner: Scanner = scan) -> list[dict[str, Any]]:
    return [
        evaluate(pair, variant, scanner)
        for pair in data["pairs"]
        for variant in ("adversarial", "benign")
    ]


def signal_count(row: dict[str, Any]) -> str:
    return f"{row['matched']}/{row['expected']}" if row["expected"] else "not asserted"


def markdown(data: dict[str, Any], rows: list[dict[str, Any]]) -> str:
    text = "# Inert adversarial corpus: current coverage\n\n"
    text += (
        "This is a capability-reader benchmark, not a malware detection score. "
        "No Home Assistant detection rule is run. Observations in benign examples "
        "are expected; they are not false alarms. JS/YAML interpretation and the "
        "behavioral gaps below remain open work even when all signal expectations match. "
        "Not asserted means no positive signal expectation; absence constraints still apply.\n\n"
        "| Pair | Adversarial signals | Benign signals | Observations (A/B) "
        "| Open detection work |\n"
        "| --- | ---: | ---: | ---: | --- |\n"
    )
    indexed = {(row["pair"], row["variant"]): row for row in rows}
    for pair in data["pairs"]:
        a, b = (indexed[pair["id"], variant] for variant in ("adversarial", "benign"))
        text += (
            f"| {pair['id']} | {signal_count(a)} | {signal_count(b)} "
            f"| {a['observations']}/{b['observations']} | {', '.join(pair['gaps'])} |\n"
        )
    text += "\n## Provenance\n\n"
    for name, source in data["sources"].items():
        text += f"- [{name}]({source['url']}): {source['note']}\n"
    return text


def outputs(data: dict[str, Any], rows: list[dict[str, Any]]) -> dict[Path, bytes]:
    return {
        ROOT / "benchmark/adversarial-baseline.json": (json.dumps(rows, indent=2) + "\n").encode(),
        ROOT / "docs/adversarial-coverage.md": markdown(data, rows).encode(),
    }


def synchronize(generated: dict[Path, bytes], *, write: bool) -> list[str]:
    stale = []
    for path, content in generated.items():
        if write:
            path.write_bytes(content)
        elif not path.exists() or path.read_bytes() != content:
            stale.append(str(path.relative_to(ROOT)))
    return stale


def main(argv: list[str]) -> int:
    if argv not in (["--check"], ["--write"]):
        print("Usage: python -m tools.adversarial --check|--write")
        return 1
    data = load()
    rows = measure(data)
    failures = [
        f"{r['pair']}/{r['variant']}"
        for r in rows
        if r["missing"] or r["forbidden"] or r["problems"]
    ]
    if failures:
        print(f"Specimen coverage regressions: {failures}")
        return 1
    stale = synchronize(outputs(data, rows), write=argv == ["--write"])
    if stale:
        print(f"Stale specimen reports: {stale}")
        return 1
    print(
        f"Checked {len(rows)} inert specimens; capability expectations match. "
        "Detection gaps remain open."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
