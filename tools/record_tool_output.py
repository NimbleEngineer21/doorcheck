"""Record what each scanning tool prints for the test fixtures.

    PATH=<folder with the pinned tools>:$PATH uv run python -m tools.record_tool_output

Run it after bumping a tool's version, then rerun the tests: the adapters are
tested against this recorded output, so a format change shows up as a failure.
"""

import argparse
from collections.abc import Sequence
from pathlib import Path

from doorcheck.adapters.base import Adapter, Parsed, prepare, raw_output
from doorcheck.adapters.semgrep import Semgrep
from doorcheck.adapters.zizmor import Zizmor

FIXTURES = Path("tests/fixtures")
CASES = ("unsafe", "clean")


def adapters(fixtures: Path) -> list[Adapter]:
    rules = (fixtures / "semgrep" / "path-join.yaml",)
    return [Semgrep(rules), Zizmor()]


def record(tools: Sequence[Adapter], fixtures: Path, cases: Sequence[str] = CASES) -> list[str]:
    """Write <fixtures>/tools/<tool>/<case>.json for every tool and case it runs on."""
    written = []
    for adapter in tools:
        for case in cases:
            output = raw_output(adapter, prepare(fixtures / "integrations" / case))
            if isinstance(output, Parsed):  # the tool had nothing to run on
                continue
            path = fixtures / "tools" / adapter.name / f"{case}.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(output)
            written.append(path.as_posix())
    return written


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--fixtures", type=Path, default=FIXTURES)
    fixtures = parser.parse_args(argv).fixtures
    for path in record(adapters(fixtures), fixtures):
        print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
