"""Fail CI unless every mutant was positively caught by a test.

Counting survivors alone is not enough: a broken mutation run reports zero
survivors and zero kills, so kills must account for every mutant. Missing or
unreadable stats fail too, so the gate can never pass by default.
"""

import json
import sys
from pathlib import Path

DEFAULT_STATS = Path("mutants/mutmut-cicd-stats.json")

# A timeout means the mutant made the tests hang, so a test did notice it.
CAUGHT = ("killed", "timeout")


def uncaught(stats: dict[str, int]) -> int:
    """Mutants not caught by a test, including ones never tested at all."""
    caught = sum(stats.get(key, 0) for key in CAUGHT)
    return stats["total"] - stats.get("skipped", 0) - caught


def main(argv: list[str]) -> int:
    path = Path(argv[1]) if len(argv) > 1 else DEFAULT_STATS
    try:
        stats = json.loads(path.read_text())
        count = uncaught(stats)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"Mutation stats missing or unreadable ({path}): {error!r}")
        return 1
    if count > 0:
        print(f"{count} mutant(s) not caught by any test. Run `mutmut browse` to see them.")
        return 1
    print(f"All {stats['total']} mutants caught.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
