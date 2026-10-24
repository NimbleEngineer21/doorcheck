"""Repository conventions that a reviewer would otherwise have to remember."""

import re
from pathlib import Path

PRAGMA = re.compile(r"pragma: no mutate(?P<rest>.*)")


def test_every_mutation_pragma_says_why() -> None:
    unexplained = [
        f"{path}:{number}"
        for folder in ("src", "tools")
        for path in sorted(Path(folder).rglob("*.py"))
        for number, line in enumerate(path.read_text().splitlines(), start=1)
        if (match := PRAGMA.search(line)) and not match.group("rest").startswith(" - ")
    ]
    assert unexplained == []
