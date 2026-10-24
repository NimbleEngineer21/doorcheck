"""Checks on raw source text that the syntax tree can't show.

- Bidirectional control characters can make code display differently from how
  it runs ("Trojan Source", CVE-2021-42574).
- Python folds lookalike letters in names (NFKC normalization), so a name
  written in fullwidth letters (U+FF45 U+FF58 U+FF45 U+FF43) runs as `exec`
  while slipping past searches for the plain name.
"""

import io
import tokenize
import unicodedata
from collections.abc import Iterator

from doorcheck.capabilities.model import Capability, Kind
from doorcheck.findings import Location

# Embedding, override and isolate controls used in Trojan Source attacks.
BIDI_CONTROLS = frozenset("‪‫‬‭‮⁦⁧⁨⁩")


def bidi_controls(source: str, path: str) -> Iterator[Capability]:
    for line_number, line in enumerate(source.splitlines(), start=1):
        for column, char in enumerate(line, start=1):
            if char in BIDI_CONTROLS:
                location = Location(path, line_number, column)
                code = f"U+{ord(char):04X}"
                yield Capability(
                    Kind.BIDI_CONTROL, location, code, {"name": unicodedata.name(char)}
                )


def confusable_names(source: str, path: str) -> Iterator[Capability]:
    """Names that Python reads as a different name than the one written.

    Call only on source that already parsed; tokenizing unparseable text raises.
    """
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type != tokenize.NAME or token.string.isascii():
            continue
        folded = unicodedata.normalize("NFKC", token.string)
        if folded != token.string:
            location = Location(path, token.start[0], token.start[1] + 1)
            yield Capability(Kind.CONFUSABLE_NAME, location, token.string, {"runs_as": folded})
