"""Make untrusted text safe to show.

Scanned code and tool output can hold characters that change how the text
around them looks: terminal escape codes that rewrite a line, bidirectional
controls that reorder it ("Trojan Source"), and zero-width characters that hide
in names. Every surface shows untrusted text through `display_safe`, which
writes those characters out visibly instead. Escaping for HTML or Markdown is
the surface's own job, on top of this.
"""

import unicodedata

KEPT = frozenset("\n\t")


def display_safe(text: str) -> str:
    """Control and invisible formatting characters as ⟨U+XXXX⟩; everything else unchanged."""
    return "".join(_visible(char) for char in text)


def _visible(char: str) -> str:
    if char in KEPT or unicodedata.category(char) not in ("Cc", "Cf"):
        return char
    return f"⟨U+{ord(char):04X}⟩"
