"""Make untrusted text safe to show.

Scanned code and tool output can hold characters that change how the text
around them looks: terminal escape codes that rewrite a line, bidirectional
controls that reorder it ("Trojan Source"), and zero-width characters that hide
in names. Every surface shows untrusted text through `display_safe`, which
writes those characters out visibly instead. Escaping for HTML or Markdown is
the surface's own job, on top of this.
"""

import re
import unicodedata

KEPT = frozenset("\n\t")
# Unicode 16.0 Default_Ignorable_Code_Point includes marks, letters and reserved
# characters too: https://www.unicode.org/Public/16.0.0/ucd/DerivedCoreProperties.txt
DEFAULT_IGNORABLE = re.compile(
    r"[\u00AD\u034F\u061C\u115F-\u1160\u17B4-\u17B5\u180B-\u180F"
    r"\u200B-\u200F\u202A-\u202E\u2060-\u206F\u3164\uFE00-\uFE0F\uFEFF"
    r"\uFFA0\uFFF0-\uFFF8\U0001BCA0-\U0001BCA3\U0001D173-\U0001D17A"
    r"\U000E0000-\U000E0FFF]"
)


def display_safe(text: str) -> str:
    """Controls and default-ignorable characters as ⟨U+XXXX⟩; other text unchanged."""
    return "".join(_visible(char) for char in text)


def _visible(char: str) -> str:
    hidden = unicodedata.category(char) in ("Cc", "Cf") or DEFAULT_IGNORABLE.fullmatch(char)
    if char in KEPT or not hidden:
        return char
    return f"⟨U+{ord(char):04X}⟩"
