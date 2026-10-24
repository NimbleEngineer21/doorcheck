import pytest

from doorcheck.text import display_safe


@pytest.mark.parametrize(
    ("text", "shown"),
    [
        ("plain text, café", "plain text, café"),
        ("tabs\tand\nnewlines", "tabs\tand\nnewlines"),
        ("\x1b[2J\x1b[32mALL CLEAR", "⟨U+001B⟩[2J⟨U+001B⟩[32mALL CLEAR"),
        ("if admin:‮ }⁦", "if admin:⟨U+202E⟩ }⟨U+2066⟩"),
        ("ex​ec", "ex⟨U+200B⟩ec"),
        ("bell\x07 and \x7f and \r", "bell⟨U+0007⟩ and ⟨U+007F⟩ and ⟨U+000D⟩"),
        ("﻿bom", "⟨U+FEFF⟩bom"),
        ("", ""),
    ],
)
def test_control_and_invisible_characters_are_written_out(text: str, shown: str) -> None:
    assert display_safe(text) == shown
