import pytest

from doorcheck.text import display_safe


@pytest.mark.parametrize(
    ("text", "shown"),
    [
        ("plain text, café", "plain text, café"),
        ("cafe\u0301, \u0915\u093f", "cafe\u0301, \u0915\u093f"),
        ("ex\u034fec", "ex⟨U+034F⟩ec"),
        ("\ufff9text\ufffaannotation\ufffb", "⟨U+FFF9⟩text⟨U+FFFA⟩annotation⟨U+FFFB⟩"),
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


@pytest.mark.parametrize(
    "codepoint",
    [
        0x115F,
        0x1160,
        0x17B4,
        0x17B5,
        0x180B,
        0x180D,
        0x180F,
        0x2065,
        0x3164,
        0xFE00,
        0xFE0F,
        0xFFA0,
        0xFFF0,
        0xFFF8,
        0xE0000,
        0xE0002,
        0xE0080,
        0xE0100,
        0xE01EF,
        0xE01F0,
        0xE0FFF,
    ],
)
def test_default_ignorable_characters_outside_control_categories_are_visible(
    codepoint: int,
) -> None:
    assert display_safe(chr(codepoint)) == f"⟨U+{codepoint:04X}⟩"


@pytest.mark.parametrize(
    "codepoint",
    [
        0x034E,
        0x0350,
        0x115E,
        0x1161,
        0x17B3,
        0x17B6,
        0x180A,
        0x1810,
        0x3163,
        0x3165,
        0xFDFF,
        0xFE10,
        0xFF9F,
        0xFFA1,
        0xFFE6,
        0x1F600,
        0xE1000,
    ],
)
def test_ordinary_characters_and_combining_marks_are_preserved(codepoint: int) -> None:
    assert display_safe(chr(codepoint)) == chr(codepoint)
