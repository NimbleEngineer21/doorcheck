import pytest

from doorcheck.capabilities.model import Kind
from doorcheck.capabilities.source_text import BIDI_CONTROLS, bidi_controls, confusable_names

# exec spelled in fullwidth letters, which NFKC folds back to ASCII.
FULLWIDTH_EXEC = "".join(chr(0xFF00 + ord(c) - 0x20) for c in "exec")


@pytest.mark.parametrize("char", sorted(BIDI_CONTROLS))
def test_every_bidi_control_is_reported_with_its_position(char: str) -> None:
    source = f"ok = 1\nif user == 'admin{char}':\n"
    (capability,) = bidi_controls(source, "a.py")
    assert capability.kind is Kind.BIDI_CONTROL
    assert (capability.location.line, capability.location.column) == (2, 18)
    assert capability.subject == f"U+{ord(char):04X}"


def test_the_character_is_named() -> None:
    (capability,) = bidi_controls(f"x{chr(0x202E)}y", "a.py")
    assert (capability.subject, dict(capability.attrs)) == (
        "U+202E",
        {"name": "RIGHT-TO-LEFT OVERRIDE"},
    )


def test_ordinary_unicode_is_not_a_bidi_control() -> None:
    assert list(bidi_controls(f"name = 'Zoë 日本 {chr(0x200B)}'\n", "a.py")) == []


def test_fullwidth_name_that_runs_as_exec_is_reported() -> None:
    source = f"print(1)\n{FULLWIDTH_EXEC}('x')\n"
    (capability,) = confusable_names(source, "a.py")
    assert capability.kind is Kind.CONFUSABLE_NAME
    assert (capability.subject, dict(capability.attrs)) == (FULLWIDTH_EXEC, {"runs_as": "exec"})
    assert (capability.location.line, capability.location.column) == (2, 1)


def test_fullwidth_letters_inside_strings_are_not_names() -> None:
    assert list(confusable_names(f"x = '{FULLWIDTH_EXEC}'\n", "a.py")) == []


def test_ordinary_non_ascii_names_are_not_confusable() -> None:
    assert list(confusable_names("café = 1\nnaïve = café\n", "a.py")) == []


def test_ascii_names_are_not_confusable() -> None:
    assert list(confusable_names("exec('x')\n", "a.py")) == []
