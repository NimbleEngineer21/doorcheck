"""Reviewed glossary bindings carried in the translation context receipt."""

import re
from collections.abc import Mapping
from typing import Any

from doorcheck.messages import MessageError
from doorcheck.text import display_safe

UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"


def bindings(settings: Mapping[str, Any], registry: Mapping[str, Any]) -> dict[str, Any]:
    value = settings.get("glossaries", {})
    if not isinstance(value, dict):
        raise MessageError("invalid glossary bindings")
    for code, binding in value.items():
        if code == "en" or code not in registry or registry[code]["deepl_target"] is None:
            raise MessageError("invalid glossary locale")
        _binding(binding)
    return value


def _binding(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != {"id", "entries"}:
        raise MessageError("invalid glossary binding")
    if not isinstance(value["id"], str) or re.fullmatch(UUID, value["id"]) is None:
        raise MessageError("invalid glossary identifier")
    entries = value["entries"]
    if not isinstance(entries, dict) or not entries or len(entries) > 1000:
        raise MessageError("invalid glossary entries")
    for source, target in entries.items():
        _term(source)
        _term(target)


def _term(value: Any) -> None:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value.encode()) > 1024
        or any(char in value for char in "\t\r\n")
        or any(ord(char) not in (8204, 8205) and display_safe(char) != char for char in value)
    ):
        raise MessageError("invalid glossary term")
