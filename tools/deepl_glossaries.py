"""Verify reviewed glossary contents before any billed translation request."""

from collections.abc import Mapping
from typing import Any

from doorcheck.messages import MessageError
from doorcheck.messages.glossaries import bindings
from tools.deepl_transport import Client


def glossary_id(code: str, settings: Mapping[str, Any]) -> str | None:
    binding = settings.get("glossaries", {}).get(code)
    return binding["id"] if binding else None


def verify(
    client: Client,
    codes: set[str],
    settings: Mapping[str, Any],
    registry: Mapping[str, Any],
    languages: Any,
) -> None:
    configured = bindings(settings, registry)
    for code in codes & configured.keys():
        target = registry[code]["deepl_target"].lower()
        _capabilities(languages, target)
        binding = configured[code]
        base = target.split("-")[0].upper()
        path = "/v3/glossaries/" + binding["id"]
        count = _metadata(client.request(path), binding["id"], base)
        data = client.request(path + "/entries?source_lang=EN&target_lang=" + base)
        entries = _entries(data, base)
        if count != len(entries) or entries != binding["entries"]:
            raise MessageError("DeepL glossary differs from reviewed entries")


def _capabilities(languages: list[dict[str, Any]], target: str) -> None:
    source = [
        row
        for row in languages
        if row["lang"].lower() == "en" and row.get("usable_as_source") is True
    ]
    targets = [
        row
        for row in languages
        if row["lang"].lower() == target
        and row.get("usable_as_target") is True
        and row.get("status") == "stable"
    ]
    if (
        not source
        or not targets
        or any(
            not {"glossary", "tag_handling"} <= row["features"].keys()
            for row in [source[0], targets[0]]
        )
    ):
        raise MessageError("configured DeepL glossary capability unavailable")


def _dictionary(data: Any, target: str) -> dict[str, Any]:
    dictionaries = data.get("dictionaries") if isinstance(data, dict) else None
    if not isinstance(dictionaries, list):
        raise MessageError("invalid DeepL glossary dictionaries")
    matches = [
        row
        for row in dictionaries
        if isinstance(row, dict)
        and isinstance(row.get("source_lang"), str)
        and row["source_lang"].lower() == "en"
        and isinstance(row.get("target_lang"), str)
        and row["target_lang"].lower() == target.lower()
    ]
    if len(matches) != 1:
        raise MessageError("DeepL glossary language pair unavailable")
    return matches[0]


def _metadata(data: Any, identifier: str, target: str) -> int:
    if not isinstance(data, dict) or data.get("glossary_id") != identifier:
        raise MessageError("invalid DeepL glossary identity")
    row = _dictionary(data, target)
    count = row.get("entry_count")
    if type(count) is not int or count <= 0 or count > 1000:
        raise MessageError("invalid DeepL glossary entry count")
    return count


def _entries(data: Any, target: str) -> dict[str, str]:
    row = _dictionary(data, target)
    if row.get("entries_format", "tsv") != "tsv" or not isinstance(row.get("entries"), str):
        raise MessageError("invalid DeepL glossary entry format")
    entries = {}
    for line in row["entries"].splitlines():
        pair = line.split("\t")
        if len(pair) != 2 or not all(pair) or pair[0] in entries:
            raise MessageError("invalid DeepL glossary TSV")
        entries[pair[0]] = pair[1]
    return entries
