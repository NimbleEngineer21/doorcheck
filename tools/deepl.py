"""Incremental, budgeted translation refresh; dry-run unless --write is explicit."""

import argparse
import json
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from xml.etree import ElementTree
from xml.sax.saxutils import escape

from doorcheck.messages import ENGLISH, MessageError
from doorcheck.messages.localization import (
    MAX_JSON_BYTES,
    TOKEN,
    catalog,
    context,
    decode,
    locales,
    source_hash,
    source_hashes,
    text_hash,
    validate_text,
)
from tools.deepl_glossaries import glossary_id, verify
from tools.deepl_transport import Client, credential
from tools.localization import MESSAGES


def protect(text: str, settings: Mapping[str, Any]) -> tuple[str, list[str]]:
    # Descending lexical order keeps a longer term ahead of its own prefix.
    terms = sorted(settings["protected_terms"], reverse=True)
    pattern = re.compile(
        "(" + "|".join([TOKEN.pattern, *(re.escape(term) for term in terms)]) + ")"
    )
    tokens = []
    parts = []
    for index, piece in enumerate(pattern.split(text)):
        if index % 2:
            tokens.append(piece)
            parts.append(f'<x id="{len(tokens) - 1}">{escape(piece)}</x>')
        else:
            parts.append(escape(piece))
    return "<text>" + "".join(parts) + "</text>", tokens


def restore(xml: str, tokens: list[str]) -> str:
    if len(xml.encode()) > MAX_JSON_BYTES or "<!" in xml:
        raise MessageError("invalid translated XML")
    try:
        root = ElementTree.fromstring(xml)  # noqa: S314 - declarations rejected, bounded owned data
    except ElementTree.ParseError as error:
        raise MessageError("invalid translated XML") from error
    if root.tag != "text" or root.attrib or len(root) != len(tokens):
        raise MessageError("translated XML structure changed")
    pieces = [root.text or ""]
    seen: set[str] = set()
    token_by_id = {str(index): token for index, token in enumerate(tokens)}
    for child in root:
        pieces.extend([_slot(child, token_by_id, seen), child.tail or ""])
    return "".join(pieces)


def _slot(child: ElementTree.Element, tokens: Mapping[str, str], seen: set[str]) -> str:
    if child.tag != "x" or set(child.attrib) != {"id"}:
        raise MessageError("translated XML slot changed")
    index = child.attrib["id"]
    if index not in tokens or index in seen or len(child) or child.text != tokens[index]:
        raise MessageError("translated XML token changed")
    seen.add(index)
    return tokens[index]


def _language(row: Any) -> dict[str, Any]:
    if not isinstance(row, dict) or not isinstance(row.get("lang"), str):
        raise MessageError("invalid DeepL language entry")
    if not isinstance(row.get("features"), dict):
        raise MessageError("invalid DeepL language features")
    return row


def supported(data: Any) -> set[str]:
    if not isinstance(data, list):
        raise MessageError("invalid DeepL language response")
    rows = [_language(row) for row in data]
    source = [
        row for row in rows if row["lang"].lower() == "en" and row.get("usable_as_source") is True
    ]
    if not source or "tag_handling" not in source[0]["features"]:
        raise MessageError("DeepL English XML translation unavailable")
    return {row["lang"].lower() for row in rows if _target(row)}


def _target(row: Mapping[str, Any]) -> bool:
    return (
        row.get("status") == "stable"
        and row.get("usable_as_target") is True
        and "tag_handling" in row["features"]
    )


def remaining(data: Any) -> int:
    if not isinstance(data, dict):
        raise MessageError("invalid DeepL usage response")
    used, limit = data.get("character_count"), data.get("character_limit")
    if type(used) is not int or type(limit) is not int or used < 0 or limit < used:
        raise MessageError("invalid or exhausted DeepL quota")
    return limit - used


def selected(value: str) -> list[str]:
    registry = locales()
    codes = value.split(",")
    if (
        not codes
        or len(codes) != len(set(codes))
        or any(code == "en" or code not in registry for code in codes)
    ):
        raise MessageError("select unique non-English Home Assistant locales")
    shipped = decode((MESSAGES / "shipped-locales.json").read_bytes())
    if not isinstance(shipped, list) or any(
        not isinstance(code, str) or code == "en" or code not in registry for code in shipped
    ):
        raise MessageError("invalid shipped locale inventory")
    return list(dict.fromkeys([*codes, *shipped]))


def existing(code: str, settings: Mapping[str, Any]) -> dict[str, Any]:
    path = MESSAGES / "translations" / f"{code}.json"
    if not path.exists():
        return {}
    data = decode(path.read_bytes())
    if (
        not isinstance(data, dict)
        or data.get("locale") != code
        or not isinstance(data.get("messages"), dict)
    ):
        raise MessageError("invalid existing translation catalog")
    # Stale receipts are expected during refresh; reusable rows must still be valid.
    result = {}
    for key, row in data["messages"].items():
        if key in ENGLISH:
            reusable = _reusable(row, ENGLISH[key], settings)
            if reusable is not None:
                result[key] = reusable
    return result


def _reusable(row: Any, source: str, settings: Mapping[str, Any]) -> dict[str, Any] | None:
    if not isinstance(row, dict) or row.get("source_hash") != source_hash(source, settings):
        return None
    if set(row) != {"text", "source_hash", "text_hash"}:
        raise MessageError("invalid existing translation message")
    if not isinstance(row.get("text"), str):
        raise MessageError("invalid existing translation text")
    validate_text(source, row["text"], settings)
    if row.get("text_hash") != text_hash(row["text"]):
        raise MessageError("existing translation receipt mismatch")
    return row


def plan(codes: list[str], settings: Mapping[str, Any]) -> tuple[dict[str, dict[str, Any]], int]:
    rows = {}
    total = 0
    for code in codes:
        kept = existing(code, settings)
        pending = [key for key in ENGLISH if key not in kept]
        size = sum(len(protect(ENGLISH[key], settings)[0]) for key in pending)
        total += size
        rows[code] = {"kept": kept, "pending": pending, "characters": size}
    return rows, total


def payload(
    texts: list[str], target: str, settings: Mapping[str, Any], glossary: str | None = None
) -> dict[str, Any]:
    result = {
        "text": texts,
        "source_lang": "EN",
        "target_lang": target,
        "tag_handling": "xml",
        "tag_handling_version": "v2",
        "ignore_tags": ["x"],
        "context": settings["description"],
        "show_billed_characters": True,
    }

    if glossary is not None:
        result["glossary_id"] = glossary
    return result


def _translations(response: Any, count: int) -> list[Any]:
    translations = response.get("translations") if isinstance(response, dict) else None
    if not isinstance(translations, list) or len(translations) != count:
        raise MessageError("invalid DeepL translation response")
    return translations


def _receipt(item: Any, key: str, tokens: list[str], settings: Mapping[str, Any]) -> dict[str, str]:
    if not isinstance(item, dict) or not isinstance(item.get("text"), str):
        raise MessageError("invalid DeepL translation entry")
    text = restore(item["text"], tokens)
    validate_text(ENGLISH[key], text, settings)
    return {
        "text": text,
        "source_hash": source_hash(ENGLISH[key], settings),
        "text_hash": text_hash(text),
    }


def translate(
    client: Client,
    target: str,
    pending: list[str],
    settings: Mapping[str, Any],
    glossary: str | None = None,
) -> dict[str, Any]:
    result = {}
    for offset in range(0, len(pending), 50):
        batch = pending[offset : offset + 50]
        prepared = [protect(ENGLISH[key], settings) for key in batch]
        response = client.request(
            "/v2/translate", payload([p[0] for p in prepared], target, settings, glossary)
        )
        translated = _translations(response, len(batch))
        for index, key in enumerate(batch):
            result[key] = _receipt(translated[index], key, prepared[index][1], settings)
    return result


def _eligible(
    rows: dict[str, dict[str, Any]], support: set[str], available_only: bool
) -> tuple[dict[str, Any], list[str]]:
    registry = locales()
    gaps = [
        code
        for code in rows
        if registry[code]["deepl_target"] is None
        or registry[code]["deepl_target"].lower() not in support
    ]
    if gaps and not available_only:
        raise MessageError("requested locales lack verified DeepL XML support: " + ",".join(gaps))
    return {code: row for code, row in rows.items() if code not in gaps}, gaps


def _request_sizes(rows: dict[str, Any], settings: Mapping[str, Any]) -> None:
    registry = locales()
    for code, row in rows.items():
        for offset in range(0, len(row["pending"]), 50):
            texts = [
                protect(ENGLISH[key], settings)[0] for key in row["pending"][offset : offset + 50]
            ]
            size = len(
                json.dumps(
                    payload(
                        texts, registry[code]["deepl_target"], settings, glossary_id(code, settings)
                    )
                ).encode()
            )
            if size > 120_000:
                raise MessageError("translation batch exceeds request byte limit")


def refresh(
    client: Client,
    rows: dict[str, dict[str, Any]],
    settings: Mapping[str, Any],
    output: Path,
    ceiling: int,
    available_only: bool,
) -> None:
    languages = client.request("/v3/languages?resource=translate_text")
    support = supported(languages)
    eligible, gaps = _eligible(rows, support, available_only)
    verify(client, set(rows), settings, locales(), languages)
    required = sum(row["characters"] for row in eligible.values())
    if required > ceiling or required > remaining(client.request("/v2/usage")):
        raise MessageError("translation estimate exceeds explicit budget or account quota")
    _request_sizes(eligible, settings)
    completed = _complete(client, eligible, settings)
    _write(completed, output, gaps, settings)


def _complete(client: Client, rows: dict[str, Any], settings: Mapping[str, Any]) -> dict[str, Any]:
    registry = locales()
    completed = {}
    for code, row in rows.items():
        messages = {
            **row["kept"],
            **translate(
                client,
                registry[code]["deepl_target"],
                row["pending"],
                settings,
                glossary_id(code, settings),
            ),
        }
        data = {"locale": code, "messages": messages}
        catalog(data, code, ENGLISH, settings)
        completed[code] = data
    return completed


def _write(
    completed: dict[str, Any], output: Path, gaps: list[str], settings: Mapping[str, Any]
) -> None:
    # All provider and validation steps finish before any output is replaced.
    output.mkdir(parents=True, exist_ok=True)
    (output / "translations").mkdir(exist_ok=True)
    for code, data in completed.items():
        save(output / "translations" / f"{code}.json", data)
    save(output / "source-hashes.json", source_hashes(ENGLISH, settings))
    shipped = set(decode((MESSAGES / "shipped-locales.json").read_bytes()))
    save(output / "shipped-locales.json", sorted(shipped | completed.keys()))
    save(output / "coverage.json", {"translated": sorted(completed), "unavailable": gaps})
    print(
        f"Refreshed {len(completed)} locale catalogs; "
        f"{len(gaps)} unavailable locales remain explicit gaps."
    )


def save(path: Path, value: Any) -> None:
    with TemporaryDirectory(dir=path.parent) as directory:
        temporary = Path(directory) / path.name
        encoder = json.JSONEncoder()
        encoder.ensure_ascii = False  # pragma: no mutate - False/None both preserve Unicode
        encoder.indent = 2
        data = encoder.encode(value)
        temporary.write_bytes((data + "\n").encode())
        temporary.replace(path)


def provider_check(
    client: Client, rows: dict[str, dict[str, Any]], settings: Mapping[str, Any] | None = None
) -> None:
    languages = client.request("/v3/languages?resource=translate_text")
    support = supported(languages)
    verify(client, set(rows), settings or {}, locales(), languages)
    eligible, gaps = _eligible(rows, support, True)
    quota = remaining(client.request("/v2/usage"))
    print(
        f"Provider XML targets available: {len(eligible)}; remaining account characters: {quota}."
    )
    print("Unavailable locale mappings: " + (",".join(gaps) if gaps else "none"))


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--locales", required=True)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--write", action="store_true")
    modes.add_argument("--check-provider", action="store_true")
    parser.add_argument("--keychain", action="store_true")
    parser.add_argument("--free", action="store_true")
    parser.add_argument("--available-only", action="store_true")
    parser.add_argument("--max-characters", type=int, default=20_000)
    parser.add_argument("--output", type=Path, default=MESSAGES)
    args = parser.parse_args(argv)
    try:
        if args.max_characters < 0:
            raise MessageError("character ceiling must be nonnegative")
        settings = context()
        rows, total = plan(selected(args.locales), settings)
        print(f"Estimated upper bound: {total} source/XML characters across {len(rows)} locales.")
        for code, row in rows.items():
            print(f"{code}: {len(row['pending'])} messages, {row['characters']} characters")
        if args.check_provider:
            provider_check(Client(credential(args.keychain), free=args.free), rows, settings)
        if args.write:
            refresh(
                Client(credential(args.keychain), free=args.free),
                rows,
                settings,
                args.output,
                args.max_characters,
                args.available_only,
            )
    except (OSError, MessageError) as error:
        print(f"Translation refresh failed: {error}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
