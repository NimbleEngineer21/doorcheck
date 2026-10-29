"""Locale metadata, source receipts and contracts for owned UI translations."""

import hashlib
import json
import re
from collections import Counter
from collections.abc import Mapping
from importlib.resources import files
from string import Formatter
from typing import Any

from doorcheck.messages import ENGLISH, MessageError, placeholders
from doorcheck.text import display_safe

MAX_JSON_BYTES = 1_000_000
TOKEN = re.compile(
    r"\{[^{}]+\}|--[a-z][a-z-]*|\b(?:doorcheck(?:\s+(?:scan|compare|hosts))?|uv(?:\s+run)?|python3?)\b|(?<![A-Za-z0-9])(?:OWNER/REPO|FOLDER|BEFORE\.json|AFTER\.json|REPORT\.json|FULL_SHA|SHA|TAG)(?![A-Za-z0-9])|(?<!\S)--(?!\S)|https?://[^\s]+"
)


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise MessageError("duplicate localization field")
        result[key] = value
    return result


def decode(data: bytes) -> Any:
    if len(data) > MAX_JSON_BYTES:
        raise MessageError("localization JSON exceeds byte limit")
    try:
        value = json.loads(data, object_pairs_hook=_unique)
        encoder = json.JSONEncoder()
        encoder.ensure_ascii = False  # pragma: no mutate - None has identical JSON behavior
        encoder.allow_nan = False  # pragma: no mutate - None also rejects nonfinite numbers
        encoder.encode(value).encode()
        return value
    except (ValueError, UnicodeError, RecursionError) as error:
        raise MessageError("invalid localization JSON") from error


def resource(name: str) -> Any:
    return decode(files().joinpath(name).read_bytes())


def context() -> dict[str, Any]:
    value = resource("translation-context.json")
    if not isinstance(value, dict) or set(value) != {"revision", "description", "protected_terms"}:
        raise MessageError("invalid translation context")
    if not all(isinstance(value[k], str) and value[k] for k in ("revision", "description")):
        raise MessageError("invalid translation context text")
    terms = value["protected_terms"]
    if not isinstance(terms, list) or not all(isinstance(term, str) and term for term in terms):
        raise MessageError("invalid protected terms")
    return value


def locales() -> dict[str, Any]:
    value = resource("locales.json")
    if not isinstance(value, dict) or set(value) != {
        "upstream_revision",
        "upstream_path",
        "locales",
    }:
        raise MessageError("invalid locale registry")
    if not isinstance(value["upstream_revision"], str) or not re.fullmatch(
        r"[0-9a-f]{40}", value["upstream_revision"]
    ):
        raise MessageError("invalid locale source revision")
    if value["upstream_path"] != "src/translations/translationMetadata.json":
        raise MessageError("invalid locale source path")
    rows = value["locales"]
    if not isinstance(rows, dict) or "en" not in rows:
        raise MessageError("invalid locale list")
    for code, row in rows.items():
        _locale(code, row)
    return rows


def _locale(code: str, row: Any) -> None:
    if not re.fullmatch(r"[a-z]{2,3}(?:-[A-Za-z0-9]+)*", code):
        raise MessageError("invalid locale code")
    if not isinstance(row, dict) or set(row) != {"name", "rtl", "deepl_target"}:
        raise MessageError("invalid locale metadata")
    target = row["deepl_target"]
    if not isinstance(row["name"], str) or not row["name"] or type(row["rtl"]) is not bool:
        raise MessageError("invalid locale label or direction")
    if target is not None and (
        not isinstance(target, str) or not re.fullmatch(r"[A-Za-z]{2,3}(?:-[A-Za-z0-9]+)*", target)
    ):
        raise MessageError("invalid provider locale mapping")


def text_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def source_hash(text: str, settings: Mapping[str, Any]) -> str:
    encoder = json.JSONEncoder(sort_keys=True)
    encoder.ensure_ascii = False  # pragma: no mutate - None also preserves Unicode
    data = encoder.encode({"text": text, "context": dict(settings)})
    return hashlib.sha256(data.encode()).hexdigest()


def source_hashes(source: Mapping[str, str], settings: Mapping[str, Any]) -> dict[str, str]:
    return {key: source_hash(text, settings) for key, text in source.items()}


def protected(text: str, settings: Mapping[str, Any]) -> Counter[str]:
    found = Counter(TOKEN.findall(text))
    for term in settings["protected_terms"]:
        found[term] = text.count(term)
    return +found


def fields(text: str) -> Counter[str]:
    placeholders(text)
    return Counter(name for _, name, _, _ in Formatter().parse(text) if name is not None)


def validate_text(source: str, translated: str, settings: Mapping[str, Any]) -> None:
    if not isinstance(translated, str) or not translated:
        raise MessageError("translation must be nonempty text")
    if fields(source) != fields(translated):
        raise MessageError("translation placeholder mismatch")
    if protected(source, settings) != protected(translated, settings):
        raise MessageError("translation protected-token mismatch")
    if any(ord(char) not in (8204, 8205) and display_safe(char) != char for char in translated):
        raise MessageError("translation contains display controls")


def catalog(
    data: Any, locale: str, source: Mapping[str, str], settings: Mapping[str, Any]
) -> dict[str, str]:
    if (
        not isinstance(data, dict)
        or set(data) != {"locale", "messages"}
        or data["locale"] != locale
    ):
        raise MessageError("invalid localized catalog")
    rows = data["messages"]
    if not isinstance(rows, dict) or rows.keys() != source.keys():
        raise MessageError("localized catalog must contain every English key")
    return {key: _message(row, key, locale, source[key], settings) for key, row in rows.items()}


def _message(row: Any, key: str, locale: str, source: str, settings: Mapping[str, Any]) -> str:
    if not isinstance(row, dict) or set(row) != {"text", "source_hash", "text_hash"}:
        raise MessageError("invalid localized message")
    if row["source_hash"] != source_hash(source, settings):
        raise MessageError(f"stale translation: {locale}/{key}")
    if not isinstance(row["text"], str) or row["text_hash"] != text_hash(row["text"]):
        raise MessageError("translation text receipt mismatch")
    validate_text(source, row["text"], settings)
    return row["text"]


def template(key: str, locale: str) -> str:
    rows = locales()
    selected = locale if locale in rows else locale.partition("-")[0]
    if selected == "en" or selected not in rows:
        return ENGLISH[key]
    try:
        data = resource(f"translations/{selected}.json")
    except FileNotFoundError:
        return ENGLISH[key]
    return catalog(data, selected, ENGLISH, context())[key]
