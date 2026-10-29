"""Reviewed glossary configuration has bounded terms and precise validation errors."""

from copy import deepcopy

import pytest

from doorcheck.messages import MessageError, localization
from doorcheck.messages.glossaries import bindings

IDENTIFIER = "12345678-1234-1234-1234-123456789abc"
REGISTRY = {
    "en": {"deepl_target": "EN"},
    "de": {"deepl_target": "DE"},
    "fr": {"deepl_target": "FR"},
    "nn": {"deepl_target": None},
}


def configured(entries=None):
    return {
        "revision": "1",
        "description": "Owned UI terminology",
        "protected_terms": [],
        "glossaries": {
            "de": {"id": IDENTIFIER, "entries": {"scan": "Prüfung"} if entries is None else entries}
        },
    }


@pytest.mark.parametrize("value", [None, [], "glossary", 1])
def test_bindings_container_error_is_specific(value):
    with pytest.raises(MessageError) as error:
        bindings({"glossaries": value}, REGISTRY)
    assert str(error.value) == "invalid glossary bindings"


@pytest.mark.parametrize("code", ["en", "nn", "unknown"])
def test_only_mapped_nonenglish_locales_can_have_glossaries(code):
    settings = configured()
    settings["glossaries"][code] = settings["glossaries"].pop("de")
    with pytest.raises(MessageError) as error:
        bindings(settings, REGISTRY)
    assert str(error.value) == "invalid glossary locale"


@pytest.mark.parametrize(
    "value",
    [
        None,
        [],
        {},
        {"id": IDENTIFIER},
        {"id": IDENTIFIER, "entries": {"scan": "Prüfung"}, "extra": True},
    ],
)
def test_binding_shape_error_is_specific(value):
    settings = configured()
    settings["glossaries"]["de"] = value
    with pytest.raises(MessageError) as error:
        bindings(settings, REGISTRY)
    assert str(error.value) == "invalid glossary binding"


@pytest.mark.parametrize(
    "identifier", [None, "bad", IDENTIFIER.upper(), "../" + IDENTIFIER, IDENTIFIER + "/entries"]
)
def test_identifier_error_is_specific(identifier):
    settings = configured()
    settings["glossaries"]["de"]["id"] = identifier
    with pytest.raises(MessageError) as error:
        bindings(settings, REGISTRY)
    assert str(error.value) == "invalid glossary identifier"


@pytest.mark.parametrize("value", [[], {}, "entries", None])
def test_entries_shape_error_is_specific(value):
    settings = configured()
    settings["glossaries"]["de"]["entries"] = value
    with pytest.raises(MessageError) as error:
        bindings(settings, REGISTRY)
    assert str(error.value) == "invalid glossary entries"


def test_exact_entry_limit_is_accepted():
    entries = {f"term{number}": f"Begriff{number}" for number in range(1000)}
    settings = configured(entries)
    assert bindings(settings, REGISTRY) == settings["glossaries"]


def test_one_entry_over_limit_is_refused():
    entries = {f"term{number}": f"Begriff{number}" for number in range(1001)}
    with pytest.raises(MessageError) as error:
        bindings(configured(entries), REGISTRY)
    assert str(error.value) == "invalid glossary entries"


@pytest.mark.parametrize(
    "term",
    [
        "x" * 1025,
        "é" * 512 + "x",
        "",
        " leading",
        "trailing ",
        "tab\tvalue",
        "line\nvalue",
        "return\rvalue",
        "escape\x1bvalue",
        "bidi\u202evalue",
        None,
    ],
)
@pytest.mark.parametrize("source", [True, False])
def test_invalid_phrase_has_exact_safe_diagnostic(term, source):
    entries = {term: "Begriff"} if source else {"term": term}
    with pytest.raises(MessageError) as error:
        bindings(configured(entries), REGISTRY)
    assert str(error.value) == "invalid glossary term"


def test_uppercase_and_exact_multibyte_phrases_are_supported():
    settings = configured({"EXTRA": "Zusätzlich", "é" * 512: "الف\u200cب\u200d"})
    assert bindings(settings, REGISTRY) == settings["glossaries"]


@pytest.mark.parametrize(
    "value", [None, [], {"en": {"id": IDENTIFIER, "entries": {"scan": "scan"}}}]
)
def test_context_validates_optional_glossary_field(monkeypatch, value):
    settings = configured()
    settings["glossaries"] = value
    monkeypatch.setattr(localization, "resource", lambda _: settings)
    monkeypatch.setattr(localization, "locales", lambda: REGISTRY)
    with pytest.raises(MessageError) as error:
        localization.context()
    expected = "invalid glossary locale" if isinstance(value, dict) else "invalid glossary bindings"
    assert str(error.value) == expected


def test_same_id_with_changed_preference_invalidates_source_receipt():
    original = configured()
    revised = deepcopy(original)
    revised["glossaries"]["de"]["entries"]["scan"] = "Überprüfung"
    assert localization.source_hash("Run a scan", original) != localization.source_hash(
        "Run a scan", revised
    )
